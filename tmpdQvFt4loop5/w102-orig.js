

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
/*fuzzSeed-204012247*/count=1; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.hypot(Math.fround(( + Math.atanh(( + Math.fround(( + Math.fround(( + Math.atanh(( + -Number.MIN_VALUE)))))))))), (Math.fround(Math.fround(Math.hypot((Math.exp(y) >>> 0), Math.fround(x)))) === ( ! (((( ~ ( - 0.000000000000001)) | 0) | (( ~ y) | 0)) | 0))))); }); testMathyFunction(mathy1, [0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 42, -(2**53-2), -(2**53), 0x080000000, 1/0, 2**53, 0.000000000000001, 0, 0x0ffffffff, 0x100000001, -0x100000001, Number.MIN_VALUE, 2**53+2, Math.PI, -1/0, -0x100000000, -(2**53+2), -0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, 2**53-2, -0, 0x080000001, 1]); ");
/*fuzzSeed-204012247*/count=2; tryItOut("mathy1 = (function(x, y) { return (((Math.fround(Math.round(Math.log2(((x | 0) > (Math.min(-Number.MIN_SAFE_INTEGER, y) >>> 0))))) < (mathy0(y, x) / Math.trunc(Math.sqrt(x)))) | 0) <= (Math.max(((y | 0) || (( + Math.cos(( + x))) | 0)), (mathy0(x, y) | 0)) | 0)); }); testMathyFunction(mathy1, [-0x080000001, Math.PI, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53, 1/0, -0x080000000, 0/0, -(2**53), 2**53-2, Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, -1/0, 0.000000000000001, -0x0ffffffff, 0x080000001, -0x100000001, Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, -(2**53+2), 1, 0, Number.MAX_VALUE, -0x07fffffff, -0, 0x100000001, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-204012247*/count=3; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.asin(( - Math.hypot(mathy4(Math.fround((x || Math.fround(Math.pow((Math.atan2(( + y), ( + x)) >>> 0), 0x080000001)))), ( + ( ! (x >>> 0)))), (x < y)))); }); testMathyFunction(mathy5, [2**53, -1/0, 0x100000001, -0x0ffffffff, Math.PI, -Number.MAX_VALUE, -0x100000000, -0x100000001, 0.000000000000001, 1.7976931348623157e308, 0, 42, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, -0, 2**53+2, -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), -0x080000001, 0x07fffffff, -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, 0/0, 1/0, -(2**53-2), 0x0ffffffff]); ");
/*fuzzSeed-204012247*/count=4; tryItOut("print(uneval(e2));");
/*fuzzSeed-204012247*/count=5; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x100000001, -Number.MAX_VALUE, 2**53-2, -0x100000001, -1/0, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, -0, 1/0, -Number.MIN_VALUE, 2**53+2, -0x0ffffffff, 0x080000001, Number.MAX_VALUE, 0x100000000, 0, 0x07fffffff, -0x100000000, 2**53, 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -(2**53), 1, 1.7976931348623157e308, 0x080000000, -0x080000000, -(2**53+2), -(2**53-2), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=6; tryItOut("b2 = new ArrayBuffer(0);");
/*fuzzSeed-204012247*/count=7; tryItOut("for (var p in g2.i0) { g2.m0.has(f1); }");
/*fuzzSeed-204012247*/count=8; tryItOut("v2 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-204012247*/count=9; tryItOut("\u3056 = linkedList(\u3056, 3248)");
/*fuzzSeed-204012247*/count=10; tryItOut("mathy2 = (function(x, y) { return (Math.asin((( + (( + ( ! ( + Math.fround(Math.log10(Math.atan2((x >>> 0), x)))))) << (((( ~ y) >>> 0) > (( + Math.fround((((( + Math.log10(( + y))) | 0) , (y | 0)) | 0))) != (x ? ( + mathy1((x | 0), y)) : (( + x) || y)))) | 0))) >>> 0)) | 0); }); testMathyFunction(mathy2, [1.7976931348623157e308, 2**53, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, 1, 0x080000001, -0x080000001, 1/0, 2**53+2, 42, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -(2**53+2), 0x0ffffffff, 2**53-2, -0x080000000, -0, 0x100000000, 0x100000001, -0x07fffffff, -(2**53), 0x080000000, 0, 0.000000000000001, -0x100000001, Math.PI, -0x100000000]); ");
/*fuzzSeed-204012247*/count=11; tryItOut("\"use strict\"; var kgjige = new ArrayBuffer(6); var kgjige_0 = new Float64Array(kgjige); kgjige_0[0] = 10; this;");
/*fuzzSeed-204012247*/count=12; tryItOut("true;");
/*fuzzSeed-204012247*/count=13; tryItOut("/*tLoop*/for (let b of /*MARR*/[objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0.000000000000001, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), 0.000000000000001, objectEmulatingUndefined(), new Number(1.5), 0.000000000000001, new Number(1.5), 0.000000000000001, new Number(1.5), 0.000000000000001, 0.000000000000001, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), 0.000000000000001, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), 0.000000000000001, new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), 0.000000000000001, objectEmulatingUndefined(), 0.000000000000001, 0.000000000000001, 0.000000000000001, objectEmulatingUndefined(), 0.000000000000001, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), 0.000000000000001, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), 0.000000000000001, objectEmulatingUndefined(), objectEmulatingUndefined(), 0.000000000000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0.000000000000001, objectEmulatingUndefined(), new Number(1.5), 0.000000000000001, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), 0.000000000000001, objectEmulatingUndefined(), 0.000000000000001]) {  /x/ ; }");
/*fuzzSeed-204012247*/count=14; tryItOut("\"use strict\"; /*MXX1*/o2 = g0.g0.Uint8Array.length;");
/*fuzzSeed-204012247*/count=15; tryItOut("for (var p in i1) { try { v2 = Array.prototype.reduce, reduceRight.call(o1.a2, f0, v2); } catch(e0) { } try { Array.prototype.push.call(a0, g1.v1, o0.b2, g0); } catch(e1) { } try { v2 = evalcx(\"/* no regression tests found */\", g1); } catch(e2) { } s2.__proto__ = g0.m0; }");
/*fuzzSeed-204012247*/count=16; tryItOut("( /x/g );");
/*fuzzSeed-204012247*/count=17; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.atan(( + (( + 0/0) ? ( + y) : ( + Math.fround(Math.hypot(x, (y >>> 0))))))) == Math.cosh((mathy2(((mathy2((x | 0), (x | 0)) | 0) + (x / x)), 0.000000000000001) == (( + (y , x)) >>> 0)))); }); testMathyFunction(mathy3, [2**53-2, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, -0x100000001, 0x080000001, 0x100000000, 1/0, 0x080000000, 42, Math.PI, -(2**53-2), 0/0, -0, Number.MAX_VALUE, 1, -(2**53), -1/0, 0, Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, 0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -(2**53+2)]); ");
/*fuzzSeed-204012247*/count=18; tryItOut("Array.prototype.sort.call(a1);");
/*fuzzSeed-204012247*/count=19; tryItOut("mathy4 = (function(x, y) { return mathy2(( + mathy1(( + Math.sinh(Math.sqrt((( ~ ( + (x < -Number.MIN_VALUE))) | 0)))), (Math.round(((Math.fround(y) >>> (x | 0)) ? Math.fround(Math.round(Math.fround((Math.acosh((((-(2**53) | -Number.MAX_SAFE_INTEGER) >>> 0) >>> 0)) | 0)))) : (y << ( + 0/0)))) >>> 0))), (( + ((Math.asinh(Math.hypot(( - -1/0), Math.fround(( ~ 0)))) >>> 0) >= ( + ( + ( + ( + ( ~ ( ! ((y || x) >>> 0))))))))) >>> 0)); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -1/0, -(2**53-2), -0x100000000, -(2**53+2), -0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, -0x080000000, 0x100000000, 0.000000000000001, 2**53-2, -0, 0x100000001, 0/0, 0, 1.7976931348623157e308, 2**53+2, 0x0ffffffff, -0x080000001, 1/0, -(2**53), 1, 2**53, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 42]); ");
/*fuzzSeed-204012247*/count=20; tryItOut("Object.defineProperty(this, \"g1.o2.t2\", { configurable: true, enumerable: true,  get: function() { a1.forEach((function mcc_() { var sptnuv = 0; return function() { ++sptnuv; if (/*ICCD*/sptnuv % 7 == 4) { dumpln('hit!'); try { h0.keys = f2; } catch(e0) { } i0.toString = (function() { for (var j=0;j<30;++j) { g1.f0(j%5==1); } }); } else { dumpln('miss!'); try { /*ADP-1*/Object.defineProperty(g0.a2, 3, ({})); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(a0, m2); } catch(e1) { } try { a1[\"\\u7821\"] = ((makeFinalizeObserver('nursery'))); } catch(e2) { } /*MXX2*/g0.WebAssemblyMemoryMode.name = b1; } };})()); return new Float32Array(a1); } });function x(a, [b, a]) { \"use strict\"; const e = (Math.hypot(-9, this && 8));t2.valueOf = (function() { try { v2 = a1.reduce, reduceRight((function(j) { if (j) { try { i2.send(s0); } catch(e0) { } try { v0 = 0; } catch(e1) { } try { delete i0[\"some\"]; } catch(e2) { } h0.get = f2; } else { e1.add(t0); } }), e, this.m1, i1, o0); } catch(e0) { } Object.seal(o0); throw this.e2; }); } a0.reverse();");
/*fuzzSeed-204012247*/count=21; tryItOut("if(('fafafa'.replace(/a/g, String.prototype.trimLeft))) {a0.push(o1, this.t1);print(this / -0); } else  if (new ((4277))()) {Array.prototype.unshift.call(a2, a1, window);var o2 = new Object; } else print(x);");
/*fuzzSeed-204012247*/count=22; tryItOut("print(x);");
/*fuzzSeed-204012247*/count=23; tryItOut("\"use strict\"; v1 = a1.length;function a(e, x, c, \u3056, NaN, NaN, e =  /x/g , d = [z1], z, b, w, b = ({}), window, \u3056 = w, x, x, x, \u3056, w, x, d, \u3056 =  \"\" , x, d, x, y =  '' , x, x =  \"\" , NaN =  /x/ , e, x, a = false, x, \u3056 = this, w, \u3056, a, x, x = -15, x, x = \"\\u6569\", 8, a = null, window,  \"\" , \u3056, x, d, x, w, z, window, x, x, x, \u3056, x = true, w, c = y, eval, eval, x, eval, y, e, 3, y = true, z, c, this.NaN, \u3056, c, y, eval,  /x/  = \"\\uF6FA\", x, NaN, x, x, x, e, b = length, x) { yield /./ym } v1 = o0.e0[\"valueOf\"];");
/*fuzzSeed-204012247*/count=24; tryItOut("/*infloop*/ for  each(x(x) in x = (Math.pow( /x/g , /\\1{2,4}(?:$.\u00aa)[]{1}\\D(?:[^]|\\W)*?/gyi).valueOf(\"number\")) ? (e in [,,]) :  ''  = Proxy.createFunction(({/*TOODEEP*/})(false), Math.pow, function shapeyConstructor(ybwucf){{ return; } if ( \"\" ) Object.preventExtensions(this);Object.defineProperty(this, \"length\", ({enumerable: false}));if (ybwucf) this[\"callee\"] = (Object.defineProperty).call;delete this[\"callee\"];return this; })) e0 = new Set;");
/*fuzzSeed-204012247*/count=25; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (((Math.cosh((( ! ( + ( ~ Number.MAX_SAFE_INTEGER))) | 0)) | 0) / (Math.log2((( ! x) ? Math.fround((Math.fround(Math.pow(y, y)) || (y | 0))) : ( + Math.fround(( ! Math.fround((Math.trunc(x) >>> 0))))))) | 0)) | 0); }); testMathyFunction(mathy3, /*MARR*/[ /x/g .watch(new String(\"13\"), WeakMap.prototype.has), x,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), x,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), undefined, undefined,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), x, (1/0),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), x, x, x, (1/0), function(){}, (1/0),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), undefined,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), function(){}, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, (1/0), function(){}, (1/0), function(){}, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, x, (1/0), x,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), undefined, function(){}, (1/0), function(){}, undefined, function(){}, undefined, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), function(){}, function(){}, function(){}, (1/0), undefined,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), undefined, (1/0), function(){}, (1/0),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), (1/0), undefined, undefined, undefined, (1/0),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), x, function(){}, function(){}, x, (1/0), function(){}, function(){}, (1/0), x, x,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), function(){}, undefined, (1/0),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), (1/0), function(){}, undefined,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has),  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), undefined,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), undefined, (1/0), x, undefined,  /x/g .watch(new String(\"13\"), WeakMap.prototype.has), undefined]); ");
/*fuzzSeed-204012247*/count=26; tryItOut("\"use strict\"; t2 + '';");
/*fuzzSeed-204012247*/count=27; tryItOut("o2.t2.toSource = (function(j) { if (j) { try { i1.send(h1); } catch(e0) { } try { /*RXUB*/var r = o1.g0.r0; var s = s1; print(s.match(r));  } catch(e1) { } try { Array.prototype.shift.call(a2, a2); } catch(e2) { } h0.delete = (function() { try { Array.prototype.sort.call(a2, (function() { try { v1 = Object.prototype.isPrototypeOf.call(e1, b1); } catch(e0) { } try { for (var p in a1) { try { /*RXUB*/var r = this.r2; var s = \"\"; print(s.split(r));  } catch(e0) { } try { t1[\"\\uC845\"] = t0; } catch(e1) { } try { a0[1]; } catch(e2) { } /*MXX1*/o0 = o1.g0.Float32Array.name; } } catch(e1) { } try { Object.defineProperty(this, \"this.b0\", { configurable: true, enumerable: (x % 2 != 1),  get: function() {  return this.t2.buffer; } }); } catch(e2) { } f1(this.i0); return b2; })); } catch(e0) { } i0 + b2; return g0; }); } else { try { g2.a1 = arguments.callee.arguments; } catch(e0) { } o2.v1 = (this.v2 instanceof g1); } });");
/*fuzzSeed-204012247*/count=28; tryItOut("\"use strict\"; /*infloop*/L:for(var x in (((Object.getOwnPropertySymbols).call)(-29))){( \"\" );s2 += s2; }");
/*fuzzSeed-204012247*/count=29; tryItOut("testMathyFunction(mathy5, [0x0ffffffff, 2**53, -(2**53), -0x07fffffff, 1, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 2**53+2, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, 0x100000001, 0.000000000000001, Math.PI, 42, -0, 2**53-2, -0x100000001, -0x0ffffffff, 0x080000000, -(2**53+2), 0/0, 0, 0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-204012247*/count=30; tryItOut("v1 = t1.byteOffset;");
/*fuzzSeed-204012247*/count=31; tryItOut("mathy3 = (function(x, y) { return Math.round(( + ( ~ Math.fround(Math.max(Math.fround(Math.hypot((Math.fround(Math.min((-0x100000001 | 0), Math.fround((( ~ (( ~ (-0x07fffffff | 0)) | 0)) | 0)))) | 0), (x | 0))), y))))); }); testMathyFunction(mathy3, [1, 1/0, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -0x0ffffffff, 0, -0x07fffffff, 0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 42, 2**53+2, 0x0ffffffff, 1.7976931348623157e308, 0/0, 2**53, 0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 0x100000001, -1/0, -(2**53+2), -(2**53-2), 2**53-2, -0, -0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=32; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.expm1(Math.min((( ~ Math.fround(mathy2(y, ( + y)))) | 0), (( ~ ((( + Math.min(( + x), ( + Math.max(y, 1.7976931348623157e308)))) | 0) | 0)) | 0))) | 0); }); testMathyFunction(mathy3, /*MARR*/[new String(''), [], new String(''), [], [], new String(''), [], new String(''), [], new String(''), [], [], new String(''), [], new String(''), [], new String(''), [], new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), [], [], [], new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), [], new String(''), new String(''), [], new String(''), new String(''), new String(''), [], [], new String(''), [], [], [], [], new String(''), [], new String(''), new String(''), new String(''), new String(''), [], new String(''), [], new String(''), new String(''), new String(''), new String(''), [], [], new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]); ");
/*fuzzSeed-204012247*/count=33; tryItOut("print(x);Array.prototype.splice.apply(a2, [NaN, 12])");
/*fuzzSeed-204012247*/count=34; tryItOut("testMathyFunction(mathy0, [0.1, (new Boolean(false)), (new Boolean(true)), undefined, (function(){return 0;}), /0/, (new Number(-0)), ({toString:function(){return '0';}}), '/0/', '0', [], (new String('')), objectEmulatingUndefined(), true, '\\0', NaN, (new Number(0)), [0], false, null, ({valueOf:function(){return 0;}}), 1, '', 0, ({valueOf:function(){return '0';}}), -0]); ");
/*fuzzSeed-204012247*/count=35; tryItOut("\"use strict\"; --x;new RegExp(\"(((?=\\ued6a|\\\\B*?)\\\\b))+\", \"gm\");");
/*fuzzSeed-204012247*/count=36; tryItOut("L:with(x ? x = new RegExp(\"(?=(?=(?=(\\\\cR))|[^]*\\\\s(?![\\\\x1a-\\\\r\\\\w\\\\v]|\\\\D)*))\", \"gim\") : new ({/*TOODEEP*/})(\"\\u683C\"))e0.add(g2);");
/*fuzzSeed-204012247*/count=37; tryItOut("\"use strict\"; \"use asm\"; v2 = t0.length;(x &= NaN);");
/*fuzzSeed-204012247*/count=38; tryItOut("i2 = g2.m1.entries;");
/*fuzzSeed-204012247*/count=39; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy2(((( ! ( + (Math.fround(x) >>> -0x080000001))) && Math.log2(( - (x | 0)))) >> Math.fround((Math.fround((((mathy0(x, x) | 0) ? y : (( ~ y) | 0)) | 0)) , Math.fround((Math.min(( + -0x0ffffffff), Math.fround((( + y) % 0x080000000))) | 0))))), (((Math.min(x, (Math.sinh(Math.atan2(Math.fround(( + Math.max(( + 2**53), x))), (y | 0))) >>> 0)) >>> 0) >> ( + (((mathy1(y, ( + mathy4((Number.MAX_VALUE >>> 0), y))) < Math.fround(Math.hypot(2**53+2, Math.fround(x)))) >>> 0) | 0))) | 0)); }); testMathyFunction(mathy5, /*MARR*/[(4277), new String('q'), new String('q'), (4277), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (4277), (4277), (4277), objectEmulatingUndefined(),  /x/ ,  /x/ , new String('q'), new String('q'),  /x/ , (4277), (4277), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), (4277), (4277), (4277), (4277),  /x/ , (4277), objectEmulatingUndefined(), objectEmulatingUndefined(), (4277), new String('q'),  /x/ ,  /x/ , new String('q'),  /x/ ,  /x/ , new String('q'), (4277), (4277), new String('q')]); ");
/*fuzzSeed-204012247*/count=40; tryItOut("m0.set(o2, a2);");
/*fuzzSeed-204012247*/count=41; tryItOut("\"use strict\"; ((4277));");
/*fuzzSeed-204012247*/count=42; tryItOut("o2.__proto__ = b1;");
/*fuzzSeed-204012247*/count=43; tryItOut("");
/*fuzzSeed-204012247*/count=44; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround(( - ( ! Math.min((Math.sin(y) | 0), Math.acosh(Math.imul(x, y)))))) !== (Math.sqrt(Math.min(mathy0(Math.asinh(y), y), (Math.max(Math.fround(y), (0x100000001 >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy2, [-0x080000001, Number.MAX_VALUE, -0x0ffffffff, -(2**53), -(2**53+2), 2**53-2, 0.000000000000001, Math.PI, 2**53+2, -0x080000000, -Number.MIN_VALUE, 0x100000000, 0x07fffffff, 0x080000000, 1.7976931348623157e308, 1, Number.MIN_SAFE_INTEGER, 0x100000001, -0, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, 42, -(2**53-2), 0, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, -1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-204012247*/count=45; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +(((null).call(([1,,]), (!new RegExp(\"\\\\2+(?!(?:\\\\b))\", \"y\")), \"\\u7630\")));\n  }\n  return f; })(this, {ff: (new Function(\"for (var v of a0) { try { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } catch(e0) { } try { v2 = (t1 instanceof this.b1); } catch(e1) { } try { v1 = false; } catch(e2) { } v0 = r2.global; }\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, ['0', [], (new Boolean(true)), false, 1, '\\0', [0], -0, (new Boolean(false)), undefined, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Number(-0)), (function(){return 0;}), null, ({valueOf:function(){return 0;}}), true, '', NaN, /0/, '/0/', ({toString:function(){return '0';}}), (new Number(0)), 0.1, 0, (new String(''))]); ");
/*fuzzSeed-204012247*/count=46; tryItOut("\"use strict\"; g1.t1 = new Int8Array(t0);");
/*fuzzSeed-204012247*/count=47; tryItOut("v2 = evalcx(\"function f1(o0.a0)  { yield 0 } \", g1);");
/*fuzzSeed-204012247*/count=48; tryItOut(";");
/*fuzzSeed-204012247*/count=49; tryItOut("v2 = (s2 instanceof o0.a1);");
/*fuzzSeed-204012247*/count=50; tryItOut("a2.push(o1.g1);");
/*fuzzSeed-204012247*/count=51; tryItOut("mathy4 = (function(x, y) { return (Math.fround(( ~ (Math.asinh(x) ? Math.atanh(0) : Math.clz32(y)))) || Math.tanh(mathy0(( + Math.min(( + Math.atan2(( ~ x), ( + ((( + x) ? x : y) | 0)))), ( + -0x080000000))), Math.fround(( ~ (mathy2(x, y) >>> 0)))))); }); testMathyFunction(mathy4, [-(2**53-2), -0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, -0, 0.000000000000001, -Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, 0, 1/0, 42, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, 0x0ffffffff, 0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, Number.MIN_VALUE, -0x07fffffff, 1, 0x100000001, 0/0, Math.PI]); ");
/*fuzzSeed-204012247*/count=52; tryItOut("delete h2.getPropertyDescriptor;");
/*fuzzSeed-204012247*/count=53; tryItOut(";");
/*fuzzSeed-204012247*/count=54; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((( + Math.pow(x, (mathy1((( ~ Math.fround(( + Math.imul(Math.fround(x), ( + x))))) >>> 0), (( + ( ! (x | 0))) == Math.fround((Math.fround(x) & Math.fround(Math.log(( + x))))))) | 0))) >>> 0) <= (( ! (Math.log(1.7976931348623157e308) | 0)) >>> 0)); }); testMathyFunction(mathy5, [-0x080000000, -0x0ffffffff, -(2**53), -Number.MIN_VALUE, 2**53, 0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, -(2**53+2), Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, -0, 0.000000000000001, -0x080000001, Math.PI, Number.MIN_VALUE, -0x100000000, -0x100000001, 0x080000001, 0x07fffffff, 1, 2**53-2, 1.7976931348623157e308, 0, 0x080000000, 42, -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-204012247*/count=55; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.min(Math.fround(Math.fround(Math.log1p((( - (( - ((mathy0(((( + x) && Math.fround(-Number.MAX_SAFE_INTEGER)) | 0), (x >>> 0)) | 0) | 0)) | 0)) | 0)))), Math.fround(Math.fround(Math.min(((( + (( + y) <= ( + -Number.MIN_SAFE_INTEGER))) ? x : ( + ( ! (mathy0(( + Math.acosh(( + y))), ((((x | 0) ? ((( - (-0x100000001 >>> 0)) >>> 0) | 0) : (( ! x) | 0)) | 0) | 0)) | 0)))) >>> 0), Math.fround(( + Math.min(Math.asin((Math.imul(x, x) >>> 0)), ( + Math.min(Math.fround(Math.expm1(Math.fround(y))), 0x100000001)))))))))); }); ");
/*fuzzSeed-204012247*/count=56; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(mathy1(Math.pow((Math.atan2(y, Math.acosh((y | 0))) >>> 0), (Math.cbrt(( + Math.log1p(Math.fround(mathy1((y >>> 0), mathy0(y, x)))))) >>> 0)), Math.atan2(y, (((y | 0) / (x | 0)) | 0))), (Math.sinh((Math.log((x | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy2, [0x0ffffffff, 0/0, 0x080000001, -0x100000001, 42, -(2**53-2), 0, -1/0, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, -0x080000001, 0x07fffffff, 1, Number.MAX_VALUE, 2**53, -0x0ffffffff, -(2**53+2), Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, 2**53-2, -0x100000000, 0x100000001, 0.000000000000001, -0, 0x100000000, -0x07fffffff]); ");
/*fuzzSeed-204012247*/count=57; tryItOut("this.a1[1] = v0;");
/*fuzzSeed-204012247*/count=58; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"for (var p in m0) { try { m1.set(m0, o0.b1); } catch(e0) { } g2 + f0; }\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 3 != 2), noScriptRval: true, sourceIsLazy: true, catchTermination: (x % 18 == 12), elementAttributeName: s0 }));");
/*fuzzSeed-204012247*/count=59; tryItOut("/* no regression tests found */");
/*fuzzSeed-204012247*/count=60; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[(4277), new Number(1), (0/0), (4277), 1.7976931348623157e308, 1.7976931348623157e308, (0/0), new Number(1), (4277), 1.7976931348623157e308, 1.7976931348623157e308, (0/0), (0/0), new Number(1), 1.7976931348623157e308, 1.7976931348623157e308, new Number(1), (4277), (0/0), (0/0), 1.7976931348623157e308, (4277), new Number(1), (4277), (4277), (0/0), 1.7976931348623157e308, 1.7976931348623157e308, (4277), (4277), new Number(1), 1.7976931348623157e308, (0/0), (0/0), (0/0), new Number(1), (4277), (4277), (0/0), (4277), (4277), 1.7976931348623157e308, (4277), (4277), (4277), (4277), (0/0), (4277), 1.7976931348623157e308, 1.7976931348623157e308, new Number(1), (0/0), (0/0), 1.7976931348623157e308, new Number(1), 1.7976931348623157e308, new Number(1), new Number(1), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), new Number(1), new Number(1), new Number(1), 1.7976931348623157e308, (4277), (4277), 1.7976931348623157e308, (4277), 1.7976931348623157e308, (4277), new Number(1), new Number(1), 1.7976931348623157e308, (0/0), (4277), (0/0), 1.7976931348623157e308, (4277), (0/0), (0/0), new Number(1), (0/0), new Number(1), 1.7976931348623157e308, (0/0), 1.7976931348623157e308, new Number(1), new Number(1), 1.7976931348623157e308, 1.7976931348623157e308, (0/0), (4277), new Number(1), (4277), (0/0), (0/0), new Number(1), (4277), new Number(1), (4277), (4277), (4277), (4277), (4277), 1.7976931348623157e308, (4277), (4277), (0/0), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (0/0), (0/0), new Number(1), (4277), (4277), (0/0), (0/0), 1.7976931348623157e308, (4277), (4277), 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, (0/0), (0/0), new Number(1), 1.7976931348623157e308, (0/0), (0/0), 1.7976931348623157e308, (0/0), new Number(1), new Number(1), 1.7976931348623157e308, (0/0), (4277)]) { /*infloop*/L: for  each(y in /^/) {s0 += s2;s0 += 'x'; } }");
/*fuzzSeed-204012247*/count=61; tryItOut("/*infloop*/L:for(let w; 'fafafa'.replace(/a/g, eval); ((makeFinalizeObserver('nursery')))) {Object.defineProperty(this, \"s1\", { configurable: true, enumerable: false,  get: function() {  return new String; } }); }");
/*fuzzSeed-204012247*/count=62; tryItOut("\"use strict\"; h2.delete = f0;");
/*fuzzSeed-204012247*/count=63; tryItOut("\"use strict\"; p2 = t0[15];");
/*fuzzSeed-204012247*/count=64; tryItOut("/*RXUB*/var r = r2; var s = s2; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-204012247*/count=65; tryItOut("\"use strict\"; for([e, a] = /*MARR*/[\"\\u3B09\", -Number.MAX_VALUE, \"\\u3B09\", \"\\u3B09\", -Number.MAX_VALUE, \"\\u3B09\", -Number.MAX_VALUE, -Number.MAX_VALUE, \"\\u3B09\", -Number.MAX_VALUE, \"\\u3B09\", -Number.MAX_VALUE, \"\\u3B09\", \"\\u3B09\", -Number.MAX_VALUE, \"\\u3B09\", \"\\u3B09\", -Number.MAX_VALUE, -Number.MAX_VALUE, \"\\u3B09\"].filter\u000c(eval, \"\\uE3F1\") in x = Proxy.create(({/*TOODEEP*/})(this), true)) selectforgc(o1);");
/*fuzzSeed-204012247*/count=66; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.clz32(Math.fround(Math.max((((Math.log1p(Math.log2(y)) ^ (x >>> 0)) ? x : Math.cosh(y)) | 0), ( ~ (Math.log(x) | 0))))); }); testMathyFunction(mathy1, [-(2**53-2), -0, 0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, -0x080000001, -Number.MAX_VALUE, 42, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, -0x100000000, 2**53+2, 0x100000001, -1/0, -0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 0/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -0x080000000, 1/0, Number.MIN_VALUE, 1, -(2**53), 2**53-2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-204012247*/count=67; tryItOut("\"use asm\"; /*iii*/e1.delete(g0);/*hhh*/function outcup(y, ...y){var twvyff, c = x, dkryvf, c, w, orjpli; '' ;}");
/*fuzzSeed-204012247*/count=68; tryItOut("a0.splice(NaN, 2);");
/*fuzzSeed-204012247*/count=69; tryItOut("for (var v of f2) { r2 = new RegExp(\"\\\\1$\", \"gym\"); }");
/*fuzzSeed-204012247*/count=70; tryItOut("function shapeyConstructor(pyhrvn){this[\"__count__\"] = (p={}, (p.z = /*RXUE*/new RegExp(\"[\\u0016-P\\\\w\\\\\\ua277]{2,}\\\\2*+\", \"gym\").exec(\"\"))());Object.seal(this);Object.freeze(this);if (pyhrvn) this[\"__proto__\"] = pyhrvn = {};{ v1 = (s2 instanceof h1); } Object.defineProperty(this, new String(\"14\"), ({value: x, writable: false, configurable: (/*UUV2*/(x.toString = x.toString))}));return this; }/*tLoopC*/for (let b of /*MARR*/[ /x/ ,  /x/ , new Boolean(true), null, null, x, new Boolean(true), objectEmulatingUndefined(), new Boolean(true),  /x/ , x, null, x, null, x, x, new Boolean(true), new Boolean(true), x, objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(),  /x/ , x, objectEmulatingUndefined(), new Boolean(true), null, x, x,  /x/ , null, objectEmulatingUndefined(), new Boolean(true), x,  /x/ , objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , null, x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x,  /x/ , new Boolean(true), x, null, x,  /x/ , new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x,  /x/ , x,  /x/ , new Boolean(true), objectEmulatingUndefined(), new Boolean(true), x,  /x/ ,  /x/ , null, objectEmulatingUndefined(), x,  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , new Boolean(true), x, null, null, objectEmulatingUndefined(), null]) { try{let nlbucm = new shapeyConstructor(b); print('EETT'); if(false) Array.prototype.reverse.call(a1, o0.g1.g2);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-204012247*/count=71; tryItOut("\"use strict\"; a2.unshift();");
/*fuzzSeed-204012247*/count=72; tryItOut("\"use asm\"; testMathyFunction(mathy1, [0x100000000, 0x0ffffffff, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, 1, 42, -0x080000000, 2**53+2, 0x07fffffff, -0x07fffffff, -0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, Math.PI, 0x100000001, 2**53-2, -0x100000000, 1/0, Number.MAX_VALUE, -Number.MIN_VALUE, 0, -0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -0x100000001, 0/0, -(2**53-2), -1/0]); ");
/*fuzzSeed-204012247*/count=73; tryItOut("testMathyFunction(mathy2, /*MARR*/[0xB504F332, 0xB504F332, [(void 0)], ({x:3}), Number.MIN_VALUE, [(void 0)], 0xB504F332, 0xB504F332, Number.MIN_VALUE, ({x:3}), 0xB504F332, 0xB504F332, 0xB504F332, Number.MIN_VALUE, 0xB504F332, [(void 0)]]); ");
/*fuzzSeed-204012247*/count=74; tryItOut("/*infloop*/M: for  each(x in []) {(\"\\u5F20\"); }g0.m0.set(e1, o0);");
/*fuzzSeed-204012247*/count=75; tryItOut("\"use strict\"; ");
/*fuzzSeed-204012247*/count=76; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( - Math.atan2(( - Math.atan2(x, y)), (mathy0((mathy0(((((y ^ x) | 0) >>> (Math.fround(Math.atan2(Math.atan2(0x080000001, x), Math.min(Number.MIN_SAFE_INTEGER, Math.PI))) | 0)) | 0), (mathy0((Math.fround(Math.hypot(y, x)) | 0), (-Number.MIN_SAFE_INTEGER | 0)) | 0)) | 0), (x | 0)) | 0))); }); ");
/*fuzzSeed-204012247*/count=77; tryItOut("\"use strict\";  for (let w of (new Map(new (x)(\"\\uB0B4\")))) { /* Comment */[,,];a2.shift(); }");
/*fuzzSeed-204012247*/count=78; tryItOut("/* no regression tests found */");
/*fuzzSeed-204012247*/count=79; tryItOut("\"use strict\"; e0.add(v2);/*RXUB*/var r = new RegExp(\"(?:(?=.){2,})\\\\3*\", \"im\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-204012247*/count=80; tryItOut("\"use strict\"; var ljwqnt = new SharedArrayBuffer(2); var ljwqnt_0 = new Uint16Array(ljwqnt); ljwqnt_0[0] = -16; var ljwqnt_1 = new Uint8Array(ljwqnt); ljwqnt_1[0] = 13; print(ljwqnt_1[2]);for (var v of h0) { try { selectforgc(o0); } catch(e0) { } try { a1.pop(); } catch(e1) { } a0 = Array.prototype.concat.apply(a0, [a0, a1]); }o0 = new Object;");
/*fuzzSeed-204012247*/count=81; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.min(((((y * ((Math.expm1(( ! Math.acosh(x))) | 0) | 0)) >>> 0) && (((x | 0) ? (y | 0) : ((y | ( ~ x)) >>> 0)) | 0)) && (( + mathy4(( + Math.acosh((( ! (y | 0)) | 0))), Math.min(y, (Math.fround(x) - x)))) / y)), Math.fround(Math.imul(Math.pow(((( ! ( + ( + (Math.fround(mathy1(y, y)) >>> 0)))) | 0) >>> 0), (y > x)), mathy3(Math.pow(x, (Math.atan2(x, y) >>> 0)), ((x >>> (Math.max(x, Number.MAX_VALUE) >>> 0)) | 0))))); }); testMathyFunction(mathy5, [0.000000000000001, 0x100000001, Number.MIN_VALUE, 1/0, 2**53-2, 42, 0, Math.PI, -0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, -0x100000001, -0x07fffffff, -(2**53-2), -1/0, -0x100000000, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -(2**53), -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, 0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, 1, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, 2**53]); ");
/*fuzzSeed-204012247*/count=82; tryItOut("/*oLoop*/for (ubwghw = 0; ubwghw < 65; ++ubwghw) { a2 + m2; } ");
/*fuzzSeed-204012247*/count=83; tryItOut("a2 = a1.slice(NaN, NaN, p1);");
/*fuzzSeed-204012247*/count=84; tryItOut("\"use strict\";  for (let c of true) {/*iii*/continue M;/*hhh*/function xhiuah(e, c, c, window =  /x/g , window, a, d, c, c, a, a = this, y, w = true, this, x, b, e = [,], x, c, c, z, window, w, x, x, x, b, ...y){(e)\nvar c, mndjcr, pocsdi, c;( '' );}if((x % 4 != 0)) { } else  if (undefined.valueOf(\"number\").unwatch(\"constructor\")) {this.m0.delete(undefined); } }");
/*fuzzSeed-204012247*/count=85; tryItOut("v0 = evaluate(\"function f2(a1)  { \\\"use strict\\\"; return this[\\\"sinh\\\"] =  /* Comment */new RegExp(\\\"(?:(?:[^]).+?\\\\u000e*)|\\\\\\\\w|(?!\\\\\\\\D)(\\\\\\\\s\\\\\\\\B)**\\\", \\\"gm\\\") } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: false }));\ns1.__proto__ = t0;\n");
/*fuzzSeed-204012247*/count=86; tryItOut("g1.f1(t1);");
/*fuzzSeed-204012247*/count=87; tryItOut("M:while((new (\"\\uCEF7\")() ? \"\\u4E0D\".__defineGetter__(\"x\", Function) : ([ '' ])) && 0)try { return w--; } catch(eval) { return; } ");
/*fuzzSeed-204012247*/count=88; tryItOut("/*vLoop*/for (usgwbj = 0; usgwbj < 132; ++usgwbj) { var z = usgwbj; a2.push( \"\" , g2, v1); } ");
/*fuzzSeed-204012247*/count=89; tryItOut("\"use strict\"; return ({b: \"\\uDB4F\"});");
/*fuzzSeed-204012247*/count=90; tryItOut("a0 = r0.exec(s1);");
/*fuzzSeed-204012247*/count=91; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((-0xe8d61*(i1)))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1, Number.MAX_VALUE, -0x100000000, Math.PI, 0x07fffffff, 0x0ffffffff, 0, -Number.MIN_VALUE, 0.000000000000001, -(2**53+2), 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, -0x07fffffff, 42, -0x0ffffffff, -(2**53-2), 1/0, -(2**53), 0x080000000, 2**53, -0x100000001, -1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 2**53-2, -0x080000000, 0x100000001, -Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-204012247*/count=92; tryItOut("{ void 0; void gc(); } print(x);");
/*fuzzSeed-204012247*/count=93; tryItOut("\"use strict\"; m0.delete(f1);");
/*fuzzSeed-204012247*/count=94; tryItOut("/* no regression tests found */");
/*fuzzSeed-204012247*/count=95; tryItOut("e2.add(t2);");
/*fuzzSeed-204012247*/count=96; tryItOut("t0 + i2;");
/*fuzzSeed-204012247*/count=97; tryItOut("\"use strict\"; o2.s2 += 'x';");
/*fuzzSeed-204012247*/count=98; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ Math.sinh((Math.asinh(Math.max(-0x07fffffff, x)) | 0))); }); testMathyFunction(mathy2, [(function(){return 0;}), (new Number(-0)), [], false, -0, (new String('')), 0, /0/, objectEmulatingUndefined(), 0.1, ({toString:function(){return '0';}}), (new Boolean(false)), ({valueOf:function(){return 0;}}), (new Boolean(true)), 1, ({valueOf:function(){return '0';}}), '\\0', (new Number(0)), true, undefined, '/0/', null, [0], NaN, '', '0']); ");
/*fuzzSeed-204012247*/count=99; tryItOut("const z;/*oLoop*/for (let lqrowo = 0; (window) && lqrowo < 5; ++lqrowo, window) { g2.a1.reverse(); } ");
/*fuzzSeed-204012247*/count=100; tryItOut("\"use strict\"; g0.g2.o2.v1 = let (ilhwds, x, NaN, ksjutd, xwmdfi, utezkb, qknuot, vqytgu) x;");
/*fuzzSeed-204012247*/count=101; tryItOut("v1 = g1.runOffThreadScript();");
/*fuzzSeed-204012247*/count=102; tryItOut("\"use strict\"; window +=  \"\" ;");
/*fuzzSeed-204012247*/count=103; tryItOut("testMathyFunction(mathy1, [1, -0x07fffffff, 0x080000001, 0/0, 0x100000000, -0x080000001, -0, 0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), -1/0, 0, -Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, -(2**53), Number.MAX_VALUE, 1.7976931348623157e308, 2**53, Math.PI, 1/0, -0x100000001, 2**53+2, 0x080000000, 0x100000001, -0x080000000, -(2**53+2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=104; tryItOut("this.v2 = g2.runOffThreadScript();");
/*fuzzSeed-204012247*/count=105; tryItOut("\"use strict\"; g1 + '';function x(x) { \"use strict\"; let (kvhepp, arguments, x, x) { {x: [{eval: {x: []}, w}, , ], ({a1:1}), x: {w, x: {x: {x}}}, \u3056: {x, x}} = eval(\"/*RXUB*/var r = /(?!\\\\d((?:(?!\\\\x78))){8388608,}+?)?/; var s = \\\"\\\"; print(uneval(r.exec(s))); \"), e, x = (void options('strict')), x = (uneval(-13));/*RXUB*/var r = r0; var s = s0; print(s.match(r)); print(r.lastIndex);  } } this.v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (4277), sourceIsLazy: (x % 3 == 2), catchTermination: (x % 30 != 28) }));");
/*fuzzSeed-204012247*/count=106; tryItOut("t0 = new Float32Array(b1, 13, 18);");
/*fuzzSeed-204012247*/count=107; tryItOut("(/*UUV1*/(d.//h\ncos = Uint8Array));");
/*fuzzSeed-204012247*/count=108; tryItOut("");
/*fuzzSeed-204012247*/count=109; tryItOut("mathy5 = (function(x, y) { return ( + Math.min((( + Math.fround(Math.tanh(Math.atanh(Math.fround(Math.abs(Math.fround(Number.MAX_SAFE_INTEGER))))))) >>> 0), (Math.exp(y) ? x : ((((Math.max((x >>> 0), (( - (x | 0)) | 0)) >>> 0) ? (mathy2(x, 0x080000000) >>> 0) : (Math.atan2(y, y) >>> 0)) >>> 0) >>> 0)))); }); ");
/*fuzzSeed-204012247*/count=110; tryItOut("i0.next();");
/*fuzzSeed-204012247*/count=111; tryItOut("((4277));var r0 = 8 % x; x = x / x; var r1 = 6 | x; x = 8 * 0; var r2 = x & r1; var r3 = r1 ^ r0; var r4 = r1 * r0; var r5 = r1 + r3; var r6 = r3 % 2; var r7 = 5 | 6; var r8 = r3 | 2; var r9 = r7 + x; var r10 = 7 ^ r6; var r11 = r6 ^ r1; r10 = 3 | 3; var r12 = 2 / r4; var r13 = 5 & 0; var r14 = r10 + r5; var r15 = r1 + r7; r15 = 5 & r0; var r16 = r5 % x; x = r11 / r13; var r17 = r1 + r13; var r18 = r12 + r8; var r19 = r3 * 8; var r20 = r19 / r14; var r21 = r12 ^ r17; var r22 = r2 | r17; var r23 = r0 * r18; var r24 = 5 % r10; var r25 = r8 * r16; var r26 = r12 / r2; r22 = r4 - 8; var r27 = 9 ^ r13; r18 = r5 - r20; print(r19); r6 = r16 ^ 4; r11 = r14 * r25; var r28 = 2 + r0; r9 = 3 ^ r13; r26 = 6 - r13; var r29 = r13 / r17; r27 = 8 / 5; var r30 = r8 * 8; print(x); var r31 = r8 * 4; var r32 = 8 - 7; var r33 = r32 % r14; var r34 = 3 / r19; var r35 = 4 & r34; var r36 = 5 * 8; var r37 = r34 + r4; var r38 = r26 % r32; var r39 = r36 ^ r1; var r40 = 4 | 4; var r41 = r32 * r28; var r42 = r19 - r28; var r43 = 0 & 5; var r44 = r38 % 7; var r45 = r22 % r14; var r46 = r20 * r33; var r47 = r16 & r15; print(r19); var r48 = 1 / r42; var r49 = r23 % r6; r10 = 4 & r48; var r50 = 4 % r5; var r51 = r34 | r28; var r52 = r30 & 0; var r53 = 9 + 9; r46 = r16 + 4; var r54 = 6 & r23; var r55 = 9 - r12; var r56 = r46 + r53; var r57 = r38 & r35; var r58 = 5 - r57; var r59 = r39 + r9; var r60 = r55 | 9; var r61 = r48 | 3; var r62 = r7 + 1; r40 = r24 ^ r34; var r63 = 3 / 3; r63 = r19 | r5; print(r26); r38 = r63 | 7; var r64 = r11 | 6; var r65 = r7 - r5; var r66 = r31 * r25; var r67 = r29 | r41; var r68 = r46 / r2; var r69 = 0 ^ r25; var r70 = 9 / 0; var r71 = r53 + r33; var r72 = r11 ^ 9; var r73 = r38 & r27; var r74 = x & 4; var r75 = 0 % r8; var r76 = r22 - r33; var r77 = 3 ^ 5; print(r74); var r78 = 0 & 7; ");
/*fuzzSeed-204012247*/count=112; tryItOut("((true < undefined));");
/*fuzzSeed-204012247*/count=113; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[ /x/ , x, x,  /x/ ]) { print(x); }");
/*fuzzSeed-204012247*/count=114; tryItOut("\"use strict\"; const a1 = new Array;");
/*fuzzSeed-204012247*/count=115; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.hypot((Math.fround(( ~ Math.fround(mathy1(y, y)))) & mathy2((Math.cosh(Math.fround(y)) | 0), (Math.log10((y | 0)) | 0))), Math.fround(((Math.fround(Math.min(( + y), ( + Math.log(Math.fround(y))))) & Math.fround(((x / x) << (Math.cosh(x) - y)))) >>> 0)))) | 0) ? (Math.tanh((( + (( + 2**53+2) , ( + ( + mathy2(( + -(2**53-2)), ( + Math.fround(Math.max(( + Math.expm1(x)), Math.fround(( + Math.min(x, Number.MAX_VALUE))))))))))) > x)) | 0) : (( ! (Math.tanh((Math.fround(y) | 0)) | 0)) >>> 0)) | 0); }); testMathyFunction(mathy5, [false, ({toString:function(){return '0';}}), (new Boolean(false)), 0, ({valueOf:function(){return '0';}}), 0.1, (function(){return 0;}), undefined, NaN, [0], (new Boolean(true)), objectEmulatingUndefined(), '\\0', 1, true, '', '/0/', /0/, null, (new String('')), [], ({valueOf:function(){return 0;}}), '0', (new Number(-0)), -0, (new Number(0))]); ");
/*fuzzSeed-204012247*/count=116; tryItOut("testMathyFunction(mathy4, [1/0, Number.MAX_VALUE, Math.PI, -0x080000001, 42, -(2**53-2), -(2**53), -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000000, 0, -0x100000000, 0x07fffffff, 0x0ffffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, 1, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, 0x080000001, 0x100000000, 2**53-2, -0x080000000, 1.7976931348623157e308, -0, 0/0, 0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=117; tryItOut("\"use strict\"; a0.sort((function() { for (var j=0;j<133;++j) { f0(j%5==1); } }), h1);\n/*MXX2*/g0.String.prototype.indexOf = a0;\n");
/*fuzzSeed-204012247*/count=118; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var cos = stdlib.Math.cos;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (((Float64ArrayView[4096])) % ((+((Int32ArrayView[1])))));\n    return (((0x1040a402)))|0;\n    d0 = (d0);\n/*tLoop*/for (let c of /*MARR*/[new Number(1), (void 0), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (void 0), new Number(1), (void 0), (void 0), new Number(1), (void 0), new Number(1), new Number(1), (void 0), (void 0), (void 0), (void 0), (void 0), new Number(1), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Number(1), (void 0), new Number(1), (void 0), (void 0), new Number(1), (void 0), (void 0), new Number(1), new Number(1), new Number(1), new Number(1), (void 0), (void 0), (void 0), new Number(1), (void 0), new Number(1), new Number(1), (void 0), (void 0)]) { return \"\u03a0\"; }    d0 = (d1);\n    (Int16ArrayView[4096]) = ((!((~((0x406c6be)+(0xdb1f7517)))))+(-0x8000000));\n    d0 = (+cos(((Float64ArrayView[2]))));\n    return (((0x3ba25e6)+(0xb2a093)))|0;\n  }\n  return f; })(this, {ff: Promise.race}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[null, .2, .2, .2, .2, null]); ");
/*fuzzSeed-204012247*/count=119; tryItOut("let (y) { print(uneval(o1.e2)); }");
/*fuzzSeed-204012247*/count=120; tryItOut("t2[\"\\u48F3\" - \"\\u39F5\".yoyo(this)];");
/*fuzzSeed-204012247*/count=121; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( ! ((Math.round((Math.fround(Math.pow(Math.fround((y ? mathy0(x, y) : x)), (Math.min(Math.fround((Math.max(1, Math.fround(y)) | 0)), (y >>> 0)) >>> 0))) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, 0x100000000, -1/0, 1.7976931348623157e308, -0x100000001, -Number.MIN_SAFE_INTEGER, 1, -(2**53), 2**53, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 0x080000000, -0x080000001, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, 42, Math.PI, 0x0ffffffff, 1/0, -0x0ffffffff, 0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, 0/0, Number.MIN_VALUE, -0, 0, Number.MAX_VALUE]); ");
/*fuzzSeed-204012247*/count=122; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ (Math.fround(Math.imul(Math.fround((Math.cos((Math.fround((( + Math.fround(mathy2(0.000000000000001, (x >>> 0)))) ? Math.fround((mathy0(( + Math.log((x | 0))), ( + x)) | 0)) : Math.fround(y))) | 0)) | 0)), Math.fround(Math.log1p(Math.max(Math.cos((y | 0)), Math.hypot(y, ( + ( - y)))))))) >>> 0)); }); ");
/*fuzzSeed-204012247*/count=123; tryItOut("testMathyFunction(mathy1, [0x080000001, 1/0, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), -0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, -0x0ffffffff, -0x100000001, -1/0, -(2**53-2), -0x07fffffff, 0x100000001, 0x07fffffff, 1, -Number.MIN_VALUE, -0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -0, 42, 0/0, 0x100000000, Math.PI, -Number.MAX_VALUE, 2**53, 0, -(2**53), 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=124; tryItOut("\"use strict\"; for (var p in o2) { try { t0[3] = \"\\u7325\"; } catch(e0) { } try { Object.freeze(a1); } catch(e1) { } o0 = g1.objectEmulatingUndefined(); }");
/*fuzzSeed-204012247*/count=125; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0.000000000000001, -0x0ffffffff, 0x080000000, -Number.MIN_VALUE, 0/0, -(2**53+2), -0x07fffffff, -0, -Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 2**53+2, 1/0, -(2**53-2), Number.MAX_VALUE, Math.PI, 0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, 1, -0x080000000, -0x100000000, 0x080000001, 42, 2**53, -(2**53), -0x100000001, -0x080000001, 2**53-2]); ");
/*fuzzSeed-204012247*/count=126; tryItOut("\"use strict\"; switch((yield  /x/ )) { default: break;  }");
/*fuzzSeed-204012247*/count=127; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.atanh(( + Math.min((Math.atan2(((( - (( + Math.fround(Math.clz32((-0 && y)))) >>> 0)) >>> 0) | 0), y) | 0), (Math.tanh(((Number.MIN_SAFE_INTEGER ? -Number.MIN_VALUE : x) , Math.fround(( ! -0x0ffffffff)))) | 0))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0/0, -0x080000001, 0x100000001, 0, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, -0, 0x080000001, 0x080000000, 0x0ffffffff, -(2**53-2), 2**53, 1, 0.000000000000001, Number.MAX_VALUE, 42, -0x100000000, -0x100000001, 0x100000000, 2**53+2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), Math.PI, 1.7976931348623157e308, -0x07fffffff, 1/0, 2**53-2]); ");
/*fuzzSeed-204012247*/count=128; tryItOut("\"use strict\"; ;");
/*fuzzSeed-204012247*/count=129; tryItOut("testMathyFunction(mathy5, [-0x080000000, -Number.MAX_VALUE, 42, 1, 0x100000001, -0x07fffffff, -0x100000000, 0.000000000000001, 0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, 0, 0x080000000, Number.MAX_VALUE, 2**53+2, 0x07fffffff, -(2**53), 0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, -0, -(2**53+2), 2**53-2, -1/0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 1/0, 0/0, -(2**53-2), -0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=130; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0(Math.pow((Math.asin((Math.sqrt(x) >>> 0)) >>> 0), Math.max(Math.fround(Math.cosh(Math.fround(((x >>> 0) * (0x07fffffff >>> 0))))), Math.fround(Math.fround((( - y) | 0))))), (Math.acos(Math.max(mathy1(-Number.MIN_SAFE_INTEGER, mathy0(Math.PI, y)), Math.sqrt(Math.hypot(x, y)))) | 0)); }); testMathyFunction(mathy2, [-0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, 0x100000000, Number.MAX_SAFE_INTEGER, -1/0, 1, -0, 0x0ffffffff, 0x100000001, 1/0, 0x080000000, -0x080000001, 2**53, Math.PI, -0x07fffffff, 0x07fffffff, 0.000000000000001, 2**53+2, -0x0ffffffff, 0, Number.MIN_VALUE, 2**53-2, -(2**53-2), -Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), 0/0, 1.7976931348623157e308, -0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-204012247*/count=131; tryItOut("\"use strict\"; for (var p in h2) { try { this.g0 + o0.f0; } catch(e0) { } try { a0 = r1.exec(s1); } catch(e1) { } try { a0.sort((function(j) { if (j) { try { Array.prototype.shift.apply(a2, []); } catch(e0) { } try { g0.g2.offThreadCompileScript(\"this.__defineSetter__(\\\"d\\\", d).__defineGetter__(\\\"b\\\", (Function).apply)\", ({ global: o2.g2.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (function(y) { neuter(b0, \"change-data\"); }.prototype) >>= x < x, sourceIsLazy: true, catchTermination: true })); } catch(e1) { } try { m1.set(a0, i1); } catch(e2) { } for (var p in g2) { v1 = (a2 instanceof o0.g1.h0); } } else { try { v1 = Object.prototype.isPrototypeOf.call(h2, b2); } catch(e0) { } try { t2.toString = f1; } catch(e1) { } try { const v1 = a1.length; } catch(e2) { } o1.v1 = o1.t1.length; } })); } catch(e2) { } a2.pop(); }");
/*fuzzSeed-204012247*/count=132; tryItOut("x = linkedList(x, 2646);");
/*fuzzSeed-204012247*/count=133; tryItOut("\"use strict\"; throw x;");
/*fuzzSeed-204012247*/count=134; tryItOut("\"use strict\"; /*hhh*/function cpbsew(){for (var v of o0) { try { Object.prototype.unwatch.call(this.e2, \"delete\"); } catch(e0) { } try { m1 = new Map; } catch(e1) { } Array.prototype.forEach.apply(a1, [o1, t2]); }}/*iii*//*infloop*/L:for(var w in ((DataView.prototype.getInt32)(new RegExp(\"(?=(?=(?:^))){2,}((\\\\3))+|(?:[\\\\B\\\\cG-\\\\\\u501f\\\\0-\\\\u003C])+|(?!\\\\3)\", \"yi\"))))( /x/g );");
/*fuzzSeed-204012247*/count=135; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.pow((( + Math.log2(( + Math.hypot(( + x), ( + ((y ** ( + Math.max(Math.fround(x), -0x080000000))) >>> 0)))))) >>> 0), Math.fround(Math.fround(Math.hypot(Math.fround((((Math.fround(Math.hypot(Math.fround((x === y)), (y | 0))) | 0) + (Math.fround(Math.expm1(Math.fround((Math.acosh((y >>> 0)) >>> 0)))) | 0)) | 0)), (Math.pow(( + mathy0(Math.fround(Math.atan2(Math.fround(0x07fffffff), Math.fround(0))), (( + (( - x) >>> 0)) >>> 0))), ((Math.fround(y) & x) * 2**53+2)) >>> 0)))))); }); testMathyFunction(mathy2, [0x0ffffffff, 0.000000000000001, 1/0, 0, 1, Math.PI, -1/0, -0x080000000, -0, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -0x07fffffff, -(2**53), Number.MAX_VALUE, 0x100000000, -0x080000001, -0x100000001, 0x080000000, 0x080000001, 2**53+2, -0x0ffffffff, -0x100000000, 0x100000001, -(2**53+2), 0/0, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-204012247*/count=136; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\w.|(?:\\B\u00dc)(?=\\S){67108865,67108865}|\\x39\\2*?{1})/gy; var s = \"_\"; print(s.split(r)); ");
/*fuzzSeed-204012247*/count=137; tryItOut("/*infloop*/for(let x in (((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: (d =  /x/g , x) =>  { yield [,] } , fix: function() { return []; }, has: undefined, hasOwn: Promise.prototype.catch, get: undefined, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: /((?=[^])|(\\B|\\B)[^]|\\B|\\0{1,1})/, keys: function() { throw 3; }, }; }))((4277))))for (var p in m1) { try { Array.prototype.forEach.apply(a1, [(function() { try { a2.forEach((function() { f0 = x; return this.e2; }), this.b2, o2.t0); } catch(e0) { } v1 = a2.length; return f1; })]); } catch(e0) { } try { m2.set(this.t2, g1); } catch(e1) { } try { v1 = g1.eval(\"this\"); } catch(e2) { } g0 = Proxy.create(h0, v2); }");
/*fuzzSeed-204012247*/count=138; tryItOut("\"use strict\"; /* no regression tests found */\n;\n");
/*fuzzSeed-204012247*/count=139; tryItOut("mathy2 = (function(x, y) { return ( + (( + ( + Math.log(( + (( ! Math.fround((Math.hypot((y | 0), (-0x080000000 | 0)) | 0))) ? (Math.min(-0, Math.fround(0x080000000)) >>> 0) : ( + Math.fround(Math.atan2(( + Math.hypot((x !== -Number.MIN_VALUE), ( + Math.sin(y)))), mathy0((x >>> 0), y))))))))) * ( + mathy1((Math.pow((mathy1((Math.sqrt(( - x)) >>> 0), Math.fround(( + Math.max(( + y), (Math.atan2(x, x) >>> 0))))) >>> 0), (Math.hypot(( + (( + (( + Math.acosh(( + y))) >> y)) << x)), 0x100000001) >>> 0)) >>> 0), (( + Math.atan(( + (mathy1(Math.fround(((( + ( + ( ~ ( + Number.MIN_VALUE)))) || (x | 0)) >>> 0)), Number.MIN_VALUE) >>> 0)))) >>> 0))))); }); testMathyFunction(mathy2, [0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0, 1, 0x080000001, 0x080000000, -0x0ffffffff, -0x100000000, 0x100000001, -0x080000000, 2**53-2, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), 42, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, Math.PI, 2**53+2, 2**53, -0, -0x07fffffff, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, 1/0, 0/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-204012247*/count=140; tryItOut("var uhguop;v2 = undefined;");
/*fuzzSeed-204012247*/count=141; tryItOut("print(x);");
/*fuzzSeed-204012247*/count=142; tryItOut("g2.a1.pop();");
/*fuzzSeed-204012247*/count=143; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-204012247*/count=144; tryItOut("Object.defineProperty(g0.o2, \"g2.v1\", { configurable: true, enumerable: false,  get: function() {  return evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 == 1), noScriptRval: ((/*MARR*/[{}, new String(''), new String(''), {}, new String(''), {}, {}].map(String.prototype.sub))()), sourceIsLazy: false, catchTermination: (x % 3 != 1) })); } });");
/*fuzzSeed-204012247*/count=145; tryItOut("v1 = evalcx(\"x = v2;\", g1);");
/*fuzzSeed-204012247*/count=146; tryItOut("\"use strict\"; e2 = this.t2[12];");
/*fuzzSeed-204012247*/count=147; tryItOut("b2 + '';");
/*fuzzSeed-204012247*/count=148; tryItOut("\"use strict\"; L:with({a: x})h1.getPropertyDescriptor = (function() { try { v0 = a1.length; } catch(e0) { } g1.v1 = Object.prototype.isPrototypeOf.call(b0, o0.t0); return p0; });");
/*fuzzSeed-204012247*/count=149; tryItOut("/*tLoop*/for (let c of /*MARR*/[objectEmulatingUndefined()]) { yield; }");
/*fuzzSeed-204012247*/count=150; tryItOut("\"use strict\"; a1.forEach((function() { try { /*RXUB*/var r = g2.r1; var s = \"\\n\"; print(s.match(r));  } catch(e0) { } try { f0 + ''; } catch(e1) { } selectforgc(o2); return o0.s2; }), t0, o0, f0, f1);");
/*fuzzSeed-204012247*/count=151; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy1((Math.exp((0x100000001 | (-0x100000000 << ( + Math.hypot(y, x))))) >>> 0), Math.round(Math.cosh(mathy1(Math.fround(Math.round(x)), Math.fround(( + ( ! ( + x)))))))) >>> 0); }); ");
/*fuzzSeed-204012247*/count=152; tryItOut("v0.valueOf = (function() { try { g1.offThreadCompileScript(\"function f1(b0)  { yield ({e: x}) } \"); } catch(e0) { } o1.i2.send(s0); return b0; });");
/*fuzzSeed-204012247*/count=153; tryItOut("let d = [(yield (((let (e=eval) e)).bind)((/*MARR*/[new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String('q')].map(/*wrap1*/(function(){ continue M;return y})())), /(?![\u00e4-\u0019])|((?:\\S)^)(^){2,4}(?=[\\b-\u00fd])/g))];print((true)( /x/ , [,,z1]));\nlet g2.m2 = new WeakMap;\n");
/*fuzzSeed-204012247*/count=154; tryItOut("/*infloop*/L:for(let a;  /x/ ; null) {for (var p in i2) { try { s0 = ''; } catch(e0) { } try { Array.prototype.pop.apply(a2, [ /x/ , e0]); } catch(e1) { } try { v2 = (m1 instanceof this.g2.g0.s2); } catch(e2) { } o2.v2 = evalcx(\"print(x);\", this.g2); } }");
/*fuzzSeed-204012247*/count=155; tryItOut("/*vLoop*/for (var toviso = 0; toviso < 3; (intern(x)), ++toviso) { var b = toviso; (new RegExp(\"(?=\\\\B|(?:[])){2}\", \"yi\"));\nreturn;\n } ");
/*fuzzSeed-204012247*/count=156; tryItOut("/*ADP-1*/Object.defineProperty(o0.a2, 2, ({}));");
/*fuzzSeed-204012247*/count=157; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.atanh((Math.pow(Math.log10(Math.imul(Math.log1p(Math.fround(Math.atan2(-0x100000000, ( ! ( + -Number.MAX_SAFE_INTEGER))))), (Math.asin((x | 0)) | 0))), (((( ~ (x | 0)) | 0) / ( + Math.trunc(( + Math.clz32(-(2**53-2)))))) | 0)) >>> 0)) | 0); }); testMathyFunction(mathy0, [NaN, 0, (function(){return 0;}), 0.1, false, null, undefined, ({valueOf:function(){return 0;}}), true, (new Number(-0)), /0/, '0', '\\0', (new String('')), ({toString:function(){return '0';}}), [], '', -0, (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Boolean(true)), [0], (new Number(0)), '/0/', objectEmulatingUndefined(), 1]); ");
/*fuzzSeed-204012247*/count=158; tryItOut("\"use strict\"; /*vLoop*/for (fmwoqr = 0; fmwoqr < 16; ++fmwoqr) { z = fmwoqr; /*ADP-3*/Object.defineProperty(a1, 7, { configurable: false, enumerable: true, writable: true, value: g1.e2 }); } ");
/*fuzzSeed-204012247*/count=159; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o0.t1, e2);");
/*fuzzSeed-204012247*/count=160; tryItOut("/*oLoop*/for (var lfurhl = 0; lfurhl < 12; ++lfurhl) { print(x); } ");
/*fuzzSeed-204012247*/count=161; tryItOut("\"use strict\"; m2.delete(m2);");
/*fuzzSeed-204012247*/count=162; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.hypot((( + Math.sqrt(( + ( ! ( + ( + ( + Math.min(Math.sin(Math.imul(-0x100000000, y)), Math.min(1.7976931348623157e308, x))))))))) | 0), (( + Math.cosh((Math.sqrt(Math.sin(Math.hypot(Math.acosh((0x07fffffff | 0)), x))) | 0))) | 0)); }); testMathyFunction(mathy0, [({valueOf:function(){return '0';}}), undefined, null, true, -0, '0', (new String('')), (new Boolean(false)), (new Number(0)), false, [], ({toString:function(){return '0';}}), '', (function(){return 0;}), NaN, 0, /0/, (new Number(-0)), ({valueOf:function(){return 0;}}), [0], objectEmulatingUndefined(), 1, (new Boolean(true)), '/0/', 0.1, '\\0']); ");
/*fuzzSeed-204012247*/count=163; tryItOut("\"use strict\"; s2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    switch ((abs((0x143b7a27))|0)) {\n      case 0:\n        (Uint16ArrayView[4096]) = ((!(Math.log2(eval = Proxy.createFunction(({/*TOODEEP*/})(true), /*wrap1*/(function(){ (new RegExp(\"\\\\2|\\\\u0031|\\\\d(?:.).\\\\b\\\\B\\\\1\", \"gim\"));return /*wrap2*/(function(){ \"use asm\"; var kmnckk = /(?=[^\u9a99\\b\ud65d]$?(.*){0,65537})|\\D/gm; var fbnztj = Date.prototype.getTimezoneOffset; return fbnztj;})()})(), ArrayBuffer.prototype.slice))))+(i1));\n        break;\n      case -2:\n        d0 = (((((d0)) - (((+(-1.0/0.0)) + (-255.0))))) / ((((-2199023255553.0)) - ((d0)))));\n        break;\n    }\n    return +((-6.189700196426902e+26));\n  }\n  return f; });");
/*fuzzSeed-204012247*/count=164; tryItOut("testMathyFunction(mathy4, [-(2**53-2), 0, -0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, -Number.MAX_VALUE, -1/0, -0x0ffffffff, Math.PI, -0, -0x080000001, 2**53, 0x0ffffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 42, 0x100000001, 0/0, -(2**53), -0x080000000, 1/0, 1.7976931348623157e308, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0x080000000, -Number.MIN_VALUE, -0x100000000, 2**53+2, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=165; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((((d1)) * ((d1))));\n    d1 = (d1);\n    (Float64ArrayView[((0x2e085664)-(0x9a834b3e)) >> 3]) = ((536870913.0));\n    d1 = (-1.5474250491067253e+26);\n    i0 = (!(i0));\n    i0 = (i0);\n    d1 = (((+(0x597eeef8)) <= (d1)));\n    d1 = (+(((0xfa551b61)-(0x4378abb3)) ^ (((0xa71ad*(i0))>>>((((0xab8a11e7)) >> ((-0x8000000))) / (~((0xfbc91f7e))))) % ((-((-2048.0) != (2251799813685249.0)))>>>((0x9c0a8756))))));\n    (Int32ArrayView[0]) = (((((Int32ArrayView[0]))>>>(Math.max(-18, -8))))-(i0));\n    return +((((d1)) % ((d1))));\n    return +((-((-8193.0))));\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0x080000001, Math.PI, 0, -1/0, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, -0x0ffffffff, 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, 1, 0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, 2**53+2, -0x080000000, 0x080000001, -0x100000000, 2**53-2, 0.000000000000001, 1/0, 0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), 2**53, 0/0, -(2**53+2), -0]); ");
/*fuzzSeed-204012247*/count=166; tryItOut("m2.has(m2);");
/*fuzzSeed-204012247*/count=167; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    {\n      i1 = (i1);\n    }\n    i0 = (!(i1));\n    i0 = (0xfe288caf);\n    return (((i0)+((((/*FFI*/ff(((2147483647.0)), ((-536870913.0)))|0)+(0x5ee5d6c6)) ^ (((0xf66fa8eb)))))))|0;\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0, -(2**53-2), -0x100000001, -(2**53), 0x07fffffff, -0x080000000, 1/0, 2**53+2, 1.7976931348623157e308, 2**53-2, -0x0ffffffff, 2**53, -Number.MAX_SAFE_INTEGER, 1, 0/0, 0x0ffffffff, 0x080000001, -0, Number.MAX_VALUE, -0x07fffffff, 0x100000001, -(2**53+2), Math.PI, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, -1/0, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, 0x080000000]); ");
/*fuzzSeed-204012247*/count=168; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[-0xB504F332, -0xB504F332, -0xB504F332, function(id) { return id }, [1], (void 0), function(id) { return id }, -0xB504F332, /\\3?\\s/y, /\\3?\\s/y, -0xB504F332, (void 0), /\\3?\\s/y, -0xB504F332, [1], -0xB504F332, -0xB504F332, -0xB504F332, function(id) { return id }, -0xB504F332, function(id) { return id }, [1], [1], (void 0), function(id) { return id }, (void 0), -0xB504F332, -0xB504F332, (void 0), [1], (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), [1]]); ");
/*fuzzSeed-204012247*/count=169; tryItOut("do {(\"\\uD9B1\"); \"\" ; } while(((Math.max( '' ,  /x/g ))) && 0);");
/*fuzzSeed-204012247*/count=170; tryItOut("\"use strict\"; for(d in ((function (d)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((d0));\n  }\n  return f;)(++Date.prototype.setFullYear))){Array.prototype.reverse.apply(a1, []);selectforgc(o0); }");
/*fuzzSeed-204012247*/count=171; tryItOut("testMathyFunction(mathy3, [0x080000000, -0x080000000, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53, 0x0ffffffff, 42, -0, 1, -(2**53-2), -1/0, -0x100000000, -0x0ffffffff, Number.MIN_VALUE, 1/0, -0x07fffffff, 0, Math.PI, -0x100000001, 2**53-2, 0x100000000, 0x07fffffff, 0.000000000000001, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0x100000001]); ");
/*fuzzSeed-204012247*/count=172; tryItOut("var eljkaz = new ArrayBuffer(1); var eljkaz_0 = new Uint32Array(eljkaz); print(eljkaz_0[0]); print(eljkaz_0[1]);print(eljkaz_0[1]);{}b2 = t2.buffer;");
/*fuzzSeed-204012247*/count=173; tryItOut("mathy3 = (function(x, y) { return Math.fround(mathy0(( ! (x , -0x100000000)), Math.fround(Math.round(( ~ Math.expm1()))))); }); testMathyFunction(mathy3, [0/0, 0x080000000, 1, -0x07fffffff, 0x07fffffff, 0x100000001, 0, 0.000000000000001, Math.PI, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, -0x100000001, -0x0ffffffff, 2**53, -(2**53+2), -0, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 42, 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, -(2**53)]); ");
/*fuzzSeed-204012247*/count=174; tryItOut("t0[({valueOf: function() { h2.keys = (function mcc_() { var wiwtmn = 0; return function() { ++wiwtmn; f0(/*ICCD*/wiwtmn % 5 == 1);};})();return 15; }})] = g2;");
/*fuzzSeed-204012247*/count=175; tryItOut("m0.has();");
/*fuzzSeed-204012247*/count=176; tryItOut("/*tLoop*/for (let y of /*MARR*/[[], x, x, [], (-1/0), (-1/0), x, [], x, x, x, x, (-1/0), [], [], (-1/0), (-1/0), x, [], x, (-1/0), [], x, [], x, [], (-1/0), x, (-1/0), x, x, (-1/0), (-1/0), x, [], x, (-1/0), x, x, [], (-1/0), x, x, (-1/0), x, x, (-1/0), (-1/0), x, x, x, x, x, x, x, [], [], x, x, x, (-1/0), [], x, x, x, (-1/0), (-1/0), x, x, (-1/0), x, [], x, [], x, (-1/0), x, [], x, (-1/0), x, [], (-1/0), x, (-1/0), x, x, x, (-1/0), [], [], [], [], [], [], (-1/0), [], x, [], [], x, (-1/0), x, [], x, x, x, (-1/0), [], (-1/0), (-1/0), x, x, x, (-1/0), [], x, x, x, [], [], x, [], [], [], x, x, x, x, x, x, x, (-1/0), [], (-1/0), x, x, x, x, x, (-1/0), x]) { /*hhh*/function ghkfjb(e = y, y, NaN, y, x, e, x =  '' , w, x, /*hhh*/function qsjjkv(...eval){a1.unshift(this.o2.m2, g1);}qsjjkv(\"\\uEB67\");, y, y, c, x = /(?=((?=(?:(?=.)|^)+)))/gi, b, z, e, y, NaN, y =  \"\" , d, x, eval, y, NaN, \u3056, x, b =  '' , \u3056, \u3056, get, NaN, x, b, y, y, z, a, eval, c = y, x, setter, y, w, eval, x, NaN = 12, \u3056, c, a = 3, NaN, d, x, x, y, a, w, a =  \"\" , x, d, y = new RegExp(\"\\\\b?\", \"gyim\"), window, y, x, y =  '' , NaN, \u3056, y, d, z, x, y, b, w, x, c, x, y, a, y, w, y, d, y, x, e, a =  /x/g , y, w, NaN, y, x, NaN, y, x = [,], x, w = NaN){y;}/*iii*/print(-11); }");
/*fuzzSeed-204012247*/count=177; tryItOut("mathy2 = (function(x, y) { return (mathy0((( - Math.sinh(((Math.fround(y) ? ( + Math.tan(Number.MIN_SAFE_INTEGER)) : Math.fround(( + (mathy0(y, (y >>> 0)) >>> 0)))) | 0))) >>> 0), (Math.fround(( ~ Math.fround((mathy1(((x >>> y) >>> 0), (( + Math.tan(( + (( ~ x) | 0)))) >>> 0)) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-(2**53), -Number.MAX_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 0x07fffffff, -(2**53+2), Number.MIN_VALUE, -0x100000000, 2**53, -0x0ffffffff, -0, 42, 0.000000000000001, 0x100000000, Math.PI, 0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 0x0ffffffff, -0x080000000, 2**53+2, Number.MAX_VALUE, -1/0, 0/0, 1, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, 0x080000001, -0x100000001, 1/0]); ");
/*fuzzSeed-204012247*/count=178; tryItOut("a1.push();");
/*fuzzSeed-204012247*/count=179; tryItOut("/*ODP-2*/Object.defineProperty(this.m1, 18, { configurable: true, enumerable: false, get: (function() { for (var j=0;j<120;++j) { f0(j%4==1); } }), set: (function() { try { Object.prototype.unwatch.call(o2, \"__iterator__\"); } catch(e0) { } try { v1 = t0.length; } catch(e1) { } b2.valueOf = o0.f2; throw t1; }) });");
/*fuzzSeed-204012247*/count=180; tryItOut("s2 = new String;");
/*fuzzSeed-204012247*/count=181; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.acos(( + Math.acos(( + Math.fround(Math.pow(Math.fround(Math.max((Math.hypot(Math.sign((x % Number.MAX_VALUE)), x) >>> 0), Math.fround(( ! y)))), Math.fround(Math.atan(( - (Math.fround(x) ? ( ~ 0) : Math.fround(y))))))))))); }); testMathyFunction(mathy0, [-0x100000000, 2**53, 42, 0.000000000000001, 0x080000001, 0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 1/0, 0x07fffffff, -1/0, 0x100000000, -(2**53), 2**53+2, 1.7976931348623157e308, -0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, 0x100000001, 1, Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, 0x080000000, -0, -0x080000000, Math.PI, -(2**53+2)]); ");
/*fuzzSeed-204012247*/count=182; tryItOut("m1 + '';");
/*fuzzSeed-204012247*/count=183; tryItOut("/*vLoop*/for (omxsjc = 0, w, x = Math.ceil((NaN(window))); omxsjc < 2; ++omxsjc) { var d = omxsjc; /* no regression tests found */ } ");
/*fuzzSeed-204012247*/count=184; tryItOut("mathy1 = (function(x, y) { return (Math.fround((Math.hypot((( - Math.fround(( + Math.log10(x)))) >>> 0), (Math.sinh(( + (((( ~ x) >>> 0) != Math.fround((Math.fround(( ! x)) ^ x))) >>> 0))) >>> 0)) >>> 0)) + Math.fround(( + Math.hypot(Math.pow(y, Math.atan2(0, (( + Number.MIN_SAFE_INTEGER) | 0))), y)))); }); testMathyFunction(mathy1, [2**53+2, Math.PI, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -(2**53), 0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 42, 0x100000001, 1/0, -0x0ffffffff, -0, -(2**53-2), -Number.MAX_VALUE, 2**53, 1, 0, -0x100000000, 2**53-2, -0x07fffffff, -0x080000001, -1/0, -(2**53+2), 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=185; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + mathy2(Math.pow(-Number.MAX_VALUE, ( + Math.atan(x))), mathy0(Math.max(Math.fround(x), (Math.log2(y) | 0)), y))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, 0x080000000, 0x080000001, 0.000000000000001, 1/0, -(2**53-2), Number.MAX_VALUE, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, -0, 1, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, Number.MIN_VALUE, 42, Math.PI, 0x100000001, 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, -0x100000001, 0, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, 1.7976931348623157e308, 0/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=186; tryItOut("mathy5 = (function(x, y) { return ( + Math.acos(( ~ (( + Math.min((( + ( + ( + y))) | 0), (Math.hypot(( + Math.max(( + Math.pow((y | 0), ((y << y) | 0))), ( + x))), Math.cbrt((x % y))) | 0))) | 0)))); }); testMathyFunction(mathy5, [1, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), NaN, [], (new Number(-0)), objectEmulatingUndefined(), '0', (function(){return 0;}), (new Boolean(true)), 0, '', undefined, (new String('')), true, (new Number(0)), /0/, '/0/', null, (new Boolean(false)), '\\0', ({valueOf:function(){return '0';}}), -0, false, [0], 0.1]); ");
/*fuzzSeed-204012247*/count=187; tryItOut("print(x);");
/*fuzzSeed-204012247*/count=188; tryItOut("mathy0 = (function(x, y) { return Math.max(( ~ ( + (x ** (( + (( + 2**53) ** (x ** -Number.MAX_SAFE_INTEGER))) != ( + ( - ( + Math.atan2(Math.fround((y ** y)), 2**53+2)))))))), (Math.clz32((Math.exp((( ~ Math.sinh(y)) | 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [0, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, 0x080000001, 0x100000000, 0x0ffffffff, 2**53-2, 2**53+2, Number.MAX_VALUE, 1/0, 0x07fffffff, 1, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, -1/0, -0x100000000, 1.7976931348623157e308, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 0/0, 2**53, 42, -0x0ffffffff, -0x100000001, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-204012247*/count=189; tryItOut("v1 = Object.prototype.isPrototypeOf.call(m0, o2.o1.m2);");
/*fuzzSeed-204012247*/count=190; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.fround(Math.clz32(Math.fround(( + ( ~ ( + (Math.fround((Math.fround((( ~ (x | 0)) | 0)) ** ( + x))) << ( + ( + ( + Math.trunc(y)))))))))))); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-204012247*/count=191; tryItOut("\"use strict\"; with({}) y = constructor;");
/*fuzzSeed-204012247*/count=192; tryItOut("{e0.delete(a2); }");
/*fuzzSeed-204012247*/count=193; tryItOut("for (var v of s2) { try { this.a1.toSource = (function() { try { g1.t1.set(t2, 3); } catch(e0) { } try { e0.has(f2); } catch(e1) { } v0 = Object.prototype.isPrototypeOf.call(b2, this.b0); return h0; }); } catch(e0) { } v2 = this.a1.length; }\nprint(new RegExp(\"(?=.|\\ucc8e+?|\\\\B|\\\\w+?|[^]+?){3,}\", \"gim\"));\n");
/*fuzzSeed-204012247*/count=194; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; }");
/*fuzzSeed-204012247*/count=195; tryItOut("s0 + i1;");
/*fuzzSeed-204012247*/count=196; tryItOut("mathy5 = (function(x, y) { return Math.log(Math.pow(( + ( ! ( + (( + Math.log((( ~ y) >>> 0))) >>> 0)))), Math.fround(Math.fround(Math.atan2(( + (( + Math.max((Math.fround((((y >>> 0) < (y >>> 0)) >>> 0)) | 0), y)) ? (mathy1((y >>> 0), (2**53 | 0)) >>> 0) : -0x07fffffff)), (Math.atan2((y >>> 0), (Math.fround(Math.atanh(Math.fround(( - x)))) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MAX_VALUE, 2**53-2, 0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -0x0ffffffff, 42, 0.000000000000001, -(2**53), -Number.MIN_VALUE, 0, -0x100000001, -0x07fffffff, 0x100000001, -(2**53+2), -(2**53-2), 0x0ffffffff, 0x080000001, 1/0, 2**53+2, -0, 0/0, Math.PI, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 0x100000000, 0x080000000, 1, -1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=197; tryItOut("mathy5 = (function(x, y) { return Math.asin(( + (Math.fround(Math.fround(Math.clz32(Math.fround(mathy1(Math.fround(x), (x | 0)))))) % Math.fround(( + (Math.fround(-Number.MAX_SAFE_INTEGER) | 0)))))); }); testMathyFunction(mathy5, /*MARR*/[new Number(1), new Number(1), new Number(1), NaN, new Number(1), NaN, NaN, NaN, new Number(1), new Number(1), NaN, NaN, new Number(1), new Number(1), new Number(1), new Number(1), NaN, new Number(1), new Number(1), NaN, NaN, NaN, NaN, NaN, new Number(1), new Number(1), new Number(1), NaN, new Number(1), new Number(1), NaN, new Number(1), NaN, new Number(1), NaN, NaN, new Number(1), NaN, new Number(1), NaN, NaN, new Number(1), NaN, NaN, NaN, new Number(1), new Number(1), NaN, new Number(1), new Number(1), NaN, NaN, new Number(1), NaN, new Number(1), NaN, NaN, new Number(1), NaN, NaN, new Number(1), NaN, new Number(1), NaN, new Number(1), new Number(1), NaN, new Number(1), NaN, new Number(1), NaN, new Number(1), NaN, NaN, NaN, new Number(1), new Number(1), NaN, NaN, NaN, NaN, NaN, new Number(1), NaN, new Number(1), NaN, new Number(1), NaN, NaN, new Number(1), new Number(1), new Number(1), new Number(1), NaN, NaN, new Number(1), new Number(1), new Number(1), NaN, new Number(1), NaN, NaN, NaN, new Number(1), new Number(1), new Number(1), NaN, new Number(1), new Number(1), new Number(1), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), NaN, new Number(1), new Number(1), NaN, NaN, NaN, new Number(1), new Number(1), NaN, new Number(1), new Number(1), NaN, new Number(1), new Number(1), new Number(1), new Number(1), NaN, NaN, new Number(1), NaN]); ");
/*fuzzSeed-204012247*/count=198; tryItOut("\"use asm\"; ;");
/*fuzzSeed-204012247*/count=199; tryItOut("\"use strict\"; /*bLoop*/for (let aazhyw = 0; aazhyw < 96; ++aazhyw) { if (aazhyw % 8 == 3) { print(-15); } else { throw new RegExp(\"\\\\2+|\\\\W{2,}\", \"yim\"); }  } function \u3056(...x)(makeFinalizeObserver('tenured'))switch((void options('strict_mode'))) { case ((({ set \"-0\"(x, ...b) { return ({a2:z2}) }  })) *= delete x.x): i1.next();h1.has = f0;break; break; default: print(x);break; case 8: /*RXUB*/var r = /(^)/ym; var s = \"\"; print(s.match(r)); break; case 7: g2.v1 = g1.eval(\"x - a\");case ([x]): case x: { void 0; gcslice(480); } print(x);break; break; case (eval(\"testMathyFunction(mathy2, [0x080000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -(2**53-2), 2**53, -0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, -0, 42, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, 0x080000001, -0x0ffffffff, -0x07fffffff, 1, -0x100000001, 0.000000000000001, -0x080000001, 0, 1/0, 2**53-2, Math.PI, 0x100000000, 0/0, 0x100000001, -1/0]); \", x.yoyo(x))): break; break;  }");
/*fuzzSeed-204012247*/count=200; tryItOut("for(var [z, x] = z in x) print(/*MARR*/[new Boolean(true),  'A' , new Boolean(true)].filter(Object.getOwnPropertyDescriptor, [[]]));");
/*fuzzSeed-204012247*/count=201; tryItOut("mathy0 = (function(x, y) { return (((Math.hypot((( ! (x | 0)) | 0), (Math.atan((( + Math.imul(( + ( + ( + Math.PI))), y)) >> Math.atan((Math.asin(x) >>> 0)))) | 0)) | 0) / (( ! ( + ( + (( + ( + ( ! y))) + ( + ((0 | 0) >>> x)))))) < (( - (((Math.cos((( - Math.fround(y)) | 0)) | 0) << y) >>> 0)) | 0))) >>> 0); }); ");
/*fuzzSeed-204012247*/count=202; tryItOut("");
/*fuzzSeed-204012247*/count=203; tryItOut("\"use strict\"; var eval = /(?!.)([^])*?/gym << eval, w = (([[]]).bind()).apply(), e, x = new ((1 for (x in [])))(((p={}, (p.z = Math.pow(-0, 2251799813685247))()))), w = x, x = x, x = (new Uint8ClampedArray(this)), rpnpws, ipzdjw, y = this;v0 = Object.prototype.isPrototypeOf.call(a1, a2);");
/*fuzzSeed-204012247*/count=204; tryItOut("testMathyFunction(mathy2, [-Number.MIN_VALUE, 0, -(2**53-2), -(2**53+2), 2**53+2, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, -0x100000000, 2**53, 0x100000001, 0x100000000, 0/0, -0x080000001, 1.7976931348623157e308, 1, Number.MIN_VALUE, 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, 0.000000000000001, -0, 1/0, -1/0, -0x100000001, Number.MAX_VALUE, Math.PI, -(2**53), 0x07fffffff]); ");
/*fuzzSeed-204012247*/count=205; tryItOut("\"use strict\"; this.g1.i0 + h2;");
/*fuzzSeed-204012247*/count=206; tryItOut("if((--EvalError.prototype)) t0[3] = ((void options('strict_mode'))); else {/* no regression tests found */ }");
/*fuzzSeed-204012247*/count=207; tryItOut("\"use strict\"; testMathyFunction(mathy0, [(function(){return 0;}), ({toString:function(){return '0';}}), '\\0', [], ({valueOf:function(){return '0';}}), -0, (new Number(-0)), 1, true, (new Boolean(true)), (new Boolean(false)), 0, '', 0.1, '0', false, undefined, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), (new Number(0)), /0/, NaN, (new String('')), null, [0], '/0/']); ");
/*fuzzSeed-204012247*/count=208; tryItOut("switch((function (a, b, e, z, b = \"\\u3EF0\", x = 21, this, c, x, w, x, x, b, undefined, x,  , x, z = null, \u3056, z = /(?:(?:^){0,})|((?:\\r){0}|(?=.+))|\\s{1,}/m, NaN, x, b, x, z, c = x, b, y, y, x, w, c, d, z = \"\\u4BC1\", x, x = new RegExp(\"([\\\\v-\\u00e4]|(.)|\\\\s.|(?!$)+?)$*\", \"yi\"), window, eval, z, x = window, x = new RegExp(\"(?:(?!\\\\b)|.|[^]?+?)\\\\b([^]|[^\\\\S/-\\\\xE3\\\\xAf-\\uad93])\", \"i\"), \u3056, NaN, y, x = /[^>\\D\u4c18-\ud1a1\\n-\u00be]/gym, x, x, window = NaN, \u3056, x, this.x, x, NaN, x, \u3056, x, \u3056, NaN, set, x, ...y) { e2.has(v0); } ).call(({a1:1}), function(id) { return id }, this).watch( '' , decodeURIComponent)) { default: break; print(v0);case z: /*infloop*/for(z; (/*RXUE*//([])*((?:\\3))|\u6489\\w+?\\B{1}\\2*?/gyi.exec(\"\\u2fa5\\u2fa5\\u2fa5\\u2fa5\\u2fa5\\u2fa5\") ^= (yield \"\\uB01B\" >>=  '' )); ({a1:1})) {a2.__iterator__ = (function() { g0.a1.length = 10; return i2; }); }case 7: /*MXX2*/g0.Symbol.prototype.constructor = t2;break; o0.h0.has = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -7.555786372591432e+22;\n    (Uint16ArrayView[((((-0x8000000) == (-0x747f4ee)) ? (0xe126806d) : (i1))-(i1)+(i1)) >> 1]) = (-((0xfe6e2a66) ? (i2) : ((1) ? ((0x0) <= (((0xe368af78))>>>((0xf928f616)))) : ((((0x8995e274)) & ((0xfe96a457))) >= ((+(-1.0/0.0)))))));\n    {\n      i2 = (i1);\n    }\n    i1 = (i1);\n    d0 = (((+abs(((((d3)) * ((d3))))))) / ((-4097.0)));\n    return (((0xffffffff) % (0x7c7043fa)))|0;\n  }\n  return f; });/*ADP-3*/Object.defineProperty(a0, 6, { configurable: x, enumerable: x >>> x, writable: (x % 3 == 2), value: h2 });case (4277): case (4277): break; case 6: let \u3056 = x, NaN =  /x/ , x, npztkm, xeiqmr;print(/*UUV1*/(y.substr = (x = w, NaN) =>  { \"use strict\"; return a } ));case 0: case (4277): /*vLoop*/for (oylprb = 0; oylprb < 9; ++oylprb, 25) { let a = oylprb; i0 = new Iterator(this.f1, true); } case (p={}, (p.z =  /* Comment */(4277))()): print(/*RXUE*//$|(?:\\D.|\\D{4,6}*(?=([^]){1,}))/gim.exec(\"\"));break;  }");
/*fuzzSeed-204012247*/count=209; tryItOut("v1 = g2.eval(\"function f1(m0)  { /*MXX2*/g1.Date.prototype.setMilliseconds = f2; } \");");
/*fuzzSeed-204012247*/count=210; tryItOut("\"use strict\"; let (x =  /x/ , [, {z}] = ((makeFinalizeObserver('nursery'))), e = x, a, x = , c = (Object.defineProperty(eval, \"constructor\", ({writable: (x % 5 == 3)})))) { var e, e, window = a, gxrzqb, vktppf, NaN, x, x;({}); }");
/*fuzzSeed-204012247*/count=211; tryItOut("\"use strict\"; x;");
/*fuzzSeed-204012247*/count=212; tryItOut("\"use strict\"; m0.has(f1);");
/*fuzzSeed-204012247*/count=213; tryItOut("this.v2 + '';\nprint(uneval(this.v2));\n");
/*fuzzSeed-204012247*/count=214; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return (Math.fround((( ! ((Math.clz32((Math.fround(( ~ Math.fround(Math.fround((y / Math.acosh(y)))))) | 0)) | 0) | 0)) >>> 0)) | Math.max(( + (-Number.MIN_VALUE >> (Math.exp((x | 0)) | 0))), Math.sqrt(( ! x)))); }); testMathyFunction(mathy0, [[], (function(){return 0;}), null, (new String('')), ({valueOf:function(){return 0;}}), '0', '/0/', ({valueOf:function(){return '0';}}), (new Number(0)), 1, -0, false, (new Boolean(false)), ({toString:function(){return '0';}}), '\\0', 0.1, objectEmulatingUndefined(), true, NaN, (new Number(-0)), /0/, [0], undefined, '', 0, (new Boolean(true))]); ");
/*fuzzSeed-204012247*/count=215; tryItOut("let (x) { /*infloop*/for(let y = (p={}, (p.z = x)());  /x/g  ? d : window; (\n)) Object.preventExtensions(e1); }");
/*fuzzSeed-204012247*/count=216; tryItOut("/* no regression tests found */");
/*fuzzSeed-204012247*/count=217; tryItOut("throw x;x = \u3056;");
/*fuzzSeed-204012247*/count=218; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.cbrt(( + Math.min(Math.atanh(( + Math.fround(Math.tan((x | 0))))), (Math.min((Math.max((x ^ -0x080000001), 0x080000001) | 0), (x | 0)) | 0))))); }); testMathyFunction(mathy2, [2**53+2, Number.MIN_VALUE, 0/0, -0, 1.7976931348623157e308, 1/0, Number.MAX_VALUE, 0x080000001, 2**53, 0x100000000, 0, 42, 0x0ffffffff, -Number.MIN_VALUE, 0x07fffffff, -0x100000000, 0x080000000, 2**53-2, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, -0x080000001, 0x100000001, 1, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), -(2**53-2), -1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=219; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.max(Math.fround(Math.log1p(Math.fround((x & mathy0((((Math.tan(x) | 0) === ((y ? y : 1/0) | 0)) | 0), Math.sqrt(y)))))), Math.fround(( - ((( + Math.atan2((-0x0ffffffff , x), Math.fround(2**53))) <= (mathy1((x | 0), (y | 0)) | 0)) | 0))))); }); testMathyFunction(mathy2, [-0x080000001, 1, 0x080000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, 0.000000000000001, -0, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000001, 0x080000000, -0x0ffffffff, -0x07fffffff, 0, 1.7976931348623157e308, 1/0, -(2**53-2), -0x080000000, Math.PI, 0/0, -0x100000001, 2**53-2, 2**53, 0x07fffffff, 42, -1/0, -(2**53), 2**53+2, -(2**53+2)]); ");
/*fuzzSeed-204012247*/count=220; tryItOut("s2 += s0;");
/*fuzzSeed-204012247*/count=221; tryItOut("o2.v0 = a1[ /x/ ];");
/*fuzzSeed-204012247*/count=222; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[[1], [(void 0)], [(void 0)],  \"use strict\" ]) { v0 = evalcx(\"/* no regression tests found */\", g1); }");
/*fuzzSeed-204012247*/count=223; tryItOut("\"use asm\"; a1.valueOf = (function() { try { s1 = Array.prototype.join.call(a0, s1, g1); } catch(e0) { } try { g2.offThreadCompileScript(\"for (var p in a0) { try { a2 = a1.slice(8, NaN, e0); } catch(e0) { } /*MXX3*/g1.Math.SQRT1_2 = g0.Math.SQRT1_2; }\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 8 != 0), sourceIsLazy: (x % 72 != 62), catchTermination: (uneval(undefined ? x : z)), elementAttributeName: s0 })); } catch(e1) { } for (var p in v1) { try { o0.a2 = Array.prototype.concat.apply(a2, [a0, a2]); } catch(e0) { } m0.delete(p2); } return g0; });");
/*fuzzSeed-204012247*/count=224; tryItOut("x, e, x;throw \"\\u75BF\";");
/*fuzzSeed-204012247*/count=225; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var acos = stdlib.Math.acos;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\na2.sort();\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = (0x8780dbc4);\n    d1 = (d0);\n    (Float32ArrayView[((-0x8000000)) >> 2]) = ((Infinity));\n    return +((d1));\n    return +((-((+acos(((-4611686018427388000.0)))))));\n  }\n  return f; })(this, {ff: String.prototype.big}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0, 2**53, 0x07fffffff, 2**53+2, Number.MAX_VALUE, 1, -1/0, -0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, -Number.MAX_VALUE, -0x100000001, 0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 1/0, 0x0ffffffff, 2**53-2, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, 42, Math.PI, 0x100000001, -(2**53-2), -(2**53), -0, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001]); ");
/*fuzzSeed-204012247*/count=226; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.acos(( + Math.imul((Math.fround(x) % ( + x)), Math.fround(( + Math.imul(Math.pow(( + 0), x), (Math.atanh((y == (Math.ceil((y >>> 0)) >>> 0))) >>> 0)))))))); }); ");
/*fuzzSeed-204012247*/count=227; tryItOut("\"use strict\"; ( /x/g .throw(28));");
/*fuzzSeed-204012247*/count=228; tryItOut("\"use strict\"; {/*infloop*/for(let y = NaN >>>= eval\u0009; Math.fround(( + Math.fround((Math.atan2((((((( ! Math.fround(Math.atan(( ~ Math.hypot(Math.atan2(( + ( ! ( + x))), x), x))))) >>> 0) ? ((Math.min((( + (x >>> 0)) >>> 0), Math.sin(Math.fround(Math.sin(Math.fround((Math.sin((x >>> 0)) >>> 0)))))) | 0) || ((x >> x) & Number.MIN_SAFE_INTEGER)) : Math.sinh(Math.clz32((0/0 , Math.fround(-0x07fffffff))))) ? Math.exp(( + (( + ( ! ( + (( + Math.abs(( + x))) % ( + 2**53-2))))) === (( + Math.cbrt(( + Math.cbrt((Math.exp(x) | 0))))) >>> 0)))) : ( + ((Math.asinh(( + Math.log2(Math.fround(Math.max(Math.fround(((0x07fffffff ? ( + x) : ( + x)) >= Math.fround(x))), Math.fround(-(2**53))))))) >>> 0) && (((( + (( ! x) | 0)) || ((Math.log10(Math.asinh((0.000000000000001 + x))) >>> 0) >>> 0)) >>> 0) >>> 0)))) >>> 0) >>> 0), (Math.fround(( ! Math.fround(( - ( + (((Math.clz32(( + -0x080000001)) - Math.fround((Math.log1p(x) ** Math.fround(0x100000000)))) ? Math.fround(Math.max(Math.fround(Math.log10(Math.fround(x))), x)) : 0.000000000000001) << ( ! Math.fround(Math.ceil((Math.imul(( + Math.asin(( + -0x080000000))), x) >>> 0)))))))))) >>> 0)) >>> 0)))); Math.imul(z = new RegExp(\"\\\\b\", \"yim\"), x) ? (eval(\"/* no regression tests found */\")) : x|=x) m2.set(intern(-8), o1);/*vLoop*/for (let mnkbkt = 0; mnkbkt < 9; ++mnkbkt) { z = mnkbkt; z, b, qnyxov, hfdgkq, window, oqzdqk, nofdhg;print(x); }  }");
/*fuzzSeed-204012247*/count=229; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return (( + (Math.min(Math.max(((1/0 ** x) !== x), Math.hypot(-0x080000001, ( + ( - ( + (x || Math.fround(y))))))), mathy0(( + (((Math.atan(x) >>> 0) - (x >>> 0)) >>> 0)), ( + x))) || ( + mathy0(Math.sqrt(Number.MIN_VALUE), x)))) % (((Math.atan2(x, ( + Math.sinh((y >>> 0)))) | 0) , (Math.ceil(y) | 0)) >>> 0)); }); testMathyFunction(mathy1, [(new String('')), (new Boolean(true)), 0, 1, '0', [0], '/0/', null, '', ({toString:function(){return '0';}}), /0/, undefined, ({valueOf:function(){return 0;}}), false, 0.1, -0, '\\0', (new Number(0)), NaN, (new Number(-0)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Boolean(false)), (function(){return 0;}), true, []]); ");
/*fuzzSeed-204012247*/count=230; tryItOut("b0 = a1[1];");
/*fuzzSeed-204012247*/count=231; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + mathy0(Math.min(Math.imul((Math.pow(((Math.pow(y, Math.max((Number.MIN_SAFE_INTEGER | 0), (Math.max(x, y) | 0))) >>> 0) >>> 0), ( - y)) >>> 0), Math.log1p(((x + (y | 0)) | 0))), (( ! y) * ( + (( - (y >>> 0)) >>> 0)))), ( + ( - ( + mathy1(((( + Math.imul(-Number.MAX_VALUE, (((-0x100000001 >>> 0) && ( + 0x100000001)) | 0))) != y) >>> 0), Math.fround((( + Math.fround(( + x))) * y)))))))); }); testMathyFunction(mathy2, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, x, x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), x, x, x, x, x, objectEmulatingUndefined()]); ");
/*fuzzSeed-204012247*/count=232; tryItOut("m0.set(x, i0);");
/*fuzzSeed-204012247*/count=233; tryItOut("/*ODP-2*/Object.defineProperty(m2, -15, { configurable: (x % 42 == 12), enumerable: false, get: (function() { e1.delete(v1); return p2; }), set: (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ceil = stdlib.Math.ceil;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        d1 = (17179869185.0);\n      }\n    }\n    i0 = (1);\n    switch ((imul((i0), ((((0x1f11418d))>>>((0xfe9de153)))))|0)) {\n      default:\n        i0 = (i0);\n    }\n    i0 = (-0x8000000);\n    {\n      i0 = (0xffffffff);\n    }\n    i0 = (i0);\n    d1 = (+ceil(((+(((((-0x8000000)+((0x2d00d76a) > (0x99a4bb04))) | ((i0)*0xfffff)) / (imul(((((0xedc4d603)) ^ ((-0x8000000)))), (i0))|0))|0)))));\n    i0 = ((Float64ArrayView[(((0x2c0fd37e) > (((i0))>>>(-0xfffff*(0xede84453))))-(i0)-(0xebac2acb)) >> 3]));\n    {\n      i0 = (0x30685693);\n    }\n    i0 = (-0x8000000);\n    {\n      d1 = (d1);\n    }\n    d1 = (((-2.4178516392292583e+24)) / ((d1)));\n    i0 = (NaN = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: 23, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: String.fromCharCode, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: Object, has: (new Function(\"delete this.e2[\\\"valueOf\\\"];\")), hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { throw 3; }, iterate: Date.prototype.getUTCSeconds, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(true), x));\n    (Uint32ArrayView[2]) = ((1));\n    i0 = (i0);\n    d1 = (d1);\n    return (((i0)))|0;\n  }\n  return f; }) });");
/*fuzzSeed-204012247*/count=234; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.pow(( + Math.imul(( + (( + ((Math.acosh(x) | 0) % ((Math.hypot(((0x100000000 % Math.imul(( + x), y)) | 0), (x | 0)) | 0) | 0))) + Math.pow(( ~ ( + ( - Math.fround(y)))), ( ~ x)))), ( + Math.max(( + Math.fround(Math.acos(Math.fround(( + (y >>> x)))))), ( + ( + Math.round(( + 0x07fffffff)))))))), ( + (((x | 0) === ( + Math.log2(((x % y) >>> 0)))) | 0))); }); testMathyFunction(mathy0, [-1/0, -0, -Number.MIN_SAFE_INTEGER, 42, -(2**53+2), 0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 1, 1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, -(2**53), Number.MIN_VALUE, 0x080000001, 2**53+2, -0x100000001, 2**53, 0, Number.MAX_VALUE, 0/0, Math.PI, -Number.MAX_VALUE, -0x080000000, -0x100000000, -0x080000001, -0x0ffffffff, 0x100000001, 0x100000000, -Number.MIN_VALUE, -(2**53-2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-204012247*/count=235; tryItOut("while(( \"\" ) && 0){v2 = Object.prototype.isPrototypeOf.call(o0, this.a2);a0.length = v2; }");
/*fuzzSeed-204012247*/count=236; tryItOut("\"use strict\"; /*RXUE*//\\W/g.exec(\"_\");");
/*fuzzSeed-204012247*/count=237; tryItOut("\"use asm\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (d0);\n    }\n    d0 = ((+(1.0/0.0)) + (17179869184.0));\n    return ((((((/*FFI*/ff()|0)*0xc80bc) >> ((i1)+(i1))) < ((-((+(-1.0/0.0)) != (((d0)) * ((+(1.0/0.0)))))) & (((0x14b00cd1))-((((0x753ce885)) | ((0x817b353a))) >= (~~(Infinity)))+(0xfb1be5f4))))))|0;\n  }\n  return f; })(this, {ff: (allocationMarker())}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0, -1/0, 0x100000000, 42, -(2**53), 0x0ffffffff, -Number.MAX_VALUE, -0x100000000, 2**53, 1, -0x080000001, -Number.MIN_VALUE, -0, 0x080000001, 0x100000001, 0.000000000000001, -(2**53+2), -0x07fffffff, 0/0, 1/0, 2**53+2, Math.PI, -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-204012247*/count=238; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.imul((( + (Math.pow(y, Math.log2((Math.min(x, (( - (y >>> 0)) >>> 0)) | 0))) | 0)) >>> 0), ( ~ Math.hypot(( + Math.sign(x)), x))); }); testMathyFunction(mathy4, [0.000000000000001, -1/0, -0x07fffffff, -0x080000000, 2**53, 1/0, -Number.MIN_SAFE_INTEGER, 0x080000000, -0, 2**53-2, 2**53+2, -0x080000001, -0x100000000, -(2**53), Number.MAX_VALUE, 0x100000001, -(2**53+2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 0, 1.7976931348623157e308, -0x100000001, -(2**53-2), Number.MIN_VALUE, 42, Math.PI, -0x0ffffffff, 0x080000001, 1, 0/0, 0x07fffffff]); ");
/*fuzzSeed-204012247*/count=239; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.hypot(( ! Math.max(Math.clz32(((Math.tan((( ! ( + x)) >>> 0)) | 0) - (0 * (y | 0)))), Math.atan((x <= Math.atan((( + y) , ( + y))))))), ( - (mathy0(Math.fround(( + Math.hypot(( + (( + x) < ( + Math.atan(x)))), y))), ((Math.log10(x) | 0) | 0)) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-204012247*/count=240; tryItOut("\"use strict\"; for (var v of o0) { this.a2[\"fixed\"] = t2; }");
/*fuzzSeed-204012247*/count=241; tryItOut("throw ((function too_much_recursion(mhkxoi) { ; if (mhkxoi > 0) { throw window;; too_much_recursion(mhkxoi - 1);  } else { v0 = g2.runOffThreadScript(); }  })(83482));\n(((void options('strict_mode'))));\n");
/*fuzzSeed-204012247*/count=242; tryItOut("/*RXUB*/var r = /\\W/m; var s = \"0\"; print(s.split(r)); ");
/*fuzzSeed-204012247*/count=243; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 2048.0;\n    var d3 = 73786976294838210000.0;\n    i0 = ((Float64ArrayView[0]));\n    switch ((0x7fffffff)) {\n      case -1:\n        switch ((((0xf974837f)-(-0x8000000)) << ((0xc429d629)*0xf6f66))) {\n        }\n      case -2:\n        (Uint32ArrayView[(-(((-(i0))|0) < (((-0x5b8e01f)*-0x719c3) ^ ((0x7fffffff) % (0x6ddcad85))))) >> 2]) = (0xe79e1*((((((0xf994445e)-( \"\" )) >> ((0xac9176a3))) / (imul((0xfc087380), ((0x6ab4c869)))|0))>>>((i1)+((((+(-1.0/0.0)))))))));\n        break;\n      case -3:\n        switch ((~((/*FFI*/ff(((~~(-32769.0))))|0)-((0x62c9c755) ? (0xe89b3eb3) : (0x71af8aad))))) {\n          case -3:\n            (Int32ArrayView[0]) = ((-0x8000000)+(0xfad04342)+(i1));\n            break;\n          case -1:\n            {\n              i1 = (0xd6df501);\n            }\n            break;\n          case -2:\n            d3 = (-2251799813685249.0);\n            break;\n          default:\n            (Uint16ArrayView[((Uint32ArrayView[2])) >> 1]) = ((((i1)+((0xf9efbbb9) ? (0xce6823cb) : (i1)))>>>(((((i1)-((-268435457.0) == (-9007199254740991.0))) >> (((0x3109a2bb) == (0x3099fca5)))))-(i0))) / (0x4e43ccab));\n        }\n    }\n    i1 = ((0xb1b819d8) == (0x6b42a92d));\n    switch ((0x4c1b001d)) {\n      case 1:\n        {\n          d2 = (-3.094850098213451e+26);\n        }\n        break;\n      case -3:\n        d3 = (Infinity);\n        break;\n      case 0:\n        d3 = (+/*FFI*/ff(((-0x8000000)), (((((((i0)-((0x67b0dee4) <= (0xc7b44bb6))) | ((-0x1086bd4)+(0xdf716d57)-(0xfced8c4c))))-(0xfe1cbc77)) ^ ((/*FFI*/ff((((0xffffffff))), ((d2)), ((~((i0)))), ((144115188075855870.0)), ((+(-1.0/0.0))), ((4294967297.0)), ((0.0078125)), ((-17592186044417.0)), ((-6.189700196426902e+26)), ((4294967297.0)), ((-1125899906842624.0)), ((-576460752303423500.0)), ((-2147483648.0)), ((-2199023255551.0)), ((-1.001953125)), ((-17592186044415.0)), ((35184372088832.0)), ((-18446744073709552000.0)), ((9.671406556917033e+24)), ((-3.777893186295716e+22)), ((8796093022209.0)), ((1023.0)), ((1.888946593147858e+22)), ((-4611686018427388000.0)))|0)))), ((d2))));\n      case -2:\n        i0 = (((((0x6471101e)))>>>(-(!(i1)))) < (0xce363828));\n        break;\n      case 0:\n        (Uint16ArrayView[((i0)) >> 1]) = (((((i0)) >> ((0xbf5c3055) / (((-0x8000000))>>>((0x8721b6e4))))) < ((((((8191.0)) - ((-1025.0))) <= ((257.0) + (-4294967297.0)))) >> ((Float64ArrayView[((-0x21fcd87)) >> 3]))))+((i0) ? (0xfb79cf26) : (0xffffffff))-(-0x8000000));\n        break;\n      case 0:\n        i0 = (/*FFI*/ff(((-7.737125245533627e+25)), ((((0x9151d1c3)-((((/*FFI*/ff(((~~(-3.0))), ((3.022314549036573e+23)), ((9223372036854776000.0)), ((288230376151711740.0)), ((34359738367.0)), ((137438953473.0)), ((33.0)), ((1.0009765625)), ((-549755813889.0)), ((9.671406556917033e+24)), ((-9223372036854776000.0)))|0))|0) < (((0x668239f) % (-0x6cc24be))|0))) ^ ((/*FFI*/ff(((d3)), ((-(this.prototype))), ((makeFinalizeObserver('tenured'))), ((+((-268435457.0)))), ((-1125899906842624.0)), ((129.0)), ((-33.0)), ((-256.0)), ((1073741823.0)), ((16385.0)), ((-536870913.0)), ((8388609.0)), ((-8796093022207.0)), ((3.777893186295716e+22)), ((549755813889.0)), ((64.0)), ((-1.5474250491067253e+26)), ((-549755813889.0)), ((-1.888946593147858e+22)), ((0.0009765625)), ((-147573952589676410000.0)), ((-7.555786372591432e+22)), ((7.555786372591432e+22)), ((1025.0)), ((-1048577.0)), ((-4097.0)), ((-35184372088833.0)), ((1152921504606847000.0)))|0)-(i1)))), ((window)), ((~~(+(0.0/0.0)))), ((((!(i0))-((0x3e6e33bd) >= (0x6233cd3d))) << ((!(0x4689aaa4))+(i1)+(0xfc1f2341)))), ((~(-((~~(-134217728.0)))))), ((d3)))|0);\n        break;\n      case -3:\n        (Uint32ArrayView[((i0)) >> 2]) = ((/*FFI*/ff(((NaN)), ((~((!(0x66ca5fbc))))))|0)-(0xfd8a09d9));\n        break;\n      case -3:\n        i0 = (!((((/*FFI*/ff(((((0xfeb0733b)+(0x62b5a427)-(0xfc37159e)) | ((((0xadf6466d)) | ((0xff4c1c5d)))))))|0)*0xd0e72) << ((NaN = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: Math.log, getPropertyDescriptor: function(){}, defineProperty: mathy5, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: undefined, has: arguments.callee.caller.caller, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(function ([y]) { }), Number.isSafeInteger, JSON.stringify))+(0x7b8baecf)))));\n        break;\n      case 0:\n        i1 = (i1);\n        break;\n      case -1:\n        (Float32ArrayView[1]) = (((!((((((6.189700196426902e+26)) / ((1.5474250491067253e+26)))) % ((d2))) >= (+((-536870912.0))))) ? (-65537.0) : (-576460752303423500.0)));\n        break;\n      case -3:\n        d2 = (-((d3)));\n        break;\n      case -2:\n        switch ((imul(((0x30fae496) > (0x70a4e62c)), (0x9dce5531))|0)) {\n          default:\n            d3 = (73786976294838210000.0);\n        }\n        break;\n      case 0:\n        (Float64ArrayView[((0x5f053b48)) >> 3]) = ((Float32ArrayView[((/*FFI*/ff((((((4277))-(0xa8718e50)-(0x166163fb)) >> (0x727c7*(/*FFI*/ff()|0)))))|0)+(((((Infinity) < (1048575.0))) | ((((0xffb01405))>>>((0xfa3bf1b9))) / (0x29d07c48))))) >> 2]));\n        break;\n      default:\n        i0 = (0xc489d011);\n    }\n    i0 = (((4194305.0)));\n    return +((((d2)) - ((((d3)) * ((d2))))));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, -0x100000001, 42, 0x100000000, 0x080000000, -0, -(2**53+2), -Number.MIN_VALUE, 2**53, -(2**53), 1.7976931348623157e308, 0x0ffffffff, -0x080000001, 0x07fffffff, 2**53+2, -1/0, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 1/0, Math.PI, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 0, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-204012247*/count=244; tryItOut("\"use strict\"; let (x) { f2(g1.m2); }");
/*fuzzSeed-204012247*/count=245; tryItOut("v0 = Array.prototype.every.call(this.a1, (function() { try { m1 = new Map(v1); } catch(e0) { } try { Array.prototype.forEach.apply(this.a2, [(function mcc_() { var jwyfrn = 0; return function() { ++jwyfrn; if (/*ICCD*/jwyfrn % 9 == 0) { dumpln('hit!'); try { b2 = t1.buffer; } catch(e0) { } e2.add(o2.g0); } else { dumpln('miss!'); try { a2.toSource = (function() { for (var j=0;j<45;++j) { f2(j%4==0); } }); } catch(e0) { } try { var v1 = evalcx(\"/* no regression tests found */\", g1); } catch(e1) { } t0.set(a0, x); } };})()]); } catch(e1) { } try { a2.shift(); } catch(e2) { } a0.toSource = (function() { (void schedulegc(g2)); return e0; }); return i1; }));");
/*fuzzSeed-204012247*/count=246; tryItOut("\"use strict\"; Array.prototype.unshift.call(o1.a0, e2);");
/*fuzzSeed-204012247*/count=247; tryItOut("\"use strict\"; \"use asm\"; Object.defineProperty(this, \"g2.v1\", { configurable: (x % 4 != 2), enumerable: true,  get: function() { g1.offThreadCompileScript(\"const h0 = ({getOwnPropertyDescriptor: function(name) { Object.seal(p0);; var desc = Object.getOwnPropertyDescriptor(m2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return m1; var desc = Object.getPropertyDescriptor(m2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { r1 = new RegExp(\\\"[^]\\\", \\\"gyi\\\");; Object.defineProperty(m2, name, desc); }, getOwnPropertyNames: function() { Object.defineProperty(this, \\\"v2\\\", { configurable: true, enumerable: window,  get: function() {  return g0.g0.t2.length; } });; return Object.getOwnPropertyNames(m2); }, delete: function(name) { v1 = Object.prototype.isPrototypeOf.call(this.b1, o1);; return delete m2[name]; }, fix: function() { t1[7] = [,];; if (Object.isFrozen(m2)) { return Object.getOwnProperties(m2); } }, has: function(name) { v1 = a0.reduce, reduceRight((function() { try { v0 = evalcx(\\\"function f0(this.b0) \\\\\\\"use asm\\\\\\\";   var ceil = stdlib.Math.ceil;\\\\n  var atan = stdlib.Math.atan;\\\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\\\n  function f(d0, d1)\\\\n  {\\\\n    d0 = +d0;\\\\n    d1 = +d1;\\\\n    var d2 = -1.5;\\\\n    d2 = (((((d0)) / ((d2)))) % ((+ceil(((+atan(((d1)))))))));\\\\n    return (((0xd6084a1e)+(-0x8000000)))|0;\\\\n    (Float64ArrayView[4096]) = ((d1));\\\\n    d1 = (-((Float32ArrayView[((0xff484043)) >> 2])));\\\\n    return (((((--b) >> (((/*FARR*/[.../*PTHR*/(function() { for (var i of (window for each (e in a))) { yield i; } })(), x, ([ '' ])].some(/*wrap1*/(function(){ print(window = window);return mathy4})(), void z-= \\\\\\\"\\\\\\\" \\\\u0009).eval(\\\\\\\"/* no regression tests found */\\\\\\\"))) / (~((0xfdbeb488))))) != (0x84a905f))))|0;\\\\n  }\\\\n  return f;\\\", g2); } catch(e0) { } try { g2.offThreadCompileScript(\\\"print(b);\\\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: undefined })); } catch(e1) { } v1 = g1.runOffThreadScript(); return h2; }));; return name in m2; }, hasOwn: function(name) { v0 = g2.eval(\\\"\\\\\\\"\\\\\\\\uB95F\\\\\\\";\\\");; return Object.prototype.hasOwnProperty.call(m2, name); }, get: function(receiver, name) { o1.b0 = new ArrayBuffer(1);; return m2[name]; }, set: function(receiver, name, val) { Object.prototype.unwatch.call(b0, 14);; m2[name] = val; return true; }, iterate: function() { for (var v of h2) { v1 = a0.length; }; return (function() { for (var name in m2) { yield name; } })(); }, enumerate: function() { Object.defineProperty(this, \\\"s1\\\", { configurable: false, enumerable: false,  get: function() {  return s2.charAt(16); } });; var result = []; for (var name in m2) { result.push(name); }; return result; }, keys: function() { this.v2 = Object.prototype.isPrototypeOf.call(o1.a2, p1);; return Object.keys(m2); } });\", ({ global: g0.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 != 1), noScriptRval:  /x/ , sourceIsLazy: true, catchTermination: true })); return evalcx(\"[[1]]\", g2); } });x = /$(?![\\S\\W])|^?{524289,524291}{0,}\\w|[^\\cE]|[^\\d\\u00B0-\u4b3b\\W\\D]{3,}|.*?([^])/g;const b = 13;/*RXUB*/var r = /((?:\\s|\\3{1025,1025}^|(?:\\B)))|\u00b8(?:[^])|[^]+?|\\D|\\d+{4,}\\3*/ym; var s = \"aa\\n\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-204012247*/count=248; tryItOut("\"use strict\"; \"use asm\"; o0.a2.splice(NaN, ({valueOf: function() { if(true) Math.pow(x, -9) / false , (w) = allocationMarker(); else  if ((((4277) /= x)(x, (x &= true.eval(\"\\\"use strict\\\"; mathy1 = (function(x, y) { return Math.sqrt(( + Math.imul(( + (( - (((( + ( + -0)) | 0) === ((( + mathy0(y, (x | 0))) ? x : y) >>> 0)) | 0)) | 0)), ((y !== Math.fround(( + ( ! Math.fround(( + (y * (y ^ x)))))))) >>> 0)))); }); testMathyFunction(mathy1, [undefined, '\\\\0', ({valueOf:function(){return 0;}}), /0/, null, '/0/', (function(){return 0;}), -0, false, (new Boolean(true)), 0.1, 1, NaN, '', (new Number(-0)), true, (new String('')), ({toString:function(){return '0';}}), (new Boolean(false)), '0', [], ({valueOf:function(){return '0';}}), [0], objectEmulatingUndefined(), (new Number(0)), 0]); \"))).throw({w: \u3056, x: {}, \u3056: x(Math.hypot(-25, 11))} = x))) /* no regression tests found */ else {e1.add(p1); }return 5; }}));");
/*fuzzSeed-204012247*/count=249; tryItOut("[];Array.prototype.unshift.apply(a1, [this.h1]);");
/*fuzzSeed-204012247*/count=250; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), NaN]) { (void schedulegc(g0)); }");
/*fuzzSeed-204012247*/count=251; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.fround(( ~ (( + ( + ( + ( + ( + x))))) | 0))), (((Math.PI > Math.imul(Math.fround(x), y)) ^ Math.fround(( + Math.min(( ! Math.max(x, x)), x)))) | 0)); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 0x080000001, -Number.MAX_VALUE, 1, 0x080000000, 1/0, -(2**53-2), 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 2**53-2, 0x100000001, 0, -0x0ffffffff, 0x07fffffff, 0.000000000000001, 0x0ffffffff, -0x100000001, -(2**53+2), -0x07fffffff, -Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, 2**53+2, -0x080000000, 42, -1/0, -0]); ");
/*fuzzSeed-204012247*/count=252; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        {\n          i0 = (x);\n        }\n      }\n    }\n    return ((-0xd666f*(i0)))|0;\n    d1 = (d1);\n    {\n      d1 = (+(-1.0/0.0));\n    }\n    i0 = (i0);\n    (Float32ArrayView[(((((new RegExp(\"\\\\s\", \"gm\")))) != (((0xfcee6e08))>>>((0xbd0758d2))))-((((0x45a54c59))>>>(-0xfcacb*(0xaf7024a0))))+(((0xcd55902a) > (0x126667fd)) ? (0x61ed8a9e) : (i0))) >> 2]) = ((((2.3611832414348226e+21)) - ((Float64ArrayView[(((+(1.0/0.0)) <= (Infinity))) >> 3]))));\n    i0 = (i0);\n    return (((i0)+(i0)-(0xf9c86b92)))|0;\n    {\n      {\n        (Uint8ArrayView[((i0)-(((0xb8ab60b3) % (0xae4050c3)))+(0x2e4660fc)) >> 0]) = ((i0));\n      }\n    }\n    i0 = (0xe3af90fe);\n    return (((0x4631298c)+((((i0)+(0x70e0cbf7)) | ((0x4c6dd3b6)-(0x8972dc31))))+(i0)))|0;\n  }\n  return f; })(this, {ff: arguments.callee}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000001, -0x080000000, 1.7976931348623157e308, -(2**53-2), -0x080000001, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, 0x100000000, -0x0ffffffff, 0x080000001, 0x0ffffffff, 1, 2**53+2, -0x100000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, 0, Number.MIN_VALUE, 0/0, 0.000000000000001, -1/0, 2**53-2, 1/0, Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, -(2**53+2), 42, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff]); ");
/*fuzzSeed-204012247*/count=253; tryItOut("e2.has(g0.b2);");
/*fuzzSeed-204012247*/count=254; tryItOut("/* no regression tests found */");
/*fuzzSeed-204012247*/count=255; tryItOut("/* no regression tests found */function b(...e) { \"use strict\"; yield (w(x)) = ( /x/g  > [[]]) } this.v0 = this.t0.length;");
/*fuzzSeed-204012247*/count=256; tryItOut("mathy5 = (function(x, y) { return Math.hypot(((( ~ (Number.MAX_SAFE_INTEGER >= y)) - y) === Math.fround((Math.fround((x !== (Math.fround(x) ? Math.fround(mathy0(x, (Math.min((x | 0), (x >>> 0)) | 0))) : Math.fround(Math.sqrt(0x07fffffff))))) ? Math.fround(Math.atan2((((y ? y : (( ! (Math.tanh((x >>> 0)) >>> 0)) >>> 0)) | 0) | 0), ((2**53 === -Number.MIN_SAFE_INTEGER) >>> 0))) : Math.fround(Math.pow((((( ~ x) | 0) >= (-1/0 | 0)) | 0), ( + Math.fround(mathy2(Math.fround(x), Math.fround(Math.asin((y | 0))))))))))), (mathy0(((mathy4(( + y), ( + Math.ceil((y >>> 0)))) >>> Math.fround(Math.hypot(Math.fround(mathy0(mathy1((Math.sign((2**53-2 | 0)) | 0), y), ( + x))), Math.fround((Math.tan((x | 0)) | 0))))) >>> 0), (((Math.hypot((x | 0), ((y == (Math.atan2(Math.clz32(-1/0), x) >>> 0)) | 0)) | 0) ? mathy2(Math.asin(-0x07fffffff), mathy3(Math.fround(0), (x >> x))) : (( + ( ! y)) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy5, [0/0, 1.7976931348623157e308, -0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), -1/0, 1, 0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, 42, -0x080000000, -0x080000001, -0x0ffffffff, 2**53, -(2**53+2), 0, 0x100000001, 0x100000000, 2**53-2, -0, Math.PI, 0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 0.000000000000001, 1/0, 0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=257; tryItOut("g2.v0 = evalcx(\"/* no regression tests found */\", g2.g1);");
/*fuzzSeed-204012247*/count=258; tryItOut("testMathyFunction(mathy0, [0x100000000, 0x0ffffffff, 2**53-2, 0.000000000000001, -0x100000000, -0x07fffffff, 0x100000001, -(2**53-2), Number.MAX_VALUE, 42, -0x080000000, -1/0, 1/0, Math.PI, -0, -(2**53), -(2**53+2), 0x07fffffff, -Number.MAX_VALUE, -0x100000001, Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 0x080000000, 0, 2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001]); ");
/*fuzzSeed-204012247*/count=259; tryItOut("/*tLoop*/for (let w of /*MARR*/[x, x, x, Infinity, x]) { /*RXUB*/var r = /(?=\\\u11e5{3,5}|\\b\\B+\\1{1,})\\2/m; var s = Math.pow(23, -3); print(s.search(r));  }");
/*fuzzSeed-204012247*/count=260; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 16385.0;\n    var i3 = 0;\n    var i4 = 0;\n    i3 = (i3);\n    d2 = ((+(0.0/0.0)) + (-67108864.0));\n    d0 = ((0x5d2be6c8) ? (d2) : (((1.0625) <= (((1125899906842625.0)) % ((36893488147419103000.0)))) ? (Infinity) : (d2)));\n    return ((this))|0;\n    return (((-0x267da53)))|0;\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-1/0, 0x080000001, 1/0, 0x080000000, -(2**53-2), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, 0, 1, 0/0, Math.PI, -(2**53+2), -0, -0x100000001, -0x080000000, -0x0ffffffff, 2**53-2, -0x100000000, 0x100000000, -Number.MAX_VALUE, -0x080000001, 2**53+2, 2**53, 1.7976931348623157e308, -0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 42, 0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=261; tryItOut("\"use asm\"; /*hhh*/function dllhjq(...x){/*RXUB*/var r = r2; var s = s1; print(s.replace(r, '')); }/*iii*/yield;");
/*fuzzSeed-204012247*/count=262; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.atan(Math.fround(( + ( + Math.tan(( + (Math.fround(Math.fround(Math.pow((y >>> 0), Math.fround(x)))) ? Math.fround(x) : Math.fround((x & (((x >>> 0) ? (Math.fround(( - Math.fround(y))) >>> 0) : (1.7976931348623157e308 >>> 0)) >>> 0))))))))))); }); testMathyFunction(mathy0, [1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x080000001, -(2**53), Number.MAX_VALUE, 0x0ffffffff, 1, 2**53, -1/0, -0x100000001, -Number.MAX_VALUE, 0x100000000, -(2**53-2), Number.MIN_VALUE, Math.PI, -0x100000000, -0x080000001, 42, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, -(2**53+2), 0, 0x100000001, 1.7976931348623157e308, -0x0ffffffff, -0, 0.000000000000001, 0x07fffffff]); ");
/*fuzzSeed-204012247*/count=263; tryItOut("{ void 0; selectforgc(this); }");
/*fuzzSeed-204012247*/count=264; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.sign(Math.fround((( + (((Math.tan((y | 0)) | 0) ^ (x >>> 0)) ** y)) ? (( ~ (y >>> 0)) >>> 0) : (Math.fround(Math.pow(Math.fround(y), Math.PI)) | 0))))) ^ ( + mathy1((Math.pow(y, y) | 0), Math.fround(mathy0(y, Math.fround(Math.min(Math.fround(Math.sqrt(Math.fround(Math.log(( + y))))), x))))))) >>> 0); }); ");
/*fuzzSeed-204012247*/count=265; tryItOut("\"use asm\"; h1.iterate = f1;");
/*fuzzSeed-204012247*/count=266; tryItOut("/*infloop*/for([] in ((Math.max(0x080000001, (( + (x >= Math.PI)) | 0)) * x))) g1.t1.set(t2, 5);");
/*fuzzSeed-204012247*/count=267; tryItOut("this.o2.g0.v0 = x;");
/*fuzzSeed-204012247*/count=268; tryItOut("/* no regression tests found */");
/*fuzzSeed-204012247*/count=269; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53-2, 1.7976931348623157e308, 0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, -Number.MIN_VALUE, 0.000000000000001, -(2**53), -0x080000001, -Number.MIN_SAFE_INTEGER, 1, 0, 2**53+2, -0x100000001, 0x0ffffffff, 1/0, -Number.MAX_VALUE, -0x0ffffffff, Math.PI, 0x080000000, 0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000, -0x07fffffff, 0x100000001, 2**53, 0/0, 42, Number.MIN_VALUE]); ");
/*fuzzSeed-204012247*/count=270; tryItOut("/* no regression tests found */");
/*fuzzSeed-204012247*/count=271; tryItOut("t0.set(a0, (makeFinalizeObserver('tenured')));");
/*fuzzSeed-204012247*/count=272; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(( ! ((Math.exp(Math.fround(Math.log1p(Math.acosh((y | 0))))) | 0) >>> 0)), Math.fround(Math.log1p(( + mathy3((y | 0), (Math.atan2((y >>> 0), Math.pow((y / (y | 0)), ( + x))) | 0))))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, 1/0, 0x080000000, 0x080000001, -0, 2**53, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, 0.000000000000001, 0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, Number.MAX_VALUE, -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, -(2**53), -0x100000001, 42, -1/0, Math.PI, -(2**53+2), -0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, 0/0, -0x080000000, Number.MIN_SAFE_INTEGER, 1, -(2**53-2)]); ");
/*fuzzSeed-204012247*/count=273; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 3.8685626227668134e+25;\n    d3 = (d3);\n    return +((35184372088833.0));\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [null, false, true, (function(){return 0;}), [0], '', ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), -0, (new Boolean(false)), '/0/', 1, 0, (new Boolean(true)), ({valueOf:function(){return 0;}}), /0/, (new String('')), NaN, (new Number(0)), ({toString:function(){return '0';}}), [], 0.1, '\\0', (new Number(-0)), '0', undefined]); ");
/*fuzzSeed-204012247*/count=274; tryItOut("mathy1 = (function(x, y) { return Math.fround(( + (Math.trunc(((mathy0(y, Math.fround(x)) && Math.cosh(( + x))) | 0)) ? ((y , (( ~ y) && ( + x))) < ( + ( ! Math.abs(( + y))))) : (Math.sqrt(Math.imul(( + y), (( ~ x) >>> 0))) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, 42, Number.MAX_VALUE, 0x07fffffff, -(2**53), 0x100000001, 0.000000000000001, 0, Math.PI, -0x07fffffff, 1.7976931348623157e308, 2**53, -Number.MIN_VALUE, 0x100000000, 0x0ffffffff, 0/0, -(2**53+2), -0x080000000, -0x0ffffffff, 0x080000000, 2**53+2, -0, 0x080000001, 2**53-2, -(2**53-2), -0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-204012247*/count=275; tryItOut("\"use strict\"; for (var p in h1) { try { i0 = t1[v2]; } catch(e0) { } try { g1.g1.offThreadCompileScript(\"h0 + i2;function eval(z, NaN)\\\"use asm\\\";   var atan2 = stdlib.Math.atan2;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    return +((+atan2(((1.25)), ((Float64ArrayView[1])))));\\n  }\\n  return f;a1.splice(NaN, 5, g1, i1, s1, s0, h2);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (Error = /*UUV1*/(w.bind = q => q)), noScriptRval: (x % 6 != 1), sourceIsLazy: false, catchTermination: /*RXUE*//(?=.)/y.exec(\"\\u63bb\") })); } catch(e1) { } Object.defineProperty(g0, \"o2\", { configurable: false, enumerable: (makeFinalizeObserver('nursery')),  get: function() {  return Object.create(g1.o1); } }); }");
/*fuzzSeed-204012247*/count=276; tryItOut("m2.get(f2);");
/*fuzzSeed-204012247*/count=277; tryItOut("M:if() { void 0; try { startgc(76217599); } catch(e) { } } print(x); else  if (Math.log(this.__defineGetter__(\"d\", objectEmulatingUndefined))) print(x);\nprint(\n/($)/gi !=  '' );\n else {for (var p in p0) { try { /*RXUB*/var r = r0; var s = s1; print(uneval(s.match(r)));  } catch(e0) { } try { a0 = a2.concat(a1, f0, h2, t1); } catch(e1) { } for (var v of o2) { for (var p in h2) { try { m1.set(o0, new RegExp(\"(?=(?:[]))+?\", \"y\")); } catch(e0) { } try { Object.preventExtensions(m1); } catch(e1) { } try { function f0(i0) \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    {\n;    }\n    return +((d0));\n  }\n  return f; } catch(e2) { } a1[v2]; } } } }");
/*fuzzSeed-204012247*/count=278; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(mathy1(Math.fround((y | Math.asin(( ! y)))), (((((Math.pow(( - y), ((((Math.imul((y | 0), y) >>> 0) !== (Math.asin((y * Number.MIN_VALUE)) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0) <= ((Math.tanh(((Math.atan2((-Number.MAX_SAFE_INTEGER >>> 0), x) ? y : y) | 0)) | 0) | 0)) | 0) >>> 0))) === Math.fround(( - mathy2(( + ( ! ( + (Math.ceil(-0x0ffffffff) , x)))), (x | 0)))))); }); testMathyFunction(mathy3, /*MARR*/[['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'], ['z'], ['z'], ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800), ['z'], ['z'], ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'], ['z'], ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800), ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'], ['z'], ['z'], ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'], ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'], ['z'], ['z'],  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800), ['z'], ['z'], ['z'], ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'], ['z'],  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'], ['z'],  \"\"  = timeout(1800), ['z'], ['z'], ['z'], ['z'], ['z'], ['z'],  \"\"  = timeout(1800), ['z'], ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800),  \"\"  = timeout(1800), ['z'], ['z'], ['z'],  \"\"  = timeout(1800), ['z'],  \"\"  = timeout(1800),  \"\"  = timeout(1800)]); ");
/*fuzzSeed-204012247*/count=279; tryItOut("with({}) { a = w; } ");
/*fuzzSeed-204012247*/count=280; tryItOut("mathy0 = (function(x, y) { return ( ~ ( + ( ~ ( + Math.log10(y))))); }); testMathyFunction(mathy0, /*MARR*/[]); ");
/*fuzzSeed-204012247*/count=281; tryItOut("g0.valueOf = (function(j) { if (j) { try { print(uneval(p2)); } catch(e0) { } try { v1 = new Number(t0); } catch(e1) { } t2[4] = (Math.imul(Object.defineProperty(x, 19, ({value:  , enumerable: false})), x)); } else { try { m0 = new Map; } catch(e0) { } s1 += s0; } });");
/*fuzzSeed-204012247*/count=282; tryItOut("mathy3 = (function(x, y) { return Math.imul(mathy2((( - ((( - ( + mathy2(x, 1))) === Math.fround(x)) >>> 0)) >>> 0), (mathy2(Math.hypot(x, ( ~ (Number.MAX_VALUE | 0))), ((x ? x : ( + Math.hypot(( + y), ( + x)))) & mathy0(x, y))) >>> 0)), Math.fround((( + Math.atan2(( + (Math.imul(( + 2**53), x) | 0)), ( + ( - Math.fround(Number.MIN_SAFE_INTEGER))))) != (( + Math.acos(x)) >>> 0)))); }); testMathyFunction(mathy3, ['', 0.1, [], '\\0', (function(){return 0;}), NaN, ({toString:function(){return '0';}}), '/0/', 1, 0, undefined, true, ({valueOf:function(){return 0;}}), (new String('')), null, [0], (new Boolean(true)), '0', (new Number(-0)), false, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), (new Boolean(false)), /0/, (new Number(0)), -0]); ");
/*fuzzSeed-204012247*/count=283; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.imul(Math.imul(Math.atanh((( - -(2**53)) | 0)), Math.imul((x >>> 0), Math.fround((Math.expm1(x) ? (Math.hypot(Math.fround(Math.tanh(Math.acos(-Number.MAX_VALUE))), Math.fround(Math.min(x, y))) | 0) : y)))), (Math.sin(( + Math.imul(Math.pow((x >> ( ~ x)), y), (((x !== (x >>> 0)) >>> 0) ? (((Math.sign(( + ( - x))) | 0) , x) | 0) : (y !== Math.atan2(1.7976931348623157e308, (x >>> 0))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [2**53-2, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 0x100000001, -1/0, Number.MAX_VALUE, 0x07fffffff, 0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 1, 42, 2**53+2, 1/0, -0x080000001, -0x100000000, -0x100000001, -0, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, -(2**53+2), 0x0ffffffff, 2**53, 0/0, Math.PI, 0x100000000, -(2**53-2)]); ");
/*fuzzSeed-204012247*/count=284; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((((((Math.fround(Math.log10(Math.round(Math.cosh(Math.pow((-0x100000001 && Number.MIN_VALUE), y))))) >>> 0) === ( ~ Math.cos(x))) >>> 0) | 0) ? (( + (Math.fround(( ! y)) , Math.fround(( ! ( + x))))) | 0) : ((Math.cosh((mathy3(Math.tanh(y), 0x080000000) | 0)) >> Math.fround(Math.sinh(Math.fround(Math.fround(Math.log1p(Math.fround(y))))))) | 0)) | 0); }); testMathyFunction(mathy5, [(new String('')), '\\0', /0/, 0.1, '', '/0/', undefined, (new Number(-0)), (new Boolean(true)), false, objectEmulatingUndefined(), 0, ({valueOf:function(){return 0;}}), null, NaN, (new Number(0)), -0, '0', true, (function(){return 0;}), ({valueOf:function(){return '0';}}), [], 1, (new Boolean(false)), [0], ({toString:function(){return '0';}})]); ");
/*fuzzSeed-204012247*/count=285; tryItOut("m2.has(b1);");
/*fuzzSeed-204012247*/count=286; tryItOut("\"use strict\"; with(/*MARR*/[new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String(''), new String(''), new String('q'), new String('q'), new String('q'), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String('q'), new String('q'), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String('q'), new String('q'), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String('q'), new String('q'), new String(''), new String('q'), new String(''), new String(''), new String(''), new String(''), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String('q'), new String(''), new String(''), new String(''), new String('q'), new String(''), new String(''), new String(''), new String(''), new String('q'), new String(''), new String('q'), new String('q'), new String(''), new String(''), new String(''), new String(''), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String(''), new String(''), new String(''), new String('q'), new String('q'), new String(''), new String(''), new String('q'), new String(''), new String('q'), new String('q'), new String(''), new String(''), new String(''), new String('q'), new String(''), new String(''), new String('q'), new String('q'), new String('q'), new String('q'), new String(''), new String(''), new String(''), new String(''), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String('q'), new String('q'), new String('q'), new String(''), new String(''), new String('q'), new String(''), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String('q'), new String(''), new String(''), new String(''), new String(''), new String(''), new String('q'), new String(''), new String(''), new String(''), new String(''), new String('q'), new String(''), new String('q'), new String('q'), new String('q'), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String('q'), new String(''), new String(''), new String('q')].some)/*RXUB*/var r = new RegExp(\".(?!\\\\2)*|\\\\W|(?=(?!$))|(?=(?:\\\\B))\\\\B{1}\\\\2+??|.{4,}\", \"gm\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-204012247*/count=287; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(Math.max(Math.fround(Math.min((( ~ (Math.exp(Math.fround(Math.sin(Math.fround((Math.fround(x) ^ Math.fround(x)))))) || (y | 0))) >>> 0), ((Math.hypot((y >> (Math.fround(mathy0(( + x), ( + Math.hypot(y, (( ! y) >>> 0))))) | 0)), ((x ? Math.hypot(Math.fround(Math.log1p(Math.fround(x))), Math.fround((x < Number.MAX_SAFE_INTEGER))) : Math.exp(x)) | 0)) | 0) >>> 0))), Math.fround(Math.atan2(Math.tanh(Math.atan2(((((Math.fround((x <= x)) >= (0.000000000000001 | 0)) >>> 0) > Math.fround((((y | 0) % ( + y)) | 0))) >>> 0), (Math.fround(mathy0((Math.atan2(( + -Number.MIN_VALUE), 1) >>> 0), (y || y))) && Math.exp(((Math.fround(y) ? Math.fround(x) : (x >>> 0)) | 0))))), (Math.fround(y) === Math.fround(((x | 0) ^ mathy0((( ~ (Math.sign(-0x100000000) | 0)) | 0), -0)))))))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, 1.7976931348623157e308, -(2**53), -0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 0x080000000, -Number.MAX_VALUE, 2**53+2, 2**53-2, 1/0, Number.MIN_VALUE, 0/0, 42, -Number.MIN_VALUE, Math.PI, 0x100000000, -0x080000000, 0x100000001, -0x07fffffff, -1/0, Number.MAX_VALUE, -0x100000001, -(2**53-2), -0x0ffffffff, 1, 2**53, -(2**53+2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=288; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return (( - (( + (mathy0((Math.log(mathy0(y, y)) >>> 0), (Math.log2(Math.atan2(y, x)) >>> 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[-Number.MIN_VALUE, ({x:3}), ({x:3}), -Number.MIN_VALUE, ({x:3}), ({x:3}), new Number(1), -Number.MIN_VALUE, ({x:3}), new Number(1), new Number(1), new Number(1), -Number.MIN_VALUE, new Number(1), -Number.MIN_VALUE, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), ({x:3}), ({x:3}), ({x:3}), ({x:3}), new Number(1), new Number(1), -Number.MIN_VALUE, new Number(1), -Number.MIN_VALUE, new Number(1), ({x:3}), -Number.MIN_VALUE, new Number(1), -Number.MIN_VALUE, ({x:3}), ({x:3}), ({x:3}), new Number(1), new Number(1), ({x:3}), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -Number.MIN_VALUE, new Number(1), ({x:3}), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), ({x:3}), new Number(1), -Number.MIN_VALUE, ({x:3}), -Number.MIN_VALUE, -Number.MIN_VALUE, new Number(1), ({x:3}), ({x:3}), new Number(1), -Number.MIN_VALUE, -Number.MIN_VALUE, ({x:3}), -Number.MIN_VALUE, ({x:3}), ({x:3}), new Number(1), -Number.MIN_VALUE, ({x:3}), -Number.MIN_VALUE, -Number.MIN_VALUE, new Number(1), ({x:3}), new Number(1), ({x:3}), new Number(1), -Number.MIN_VALUE, -Number.MIN_VALUE, new Number(1), -Number.MIN_VALUE, new Number(1), new Number(1), new Number(1), ({x:3}), -Number.MIN_VALUE, new Number(1), new Number(1), -Number.MIN_VALUE, new Number(1), -Number.MIN_VALUE, new Number(1), -Number.MIN_VALUE, new Number(1), ({x:3}), new Number(1), ({x:3}), ({x:3}), ({x:3}), -Number.MIN_VALUE, -Number.MIN_VALUE, ({x:3}), new Number(1), -Number.MIN_VALUE, ({x:3}), -Number.MIN_VALUE, -Number.MIN_VALUE, ({x:3}), new Number(1), new Number(1), new Number(1), -Number.MIN_VALUE, ({x:3}), ({x:3}), -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -Number.MIN_VALUE, -Number.MIN_VALUE, new Number(1), new Number(1), -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, new Number(1), new Number(1), new Number(1), ({x:3}), ({x:3}), new Number(1), ({x:3}), new Number(1), -Number.MIN_VALUE, ({x:3}), -Number.MIN_VALUE, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), new Number(1)]); ");
/*fuzzSeed-204012247*/count=289; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"function f0(s2)  { yield s2 } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (4277), noScriptRval: true, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-204012247*/count=290; tryItOut("/* no regression tests found */");
/*fuzzSeed-204012247*/count=291; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-204012247*/count=292; tryItOut("\"use strict\"; /*oLoop*/for (xdkeqx = 0; xdkeqx < 115; ++xdkeqx) { o0.h1.set = (function(j) { if (j) { try { for (var p in o0.v0) { try { this.v0 = (g0 instanceof o0); } catch(e0) { } v2 + ''; } } catch(e0) { } try { f2 = s0; } catch(e1) { } m2.has(b0); } else { try { selectforgc(o1.o0); } catch(e0) { } s2 += g2.s2; } }); } ");
/*fuzzSeed-204012247*/count=293; tryItOut("v2 = r2.global;");
/*fuzzSeed-204012247*/count=294; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-204012247*/count=295; tryItOut("testMathyFunction(mathy3, /*MARR*/[ \"use strict\" ,  \"use strict\" ,  /x/g ,  /x/g ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  /x/g ,  \"use strict\" ,  /x/g ,  \"use strict\" ,  /x/g ,  /x/g ,  \"use strict\" ,  /x/g ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  /x/g ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  /x/g ,  /x/g ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  /x/g ,  \"use strict\" ,  \"use strict\" ]); ");
/*fuzzSeed-204012247*/count=296; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-204012247*/count=297; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.min(((Math.hypot(((Math.atan((y , y)) < (Math.pow((( + (( + y) == ( + y))) | 0), y) | 0)) | 0), (((Math.imul(Math.fround(x), x) >>> 0) == y) | 0)) | 0) >>> 0), ((((Math.fround(Math.log2(( + Math.clz32(x)))) - ((( + ( ~ (Math.expm1((Math.trunc((Number.MIN_VALUE >>> 0)) | 0)) | 0))) >= 2**53-2) | 0)) >>> 0) > Math.sqrt(Math.fround((Math.fround(( + (0.000000000000001 + x))) ? Math.fround((Math.cos((0x0ffffffff >>> 0)) >>> 0)) : (Math.pow((Math.ceil((((2**53+2 >>> 0) ^ (x >>> 0)) >>> 0)) >>> 0), (Math.log1p(0/0) >>> 0)) >>> 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53+2), 0/0, 1/0, -0x07fffffff, 0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -1/0, 1, 42, 0x100000001, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, Math.PI, -0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 2**53+2, -Number.MIN_VALUE, 0x0ffffffff, -0x100000000, -0, Number.MIN_VALUE, -(2**53), 0x100000000, 0x080000001]); ");
/*fuzzSeed-204012247*/count=298; tryItOut("Object.defineProperty(this, \"v1\", { configurable: true, enumerable: false,  get: function() {  return g1.runOffThreadScript(); } });");
/*fuzzSeed-204012247*/count=299; tryItOut("g0.offThreadCompileScript(\"a1.sort((function(j) { if (j) { try { o2.v0 = Object.prototype.isPrototypeOf.call(g2, o2.g0); } catch(e0) { } try { a0 + a2; } catch(e1) { } try { v0 = r0.global; } catch(e2) { } h2 = {}; } else { try { g0.t1 = new Uint32Array(b2, 76, 7); } catch(e0) { } t1 = new Float32Array(this.b0, 60, 14); } }));\");");
/*fuzzSeed-204012247*/count=300; tryItOut("switch(Math.min(-12, (4277))) { case x: ( \"\" );\nv1.toSource = f0;\nbreak; case 4: (new eval(e));break; case 7: t1.toString = (function() { for (var j=0;j<1;++j) { this.o1.f0(j%2==0); } });break; break; case (window = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"$\", \"im\")), function(y) { \"use strict\"; m1.get(a2); })): break;  }");
/*fuzzSeed-204012247*/count=301; tryItOut("selectforgc(o0);");
/*fuzzSeed-204012247*/count=302; tryItOut("\"use strict\"; with(x)/*infloop*/do (new RegExp(\"(?:\\\\3{2049,2052})\", \"gm\")); while(\"\\uA87E\");function x(x, this.x, {}, [], NaN, w)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((1.5));\n  }\n  return f;for (var v of t1) { /*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { ;return 9; }}), { configurable: true, enumerable: (x % 36 == 12), get: (function() { try { g0.p2 = t0[4]; } catch(e0) { } try { v1 = (i1 instanceof g1); } catch(e1) { } try { e1.has(f0); } catch(e2) { } s1 += 'x'; return h2; }), set: (function mcc_() { var wwlvjk = 0; return function() { ++wwlvjk; f1(/*ICCD*/wwlvjk % 8 == 2);};})() }); }");
/*fuzzSeed-204012247*/count=303; tryItOut("s1 = s0.charAt(9);");
/*fuzzSeed-204012247*/count=304; tryItOut("\"use strict\"; return (let (c = /\\B/gyi)  /x/ );return;");
/*fuzzSeed-204012247*/count=305; tryItOut("print(x);");
/*fuzzSeed-204012247*/count=306; tryItOut("testMathyFunction(mathy2, [0, (new Boolean(true)), ({valueOf:function(){return 0;}}), '/0/', NaN, -0, (new String('')), '', true, '0', [], 0.1, (new Number(-0)), (new Number(0)), objectEmulatingUndefined(), /0/, '\\0', (new Boolean(false)), undefined, 1, false, ({toString:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return '0';}}), [0], null]); ");
/*fuzzSeed-204012247*/count=307; tryItOut("h0.iterate = (function mcc_() { var uavush = 0; return function() { ++uavush; f0(uavush > 5);};})();");
/*fuzzSeed-204012247*/count=308; tryItOut("t1 = new Uint8Array(this.a2);");
/*fuzzSeed-204012247*/count=309; tryItOut("m1.set(g0.g0, e2);");
/*fuzzSeed-204012247*/count=310; tryItOut(";function  (x = (function(y) { yield y; o1.v0 = g0.runOffThreadScript();; yield y; }), x)\"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var atan = stdlib.Math.atan;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    switch ((((i0)) << ((i0)))) {\n      default:\n        d1 = (2.4178516392292583e+24);\n    }\n    (Int8ArrayView[4096]) = ((0xffc84fea)+((abs((((0x10eb7339) % (0x5d26f79)) << (((-16385.0) < (8388609.0))-((((0xfd21b814))>>>((0xa314472))))+(((((0xfe151936)) << ((-0x8000000))))))))|0) <= (~~(+(1.0/0.0)))));\n    i0 = ((d1) != (-524288.0));\n    d1 = (d1);\n    i0 = (0xffc76460);\n    i0 = ((~~(d1)));\n    i0 = ((Float64ArrayView[4096]));\n    return (((0x3b69492a)-(i0)))|0;\n    {\n      d1 = (((+(0.0/0.0))) % ((-2.3611832414348226e+21)));\n    }\n    d1 = (NaN);\n    d1 = (d1);\n    i0 = ((((((/*UUV1*/(c.has = Object.getOwnPropertySymbols)) ^ ((((d1)))))))>>>((0xdddfbdcd))) < (((-0x8000000)+(0xf8a06c42))>>>(new  ''  >>> /(?:(?!\\w+))/gim((function ([y]) { })() << [,]))));\n    d1 = (-4294967297.0);\n    switch ((abs((0x53914e28))|0)) {\n      case -3:\n        i0 = (1);\n        break;\n      case -2:\n        d1 = (+((+abs(((-6.044629098073146e+23))))));\n      case -2:\n        d1 = (+abs(((d1))));\n    }\n    d1 = (+atan(((d1))));\n    i0 = (((0x70695*(0xe227d95d))>>>((0xb42ad436)*0xb562d)));\n    {\n      {\n        return (((0x8b28f0cf)+(0x10eb0520)))|0;\n      }\n    }\n    d1 = (-0.0078125);\n    return (((0xf86eae1e)+(i0)))|0;\n  }\n  return f;/*MXX1*/Object.defineProperty(g0, \"o2\", { configurable: true, enumerable: (x % 5 != 1),  get: function() {  return g2.Date.prototype.getMinutes; } });");
/*fuzzSeed-204012247*/count=311; tryItOut("mathy3 = (function(x, y) { return mathy2(Math.fround(( + Math.atan2(( + ( - Math.fround(( - Math.fround(y))))), (((x | 0) !== (mathy2(Math.fround(Math.hypot(Math.fround(x), Math.fround(y))), y) | 0)) | 0)))), Math.hypot(Math.max((mathy0(((Math.min(((x ^ x) || x), (( - Math.fround(x)) | 0)) >>> 0) | 0), ( + mathy2(Math.imul(x, ( + x)), y))) | 0), mathy2((Math.fround(Math.cosh(( + x))) >>> 0), 1.7976931348623157e308)), mathy2(Math.imul(Math.imul((x | 0), Math.fround(( - y))), (Math.trunc((((y | (y >>> 0)) >>> 0) | 0)) | 0)), ((((mathy0((Math.fround(Math.cbrt((0/0 >>> 0))) >>> 0), Math.fround(x)) >>> 0) >= x) >= (Math.atan2(( ! y), y) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[{}, {},  /x/ , {},  /x/ ,  /x/ , {},  /x/ , {}]); ");
/*fuzzSeed-204012247*/count=312; tryItOut("f0.toSource = f0;");
/*fuzzSeed-204012247*/count=313; tryItOut("/*vLoop*/for (cztoxl = 0; cztoxl < 72; ++cztoxl) { var c = cztoxl; return ( \"\" .toLocaleDateString());\ns2.toSource = (function() { try { this.a1.unshift(f1, e0); } catch(e0) { } p0 + ''; return o1; });\n } ");
/*fuzzSeed-204012247*/count=314; tryItOut("if(true) { if () /*vLoop*/for (var mimjtd = 0; mimjtd < 51; ++mimjtd) { var w = mimjtd; s2 += g0.o0.s0; }  else /*RXUB*/var r = /(?=(?:[^]{2,}[^]*?|\\\ud6ac??|\\D)[\\x8B-\u00ac\\u00e4-\u00f7]{2,})/y; var s = \"\\u00cb\\u00cb\\u00cb\\u00cb\\u00cb\\u00cb\\u00cb\\u00cb\\u00cb\\u00f7\"; print(s.split(r)); print(r.lastIndex); }");
/*fuzzSeed-204012247*/count=315; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.acos((Math.acosh(( + mathy0(x, ( + 0x080000001)))) | 0)) | 0); }); testMathyFunction(mathy2, [0x100000000, -(2**53), 42, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, -0x100000000, -Number.MIN_VALUE, 2**53+2, -(2**53+2), 2**53-2, 2**53, -(2**53-2), -0x080000001, -0x07fffffff, 0, 0x080000001, Number.MAX_VALUE, -0x080000000, Math.PI, 0x080000000, -1/0, 0x07fffffff, 0x0ffffffff, 0/0, 1/0, 1, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-204012247*/count=316; tryItOut("\"use strict\"; Array.prototype.pop.apply(o0.a1, []);");
/*fuzzSeed-204012247*/count=317; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.hypot(( - ((Math.expm1(((Math.hypot(y, x) | 0) | 0)) | 0) | 0)), (Math.max(( + mathy3(mathy3(x, x), y)), (x >>> 0)) ? ( ! (Math.pow(0, -Number.MAX_SAFE_INTEGER) >>> 0)) : Math.fround(Math.max(Math.fround(mathy0(x, Math.fround(((((x << (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) >> (y >>> 0)) >>> 0)))), Math.fround(x))))); }); testMathyFunction(mathy5, [0.000000000000001, 0x100000001, 2**53+2, 0x100000000, 1/0, -1/0, -Number.MAX_VALUE, -0x100000001, -0x080000001, 0x07fffffff, -(2**53+2), 1.7976931348623157e308, 0/0, -0x100000000, Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -(2**53), 2**53-2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, 0x080000001, -0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, -(2**53-2), -0, 42]); ");
/*fuzzSeed-204012247*/count=318; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1/gy; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-204012247*/count=319; tryItOut("mathy1 = (function(x, y) { return mathy0((Math.fround(( ~ Math.fround((Math.ceil(( + ( ~ ( + Math.trunc(Math.fround(y)))))) >>> 0)))) | 0), (Math.round(( + Math.fround(( + (Math.sqrt((y | 0)) | 0))))) | 0)); }); testMathyFunction(mathy1, /*MARR*/[ /x/ , arguments.callee, undefined, arguments.callee, undefined,  /x/ ,  /x/ , arguments.callee, undefined,  /x/ , arguments.callee,  /x/ ,  /x/ ,  /x/ ,  /x/ , undefined, arguments.callee, undefined, undefined, undefined, arguments.callee, arguments.callee,  /x/ , undefined, undefined, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee,  /x/ , arguments.callee, undefined,  /x/ , undefined,  /x/ , arguments.callee, undefined, undefined,  /x/ , arguments.callee, undefined, arguments.callee, arguments.callee, undefined,  /x/ , arguments.callee, undefined, arguments.callee, undefined, undefined, arguments.callee,  /x/ , undefined, arguments.callee, arguments.callee,  /x/ ,  /x/ ,  /x/ , arguments.callee, arguments.callee,  /x/ , arguments.callee, undefined, arguments.callee,  /x/ , arguments.callee, arguments.callee, arguments.callee, arguments.callee, undefined,  /x/ , undefined, arguments.callee, undefined, undefined, undefined, undefined, arguments.callee, arguments.callee, undefined,  /x/ , arguments.callee, undefined,  /x/ ,  /x/ , undefined, undefined,  /x/ , arguments.callee, undefined, arguments.callee, undefined, arguments.callee,  /x/ ,  /x/ , arguments.callee,  /x/ , undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, arguments.callee, arguments.callee, undefined, undefined,  /x/ , arguments.callee,  /x/ ,  /x/ ,  /x/ ,  /x/ , arguments.callee,  /x/ , arguments.callee,  /x/ , undefined, arguments.callee, arguments.callee, arguments.callee, arguments.callee,  /x/ ,  /x/ , arguments.callee,  /x/ , undefined, undefined]); ");
/*fuzzSeed-204012247*/count=320; tryItOut("let (a) { v0 = Object.prototype.isPrototypeOf.call(b2, g1); }v0 = g1.runOffThreadScript();");
/*fuzzSeed-204012247*/count=321; tryItOut("mathy0 = (function(x, y) { return ( + (( ! Math.fround((( ~ -0x080000001) - Math.min(Math.max(y, Math.fround(Math.atan2(Math.fround(0x07fffffff), y))), -1/0)))) | 0)); }); testMathyFunction(mathy0, [-0, -0x07fffffff, 0/0, Number.MIN_VALUE, -0x080000001, 0x0ffffffff, 0x100000001, 0.000000000000001, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53), -Number.MAX_VALUE, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, -0x080000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 0x080000001, Math.PI, 0x07fffffff, Number.MAX_VALUE, 1, 0x080000000, -0x100000000, 2**53+2, -0x100000001, -1/0, -(2**53-2), 0x100000000, 42]); ");
/*fuzzSeed-204012247*/count=322; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -17179869185.0;\n    var d3 = -140737488355328.0;\n    d1 = (d3);\n    d3 = (d2);\n    {\n      d1 = (((d2)) - ((+(-1.0/0.0))));\n    }\n    {\n      d1 = (d3);\n    }\n    (Float64ArrayView[((0xffffffff)-(/*FFI*/ff(((((0x1e92245b)) | ((0xfd514cf1)-(0xffffffff)-(0x9403fc9e)))), ((((0xfb2dbe02)) ^ ((d2)))), ((abs(((d0)))|0)), ((abs((-0x8000000))|0)))|0)) >> 3]) = ((+/*FFI*/ff(((((Int16ArrayView[2])) ^ (-0x9871c*(0x867201f4)))))));\n    d1 = (d1);\n;    d2 = (d0);\n    d3 = ((+abs(((((((d1) + (d1))) - ((+(abs((~~(-33554432.0)))|0)))) + (((d0)) / (((this.x) / ((((-8796093022207.0)) - ((-536870913.0))))))))))) + (d2));\n    (Float32ArrayView[0]) = (((/*RXUE*//(((?=(?=[\\n-\\r\\u00fd-\uc18b(-\\B]))))|(?:(?:\\B)?)*/gi.exec(\"\")) >>>= x));\n    {\n      d2 = (d2);\n    }\n    d0 = (d1);\n    return (((/*FFI*/ff(((((0xd26d0b31)-(0x7994199b)) >> (-(0xff6fea7e)))), ((d1)), ((((~~(-8589934593.0)) / (((0xb412761b)) ^ ((0xffffffff)))) & ((0x354f7805)))), ((~~(68719476737.0))), ((+(1.0/0.0))))|0)+(0x7c1763d1)+(0x2784df9)))|0;\n  }\n  return f; })(this, {ff: eval|=\"\\uE013\"\n}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000001, -0x080000001, 0, -0x100000000, 0x080000001, 0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 42, -(2**53-2), Math.PI, 1/0, 0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 2**53, Number.MIN_VALUE, 2**53-2, 2**53+2, 1, Number.MAX_VALUE, 0/0, 0x100000000, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -(2**53), -0, -0x07fffffff, -1/0]); ");
/*fuzzSeed-204012247*/count=323; tryItOut("s1 = new String(b0);for (var v of a2) { t0 + e2; }");
/*fuzzSeed-204012247*/count=324; tryItOut("\"use strict\"; m1.toSource = (function(j) { f0(j); });");
/*fuzzSeed-204012247*/count=325; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy4(Math.fround((( - ((x > Math.atan(Math.cbrt(( + Math.fround(( ~ (x >>> 0))))))) | 0)) | 0)), Math.fround(Math.max(Math.min(Math.max(x, x), ((Math.pow(Math.fround(x), (((2**53+2 != (-0x080000001 | 0)) | 0) >>> 0)) >>> 0) ** x)), (( ! (Math.log2(( ~ (-(2**53+2) | 0))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), x, 1e81, x, x, false, x, false, false, x, false, false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), 1e81, objectEmulatingUndefined(), -Infinity, false, 1e81, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, x, objectEmulatingUndefined(), objectEmulatingUndefined(), 1e81, false, objectEmulatingUndefined(), x, false, -Infinity, x, -Infinity, x, false, -Infinity, 1e81, false, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, objectEmulatingUndefined(), false, x, objectEmulatingUndefined(), x, 1e81, 1e81, -Infinity, false, false, objectEmulatingUndefined(), 1e81, 1e81, x, -Infinity, false, false, x, 1e81, 1e81, false, -Infinity, 1e81, x, x, objectEmulatingUndefined(), 1e81, x, x, false, 1e81, x, false, 1e81, x, x, objectEmulatingUndefined(), false, objectEmulatingUndefined(), 1e81, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 1e81, -Infinity, -Infinity, objectEmulatingUndefined(), -Infinity]); ");
/*fuzzSeed-204012247*/count=326; tryItOut("for(let w in ((arguments.callee.caller.caller.caller.caller)((Number.prototype.valueOf))))/*ODP-1*/Object.defineProperty(b2, 17, ({}));");
/*fuzzSeed-202342322*/count=1; tryItOut("(x + x);");
/*fuzzSeed-202342322*/count=2; tryItOut("\"use strict\"; var z = [new /((?=^))/gyim( \"\" , 18)], x = x, y = (continue ), x = ((function fibonacci(jarahv) { v2 = g0.eval(\"continue ;\");; if (jarahv <= 1) { ; return 1; } ; return fibonacci(jarahv - 1) + fibonacci(jarahv - 2);  })(6));const b = x;o1.__proto__ = e2;");
/*fuzzSeed-202342322*/count=3; tryItOut("o0.__proto__ = e2;");
/*fuzzSeed-202342322*/count=4; tryItOut(";");
/*fuzzSeed-202342322*/count=5; tryItOut("testMathyFunction(mathy5, [-0x07fffffff, -(2**53+2), 2**53, -0x080000001, 0/0, -0x0ffffffff, 0x080000000, 1.7976931348623157e308, -0x100000001, -0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), 0x100000001, -1/0, 1/0, Number.MAX_VALUE, 2**53+2, 1, 0x07fffffff, 2**53-2, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, -0x080000000, 0x100000000, 0x080000001, -Number.MAX_VALUE, 42, -(2**53-2), -0x100000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=6; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.atan2(Math.fround(( ! mathy0(x, ( - 0x0ffffffff)))), Math.cos((x / Math.min(Math.log1p((( + (x != x)) >>> 0)), Math.fround(( - Math.fround(x))))))), (Math.hypot(Math.fround((Math.clz32(Math.fround((Math.fround(( + (Number.MIN_SAFE_INTEGER ? ( + x) : Math.fround(y)))) >>> Math.fround(y)))) ? Math.cos((0x0ffffffff % Math.fround(y))) : mathy0((((x | 0) ? ((( + y) >>> 0) | 0) : (Math.pow(x, y) >>> 0)) | 0), x))), (( ! (( ~ (0.000000000000001 >>> 0)) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -0, -0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, Math.PI, -(2**53), 1/0, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, 0/0, 0x080000001, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, -0x100000000, 2**53, -(2**53-2), 0x100000001, 42, -1/0, 0x07fffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0, 2**53-2, -(2**53+2), 0.000000000000001, -0x0ffffffff]); ");
/*fuzzSeed-202342322*/count=7; tryItOut("\"use strict\"; switch(x.yoyo(-this)) { case 4: g1.a2 = a2[5];break; v2 = Object.prototype.isPrototypeOf.call(t1, b2);break;  }");
/*fuzzSeed-202342322*/count=8; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=9; tryItOut("for (var v of h2) { try { s1.toString = f1; } catch(e0) { } try { s0 += s0; } catch(e1) { } try { f1 = (function() { t0.set(a1, 13); throw t2; }); } catch(e2) { } this.i2 = new Iterator(g2, true); }");
/*fuzzSeed-202342322*/count=10; tryItOut("mathy3 = (function(x, y) { return Math.imul(Math.max(Math.imul(( + (((Math.fround(mathy0(Math.fround(((y >>> 0) && 1)), (x >>> 0))) >>> 0) ? (Number.MAX_VALUE >>> 0) : x) >>> Math.sign((x >>> 0)))), mathy1(Math.fround(x), ( + Math.clz32((Math.trunc(x) | 0))))), Math.hypot(Math.expm1(-(2**53)), ((( + Math.fround(mathy2(x, ((Math.fround(y) !== y) >>> 0)))) > (( ~ (y >>> 0)) >>> 0)) >>> 0))), ( - ((Math.pow(y, x) >>> 0) ? Math.fround(( ! Math.fround((Math.asinh((y | 0)) | 0)))) : ( - (Math.log2((mathy1(( + Math.log2(x)), ( + -Number.MAX_VALUE)) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-202342322*/count=11; tryItOut("v1 = a0.length;");
/*fuzzSeed-202342322*/count=12; tryItOut("/*infloop*/L:for(intern(({window: {\u3056: x}, x} = {x: e, x: {}} = x)); 'fafafa'.replace(/a/g, new Function).asin(null, 6); (x <= let (y = arguments) this)) for (var v of m1) { try { g2.o0 = {}; } catch(e0) { } try { this.a1[13]; } catch(e1) { } try { s2 + a2; } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(m1, p2); }");
/*fuzzSeed-202342322*/count=13; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?![^]+){0}|.)\", \"gyim\"); var s = \"\\n\"; print(s.split(r)); ");
/*fuzzSeed-202342322*/count=14; tryItOut("Float32Array(new RegExp(\"(?:(?=[^])|(?:[\\\\cT-\\\"\\\\u001f\\\\xC4\\\\u000F-\\uda84])[^]\\\\b\\\\b*?)*\", \"i\"), intern(x)) = a1[2];");
/*fuzzSeed-202342322*/count=15; tryItOut("switch(/*FARR*/[, ].map([[]], /*MARR*/[null, null, null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"\" , objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), null,  \"\" , (void 0),  \"\" , objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), null, (void 0),  \"\" , objectEmulatingUndefined(), null, objectEmulatingUndefined(), null,  \"\" ,  \"\" , objectEmulatingUndefined(),  \"\" , null, null, null, null, objectEmulatingUndefined(), null, objectEmulatingUndefined(),  \"\" , (void 0),  \"\" , null, (void 0),  \"\" , null, objectEmulatingUndefined(), (void 0),  \"\" , null].some)) { case [x]: v1 = g1.runOffThreadScript(); }");
/*fuzzSeed-202342322*/count=16; tryItOut("Object.prototype.unwatch.call(o2, \"tanh\");");
/*fuzzSeed-202342322*/count=17; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ! (Math.fround((Math.imul((Math.max((Math.min((x | 0), (x | 0)) | 0), (Math.cbrt(((Math.log((y >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0), (( - 2**53+2) >>> 0)) >>> 0)) && mathy0((Math.fround(Math.sin(Math.fround(( ~ x)))) >>> 0), ( ! Math.fround(Math.trunc(Math.pow((( + y) <= ( + y)), (2**53 | 0)))))))); }); testMathyFunction(mathy1, [(new Boolean(true)), '0', [], (function(){return 0;}), (new Number(-0)), '\\0', objectEmulatingUndefined(), [0], '/0/', false, -0, null, (new Number(0)), true, '', /0/, 0, 1, ({valueOf:function(){return 0;}}), undefined, (new String('')), (new Boolean(false)), 0.1, ({toString:function(){return '0';}}), NaN, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-202342322*/count=18; tryItOut("\"use strict\"; v0 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-202342322*/count=19; tryItOut("if((x % 6 == 0)) /*ADP-1*/Object.defineProperty(a0, ({}), ({}));");
/*fuzzSeed-202342322*/count=20; tryItOut("Array.prototype.reverse.apply(g0.a1, [c = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: SharedArrayBuffer, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })( /x/ .unwatch(new String(\"19\"))), let (y = \"\\u6970\")  /x/g ), e1]);");
/*fuzzSeed-202342322*/count=21; tryItOut("testMathyFunction(mathy5, [1, 0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 0x07fffffff, -Number.MAX_VALUE, -(2**53), 0x080000000, 0.000000000000001, -0x100000000, 2**53, -1/0, -(2**53+2), -0x07fffffff, Number.MIN_VALUE, -0x080000001, 42, -0x100000001, Math.PI, 1/0, -Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 0, 0x100000001, -0, 2**53-2, 2**53+2, -0x080000000]); ");
/*fuzzSeed-202342322*/count=22; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.abs((Math.imul((Math.pow((( + (( + y) << ( + Math.max(y, ( + y))))) >>> 0), (Math.fround(y) != y)) | 0), (( + (Math.fround(0x07fffffff) > Math.fround(y))) >>> 0)) >>> 0)) ? Math.fround(( ! (( + mathy0(( ~ (( ~ (( + Math.asin(Number.MIN_VALUE)) | 0)) | 0)), ( + Math.fround(mathy2(Math.fround((Math.fround(x) / Math.fround(x))), Math.fround((Math.fround(Number.MAX_SAFE_INTEGER) < Math.fround(Math.exp(x))))))))) | 0))) : Math.fround((Math.fround(( ! ((Math.abs((y | 0)) | 0) ? y : ( ~ -0)))) > Math.fround(Math.imul((mathy0((-Number.MAX_SAFE_INTEGER | 0), (y >>> 0)) | 0), (Math.sinh(Math.fround(( ~ (mathy2((Math.acos(Math.fround(x)) >>> 0), ((-(2**53-2) >> y) >>> 0)) >>> 0)))) | 0)))))); }); testMathyFunction(mathy3, [Number.MIN_VALUE, Math.PI, 42, 0x100000001, 0x07fffffff, 2**53, 0, 2**53+2, -0x0ffffffff, 0/0, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, 1, 1.7976931348623157e308, -0, Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, -0x07fffffff, 0x100000000, -0x080000001, -Number.MIN_VALUE, 1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53), -1/0, 0x0ffffffff]); ");
/*fuzzSeed-202342322*/count=23; tryItOut("/*tLoop*/for (let x of /*MARR*/[]) { print(x);e2.delete(p0); }");
/*fuzzSeed-202342322*/count=24; tryItOut("Array.prototype.push.call(a1, v0);");
/*fuzzSeed-202342322*/count=25; tryItOut("v2 + '';");
/*fuzzSeed-202342322*/count=26; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return Math.clz32(Math.cbrt(Math.hypot(Math.max(Math.cosh(new RegExp(\"\\\\2\", \"i\")), (((( + Math.atan(x)) | 0) === x) | 0)), (Math.sin(0.000000000000001) | 0)))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 2**53-2, -0, 2**53, 0x080000000, -0x080000001, -1/0, -(2**53), Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, 42, 0, -0x0ffffffff, 2**53+2, -0x080000000, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 1, -(2**53+2), -0x100000001, 0x100000000, -Number.MAX_VALUE, 1/0, -(2**53-2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001]); ");
/*fuzzSeed-202342322*/count=27; tryItOut("/*hhh*/function xxntrl(){print(x);}/*iii*/a0.length = 17;");
/*fuzzSeed-202342322*/count=28; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 4503599627370497.0;\n    d2 = (Infinity);\n    return +(((Int16ArrayView[((i0)+(-0x8000000)) >> 1])));\n  }\n  return f; })(this, {ff: Array.of}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[ '\\0' , undefined,  '\\0' , undefined, undefined,  '\\0' , undefined, undefined,  '\\0' , new String('q'), undefined,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , undefined,  '\\0' , undefined,  '\\0' ]); ");
/*fuzzSeed-202342322*/count=29; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ (Math.sign(Math.fround(( + (x | 0)))) >>> 0)); }); ");
/*fuzzSeed-202342322*/count=30; tryItOut("\"use strict\"; ");
/*fuzzSeed-202342322*/count=31; tryItOut(";");
/*fuzzSeed-202342322*/count=32; tryItOut("\"use strict\"; testMathyFunction(mathy3, [1, Number.MIN_VALUE, -(2**53+2), -0x080000000, Math.PI, 0x080000001, -Number.MIN_SAFE_INTEGER, -0, 0, -0x100000000, 2**53-2, -Number.MIN_VALUE, 0x07fffffff, 0x100000000, 2**53+2, -0x0ffffffff, 42, 2**53, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53), 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), -1/0, 0x080000000, 1/0, 1.7976931348623157e308, -0x080000001, 0/0, -0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=33; tryItOut("\"use asm\"; this.zzz.zzz;let(y) ((function(){for(let c in []);})());");
/*fuzzSeed-202342322*/count=34; tryItOut("g1.e0 + o2;");
/*fuzzSeed-202342322*/count=35; tryItOut("\"use strict\"; o1.a2.shift(i1);");
/*fuzzSeed-202342322*/count=36; tryItOut("{ void 0; void 0; }");
/*fuzzSeed-202342322*/count=37; tryItOut("/*infloop*/do function shapeyConstructor(vchylw){if (vchylw) Object.defineProperty(this, \"__iterator__\", ({get: function  vchylw (c) { yield new RegExp(\"\\\\W\\\\D{2,6}|\\\\3{4,4}|\\\\1+\", \"ym\").unwatch(\"10\") } , set: function  window (d) { \"use strict\"; print(x); } , enumerable: (vchylw % 5 != 0)}));delete this[\"call\"];{ const x = [1,,] && /\\1/gyi, vchylw = (vchylw >>> (Math.sin((vchylw | 0)) | 0)), b, window;\u000c(vchylw); } { a0 = /*MARR*/[new String('q'), new String('q'), new String('q'), new String('q'), -0x2D413CCC, new String('q'), -0x2D413CCC, new String('q'), -0x2D413CCC, new String('q'), new String('q'), -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, new String('q'), new String('q'), new String('q'), -0x2D413CCC, new String('q'), new String('q'), new String('q')]; } Object.seal(this);if (vchylw) for (var ytqykmlco in this) { }delete this[\"toSource\"];this[new String(\"-19\")] =  /x/g ;Object.seal(this);for (var ytqcbsjqt in this) { }return this; }/*tLoopC*/for (let a of /*MARR*/[objectEmulatingUndefined(), function(){}, function(){}, eval, objectEmulatingUndefined(), eval, objectEmulatingUndefined(), objectEmulatingUndefined(), eval, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), eval, eval, function(){}, function(){}, eval, function(){}, objectEmulatingUndefined(), eval, function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), eval, objectEmulatingUndefined(), eval, eval, objectEmulatingUndefined(), eval, eval, objectEmulatingUndefined(), objectEmulatingUndefined()]) { try{let uwnfcy = shapeyConstructor(a); print('EETT'); print(a);}catch(e){print('TTEE ' + e); } } while((4277));");
/*fuzzSeed-202342322*/count=38; tryItOut("Array.prototype.forEach.call(a1, (function(j) { if (j) { t1[v2] = s2; } else { try { o0.s2 += 'x'; } catch(e0) { } try { Object.preventExtensions(o0.g0.h1); } catch(e1) { } v0 = r2.global; } }));");
/*fuzzSeed-202342322*/count=39; tryItOut("\"use strict\"; /*infloop*/while(((void options('strict')))){print((4277)); }");
/*fuzzSeed-202342322*/count=40; tryItOut("i2.next();");
/*fuzzSeed-202342322*/count=41; tryItOut("\"use strict\"; o0 = new Object;print(x);");
/*fuzzSeed-202342322*/count=42; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((( ! ((((( - x) >>> 0) !== (( ! x) >>> 0)) >>> 0) >>> 0)) | 0) / ((( + ((((Math.sinh(y) | 0) >>> 0) % x) >>> 0)) >= Math.fround(( + ((y | 0) ? (Math.atan((y < 0x100000001)) >>> 0) : (Math.fround(Math.atan2((2**53+2 + -Number.MIN_VALUE), Math.fround(Math.sin(y)))) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, 2**53, 0.000000000000001, 0x080000000, -(2**53+2), -1/0, -(2**53-2), 0/0, -0x07fffffff, 0x07fffffff, 2**53-2, -0x100000001, -Number.MAX_VALUE, 2**53+2, 0x080000001, 0x100000000, -0x080000000, 42, -0x100000000, -(2**53), -0, 1, Math.PI, -Number.MIN_VALUE, 0x100000001, Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=43; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.log2(Math.trunc((( + Math.log(0/0)) ** Math.fround(Math.max(Math.fround(y), (-1/0 | 0)))))) ? (((Math.pow(-Number.MAX_SAFE_INTEGER, Math.fround(Math.imul(Math.fround(-0x07fffffff), Math.fround(y)))) | 0) << ( + (Math.min(y, Math.acosh(Math.fround(0x0ffffffff))) | 0))) | 0) : mathy2((( + Math.log(( + (0x100000001 != (( ~ 0x080000001) | 0))))) >>> 0), mathy0(((Math.fround(Math.max((mathy2((Math.tanh((x | 0)) | 0), (x | 0)) >>> 0), (x * (y | 0)))) ? ( + mathy1(( + ( ! Math.hypot(Math.fround(y), y))), ( + (Math.sign((Math.fround(( ~ ( + y))) >>> 0)) | 0)))) : (( + Math.trunc((x | 0))) >>> 0)) >>> 0), (( ~ (Math.log2(1/0) | 0)) | 0)))); }); testMathyFunction(mathy3, [(new String('')), (new Number(-0)), ({valueOf:function(){return 0;}}), 1, null, false, (new Number(0)), undefined, 0, '', (function(){return 0;}), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), [0], '/0/', '0', (new Boolean(false)), 0.1, NaN, '\\0', (new Boolean(true)), -0, [], objectEmulatingUndefined(), /0/, true]); ");
/*fuzzSeed-202342322*/count=44; tryItOut("s0 = a2[7];");
/*fuzzSeed-202342322*/count=45; tryItOut("\"use strict\"; s0.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15) { var r0 = a9 ^ 8; var r1 = a10 % 6; var r2 = 7 ^ a11; var r3 = x - a4; var r4 = a11 % 7; var r5 = 3 % 3; x = 1 | r3; var r6 = x * 8; var r7 = r5 + 2; var r8 = a9 | a2; var r9 = a2 & r0; a6 = 1 / 3; var r10 = 1 % r5; var r11 = 5 / a1; a5 = 1 / r2; var r12 = 0 ^ r10; var r13 = a1 | a5; var r14 = 4 - a15; a8 = r12 / r11; var r15 = r2 + 9; var r16 = r11 % a5; var r17 = 9 ^ a10; print(a11); var r18 = 2 * 6; var r19 = 0 & a2; var r20 = r18 & a14; r8 = r9 * r20; var r21 = r17 | 4; var r22 = r0 | 0; var r23 = a3 % a8; var r24 = a13 & r15; var r25 = 8 & 7; var r26 = 4 ^ r1; var r27 = a12 - r22; var r28 = r27 ^ r17; var r29 = r5 | a0; var r30 = r9 / a6; r0 = 4 - 0; r2 = r0 * 2; r17 = 2 & r5; var r31 = r16 + a9; r23 = r6 / 6; r27 = r14 - r1; a6 = a13 & 4; return a12; });");
/*fuzzSeed-202342322*/count=46; tryItOut("\"use strict\"; Array.prototype.push.call(a0, x, g2, this.m0);");
/*fuzzSeed-202342322*/count=47; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.cosh(( + ((mathy0(0x0ffffffff, y) >>> 0) > ((mathy0((( + mathy0(( + 0), y)) | 0), (( + x) | 0)) | 0) >>> 0)))); }); ");
/*fuzzSeed-202342322*/count=48; tryItOut("a2 = Array.prototype.concat.apply(a0, [a2, a0, m0, a2, f2]);");
/*fuzzSeed-202342322*/count=49; tryItOut("/*RXUB*/var r = new RegExp(\"(?=$[^]*?{3})(?!(?!\\u8a3d$|(?=\\u00e3)))+?(?:^){4,6}+\", \"gym\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u8a3d\\n\\u89a6\\n\\u8a3d\\n\\u89a6\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-202342322*/count=50; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ~ Math.acos((Math.hypot((Math.fround(( ! Math.fround((Math.fround(x) >= Math.fround(x))))) | 0), (( + ((( - mathy0(x, x)) | 0) ? x : (y - ( + (( + x) & x))))) | 0)) | 0))); }); testMathyFunction(mathy5, [({valueOf:function(){return '0';}}), '0', undefined, ({valueOf:function(){return 0;}}), 0, [], '', (new Number(0)), '/0/', false, 0.1, true, objectEmulatingUndefined(), [0], ({toString:function(){return '0';}}), null, 1, (function(){return 0;}), (new Boolean(true)), '\\0', -0, (new Boolean(false)), NaN, (new Number(-0)), (new String('')), /0/]); ");
/*fuzzSeed-202342322*/count=51; tryItOut("\"use strict\"; v1 = g2.runOffThreadScript();\ng0 + '';\n");
/*fuzzSeed-202342322*/count=52; tryItOut("let [, , ] = Math.pow((void version(170)), 5), pkjlrz, \u3056, x, x, eval = 'fafafa'.replace(/a/g, decodeURIComponent), y, x = x, ahyyhc;for (var p in t2) { try { t0[({valueOf: function() { a1.shift(m1);return 1; }})] = \"\\u9C2F\"; } catch(e0) { } try { m2.delete(b1); } catch(e1) { } h0.has = g2.f0; }");
/*fuzzSeed-202342322*/count=53; tryItOut("\"use strict\"; M:do {/*hhh*/function kgdbmq(x = ((neuter)(new ( \"\" )(false), false)), ...x){print(Math.min(a,  \"\" ));}kgdbmq();/*RXUB*/var r = /(\\b)(?:[\\W\\d\\cD-\\cF]+|^)?/gyim; var s = \"\"; print(uneval(s.match(r)));  } while((this) && 0);");
/*fuzzSeed-202342322*/count=54; tryItOut("mathy1 = (function(x, y) { return (Math.cosh(Math.tan(-0x100000000)) + ( + Math.hypot(( + ( + (((Math.atan2((x | 0), (x | 0)) | 0) | 0) & x))), (( + ( + ( + ( ~ (y | 0))))) | 0)))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, 0x100000000, -0x100000001, -Number.MAX_VALUE, 0.000000000000001, Number.MAX_VALUE, -0x100000000, -1/0, -0, 0x080000000, 42, -0x080000001, -0x0ffffffff, 1.7976931348623157e308, 2**53+2, 0x100000001, Math.PI, 0, -(2**53), -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53-2), 0/0, 0x080000001, 2**53-2, -0x080000000, 1, -(2**53+2), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=55; tryItOut("\"use strict\"; /*oLoop*/for (oaiwyw = 0; oaiwyw < 31; ++oaiwyw) { if(x = Proxy.createFunction(({/*TOODEEP*/})(13), /*wrap2*/(function(){ var ifhzqn = /(?!\\B|([^]){1,})\\b+?.|\\B/; var vrxymr = /*wrap3*/(function(){ \"use strict\"; var rhtghv = /\\3/yim; (({/*TOODEEP*/}))(); }); return vrxymr;})())) { if ( /x/ .__defineSetter__(\"e\", Array.prototype.reduce)) {t0 = new Int8Array(b1, 0, this);s0 += s1; }} else {a2.splice(NaN, new RegExp(\"(?!\\\\D)\", \"gi\"), g1.a1, s1); } } ");
/*fuzzSeed-202342322*/count=56; tryItOut("/*tLoop*/for (let e of /*MARR*/[new Number(1.5), 27.throw(\"\\u5E61\"), new Number(1.5), 0x20000000, 27.throw(\"\\u5E61\"), new Boolean(false), 27.throw(\"\\u5E61\"), new Boolean(false), 0x20000000, new Number(1.5), new Boolean(false), new Boolean(false), 27.throw(\"\\u5E61\"), new Number(1.5), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), new Boolean(false), 27.throw(\"\\u5E61\"), 0x20000000, 0x20000000, 27.throw(\"\\u5E61\"), new Number(1.5), 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 0x20000000, 27.throw(\"\\u5E61\"), new Boolean(false), 27.throw(\"\\u5E61\"), 27.throw(\"\\u5E61\"), new Boolean(false), new Number(1.5), new Boolean(false), 27.throw(\"\\u5E61\"), new Number(1.5), new Boolean(false), 27.throw(\"\\u5E61\"), new Boolean(false), new Number(1.5), new Number(1.5), new Boolean(false)]) { print(e); }");
/*fuzzSeed-202342322*/count=57; tryItOut("throw x;z.lineNumber;");
/*fuzzSeed-202342322*/count=58; tryItOut("mathy1 = (function(x, y) { return Math.imul(Math.pow((mathy0(( + Math.fround(( ~ Math.fround((Math.hypot((x ? (y < x) : y), x) | 0))))), (( - (( + mathy0((Math.atan((x >>> 0)) | 0), ( + 1/0))) | 0)) | 0)) | 0), (Math.exp((( - (Math.abs(x) | 0)) | 0)) >>> 0)), ((Math.pow(((Math.exp(( ~ x)) | 0) >>> 0), (0x100000000 >>> 0)) | ((Math.imul((Math.min(( + y), ((Math.cos((y | 0)) | 0) >>> 0)) >>> 0), (Math.max((Math.imul((y >>> 0), (x >>> 0)) >>> 0), x) | 0)) | 0) >>> 0)) !== ((( + Math.min(x, (( + ( - ( + -Number.MIN_VALUE))) >>> 0))) | x) && ( - (Math.hypot((x | 0), ( - x)) | 0))))); }); ");
/*fuzzSeed-202342322*/count=59; tryItOut("testMathyFunction(mathy5, [-(2**53-2), -0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 1/0, Number.MIN_VALUE, -(2**53), -0x07fffffff, 1.7976931348623157e308, -0, 2**53+2, 0/0, -(2**53+2), 0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 0x0ffffffff, Math.PI, 0, 1, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 0x100000000, -1/0, -0x100000000, 0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-202342322*/count=60; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.2089258196146292e+24;\n    var i3 = 0;\n    var d4 = 131071.0;\n    d2 = (NaN);\n    {\n      {\n        i1 = ((36028797018963970.0));\n      }\n    }\n    return (((i1)+(0x95c1a4a0)))|0;\n    return (( '' ))|0;\n  }\n  return f; })(this, {ff: Array.prototype.entries}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [(new Boolean(true)), (new Boolean(false)), 0, NaN, objectEmulatingUndefined(), 0.1, /0/, false, [], undefined, [0], ({toString:function(){return '0';}}), '/0/', -0, '\\0', ({valueOf:function(){return 0;}}), null, ({valueOf:function(){return '0';}}), (function(){return 0;}), (new Number(0)), (new String('')), '0', (new Number(-0)), 1, true, '']); ");
/*fuzzSeed-202342322*/count=61; tryItOut("\"use strict\"; const ovwgbn;g1.e2.has(v1);");
/*fuzzSeed-202342322*/count=62; tryItOut("\"use strict\"; m0.get(m2);");
/*fuzzSeed-202342322*/count=63; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    i1 = (!(i1));\n    i1 = (i0);\n    switch (((((0x6736a32e))) << ((0xcb3205af)-(0xec2b0007)-(0x4a9aa3cb)))) {\n      case -2:\n        (Float32ArrayView[2]) = ((((17.0)) % ((-((-8589934593.0))))));\n        break;\n      default:\n        {\n          i0 = (/*FFI*/ff(((((i0)-((((i1))>>>((0x2343ba5d)-(0xffffffff)+(0xfd6faea2))) > ((((0x5e2c8a9d))+((-0x8000000) ? (0xf9877dba) : (0xcb5e4df2)))>>>((i1))))) ^ ((0x89eea31f) / (0x29b6c1ee)))), ((((!(((((0x79a48273) < (-0x562d651))) << (-(i0)))))) >> ((i1)))), ((abs((((i0)) << ((i1))))|0)), ((+(1.0/0.0))), ((((i1)-(i0)) << (0xfffff*(i1)))))|0);\n        }\n    }\n    {\n      i0 = (i1);\n    }\n    i1 = (i0);\n    i1 = (i1);\n    i0 = (i0);\n    i1 = (0x3229feab);\n    switch ((((i0)+(!(0x4248f95c))-(i1))|0)) {\n      case 0:\n        i0 = ((((i1)+(i0))>>>((i1))));\n      case 1:\n        {\n          i0 = (i1);\n        }\n        break;\n      case -1:\n        {\n          i0 = (((((0xffffffff) > (((0x4854931d)+(0xfddf2053))>>>((!(0xd17289a2)))))-(i0)-((i1) ? ((0xf47524a7) ? (0x6a660c2) : (0xf8cf68ca)) : (i1))) >> (((0xb42f50d3) < (0x3d18f001))+((((/*FFI*/ff(((-65.0)), ((-295147905179352830000.0)), ((65.0)), ((1.0009765625)), ((0.0009765625)), ((-3.094850098213451e+26)), ((-16777217.0)), ((-73786976294838210000.0)), ((35184372088833.0)), ((3.094850098213451e+26)), ((1.9342813113834067e+25)))|0)-(/*FFI*/ff(((-2147483648.0)), ((7.737125245533627e+25)), ((-1.001953125)))|0)) & ((i1))) == ((((1.0625) == (-34359738367.0))-(i1)-(-0x8000000))|0)))));\n        }\n        break;\n    }\n    {\n      i0 = ((((i0)-(i0)+(i1))>>>((i0)-((0xf19fb5ea))-((-2305843009213694000.0)))));\n    }\n    return +(((Float32ArrayView[1])));\n  }\n  return f; })(this, {ff: arguments.callee}, new ArrayBuffer(4096)); ");
/*fuzzSeed-202342322*/count=64; tryItOut("delete a0[\"w\"];");
/*fuzzSeed-202342322*/count=65; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?:\\\\3))\\\\3|^+?+\", \"gm\"); var s = \"\\n\\n\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=66; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"^|(\\\\cA*?)^*?\", \"gym\"); var s = \"\\n\"; print(s.split(r)); ");
/*fuzzSeed-202342322*/count=67; tryItOut("for (var v of b1) { try { h2 + ''; } catch(e0) { } try { print(b0); } catch(e1) { } try { t2[4] = Math.pow(x, x); } catch(e2) { } a2.pop(); }");
/*fuzzSeed-202342322*/count=68; tryItOut("var yomliw = new ArrayBuffer(2); var yomliw_0 = new Int16Array(yomliw); var yomliw_1 = new Int8Array(yomliw); print(yomliw_1[0]); print(false);Array.prototype.sort.apply(a2, [(function() { for (var j=0;j<12;++j) { f2(j%5==1); } }), m0, a2]);");
/*fuzzSeed-202342322*/count=69; tryItOut("\"use strict\"; /*bLoop*/for (var cwauth = 0; cwauth < 20; ++cwauth) { if (cwauth % 10 == 5) {  for (var a of ((void shapeOf((4277))))) Object.defineProperty(x, \"prototype\", ({enumerable: (a % 4 == 3)})); } else { var hgajsd = new SharedArrayBuffer(16); var hgajsd_0 = new Int8Array(hgajsd); hgajsd_0[0] = 15; var hgajsd_1 = new Float32Array(hgajsd); hgajsd_1[0] = -13; e1.add(i1);Array.prototype.forEach.apply(g2.a0, [this.g2.f1, b2, this.f0]); }  } ");
/*fuzzSeed-202342322*/count=70; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + (Math.log1p((( + (( + x) < ( + (Math.ceil((y >>> 0)) >>> 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, -0x080000001, 1, 0x07fffffff, -(2**53+2), -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, 1/0, 2**53+2, 0x0ffffffff, -1/0, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 0, -(2**53-2), 2**53, -(2**53), -0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 42, -0x100000000, 2**53-2, 0/0, 0x100000000, -0, Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-202342322*/count=71; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, -1/0, Number.MAX_SAFE_INTEGER, 0x080000000, 0, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53+2, -0, -0x100000001, 0x080000001, 1/0, -(2**53+2), 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 42, Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, -0x080000001, 1, -(2**53), 0/0, 2**53-2, -0x100000000, -0x080000000, Math.PI]); ");
/*fuzzSeed-202342322*/count=72; tryItOut("\"use asm\"; /*bLoop*/for (var irqurq = 0; irqurq < 43; ++irqurq) { if (irqurq % 3 == 2) { Array.prototype.sort.apply(a2, [(function() { try { v2 = t0.length; } catch(e0) { } g0.t1 = new Int32Array(o0.t2); return t1; }), o2]); } else { for (var p in h1) { try { a2.forEach(); } catch(e0) { } try { i2.toSource = f2; } catch(e1) { } s0 += 'x'; }function b(y, ...w) { return \"\\u15F6\" } s2 += 'x'; }  } ");
/*fuzzSeed-202342322*/count=73; tryItOut("/*RXUB*/var r = /./g; var s = \"\\n\"; print(r.exec(s)); ");
/*fuzzSeed-202342322*/count=74; tryItOut("Object.freeze(m2);");
/*fuzzSeed-202342322*/count=75; tryItOut("v0 = evalcx(\"\\\"use strict\\\"; v1 = g2.runOffThreadScript();\", g0.g2);");
/*fuzzSeed-202342322*/count=76; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( - (Math.min(((( - Math.hypot(y, y)) && ( + Math.atan2((( + mathy1(y, ( + y))) >>> 0), 0/0))) >>> 0), Math.fround((mathy2(( + Math.exp(Math.fround(Math.fround(( + Math.fround(y)))))), (0.000000000000001 ? y : x)) >>> 0))) | 0))); }); testMathyFunction(mathy3, [1, (new Number(0)), '0', ({valueOf:function(){return '0';}}), -0, 0.1, (new String('')), [0], undefined, /0/, 0, (new Boolean(true)), ({valueOf:function(){return 0;}}), '', true, '\\0', '/0/', false, NaN, (new Number(-0)), (function(){return 0;}), null, [], objectEmulatingUndefined(), ({toString:function(){return '0';}}), (new Boolean(false))]); ");
/*fuzzSeed-202342322*/count=77; tryItOut("a2 = [];");
/*fuzzSeed-202342322*/count=78; tryItOut("\"use strict\"; /*vLoop*/for (var pkkodg = 0; pkkodg < 20; ++pkkodg) { const a = pkkodg; g1.t2 = new Int32Array(t1); } a1 = g1.a0.slice(NaN, NaN, s0);");
/*fuzzSeed-202342322*/count=79; tryItOut("t1[(WeakSet.prototype.add).call((4277), )] = new Array(25);");
/*fuzzSeed-202342322*/count=80; tryItOut("v0 = (f2 instanceof i0);");
/*fuzzSeed-202342322*/count=81; tryItOut("\"use strict\"; print(uneval(p0));");
/*fuzzSeed-202342322*/count=82; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?![N-\\\\r\\\\cQ\\u1fe2]|[^]\\\\D{4}\\uebae{1,}|[v\\u00b4-\\\\b\\\\s]..[^]{1,5})\\\\3|(?!(?:\\u8ddd))|(?=[^][\\\\ufe3d\\\\cV\\ufb35\\\\b-\\\\u3aFD]))|(?!^{1,})*|.+{67108863,}|(?:(?:.))|\\\\2\", \"gyi\"); var s = \"\\n\"; print(s.replace(r, eval-=x)); print(r.lastIndex); /*RXUB*/var r = /\\1/m; var s = \"\\u00f3\\u0001\\u0001\"; print(s.match(r)); \nvar ucsqah = new SharedArrayBuffer(16); var ucsqah_0 = new Uint32Array(ucsqah); ucsqah_0[0] = -0.006; v1 = new Number(Infinity);\n");
/*fuzzSeed-202342322*/count=83; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i3 = ((-1.001953125) != (-9007199254740992.0));\n    i0 = (i1);\n    return (((i2)+(((imul((i1), ((((0xfe4fe323)) << ((0x34586b23)))))|0) >= (((-0x7c2fad5)-(0xfc7d1bb9)) ^ ((0x8d1c7310) % (0xffffffff)))) ? (/*FFI*/ff(((abs((imul((i2), (i1))|0))|0)), ((0x5dcc6ece)), ((-3.094850098213451e+26)), ((+(0.0/0.0))), ((274877906944.0)), ((-147573952589676410000.0)), ((36893488147419103000.0)), ((-1.03125)), ((-7.555786372591432e+22)))|0) : ((274877906945.0) < (+/*FFI*/ff(((-17179869185.0)), ((-131073.0)), ((31.0)), ((-2.3611832414348226e+21)), ((-274877906945.0)), ((9.44473296573929e+21))))))-((new (eval)()) != (-2049.0))))|0;\n  }\n  return f; })(this, {ff: function(y) { \"use asm\"; return ({}[\"x\"]) }}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [1, -Number.MAX_SAFE_INTEGER, 0x100000001, 42, 0x100000000, 0.000000000000001, Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, 0/0, -0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, -0, 0x080000001, -1/0, 0, Math.PI, -(2**53), 0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, -0x080000001, -(2**53+2), 2**53, -0x080000000, 1.7976931348623157e308, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-202342322*/count=84; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(f2, e2);");
/*fuzzSeed-202342322*/count=85; tryItOut("\"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    i1 = (i0);\n    switch ((-0x8000000)) {\n    }\n    {\n      i0 = (0x1b5d0797);\n    }\n    i1 = ((0x4b11db95));\n    {\n      i0 = (i0);\n    }\n    {\n      i0 = (i0);\n    }\n    /*FFI*/ff(((((/*FFI*/ff(((((-4.722366482869645e+21)) - ((NaN)))), ((((-0x8000000)) << ((0x6ae66c1)))), ((abs((0x7fffffff))|0)), ((9223372036854776000.0)), ((1.5111572745182865e+23)), ((16777217.0)), ((-1152921504606847000.0)), ((-1125899906842625.0)), ((4.835703278458517e+24)), ((262145.0)), ((32769.0)), ((-1.0625)), ((35184372088833.0)), ((-274877906943.0)), ((-3.022314549036573e+23)), ((-2.3611832414348226e+21)), ((36028797018963970.0)), ((-2097153.0)))|0)-(i0)) << ((Int16ArrayView[2])))), ((((288230376151711740.0)) % ((Float32ArrayView[1])))), ((((i1)) | ((Float64ArrayView[4096])))));\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: (function(x, y) { return (Math.sign((1.7976931348623157e308 >>> 0)) >>> 0); })}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-202342322*/count=86; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:(.?|\\\\3)*?)){4}\", \"g\"); var s = \"\"; print(s.replace(r, 'x', \"g\")); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=87; tryItOut("/*infloop*/ for (window of (uneval(/\\u1d05{4,}/gim))) g2.g1.offThreadCompileScript(\"function f0(g0)  { return Object.defineProperty(g0, \\\"getUTCSeconds\\\", ({get: x =>  { return (4277) } , set: (function(x, y) { return x; }), configurable: true})) } \");");
/*fuzzSeed-202342322*/count=88; tryItOut("testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, 2**53+2, 0x100000000, 0, -0x080000001, Number.MAX_VALUE, -0, 2**53, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, -(2**53), 0x07fffffff, 0.000000000000001, -Number.MIN_VALUE, 1, 0x100000001, Number.MIN_VALUE, -(2**53-2), -0x100000000, 0x080000000, -(2**53+2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000000, 42, 1.7976931348623157e308, 0/0, Math.PI, -0x100000001]); ");
/*fuzzSeed-202342322*/count=89; tryItOut("mathy5 = (function(x, y) { return (Math.pow(eval(\"v1 = Object.prototype.isPrototypeOf.call(v1, p0);\",  /x/g ), (Math.fround(( ! (Math.max((Math.asinh(x) && y), Math.pow((mathy4((x >>> 0), (x >>> 0)) >>> 0), x)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [Number.MAX_VALUE, -(2**53+2), 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, -Number.MAX_VALUE, 0/0, -0x080000001, -(2**53-2), 1, 0x100000001, -0, 0.000000000000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, Math.PI, -0x100000001, 2**53+2, -1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, -0x100000000, 42, 1/0, -(2**53), 1.7976931348623157e308, -0x07fffffff, 2**53, -Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-202342322*/count=90; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=91; tryItOut("if(true) {/*bLoop*/for (var feyhvj = 0, /*FARR*/[].filter; feyhvj < 41; ++feyhvj) { if (feyhvj % 6 == 3) { ((let (z =  /x/g )  \"\" )); } else { /*hhh*/function auujag(y, w, x, delete =  /x/ , NaN, \u3056 = w, x =  /x/g , w, x, window, d = \"\\uAB3B\", w = ({a1:1}), x, \u3056 = this, eval, window, x, x =  \"\" , eval, a, NaN, x, \u3056, x =  '' , w, eval, y, x, d, \u3056, window, c, window, b, this, z = this, \u3056, x = (function ([y]) { })(), x, x, x, y, b, b, d, a, x, x, x, x, window, e = 24, \u3056, a, x, x, b, x, w, b, c, y =  \"\" , d, x, y, x, x = undefined, y, x, e, NaN, x, NaN, window =  \"\" , w, e, window, x, d, \u3056){print( /x/g );}/*iii*/a0.pop(); }  }  } else  if ( '' ) decodeURI;");
/*fuzzSeed-202342322*/count=92; tryItOut("mathy2 = (function(x, y) { return Math.fround(((Math.fround(Math.max(((x | (Math.cos(( + ( + ( + (y | 0))))) | 0)) >>> 0), ( ~ Math.fround(Math.log(( + x)))))) | 0) | Math.fround((( - ((((x ? (x >>> 0) : Math.atan2(Math.fround(Number.MIN_SAFE_INTEGER), x)) | 0) >>> (Number.MAX_SAFE_INTEGER | 0)) >>> 0)) >= ( ~ ((0x080000001 ? y : (42 & x)) >>> 0)))))); }); testMathyFunction(mathy2, [-0, 0.000000000000001, 2**53+2, -0x100000001, 0x07fffffff, -(2**53), Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000000, 0, 0x0ffffffff, -1/0, 0x080000000, -(2**53-2), -0x0ffffffff, 0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, 1.7976931348623157e308, 0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, 1/0, -(2**53+2), 42, 1]); ");
/*fuzzSeed-202342322*/count=93; tryItOut("/*RXUB*/var r = /(?:((?:[^]))(?:([^])))/m; var s = \"\"; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-202342322*/count=94; tryItOut("o2.m1.get(f0);");
/*fuzzSeed-202342322*/count=95; tryItOut("testMathyFunction(mathy4, [-0x07fffffff, 0x080000001, 0x07fffffff, -0x100000000, 0x0ffffffff, -(2**53), -Number.MAX_VALUE, 0x100000001, 0x080000000, 42, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000000, 0/0, 2**53-2, -0, -0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, -0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, 0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, 2**53, Math.PI, Number.MIN_VALUE]); ");
/*fuzzSeed-202342322*/count=96; tryItOut("\"use strict\"; /*infloop*/do {/*vLoop*/for (var uagbhq = 0; uagbhq < 62; ++uagbhq) { let b = uagbhq; g1.t2.set(t0, 3); }  } while((/*UUV1*/(w.imul = b => window)));");
/*fuzzSeed-202342322*/count=97; tryItOut("return;let(w, {window: [, , x], x: x, y, y: []} = x, c = ( /* Comment */new RegExp(\"(?=(?:(\\\\1))+)\", \"m\"))) { x = e;}");
/*fuzzSeed-202342322*/count=98; tryItOut("/*vLoop*/for (var nlirvq = 0; nlirvq < 50; ++nlirvq) { let a = nlirvq; print(a1);\n\"\\u9125\";\n } ");
/*fuzzSeed-202342322*/count=99; tryItOut("m1.set(t0, v2);");
/*fuzzSeed-202342322*/count=100; tryItOut("t2.__proto__ = e2\n");
/*fuzzSeed-202342322*/count=101; tryItOut("let w = (Root(window).watch(\"call\", function  z (x, {}, x, z, x, x, b = x, \u3056, w, x, x = new RegExp(\"(?=((?:\\\\w|[^\\\\u0050-\\\\u007e\\u1598]{64,}\\u3c63|\\\\x41+))){4,7}\", \"i\"), x, window = \"\\uE346\", eval = \"\\uD865\", y, NaN, y = null, x, ...set)\"use asm\";   var imul = stdlib.Math.imul;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -9.44473296573929e+21;\n    var d3 = 590295810358705700000.0;\n    var d4 = -137438953471.0;\n    var d5 = -2199023255553.0;\n    var d6 = -262144.0;\n    d1 = (+(((0x7e78325a)-(-0x8000000)) & (((((1)) ^ ((0x51a4ff43)-((-8388609.0) >= (-1099511627777.0)))) >= (~((~((0xc6b08aad))) / (imul((0xfededdb9), (0xdfcc8748))|0))))-(0xa1a78aa0))));\n    d5 = (1.0);\n    {\n      (Float64ArrayView[1]) = ((d0));\n    }\n    d0 = (+(((0x396229b1)+((((d2)) / ((((-16777217.0)) % ((-17179869185.0))))) > (d3))+((d3) >= (-65537.0)))>>>((0xff571a95))));\n    d3 = (+(-1.0/0.0));\n    d4 = (d1);\n    {\n      d1 = (d5);\n    }\n    return +((d4));\n  }\n  return f;)), b = [(new ( /x/ )(\u3056))true for (x in \"\\uB78B\")].link(new RegExp(\"(?!(?:\\\\B.){8388609,8388610})|[^]+?\", \"gym\")), z, x, a;print([,,z1]);");
/*fuzzSeed-202342322*/count=102; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + (Math.max(( + (Math.atan(( + Math.fround(Math.fround(( ~ (y | 0)))))) >>> 0)), ((( + (Math.fround(Math.atan2(( - y), ( ~ 1))) >>> 0)) >>> 0) | 0)) | 0)) !== ( + Math.pow((Math.sinh(Math.atan2((Math.fround(( ! Math.fround(42))) >>> 0), (((( ! x) | 0) | 0) & (x >>> 0)))) | 0), Math.log1p((Math.log1p(0) | 0)))))); }); testMathyFunction(mathy0, [Math.PI, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0/0, 0x080000000, 0x080000001, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, -0x080000000, 1/0, -(2**53+2), 2**53+2, 2**53-2, -0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 42, 0x100000001, -0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0, Number.MAX_VALUE, 2**53, -0x100000000, -0, -0x100000001, -0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, 1]); ");
/*fuzzSeed-202342322*/count=103; tryItOut("\"use strict\"; ;");
/*fuzzSeed-202342322*/count=104; tryItOut("\"use strict\"; g2.v1 = r1.exec;");
/*fuzzSeed-202342322*/count=105; tryItOut("{g0.p2 = o2.g2.objectEmulatingUndefined();\nprint( /x/g );\n/*RXUB*/var r = /((?:([^\\b-\\b\\S]|[])[^]|.*))((?=[^]+|(?:(\\1))))+/yim; var s = \"\\n\\n\\u7bca\\u7bca\\u7bca\\n\\u3486\\n\\n\\u7bca\\u7bca\\u7bca\\n\\u3486\\n\\n\\u7bca\\u7bca\\u7bca\\n\\u3486\\n\\n\\u7bca\\u7bca\\u7bca\\n\\u3486\"; print(s.search(r));  }");
/*fuzzSeed-202342322*/count=106; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x080000000, -(2**53), -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, -(2**53+2), -0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, -0x100000000, -0, 0x100000001, -1/0, 0, 0x0ffffffff, 1, 0/0, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, -0x100000001, 2**53, 2**53+2, 0.000000000000001, 1.7976931348623157e308, Math.PI]); ");
/*fuzzSeed-202342322*/count=107; tryItOut("/*RXUB*/var r = /((?!((?=.|\\u0010[^](?:.|[^]))))){3,}[^]/gim; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-202342322*/count=108; tryItOut("testMathyFunction(mathy2, [0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -(2**53), Math.PI, 0x07fffffff, 2**53+2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, 42, -(2**53+2), Number.MAX_VALUE, 1, -0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, 2**53-2, 0x100000000, -0x100000001, 0, Number.MIN_VALUE, 0.000000000000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, 0x0ffffffff, 2**53, -0x0ffffffff, 1/0]); ");
/*fuzzSeed-202342322*/count=109; tryItOut("g0.offThreadCompileScript(\"print(x);i2.send(this.v0);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: Math.max(x, 1842685648), noScriptRval: (x % 17 == 5), sourceIsLazy: false, catchTermination: [] = (void shapeOf(delete w.x)), sourceMapURL: s1 }));");
/*fuzzSeed-202342322*/count=110; tryItOut("\"use strict\"; M:while((x) && 0)a1.push(null, m2, this);");
/*fuzzSeed-202342322*/count=111; tryItOut("o1 + p0;");
/*fuzzSeed-202342322*/count=112; tryItOut("let (b) { for (var v of g2.s1) { try { a1 = (let (x) Math.cosh(3349484025)) for ((arguments[window]) in Math.max(0, (\u3056.valueOf(\"number\")))) for each (z in x) if (/*UUV1*/(\"-16\".raw = function(y) { \"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2+|(?![^]|\\\\D|\\\\s{1,}?)?(?!(?:[^]?$|^|[^]{0,3}){0,3})\\\\2\", \"yim\"); var s = \"o\"; print(s.split(r)); print(r.lastIndex);  })); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(m1, a0); } catch(e1) { } try { o0 = new Object; } catch(e2) { } t2 = t1.subarray(1); } }");
/*fuzzSeed-202342322*/count=113; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy0((Math.sqrt((mathy0(Math.log2(x), (mathy1(((x == y) | 0), (y | 0)) | 0)) <= ( - (x >>> 0)))) >>> 0), (((( + y) == y) === Math.hypot(( + -0x100000001), ( ~ Number.MIN_VALUE))) ? ( - Math.fround(y)) : ((Math.min((x | 0), (x | 0)) | 0) >= mathy2(Math.fround((( + 1) != (((y | 0) ? (y | 0) : (x | 0)) | 0))), (-1/0 | 0))))); }); ");
/*fuzzSeed-202342322*/count=114; tryItOut("\"use strict\"; v0 = evaluate(\"p2.__proto__ = v0;\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 68 != 39), noScriptRval: true, sourceIsLazy: (({b: (function shapeyConstructor(zsxeen){Object.preventExtensions(zsxeen);return zsxeen; }(false)).is((4277))})), catchTermination: (x % 32 != 8) }));");
/*fuzzSeed-202342322*/count=115; tryItOut("\"use strict\"; v1 = (i1 instanceof h0);");
/*fuzzSeed-202342322*/count=116; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.asinh((Math.log1p(( ! (Math.imul((mathy2(x, (( + (x | 0)) >>> 0)) | 0), (Math.cos((Math.acos(( + 2**53)) | 0)) | 0)) | 0))) | 0)) | 0); }); ");
/*fuzzSeed-202342322*/count=117; tryItOut("Array.prototype.reverse.apply(a0, [b0]);");
/*fuzzSeed-202342322*/count=118; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.fround(mathy0(Math.fround(( ! y)), Math.fround(( ! (( + (Math.atan2((mathy0(((((y >>> 0) + (x >>> 0)) >>> 0) | 0), (x | 0)) | 0), (x | 0)) << Math.atanh(Math.asin(( + x))))) >>> 0))))) - (Math.fround(Math.pow((Math.log(( + x)) | 0), ( + mathy0(( + Math.cbrt(( + y))), ( + ( ! (y | 0))))))) ? mathy0(mathy0(y, x), (Math.acosh(mathy0((Math.trunc(y) >>> 0), -0x07fffffff)) | 0)) : ((Math.cosh((Math.fround(( + Math.fround(x))) && Math.imul((x && x), -Number.MIN_VALUE))) >>> 0) | 0))); }); testMathyFunction(mathy1, [-0x07fffffff, 2**53, 2**53-2, 0, -0x080000001, 42, Math.PI, 0x07fffffff, -0x100000000, -0, -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, -0x100000001, 0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, -(2**53-2), Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, 0/0, -(2**53+2), -(2**53), 1, -0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-202342322*/count=119; tryItOut("mathy3 = (function(x, y) { return Math.sinh(Math.fround(((Math.fround(Math.cos(((Math.min((x >>> 0), (x >>> 0)) >>> 0) % Math.atan2(y, /*tLoop*/for (let c of /*MARR*/[new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]) { g2.v0 = new Number(NaN); })))) == Math.imul(Math.log2((( + (( + y) * ( + y))) >>> 0)), y)) >>> 0))); }); ");
/*fuzzSeed-202342322*/count=120; tryItOut("testMathyFunction(mathy1, [2**53-2, 2**53+2, 0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, 0x080000001, -0x080000000, -0x100000001, -(2**53-2), 42, -0x0ffffffff, 1, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, 0x100000000, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, -(2**53), 0x100000001, -0, 0x080000000, -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE]); ");
/*fuzzSeed-202342322*/count=121; tryItOut("m0.delete(e1);");
/*fuzzSeed-202342322*/count=122; tryItOut("\"use strict\"; this.v1 = (f0 instanceof g2);");
/*fuzzSeed-202342322*/count=123; tryItOut("\"use strict\"; \"use asm\"; for (var p in t2) { try { v1 = Array.prototype.every.apply(a0, [(function() { try { var o0 = {}; } catch(e0) { } try { b0 = g2.t1.buffer; } catch(e1) { } a2.forEach((function() { try { /*MXX2*/this.g1.Promise.all = v0; } catch(e0) { } Array.prototype.splice.call(o1.a0, 4, 9); return h2; }), b0, p0, Math.max(eval(\"testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x080000001, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, 0, -0, Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), -0x080000001, 0x07fffffff, 42, 1/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 1, 0/0, Number.MAX_VALUE, 0x100000000, 0x100000001, -0x0ffffffff, 2**53+2, -0x080000000, 2**53-2, -Number.MAX_VALUE, -0x07fffffff, -1/0, -(2**53), 0x0ffffffff, -0x100000000, 0.000000000000001]); \"), 12), s2); return o1.b1; }), t2, p2, /*MARR*/[new String('q'), new String('q'),  \"use strict\" ,  \"use strict\" , new String('q'), new String('q'), new String('q'),  \"use strict\" ,  \"use strict\" , new Boolean(true)].sort]); } catch(e0) { } print(v1); }");
/*fuzzSeed-202342322*/count=124; tryItOut("\"use strict\"; return;");
/*fuzzSeed-202342322*/count=125; tryItOut("e1.has(v0);");
/*fuzzSeed-202342322*/count=126; tryItOut("\"use strict\"; e2.delete(t2);");
/*fuzzSeed-202342322*/count=127; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-202342322*/count=128; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.max(Math.fround(( + Math.clz32(( + ( + Math.hypot(Math.fround(( + 0x080000000)), Math.round((y >>> 0)))))))), Math.fround(Math.max((Math.atan2((( ! -0x100000000) | 0), ((((( ! 0x100000000) >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0) | 0)) >>> 0), Math.fround(( + Math.fround(x))))))); }); testMathyFunction(mathy0, [1/0, -0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000001, -0, -0x100000000, 0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -(2**53+2), -Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, Math.PI, 42, 0/0, Number.MAX_VALUE, -1/0, -0x080000000, 2**53, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, 2**53-2, 1, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=129; tryItOut("Object.defineProperty(y, \"0\", ({value: new (Uint8ClampedArray)(((void options('strict'))), 'fafafa'.replace(/a/g, (runOffThreadScript).bind(\"\\uDBB7\", this))), writable: true, configurable: /*UUV1*/(x.setMinutes = function(y) { g0.offThreadCompileScript(\"([x = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), DataView.prototype.setInt16)])\"); }), enumerable: x **= [,,] ^ null}))");
/*fuzzSeed-202342322*/count=130; tryItOut(" for (var y of ((void shapeOf(intern(null))))) {print(y);Array.prototype.unshift.apply(this.a0, [m0, t0, s1]); }");
/*fuzzSeed-202342322*/count=131; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow(((((x >= (Math.imul((y < (( ~ Math.log10(y)) | 0)), ((Math.fround((y | 0)) | 0) >>> 0)) >>> 0)) >>> 0) === (Math.fround(( + ((Math.abs(-0x100000001) << Math.log(( + ( + ( + x))))) | 0))) >>> 0)) >>> 0), (Math.cbrt(Math.max(Math.pow(y, (x % ( + x))), Math.atan2(-0x100000001, ( + (((-(2**53-2) >>> 0) / (y >>> 0)) >>> 0))))) | 0)); }); testMathyFunction(mathy0, [-1/0, -0, Math.PI, 42, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 2**53, 2**53-2, 0x080000000, 0x07fffffff, -(2**53), 1, 0x0ffffffff, 0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, 1/0, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), -0x080000000, 0x080000001, -Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-202342322*/count=132; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.min((Math.atan2(((((((( + y) ? -0x07fffffff : ((Math.atan2(y, x) >>> 0) | 0)) >>> 0) > (y >>> 0)) >>> 0) >> x) | ( - Math.fround(( ! Math.fround(Math.fround((Math.fround((Math.sinh(y) | 0)) ^ (Math.min((y >>> 0), (y >>> 0)) >>> 0)))))))), Math.fround(( ~ Math.fround(Number.MAX_VALUE)))) | 0), Math.fround(( ! ( - (( + ( ! (-Number.MAX_VALUE >>> 0))) >>> 0))))) >>> 0); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, -0x100000000, -0x100000001, 0, -(2**53), 42, 2**53-2, 0x080000001, Number.MAX_VALUE, 2**53, -0, Math.PI, 0x100000001, -0x0ffffffff, 1/0, 0.000000000000001, -0x080000000, -(2**53+2), -Number.MIN_VALUE, -(2**53-2), -0x07fffffff, 1, -1/0, 1.7976931348623157e308, 0x080000000, 0/0, 0x100000000]); ");
/*fuzzSeed-202342322*/count=133; tryItOut("\"use strict\"; g2.a1[1] = this;");
/*fuzzSeed-202342322*/count=134; tryItOut("mathy2 = (function(x, y) { return (( + (Math.asinh(y) >>> 0)) - (Math.sinh(mathy1(mathy1(y, x), y)) << Math.min(Math.pow(Math.acosh(( + (0x0ffffffff << ( + Math.fround(Math.atanh(Math.fround(0x080000001))))))), ( + Math.log10(x))), Math.fround(( + Math.sign((( + Math.asinh(( + x))) >>> 0))))))); }); testMathyFunction(mathy2, [-(2**53+2), -1/0, -0x07fffffff, 0x100000000, -(2**53-2), -0x100000000, 1/0, -Number.MIN_VALUE, Math.PI, 1.7976931348623157e308, 0x07fffffff, 2**53, 0x0ffffffff, -0, -0x080000001, 2**53+2, -0x100000001, -0x080000000, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53-2, -(2**53), 0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, 0, 1, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-202342322*/count=135; tryItOut("for (var p in i1) { a2.sort((function mcc_() { var yuyfnv = 0; return function() { ++yuyfnv; if (true) { dumpln('hit!'); try { for (var v of v0) { i1.send(e2); } } catch(e0) { } try { Object.freeze(m2); } catch(e1) { } try { e1 = new Set(o2.o2); } catch(e2) { } /*RXUB*/var r = r2; var s = \"\\u00ea\"; print(r.test(s));  } else { dumpln('miss!'); g0.offThreadCompileScript(\"\\\"use strict\\\"; print(x);\"); } };})()); }");
/*fuzzSeed-202342322*/count=136; tryItOut("\"use strict\"; var x = let (y = (allocationMarker())) (new RegExp(\"(?=(?:[^]|.|[^]){4})|(?!(?=\\\\x09){2,})|\\\\1|[^]*?*\", \"y\")\n), fjctmw, x, setter, quqgep, x, udvygs;;\nprint(x);\n");
/*fuzzSeed-202342322*/count=137; tryItOut("for (var v of this.a2) { try { /*RXUB*/var r = r0; var s = g0.s1; print(r.test(s));  } catch(e0) { } try { s2 += 'x'; } catch(e1) { } try { g1 = a0[0]; } catch(e2) { } this.p0.toSource = (function(j) { if (j) { try { for (var v of h2) { /*RXUB*/var r = r2; var s = s0; print(s.search(r));  } } catch(e0) { } try { h2 + s2; } catch(e1) { } try { /*oLoop*/for (var kvnext = 0; kvnext < 30; ++kvnext) { v2 = g1.runOffThreadScript(); }  } catch(e2) { } g2.offThreadCompileScript(\"v2 = o0.g0.eval(\\\"mathy5 = (function(stdlib, foreign, heap){ \\\\\\\"use asm\\\\\\\";   var abs = stdlib.Math.abs;\\\\n  var ff = foreign.ff;\\\\n  function f(i0, i1)\\\\n  {\\\\n    i0 = i0|0;\\\\n    i1 = i1|0;\\\\n    var i2 = 0;\\\\n(x);    {\\\\n      /*FFI*/ff(((~~(67108865.0))), ((((i1)) ? (2147483649.0) : (+abs(((-1.001953125)))))));\\\\n    }\\\\n    /*FFI*/ff();\\\\n    i0 = (i1);\\\\n    {\\\\n      i0 = (((((-3.022314549036573e+23) != (+(-1.0/0.0)))) | ((0x2bbe4c87) % (0x588a158e))) <= (((i2)) >> ((i2)+(i1)-(i0))));\\\\n    }\\\\n    i0 = (i1);\\\\n    return (((i1)+(/*FFI*/ff(((~~(-4095.0))), ((+(1.0/0.0))), ((((i2)) | ((new \\\\\\\"\\\\\\\\u299C\\\\\\\"( /x/ , window) * (new OSRExit(x, (function ([y]) { })())))))), (((((0x6661fd57)))|0)))|0)))|0;\\\\n  }\\\\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: new Function, get: ArrayBuffer.prototype.slice, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: Array.prototype.toString, enumerate: undefined, keys: undefined, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, 0x080000001, -0x100000000, -0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -0, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, -0x080000001, 1.7976931348623157e308, 2**53-2, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 0/0, -0x100000001, -0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, Math.PI, 0x0ffffffff, -1/0, 0x100000000, -0x080000000, -Number.MAX_VALUE, -(2**53+2), 0, 2**53+2, 1, -(2**53)]); \\\");\"); } else { selectforgc(g1.o2); } }); }");
/*fuzzSeed-202342322*/count=138; tryItOut("\"use strict\"; g0.v1 = g2.eval(\"v2 = o2.t0.length;\");");
/*fuzzSeed-202342322*/count=139; tryItOut("s0 = x;");
/*fuzzSeed-202342322*/count=140; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.tanh(( ~ Math.fround(( + ((Math.hypot((( + ( - ( + Math.expm1(x)))) && y), ((Math.atanh((x >>> 0)) >>> 0) !== Math.clz32((Math.round(( + 0.000000000000001)) >>> 0)))) | 0) << (((y | 0) , ((( + 0x100000001) | 0) | 0)) | 0)))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, Math.PI, 1/0, 0x080000001, 2**53, 0x080000000, 0, Number.MIN_VALUE, Number.MAX_VALUE, 42, -0x100000001, 2**53-2, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, -1/0, -0x0ffffffff, 0x100000000, 0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, 0x07fffffff, -0x080000001, 2**53+2, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53), 1]); ");
/*fuzzSeed-202342322*/count=141; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (((mathy2(((( + Math.fround(( - x))) | 0) >>> 0), ( + (( + Math.asinh((( ~ (-0 >>> 0)) >>> 0))) && Math.fround(mathy2(( + Math.imul(Math.fround(mathy1(Math.fround(x), Math.fround(y))), x)), Math.fround(( ! (x == y)))))))) >>> 0) | 0) ? (( + Math.acosh((Math.min(((mathy3(Math.fround(( + mathy3(( + x), ( + x)))), (( + Math.min(( + ( + Math.sqrt(x))), -1/0)) >>> 0)) >>> 0) ? ( + ( + ( + mathy3(x, x)))) : Math.clz32(x)), ( - Math.tanh((mathy1((-0x100000001 | 0), (y | 0)) | 0)))) | 0))) | 0) : ( + (((mathy1((x | 0), (mathy3((( - Math.fround(-0x0ffffffff)) >>> 0), Math.fround(( - Math.imul(-0x100000000, x)))) | 0)) | 0) >>> 0) === ( + ( + mathy3(( - (((x | 0) ? (y | 0) : (-0x080000000 | 0)) | 0)), Math.exp(-(2**53+2))))))))); }); testMathyFunction(mathy4, /*MARR*/[]); ");
/*fuzzSeed-202342322*/count=142; tryItOut("\"use strict\"; i1.next();");
/*fuzzSeed-202342322*/count=143; tryItOut("mathy0 = (function(x, y) { return Math.log10(((Math.imul(Math.imul(x, (Math.exp(((( + x) / ( + x)) | 0)) | 0)), (( - ( + x)) ** (( + Math.imul(( + y), ( + Math.asinh(2**53)))) ? -0x07fffffff : ((Math.fround(Math.pow(Math.fround(Number.MAX_VALUE), ( + (( + y) <= ( + y))))) || ((Math.acos(-Number.MAX_SAFE_INTEGER) >> (y >>> 0)) >>> 0)) | 0)))) | 0) >>> 0)); }); testMathyFunction(mathy0, [2**53+2, 0x100000000, 2**53, -0x100000000, 0/0, 0x100000001, -1/0, Number.MAX_VALUE, -0, 1/0, 1, -(2**53), -Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, 0x080000001, 0x07fffffff, 2**53-2, -0x07fffffff, 0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -0x080000001, -(2**53-2), 42, 0, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-202342322*/count=144; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((((/*FFI*/ff(((-2.4178516392292583e+24)), ((((0xda21715f)-(0xf95033ba)) & (-0xa342*(0xff1b7f53)))), ((((-9223372036854776000.0)) / ((-67108865.0)))), ((-1.1805916207174113e+21)), ((-1.5)), ((140737488355329.0)), ((549755813889.0)), ((1073741825.0)), ((576460752303423500.0)))|0)*0x6a16d) ^ (-(0xae13cda4))) == (((i0)+(!(i1))) & (-0xa4466*(0x43485bda))));\n    return (((0x274367d6) / ((((((x))>>>((i0)+(i1))))*-0xfffff)>>>(((0xffffffff))+((0xb497a3f1))-(i0)))))|0;\n  }\n  return f; })(this, {ff: q => q}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [(new Boolean(true)), null, (new Number(-0)), '/0/', ({toString:function(){return '0';}}), NaN, [0], 0, (new String('')), -0, (function(){return 0;}), '0', objectEmulatingUndefined(), '', /0/, 1, (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Number(0)), false, true, ({valueOf:function(){return 0;}}), 0.1, undefined, '\\0', []]); ");
/*fuzzSeed-202342322*/count=145; tryItOut("v0 = (t2 instanceof p1);");
/*fuzzSeed-202342322*/count=146; tryItOut("\"use asm\"; print(x);");
/*fuzzSeed-202342322*/count=147; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[Infinity, Infinity, [1], true, [1], [1], true, [1], Infinity, true, true, true, true, objectEmulatingUndefined(), true, Infinity, [1], true, Infinity, true, [1], [1], true, Infinity, [1], [1], objectEmulatingUndefined(), Infinity, Infinity, Infinity, true, Infinity, Infinity, [1], [1], [1], objectEmulatingUndefined(), [1], Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, true, true, Infinity, true, [1]]); ");
/*fuzzSeed-202342322*/count=148; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i1, b1);");
/*fuzzSeed-202342322*/count=149; tryItOut("this.o2.h2 = ({getOwnPropertyDescriptor: function(name) { f2 = x;; var desc = Object.getOwnPropertyDescriptor(p2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { t2[1] = \n/\\3|(?:[\u00e8\\D\u678d])*[^]{2}|\\d{512,}|\\uDbEF((?=.|.))\\3/gym;; var desc = Object.getPropertyDescriptor(p2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v2 = (i1 instanceof i0);; Object.defineProperty(p2, name, desc); }, getOwnPropertyNames: function() { h0.delete = WeakSet.prototype.add.bind(this.a0);; return Object.getOwnPropertyNames(p2); }, delete: function(name) { i2.toSource = (function() { a2.shift(b0, v0, o0.t2, o0.f1); return h1; });; return delete p2[name]; }, fix: function() { h2 = ({getOwnPropertyDescriptor: function(name) { /*MXX3*/g0.RegExp.$1 = g0.RegExp.$1;; var desc = Object.getOwnPropertyDescriptor(t1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { for (var v of p0) { try { v1 = -0; } catch(e0) { } try { let v1 = g1.runOffThreadScript(); } catch(e1) { } /*MXX3*/this.g0.Date.prototype.getUTCDay = g1.Date.prototype.getUTCDay; }; var desc = Object.getPropertyDescriptor(t1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v2 = a1.length;; Object.defineProperty(t1, name, desc); }, getOwnPropertyNames: function() { Array.prototype.shift.call(a0, i1, m2, h0);; return Object.getOwnPropertyNames(t1); }, delete: function(name) { Array.prototype.shift.apply(a2, []);; return delete t1[name]; }, fix: function() { v2 = (o0.e0 instanceof h0);; if (Object.isFrozen(t1)) { return Object.getOwnProperties(t1); } }, has: function(name) { t0[11] = i0;; return name in t1; }, hasOwn: function(name) { s1 += s0;; return Object.prototype.hasOwnProperty.call(t1, name); }, get: function(receiver, name) { this.o2.e0 = x;; return t1[name]; }, set: function(receiver, name, val) { v0 = o1.o0.a1.length;; t1[name] = val; return true; }, iterate: function() { p1.valueOf = f0;; return (function() { for (var name in t1) { yield name; } })(); }, enumerate: function() { b1 = new SharedArrayBuffer(40);; var result = []; for (var name in t1) { result.push(name); }; return result; }, keys: function() { this.h0.delete = f0;; return Object.keys(t1); } });; if (Object.isFrozen(p2)) { return Object.getOwnProperties(p2); } }, has: function(name) { b2 = t0.buffer;; return name in p2; }, hasOwn: function(name) { delete g2.h0.fix;; return Object.prototype.hasOwnProperty.call(p2, name); }, get: function(receiver, name) { g1.a1.push(v0);; return p2[name]; }, set: function(receiver, name, val) { b1.toSource = (function(j) { if (j) { try { Object.freeze(h0); } catch(e0) { } try { v2 = (function ([y]) { }.__defineGetter__(\"window\", /*wrap1*/(function(){ g0.toSource = (function mcc_() { var qcwxbf = 0; return function() { ++qcwxbf; g2.f1(/*ICCD*/qcwxbf % 11 == 8);};})();return (let (e=eval) e)})())); } catch(e1) { } a2 = r0.exec(g2.s2); } else { try { v1 = a2.length; } catch(e0) { } try { a0 + ''; } catch(e1) { } Array.prototype.pop.call(a1); } });; p2[name] = val; return true; }, iterate: function() { this.o0.__proto__ = o1.o0;; return (function() { for (var name in p2) { yield name; } })(); }, enumerate: function() { Object.defineProperty(this, \"v2\", { configurable: allocationMarker(), enumerable: false,  get: function() {  return Array.prototype.reduce, reduceRight.apply(a1, [(function() { for (var j=0;j<3;++j) { f1(j%5==1); } }), o1.e2, m2]); } });; var result = []; for (var name in p2) { result.push(name); }; return result; }, keys: function() { v1 = (e0 instanceof f2);; return Object.keys(p2); } });");
/*fuzzSeed-202342322*/count=150; tryItOut("Array.prototype.forEach.call(a1, (function() { this.s2 += s1; return f0; }));c = -8.yoyo(x);");
/*fuzzSeed-202342322*/count=151; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a1, 8, ({value: WebAssemblyMemoryMode(new RegExp(\"[^][][^\\\\cW-\\u8a7a\\u4f2b\\\\s]+$*|(?:\\\\B|(?!(?:\\\\B)))[^]{4}\", \"yi\")).unwatch(\"__count__\"), configurable: true}));");
/*fuzzSeed-202342322*/count=152; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=153; tryItOut("v2 = evalcx(\"this.h0.get = f2;\\n/*infloop*/do t2.set(a0, x); while(new RegExp(\\\"(?!^*?[^].{2,})+?\\\", \\\"gm\\\"));\\n\", o0.o1.g0);");
/*fuzzSeed-202342322*/count=154; tryItOut("e0.add(g1);");
/*fuzzSeed-202342322*/count=155; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.log2((Math.trunc(Math.max(((( ! (x >>> 0)) >>> 0) ? Math.trunc(0.000000000000001) : x), Math.max(( + Math.imul(y, (((y | 0) < (y | 0)) | 0))), y))) | 0))); }); testMathyFunction(mathy0, /*MARR*/[(void 0), this, (void 0), this, (void 0), (void 0), this, this, (void 0), (void 0), this, (void 0), this, this, (void 0), this, (void 0), this, this, (void 0), this, (void 0), (void 0), (void 0), (void 0), (void 0), this, this, (void 0), this, this, this, this, (void 0)]); ");
/*fuzzSeed-202342322*/count=156; tryItOut("g2.g0.t0 = new Uint8ClampedArray(a2);g2.a2.splice(NaN, 5, a2, e0);");
/*fuzzSeed-202342322*/count=157; tryItOut("Object.defineProperty(this, \"o0\", { configurable: (x % 3 == 1), enumerable: false,  get: function() { a1 = []; return {}; } });Array.prototype.sort.apply(a0, [f2, i0]);");
/*fuzzSeed-202342322*/count=158; tryItOut("for (var p in p1) { v0 = Object.prototype.isPrototypeOf.call(g0, o2); }");
/*fuzzSeed-202342322*/count=159; tryItOut("null || null;");
/*fuzzSeed-202342322*/count=160; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((((i1)-(0x308d3952)) & ((0xfde901c5)-(i1))) >= (~((imul(((288230376151711740.0) <= (-2097153.0)), (0xd6bd491a))|0) % ((((0x9fe6e934))) >> ((((0xffffffff)) ^ ((0xa3f4f91c))) % (((0x9294409f)) >> ((0x28934cb3))))))));\n    i1 = (((0xfffff*((d0) >= (+(-1.0/0.0))))|0));\n    d0 = (-1.9342813113834067e+25);\n    {\n      d0 = (d0);\n    }\n    (Int8ArrayView[2]) = ((!((~((0xee54c158)*-0x5562a)))));\n    return +((d0));\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000000, -(2**53+2), 0x100000000, 0x07fffffff, 2**53+2, 1, 0x100000001, Number.MAX_VALUE, -0, 2**53, -0x080000000, 2**53-2, Math.PI, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, 0.000000000000001, -(2**53-2), -0x100000001, -0x07fffffff, -1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 42, 0x0ffffffff, 0, -0x080000001, 1/0]); ");
/*fuzzSeed-202342322*/count=161; tryItOut("(/[^\\cX-\\u0034\\u00cC-`]|((?![^]|\\S))|\\S((?:\\1{5}))/gym);");
/*fuzzSeed-202342322*/count=162; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( - ((((Math.min(( + y), ( + Math.tan(( + y)))) | 0) ** (Math.fround(( ~ ( ! ( + ((((mathy1(Math.fround(( ~ 0)), (0x080000001 >>> 0)) >>> 0) >>> 0) & (Math.sinh(y) >>> 0)) >>> 0))))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x07fffffff, 1/0, Math.PI, 2**53+2, -Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1, -(2**53), -0x0ffffffff, -(2**53+2), -0x080000001, Number.MAX_VALUE, 0x100000001, 0x0ffffffff, 0x080000001, 0x100000000, 2**53-2, -1/0, -Number.MIN_VALUE, -0x080000000, 2**53, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -(2**53-2), 42, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0, -0]); ");
/*fuzzSeed-202342322*/count=163; tryItOut("\"use strict\"; g2.v1 = g0.runOffThreadScript();print(x);");
/*fuzzSeed-202342322*/count=164; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.max(( + ( ~ ( + Math.exp(( + (Math.tan((( - x) >>> 0)) | 0)))))), ( + ( - Math.pow(x, (Math.log10(Math.pow(( + (x ? y : Math.fround(y))), (-0x0ffffffff >>> 0))) ** Math.cbrt(x))))))); }); testMathyFunction(mathy0, [1, -1/0, 0x080000001, 42, -Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, -0x080000000, 0, 2**53-2, 0/0, -0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), 0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x100000001, 0x080000000, -0x100000000, -Number.MIN_VALUE, -(2**53+2), -0x080000001, 0x100000001, 0.000000000000001, 0x100000000, 0x07fffffff, Math.PI]); ");
/*fuzzSeed-202342322*/count=165; tryItOut("\"use strict\"; g2.o0.s1 = new String(g2.o2.e0);");
/*fuzzSeed-202342322*/count=166; tryItOut("let (y) { v0 = false; }");
/*fuzzSeed-202342322*/count=167; tryItOut("\"use strict\"; /*MXX2*/o1.g0.g0.Uint8ClampedArray.prototype = v2;");
/*fuzzSeed-202342322*/count=168; tryItOut("let ([] = x, x = (a--), x = x = window) { v1 = evalcx(\"(void schedulegc(g0.g1));\", g0); }");
/*fuzzSeed-202342322*/count=169; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=170; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy2((Math.tanh((((( + (Math.acos(-(2**53+2)) | 0)) >> ( + Math.hypot(x, Math.fround((Math.fround(y) && Math.fround(x)))))) >>> 0) * x)) >>> 0), ((Math.atan2(Math.round(Math.fround(( + (x >>> 0)))), ((0x100000001 | 0) != mathy0((0x100000001 ** Math.PI), Math.fround(mathy1(Math.fround(y), Math.fround(x)))))) | 0) ? ( + ((((x / ((((y | 0) ? x : y) << (((y | 0) + x) >>> 0)) << Math.PI)) | 0) ** (-Number.MAX_SAFE_INTEGER | 0)) | 0)) : mathy0((( + Math.fround(( ~ ( + x)))) ^ (Math.sqrt((x >>> 0)) >>> 0)), (((x , Math.max(x, ((y ** x) >>> 0))) >>> 0) % Math.fround((Math.trunc((x >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [-0x100000001, 0x100000001, 0/0, 1/0, -0x0ffffffff, -0, -0x100000000, 1.7976931348623157e308, 2**53, 0, 2**53-2, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -0x07fffffff, -(2**53-2), 0.000000000000001, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 42, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, -0x080000001, -1/0, 0x080000001]); ");
/*fuzzSeed-202342322*/count=171; tryItOut("\"use strict\"; a2 = [];");
/*fuzzSeed-202342322*/count=172; tryItOut("\"use strict\"; Array.prototype.push.apply(this.a2, [p1, s0]);");
/*fuzzSeed-202342322*/count=173; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( ~ (mathy2((((Math.max(mathy0(( - x), Math.fround(y)), (((y >>> 0) / (( - y) >>> 0)) | 0)) >>> 0) != Math.max((y >>> 0), y)) | 0), Math.imul(( + x), (Math.max(Math.exp((0/0 >>> 0)), -0) , Math.acos(Math.atan2(x, x))))) | 0)); }); testMathyFunction(mathy4, [-(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, 2**53, -0x100000000, -Number.MIN_VALUE, 0x0ffffffff, 2**53-2, 0x100000001, -(2**53+2), 1, Math.PI, -0x080000001, 0.000000000000001, 0/0, Number.MIN_VALUE, 0x080000000, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, -0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 42, 0x080000001, -Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, 0, -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=174; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.asin((Math.imul(( + ( + ( + ( ! Math.fround(mathy0(Math.fround(mathy0(y, (( + ( ~ ( + x))) >>> 0))), Math.fround(y))))))), mathy0((Math.fround((Math.atanh((Math.fround(( ~ Math.fround(x))) | 0)) | 0)) >> ( + Math.log2(x))), Math.sqrt((Math.log10((y >>> 0)) >>> 0)))) | 0)); }); testMathyFunction(mathy1, /*MARR*/[new Boolean(true), (0/0), (0/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (0/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), new Boolean(true), (0/0), (0/0), (0/0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (0/0), (0/0), (0/0), new Boolean(true), (0/0), new Boolean(true), (0/0)]); ");
/*fuzzSeed-202342322*/count=175; tryItOut("s2 = s1.charAt(12);a0.forEach((function mcc_() { var xosgsp = 0; return function() { ++xosgsp; if (/*ICCD*/xosgsp % 8 != 1) { dumpln('hit!'); try { v2 = t1.byteOffset; } catch(e0) { } for (var p in g0.b0) { try { v0 = Object.prototype.isPrototypeOf.call(t0, i2); } catch(e0) { } try { Array.prototype.sort.apply(a0, [(function(j) { if (j) { try { print(a1); } catch(e0) { } try { Object.defineProperty(this, \"v0\", { configurable: true, enumerable: true,  get: function() {  return t2.length; } }); } catch(e1) { } v2 = evaluate(\"function this.f2(h2)  { ; } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 20 != 19) })); } else { try { g2 + this.g0; } catch(e0) { } try { o0 = new Object; } catch(e1) { } t0.__proto__ = t1; } })]); } catch(e1) { } try { print(uneval(i0)); } catch(e2) { } for (var v of this.o0.o2) { v1 = Object.prototype.isPrototypeOf.call(f2, b2); } } } else { dumpln('miss!'); try { s0 += 'x'; } catch(e0) { } try { /*MXX1*/o1 = g2.WeakMap.prototype.constructor; } catch(e1) { } try { this.b1 = t1[7]; } catch(e2) { } v0 = t2.byteOffset; } };})());");
/*fuzzSeed-202342322*/count=176; tryItOut("switch(x) { default: f2.__proto__ = p1;break; case  \"\" : v2 = g0.runOffThreadScript();break;  }");
/*fuzzSeed-202342322*/count=177; tryItOut("for (var p in g0.i1) { try { Object.defineProperty(this, \"h2\", { configurable: false, enumerable: false,  get: function() {  return {}; } }); } catch(e0) { } try { e1 = t0[v1]; } catch(e1) { } for (var v of s0) { try { v0 = g2.runOffThreadScript(); } catch(e0) { } try { a2.forEach((function(j) { if (j) { try { a1.shift(length, m0, p2); } catch(e0) { } try { i0 = new Iterator(g1); } catch(e1) { } try { e0.has(e2); } catch(e2) { } g1.s0 += 'x'; } else { try { a0 + this.f2; } catch(e0) { } o2.g2.offThreadCompileScript(\"function f0(f0) \\\"\\\\u0EC0\\\"\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 != 0), noScriptRval: (x % 33 != 29), sourceIsLazy: \"\\u180B\", catchTermination: (x % 6 == 5) })); } }), h1, o1); } catch(e1) { } v1 = Object.prototype.isPrototypeOf.call(e0, a1); } }\nprint(x);\n");
/*fuzzSeed-202342322*/count=178; tryItOut("Array.prototype.unshift.apply(a2, [m2, a1]);var v1 = false;");
/*fuzzSeed-202342322*/count=179; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; gcslice(15008); } void 0; } this.m0.get(p0);");
/*fuzzSeed-202342322*/count=180; tryItOut("testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, -0x0ffffffff, -0x080000000, -0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 0x080000001, 0.000000000000001, 2**53-2, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, -0x080000001, 0x0ffffffff, 0x07fffffff, -0, -1/0, -Number.MIN_VALUE, -(2**53), 0x100000000, Number.MAX_VALUE, -0x100000000, 0, -Number.MAX_VALUE, 1/0, Math.PI, -Number.MAX_SAFE_INTEGER, 0/0, 42, 1.7976931348623157e308, -0x100000001]); ");
/*fuzzSeed-202342322*/count=181; tryItOut("\"use strict\"; h2.delete = (function(j) { if (j) { try { v0 = let (c) (c) = \"\\uD3A5\" += x; } catch(e0) { } try { /*MXX1*/o2 = this.g2.Float32Array.prototype; } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(s2, i0); } catch(e2) { } o1.v0 = (x % 3 != 0); } else { g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: true })); } });");
/*fuzzSeed-202342322*/count=182; tryItOut("mathy4 = (function(x, y) { return ( - Math.fround(Math.ceil(Math.pow((Math.min(Math.fround(x), (x | 0)) >>> 0), Math.asinh((((Math.fround(Math.pow(y, x)) ? Math.fround(Math.fround(Math.asin((Number.MAX_VALUE >>> 0)))) : Math.fround(( + (y | 0)))) >>> 0) | 0)))))); }); ");
/*fuzzSeed-202342322*/count=183; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.sqrt(( - Math.pow(((Math.sign((y >>> 0)) >>> 0) | 0), Math.fround((Math.max(Math.fround(Math.min((0x080000000 | 0), (x >>> 0))), ( + Math.fround(( + y)))) >>> 0))))) > Math.max(Math.fround((( ! x) != Math.fround(Math.imul((1.7976931348623157e308 >>> 0), Math.fround(Math.fround((Math.fround(( ! 1)) % Math.imul((x >>> 0), Number.MAX_VALUE)))))))), Math.fround(Math.abs(( + ( + ((Math.pow(( + (((y >>> 0) && (( + (1 != (y | 0))) >>> 0)) >>> 0)), ((Math.hypot((Math.trunc((y >>> 0)) >>> 0), (2**53 >>> 0)) >>> 0) | 0)) >>> 0) >>> 0))))))); }); testMathyFunction(mathy2, [42, -0, 1.7976931348623157e308, -1/0, 2**53, 0/0, 0x100000001, 1/0, -(2**53+2), 0x080000001, -0x080000000, -0x0ffffffff, -(2**53-2), 0x080000000, -Number.MAX_VALUE, 0, -0x100000000, -Number.MIN_VALUE, 1, -(2**53), -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, -0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, 2**53+2, -0x07fffffff, 0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-202342322*/count=184; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=185; tryItOut("o0.h2.delete = f1;");
/*fuzzSeed-202342322*/count=186; tryItOut("e0.add(o0.o2);");
/*fuzzSeed-202342322*/count=187; tryItOut("\"use strict\"; i2.next();");
/*fuzzSeed-202342322*/count=188; tryItOut("mathy5 = (function(x, y) { return ( ! ( ! ( ! (x | 0)))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -(2**53), -0x07fffffff, 0, -0, Number.MIN_VALUE, 0/0, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, 2**53-2, 0x100000001, -(2**53+2), -0x0ffffffff, -0x080000001, 0.000000000000001, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, 2**53+2, -0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, Math.PI, 42, 1, 1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0]); ");
/*fuzzSeed-202342322*/count=189; tryItOut("\"use strict\"; e1.has(o0.t1);");
/*fuzzSeed-202342322*/count=190; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x100000000, 2**53+2, 42, 0x100000000, 0x080000000, 1.7976931348623157e308, -(2**53), 2**53-2, -(2**53-2), -0x0ffffffff, -0x080000001, -0x080000000, 1, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), 0x080000001, -1/0, -0, -0x100000001, 2**53, Math.PI, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, 0, 0x07fffffff, 0x100000001]); ");
/*fuzzSeed-202342322*/count=191; tryItOut("s1 += s1;");
/*fuzzSeed-202342322*/count=192; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use asm\"; return Math.tanh(((((Math.ceil(( - y)) >> (Math.fround(Math.fround(((Math.fround(x) > Math.fround(x)) % y))) - y)) >>> 0) ? (Math.acos(Math.imul(x, x)) >>> 0) : ((((x >= ( + y)) == ( + (0x080000001 - x))) ^ Math.fround(Math.acos(((Math.atan2((2**53+2 || (-1/0 | 0)), y) >>> 0) ^ Math.pow(y, y))))) | 0)) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new Boolean(true), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true)]); ");
/*fuzzSeed-202342322*/count=193; tryItOut("testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, 0x0ffffffff, -0x100000000, 0x080000001, Math.PI, 0x07fffffff, 0x080000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, -0x080000000, Number.MAX_SAFE_INTEGER, 1, -(2**53+2), 42, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_VALUE, 2**53, 0, -(2**53), 0x100000001, -1/0, 0x100000000, Number.MIN_VALUE, 2**53-2, -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001]); ");
/*fuzzSeed-202342322*/count=194; tryItOut("i0.toString = (function() { try { for (var p in a0) { try { v2 = r0.sticky; } catch(e0) { } try { v1 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 == 0), sourceIsLazy: Object.defineProperty(w, \"apply\", ({enumerable: false})), catchTermination: ({ set 24 x () { \"use strict\"; yield (Math.imul(null, (function ([y]) { })())) }  })() })); } catch(e1) { } try { i2 = a1[({valueOf: function() { s1[\"parseInt\"] = g2.b2;switch(\"\\uC8DD\") { case null: ddjmwm;print(x);case 4: case 7: break; print(x);break; case 27:  }return 0; }})]; } catch(e2) { } for (var p in o1.b1) { g1.g1.a1.reverse(b2, g2.m2); } } } catch(e0) { } a2 = a2.map((function() { for (var j=0;j<7;++j) { f2(j%3==1); } })); return m1; });");
/*fuzzSeed-202342322*/count=195; tryItOut("\"use strict\"; \"14\" = ((makeFinalizeObserver('nursery'))), eval, d = Math.trunc(-29), y, x, gtcqva, x = /*UUV2*/(NaN.delete = NaN.getSeconds);h1.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-202342322*/count=196; tryItOut("\"use strict\"; v0 = evalcx(\"h2 + t0;\", g0);");
/*fuzzSeed-202342322*/count=197; tryItOut("function shapeyConstructor(uilcfj){if (uilcfj) uilcfj[\"toExponential\"] = new RegExp(\"[^\\\\d](?:.|\\\\u0073){0,3}+?\", \"y\");Object.defineProperty(uilcfj, 5, ({configurable: window, enumerable: true}));Object.defineProperty(uilcfj, \"toUpperCase\", ({enumerable: false}));Object.freeze(uilcfj);if (uilcfj) Object.preventExtensions(uilcfj);if (-20) uilcfj[\"toExponential\"] =  \"\" ;uilcfj[\"toExponential\"] = Function;{ /*tLoop*/for (let w of /*MARR*/[null, Math.PI, this.NaN, this.NaN, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, this.NaN, Math.PI, 033, null, this.NaN, 033]) { print(\"\\uA652\"); } } { if(true) h0.__proto__ = g2; else print(x); } return uilcfj; }/*tLoopC*/for (let b of /*FARR*/[(4277)]) { try{let uputmi = new shapeyConstructor(b); print('EETT'); v1 = (s0 instanceof this.h2);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-202342322*/count=198; tryItOut("f1(g1);");
/*fuzzSeed-202342322*/count=199; tryItOut("mathy5 = (function(x, y) { return (( + (( + ((Math.min(x, 0x100000001) % (Math.fround(( ~ Math.fround(1))) >>> 0)) >>> 0)) / ( + (Math.sinh((Math.min((((( + (-0x080000000 | 0)) ? (y | 0) : (x | 0)) >>> 0) >>> 0), (mathy3((y << (0.000000000000001 === x)), mathy3(x, x)) >>> 0)) | 0)) | 0)))) ? ( ~ ( - ( + ((y ? Math.max(0x080000001, Math.fround(x)) : x) >= ( + x))))) : (Math.imul((( + Math.sin((y >>> 0))) === (x >>> 0)), ((y ? Math.fround(Math.imul(Math.fround(y), Math.fround(-0))) : (x ? (Math.asin((x >>> 0)) >>> 0) : y)) >>> 0)) == (Math.fround(( ~ Math.fround(0x080000000))) | 0))); }); testMathyFunction(mathy5, [0x07fffffff, 0, -1/0, -0x100000000, 0x100000000, 2**53, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, 0/0, -0x07fffffff, -(2**53+2), 2**53+2, 0x0ffffffff, -(2**53-2), Number.MIN_VALUE, -0x100000001, -(2**53), 42, -0, -Number.MIN_VALUE, 1, -0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 2**53-2]); ");
/*fuzzSeed-202342322*/count=200; tryItOut("throw new x();function x(x) { print(x); } o0.g0.v2 = g0.runOffThreadScript();");
/*fuzzSeed-202342322*/count=201; tryItOut("/*RXUB*/var r = /([\\w\\f]|\\cL+)/gim; var s = \"\\u000c\"; print(r.test(s)); ");
/*fuzzSeed-202342322*/count=202; tryItOut("s2 += 'x';");
/*fuzzSeed-202342322*/count=203; tryItOut("mathy4 = (function(x, y) { return (((( ! (((mathy1((y >>> 0), ((( + x) >>> 0) >>> 0)) >>> 0) , y) >>> 0)) & ( + mathy0(( ! (y >>> 0)), (Math.fround((Math.fround(Math.fround(( + ( + (((x >>> 0) ^ (y >>> 0)) | 0))))) >= (( ! (y | 0)) | 0))) | 0)))) === (Math.imul(Math.acos((Math.fround(y) | 0)), Math.fround(Math.imul(((Math.sin(Math.fround(y)) | 0) ? Math.log2((Math.log((Math.pow(y, (Math.PI | 0)) >>> 0)) >>> 0)) : x), (Math.min((( ~ y) | 0), (Math.fround(Math.pow(Math.fround(-0x080000001), x)) | 0)) >>> 0)))) | 0)) | 0); }); ");
/*fuzzSeed-202342322*/count=204; tryItOut("Array.prototype.push.apply(a2, [this.t0, f1, i0, v0, g0.m0]);");
/*fuzzSeed-202342322*/count=205; tryItOut("\"use strict\"; g1.i0.next();");
/*fuzzSeed-202342322*/count=206; tryItOut("/*tLoop*/for (let x of /*MARR*/[false, false, 1.3, false, 1.3, 1.3]) { e0.toString = f1;\n( /x/ .eval(\"for (var v of o0) { Array.prototype.push.call(a0, h1); }\"));\n }");
/*fuzzSeed-202342322*/count=207; tryItOut("\"use strict\"; var feihuo = new ArrayBuffer(12); var feihuo_0 = new Float32Array(feihuo); feihuo_0[0] = -9; neuterv2 + p0;(void schedulegc(g0));for (var p in a0) { e2.delete(function ([y]) { }); }v2 = (f2 instanceof p0);");
/*fuzzSeed-202342322*/count=208; tryItOut("\"use strict\"; g2.v0 = o2.o2.a1.some((function() { for (var j=0;j<8;++j) { f1(j%2==0); } }));");
/*fuzzSeed-202342322*/count=209; tryItOut("for(let w of (new ({/*TOODEEP*/})(-23)) for each (x in /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), window, window, new Boolean(false), window, new Number(1), window, window, new Boolean(false), new Number(1), [], [], new Boolean(false), new Number(1), window, [], [], [], window, [], [], [], [], [], [], [], [], new Number(1), function(){}, new Number(1), new Number(1), [], new Number(1), [], window, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, [], new Boolean(false), new Boolean(false), [], new Boolean(false), new Number(1), new Number(1), [], function(){}, new Boolean(false), new Boolean(false)]) for each (d in /*MARR*/[ \"\" ,  \"\" , 1.2e3,  \"\" , 1.2e3, 0x99,  \"\" , 1.2e3, 1.2e3,  /x/g , 1.2e3,  \"\" , 1.2e3, 0x99,  /x/g ,  /x/g , 0x99, 1.2e3,  /x/g , 1.2e3, 1.2e3,  \"\" ,  \"\" , 1.2e3,  \"\" ,  /x/g ,  \"\" ,  \"\" ,  \"\" , 1.2e3,  \"\" , 0x99, 1.2e3,  \"\" , 1.2e3, 0x99, 1.2e3, 1.2e3,  /x/g ,  \"\" , 0x99, 0x99,  \"\" ,  /x/g ,  /x/g ,  \"\" ,  /x/g ,  /x/g ,  \"\" ,  /x/g ,  /x/g ,  /x/g , 0x99,  /x/g , 0x99,  /x/g , 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  \"\" , 0x99,  \"\" ,  \"\" , 1.2e3, 1.2e3,  /x/g , 0x99, 0x99,  \"\" , 1.2e3, 1.2e3, 0x99, 0x99, 0x99])\u0009 for each (e in 18)) this.zzz.zzz = x;for(let d of /*MARR*/['fafafa'.replace(/a/g, q => q), new String('q'), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), new String('q'), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), new String('q'), new String('q'), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), new String('q'), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), new String('q'), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), 'fafafa'.replace(/a/g, q => q), new String('q'), new String('q')]) for(let b in new Array(23)) let(x) { let(d) ((function(){for (var v of b0) { try { /*RXUB*/var r = r2; var s = s2; print(s.search(r)); print(r.lastIndex);  } catch(e0) { } try { e0.__proto__ = o1.i1; } catch(e1) { } try { delete h2.hasOwn; } catch(e2) { } e1 + o1; }})());}");
/*fuzzSeed-202342322*/count=210; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=211; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( - ( + mathy3(( + ((( + (((( + x) ? ( + x) : ( + x)) >>> 0) ? ( - y) : (y | 0))) | 0) | Math.max((Math.pow(y, Math.min(0/0, (x / Number.MIN_SAFE_INTEGER))) >>> 0), Math.asinh((( - y) | 0))))), ( + ( + Math.imul(( + ( + y)), ( + ( ! Math.fround(Math.fround(Math.max(Math.fround(1.7976931348623157e308), y))))))))))) >>> 0); }); testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), undefined, objectEmulatingUndefined(), [0], ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (function(){return 0;}), (new Number(-0)), [], 0, '/0/', false, (new Boolean(false)), (new Number(0)), true, '', (new String('')), (new Boolean(true)), '\\0', NaN, -0, null, '0', 1, /0/, 0.1]); ");
/*fuzzSeed-202342322*/count=212; tryItOut("\"use strict\"; c = linkedList(c, 3417);");
/*fuzzSeed-202342322*/count=213; tryItOut("/*RXUB*/var r = new RegExp(\".\", \"y\"); var s = x; print(s.search(r)); ");
/*fuzzSeed-202342322*/count=214; tryItOut("{ void 0; verifyprebarriers(); }function c(x, x)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return ((((((1)-((((0xff7786f4))|0)))>>>((i2)-(i1))) == (((i1)+(i3)-((0xde54fe54) != (0xaefbec4b)))>>>((i1))))-(i2)))|0;\n  }\n  return f;let(pprtwf, wltgyf, bwikar, aqweum, zjjoag, x, NaN, qfagbd, bttuzr, eval) ((function(){d = b;})());arguments[3] = eval;");
/*fuzzSeed-202342322*/count=215; tryItOut("mathy1 = (function(x, y) { return (Math.cbrt(Math.sin(((Math.fround(Math.log10((((0x100000001 | 0) === (x | 0)) | 0))) / (( + (( + 2**53+2) >>> ( + y))) | 0)) | 0))) | 0); }); ");
/*fuzzSeed-202342322*/count=216; tryItOut("this.m2.set(m2, p0);");
/*fuzzSeed-202342322*/count=217; tryItOut("s0 += 'x';");
/*fuzzSeed-202342322*/count=218; tryItOut("");
/*fuzzSeed-202342322*/count=219; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return (Math.fround((Math.fround(( + (Math.fround(((Math.fround(x) == (( + Math.expm1((( + x) | 0))) | 0)) | 0)) != 0x100000000))) ? Math.fround((( ! y) === Math.atan2(Math.log10(x), x))) : Math.fround((Math.tan((Math.min(((Math.fround((Math.sinh(y) | 0)) | 0) >>> 0), (0/0 >>> 0)) >>> 0)) | 0)))) != (((x >= ((((y >>> 0) - (Math.abs(((y ? -0x080000000 : y) ^ x)) >>> 0)) >>> 0) >>> 0)) >>> 0) - ( + Math.tanh((Math.fround((Math.fround((y % (y | 0))) - Math.fround(Math.min(Math.max(y, x), x)))) >>> 0))))); }); testMathyFunction(mathy1, [-(2**53), 0/0, -(2**53+2), -0x07fffffff, 1, -0x0ffffffff, 0x100000001, -Number.MAX_VALUE, 1/0, -0x080000000, 0, 0x080000001, -0, -0x080000001, 0.000000000000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, 0x07fffffff, 0x080000000, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000, -1/0, 42, Number.MAX_VALUE, -0x100000001, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=220; tryItOut("with({b:  '' }){m0 = new WeakMap; }");
/*fuzzSeed-202342322*/count=221; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.asin((Math.imul(( - Math.fround(Math.fround(x))), (Math.fround(Math.tan(Math.cosh(mathy0(Math.PI, (( + Math.fround(y)) >>> 0))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [true, -0, null, (new Number(0)), (new Boolean(false)), '/0/', [0], ({valueOf:function(){return 0;}}), '', (function(){return 0;}), false, (new Boolean(true)), ({valueOf:function(){return '0';}}), 0, undefined, (new String('')), (new Number(-0)), objectEmulatingUndefined(), 0.1, [], NaN, /0/, '\\0', '0', ({toString:function(){return '0';}}), 1]); ");
/*fuzzSeed-202342322*/count=222; tryItOut("testMathyFunction(mathy1, [-(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 0/0, -(2**53), 42, -0, 2**53-2, 0x07fffffff, 2**53, -1/0, 0.000000000000001, Number.MIN_VALUE, 0x100000000, 0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, -Number.MIN_VALUE, -0x080000001, 1/0, -Number.MAX_VALUE, Number.MAX_VALUE, 1, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 0, -0x100000001, 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=223; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[-Infinity, -Infinity, [1]]) { a0.forEach((function(j) { if (j) { try { o0 = a1[2]; } catch(e0) { } try { e0.add(b2); } catch(e1) { } try { o0 = o1.__proto__; } catch(e2) { } m0 = new WeakMap; } else { v0 = Object.prototype.isPrototypeOf.call(this.p2, s0); } }), b2, f1); }");
/*fuzzSeed-202342322*/count=224; tryItOut("\"use strict\"; testMathyFunction(mathy4, [[0], undefined, ({valueOf:function(){return '0';}}), [], false, -0, (new Boolean(false)), (new Number(-0)), '/0/', ({toString:function(){return '0';}}), '\\0', (function(){return 0;}), ({valueOf:function(){return 0;}}), 0, objectEmulatingUndefined(), (new Boolean(true)), '', (new String('')), '0', 0.1, NaN, null, (new Number(0)), 1, true, /0/]); ");
/*fuzzSeed-202342322*/count=225; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.cosh(Math.fround(((Math.fround(Math.min(Math.fround(Math.tanh((Math.abs((y | 0)) >>> 0))), Math.fround((( ! y) | 0)))) | 0) < ((Math.log10(((Math.cbrt((Math.sin(( ! x)) >>> 0)) >>> 0) | 0)) | 0) | 0)))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), window, objectEmulatingUndefined(), window, window, objectEmulatingUndefined(), window, window, window, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), window, objectEmulatingUndefined(), objectEmulatingUndefined(), window, objectEmulatingUndefined(), objectEmulatingUndefined(), window, window, window, objectEmulatingUndefined(), window, objectEmulatingUndefined(), window, window, window, window, window, window, window, window, window, window, window, objectEmulatingUndefined(), objectEmulatingUndefined(), window, objectEmulatingUndefined(), window, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), window, objectEmulatingUndefined(), window, window, window, window, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), window, objectEmulatingUndefined(), window, window, objectEmulatingUndefined(), window, window, window, window, window, window, window]); ");
/*fuzzSeed-202342322*/count=226; tryItOut("mathy1 = (function(x, y) { return (Math.hypot(( ! Math.fround(Math.tan(Math.log1p((mathy0(x, (( + ( + ( + (y + ( + y))))) >>> 0)) | 0))))), Math.fround(mathy0(Math.fround(Math.atan2((y !== y), Math.pow(Math.fround(( + (y | 0))), Math.atan2(mathy0(y, y), x)))), Math.fround((y + y))))) >>> 0); }); testMathyFunction(mathy1, [0x07fffffff, -1/0, -0, 2**53, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, -0x100000001, 1, 0x080000001, -0x0ffffffff, Number.MIN_VALUE, 42, 0/0, -(2**53+2), 0x100000001, 0x080000000, 0, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, -Number.MAX_VALUE, -(2**53), -0x080000001, 1/0, 0x100000000, 2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=227; tryItOut("\"use strict\"; \"use asm\"; print(Math.max(x, true.yoyo(x)));");
/*fuzzSeed-202342322*/count=228; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.clz32((Math.hypot(( ! -Number.MAX_SAFE_INTEGER), (Math.fround((Math.fround((((( - x) >>> 0) ? (( + ((((x >>> 0) ? ((x * x) >>> 0) : (x >>> 0)) >>> 0) === ( + Math.fround(( ! Math.fround(-0x080000000)))))) >>> 0) : (Math.sinh(( + Math.fround(( - x)))) >>> 0)) >>> 0)) && Math.fround(((Math.imul((1/0 >>> 0), ( + x)) | 0) && x)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[{}, {}]); ");
/*fuzzSeed-202342322*/count=229; tryItOut("/*bLoop*/for (let jkcuns = 0; jkcuns < 57; ++jkcuns) { if (jkcuns % 5 == 3) { /*tLoop*/for (let b of /*MARR*/[(0/0), (0/0), (0/0), -(2**53+2), new Boolean(false), [], -(2**53+2), [], (0/0), [], false, false, [], (0/0), -(2**53+2), (0/0), [], -(2**53+2), false, (0/0), new Boolean(false), new Boolean(false), -(2**53+2), -(2**53+2), (0/0), new Boolean(false), (0/0), [], -(2**53+2), new Boolean(false), new Boolean(false), false, false, [], (0/0), [], new Boolean(false), false, new Boolean(false), false, [], false, []]) { {} } } else { Array.prototype.sort.apply(a2, [Number.isFinite.bind(s0)]); }  } ");
/*fuzzSeed-202342322*/count=230; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-202342322*/count=231; tryItOut("\"use strict\"; M: for  each(let z in 24) {a1.sort((function(j) { if (j) { s0 + ''; } else { try { selectforgc(o0); } catch(e0) { } try { Object.preventExtensions(f0); } catch(e1) { } o1.v0 = new Number(Infinity); } }));g2.o1.g2.v0 = new Number(NaN); }");
/*fuzzSeed-202342322*/count=232; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"a\"; print(s.split(r)); ");
/*fuzzSeed-202342322*/count=233; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return ( - ( ! Math.min(Math.sqrt(x), Math.log2(Math.acos(x))))); }); testMathyFunction(mathy3, [0.1, 1, ({valueOf:function(){return '0';}}), null, 0, (new Number(0)), '/0/', (function(){return 0;}), NaN, (new Boolean(true)), undefined, /0/, '\\0', ({valueOf:function(){return 0;}}), [], (new String('')), -0, (new Boolean(false)), ({toString:function(){return '0';}}), true, false, '0', (new Number(-0)), '', objectEmulatingUndefined(), [0]]); ");
/*fuzzSeed-202342322*/count=234; tryItOut("/*RXUB*/var r = new RegExp(\"(?=.^[^\\\\w\\\\v]|([^])[\\\\uea84\\\\d]*?|(\\u00ed)|(?=[^][^\\ud177-\\\\u8381\\\\v]|(.))|\\\\2|(?=(?=\\\\u00C0))|[^]|[^]\\\\d\\\\b\\\\w\\\\B\\\\B{4096,4100}|([^\\\\uB000\\\\t-\\u543d\\\\W].*)\\u0b87*?|[^]*\\\\d|(?=(?:[\\\\b-\\\\u00ee\\u00c8\\\\u0042\\u00c6]\\\\xeF)).?{1,})\", \"gyim\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-202342322*/count=235; tryItOut("v1 = evaluate(\"e2.has(i1);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 17 == 0), noScriptRval: (4277), sourceIsLazy: true, catchTermination: false, sourceMapURL: s2 }));");
/*fuzzSeed-202342322*/count=236; tryItOut("\"use strict\"; \"use asm\"; L:if((x % 6 == 3)) b0 + ''; else  if (\"\\u0011\") t2.toString = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -2.0;\n    d1 = (-134217729.0);\n    {\n      d1 = (d1);\n    }\n    (Int32ArrayView[((((/*FFI*/ff(((d0)), ((-0.001953125)))|0))>>>((!(/*FFI*/ff(((-33554433.0)), ((7.737125245533627e+25)), ((1.1805916207174113e+21)), ((1073741825.0)), ((-6.189700196426902e+26)), ((4294967295.0)), ((3.8685626227668134e+25)), ((4398046511103.0)), ((-67108865.0)), ((8796093022207.0)), ((-2147483649.0)), ((-576460752303423500.0)))|0)))) / ((((imul((0xfaba5204), (0xffffffff))|0)))>>>(-0xfffff*(0x7cee6f5)))) >> 2]) = (((0x3c665fda) < ((0x91454*(0xf835186b)) << ((0x93dd22d9) / (0x0))))-((0x43e26db1) ? (((0x6c3fb2e8) != (0x1157e79c)) ? (/*FFI*/ff(((d0)), ((17179869185.0)), ((-268435455.0)), ((576460752303423500.0)), ((-0.0625)), ((-2305843009213694000.0)))|0) : ((-(((-3.094850098213451e+26) + (-9223372036854776000.0)))))) : (!(-0x56e924f)))+(0x98e8546c));\n    d1 = (d1);\n    (Uint16ArrayView[(((0xffffffff) != (0xb47e6d45))-(((0x36778b20)) ? ((((0x81bd2eea)) & ((0x2e5a81e7)))) : (0x989f62f3))) >> 1]) = ((0x5d7d89c4)+((d2) == (d0))-(0x740a0262));\n    return +((d2));\n  }\n  return f; })(this, {ff: Object.prototype.__lookupGetter__}, new ArrayBuffer(4096)); else {s2 += 'x'; }");
/*fuzzSeed-202342322*/count=237; tryItOut("mathy3 = (function(x, y) { return ( + ( - ((Math.log10((((y || ((Math.fround((Math.imul((y | 0), (( ! (((x >>> 0) / y) >>> 0)) | 0)) | 0)) ? (Math.max(1, x) | 0) : Math.fround(Math.cbrt((( + Math.log(( + y))) | 0)))) | 0)) | 0) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy3, [null, '0', '\\0', 0.1, '', ({valueOf:function(){return '0';}}), (new Number(0)), true, /0/, '/0/', 1, (new Boolean(true)), [0], 0, ({valueOf:function(){return 0;}}), (new String('')), -0, undefined, (function(){return 0;}), false, (new Boolean(false)), objectEmulatingUndefined(), NaN, ({toString:function(){return '0';}}), [], (new Number(-0))]); ");
/*fuzzSeed-202342322*/count=238; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.max(((( + Math.fround(mathy0(( + ( + Math.fround(x))), (( ~ ( + y)) >>> 0)))) >>> 0) & (Math.ceil(( + Math.tanh(Math.log1p((x - (x >>> 0)))))) >>> 0)), Math.expm1(( ~ (( + (( + mathy0(( + ((mathy1((-0x100000000 >>> 0), (y >>> 0)) >>> 0) === (x >>> 0))), ( + x))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0, 42, 2**53+2, Number.MAX_VALUE, 0x100000001, 0/0, -1/0, -(2**53+2), 2**53-2, 1/0, -Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, -0x07fffffff, 0x080000001, Math.PI, 0x080000000, 1.7976931348623157e308, 1, -0x080000000, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0, -0x100000001, 0.000000000000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-202342322*/count=239; tryItOut("h1.enumerate = f1;");
/*fuzzSeed-202342322*/count=240; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=241; tryItOut("/*bLoop*/for (var pmqqnb = 0; (-21) && pmqqnb < 84; ++pmqqnb) { if (pmqqnb % 2 == 1) { {} } else { throw this; }  } ");
/*fuzzSeed-202342322*/count=242; tryItOut("/*ADP-3*/Object.defineProperty(a2, 18, { configurable: (p={}, (p.z = (x.unwatch(\"toSource\")))()), enumerable: (x % 4 != 2), writable: false, value: [x] });");
/*fuzzSeed-202342322*/count=243; tryItOut("\"use strict\"; ;");
/*fuzzSeed-202342322*/count=244; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return (Math.fround(Math.fround(Math.max(Math.fround(Math.asin(Math.atan2((x >>> 0), (((0x100000001 >>> 0) >>> (Math.imul(y, (y | 0)) | 0)) >>> 0)))), (Math.sign((((Math.round(x) >>> 0) >> x) >>> 0)) >>> 0)))) !== ( + ((-0 >= (Math.sin((x >>> 0)) | 0)) + Math.min(( + Math.imul((x >>> 0), ( + y))), ( + Math.asinh(Math.log(-0))))))); }); testMathyFunction(mathy2, [0, -Number.MAX_VALUE, 0.000000000000001, 1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, 42, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53, -0x07fffffff, 2**53+2, Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), 0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -0x080000000, -0x100000001, -0x100000000, 1, 0x100000000, Number.MAX_VALUE, -0x080000001, -0, -0x0ffffffff, -(2**53), 0x100000001]); ");
/*fuzzSeed-202342322*/count=245; tryItOut("mathy3 = (function(x, y) { return Math.asin(( + Math.pow(y, Math.fround(Math.atan2(Math.fround(Number.MIN_VALUE), ((( - Math.fround(-Number.MIN_VALUE)) >>> 0) | 0)))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x100000001, -0x07fffffff, 2**53, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, -0x100000000, 1, 0x080000000, 2**53-2, -1/0, -(2**53), 0x080000001, -0, 0x0ffffffff, Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), 42, 0.000000000000001, 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0/0, -0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-202342322*/count=246; tryItOut("\"use strict\"; var w =  /x/ ;m1.has(\"\\uD690\");");
/*fuzzSeed-202342322*/count=247; tryItOut("\"use strict\"; Array.prototype.sort.call(o0.a0, (function() { try { h2.has = (function(j) { if (j) { v1.__iterator__ = f0; } else { try { m1.set(o0, p0); } catch(e0) { } try { v0 = evalcx(\"this.a2.__proto__ = e1;\", g0.g2); } catch(e1) { } p2 + g2; } }); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(f2, p1); } catch(e1) { } this.v0 = g1.runOffThreadScript(); return s2; }));");
/*fuzzSeed-202342322*/count=248; tryItOut("\"use strict\"; v0 = g1.runOffThreadScript();");
/*fuzzSeed-202342322*/count=249; tryItOut("v1 = o2.a2.length;");
/*fuzzSeed-202342322*/count=250; tryItOut("o2 + e0;");
/*fuzzSeed-202342322*/count=251; tryItOut("\"use strict\"; e1.has(this.t2);");
/*fuzzSeed-202342322*/count=252; tryItOut("const x = ({}) =  \"\" .yoyo(new RegExp(\"(?:(?:(?:[^])+)|\\\\S?+)\", \"i\"));t0 = t1.subarray(6, 18);");
/*fuzzSeed-202342322*/count=253; tryItOut("");
/*fuzzSeed-202342322*/count=254; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=255; tryItOut("testMathyFunction(mathy4, [2**53, Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, 1, -(2**53-2), -0, 0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, 0x0ffffffff, 0x100000001, 42, -1/0, 1/0, -0x100000001, 2**53-2, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, 2**53+2, 0/0, 0x080000001, -Number.MAX_VALUE, 0.000000000000001, 0]); ");
/*fuzzSeed-202342322*/count=256; tryItOut("h2.keys = f2;");
/*fuzzSeed-202342322*/count=257; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.cosh(Math.log(mathy0((x == ((x ^ 1/0) | 0)), (( ~ (y | 0)) | 0)))) >>> 0); }); ");
/*fuzzSeed-202342322*/count=258; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (Math.fround((Math.min((Math.min((x <= ( + x)), ( + 42)) >>> 0), (Math.max((Math.atan2(y, (y >>> 0)) % y), (x >>> 0)) >>> 0)) || ((( ~ ((x === Math.fround(( ~ y))) | 0)) | 0) >>> 0))) - Math.max((Math.fround((Math.fround(( ! (x != (x | 0)))) >= Math.fround((((((y === x) >>> 0) >>> 0) ? (( + (2**53-2 ? ( + y) : ( + x))) >>> 0) : Math.fround(Math.sinh(y))) >>> 0)))) >>> 0), ((Math.min(( + 0x100000000), y) | 0) * (( ! ( ! y)) >>> 0)))); }); testMathyFunction(mathy0, [-1/0, 1/0, -0x0ffffffff, 1, 0x07fffffff, -0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, -0x07fffffff, 2**53, 2**53+2, -0x080000001, 0x100000001, 0x0ffffffff, -(2**53-2), -0x100000001, 2**53-2, -(2**53), -Number.MAX_VALUE, 0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, -(2**53+2), Number.MIN_VALUE, -0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, 42, 0]); ");
/*fuzzSeed-202342322*/count=259; tryItOut("testMathyFunction(mathy0, [0.000000000000001, 0x080000000, Math.PI, 2**53-2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, -(2**53-2), 1.7976931348623157e308, -Number.MIN_VALUE, -0, 0, -Number.MAX_VALUE, 1, 42, 2**53, -1/0, 0x080000001, -0x07fffffff, 1/0, -0x100000000, 2**53+2, 0x0ffffffff, -0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, 0/0, -0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=260; tryItOut("\"use strict\"; a0.push(g2.o1, f2);");
/*fuzzSeed-202342322*/count=261; tryItOut("for(let e in []);/*RXUB*/var r = r0; var s = s1; print(s.replace(r, Promise.prototype.then, \"gyim\")); ");
/*fuzzSeed-202342322*/count=262; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-202342322*/count=263; tryItOut("/*hhh*/function uoxarg(window, x = (uneval(new RegExp(\"(?:\\\\B){4,}\\\\b?\", \"yi\")))){a1.length = 2;}/*iii*/m1 = new Map;");
/*fuzzSeed-202342322*/count=264; tryItOut("mathy1 = (function(x, y) { return Math.log2(( + Math.atan2((((((Math.pow(((y ? (y | 0) : 1) | 0), ( + ( + Math.pow(Math.fround((x & y)), ( + Math.fround(( ! y))))))) | 0) >>> 0) >>> (Math.acos((((((x >>> 0) ? (x >>> 0) : (x >>> 0)) >>> 0) >>> 0) <= x)) >>> 0)) >>> 0) >>> 0), Math.exp(Math.min(( + x), y))))); }); testMathyFunction(mathy1, [-1/0, 2**53-2, Number.MIN_VALUE, -Number.MIN_VALUE, Math.PI, 0x100000000, -0x080000001, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -0x100000001, 0x07fffffff, 0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, 1, Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, -(2**53-2), -Number.MIN_SAFE_INTEGER, 42, 0x100000001, -0, 0x080000000, 0/0, 2**53, 0x080000001, 0, -0x080000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000]); ");
/*fuzzSeed-202342322*/count=265; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return ((((33.0) < (d1))+((i2) ? ((((Float32ArrayView[((0x4889dfc0)) >> 2])) % ((+abs(((Float32ArrayView[2])))))) != (2097153.0)) : (i0))))|0;\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-202342322*/count=266; tryItOut("print(f2);");
/*fuzzSeed-202342322*/count=267; tryItOut("v1 = b2.byteLength;");
/*fuzzSeed-202342322*/count=268; tryItOut("while(((makeFinalizeObserver('nursery'))) && 0){print(/*FARR*/[, , d ? \"\\u52F2\" : \"\\u7ED2\", , ].sort(Array.prototype.concat++)); }\u0009");
/*fuzzSeed-202342322*/count=269; tryItOut("((4277));");
/*fuzzSeed-202342322*/count=270; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ! (Math.hypot(Math.fround((( + Math.asinh(( + 0.000000000000001))) < ( - -0x100000000))), ( + Math.imul(( + Math.atan2(( + 0x07fffffff), ( + y))), (Math.max((Math.tanh(Math.acosh(y)) | 0), ((y | y) | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy4, [null, ({toString:function(){return '0';}}), 0, [], (new Boolean(false)), -0, true, (new Number(-0)), '', objectEmulatingUndefined(), 1, ({valueOf:function(){return 0;}}), 0.1, '/0/', '\\0', NaN, (function(){return 0;}), undefined, (new String('')), /0/, '0', (new Boolean(true)), [0], false, (new Number(0)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-202342322*/count=271; tryItOut("var eybqhs, e = timeout(1800), x = (({x: /*MARR*/[ \"use strict\" , [],  \"use strict\" , function(){}, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,  \"use strict\" , function(){}, [], false, false, false, false, false, false, false, false, false, false, false, false, false, false, function(){}, function(){}, false, false, function(){}, false, false, false].sort})), d = ((Date.prototype.setHours).call(({x: [[1]]}), )), w = x, x = true, bxopzo, rjmgqy, ueywkq;print((4277));");
/*fuzzSeed-202342322*/count=272; tryItOut("/*MXX2*/g1.RegExp.prototype.flags = o2.o1;");
/*fuzzSeed-202342322*/count=273; tryItOut("v0 = g2.runOffThreadScript();");
/*fuzzSeed-202342322*/count=274; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + (Math.asinh(x) <= (-0x100000001 * (( ~ ( + Math.fround(( ~ Math.fround(Number.MIN_VALUE))))) >>> 0)))) < ( + Math.atan2(Math.fround((((-Number.MIN_SAFE_INTEGER ** ( - -Number.MAX_VALUE)) | 0) >= Math.fround((Math.abs((Math.hypot(x, Math.min((x < y), -(2**53+2))) >>> 0)) | 0)))), Math.max(( ~ ( + ( ! ( + y)))), Math.imul(Math.expm1(Math.log2(Math.atan2(42, y))), (((Math.hypot(( + y), ( + x)) | 0) == (-0x100000001 | 0)) | 0)))))); }); testMathyFunction(mathy0, ['', [], 1, undefined, 0.1, /0/, null, ({valueOf:function(){return '0';}}), 0, (new Number(-0)), (new Number(0)), ({valueOf:function(){return 0;}}), '/0/', true, '\\0', ({toString:function(){return '0';}}), '0', NaN, [0], (function(){return 0;}), (new Boolean(true)), objectEmulatingUndefined(), -0, (new Boolean(false)), false, (new String(''))]); ");
/*fuzzSeed-202342322*/count=275; tryItOut("m2 = new WeakMap;");
/*fuzzSeed-202342322*/count=276; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.imul(Math.asin(( ~ Math.fround(Math.min(x, x)))), Math.fround((mathy0(( + Math.imul(( + ((((Math.atan2(Number.MIN_SAFE_INTEGER, Math.PI) | 0) | 0) > (-0x080000000 >>> 0)) >>> 0)), (Math.sinh((((((x >>> 0) >= Math.fround(x)) >>> 0) < Math.fround(x)) | 0)) | 0))), Math.pow((( + ((y > y) >>> 0)) >>> 0), Math.max((y >>> 0), Math.fround(mathy1(Math.fround(( ~ (x >>> 0))), Math.fround(0)))))) >>> (( - mathy1(Math.log2(x), ((mathy0((Math.hypot(x, x) >>> 0), (-0x0ffffffff >>> 0)) >>> 0) | 0))) ? ((((-0x080000001 | 0) << (x | 0)) | 0) || (( + (x | 0)) | 0)) : Math.imul((((x || x) | 0) & x), 1/0)))))); }); testMathyFunction(mathy3, /*MARR*/[null, 2**53+2, 2**53+2, null, arguments.caller, arguments.caller, 2**53+2, arguments.caller, null, arguments.caller, arguments.caller, 2**53+2, null]); ");
/*fuzzSeed-202342322*/count=277; tryItOut("let (x) { s1 = ''; }");
/*fuzzSeed-202342322*/count=278; tryItOut("v1 = Object.prototype.isPrototypeOf.call(f1, g1.s2);");
/*fuzzSeed-202342322*/count=279; tryItOut("\"use strict\"; \"use asm\"; /*vLoop*/for (var cidgwu = 0; cidgwu < 86; ++cidgwu) { d = cidgwu; print(b1);d.message; } ");
/*fuzzSeed-202342322*/count=280; tryItOut("/*oLoop*/for (ovybjy = 0; ovybjy < 0; ++ovybjy) { t0[17]; } ");
/*fuzzSeed-202342322*/count=281; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-202342322*/count=282; tryItOut("mathy0 = (function(x, y) { return Math.max(Math.acosh((Math.imul((( - 0x080000000) >>> 0), (( + (Math.ceil(Math.fround(x)) >> y)) >>> 0)) >>> 0)), Math.min(Math.fround(((x >> y) , 0/0)), Math.fround(Math.fround((( ~ Math.fround(( - Math.fround(Math.imul(y, -1/0))))) | 0))))); }); testMathyFunction(mathy0, [NaN, (new String('')), objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), -0, undefined, (new Boolean(true)), false, '\\0', '', [], 0.1, (new Number(0)), true, (new Boolean(false)), 1, '0', /0/, '/0/', (new Number(-0)), 0, (function(){return 0;}), [0], null, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-202342322*/count=283; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.asin((Math.atan(( - Math.sin((x ? y : (Math.trunc((-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0))))) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[true, -Number.MAX_VALUE, null, (void 0), -Number.MAX_VALUE, true, (void 0), -Number.MAX_VALUE, null, (void 0), (void 0), (void 0), null, (void 0), null, (void 0), true, -Number.MAX_VALUE, null, true, -Number.MAX_VALUE, true, true, true, true, null, true, -Number.MAX_VALUE, true, true, -Number.MAX_VALUE, null, null, true, (void 0), null, true, true, true, true, true, true, true, null, true, true, -Number.MAX_VALUE, (void 0), true, null, null, null, true]); ");
/*fuzzSeed-202342322*/count=284; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + (((x | 0) & (Math.fround(Math.fround(0x080000001)) | 0)) | 0)) || Math.atan2((( ~ (Math.fround(Math.max(Math.fround(Math.sqrt(x)), ( + Math.hypot(2**53, Math.fround(x))))) | 0)) > ( + ((Math.hypot(x, Math.fround(x)) | 0) ^ (Math.cosh(0x0ffffffff) | 0)))), Math.fround(( ! (Math.cosh((y | 0)) >>> 0))))); }); ");
/*fuzzSeed-202342322*/count=285; tryItOut("mathy5 = (function(x, y) { return ( + ((Math.fround(( ! (Math.fround(Math.hypot(Math.fround((y >> y)), Math.fround(y))) === Math.clz32(y)))) && (x | (Math.pow(Math.cosh(Math.abs(y)), (x >>> 0)) | 0))) && ( + Math.fround(( ~ y))))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, 1/0, 0x0ffffffff, 0x07fffffff, 0/0, -Number.MIN_VALUE, -0x07fffffff, 0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0, 2**53-2, -0x100000000, -0x080000000, -0, 0x100000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0, 0.000000000000001, Math.PI, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), -0x100000001, -Number.MAX_VALUE, 2**53, -(2**53), 42, 0x080000001, 0x100000000]); ");
/*fuzzSeed-202342322*/count=286; tryItOut("/*oLoop*/for (var zirjss = 0; zirjss < 0; ++zirjss) { this = a0[({valueOf: function() { s0.valueOf = (function() { try { s0 += s1; } catch(e0) { } try { v2 = (g0.f1 instanceof v2); } catch(e1) { } try { for (var v of h2) { try { this.a1 = a2.slice(NaN, NaN); } catch(e0) { } try { selectforgc(o0); } catch(e1) { } try { o2 + ''; } catch(e2) { } i0 = new Iterator(g2, true); } } catch(e2) { } this.m1.get(i2); throw b2; });return 15; }})]; } ");
/*fuzzSeed-202342322*/count=287; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.fround((Math.round(y) || ( + ( + mathy1(Math.fround((((y | 0) | (x | 0)) | 0)), Math.fround(Math.cbrt(( + Math.asinh(( + y)))))))))) < (y ** ( ~ (Math.atan2((((( + -Number.MIN_SAFE_INTEGER) >= y) >>> 0) >>> 0), (mathy2((( - x) >>> 0), Math.fround(x)) >>> 0)) >>> 0)))) === ((Math.round(y) ? ((1 ? x : x) | 0) : (((mathy3((x | 0), (Math.sin(y) | 0)) | 0) ^ mathy0(((Math.min(Math.fround(( ~ ( + x))), ((Math.max((x | 0), (Math.PI | 0)) | 0) >>> 0)) >>> 0) | 0), (Math.max(y, (x == x)) | 0))) | 0)) | 0)); }); testMathyFunction(mathy4, [0, 1.7976931348623157e308, 2**53, -0x100000001, -0x07fffffff, -(2**53-2), 0/0, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, -0x100000000, 0x100000001, 0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, 0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 42, -0, -0x080000001, 0x0ffffffff, -1/0, 1, 1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001]); ");
/*fuzzSeed-202342322*/count=288; tryItOut("\"use strict\"; v1 = 4;");
/*fuzzSeed-202342322*/count=289; tryItOut("\"use strict\"; i1.next();");
/*fuzzSeed-202342322*/count=290; tryItOut("t1 = t1.subarray(v0, new RegExp(\"(\\\\xa2{3,})+?\", \"i\"));function get(...e) { print(x); } /*MXX2*/o0.g0.String.prototype.includes = f1;");
/*fuzzSeed-202342322*/count=291; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.imul(Math.fround(Math.sinh(Math.fround(( + Math.asinh(( + (((2**53-2 >>> 0) , (x >>> 0)) >>> 0))))))), ( + ( + Math.asin((( ~ (y | 0)) | 0))))); }); testMathyFunction(mathy5, [-(2**53+2), 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, Number.MAX_VALUE, -0, -0x0ffffffff, 0x0ffffffff, 2**53, -Number.MAX_VALUE, 0, Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -1/0, -0x07fffffff, -(2**53), 1/0, -Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, 0x100000001, Math.PI, 0.000000000000001, 2**53-2, -0x080000001, 0x100000000, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 1, 0x080000000, 42, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=292; tryItOut("v0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    {\n      d1 = (d1);\n    }\n    (Uint16ArrayView[2]) = ((Int16ArrayView[((/*FFI*/ff((((((!(i0))) ^ ((/*FFI*/ff(((((140737488355329.0)) % ((0.25)))), ((imul((0xca6a12e3), (-0x8000000))|0)), ((17592186044416.0)))|0)+(i0))))), ((d1)), ((+(-1.0/0.0))), ((d1)), ((d1)), ((((0xfbd4d1e8)) ^ ((0xf8d1248e)))), ((35184372088831.0)))|0)+(-0x8000000)) >> 1]));\n    return (((Float32ArrayView[((i2)) >> 2])))|0;\n  }\n  return f; })(this, {ff: Int8Array}, new SharedArrayBuffer(4096));");
/*fuzzSeed-202342322*/count=293; tryItOut("b1.toString = g0.f1;");
/*fuzzSeed-202342322*/count=294; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.cbrt(Math.fround(( - Math.max(Math.max(Math.fround(y), y), Math.fround(mathy0(Math.hypot(y, -0x080000001), ( ! y))))))) >>> 0); }); testMathyFunction(mathy5, [-0, -Number.MIN_VALUE, Math.PI, 0/0, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 2**53+2, -1/0, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 0x080000000, 0x0ffffffff, Number.MAX_VALUE, 2**53-2, 0x07fffffff, -Number.MAX_VALUE, 2**53, 0x100000001, 42, 1/0, 0x080000001, -0x07fffffff, -(2**53+2), -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, -(2**53-2), -0x080000000, 0]); ");
/*fuzzSeed-202342322*/count=295; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( + (( + (x > x)) !== ( + mathy0(y, ( + (Math.ceil(Math.pow(x, y)) << Math.hypot(((x || x) >>> 0), y)))))))); }); testMathyFunction(mathy1, [-0x080000001, 2**53, -1/0, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), Number.MIN_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0x0ffffffff, 1, Math.PI, -0x080000000, 0x07fffffff, -(2**53), -Number.MAX_VALUE, 0x100000000, -0x07fffffff, 0x080000000, 0.000000000000001, -(2**53-2), 0, 2**53-2, 2**53+2, 0x100000001, 42, 0x0ffffffff, 0x080000001]); ");
/*fuzzSeed-202342322*/count=296; tryItOut("i2.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31) { a21 = 1 % a22; var r0 = 1 * 5; var r1 = a25 - a4; var r2 = a12 + 7; var r3 = a19 | a2; var r4 = a5 % 9; var r5 = a13 - a18; a5 = a23 + r0; var r6 = a15 - a26; var r7 = 7 * a11; var r8 = a22 / a5; var r9 = a25 + 7; var r10 = a0 - 7; var r11 = 9 + a2; var r12 = r6 - a12; var r13 = 9 | r2; var r14 = a27 ^ a30; a28 = r3 & r5; var r15 = 6 - 1; var r16 = x * a16; var r17 = a4 / 0; var r18 = r3 * 5; var r19 = r13 | a29; var r20 = 8 | 8; r7 = a16 + 8; a19 = a16 | r16; var r21 = r4 / 9; var r22 = 8 * a29; a15 = r18 * a15; var r23 = a18 ^ 1; var r24 = a3 | a11; var r25 = a24 + 2; var r26 = 8 + a17; a13 = 4 | a1; a4 = 7 | r19; var r27 = 2 * r6; var r28 = r27 * a26; var r29 = r17 & a6; var r30 = 5 % a12; r9 = 0 + a29; var r31 = a27 % r26; var r32 = r24 & a6; var r33 = r12 * r16; a0 = a12 - r32; var r34 = a21 | r5; r0 = 2 ^ 8; var r35 = r21 ^ 5; var r36 = r13 + 9; var r37 = 4 & r22; var r38 = r37 | 0; x = r36 ^ r25; var r39 = 6 % r2; var r40 = 5 / r1; print(r23); var r41 = 1 / 9; var r42 = r35 * r16; var r43 = r40 + 6; r12 = r18 ^ r10; var r44 = x & r30; var r45 = a14 * 5; var r46 = 7 & r16; var r47 = r28 & a30; var r48 = a28 + 9; a23 = 3 + r43; var r49 = 1 - 5; print(r33); var r50 = r6 * r34; var r51 = r14 | a6; var r52 = 3 - r3; var r53 = r44 + a11; var r54 = r32 | a22; print(r46); var r55 = 4 / r32; var r56 = r18 + 4; var r57 = r55 * a28; r44 = r24 | 9; var r58 = r30 | a28; var r59 = r27 * 1; var r60 = r51 * a15; var r61 = a2 | r52; var r62 = 4 - r54; print(x); r36 = a27 / r18; var r63 = 5 + a3; var r64 = a7 | r41; var r65 = a4 % a26; a15 = a4 | r38; var r66 = a17 | a15; var r67 = r60 % a16; var r68 = 8 + 5; var r69 = r16 % a4; r9 = 3 ^ r53; var r70 = 5 | r40; var r71 = a22 % r59; var r72 = r6 + 7; var r73 = a21 % 7; var r74 = r57 | a25; r3 = r28 + r27; var r75 = a14 / r51; r75 = a1 * a28; var r76 = 1 / 2; var r77 = 1 * r34; r31 = r45 - x; var r78 = a4 & 6; var r79 = r78 * r71; var r80 = 1 * r44; var r81 = r17 % r76; var r82 = r61 % r1; var r83 = r47 | a13; var r84 = r83 * 1; var r85 = r0 & a31; var r86 = r10 | r42; var r87 = r71 * r43; print(r12); var r88 = 5 - 3; var r89 = r26 / a17; var r90 = r46 / r65; var r91 = r16 % r67; r86 = r33 - a5; var r92 = 4 ^ 0; r38 = r10 - r78; a17 = r84 % r52; var r93 = r11 / 3; var r94 = r54 | a7; a0 = r55 % 8; r54 = a6 / r55; var r95 = a3 + r56; var r96 = r69 & 0; r45 = r12 - a30; r20 = r81 % 7; var r97 = r14 - a12; r64 = 3 / r1; var r98 = r54 ^ 8; var r99 = r39 - 4; a31 = r91 | 6; var r100 = r60 + r7; var r101 = r35 - a5; print(r74); r77 = r37 + 8; var r102 = 0 / a14; var r103 = r25 ^ r84; var r104 = 4 & a31; var r105 = r43 * r81; var r106 = 8 | 2; var r107 = r21 ^ r20; var r108 = 1 & a15; var r109 = 9 ^ a10; r61 = r14 % r84; var r110 = 6 | r56; var r111 = 8 - r76; r65 = a9 - r12; var r112 = r53 | r11; var r113 = 3 ^ 3; print(r24); var r114 = a0 - r44; var r115 = 7 + r45; var r116 = 9 | 4; var r117 = 8 % a4; var r118 = r106 + 0; var r119 = r103 - r47; var r120 = r86 + 3; var r121 = r73 - 1; var r122 = 7 / r47; r59 = a12 * 3; var r123 = r103 + r55; var r124 = r11 & r67; var r125 = 3 + a30; r46 = 1 & 1; var r126 = r71 + r30; var r127 = r49 ^ a3; var r128 = r124 % r96; var r129 = a16 & 6; var r130 = 8 / r101; var r131 = r2 ^ r124; var r132 = r82 - a10; r16 = r37 * a28; var r133 = 0 & a7; var r134 = 9 * r105; var r135 = a1 ^ 2; var r136 = r62 - r105; var r137 = r56 ^ a0; var r138 = a12 * r0; var r139 = 3 + r77; var r140 = 0 / a11; var r141 = r27 - r127; var r142 = a8 - 3; var r143 = r75 | r2; var r144 = a7 - 8; var r145 = 6 % r78; var r146 = r140 / 4; var r147 = r76 * r63; var r148 = 8 * r13; var r149 = 7 | 1; var r150 = 8 + 1; var r151 = r28 ^ r138; var r152 = 9 * r115; return a29; });\n/*MXX3*/o1.g1.RegExp.prototype.source = g2.RegExp.prototype.source;\n");
/*fuzzSeed-202342322*/count=297; tryItOut("mathy2 = (function(x, y) { return ( + ( ! (( - Math.min(x, y)) >>> 0))); }); ");
/*fuzzSeed-202342322*/count=298; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-(2**53+2), 42, 1.7976931348623157e308, 0x100000001, 0x080000001, -0x07fffffff, -0x100000000, -(2**53), 0x0ffffffff, 1/0, -1/0, 1, -0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, 0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 2**53, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0/0, -Number.MAX_VALUE, -0x100000001, -(2**53-2), 0, 2**53+2]); ");
/*fuzzSeed-202342322*/count=299; tryItOut("/*ODP-2*/Object.defineProperty(a2, x, { configurable: ((Math.atan(((( ~ Math.hypot(( + x), (Math.acosh((0x100000000 | 0)) | 0))) | 0) | 0)) | 0)), enumerable: (new (d = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: new RegExp(\"(?:(?!.|\\\\b+?))|$|(?=\\\\S){536870913,}\", \"\"), defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })( /x/g ), [z1,,] ?  ''  : this))()), get: (function(j) { this.f0(j); }), set: (function() { try { print(m1); } catch(e0) { } for (var p in s2) { try { v2 = g0.eval(\"/* no regression tests found */\"); } catch(e0) { } try { Object.defineProperty(o1, \"v1\", { configurable: true, enumerable: true,  get: function() {  return null; } }); } catch(e1) { } t2 = x; } return s0; }) });");
/*fuzzSeed-202342322*/count=300; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.cosh(( ! Math.log2(((( ~ (-0x080000000 >>> 0)) >>> 0) >= Math.fround((Math.imul(x, x) <= mathy2(x, (Math.fround(y) && Math.fround(Number.MAX_SAFE_INTEGER))))))))); }); ");
/*fuzzSeed-202342322*/count=301; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=302; tryItOut("mathy5 = (function(x, y) { return Math.max(((mathy2(( + Math.fround(Math.PI)), (Math.atan2((x | 0), (0x0ffffffff | 0)) | 0)) > ( + mathy0(( ! Math.atan2(x, (x >>> 0))), Math.atan(Math.fround(x))))) | 0), ( + ((Math.atan2((-0 !== ( + ( - Math.fround(0/0)))), 0) >>> 0) >>> 0))); }); ");
/*fuzzSeed-202342322*/count=303; tryItOut("\"use strict\"; o2 = Object.create(m1);function x(...\"-4\") { yield  ''  } h1.defineProperty = o1.f0;");
/*fuzzSeed-202342322*/count=304; tryItOut("/*tLoop*/for (let a of /*MARR*/[(void 0), (void 0), (void 0), undefined, undefined, [], (void 0), (void 0), (void 0), [], [], (void 0), undefined, [], (void 0), undefined, [], (void 0), [], (void 0), (void 0), undefined, [], [], [], (void 0), [], [], undefined, undefined, undefined, (void 0), (void 0), (void 0), [], [], (void 0), undefined, (void 0), [], undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, (void 0), [], undefined, undefined, [], (void 0), undefined, []]) { s1 += s1; }");
/*fuzzSeed-202342322*/count=305; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"/*infloop*/while( \\\"\\\" )g0.offThreadCompileScript(\\\"function f0(g1.v0)  { return -7 } \\\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 6 != 3), sourceIsLazy: true, catchTermination: false }));\");");
/*fuzzSeed-202342322*/count=306; tryItOut("\"use strict\"; ");
/*fuzzSeed-202342322*/count=307; tryItOut("\"use strict\"; b1 = new SharedArrayBuffer(24);");
/*fuzzSeed-202342322*/count=308; tryItOut("s1 += s1;");
/*fuzzSeed-202342322*/count=309; tryItOut("m2.toSource = (function() { try { s2 = new String(i2); } catch(e0) { } try { e2.delete(new RegExp(\"\\\\2\", \"m\")); } catch(e1) { } m1 + ''; return s0; });");
/*fuzzSeed-202342322*/count=310; tryItOut("\"use strict\"; this.h1.get = (function mcc_() { var yyyntm = 0; return function() { ++yyyntm; f2(/*ICCD*/yyyntm % 4 == 1);};})();");
/*fuzzSeed-202342322*/count=311; tryItOut("/*infloop*/for(z; \"\\u9824\"; e % x) {Object.defineProperty(this, \"a0\", { configurable: (p={}, (p.z =  '' )()), enumerable: (x % 47 != 34),  get: function() {  return a2.map((function() { for (var j=0;j<113;++j) { f0(j%5==1); } }), t1, f1, t2, o1.m0, g1.t1, o1); } }); }");
/*fuzzSeed-202342322*/count=312; tryItOut("\"use strict\"; delete v0[17];");
/*fuzzSeed-202342322*/count=313; tryItOut("var evbrrr = new ArrayBuffer(4); var evbrrr_0 = new Uint8ClampedArray(evbrrr); print(evbrrr_0[0]); evbrrr_0[0] = -23; var evbrrr_1 = new Float32Array(evbrrr); print(evbrrr_1[0]); var evbrrr_2 = new Uint16Array(evbrrr); evbrrr_2[0] = 6; var evbrrr_3 = new Uint8ClampedArray(evbrrr); print(evbrrr_3[0]); evbrrr_3[0] = -28; var evbrrr_4 = new Uint16Array(evbrrr); var evbrrr_5 = new Uint16Array(evbrrr); print(evbrrr_5[0]); evbrrr_5[0] = -10; /*ADP-3*/Object.defineProperty(a1, 3, { configurable: false, enumerable: (evbrrr_1 % 6 == 4), writable: false, value: evbrrr_1 =  /x/ .__defineSetter__(\"evbrrr_3[2]\", ({/*TOODEEP*/})) });");
/*fuzzSeed-202342322*/count=314; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( ~ ((((((Math.max(y, (Math.tan(Math.pow(y, Math.fround((Math.fround(y) && 1)))) >>> 0)) >>> 0) % ( ! (y & x))) | 0) != ((((x >>> 0) < ((((( + (( + x) , ( + x))) >>> 0) , ((Number.MIN_VALUE | -0x080000001) >>> 0)) >>> 0) >>> 0)) | 0) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy4, [(new Boolean(true)), ({valueOf:function(){return 0;}}), undefined, '', (function(){return 0;}), true, /0/, '\\0', (new Number(0)), (new String('')), NaN, 0.1, (new Number(-0)), [0], [], '/0/', objectEmulatingUndefined(), -0, ({valueOf:function(){return '0';}}), false, '0', null, 0, ({toString:function(){return '0';}}), 1, (new Boolean(false))]); ");
/*fuzzSeed-202342322*/count=315; tryItOut("\"use strict\"; (\u000ceval) = ((-9).call\u000c(false,  \"\" ,  '' ));");
/*fuzzSeed-202342322*/count=316; tryItOut("\"use strict\"; b0[\"c\"] = e2;");
/*fuzzSeed-202342322*/count=317; tryItOut("a1.splice(NaN, ({valueOf: function() { print(uneval(s0));return 6; }}), p2, i1, b2)\n");
/*fuzzSeed-202342322*/count=318; tryItOut("{print(o0);print(x); }");
/*fuzzSeed-202342322*/count=319; tryItOut("testMathyFunction(mathy2, ['', null, /0/, [], 0, -0, (new Boolean(false)), (new Boolean(true)), undefined, 0.1, (new Number(-0)), (new String('')), (function(){return 0;}), true, NaN, 1, false, '\\0', '0', [0], ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (new Number(0)), objectEmulatingUndefined(), '/0/']); ");
/*fuzzSeed-202342322*/count=320; tryItOut("\"use strict\"; t2.valueOf = f2;");
/*fuzzSeed-202342322*/count=321; tryItOut("let (b) { function f0(v2)  { \"use asm\"; yield undefined } \no0.h2 = {};\n }");
/*fuzzSeed-202342322*/count=322; tryItOut("L:switch() { default: break; ;break;  }");
/*fuzzSeed-202342322*/count=323; tryItOut("\"use strict\"; a2[(Object.defineProperty(x, \"caller\", ({set: function shapeyConstructor(vmugpk){Object.freeze(this);Object.preventExtensions(this);if ((4277)) for (var ytqralxfe in this) { }this[\"getUTCMilliseconds\"] = (\n\"\\u99DA\");if (vmugpk) for (var ytqsbvnaw in this) { }for (var ytqzpffum in this) { }this[\"getOwnPropertyDescriptor\"] = this.toFixed( \"\" ,  /x/ );return this; }})))] = g0;");
/*fuzzSeed-202342322*/count=324; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1152921504606847000.0;\n    var d3 = -65537.0;\n    var i4 = 0;\n    d2 = (d3);\n    i4 = (0xa6dbba8f);\n    d2 = (17.0);\n    d3 = (Infinity);\n    return +((+(~((((((Int8ArrayView[((0x4862b153)) >> 0]))-(0x4de6eb85)+(0xdc11ac34))>>>((((0x5548e9ba)+(0x6f5a88da))>>>((0x948a3fce)-(-0x8000000))) % (0x9bde679a))))))));\n  }\n  return f; })(this, {ff: x.eval(\"/* no regression tests found */\")}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [2**53-2, 0x100000001, -0x080000001, Math.PI, 0x0ffffffff, -(2**53), 0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0/0, 2**53+2, 1, -0x080000000, -0x07fffffff, 1/0, Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, 0x080000001, -0x100000000, -0, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=325; tryItOut("/*oLoop*/for (let qjqbos = 0; qjqbos < 19; ++qjqbos) { v1 = evaluate(\"a1.reverse(i1, e1);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: Math.max(-27, true), noScriptRval: (x % 5 == 4), sourceIsLazy: true, catchTermination: true })); } ");
/*fuzzSeed-202342322*/count=326; tryItOut("Array.prototype.sort.call(a2, (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -140737488355329.0;\n    return ((-(((((((-((-134217729.0)))) / ((-((-1.001953125))))) < (+atan2(((Infinity)), ((+(-1.0/0.0)))))))>>>(((0x7abca6f8))-(x))) != (0x33f4953e))))|0;\n  }\n  return f; }), f2, this.__defineSetter__(\"b\", new Function));");
/*fuzzSeed-202342322*/count=327; tryItOut("mathy4 = (function(x, y) { return (((( + ( + ( + mathy3(Math.hypot(Number.MIN_SAFE_INTEGER, (y | 0)), Math.imul(((((Math.max(x, (0/0 >>> 0)) >>> 0) >>> 0) != (Math.pow(0x100000000, x) >>> 0)) >>> 0), ((x | 0) , y)))))) >>> 0) ? (((Math.imul(x, Math.pow((y === y), (0x080000001 >>> 0))) < ( + mathy1(( + y), (((x | -0x100000001) >>> 0) && ( + ((((((y >>> 0) ? (y >>> 0) : (y >>> 0)) >>> 0) | 0) % (Math.pow(Number.MAX_VALUE, (y >>> 0)) | 0)) | 0)))))) != (((Math.fround(( + ( + x))) >= (( + ( + (x ? (0x080000001 >>> 0) : x))) >>> 0)) >>> 0) | 0)) >>> 0) : ((((( + ( ! Math.pow(x, ( ~ x)))) >>> 0) >> (((y | 0) ? ( - mathy3(2**53+2, (x >>> 0))) : (((( + Math.max(x, x)) << -Number.MIN_SAFE_INTEGER) >>> 0) ** (y >>> 0))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [2**53, 1/0, 0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, -Number.MAX_VALUE, 1, -0x080000001, -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -0x080000000, 0x080000001, 0, 2**53+2, 0x0ffffffff, -(2**53), 0.000000000000001, 0x07fffffff, -0x100000001, 0x100000000, 1.7976931348623157e308, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -0, 42, Math.PI, -0x100000000]); ");
/*fuzzSeed-202342322*/count=328; tryItOut("/*tLoop*/for (let y of /*MARR*/[(0/0), new String(''), (0/0), (0/0), (0/0), (0/0), new String(''), new String(''), new String(''), new String(''), new String(''), (0/0), new String(''), (0/0), new String(''), (0/0), (0/0), new String(''), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), new String(''), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), new String(''), new String(''), (0/0), (0/0), new String(''), new String(''), (0/0), new String(''), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), new String(''), (0/0), (0/0), (0/0), (0/0), new String(''), new String(''), new String(''), (0/0), (0/0), new String(''), new String(''), new String(''), (0/0), (0/0), new String(''), (0/0), new String(''), new String(''), (0/0), (0/0), (0/0), new String(''), (0/0), (0/0), new String(''), (0/0), new String(''), (0/0), (0/0), (0/0), (0/0), new String(''), (0/0), new String(''), new String(''), new String(''), new String(''), (0/0), new String(''), (0/0), new String(''), (0/0), (0/0), (0/0)]) { for (var p in a2) { for (var v of g1.a0) { try { a1.forEach((function() { for (var j=0;j<4;++j) { g0.f2(j%5==0); } })); } catch(e0) { } v1 = Infinity; } }function y({w: z, \u3056: e, y}, y, y = (4277), y, window, y, x, x = this, y, window, x, y, y =  /x/ , w = null, y, z = true, e, x, z, y, y, z, eval, x, window, a, y, w = \"\\uF980\", window, NaN =  '' , y, y = [1,,], y, x, w, x = window, \u3056, y, y, y, c, y, e, this, b, x, y, x, z =  \"\" , w, y, y, \u3056, NaN, y, c, \u3056 = -28, a, w, y, y =  '' , e, NaN, y, z, NaN, y, x, \u3056, x, \u3056, NaN, e, \u3056, x, y, a = [1,,], x =  '' , x, x, e = window, d, a = /(?=(?:^|.{1,1}(?![^\\S\\d]{3}))*?\\\u00ab)/, NaN = w, this.x, y, x, z, ...y) { return false } eval(\"print(-11);\"); }");
/*fuzzSeed-202342322*/count=329; tryItOut("mathy3 = (function(x, y) { return Math.imul(Math.fround(( ~ ((Math.acos((( + (x && (x | 0))) >>> 0)) >>> 0) | 0))), (Math.imul((( + Math.acos(( + ( ~ (Math.fround((y , Math.fround((mathy0(( + y), ( + y)) >>> 0)))) >>> 0))))) >>> 0), ( + (x ? (( + ((Math.expm1(((Math.fround(x) ? (0/0 | 0) : ( + Math.asin((-Number.MIN_SAFE_INTEGER >>> 0)))) | 0)) | 0) | 0)) | 0) : Math.min(y, y)))) >>> 0)); }); testMathyFunction(mathy3, [(new Boolean(false)), NaN, '\\0', [0], undefined, ({valueOf:function(){return '0';}}), '0', (new Number(-0)), '/0/', (new String('')), false, -0, '', objectEmulatingUndefined(), null, (new Boolean(true)), ({valueOf:function(){return 0;}}), (new Number(0)), 0.1, [], true, /0/, (function(){return 0;}), 1, ({toString:function(){return '0';}}), 0]); ");
/*fuzzSeed-202342322*/count=330; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + (((((Math.fround(Math.abs((y , -(2**53-2)))) * ( + x)) | 0) | 0) ? mathy0(x, (( ! Math.fround((-0x080000000 ? (Math.atan2((x | 0), x) | 0) : (Math.pow((y >>> 0), x) >>> 0)))) >>> 0)) : Math.log(( ! (Math.pow(Math.fround(mathy0(Math.fround(x), Math.fround(y))), y) | 0)))) & ( + mathy0(( + Math.atan2(Math.exp(( - y)), ( + Math.fround((( ~ (((Math.atanh(x) | 0) , 42) | 0)) === ((Math.atan2(-0x080000001, Number.MIN_VALUE) + Math.imul(Math.fround(mathy0(Math.fround(-0x100000001), Math.fround(y))), Number.MAX_SAFE_INTEGER)) >>> 0)))))), mathy0(Math.fround(( - Math.fround(( ~ -0x100000000)))), Math.asin(x)))))); }); testMathyFunction(mathy1, [-0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, 1, 0, 0x0ffffffff, -0x080000001, -0, Number.MIN_SAFE_INTEGER, -1/0, 0/0, 1.7976931348623157e308, -(2**53+2), 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 1/0, -0x100000000, -0x07fffffff, 2**53-2, -(2**53-2), Number.MAX_VALUE, -(2**53), Number.MIN_VALUE, 0.000000000000001, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, 0x080000001, 0x080000000]); ");
/*fuzzSeed-202342322*/count=331; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = ((imul(((((i1)) | ((i1)-((0x737e8b50)))) != (((-0x70a7def)+(!(0xfdc826fc))) & ((i1)-('fafafa'.replace(/a/g, new Function))))), (0xff1ca2e3))|0) < (~((!(((0xe6e55*(0xfb51937b))>>>((-0x8000000)+(0xfc845a23)-(-0x7d68634))) == (0xa7927507)))-(-0x8000000))));\n    }\n    (Uint32ArrayView[1]) = (0x8f84a*(!(i1)));\n    (Int8ArrayView[((Float32ArrayView[((i1)+(i1)) >> 2])) >> 0]) = ((i1)-(((576460752303423500.0)))+(0xffffffff));\n    d0 = (-144115188075855870.0);\n    {\n      (Uint8ArrayView[0]) = ((0xc61997a9));\n    }\n    {\n      i1 = (i1);\n    }\n    d0 = (-3.022314549036573e+23);\n    d0 = (+pow(((0x5a3a2830)), ((+((268435457.0))))));\n    (Float32ArrayView[0]) = ((-67108864.0));\n    {\n      return +((d0));\n    }\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: Array.prototype.pop}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-202342322*/count=332; tryItOut("\"use strict\"; m0.set(a2, a1);");
/*fuzzSeed-202342322*/count=333; tryItOut("\"use strict\"; f1.valueOf = (function() { try { print(f0); } catch(e0) { } m0 = new Map(g0.e0); return f2; });");
/*fuzzSeed-202342322*/count=334; tryItOut("this.o0.a1.forEach((function() { for (var j=0;j<26;++j) { f1(j%5==0); } }));");
/*fuzzSeed-202342322*/count=335; tryItOut("mathy0 = (function(x, y) { return (Math.hypot((Math.cos(y) >>> 0), (( ~ ( + Math.abs(Math.hypot(y, x)))) <= Math.fround(Math.sign(Math.fround(y))))) ? Math.exp(((Math.cosh(x) >>> 0) * Math.ceil(Math.sinh((x | 0))))) : (( + (Math.min(x, (Math.expm1((-Number.MIN_SAFE_INTEGER != Math.max(y, y))) >>> 0)) >>> 0)) & (Math.cos(Math.fround(Math.log(Math.fround((Math.min(-0x080000001, x) | 0))))) | 0))); }); testMathyFunction(mathy0, [1/0, 42, 0, 0.000000000000001, -0x080000000, 0/0, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53-2), -1/0, 0x080000001, 0x100000001, 2**53+2, -0, 0x080000000, -(2**53), -0x080000001, 1, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, 2**53, Math.PI, 0x07fffffff, -0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, -(2**53+2), -0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-202342322*/count=336; tryItOut("mathy4 = (function(x, y) { return ((Math.tanh((Math.pow(Math.log1p(Math.atan2((((( + y) << (y >>> 0)) >>> 0) | 0), Math.sqrt(y))), ((Math.fround(mathy1(Math.fround(-0x100000000), ((Math.min(y, (y | 0)) | 0) >>> 0))) | 0) > x)) >>> 0)) >>> 0) ? (( ! (Math.atan2(( ~ Math.asin(x)), y) <= x)) >>> 0) : (Math.tanh((( + ((x >>> 0) ^ (( ~ x) | x))) | 0)) | 0)); }); ");
/*fuzzSeed-202342322*/count=337; tryItOut("for (var p in m1) { try { o2 + this.o1; } catch(e0) { } Array.prototype.reverse.apply(a1, [o0.p1, f1, b2]); }");
/*fuzzSeed-202342322*/count=338; tryItOut("\"use strict\"; h2 = v1;");
/*fuzzSeed-202342322*/count=339; tryItOut("Array.prototype.splice.call(a1, -9, ({valueOf: function() { v0.toSource = (function() { try { g2.v2 = Object.prototype.isPrototypeOf.call(e2, g1.g1); } catch(e0) { } v2 = true; return t0; });return 2; }}));");
/*fuzzSeed-202342322*/count=340; tryItOut("/*tLoop*/for (let z of /*MARR*/[false, ({}), ({}), false, false, false, ({}), ({}), ({}), false, false, false, ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), false, false, false, false, ({}), ({}), false, false, false, ({}), ({}), ({}), ({}), false, false, ({}), ({}), false, ({}), false, false, ({}), false, false, ({}), ({}), false, ({}), false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, ({}), false, false, false, false, ({}), false, ({}), ({}), ({}), false, ({}), ({}), false, ({}), false, ({}), ({}), false, ({}), false, false, ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), false, false, ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), false, false, false, ({}), false, false, ({}), ({}), ({}), false, ({}), false, false, false, false, false, false, false, ({}), false, ({}), false, false, ({}), ({}), ({}), false]) { /*tLoop*/for (let b of /*MARR*/[(void 0), new Boolean(true), {}, new Boolean(true), new Boolean(true), (void 0), {}, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (void 0)]) { /*MXX3*/g1.Promise.prototype.catch = g1.Promise.prototype.catch; } }");
/*fuzzSeed-202342322*/count=341; tryItOut("var fbolek = new SharedArrayBuffer(4); var fbolek_0 = new Float64Array(fbolek); var fbolek_1 = new Uint8Array(fbolek); fbolek_1[0] = 21; var fbolek_2 = new Uint32Array(fbolek); var fbolek_3 = new Float32Array(fbolek); fbolek_3[0] = -9; /*RXUB*/var r = this.r2; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); s2 += 'x';/*RXUB*/var r = new RegExp(\"[^](?!([\\\\\\u00fd]\\\\d\\\\B-\\\\u0095])|(?:\\\\u73C2)|\\u00b5+?)?(?:..?|.*?+)|(?!(?=[^])|(?=[^])?^|(\\\\b)|[^\\u0016-\\\\u8f6A\\\\W\\\\d\\\\d]+(?:(\\\\s|[^]))*?)\", \"ym\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-202342322*/count=342; tryItOut("mathy2 = (function(x, y) { return (Math.max((( ~ Math.fround(Math.atan2(x, ( + ( ! 0/0))))) | 0), (Math.min(Math.fround((Math.fround(Math.atan2(y, (( + Math.max(y, y)) | 0))) || x)), (Math.hypot(Math.exp(((x | 0) || ((x >>> 0) ^ x))), ( ! y)) | 0)) | 0)) | 0); }); testMathyFunction(mathy2, [-0, 0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000000, 1, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, Number.MIN_VALUE, 0/0, -0x080000001, 0x07fffffff, 0x080000001, 0, -(2**53-2), 2**53, 0.000000000000001, -Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), 42, 0x0ffffffff, 2**53+2, -1/0, Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, -0x07fffffff]); ");
/*fuzzSeed-202342322*/count=343; tryItOut("\"use strict\"; function shapeyConstructor(tvasli){if ( \"\" ) Object.defineProperty(this, \"endsWith\", ({configurable: (x % 19 != 18), enumerable: false}));return this; }/*tLoopC*/for (let w of [(/*FARR*/[...[], -3, ...[], 16, [,,]].some(objectEmulatingUndefined)) for (this.a of ( == (4277))) for each (\u3056 in /*MARR*/[]) for (\u3056 of x) if ( /* Comment *//*FARR*/[false, b, ...[]])]) { try{let alxgzf = new shapeyConstructor(w); print('EETT'); aozhtr(((uneval(x))), ((uneval(new /[^]|(?!(.|.*?)(?=\\d|[^\\s\\\u00f0\\S])(?!\\f){1,1})/gi( /x/ ,  '' )))));/*hhh*/function aozhtr(...c){((4277));}}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-202342322*/count=344; tryItOut("v1 = (i2 instanceof s2);");
/*fuzzSeed-202342322*/count=345; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.log2(( + ( + mathy1(( + ( - Math.sqrt(Math.min(x, ( + Math.clz32(-0x0ffffffff)))))), ( + (Math.pow(Math.fround(mathy1(( + ( + mathy1(x, (x | 0)))), ( + ( - Math.log1p(y))))), ( + ( - 1.7976931348623157e308))) >>> 0))))))); }); testMathyFunction(mathy2, ['/0/', ({toString:function(){return '0';}}), null, (new Boolean(true)), false, (new String('')), /0/, -0, (new Number(-0)), '', objectEmulatingUndefined(), '\\0', true, undefined, 0.1, NaN, ({valueOf:function(){return 0;}}), [0], 0, (new Number(0)), 1, [], (function(){return 0;}), (new Boolean(false)), '0', ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-202342322*/count=346; tryItOut("v2 = Object.prototype.isPrototypeOf.call(s0, m2);");
/*fuzzSeed-202342322*/count=347; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.atan2((( + ( ~ ( + (( + x) % ( + x))))) >>> 0), (Math.hypot(Math.fround(mathy2((( ~ y) >>> 0), ( ! mathy3(x, -1/0)))), ((( ! (( - (y | 0)) >>> 0)) >>> 0) ? Math.asin(((Math.cosh(0x080000001) ? (x >>> 0) : (( ~ (x >>> 0)) >>> 0)) >>> 0)) : ((Math.pow(((Math.max(((( ! (y >>> 0)) >>> 0) | 0), (y | 0)) | 0) >>> 0), (( - ( + mathy3(y, (-0x100000001 | 0)))) | 0)) | 0) >>> 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-202342322*/count=348; tryItOut("mathy0 = (function(x, y) { return (Math.ceil(( + Math.fround((Math.fround((Math.asin(( + (( + 0/0) && (Math.exp((y >>> 0)) - y)))) | 0)) < Math.fround((( + ((x >>> 0) * (( + ((Math.sinh((-0x100000000 >>> 0)) >>> 0) ? -1/0 : (x ^ 2**53-2))) >>> 0))) === ((((x | 0) >>> (( + Math.atan2(2**53, (y | 0))) | 0)) | 0) | 0))))))) | 0); }); testMathyFunction(mathy0, /*MARR*/[[(void 0)], x, true, true, true, x, true, [(void 0)], true, x, true, true, [(void 0)], [(void 0)], true, x, true, x, [(void 0)], true, [(void 0)], x, true, [(void 0)], x, [(void 0)], [(void 0)], [(void 0)], [(void 0)], x, [(void 0)], true, true, true, x, x, x, [(void 0)], x, x, x, true, true, x, x, true, x, true, true, x, x, x, x, x, x, x, true, [(void 0)], true, true, true, x, true, true, true, x, [(void 0)], true, x, [(void 0)], true, [(void 0)], x, x, true, [(void 0)], true, x, true, x, x, x, [(void 0)], true, [(void 0)], true, x, [(void 0)], [(void 0)], [(void 0)], x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, [(void 0)], true, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], true, x, true, [(void 0)]]); ");
/*fuzzSeed-202342322*/count=349; tryItOut("testMathyFunction(mathy2, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, -0, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000000, 0, -1/0, 1/0, -0x100000001, 0x07fffffff, -0x0ffffffff, -(2**53+2), -(2**53), 0x100000000, 0x0ffffffff, 2**53, 42, -0x080000000, Number.MIN_VALUE, 2**53+2, 0/0, 0x080000001, -Number.MIN_VALUE, 0.000000000000001, Math.PI, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 1]); ");
/*fuzzSeed-202342322*/count=350; tryItOut("let eval;a2.forEach((function mcc_() { var zgiwvu = 0; return function() { ++zgiwvu; f1(/*ICCD*/zgiwvu % 2 == 0);};})());");
/*fuzzSeed-202342322*/count=351; tryItOut("selectforgc(this.o2);");
/*fuzzSeed-202342322*/count=352; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.sinh(Math.fround(Math.log(Math.fround(Math.imul(Math.fround(( + y)), Math.fround((Math.log10((x | 0)) | 0))))))) | mathy1(Math.asin(((Math.fround(y) || Math.fround(y)) && mathy3(-Number.MAX_SAFE_INTEGER, ( - y)))), (Math.min(( + x), Math.fround((Math.expm1((Math.asinh((x | 0)) | 0)) | 0))) >>> 0))); }); testMathyFunction(mathy4, [42, -Number.MAX_VALUE, 2**53, 0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, 1.7976931348623157e308, -(2**53), Number.MAX_VALUE, -1/0, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, -Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 0, -0, -(2**53+2), 2**53-2, 1, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, -0x0ffffffff, 0/0, 0x07fffffff, -0x080000000, 1/0, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=353; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=354; tryItOut("mathy5 = (function(x, y) { return Math.fround(mathy1(Math.fround((Math.atan2(((Math.atan2((Math.atan2(Math.fround(Math.min(Math.fround(y), (( ! -Number.MAX_VALUE) >>> 0))), ( + (( + Math.trunc(( + x))) >>> 0))) >>> 0), ((( + (( + Math.sin(( + x))) | 0)) >>> 0) >>> 0)) >>> 0) | 0), (Math.fround((Math.fround((-0x0ffffffff != y)) | Math.fround(0x100000000))) | 0)) | 0)), Math.fround(Math.atanh(( + mathy2(( + x), ( + ( ~ ( + Math.fround((Math.fround(x) || Math.fround(( ~ x))))))))))))); }); testMathyFunction(mathy5, /*MARR*/[true, new Number(1), new Number(1), true, new Number(1), new Number(1), new Number(1), true, true, true, true, true, new Number(1), true, new Number(1), new Number(1), new Number(1), true, new Number(1), true, new Number(1), new Number(1), true, true, new Number(1), true, new Number(1), new Number(1), new Number(1), new Number(1), true, true, true, true, true, new Number(1), true, true, new Number(1), true, new Number(1), true, true, true, true, new Number(1), new Number(1), true, new Number(1), true, true, true, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), true, new Number(1), new Number(1), new Number(1), true, new Number(1), new Number(1), new Number(1), true, new Number(1), new Number(1), new Number(1), true, new Number(1), true, new Number(1), true, new Number(1), true, new Number(1), true, true, true, new Number(1), new Number(1), true, true, true, true, new Number(1), true, new Number(1), new Number(1), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, new Number(1), true, new Number(1), true, true, new Number(1), true, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), true, true, new Number(1), new Number(1), true, true, true, true, new Number(1), true, new Number(1), true]); ");
/*fuzzSeed-202342322*/count=355; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.expm1((Math.cos(( + Math.fround(Math.min(Math.fround(( + Math.expm1(y))), Math.fround((( + y) , y)))))) >>> 0)); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, 0x0ffffffff, 0x07fffffff, -0x100000000, 2**53+2, Number.MAX_VALUE, 1, 0.000000000000001, 0x080000000, -0x080000001, -0x080000000, Math.PI, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 0, -0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, 0/0, 42, -0x0ffffffff, -(2**53), 0x100000000, -(2**53+2), -0, 0x100000001, 1/0, 0x080000001, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-202342322*/count=356; tryItOut("Array.prototype.shift.call(a1);");
/*fuzzSeed-202342322*/count=357; tryItOut("v0 = evaluate(\"g2.s0 += 'x';\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-202342322*/count=358; tryItOut("\"use strict\"; Array.prototype.shift.call(a1);");
/*fuzzSeed-202342322*/count=359; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (((((Math.sinh((Math.hypot(( + (( + -0x0ffffffff) ** ( + ( + ( ~ x))))), ( - ( + ( - ( + -0))))) | 0)) | 0) >>> 0) === ((((Math.min((x | 0), (Math.fround(( ! (( + (-Number.MIN_VALUE | 0)) | 0))) | 0)) | 0) >= -0x080000001) >>> 0) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy0, [objectEmulatingUndefined(), [0], '/0/', (new Boolean(false)), 1, (new String('')), -0, 0.1, 0, '\\0', true, undefined, [], (new Boolean(true)), (new Number(0)), ({valueOf:function(){return '0';}}), '', (new Number(-0)), ({valueOf:function(){return 0;}}), '0', NaN, /0/, (function(){return 0;}), false, null, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-202342322*/count=360; tryItOut("o2.h1.delete = f1;");
/*fuzzSeed-202342322*/count=361; tryItOut("for (var v of g1) { try { t2[x] = undefined; } catch(e0) { } try { s0 += 'x'; } catch(e1) { } try { v0 = Infinity; } catch(e2) { } v1 = new Number(-0); }\nArray.prototype.splice.apply(g1.a2, [NaN, \"\\u8B75\" = String.fromCharCode(), g0]);\n");
/*fuzzSeed-202342322*/count=362; tryItOut("o2 = new Object;");
/*fuzzSeed-202342322*/count=363; tryItOut("this.e1.add(g0.b0);");
/*fuzzSeed-202342322*/count=364; tryItOut("\"use strict\"; print(({x: x}));");
/*fuzzSeed-202342322*/count=365; tryItOut("\"use strict\"; /*vLoop*/for (gnpdgr = 0; ([]) && gnpdgr < 29; ++gnpdgr) { a = gnpdgr; /*RXUB*/var r = r2; var s = s1; print(uneval(r.exec(s))); print(r.lastIndex);  } ");
/*fuzzSeed-202342322*/count=366; tryItOut("v0 = evalcx(\"\\\"use strict\\\"; s0 = Array.prototype.join.apply(g1.a0, [s2]);\", o0.g1);");
/*fuzzSeed-202342322*/count=367; tryItOut("g1.t2.set(t1, 1);");
/*fuzzSeed-202342322*/count=368; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x100000000, 2**53, 0x080000001, 0x0ffffffff, -0x100000001, 2**53+2, -0, Number.MIN_SAFE_INTEGER, 1, -0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, 1/0, 0, 2**53-2, 0.000000000000001, -(2**53+2), 0/0, Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, -0x07fffffff, -1/0, 42, 0x100000001, 0x07fffffff, -0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000]); ");
/*fuzzSeed-202342322*/count=369; tryItOut("e1.__iterator__ = f2;");
/*fuzzSeed-202342322*/count=370; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ! ((Math.fround(Math.exp(y)) , Math.log1p(( + Math.atan2(( + Math.log2(x)), ( + (Math.hypot(( + y), ( + (x - 0))) >= y)))))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), (1/0), (1/0), (1/0), objectEmulatingUndefined(), function(){}, (1/0)]); ");
/*fuzzSeed-202342322*/count=371; tryItOut("Array.prototype.sort.apply(this.a2, [f1]);");
/*fuzzSeed-202342322*/count=372; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.acos(( ! ( - (x ? ( + 0x100000001) : (y | 0))))); }); testMathyFunction(mathy4, [objectEmulatingUndefined(), NaN, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (new Boolean(true)), [0], (new String('')), true, -0, '', (new Number(0)), null, (new Boolean(false)), (function(){return 0;}), '/0/', 0.1, 1, 0, [], undefined, (new Number(-0)), '\\0', false, '0', ({valueOf:function(){return 0;}}), /0/]); ");
/*fuzzSeed-202342322*/count=373; tryItOut("\"use strict\"; while(((Proxy.revocable)()) && 0){v2 = this.o2.a0.length;a1 + ''; }let e = (void options('strict_mode'));");
/*fuzzSeed-202342322*/count=374; tryItOut("\"use strict\"; Array.prototype.shift.call(a1);");
/*fuzzSeed-202342322*/count=375; tryItOut("/*tLoop*/for (let e of /*MARR*/[2**53, (1/0), (1/0), (1/0), 2**53, (1/0), 2**53, 2**53, 2**53, (1/0), 2**53, 2**53, (1/0), (1/0), 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, (1/0), 2**53, 2**53, (1/0), 2**53, 2**53, 2**53, (1/0), 2**53, (1/0), (1/0), (1/0), 2**53, 2**53, (1/0), (1/0), (1/0), (1/0), 2**53, 2**53, 2**53, (1/0), (1/0), 2**53, (1/0), 2**53, 2**53, 2**53, (1/0), (1/0), (1/0), 2**53, (1/0), (1/0), (1/0)]) { {this.v2 = (i1 instanceof o0); } }");
/*fuzzSeed-202342322*/count=376; tryItOut("o2.a2.unshift(g2, g2);");
/*fuzzSeed-202342322*/count=377; tryItOut("print(uneval(p1));");
/*fuzzSeed-202342322*/count=378; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.sinh(Math.fround(Math.sign(Math.atan2(Math.cosh(Math.cos(y)), (y > Math.cosh((Math.hypot(((0x0ffffffff == y) | 0), (Math.acos(y) | 0)) | 0)))))))); }); ");
/*fuzzSeed-202342322*/count=379; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.log1p(((Math.fround((42 / (Math.pow((0.000000000000001 | 0), (y | 0)) | 0))) ? Math.cosh((((x | 0) * (( - -1/0) | 0)) | 0)) : ((Math.log1p((0x100000001 | 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [({valueOf:function(){return '0';}}), (new Number(0)), ({toString:function(){return '0';}}), 1, 0.1, null, NaN, '0', (new Number(-0)), (new Boolean(true)), true, -0, /0/, [0], '/0/', '', objectEmulatingUndefined(), false, 0, ({valueOf:function(){return 0;}}), undefined, (new Boolean(false)), (new String('')), (function(){return 0;}), '\\0', []]); ");
/*fuzzSeed-202342322*/count=380; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -3.022314549036573e+23;\n    d2 = (+(-1.0/0.0));\n    d2 = (268435457.0);\n    d2 = (137438953473.0);\n    i0 = (0xfe87f269);\n    return (((((x , Math.pow(14, true))>>>((i0)-((~~(-281474976710657.0)))+((((/*FFI*/ff(((1099511627777.0)))|0)+((0x4b04262) <= (0x7fffffff))-(/*FFI*/ff(((-33554432.0)), ((129.0)), ((524289.0)), ((8388607.0)))|0))|0)))))))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [2**53+2, 0, -Number.MAX_VALUE, -0x080000001, 0.000000000000001, 1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 0x100000001, 42, Math.PI, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 1, 0x080000000, 0x07fffffff, -(2**53-2), -Number.MIN_VALUE, 0x100000000, -1/0, -0x07fffffff, Number.MIN_VALUE, -(2**53), -0, 0x080000001, -0x100000000, -(2**53+2)]); ");
/*fuzzSeed-202342322*/count=381; tryItOut("s0.toSource = (function() { for (var j=0;j<141;++j) { f2(j%5==1); } });");
/*fuzzSeed-202342322*/count=382; tryItOut("\"use strict\"; /*infloop*/ for  each(let c in Math.imul(-0, -2)) with((window.throw(\"\\u6B9C\"))){print(true); }");
/*fuzzSeed-202342322*/count=383; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Int8ArrayView[((i0)+(i1)-((~((0xec73d01e)-(0xcf5dacf)-(0x685ef0c1))))) >> 0]) = ((window >> \"\\u1F68\")+(i0));\n    return (((i1)+(i0)+(i0)))|0;\n  }\n  return f; })(this, {ff: (Object.defineProperty(x, -16, ({})))}, new ArrayBuffer(4096)); ");
/*fuzzSeed-202342322*/count=384; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.sin(( + (( ~ (Math.atan(( + (( + Math.fround((y ** Math.fround(y)))) !== ( + ( ~ x))))) === x)) ? Math.pow(x, (Math.pow((Math.max(x, -0x07fffffff) | 0), ((( ~ ((0x100000000 & 0x0ffffffff) | 0)) | 0) | 0)) | 0)) : (( + (( + Math.imul(((((x >>> 0) == (Number.MIN_VALUE | 0)) >>> 0) >>> 0), x)) ? ( + Math.log2(x)) : ( + ((Math.log1p(0x07fffffff) >>> 0) / ( + y))))) ? ( + Math.fround(Math.log10(Math.fround(Math.fround(( - Math.fround(2**53-2))))))) : Math.log1p(Math.atan2((y >>> 0), Math.min((x && (y | 0)), y))))))); }); testMathyFunction(mathy0, [0x080000000, -(2**53+2), 2**53, -0x0ffffffff, 0x100000001, Number.MIN_VALUE, -(2**53-2), -0x100000000, -0x080000000, -Number.MAX_VALUE, -0x100000001, 0.000000000000001, 2**53+2, -Number.MIN_SAFE_INTEGER, 0, 1/0, -0x07fffffff, Math.PI, Number.MAX_VALUE, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, 1, 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, 0x080000001, 0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, -0, -Number.MIN_VALUE]); ");
/*fuzzSeed-202342322*/count=385; tryItOut("\"use strict\"; v0 = g0.eval(\"mathy4 = (function(x, y) { return (Math.trunc((( ! (Math.fround(( + ( + (((0.000000000000001 | 0) ? ((Math.tanh(x) >>> 0) | 0) : (Math.atan2((-1/0 >>> 0), Math.fround(-(2**53))) | 0)) | 0)))) | 0)) | 0)) >>> 0); }); \");");
/*fuzzSeed-202342322*/count=386; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.hypot((Math.hypot((y ? (Math.fround((Math.fround(( ! Math.fround(x))) >> (( + mathy1(( + ((( + y) ? ( + y) : ( + 2**53-2)) | 0)), ( + 0x100000001))) << y))) | 0) : Math.fround(( ! ( + (x >> 0x07fffffff))))), ( + (( + Math.min(( + y), ( + ( - Math.fround(mathy0(Number.MAX_SAFE_INTEGER, Math.fround(2**53-2))))))) ^ ( + ( ~ ( + y)))))) | 0), (( + ( ~ (Math.fround(Math.cos(( + (((( + Math.acos(( + x))) >>> 0) << (((x | 0) % x) >>> 0)) >>> 0)))) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-202342322*/count=387; tryItOut("\"use strict\"; Object.seal(v1);");
/*fuzzSeed-202342322*/count=388; tryItOut("mathy3 = (function(x, y) { return ( + mathy2(((( + (( + x) / ( + Math.min(x, -(2**53-2))))) != (0x07fffffff | 0)) >>> 0), ( + (x | Math.fround((( + (Math.pow(0/0, 1.7976931348623157e308) >>> 0)) > Math.fround(( ~ (x >>> 0))))))))); }); testMathyFunction(mathy3, [0/0, -1/0, 1/0, -0x100000000, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0, 0x100000000, 1.7976931348623157e308, 0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, -Number.MIN_VALUE, 0x100000001, 2**53-2, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, 42, 0x080000000, 0x080000001, -0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), Math.PI, 1, 2**53+2, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=389; tryItOut("\"use strict\"; (void schedulegc(this.g2));");
/*fuzzSeed-202342322*/count=390; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.tanh(Math.hypot(x, ((-0x080000000 | 0) === (Math.max(( ~ y), x) | 0)))) % ( + Math.imul(( + (((Math.atanh(Math.fround((Math.max(mathy0(Math.abs(( + y)), -0x07fffffff), (Math.atan(x) | 0)) | 0))) | 0) & (y | 0)) | 0)), ( + ( + mathy3(Math.cos(Math.ceil((mathy1(( + mathy3(Math.fround(-0x0ffffffff), ( + y))), (x >>> 0)) | 0))), x))))))); }); testMathyFunction(mathy4, [-0x100000001, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, 0x0ffffffff, -1/0, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, 0, -0x080000001, 0x100000000, 0x07fffffff, 2**53, 0/0, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -(2**53), 2**53-2, 0.000000000000001, 0x080000001, -0x07fffffff, -0x080000000, -0x0ffffffff, 1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-202342322*/count=391; tryItOut("Array.prototype.sort.apply(g0.a0, [(function mcc_() { var ctetyz = 0; return function() { ++ctetyz; if (/*ICCD*/ctetyz % 10 == 5) { dumpln('hit!'); try { v2 = g1.a0.length; } catch(e0) { } try { g2.o2 + ''; } catch(e1) { } try { v1 = NaN; } catch(e2) { } v0 = (p1 instanceof g1.i1); } else { dumpln('miss!'); try { f0 = t2[16]; } catch(e0) { } for (var v of g0.f2) { try { i2 + ''; } catch(e0) { } try { i2 = new Iterator(g0.o2.p0); } catch(e1) { } m1.has(m1); } } };})(), g1, this.i0]);");
/*fuzzSeed-202342322*/count=392; tryItOut("\"use strict\"; (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24) { var r0 = 5 ^ 5; a13 = 8 + a9; var r1 = 3 / 8; var r2 = a6 / 2; var r3 = a19 & 2; var r4 = a20 / a18; var r5 = a10 * a20; a17 = r3 - a0; var r6 = 5 - a1; var r7 = a11 * a4; var r8 = r3 + r3; r0 = 7 % a15; a20 = 0 % a21; a18 = a22 ^ 0; var r9 = a3 % a6; print(a17); print(a1); var r10 = r6 / a23; var r11 = a12 & a17; var r12 = 8 + a4; var r13 = 6 + a24; r6 = 7 / r0; r1 = a19 & a18; var r14 = 8 | a5; r1 = r1 % 2; var r15 = 7 * a20; print(a9); var r16 = r1 | 3; r14 = a14 - a5; var r17 = 5 | a15; var r18 = x ^ a24; r8 = r2 & a4; var r19 = r11 * r16; var r20 = 6 | 0; a9 = a19 + a9; var r21 = a23 / r13; var r22 = a19 * 4; a18 = a17 + a21; print(a9); r2 = r1 - x; var r23 = r5 - r10; print(r9); var r24 = 2 - a8; var r25 = a4 | a20; var r26 = r14 ^ 1; var r27 = r26 * 1; var r28 = r18 ^ a4; r27 = a15 * a8; print(r6); r6 = a7 / 1; var r29 = r9 + a4; var r30 = r1 | r7; var r31 = 1 - a7; var r32 = r9 - 7; var r33 = 9 * 8; a7 = r16 * 4; var r34 = a4 % r30; var r35 = a20 * a17; a14 = r25 / r22; r1 = a20 % 8; a3 = 1 | 1; var r36 = a16 * a9; var r37 = r4 + r18; var r38 = r15 + 6; var r39 = 0 + r9; r35 = a6 & r13; var r40 = 3 % 7; var r41 = r10 - r31; var r42 = r6 + r27; a12 = a17 * r10; a23 = a17 / r41; var r43 = 3 * 6; var r44 = r18 + a18; var r45 = a10 % r37; var r46 = a20 & 5; r18 = r3 / 5; var r47 = r38 % r4; var r48 = 4 & 1; var r49 = r47 * x; var r50 = 3 / r19; var r51 = r45 / r4; var r52 = 3 * a1; x = r8 | r44; print(r50); var r53 = 4 / r10; r41 = 0 ^ 6; var r54 = r8 ^ a12; var r55 = 8 ^ a7; a19 = r8 % 3; var r56 = r55 & r39; r0 = a0 ^ r41; var r57 = 5 ^ 5; print(r31); var r58 = r22 / 3; var r59 = r57 / r28; r35 = r12 / r42; var r60 = 1 % r52; var r61 = a10 % 3; var r62 = 5 ^ 0; var r63 = 9 ^ r46; return a14; })");
/*fuzzSeed-202342322*/count=393; tryItOut("\"use strict\"; g1.o0.h0 = ({getOwnPropertyDescriptor: function(name) { a0 = arguments;; var desc = Object.getOwnPropertyDescriptor(g0.a1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { Array.prototype.shift.apply(a1, []);; var desc = Object.getPropertyDescriptor(g0.a1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e2.delete(o0);; Object.defineProperty(g0.a1, name, desc); }, getOwnPropertyNames: function() { i2 + v0;; return Object.getOwnPropertyNames(g0.a1); }, delete: function(name) { p1 = m2.get(h0);; return delete g0.a1[name]; }, fix: function() { /*ADP-3*/Object.defineProperty(a0, 16, { configurable: (x % 36 == 19), enumerable: [true], writable: true, value: v0 });; if (Object.isFrozen(g0.a1)) { return Object.getOwnProperties(g0.a1); } }, has: function(name) { throw v0; return name in g0.a1; }, hasOwn: function(name) { Array.prototype.sort.call(a2, (function() { for (var j=0;j<77;++j) { f0(j%2==0); } }), o0.f0, t1, m2);; return Object.prototype.hasOwnProperty.call(g0.a1, name); }, get: function(receiver, name) { i1.__iterator__ = (function() { try { a1.shift(); } catch(e0) { } try { a0.splice(5, 13, g1); } catch(e1) { } v1 = r1.source; return m0; });; return g0.a1[name]; }, set: function(receiver, name, val) { var g2.v0 = this.t0.BYTES_PER_ELEMENT;; g0.a1[name] = val; return true; }, iterate: function() { h0.getOwnPropertyNames = f1;; return (function() { for (var name in g0.a1) { yield name; } })(); }, enumerate: function() { this.h1 = ({getOwnPropertyDescriptor: function(name) { for (var v of o0.v2) { try { Array.prototype.shift.apply(this.a1, [new Array.from(((x) = new RegExp(\"\\\\1{2,3}\", \"gi\")),  /x/ ), a1]); } catch(e0) { } try { a2[ '' ] = this.s0; } catch(e1) { } /*ODP-3*/Object.defineProperty(p0, 5, { configurable: false, enumerable: a =  /x/g , writable: (x % 5 != 3), value: t2 }); }; var desc = Object.getOwnPropertyDescriptor(v2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var v2 = g1.runOffThreadScript();; var desc = Object.getPropertyDescriptor(v2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { e2.delete(p2);; Object.defineProperty(v2, name, desc); }, getOwnPropertyNames: function() { e1.add(o2.b2);; return Object.getOwnPropertyNames(v2); }, delete: function(name) { o2 = new Object;; return delete v2[name]; }, fix: function() { o0.t1 = this.t2.subarray(17);; if (Object.isFrozen(v2)) { return Object.getOwnProperties(v2); } }, has: function(name) { g0.m0.get(t0);; return name in v2; }, hasOwn: function(name) { s0 = s2.charAt(v0);; return Object.prototype.hasOwnProperty.call(v2, name); }, get: function(receiver, name) { t2 = new Int8Array(t0);; return v2[name]; }, set: function(receiver, name, val) { a1 = a0.map((function() { for (var j=0;j<12;++j) { f0(j%5==0); } }),  \"\" , i2);; v2[name] = val; return true; }, iterate: function() { ;; return (function() { for (var name in v2) { yield name; } })(); }, enumerate: function() { this.a0[({valueOf: function() { a2.unshift(m0);return 13; }})] = new ((void shapeOf(undefined)))(x);; var result = []; for (var name in v2) { result.push(name); }; return result; }, keys: function() { throw g2; return Object.keys(v2); } });; var result = []; for (var name in g0.a1) { result.push(name); }; return result; }, keys: function() { for (var p in t1) { try { o0.o0.a0.forEach((function mcc_() { var ejelfg = 0; return function() { ++ejelfg; f0(/*ICCD*/ejelfg % 11 == 9);};})(), o2.p0, o1.e1); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(o0.v2, e2); } catch(e1) { } b2 = t1.buffer; }; return Object.keys(g0.a1); } });v0 = Object.prototype.isPrototypeOf.call(b2, s2);");
/*fuzzSeed-202342322*/count=394; tryItOut("\"use strict\"; v2 = t1.length;");
/*fuzzSeed-202342322*/count=395; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( ~ (( + ( ! ( + ( ! ((( + x) ^ Math.fround(-0x07fffffff)) && x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x080000000, 1/0, 0x080000000, -Number.MIN_VALUE, 0x100000000, -0x100000000, -0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -0x100000001, Math.PI, 2**53-2, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), 0x07fffffff, 1, -(2**53), -(2**53+2), -Number.MAX_VALUE, 0, 0x080000001, -1/0, 42, 2**53, 0x0ffffffff, -0, 0x100000001, 0/0]); ");
/*fuzzSeed-202342322*/count=396; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+(((i0)) >> ((0xffffffff)+(0xfda04dc2)-((((0x9c456b38)) & ((i0))) > (abs((-0x8000000))|0)))));\n    {\n      (Uint16ArrayView[((let (y = [x]) (4277))) >> 1]) = ((!(/*FFI*/ff(((NaN)), (((((0x9b7348f5) ? (0xe5aad056) : (0x9ad0d31c))+((0x0) > (0x8fb403dc))+(0x4e049409))|0)), ((((i0)+(i0)) >> ((i0)+((0xb0f2902b))))), (((((-3.8685626227668134e+25) + (-1152921504606847000.0))) / ((Float32ArrayView[1])))), ((~~(d1))), ((-65537.0)), ((2048.0)), ((2.3611832414348226e+21)), ((-18446744073709552000.0)))|0))+(!(i0))+(((d1))));\n    }\n    {\n      i0 = (0xfa6d448f);\n    }\n    (Uint8ArrayView[(((abs((((0xfa1032d5)) >> ((0x1d4ad799))))|0) != ((-0x90084*(0x7639fc4a)) ^ ((Uint8ArrayView[1]))))+(((0xcad841d1)-(0xffffffff)))) >> 0]) = ((i0));\n    i0 = (!((0xfbc9f97) ? (i0) : ((((((1.1805916207174113e+21)) % ((34359738369.0)))) / ((32768.0))) >= ((i0) ? (+/*FFI*/ff(((2251799813685249.0)), ((-1.888946593147858e+22)), ((-9.0)), ((-6.044629098073146e+23)))) : (+(1.0/0.0))))));\n    return (((0x7fc60e06)-(i0)))|0;\n  }\n  return f; })(this, {ff: String.prototype.toString}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0, Math.PI, -Number.MIN_VALUE, 0x080000000, 2**53, -0x100000001, -0x07fffffff, -0, -1/0, -Number.MAX_VALUE, -(2**53-2), Number.MIN_VALUE, -0x080000000, 1, 0x100000001, -0x080000001, 0x100000000, 0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -(2**53), 0x080000001, 2**53+2, 42, Number.MAX_VALUE, 0.000000000000001, 0/0, 1/0]); ");
/*fuzzSeed-202342322*/count=397; tryItOut("e0.has(o2);");
/*fuzzSeed-202342322*/count=398; tryItOut("/*vLoop*/for (var wmqskb = 0; wmqskb < 97; ++wmqskb) { var y = wmqskb; const v1 = a1.some((function(j) { if (j) { try { s0 += s2; } catch(e0) { } o1.p1 + ''; } else { try { Array.prototype.pop.call(a0); } catch(e0) { } f2(this.t1); } }), this.s2); } ");
/*fuzzSeed-202342322*/count=399; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + (( + Math.acosh(1/0)) != ( + Math.imul(Math.fround((Math.fround(Math.pow(0, (Math.hypot(y, Math.fround(0x0ffffffff)) >>> 0))) & (y >>> 0))), (-Number.MIN_SAFE_INTEGER <= Math.imul(y, y)))))) !== Math.fround(((( + (Math.imul(((( ~ (y | 0)) | 0) >>> 0), (((Math.pow(-(2**53+2), Math.pow(x, x)) >>> 0) != x) >>> 0)) >>> 0)) >>> 0) ? (Math.round(( + (( + y) ? ( + ( + ( ! Math.fround(( ! x))))) : Math.fround(Math.imul(Math.fround(y), Math.fround(y)))))) >>> 0) : Math.imul(x, (Math.pow(0x100000001, (y >>> 0)) * (Math.fround(Math.acosh(Math.fround(Math.pow(( + 0.000000000000001), x)))) >>> 0)))))); }); testMathyFunction(mathy0, [-0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -0x100000000, -0x080000000, 42, -(2**53-2), -0x100000001, 1/0, -(2**53+2), 0.000000000000001, -0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, 0x100000000, 2**53, -(2**53), 0x100000001, 0x080000001, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, 0, -0x080000001, 0x07fffffff, 1]); ");
/*fuzzSeed-202342322*/count=400; tryItOut("g2.i1.next();");
/*fuzzSeed-202342322*/count=401; tryItOut("var c = -7 >> \"\\u1D41\";print(true);for (var p in g0.h2) { try { /*MXX2*/g0.g1.g1.String = b0; } catch(e0) { } try { ; } catch(e1) { } /*MXX2*/g1.ReferenceError.prototype = e1; }function y()x & evalh1.set = (function() { try { v2 = g0.a2.length; } catch(e0) { } try { Array.prototype.splice.call(o0.o1.a1, 11, window); } catch(e1) { } m0.delete(v0); return h2; });");
/*fuzzSeed-202342322*/count=402; tryItOut("const \u3056 = this();print(x);");
/*fuzzSeed-202342322*/count=403; tryItOut("/*oLoop*/for (var nlpets = 0; nlpets < 4; ++nlpets) { print(\"\\uEC54\"); } ");
/*fuzzSeed-202342322*/count=404; tryItOut("mathy2 = (function(x, y) { return (Math.max(( ~ ((Math.atanh(( ! -1/0)) === ( + mathy1(y, y))) >>> 0)), ( + Math.acos((Math.fround((Number.MAX_VALUE >>> 0)) | 0)))) >>> 0); }); testMathyFunction(mathy2, [-0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, 1, 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, -0, -0x0ffffffff, -Number.MAX_VALUE, -0x080000000, 0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -(2**53-2), Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, 0x080000000, 0/0, 42, 0x100000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, -Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, 1/0, 0, -0x080000001, 2**53+2]); ");
/*fuzzSeed-202342322*/count=405; tryItOut("\"use strict\"; m2 + '';");
/*fuzzSeed-202342322*/count=406; tryItOut("\"use strict\"; /*iii*/v1 = a1.length;/*hhh*/function swqhnt(x = (\"\\uC8B4\").bind().prototype, ...\u3056){m1.get(a1);}");
/*fuzzSeed-202342322*/count=407; tryItOut("mathy5 = (function(x, y) { return (( + (( ! Math.fround((Math.cos((Math.min((y >>> 0), Math.fround(Math.pow(Math.fround(x), ( - y)))) | 0)) | 0))) >>> 0)) != ( + Math.sign((Math.asinh(Math.imul(y, ((( + Math.hypot(( + y), (y >>> 0))) , Math.cos(y)) | 0))) >>> 0)))); }); testMathyFunction(mathy5, /*MARR*/[ /x/g , (1/0), {x:3},  /x/g , {x:3},  /x/g ,  /x/g , {x:3},  /x/g , {x:3},  /x/g , {x:3}, {x:3}, {x:3}, (1/0), (1/0), (1/0), {x:3}, (1/0), (1/0), {x:3}, {x:3}, {x:3},  /x/g ,  /x/g , {x:3}, {x:3}, (1/0), {x:3}, {x:3}, {x:3}, {x:3},  /x/g , {x:3}, (1/0), {x:3}, {x:3}, (1/0), {x:3},  /x/g , {x:3}, {x:3},  /x/g ,  /x/g ,  /x/g , {x:3}, {x:3}, {x:3}, {x:3}, (1/0), (1/0),  /x/g , (1/0), {x:3},  /x/g ,  /x/g ,  /x/g , {x:3}, {x:3}, {x:3},  /x/g , {x:3},  /x/g , {x:3}, {x:3}, {x:3}, {x:3},  /x/g ,  /x/g ,  /x/g , {x:3}, (1/0), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, (1/0), {x:3}, {x:3}, (1/0), (1/0), (1/0),  /x/g ,  /x/g , {x:3}, {x:3}, (1/0), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, (1/0), {x:3}, (1/0), (1/0), (1/0), {x:3}, {x:3}, {x:3}, (1/0), (1/0),  /x/g ,  /x/g , {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, (1/0), (1/0), {x:3},  /x/g ,  /x/g , {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, (1/0),  /x/g , (1/0), {x:3}]); ");
/*fuzzSeed-202342322*/count=408; tryItOut("{ void 0; void schedulegc(this); } /*hhh*/function xdojol(\u3056){print(x);}xdojol(new RegExp(\"((?:\\\\B|\\\\b?)+?)\", \"gym\"));");
/*fuzzSeed-202342322*/count=409; tryItOut("testMathyFunction(mathy1, ['0', (new Boolean(true)), '', -0, (new Boolean(false)), (function(){return 0;}), objectEmulatingUndefined(), (new String('')), '\\0', ({valueOf:function(){return 0;}}), null, NaN, /0/, [], [0], undefined, ({toString:function(){return '0';}}), 0, true, 0.1, false, (new Number(0)), (new Number(-0)), 1, '/0/', ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-202342322*/count=410; tryItOut(";");
/*fuzzSeed-202342322*/count=411; tryItOut("\"use strict\"; Array.prototype.push.call(a2, m2);");
/*fuzzSeed-202342322*/count=412; tryItOut("/*ADP-3*/Object.defineProperty(a1, (4277), { configurable: window, enumerable: true, writable: (x % 4 != 3), value: g2 });");
/*fuzzSeed-202342322*/count=413; tryItOut("mathy0 = (function(x, y) { return (Math.atan2((((((2**53-2 >>> 0) < (y <= Math.trunc(Math.min((x | 0), Math.min(x, y))))) >>> 0) || (Math.min((( + Math.imul(( + Math.fround(( + Math.fround(( + 0.000000000000001))))), y)) | 0), ((Math.fround(0) ? Math.hypot(x, (Math.PI | 0)) : y) >>> 0)) >>> 0)) | 0), (((( ~ y) ? ((( ~ -Number.MIN_VALUE) | 0) | 0) : (Math.hypot(((y & y) <= Math.trunc(Number.MIN_VALUE)), (y - x)) | 0)) == (( - x) & ((( + y) ? ( + Math.log((x | 0))) : (Math.pow((x << y), x) >>> 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, 1.7976931348623157e308, 1, 1/0, -0, 0x07fffffff, 0x100000000, 0/0, 2**53+2, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, 0.000000000000001, -(2**53), 2**53, 0x080000000, 42, 0x100000001, 2**53-2, 0x0ffffffff, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, -(2**53-2), -0x100000000]); ");
/*fuzzSeed-202342322*/count=414; tryItOut("a0 = arguments;");
/*fuzzSeed-202342322*/count=415; tryItOut("print(new DFGTrue(13,  /x/g ));\n/*RXUB*/var r = /(?!\\b+?|(?!.)|\\\u00c9{2147483647}+?[^]|\\1{1})[^]*|\\W/gyim; var s = \"0\"; print(s.search(r)); \n");
/*fuzzSeed-202342322*/count=416; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((Math.fround((Math.fround(Math.expm1(( + Math.expm1(Math.fround(y))))) % Math.fround(Math.max(Math.fround(Math.sign(((x + (( + y) != 0x080000000)) | 0))), Math.fround((( ~ x) - 2**53+2)))))) | 0) & ((Math.max(Math.sinh(Math.fround(( ~ (0.000000000000001 >>> 0)))), (Math.cos((Math.atan2(Math.fround(Math.max(Math.fround(y), Math.fround((y == y)))), y) >>> 0)) >>> 0)) <= ( - 0x0ffffffff)) | 0)) | 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -0x080000001, 1, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53-2), -0, Math.PI, 0x080000000, 0x0ffffffff, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, 0.000000000000001, 2**53, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, Number.MIN_VALUE, 0x07fffffff, 0x100000001, 2**53+2, -0x100000000, 42, -1/0, -(2**53), 0/0, -0x0ffffffff, 2**53-2, -Number.MAX_VALUE, 0]); ");
/*fuzzSeed-202342322*/count=417; tryItOut("x = x / x; var r0 = x * 9; x = r0 / 0; var r1 = 7 % r0; r0 = r1 - r1; var r2 = 2 / 6; var r3 = r2 * x; var r4 = 2 + r1; print(r3); var r5 = r2 ^ r1; var r6 = 4 | r0; var r7 = 1 * r1; var r8 = r0 | 0; var r9 = r4 | r8; ");
/*fuzzSeed-202342322*/count=418; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a0, []);");
/*fuzzSeed-202342322*/count=419; tryItOut("print(uneval(b2));");
/*fuzzSeed-202342322*/count=420; tryItOut("testMathyFunction(mathy5, [-0x080000000, 0/0, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 2**53-2, -(2**53-2), 42, -Number.MAX_VALUE, 1/0, -0x100000001, -0x07fffffff, 1, -Number.MIN_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0, Number.MIN_SAFE_INTEGER, 0, 0x100000000, 0x0ffffffff, -0x100000000, -0x080000001, 0x080000000, Math.PI, Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-202342322*/count=421; tryItOut("a0.sort((function() { a0[5] = \"\\uA645\" &= 5; return g0.o2.o0.g0; }));");
/*fuzzSeed-202342322*/count=422; tryItOut("v0.toSource = (function mcc_() { var pcoyez = 0; return function() { ++pcoyez; f0(/*ICCD*/pcoyez % 11 == 7);};})();function (d)(\u3056, \u3056)(4277)Object.prototype.watch.call(v0, \"splice\", (function() { try { a1.splice(NaN, 16, b2); } catch(e0) { } try { Object.defineProperty(this, \"a0\", { configurable: (p={}, (p.z = \"\\uD6F0\")()), enumerable: false,  get: function() {  return g0.a1.concat(f2, g1, t1); } }); } catch(e1) { } try { for (var p in e2) { try { v1 = evaluate(\"\\\"\\\\u3028\\\"\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x % 3 != 1), catchTermination: this })); } catch(e0) { } g2.m0.set(g2, (new RegExp(\"\\\\1|(?!([^])){2}\", \"gyi\") < [1])); } } catch(e2) { } this.s0 = ''; return p0; }));");
/*fuzzSeed-202342322*/count=423; tryItOut("mathy1 = (function(x, y) { return Math.exp(Math.round(((Math.atan2((y >>> 0), (Math.fround(Math.imul(((y ? (0 | 0) : (( + x) | 0)) | 0), x)) >>> 0)) >>> 0) ? y : (( - (y | 0)) >>> 0)))); }); ");
/*fuzzSeed-202342322*/count=424; tryItOut("function shapeyConstructor(zwforv){\"use strict\"; for (var ytqkcxjkm in zwforv) { }zwforv[\"0\"] = (4277);Object.freeze(zwforv);zwforv[\"wrappedJSObject\"] = (\"\\uB5DD\" ? [,] : new RegExp(\"[\\u001c\\\\s\\u8051-\\\\u0992\\\\u051f]\", \"gi\")).call;Object.freeze(zwforv);if (zwforv) zwforv[\"0\"] = Math.tanh;return zwforv; }/*tLoopC*/for (let y of ((4277) if (++arguments[\"14\"]))) { try{let pzmchb = shapeyConstructor(y); print('EETT'); /*RXUB*/var r = r2; var s = \"\\n\\n\"; print(s.split(r)); }catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-202342322*/count=425; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; abortgc(); } void 0; } /*bLoop*/for (var brevpe = 0; brevpe < 73; ++brevpe) { if (brevpe % 5 == 1) { print( '' ); } else { ( /x/g ); }  } ");
/*fuzzSeed-202342322*/count=426; tryItOut("testMathyFunction(mathy4, [-(2**53+2), -0x100000001, 2**53-2, -0x0ffffffff, Number.MIN_VALUE, 1/0, 0, 0x080000000, 0/0, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, Number.MAX_VALUE, -(2**53), 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, 42, -0x080000001, -0x080000000, 2**53+2, -0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 2**53, -Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0, 1]); ");
/*fuzzSeed-202342322*/count=427; tryItOut("\"use asm\"; a0.unshift(a2);");
/*fuzzSeed-202342322*/count=428; tryItOut("/*oLoop*/for (let uivkbc = 0; uivkbc < 49; ++uivkbc) { x.unwatch(\"prototype\"); } ");
/*fuzzSeed-202342322*/count=429; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max((Math.cos((((((Math.fround(x) >= Math.fround((Math.imul(x, ( + ( ! 0x080000001))) >>> 0))) | 0) >>> 0) , (mathy0((Math.log((0x0ffffffff >>> 0)) * Number.MIN_SAFE_INTEGER), (-(2**53+2) >>> 0)) >>> 0)) | 0)) | 0), (Math.fround(Math.fround(Math.imul(y, (Math.hypot((x >>> 0), (x >>> 0)) >>> 0)))) | ( + Math.fround((Math.fround(mathy0((((Math.max(Number.MAX_SAFE_INTEGER, x) >>> 0) << Math.fround((Math.fround(x) | Math.fround(y)))) >>> 0), mathy0(( + Math.fround(( + y))), x))) && Math.fround(Math.min(y, x))))))); }); testMathyFunction(mathy1, [-1/0, 1, 1/0, Math.PI, 0x07fffffff, -0x080000001, -(2**53), 0x080000000, -(2**53+2), -0x080000000, Number.MAX_VALUE, 0/0, 0x080000001, 0x100000001, 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, -0, 0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, -0x100000000, 2**53-2, -Number.MIN_VALUE, 0, 2**53+2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=430; tryItOut("\"use strict\"; L: i0 = t0[new RegExp(\"(?:\\\\b|(?!(\\\\B)))\", \"gyi\")];");
/*fuzzSeed-202342322*/count=431; tryItOut("for (var p in e0) { v0 = (i0 instanceof h0); }\no2 = Object.create(f1);\n");
/*fuzzSeed-202342322*/count=432; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-202342322*/count=433; tryItOut("mathy0 = (function(x, y) { return (Math.max(Math.cbrt(x), (( - (((Math.imul(( + 2**53+2), 0x07fffffff) >>> 0) && (Math.asinh(2**53-2) >>> 0)) >>> 0)) | 0)) < (( + Math.fround(( + Math.atan(( + ( ! ( + Math.sin(y)))))))) >>> 0)); }); ");
/*fuzzSeed-202342322*/count=434; tryItOut("Array.prototype.push.call(o2.a1, f0, \n(void window) || null(new RegExp(\"[^\\\\u0088-\\\\v]\", \"im\")-=Math.imul(29,  /x/g )), b0, (Function).call(((/*UUV2*/(\u3056.substring = \u3056.__lookupGetter__))(x)), x));");
/*fuzzSeed-202342322*/count=435; tryItOut("a1.splice(NaN, 0, a1);");
/*fuzzSeed-202342322*/count=436; tryItOut("for (var v of o2) { try { v2 = new Number(o0); } catch(e0) { } try { for (var v of g2) { try { o2.g0.v2.toSource = (function() { try { t0 = new Int32Array(b0); } catch(e0) { } f1 = Proxy.createFunction(h0, f2, f1); return o0.h2; }); } catch(e0) { } try { e0 = new Set(this.h0); } catch(e1) { } e0.toSource = (function() { for (var j=0;j<9;++j) { g1.f2(j%2==0); } }); } } catch(e1) { } Object.defineProperty(this, \"this.v0\", { configurable: true, enumerable: (x % 6 != 5),  get: function() {  return t2.length; } }); }\n;\n");
/*fuzzSeed-202342322*/count=437; tryItOut("\"use strict\"; /*bLoop*/for (pncbty = 0; pncbty < 133; ++pncbty) { if (pncbty % 92 == 70) { { void 0; void schedulegc(22); } } else { a1.sort((function() { for (var j=0;j<24;++j) { o1.g0.f2(j%5==1); } }), h0, window, f0, a1, v0, o0.o0);Array.prototype.pop.apply(this.a1, [ '' , a2]); }  } ");
/*fuzzSeed-202342322*/count=438; tryItOut("this.s2.valueOf = (function() { try { e0.has(s2); } catch(e0) { } try { /*MXX1*/o2 = g0.g1.Int32Array.prototype.BYTES_PER_ELEMENT; } catch(e1) { } /*MXX1*/o0 = g1.Array.prototype.find; throw p1; });");
/*fuzzSeed-202342322*/count=439; tryItOut("\"use strict\"; do s1 += 'x'; while(((eval)(x, (4277) instanceof x)) && 0);");
/*fuzzSeed-202342322*/count=440; tryItOut("\"use strict\"; t2.set(t1, new (String.prototype.small)((let (e=eval) e)))\n(x);");
/*fuzzSeed-202342322*/count=441; tryItOut("mathy3 = (function(x, y) { return (Math.tan(( + (Math.trunc(Math.cos(Math.min(x, x))) === (Math.fround(mathy2(y, ( + mathy2((( - (y | 0)) | 0), y)))) | 0)))) | 0); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 0x0ffffffff, 0x080000001, -0, -(2**53), 0x07fffffff, 0x080000000, 1/0, 2**53-2, -1/0, 0, -0x07fffffff, 0x100000000, Math.PI, 1, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -0x100000000, 2**53+2, 42, -Number.MAX_VALUE, -0x100000001, 2**53, -0x080000001, -Number.MIN_VALUE, 0/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-202342322*/count=442; tryItOut("a1.pop(o1.m2);");
/*fuzzSeed-202342322*/count=443; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((( ~ (((Math.fround(Math.imul(Math.hypot(mathy0(Math.fround(x), -Number.MAX_SAFE_INTEGER), y), x)) >>> 0) === (Math.pow(Math.fround(y), x) >>> 0)) >>> 0)) ** Math.exp(((Math.atan2(Math.hypot(y, 0x07fffffff), (Math.imul(y, ( ~ (( ~ (-(2**53+2) >>> 0)) >>> 0))) >>> 0)) >>> 0) >>> ( ! ( + Math.max(( + x), 42))))))); }); ");
/*fuzzSeed-202342322*/count=444; tryItOut("\"use asm\"; /*oLoop*/for (var jfbert = 0; jfbert < 21; new RegExp(\"(?:.*)|(?!\\\\2{1,})(?=$*|\\\\1){63}{4,}\", \"\"), ++jfbert) { v0 + g0.m2; } ");
/*fuzzSeed-202342322*/count=445; tryItOut("a1 + m1;");
/*fuzzSeed-202342322*/count=446; tryItOut("\"use strict\"; /*infloop*/for(let z = (4277); (4277); [(void options('strict'))]) o2 = p1.__proto__;");
/*fuzzSeed-202342322*/count=447; tryItOut("\"use strict\"; a2 + i1;");
/*fuzzSeed-202342322*/count=448; tryItOut("/*vLoop*/for (let suudgm = 0; suudgm < 30; ++suudgm) { const b = suudgm; v1 + i0; } \n/*RXUB*/var r = /(?=(?=$)[^]|$?|[]|.{0}*?(?:^{1,})*)/gy; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); \n");
/*fuzzSeed-202342322*/count=449; tryItOut("h1.get = (function() { try { e1.has(s1); } catch(e0) { } Array.prototype.unshift.apply(a2, [v0, g2.s2, p1, i2, h0, [[]], x < this.throw( /x/g )]); return g1.v0; });");
/*fuzzSeed-202342322*/count=450; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.replace(r, x, \"m\")); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=451; tryItOut("Object.defineProperty(this, \"t1\", { configurable: (x % 29 == 16), enumerable: (x % 6 == 2),  get: function() { m0 = new Map(g2.s1); return t1.subarray(3); } });");
/*fuzzSeed-202342322*/count=452; tryItOut("Array.prototype.splice.apply(a2, [NaN, 3, v1, g1]);");
/*fuzzSeed-202342322*/count=453; tryItOut("print({} = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { throw 3; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: false, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })([1,,]), 28));");
/*fuzzSeed-202342322*/count=454; tryItOut("testMathyFunction(mathy3, [(new String('')), NaN, ({toString:function(){return '0';}}), [0], true, (new Number(-0)), [], ({valueOf:function(){return '0';}}), (new Boolean(false)), (new Boolean(true)), '\\0', objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), '', -0, (new Number(0)), 0, 1, (function(){return 0;}), false, 0.1, '/0/', '0', null, /0/, undefined]); ");
/*fuzzSeed-202342322*/count=455; tryItOut("a2.pop();");
/*fuzzSeed-202342322*/count=456; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.atanh(Math.fround(Math.sin(Math.fround(Math.fround(Math.atan2((Math.pow(( ! (Math.asinh(y) | 0)), ( + x)) * ((( + (( + y) >> x)) >>> 0) && (mathy1((x >>> 0), (mathy1((x | 0), 2**53) >>> 0)) >>> 0))), ((Math.min(((( + (-Number.MIN_SAFE_INTEGER | 0)) | 0) >>> 0), x) >>> 0) & x)))))))); }); testMathyFunction(mathy3, [0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, -0x080000001, -(2**53-2), 0.000000000000001, -(2**53+2), Math.PI, Number.MIN_VALUE, 0/0, 1, 2**53-2, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 1.7976931348623157e308, -0x100000000, 2**53+2, -0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 0, -1/0, 0x07fffffff, -Number.MIN_VALUE, -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -0x080000000]); ");
/*fuzzSeed-202342322*/count=457; tryItOut("mathy4 = (function(x, y) { return Math.log10(Math.fround(Math.imul(Math.fround(( + mathy0(( + mathy1((Math.max(y, (y >>> 0)) >>> 0), (y >>> 0))), ( + x)))), Math.fround((Math.round(( + ( ~ y))) | 0))))); }); testMathyFunction(mathy4, [(new Number(0)), (new String('')), ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), 1, NaN, undefined, '/0/', (new Number(-0)), /0/, null, false, [0], (new Boolean(false)), [], -0, (new Boolean(true)), (function(){return 0;}), 0.1, '', true, 0, '\\0', objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), '0']); ");
/*fuzzSeed-202342322*/count=458; tryItOut("d = (this <= SharedArrayBuffer.valueOf(\"number\"));Object.defineProperty(this, \"v2\", { configurable: ((this.zzz.zzz) = \u0009d), enumerable: true,  get: function() {  return evaluate(\"(b)()\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 8 == 2), sourceIsLazy: false, catchTermination: x })); } });");
/*fuzzSeed-202342322*/count=459; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?=(?:(?=.+)*?)+?|\\\\2.|[^]{3,}?))\", \"i\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-202342322*/count=460; tryItOut("m0.get(h0);");
/*fuzzSeed-202342322*/count=461; tryItOut("v0 = a0.length;");
/*fuzzSeed-202342322*/count=462; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (mathy0((Math.hypot(Math.fround(( ~ (y | 0))), (Math.fround(x) >> ( + (( - (Number.MAX_SAFE_INTEGER | 0)) | 0)))) >>> 0), (((( + (Math.log(((((-0 >>> 0) << ((( ! Number.MAX_VALUE) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0)) ? ( + ( + Math.max((-0x080000000 >>> 0), ( + (( + Math.sin((x | 0))) ** (0 >>> 0)))))) : x) || Math.fround(Math.sqrt((( + ( - x)) , (Math.pow(0x100000000, Math.exp(y)) >>> 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), -0x080000001, 0.000000000000001, 0x07fffffff, 0x0ffffffff, -0x100000001, Number.MAX_VALUE, -0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 1, 0, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, 0x080000000, -0, Math.PI, -(2**53+2), Number.MIN_VALUE, -1/0, 42, -(2**53-2), -0x080000000, 2**53+2, 0/0, 2**53-2, 0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, 0x080000001]); ");
/*fuzzSeed-202342322*/count=463; tryItOut("v2 = (m2 instanceof h0);");
/*fuzzSeed-202342322*/count=464; tryItOut("t2 = g1.m0.get(Math.hypot(x, ((Math.tan(((function too_much_recursion(qeehha) { ; if (qeehha > 0) { print(-18);; too_much_recursion(qeehha - 1);  } else {  }  })(15958)))))()));");
/*fuzzSeed-202342322*/count=465; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + (( + Math.expm1(( + ( - mathy2(0x100000001, ( ~ y)))))) >= ( + ( - Math.atan2((Math.acos((x | 0)) | 0), Math.trunc(Math.fround(( + (y >= (( ! (y >>> 0)) >>> 0)))))))))); }); testMathyFunction(mathy4, [Math.PI, 0x100000000, -(2**53-2), 0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 2**53, 0, -0x100000000, -Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, Number.MAX_VALUE, 2**53+2, 1/0, 0x100000001, 2**53-2, 1.7976931348623157e308, 0x080000000, -Number.MIN_VALUE, 0/0, 42, 1, -0x080000001, 0.000000000000001]); ");
/*fuzzSeed-202342322*/count=466; tryItOut("\"use strict\"; a1.sort(f0);");
/*fuzzSeed-202342322*/count=467; tryItOut("\"use strict\"; v2 = evalcx(\"((void options('strict_mode')))\", g2);");
/*fuzzSeed-202342322*/count=468; tryItOut("function f1(s1)  { let s2 = new String; } \ns2 += 'x';");
/*fuzzSeed-202342322*/count=469; tryItOut("\"use asm\"; ;");
/*fuzzSeed-202342322*/count=470; tryItOut("testMathyFunction(mathy4, ['0', undefined, true, (new Number(0)), /0/, null, '/0/', [], (new Boolean(false)), '\\0', ({valueOf:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return 0;}}), 0, 1, objectEmulatingUndefined(), (new String('')), [0], 0.1, -0, false, '', (new Boolean(true)), ({toString:function(){return '0';}}), (function(){return 0;}), NaN]); ");
/*fuzzSeed-202342322*/count=471; tryItOut("/*tLoop*/for (let w of /*MARR*/[.2, .2, function(){},  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , .2, -Infinity, function(){}, function(){}]) { print(uneval(i2));function w() { return [,,] } window;e1.add(s0);\nprint(a1);\n }");
/*fuzzSeed-202342322*/count=472; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((Float32ArrayView[4096]));\n  }\n  return f; })(this, {ff: Int16Array}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [2**53-2, -0x080000001, -0x080000000, 0x080000000, 0, Math.PI, 0.000000000000001, -0x07fffffff, 0/0, -1/0, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), Number.MIN_VALUE, 1, -Number.MAX_VALUE, 1.7976931348623157e308, 42, 0x0ffffffff, -0x100000000, Number.MAX_VALUE, -0, -0x100000001, 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), -(2**53-2), 1/0, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-202342322*/count=473; tryItOut("/*RXUB*/var r = /(?:(\\2{33554431,33554433})|\\W*?(?=(?![^]+?)[^]$)|((?=[^]+|\\b))?)/ym; var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=474; tryItOut("mathy3 = (function(x, y) { return (Math.acosh(( + (( + Math.log(( + Math.fround(Number.MIN_VALUE)))) >>> ((y >> Math.fround(( + (( + x) != ( + ( + mathy1(x, ( + x)))))))) >>> 0)))) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[x, function(){}, x, function(){}, x, function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, x, function(){}, function(){}, x, function(){}, function(){}, arguments.callee, function(){}, function(){}, x, x, function(){}, x, arguments.callee, arguments.callee, function(){}, x, x, function(){}, function(){}, function(){}, function(){}, arguments.callee, arguments.callee, arguments.callee, arguments.callee, function(){}, x, x, x, function(){}, arguments.callee, x, function(){}, function(){}, arguments.callee, x, x, x, x, arguments.callee, x, x, x, x, arguments.callee, arguments.callee, function(){}, x, function(){}]); ");
/*fuzzSeed-202342322*/count=475; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - ((((( + mathy0(( + Math.sqrt(2**53+2)), ( + Math.pow(y, Math.atan2(x, y))))) | 0) != (Math.atan2(((( + (x | 0)) | 0) | 0), (Math.trunc((((mathy1((1/0 | 0), (-(2**53-2) | 0)) | 0) & (Math.min(y, y) >>> 0)) >>> 0)) | 0)) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, 0, Number.MAX_VALUE, 2**53, 1.7976931348623157e308, -1/0, 2**53+2, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, 0x0ffffffff, -0x080000001, 0.000000000000001, -Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x100000001, 1, -0x07fffffff, -0x080000000, 42, 0/0, 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, -0]); ");
/*fuzzSeed-202342322*/count=476; tryItOut("/*bLoop*/for (gwerun = 0; (x) && gwerun < 41; ++gwerun) { if (gwerun % 6 == 3) { /* no regression tests found */ } else { v0 = t1[(/*MARR*/[new Boolean(false), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), x, x, 2**53-2, x, x, objectEmulatingUndefined(), x, x, new Boolean(false), new Boolean(false), x, objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), x, new Boolean(false), new Boolean(false), objectEmulatingUndefined(), 2**53-2, 2**53-2, objectEmulatingUndefined(), x, objectEmulatingUndefined(), 2**53-2, 2**53-2, 2**53-2, x, new Boolean(false), new Boolean(false), x, new Boolean(false), x, x, 2**53-2, x, 2**53-2, objectEmulatingUndefined(), new Boolean(false), new Boolean(false), x, 2**53-2, objectEmulatingUndefined(), objectEmulatingUndefined(), 2**53-2, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), 2**53-2, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, 2**53-2, new Boolean(false), new Boolean(false), 2**53-2, new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), 2**53-2, x, x, x, new Boolean(false), new Boolean(false), 2**53-2, objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), x, objectEmulatingUndefined(), 2**53-2, 2**53-2, x, 2**53-2, 2**53-2, objectEmulatingUndefined(), 2**53-2, x, new Boolean(false), new Boolean(false), new Boolean(false), x, objectEmulatingUndefined(), 2**53-2, x, objectEmulatingUndefined(), x, new Boolean(false), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), 2**53-2, 2**53-2, objectEmulatingUndefined(), x])]; }  } ");
/*fuzzSeed-202342322*/count=477; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.max(Math.cbrt((( + y) ? Math.max(( + ( + (( + y) ? ( + (( + Math.fround(x)) >= ( + (( - x) | 0)))) : ( - y)))), ( + (( + (y >>> 0)) >>> 0))) : (Math.fround(( ! Math.fround(Math.acosh(-Number.MIN_VALUE)))) | 0))), (( ! Math.sin(x)) | 0)); }); testMathyFunction(mathy0, [Number.MIN_VALUE, Math.PI, 0x0ffffffff, -0x080000000, 0x080000001, -1/0, -Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 0, 0x100000000, 0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -0x0ffffffff, 1/0, 0/0, 1, -Number.MAX_VALUE, 2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, -0, 0.000000000000001, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -(2**53-2), 0x07fffffff, 0x100000001, 2**53, Number.MAX_VALUE]); ");
/*fuzzSeed-202342322*/count=478; tryItOut("\"use strict\"; Array.prototype.sort.call(a2, f2);");
/*fuzzSeed-202342322*/count=479; tryItOut("/*RXUB*/var r = o1.r2; var s = o1.s1; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=480; tryItOut("\"use strict\"; let d = (makeFinalizeObserver('tenured'));selectforgc(o0);");
/*fuzzSeed-202342322*/count=481; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.pow(( + (( + ( ! ( + Math.hypot(( + Math.min(x, Math.fround(-1/0))), ( + (y === x)))))) != Math.acosh(x))), (( + Math.fround(Math.log1p(Math.fround(x)))) >>> 0)) >>> 0) !== (( ! (Math.log(Math.exp((1/0 || x))) | 0)) | 0)); }); ");
/*fuzzSeed-202342322*/count=482; tryItOut("t0 = new Float64Array(17)\n");
/*fuzzSeed-202342322*/count=483; tryItOut("g0 + '';");
/*fuzzSeed-202342322*/count=484; tryItOut("\"use strict\"; Object.preventExtensions(v2);\nfor (var v of a2) { try { a1.pop(); } catch(e0) { } try { g1.v0 = t0.length; } catch(e1) { } Array.prototype.unshift.call(a1); }\n");
/*fuzzSeed-202342322*/count=485; tryItOut("b1 = new ArrayBuffer(104);");
/*fuzzSeed-202342322*/count=486; tryItOut("\"use strict\"; m1.set(({ set valueOf(window)\"use asm\";   var abs = stdlib.Math.abs;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+((((-(0xfc7d0115)) >> ((0xffffffff)+(0xf8160736))) / ((((0xcb7a1287) == (((0x8dd2a173))>>>((0x2e7a0ef))))) ^ (((Uint32ArrayView[(0xf44ca*(0x40d0e92d)) >> 2]))-(0x58e6b84a))))|0));\n    return (((Uint16ArrayView[(((abs((~((0x28d87e11))))|0))*0xc50a6) >> 1])))|0;\n  }\n  return f;, /*toXFun*/toSource: function(y) { delete h0.get; } }), i2);");
/*fuzzSeed-202342322*/count=487; tryItOut("");
/*fuzzSeed-202342322*/count=488; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      return +((((d1)) * ((((+(abs((~~((Float64ArrayView[((0x1e200de6) % (0x388c981d)) >> 3]))))|0))) % (((((0.0078125) + ((Uint8ArrayView[0])))) - ((+/*FFI*/ff(((~(((0xfdd1995e) ? (0xc112c0cc) : (0xfa5c7c4f))))), ((-8589934591.0)), (([] = d--)), ((-1.03125)), ((6.189700196426902e+26)), ((1099511627777.0)), ((-7.555786372591432e+22)), ((-9.671406556917033e+24)), ((-2049.0)))))))))));\n    }\n    (Uint32ArrayView[(-(0x59ba974b)) >> 2]) = (((((0xa4ab7928))) << ((i0)*0xfffff)));\n    return +(((i0) ? (1073741824.0) : (-1.03125)));\n  }\n  return f; })(this, {ff: function(y) { o1 = Object.create(b1); }}, new ArrayBuffer(4096)); ");
/*fuzzSeed-202342322*/count=489; tryItOut("mathy0 = (function(x, y) { return (((Math.fround(Math.trunc(Math.fround(Math.imul(((( - (x & 1/0)) < x) | 0), (Math.PI >> ( + Math.imul(( + Number.MIN_SAFE_INTEGER), (x | 0)))))))) >>> 0) === (Math.min(Math.atan2((( + (y | 0)) | 0), (Math.expm1(Math.pow(y, Math.sinh(-Number.MIN_SAFE_INTEGER))) >>> 0)), Math.fround(( - ( + ((( - (Math.imul(-(2**53+2), -0x080000000) >>> 0)) | 0) >>> y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, 0/0, 0x0ffffffff, 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, Math.PI, 0x080000000, 0x100000000, -0, -0x080000001, 0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, -1/0, -0x100000000, 0x100000001, 42, -(2**53-2), Number.MIN_VALUE, 1, -0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), 2**53-2, 2**53, -0x080000000, -Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-202342322*/count=490; tryItOut("a2.unshift(h0, m1, i2);");
/*fuzzSeed-202342322*/count=491; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround((( + Math.atan2((( - (x > ( + (x , ( + x))))) ^ (Math.tanh(y) | 0)), Math.fround(((( ~ ((Math.log10(Math.fround(Math.atan2(Math.fround(y), Math.fround(x)))) >>> 0) ** (Math.exp((Number.MIN_SAFE_INTEGER >>> 0)) | 0))) >>> 0) != (Number.MAX_SAFE_INTEGER >>> 0))))) << (Math.atanh(( - ( ! ((42 ^ ( - x)) | 0)))) | 0))); }); testMathyFunction(mathy1, [-0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, Math.PI, 1/0, 0.000000000000001, 2**53+2, -Number.MAX_VALUE, 42, 0x080000000, 0, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -0x0ffffffff, 2**53, -0x100000000, -0x100000001, -Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, -0, 0x080000001, 0x07fffffff, 0x100000001, 0x100000000, 1, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-202342322*/count=492; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=493; tryItOut("\"use strict\"; this.zzz.zzz;Error.prototype.message = x;");
/*fuzzSeed-202342322*/count=494; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + Math.pow(((( + Math.acos(x)) && (Math.sign(0x080000000) >>> 0)) | 0), ( ~ Math.min((y === (Math.PI < (x | 0))), (y >>> 0))))) ? Math.hypot(((Math.asin(Math.min((( + new RegExp(\"[^]\", \"im\")) >>> x), Math.PI)) >>> 0) , (((y | 0) & ( + y)) | 0)), Math.fround(( + (((y >>> 0) & ((( + (Math.max(y, x) | 0)) | 0) | 0)) | 0)))) : (Math.max((((Math.expm1(Math.fround(Math.sin(x))) >>> 0) | 0) / (Math.fround(Math.pow(y, (Math.pow((x ^ Math.fround(y)), (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))) - Math.fround(Math.sqrt(Math.fround(x))))), ((Math.fround(Math.acos(0x07fffffff)) * ( + y)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [-(2**53+2), 0x100000001, 0x080000001, 2**53, Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -(2**53), 0x0ffffffff, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, -0, 1/0, 1, -0x07fffffff, 0.000000000000001, -(2**53-2), 0x100000000, 2**53+2, 0, -0x080000001, -0x080000000, 1.7976931348623157e308, 42, -0x100000001, -1/0]); ");
/*fuzzSeed-202342322*/count=495; tryItOut("e1.add(i0);");
/*fuzzSeed-202342322*/count=496; tryItOut("\"use strict\"; ");
/*fuzzSeed-202342322*/count=497; tryItOut("\"use strict\"; this.m1 = a0[({valueOf: function() { Array.prototype.sort.call(a1, Map.prototype.has, m0);return 5; }})];");
/*fuzzSeed-202342322*/count=498; tryItOut("v1 = (g1 instanceof t2);");
/*fuzzSeed-202342322*/count=499; tryItOut("let b = (x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: Math.ceil, keys: undefined, }; })(typeof ((function fibonacci(wbeyjt) { ; if (wbeyjt <= 1) { ; return 1; } ; return fibonacci(wbeyjt - 1) + fibonacci(wbeyjt - 2);  })(1))), /*MARR*/[new String('q'), x, x, new Number(1), x, new String('q'), x, new Number(1), new String('q'), new String('q'), new String('q'), new Number(1), new String('q'), new String('q'), x, new String('q'), new String('q'), x, new Number(1), x, new Number(1), x, x, new String('q'), x, x, new String('q'), new String('q'), new String('q'), x, new Number(1), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String('q'), x, new String('q'), new Number(1), x, x, new Number(1), new String('q'), new Number(1), new Number(1), x, new Number(1), x, new String('q'), x, x, new Number(1), new Number(1), new Number(1), new String('q'), new String('q'), new String('q'), x, x, new Number(1), new Number(1), new String('q'), x, x, new String('q'), new Number(1), new String('q'), new String('q'), x, new String('q'), x, new String('q'), x, new Number(1), new Number(1), new Number(1), x, new Number(1), new String('q'), x, x].sort)), vzsvif, a = (4277), a, eval;function shapeyConstructor(raaflu){delete raaflu[x.toLocaleLowerCase([[]])];return raaflu; }/*tLoopC*/for (let a of /*FARR*/[x, (void options('strict_mode'))]) { try{let wmspqp = new shapeyConstructor(a); print('EETT'); e2.delete(v2);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-202342322*/count=500; tryItOut("\"use strict\"; v1 = g1.eval(\"function f0(h0)  { return h0.__defineSetter__(\\\"\\\\u3056\\\", (function(x, y) { \\\"use strict\\\"; return -0x100000000; })) } \");");
/*fuzzSeed-202342322*/count=501; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((((Math.tan(Math.fround((Math.fround(Math.atan2(Math.fround(x), Math.fround(1/0))) <= Math.fround(y)))) | 0) == (( - y) | 0)) | 0) % Math.fround((Math.fround(mathy0((( + ( - 0x100000000)) | 0), Math.fround(y))) , Math.fround((-(2**53+2) & Math.exp(x)))))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, 2**53+2, -0x100000001, 0x0ffffffff, -0, -0x0ffffffff, -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_VALUE, -(2**53+2), -0x080000001, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, Math.PI, -(2**53-2), -0x100000000, 42, 0/0, -Number.MAX_SAFE_INTEGER, 1, -(2**53), 0, -0x07fffffff, 2**53, 1.7976931348623157e308, 0x100000001, -0x080000000]); ");
/*fuzzSeed-202342322*/count=502; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.ceil(((Math.hypot((Math.min((Math.imul((( ~ y) >>> 0), x) | 0), (Math.pow(Math.fround(( ~ Math.fround(Math.fround(Math.asin(Math.fround(x)))))), Number.MIN_VALUE) >>> 0)) | 0), ((Math.pow(y, (Math.pow(( + x), ( + (y === (x | 0)))) | 0)) | 0) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy0, [0x0ffffffff, 1, 0, -0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000000, -0x100000001, 0x07fffffff, -0x080000001, 2**53, 2**53+2, 42, Number.MAX_VALUE, 0/0, 0x100000000, 0x100000001, 0.000000000000001, -0x080000000, Math.PI, -(2**53+2), -0, 1.7976931348623157e308, 0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), -(2**53-2), 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 2**53-2]); ");
/*fuzzSeed-202342322*/count=503; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=504; tryItOut("\"use strict\"; v0 = new Number(-Infinity);");
/*fuzzSeed-202342322*/count=505; tryItOut("\"use strict\"; v1 = o0.g0.r1.source;");
/*fuzzSeed-202342322*/count=506; tryItOut("((timeout(1800)));");
/*fuzzSeed-202342322*/count=507; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return (((Math.imul(Math.exp(Math.fround(Math.fround(Math.pow(Math.fround(Math.max((Math.clz32(y) >>> 0), 0)), Math.fround(Math.cbrt(Math.pow(x, ( + y)))))))), ( + (( + Math.fround(mathy1(Math.fround(x), Math.fround(mathy0((Math.hypot((y >>> 0), x) >>> 0), y))))) ? (( ! ((((y | 0) << (y | 0)) | 0) !== x)) >>> 0) : ( + ( + Math.imul(Math.fround(Math.asin(x)), ( + Math.pow(y, (y !== Math.fround(y)))))))))) | 0) | (Math.imul((( - (( - (0.000000000000001 >>> 0)) >>> 0)) | 0), ((-Number.MAX_SAFE_INTEGER && ( + y)) | 0)) === ( + (Math.pow(Math.fround(Math.tanh(x)), Math.fround(Math.fround(Math.atan2(( + y), ( + ( + Math.imul(y, (Math.atanh((Math.fround(Math.min(Math.fround(y), Math.fround(y))) >>> 0)) >>> 0)))))))) >>> 0)))) | 0); }); testMathyFunction(mathy3, [-(2**53), 0/0, -(2**53-2), 1, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 1/0, -0x07fffffff, -Number.MAX_VALUE, -1/0, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0, 2**53, 2**53-2, Number.MIN_VALUE, 0.000000000000001, -0x080000001, 1.7976931348623157e308, 0x080000000, Math.PI, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000001, Number.MAX_VALUE, 42, -(2**53+2), -0, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-202342322*/count=508; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.atan2((Math.fround((Math.round(Math.clz32(( + y))) ? (Math.atan2((((y | 0) < -0x100000000) === (( + (( + ( - ( + x))) | 0)) | 0)), ((Math.min(((Math.hypot((Number.MAX_VALUE >>> 0), ( + (((0x0ffffffff | 0) > Math.min(Math.fround(x), Number.MAX_VALUE)) >>> 0))) >>> 0) | 0), (Math.cbrt(( + 0x07fffffff)) | 0)) | 0) >>> 0)) >>> 0) : (Math.fround(mathy0(Math.fround(( + ((y | 0) <= (Math.min(y, ((0/0 | x) >>> 0)) | 0)))), x)) >>> ( - (x >>> 0))))) | 0), (( + (Math.fround((( ! Number.MAX_VALUE) | 0)) << Math.fround(y))) | 0))); }); testMathyFunction(mathy1, [(new Boolean(true)), '/0/', (new Number(0)), [0], objectEmulatingUndefined(), -0, 0, '', NaN, /0/, (function(){return 0;}), ({valueOf:function(){return '0';}}), (new Number(-0)), '0', 0.1, true, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Boolean(false)), 1, false, null, [], (new String('')), undefined, '\\0']); ");
/*fuzzSeed-202342322*/count=509; tryItOut("m2 + '';");
/*fuzzSeed-202342322*/count=510; tryItOut("\"use strict\"; return;");
/*fuzzSeed-202342322*/count=511; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=512; tryItOut("for(var a = (allocationMarker()) in Error((x = window))) L: {/* no regression tests found */ }");
/*fuzzSeed-202342322*/count=513; tryItOut("print(27.eval(\"/* no regression tests found */\"));");
/*fuzzSeed-202342322*/count=514; tryItOut("/*MXX3*/o0.g1.Math.sign = g2.Math.sign;");
/*fuzzSeed-202342322*/count=515; tryItOut("/*oLoop*/for (var hlcxmt = 0; hlcxmt < 8; ++hlcxmt) { /*infloop*/M: for  each(x in (z.resolve(/(?:(?=\\2))?/ym, \"\\u4AB2\"))) print(); } ");
/*fuzzSeed-202342322*/count=516; tryItOut("/*RXUB*/var r = new RegExp(\"$+(?=(?:\\\\3+))^\", \"gyim\"); var s = true; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=517; tryItOut("a2.push(g1, p1, (void options('strict_mode')), g1.g1.b0, (4277), p2, o1);");
/*fuzzSeed-202342322*/count=518; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.abs((Math.log1p((Math.exp(( + Math.exp((Math.round(-Number.MAX_SAFE_INTEGER) >>> 0)))) * y)) | 0)); }); testMathyFunction(mathy2, [0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, -(2**53-2), -0x0ffffffff, 2**53+2, -0x100000000, -0x07fffffff, 1.7976931348623157e308, 42, 2**53, -0x100000001, -Number.MAX_VALUE, -(2**53), 0/0, -1/0, 0.000000000000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0, 0x080000001, 2**53-2, 1/0, 1, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000]); ");
/*fuzzSeed-202342322*/count=519; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.max(Math.fround((mathy1(mathy0((( ! Math.fround((x || Math.fround(-Number.MIN_SAFE_INTEGER)))) | 0), ( + ( ~ ( + 0x100000001)))), (((Math.fround((( ! (-Number.MIN_SAFE_INTEGER | 0)) | 0)) !== Math.fround(( + mathy1(( + Number.MIN_VALUE), ( + y))))) >>> 0) | 0)) | 0)), Math.fround(Math.abs(((Math.log2(Math.fround((((Math.atanh(mathy4(y, (y >>> 0))) >>> 0) ? ((((x | 0) + x) | 0) | 0) : y) >>> 0))) + Math.fround(Math.log1p(Math.fround(-Number.MAX_VALUE)))) >>> 0))))); }); ");
/*fuzzSeed-202342322*/count=520; tryItOut("Array.prototype.pop.apply(o0.a1, [f1, h0]);");
/*fuzzSeed-202342322*/count=521; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"(?=(?=\\\\r(?=\\\\3)))\", \"y\"); var s = \"\\u000d\"; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-202342322*/count=522; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=523; tryItOut("mathy2 = (function(x, y) { return Math.hypot(Math.fround(( ~ Math.fround(Math.fround((x === Math.fround(x)))))), ( - ( + Math.imul(Math.trunc((mathy0(y, (y | 0)) >>> 0)), (( + ((Math.fround(mathy0(Math.fround(( + 2**53-2)), -0x100000001)) >>> 0) !== ( + Math.fround(mathy1(( + Math.sign(( + -0x100000000))), (x | 0)))))) >>> 0))))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 42, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000001, -0x0ffffffff, -(2**53-2), 0x080000000, -0x080000000, Math.PI, -0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 1/0, 1, 2**53-2, 0x07fffffff, 2**53+2, 0/0, 0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, -0x100000001, 0x0ffffffff, -0, 0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, -1/0, 0x100000000]); ");
/*fuzzSeed-202342322*/count=524; tryItOut("\"use asm\"; a1.shift();function window() { e0.__proto__ = v1; } print(new RegExp(\"(?!(\\\\cS))\", \"yi\"));");
/*fuzzSeed-202342322*/count=525; tryItOut("e0 + o0;");
/*fuzzSeed-202342322*/count=526; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.log2(Math.fround((Math.hypot((Math.fround(((y >>> 0) | Math.fround(x))) | 0), (Math.fround(mathy3((Math.fround((( + ( + ( - ( + ((y % x) >>> 0))))) && (x + y))) >>> 0), Math.fround(y))) | 0)) | 0))); }); testMathyFunction(mathy4, [-(2**53), -0, 0/0, -0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 1, 0x080000000, 0x080000001, 0x100000001, 2**53, 2**53+2, -Number.MAX_VALUE, -0x080000001, -1/0, -0x100000001, 1/0, -0x080000000, -(2**53-2), Math.PI, -Number.MAX_SAFE_INTEGER, 0, -0x100000000, -(2**53+2), 42, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=527; tryItOut(" for  each(let d in x) {print(v1); }");
/*fuzzSeed-202342322*/count=528; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( + Math.fround(Math.asinh(Math.fround((Math.cbrt((Math.log2((( ~ ((((Number.MIN_SAFE_INTEGER >>> 0) >= (y >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0)) >>> 0))))) | 0); }); testMathyFunction(mathy2, [-0, 0x080000000, -1/0, 2**53, 1, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, -0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, Math.PI, 0x100000000, 0x0ffffffff, -0x080000000, -0x07fffffff, -0x100000000, -(2**53+2), 1.7976931348623157e308, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000001, 1/0, 0x07fffffff, 0, 42, 2**53+2]); ");
/*fuzzSeed-202342322*/count=529; tryItOut("\"use strict\"; h0.__proto__ = m0;o1.a2.shift();");
/*fuzzSeed-202342322*/count=530; tryItOut("Array.prototype.splice.apply(a2, [0, 10])\n");
/*fuzzSeed-202342322*/count=531; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ( ~ (mathy1(( + Math.atan2(0x100000000, ( + Math.fround(Math.sin(y))))), (((( - (( + (x | 0)) | 0)) >>> 0) || Math.fround((mathy1(( ! -(2**53+2)), (0.000000000000001 >>> 0)) >>> 0))) >>> 0)) | 0)); }); ");
/*fuzzSeed-202342322*/count=532; tryItOut("mathy5 = (function(x, y) { return ((( + Math.asin(( + Math.sin((x | 0))))) | (Math.min(Math.fround(( + mathy2(( + (Math.atan2((Math.log10(Number.MAX_SAFE_INTEGER) | 0), Math.fround((Math.hypot(0/0, (y | 0)) | 0))) | 0)), ((((Math.pow((x | 0), (x | 0)) | 0) >>> 0) ^ (( ! (mathy0((y | 0), y) >>> 0)) >>> 0)) | 0)))), ( + y)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000001, 0, 42, Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, -Number.MIN_VALUE, 1, 2**53, 0x07fffffff, -0x080000001, -0x07fffffff, Math.PI, 0x0ffffffff, -(2**53-2), 1.7976931348623157e308, 0x100000000, -(2**53), -Number.MAX_VALUE, 0/0, 1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, -1/0, 2**53-2, -0x0ffffffff, 0x080000000, 0.000000000000001]); ");
/*fuzzSeed-202342322*/count=533; tryItOut("\"use strict\"; v1 = (a2 instanceof p2);\no1.e1.has(this.g0.i0);\n");
/*fuzzSeed-202342322*/count=534; tryItOut("Array.prototype.shift.call(a0);");
/*fuzzSeed-202342322*/count=535; tryItOut("\"use strict\"; throw StopIteration;x.message;");
/*fuzzSeed-202342322*/count=536; tryItOut("mathy3 = (function(x, y) { return Math.log2((( ! ((y - x) | ( + ((((Number.MIN_VALUE < (0/0 >>> 0)) >>> 0) >> ( ~ (x >>> 0))) != (Math.fround(Math.hypot(Math.fround(y), x)) >>> 0))))) >>> 0)); }); testMathyFunction(mathy3, /*MARR*/[(void 0), (void 0),  /x/g ,  /x/g , -0x100000001,  /x/g , -0x100000001, (void 0),  /x/g , [], [], (void 0), (void 0),  /x/g ,  /x/g ,  /x/g , [], [], -0x100000001, {x:3}, [],  /x/g , [], -0x100000001, -0x100000001, [], {x:3}, -0x100000001, [], {x:3}, [], {x:3}, {x:3}, [], {x:3}, (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , -0x100000001, [], [], (void 0), (void 0), {x:3}, -0x100000001,  /x/g , {x:3}, [], -0x100000001, [], (void 0),  /x/g , {x:3}, -0x100000001, -0x100000001,  /x/g , [], -0x100000001, -0x100000001, (void 0), -0x100000001, [], (void 0), -0x100000001,  /x/g , (void 0),  /x/g ,  /x/g , (void 0), (void 0), [], (void 0), {x:3}, {x:3},  /x/g , {x:3}, {x:3}, {x:3}, [], [], {x:3}, {x:3}, [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], {x:3},  /x/g , (void 0),  /x/g , {x:3},  /x/g , (void 0),  /x/g ,  /x/g ,  /x/g , -0x100000001, [],  /x/g , (void 0), -0x100000001, [], (void 0), [], {x:3}, [], (void 0), (void 0), (void 0),  /x/g ,  /x/g , {x:3}, {x:3}, (void 0),  /x/g , {x:3}, [], -0x100000001]); ");
/*fuzzSeed-202342322*/count=537; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( ~ Math.expm1(( + (( + (y >>> 0)) % ((0x0ffffffff , y) | 0))))) + (Math.sin((((Math.fround((Math.ceil((Math.trunc(( + y)) | 0)) | 0)) ? Math.fround((Math.atan(Math.hypot(Math.fround(Math.max(( + y), ( + x))), ( + (((Number.MIN_VALUE >>> 0) >= x) >>> 0)))) >>> 0)) : ( ~ Math.cbrt(Math.tanh(Math.fround(x))))) | 0) | 0)) | 0)); }); testMathyFunction(mathy4, [[0], '\\0', ({toString:function(){return '0';}}), NaN, undefined, (function(){return 0;}), false, 0.1, [], (new Boolean(false)), '', ({valueOf:function(){return '0';}}), null, '/0/', 1, 0, (new Number(-0)), (new Boolean(true)), -0, true, (new String('')), (new Number(0)), /0/, objectEmulatingUndefined(), '0', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-202342322*/count=538; tryItOut("m2.delete(i0);");
/*fuzzSeed-202342322*/count=539; tryItOut("print(/\\1{2,1025}/gym);");
/*fuzzSeed-202342322*/count=540; tryItOut("/*oLoop*/for (let fmezeg = 0, true; fmezeg < 79; ++fmezeg) { v2 = (e1 instanceof this.s0); } ;");
/*fuzzSeed-202342322*/count=541; tryItOut("\"use strict\"; var uhsukd = new ArrayBuffer(4); var uhsukd_0 = new Uint8Array(uhsukd); uhsukd_0[0] = -19; var uhsukd_1 = new Uint16Array(uhsukd); print(uhsukd_1[0]); var uhsukd_2 = new Uint32Array(uhsukd); print(uhsukd_2[0]); var uhsukd_3 = new Int8Array(uhsukd); uhsukd_3[0] = -22; var uhsukd_4 = new Uint8ClampedArray(uhsukd); print(uhsukd_4[0]); var uhsukd_5 = new Int8Array(uhsukd); uhsukd_5[0] = 7; var uhsukd_6 = new Float64Array(uhsukd); uhsukd_6[0] = (Array.of)(window); var uhsukd_7 = new Float32Array(uhsukd); uhsukd_7[0] = -6; var uhsukd_8 = new Uint32Array(uhsukd); uhsukd_8[0] = 11; var uhsukd_9 = new Float32Array(uhsukd); print(uhsukd_9[0]); uhsukd_9[0] = -20; var uhsukd_10 = new Int16Array(uhsukd); print(uhsukd_10[0]); uhsukd_10[0] = 1633109852; var uhsukd_11 = new Float64Array(uhsukd); uhsukd_11[0] = 19; /* no regression tests found */for (var v of a0) { try { h2.enumerate = f2; } catch(e0) { } try { s2 = this.g1.objectEmulatingUndefined(); } catch(e1) { } try { m0.set(this.t1, this.a0); } catch(e2) { } this.e0.has(o1); }selectforgc(this.o1.o2);/*MXX3*/g2.String.prototype.trimLeft = g2.String.prototype.trimLeft;v0 = t2.length;with((function ([y]) { })()){( '' ); }print((4277));/*bLoop*/for (var gammvo = 0; gammvo < 95; ++gammvo) { if (gammvo % 3 == 1) { e2.delete(p2); } else { (-17); }  } for (var p in a1) { try { i1 = x; } catch(e0) { } Array.prototype.shift.call(a1, g1, o1.o0); }var y = ({}) = let (c)  /x/ ;");
/*fuzzSeed-202342322*/count=542; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(mathy0(Math.fround((( ! ((( - 0/0) | 0) >>> 0)) >>> 0)), Math.fround((mathy2((Math.fround(Math.trunc(Math.fround(Math.atan2((( ! Math.imul(x, 2**53-2)) | 0), (x | 0))))) | 0), ((mathy1(((y & ( + 0x080000000)) | 0), Math.fround(Math.hypot(((( ~ (x | 0)) | 0) >>> 0), Math.fround(Math.hypot(-0x080000000, y))))) | 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, objectEmulatingUndefined()]); ");
/*fuzzSeed-202342322*/count=543; tryItOut("mathy5 = (function(x, y) { return ((Math.abs(( + Math.round(( + (Math.fround(( + ( ~ (x >>> 0)))) > 0x0ffffffff))))) | 0) ? Math.fround((Math.max(( + 2**53+2), ( + ( - Math.fround(( + Math.fround(Math.max(mathy4(x, y), Number.MAX_VALUE))))))) ** (Math.ceil(Math.atan2(y, (x >>> 0))) | 0))) : ( ~ ((0x100000001 > mathy4(x, ((Math.fround(( ~ y)) < -(2**53-2)) / (( + -0) - (x & (y | 0)))))) | 0))); }); testMathyFunction(mathy5, [-1/0, -(2**53+2), -0x100000000, 0x080000000, 0x100000001, -Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, 1, -0x080000001, -0x080000000, Number.MIN_VALUE, -(2**53-2), 0/0, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, 0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, 2**53-2, 0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 1/0, 1.7976931348623157e308, 2**53+2, -(2**53), 42, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001]); ");
/*fuzzSeed-202342322*/count=544; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.sin(Math.fround(Math.pow(( + ( ~ ( + (((x >>> 0) >= (Math.fround((Math.fround((Math.hypot((y >>> 0), (x >>> 0)) >>> 0)) , Math.fround(( ! y)))) >>> 0)) >>> 0)))), Math.hypot(Math.fround(( ~ Math.atanh(((Math.expm1((x | 0)) | 0) | 0)))), ( + y)))))); }); testMathyFunction(mathy1, [0x080000000, -0x0ffffffff, 0.000000000000001, -1/0, Number.MAX_VALUE, 0, Math.PI, -0x080000000, Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -0x080000001, -0x100000001, -Number.MAX_VALUE, 0x07fffffff, 0x100000000, 2**53, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), 2**53-2, 1/0, 1.7976931348623157e308, -0x07fffffff, -(2**53+2), 0x100000001, -Number.MAX_SAFE_INTEGER, 1, 42, 0/0, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-202342322*/count=545; tryItOut("\"use asm\"; Array.prototype.unshift.apply(a0, []);");
/*fuzzSeed-202342322*/count=546; tryItOut("testMathyFunction(mathy4, [true, (new Boolean(false)), NaN, (new Boolean(true)), ({valueOf:function(){return 0;}}), [], '\\0', undefined, (new Number(0)), /0/, '', ({toString:function(){return '0';}}), 0, [0], -0, '/0/', false, (new String('')), '0', 0.1, ({valueOf:function(){return '0';}}), (function(){return 0;}), 1, (new Number(-0)), objectEmulatingUndefined(), null]); ");
/*fuzzSeed-202342322*/count=547; tryItOut("mathy3 = (function(x, y) { return Math.imul((Math.imul(((( ~ (Math.sinh(Math.fround(y)) | 0)) | 0) | 0), (Math.fround(mathy0((Math.min(Math.fround(Math.sign(Math.fround(((( + (Math.max(x, (x >>> 0)) >>> 0)) ? (x | 0) : (( ! 0x100000001) | 0)) | 0)))), (Math.atan2(y, ( + mathy1(( + y), ( + x)))) >>> 0)) | 0), Math.fround(-(2**53-2)))) | 0)) | 0), Math.fround(Math.imul(Math.fround((Math.atan(Math.fround(Math.round(Math.fround(Math.atan2(x, x))))) | 0)), Math.fround(( + Math.max((mathy2(((((Math.log2((y | 0)) | 0) >>> 0) != (x >>> 0)) >>> 0), x) | 0), ( + 0/0))))))); }); testMathyFunction(mathy3, [-0x100000000, 1.7976931348623157e308, 1/0, -0x0ffffffff, 0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -0, 0x0ffffffff, 0.000000000000001, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, 0, -Number.MIN_VALUE, -0x080000001, 0x100000001, 1, 2**53+2, 42, Number.MAX_VALUE, 2**53, -0x07fffffff, 0x100000000, 0/0, 0x080000001, Number.MIN_VALUE, -(2**53+2), 2**53-2, -1/0, Math.PI]); ");
/*fuzzSeed-202342322*/count=548; tryItOut("t2.valueOf = (let (e=eval) e);");
/*fuzzSeed-202342322*/count=549; tryItOut("testMathyFunction(mathy3, [2**53-2, 1, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, 0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, 0x080000000, -0x07fffffff, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, 0/0, 1/0, 0x100000000, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 42, -(2**53), Math.PI, -Number.MIN_VALUE, 1.7976931348623157e308, -0, -(2**53+2), -(2**53-2), 0]); ");
/*fuzzSeed-202342322*/count=550; tryItOut("/*oLoop*/for (odvnxp = 0, eval =  \"\" .getUTCMilliseconds(); odvnxp < 62; ++odvnxp) { /*RXUB*/var r = r0; var s = (void shapeOf( \"\" )); print(s.search(r));  } ");
/*fuzzSeed-202342322*/count=551; tryItOut("(this);");
/*fuzzSeed-202342322*/count=552; tryItOut("e2.has(o2);");
/*fuzzSeed-202342322*/count=553; tryItOut("\"use strict\"; /*RXUB*/var r = (\"\\u9390\" !=  /x/  || ~new RegExp(\"(?=(?:\\\\1)|\\\\D+?)\", \"yim\") ? --x :  '' ( /x/g )); var s = \"\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=554; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=555; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=556; tryItOut("mathy3 = (function(x, y) { return ( + Math.abs(( + ( ~ Math.fround(((( ~ ( ~ x)) | 0) - ( + Math.pow(Math.fround(((((x >>> 0) , (x >>> 0)) >>> 0) % ( + y))), ( + (Math.sinh((x | 0)) | 0)))))))))); }); testMathyFunction(mathy3, /*MARR*/[new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), undefined, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), undefined, undefined, (void 0), undefined, undefined, undefined, new Boolean(true), undefined, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), undefined, undefined, undefined, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), undefined, new Boolean(true), (void 0), undefined, undefined, (void 0), (void 0), undefined, new Boolean(true), new Boolean(true), new Boolean(true), (void 0), undefined, new Boolean(true), new Boolean(true), new Boolean(true), undefined, (void 0), (void 0), new Boolean(true), new Boolean(true), undefined, new Boolean(true), new Boolean(true), new Boolean(true), undefined, new Boolean(true), undefined, new Boolean(true)]); ");
/*fuzzSeed-202342322*/count=557; tryItOut("if((x % 6 != 2)) {v1.__proto__ = g2.p2; } else  if (allocationMarker()) {print(x); } else delete h2.keys;");
/*fuzzSeed-202342322*/count=558; tryItOut("t1 = this.f2;");
/*fuzzSeed-202342322*/count=559; tryItOut("var ntabba = new ArrayBuffer(0); var ntabba_0 = new Uint8ClampedArray(ntabba); yield window;");
/*fuzzSeed-202342322*/count=560; tryItOut("y = (4277);o1.o1 = m1.get(f1);\n/* no regression tests found */\n");
/*fuzzSeed-202342322*/count=561; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[NaN, x, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, x, x, Infinity, x, 5.0000000000000000000000, 5.0000000000000000000000,  \"\" , Infinity,  \"\" , Infinity, 5.0000000000000000000000, 5.0000000000000000000000, NaN, Infinity, 5.0000000000000000000000, x, NaN, Infinity, 5.0000000000000000000000, 5.0000000000000000000000,  \"\" , x, NaN, 5.0000000000000000000000, x,  \"\" , Infinity, 5.0000000000000000000000, 5.0000000000000000000000, x,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , x, NaN,  \"\" , 5.0000000000000000000000, 5.0000000000000000000000, Infinity, 5.0000000000000000000000, Infinity, 5.0000000000000000000000, NaN, Infinity, 5.0000000000000000000000, NaN, NaN, Infinity, Infinity, 5.0000000000000000000000,  \"\" , x, 5.0000000000000000000000, 5.0000000000000000000000, x, NaN, Infinity, NaN, NaN, NaN, NaN, NaN, NaN, 5.0000000000000000000000,  \"\" , NaN, NaN, Infinity, x, NaN, 5.0000000000000000000000, x, x, NaN, x, NaN, 5.0000000000000000000000, Infinity, x, Infinity, x]); ");
/*fuzzSeed-202342322*/count=562; tryItOut("/*tLoop*/for (let b of /*MARR*/[new String('q'), x, new String('q'), true, -(2**53+2), x, x, true, x, true, x, true, new String('q'), x, -(2**53+2), x, new String('q'), true, new String('q'), -(2**53+2), new String(''), true, new String(''), true, new String('q'), new String('q'), -(2**53+2), new String('q'), new String(''), true, true, x, new String(''), new String('q'), -(2**53+2), -(2**53+2), new String('q'), true, new String('q'), true, x, new String(''), new String(''), new String('q'), new String('q'), -(2**53+2), new String('q'), -(2**53+2), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String('q'), new String('q'), x, true, new String('q'), x, true, new String('q')]) { for (var p in b0) { try { (void schedulegc(g1)); } catch(e0) { } try { i1.send(s1); } catch(e1) { } a2.unshift(this.g2); } }");
/*fuzzSeed-202342322*/count=563; tryItOut("i1 + '';");
/*fuzzSeed-202342322*/count=564; tryItOut("v0.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -129.0;\n    d1 = (d2);\n    {\n      i0 = (0x5c0b5040);\n    }\n    {\n      i0 = (0x78a20c45);\n    }\n    i0 = ((0x4a86372d) <= (((+/*FFI*/ff()))));\n    d1 = ((+(1.0/0.0)) + (-1.125));\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: encodeURIComponent}, new SharedArrayBuffer(4096));");
/*fuzzSeed-202342322*/count=565; tryItOut("v0 = Object.prototype.isPrototypeOf.call(p2, e0);");
/*fuzzSeed-202342322*/count=566; tryItOut("/*vLoop*/for (var abomfo = 0; abomfo < 28; ++abomfo,  /x/g ) { var y = abomfo;  /x/g ; } ");
/*fuzzSeed-202342322*/count=567; tryItOut("/*vLoop*/for (eokxxx = 0; eokxxx < 60; ++eokxxx) { a = eokxxx; v1 = (a2 instanceof m2); } ");
/*fuzzSeed-202342322*/count=568; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.atan2(Math.fround(Math.cos(Math.max((( + Math.imul(((Math.imul((( + y) == Math.sinh(x)), x) >>> 0) | 0), Math.fround((x === (y || ( + x)))))) >>> 0), ( + ( + ( + (x ** x))))))), (mathy0((Math.atan2(( ~ (Number.MAX_SAFE_INTEGER | 0)), (( + mathy1((Math.atan2(x, x) >>> y), ( + (mathy0(( + ( ~ x)), ( + y)) >>> 0)))) >>> 0)) >>> 0), Math.sqrt(( + Math.fround((Math.fround(((( + y) * (-Number.MAX_VALUE >>> 0)) >>> 0)) ^ Math.fround(42)))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-202342322*/count=569; tryItOut("x.name;return x;");
/*fuzzSeed-202342322*/count=570; tryItOut("while((NaN) && 0){h0 = m1.get(g1.m2);print(x); }");
/*fuzzSeed-202342322*/count=571; tryItOut("i0.next();");
/*fuzzSeed-202342322*/count=572; tryItOut("L:if((x % 16 != 4)) { if (delete x.y) {t2.set(a2, /*FARR*/[window.eval(\"new RegExp(\\\"(?=\\\\\\\\1{0,1}[\\\\uce7a]?){1,2}\\\", \\\"g\\\")\"), .../*FARR*/[, 26, ...[], x,  \"\" , ...[],  \"\" , ...[]], ((Object.getOwnPropertyDescriptor)()), .../*MARR*/[ '' , objectEmulatingUndefined(), undefined, eval, undefined, eval, undefined, undefined, objectEmulatingUndefined(), x, x,  '' , objectEmulatingUndefined(), x, eval, x,  '' , eval, undefined, objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x,  '' , undefined, x, eval, undefined,  '' , undefined,  '' , x, x,  '' , objectEmulatingUndefined(), eval, eval, x, eval,  '' , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), eval, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,  '' , undefined,  '' , eval, eval, objectEmulatingUndefined(), eval, x, undefined, eval, undefined,  '' , objectEmulatingUndefined(),  '' ,  '' , objectEmulatingUndefined(),  '' , undefined, eval, undefined,  '' ,  '' , x], .../*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false), new Boolean(false), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false)], Math.atan2(27, 0), , ...Math.pow({}, ({})), , window = Proxy.createFunction(({/*TOODEEP*/})(this),  \"\" ), , .../*FARR*/[/(?:[^]+)\\1*([^])*?|(?:([^]|$))*?[^][\\cH-\\u0007\\D\\d\\v-\\xbC]?/], ...(function() { yield [[]]; } })(), \"\\uF01A\", .../*FARR*/[\"\\uEB57\", /\\D/gyim, b], false, (new Function).call( \"\" , w), new RegExp(\"(?=\\\\D){1,}\", \"gy\")\n, , z, , , x, yield \"\\u24A5\", x, (\"\\uE41E\" && w), ((\u3056 = /.{2,}|\\3/m))].map(Math.asin, (y--)));for (var p in s2) { try { s2 = new String; } catch(e0) { } try { h1.getOwnPropertyNames = f2; } catch(e1) { } try { s0 += s2; } catch(e2) { } e2.delete(a2); } } else /*bLoop*/for (let hewoyr = 0; hewoyr < 105; ++hewoyr) { if (hewoyr % 23 == 8) { a0.forEach((function() { o0.a2.sort((function(j) { if (j) { try { v1 = (v1 instanceof m0); } catch(e0) { } try { o0.i0.send(this.g1); } catch(e1) { } try { t1.toSource = (function() { for (var j=0;j<119;++j) { f1(j%5==1); } }); } catch(e2) { } e2.add(this.a2); } else { try { Array.prototype.splice.call(a0, NaN, 12); } catch(e0) { } try { v1 = evaluate(\"f0.__iterator__ = (function(j) { if (j) { try { g0.e2 = new Set; } catch(e0) { } try { /*MXX1*/o0 = g1.String.prototype.constructor; } catch(e1) { } s1 += 'x'; } else { try { a2[v1] =  '' ; } catch(e0) { } try { v1 = o2.g0.runOffThreadScript(); } catch(e1) { } try { selectforgc(o0); } catch(e2) { } b0 = t1.buffer; } });\", ({ global: o0.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  /x/g , noScriptRval: false, sourceIsLazy: (x % 4 != 3), catchTermination: (x % 5 != 1) })); } catch(e1) { } t2 = new Int32Array(a2); } }), p0, m2, o1.e1); return a0; })); } else { Object.seal(o1.h0); }  } }");
/*fuzzSeed-202342322*/count=573; tryItOut("i2 = new Iterator(i2, true);");
/*fuzzSeed-202342322*/count=574; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ! Math.min(Math.fround(Math.log1p(( + ( ~ (mathy3((x | 0), Math.fround(x)) | 0))))), Math.fround(( ! Math.fround(( ~ -0x080000000)))))); }); testMathyFunction(mathy4, [false, 1, '', '/0/', '\\0', -0, (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Number(0)), ({toString:function(){return '0';}}), (function(){return 0;}), [], [0], 0, (new String('')), /0/, undefined, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), 0.1, null, true, NaN, '0', (new Number(-0)), (new Boolean(true))]); ");
/*fuzzSeed-202342322*/count=575; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=576; tryItOut("m1.get(t1);");
/*fuzzSeed-202342322*/count=577; tryItOut("/*oLoop*/for (xsjgsb = 0; xsjgsb < 23; ++xsjgsb) { v1 = r2.ignoreCase; } ");
/*fuzzSeed-202342322*/count=578; tryItOut("mathy0 = (function(x, y) { return ( ! ( + ( ! Math.max(x, y)))); }); testMathyFunction(mathy0, [-0x07fffffff, 2**53, Number.MAX_VALUE, -(2**53-2), -(2**53), 1, 0, -0x080000000, Number.MIN_VALUE, -0x080000001, 0x080000000, -0x100000000, 0x07fffffff, 2**53+2, 0x0ffffffff, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -0x100000001, 0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 42, -1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0/0, -0, 2**53-2]); ");
/*fuzzSeed-202342322*/count=579; tryItOut("mathy1 = (function(x, y) { return (Math.imul(Math.fround(Math.max((Math.atan2(Math.sign((y | 0)), (y + y)) , x), y)), ( + (( + ( ~ Math.fround(y))) / Math.atan2(x, x)))) >>> Math.imul(Math.ceil(mathy0((y >>> 0), ( + Math.log1p(x)))), Math.imul(( + Math.tan(( + y))), x))); }); ");
/*fuzzSeed-202342322*/count=580; tryItOut("with(eval.valueOf(\"number\")){t1 = new Uint16Array(t2); }");
/*fuzzSeed-202342322*/count=581; tryItOut("\"use strict\"; v0 = (o1 instanceof p1);");
/*fuzzSeed-202342322*/count=582; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.clz32(mathy0(Math.hypot((( + (Number.MAX_VALUE >>> 0)) >>> 0), Math.fround(Math.tanh(Math.fround(( - y))))), (( + Math.tan(( + mathy0(-0x080000000, (Number.MIN_SAFE_INTEGER && x))))) * (( - Math.fround(( - 0x100000000))) >>> 0)))); }); testMathyFunction(mathy1, [(new Number(0)), false, undefined, /0/, 1, (new String('')), [0], '', ({toString:function(){return '0';}}), true, null, 0, (new Number(-0)), ({valueOf:function(){return 0;}}), (new Boolean(false)), [], NaN, (new Boolean(true)), '0', 0.1, ({valueOf:function(){return '0';}}), -0, objectEmulatingUndefined(), '\\0', '/0/', (function(){return 0;})]); ");
/*fuzzSeed-202342322*/count=583; tryItOut("\"use strict\"; { void 0; setGCCallback({ action: \"majorGC\", depth: 10, phases: \"end\" }); } a0.unshift(e0);function e(x, x, x, w, e, x, eval,   = [] = (allocationMarker()), eval, a, eval, x, z = false,  , \u3056, z, d, x, c = [z1,,], x, y, e, window = new RegExp(\"([^])\", \"gym\"), x, x, window, eval = new RegExp(\"([^\\\\cQ\\\\r-n]|\\\\2*?\\\\W?+?)\", \"g\"), b, b, \u3056 = \u3056, window, x, x = new RegExp(\"(?!(?:(?=(?!$|.)\\\\d{3,}|(?=^))))*\", \"yi\"), get, d, d = new RegExp(\"(?:(?=$+)|.|$)|${134217729,}\", \"gy\"), b, x, true, z, x = [,,], NaN, y = [z1,,], x = -9, e, w, w, x, b, x, yield = \"\\u63C5\", eval, x, x, x) { return (void shapeOf(/*MARR*/[new String(''), new String(''), new String(''), 3, 3, 3, Number.MAX_SAFE_INTEGER, new String(''), 3, 3, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new String(''), Number.MAX_SAFE_INTEGER, 3, 3, 3, new String(''), 3, new String(''), Number.MAX_SAFE_INTEGER, 3, 3, new String(''), Number.MAX_SAFE_INTEGER, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, Number.MAX_SAFE_INTEGER, 3, 3, new String(''), Number.MAX_SAFE_INTEGER, 3, 3, new String(''), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 3, new String(''), 3, 3, new String(''), Number.MAX_SAFE_INTEGER, new String(''), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 3, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new String(''), new String(''), new String(''), Number.MAX_SAFE_INTEGER, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), 3, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 3, new String(''), new String(''), Number.MAX_SAFE_INTEGER, new String(''), 3, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new String(''), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 3, Number.MAX_SAFE_INTEGER, new String(''), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 3, 3, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new String(''), Number.MAX_SAFE_INTEGER, 3, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, new String(''), Number.MAX_SAFE_INTEGER, 3, new String(''), Number.MAX_SAFE_INTEGER, new String('')].filter)) } this.zzz.zzz;");
/*fuzzSeed-202342322*/count=584; tryItOut("(void schedulegc(g1.g0));");
/*fuzzSeed-202342322*/count=585; tryItOut("function this.f1(h1)  { /*tLoop*/for (let d of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, x, x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined()]) {  for  each(let x in  /x/g ) m1.get(s0); } } ");
/*fuzzSeed-202342322*/count=586; tryItOut("\"use strict\"; a0.push(m0);");
/*fuzzSeed-202342322*/count=587; tryItOut("for (var v of this.g0) { try { v2 = (h2 instanceof m1); } catch(e0) { } g1.p0 + ''; }");
/*fuzzSeed-202342322*/count=588; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(g2, a2);");
/*fuzzSeed-202342322*/count=589; tryItOut("p1 + i0;");
/*fuzzSeed-202342322*/count=590; tryItOut("v0 = Object.prototype.isPrototypeOf.call(o0, o1);");
/*fuzzSeed-202342322*/count=591; tryItOut("g1.offThreadCompileScript(\"function f2(e0) \\\"use asm\\\";   function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var d2 = 147573952589676410000.0;\\n    switch ((((0x0) % (0x381c155f)) << ((0x3e7128c5) % (0x4f3d87f0)))) {\\n      case -1:\\n        d2 = (d0);\\n        break;\\n      case 0:\\n        d0 = (-34359738368.0);\\n      case -2:\\n        {\\n          d0 = (((d2)));\\n        }\\n        break;\\n      default:\\n        d2 = (1.0);\\n    }\\n    {\\n      d2 = (d2);\\n    }\\n    d0 = (d2);\\n    return ((-0xd40fa*(0xb90b8d54)))|0;\\n    return (((0x845d7be)))|0;\\n  }\\n  return f;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 == 1), noScriptRval: true, sourceIsLazy: (x % 4 != 1), catchTermination: (x % 36 == 27) }));");
/*fuzzSeed-202342322*/count=592; tryItOut("while(((a = Proxy.createFunction(({/*TOODEEP*/})(26), function  c (w) { \"use strict\"; yield function ([y]) { } } , Map.prototype.entries))) && 0)\"\\uF7F5\";");
/*fuzzSeed-202342322*/count=593; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=594; tryItOut("\"use strict\"; i0.send(o1);");
/*fuzzSeed-202342322*/count=595; tryItOut("x = h2;");
/*fuzzSeed-202342322*/count=596; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=597; tryItOut("r2 = new RegExp(\"(?!\\\\1.|\\\\w*)[^][^].{4}|\\\\x00|\\\\b(?:^\\\\s).[^-\\\\w\\\\D\\\\r\\\\S]|[^]{0,0}{3,}\", \"gm\");");
/*fuzzSeed-202342322*/count=598; tryItOut("\"use strict\"; /*infloop*/for(var e in ((function(y) { return a-- })(\"\\u4826\".__defineGetter__(\"x\", -11) && let (d = [,], mqpghz, e, x, yeisnm, iisqhr, ccqxje, xyznmo, dgskdq, x) (4277))))kerpds(\"\\uBAB0\"(-27, false),  /x/ );/*hhh*/function kerpds(x, e){/*RXUB*/var r = r1; var s = \"\\u00de\\n\"; print(uneval(r.exec(s))); \u0009}");
/*fuzzSeed-202342322*/count=599; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1/0, 0.000000000000001, -(2**53-2), -0x080000001, -Number.MIN_VALUE, -(2**53), 0, 0/0, -Number.MAX_VALUE, 0x100000000, -1/0, 1, -0x080000000, -0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), 0x100000001, -0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, 0x0ffffffff, 0x080000001, 0x07fffffff, Number.MIN_VALUE, 0x080000000, -0, Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, Math.PI]); ");
/*fuzzSeed-202342322*/count=600; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=601; tryItOut(" = a1[x];");
/*fuzzSeed-202342322*/count=602; tryItOut("\"use strict\"; print(x);function y(...x) { \"use strict\"; return x } return;");
/*fuzzSeed-202342322*/count=603; tryItOut("mathy4 = (function(x, y) { return Math.fround(( + ( + (Math.atan2(( + ((y ** 0) ? ( + Math.sqrt(Math.max(( ! y), y))) : ((Math.expm1(1/0) | 0) | 0))), ( + Math.acos(( + x)))) ? (( - (x | 0)) | 0) : (Math.asin(Math.fround(( ! ( + (( + 0x080000001) << ( + -Number.MIN_VALUE)))))) * ( - -0x080000001)))))); }); testMathyFunction(mathy4, [1/0, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 2**53, 0, 1, 0x100000001, 2**53-2, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000, 0/0, -0x080000001, 0x07fffffff, -0x07fffffff, -0, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0x080000001, 0x100000000, 0.000000000000001, 2**53+2, -(2**53+2), 42, 0x0ffffffff, -1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-202342322*/count=604; tryItOut("Array.prototype.shift.call(a2, o0);");
/*fuzzSeed-202342322*/count=605; tryItOut("h1.delete = f2;");
/*fuzzSeed-202342322*/count=606; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var cos = stdlib.Math.cos;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        {\n          {\n            i1 = (0x2ed40d4a);\n          }\n        }\n      }\n    }\n    i1 = (/*FFI*/ff(((0x1a4744ad)), ((((d0)) / ((+pow(((d0)), ((36893488147419103000.0))))))), ((((d0)) / ((((-1.2089258196146292e+24)) % ((d0)))))))|0);\n    i1 = (i1);\n    d0 = (-67108865.0);\n    i1 = (/*FFI*/ff()|0);\n    d0 = (7.737125245533627e+25);\n    {\n;    }\n    return +((+((d0))));\n    i1 = (!((0xfa16add7) ? (!(0xfe1930fb)) : ((d0) != (+pow(((+cos(((d0))))), ((-((d0)))))))));\n    (Int8ArrayView[(((/*FFI*/ff()|0) ? ((9007199254740991.0) == (16384.0)) : (i1))-(i1)+(0xa392e723)) >> 0]) = ((((0xffffffff) ? (-0x8000000) : (/*FFI*/ff()|0)) ? (0x1129ee01) : (0xfa154719))*-0x9d546);\n    {\n      (Uint32ArrayView[((-0x18bd66c)) >> 2]) = ((i1)-(0x74513e1c));\n    }\n    i1 = (0xae65dc4c);\n    d0 = (d0);\n    d0 = (+pow(((d0)), ((d0))));\n    return +((536870913.0));\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: offThreadCompileScript, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: undefined, set: function() { return false; }, iterate: function() { throw 3; }, enumerate: undefined, keys: runOffThreadScript, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 1, 0/0, 0, 0x080000001, 0x0ffffffff, 0.000000000000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, 1.7976931348623157e308, 42, -0x080000000, 0x080000000, -Number.MIN_VALUE, 0x07fffffff, 0x100000000, -1/0, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53, -(2**53+2), Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, -(2**53-2), -0, Number.MIN_VALUE, 1/0, -Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-202342322*/count=607; tryItOut("this.e0.has(s0);");
/*fuzzSeed-202342322*/count=608; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! (( ~ (( + y) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [0, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, 1.7976931348623157e308, 2**53, 0x100000001, -0x07fffffff, 42, 0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -0, Number.MIN_VALUE, -Number.MIN_VALUE, -1/0, 0/0, -0x100000001, -(2**53+2), Math.PI, 2**53+2, -(2**53-2), Number.MAX_VALUE, 0x100000000, -0x100000000, 1/0, 1, 0x080000001, -Number.MAX_VALUE, -0x0ffffffff, -(2**53), 0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=609; tryItOut("v1 = -0;");
/*fuzzSeed-202342322*/count=610; tryItOut("e0.has(a0);");
/*fuzzSeed-202342322*/count=611; tryItOut("a0 + e0;");
/*fuzzSeed-202342322*/count=612; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.sin(Math.expm1(( ! Math.cbrt(Math.max((Math.pow(2**53, 0) >>> 0), (y >>> 0)))))); }); testMathyFunction(mathy0, ['0', -0, 0.1, (new String('')), [0], ({valueOf:function(){return 0;}}), (new Number(0)), true, objectEmulatingUndefined(), 0, [], ({toString:function(){return '0';}}), (new Boolean(true)), (new Number(-0)), (function(){return 0;}), '', (new Boolean(false)), 1, NaN, '\\0', false, null, ({valueOf:function(){return '0';}}), /0/, '/0/', undefined]); ");
/*fuzzSeed-202342322*/count=613; tryItOut("testMathyFunction(mathy1, ['0', ({toString:function(){return '0';}}), 1, false, (function(){return 0;}), NaN, (new String('')), 0, null, undefined, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), 0.1, [], (new Number(0)), (new Number(-0)), -0, '/0/', '', /0/, (new Boolean(true)), true, [0], '\\0', (new Boolean(false))]); ");
/*fuzzSeed-202342322*/count=614; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround(Math.atan(Math.atanh((Math.min(-0, y) >>> (0x100000000 !== ( + Math.log10(( + y)))))))) << mathy1(Math.imul(( + y), 0x080000000), Math.imul(0x100000001, ((Math.fround(Math.atan2((( ! (y | 0)) >>> 0), Math.fround(x))) | 0) && (Math.pow(( + Math.cos(( + 1.7976931348623157e308))), Math.atan(((mathy1((y >>> 0), (x >>> 0)) >>> 0) >>> 0))) | 0))))); }); ");
/*fuzzSeed-202342322*/count=615; tryItOut("");
/*fuzzSeed-202342322*/count=616; tryItOut("testMathyFunction(mathy4, [(new Boolean(false)), null, (new String('')), (new Boolean(true)), (function(){return 0;}), [], false, NaN, ({toString:function(){return '0';}}), -0, true, 0, ({valueOf:function(){return 0;}}), '', [0], objectEmulatingUndefined(), (new Number(-0)), (new Number(0)), /0/, '\\0', 1, '/0/', 0.1, undefined, ({valueOf:function(){return '0';}}), '0']); ");
/*fuzzSeed-202342322*/count=617; tryItOut("var b =  /x/g  ** arguments--;v2 = Object.prototype.isPrototypeOf.call(v2, g0);");
/*fuzzSeed-202342322*/count=618; tryItOut("Array.prototype.reverse.call(a2, h0);");
/*fuzzSeed-202342322*/count=619; tryItOut("o0.e0.delete(e2);");
/*fuzzSeed-202342322*/count=620; tryItOut("mathy2 = (function(x, y) { return (Math.hypot(( + (( - ( + x)) | 0)), Math.cos(mathy0((x , (Math.cosh(1/0) | 0)), ( ~ ( + ( + Math.log2(0x080000000))))))) >>> 0); }); testMathyFunction(mathy2, [true, /0/, (new Boolean(true)), NaN, 0.1, ({valueOf:function(){return 0;}}), null, '\\0', ({toString:function(){return '0';}}), '0', (function(){return 0;}), [0], [], objectEmulatingUndefined(), (new String('')), '/0/', '', 1, (new Boolean(false)), undefined, (new Number(0)), 0, false, (new Number(-0)), ({valueOf:function(){return '0';}}), -0]); ");
/*fuzzSeed-202342322*/count=621; tryItOut("testMathyFunction(mathy2, [({toString:function(){return '0';}}), '', [], (new Number(0)), ({valueOf:function(){return '0';}}), true, 0.1, false, 0, /0/, objectEmulatingUndefined(), '/0/', (new Boolean(false)), (new Number(-0)), '\\0', -0, NaN, ({valueOf:function(){return 0;}}), null, (new Boolean(true)), (new String('')), '0', [0], undefined, 1, (function(){return 0;})]); ");
/*fuzzSeed-202342322*/count=622; tryItOut("\"use strict\"; (((makeFinalizeObserver('nursery')))(((e) = /*UUV1*/(x.log = /*wrap1*/(function(){ /*vLoop*/for (var eikuij = 0, [[]]; eikuij < 26; ++eikuij) { var a = eikuij; v2 = (o2 instanceof i1); } return Map.prototype.set})()))) = /*RXUE*/new RegExp(\"(?!(?:[^]){8388609,8388612})*?\", \"yim\").exec(\"\"));");
/*fuzzSeed-202342322*/count=623; tryItOut("mathy3 = (function(x, y) { return ( + Math.hypot(( ~ ( + ((( ~ (x >>> 0)) | 0) ** ((( + ( + ( + (( + -0x100000000) << ( + y))))) ^ 42) >>> 0)))), Math.fround(Math.asinh(Math.fround(Math.tan(( + ( + (Math.asinh(Number.MAX_VALUE) ? mathy0(0x100000000, 1.7976931348623157e308) : x))))))))); }); testMathyFunction(mathy3, ['0', '/0/', '\\0', [], 0, 1, ({toString:function(){return '0';}}), NaN, objectEmulatingUndefined(), (new Boolean(false)), null, (new Number(0)), undefined, ({valueOf:function(){return '0';}}), -0, true, (new Boolean(true)), (new String('')), 0.1, [0], '', (new Number(-0)), (function(){return 0;}), false, /0/, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-202342322*/count=624; tryItOut("g2.g1.offThreadCompileScript(\"/*infloop*/ for (var d of new RegExp(\\\"(.|[^\\\\\\\\v\\\\\\\\f\\\\\\\\cD-\\\\\\\\f]-\\\\ub8bb]\\\\\\\\d|(?!\\\\\\\\B))|(?:(?:(?![\\\\u0085-\\\\u00a8\\\\\\\\b-\\\\uc6e8\\\\\\\\u7E99][^]*))){34359738367,}\\\", \\\"\\\") **= -4) {(4277) = a0[({valueOf: function() { s2 += s2;return 12; }})]; }\\n/*MXX2*/o2.g0.EvalError.prototype.name = o1.h1;\\n\", ({ global: o0.g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: x, sourceIsLazy: false, catchTermination: c ?  /x/  : x }));");
/*fuzzSeed-202342322*/count=625; tryItOut("a1.splice(NaN, 13);");
/*fuzzSeed-202342322*/count=626; tryItOut("s1 += g2.s0;a0 = new Array;");
/*fuzzSeed-202342322*/count=627; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x07fffffff, -0x080000000, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 0x07fffffff, -(2**53+2), -0x0ffffffff, 2**53, 2**53+2, 2**53-2, 0, 1/0, -0x100000000, 0.000000000000001, -(2**53-2), 0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, 0x100000001, -Number.MAX_VALUE, Math.PI, 1, 0/0, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, -(2**53)]); ");
/*fuzzSeed-202342322*/count=628; tryItOut("s1 += s0;");
/*fuzzSeed-202342322*/count=629; tryItOut("mathy3 = (function(x, y) { return Math.min(mathy2(Math.fround(Math.atan2(Math.fround(y), (Math.sign((( + (y >>> x)) == y)) >>> 0))), ( + ( + Math.acos(( + x))))), ( + ( - ( ~ Math.imul((x | -(2**53-2)), Math.PI))))); }); testMathyFunction(mathy3, /*MARR*/[Infinity, 1.3, Infinity, 2**53-2, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, 1.3, Infinity, 2**53-2]); ");
/*fuzzSeed-202342322*/count=630; tryItOut("\"use strict\"; testMathyFunction(mathy0, [(new Boolean(true)), '0', (new Number(-0)), true, '\\0', (new String('')), objectEmulatingUndefined(), (new Number(0)), undefined, 0.1, (function(){return 0;}), (new Boolean(false)), ({valueOf:function(){return 0;}}), NaN, [], null, 1, false, /0/, '/0/', 0, [0], '', ({valueOf:function(){return '0';}}), -0, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-202342322*/count=631; tryItOut("testMathyFunction(mathy4, [(new String('')), 0.1, '', [0], NaN, [], objectEmulatingUndefined(), '\\0', null, 0, (new Number(0)), /0/, 1, -0, (function(){return 0;}), undefined, (new Boolean(false)), '0', false, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), '/0/', true, ({valueOf:function(){return '0';}}), (new Number(-0)), (new Boolean(true))]); ");
/*fuzzSeed-202342322*/count=632; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (/*FFI*/ff()|0);\n    }\n    i0 = ((((2251799813685249.0)) / ((-17179869185.0))) < (((((Float64ArrayView[0])) * ((33554432.0)))) / ((NaN))));\n    i0 = (-0x8000000);\n    i0 = (i0);\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: (new Function(\"t2 = new Uint8Array(b1);\"))}, new ArrayBuffer(4096)); ");
/*fuzzSeed-202342322*/count=633; tryItOut("if(true) (5); else  if (\"\\u85FD\") t1 = v1;");
/*fuzzSeed-202342322*/count=634; tryItOut("this.a0 = this.o0.a0.concat(t1, t0, a0, t1, a1, o0.a0, a2, this.g2.a2, t0, this.t0);");
/*fuzzSeed-202342322*/count=635; tryItOut("/*RXUB*/var r = new RegExp(\"[^\\\\W\\\\s\\\\cZ-\\\\x14]{4,8}|(?!(?=..+)\\\\D?)|(?=[^]*?|([\\\\\\u0005])*|(?:(?:[^][\\\\xA2\\\\u00a8-\\\\xe0\\\\D]))){3,274877906947}{4,}\", \"gyi\"); var s = \"\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\\n\\u00a8\"; print(s.replace(r, '')); ");
/*fuzzSeed-202342322*/count=636; tryItOut("mathy5 = (function(x, y) { return ( - ( - ( + Math.max(( ! mathy3(0x100000000, Math.clz32(( + y)))), ( - (( + Math.expm1(y)) || ( ! 0x080000000))))))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, Number.MAX_VALUE, -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, -1/0, 0x07fffffff, 0x100000000, 0x080000000, 42, -0x07fffffff, 0x080000001, -0x0ffffffff, 1/0, 0/0, 0, -(2**53-2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, -Number.MAX_VALUE, -0, 2**53-2, -Number.MIN_VALUE, 1, 0.000000000000001, 0x100000001, Math.PI]); ");
/*fuzzSeed-202342322*/count=637; tryItOut("\"use strict\"; var zwrrsm;v2 = Array.prototype.some.apply(a0, [(function() { try { Array.prototype.reverse.call(a0, m2); } catch(e0) { } try { a1.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15) { a5 = 4 ^ a12; var r0 = a2 ^ 1; var r1 = a2 % 1; var r2 = a7 ^ 3; a10 = r0 % x; var r3 = a2 & a13; var r4 = x ^ a14; var r5 = r3 ^ a0; var r6 = a9 * a11; var r7 = a1 | r3; print(a13); var r8 = 4 % 9; var r9 = a6 / a7; return a1; }), m1); } catch(e1) { } o1 + i0; return e0; })]);");
/*fuzzSeed-202342322*/count=638; tryItOut("mathy0 = (function(x, y) { return ( + Math.imul(( + Math.clz32(((x >>> 0) - (Math.atanh((0x080000001 >>> 0)) >>> 0)))), (( + Math.sign(Math.fround(x))) | Math.atan2(x, x)))); }); testMathyFunction(mathy0, [-0x080000000, -0x100000000, 42, -Number.MIN_VALUE, 2**53, -(2**53), 1, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, -0x07fffffff, 0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, 0, 0x080000001, -1/0, 1/0, Number.MAX_VALUE, -(2**53-2), 0x100000000, Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -0x100000001, 0x100000001, 0.000000000000001, Math.PI, -(2**53+2), -0x0ffffffff, 2**53-2, 1.7976931348623157e308]); ");
/*fuzzSeed-202342322*/count=639; tryItOut("mathy4 = (function(x, y) { return (Math.exp(( + Math.sqrt(( + (-1/0 ? Math.asinh(x) : (y >>> 0)))))) >= Math.fround(Math.fround(Math.sign((( ~ ( - y)) === 0x080000001))))); }); testMathyFunction(mathy4, [0x100000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, 1/0, 1, 0x080000000, -0x07fffffff, -0x100000000, -0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, 2**53+2, -(2**53), -0x080000001, -(2**53-2), -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 0.000000000000001, -1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0, 0/0, -0x100000001, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, -0, 42]); ");
/*fuzzSeed-202342322*/count=640; tryItOut("for (var p in g1) { try { f2.__iterator__ = (function() { for (var j=0;j<14;++j) { f1(j%4==1); } }); } catch(e0) { } try { i0 = a0[4]; } catch(e1) { } try { /*RXUB*/var r = r1; var s = \"\\u1f8d\"; print(s.replace(r, function(y) { yield y; v0 = evalcx(\"o2 = Object.create(m0);\", g2);; yield y; }));  } catch(e2) { } Array.prototype.pop.apply(a1, [ '' , \"\\u421E\"\n.__defineGetter__(\"x\", decodeURI) !== x, this.g0.h2, h0]); }");
/*fuzzSeed-202342322*/count=641; tryItOut("\"use strict\"; let(x = \"\\u0B88\", huccgp) ((function(){(window);})());");
/*fuzzSeed-202342322*/count=642; tryItOut("\"use strict\"; Object.seal(g1);");
/*fuzzSeed-202342322*/count=643; tryItOut("mathy5 = (function(x, y) { return Math.cbrt(Math.round(Math.min((y | 0), x))); }); testMathyFunction(mathy5, [(new String('')), false, '0', '\\0', (new Number(-0)), [], 0, (new Number(0)), ({toString:function(){return '0';}}), 0.1, ({valueOf:function(){return 0;}}), undefined, '', true, ({valueOf:function(){return '0';}}), '/0/', null, NaN, [0], 1, /0/, objectEmulatingUndefined(), (new Boolean(true)), (function(){return 0;}), (new Boolean(false)), -0]); ");
/*fuzzSeed-202342322*/count=644; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-202342322*/count=645; tryItOut("\"use strict\"; \"use asm\"; ");
/*fuzzSeed-202342322*/count=646; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.max(( + mathy3(((Math.min((Math.min(mathy0((y | 0), 42), (x >>> 0)) | 0), x) >>> 0) | 0), ( + mathy1((Math.log(x) >>> 0), ( + x))))), ( ~ (Math.pow((( + (( + y) + ( + (((-0x080000000 >>> 0) || (y >>> 0)) >>> 0)))) < ( + (( - (Math.pow(Math.PI, x) >>> 0)) ^ x))), mathy3((((0 >>> 0) !== (( + ((0x080000001 >>> 0) && y)) >>> 0)) >>> 0), x)) >>> 0))); }); ");
/*fuzzSeed-202342322*/count=647; tryItOut("x = x;[z1];");
/*fuzzSeed-202342322*/count=648; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((Math.fround(Math.log1p(y)) ? (((y | 0) % ((mathy1(((x < ( - Math.fround((y ? (x >>> 0) : ( + -0x080000001))))) | 0), (x | 0)) | 0) | 0)) | 0) : ((((Math.fround(Math.atanh(y)) && x) & x) >>> 0) >>> 0)) <= Math.fround((Math.fround((Math.fround(Math.sign(Math.fround(Math.max(( + x), y)))) / ((( + ( - (x ^ (mathy1(y, y) >>> 0)))) ^ Math.fround((( ~ (Math.imul(x, x) >>> 0)) >>> 0))) | 0))) * Math.fround(( ! x))))) | 0); }); testMathyFunction(mathy2, [1/0, 2**53+2, 2**53, Number.MAX_VALUE, -(2**53+2), 2**53-2, -0x100000000, -0x080000000, 1, Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -0x100000001, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_VALUE, -(2**53), 0x07fffffff, 0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -1/0, 0, -0x080000001, -Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, -0x0ffffffff, 42, 0x100000001, 1.7976931348623157e308, 0/0]); ");
/*fuzzSeed-202342322*/count=649; tryItOut("/*hhh*/function fnnnua(){print(x);}fnnnua();");
/*fuzzSeed-202342322*/count=650; tryItOut("mathy1 = (function(x, y) { return ( + ( - ( ! Math.log2(( + ((Math.atan2(( + x), (-0x080000001 >>> 0)) | 0) % Math.log2(Math.fround(x)))))))); }); ");
/*fuzzSeed-202342322*/count=651; tryItOut("/* no regression tests found */");
/*fuzzSeed-202342322*/count=652; tryItOut("mathy2 = (function(x, y) { return Math.atanh(mathy1(Math.cosh(Math.imul(( + (Math.imul(( + y), y) | 0)), ((((((mathy0((y | 0), y) | 0) >>> 0) >> x) >>> 0) ? Math.fround(( ! ( + (( + x) ? ( + Number.MAX_VALUE) : ( + x))))) : (y >>> 0)) >>> 0))), (Math.fround((((((Math.fround(x) * (y >>> 0)) >>> 0) >>> 0) - ((Math.max(((((( ! y) | 0) | 0) >> y) >>> 0), ((mathy0((y >>> 0), ((Math.hypot((y | 0), 0x07fffffff) | 0) | 0)) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0)) , Math.fround(Math.log10((( ~ x) >>> 0)))))); }); ");
/*fuzzSeed-202342322*/count=653; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(Math.pow(Math.fround((mathy0(( + Math.pow(Math.imul((Math.pow((y >>> 0), (y >>> 0)) | 0), x), ( + (( ! (y | 0)) | 0)))), (Math.log2(((Math.ceil((x | 0)) / ( + ( - x))) | 0)) | 0)) >>> 0)), Math.fround(( ! ((( ! ((Math.asinh(x) ? x : (Math.fround((Math.min(Math.atan2(( + x), ( + -Number.MAX_SAFE_INTEGER)), y) | 0)) | 0)) | 0)) | 0) >>> 0))))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 1/0, Math.PI, -(2**53), Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, 0x100000001, 1, 2**53, 2**53+2, 0, 0x080000000, 0x100000000, -0, 0/0, -1/0, 0x07fffffff, Number.MAX_VALUE, -0x07fffffff, -(2**53-2), 42, 0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 1.7976931348623157e308, -0x0ffffffff, -0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=654; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-(2**53), 0x100000000, 0/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, -0x080000001, -(2**53-2), 2**53-2, -0x100000001, -0x100000000, 2**53, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, 42, -0, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -1/0, 0x080000000, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1/0, 1, -(2**53+2), 0x100000001, Number.MIN_VALUE, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-202342322*/count=655; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((Math.atan((Math.min((Math.fround((( ~ ( + (Math.atanh((y >>> 0)) >>> 0))) | 0)) | 0), (Math.atan2(-1/0, (x >>> 0)) >>> 0)) | 0)) | 0) === mathy1((((Math.pow((( + (0x100000000 !== x)) | 0), x) | 0) || (Math.min(( ! Math.fround((Math.fround((( ~ -0x080000000) | 0)) ? ( - x) : x))), Math.acos(Math.fround(((1 >>> 0) ? (y >>> 0) : x)))) | 0)) | 0), Math.fround(mathy3((( ~ (( + mathy2(y, ( + x))) >>> 0)) | 0), (( ! (y * 0.000000000000001)) | 0))))); }); ");
/*fuzzSeed-202342322*/count=656; tryItOut("Array.prototype.reverse.call(o2.a2);");
/*fuzzSeed-202342322*/count=657; tryItOut("i0.next();");
/*fuzzSeed-202342322*/count=658; tryItOut("\"use strict\"; switch(y) { default: break;  }");
/*fuzzSeed-202342322*/count=659; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=660; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -4.835703278458517e+24;\n    return +((+exp(((d2)))));\n  }\n  return f; })(this, {ff: function(y) { yield y; a0 = Proxy.create(h1, v0);; yield y; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1/0, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, 0x080000001, -(2**53), 0x100000000, 2**53-2, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 42, 0x07fffffff, 1.7976931348623157e308, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, Math.PI, -0x100000000, -0x100000001, -0x0ffffffff, 1, -0, 0x080000000, 2**53, -0x07fffffff, -0x080000001, -0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-202342322*/count=661; tryItOut("/*RXUB*/var r = new RegExp(\"^{3,}|\\\\B|.{1,}?^(?:\\\\2)*+{4,}*?\", \"yi\"); var s = \"\"; print(s.match(r)); t2 = o2.t0.subarray(4, ({valueOf: function() { s2 + '';return 12; }}));");
/*fuzzSeed-202342322*/count=662; tryItOut("/*MXX2*/g0.Number.prototype = f0;");
/*fuzzSeed-202342322*/count=663; tryItOut("\"use strict\"; g2 = this;");
/*fuzzSeed-202342322*/count=664; tryItOut("g1.o2.v1 = g1.eval(\"function f1(t2) \\\"use asm\\\";   function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    i0 = (!(i0));\\n    i1 = (i0);\\n    return (((-0x2b465f9)))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-202342322*/count=665; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; gcslice(71985); } void 0; } {}");
/*fuzzSeed-202342322*/count=666; tryItOut("o0.h2.toString = f1;");
/*fuzzSeed-202342322*/count=667; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.fround(Math.pow(Math.fround(Math.hypot(Math.fround(((Math.max(((Math.fround(((x | 0) >>> (x | 0))) ^ (x | 0)) | 0), (Math.hypot(Math.ceil(x), y) >>> 0)) | 0) % (x >>> 0))), Math.atan2(( + x), (Math.min((Math.fround(((x | 0) > (x | 0))) >>> 0), ( + 0x0ffffffff)) >>> 0)))), Math.fround(Math.tan((( - (Math.hypot(-0x0ffffffff, Math.PI) >>> 0)) >>> 0))))) - Math.pow(( ~ ((( ~ ((( ! x) >>> 0) | 0)) | 0) >>> 0)), Math.sign(( + (( ! x) == (Math.clz32(y) >>> 0)))))); }); testMathyFunction(mathy0, /*MARR*/[]); ");
/*fuzzSeed-202342322*/count=668; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-202342322*/count=669; tryItOut("\"use strict\"; Object.prototype.unwatch.call(f1, \"splice\");");
/*fuzzSeed-202342322*/count=670; tryItOut("v1 = evaluate(\"function f0(g1.e1) (NaN = \\\"\\\\u6C94\\\")\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: \u3056 % x, noScriptRval: x, sourceIsLazy: true, catchTermination: false, element: o1, elementAttributeName: s0 }));");
/*fuzzSeed-202342322*/count=671; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.max(( + ((( ~ ((( + (x | 0)) | 0) / (((x >>> 0) <= (y >>> 0)) >>> 0))) >>> 0) === ( + Math.fround(y)))), Math.fround(mathy1(Math.sign(Math.imul(x, (mathy1(( + (Math.cos((mathy0((y >>> 0), y) >>> 0)) >>> 0)), ( + x)) | 0))), Math.fround(( + Math.fround((y || (( ~ (y >>> 0)) >>> 0))))))))); }); testMathyFunction(mathy3, [-0x080000000, -1/0, -(2**53), Math.PI, Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, -(2**53-2), 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), 0x080000001, 1.7976931348623157e308, 1, Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, 0/0, 0.000000000000001, 0x100000000, -0, -Number.MAX_VALUE, 2**53, -0x0ffffffff, Number.MAX_VALUE, -0x100000001, 2**53+2, -0x080000001, -Number.MIN_VALUE, 2**53-2, 1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-202342322*/count=672; tryItOut("var x = undefined;return;\nm0.has(e2);\n");
/*fuzzSeed-202342322*/count=673; tryItOut("\"use strict\"; m1.has(f2);");
/*fuzzSeed-202342322*/count=674; tryItOut("mathy0 = (function(x, y) { return Math.fround(((( ~ (((Math.imul(((Math.hypot((y >>> 0), (x | 0)) | 0) >> (-(2**53-2) | 0)), ( ~ (x , y))) >>> 0) || (Math.hypot((Math.sinh(((((y | 0) !== x) | 0) >>> 0)) >>> 0), (Math.log1p(x) >>> 0)) >>> 0)) >>> 0)) | 0) ** ((Math.pow((Math.imul(1, Math.sqrt(((Math.fround((Math.acosh(/*MARR*/[undefined, undefined, false, false, false, false, undefined, true, true, true, true, undefined, undefined, false, true, false, false, true, true, undefined, true, true, undefined, undefined, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, undefined, undefined, false, undefined, true, false, false, false, undefined, false, true, false, undefined, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, true, undefined, false, true, false, undefined, undefined, true, true, true, true, false, false, undefined, true, false, undefined, undefined, undefined, false, false, false, undefined, undefined, undefined, undefined, false, false, undefined, true, undefined, true, undefined, true, undefined, false, false, true, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, undefined, undefined, undefined, undefined, undefined, undefined, undefined, true, true, false, true, true, undefined, true, false]) | 0)) , (Math.acos((x ? x : (y | 0))) | 0)) | 0))) >>> 0), (Math.log(x) >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy0, /*MARR*/[ 'A' , (void 0), objectEmulatingUndefined(), (void 0)]); ");
/*fuzzSeed-202342322*/count=675; tryItOut("mathy0 = (function(x, y) { return (( ~ ((((Math.imul(42, ( + ( + ( + (((Math.atan(y) >>> 0) ** (Math.tan(y) >>> 0)) >>> 0))))) >>> 0) - ((x * Math.fround(x)) ? (x | 0) : -(2**53))) << ( + y)) | 0)) | 0); }); testMathyFunction(mathy0, [-1/0, -0x07fffffff, 0x100000001, -(2**53-2), -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 0.000000000000001, -0x080000001, 1/0, 0/0, 2**53+2, 42, Math.PI, -0x100000001, -Number.MAX_VALUE, 0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, 0x100000000, 1.7976931348623157e308, 0x0ffffffff, -0x080000000, 2**53, -Number.MIN_VALUE, 1, -(2**53), 0x080000001]); ");
/*fuzzSeed-202342322*/count=676; tryItOut("a2[18] = x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { throw 3; }, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(true), /*wrap3*/(function(){ var rtdwfm = true; (function(q) { return q; })(); }))");
/*fuzzSeed-202342322*/count=677; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul(Math.fround(Math.log10(Math.fround(( + mathy0(y, (Math.fround((mathy0((y ? x : x), y) * Math.fround(Math.trunc((y >>> 0))))) , Math.hypot((( - x) >>> 0), ((2**53+2 >>> 0) ? 0/0 : (( + (Math.fround(x) ? Math.fround(y) : ( + x))) >>> 0))))))))), Math.fround(mathy0(Math.fround((Math.sinh(y) ** x)), Math.fround(Math.pow(( + Math.cbrt(( + ((( + Number.MAX_SAFE_INTEGER) + (y >>> 0)) >>> 0)))), ( ~ (( + x) >>> mathy0(y, x)))))))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, -0x07fffffff, -Number.MAX_VALUE, 0, -0x100000001, 2**53+2, 1.7976931348623157e308, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, Number.MIN_VALUE, -(2**53), 0/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, Math.PI, -0x080000000, 42, 2**53-2, -(2**53+2), -(2**53-2), -1/0, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, 0.000000000000001, 1, 0x07fffffff]); ");
/*fuzzSeed-202342322*/count=678; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[-Infinity, -Infinity, objectEmulatingUndefined(), -Infinity, new Number(1.5), objectEmulatingUndefined(), (0/0), (0/0), new Number(1.5), -Infinity, new Number(1.5), new Number(1.5), (0/0), -Infinity, new Number(1.5), (0/0), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), -Infinity, -Infinity, (0/0), (0/0), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), -Infinity, -Infinity, objectEmulatingUndefined(), new Number(1.5), -Infinity, new Number(1.5), -Infinity, (0/0), -Infinity, (0/0), -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), (0/0), -Infinity, -Infinity, -Infinity, (0/0), (0/0), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1.5), objectEmulatingUndefined(), -Infinity, -Infinity, (0/0), -Infinity, -Infinity, objectEmulatingUndefined(), (0/0), -Infinity, (0/0), objectEmulatingUndefined(), (0/0), new Number(1.5), -Infinity, new Number(1.5), new Number(1.5), (0/0), new Number(1.5), -Infinity, new Number(1.5), new Number(1.5), -Infinity, -Infinity, -Infinity, objectEmulatingUndefined(), -Infinity, objectEmulatingUndefined(), -Infinity, -Infinity, new Number(1.5), new Number(1.5), -Infinity, -Infinity, (0/0), new Number(1.5), (0/0), new Number(1.5), (0/0), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), (0/0), (0/0), -Infinity, new Number(1.5), new Number(1.5), new Number(1.5), -Infinity, new Number(1.5), (0/0), new Number(1.5), (0/0), objectEmulatingUndefined(), (0/0)]) { t2[({valueOf: function() { a2.sort((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -3.8685626227668134e+25;\n    i0 = (0xe7360a18);\n    d3 = (-127.0);\n    {\n      switch ((((i1)+((0x55e51913))) << ((let (c = /*FARR*/[...[], \"\\uD27E\", -23, ...[], z, ].map) (new window(-15,  /x/g )))))) {\n        default:\n          i1 = (0xed216814);\n      }\n    }\n    return (((i2)))|0;\n  }\n  return f; })(this, {ff: function(y) { return \"\\uE149\" }}, new SharedArrayBuffer(4096)));return 14; }})]; }");
/*fuzzSeed-202342322*/count=679; tryItOut("mathy1 = 21; testMathyFunction(mathy1, ['/0/', true, false, (new Number(0)), ({toString:function(){return '0';}}), undefined, '\\0', ({valueOf:function(){return '0';}}), (function(){return 0;}), 1, (new Boolean(true)), '0', -0, ({valueOf:function(){return 0;}}), null, NaN, (new String('')), [0], '', /0/, (new Number(-0)), (new Boolean(false)), [], 0, 0.1, objectEmulatingUndefined()]); ");
/*fuzzSeed-202342322*/count=680; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.sqrt(Math.expm1((Math.min(y, Math.fround((Math.fround(x) / Math.fround(-(2**53+2))))) ? (( ! y) >>> 0) : (x ** 0x100000000))))); }); testMathyFunction(mathy0, [/0/, (new Number(-0)), ({toString:function(){return '0';}}), undefined, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), false, (new Boolean(true)), 0.1, ({valueOf:function(){return '0';}}), '\\0', [0], null, '0', (new Boolean(false)), true, '/0/', -0, '', 0, (function(){return 0;}), NaN, [], 1, (new String('')), (new Number(0))]); ");
/*fuzzSeed-202342322*/count=681; tryItOut("g2.m0.has(g0.i0);function b(w, ...y)(4277)print(x);");
/*fuzzSeed-202342322*/count=682; tryItOut("selectforgc(o1);/*tLoop*/for (let c of /*MARR*/[true, this, this, {x:3}, {x:3}, this, x = d, true, true, this, this, this, this, x = d, x = d, this, new Boolean(false), new Boolean(false), true, x = d, this, new Boolean(false), x = d, this, true, new Boolean(false), this, this, new Boolean(false), x = d, true, {x:3}, x = d, new Boolean(false), new Boolean(false), this, x = d, new Boolean(false), {x:3}, new Boolean(false), this, this, new Boolean(false), this, x = d, {x:3}, true, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, new Boolean(false), x = d, this, this, {x:3}, this, x = d, this, x = d, true, new Boolean(false), x = d, {x:3}, true, {x:3}, true, x = d, this, this, new Boolean(false), true, {x:3}, x = d]) { ((y++)); }");
/*fuzzSeed-202342322*/count=683; tryItOut("\"use strict\"; /*oLoop*/for (var dvaomu = 0; dvaomu < 41; ++dvaomu) { for (var p in g2) { t1[16] = s2; } } ");
/*fuzzSeed-202342322*/count=684; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((\\u95d3+)){0,}(?!\\\\w)|$(?!\\u00a1|\\\\B{3,})|(?:[^]*?.)*|\\\\b|(?!\\\\3)*\\\\2.?\\\\W{8388608,}|(?:(?!^))\", \"yim\"); var s = \"\\n\\n\\n\\n\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=685; tryItOut("\"use strict\"; \"use asm\"; /*hhh*/function brczkg(x, x, e, x, w = x *= x, y, window, x, x =  /x/g , c, x, {}, b, window, NaN, w, x, x = x, x, x, c, w, eval, x, x, y, x, w, get, x, z, b, a, w, x, x = window, y = \u3056, x, a, NaN, x, e, e, x, x, x, \u3056, x, c, d, NaN, this.eval, eval, c, z = false,  , x = this, z, eval, a = [[1]], NaN, y, x, z, c, b, x, this.x, b, y, NaN, e, ...x){a1 = (function() { \"use strict\"; yield {} = \"\\u6CAB\"; } })();}brczkg((arguments[\"UTC\"] = [[]]) /= (new (arguments.callee)(({entries: false }), offThreadCompileScript.prototype)));");
/*fuzzSeed-202342322*/count=686; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[function(){}, x, true, function(){}, Infinity, function(){}, x, true, Infinity, function(){}, true, Infinity, Infinity]) { print(d); }");
/*fuzzSeed-202342322*/count=687; tryItOut("");
/*fuzzSeed-202342322*/count=688; tryItOut("/*RXUB*/var r = new RegExp(\".|(?=\\\\2){2}(?=\\\\1){1}\", \"ym\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=689; tryItOut("\"use strict\"; /*RXUB*/var r = /(\u9b6a)/m; var s = (x) >= /(?!$+?($)**)(?=\\B|\\3[^]+?)+?/gim.__defineGetter__(\"eval\", Date.prototype.getUTCMonth); print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=690; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( - Math.fround(mathy1(( - ( ! (Math.trunc(( + (y ? -1/0 : y))) | 0))), Math.acos((Math.exp(Math.fround(Math.hypot(Math.fround(y), Math.fround(x)))) - ( ! ( - y))))))); }); testMathyFunction(mathy2, [NaN, /0/, (new Number(-0)), 1, ({toString:function(){return '0';}}), -0, '', (function(){return 0;}), (new Boolean(true)), false, true, (new String('')), ({valueOf:function(){return 0;}}), (new Number(0)), '/0/', (new Boolean(false)), objectEmulatingUndefined(), 0, undefined, '0', [], 0.1, null, '\\0', [0], ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-202342322*/count=691; tryItOut("\"use strict\"; \"use asm\"; var r0 = 2 ^ x; var r1 = r0 + 4; x = r1 + r1; var r2 = x & 9; var r3 = x ^ r1; var r4 = r0 | x; x = 0 & r0; var r5 = r2 / 5; var r6 = 4 % r5; var r7 = r1 / r3; r3 = r6 * r2; var r8 = 5 * 2; var r9 = 4 + 2; r1 = r8 % r7; var r10 = 8 | r9; var r11 = 8 / x; var r12 = 6 * r2; var r13 = r4 / r6; var r14 = r1 ^ r3; r4 = r4 + r7; var r15 = 5 + r4; var r16 = r15 / r4; var r17 = 9 + 5; r1 = r0 - r7; var r18 = 4 | 0; var r19 = r17 * r0; var r20 = 6 + 8; var r21 = r17 ^ r13; r10 = 0 / 8; print(r3); var r22 = r4 % 0; var r23 = x / r18; var r24 = 4 + r6; var r25 = 3 / 4; var r26 = r3 + r23; var r27 = 1 / r2; r21 = r4 / r19; var r28 = 7 & r11; r15 = r25 ^ x; var r29 = r20 / 7; var r30 = r7 % 5; var r31 = r19 ^ r30; var r32 = 2 & 6; var r33 = r25 + 3; var r34 = 5 - r15; var r35 = 5 + r10; var r36 = r5 | r23; var r37 = r16 / 6; print(r12); var r38 = r32 * r34; var r39 = r31 / r14; var r40 = 5 & 1; var r41 = 4 % 6; var r42 = r29 / r41; print(r30); var r43 = 1 | r5; var r44 = 8 % r13; r9 = r11 / r3; var r45 = r20 | r18; var r46 = r28 * r2; var r47 = 6 ^ r10; print(r36); var r48 = 3 % 3; var r49 = r32 & 6; var r50 = r40 & 3; var r51 = r4 ^ r41; print(r29); var r52 = r19 + r25; ");
/*fuzzSeed-202342322*/count=692; tryItOut("v1 = Object.prototype.isPrototypeOf.call(i1, m0);");
/*fuzzSeed-202342322*/count=693; tryItOut("testMathyFunction(mathy4, [-(2**53-2), -0x080000000, 0/0, -Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, 2**53+2, -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -0, 42, Math.PI, 0, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 2**53-2, 0x07fffffff, -0x0ffffffff, -0x100000001, 1, 0x080000000, -1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, -0x080000001, 1/0, -Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-202342322*/count=694; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return (((Math.min((Math.fround(((Math.fround(y) + (x >>> 0)) >>> 0)) + ( + mathy1(( + (mathy0((y >>> 0), ((mathy0(y, (Math.fround(mathy0(Math.fround(y), (y >>> 0))) >>> 0)) >>> 0) >>> 0)) >>> 0)), ( + mathy1(( ! 0x100000000), ( ~ x)))))), ( + Math.pow(( + (mathy0(( + Math.tan(x)), (y | 0)) | 0)), ( + mathy1(( + (( + x) !== ( + x))), ( ! ( + (x * x)))))))) | 0) + (mathy1(( ~ Math.sin(( + Math.max(( + y), ( + Math.imul(0x100000001, x)))))), (( ! y) !== (-1/0 + y))) | 0)) | 0); }); testMathyFunction(mathy2, [true, (function(){return 0;}), ({valueOf:function(){return 0;}}), 0.1, (new Boolean(true)), null, ({toString:function(){return '0';}}), '/0/', NaN, 0, objectEmulatingUndefined(), undefined, false, [], (new Boolean(false)), /0/, (new Number(0)), ({valueOf:function(){return '0';}}), (new Number(-0)), '\\0', 1, '', '0', [0], (new String('')), -0]); ");
/*fuzzSeed-202342322*/count=695; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atanh((( + Math.hypot(((Math.pow(((Math.imul(((((( + ( ~ (x >>> 0))) | 0) != (( - Math.fround(((y >>> 0) === (-(2**53+2) >>> 0)))) >>> 0)) | 0) >>> 0), Math.pow(y, x)) >>> 0) >>> 0), (y >>> 0)) >>> 0) | 0), ( + Math.fround(( ! x))))) | 0)) | 0); }); testMathyFunction(mathy0, [2**53, -0x100000001, -1/0, 0x07fffffff, -0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, 1, Number.MIN_VALUE, 2**53+2, 0/0, 0, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, 0x080000001, -0x080000001, 1.7976931348623157e308, 1/0, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, 0x100000001, 42, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-202342322*/count=696; tryItOut("testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x]); ");
/*fuzzSeed-202342322*/count=697; tryItOut("Array.prototype.forEach.apply(a1, []);");
/*fuzzSeed-202342322*/count=698; tryItOut("\"use strict\"; \"use asm\"; e1.add(s1);");
/*fuzzSeed-202342322*/count=699; tryItOut("v0 = g1.eval(\"new mathy4((4277), ((timeout(1800)))(x))\");");
/*fuzzSeed-202342322*/count=700; tryItOut("/*RXUB*/var r = new RegExp(\"((?!P))\", \"yi\"); var s = \"p\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-202342322*/count=701; tryItOut("mathy2 = (function(x, y) { return ( + Math.hypot(( + Math.imul((Math.sin((Math.fround(Math.pow(mathy0(x, x), y)) > (Math.clz32(y) | 0))) >>> 0), Math.fround(((y | 0) >> (Math.max(Math.hypot(x, x), y) | 0))))), Math.fround(Math.fround(mathy1(Math.fround(Math.atan2(( + Math.tanh(Math.fround(( + x)))), (Math.fround((( - (Math.asinh(x) | 0)) | 0)) ^ (Math.cbrt(0x100000000) / (x , (Math.abs(0x100000000) >>> 0)))))), Math.fround(Math.fround((Math.fround(Math.sign(( ! Math.tanh(x)))) % Math.fround(Math.min(Math.fround(( ~ (x >>> 0))), y)))))))))); }); testMathyFunction(mathy2, [0.000000000000001, -0x100000001, 2**53, 1.7976931348623157e308, 42, -Number.MAX_VALUE, 0x07fffffff, -1/0, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 1, 2**53-2, -(2**53-2), 0x100000000, 1/0, Math.PI, -(2**53+2), 0x080000000, -0x100000000, -0, Number.MIN_VALUE, 2**53+2, -0x07fffffff, -(2**53), -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, 0x100000001]); ");
/*fuzzSeed-202342322*/count=702; tryItOut("Array.prototype.unshift.call(o2.g2.o0.a0);");
/*fuzzSeed-202342322*/count=703; tryItOut("v2 = (v0 instanceof h2);");
/*fuzzSeed-202342322*/count=704; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.cos(Math.asin(((Math.max(((y >>> 0) - y), (mathy3(0x100000000, x) | 0)) >>> 0) * ( + Math.max(( + x), ( + (( + ( + ( + Math.min(y, (y | 0))))) > (42 >>> 0)))))))); }); testMathyFunction(mathy5, /*MARR*/[undefined, x, undefined, undefined, x, x, x, x, undefined, x, x, undefined, undefined, x, undefined, undefined, undefined, x, undefined, undefined, x, x, undefined, x, undefined, x, x, x, undefined, undefined, undefined, undefined, x, undefined, x, x, x, undefined, x, x, undefined, undefined, x, x, undefined, x, x, x]); ");
/*fuzzSeed-202342322*/count=705; tryItOut("\"use strict\"; a2 = arguments;");
/*fuzzSeed-202342322*/count=706; tryItOut("v0 = Object.prototype.isPrototypeOf.call(e0, e0);");
/*fuzzSeed-202342322*/count=707; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atan2((Math.tan((Math.min(0, (( - ( + (( + ( + ( + 0x100000000))) ? ( + -Number.MAX_SAFE_INTEGER) : ( + y)))) | 0)) >>> 0)) | 0), Math.fround((( + Math.cos(-0)) ? ( - Math.fround(( ~ (( + ((y | 0) ^ Math.fround(( + Math.acos(( + ( + -0x080000000))))))) | 0)))) : ((Math.sign((x >>> 0)) >>> 0) ** Math.sqrt((x | 0)))))) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[ '' , Infinity,  '' , Infinity, 1e81, Infinity, Infinity, 1e81, 1e81,  '' , 1e81, 1e81, 1e81, Infinity, 1e81, Infinity,  '' , 1e81,  '' ,  '' , 1e81,  '' , Infinity, Infinity, 1e81, Infinity]); ");
/*fuzzSeed-202342322*/count=708; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    (Float64ArrayView[((~((i3)-((0x33ce8710) ? (0x9ea23b8c) : (-0x8000000)))) % (((0x0) % (0x54e9154f)) >> (-0x575b6*((-2.3611832414348226e+21) != (-1.0))))) >> 3]) = ((Float32ArrayView[((i3)+(!(((2.3611832414348226e+21))))+(0xc10078)) >> 2]));\n    i1 = ((0xfe2db) >= (~((!(i1))-(i1)+((((0x3d976e82) % (0x7cb33c3d))>>>((-0x8000000)+(0x8b9b2cab))) != (0x9227b487)))));\n    i3 = (i3);\n    i2 = (!(((-(((((140737488355329.0)) / ((127.0)))) <= (abs((((0xc9ad0b7e))|0))|0)))>>>((0x26b96e1a)+(!(i3)))) != (((i3)+(i3))>>>((((0x7200cc4) / (0x4b1506f9))|0) % (((0x93915fa0)+(0x35d2ac2b)) >> ((0xf48abc56)-(-0x8000000)+(0x343ac654)))))));\n    i2 = (i1);\n    {\n      {\n        i2 = (i1);\n      }\n    }\n    i3 = (i2);\n    {\n      switch ((((0xa4485396) % (0xf829b7d)) << ((allocationMarker())-((0x92fe723))))) {\n        case -2:\n          i1 = ((((i3)-(i1)) >> ((i1))) < (((i2)-((i3) ? (((0xf2cb2c1b) / (0x7765edeb))) : ((((-0x8000000)) ^ ((0x6162ca74)))))) | ((((0xb805360d) % (0xd3a76a29))|0) % (0x5e2b3a8))));\n          break;\n      }\n    }\n    (Uint8ArrayView[1]) = ((Int16ArrayView[(-(0x14a4d356)) >> 1]));\n    {\n      {\n        i1 = (-0x8000000);\n      }\n    }\n    i2 = (0xffffffff);\n    return +((((Float32ArrayView[2])) - ((2049.0))));\n    d0 = (9.0);\n    i1 = (i3);\n    i3 = ((i1) ? (i3) : (i3));\n    d0 = (d0);\n    d0 = (+((+(1.0/0.0))));\n    d0 = (+((+((Date.prototype.valueOf())))));\n    return +((+pow(((-9223372036854776000.0)), ((Float32ArrayView[2])))));\n  }\n  return f; })(this, {ff: arguments.callee}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[[1], new Boolean(true), new Boolean(true), ['z'], null, ['z'], new Boolean(true), [1], ['z'], null, [1], new Boolean(true), null, [1], null, null, new Boolean(true), ['z'], [1]]); ");
/*fuzzSeed-202342322*/count=709; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-202342322*/count=710; tryItOut("/*MXX2*/g2.DataView.prototype.setFloat64 = h2;v2 = (e1 instanceof g1.e1);");
/*fuzzSeed-202342322*/count=711; tryItOut("\"use strict\"; i1 + '';");
/*fuzzSeed-202342322*/count=712; tryItOut("function f2(g2)  { t1[3] = h2; } ");
/*fuzzSeed-202342322*/count=713; tryItOut("testMathyFunction(mathy5, [(function(){return 0;}), (new Number(-0)), [], -0, [0], '0', /0/, (new Number(0)), 0.1, true, NaN, '', '/0/', ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), undefined, null, 0, false, ({toString:function(){return '0';}}), (new Boolean(false)), (new String('')), '\\0', (new Boolean(true)), 1]); ");
/*fuzzSeed-202342322*/count=714; tryItOut("/*MXX2*/g0.Date.prototype.toTimeString = s0;");
/*fuzzSeed-202342322*/count=715; tryItOut("testMathyFunction(mathy2, /*MARR*/[0xB504F332, (), x, (), (), 0xB504F332, x, x, 0xB504F332, 0xB504F332, x, x, x, 0xB504F332, (), x, x, 0xB504F332, (), 0xB504F332, x, 0xB504F332, x, 0xB504F332, x, (), 0xB504F332, 0xB504F332, (), (), x, x, (), 0xB504F332, (), x, x, 0xB504F332, x, (), (), (), (), (), (), (), (), (), (), (), (), (), x, (), 0xB504F332, x, x, (), 0xB504F332, (), 0xB504F332, 0xB504F332, (), x, x, x, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, x, 0xB504F332, (), 0xB504F332, 0xB504F332, 0xB504F332, x, x, 0xB504F332, 0xB504F332, x, (), 0xB504F332, (), (), 0xB504F332, x, 0xB504F332, 0xB504F332, (), (), x, (), x, 0xB504F332, x, x, 0xB504F332, 0xB504F332, x, ()]); ");
/*fuzzSeed-202342322*/count=716; tryItOut("v1 = g1.runOffThreadScript();");
/*fuzzSeed-202342322*/count=717; tryItOut("\"use strict\"; \"use asm\"; e = linkedList(e, 672);");
/*fuzzSeed-202342322*/count=718; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.imul(Math.max((Math.fround(mathy2(Math.fround(Math.hypot(y, -0x080000001)), Math.fround(x))) == ((Math.min((x | 0), (y | 0)) | 0) | 0)), ((mathy1((y >>> 0), (x >>> 0)) >>> 0) != ((Math.max(y, y) >>> 0) ^ ( ! x)))), ( + (( + ( + Math.pow(Math.atan2((Math.fround(Math.log10(( + (-Number.MAX_SAFE_INTEGER >= ( + Math.imul(0x0ffffffff, ( + y))))))) >>> 0), x), Math.max((( + y) - y), (Math.fround(x) ** x))))) - Math.fround(( + Math.max(((( ~ (Math.cbrt(1) >>> 0)) > Math.abs(y)) | 0), (( + Math.fround((Math.fround(Math.imul(( + x), Math.fround(Math.pow((42 | 0), 0x100000001)))) >> Math.fround(x)))) | 0))))))) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[null, ['z'], new Boolean(false), new Boolean(false), null, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, null, function(){}, new Boolean(false), ['z'], function(){}, ['z'], new Boolean(false), function(){}, function(){}, ['z'], new Boolean(false), ['z'], ['z'],  '' , new Boolean(false), new Boolean(false), function(){}, new Boolean(false),  '' , null, null,  '' , new Boolean(false), null, function(){}, null, function(){}, new Boolean(false), null,  '' , function(){}, ['z'], new Boolean(false), function(){}, null, ['z'], null, function(){}, ['z'], new Boolean(false), ['z'], function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(false),  '' , null, null,  '' , null, null, new Boolean(false),  '' , new Boolean(false), new Boolean(false), function(){}, new Boolean(false), function(){},  '' ,  '' , ['z'], null, new Boolean(false), new Boolean(false), function(){}, ['z'], new Boolean(false), new Boolean(false), ['z'], null, function(){},  '' ,  '' ,  '' , new Boolean(false), function(){}, ['z'], null, new Boolean(false), ['z'],  '' , null, ['z'], null, null, new Boolean(false), function(){}, null, null,  '' , ['z'], ['z'], new Boolean(false),  '' , function(){}, ['z'], function(){}, function(){}, function(){}, null, function(){}, function(){}, ['z'], null, ['z'],  '' ,  '' , new Boolean(false),  '' ,  '' , function(){}, null, ['z'], new Boolean(false),  '' ,  '' , ['z'], null, ['z'], null, new Boolean(false), null]); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
