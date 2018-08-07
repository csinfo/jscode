

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
/*fuzzSeed-116066984*/count=1; tryItOut("/*bLoop*/for (var kwtlmn = 0; kwtlmn < 30; (4277), ++kwtlmn) { if (kwtlmn % 5 == 4) { ;a0.shift(g1, s0, m1, b0, a1, s2); } else { --w; }  } ");
/*fuzzSeed-116066984*/count=2; tryItOut("g2.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-116066984*/count=3; tryItOut("\"use strict\"; \"\\u4195\";");
/*fuzzSeed-116066984*/count=4; tryItOut("v2 = true;");
/*fuzzSeed-116066984*/count=5; tryItOut("(((void shapeOf([ '' ]))));");
/*fuzzSeed-116066984*/count=6; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=7; tryItOut("g0.o0 = new Object;");
/*fuzzSeed-116066984*/count=8; tryItOut("mathy5 = (function(x, y) { return ((((((Math.imul(x, Math.fround((Math.fround(y) ? Math.fround(Math.fround(( + Math.fround(( + ( + ( + Number.MIN_SAFE_INTEGER))))))) : ( + Math.fround((Math.fround(Math.min((y | 0), x)) >= Math.fround(y))))))) >>> 0) + Math.cbrt((( ! (( + Math.imul(( + y), ( + x))) | 0)) | 0))) | 0) | 0) >>> ((Math.fround((Math.fround(( - Math.fround((Math.fround(x) || mathy3(Math.fround(mathy0(1/0, Math.fround(x))), -Number.MAX_VALUE))))) !== (( - (Math.abs(x) >>> 0)) >>> 0))) ? Math.fround(mathy0(Math.fround(( + Math.exp(( + mathy4(y, -(2**53+2)))))), Math.ceil(mathy3(y, x)))) : Math.fround(mathy0(mathy4((-(2**53+2) >>> 0), Math.fround(( + (( + ( + mathy1(x, ( + -Number.MAX_SAFE_INTEGER)))) ? ( + x) : Math.fround(( ~ x)))))), (mathy2(((y + ( + y)) | 0), Math.fround((Math.acosh((x | 0)) | 0))) | 0)))) | 0)) | 0); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -0x080000001, -0x100000000, 1/0, 2**53-2, -0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, Math.PI, 1, 0x080000000, 0x0ffffffff, -(2**53), 0x07fffffff, -0x080000000, 0x080000001, 0x100000001, 2**53, 0/0, 0x100000000, Number.MIN_VALUE, 0, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, Number.MAX_VALUE, -0, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=9; tryItOut("m1.has((4277));");
/*fuzzSeed-116066984*/count=10; tryItOut("mathy0 = (function(x, y) { return ( + (( + (( + ((Math.acos(x) >>> 0) % Math.asinh((Math.fround(Math.abs(( + Math.max(y, x)))) >>> 0)))) >>> 0)) ? Math.fround(Math.sin(Math.fround(Math.trunc(x)))) : ( + (Math.min(Math.fround(Math.atan2(Math.fround(Math.fround((Math.fround(Math.imul(( + Math.min(( + x), ( + (Math.min((y >>> 0), (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)))), x)) << Math.fround(( + ( + -0x07fffffff)))))), (Math.trunc((Math.cbrt(y) | 0)) | 0))), Math.fround(Math.log1p(((Math.tan(x) >>> 0) ? 2**53 : (x >>> 0))))) >>> 0)))); }); testMathyFunction(mathy0, [-(2**53), -(2**53-2), Math.PI, -0x07fffffff, 42, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 1, -Number.MAX_VALUE, -0x080000001, 2**53+2, 0/0, -0x080000000, 0x080000001, 2**53-2, Number.MIN_VALUE, 0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000001, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, -0x100000001, 1.7976931348623157e308, -1/0, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, 0x080000000, 0x100000000, 0x07fffffff, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=11; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = ((0xffb05254) ? (+atan2(((d0)), ((d0)))) : (d0));\n    d0 = (-2047.0);\n    {\n      (Float64ArrayView[2]) = ((let (zhxwme, x = x, qtuvzu) (4277)));\n    }\n    d0 = (d0);\n    return ((-(i1)))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=12; tryItOut("{ void 0; gcslice(342); } f0(a2);");
/*fuzzSeed-116066984*/count=13; tryItOut("/*infloop*/M:for(var x in ((Math.min((makeFinalizeObserver('nursery')), 9))(true)))(({}));");
/*fuzzSeed-116066984*/count=14; tryItOut("\"use strict\"; window;\nreturn;\n");
/*fuzzSeed-116066984*/count=15; tryItOut("t1 = new Uint8Array(a1);");
/*fuzzSeed-116066984*/count=16; tryItOut("Array.prototype.splice.call(a2, NaN, 15, g2.p2, m1);");
/*fuzzSeed-116066984*/count=17; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.max(window, -0) & (4277); }); testMathyFunction(mathy3, [-0x100000000, 0x080000001, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, -1/0, -(2**53), 1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, 0, 1, -0x07fffffff, 0x0ffffffff, -0x0ffffffff, 0x100000001, 2**53-2, 0x07fffffff, -0, 0x080000000, 0.000000000000001, -(2**53-2), Number.MIN_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), Math.PI, 42]); ");
/*fuzzSeed-116066984*/count=18; tryItOut("/*RXUB*/var r = new RegExp(\"\\ucfcc*|(?=\\\\3*){1}\", \"\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116066984*/count=19; tryItOut("e1.delete(b2);");
/*fuzzSeed-116066984*/count=20; tryItOut("mathy3 = (function(x, y) { return ((((mathy2((Math.cbrt(( + Math.atan2((( ! y) | 0), ( + mathy0(( + x), ( + Math.trunc((x >>> 0)))))))) | 0), (Math.asinh(Math.cbrt((Math.min((((y >>> 0) * (y >>> 0)) >>> 0), ( + -Number.MAX_VALUE)) + y))) | 0)) | 0) | 0) | ( + ( - Math.cos(((x , (Math.fround(( + ((x >>> 0) + ( + y)))) <= Math.fround(Math.atan2(Math.fround(Math.pow(x, x)), ( + ( - ( + x))))))) | 0))))) | 0); }); testMathyFunction(mathy3, [-0, 42, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), -0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, 0x080000000, 1.7976931348623157e308, -0x080000000, 0/0, -1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, 2**53+2, -(2**53), -Number.MAX_VALUE, 2**53-2, Number.MAX_VALUE, Math.PI, 2**53, 0.000000000000001, -Number.MIN_VALUE, 0x100000001, -0x080000001, 0x100000000, 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=21; tryItOut("\"use strict\"; \"use asm\"; f1[new String(\"2\")] = p2;yield x;");
/*fuzzSeed-116066984*/count=22; tryItOut("\"use strict\"; /*MXX1*/o1 = o1.o0.g2.Array.prototype.copyWithin;");
/*fuzzSeed-116066984*/count=23; tryItOut("v2 = o1.p0[\"call\"];");
/*fuzzSeed-116066984*/count=24; tryItOut("/* no regression tests found *//*tLoop*/for (let z of /*MARR*/[new String('q'), x, (0/0), new String('q'), x, x, new String('q'), (0/0), x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), x, (0/0), (0/0), (0/0), x, x, x, new String('q'), new String('q'), (0/0), x, (0/0), x, x, x, (0/0), new String('q'), x, (0/0), (0/0)]) { g2.f1.valueOf = (function() { try { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = fillShellSandbox(newGlobal({ sameZoneAs: undefined, disableLazyParsing: false })); f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } catch(e0) { } try { e1.has(t0); } catch(e1) { } try { o2.b0 + ''; } catch(e2) { } for (var p in p2) { try { Object.freeze(o1); } catch(e0) { } e1.has(null); } return this.a1; }); }");
/*fuzzSeed-116066984*/count=25; tryItOut("L: ((x = Proxy.createFunction(({/*TOODEEP*/})([1,,]), (1 for (x in [])), neuter)));");
/*fuzzSeed-116066984*/count=26; tryItOut("\"use asm\"; t1.set(a0, 9);");
/*fuzzSeed-116066984*/count=27; tryItOut("mathy1 = (function(x, y) { return ( + ( ~ (((( + mathy0(y, ( - (y || y)))) | 0) ? Math.fround(Math.atan2(Number.MIN_VALUE, ( + (( ~ (( + ( + ( + x))) >>> 0)) >>> 0)))) : ( + (( + x) <= Math.fround((y | y))))) | 0))); }); ");
/*fuzzSeed-116066984*/count=28; tryItOut("testMathyFunction(mathy0, [-0x0ffffffff, 2**53+2, -0x07fffffff, -0, -0x100000001, 0x080000000, 2**53-2, -(2**53), -(2**53-2), Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 1/0, 0x07fffffff, 42, 1.7976931348623157e308, Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, 2**53, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, 1, 0x100000000, 0x100000001, Number.MAX_VALUE, 0x080000001, -(2**53+2)]); ");
/*fuzzSeed-116066984*/count=29; tryItOut("/*bLoop*/for (var dlkavy = 0; dlkavy < 105; ++dlkavy) { if (dlkavy % 3 == 1) { return; } else { /*MXX3*/g0.String = o0.g0.String; }  } ");
/*fuzzSeed-116066984*/count=30; tryItOut("\"use strict\"; M:\nif(\u000c(x % 3 == 2)) {\u000cv2 = a2.length; } else  if (this)  '' ;");
/*fuzzSeed-116066984*/count=31; tryItOut("\"use strict\"; v2 = (s1 instanceof h2);");
/*fuzzSeed-116066984*/count=32; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + (Math.fround(( - x)) == Math.fround(Math.imul(((Math.min(( + y), ( + y)) | 0) >>> 0), (( + (Math.pow((Math.expm1(x) | 0), (x | 0)) | 0)) >>> 0))))) ** Math.hypot(( + ( + ( + Math.acos(((y ? (x | 0) : (Math.cbrt(( + y)) | 0)) | 0))))), Math.fround(mathy0(Math.fround((y != 0)), mathy0(y, ( + Math.log2(( + x)))))))); }); ");
/*fuzzSeed-116066984*/count=33; tryItOut("m1.has((4277));");
/*fuzzSeed-116066984*/count=34; tryItOut("\"use strict\"; /*infloop*/ for  each(let this.zzz.zzz in 29) {print(x);g1 + this.p0; }");
/*fuzzSeed-116066984*/count=35; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + mathy3(Math.fround(Math.min(( + Math.log2(( + x))), Math.fround(Math.atan(( + (( + x) & ( + y))))))), Math.min(( + x), ((Math.fround(Math.acos(( + y))) & Math.fround(( - y))) >>> 0)))) ? ( + (( + (Math.hypot(Math.fround(Math.fround(Math.trunc(x))), (Math.atanh(Math.hypot(y, Math.fround(x))) >>> 0)) >>> 0)) > ( + Math.fround(Math.abs((((y ** Math.min(-(2**53-2), ( + y))) <= mathy2(0x080000000, (( + Math.min(( + 0x07fffffff), ( + -Number.MIN_SAFE_INTEGER))) >>> 0))) | 0)))))) : (( + ( + (Math.cos(y) ? -Number.MAX_SAFE_INTEGER : (((a >>> 0) != (Math.fround(Math.trunc(Math.fround(x))) >>> 0)) >>> 0)))) - Math.fround(Math.expm1(Math.fround(Math.max((( + (Math.max(( + Math.cos(0.000000000000001)), (y >>> 0)) | 0)) | 0), x)))))); }); testMathyFunction(mathy4, [-1/0, 1/0, 42, 0/0, Number.MIN_VALUE, -0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, 1, -0x07fffffff, Math.PI, -0x0ffffffff, 0, 0x100000001, 2**53, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, -(2**53), 0x080000001, -0x080000001, 0x080000000, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=36; tryItOut("testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, 1.7976931348623157e308, 42, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0x080000001, 2**53, -0x080000000, -1/0, 0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -0, -0x100000001, 1, 0x0ffffffff, Number.MIN_VALUE, 0, 0x080000000, -0x080000001, -Number.MAX_VALUE, 0x07fffffff, -0x100000000, 0/0, 0x100000001, -Number.MIN_VALUE, -(2**53-2), Math.PI]); ");
/*fuzzSeed-116066984*/count=37; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return ((-(!((0xeb21b8f9) == (0x0)))))|0;\n  }\n  return f; })(this, {ff: (eval = Proxy.createFunction(({/*TOODEEP*/})( /x/g ), this,  \"\" ))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, -0, 0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), 0.000000000000001, -0x07fffffff, 0, 0/0, 1, 1/0, 0x100000000, -(2**53-2), Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, -Number.MAX_VALUE, 0x0ffffffff, 42, -0x100000001, 0x100000001, -(2**53+2), -0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000000, 2**53, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=38; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=39; tryItOut("\"use asm\"; function shapeyConstructor(mthtnm){return mthtnm; }/*tLoopC*/for (let w of []) { try{let hgzfgg = new shapeyConstructor(w); print('EETT'); g0.o2.a1.shift();}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-116066984*/count=40; tryItOut("/*RXUB*/var r = /[#\\S\\W]/gyim; var s = \"C\"; print(s.replace(r, ((new  /x/ (/\\2/, window))()), \"gym\")); ");
/*fuzzSeed-116066984*/count=41; tryItOut("/*infloop*/while(Math.min(-15, -15))print(x);");
/*fuzzSeed-116066984*/count=42; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.fround((Math.min(Math.max((( + Math.pow(x, ( + Math.min(x, x)))) | 0), Math.fround((Math.fround(y) & x))), (Math.min(( - Math.cbrt(Number.MAX_SAFE_INTEGER)), x) | 0)) | 0))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 1, -0x080000000, -1/0, -Number.MIN_VALUE, 0, 2**53, 0x100000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, -0x0ffffffff, -(2**53), 0x100000000, 0.000000000000001, -(2**53-2), 0x080000001, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 1/0, 42, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0, 2**53-2, 0/0, 2**53+2]); ");
/*fuzzSeed-116066984*/count=43; tryItOut("mathy0 = (function(x, y) { return Math.clz32(Math.hypot(( ~ ( ~ (Math.fround((Math.fround(-Number.MAX_SAFE_INTEGER) === Math.fround(y))) !== Number.MAX_SAFE_INTEGER))), Math.fround(( ~ ( + 1.7976931348623157e308))))); }); testMathyFunction(mathy0, [-(2**53), Number.MIN_SAFE_INTEGER, 2**53, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, 0x080000001, 1, -1/0, Number.MAX_VALUE, 2**53+2, -0, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -0x0ffffffff, 0x080000000, -(2**53-2), Number.MIN_VALUE, 1/0, 1.7976931348623157e308, 0, 2**53-2, 42, 0x100000001, -0x100000000, 0x07fffffff, -0x080000000, 0x100000000, 0.000000000000001, -0x100000001, Math.PI]); ");
/*fuzzSeed-116066984*/count=44; tryItOut("\"use strict\"; print(uneval(t1));");
/*fuzzSeed-116066984*/count=45; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.log10((Math.fround(Math.acos(Math.fround(((x ? (x >>> 0) : (x >>> 0)) >>> 0)))) >>> 0))) != Math.fround((((x >>> 0) ^ ((y * Math.fround(Math.fround(Math.sin(( + ( ! (y >>> 0))))))) | 0)) >>> 0))) >>> 0) != Math.min(Math.fround(Math.tan(y)), ((( - (Math.imul(x, x) >>> 0)) >>> 0) >> (Math.asinh(y) ? y : (Math.atanh(y) | 0))))); }); testMathyFunction(mathy0, [0x07fffffff, -0x07fffffff, 0x080000000, Number.MAX_VALUE, -0x100000000, -(2**53), -Number.MAX_VALUE, -0x080000000, 2**53+2, 1.7976931348623157e308, 0, 0x100000000, -(2**53-2), 42, 1/0, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, 1, 0.000000000000001, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -Number.MIN_VALUE, -0, -(2**53+2), Math.PI, 2**53-2]); ");
/*fuzzSeed-116066984*/count=46; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-116066984*/count=47; tryItOut("\"use strict\"; jluucy((void version(185)), 1);/*hhh*/function jluucy(x){/*tLoop*/for (let z of /*MARR*/[(-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), true, true, (-1/0), true, (-1/0), true, (-1/0), true, true, (-1/0), (-1/0), true, true, (-1/0), true, (-1/0), (-1/0), true, (-1/0), (-1/0), (-1/0), true, (-1/0), (-1/0), true, true, true, true, (-1/0)]) { print([z1,,]); }\u000c}");
/*fuzzSeed-116066984*/count=48; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x100000001, -0x07fffffff, 2**53-2, -0x080000000, 0x0ffffffff, -(2**53-2), 1/0, Number.MAX_SAFE_INTEGER, 0/0, -1/0, -Number.MAX_VALUE, Math.PI, -(2**53), -0x0ffffffff, 0, -0x080000001, 2**53, 2**53+2, 0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, 42, -0, 0x100000000, -0x100000000, -Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, -0x100000001, 0x07fffffff, 0x080000001]); ");
/*fuzzSeed-116066984*/count=49; tryItOut("\"use strict\"; m2.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+(0.0/0.0));\n    return (((1)))|0;\n  }\n  return f; });");
/*fuzzSeed-116066984*/count=50; tryItOut("\u0009do print((delete a.NaN)); while(((void options('strict'))) && 0);a\u000c = (e /= e);");
/*fuzzSeed-116066984*/count=51; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?=\\\\u003c)|(?=([\\\\u00E6\\\\w]){1,5}|^)*?+)+\", \"y\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-116066984*/count=52; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return Math.max(( ! Math.acos(Math.fround(Math.sinh((Math.fround((Math.fround(Number.MAX_VALUE) === ( + x))) >>> 0))))), ( + ( ~ ( + Math.imul(x, Math.fround(( + ( ! Math.fround(x))))))))); }); ");
/*fuzzSeed-116066984*/count=53; tryItOut("/*hhh*/function kgfcke(...w){v1 = g0.eval(\"e0 = new Set;\");}kgfcke(x %= (/*FARR*/[...[], ...[], [,]].sort(Math.sinh)));");
/*fuzzSeed-116066984*/count=54; tryItOut("\"use strict\"; {i0.next(); }");
/*fuzzSeed-116066984*/count=55; tryItOut("/*ODP-3*/Object.defineProperty(o0.f2, \"getInt16\", { configurable: window, enumerable: false, writable: false, value: window });");
/*fuzzSeed-116066984*/count=56; tryItOut("testMathyFunction(mathy1, /*MARR*/[Infinity,  /x/g , Infinity, Infinity]); ");
/*fuzzSeed-116066984*/count=57; tryItOut("v2 = Object.prototype.isPrototypeOf.call(o1, b2);");
/*fuzzSeed-116066984*/count=58; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ~ (( ~ Math.fround(Math.fround(Math.imul(( + (( + x) ** Math.fround(0x080000001))), ( ~ x))))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[ \"use strict\" , (1/0), arguments, function(){}, arguments,  \"use strict\" , arguments, (1/0), function(){}, function(){}, function(){}, arguments, (1/0), arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, x, (1/0), x, arguments, function(){},  \"use strict\" , x, x, function(){},  \"use strict\" , x, (1/0), function(){}, arguments, arguments, (1/0), arguments, (1/0), function(){}]); ");
/*fuzzSeed-116066984*/count=59; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((Math.fround((Math.fround(Math.atanh((((Math.pow(y, x) | 0) ? (( ~ (x | 0)) >>> 0) : ( + ( ~ ( + 1.7976931348623157e308)))) | 0))) != Math.fround(Math.max(( + Math.imul(( + 1/0), ( + (Math.pow(-Number.MAX_SAFE_INTEGER, (mathy1((x >>> 0), (x >>> 0)) >>> 0)) >>> 0)))), (Math.cbrt(((mathy1((y | 0), ((Math.clz32(Math.fround(-(2**53+2))) >>> 0) | 0)) | 0) | 0)) | 0))))) | 0) > ((( ! Math.hypot((( - (( - (x > y)) >>> 0)) >>> 0), mathy0(((Math.pow((-0 | 0), y) >>> 0) >>> 0), x))) | 0) | 0)) | 0); }); testMathyFunction(mathy2, [-0, -Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, 2**53, 0.000000000000001, 2**53-2, 0x080000000, -Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, 42, -(2**53+2), Number.MIN_VALUE, 1, 1/0, -(2**53-2), 0, -0x100000000, Math.PI, -0x0ffffffff, -(2**53), 0x07fffffff, -0x080000000, -0x100000001]); ");
/*fuzzSeed-116066984*/count=60; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(((( + Math.trunc(( + Math.atan2(y, 1.7976931348623157e308)))) | 0) || ( - Math.min((-Number.MIN_VALUE | 0), (x > ( + Math.imul(/*RXUB*/var r = /(\\b|\\3+{0}|(?=(?!^\\2(?:\ue16d|\\D)))\\D)/gm; var s = \"\"; print(uneval(s.match(r))); , ( + y))))))), (( ! (( - ( + x)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=61; tryItOut("Array.prototype.push.call(a2, h0, t2);");
/*fuzzSeed-116066984*/count=62; tryItOut("/*infloop*/while()for (var p in o2) { g1.e1 + ''; }");
/*fuzzSeed-116066984*/count=63; tryItOut("\"use strict\"; h0.has = f1;");
/*fuzzSeed-116066984*/count=64; tryItOut("\"use strict\"; new (function(y) { \"use strict\"; return x })() = a1[v0];\nprint(f0);\n");
/*fuzzSeed-116066984*/count=65; tryItOut("testMathyFunction(mathy0, [1/0, -0x080000001, -(2**53+2), -0x100000001, 42, -Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, Math.PI, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, 0.000000000000001, 2**53+2, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, 0x080000000, 0x080000001, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, 0, 1.7976931348623157e308, -(2**53-2), 0x07fffffff, -(2**53), 2**53, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, 1]); ");
/*fuzzSeed-116066984*/count=66; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.cbrt(Math.atan(( + Math.hypot(Math.fround((( ! (-1/0 >>> 0)) >>> 0)), Math.fround(Math.fround(mathy3(Math.fround(y), x))))))); }); testMathyFunction(mathy4, [-0x07fffffff, 0x0ffffffff, -1/0, 1, 1.7976931348623157e308, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -Number.MIN_VALUE, 0.000000000000001, -0, -0x080000000, 2**53-2, 0/0, -0x100000001, Math.PI, 2**53, 0x100000001, Number.MAX_VALUE, 0x07fffffff, 0x080000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 42, 2**53+2, -(2**53-2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, -0x100000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, 0]); ");
/*fuzzSeed-116066984*/count=67; tryItOut("\"use strict\"; if(Number.prototype.toLocaleString((x % x))) { if ((4277)) {/*\n*/v0.__proto__ = b1; }} else {M:with((4277)){b1 = x; } }");
/*fuzzSeed-116066984*/count=68; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ (Math.atan2(( + ( + ( + 0x080000000))), Math.hypot(( + ( + ( - (Math.acosh((x | 0)) | 0)))), x)) | 0)); }); testMathyFunction(mathy1, [2**53+2, -0x100000001, -0x100000000, 1, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, 42, 0/0, -0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 2**53-2, 2**53, -1/0, 0x080000001, 0x100000001, -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), 0x100000000, -Number.MAX_VALUE, Math.PI, -0x080000001, 0, -0x080000000, 0x080000000, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001]); ");
/*fuzzSeed-116066984*/count=69; tryItOut("/*oLoop*/for (var jwsozo = 0; jwsozo < 1; ++jwsozo) { continue L; } ");
/*fuzzSeed-116066984*/count=70; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=71; tryItOut("\"use strict\"; const grbwzn, x, NaN = , dlqsji, d, a = this.__defineGetter__(\"y\", Date.prototype.getMonth);Array.prototype.reverse.apply(a0, []);");
/*fuzzSeed-116066984*/count=72; tryItOut("/*vLoop*/for (let nvuswh = 0, []; nvuswh < 9; ++nvuswh) { let x = nvuswh; /* no regression tests found */ } ");
/*fuzzSeed-116066984*/count=73; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 2147483649.0;\n    var i3 = 0;\n    return +((d1));\n  }\n  return f; })(this, {ff: Math.ceil}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=74; tryItOut("b0 + i0;");
/*fuzzSeed-116066984*/count=75; tryItOut("mathy1 = (function(x, y) { return (Math.max(Math.fround(Math.fround(Math.trunc((mathy0(y, mathy0((0.000000000000001 | 0), (Math.max(Number.MIN_SAFE_INTEGER, (y | 0)) | 0))) >>> 0)))), Math.fround(( - ( ~ (((( + (x ** (Math.pow(x, (y >>> 0)) >>> 0))) >>> 0) ? (((1 >>> 0) != (x >>> 0)) >>> 0) : ( + ( ! x))) | 0))))) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[.2, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, .2, false, .2, .2, .2, objectEmulatingUndefined(), objectEmulatingUndefined(), .2, objectEmulatingUndefined(), .2, false, .2, objectEmulatingUndefined(), .2, objectEmulatingUndefined(), objectEmulatingUndefined(), .2, false, false, .2, objectEmulatingUndefined(), .2, false, objectEmulatingUndefined(), .2, false, .2, objectEmulatingUndefined(), .2, objectEmulatingUndefined(), false, false, false, objectEmulatingUndefined(), false, false, .2]); ");
/*fuzzSeed-116066984*/count=76; tryItOut("for(c in \"\\u6427\" ? (4277) : /*FARR*/[...[], false, null, c, /((?:\\D))/yim, window, ...[], ].some) e1 = Proxy.create(g0.h1, t2);");
/*fuzzSeed-116066984*/count=77; tryItOut("a0 = Array.prototype.slice.call(a0, NaN, NaN);function e(x, w) { g2 + b1; } yield d;");
/*fuzzSeed-116066984*/count=78; tryItOut("/*tLoop*/for (let b of /*MARR*/[(0x50505050 >> 1),  /x/g ]) { /* no regression tests found */ }");
/*fuzzSeed-116066984*/count=79; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.ceil(Math.atan2(Math.fround((Math.clz32(x) | 0)), Math.ceil((Math.fround(( ! Math.fround((Math.pow(y, (y | 0)) ? x : Math.PI)))) | 0))))); }); testMathyFunction(mathy5, [2**53-2, -(2**53-2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0x080000000, Number.MIN_VALUE, Math.PI, 0x100000000, 0x080000001, 1, 0.000000000000001, 0/0, -1/0, -0x080000001, -0x100000000, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 2**53+2, 0x100000001, -0, 42, 1/0, Number.MAX_VALUE, 0, -0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-116066984*/count=80; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( ~ ( + ( ! ( + ( - (x && (Math.atanh(x) | 0))))))) & Math.fround((Math.fround((((0x080000001 | (Math.sqrt(Math.fround(( ~ Math.fround(y)))) | 0)) | 0) <= ( + ( + Math.tanh((y | 0)))))) === Math.sinh(1)))); }); testMathyFunction(mathy1, [0/0, 1, 0.000000000000001, -0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, Number.MIN_VALUE, -(2**53-2), 0x080000000, -1/0, -0x080000001, 0, -(2**53), -0x07fffffff, 42, 0x100000000, -0x080000000, -0, Math.PI, 2**53-2, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -Number.MAX_VALUE, -(2**53+2), -0x100000000]); ");
/*fuzzSeed-116066984*/count=81; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround(( + mathy2(( + Math.fround(( ! Math.fround(0/0)))), ( + Math.imul(Math.cosh(((Math.hypot((y | 0), (y | 0)) | 0) >>> 0)), ( - Math.pow(y, y))))))))); }); ");
/*fuzzSeed-116066984*/count=82; tryItOut("/*RXUB*/var r = /*UUV1*/(window.parse = function(q) { return q; }); var s = \"a\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=83; tryItOut("vbpfqx(Math.atan2(7, -12), window);/*hhh*/function vbpfqx(){v2 = Object.prototype.isPrototypeOf.call(h1, v1);}");
/*fuzzSeed-116066984*/count=84; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, -1/0, 1.7976931348623157e308, -0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, 0x0ffffffff, -0x080000001, 0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, -(2**53+2), Math.PI, -0x07fffffff, 1/0, -(2**53), Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, 0x100000001, -0, 0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -(2**53-2), -0x100000001, 0/0]); ");
/*fuzzSeed-116066984*/count=85; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((((((Math.fround(y) * ((Math.imul((( + mathy4(x, Math.fround(-0x100000000))) | 0), (Math.expm1(x) | 0)) | 0) == y)) | 0) >>> 0) || Math.fround(mathy2(Math.fround(Math.cos(( + ( + ( + y))))), Math.fround(( ! ((Math.asinh(( ~ (x === 0x080000000))) | 0) | 0)))))) | 0) >> (((x / Math.fround(( + Math.abs(( + x))))) ? Math.hypot((( + Math.hypot(((( ~ (-0x080000000 | 0)) | 0) | 0), y)) ** mathy2((x & x), y)), (Math.expm1((Math.pow(([[]] | 0), (( - ( + x)) | 0)) >>> 0)) >>> 0)) : (mathy1(((Math.min((y >>> 0), 0x080000001) | 0) >>> 0), (x >>> 0)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=86; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (((( ~ x) ** Math.trunc((x >>> 0))) ** (Math.asinh(Math.fround(Math.atan2((y >= (Math.imul((Math.hypot(-Number.MAX_SAFE_INTEGER, Math.acosh(-(2**53))) | 0), Math.clz32(((( ~ 1.7976931348623157e308) >>> 0) | 0))) >>> 0)), ( + ((x >>> 0) % ( + Math.fround(( - Math.fround(Math.hypot(Math.fround(y), Math.fround(y))))))))))) | 0)) | 0); }); testMathyFunction(mathy3, /*MARR*/[ \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" , objectEmulatingUndefined()]); ");
/*fuzzSeed-116066984*/count=87; tryItOut("\"use strict\"; g1 = this;");
/*fuzzSeed-116066984*/count=88; tryItOut("throw x;a1 = (function() { yield  /x/g ; } })();");
/*fuzzSeed-116066984*/count=89; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + ( ~ Math.sign(Math.fround((Math.fround(-0x080000000) == Math.fround(mathy1(Math.imul((Math.hypot(x, x) >>> 0), 2**53+2), (y ? 1.7976931348623157e308 : (Math.tanh((y >>> 0)) >>> 0))))))))) == ( + Math.cos(( + Math.tan((y | 0))))))); }); testMathyFunction(mathy2, [0/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 0x100000001, 42, 1/0, 0x07fffffff, 1, 0x100000000, -(2**53), 2**53+2, -0, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 0.000000000000001, 0, -Number.MIN_VALUE, -0x080000000, -(2**53-2), -(2**53+2), -1/0, 0x0ffffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, 0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -0x07fffffff, -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=90; tryItOut("\"use strict\"; a2 = a1.filter(o0.f0, g1.s2);");
/*fuzzSeed-116066984*/count=91; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.pow((Math.fround((Math.fround(Math.max((42 >>> 0), Math.imul((( ~ x) | 0), (Math.sqrt(x) >>> 0)))) && Math.fround(Math.log((( + (( ~ (x >>> 0)) >>> 0)) | 0))))) | 0), ((( + (( + (Math.hypot(Math.pow(y, Math.asin(y)), y) >>> 0)) - ( + y))) != Math.fround((Math.fround(y) > Math.fround(Math.log2(( + y)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [2**53+2, 2**53, 0/0, 0, 0x07fffffff, -0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -1/0, 0x0ffffffff, 42, -0x0ffffffff, -0x100000001, -(2**53-2), -Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), Number.MAX_VALUE, -0x100000000, -0, 0x100000001, 2**53-2, 0x100000000, 0x080000001, Math.PI, 1/0, 1.7976931348623157e308, 0.000000000000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=92; tryItOut("\"use strict\"; this.f1.__proto__ = i0;");
/*fuzzSeed-116066984*/count=93; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.fround((( + Math.max(( + x), x)) ** Math.tan(( - ( + y)))))) >>> Math.fround(Math.log2(Math.max(( + (((((Math.max((x | 0), (x | 0)) | 0) | 0) + (( ! x) | 0)) | 0) ^ y)), ( + Math.cos(((y ? (y >>> 0) : Math.fround(y)) >>> 0)))))))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), (new String('')), (new Number(0)), 0.1, 1, (new Boolean(false)), [0], null, true, '', ({valueOf:function(){return '0';}}), '\\0', false, undefined, '0', (new Number(-0)), ({valueOf:function(){return 0;}}), /0/, '/0/', -0, [], 0, (new Boolean(true)), (function(){return 0;}), ({toString:function(){return '0';}}), NaN]); ");
/*fuzzSeed-116066984*/count=94; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.ceil(Math.imul(((( ! ( ~ ( + Math.log2(y)))) | 0) <= (Math.fround((y << Math.fround(Math.asinh(( + Math.clz32(y)))))) | 0)), (Math.atan((((y | 0) === x) | 0)) ? Math.imul((( ~ ( + Math.imul(Math.fround(x), Math.fround(-0x080000001)))) >>> 0), (0.000000000000001 >>> 0)) : Math.fround(Math.acos(Math.fround(Math.max(Math.fround((x >>> (Math.fround(Math.pow(Math.fround(y), Math.fround(x))) | 0))), (( - x) >= y)))))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, -0x100000000, 2**53, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, Number.MAX_VALUE, -0x100000001, 2**53-2, 0x07fffffff, -0x080000000, 1, 42, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2, Math.PI, -0, -1/0, -0x07fffffff, 0x080000001, -(2**53+2), -Number.MIN_VALUE, 0/0, 0, 1.7976931348623157e308, 1/0, -0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-116066984*/count=95; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      i2 = (i2);\n    }\n    (Uint16ArrayView[((0xffffffff)-(i2)) >> 1]) = ((((((0xffffffff)-(i2)) ^ ((0xbb7b30c8) % (0xc6e715c1))) % (((0xfae12022)) | (((d0))))) | (((~((i2)-((0x6e6dd11e)))) != (imul((-0x8000000), (0xd08119c9))|0))-(i2))) % (((-0x8000000)+((imul(((Int32ArrayView[0])), (i2))|0))+(0xedb42c97)) ^ ((((0xcefd5e8f)-(i2)) ^ (((((0xf9a41ac5)) << ((-0x8000000)))))) / (((i2)*-0xf930e)|0))));\n    return +(((i2) ? (d0) : (d0)));\n  }\n  return f; })(this, {ff: Float64Array}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x100000001, 0/0, -0x080000000, 1.7976931348623157e308, 42, -(2**53), -0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 0x080000000, 0.000000000000001, 1, -Number.MIN_VALUE, 1/0, 0, -(2**53+2), -0x07fffffff, -1/0, Math.PI, 2**53, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, -0, 0x080000001, -0x0ffffffff, -Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-116066984*/count=96; tryItOut("mathy0 = (function(x, y) { return ( + ( + ( + Math.atan2(( - (((y >>> 0) - ((Math.atanh(0x080000000) >>> 0) >>> 0)) >>> 0)), Math.fround(Math.atan2(Math.fround(( + (( + x) - ( + x)))), Math.fround(Number.MIN_SAFE_INTEGER))))))); }); testMathyFunction(mathy0, /*MARR*/[null, null, null, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), null, null, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), null, new Boolean(true), null, null, null, new Boolean(true), null, null, null, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), null, new Boolean(true), new Boolean(true), null, null, new Boolean(true), new Boolean(true), null, null, new Boolean(true), null, new Boolean(true), new Boolean(true), new Boolean(true), null, null, null, null, null, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), null, null, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), null, new Boolean(true), new Boolean(true), new Boolean(true), null, new Boolean(true), null, null, null, new Boolean(true), new Boolean(true), null, new Boolean(true), null, null, new Boolean(true), null, new Boolean(true), null, null, new Boolean(true), new Boolean(true), new Boolean(true), null, new Boolean(true), new Boolean(true), null, new Boolean(true), new Boolean(true), null, null, null, null, null, null, new Boolean(true), null, new Boolean(true), null, new Boolean(true), new Boolean(true), null, null, null, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), null, new Boolean(true), null, new Boolean(true), null, new Boolean(true), new Boolean(true), null, null]); ");
/*fuzzSeed-116066984*/count=97; tryItOut("g1.r2 = new RegExp(\"(?!(?:([^]\\\\B|(?=\\u7877)*)))\", \"g\");");
/*fuzzSeed-116066984*/count=98; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=99; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.cosh((Math.imul(( ~ (Math.expm1((Math.trunc(Math.fround((( - x) | 0))) >>> 0)) >>> 0)), mathy2(y, Math.min(2**53+2, ((-0x100000001 | 0) + x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[new Number(1), (void 0), null, 1e81, (void 0), null, new Number(1), null, (void 0)]); ");
/*fuzzSeed-116066984*/count=100; tryItOut("{g2.s2 += 'x';print(x <<= x);function y() /* Comment */(d = Proxy.createFunction(({/*TOODEEP*/})(true), encodeURIComponent))let (x, x, wedqwz, y, jhmgwg, w, zqcabl, x, rkbrng) { v1 = Object.prototype.isPrototypeOf.call(g2, v2);\nnew Function\n } }");
/*fuzzSeed-116066984*/count=101; tryItOut("this.g2.offThreadCompileScript(\"a1[18] = i2;\");");
/*fuzzSeed-116066984*/count=102; tryItOut("testMathyFunction(mathy1, /*MARR*/[ 'A' , [1],  'A' , [1],  'A' , [1], [1],  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ]); ");
/*fuzzSeed-116066984*/count=103; tryItOut("rswgrw();/*hhh*/function rswgrw(x =  /x/g , x){print(function ([y]) { });}");
/*fuzzSeed-116066984*/count=104; tryItOut("\"use strict\"; o0.v0 = g2.eval(\"\\\"use strict\\\"; mathy0 = (function(x, y) { \\\"use strict\\\"; return ( + Math.hypot(( + Math.atan2((Math.sin(Math.sqrt(( + x))) | 0), Math.fround((Math.fround(Math.ceil(Math.fround(Math.cos(Math.fround(y))))) | Math.fround(Math.sin(Math.atan2(-0x100000000, Math.fround(Math.sign((1/0 >>> 0)))))))))), ( + Math.fround(Math.cos(( ~ Math.min(y, -0x100000001))))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, 0x080000000, -(2**53), 2**53+2, 0/0, Number.MIN_VALUE, 0x100000001, 42, -0x100000000, 0, -Number.MIN_SAFE_INTEGER, -1/0, -0, -(2**53-2), 1/0, Number.MAX_VALUE, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, -0x100000001, -0x080000001, 0x100000000, 0x080000001, 0x0ffffffff, -0x080000000, 1, -(2**53+2), -Number.MIN_VALUE, -0x0ffffffff]); \");");
/*fuzzSeed-116066984*/count=105; tryItOut("\"use strict\"; yield;\nbreak M;\nlet w = (p={}, (p.z = (delete false))());");
/*fuzzSeed-116066984*/count=106; tryItOut("{ void 0; void relazifyFunctions(this); } print(x);\ng0.offThreadCompileScript(\"function f1(f0)  { \\\"use strict\\\"; return window } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: true }));\n");
/*fuzzSeed-116066984*/count=107; tryItOut("/*infloop*/ for (let eval of x) {new RegExp(\"\\\\1\", \"gim\") ?  \"\"  : false;/*infloop*/for(x = (b, y) => \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((16777217.0));\n  }\n  return f; >>> Math.pow([,,z1], 4); \u000c(void shapeOf((4277))); x) {h1.toString = (function() { try { s2.toString = (function(j) { if (j) { try { s2 = ''; } catch(e0) { } try { a1.sort(Boolean.prototype.valueOf.bind(a0), b1); } catch(e1) { } try { a1.reverse(i1); } catch(e2) { } v1.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   var asin = stdlib.Math.asin;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      d0 = (+(-1.0/0.0));\n    }\n    return (((0xfd98f709)))|0;\n    i2 = ((((0xfb630747)-((i2) ? ((0xffffffff) >= (0xe83374d0)) : (/*FFI*/ff(((d0)))|0))) & (((((0x2cc3cdd6) ? (-0x6eb6de3) : (0xffffffff))+(0x2a894ea5))|0) / (~((-0x8000000)-(((0x3b403165) == (0x1df7e0ad)))-(/*FFI*/ff(((7.555786372591432e+22)), ((-1099511627777.0)), ((-18014398509481984.0)), ((65.0)))|0))))) <= ((((-(0xffffffff))>>>((0x94084d81))) / ((-0xfffff*(0xf631c85c))>>>((i2)-((0x1e8fa12) == (0x79fb5ae4))))) | ((0xc8787de5)-(!((((0x3176c2ee))>>>((0x2bdf6157)-(0x97d34da4))))))));\n    i2 = (0x24b6159c);\n    d0 = (-65.0);\n    {\n      (x) = ((-0x8000000));\n    }\n    (Float64ArrayView[0]) = ((0.0625));\n    return (((0xfccc568a)+(0xfa1bfd7c)))|0;\n    {\n      {\n        d1 = (d1);\n      }\n    }\n    d0 = (d1);\n    return (((((+asin(((+/*FFI*/ff(((-(((0xffffffff) ? (1.888946593147858e+22) : (-18014398509481984.0)))))))))) >= ([] = \nnull)) ? ((-0x8000000) == (imul((i2), (i2))|0)) : (-0x8000000))))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use strict\"; var nozkyv = \"\\u2694\"; (Promise.prototype.catch)(); })}, new SharedArrayBuffer(4096)); } else { try { /*RXUB*/var r = r0; var s = s2; print(r.test(s));  } catch(e0) { } try { Object.prototype.unwatch.call(this.f1, \"fixed\"); } catch(e1) { } Object.preventExtensions(this.t0); } }); } catch(e0) { } try { for (var p in a1) { try { a0[18] = f0; } catch(e0) { } a1 + ''; } } catch(e1) { } try { v1 = (b2 instanceof o1.m1); } catch(e2) { } /*MXX2*/g2.EvalError.prototype.toString = g0.p2; return h1; }); } }");
/*fuzzSeed-116066984*/count=108; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=^|\\3{4,65540})*|\u54fc\\S*?|(?:(?:\\u00b8))\\b|'+?[^]?|\\b|$?|\\3{1,4}*{2,5}/yim; var s = \"\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\n\\n\\n\\n\\n\\n__\\u7857\\u7857\\u7857__\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\n\\n\\n\\n\\n\\n__\\u7857\\u7857\\u7857__\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\n\\n\\n\\n\\n\\n__\\u7857\\u7857\\u7857__\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3__\\u7857\\u7857\\u7857____\\u7857\\u7857\\u7857____\\u7857\\u7857\\u7857____\\u7857\\u7857\\u7857__\\u364e\\u364e\\u364e\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\n\\n\\n\\n\\n\\n__\\u7857\\u7857\\u7857__\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\n\\n\\n\\n\\n\\n__\\u7857\\u7857\\u7857__\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3\\n\\n\\n\\n\\n\\n__\\u7857\\u7857\\u7857__\\u51a2\\u00e3\\u51a2\\u00e3\\u51a2\\u00e3__\\u7857\\u7857\\u7857____\\u7857\\u7857\\u7857____\\u7857\\u7857\\u7857____\\u7857\\u7857\\u7857__\\u364e\\u364e\\u364e\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116066984*/count=109; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.ceil((((( + Math.atan2(((mathy1(( + Math.fround((Math.atan(y) | 0))), ( + Math.max(( + 0x07fffffff), ( + x)))) | 0) === Math.atan2(y, Math.abs(( + x)))), Math.fround(( ~ Math.fround(( + Math.fround(Math.fround(( ! Math.fround(x)))))))))) | 0) ? Math.fround(( - -0x0ffffffff)) : ( + (((( - Math.fround((( + (0x07fffffff | 0)) | 0))) | 0) < ( ~ x)) >>> 0))) | 0)); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 2**53+2, 42, -(2**53+2), 0x100000001, -1/0, -0x080000001, 0x100000000, -(2**53), Number.MAX_VALUE, 2**53-2, 1/0, 0x080000001, 1, 0x0ffffffff, 0.000000000000001, 0x07fffffff, -0x100000000, Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0, 0/0, 2**53, 0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -0, Math.PI]); ");
/*fuzzSeed-116066984*/count=110; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ (( + (( + ( - ( + ( - x)))) | 0)) | 0)); }); testMathyFunction(mathy2, /*MARR*/[null, null, null, true, true, true, null, null, null, true, true, null, true, true, null, null, true, true, null, null, true, true, true, true, true, null, true, true, true, true, true, null, null, true, true, true, null, null, null, null, null, null, null, null, null, true, null, true, null, true, null, null, true, null, null, true, null, null, null, null, true, null, null, null, true, true, null, null, true, null, true, null, true, null, null, true, null, null, true, true, true, true, true, null, true, null, null, null, true, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, true, null, true, true, null, null, null, null, null, true, true, true, true, true, null, true, null, true, null, true, null, true, true, null, true, true, true, null, true, null, null, null, null, null, null, true, true, true, true, null, null, true, null]); ");
/*fuzzSeed-116066984*/count=111; tryItOut("Array.prototype.shift.apply(a1, []);\nprint(null);\n");
/*fuzzSeed-116066984*/count=112; tryItOut("\"use asm\"; /* no regression tests found */x;");
/*fuzzSeed-116066984*/count=113; tryItOut("i0.valueOf = (function() { try { o0 + ''; } catch(e0) { } try { h0 + p0; } catch(e1) { } try { s2 = ''; } catch(e2) { } g1 = this; return i1; });");
/*fuzzSeed-116066984*/count=114; tryItOut("mathy1 = (function(x, y) { return mathy0((Math.acos(Math.fround(( ! y))) >>> 0), Math.fround((( - Math.fround(Math.fround(Math.pow(Math.pow(x, y), mathy0(Math.fround(0x100000000), (Math.hypot((y | 0), (x | 0)) | 0)))))) << ( + ( + ( + Math.imul((0x07fffffff >>> 0), (( ~ -0x100000000) >>> 0)))))))); }); testMathyFunction(mathy1, [-0x080000000, -0x07fffffff, -1/0, 42, 0x0ffffffff, -0x100000000, -0x080000001, 0, 1, -0x0ffffffff, -Number.MIN_VALUE, 0x080000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0/0, 2**53, 2**53+2, 0x07fffffff, -(2**53), 0x080000000, -0, 0x100000001, 2**53-2, -Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, Math.PI, 0x100000000, 1/0, -(2**53-2), -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=115; tryItOut("let (y) { { /x/ ; }function d(x) { \u000cyield (4277) } b2 = new SharedArrayBuffer(4); }");
/*fuzzSeed-116066984*/count=116; tryItOut("e1 = new Set;");
/*fuzzSeed-116066984*/count=117; tryItOut("Array.prototype.splice.apply(a0, [p2]);");
/*fuzzSeed-116066984*/count=118; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.max((Math.pow((y | 0), ( + ((y , y) + ( ! Math.fround(y))))) >>> 0), ( ~ -0)) < (Math.max(Math.fround((Math.fround(Math.max(Math.pow(Math.fround(y), x), (Math.acosh(((y <= (( - (x >>> 0)) >>> 0)) | 0)) | 0))) == (y - (Math.min((( + x) >>> 0), (x | 0)) >>> 0)))), (Math.fround(Math.fround(Math.atanh(Math.fround(( + ( - -0x0ffffffff)))))) | 0)) >>> 0)); }); testMathyFunction(mathy0, [-0x080000001, 0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 0x100000001, -0x07fffffff, -0x080000000, -0x100000000, -0x100000001, 2**53-2, Math.PI, 0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), 1/0, Number.MIN_VALUE, -(2**53-2), -(2**53), Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -0, 2**53, 0/0, 1.7976931348623157e308, 0x0ffffffff, 2**53+2, 1, 42, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=119; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116066984*/count=120; tryItOut("\"use strict\"; {t2.set(t2, ({valueOf: function() { for (var p in p1) { try { v1 = g0.runOffThreadScript(); } catch(e0) { } try { this.v1 = g1.runOffThreadScript(); } catch(e1) { } i1.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (NaN);\n    i0 = (0xf7d6da26);\n    return ((((imul(((i0) ? ((0x2949594e) ? (0xffffffff) : (0xff0c242e)) : (1)), (-0x8000000))|0) != (((0x4d302254))|0))+(0xf98c2a98)))|0;\n    d1 = (d1);\n    {\n      {\n        {\n          {\n            {\n              (Int16ArrayView[((Uint8ArrayView[((0x609517fc)-(0xb42bb42b)) >> 0])) >> 1]) = ((i0));\n            }\n          }\n        }\n      }\n    }\n    return (((i0)))|0;\n    d1 = ((0x8319f952) ? (((+(imul(((imul((-0x8000000), (i0))|0)), (i0))|0)))) : (d1));\n    i0 = (0xfa8ab8e0);\n    i0 = ((~~(-6.189700196426902e+26)) > (imul(((imul(((4277)), (i0))|0) != (imul((i0), (i0))|0)), (1))|0));\n    {\n      {\n        {\n          d1 = (d1);\n        }\n      }\n    }\n    return ((((d1))+((-2199023255551.0) > (d1))))|0;\n  }\n  return f; }); }return 3; }})); }");
/*fuzzSeed-116066984*/count=121; tryItOut("s0 = '';");
/*fuzzSeed-116066984*/count=122; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-116066984*/count=123; tryItOut("mathy0 = (function(x, y) { return (( + ( + Math.pow(( + Math.imul(( + ( + (( + Math.fround(( ! (x >>> 0)))) > y))), x)), ( + Math.max(Number.MIN_SAFE_INTEGER, (( ~ ((y + Math.hypot(y, Math.fround(x))) | 0)) | 0)))))) == Math.fround(Math.imul((Math.acosh(( ! (-0x080000000 - y))) >>> 0), Math.fround(Math.imul(x, y))))); }); testMathyFunction(mathy0, [-0x100000001, 0x07fffffff, 0/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, -0x080000001, 0x0ffffffff, Number.MAX_VALUE, 0, 2**53-2, -1/0, -Number.MIN_VALUE, 0x080000000, 2**53, -(2**53-2), 2**53+2, -0x080000000, -0x0ffffffff, -(2**53+2), 1.7976931348623157e308, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, -(2**53), 1, -Number.MIN_SAFE_INTEGER, -0x100000000, -0, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x100000001, 0.000000000000001]); ");
/*fuzzSeed-116066984*/count=124; tryItOut("var clqozw = new SharedArrayBuffer(0); var clqozw_0 = new Int8Array(clqozw); print(clqozw_0[0]); var clqozw_1 = new Int32Array(clqozw); print(clqozw_1[0]); clqozw_1[0] = -15; this.v0 = Object.prototype.isPrototypeOf.call(f0, g1.b2);var sbrgxq = new SharedArrayBuffer(2); var sbrgxq_0 = new Uint16Array(sbrgxq); sbrgxq_0[0] = -15; print(clqozw_0[0]);");
/*fuzzSeed-116066984*/count=125; tryItOut("Array.prototype.push.apply(a0, [o0.s1, h2]);");
/*fuzzSeed-116066984*/count=126; tryItOut("\"use strict\"; \"use asm\"; break L;x;");
/*fuzzSeed-116066984*/count=127; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"function f1(f2) (void options('strict'))\");");
/*fuzzSeed-116066984*/count=128; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.fround((((( ~ ( + (0x100000000 >>> 0))) | 0) >> (( ~ x) | 0)) | 0)) ? Math.cosh((Math.pow(Math.fround(Math.max((y !== 0x07fffffff), x)), (x | 0)) >>> 0)) : ((((y + y) * (Math.fround((x & (Math.pow(Math.fround(y), Math.fround(y)) | 0))) >>> 0)) >>> 0) >>> ( + ( ~ 42)))); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 2**53+2, 1, -Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 0x080000000, 0x07fffffff, -0, 0x100000001, -0x100000000, 0/0, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, -(2**53-2), 0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, -(2**53), 0, 42, -0x0ffffffff, Number.MAX_VALUE, -1/0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, 0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=129; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - (mathy0(Math.fround(mathy0(Math.fround(Math.fround(mathy0((Math.fround(Number.MAX_SAFE_INTEGER) ? ((( + x) & 0x080000001) | 0) : (mathy0(x, (x | 0)) | 0)), (( + y) === ( + x))))), (( ! x) >>> 0))), (x | y)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [objectEmulatingUndefined(), null, [0], -0, '\\0', ({valueOf:function(){return '0';}}), '', true, ({valueOf:function(){return 0;}}), '/0/', 0.1, (new String('')), (new Boolean(false)), (new Boolean(true)), NaN, ({toString:function(){return '0';}}), false, (function(){return 0;}), 1, /0/, (new Number(0)), 0, (new Number(-0)), [], '0', undefined]); ");
/*fuzzSeed-116066984*/count=130; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.sqrt(((mathy2(mathy0(y, ( ~ (((y >>> ( + x)) | 0) | 0))), y) === Math.hypot(x, x)) * (Math.hypot(( + mathy2((Math.sqrt((y >>> 0)) >>> 0), (Math.clz32(Math.fround(0.000000000000001)) >>> 0))), -(2**53+2)) == y))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -1/0, 2**53, 1.7976931348623157e308, 1/0, Math.PI, Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, 0x07fffffff, 0x080000000, 0, -0x07fffffff, Number.MIN_VALUE, -(2**53-2), -0x080000001, 2**53+2, -0, 2**53-2, -0x0ffffffff, 42, 0x100000001, 0x080000001, 0/0, -(2**53), -Number.MIN_VALUE, -0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, 0x100000000]); ");
/*fuzzSeed-116066984*/count=131; tryItOut("m0.has(this.o2.a1);");
/*fuzzSeed-116066984*/count=132; tryItOut("mathy0 = (function(x, y) { return Math.log(((Math.fround(Math.cbrt(y)) >> (Math.tan((Math.clz32(x) >>> 0)) >>> 0)) && (Math.sqrt(((( ~ ( + Math.min(( + y), ( + ( ~ 0.000000000000001))))) >>> 0) >>> 0)) / (Math.pow((Math.fround(Math.hypot(((( - (y | 0)) | 0) * y), Math.fround(-Number.MAX_VALUE))) >>> 0), (Math.fround(Math.sqrt(y)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [NaN, /0/, false, true, undefined, '/0/', [0], objectEmulatingUndefined(), null, -0, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Number(0)), 1, (new String('')), (new Boolean(false)), '\\0', 0, '0', ({toString:function(){return '0';}}), 0.1, '', (new Number(-0)), (function(){return 0;}), [], (new Boolean(true))]); ");
/*fuzzSeed-116066984*/count=133; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\nprint(x);    d0 = (+(1.0/0.0));\n;    {\n      d0 = (+(-1.0/0.0));\n    }\n    d0 = (d0);\n;    d0 = (+(0.0/0.0));\n    d0 = (+atan2(((+(-1.0/0.0))), ((+(1.0/0.0)))));\n    return +((17592186044415.0));\n  }\n  return f; })(this, {ff: arguments.callee}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, ['', '/0/', ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), 0, undefined, (new Number(-0)), NaN, (new Boolean(true)), (new String('')), false, [], 0.1, ({valueOf:function(){return '0';}}), (new Number(0)), [0], /0/, null, -0, (new Boolean(false)), true, '0', 1, '\\0', objectEmulatingUndefined(), (function(){return 0;})]); ");
/*fuzzSeed-116066984*/count=134; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.pow(Math.fround(( - ((Math.tan(( + Math.acosh(( + ( - (y | 0)))))) < -Number.MIN_VALUE) >>> 0))), ( - (mathy0((Math.imul((mathy3(( + (-Number.MAX_VALUE ? -0x100000001 : Math.fround(y))), (x >= x)) >>> 0), ( ! y)) | 0), (Math.abs(( + with({}) return;)) >>> 0)) | 0))); }); testMathyFunction(mathy4, [0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, -0x100000000, Number.MIN_VALUE, 0.000000000000001, 0/0, -(2**53), -(2**53+2), 2**53+2, 1, 0x080000001, -1/0, 0x100000000, 42, -0x080000001, 0x080000000, -0x080000000, -Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1/0, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 0, 2**53-2]); ");
/*fuzzSeed-116066984*/count=135; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.pow((Math.cos(( + mathy0(Math.pow(( ~ mathy0(2**53, ( + Math.exp(y)))), Math.fround(y)), ((Number.MIN_VALUE > Math.pow(y, y)) > ( ! (x | 0)))))) | 0), (( + (( + (Math.log(( + x)) | 0)) ? ( + ( - Math.fround(mathy0(mathy0(-0, Math.sin(x)), ( + ( ! x)))))) : ( + (mathy1((x | 0), (((( - (y | 0)) | 0) && ((((( + x) ? ( ~ x) : (Math.fround(y) ? y : ( + x))) >>> 0) + Number.MAX_VALUE) >>> 0)) | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, Math.PI, 1/0, -Number.MAX_VALUE, 0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, -0x07fffffff, -(2**53+2), 2**53, 0.000000000000001, 2**53+2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -0x080000000, Number.MIN_VALUE, 2**53-2, -0, 0/0, 42, -(2**53), -(2**53-2), -1/0, 0x080000001, 0x100000001, 0x080000000, -0x100000001, -0x0ffffffff, 1]); ");
/*fuzzSeed-116066984*/count=136; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((( + Math.imul(( ! (mathy4(( + -0), ( + (( - (Math.hypot(0x080000001, x) > y)) | 0))) | 0)), ( + Math.max((( + (Math.atan2(x, -0x080000000) >>> 0)) * ( + y)), (( + Math.min(( ! (y | 0)), ( + ( + Math.atan2(( + y), x))))) >>> 0))))) | 0) ** ( + (((Math.pow(Math.fround(( ! Math.fround(Math.max(Math.fround(Math.atan(y)), Math.fround((-(2**53+2) < -Number.MAX_SAFE_INTEGER)))))), (Math.ceil((((-Number.MIN_VALUE >>> 0) != (Math.fround(mathy1((Math.fround(mathy4(Math.fround(-Number.MIN_VALUE), x)) | 0), Math.fround((Math.fround(Number.MIN_SAFE_INTEGER) >> y)))) >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0) << (Math.fround(( ! Math.fround((Math.max((mathy2(x, Number.MIN_VALUE) >>> 0), (( + -1/0) === Math.fround(y))) >>> 0)))) | 0)))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -(2**53+2), 0/0, 0x100000001, -0x080000000, 1/0, -1/0, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 0, 2**53, 2**53-2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, 0x080000001, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -0, 0x100000000, -Number.MIN_SAFE_INTEGER, 1, 42, 0x07fffffff, -0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000]); ");
/*fuzzSeed-116066984*/count=137; tryItOut("a2.push(o2.p0, m2, (Math.min(6, x)), e1, b2, e2, g1.v1);");
/*fuzzSeed-116066984*/count=138; tryItOut("/*RXUB*/var r = /(\\3|\u00c3{1,4})/g; var s = \"\\u00c3\"; print(s.search(r)); ");
/*fuzzSeed-116066984*/count=139; tryItOut("\"use strict\"; Array.prototype.unshift.apply(a0, [e0, this.t1, g0, f0]);");
/*fuzzSeed-116066984*/count=140; tryItOut("\"use strict\"; /*oLoop*/for (gfwqag = 0; gfwqag < 15; ++gfwqag) { var v1 = Array.prototype.some.call(a1, f0, this.h0, e0, g0.f1, g0, true); } ");
/*fuzzSeed-116066984*/count=141; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"g2.s1 += 'x';\");");
/*fuzzSeed-116066984*/count=142; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=\\\\1{1})\", \"y\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=143; tryItOut("s2 + i1;");
/*fuzzSeed-116066984*/count=144; tryItOut("v1 = new Number(s1);");
/*fuzzSeed-116066984*/count=145; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( - (mathy0(((mathy0(( ! (((Math.fround(( ! Math.fround(y))) | 0) > Math.round(( + x))) | 0)), mathy0((Math.pow((Number.MAX_VALUE | 0), (x >>> 0)) | 0), ( ! Math.fround(0.000000000000001)))) >>> 0) >>> 0), ((-Number.MIN_SAFE_INTEGER <= (y < Math.sin(Math.tanh(y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, 42, 0, 0x080000000, 0/0, 2**53+2, -0x0ffffffff, -0, 0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, -Number.MAX_VALUE, -0x100000001, -0x080000001, 0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, 1, -(2**53+2), 1/0, 2**53, Math.PI, -1/0]); ");
/*fuzzSeed-116066984*/count=146; tryItOut("\"use strict\"; for(c = ((function fibonacci(kmudoe) { ; if (kmudoe <= 1) { ; return 1; } ; return fibonacci(kmudoe - 1) + fibonacci(kmudoe - 2);  })(5)) in delete c.x) {/*RXUB*/var r = o1.r2; var s = g1.o0.s1; print(uneval(s.match(r))); print(r.lastIndex);  }");
/*fuzzSeed-116066984*/count=147; tryItOut("\"use strict\"; t0[10];\nthis.v2 = evalcx(\"function this.f0(f0) \\\"use asm\\\"; v0 = t0.length;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    var d3 = -1.0625;\\n    i2 = (((-(0x66b2e0d9))>>>(-(i2))) > (0x8fdf284a));\\n    (Float64ArrayView[((1)) >> 3]) = ((1.0));\\n    (Uint32ArrayView[2]) = ((0x31451453));\\n    d1 = (((((i2)+((((0x2ab8a144))>>>((0xffffffff)))))>>>((x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: \\\"\\\\uDF05\\\", getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { throw 3; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: undefined, enumerate: window, keys: function() { return Object.keys(x); }, }; })(\\\"\\\\uDDEC\\\".yoyo(undefined)), new Function, (delete window.x))))) == (((0x8ed13591)+(!(0xe07b3337))+(i2))>>>((0x734969df)))) ? (d3) : ((0xffffffff)));\\n    i0 = (((0xaf34fbe8)) ? (((((0x739dc597) ? (0x11593678) : (0xfcf66035))-(-0x8000000)) >> ((i0)-((33554431.0))))) : (((i0)+(1))));\\n    i2 = (((((((!((0x1659803d) > (0x16241640)))+(i0))>>>((~~(65536.0)) / (((0xfd69208b)) | ((0xfedde47d))))) != (0xf14889bd))) ^ (((-0x3c5bb*(!((0x48d66678)))) >> ((!(1))*0x521f7)) % (((0xffffffff) / (((-0x8000000))>>>((0xfaec33b3)))) | ((i0))))));\\n    return (((i0)-(i0)))|0;\\n  }\\n  return f;\", g0);\n");
/*fuzzSeed-116066984*/count=148; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=149; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1, 0/0, -0x100000001, -0x080000001, -0x100000000, -Number.MIN_VALUE, -(2**53-2), 0x07fffffff, 0x080000000, 0x0ffffffff, 0x100000000, 1.7976931348623157e308, 2**53+2, Number.MIN_SAFE_INTEGER, -0, 42, Number.MIN_VALUE, 2**53, 2**53-2, 0x100000001, 0.000000000000001, -Number.MAX_VALUE, -1/0, -0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, 0, -(2**53), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, Number.MAX_VALUE, -0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-116066984*/count=150; tryItOut("a2 = Array.prototype.concat.apply(a0, [t1, a1, o1.b1, d + \u3056, this.p1]);\nArray.prototype.splice.apply(this.a2, [NaN, 17]);\n");
/*fuzzSeed-116066984*/count=151; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(mathy4(( ~ Math.fround((( ~ (( + ( ~ ( + (((x | 0) ** x) | 0)))) >>> 0)) | 0))), Math.tanh(Math.fround(Math.min(Math.fround(Math.fround(( ! ( + ( + mathy4((( + (((x << y) | 0) <= ( + x))) >>> 0), 2**53)))))), Math.fround(( + mathy2(x, (mathy1(Math.fround(y), ( + (2**53-2 + y))) && x))))))))); }); testMathyFunction(mathy5, [-0x07fffffff, 0x080000001, 0x07fffffff, -(2**53-2), -0x080000001, -(2**53+2), 1.7976931348623157e308, 0x0ffffffff, -0x100000000, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, 0, 1/0, Math.PI, 0/0, -Number.MIN_SAFE_INTEGER, 2**53, 42, 1, -Number.MIN_VALUE, -0x0ffffffff, 2**53-2, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, 0.000000000000001, -0, -Number.MAX_VALUE, 0x080000000, -0x080000000, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=152; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.fround((Math.min((((x ** ( - ( + Math.acos(( + y))))) != x) | 0), (Math.sin((Math.sqrt(x) >>> 0)) | 0)) | 0)) >> ( ! (Math.fround((Math.fround(Math.sqrt(( + Math.fround(Math.abs(( + y)))))) ? 1/0 : Math.fround(( ! ( ! y))))) ? Math.pow(-Number.MIN_SAFE_INTEGER, Math.log2(x)) : x))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -1/0, -0x100000000, -0x100000001, 0.000000000000001, 0x100000001, -0x0ffffffff, -(2**53-2), -0, 0x080000001, -(2**53+2), -0x080000001, -Number.MIN_VALUE, 0x07fffffff, 42, 2**53-2, 0, -(2**53), 0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 0x080000000, 1.7976931348623157e308, 2**53, 0/0, Number.MAX_VALUE, 1, 1/0, -0x07fffffff, 0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=153; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(?=(?![\u00c6-\u0090\\S]*?((?!.))?))+)+?/gy; var s = \"\\n\\u00a6\\u00a6\\n\"; print(s.match(r)); ");
/*fuzzSeed-116066984*/count=154; tryItOut("v0 = (i1 instanceof p2);");
/*fuzzSeed-116066984*/count=155; tryItOut("m1.set((makeFinalizeObserver('tenured')), (4277));");
/*fuzzSeed-116066984*/count=156; tryItOut("\"use strict\"; for (var p in m0) { s1 += this.s1; }");
/*fuzzSeed-116066984*/count=157; tryItOut("\"use strict\"; g0.v2 = o1.g1.runOffThreadScript();");
/*fuzzSeed-116066984*/count=158; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - Math.min(( ~ (Math.tanh(mathy0(y, -0x07fffffff)) | 0)), Math.pow(( + y), Math.max(x, Math.log(Math.min(-(2**53-2), 0x0ffffffff)))))) >>> 0); }); testMathyFunction(mathy5, [-(2**53+2), -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, 1, 0x100000000, 0/0, -0x080000000, -0x080000001, -(2**53), 0x080000001, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 0x080000000, Math.PI, 1/0, -0x0ffffffff, 0, 2**53-2, -0x100000001, -0x100000000, 2**53, 42]); ");
/*fuzzSeed-116066984*/count=159; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116066984*/count=160; tryItOut("return x;\n/*MXX1*/o2 = g0.Uint8ClampedArray.prototype.constructor;\n");
/*fuzzSeed-116066984*/count=161; tryItOut("y.constructor;this.zzz.zzz;");
/*fuzzSeed-116066984*/count=162; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use asm\"; return ( + ( + Math.max(( + (Math.fround(x) ^ Math.fround((Math.expm1(( + Math.fround(Math.max(Math.fround(y), Math.fround(Math.exp(( + x))))))) >>> 0)))), ( + ( ! ( + y)))))); }); testMathyFunction(mathy2, [-0x100000000, 42, -0x080000000, Number.MIN_VALUE, 2**53-2, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, 2**53, -0, 1.7976931348623157e308, 0x080000001, 0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, 1/0, -1/0, -0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, -(2**53+2), -Number.MIN_VALUE, -0x0ffffffff, 0, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0/0, 2**53+2]); ");
/*fuzzSeed-116066984*/count=163; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 4503599627370497.0;\n    var i5 = 0;\n    var i6 = 0;\n    var i7 = 0;\n    {\n      i7 = ((-0xfffff*(/*FFI*/ff((((((1.2089258196146292e+24) != (4503599627370495.0))-(i2)) << ((-0x151db6)-(-0x8000000)))), ((abs(((null ^ window) ^ ((0xfcd47f71)-(0x6a7beef0))))|0)), ((-7.737125245533627e+25)), ((d4)), (({}.watch([[]], ({a2:z2})))), ((((0xfef779f6)-(0x46259469)) | (((0x48190f4a) != (-0x8000000))))))|0)));\n    }\n    i6 = (0x75b05817);\n    return (((i2)-((0xfd75af0b) ? (i1) : (i6))))|0;\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ \"use strict\"; var yaoqrm = new RegExp(\".\", \"gym\"); var hiidwa = (Math.sign).apply; return hiidwa;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x0ffffffff, -0x080000000, -0, -0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 0x080000000, 2**53-2, 0x07fffffff, 0x080000001, -(2**53), 1/0, -(2**53-2), -1/0, 0, 0/0, 0x100000000, Math.PI, 42, -0x0ffffffff, -(2**53+2), -Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, -0x080000001, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=164; tryItOut("\"use strict\"; s0 += s1;");
/*fuzzSeed-116066984*/count=165; tryItOut("\"use strict\"; m2.delete(a2);");
/*fuzzSeed-116066984*/count=166; tryItOut("let(a) { yield  /x/g ;}let(e = ((void shapeOf((let (trnstl, hfeudb, x, lvdewp) -14 = (/*FARR*/[...[this.z = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\".?\", \"gym\")), (Math.sqrt).apply, Function) for (x of []) for (NaN of  /x/ )], /(?:\\2)/gyim.toLocaleDateString(), , (4277), , window ? window :  \"\" ,  '' , (4277), .../*MARR*/[new String(''), new String(''), NaN, NaN,  /x/g , false, new String(''), false, NaN, new String(''), false, new String(''), false, NaN, new String(''), false, NaN,  /x/g ,  /x/g , new String(''), new String(''), false, NaN, new String(''),  /x/g , false, false], x, Math.round(-10), \"\\uC9FD\", .../*MARR*/[(-1/0), (-1/0)], \"\u03a0\", .../*PTHR*/(function() { for (var i of x) { yield i; } })(), , ...(4277) for each (eval in []) for (x of []), .../*FARR*/[...new Array(Number.MAX_VALUE),  ''  /= x, window\n, c = Proxy.create(({/*TOODEEP*/})(\"\\u53E3\"), new RegExp(\"(\\u00d9)\", \"yi\")), (void version(170)), ], .../*MARR*/[], ...x for (x in  \"\" ) for each (x in []) for each (x in []), , ...DataView.prototype.setUint8, , ...\"\\u1E6A\" <= x for (x of \"\\u5B2C\") for (arguments[\"anchor\"] in undefined) if (true), (Math.sinh(true)), let (eval = this, jruajg, x, y, NaN, rwxvhc, xqypxw) (Number()), timeout(1800), , ...new Array(0.842), \"\\u7B8B\", x, (().__defineGetter__(\"w\", Promise)), (4277), , , x, ({x: null }), , ((function sum_slicing(azuyti) { ; return azuyti.length == 0 ? 0 : azuyti[0] + sum_slicing(azuyti.slice(1)); })(/*MARR*/[-Infinity, x, -Infinity, -Infinity, x, [,,z1], x, x, [,,z1], x, 0x10000000, -Infinity, -Infinity, x, x, x, x, x, x, x, x, x, x, -Infinity, -Infinity, x, -Infinity, x, 0x10000000, -Infinity, -Infinity, 0x10000000, x, [,,z1], x, -Infinity, -Infinity, x, -Infinity, [,,z1], [,,z1], -Infinity, x, -Infinity, [,,z1], -Infinity, 0x10000000, 0x10000000, [,,z1], x, [,,z1], [,,z1], -Infinity, [,,z1], -Infinity, [,,z1], x, x, -Infinity, x, -Infinity, [,,z1], [,,z1], x, [,,z1], [,,z1], -Infinity, x, -Infinity, 0x10000000, -Infinity, x, -Infinity, [,,z1], 0x10000000, [,,z1], 0x10000000, x, 0x10000000, -Infinity, x, -Infinity, -Infinity, [,,z1], -Infinity, [,,z1], -Infinity, -Infinity, x, 0x10000000, 0x10000000, x, [,,z1], -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, [,,z1], [,,z1], 0x10000000, -Infinity, [,,z1]]))].sort(Array.prototype.slice, x)))))), [x, , x, , x] = ().__defineSetter__(\"x\", (Date.prototype.getUTCMilliseconds).apply), \u3056 = (eval(\"\\\"use strict\\\"; s2 = s1.charAt(0);\", x >> x)), x = (/*RXUE*//\\W/yi.exec(\"a\")), \u3056 = (Math.fround(-20)), x = window, [] = (4277)) ((function(){let(a) ((function(){with({}) { let(window, a = --y.eval(\"window;\"), NaN = intern(Function), b, eval = ((4277).__defineSetter__(\"x\", runOffThreadScript)\u000c), x = /*FARR*/[,  '' ].map((/(?!((?![])){0,0}(?:[]|$){4,})|\\d++?/gyim).call), txyeuz, \u3056 = null, tbfphm) ((function(){throw x;})()); } })());})());");
/*fuzzSeed-116066984*/count=167; tryItOut("t0 + f2;");
/*fuzzSeed-116066984*/count=168; tryItOut("e0 = new Set;");
/*fuzzSeed-116066984*/count=169; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.pow(( + x), (mathy2((Math.hypot(y, -1/0) | 0), (-0x0ffffffff | 0)) | 0)) ? Math.log(Math.fround(( + Math.fround((( ~ (Math.ceil(x) | 0)) >>> 0))))) : Math.round(( + Math.trunc(( + Math.atanh(x)))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 1.7976931348623157e308, 0x07fffffff, 2**53, 2**53-2, -1/0, Number.MIN_SAFE_INTEGER, 0/0, Math.PI, -(2**53+2), 42, -Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -(2**53-2), 0.000000000000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, 0x100000000, 2**53+2, -0x100000001, Number.MAX_SAFE_INTEGER, -0, 0x080000001, 1, -0x0ffffffff, 0, -(2**53), 1/0, 0x100000001, Number.MAX_VALUE, -0x080000001]); ");
/*fuzzSeed-116066984*/count=170; tryItOut("\"use strict\"; if(Math.cbrt(-8)) { if (-25) for (var p in m1) { try { s2 = new String(v0); } catch(e0) { } for (var v of p1) { try { ; } catch(e0) { } try { this.m1.toString = f2; } catch(e1) { } this.v2 = g2.runOffThreadScript(); } }} else {for(var w in ((({/*TOODEEP*/}))(undefined))) /x/g ; }");
/*fuzzSeed-116066984*/count=171; tryItOut("mathy1 = arguments.callee.caller; testMathyFunction(mathy1, [0/0, Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 1, 1/0, 0x0ffffffff, -Number.MIN_VALUE, 42, -0, 2**53+2, 0x07fffffff, -0x100000001, Number.MAX_VALUE, 0.000000000000001, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, Math.PI, -0x080000001, -0x07fffffff, 0, -(2**53+2), 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-116066984*/count=172; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(\\\\x93){3,5}(?=\\\\2)+\", \"i\"); var s = \"\\ub5ce\\ub5ce\\ub5ce\\u0093\\ue14f\\u0093\\u0093\\u0093\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=173; tryItOut("var smoghd = new ArrayBuffer(32); var smoghd_0 = new Int16Array(smoghd); print(smoghd_0[0]); smoghd_0[0] = -17; var smoghd_1 = new Int8Array(smoghd); print(smoghd_1[0]); smoghd_1[0] = -17; var smoghd_2 = new Float64Array(smoghd); smoghd_2[0] = -8; this.m0.toString = (function(j) { if (j) { try { g0.g0.toString = (function() { try { g1.m0.set(o2, this.g2); } catch(e0) { } Array.prototype.sort.call(a2, -14); throw g2; }); } catch(e0) { } try { v1 = g1.eval(\"m1 = new Map(g2);\"); } catch(e1) { } m2 + ''; } else { try { v0 = null; } catch(e0) { } try { s0 += s2; } catch(e1) { } try { for (var v of o1) { Array.prototype.pop.apply(a2, []); } } catch(e2) { } e1.has(o2.o0); } });m0.has(t0);(14);v0 = t0.length;f2.valueOf = (function mcc_() { var krnnzt = 0; return function() { ++krnnzt; f0(/*ICCD*/krnnzt % 4 == 1);};})();t2 = t0[4];");
/*fuzzSeed-116066984*/count=174; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround((Math.log(Math.max((Math.fround((Math.fround(y) & Math.fround(x))) << Number.MAX_VALUE), ( - (y - ( + Math.atan2(Math.min(Math.fround(x), Math.fround(y)), y)))))) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=175; tryItOut("Array.prototype.shift.apply(a0, []);");
/*fuzzSeed-116066984*/count=176; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\\u7347\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=177; tryItOut("mathy3 = (function(x, y) { return ( - (( + (( + Math.cosh(x)) ^ ( + mathy1(Math.fround(( + y)), Math.cbrt(((Math.acosh(y) > y) | 0)))))) >= ( + ( + ( ! ( + Math.sin(y))))))); }); testMathyFunction(mathy3, /*MARR*/[-0x2D413CCC, function(){}, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, function(){}, new Boolean(true), function(){}, new Boolean(true), -0x2D413CCC, new Boolean(true), new Boolean(true), function(){}, new Boolean(true), function(){}, new Boolean(true), function(){}]); ");
/*fuzzSeed-116066984*/count=178; tryItOut("Object.defineProperty(this, \"a2\", { configurable: x.throw((.valueOf(\"number\"))), enumerable: true,  get: function() {  return r1.exec(s2); } });g2.s2 += 'x';");
/*fuzzSeed-116066984*/count=179; tryItOut("return 0\n");
/*fuzzSeed-116066984*/count=180; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xfff5e34e);\n    i0 = (0x146ca913);\n    return +((-1.00390625));\n    i0 = ((~~(-1.001953125)) == (~(((-1073741824.0) != (+/*FFI*/ff(((~((i0)))), ((+((((524287.0)) / ((8589934593.0)))))), ((((-0.015625)) / ((524287.0)))), ((((0x4cf7978d))|0)), ((68719476737.0))))))));\n    i0 = ((((i0)-(i0))>>>((((-0x86ce*(0x9208f850)) & ((0x8ada67ef) / (0xd1a13968))) != (((0x19b58207)-(0xffffffff)) << (((0x4ffbb764) > (0x57e9c793)))))+(!(i0)))) < (0x932779ab));\n    (Float64ArrayView[(((-0x8000000) ? ((((0xffb5a713)) >> ((0x8d75c426))) != (((0x720e3b4d)) ^ ((0xffffffff)))) : (0xa8dda837))) >> 3]) = ((d1));\n    d1 = (d1);\n    switch ((imul(((0xfcd44405) >= (0xececc915)), ((~((0xd703b444)))))|0)) {\n    }\n    d1 = (1.001953125);\n    return +((+(~~(18014398509481984.0))));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=181; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((Infinity) != (-9.44473296573929e+21));\n    {\n      i1 = (i0);\n    }\n    return +((((549755813889.0))));\n  }\n  return f; })(this, {ff: new false()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -0x100000000, 2**53-2, 0/0, -(2**53+2), -0, 0x0ffffffff, Number.MAX_VALUE, -(2**53-2), 0.000000000000001, 0x07fffffff, 1.7976931348623157e308, 2**53, 0, Math.PI, 1/0, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53+2, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 42, 0x080000000, 0x080000001, Number.MIN_VALUE, 1, 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=182; tryItOut("\"use strict\"; o1.o2.m0.get((x = window));");
/*fuzzSeed-116066984*/count=183; tryItOut("for(let a in (((\"\\u0E63\").bind(x <= z, \"\\u6E86\"))(x)))v1 = g0.eval(\"function f1(v0) \\\"use asm\\\";   var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    i1 = ((((Float32ArrayView[((i0)+(!(i0))) >> 2])) % (((-268435455.0)))) > (-7.555786372591432e+22));\\n    i1 = (i0);\\n    i1 = (i1);\\n    return (((((0x3b937370) / (((!(-0x8000000)))>>>(((0xbc942ada) == (0x97e5c14f))))) ^ ((((134217728.0))))) / (((((x)+(i1)+(0x61470254)) >> ((i1)-(i0))) % (((i0)-(1)+(i0))|0))|0)))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-116066984*/count=184; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: (String.prototype.substr).call}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -1/0, -0x0ffffffff, -(2**53-2), -0, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, 0x07fffffff, 0x080000000, 42, 0, -0x100000001, -Number.MIN_VALUE, Math.PI, -0x07fffffff, 1, -0x080000000, 2**53, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, 0x100000000, 0x100000001, 1.7976931348623157e308, -0x100000000, 2**53+2, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=185; tryItOut("mathy4 = (function(x, y) { return ( + (( + Math.sqrt(Math.trunc(y))) & ((Math.cbrt((( + (Math.imul((Math.max(Math.fround(x), 0x080000000) >>> 0), mathy2(Number.MIN_VALUE, (Math.imul((y | 0), (-0x080000001 | 0)) | 0))) >>> 0)) >>> 0)) >>> 0) || Math.fround(((( ! (x >>> 0)) >>> 0) || Math.imul((( + y) / x), y)))))); }); testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), 1, objectEmulatingUndefined(), [], '0', '\\0', false, true, (new String('')), 0, (new Boolean(false)), 0.1, (function(){return 0;}), -0, (new Boolean(true)), (new Number(-0)), null, '/0/', '', ({valueOf:function(){return 0;}}), /0/, NaN, (new Number(0)), undefined, [0]]); ");
/*fuzzSeed-116066984*/count=186; tryItOut("f0(i2);");
/*fuzzSeed-116066984*/count=187; tryItOut("/*tLoop*/for (let c of /*MARR*/[ /x/ , 0x3FFFFFFF,  /x/ ,  /x/ ,  /x/ ]) { m2.set(h1, g0.b2); }");
/*fuzzSeed-116066984*/count=188; tryItOut("/*vLoop*/for (var ypnhnj = 0; ypnhnj < 0; ++ypnhnj) { y = ypnhnj; a1.shift(); } ");
/*fuzzSeed-116066984*/count=189; tryItOut("\"use strict\"; /*vLoop*/for (xfnwqp = 0, x; xfnwqp < 37; ++xfnwqp) { let a = xfnwqp; a1[v1] = o0.t0; } ");
/*fuzzSeed-116066984*/count=190; tryItOut("mathy5 = (function(x, y) { return (Math.hypot((Math.fround(( - Math.fround(((Math.abs((Math.max((x | 0), (x | 0)) | 0)) ? x : ( ~ ( - (y | 0)))) >>> 0)))) | 0), (mathy0(Math.fround((( + Math.sin(y)) , (( - y) ? ( - 0x080000000) : ((x || y) | 0)))), ( + ((Math.imul((( + ( - ( + (((y ? 2**53 : (1/0 | 0)) >>> x) >>> 0)))) >>> 0), ((Math.pow(x, 42) >>> 0) >>> 0)) >>> 0) & ( + Math.max(( + x), Math.pow(( + y), (1 | 0))))))) | 0)) | 0); }); testMathyFunction(mathy5, [Number.MIN_VALUE, 0.000000000000001, -Number.MIN_VALUE, -(2**53-2), 2**53+2, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, -(2**53+2), 0, -0x080000000, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, 0/0, -(2**53), 0x100000001, 0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, -0x080000001, -0x07fffffff, 1/0, 2**53-2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, 1, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=191; tryItOut("Array.prototype.pop.call(a2);");
/*fuzzSeed-116066984*/count=192; tryItOut("i1 = g0.a0[16];");
/*fuzzSeed-116066984*/count=193; tryItOut("\"use strict\"; p1[\"atan\"] = g2.h1;");
/*fuzzSeed-116066984*/count=194; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.pow(Math.fround(( ! ( + Math.min(( + ( + ( ~ (y >>> 0)))), ( + (Math.hypot((y >>> 0), (y | 0)) | 0)))))), (mathy0(((Math.max(y, ((( ! ((y < (x + y)) | 0)) | 0) | 0)) | 0) >>> 0), Math.atanh(y)) >>> 0)); }); testMathyFunction(mathy1, [0.000000000000001, 2**53, 2**53+2, 0x080000001, 0x080000000, Number.MAX_VALUE, 2**53-2, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 42, 1/0, 0/0, Number.MIN_VALUE, 0, -0x100000001, -0, 0x100000001, -0x080000001, -0x07fffffff, 1.7976931348623157e308, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 1, -(2**53-2), -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-116066984*/count=195; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; }");
/*fuzzSeed-116066984*/count=196; tryItOut("mathy2 = (function(x, y) { return mathy1((( + (( - (Math.trunc(Math.pow(( + x), 2**53+2)) | 0)) | 0)) ^ ( + (( + Math.pow(Math.fround(x), Math.fround((( + (( - y) >>> 0)) >>> 0)))) == ( + Math.fround(Math.sin((x >>> 0))))))), ((( - ( ~ y)) ? ( + ( ~ (Math.cos((x >>> 0)) >>> 0))) : ( + (( + Math.fround(Math.log2(Math.fround(( ! x))))) % ( + y)))) | 0)); }); testMathyFunction(mathy2, [42, -1/0, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, -0x07fffffff, 2**53+2, 0x080000000, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -(2**53), -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 1, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, 2**53, -(2**53-2), 1.7976931348623157e308, 0x100000000, 2**53-2, Number.MIN_VALUE, 0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000000, -Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-116066984*/count=197; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.exp(Math.clz32(Math.fround(( + Math.tan(Math.fround(Math.cbrt(Math.sinh((y >>> 0))))))))) >>> 0); }); testMathyFunction(mathy1, [1.7976931348623157e308, 1/0, 2**53, 42, 0x0ffffffff, Number.MAX_VALUE, 0x080000000, 0x100000000, 0, -0x100000001, -1/0, 0x080000001, -(2**53), -0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, 2**53+2, 0/0, 0.000000000000001, 1, 0x07fffffff, -0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, Math.PI]); ");
/*fuzzSeed-116066984*/count=198; tryItOut("\"use strict\"; z = x;\"\\u5CF0\";a2 = arguments.callee.arguments;");
/*fuzzSeed-116066984*/count=199; tryItOut("/*infloop*/M: for  each(((p={}, (p.z = (x))())).NaN in ((yield ((/*UUV2*/(this.valueOf = this.anchor)).throw(((void options('strict')))))))) let (b = [[]]) e;");
/*fuzzSeed-116066984*/count=200; tryItOut("v0 = true;");
/*fuzzSeed-116066984*/count=201; tryItOut("print(uneval(v1));");
/*fuzzSeed-116066984*/count=202; tryItOut("Array.prototype.reverse.call(a1);");
/*fuzzSeed-116066984*/count=203; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max((Math.cbrt(Math.fround(Math.acos(x))) - (( + (((( + (( + x) ? ( + y) : ( + x))) | 0) >= Math.fround(-0x07fffffff)) | 0)) , ( + ( - ( + mathy0(x, y)))))), Math.max((( - (Math.acosh(x) | 0)) | 0), Math.clz32(y))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -(2**53-2), 42, -0x07fffffff, 2**53-2, 1.7976931348623157e308, 0, -Number.MIN_SAFE_INTEGER, -0x100000001, -1/0, 0x07fffffff, -(2**53), 0x080000000, 0.000000000000001, 2**53, -0x080000000, -Number.MIN_VALUE, 0x080000001, -0x080000001, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 1, 0/0, 1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, 2**53+2, 0x100000000]); ");
/*fuzzSeed-116066984*/count=204; tryItOut("\"use strict\"; for (var p in i0) { try { /*RXUB*/var r = r0; var s = \"\"; print(s.split(r));  } catch(e0) { } a0.unshift(a1, v1, o0.g2.p1, p0, (4277) * (w =  '' ).call((4277), \nnew RegExp(\"\\uadc7{1}\", \"yim\"))); }");
/*fuzzSeed-116066984*/count=205; tryItOut("g0.v2 = g0.runOffThreadScript();");
/*fuzzSeed-116066984*/count=206; tryItOut("\"use strict\"; \"use asm\"; v1 = false;");
/*fuzzSeed-116066984*/count=207; tryItOut("z.message;");
/*fuzzSeed-116066984*/count=208; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (( - Math.atan(( ~ (Math.fround(Math.clz32((y >>> 0))) && ( + y))))) | 0)); }); testMathyFunction(mathy0, [0x100000001, -1/0, 0x0ffffffff, 2**53+2, -(2**53-2), 1/0, -(2**53), -Number.MAX_VALUE, 0.000000000000001, 0x080000001, -0x100000000, 0x07fffffff, -0x100000001, Math.PI, -0x07fffffff, 2**53, -0, 0x100000000, 0/0, 42, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, 0x080000000, 0, 1, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), 2**53-2, -0x080000001]); ");
/*fuzzSeed-116066984*/count=209; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\b)*?\", \"m\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-116066984*/count=210; tryItOut("(x);");
/*fuzzSeed-116066984*/count=211; tryItOut("v0 = (b2 instanceof h2);");
/*fuzzSeed-116066984*/count=212; tryItOut("mathy0 = (function(x, y) { return (( + ( + (( + Math.fround((Math.fround(( + (0x0ffffffff < ( + (Math.tanh((x >>> 0)) >>> 0))))) | Math.fround(( + (Math.imul(y, x) ^ ( + ( ~ x)))))))) , Math.tan(Math.cos(Math.acos(x)))))) >>> 0); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, 0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, 0x0ffffffff, -0x100000001, 1, Math.PI, 2**53+2, 1.7976931348623157e308, Number.MAX_VALUE, -0x07fffffff, 0x080000001, 0/0, 1/0, 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, 42, 0.000000000000001, -0x080000001, -(2**53-2), 0, 0x080000000]); ");
/*fuzzSeed-116066984*/count=213; tryItOut(" '' ;NaN;");
/*fuzzSeed-116066984*/count=214; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=215; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-116066984*/count=216; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (( - Math.cosh(Math.abs((( ~ ( - Math.PI)) | 0)))) | 0)); }); testMathyFunction(mathy3, [-0x07fffffff, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), -Number.MIN_VALUE, Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, 0x0ffffffff, 42, -0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0x080000001, -(2**53), -0x080000000, 0x100000001, 0, 0/0, 1, -0, 2**53, 2**53+2, Math.PI, 2**53-2]); ");
/*fuzzSeed-116066984*/count=217; tryItOut("e1.valueOf = (function(j) { if (j) { try { v1.__iterator__ = o2.f0; } catch(e0) { } a2.sort(f2, a1); } else { v0 = Object.prototype.isPrototypeOf.call(o2, o1.i1); } });");
/*fuzzSeed-116066984*/count=218; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x100000000, 0x080000000, 2**53+2, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0, 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, 1/0, 2**53, 1, 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, Math.PI, 0x0ffffffff, 42, 2**53-2, -(2**53+2), -0x100000001, -Number.MAX_VALUE, -0x100000000, -0x080000001, 0x080000001, 0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -(2**53), -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=219; tryItOut("v1 = Infinity;");
/*fuzzSeed-116066984*/count=220; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((((( - Math.fround((Math.pow((Math.min(x, Math.fround(( - Math.fround((((x >>> 0) == (mathy2(x, x) >>> 0)) >>> 0))))) >>> 0), ( ~ mathy3(y, (-0x100000000 !== Math.fround(Math.imul(x, Math.fround(-1/0))))))) | 0))) | 0) | 0) <= ( + Math.fround(((( + ((Math.min((y | 0), (Math.imul(y, x) | 0)) >>> 0) | 0)) | 0) | 0)))) | 0); }); ");
/*fuzzSeed-116066984*/count=221; tryItOut("print(uneval(v0));");
/*fuzzSeed-116066984*/count=222; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.asinh(Math.fround(Math.pow(Math.fround(Math.atanh(( + y))), ( + (Math.imul(Math.asin(Math.fround(x)), ( + (( + ( + (( + y) ? ( + y) : ((y != -0x07fffffff) >>> 0)))) , ( + -Number.MIN_VALUE)))) >>> 0)))))); }); testMathyFunction(mathy3, [undefined, true, 0.1, (new Boolean(true)), (new String('')), '\\0', [], [0], false, ({valueOf:function(){return '0';}}), 1, -0, NaN, (function(){return 0;}), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Boolean(false)), '0', (new Number(-0)), (new Number(0)), /0/, objectEmulatingUndefined(), '/0/', '', 0, null]); ");
/*fuzzSeed-116066984*/count=223; tryItOut("o0.g0.e1.delete(a2);");
/*fuzzSeed-116066984*/count=224; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.min(Math.max(Math.fround(mathy1((Math.fround(2**53+2) % ( + (((x >= x) >>> 0) ? ( + y) : ( + x)))), Math.log2((((( + 0x080000001) & y) - (mathy1(mathy1(-0x100000000, -Number.MAX_SAFE_INTEGER), Math.PI) | 0)) | 0)))), Math.fround((( - (Math.atan2((x >>> 0), (( + (( + ( ~ (y | 0))) / ( + x))) >>> 0)) >>> 0)) >>> 0))), Math.fround(Math.max(Math.cos(Math.fround(( ! (Math.log10(x) >>> 0)))), Math.fround(mathy1(( + (-Number.MAX_VALUE ? (x >>> 0) : Number.MIN_SAFE_INTEGER)), Math.sin(Math.pow((( ~ y) >>> 0), x)))))))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1, 2**53-2, -(2**53+2), 2**53, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 1.7976931348623157e308, 2**53+2, 0x07fffffff, 0x080000000, -0x0ffffffff, 0.000000000000001, 0, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 0/0, -Number.MIN_VALUE, 0x100000000, -0x100000000, -0, -0x07fffffff, -1/0, 0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, 42, Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=225; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.imul(Math.fround(Math.sinh(((Math.log10(((x >>> x) === x)) | 0) | 0))), (Math.atan2(Math.cosh((Math.clz32(( + x)) ? (((Math.abs(y) >>> 0) !== (y >>> 0)) >>> 0) : x)), Math.fround((Math.fround(( ~ (Math.expm1(Math.fround(x)) | 0))) | (( + (Math.clz32((Math.cosh((y | 0)) | 0)) | 0)) >> Math.fround(( ! (y | 0))))))) | 0)) | 0); }); testMathyFunction(mathy3, [0x080000001, 0x100000000, 1.7976931348623157e308, -0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, 0x100000001, 0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, -0x100000000, 0/0, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), 0x07fffffff, -0, 2**53, 2**53-2, 0.000000000000001, 0x080000000, -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -0x080000000, 1/0, 2**53+2, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-116066984*/count=226; tryItOut("\"use strict\"; var hbadlv = new ArrayBuffer(12); var hbadlv_0 = new Int8Array(hbadlv); /*RXUB*/var r = o1.r1; var s = \"\\u00f3\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116066984*/count=227; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=228; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; void gc(); } void 0; } const i1 = new Iterator(i2, true);");
/*fuzzSeed-116066984*/count=229; tryItOut("a1 = a0.map(String.prototype.match.bind(t0));");
/*fuzzSeed-116066984*/count=230; tryItOut("");
/*fuzzSeed-116066984*/count=231; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( + Math.log((( + Math.exp(( + (y % (x > (x | 0)))))) > x)))); }); testMathyFunction(mathy2, [42, Number.MIN_VALUE, 0, 0/0, Math.PI, 0x100000000, -1/0, -0x080000001, 0x100000001, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 1, 0.000000000000001, 0x0ffffffff, 1.7976931348623157e308, -0x100000000, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, -0x07fffffff, -(2**53), Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, -0x100000001, -(2**53-2), -(2**53+2), 0x07fffffff]); ");
/*fuzzSeed-116066984*/count=232; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[null, 1e81, 1e81, 1e81,  \"\" , 1e81, null, 1e81, 1e81, null, null,  \"\" , null, 1e81,  \"\" ,  \"\" , 1e81, 1e81, null,  \"\" , null, null, 1e81,  \"\" , null,  \"\" , 1e81, null, 1e81,  \"\" , 1e81, 1e81, 1e81, 1e81,  \"\" ,  \"\" , 1e81, 1e81, 1e81, null,  \"\" , 1e81,  \"\" , 1e81, null, null, null,  \"\" , 1e81, 1e81, 1e81, 1e81, null, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, null, null,  \"\" , null, null,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 1e81, 1e81,  \"\" ,  \"\" ,  \"\" ,  \"\" , null, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, null, null, null,  \"\" , null,  \"\" , 1e81, null, 1e81, 1e81,  \"\" , null, null, null, 1e81,  \"\" , null, 1e81, null, null, null, 1e81,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 1e81, null,  \"\" , null,  \"\" , null, null,  \"\" ,  \"\" , 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81, 1e81,  \"\" , 1e81, null, 1e81,  \"\" ,  \"\" , 1e81,  \"\" , 1e81,  \"\" , 1e81, 1e81, 1e81,  \"\" , null,  \"\" ,  \"\" ,  \"\" ,  \"\" , null, null,  \"\" , null,  \"\" ,  \"\" , null, null, null,  \"\" , null,  \"\" , 1e81, 1e81,  \"\" ,  \"\" ]) { m2 = new WeakMap; }");
/*fuzzSeed-116066984*/count=233; tryItOut("mathy4 = (function(x, y) { return (Math.hypot(((Math.imul(Number.MIN_SAFE_INTEGER, Math.acos((-0x0ffffffff >>> ( + (Math.imul(0x100000001, x) > Math.fround((y ** y))))))) >>> 0) < ( + Math.atan2(Math.min(1/0, Math.atan(x)), Math.ceil(Math.asinh(-(2**53)))))), ( ! ( - ((((( ~ x) | 0) ** ( + (Math.fround(( ~ ( + Math.fround(Math.min(Number.MIN_SAFE_INTEGER, x))))) ? ( + Math.fround(Math.min(y, y))) : ( + x)))) | 0) >>> 0)))) | 0); }); ");
/*fuzzSeed-116066984*/count=234; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot((( ! mathy1(x, (y != Math.atan2(Math.fround(mathy1((x >>> 0), y)), Math.fround(2**53+2))))) >>> 0), ( + ( - (Math.log((y >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [-0, Number.MAX_VALUE, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, Math.PI, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), -0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, -(2**53-2), -1/0, 1, 0x080000000, -0x07fffffff, 0x100000000, -0x100000000, 1/0, 0x07fffffff, Number.MIN_VALUE, 42, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0, 2**53, 0x0ffffffff, 0.000000000000001, 0x080000001, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=235; tryItOut("a2.shift(h1);");
/*fuzzSeed-116066984*/count=236; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[NaN, NaN, new String(''), new String(''), new String(''), new String(''), new String(''), -5, -5, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), NaN, new String(''), new String(''), new String(''), new String(''), NaN, new String(''), new String(''), new String(''), new String(''), NaN, -5, new String(''), new String(''), new String(''), -5, NaN, new String(''), new String(''), NaN, new String(''), NaN, NaN, new String(''), new String(''), -5, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), -5, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), -5, new String(''), new String(''), new String(''), NaN, -5, new String(''), new String(''), new String(''), new String(''), new String(''), -5, -5, -5, -5, -5, NaN, NaN, new String(''), new String(''), new String(''), new String(''), NaN, new String(''), NaN, new String(''), -5, -5, -5, -5, -5, -5, -5, -5, new String(''), new String(''), -5, new String(''), -5, new String(''), new String(''), -5, -5, -5]) { return this; }");
/*fuzzSeed-116066984*/count=237; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -33554433.0;\n    var d4 = 1125899906842625.0;\n    var i5 = 0;\n    {\n      d3 = (d4);\n    }\n    (Float64ArrayView[((0xd3e13e38)+(0x2fd844d9)+(((-8796093022209.0) == (-147573952589676410000.0)) ? ((0x463571a0)) : (0x6dd3a514))) >> 3]) = ((+(1.0/0.0)));\n    return +((d4));\n  }\n  return f; })(this, {ff: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: (function(x, y) { return x; }), fix: mathy3, has: function() { return false; }, hasOwn: function() { return false; }, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: function(y) { window; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, -0x100000000, -(2**53), -0, -0x080000000, 2**53, -0x080000001, -(2**53+2), -1/0, -0x07fffffff, 1, 42, 0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 0, 0/0, 0x07fffffff, 2**53+2, -0x0ffffffff, 1/0, 0x080000001, Math.PI]); ");
/*fuzzSeed-116066984*/count=238; tryItOut("mathy5 = (function(x, y) { return Math.log1p((Math.acosh(( + (( ~ ( + Math.fround(Math.min(( + y), Math.fround(mathy4(0x080000001, (x - y))))))) | 0))) >>> 0)); }); testMathyFunction(mathy5, [0x080000001, 0.000000000000001, -1/0, -0x080000000, 2**53-2, -(2**53), 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, -0, Number.MIN_VALUE, 0x100000001, -0x080000001, 2**53, 2**53+2, -(2**53-2), 0x080000000, 0x100000000, 0/0, 1/0, Number.MIN_SAFE_INTEGER, 0, 1, -(2**53+2), 0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, -0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=239; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (((( ! x) >>> 0) || ( - ( + ( ! ( + (( + mathy3((mathy4((x >>> 0), (x >>> 0)) >>> 0), (Math.atan2((y | 0), (y | 0)) | 0))) === ( + -0x080000000))))))) !== Math.cos(( ~ ( + ( ~ ( + ( ~ (Math.abs(y) == Math.imul((y | 0), Math.fround(y)))))))))); }); testMathyFunction(mathy5, [objectEmulatingUndefined(), '0', (new String('')), [0], ({valueOf:function(){return '0';}}), 0.1, (new Boolean(false)), (new Number(0)), (new Boolean(true)), [], false, null, -0, '\\0', 1, undefined, '/0/', '', /0/, (function(){return 0;}), ({valueOf:function(){return 0;}}), true, NaN, 0, ({toString:function(){return '0';}}), (new Number(-0))]); ");
/*fuzzSeed-116066984*/count=240; tryItOut("/*RXUB*/var r = /\\3/m; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-116066984*/count=241; tryItOut("mathy3 = (function(x, y) { return Math.clz32(((( - ( + mathy0(( + Math.max(x, x)), x))) | Math.fround(Math.sinh(Math.fround((Math.clz32((mathy1(Math.fround(Math.atan2((x >>> 0), Math.fround(2**53-2))), x) >>> 0)) | 0))))) >>> 0)); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, 42, 0x080000001, -Number.MAX_VALUE, -1/0, 0, -0x100000000, 2**53+2, -(2**53-2), Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000, 0x100000001, -Number.MIN_VALUE, -0x07fffffff, 2**53, -0, 0.000000000000001, -0x0ffffffff, 0x080000000, 2**53-2, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, -(2**53+2), 1/0, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=242; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=243; tryItOut("\"use strict\"; let(x) { for(let b of /*wrap2*/(function(){ \"use strict\"; var gsnixq = 1; var awvyor = (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { throw 3; }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: (1 for (x in [])), set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: false, keys: function() { return Object.keys(x); }, }; }); return awvyor;})()) x.stack;}");
/*fuzzSeed-116066984*/count=244; tryItOut("Array.prototype.forEach.call(a2, f1);");
/*fuzzSeed-116066984*/count=245; tryItOut("if((w = Proxy.createFunction(({/*TOODEEP*/})(NaN),  /x/ ))) L: yield 26;print(\"\u03a0\");");
/*fuzzSeed-116066984*/count=246; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.asin(Math.fround(Math.imul((((Math.hypot(0x100000001, ( ~ (y >>> x))) < x) != ((Math.max(y, x) | 0) ? ((((y >>> 0) ^ (x | 0)) | 0) | 0) : (x >>> 0))) >>> 0), (Math.expm1((x | y)) >>> 0)))); }); testMathyFunction(mathy4, [0x07fffffff, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 0x080000000, 0.000000000000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, -0, -Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, 1, -(2**53+2), -(2**53), -(2**53-2), 0/0, 2**53, 0x100000000, -0x100000001, -0x080000001, Number.MAX_VALUE, 0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, 0, 42, 1/0]); ");
/*fuzzSeed-116066984*/count=247; tryItOut("\"use strict\"; var y = null;t2 + h0;");
/*fuzzSeed-116066984*/count=248; tryItOut("g2.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-116066984*/count=249; tryItOut("\"use strict\"; for(\u000cw in \"\\uC39A\") o1.e1.add(g2);function e(\u3056, w, z, e, x = window, \u3056, __iterator__, c, \u3056, y, window, w, e, w, w, w, x, z, x, \u3056 = window, x, b, w, x, c, NaN, y = eval, z, c =  \"\" , w =  '' , x, x, w, setter, x, w, d, b, d, eval, c = \"\\uDD72\", x = /[^\u4d3c]/i, w, w, d,   =  \"\" , e = [,], b, eval, y, w, a, e, w =  \"\" , e, eval = window, x, NaN, w) { \"use asm\"; v0 = Array.prototype.reduce, reduceRight.call(this.a2, (function(j) { if (j) { try { o1.__proto__ = a2; } catch(e0) { } v2.valueOf = (function(j) { if (j) { m1 + ''; } else { try { m2.set(this.s0, h2); } catch(e0) { } try { this.v0 = 4; } catch(e1) { } o1.e2 = new Set; } }); } else { i1.send(this.g0.t1); } }), h0, a0); } r1 = /((?!\\W)\\v\\3)(?=(\\B))*|U|([^]){0}/gyi;");
/*fuzzSeed-116066984*/count=250; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=251; tryItOut("\"use strict\"; if(false) {g2 = g0; } else  if (x) {m0 = new WeakMap;a1.shift(); } else {/*RXUB*/var r = /(?:(?:\\u3998(^)|\\s|[^\\u7015\\cG-\\f\\u0040\udbc0]{4,7}*?))|\\2|[\u00df\\cZ](\\b*?)|(?:^)+{1,3}\\2*/gy; var s = \"\"; print(s.split(r)); Object.freeze(b2); }");
/*fuzzSeed-116066984*/count=252; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.acos(Math.round(Math.imul(y, mathy0(x, Math.imul(Math.fround((Math.abs((-(2**53-2) >>> 0)) >>> 0)), 0x080000001))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, 1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 1, -1/0, -(2**53-2), Math.PI, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0, -0x0ffffffff, 2**53+2, -0x080000001, 0/0, 0x080000001, -0x080000000, Number.MAX_VALUE, 42, 0x07fffffff, -0x100000000, -0x07fffffff, -0, 2**53, 0x100000000, -(2**53+2), -(2**53), -0x100000001, Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=253; tryItOut("m0.get(g0);");
/*fuzzSeed-116066984*/count=254; tryItOut("\"use strict\"; ((4277));");
/*fuzzSeed-116066984*/count=255; tryItOut("g2.__proto__ = o0;");
/*fuzzSeed-116066984*/count=256; tryItOut("/*vLoop*/for (var oiwvcu = 0; oiwvcu < 25; x &= true, ++oiwvcu) { const d = oiwvcu; e0.add((4277)); } ");
/*fuzzSeed-116066984*/count=257; tryItOut("testMathyFunction(mathy0, /*MARR*/[function(){}, false, function(){}, function(){}, function(){}, function(){}, false, function(){}, false, false, false, false, false, function(){}, false, function(){}, function(){}, false, false, false, function(){}, function(){}, false, function(){}, false, false, false, false, function(){}, function(){}, function(){}, false, function(){}, function(){}, function(){}, false, false, function(){}, false, false, function(){}, function(){}, false, function(){}, false, false, function(){}, false, false, function(){}, function(){}, false, false, false]); ");
/*fuzzSeed-116066984*/count=258; tryItOut("Array.prototype.forEach.call(a0, f0);");
/*fuzzSeed-116066984*/count=259; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=260; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((( + ( ! Math.fround(Math.fround((Math.atan2(((-0x100000001 ? (x >>> 0) : (-0x100000000 >>> 0)) >>> 0), (Math.max(x, (x >>> 0)) >>> 0)) & (x / 42)))))) <= ( + Math.imul(Math.cos((( + mathy0(( + x), ( + x))) >>> 0)), Math.fround(Math.max((((-0x100000001 | 0) < (Number.MAX_VALUE | 0)) | 0), -Number.MAX_VALUE))))) >>> 0) ** (Math.log10(Math.sinh((Math.log(x) >>> 0))) | 0)); }); testMathyFunction(mathy1, [0x080000000, Number.MIN_VALUE, 1, -(2**53), Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, 0.000000000000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 1.7976931348623157e308, 1/0, -0x0ffffffff, 2**53-2, 0x080000001, -0x080000000, -Number.MIN_VALUE, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, -0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, -Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, Math.PI, 2**53+2, -0, 0]); ");
/*fuzzSeed-116066984*/count=261; tryItOut("\"use strict\"; /*infloop*/for({\u3056, (eval), eval} = (arguments.callee.arguments = undefined); window.yoyo(y); \"\\uC9C3\") /*oLoop*/for (gycpel = 0; gycpel < 77; ++gycpel) { a1 = []; } ");
/*fuzzSeed-116066984*/count=262; tryItOut("f1 = Proxy.createFunction(h0, o0.f2, f0);");
/*fuzzSeed-116066984*/count=263; tryItOut("\"use strict\"; /*hhh*/function iuayix(x = /\\1/gym, eval, y, x, w, b = window, NaN, x = true, window, x, x, w = eval, x, window, d = this, x, x, x =  \"\" , e, \u3056, e, x, a, x, d, \u3056, x = undefined, e, window, window, x, NaN = this, c, \u3056, c, y, x, c, d, \u3056, y, x, x, z, d = /(([\\D\\s\\D\\u0075-\\u00c5]){4,6})/gm, window, x, x =  /x/ , c, c, x =  /x/g , c, NaN, \"\\uBB9D\" = 11, x, e, w, e, b, this.x){m2.delete(v1);}/*iii*/(x);");
/*fuzzSeed-116066984*/count=264; tryItOut("v0 = true;");
/*fuzzSeed-116066984*/count=265; tryItOut("print(/^/gym);");
/*fuzzSeed-116066984*/count=266; tryItOut("\"use strict\"; for (var v of b2) { try { /*MXX2*/g1.DataView.name = t0; } catch(e0) { } g2.offThreadCompileScript(\"/* no regression tests found */\"); }");
/*fuzzSeed-116066984*/count=267; tryItOut("\"use strict\"; /*vLoop*/for (var kahios = 0, x; kahios < 39; ++kahios) { let e = kahios; t0[3]; } ");
/*fuzzSeed-116066984*/count=268; tryItOut("/*tLoop*/for (let e of /*MARR*/[Number.MAX_VALUE, objectEmulatingUndefined(), Number.MAX_VALUE, [undefined], new Boolean(true)]) { o0 = {}; }");
/*fuzzSeed-116066984*/count=269; tryItOut("v2 = t1.length;");
/*fuzzSeed-116066984*/count=270; tryItOut("print(f2);");
/*fuzzSeed-116066984*/count=271; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      return (((((0x684acfbc) <= (0x5d8cdaa9)) ? (i0) : (i1))+((abs((((((32768.0) + (-33554432.0)) != (1152921504606847000.0))) >> ((Uint8ArrayView[0]))))|0))))|0;\n    }\n    {\n      i1 = ((0x0) >= ((((0x0)))>>>((i0)-(i1))));\n    }\n    return (((i0)-(i0)))|0;\n  }\n  return f; })(this, {ff: (/*wrap2*/(function(){ \"use strict\"; var qywimb = \u3056 !== x; var zzepuq = runOffThreadScript; return zzepuq;})()).bind}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=272; tryItOut("mathy3 = (function(x, y) { return ( - ((((( - Math.fround(Math.hypot(y, x))) | 0) ^ ((Math.hypot((y | 0), (( + Math.sinh(( + (x != x)))) | 0)) | 0) | 0)) | 0) | 0)); }); testMathyFunction(mathy3, [0, -0x080000000, 2**53, 0x100000000, 0x100000001, -0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, 0.000000000000001, 0x080000000, -(2**53-2), 0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, -0x100000000, -0, -0x0ffffffff, -1/0, 1/0, -(2**53+2), 0x07fffffff, Number.MIN_VALUE, -(2**53), 2**53-2, 42, 0/0, 1.7976931348623157e308]); ");
/*fuzzSeed-116066984*/count=273; tryItOut("var x, NaN =  /x/g , kdehpi, w, w, NaN, eval, clkkye, getgti;Array.prototype.forEach.call(a1, (function() { for (var j=0;j<5;++j) { f0(j%3==1); } }), o0, e2, this.e1);");
/*fuzzSeed-116066984*/count=274; tryItOut("this.v1 = evaluate(\"function this.f2(o2)  { return this } \", ({ global: o2.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 3 == 1), sourceIsLazy: (makeFinalizeObserver('tenured')), catchTermination: (x % 31 != 25) }));");
/*fuzzSeed-116066984*/count=275; tryItOut("(( /* Comment */ /x/ ));");
/*fuzzSeed-116066984*/count=276; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.ceil(Math.fround(Math.fround(mathy4(((( + 1/0) ? Math.fround(Math.atan2(Math.fround(y), Math.fround(x))) : (Math.acosh((Math.fround((y >>> 0)) >>> 0)) >>> 0)) | 0), Math.fround(( + (Math.sign(((y ? 1/0 : (-0x080000000 | 0)) | 0)) - Math.max(y, (x ? x : x))))))))); }); testMathyFunction(mathy5, [0x100000001, 0x080000001, 0x100000000, Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, 0x0ffffffff, 2**53-2, Number.MIN_VALUE, 0/0, 2**53+2, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, -(2**53+2), -0, 2**53, -0x080000000, 0x080000000, -(2**53-2), -0x100000001, -Number.MIN_VALUE, 42, -0x080000001, 1.7976931348623157e308, -0x100000000, Math.PI, -1/0, 0, 1, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=277; tryItOut("testMathyFunction(mathy1, [-(2**53+2), -0x080000000, 0x080000001, Number.MAX_VALUE, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, 2**53+2, 2**53-2, 0/0, 0x100000001, 42, 0, Number.MAX_SAFE_INTEGER, -(2**53), 1, -0x0ffffffff, -0, 0x080000000, 1/0, 2**53, 0.000000000000001, 0x07fffffff, -0x080000001, -0x100000001, -0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-116066984*/count=278; tryItOut("\"use strict\"; o2.f2(h2);");
/*fuzzSeed-116066984*/count=279; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ! (Math.abs(Math.fround(mathy0(Math.fround(y), Math.fround((x >= x))))) | 0)); }); testMathyFunction(mathy1, [2**53, -0, 1/0, -0x080000000, 2**53-2, Number.MAX_VALUE, -0x100000001, 1, -0x080000001, -0x100000000, 0, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, -0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, Math.PI, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000001, 2**53+2, 0.000000000000001, 0x07fffffff, -(2**53), 0x100000000, -(2**53-2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, Number.MAX_SAFE_INTEGER, 0/0, 0x080000001]); ");
/*fuzzSeed-116066984*/count=280; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=281; tryItOut("g1.v0 = true;");
/*fuzzSeed-116066984*/count=282; tryItOut("selectforgc(o2);");
/*fuzzSeed-116066984*/count=283; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.expm1(Math.tanh((( + ( - ( + ((x >>> 0) >= y)))) | 0))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, 1/0, 0x07fffffff, Number.MIN_VALUE, 42, 2**53+2, -1/0, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001, 0.000000000000001, -0x100000000, -0x100000001, 1, 0, -0, -0x0ffffffff, 2**53, Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, -(2**53+2), -(2**53), Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, 1.7976931348623157e308, -0x080000000]); ");
/*fuzzSeed-116066984*/count=284; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.hypot(Math.log1p(Math.fround(Math.acosh((-Number.MIN_SAFE_INTEGER ? ( + Math.log2(Number.MIN_VALUE)) : (Math.imul((x >>> 0), (Math.log2(y) >>> 0)) >>> 0))))), ( - ( ! ( + Math.abs(( + (( ! (x >>> 0)) | 0))))))); }); ");
/*fuzzSeed-116066984*/count=285; tryItOut("var fhrvdt = new SharedArrayBuffer(16); var fhrvdt_0 = new Uint8Array(fhrvdt); fhrvdt_0[0] = -13; var fhrvdt_1 = new Int16Array(fhrvdt); var fhrvdt_2 = new Uint16Array(fhrvdt); v1 = a2.length;return  '' ;");
/*fuzzSeed-116066984*/count=286; tryItOut("a1[v0] = e1;");
/*fuzzSeed-116066984*/count=287; tryItOut("\"use strict\"; print(x);a1.sort((function mcc_() { var tlsjrs = 0; return function() { ++tlsjrs; f0(/*ICCD*/tlsjrs % 2 == 1);};})(), v2);");
/*fuzzSeed-116066984*/count=288; tryItOut("testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x07fffffff, -0x080000001, 0x07fffffff, -1/0, 2**53-2, 0.000000000000001, -(2**53), 1/0, Math.PI, Number.MAX_VALUE, -0, 2**53+2, -0x080000000, 42, 0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, Number.MIN_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -(2**53+2), 0x080000000, -0x100000001, -0x0ffffffff, 0, 2**53]); ");
/*fuzzSeed-116066984*/count=289; tryItOut("\"use asm\"; var erfxrf = new ArrayBuffer(4); var erfxrf_0 = new Int16Array(erfxrf); print(erfxrf_0[0]); erfxrf_0[0] = -24; var erfxrf_1 = new Uint8Array(erfxrf); erfxrf_1[0] = 25; var erfxrf_2 = new Uint16Array(erfxrf); var erfxrf_3 = new Uint32Array(erfxrf); erfxrf_3[0] = -1; var erfxrf_4 = new Uint32Array(erfxrf); var erfxrf_5 = new Int8Array(erfxrf); var erfxrf_6 = new Int32Array(erfxrf); print(erfxrf_6[0]); erfxrf_6[0] = 25; var erfxrf_7 = new Int16Array(erfxrf); print(erfxrf_7[0]); this.g0 + t2;");
/*fuzzSeed-116066984*/count=290; tryItOut("(this);-3;");
/*fuzzSeed-116066984*/count=291; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.hypot(Math.fround(Math.max((x >>> 0), (Math.fround(y) == Math.atan2(Math.fround(0x0ffffffff), Math.fround(Math.fround(Math.max(x, x))))))), Math.fround((mathy0(Math.acosh(Math.atan2((Math.fround(( + x)) | 0), (x | 0))), Math.min(((Math.imul((x | 0), (x | 0)) | 0) != -1/0), ( + (x - x)))) >>> 0))), (((Math.tan(mathy0(Math.fround(mathy0(mathy0(y, x), (x | 0))), x)) >>> 0) <= ((( + ( + ( + (( ~ x) >>> 0)))) ? (((( - (( ~ (y | 0)) | 0)) >>> 0) > ((x , ( + Math.fround(( + x)))) | 0)) | 0) : mathy0(y, -0x080000001)) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0.000000000000001, -(2**53), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, 0x0ffffffff, Math.PI, -0x0ffffffff, 42, -0x07fffffff, Number.MAX_VALUE, -(2**53-2), -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, -0x100000000, -Number.MAX_VALUE, 1, 0x100000000, 0x080000000, 0x100000001, -0x080000001, 1.7976931348623157e308, 0x07fffffff, 2**53+2, -Number.MIN_VALUE, -(2**53+2), 2**53-2, 1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, 0/0]); ");
/*fuzzSeed-116066984*/count=292; tryItOut("h2 = {};");
/*fuzzSeed-116066984*/count=293; tryItOut("\"use strict\"; this.f2 = Proxy.createFunction(g0.h2, f2, f0);");
/*fuzzSeed-116066984*/count=294; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=295; tryItOut("/*infloop*/for(x in ((q => q)(w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(x), b =>  { return /*MARR*/[true,  /x/ , e,  /x/ , new Number(1),  /x/ , true, true,  /x/ , e, true,  /x/ , -3/0, -3/0, true, -3/0, e, -3/0, true,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1), true,  /x/ , new Number(1), e, -3/0, true, new Number(1), e, e,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , -3/0, true, true, -3/0,  /x/ ,  /x/ , e, true,  /x/ ,  /x/ ,  /x/ , new Number(1), -3/0, e, new Number(1),  /x/ , new Number(1), e,  /x/ , e, new Number(1), e, new Number(1), new Number(1), true, new Number(1), new Number(1), e, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), true, e,  /x/ , true, true, -3/0,  /x/ , -3/0, e, e,  /x/ , true,  /x/ ,  /x/ , -3/0, -3/0, -3/0]\u0009.sort(Object, 302699311.5) } , Math.asinh))))for (var v of b2) { try { i0.next(); } catch(e0) { } try { /*ODP-2*/Object.defineProperty(this.p0, \"clz32\", { configurable: (x % 2 != 1), enumerable: (x % 5 != 2), get: (function() { try { v2 = g2.eval(\"function f2(s0)  { return  ''  } \"); } catch(e0) { } try { h0.delete = (function(j) { if (j) { try { s0 += o0.s1; } catch(e0) { } v0 = t0.BYTES_PER_ELEMENT; } else { /*RXUB*/var r = r1; var s = true; print(uneval(s.match(r))); print(r.lastIndex);  } }); } catch(e1) { } try { x = i0; } catch(e2) { } e2.has(v2); throw a1; }), set: (function() { delete h2.has; return f0; }) }); } catch(e1) { } s0 += 'x'; }");
/*fuzzSeed-116066984*/count=296; tryItOut("s0 = new String;");
/*fuzzSeed-116066984*/count=297; tryItOut("a1 + i1;");
/*fuzzSeed-116066984*/count=298; tryItOut("a2 = r0.exec(s1);");
/*fuzzSeed-116066984*/count=299; tryItOut("mathy2 = (function(x, y) { return ( - ( - (Math.fround(mathy0(Math.fround(Math.pow(( + (Math.fround((0 >> x)) - y)), x)), Math.fround(x))) <= ((((y >>> 0) ** Math.fround(Math.tan(( + x)))) >>> 0) >>> 0)))); }); testMathyFunction(mathy2, [0x100000001, 0x080000001, 0x100000000, 0x07fffffff, -1/0, Math.PI, 2**53-2, -0x080000000, 1, 0/0, -0x0ffffffff, 0, 2**53, 0x080000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53+2, -(2**53), -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), -0x100000001, 42, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, -(2**53+2), -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -0, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=300; tryItOut("/*oLoop*/for (var oftzag = 0; oftzag < 0; ++oftzag) { M:if((x % 66 != 22)) {i2.send(t0);; } else  if (arguments) {v1.toString = (function() { try { neuter(b1, \"change-data\"); } catch(e0) { } try { x = g1.o0.i2; } catch(e1) { } Object.seal(g1.a0); throw s0; });yield  '' ; }\n-14;\n } ");
/*fuzzSeed-116066984*/count=301; tryItOut("mathy2 = (function(x, y) { return (mathy0(((Math.fround(Math.atanh(Math.fround(mathy1(Math.hypot(y, x), (x >>> 0))))) ? ((mathy0(( + ( ! ( + y))), (x >>> 0)) >>> 0) && Math.fround(( + Math.fround(Math.fround(Math.min(Math.exp(y), Math.fround(y))))))) : ((((y >>> 0) / (( + (-0x100000001 ? (y | 0) : (y | 0))) >>> 0)) >>> 0) >>> 0)) >>> 0), ( + (Math.atan2((x ** mathy1(( ! x), y)), Math.sinh((( - (0x100000000 | 0)) | 0))) <= ( + ( + Math.exp((y , y))))))) >>> 0); }); ");
/*fuzzSeed-116066984*/count=302; tryItOut("");
/*fuzzSeed-116066984*/count=303; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + Math.fround((mathy1(Math.tan(((Math.pow(mathy0(y, y), x) >>> 0) / y)), Math.expm1(Math.atan2((y >>> 0), Math.fround(y)))) , ( + ( ! x))))) | 0); }); testMathyFunction(mathy5, [-(2**53+2), -0x100000000, 1.7976931348623157e308, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, 42, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 0x07fffffff, 2**53-2, 0/0, -0x100000001, -0x0ffffffff, -(2**53-2), -Number.MIN_VALUE, -0x080000000, Math.PI, Number.MAX_VALUE, 0x080000000, 2**53, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1, 1/0, -0x07fffffff, 0x100000000, -0x080000001, 0, -(2**53), -0]); ");
/*fuzzSeed-116066984*/count=304; tryItOut("\"use strict\"; for (var p in g0) { try { v2 = t0.length; } catch(e0) { } this.v0 = g2.runOffThreadScript(); }");
/*fuzzSeed-116066984*/count=305; tryItOut("t2.toString = f2;");
/*fuzzSeed-116066984*/count=306; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.imul((Math.hypot((( + ((y >>> 0) < (Math.pow(( + Math.hypot(y, Math.fround(y))), ( + (((mathy2((x >>> 0), (-0x100000001 | 0)) >>> 0) >> ( + x)) >>> 0))) >>> 0))) >>> 0), (Math.cbrt((((((y >> y) | 0) <= (x | 0)) | 0) | 0)) >>> 0)) >>> 0), ((( - (Math.atanh(y) >>> 0)) >>> 0) | 0)) >>> 0); }); testMathyFunction(mathy3, [-(2**53-2), -Number.MIN_VALUE, 2**53+2, 0x07fffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, -0x100000000, -(2**53), Math.PI, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, Number.MIN_VALUE, 1/0, 1, -Number.MAX_VALUE, 0x100000000, -(2**53+2), 0x0ffffffff, 2**53-2, 0x100000001, -0x080000000, 42, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 2**53, -0, 0, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-116066984*/count=307; tryItOut("\"use strict\"; ;;");
/*fuzzSeed-116066984*/count=308; tryItOut("\"\\u0019\";this.i1 = t0[16];");
/*fuzzSeed-116066984*/count=309; tryItOut("\"use strict\"; o0.i1 + i1;");
/*fuzzSeed-116066984*/count=310; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.acosh(( + (mathy3(Math.asin(( + Number.MIN_SAFE_INTEGER)), Math.ceil((( - (Math.asin((Math.min(( ~ y), y) | 0)) | 0)) >>> 0))) >>> 0))); }); testMathyFunction(mathy4, ['\\0', /0/, (new Number(0)), (function(){return 0;}), (new String('')), '0', 1, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), undefined, objectEmulatingUndefined(), (new Number(-0)), [0], (new Boolean(false)), [], (new Boolean(true)), '', NaN, ({valueOf:function(){return 0;}}), false, true, '/0/', null, 0, -0, 0.1]); ");
/*fuzzSeed-116066984*/count=311; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?!\\\\u00Cf{2,})+((.{2,2})){3,3}+?[\\\\cO\\\\r-\\u00ea\\\\f-\\u3877\\\\W])\", \"im\"); var s = Math.atan2(((function too_much_recursion(clcuge) { ; if (clcuge > 0) { ; too_much_recursion(clcuge - 1);  } else {  }  })(1)),  /x/g .eval(\"\\\"use strict\\\"; const f0 = Proxy.createFunction(g1.h2, f1, f0);\")); print(s.search(r)); ");
/*fuzzSeed-116066984*/count=312; tryItOut("a0 = a0.concat(t0, t1, m0);");
/*fuzzSeed-116066984*/count=313; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=314; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Uint16ArrayView[((i1)) >> 1]) = (((yield y >>= this.x = ((void options('strict'))))));\n    i1 = (0xd1f8faae);\n    {\n      {\n        return +((((!(0xf950c95c))-(Object( /x/ , 'fafafa'.replace(/a/g, new Function))))));\n      }\n    }\n    d0 = ((((i1) ? (i1) : (0xcedcfd0a)) ? (0x40cd2b1c) : (i1)) ? (d0) : (9.0));\n    d0 = (-1073741825.0);\n    return +((-3.022314549036573e+23));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use asm\"; var pddopa = null; (function(y) { Object.defineProperty(g0, \"t1\", { configurable: false, enumerable: (pddopa % 4 == 0),  get: function() {  return t0.subarray(0, v0); } }); })(); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 0/0, 0, 1, 0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x07fffffff, -0x080000000, -0x100000001, 0x100000000, -0x100000000, 2**53, Number.MAX_SAFE_INTEGER, -0, 42, 0x0ffffffff, 2**53-2, 0x080000001, 1/0, -(2**53-2), 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000001, -1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, 2**53+2, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=315; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.sqrt(( + Math.hypot((Math.log1p((Math.sqrt((Math.pow(Math.fround(( - Math.fround(-0x100000000))), x) >>> 0)) >>> 0)) >>> 0), Math.ceil(x)))) | 0); }); testMathyFunction(mathy4, [-(2**53), -0x080000000, -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, 2**53+2, 2**53, 1.7976931348623157e308, -0, -0x080000001, 1, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 0.000000000000001, -0x100000001, 42, 0, -0x100000000, -Number.MIN_VALUE, 0x07fffffff, 0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, 0x080000001, 0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-116066984*/count=316; tryItOut("mathy3 = (function(x, y) { return Math.imul(Math.sqrt(mathy0(Math.max(mathy2(y, 1), x), ( + ( + ((y <= x) === (x > 0/0)))))), (( + (( + (( - Number.MIN_SAFE_INTEGER) >>> 0)) ? ( + (Math.pow(Math.fround(Math.fround(Math.fround(0x100000001))), 2**53-2) != x)) : Math.min(Math.sinh((y | 0)), y))) ? Math.fround(Math.pow(x, ((y <= (Math.cosh(((x < y) >>> 0)) | 0)) | 0))) : (y && (( ~ Number.MIN_VALUE) >>> 0)))); }); testMathyFunction(mathy3, [1/0, 0x080000000, -(2**53+2), -0x080000001, 2**53, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000000, 0, 0/0, 0x100000001, -0, Math.PI, 1.7976931348623157e308, 0x080000001, -Number.MAX_VALUE, 2**53+2, -(2**53-2), Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, 1, -0x07fffffff, 2**53-2, 42, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-116066984*/count=317; tryItOut("\"use asm\"; (void schedulegc(g2));");
/*fuzzSeed-116066984*/count=318; tryItOut("\"use asm\"; for (var v of t2) { try { for (var v of i0) { delete i0[\"__parent__\"]; } } catch(e0) { } try { v0 = new Number(Infinity); } catch(e1) { } try { Array.prototype.splice.apply(o1.a2, [10, 6, p2, o2, g1.g2.f0]); } catch(e2) { } Object.defineProperty(this, \"v2\", { configurable: true, enumerable: (x % 3 == 2),  get: function() {  return -Infinity; } }); }");
/*fuzzSeed-116066984*/count=319; tryItOut("/*MXX3*/g1.Number.isInteger = g0.Number.isInteger;");
/*fuzzSeed-116066984*/count=320; tryItOut("o0.v2 = g2.runOffThreadScript();");
/*fuzzSeed-116066984*/count=321; tryItOut("(window--.watch((4277), -18 % 23));");
/*fuzzSeed-116066984*/count=322; tryItOut("/*RXUB*/var r = /[^]{34359738369,34359738372}\\s?(?=(?=\\cK))(\u0777)(?=(?:.))|(?=(?=\\\u2dac|.*))*\\2+\\1\\B{0,4}[^\\cP-\\cW\ucfd0\\\u0f80-\u51ad\u1431]|(?:.|\\u7215)*?|(?=\\S|\\b[\\\u00df\\u00dD-\\u95C2\uf701]*|(?:\\cU))|[^]\\r/; var s = \"\\u000d\"; print(s.replace(r, a =>  { \"use strict\"; \"use asm\"; return new Boolean(true) } )); ");
/*fuzzSeed-116066984*/count=323; tryItOut("\"use strict\"; /*infloop*/L:for(d; ((makeFinalizeObserver('nursery'))); (void options('strict'))) {v2 = t0.length;a1 + ''; }");
/*fuzzSeed-116066984*/count=324; tryItOut("/*ADP-1*/Object.defineProperty(a2, 19, ({value: ({NaN:  /x/g  , new RegExp(\"(\\\\B.|[^\\\\d]\\\\cW+){1,5}\", \"i\")}), configurable: (x % 71 == 21)}));");
/*fuzzSeed-116066984*/count=325; tryItOut("print(( \"\" ([z1])) = (w in this));");
/*fuzzSeed-116066984*/count=326; tryItOut("let t0 = t1.subarray(10);");
/*fuzzSeed-116066984*/count=327; tryItOut("this.t1 = new Uint8ClampedArray(t2);Object.preventExtensions(t2);");
/*fuzzSeed-116066984*/count=328; tryItOut("mathy2 = (function(x, y) { return ( + ( ! Math.fround(Math.imul(Math.fround(( + Math.fround((Math.pow((Math.imul(x, x) >>> 0), (Math.log(x) >>> 0)) >>> 0)))), Math.fround(mathy1(Math.fround((Math.imul(y, x) ? Math.fround(( + Math.atan2(mathy0(( + 0x100000001), -0x0ffffffff), 0x080000001))) : Number.MAX_VALUE)), Math.fround((Math.fround((Math.fround(x) ? Math.fround(x) : y)) ? Math.log(y) : (( - (Math.imul(x, (( + (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)) >>> 0)) >>> 0))))))))); }); testMathyFunction(mathy2, /*MARR*/[undefined, true, undefined, true, undefined, true, undefined, undefined, true, true]); ");
/*fuzzSeed-116066984*/count=329; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.min(Math.fround(( + mathy1(( + (Math.fround((Math.fround(Math.min(( + y), Math.fround(( ~ y)))) - ( + Math.hypot(( + Math.fround(Math.log(Math.fround(y)))), ( + y))))) && ((( + ( ~ Math.fround(Math.hypot(y, (y | 0))))) , x) >>> 0))), ( + Math.asinh((x ** -0x080000000)))))), ( ! ((((x + 1) >>> 0) ? ((Math.cos(((y - x) | 0)) | 0) >>> 0) : Math.pow((( ~ 0/0) | 0), Math.hypot(( + -1/0), ( + x)))) >>> 0))) | 0); }); ");
/*fuzzSeed-116066984*/count=330; tryItOut("testMathyFunction(mathy0, [0, -0, -0x080000000, 0x100000001, 42, 1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -1/0, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, -0x100000000, 2**53, -(2**53+2), 0x07fffffff, 0x080000001, 0x080000000, 1, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 2**53-2, 0/0, -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=331; tryItOut("mathy5 = (function(x, y) { return Math.max(Math.fround(Math.asin(Math.pow(((( ! (y >>> 0)) >>> 0) - x), -0x080000001))), ( + ( ! ( + ((x >= x) >>> 0))))); }); testMathyFunction(mathy5, [-0x100000001, 0/0, -(2**53+2), -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, Number.MIN_VALUE, 1, -0x080000000, 0x0ffffffff, -0, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, -(2**53), 2**53, 0x100000000, 1/0, -0x080000001, 0x07fffffff, -1/0, Math.PI, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=332; tryItOut("v2 = g2.runOffThreadScript();\ni2.next();\n");
/*fuzzSeed-116066984*/count=333; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a1, allocationMarker(), ({enumerable: (x % 26 == 23)}));");
/*fuzzSeed-116066984*/count=334; tryItOut("e0.delete(s0);");
/*fuzzSeed-116066984*/count=335; tryItOut("\"use strict\"; \"use asm\"; for(window = ({} = \u3056 != z) in null) {print(x);print(x); }");
/*fuzzSeed-116066984*/count=336; tryItOut("\"use strict\"; testMathyFunction(mathy2, [42, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, 0x100000000, -0x100000000, 1/0, 1, 2**53, -(2**53-2), -Number.MAX_VALUE, 0x0ffffffff, -1/0, 0x080000000, -0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0.000000000000001, -(2**53), 0/0, 2**53+2, 0, Number.MIN_VALUE, -0x0ffffffff, -0, 0x07fffffff, -0x080000001, 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI]); ");
/*fuzzSeed-116066984*/count=337; tryItOut("\"use strict\"; y;\n[];\n");
/*fuzzSeed-116066984*/count=338; tryItOut("/*infloop*/L:for(var z = [1]; /*MARR*/[(decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (-1/0), (-1/0), (-1/0), (decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (-1/0), (decodeURIComponent).call(this, x, false), (-1/0), (-1/0), (decodeURIComponent).call(this, x, false), (-1/0), (-1/0), (decodeURIComponent).call(this, x, false), (-1/0), (decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (decodeURIComponent).call(this, x, false), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (decodeURIComponent).call(this, x, false), (-1/0), (-1/0), (decodeURIComponent).call(this, x, false), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (decodeURIComponent).call(this, x, false), (-1/0), (-1/0), (decodeURIComponent).call(this, x, false), (-1/0), (-1/0), (-1/0)].filter(/*RXUE*/new RegExp(\"(?=\\\\B+?){65,}\", \"\").exec(\"\"), Object.defineProperty(b, \"sub\", ({writable: (x % 6 == 3), configurable: true, enumerable: (x % 4 != 1)}))); (4277)) {a2.unshift(o0.g0.o1.o2.e2); }");
/*fuzzSeed-116066984*/count=339; tryItOut("v2 = Object.prototype.isPrototypeOf.call(a0, m0);");
/*fuzzSeed-116066984*/count=340; tryItOut("mathy1 = (function(x, y) { return ( + Math.exp(( + Math.atan2((Math.round((Math.clz32(( ! y)) | 0)) | 0), ((mathy0((( + ( ~ Math.fround(Math.tanh(( + ( + (Math.cosh(-1/0) >>> 0))))))) | 0), (x | 0)) | 0) >>> 0))))); }); testMathyFunction(mathy1, [undefined, (function(){return 0;}), true, (new Number(-0)), 0.1, [], '\\0', (new Boolean(false)), (new String('')), objectEmulatingUndefined(), '', null, ({valueOf:function(){return '0';}}), '/0/', ({valueOf:function(){return 0;}}), 0, (new Number(0)), (new Boolean(true)), ({toString:function(){return '0';}}), -0, 1, NaN, '0', [0], false, /0/]); ");
/*fuzzSeed-116066984*/count=341; tryItOut("mathy2 = (function(x, y) { return Math.log10((Math.acosh(Math.cosh((((y | 0) >= ((y - (x >>> 0)) >>> 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), undefined, '0', ({toString:function(){return '0';}}), [], (new Boolean(true)), /0/, -0, '/0/', 0, (function(){return 0;}), 0.1, null, [0], ({valueOf:function(){return '0';}}), true, false, (new String('')), (new Boolean(false)), '', objectEmulatingUndefined(), (new Number(-0)), NaN, 1, (new Number(0)), '\\0']); ");
/*fuzzSeed-116066984*/count=342; tryItOut("/*RXUB*/var r = new RegExp(\"^{3,}|\\\\B|(?=(?:(?=\\\\d[^\\u00f5\\u00f9\\\\\\u0095\\\\W])|^^*?.{3})|\\\\b|(?=$))\", \"gm\"); var s = \"\\n\\nH\\n\\n\\n\\u8d46\\n\\n\\u8d46\\n\\n\\u8d46\\n\\n\\u8d46\\n\\n\\u8d46\\n\\n\\u8d46\\n\\n\\u8d46\\n\\n\\u8d46\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=343; tryItOut("\"use strict\"; v1 = o1.a1.reduce, reduceRight(f1, o0.s2);");
/*fuzzSeed-116066984*/count=344; tryItOut("g0 + '';");
/*fuzzSeed-116066984*/count=345; tryItOut("\"use strict\"; v0 = evalcx(\"function f0(f1)  { yield String.prototype.strike.prototype } \", g2);");
/*fuzzSeed-116066984*/count=346; tryItOut("/*RXUB*/var r = /(?:(?!\\2|\\3*\u4e3b+?\\s*))/gy; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=347; tryItOut("\"use strict\"; return x;\u000ctry { return x ** x; } finally { (((function factorial(vnmpgc) { ; if (vnmpgc == 0) { ; return 1; } v2 = Infinity;; return vnmpgc * factorial(vnmpgc - 1);  })(0)))(eval(\"print(x);\")) = b; } ");
/*fuzzSeed-116066984*/count=348; tryItOut("g2.e1.add(i0);delete f1[\"search\"];");
/*fuzzSeed-116066984*/count=349; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return Math.log10(( + ((( ~ (x * Math.sign(( + (0x100000000 !== -(2**53-2)))))) >>> 0) == (Math.atan2(Math.trunc(( ~ Math.fround(Math.tan((Math.asinh(y) >>> 0))))), Math.atan2(x, ( + 1))) | 0)))); }); testMathyFunction(mathy3, [-0x100000001, 0, 1, 1.7976931348623157e308, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0, 0.000000000000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -1/0, 0x080000001, -(2**53+2), 1/0, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, -0x07fffffff, Math.PI, 2**53+2, 42, 0x07fffffff, 0x100000001, Number.MAX_VALUE, 2**53-2, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, 0/0, -(2**53), -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=350; tryItOut("\"use strict\"; {o0 = new Object;try { this.zzz.zzz; } catch(x) { for(let y in []); } finally { e = x; }  }");
/*fuzzSeed-116066984*/count=351; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=352; tryItOut("s2 += 'x';");
/*fuzzSeed-116066984*/count=353; tryItOut("a2.pop();");
/*fuzzSeed-116066984*/count=354; tryItOut("\"use strict\"; t1[-21.unwatch(\"UTC\")] = e0;");
/*fuzzSeed-116066984*/count=355; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return Math.log(((Number.MIN_SAFE_INTEGER === Math.imul(( + ( + y)), (x / Math.cosh(Math.fround(y))))) ? ( + Math.sinh((Math.max(print(y);, Math.fround(y)) | 0))) : ((Math.fround(-(2**53)) != Math.fround(Math.sign((((( + Number.MAX_SAFE_INTEGER) | 0) % (mathy0(( + Math.acosh(( + 0x080000001))), 0/0) | 0)) | 0)))) >>> 0))); }); ");
/*fuzzSeed-116066984*/count=356; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1/g; var s = \"\\n\"; print(r.test(s)); ");
/*fuzzSeed-116066984*/count=357; tryItOut("for (var v of b1) { h1.get = (function() { for (var j=0;j<80;++j) { g2.f1(j%5==1); } }); }");
/*fuzzSeed-116066984*/count=358; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.sinh((Math.fround((Math.ceil(y) || (Math.max(x, (Math.imul(x, Math.ceil(( - ( + y)))) >>> 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), 42, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -1/0, 0.000000000000001, -(2**53+2), 0, 0x0ffffffff, -0x080000001, Number.MAX_VALUE, -0x100000001, -(2**53), 2**53, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, -0, 0/0, 1.7976931348623157e308, 0x100000000, 0x080000001, 1/0, -0x080000000, Math.PI, 0x080000000, 1, 0x100000001]); ");
/*fuzzSeed-116066984*/count=359; tryItOut("var plzrto, zynudo, y, d, xodqmx, window, qejram;(new RegExp(\"((?!(\\\\b)))|.\", \"i\"));yield;");
/*fuzzSeed-116066984*/count=360; tryItOut("testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-116066984*/count=361; tryItOut("v2 = Array.prototype.reduce, reduceRight.call(a1, (function(j) { if (j) { try { i0 = new Iterator(h0, true); } catch(e0) { } s1 += this.s0; } else { /*ODP-3*/Object.defineProperty(t0, \"4\", { configurable: (new ((this.__defineGetter__\u0009(\"x\", arguments)))((4277))), enumerable: false, writable: (x % 4 == 3), value: this.i1 }); } }));");
/*fuzzSeed-116066984*/count=362; tryItOut("testMathyFunction(mathy5, [0, -0, 0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, -(2**53+2), -Number.MIN_VALUE, 1, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, 2**53, Number.MAX_VALUE, 1/0, -(2**53-2), -0x080000000, 0x100000001, Math.PI, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -0x080000001, 2**53+2, -1/0, -0x100000000, 42, 2**53-2, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=363; tryItOut("/*infloop*/for(var ({x, a, d, x: [, , [[x], , {x: {}}, {w: {}, x, \u3056}], ], w: [x, , {c, x: [, ], x: {c: \u0009[b, {w: w}], e: {y: a}}, x}]}) in ((Set.prototype.has)((DataView.prototype.getFloat64)(this).eval(\"/* no regression tests found */\"))))\u0009o0.p1 + b2;");
/*fuzzSeed-116066984*/count=364; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=365; tryItOut("/*infloop*/do {for (var v of v1) { try { Array.prototype.splice.apply(a0, [NaN, 12, g2, /[\\{-\u00b9\\b][^]/gi]); } catch(e0) { } try { v1 = a0.length; } catch(e1) { } try { e1.add(g0.m0); } catch(e2) { } v1 = Array.prototype.some.apply(a0, [(function() { try { g0.v0 = false; } catch(e0) { } try { m0.get(\"\\uA86B\"); } catch(e1) { } a1 = []; return b1; })]); }this.e1 = new Set(f0); } while((4277));");
/*fuzzSeed-116066984*/count=366; tryItOut("let (\u000cx = this, [] = x, ugjgah, z, b) { v2 = evaluate(\"(\\u3056 = new RegExp(\\\"(?!(?:(?=[^\\\\\\\\x5b-\\\\\\\\u00b2\\\\u00ea-\\\\\\\\u00d5]{1}\\\\\\\\B{0,2}|[^]{2})))+\\\", \\\"gm\\\"))\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 16 != 13), noScriptRval: (x % 109 == 73), sourceIsLazy:  /x/ , catchTermination: false })); }");
/*fuzzSeed-116066984*/count=367; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: (x % 50 != 21), enumerable: false,  get: function() {  return evalcx(\"v1 = a0[/*FARR*/[].filter];\", this.g2); } });");
/*fuzzSeed-116066984*/count=368; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.hypot(( + (( ! Math.asinh(Math.sinh(Math.min((Math.sqrt(Math.fround(x)) >>> 0), ( - (Math.fround(Math.imul(y, Math.fround(2**53+2))) | 0)))))) >>> 0)), Math.atan2((( ~ ( + y)) >>> 0), Math.atan2(( + y), (Math.hypot(y, ((Math.pow((y >>> 0), (y >>> 0)) || y) >>> 0)) | 0)))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 1/0, 0x080000000, -0x0ffffffff, 0, 0x080000001, Math.PI, -(2**53), -Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, 0/0, -0x080000001, 2**53, 0x100000000, 2**53-2, 1, Number.MAX_VALUE, 2**53+2, 0x100000001, -(2**53-2), -0, 0x07fffffff]); ");
/*fuzzSeed-116066984*/count=369; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=370; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ((( + x) * (( ! (mathy0(x, x) | 0)) | 0)) ? ( + ( + Math.cbrt(( + (Math.cos(y) == -1/0))))) : (( + (Math.min(-Number.MIN_SAFE_INTEGER, Math.log(x)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-116066984*/count=371; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.min(Math.fround(Math.hypot(((x < y) + y), Math.cos((Math.imul((-Number.MAX_VALUE >>> 0), (( + Math.atan2((x >>> 0), (Math.fround(Math.atan2(Math.fround(y), ( + ((y >>> 0) * x)))) | 0))) >>> 0)) >>> 0)))), Math.fround(Math.tan(((( - Math.fround((( + ( ~ ( + x))) <= Math.fround(-0x100000000)))) != Math.fround(Math.min(x, Math.fround(Math.min(( + Math.fround(Math.atan2(y, Math.PI))), ( + (( + ( ~ ( + y))) != x))))))) | 0))))); }); testMathyFunction(mathy0, [-(2**53), 2**53-2, 0x100000000, 2**53, 0x080000000, 2**53+2, -0x0ffffffff, -Number.MAX_VALUE, Math.PI, -0x080000000, 0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, -0, -1/0, -(2**53+2), Number.MAX_VALUE, 0/0, -0x100000000, -0x080000001, 0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 42, -Number.MIN_VALUE, 1/0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-116066984*/count=372; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.max(((Math.atan2(( + (( + Math.imul(x, (y | 0))) ? (( - x) | 0) : x)), ((x === (x - -0x100000000)) >>> 0)) >>> 0) ? ( + Math.ceil(( + (y !== y)))) : Math.hypot(1/0, ( + ( ~ 0x080000000)))), Math.fround(( + ( + -0x100000000)))) / ((Math.fround((( + (( + x) > ( + mathy0(x, ( + x))))) % ( + (mathy0((Math.hypot(x, y) >>> 0), ((y + y) >>> 0)) >>> 0)))) ? (( + (Math.atanh(( + -1/0)) + y)) >>> 0) : ((( + (( + (y & ( + mathy0(x, Math.fround(y))))) != ( + x))) && Math.fround(x)) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, 2**53-2, -(2**53+2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, 1, -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, 42, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, 0/0, 2**53+2, -1/0, Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, -0, 0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, 1/0, 0x100000001]); ");
/*fuzzSeed-116066984*/count=373; tryItOut("let(z) { for(let x in []);}");
/*fuzzSeed-116066984*/count=374; tryItOut("const x = ({ get \"24\"()\"use asm\";   var imul = stdlib.Math.imul;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    i1 = (i1);\n    (Uint32ArrayView[2]) = ((i1)+(((((Float64ArrayView[2]))*0x81cd3) ^ ((1)+((((0xfe9eb9bd)) | ((0xd443f9b))))+(!(i0)))) == (((i1)+(!(i1))) ^ (((Float32ArrayView[1]))-(i1)))));\n    i1 = (i1);\n    i1 = ((imul((i0), (i0))|0) <= (~~(-562949953421313.0)));\n    i0 = (i0);\n    i0 = (i0);\n    return +((((+(1.0/0.0))) * ((0.001953125))));\n  }\n  return f;, setUTCDate:  /x/g  });(\u000c-0.626);");
/*fuzzSeed-116066984*/count=375; tryItOut("const b = (x), d = ;var g1.m2 = new Map;");
/*fuzzSeed-116066984*/count=376; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max(Math.fround((Math.fround(Math.pow(( + Math.sign(Math.round(y))), ( + ((x !== ( - x)) ? (y | 0) : (y | 0))))) * Math.fround(( - Math.fround((Math.abs(Math.imul((y >>> 0), 0x080000001)) | 0)))))), Math.fround((((Math.fround(Math.trunc((Math.min((y | 0), ( + ( - (x ^ y)))) / (((-0x080000001 | 0) % (Math.pow(x, (( ! (0x100000000 | 0)) | 0)) | 0)) >>> 0)))) >>> 0) < (Math.fround(Math.max(( ! ((x | 0) % (y >>> 0))), ( + x))) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [0, 2**53+2, -Number.MIN_VALUE, 1/0, 0x100000001, 2**53-2, 0.000000000000001, Number.MAX_VALUE, -0x0ffffffff, 0/0, 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53), 2**53, -0, 1, -0x100000000, -(2**53-2), -0x080000000, -(2**53+2), -0x080000001, -1/0, 0x080000001, 0x080000000, 0x100000000, 42, -0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=377; tryItOut("v1 = evalcx(\"(-17)((x++))\", o2.g1);");
/*fuzzSeed-116066984*/count=378; tryItOut("s1 = s1.charAt(12);");
/*fuzzSeed-116066984*/count=379; tryItOut("\"use strict\"; for (var v of p1) { try { /*MXX2*/g0.Function.prototype.caller = this.o1.g2.a0; } catch(e0) { } try { /*ODP-1*/Object.defineProperty(g0, \"min\", ({value: (new Set((/*MARR*/[Infinity, new Number(1), ['z'], new Number(1), ['z'], Infinity, Infinity, function(){}, (0/0), (0/0), (0/0), Infinity, (0/0), new Number(1), ['z'], Infinity, (0/0), Infinity, function(){}, ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], function(){}, new Number(1), Infinity].filter))), writable: (x % 6 != 1), configurable: function(y) { yield y; p0.toString = (new Function(\"(false);\"));; yield y; }, enumerable: [true.__defineSetter__(\"x\", x)] >>>= -1307008277})); } catch(e1) { } Array.prototype.push.call(a2, e0); }");
/*fuzzSeed-116066984*/count=380; tryItOut("i0.next();");
/*fuzzSeed-116066984*/count=381; tryItOut("((4277) >> [[]]);");
/*fuzzSeed-116066984*/count=382; tryItOut("this.b0 + b1;");
/*fuzzSeed-116066984*/count=383; tryItOut("a0.push(this.f0, p1);");
/*fuzzSeed-116066984*/count=384; tryItOut("/*oLoop*/for (var ebyevs = 0; ebyevs < 12 && ([x]); ++ebyevs) { Object.freeze(p1); } ");
/*fuzzSeed-116066984*/count=385; tryItOut("/*infloop*/xdo {var r0 = x | x; var r1 = 5 & r0; var r2 = r0 - x; var r3 = 6 & 8; print(r3); var r4 = r3 - 4; var r5 = r4 ^ r1; var r6 = 7 & r4; var r7 = r0 % r4; var r8 = r4 / 2; print(x); var r9 = r2 / r2; var r10 = r7 + 2; r3 = 3 ^ r4; var r11 = r4 + r8; var r12 = 9 & 4; r11 = r0 | 2; var r13 = x | r9; var r14 = r1 - 3; r2 = r14 ^ 3; var r15 = r10 + 3; var r16 = r11 | r5; var r17 = r3 * x; r15 = 8 % r4; var r18 = r2 / 1; r3 = 7 & r8; var r19 = r11 * r12; r17 = r18 - 0; r11 = r9 & 9; /*tLoop*/for (let x of /*MARR*/[(0x50505050 >> 1), new String('q'), (0x50505050 >> 1), -0x080000000, (0x50505050 >> 1), (0x50505050 >> 1), new String('q'), (0x50505050 >> 1), new String('q'), (0x50505050 >> 1), new String('q'), new String('q'), new String('q'), -0x080000000, (0x50505050 >> 1), new String('q'), (0x50505050 >> 1), -0x080000000, new String('q'), -0x080000000, -0x080000000, -0x080000000, (0x50505050 >> 1), (0x50505050 >> 1), -0x080000000, -0x080000000, new String('q'), new String('q'), new String('q'), (0x50505050 >> 1), (0x50505050 >> 1), new String('q'), -0x080000000, -0x080000000, (0x50505050 >> 1), (0x50505050 >> 1), -0x080000000, (0x50505050 >> 1), (0x50505050 >> 1), new String('q'), -0x080000000, -0x080000000, -0x080000000]) { return; } } while(((function factorial_tail(cfrpgb, arwctn) { {}(false);; if (cfrpgb == 0) { ; return arwctn; } ; return factorial_tail(cfrpgb - 1, arwctn * cfrpgb); (void schedulegc(g0));function z(w, x, x, \u3056, x, x, x, eval = null, b, b = \"\\u34EB\", b = new RegExp(\".(?:[^\\\\x7a-\\u00a4])+?|(?!(?!.)\\\\B)|(\\\\b[^\\\\S])+|$?\", \"\"), NaN, x, x, y = z, b, x, d, \u3056, eval, x, x, this.x, window, w, x, c, x, z, x, x, window, x, window, x, w, d, window, w, NaN, \u3056, e = 10, x, window = Math, c, z, \u3056, window, z, d, c, x, x = \"\\u6AE4\")\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 9007199254740992.0;\n    var i3 = 0;\n    var d4 = 73786976294838210000.0;\n    i3 = (!(0x50d2f842));\n    d0 = (d1);\n    d1 = (d4);\n    {\n      d4 = (2049.0);\n    }\n    d1 = (-1048576.0);\n    return +((295147905179352830000.0));\n  }\n  return f;print(b1); })(64716, 1)));");
/*fuzzSeed-116066984*/count=386; tryItOut("\"use strict\"; for(y = x = Proxy.createFunction(({/*TOODEEP*/})(true), ( /x/g ).bind, arguments.callee).__defineSetter__(\"b\", decodeURI) in this.a) /*ADP-2*/Object.defineProperty(a1, 6, { configurable: true, enumerable: Object.defineProperty(w, \"indexOf\", ({get: (Object.setPrototypeOf).call, set: JSON.stringify})), get: (function() { for (var j=0;j<0;++j) { f2(j%5==1); } }), set: (function(j) { if (j) { try { e2.has(b2); } catch(e0) { } try { o1.v1 = Object.prototype.isPrototypeOf.call(g0.e0, e1); } catch(e1) { } try { v1 = Object.prototype.isPrototypeOf.call(i0, o2); } catch(e2) { } g2.offThreadCompileScript(\"Array.prototype.forEach.apply(a2, [(function(j) { if (j) { try { /*MXX2*/g0.DFGTrue.length = b0; } catch(e0) { } o0.a1.splice(NaN, true.unwatch(\\\"toSource\\\")\\u000c.throw(x)); } else { try { o0 + ''; } catch(e0) { } try { s1 += 'x'; } catch(e1) { } (void schedulegc(g2)); } }), b0]);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (void options('strict_mode'))(y * false, d), catchTermination: 7.throw(\"\\u17EB\"), elementAttributeName: s0, sourceMapURL: s1 })); } else { try { for (var v of e2) { try { v1 = g0.eval(\"o2.g0.m0 = new Map;\"); } catch(e0) { } v1 = Object.prototype.isPrototypeOf.call(o0, s2); } } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(g2, b1); } catch(e1) { } i1.next(); } }) });");
/*fuzzSeed-116066984*/count=387; tryItOut("mathy4 = (function(x, y) { return Math.tanh(((( ! Math.min(y, (Math.imul(( + (( + (( + -0x07fffffff) + ( + y))) >>> 0)), Math.fround(Math.max(x, y))) | 0))) | 0) | 0)); }); testMathyFunction(mathy4, [objectEmulatingUndefined(), (new String('')), true, NaN, [], (new Boolean(false)), '\\0', 0.1, (new Boolean(true)), ({valueOf:function(){return 0;}}), [0], null, 1, '0', -0, (new Number(-0)), /0/, false, 0, undefined, '/0/', ({toString:function(){return '0';}}), (new Number(0)), ({valueOf:function(){return '0';}}), (function(){return 0;}), '']); ");
/*fuzzSeed-116066984*/count=388; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(\\\\3{4294967297,})\", \"y\"); var s = \"\\n\\u3173\\n\\na U1\\u00fb1\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=389; tryItOut("mathy1 = (function(x, y) { return Math.fround(mathy0(( + Math.atan(( ~ x))), Math.fround(Math.cbrt(Math.atanh(((x | ((Math.min((y && y), y) | 0) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy1, [-1/0, -0x100000001, 0x080000000, 0x080000001, Number.MAX_VALUE, -(2**53), -0x080000000, 0, 0x07fffffff, -0x100000000, 0x100000001, 1.7976931348623157e308, -(2**53+2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 0/0, -Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, -(2**53-2), 42, 0.000000000000001, -0x0ffffffff, 2**53+2, Math.PI, 2**53, 0x100000000, Number.MIN_SAFE_INTEGER, -0, 1, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=390; tryItOut("v1 = evalcx(\"/* no regression tests found */\", g0);");
/*fuzzSeed-116066984*/count=391; tryItOut("\"use strict\"; yield /*FARR*/[...[], eval, ...[], ...[]].map;(x) = b;");
/*fuzzSeed-116066984*/count=392; tryItOut("/*infloop*/L:for(var (y) in ((function(y) { /*infloop*/L:for(let e in /\\B|(($)){0}\\B|\\1$/yim) (x); })(Math.max(-25, -16) -= ( \"\" )(x))))a0.forEach((function() { for (var j=0;j<7;++j) { f1(j%4==1); } }));");
/*fuzzSeed-116066984*/count=393; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=394; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.hypot((( - (mathy0((( ! Math.round(x)) | 0), (Math.imul(y, ( + ( ! ( + y)))) | 0)) | 0)) >>> 0), ((( + Math.fround((( + Math.trunc((Math.acos(Math.fround(( ~ (x | 0)))) | 0))) >= ( + Math.sign(x))))) >>> 0) | 0)); }); ");
/*fuzzSeed-116066984*/count=395; tryItOut("h2.hasOwn = f2;");
/*fuzzSeed-116066984*/count=396; tryItOut("mathy4 = (function(x, y) { return Math.imul(mathy2(( ~ ((( + x) >>> 0) != (( ! x) | 0))), (Math.sinh((Math.atanh((Math.fround(x) - Math.fround(((y | 0) , (0.000000000000001 >>> 0))))) >>> 0)) | 0)), (Math.atanh((false >>> 0)) | 0)); }); testMathyFunction(mathy4, [-0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, -(2**53+2), 2**53+2, Math.PI, -Number.MAX_VALUE, 0x080000001, 0x07fffffff, 1/0, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -(2**53-2), -0x0ffffffff, 0x0ffffffff, 0.000000000000001, 0x080000000, 0x100000001, -0x100000001, 1, 42, Number.MIN_VALUE, 2**53-2, 0x100000000, -(2**53), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 0, Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-116066984*/count=397; tryItOut("testMathyFunction(mathy1, [2**53-2, 0x100000000, Number.MIN_VALUE, -1/0, -(2**53+2), 0x07fffffff, 0x0ffffffff, -0x080000000, -0x07fffffff, 2**53, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -0, -0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, 1, 0/0, -(2**53-2), 2**53+2, 1/0, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), -0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, 0x080000001, 0x080000000, 42, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=398; tryItOut("a1.splice(NaN, 16);");
/*fuzzSeed-116066984*/count=399; tryItOut("\"use strict\"; { void 0; void gc('compartment', 'shrinking'); } v0 = Array.prototype.every.call(g1.a2, (function() { for (var j=0;j<64;++j) { o2.f0(j%3==1); } }), p0);");
/*fuzzSeed-116066984*/count=400; tryItOut("\"use strict\"; a1.push(o2.m1, this.i2, i2, p2);");
/*fuzzSeed-116066984*/count=401; tryItOut("h1 = x;");
/*fuzzSeed-116066984*/count=402; tryItOut("\"use strict\"; i0 = new Iterator(i2, true);");
/*fuzzSeed-116066984*/count=403; tryItOut("testMathyFunction(mathy1, [-Number.MAX_VALUE, -0x100000001, 1, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, 1/0, 2**53, -(2**53), 42, -1/0, -0x100000000, 2**53-2, 0x080000000, 1.7976931348623157e308, -(2**53-2), 0x100000001, Math.PI, 2**53+2, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, 0x080000001, 0.000000000000001, 0, Number.MAX_VALUE, -0x080000000, 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=404; tryItOut("\"use strict\"; s2 += this.s0;");
/*fuzzSeed-116066984*/count=405; tryItOut("for (var p in b2) { try { h0 = {}; } catch(e0) { } m1.has(b2); }");
/*fuzzSeed-116066984*/count=406; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 1.9342813113834067e+25;\n    d1 = (+(((!(!(0xffc30b12))))>>>((i2)-(0xffffffff)-(-0x8000000))));\n    {\n      d3 = (+((((i2) ? (0xbcc5a27) : (0xfab7eec5)))|0));\n    }\n    d1 = ((-72057594037927940.0) + (+(1.0/0.0)));\n    d1 = (((Float64ArrayView[0])) - ((d1)));\n    {\n      d3 = (((Float32ArrayView[0])) / ((d3)));\n    }\n    return +((d3));\n    d0 = (d3);\n    return +((-34359738369.0));\n    i2 = ((((0x79c7ffd5)) & (-(0xfe06dc35))) == (((0xf8ee0b1e)) >> (((0x33a1987e) != ((d0)))+(0x2e2452bc)-((0x689c4b0f) == (((0xfbee28be)-(0xfbad07db)+(0x616a3230))|0)))));\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: Date.prototype.toGMTString}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [1, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, -1/0, 0x100000001, 0x100000000, -0x100000000, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, 0x080000000, -0x07fffffff, Number.MIN_VALUE, -(2**53-2), 2**53+2, -(2**53+2), 0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, -0x100000001, 2**53-2, Math.PI, 1.7976931348623157e308, 0/0, 0, 0x0ffffffff, -0]); ");
/*fuzzSeed-116066984*/count=407; tryItOut("\"use strict\"; g0 = this;\ng2.offThreadCompileScript(\"var xkgzfe = new ArrayBuffer(0); var xkgzfe_0 = new Int8Array(xkgzfe); print(xkgzfe_0[0]); xkgzfe_0[0] = -22; var xkgzfe_1 = new Uint32Array(xkgzfe); print(xkgzfe_1[0]); var xkgzfe_2 = new Uint32Array(xkgzfe); xkgzfe_2[0] = 0; var xkgzfe_3 = new Int32Array(xkgzfe); print(xkgzfe_3[0]);a2[17];t2 = new Int16Array(b2);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: ((4277) << x), noScriptRval: (x % 83 != 67), sourceIsLazy: (true.__defineGetter__(\"y\", undefined)) &= ((function sum_slicing(tukihn) { ; return tukihn.length == 0 ? 0 : tukihn[0] + sum_slicing(tukihn.slice(1)); })(/*MARR*/[new Number(1.5),  /x/g ,  /x/g , -Infinity, 2**53,  /x/g , 2**53, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, 2**53,  /x/g , new Number(1.5), 2**53, -Infinity, -Infinity,  /x/g , -Infinity, new Number(1.5),  /x/g , -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity,  /x/g , -Infinity, -Infinity, -Infinity, new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), 2**53, -Infinity,  /x/g ,  /x/g , -Infinity, -Infinity,  /x/g , -Infinity,  /x/g , new Number(1.5), -Infinity, -Infinity,  /x/g ,  /x/g , new Number(1.5), new Number(1.5), 2**53, 2**53, new Number(1.5), 2**53, 2**53, 2**53, new Number(1.5),  /x/g ,  /x/g , new Number(1.5),  /x/g , -Infinity, 2**53, -Infinity])), catchTermination: false }));\n");
/*fuzzSeed-116066984*/count=408; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    i0 = (i1);\n    i0 = (((((0x0) >= (0x1c232132))) << ((abs((~(((4503599627370497.0) == (2.4178516392292583e+24))+(!(i1)))))|0) % ((( \"\" )) ^ ((i1))))));\nprint([6]);    i0 = (/*FFI*/ff()|0);\n    switch ((abs((((0x56ea826c)+(0xff8ae8e5)-(0xc33e48a)) >> ((0xca3316bf)+(0xfc6c1c09))))|0)) {\n      case 0:\n        i0 = (((~(-(i0))) > (( '' ) << (0x6fa1c*(/*FFI*/ff(((abs((0x6e720ebd))|0)))|0)))) ? ((+abs(((-4.835703278458517e+24)))) >= (7.737125245533627e+25)) : (i1));\n        break;\n    }\n    return +((-268435455.0));\n    return +((4503599627370497.0));\n    {\n      i0 = (i1);\n    }\n    i1 = (i1);\n    (Uint32ArrayView[((i0)) >> 2]) = ((i1));\n    {\n      i1 = (((-1.1805916207174113e+21) <= (-4.835703278458517e+24)) ? (i1) : (i0));\n    }\n    i0 = (-0x8000000);\n    i1 = (i1);\n    return +((-7.737125245533627e+25));\n  }\n  return f; })(this, {ff: arguments.callee.caller.caller}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-1/0, Number.MAX_VALUE, 0, 1, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, 0x100000000, -Number.MIN_VALUE, -0x080000001, 2**53, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0.000000000000001, 0x0ffffffff, 2**53+2, 0x080000000, -Number.MAX_VALUE, -0, -0x100000000, 1/0, -0x07fffffff, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), 42, 0x080000001, -(2**53), 2**53-2, -0x100000001, 0x07fffffff, Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=409; tryItOut("/*RXUB*/var r = new RegExp(\"(?!([\\\\cP-\\u00b4]\\\\2(?=\\\\2)*))+\", \"gy\"); var s = \"[[\\n\\n\\n\\n\\n\\n[\\n[\\n[[\\n\\n\\n\\n\\n\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=410; tryItOut("mathy3 = (function(x, y) { return Math.log2(Math.imul((( + ( ~ -0)) ? ( + Math.min(( + (y % -(2**53+2))), ( + -0x080000001))) : (( ~ x) | 0)), mathy1((( ! (Math.fround((Math.fround(y) != y)) >>> 0)) | 0), ((Math.fround(y) || ( + mathy2(( + 0x07fffffff), ( + (Math.abs(y) * -0x07fffffff))))) >>> 0)))); }); testMathyFunction(mathy3, [0/0, -(2**53-2), 2**53+2, 42, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, 2**53, -0x0ffffffff, -0x07fffffff, 0x080000000, 1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, 1, 0x080000001, 2**53-2, -0x100000001, 0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), -0x100000000, 0x07fffffff, -(2**53), Math.PI, -1/0, -0x080000001, 0x100000001, 0]); ");
/*fuzzSeed-116066984*/count=411; tryItOut("if(false) Array.prototype.reverse.call(o2.a1); else  if (undefined) {g2.v1 = (x % 2 == 1);print( \"\" ); }");
/*fuzzSeed-116066984*/count=412; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((( - Math.max(x, Math.atan2(Math.max(y, y), ( + y)))) | 0) ? ((((Math.sign((Math.sign((Math.fround(Math.asinh(Math.fround(y))) >>> 0)) ** -0x07fffffff)) >>> 0) / ((Math.ceil((Math.atan2(( + Math.imul(( + x), x)), (((mathy0(y, x) || y) | 0) >>> x)) >>> 0)) >>> 0) | 0)) | 0) | 0) : (Math.clz32(Math.fround(( ! Math.round(Math.fround(mathy0(Math.fround(mathy0((y >>> 0), (y >>> 0))), y)))))) | 0)); }); testMathyFunction(mathy1, [-0x080000000, -Number.MIN_VALUE, 1, -Number.MAX_VALUE, 0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, 0x080000001, -(2**53), -0x100000001, Number.MAX_VALUE, 1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, -0x080000001, 42, -1/0, -0, 0/0, 2**53+2, 2**53, -(2**53+2), -0x07fffffff, 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, 0, -0x100000000]); ");
/*fuzzSeed-116066984*/count=413; tryItOut("testMathyFunction(mathy5, [1.7976931348623157e308, 2**53-2, -(2**53-2), -(2**53+2), 2**53, 0/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, -Number.MIN_VALUE, 1, 0x100000000, Number.MAX_VALUE, 0x0ffffffff, 2**53+2, -0x100000001, -0, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 42, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, Math.PI, 0x07fffffff, 1/0, 0, -0x080000000, 0x080000000, -0x080000001, Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-116066984*/count=414; tryItOut("Object.defineProperty(this, \"this.s1\", { configurable: new RegExp(\"(?!(?!\\u176c)|$(?:[^]){3,6}[\\\\xB8-\\u0084\\\\cO\\\\cY-\\\\B]|\\\\B{4,1073741829})\\u0019(?!.+)\\\\xdF{1,}\\\\d{1,1073741825}\", \"g\") >>>  \"\" , enumerable: true,  get: function() {  return s2.charAt(0); } });");
/*fuzzSeed-116066984*/count=415; tryItOut("mathy2 = (function(x, y) { return Math.expm1(Math.fround(( + (Math.fround(( + (mathy0(Math.fround(Math.sign(Math.fround(( ~ Math.fround(x))))), Math.hypot(-Number.MIN_SAFE_INTEGER, y)) | 0))) , ( + ((Math.fround(Math.fround(( ~ x))) ? mathy1(y, Math.tan((0x100000001 >>> 0))) : (Math.imul(( + ( - (((x >>> 0) - (x >>> 0)) >>> 0))), Math.hypot(x, -1/0)) >>> 0)) >= Math.min(((x >>> 0) ? (Math.min((Math.expm1(y) >>> 0), (2**53-2 >>> 0)) >>> 0) : ((mathy1((x >>> 0), Math.fround((x == y))) >>> 0) >>> 0)), y))))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, Number.MAX_VALUE, -1/0, -0x080000001, -(2**53+2), Math.PI, 0x100000001, 0x07fffffff, -Number.MAX_VALUE, 0x100000000, 1/0, -Number.MIN_SAFE_INTEGER, 1, 0x080000001, -0x07fffffff, -0, -(2**53-2), 0.000000000000001, -0x100000000, 0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, 2**53-2, 42, -0x080000000, Number.MIN_VALUE, 2**53+2, -0x100000001, -Number.MIN_VALUE, 0x080000000, 2**53, -(2**53), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=416; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy1(Math.pow(( + ( + Math.fround((y | 0)))), Math.tan(Math.fround(((mathy2(Math.fround(mathy1(Math.fround(0/0), Math.imul(-Number.MIN_VALUE, y))), y) >>> 0) ? Math.fround(x) : Math.fround(( + Math.min(y, Math.fround(Math.ceil(x))))))))), ( + Math.hypot((( + (( - Math.fround(Math.asinh((y | 0)))) >>> 0)) << ( + Math.log2(0x080000000))), ((Math.sign(Math.imul((y | 0), x)) ? (y | 0) : ( ! Math.atan2(( + y), Math.min((y >>> 0), x)))) / x)))); }); testMathyFunction(mathy3, /*MARR*/[(-1/0), (-1/0), (-1/0), x, (-1/0), [,,z1], [,,z1], [,,z1], (-1/0), [,,z1], x, (-1/0), (-1/0), (-1/0), (-1/0), x, x, x, [,,z1], x, (-1/0), [,,z1], [,,z1], (-1/0), x, (-1/0), (-1/0), [,,z1], x, [,,z1], x, x, (-1/0), [,,z1], [,,z1], x, [,,z1], (-1/0), x, x, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0)]); ");
/*fuzzSeed-116066984*/count=417; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.cosh(Math.fround(Math.hypot(Math.log(( - y)), ( + Math.pow(( + Math.hypot(x, ( + y))), 0))))); }); testMathyFunction(mathy3, [0x080000001, -0x0ffffffff, -0x100000000, 42, -0x100000001, 1, 0x080000000, 2**53-2, -0, 0, -Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), 1/0, 0.000000000000001, 0x100000001, Math.PI, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, -0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), -0x07fffffff, -(2**53+2), 2**53]); ");
/*fuzzSeed-116066984*/count=418; tryItOut("\"use strict\"; /*hhh*/function uyxhoe(x){v1 = NaN;}/*iii*/(w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(\"\\uCFFF\"), eval));");
/*fuzzSeed-116066984*/count=419; tryItOut("\"use strict\"; a1.pop();");
/*fuzzSeed-116066984*/count=420; tryItOut("v2 = Array.prototype.reduce, reduceRight.apply(a0, [(function() { s1 = new String(s2); return e2; })]);");
/*fuzzSeed-116066984*/count=421; tryItOut("\"use strict\"; with({}) { (15); } let(window = NaN, woojkt, window, e, wuqndx, qclbbs, x, sfruup, prdicy) { (z);}/*infloop*/L:do print(f0); while((\"\\u5E79\".yoyo([z1])));\nv1 = g0.runOffThreadScript();v1.__proto__ = o1;\n");
/*fuzzSeed-116066984*/count=422; tryItOut("t1.__proto__ = p1;");
/*fuzzSeed-116066984*/count=423; tryItOut("t2.valueOf = this.f2;");
/*fuzzSeed-116066984*/count=424; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=425; tryItOut("delete b2[\"toString\"];");
/*fuzzSeed-116066984*/count=426; tryItOut("\"use strict\"; this.e1 = Proxy.create(h1, g0.o1.p2);");
/*fuzzSeed-116066984*/count=427; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[new String(''), new String(''), new String('')]) { print(-24); }");
/*fuzzSeed-116066984*/count=428; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.imul(Math.fround(Math.asin(Math.fround(Math.fround(Math.acosh(Math.fround((((Math.fround(Math.atan(Math.fround(x))) >>> 0) <= (x >>> 0)) >>> 0))))))), (mathy1((Math.max((Math.log2(y) >>> 0), ((mathy1((Math.fround((Math.fround(x) & x)) | 0), ((Math.fround(mathy0(x, (((x >>> 0) == (x >>> 0)) >>> 0))) <= Math.fround(( + ( ~ ( + -Number.MAX_VALUE))))) | 0)) | 0) >>> 0)) >>> 0), ( + (( + x) === Math.exp(Math.fround(Math.min((( ~ y) | 0), Math.fround((( + Math.tan((x | 0))) >>> 0)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -Number.MAX_VALUE, -1/0, Number.MIN_VALUE, -Number.MIN_VALUE, -0, -0x100000001, 1.7976931348623157e308, 2**53-2, 0x100000000, Math.PI, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, 0x080000000, 0x0ffffffff, 0.000000000000001, 0, -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 1, 1/0, 42, -0x080000001, -(2**53), 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), 0x080000001]); ");
/*fuzzSeed-116066984*/count=429; tryItOut("s0 = a1.join(s1, o1.s0, t1, a2, h2);");
/*fuzzSeed-116066984*/count=430; tryItOut("m1.get(g1.i2);");
/*fuzzSeed-116066984*/count=431; tryItOut("\"use strict\"; M:for(let x = \u3056 >>= e in ( /* Comment */(neuter)\u0009(x))) /*ODP-3*/Object.defineProperty(g1, \"__iterator__\", { configurable: true, enumerable: true, writable: false, value: \n(4277) });");
/*fuzzSeed-116066984*/count=432; tryItOut("v1 = t2.length;");
/*fuzzSeed-116066984*/count=433; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(s0, i2);");
/*fuzzSeed-116066984*/count=434; tryItOut("\"use strict\"; do v2 = a2.length; while((-3) && 0);");
/*fuzzSeed-116066984*/count=435; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.fround((Math.fround(( ! y)) | 0))); }); ");
/*fuzzSeed-116066984*/count=436; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; setJitCompilerOption('baseline.warmup.trigger', 14); } void 0; } {};undefined\np2 + f1;");
/*fuzzSeed-116066984*/count=437; tryItOut("s1 + '';");
/*fuzzSeed-116066984*/count=438; tryItOut("(arguments ? x :  /x/ )\n;\n(x);\n");
/*fuzzSeed-116066984*/count=439; tryItOut("\"use strict\"; Array.prototype.push.call(a2, i0, (/*FARR*/[.../*MARR*/[function(){}, function(){}, 0.000000000000001, 0.000000000000001, 0.000000000000001, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, [undefined], 0.000000000000001, function(){}, new Boolean(false), function(){}, 0.000000000000001, function(){}, 0.000000000000001, new Boolean(false), [undefined], 0.000000000000001, 0.000000000000001, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), 0.000000000000001, [undefined], new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, [undefined], 0.000000000000001, 0.000000000000001, new Boolean(false), 0.000000000000001, new Boolean(false), [undefined], [undefined], function(){}, [undefined], function(){}, function(){}, 0.000000000000001, function(){}, function(){}, new Boolean(false), function(){}, function(){}, 0.000000000000001, 0.000000000000001, [undefined], [undefined], new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, [undefined], 0.000000000000001, new Boolean(false), 0.000000000000001, function(){}, [undefined], new Boolean(false), function(){}, function(){}, function(){}, new Boolean(false), [undefined], new Boolean(false), function(){}, [undefined], 0.000000000000001, 0.000000000000001, new Boolean(false), function(){}, 0.000000000000001, [undefined], new Boolean(false), function(){}, function(){}, [undefined], 0.000000000000001, [undefined], [undefined], [undefined], [undefined], new Boolean(false), 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, [undefined], 0.000000000000001, new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, [undefined], function(){}, 0.000000000000001, [undefined], function(){}, [undefined], [undefined], [undefined], 0.000000000000001, new Boolean(false), function(){}, 0.000000000000001, 0.000000000000001, function(){}, new Boolean(false), [undefined], [undefined], function(){}, new Boolean(false), [undefined], function(){}, [undefined], function(){}, [undefined], [undefined], [undefined], function(){}, 0.000000000000001], (let (c) e ^= c), (Math.max(x, (arguments.callee.arguments = undefined)))(), .../*FARR*/['fafafa'.replace(/a/g, function(y) { return (\"\\uD170\".\u000c__defineSetter__(\"NaN\", decodeURIComponent)) }), ...((4277) for each (x in /*PTHR*/(function() { for (var i of /*MARR*/[x, false, false, false, false, x, x, x, x, x, x, x, x, false, false, false, x, false, x, x, false, x, false, x, false, x, false, false]) { yield i; } })())), .../*FARR*/[false !== new RegExp(\"(?:\\\\b\\\\B(?:.|[\\\\w\\\\cW\\\\n])*){3}\", \"gim\"), ...new Array(15), ], x, ((void options('strict'))) != x, .../*MARR*/[new Number(1.5), (void 0), new Number(1.5), new Number(1.5), new Number(1.5), (void 0), (void 0), new Number(1.5), new Number(1.5), (void 0), (void 0), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Number(1.5), (void 0), (void 0), new Number(1.5), new Number(1.5), (void 0), (void 0), new Number(1.5), (void 0), (void 0), new Number(1.5), (void 0), (void 0), new Number(1.5), (void 0), (void 0), new Number(1.5), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Number(1.5), (void 0), new Number(1.5), (void 0), (void 0), (void 0), (void 0), new Number(1.5), (void 0), (void 0), (void 0), new Number(1.5), (void 0), (void 0), (void 0), new Number(1.5), (void 0), (void 0), (void 0), (void 0), new Number(1.5), (void 0), new Number(1.5), new Number(1.5), (void 0), (void 0), new Number(1.5), new Number(1.5), new Number(1.5), (void 0), (void 0), new Number(1.5), (void 0), (void 0), new Number(1.5), new Number(1.5), (void 0), new Number(1.5), (void 0), new Number(1.5), (void 0)], , x, [], x, ...[x > x if (this.yoyo(/\\B/gym += null))], x], .../*FARR*/[x.unwatch(\"prototype\")], (( + x) ? ( + x) : Number.MAX_SAFE_INTEGER), x, (/*MARR*/[ '' , x,  '' ,  \"use strict\" , arguments.caller,  '' , arguments.caller,  \"use strict\" , arguments.caller, x, x, arguments.caller, x,  '' , arguments.caller, x, arguments.caller, x, arguments.caller,  \"use strict\" , arguments.caller, arguments.caller, x,  '' ,  '' ,  \"use strict\" , x,  '' , x, x,  '' ,  \"use strict\" ,  '' , x, x,  \"use strict\" , arguments.caller,  '' ,  '' ,  '' ,  \"use strict\" ,  '' , arguments.caller,  \"use strict\" , arguments.caller,  '' ,  '' , x, x, arguments.caller,  \"use strict\" , x, arguments.caller,  '' ,  '' , arguments.caller, arguments.caller,  '' , arguments.caller,  \"use strict\" ,  '' , arguments.caller,  '' , x,  '' , x, arguments.caller,  \"use strict\" ,  \"use strict\" , arguments.caller, x, arguments.caller, arguments.caller,  '' ,  \"use strict\" , arguments.caller,  '' , arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller,  '' ,  \"use strict\" ,  '' , arguments.caller, x,  \"use strict\" , arguments.caller,  '' , arguments.caller, arguments.caller, arguments.caller,  \"use strict\" ,  \"use strict\" , x,  '' , arguments.caller,  '' ,  '' ,  '' ,  '' ,  \"use strict\" ,  \"use strict\" ,  '' , x,  '' , x, arguments.caller, arguments.caller,  '' ,  \"use strict\" , arguments.caller, x, x,  '' ,  \"use strict\" ,  '' ,  \"use strict\" , x,  \"use strict\" , arguments.caller, arguments.caller, arguments.caller,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , x, x, x, x,  '' ,  \"use strict\" , arguments.caller,  '' , arguments.caller,  '' , x, arguments.caller,  '' ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  '' ,  \"use strict\" , arguments.caller,  '' ].sort), ((function factorial_tail(hghaim, qelyit) { print(x);; if (hghaim == 0) { ; return qelyit; } (void options('strict'));; return factorial_tail(hghaim - 1, qelyit * hghaim); for (var p in a1) { try { this.g0.v2 = o0.g0.eval(\"\\\"use strict\\\"; m2.set(b1, b0);\"); } catch(e0) { } /*MXX1*/o0 = g0.Object.prototype.constructor; }o2.__proto__ = s1; })(14958, 1)), Object.defineProperty(x, \"freeze\", ({get: /*wrap2*/(function(){ \"use strict\"; var rbwcpl = NaN--; var wkykac = Root; return wkykac;})(), configurable: (x % 3 != 0)})), (Math.atanh(-10)), \"\\uBD92\", y = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(false), (x = 2033486538.5)), undefined].some.throw(WebAssemblyMemoryMode(x) ? (4277) : Map(((void options('strict_mode'))), allocationMarker()))), s1, o2, i0, g2, o0.o2.o1.g1.e0);");
/*fuzzSeed-116066984*/count=440; tryItOut("\"use strict\"; /*hhh*/function kptdmd(9 = \"\\uF4A1\" %  /x/  < ( ''  ** x) != allocationMarker()){v1 = Object.prototype.isPrototypeOf.call(m0, a1);}kptdmd();");
/*fuzzSeed-116066984*/count=441; tryItOut("testMathyFunction(mathy0, [Number.MIN_VALUE, -0x100000001, 0x080000001, 2**53+2, 0.000000000000001, 42, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1/0, 0, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -0, 0x07fffffff, -0x0ffffffff, 0x100000001, 0/0, 1, 2**53, -0x07fffffff, 0x080000000, -1/0, -0x080000001, 0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, -(2**53), -0x080000000]); ");
/*fuzzSeed-116066984*/count=442; tryItOut("/*RXUB*/var r = /(?:(?=\\2[^][^])|\\r[^\\cT-\\\u008f]|\\cL|\\b*?+?|^|^){0,}(?!(?=[^\\w\u35df-\\uBF07\\u000c])){536870912}|[]|^|${3}{1,}|[^]|(?=\\W+)**??/m; var s = \"\"; print(s.replace(r, '', \"ym\")); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=443; tryItOut("/*bLoop*/for (var qfyjul = 0; qfyjul < 45; ++qfyjul) { if (qfyjul % 5 == 4) { return yield x; } else { function f0(t1) \"use asm\";   var NaN = stdlib.NaN;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    switch ((0x28739713)) {\n      default:\n        (Float64ArrayView[((i1)) >> 3]) = ((+(1.0/0.0)));\n    }\n    d0 = (d0);\n    (Float64ArrayView[((i1)-(0xffffffff)) >> 3]) = ((+((((~~((+(-1.0/0.0)) + (((NaN)) - ((+(0x89e2c40d)))))))-(((((0x35c5599b)+(0x896f982e)) >> (((0xfa88a041) ? (0xfd7a091a) : (0x945a4f4f))))) ? (i1) : (!((Float64ArrayView[1])))))|0)));\n    return (((i1)-(0xfda57eba)))|0;\n  }\n  return f; }  } ");
/*fuzzSeed-116066984*/count=444; tryItOut("mathy1 = (function(x, y) { return (mathy0((( ~ (((mathy0(x, Math.pow((( - x) | 0), Math.fround(( ! x)))) ? Math.sinh(( + mathy0(( + Math.atan2((Math.acosh((y | 0)) | 0), x)), x))) : ( + Math.acosh((x >>> 0)))) | 0) >>> 0)) | 0), ((( + (((Math.log2(( + mathy0(0.000000000000001, x))) >>> 0) - (Math.atan2(( + ( ~ ( + x))), (Math.asinh((y | 0)) | 0)) | 0)) >>> 0)) << ( ~ ((mathy0((x === -(2**53)), (((y >>> 0) ? ((y & y) >>> 0) : Math.fround(y)) >>> 0)) >>> 0) | 0))) | 0)) | 0); }); testMathyFunction(mathy1, [42, -0x07fffffff, -1/0, 2**53-2, -(2**53+2), -0x100000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, 1/0, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1, 0, 0/0, 0x100000000, 0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, -0, -0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-116066984*/count=445; tryItOut("/*vLoop*/for (let uunqav = 0; uunqav < 105; ++uunqav) { var a = uunqav; print(x); } ");
/*fuzzSeed-116066984*/count=446; tryItOut("\"use strict\"; o1 + v2;");
/*fuzzSeed-116066984*/count=447; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ( - (Math.asin(( + ( + Math.imul(( + ( + Math.atanh(( + Math.abs((y | 0)))))), ( + Math.atan2((Math.abs(y) >>> 0), y)))))) >>> 0)); }); testMathyFunction(mathy5, [0.000000000000001, 42, -(2**53-2), 0x080000000, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, Number.MIN_VALUE, -1/0, -0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, 2**53-2, -0x080000001, -0x0ffffffff, Math.PI, 0x100000001, 0/0, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, 1, -(2**53+2), 1.7976931348623157e308, -0x100000001, 0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-116066984*/count=448; tryItOut("\"use strict\"; /*RXUB*/var r = /\\3(?:\\D)/; var s = \"[\\n[\\n[\\n[\\n\"; print(r.exec(s)); ");
/*fuzzSeed-116066984*/count=449; tryItOut(";");
/*fuzzSeed-116066984*/count=450; tryItOut("v0 = Object.prototype.isPrototypeOf.call(m2, t0);");
/*fuzzSeed-116066984*/count=451; tryItOut("with(x)a1.toSource = f2;\ng2.v2 + '';\n");
/*fuzzSeed-116066984*/count=452; tryItOut("print(x);");
/*fuzzSeed-116066984*/count=453; tryItOut("\"use asm\"; M:for(var a in (((Math.pow(x(x, [[1]]), -3)).call)((function ([y]) { })( \"\" )))){neuter(b0, \"change-data\");function this() { return  \"\"  } a1.__proto__ = v0;for (var v of i1) { try { g1 = a1[1]; } catch(e0) { } try { i2 = new Iterator(v2, true); } catch(e1) { } try { Array.prototype.forEach.apply(a1, [(function() { try { o1.v1 = new Number(t0); } catch(e0) { } try { for (var v of h0) { /*MXX2*/g1.g2.Float64Array.name = h0; } } catch(e1) { } try { this.a1.pop(); } catch(e2) { } m1.get(this.i2); return m0; })]); } catch(e2) { } a2.shift(t1); } }");
/*fuzzSeed-116066984*/count=454; tryItOut("\"use asm\"; i1 = e0.values;");
/*fuzzSeed-116066984*/count=455; tryItOut("mathy3 = (function(x, y) { return Math.asinh(Math.fround(Math.log1p(Math.fround((((y ? (Math.sqrt(Math.max(Math.hypot(x, x), (Math.fround(((x | 0) || (x | 0))) >>> 0))) | 0) : (-(2**53) >= ( - (Math.asinh(x) >>> 0)))) >> (y | 0)) | 0))))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 0.000000000000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, -0x100000001, -0x100000000, -0, -Number.MAX_VALUE, 1, -(2**53), Number.MIN_VALUE, 0x07fffffff, 0x080000001, 0x100000001, -0x080000000, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, 0, 2**53, Number.MAX_VALUE, 42, -1/0, -0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=456; tryItOut("\"use strict\"; for (var p in g1) { v1 = g2.eval(\"this.a0 + b2;\"); }");
/*fuzzSeed-116066984*/count=457; tryItOut("new function shapeyConstructor(xjlmiw){\"use strict\"; xjlmiw[\"pow\"] = function(){};if (16) Object.defineProperty(xjlmiw, \"pow\", ({get: RegExp, set: SyntaxError, enumerable: (x % 5 != 0)}));xjlmiw[\"search\"] = window;return xjlmiw; }(x, \"\\u81E0\");");
/*fuzzSeed-116066984*/count=458; tryItOut("mathy3 = (function(x, y) { return (mathy0(( + ( + Math.exp(( + (Math.hypot((Math.sin(x) | 0), Math.fround(mathy0(x, (Math.atan(x) == y)))) | 0))))), (((((Math.hypot((( + Math.exp(Math.fround(x))) | 0), (( ~ x) >= x)) | 0) >>> 0) << Math.atan2((((0x080000000 | 0) && 42) == y), x)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), [], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), [], [], (void 0), [], [], (void 0), objectEmulatingUndefined(), [], objectEmulatingUndefined(), []]); ");
/*fuzzSeed-116066984*/count=459; tryItOut("\"use strict\"; g0.v1 = Object.prototype.isPrototypeOf.call(o2.s2, h0);a0 = arguments;");
/*fuzzSeed-116066984*/count=460; tryItOut("let(zzbimd, muqmgr, x = eval, x = [1,,], x, x) { x.constructor;}");
/*fuzzSeed-116066984*/count=461; tryItOut("mathy2 = (function(x, y) { return (Math.imul((( + Math.ceil(mathy0(Math.max(x, 0.000000000000001), (Math.log10(y) >>> 0)))) | 0), ((Math.fround(Math.atan2(Math.fround(Math.pow(((Math.max(y, x) < x) >>> 0), -(2**53-2))), Math.fround((y ** Math.sign(x))))) === ( + Math.expm1((y | 0)))) | 0)) ? ((((( + Math.min((-0x100000000 ^ 1/0), ( + Math.sinh(Math.fround(y))))) <= Math.pow((( ~ x) >>> 0), x)) | 0) * Math.fround((Math.tan((y >>> 0)) >>> 0))) | 0) : Math.min((( ! (( ! x) >>> 0)) >>> 0), ( + (Math.cos(y) - ( - y))))); }); testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), -0, (new Boolean(true)), [], null, (new Number(0)), ({toString:function(){return '0';}}), [0], 0, (function(){return 0;}), 1, '\\0', ({valueOf:function(){return '0';}}), NaN, (new String('')), (new Boolean(false)), (new Number(-0)), undefined, false, true, objectEmulatingUndefined(), /0/, '/0/', '0', 0.1, '']); ");
/*fuzzSeed-116066984*/count=462; tryItOut("\"use strict\"; /*infloop*/for(var x in x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return false; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: undefined, set: function() { return false; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(x), -0x100000001)) {x; }");
/*fuzzSeed-116066984*/count=463; tryItOut("var szmfvz = new ArrayBuffer(0); var szmfvz_0 = new Int32Array(szmfvz); var szmfvz_1 = new Float32Array(szmfvz); szmfvz_1[0] = -3; a2.forEach((function(stdlib, foreign, heap){ \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((0x3950f12)))|0;\n    i1 = (i1);\n    i1 = (i1);\n    i1 = ((0xc9a48df0) ? ((((0xa88d463d)-(i1))>>>((!((0x774afb67) < (0x3f956c05)))+(0x31a6b2a8)))) : (0xf9efe23a));\n    {\n      d0 = (-((-17592186044417.0)));\n    }\n    return (( ''  >>>= undefined &= (4277)))|0;\n  }\n  return f; }));t0[5] = i2;print(szmfvz);for (var v of e0) { try { v0 = g1.eval(\"v0 = b2.byteLength;\"); } catch(e0) { } Array.prototype.reverse.apply(a1, [s0, m0]); }");
/*fuzzSeed-116066984*/count=464; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.min(Math.fround(( ~ Math.fround(Math.atan2(Math.fround(( ! 0.000000000000001)), y)))), (((Math.ceil(( + y)) * Math.clz32(Math.fround(x))) ? ((((( + (( ! ((Math.acosh(0/0) >>> 0) >>> 0)) >>> 0)) | 0) >>> 0) == 0/0) >>> 0) : (Math.hypot(((0x100000001 - y) >>> 0), (Math.asin((Math.asinh(1) >>> 0)) >>> 0)) >>> 0)) % ((( - (Math.abs((( ! Math.ceil((x | 0))) >>> 0)) | 0)) | 0) >> Math.fround(Math.asin(Math.fround((mathy1(((Math.min(y, x) >>> 0) >>> 0), (( ! Number.MAX_VALUE) >>> 0)) >>> 0))))))); }); ");
/*fuzzSeed-116066984*/count=465; tryItOut("if(true) { if ((null).call(\"\\u2EA5\", window,  /x/ )) print(x); else /*MXX3*/g1.Array.prototype.findIndex = g2.Array.prototype.findIndex;}");
/*fuzzSeed-116066984*/count=466; tryItOut("\"use strict\"; v0 = (o1 instanceof p0);");
/*fuzzSeed-116066984*/count=467; tryItOut("/*RXUB*/var r = /(?=[\\cV-\\u00D9\\W\\S\\0-\\t])/y; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=468; tryItOut("/*oLoop*/for (let zqvkta = 0; zqvkta < 100; ++zqvkta) { /* no regression tests found */ } ");
/*fuzzSeed-116066984*/count=469; tryItOut("\"use strict\"; a2.shift();");
/*fuzzSeed-116066984*/count=470; tryItOut("o0.__proto__ = h0;");
/*fuzzSeed-116066984*/count=471; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.sign(((Math.cosh(((Math.imul(( - (x >>> 0)), (Math.sqrt((Math.fround(( - x)) | 0)) | 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0x080000001, 0.000000000000001, 2**53+2, 0x100000001, -(2**53), 0, 0x080000000, 0x0ffffffff, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 42, Math.PI, Number.MIN_VALUE, 1, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, -0x100000001, -0x100000000, 1/0, 2**53, 0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=472; tryItOut("break M;yield 21;f2 = Proxy.createFunction(h1, f2, this.f1);");
/*fuzzSeed-116066984*/count=473; tryItOut("\"use strict\"; v2 = a1.every((function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = ((((i0))>>>((((0xc92d02ec)) ? (i0) : ((0xe40e9c9e) > (0x68c40a3c)))+(0xfa7d2bd9)+((((0xfa995521)-(0x8f60151e)-(0xae24c804))>>>((0xfd2237b9)))))) < ((((-131073.0) >= (+(((-0x8000000))>>>((0x2984bab8)))))+(i0))>>>((0xffffffff))));\n    }\n    (Float32ArrayView[((0xffe765df)) >> 2]) = ((-1099511627777.0));\n    return (((/*FFI*/ff(((Infinity)), ((-((Float32ArrayView[((0x18e58e94)-(-0x8000000)-((-0x8000000) != (0x56e84b97))) >> 2])))))|0)-(-0x8000000)-(i0)))|0;\n  }\n  return f; })(this, {ff: Math.cos(-17)}, new ArrayBuffer(4096)), m2);");
/*fuzzSeed-116066984*/count=474; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( - ((((((x >>> 0) ^ ((( ! (x | 0)) != Math.trunc(y)) >>> 0)) >>> 0) >>> 0) | (mathy0((Math.atan(Math.max(x, Math.sinh(y))) >>> 0), ((( ~ (( - (( + Math.hypot(x, ( + x))) >>> 0)) >>> 0)) ? y : x) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1, 0x080000001, 0x100000000, -1/0, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, -0x100000000, 2**53-2, Number.MAX_VALUE, Number.MIN_VALUE, -0x100000001, 1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 0, -0, -0x07fffffff, 0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53+2), 0x07fffffff, Math.PI, -Number.MIN_VALUE, -(2**53), 42, 2**53, -0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-116066984*/count=475; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[4096]) = ((524289.0));\n    d1 = (+atan2(((Float32ArrayView[0])), ((Float32ArrayView[2]))));\n    i0 = (0xd2e62f94);\n    i0 = (0xc0c48abf);\n    i0 = (!(i0));\n    (Uint8ArrayView[2]) = ((!(!(-0x8000000)))-(i0)+(0xff4f536e));\n    return (((0xfdb43fec)-(0x6e30cc70)))|0;\n  }\n  return f; })(this, {ff: Object.prototype.__defineSetter__}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000001, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, 0x100000000, -(2**53), 0x100000001, 42, 0, -1/0, -0x07fffffff, -0x080000000, -(2**53+2), -0x0ffffffff, -Number.MAX_VALUE, 1, 2**53, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, -0x100000000, -0, Number.MIN_VALUE, 0x080000001, 1/0, -0x080000001, 0/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, Number.MAX_VALUE, 0x080000000]); ");
/*fuzzSeed-116066984*/count=476; tryItOut("/*infloop*/for(e =  '' ; Proxy(); ((function too_much_recursion(yavbsf) { ; if (yavbsf > 0) { M:do /*ADP-1*/Object.defineProperty(a1, 12, ({set: function(q) { return q; }, configurable: false, enumerable: Math})); while((undefined) && 0);; too_much_recursion(yavbsf - 1);  } else {  }  })(35234))) /*RXUB*/var r = new RegExp(\"(?=\\\\1*|(?=.))\", \"yi\"); var s = \"\\u9bc5\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=477; tryItOut("\"use strict\"; print(t1);");
/*fuzzSeed-116066984*/count=478; tryItOut("testMathyFunction(mathy5, [(new String('')), '', 0, null, NaN, 1, ({valueOf:function(){return 0;}}), true, (new Number(-0)), false, '/0/', (new Boolean(false)), '0', (new Number(0)), [], undefined, ({toString:function(){return '0';}}), [0], (new Boolean(true)), -0, ({valueOf:function(){return '0';}}), 0.1, (function(){return 0;}), /0/, '\\0', objectEmulatingUndefined()]); ");
/*fuzzSeed-116066984*/count=479; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=480; tryItOut("print(f1);");
/*fuzzSeed-116066984*/count=481; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( ! ( + ( + ( ~ Math.clz32(( + (( + Math.max(x, x)) ? ( + Math.fround((Math.fround(0.000000000000001) == Math.fround(x)))) : x)))))))); }); ");
/*fuzzSeed-116066984*/count=482; tryItOut("for (var v of e2) { try { v0 = r2.toString; } catch(e0) { } v1 = (t1 instanceof o1.p0); }");
/*fuzzSeed-116066984*/count=483; tryItOut("testMathyFunction(mathy5, [-0x080000000, -0x100000001, 1, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, 2**53+2, 1.7976931348623157e308, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, -0, 0.000000000000001, 0x100000001, 2**53, 0, 0x080000000, Math.PI, -0x100000000, -1/0, -(2**53+2), 2**53-2, -0x0ffffffff, -(2**53), 1/0]); ");
/*fuzzSeed-116066984*/count=484; tryItOut("v2 = g1.g1.eval(\"\\\"use strict\\\"; mathy2 = (function(x, y) { return Math.pow(( ! ( - Math.sinh(( + x)))), (( ! (mathy0((-0x0ffffffff - ( + Math.fround((Math.fround(-0x100000000) << Math.fround((mathy1(x, x) >>> 0)))))), y) | 0)) + (( + (y >>> 0)) ? ( + (( + -Number.MAX_VALUE) == ( + (mathy0((1/0 >>> 0), ((1/0 ? (x >>> 0) : (Math.fround(x) - -0x080000000)) | 0)) >>> 0)))) : y))); }); \");");
/*fuzzSeed-116066984*/count=485; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[false, false, false, null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), false, null, null, false, false, null, null, null, false, false, new Number(1.5), new Number(1.5), false, false, null, new Number(1.5), null, new Number(1.5), new Number(1.5), null, new Number(1.5), new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-116066984*/count=486; tryItOut("L:if((x % 16 != 7)) { if (({\"20\": true })) {/\\2{1,5}/gi; } else }");
/*fuzzSeed-116066984*/count=487; tryItOut("\"use strict\"; var dzzcpp, glipck, yhpcah, krraee, haxxjq, x, hmiios, vugofk;print((w = -13));");
/*fuzzSeed-116066984*/count=488; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return Math.fround((Math.fround((( - ( ! ( ~ y))) >>> 0)) >>> Math.fround(( + ( - mathy0(((Math.max((x | 0), ( ~ mathy1(y, (x << y)))) | 0) >>> 0), Math.fround(Math.hypot(( + ( ! ( + ((x >>> 0) & (1.7976931348623157e308 >>> 0))))), Math.fround(( + ((y | 0) ^ y))))))))))); }); ");
/*fuzzSeed-116066984*/count=489; tryItOut("\"use strict\"; {var r0 = 3 % x; var r1 = x * 5; var r2 = r0 | x; var r3 = r0 ^ 1; var r4 = r3 / r2; var r5 = 1 % 4; var r6 = r4 / r3; var r7 = r3 + r2; var r8 = r7 * r6; var r9 = r4 + 4; var r10 = r4 / r3; var r11 = r9 - 5; var r12 = 8 | r6; var r13 = r2 + r12; var r14 = 5 / 1; r14 = 3 - 4; var r15 = r4 / r12; r11 = r11 | r9; var r16 = r14 % 4; var r17 = r8 ^ x;  }");
/*fuzzSeed-116066984*/count=490; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -6.044629098073146e+23;\n    var i4 = 0;\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: Object.assign}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, ['/0/', [], '\\0', ({valueOf:function(){return '0';}}), [0], NaN, /0/, '0', '', ({toString:function(){return '0';}}), true, (new Number(-0)), objectEmulatingUndefined(), 0, (new Boolean(false)), false, undefined, 0.1, (new Boolean(true)), (new String('')), 1, (new Number(0)), (function(){return 0;}), -0, null, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-116066984*/count=491; tryItOut("null;");
/*fuzzSeed-116066984*/count=492; tryItOut("/*RXUB*/var r = null; var s = \"[\\n\\n\\n\\n\\n\\n[\\n\\n\\n\\n\\n\\n[\\n\\n\\n\\n\\n\\n\\u00e0[\\n\\n\\n\\n\\n\\n\"; print(s.replace(r, Promise.prototype.catch, \"yim\")); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=493; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\1|^($+)|\\\\D*|(?=(?=\\\\B|(?:.))[^](?:\\\\d))|(?:\\\\B(?=[^]|[^]|[^])+)?\", \"\"); var s = \"[\\n[\\n[\\n[\\n\"; print(s.search(r)); ");
/*fuzzSeed-116066984*/count=494; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-116066984*/count=495; tryItOut("\"use strict\"; f1 + '';");
/*fuzzSeed-116066984*/count=496; tryItOut("g2.v1 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x = ({x: /\\1/gym }), noScriptRval: false, sourceIsLazy: (x % 2 != 0), catchTermination: false }));");
/*fuzzSeed-116066984*/count=497; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return x; }); testMathyFunction(mathy0, [0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, 2**53+2, 1, -(2**53-2), Math.PI, 0.000000000000001, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 2**53-2, -(2**53+2), 0x080000000, 2**53, Number.MIN_VALUE, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, 0, 1.7976931348623157e308, -Number.MAX_VALUE, 42, 0/0, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=498; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\b\", \"gyim\"); var s = this; print(s.split(r)); ");
/*fuzzSeed-116066984*/count=499; tryItOut("do print(\u3056 = window); while((new new RegExp(\"\\\\W\", \"gyim\")(new RegExp(\"(?=[^](?:\\\\3|\\\\W\\\\d?))|\\\\3|(?:.)|(?!(\\\\s))?|(?=\\\\W+?)[]|(?:[^]){4,}\\\\W+?\", \"gm\") in function ([y]) { })) && 0);");
/*fuzzSeed-116066984*/count=500; tryItOut("h1.fix = f2;");
/*fuzzSeed-116066984*/count=501; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-116066984*/count=502; tryItOut("mathy1 = (function(x, y) { return Math.exp(Math.hypot(( + (( + Math.round(y)) < (x >>> 0))), Math.min(( ~ x), Math.cbrt(mathy0(Math.fround(mathy0(Math.fround(x), Math.fround(y))), y))))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), -0x080000000, -Number.MIN_VALUE, Math.PI, 0x100000001, Number.MIN_VALUE, 1, 0x0ffffffff, -0x100000000, 2**53, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, 0/0, -(2**53), 42, 2**53+2, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, 0x100000000, -Number.MIN_SAFE_INTEGER, -1/0, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, -Number.MAX_VALUE, 1/0, -(2**53+2), -0x100000001, 0, 0x080000000]); ");
/*fuzzSeed-116066984*/count=503; tryItOut("\"use strict\"; m0.get( /x/g );");
/*fuzzSeed-116066984*/count=504; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan2((((( + Math.fround(Math.imul(( ~ -(2**53+2)), (Math.pow((x | 0), (Number.MAX_VALUE | 0)) | 0)))) >>> 0) ? (((Math.min(y, (Math.log10(( + ( + Math.min(x, (x >>> 0))))) >>> 0)) >>> 0) | 0) ? Math.fround((( + mathy2(( + mathy3(( + y), y)), ( + (Math.hypot((-0x07fffffff | 0), (x | 0)) | 0)))) >= Math.fround(y))) : ((( ! (-Number.MAX_SAFE_INTEGER | 0)) % Number.MIN_SAFE_INTEGER) | 0)) : ( + Math.min((( ~ x) % mathy2(y, ( + ( + ( + (Math.sinh(x) | 0)))))), Math.max(Math.fround(((Math.atan2(Math.pow(y, x), (( ! Math.fround(y)) >>> 0)) | 0) % Math.asin((2**53-2 << y)))), (x | 0))))) | 0), (Math.max((Math.fround(( ~ ((mathy2(y, Math.max(x, x)) >>> 0) === 0x100000000))) | 0), ((((( + (x & Math.log1p(x))) | 0) | 0) || ((mathy1(y, (Math.abs(Math.asinh(x)) >>> 0)) >>> 0) | 0)) | 0)) | 0)); }); testMathyFunction(mathy4, [0x100000001, 0x080000001, -0x07fffffff, 0.000000000000001, 0, -Number.MAX_VALUE, -0x080000000, 0x080000000, 2**53-2, -Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 1/0, -0x100000000, 0x07fffffff, Number.MIN_VALUE, 1, 2**53, Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -0, 0x100000000, Number.MAX_VALUE, -(2**53), 0x0ffffffff, -(2**53-2), -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, -1/0, 42]); ");
/*fuzzSeed-116066984*/count=505; tryItOut("/*tLoop*/for (let d of /*MARR*/[true, true, NaN, NaN, NaN, NaN, true, NaN, true, NaN, NaN, NaN, NaN, true, true, true, true, true, true, NaN, true, NaN, NaN, NaN, true, NaN, NaN, NaN, true, true]) { x = s0; }");
/*fuzzSeed-116066984*/count=506; tryItOut("print(x);(this); '' ");
/*fuzzSeed-116066984*/count=507; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (((Math.pow((Math.atan2((Math.imul((( + (((Math.pow(0x07fffffff, (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) != (Math.fround(Math.max(x, y)) | 0)) | 0)) >>> 0), Math.fround(mathy3(Math.fround(x), Math.fround(y)))) >>> 0), Math.fround(y)) >>> 0), Math.fround(Math.atan2(Math.fround((Math.round(y) * (y | 0))), (y >>> 0)))) >>> 0) >> (Math.max(( + ( ! ( + (y >>> ( ! y))))), Math.imul(( ~ y), (Math.pow(Math.fround(Math.sqrt(Math.fround(-0x100000001))), (0x100000001 >>> 0)) | 0))) | 0)) | 0); }); ");
/*fuzzSeed-116066984*/count=508; tryItOut("");
/*fuzzSeed-116066984*/count=509; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[1.7976931348623157e308, 1.7976931348623157e308,  '' , 1.7976931348623157e308,  '' , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  '' , 1.7976931348623157e308,  '' , 1.7976931348623157e308, 1.7976931348623157e308,  '' , 1.7976931348623157e308, 1.7976931348623157e308,  '' ,  '' , 1.7976931348623157e308, 1.7976931348623157e308,  '' , 1.7976931348623157e308,  '' , 1.7976931348623157e308, 1.7976931348623157e308,  '' , 1.7976931348623157e308,  '' , 1.7976931348623157e308,  '' , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  '' ]); ");
/*fuzzSeed-116066984*/count=510; tryItOut("\"use strict\"; for (var p in s1) { try { s2 += 'x'; } catch(e0) { } a2 + g2; }");
/*fuzzSeed-116066984*/count=511; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x100000001, -0x100000001, -1/0, -0x0ffffffff, -0x080000000, 0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, 2**53, Number.MIN_VALUE, 0x07fffffff, 0, 0x080000000, 0/0, Number.MAX_VALUE, 0x100000000, 2**53+2, 1, 0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), -Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, -0, -(2**53), -0x080000001, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=512; tryItOut("for (var p in m0) { h2 = {}; }");
/*fuzzSeed-116066984*/count=513; tryItOut("a0.forEach((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (x ** (x *= eval));\n    return +((32768.0));\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)));");
/*fuzzSeed-116066984*/count=514; tryItOut("mathy1 = (function(x, y) { return ( + Math.fround(( - (mathy0((( + (( ! x) | 0)) >>> 0), (y | 0)) >>> 0)))); }); testMathyFunction(mathy1, [-(2**53-2), -0x080000000, -0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000000, Number.MIN_VALUE, -(2**53+2), 0x080000001, -0, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, 0x07fffffff, -0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, 2**53+2, -(2**53), Number.MAX_VALUE, 0, Math.PI, 42, 1, 1/0, 2**53-2, 0x100000001]); ");
/*fuzzSeed-116066984*/count=515; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (( ! Math.asinh(((((x >>> 0) == Math.pow(Math.tan(x), y)) >>> 0) | 0))) | 0); }); testMathyFunction(mathy0, ['', objectEmulatingUndefined(), (new Number(0)), NaN, 1, 0.1, ({valueOf:function(){return '0';}}), '0', [], ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), false, -0, null, (new Boolean(true)), true, '\\0', (new String('')), (new Number(-0)), /0/, (new Boolean(false)), undefined, 0, [0], '/0/', (function(){return 0;})]); ");
/*fuzzSeed-116066984*/count=516; tryItOut("Object.defineProperty(this, \"h0\", { configurable: true, enumerable: false,  get: function() {  return ({getOwnPropertyDescriptor: function(name) { for (var v of o2) { try { Object.prototype.unwatch.call(o2.o0.s2, b & x); } catch(e0) { } try { a1.forEach((function(j) { if (j) { Object.defineProperty(this, \"o1\", { configurable: false, enumerable: (4277),  get: function() {  return Object.create(f0); } }); } else { try { print(uneval(this.i0)); } catch(e0) { } try { /*MXX3*/g2.Array.isArray = g1.Array.isArray; } catch(e1) { } this.e1.add(p0); } }), e2, i2); } catch(e1) { } o2 = g1.m2.get(-3); }; var desc = Object.getOwnPropertyDescriptor(s2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { b1 = new ArrayBuffer(26);; var desc = Object.getPropertyDescriptor(s2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a0.forEach((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xff2a11c0);\n    return (((+(-1.0/0.0))))|0;\n  }\n  return f; })(this, {ff: (RegExp).apply}, new ArrayBuffer(4096)));; Object.defineProperty(s2, name, desc); }, getOwnPropertyNames: function() { throw i1; return Object.getOwnPropertyNames(s2); }, delete: function(name) { for (var p in p0) { selectforgc(o1); }; return delete s2[name]; }, fix: function() { t2 = new Uint16Array(t0);; if (Object.isFrozen(s2)) { return Object.getOwnProperties(s2); } }, has: function(name) { m0.has(e0);; return name in s2; }, hasOwn: function(name) { o0.v2 = false;; return Object.prototype.hasOwnProperty.call(s2, name); }, get: function(receiver, name) { g0.offThreadCompileScript(\"(new (this.__defineSetter__(\\\"e\\\", (new (mathy3)(/*FARR*/[, eval, new RegExp(\\\"((?=.+?))*\\\", \\\"\\\"), eval].sort(runOffThreadScript, null)))))(e, x))\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 1), noScriptRval: ({e: (\"\\u4EC6\".__defineSetter__(\"z\", q => q)) }) ? eval(\"true;\", 22) : (makeFinalizeObserver('tenured')), sourceIsLazy: (4277), catchTermination: true }));; return s2[name]; }, set: function(receiver, name, val) { a1.valueOf = (function(j) { this.f1(j); });; s2[name] = val; return true; }, iterate: function() { for (var p in g1) { try { s1.toString = f1; } catch(e0) { } try { a1 = Array.prototype.concat.apply(this.a2, [a2, t2, a0]); } catch(e1) { } try { (void schedulegc(g1)); } catch(e2) { } h2.get = f2; }; return (function() { for (var name in s2) { yield name; } })(); }, enumerate: function() { a0.forEach((function() { try { v2 = (f0 instanceof v2); } catch(e0) { } this.e1.has(a2); return v1; }));; var result = []; for (var name in s2) { result.push(name); }; return result; }, keys: function() { print(g2.e2);; return Object.keys(s2); } }); } });");
/*fuzzSeed-116066984*/count=517; tryItOut("mathy0 = (function(x, y) { return Math.atan2(Math.fround(( + ( ! (Math.pow(((( + y) % Math.atan2(( + y), ((x ** x) | 0))) | 0), (((Math.hypot(-(2**53), x) | 0) >> x) | 0)) | 0)))), Math.fround((( ~ Math.fround((Math.expm1(y) | 0))) !== Math.pow(((((( + Math.min(2**53+2, x)) >>> 0) - (Math.log10((y | 0)) >>> 0)) >>> 0) >>> 0), (( - y) >>> 0))))); }); testMathyFunction(mathy0, [1, undefined, true, ({valueOf:function(){return '0';}}), 0, false, '0', /0/, (new Number(-0)), '/0/', ({valueOf:function(){return 0;}}), (new String('')), 0.1, (function(){return 0;}), (new Number(0)), '\\0', NaN, -0, (new Boolean(false)), ({toString:function(){return '0';}}), [0], '', (new Boolean(true)), objectEmulatingUndefined(), null, []]); ");
/*fuzzSeed-116066984*/count=518; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return mathy1(( - Math.fround((Math.fround(y) % Math.fround((((((Math.cos(x) + x) | 0) % (0.000000000000001 >>> 0)) >>> 0) ? x : Math.imul((y | 0), -Number.MAX_VALUE)))))), Math.fround(Math.max(( + (Math.atan(Math.trunc(y)) != mathy2(Math.fround(Math.cosh(y)), Math.fround(Math.sinh((Number.MIN_SAFE_INTEGER | 0)))))), Math.fround(( + ((Math.fround((Math.fround(y) ? Math.fround(( + mathy0((y >>> 0), (x | 0)))) : Math.fround(( + ( ~ ( + Math.max(y, Math.max((x | 0), x)))))))) | 0) === ( + ( + mathy0((( + Math.atan2(( + ( + mathy1(( + x), -0x080000001))), ( + (( + x) | 0)))) < ( ! y)), 0x080000001))))))))); }); testMathyFunction(mathy3, [true, undefined, 0, ({valueOf:function(){return 0;}}), 1, null, ({toString:function(){return '0';}}), -0, (new Number(0)), '', (new Boolean(true)), (function(){return 0;}), [], '/0/', '0', '\\0', ({valueOf:function(){return '0';}}), (new String('')), [0], objectEmulatingUndefined(), false, 0.1, (new Boolean(false)), /0/, NaN, (new Number(-0))]); ");
/*fuzzSeed-116066984*/count=519; tryItOut("\"use strict\"; ;");
/*fuzzSeed-116066984*/count=520; tryItOut("mathy0 = (function(x, y) { return (( + Math.hypot((( - x) ? ((Math.max(y, ( + Number.MIN_SAFE_INTEGER)) >= y) / 0) : ((Math.imul(y, x) >>> 0) ? (x >>> 0) : ((((y >>> 0) % (y >>> 0)) >>> 0) >>> 0))), ((x | 0) + Math.fround((Math.tan(( + x)) | 0))))) >= Math.expm1(Math.fround(Math.atan2((Math.atanh((x | 0)) | 0), Math.min(Math.fround(( ~ Math.fround(( ! x)))), (((x >>> 0) >>> (Math.min(x, x) >>> 0)) , (( + (y | 0)) | 0))))))); }); testMathyFunction(mathy0, [-1/0, Math.PI, -(2**53), 42, -0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53+2), 2**53-2, -0x080000001, 0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, 0, 1/0, 2**53, 0/0, 0x0ffffffff, 0x100000001, -0, -0x100000000, 0.000000000000001, Number.MAX_VALUE, 0x100000000, 0x07fffffff, 2**53+2, -(2**53-2), -0x0ffffffff, -0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-116066984*/count=521; tryItOut("testMathyFunction(mathy5, [0x07fffffff, -0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, 0, -0x100000001, Math.PI, 2**53, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -(2**53), -0x07fffffff, -0x080000000, 0/0, 1, -(2**53-2), -0, 0x080000001, -Number.MIN_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, 0x080000000, -1/0, 42, -0x080000001, 0.000000000000001, 1/0, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-116066984*/count=522; tryItOut("\"use strict\"; print(x);let d = this.__defineGetter__(\"x\", neuter);");
/*fuzzSeed-116066984*/count=523; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(o0.a0, 17, { configurable: (x % 3 != 0), enumerable: (4277), get: (function() { s2 += 'x'; return this.e1; }), set: Math.min.bind(a2) });");
/*fuzzSeed-116066984*/count=524; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[((i0)) >> 2]) = ((d1));\n    {\n      i0 = (i0);\n    }\n    d1 = (+((((~((0xffffffff)*0x425a6)) >= ((((0x580c640))) ^ (((0xfeb44b98) ? (-0x8000000) : (0xff661c0a)))))+((abs(((((0x2fe8db0d) ? (0x43fcba2a) : (0x78131b7f))-(i0)) & ((0x2c1c3b93)+((0xf4a60757)))))|0))) & ((-0x8000000))));\n    {\n      i0 = (0xf8d94edf);\n    }\n    {\n      return (((~~(+pow(((d1)), ((590295810358705700000.0))))) % (((0xfb8a8e36)) >> (((+abs(((Float32ArrayView[(/*RXUE*/new RegExp(\"(?:\\\\b)?\", \"gm\").exec(\"\\u0008\")) >> 2])))) >= (-2.4178516392292583e+24))))))|0;\n    }\n    /*FFI*/ff(((((x = [1])) - ((Float64ArrayView[(((+((65535.0))) >= (-73786976294838210000.0))) >> 3])))), ((-4503599627370497.0)), ((d1)));\n    (Float32ArrayView[((((((0xc0b5a82) ? (0x7e86a028) : (0xf1e19f0a)))>>>((0xb6cfc752)+(i0))))) >> 2]) = ((((+/*FFI*/ff(((-257.0)), (((0xf6cb8*(0x2532be68)) | ((imul((0x5e295792), (0xfe8e5f14))|0) % (((0xfd174463)) & ((0xfe7c29b4)))))), ((+(0.0/0.0))), ((0x6044b03a)), ((((i0)+((0xfd9376f8) ? (0xf4ade37) : (0x1fc1a162)))|0)), ((((0xfbaa6091)) ^ ((0x57493043)))), ((147573952589676410000.0)), ((-18446744073709552000.0)), ((1.9342813113834067e+25)), ((1.25)), ((-1023.0)), ((-536870913.0)), ((2.4178516392292583e+24)), ((-288230376151711740.0)), ((8388609.0))))) / ((d1))));\n    {\n      d1 = (+(1.0/0.0));\n    }\n    {\n      d1 = (-4503599627370497.0);\n    }\n    d1 = (+(0.0/0.0));\n    switch ((abs((abs((0x529e7aee))|0))|0)) {\n      case 1:\n        return ((((0xfd401091))-(0xac5f991e)))|0;\n      case -3:\n        {\n          d1 = (d1);\n        }\n        break;\n      case -2:\n        {\n          (Int16ArrayView[1]) = ((((((i0))) - ((Float32ArrayView[1]))) >= (d1))*-0xcdcfb);\n        }\n      case 0:\n        {\n          {\n            d1 = (-1.888946593147858e+22);\n          }\n        }\n        break;\n      case -2:\n        i0 = (i0);\n        break;\n      case -1:\n        i0 = (i0);\n        break;\n    }\n    i0 = (/*FFI*/ff(((((0xfd892923)+(i0)) & ((!((((0xff9e55e7))>>>((0x39510dbe))) <= (0x7c0772f0)))+(!(/*FFI*/ff(((0x3e55be8)))|0))-(0xd1af9efa)))), ((d1)), ((Float32ArrayView[1])))|0);\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [1/0, 0x100000000, -0x100000001, -0x07fffffff, Number.MIN_VALUE, 2**53+2, -(2**53-2), 0.000000000000001, -(2**53), -0, Number.MAX_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 1, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, 0, 0/0, Math.PI, 2**53-2, -0x080000000, -0x100000000, 42, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000000, -1/0]); ");
/*fuzzSeed-116066984*/count=525; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=526; tryItOut("delete this.p0[this]\n");
/*fuzzSeed-116066984*/count=527; tryItOut("\"use strict\"; (eval(\"mathy5 = (function(x, y) { \\\"use strict\\\"; return Math.fround((Math.fround(Math.atan2(mathy1(Math.fround(mathy3(y, y)), y), (((0 >>> 0) << (mathy4(-(2**53), ( + -Number.MAX_SAFE_INTEGER)) >>> 0)) >>> 0))) - Math.fround(Math.hypot(Math.fround(Math.trunc(Math.fround(Math.ceil((x | 0))))), Math.abs((Math.fround((Math.fround((Math.abs(Math.fround(y)) | 0)) !== Math.fround(((( ~ y) >>> 0) != (Math.min(Math.fround(1/0), (( + y) >>> 0)) | 0))))) >>> 0)))))); }); testMathyFunction(mathy5, [0x100000000, -Number.MIN_VALUE, 0x100000001, -1/0, 0x07fffffff, -0x080000001, 2**53+2, Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, 0x0ffffffff, 0x080000000, 42, 1.7976931348623157e308, -0x07fffffff, 2**53, Number.MAX_VALUE, 1/0, -(2**53+2), -0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0, 0x080000001, -0x100000001, -Number.MAX_VALUE, 1, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2]); \", undefined));");
/*fuzzSeed-116066984*/count=528; tryItOut("\"use strict\"; i2 + '';");
/*fuzzSeed-116066984*/count=529; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((( + ( + ( + ( - Math.fround((Math.fround(Math.cos(y)) >= Math.fround(x))))))) - Math.imul(Math.fround((Math.fround(((y | 0) - Math.acosh(Number.MIN_VALUE))) <= Math.fround((Math.fround(( - Math.fround(-0x100000000))) >= 0x080000001)))), (Math.abs(((( ! (0x100000000 | 0)) | 0) | 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 1/0, 0, 0/0, -(2**53-2), 1, 2**53-2, 0x0ffffffff, Math.PI, Number.MAX_VALUE, -0x07fffffff, -1/0, 42, 0x080000001, -0x080000001, 0.000000000000001, -Number.MAX_VALUE, Number.MIN_VALUE, 0x07fffffff, -0, 2**53, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0x100000001, -0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, 2**53+2]); ");
/*fuzzSeed-116066984*/count=530; tryItOut("/*RXUB*/var r = /\\3/gy; var s = \"\\naa0\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=531; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\S{4}){1}(?=\\\\b)^|(?=.)|\\\\W|[^]|(?=\\\\b){7}*?^\", \"gyi\"); var s = false; print(r.exec(s)); ");
/*fuzzSeed-116066984*/count=532; tryItOut("m1.set(p0, a0);");
/*fuzzSeed-116066984*/count=533; tryItOut("tovkke();/*hhh*/function tovkke(NaN){continue ;}");
/*fuzzSeed-116066984*/count=534; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"$\\\\B(?:\\\\2)|(?=\\\\xDc){0,}\\\\1|([^]){0,4}\", \"i\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.match(r)); ");
/*fuzzSeed-116066984*/count=535; tryItOut("g2.v2 = t0.byteOffset;");
/*fuzzSeed-116066984*/count=536; tryItOut("mathy2 = (function(x, y) { return (Math.pow((( + (Math.fround((((((x + (x >>> 0)) >>> 0) | 0) ? (x >>> 0) : (y | 0)) | 0)) >>> 0)) >>> 0), (( + ((( ! y) >>> x) | 0)) | 0)) ? Math.fround(mathy0(( ~ ( + x)), ( + x))) : ( + mathy1(( + (((Math.fround(( - Math.fround((Math.pow((( + ((Math.pow(y, -0x07fffffff) | 0) % ( + Math.trunc(-Number.MAX_VALUE)))) >>> 0), (x | 0)) | 0)))) | 0) != (( + (((y / Math.fround(((y < 0x080000001) | 0))) | 0) ? Math.ceil((Math.acosh(( + y)) >>> 0)) : (((y | 0) <= x) | 0))) | 0)) | 0)), ( + mathy1(((Math.exp((x | 0)) | 0) >>> 0), Math.fround(Math.pow(( + 0x080000001), (Math.pow(Number.MIN_SAFE_INTEGER, x) | 0)))))))); }); testMathyFunction(mathy2, [2**53+2, Number.MIN_VALUE, -0x0ffffffff, 0x080000000, Math.PI, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, 1/0, 0/0, 1, -(2**53-2), 2**53, 42, 0, 2**53-2, -0, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -0x080000001, 0.000000000000001, -Number.MAX_VALUE, -(2**53), 0x100000000, -1/0, Number.MAX_VALUE, 0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, 0x080000001]); ");
/*fuzzSeed-116066984*/count=537; tryItOut("/*RXUB*/var r = r1; var s = s1; print(r.test(s)); ");
/*fuzzSeed-116066984*/count=538; tryItOut("\"use strict\"; h0 = t2[5];function NaN() { return ((p={}, (p.z = undefined)()).unwatch(9)) } (void schedulegc(g0));");
/*fuzzSeed-116066984*/count=539; tryItOut("g2[\"1\"] = f2;");
/*fuzzSeed-116066984*/count=540; tryItOut("gsnitz(/*wrap3*/(function(){ \"use strict\"; var unbpkc = window; (c => null)(); }).prototype, x);/*hhh*/function gsnitz(x){yield;}");
/*fuzzSeed-116066984*/count=541; tryItOut("\"use strict\"; ((\"\\uD664\" instanceof length)());");
/*fuzzSeed-116066984*/count=542; tryItOut("for (var p in o0.h0) { try { /*MXX3*/g1.Object.setPrototypeOf = g2.Object.setPrototypeOf; } catch(e0) { } e1.valueOf = (function() { try { v0 = Object.prototype.isPrototypeOf.call(a1, o1.b2); } catch(e0) { } try { v1 = g1.runOffThreadScript(); } catch(e1) { } try { h0.has = f2; } catch(e2) { } print(this.s2); throw t2; }); }");
/*fuzzSeed-116066984*/count=543; tryItOut("t1[3];");
/*fuzzSeed-116066984*/count=544; tryItOut("\"use strict\"; m0 + '';");
/*fuzzSeed-116066984*/count=545; tryItOut("h2 + m0;");
/*fuzzSeed-116066984*/count=546; tryItOut("v2 = evaluate(\"a2.pop();\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 72 == 17), noScriptRval: true, sourceIsLazy: true, catchTermination: (4277) }));");
/*fuzzSeed-116066984*/count=547; tryItOut("for(let w of (x(/ if (/.*?\\s+?|\u00d4|($)?(?!(?=\\b)|\\3{3})?{0,}/i))) let(d) { for(let c in /*FARR*/[]) let(w = ( /x/g  ? new RegExp(\"((?=[^]\\\\\\u5cad))\\\\B*|\\\\2\\\\2\", \"g\") : length), e = /*MARR*/[true, (-1/0), (-1/0), (-1/0), true].sort((1 for (x in []))), zrbizc) ((function(){let(e, d, jtehap) { return;}})());}this.zzz.zzz;");
/*fuzzSeed-116066984*/count=548; tryItOut("mathy1 = (function(x, y) { return (( ! (((Math.asinh((((( + Math.hypot(( + (y > 1)), ( + x))) | 0) , (( + (( + 0x080000000) ? x : ( + 0x100000001))) | 0)) | 0)) >>> Math.imul((y ** ((y || Number.MAX_SAFE_INTEGER) | 0)), window)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [2**53+2, -0x100000000, -(2**53-2), 1, -Number.MIN_VALUE, -(2**53+2), 2**53, -0x07fffffff, Number.MAX_VALUE, 0x07fffffff, -0x080000000, 1.7976931348623157e308, 42, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0, 2**53-2, -0, Math.PI, 0x080000001, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0x100000000, 0x100000001, 0x080000000, -0x0ffffffff, -1/0, 1/0]); ");
/*fuzzSeed-116066984*/count=549; tryItOut("h0.toSource = (function() { try { t1.set(a1, false); } catch(e0) { } try { h1.get = (new Function).bind((w = /*MARR*/[ 'A' , null, null, null, null]), (({eval: e, /*toXFun*/toString: function() { return length; } }))); } catch(e1) { } Array.prototype.push.apply(a1, [g2, (this.__defineSetter__(\"b\", ({/*TOODEEP*/})) ? let (b) null : (window)( \"\" ) = ( + Math.fround(x)))]); return this.v0; });");
/*fuzzSeed-116066984*/count=550; tryItOut("/*RXUB*/var r = /(?:\\s|(?=\\2))+/gyim; var s = \"a\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=551; tryItOut("m0 + '';");
/*fuzzSeed-116066984*/count=552; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a1, v0, { configurable: (x % 15 == 8), enumerable: x, writable: -13 % -20(), value: h1 });");
/*fuzzSeed-116066984*/count=553; tryItOut("\"use strict\"; v2 = v0[\"15\"];");
/*fuzzSeed-116066984*/count=554; tryItOut("a2.unshift(f2, this.a1);");
/*fuzzSeed-116066984*/count=555; tryItOut("\"use strict\"; v2 = r1.constructor;");
/*fuzzSeed-116066984*/count=556; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; gcslice(20150073); } void 0; }");
/*fuzzSeed-116066984*/count=557; tryItOut("mathy2 = (function(x, y) { return (( ~ (Math.pow(Math.log10(-0), (y >> (((Math.exp((Math.fround(x) ? -0 : Math.fround(x))) | 0) >>> 0) ** (Math.atanh((Math.cbrt((y >>> 0)) >>> 0)) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy2, [42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -0x07fffffff, 2**53+2, 0x080000000, -(2**53), -1/0, 0.000000000000001, Math.PI, 0x100000001, -0x0ffffffff, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 0/0, 1, 0x080000001, -0x100000001, -(2**53-2), Number.MAX_VALUE, 0, -0x080000001, -Number.MIN_VALUE, -0x100000000, Number.MIN_VALUE, 0x100000000, 2**53, -(2**53+2), 1/0]); ");
/*fuzzSeed-116066984*/count=558; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=559; tryItOut("g1.offThreadCompileScript(\"function f1(g0) (\\\"\\\\uDE49\\\" ? Math : undefined)\");");
/*fuzzSeed-116066984*/count=560; tryItOut("with\u0009(/*MARR*/[Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), (0/0), Number.MIN_SAFE_INTEGER, (0/0), ({}), (0/0), (0/0), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), ({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), ({}), ({}), (0/0)].map((/(?!((?:\\3)))|(?!^){0,}|^[^]|R*|[\\xFA\\xD8-\\u1482\\s][^]/gy).bind( \"\" ), /(?![]{2}|(?!\\w{1,2}))/y) < (4277))s2 = '';");
/*fuzzSeed-116066984*/count=561; tryItOut("s1 += 'x';");
/*fuzzSeed-116066984*/count=562; tryItOut("testMathyFunction(mathy2, [-0x080000001, Number.MAX_VALUE, 2**53, 0x0ffffffff, -0, 42, 1.7976931348623157e308, 0x100000000, -0x0ffffffff, -(2**53+2), 0, Number.MIN_VALUE, 0/0, 2**53+2, -0x080000000, -1/0, -(2**53-2), 0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, -0x100000000, 0x080000000, 1/0, 1, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, 2**53-2, 0.000000000000001]); ");
/*fuzzSeed-116066984*/count=563; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-116066984*/count=564; tryItOut("mathy1 = (function(x, y) { return Math.atanh((((0.000000000000001 > mathy0(Math.fround(x), Math.fround(( - ( + (x > x)))))) * x) ? Math.cos((mathy0((( ! (( + Math.min(( + 0x100000001), ( + Number.MIN_VALUE))) >>> 0)) >>> 0), Math.hypot(x, -0x080000001)) >>> 0)) : Math.trunc((Number.MAX_SAFE_INTEGER / (mathy0(y, (mathy0((y | 0), x) >>> 0)) | 0))))); }); testMathyFunction(mathy1, /*MARR*/[{} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, -Infinity, -Infinity, {} = Math.imul(eval, 16), -Infinity, -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, -Infinity, {} = Math.imul(eval, 16), -Infinity, -Infinity, -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, -Infinity, -Infinity, -Infinity, {} = Math.imul(eval, 16), -Infinity, -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, -Infinity, -Infinity, -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, -Infinity, -Infinity, -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, -Infinity, -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), {} = Math.imul(eval, 16), -Infinity, {} = Math.imul(eval, 16), -Infinity]); ");
/*fuzzSeed-116066984*/count=565; tryItOut("/*tLoop*/for (let y of /*MARR*/[new Number(1), new Number(1), new Number(1), new Number(1), -(2**53), new Number(1), -(2**53), -(2**53), -(2**53), -(2**53), new Number(1), -(2**53), -(2**53), new Number(1), new Number(1), new Number(1), -(2**53), new Number(1), new Number(1), new Number(1), new Number(1), -(2**53), new Number(1), -(2**53), new Number(1), -(2**53), new Number(1), -(2**53), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), -(2**53), -(2**53), -(2**53), new Number(1), new Number(1), -(2**53), new Number(1), -(2**53), -(2**53), -(2**53), -(2**53), new Number(1), new Number(1), -(2**53), new Number(1), new Number(1), -(2**53), -(2**53), new Number(1), new Number(1)]) { M:with({\u0009a: x})({window: /^?|[\\cD-\u66fe\\D\\D\u001a]|\\D|.*/g}); }");
/*fuzzSeed-116066984*/count=566; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i2 = ((1.03125) > (Infinity));\n    return +((3.0));\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 1, -0, 2**53, Math.PI, 0x100000001, 1/0, -Number.MIN_VALUE, -0x100000000, 2**53+2, -1/0, -0x080000001, -0x080000000, -(2**53+2), 0, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, -(2**53), 0/0, -(2**53-2), 1.7976931348623157e308, Number.MAX_VALUE, 42, Number.MIN_VALUE, 0x07fffffff, 2**53-2, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=567; tryItOut("mathy1 = (function(x, y) { return Math.fround(( ~ ((Math.imul(((( ! (( ! (Math.expm1((x | 0)) >>> 0)) >>> 0)) >>> 0) | 0), (Math.pow(y, y) | 0)) | 0) > ( ! y)))); }); testMathyFunction(mathy1, [-0x080000001, 0x100000001, -0x07fffffff, 0, -(2**53), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, Math.PI, -0, 1, -0x080000000, 2**53, 0/0, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, 2**53-2, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), -0x0ffffffff, 0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 42, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-116066984*/count=568; tryItOut("");
/*fuzzSeed-116066984*/count=569; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(e0, v1);");
/*fuzzSeed-116066984*/count=570; tryItOut("/*RXUB*/var r = new RegExp(\"(?:((?:(?:[^]))*))\", \"g\"); var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-116066984*/count=571; tryItOut("/*RXUB*/var r = new RegExp(\"\\u009c|(?:[^\\\\D]{1}){1024,1026}\", \"i\"); var s = \"aaaaaaaaaaaa\\u09c2aaaaaaaaa\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-116066984*/count=572; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0/0, 2**53+2, 0.000000000000001, 1/0, -0, -0x080000001, -(2**53+2), -0x080000000, 0x100000001, 0x080000000, 2**53-2, 0, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53, Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, 1, 0x100000000, -(2**53-2), -0x07fffffff, 42, -Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 0x0ffffffff, Math.PI, -0x100000000, -(2**53)]); ");
/*fuzzSeed-116066984*/count=573; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-116066984*/count=574; tryItOut("(void schedulegc(g2));let c = /(?!\u00f2)[\\u00ea-\\ufA00]/gym;");
/*fuzzSeed-116066984*/count=575; tryItOut("/*oLoop*/for (var jpbqjj = 0; jpbqjj < 72; ++jpbqjj) { ; } ");
/*fuzzSeed-116066984*/count=576; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g1.e0, o1);");
/*fuzzSeed-116066984*/count=577; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=578; tryItOut("\"use asm\"; yield /*UUV1*/(x.getUint32 = function (y, ...x) { return b } );with({}) let(x) { w;}");
/*fuzzSeed-116066984*/count=579; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = new RegExp(\"\\\\2\", \"gyi\"); var s = Math.max(\"\\uF22E\", -1568083920) ^= (/\\3/ym &= Object.defineProperty(x, \"pop\", ({writable: false, configurable: false, enumerable: true}))).valueOf(\"number\"); print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=580; tryItOut("this.g0.v2 = this.g2.runOffThreadScript();");
/*fuzzSeed-116066984*/count=581; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=582; tryItOut("b0.__proto__ = o0;");
/*fuzzSeed-116066984*/count=583; tryItOut("\"use strict\"; h1.get = f1;");
/*fuzzSeed-116066984*/count=584; tryItOut("mathy2 = (function(x, y) { return ( + ( + (( + Math.hypot(0x100000001, -Number.MAX_VALUE)) , ( + (Math.max(y, Math.max((( + Math.asinh(( + y))) ** -0), Math.hypot(y, ( + Number.MIN_VALUE)))) % ( ~ ( + ( ~ ( + Math.imul(x, (Math.fround((-(2**53-2) ? (-(2**53) | 0) : Math.fround(x))) | 0))))))))))); }); testMathyFunction(mathy2, [Math.PI, 1/0, -0x080000000, 0x0ffffffff, 1, 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0, 0x07fffffff, -Number.MAX_VALUE, 0x080000000, -0x080000001, 0/0, 42, 2**53+2, -0x100000000, 2**53-2, -Number.MIN_VALUE, -0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), 0x100000001, 2**53, -0x0ffffffff, 0x080000001, -1/0, -(2**53-2), -0, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=585; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.cos(((( + ( + (( + (Math.pow((( + Math.min(( + y), ( + (Math.tan(Math.fround(y)) >>> 0)))) >>> 0), (Number.MIN_VALUE | 0)) | 0)) | Math.ceil(Math.cbrt(y))))) * ( + ( ! ( + (Math.fround(y) ? ((((y >>> 0) - Math.fround(-Number.MAX_VALUE)) | 0) | 0) : (Number.MAX_VALUE ? Math.atan2(y, Math.round(y)) : y)))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-116066984*/count=586; tryItOut("Object.seal(i1);");
/*fuzzSeed-116066984*/count=587; tryItOut("testMathyFunction(mathy2, [0x100000001, 2**53-2, -(2**53-2), 0x080000001, -0x100000001, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, -0, -0x080000000, -0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 1/0, Number.MIN_VALUE, -0x100000000, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x07fffffff, -Number.MAX_VALUE, 0.000000000000001, -(2**53), Math.PI, 0x080000000, 42, -1/0, 0]); ");
/*fuzzSeed-116066984*/count=588; tryItOut("\"use strict\"; Array.prototype.shift.call(a0, i0);");
/*fuzzSeed-116066984*/count=589; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.imul(Math.clz32(( ~ Math.PI)), (((((Math.log10((-0x100000001 | 0)) | 0) < ( + (( + y) % Math.fround((Math.fround(y) ? Math.fround(x) : ((((y >>> 0) < y) >>> 0) | 0)))))) >>> 0) < mathy4(y, ( ! ( + (x != Math.fround(mathy2(y, 0x07fffffff))))))) >>> 0)); }); testMathyFunction(mathy5, [0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -0x100000000, -1/0, -0, -0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, -Number.MIN_VALUE, 0.000000000000001, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, 2**53-2, -(2**53), 42, -(2**53+2), 2**53+2, 1, -0x0ffffffff, -0x080000001, 0x07fffffff, 0x080000000, Number.MIN_VALUE, 0x100000001, 0x0ffffffff, 0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-116066984*/count=590; tryItOut("\"use strict\"; /*vLoop*/for (var kdycap = 0; kdycap < 0; ++kdycap) { e = kdycap; print(c = x);v1 = evalcx(\"h1.hasOwn = f0;\", this.g1); } ");
/*fuzzSeed-116066984*/count=591; tryItOut("t1 = new Uint8Array(b2)\n");
/*fuzzSeed-116066984*/count=592; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( ~ Math.pow(Math.fround(mathy0(Math.cosh(x), ( + Math.log2(( + y))))), (Math.fround((x / Math.fround(y))) ^ ( + x)))) && (mathy0(((Math.exp(mathy0(x, (( ~ x) & y))) == ( + (( + ( ~ (Math.imul(x, -Number.MAX_VALUE) | 0))) ? Math.fround(( ! (mathy0((y | 0), (42 | 0)) | 0))) : Math.fround(Math.sin((0/0 | 0)))))) | 0), (Math.min(-0x0ffffffff, mathy0(Math.tanh(( + x)), Math.pow(-0x100000000, y))) | 0)) | 0)); }); testMathyFunction(mathy1, [[], (new Boolean(false)), undefined, ({valueOf:function(){return '0';}}), (new String('')), ({toString:function(){return '0';}}), objectEmulatingUndefined(), (new Number(-0)), '\\0', null, NaN, false, /0/, (new Boolean(true)), [0], (new Number(0)), (function(){return 0;}), ({valueOf:function(){return 0;}}), '/0/', '', '0', 0.1, -0, 0, true, 1]); ");
/*fuzzSeed-116066984*/count=593; tryItOut("\"use strict\"; a0.reverse(t2);function w() { \"use strict\"; return e } ;");
/*fuzzSeed-116066984*/count=594; tryItOut("if(true) { if (Math.expm1(x) ? [1,,] : (x) = 2) this.a2 = r0.exec(this.s2);} else {o0 = new Object; }");
/*fuzzSeed-116066984*/count=595; tryItOut("testMathyFunction(mathy5, [-0x0ffffffff, 1, -0x080000000, 42, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 0x07fffffff, -1/0, 1/0, Number.MIN_VALUE, 0x080000001, 0/0, 2**53, 2**53+2, 0x080000000, 2**53-2, 0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, -(2**53+2), Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, 0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, 0, -Number.MAX_VALUE, -0x07fffffff, Math.PI, -0x100000000]); ");
/*fuzzSeed-116066984*/count=596; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=597; tryItOut("a1.unshift();");
/*fuzzSeed-116066984*/count=598; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2\\xA9+?([^])+?|([^\u001e]|(\\d)?){3,4}/y; var s = \"\\u0089\\u0089\\naaaa\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=599; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-116066984*/count=600; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return mathy3(Math.fround((Math.imul(( + mathy0(mathy3(Math.hypot(( + x), Math.max((Math.log1p(y) >>> 0), (x >>> 0))), (( - ( + ( ~ Math.hypot(-0, y)))) >>> 0)), ( + ( - ( + Math.tan(( + Math.fround(( ! (Math.cos((x >>> 0)) >>> 0)))))))))), (( + Math.tanh((Math.min((Math.max(( + x), ( - (y | 0))) | 0), (Math.fround((x != y)) | 0)) | 0))) >>> 0)) >>> 0)), Math.fround(Math.log2((Math.fround(( ~ Math.fround(Math.hypot(Math.fround(y), Math.fround((Math.atan2(x, y) ** y)))))) , (Math.min(( + Math.tanh(Math.fround(x))), mathy3(1, x)) >= y))))); }); testMathyFunction(mathy4, [-0x080000000, 0x080000000, 0x07fffffff, 1, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -0x080000001, -Number.MIN_VALUE, -(2**53+2), -0x100000001, -0, -(2**53), Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, 1/0, Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, -1/0, 0x100000001, 1.7976931348623157e308, -0x07fffffff, Number.MIN_VALUE, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, Math.PI, -Number.MAX_SAFE_INTEGER, 0, 2**53]); ");
/*fuzzSeed-116066984*/count=601; tryItOut("L: (x);");
/*fuzzSeed-116066984*/count=602; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.min((( ! (( + Math.expm1(( + x))) | 0)) << Math.fround((Math.fround(((x >>> 0) * 2**53-2)) + ( - Math.imul(Math.pow((x >>> 0), Math.atan2(0x080000001, y)), -(2**53+2)))))), Math.cosh(((Math.fround(x) ? (( + ( + x)) >>> 0) : ((( - (Math.max(y, (( + ( - ( + x))) | 0)) >>> 0)) ? x : (-0x080000001 | 0)) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy0, [-0x0ffffffff, -0x07fffffff, -0, 42, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, 0x100000000, 0/0, -0x100000000, -Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, 2**53+2, -0x080000001, -1/0, 2**53-2, 1/0, -(2**53), -0x080000000, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 2**53, 0x0ffffffff, 0, -(2**53+2), 1, -Number.MAX_VALUE, 0x080000000, -0x100000001]); ");
/*fuzzSeed-116066984*/count=603; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((((Math.sqrt((((Math.fround(( + Math.fround(Math.max(( ~ x), Math.fround(x))))) | 0) >= (Math.pow(x, Math.max(x, ( + Math.asin(( + y))))) | 0)) | 0)) >>> 0) >>> 0) ? (Math.expm1(Math.log1p(Math.asin(-0x080000000))) >>> 0) : (Math.sqrt(( ! (((Math.atan2((x | 0), (Math.round(y) | 0)) >>> 0) ^ (x <= (( ~ (-Number.MAX_VALUE >>> 0)) >>> 0))) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), 1/0, -0x100000000, -0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, 0/0, Math.PI, -(2**53), -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, -0x100000001, -0x080000001, 0x080000000, -(2**53+2), 1.7976931348623157e308, 1, 0x100000001, 42, 0, 0x080000001, -1/0, 0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-116066984*/count=604; tryItOut("/*oLoop*/for (var wntchj = 0; wntchj < 6 && (-5); ++wntchj) { a0.shift(o1); } ");
/*fuzzSeed-116066984*/count=605; tryItOut("testMathyFunction(mathy3, [2**53, 2**53+2, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, -0x0ffffffff, 0x080000000, -(2**53-2), 0.000000000000001, -0x100000000, 0, -Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, 0x100000001, 1, -0, 0/0, 0x0ffffffff, -(2**53), 42, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -0x100000001, 0x07fffffff, 2**53-2, 1.7976931348623157e308, Math.PI, 0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=606; tryItOut("\"use strict\"; var gyctey = new SharedArrayBuffer(2); var gyctey_0 = new Int8Array(gyctey); gyctey_0[0] = 1.2e3; print(gyctey_0);");
/*fuzzSeed-116066984*/count=607; tryItOut("mathy1 = (function(x, y) { return Math.sign(( + (( + Math.fround((Math.fround(Math.atan2(y, Math.cbrt(y))) > Math.fround(( + Math.sin(( + ((Math.imul(x, ( + y)) >>> 0) === y)))))))) + Math.fround((Math.hypot((( + -(2**53+2)) | 0), (Math.atan2((((y === -Number.MAX_SAFE_INTEGER) | 0) || (Math.acos(x) | 0)), ( - 0.000000000000001)) | 0)) | 0))))); }); testMathyFunction(mathy1, [0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, -(2**53-2), -0x100000001, -Number.MAX_VALUE, -(2**53+2), -0x100000000, -0, -(2**53), 1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, -0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 42, 2**53+2, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, 1.7976931348623157e308, 2**53-2, Number.MAX_VALUE, Math.PI, 0, 0.000000000000001, -0x080000001, 0/0, -1/0]); ");
/*fuzzSeed-116066984*/count=608; tryItOut("/*infloop*/do {var nxdvpr = new ArrayBuffer(16); var nxdvpr_0 = new Uint8ClampedArray(nxdvpr); nxdvpr_0[0] = 12; p2.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) { var r0 = a8 | a6; var r1 = 0 % a6; var r2 = r1 * 2; var r3 = nxdvpr & 7; var r4 = nxdvpr_0 % 4; var r5 = r3 & 6; var r6 = a2 * a8; print(r2); a6 = 3 | a11; var r7 = 2 * 1; var r8 = a12 + 5; a4 = a13 | r8; var r9 = x & x; x = 0 % a0; var r10 = a12 & a3; var r11 = nxdvpr_0[0] & 7; var r12 = 9 + r5; var r13 = r9 ^ r9; var r14 = a0 | 5; var r15 = 4 / r9; nxdvpr_0 = 3 / 3; r12 = r15 ^ r1; var r16 = r15 % r1; var r17 = 2 + r6; var r18 = 6 - r0; var r19 = a15 - 6; var r20 = a13 ^ nxdvpr_0[3]; var r21 = 6 & r8; print(r10); var r22 = 3 - 4; var r23 = a2 / a12; r8 = 4 ^ 8; var r24 = r9 & a0; var r25 = r22 * r21; var r26 = r24 | r11; print(a12); x = a14 | r19; a15 = x % r13; x = a1 / a10; var r27 = r1 & a8; var r28 = x & nxdvpr_0[0]; var r29 = a3 & 3; var r30 = a5 + 1; var r31 = r9 % a6; var r32 = r2 % a14; var r33 = r13 ^ r11; var r34 = r18 + a1; var r35 = r14 - 6; var r36 = r23 * 5; var r37 = nxdvpr_0 | 2; var r38 = a7 & a12; var r39 = r5 | 2; a5 = 6 & r10; var r40 = r12 + 8; var r41 = r23 % nxdvpr_0[0]; x = r16 - 9; var r42 = r29 + r8; nxdvpr = 6 ^ 7; var r43 = 1 / 5; var r44 = 8 % r41; var r45 = r8 * nxdvpr_0[3]; var r46 = r36 - 7; var r47 = r12 * 1; a4 = r23 - 8; r42 = r20 ^ 2; var r48 = 1 - a14; var r49 = 6 * a1; var r50 = 4 | r4; r47 = r12 - nxdvpr_0[0]; var r51 = 1 & nxdvpr; var r52 = a12 ^ r9; r13 = a6 - 9; print(a14); var r53 = 9 / r44; var r54 = 4 % 7; nxdvpr_0 = r13 / a2; var r55 = r5 - r51; var r56 = 6 % 7; var r57 = r32 / r21; r26 = r22 ^ r37; var r58 = a14 | r25; var r59 = r29 ^ 5; var r60 = r5 + 8; var r61 = 8 | 6; r8 = r3 + r37; var r62 = r51 & 1; var r63 = r27 & r17; a1 = 5 / r35; var r64 = r9 | r38; print(a8); var r65 = r37 / r50; var r66 = 4 % r8; var r67 = r21 ^ 5; var r68 = 6 ^ r6; var r69 = r65 | r66; r32 = r35 & r62; var r70 = 1 % 5; var r71 = a11 * 3; var r72 = r30 + r63; print(r37); var r73 = 0 / r7; var r74 = r45 % 9; print(r4); var r75 = 8 % r33; a15 = a0 % 4; var r76 = 2 ^ r5; var r77 = 4 + a16; var r78 = 6 + 4; var r79 = 0 - 1; r6 = r14 % 9; r78 = a13 ^ 4; var r80 = r37 / r36; var r81 = 8 ^ 1; var r82 = r21 * r12; var r83 = 4 ^ r15; r1 = 3 - 6; var r84 = 8 % r3; return a16; });\"\\u4BA6\";([,,z1]);m0 = new Map;this.v2 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 6 != 2), sourceIsLazy: true, catchTermination: (nxdvpr % 18 == 13) }));Array.prototype.pop.call(a2);selectforgc(o2);p0 + '';/*tLoop*/for (let x of /*MARR*/[Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, new Boolean(false), Infinity, objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), new Boolean(false), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined()]) { Array.prototype.push.call(a0, g0);\n{}\n } } while(this.__defineSetter__(\"x\", /*wrap3*/(function(){ \"use strict\"; var blumbb = null; (new Function)(); })));");
/*fuzzSeed-116066984*/count=609; tryItOut("\"use strict\"; {s0 = s1.charAt(9);s2 = g1.objectEmulatingUndefined(); }");
/*fuzzSeed-116066984*/count=610; tryItOut("mathy3 = (function(x, y) { return Math.hypot(( + Math.tanh(( + ( + Math.atan2(( + Math.cos(y)), ( + (( + ((Math.fround(Math.atan2(y, y)) >= (Math.fround(Math.min(Math.fround(x), (y | 0))) || 1.7976931348623157e308)) | 0)) | 0))))))), Math.abs(( - (Math.atan2(( + Math.PI), Math.cos(2**53+2)) >>> 0)))); }); testMathyFunction(mathy3, [2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, 42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -0x080000000, -(2**53+2), -0x07fffffff, Math.PI, -0x0ffffffff, 0x080000000, -(2**53), 2**53+2, -(2**53-2), Number.MAX_VALUE, 0x080000001, 0x100000000, 0/0, 1.7976931348623157e308, -0x100000000, 1/0, 1, -0, 2**53, 0.000000000000001, 0, -0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000001]); ");
/*fuzzSeed-116066984*/count=611; tryItOut("m2.has(f1);");
/*fuzzSeed-116066984*/count=612; tryItOut("v2 = t2.length;");
/*fuzzSeed-116066984*/count=613; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.pow((( + Math.sinh((( + mathy2(( + (( + x) + ( + (( + Math.hypot(x, (((x >>> 0) ? (-0x100000001 >>> 0) : (x >>> 0)) | 0))) ? Math.pow(Math.atanh((y >>> 0)), Math.fround(x)) : ( + 1.7976931348623157e308))))), ( + ( + Math.trunc(( + ( ~ ( + Math.fround(( ~ Math.fround(y))))))))))) | 0))) | 0), (Math.atanh((Math.cos(y) - (( ~ ((( ! x) | 0) >>> 0)) | 0))) | 0)) | 0); }); testMathyFunction(mathy3, [-0, 2**53+2, -0x07fffffff, 1/0, 0x0ffffffff, -Number.MIN_VALUE, 0/0, 0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0, -0x100000001, 42, 1, -1/0, Number.MAX_VALUE, 2**53, 1.7976931348623157e308, 0.000000000000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000000, -0x0ffffffff, 0x100000001, -0x080000001, -Number.MAX_VALUE, -(2**53-2), Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=614; tryItOut("function shapeyConstructor(vtgyxd){if ((4277)) Object.defineProperty(this, \"clear\", ({}));this[\"callee\"] = eval;return this; }/*tLoopC*/for (let b of /*FARR*/[]) { try{let qzcxzt = new shapeyConstructor(b); print('EETT'); for (var p in this.m0) { /*MXX1*/o1 = g0.Array.prototype.toString; }}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-116066984*/count=615; tryItOut("\"use strict\"; return;print(this.zzz.zzz);");
/*fuzzSeed-116066984*/count=616; tryItOut("\"use strict\"; t0 = a2[({valueOf: function() { { void 0; abortgc(); }return 9; }})];");
/*fuzzSeed-116066984*/count=617; tryItOut("mathy0 = (function(x, y) { return (Math.exp(( + (( + ( + ( ! Math.fround(( ! Math.fround(y)))))) + (Math.fround((Math.fround(x) + Math.fround(((Math.PI >>> 0) ? (x >>> 0) : (x >>> 0))))) >>> 0)))) ? Math.atan2(( + Math.atan2((Math.max((Math.fround((x | 0)) | 0), y) | 0), (Math.ceil(((Math.expm1(( + x)) | 0) >>> 0)) >>> 0))), (( - (( ~ Math.max(y, ((((-(2**53) ? x : Number.MAX_VALUE) >>> 0) ** Math.fround((-Number.MAX_SAFE_INTEGER > y))) >>> 0))) >>> 0)) >>> 0)) : ( - Math.imul(( ! -Number.MAX_SAFE_INTEGER), Math.fround(Math.fround(( ! Math.fround((( + x) ? ( + Math.fround((Math.fround(x) !== ( + y)))) : ( + y))))))))); }); testMathyFunction(mathy0, [0, 0x100000001, -0x100000001, 2**53+2, -1/0, -(2**53+2), -0x080000001, Math.PI, 0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, -0, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 42, 1, 0x080000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, 0x07fffffff, -(2**53-2), 0/0, 0.000000000000001, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=618; tryItOut("\"use strict\"; h0.enumerate = (function() { try { o1.v1 = new Number(a0); } catch(e0) { } v0 = (t0 instanceof o0.t0); return h2; });");
/*fuzzSeed-116066984*/count=619; tryItOut("print(x);throw x;");
/*fuzzSeed-116066984*/count=620; tryItOut("");
/*fuzzSeed-116066984*/count=621; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=622; tryItOut("/*bLoop*/for (let zjxzrm = 0; zjxzrm < 110; ++zjxzrm) { if (zjxzrm % 4 == 2) { e1.add(e0); } else { (//h\n(Math.pow(12,  /x/ ))); }  } ");
/*fuzzSeed-116066984*/count=623; tryItOut("v1 = r2.test;");
/*fuzzSeed-116066984*/count=624; tryItOut("/*bLoop*/for (var tgwqqz = 0; tgwqqz < 54; ++tgwqqz) { if (tgwqqz % 9 == 5) { (/\\3/gim); } else { m2.has(e0); }  } ");
/*fuzzSeed-116066984*/count=625; tryItOut("a0.shift();let x = c-- % (this.__defineGetter__(\"b\", JSON.parse)) ? new String('q') : 8.unwatch(\"toString\");");
/*fuzzSeed-116066984*/count=626; tryItOut("/*bLoop*/for (var azdbfz = 0; azdbfz < 49; ++azdbfz) { if (azdbfz % 6 == 5) { f2.valueOf = (function() { try { print(p0); } catch(e0) { } try { for (var v of b2) { try { delete o1.t2[4]; } catch(e0) { } try { /*ADP-1*/Object.defineProperty(a1, 14, ({})); } catch(e1) { } /*MXX3*/this.g0.Uint8Array.prototype = this.g2.g0.Uint8Array.prototype; } } catch(e1) { } try { f0(v0); } catch(e2) { } print(a2); return p1; }); } else { /*RXUB*/var r = r2; var s = s0; print(uneval(s.match(r)));  }  } ");
/*fuzzSeed-116066984*/count=627; tryItOut("v0 = Object.prototype.isPrototypeOf.call(i0, t0);");
/*fuzzSeed-116066984*/count=628; tryItOut("mathy2 = (function(x, y) { return (( + Math.fround(( + ((((mathy1(mathy0((y | 0), ((x < y) | 0)), (y >>> 0)) >>> 0) >>> 0) << ( + (mathy0(( ! -(2**53-2)), ( + Math.atan(y))) | 0))) >> Math.fround(Math.clz32(( + Math.min(x, y)))))))) >>> 0); }); testMathyFunction(mathy2, [({valueOf:function(){return '0';}}), NaN, 1, (new String('')), false, '', '0', (function(){return 0;}), '\\0', null, ({valueOf:function(){return 0;}}), true, /0/, ({toString:function(){return '0';}}), 0, '/0/', undefined, (new Boolean(true)), 0.1, [0], (new Number(0)), (new Boolean(false)), [], -0, (new Number(-0)), objectEmulatingUndefined()]); ");
/*fuzzSeed-116066984*/count=629; tryItOut("\"use strict\"; /*oLoop*/for (let yixbef = 0; yixbef < 75; ++yixbef) { this.f0(o0); } ");
/*fuzzSeed-116066984*/count=630; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.hypot(Math.fround(Math.fround(Math.hypot(( ~ ( + (y | 0))), (( + (x === (( + mathy0(0x07fffffff, x)) | -(2**53-2)))) | 0)))), ( + Math.cbrt(( + (( ! (( ! y) >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [-(2**53-2), 0/0, 0x0ffffffff, Number.MAX_VALUE, -0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, 2**53-2, -0x080000001, 0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, 2**53+2, -(2**53+2), -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, 0, 2**53, 42, 1.7976931348623157e308, Math.PI, -0x100000001, -0x080000000, 0.000000000000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 1, -(2**53)]); ");
/*fuzzSeed-116066984*/count=631; tryItOut("s0 += s2;v2 = g0.eval(\"function f2(m0)  { \\\"use strict\\\"; g0.offThreadCompileScript(\\\"print(window);\\\"); } \");");
/*fuzzSeed-116066984*/count=632; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + Math.fround((Math.fround(( - x)) < Math.sinh((x == Math.sin(x)))))) | 0); }); ");
/*fuzzSeed-116066984*/count=633; tryItOut("a1.shift(f0);");
/*fuzzSeed-116066984*/count=634; tryItOut("this.e0.delete(s2);");
/*fuzzSeed-116066984*/count=635; tryItOut("\"use strict\"; v0 = (t1 instanceof a1);");
/*fuzzSeed-116066984*/count=636; tryItOut("this.g0.s0 += s2;");
/*fuzzSeed-116066984*/count=637; tryItOut("a2 = arguments.callee.arguments;");
/*fuzzSeed-116066984*/count=638; tryItOut("let x, z = function(y) { m0.set(m0, m2); }.prototype, kmsxnv, x = x, eval = intern(delete x.x), x = Math.acosh(x), NaN, dvggvb, x = Math.hypot(-6, -7), \u3056;/* no regression tests found */");
/*fuzzSeed-116066984*/count=639; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x100000000, 0.000000000000001, -Number.MAX_VALUE, 0/0, 1, Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), Math.PI, 2**53+2, 0x07fffffff, -0, -(2**53), 2**53, -0x100000000, 2**53-2, -0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000001, 0, 1/0, -0x07fffffff, -1/0, -0x0ffffffff, -(2**53-2), -0x080000001, 1.7976931348623157e308, 42, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=640; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atanh((Math.fround(mathy0(Math.fround((((((( + Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround(x)))) ? x : ((Math.clz32((y >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0) * (y >>> 0)) >>> 0)), Math.fround(x))) & Math.cosh((Math.log1p((y >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-116066984*/count=641; tryItOut(";");
/*fuzzSeed-116066984*/count=642; tryItOut("v1 = t2.length;");
/*fuzzSeed-116066984*/count=643; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    i1 = (i1);\n    switch ((~~(+/*FFI*/ff(((-4611686018427388000.0)), ((+(0x0))))))) {\n      default:\n        {\n          return +((-4097.0));\n        }\n    }\n    i1 = (i1);\n    return +((-1.001953125));\n    {\n      {\n        {\n          {\n            return +((+pow(((((+((-134217729.0)))) % ((-144115188075855870.0)))), ((+((-2147483647.0)))))));\n          }\n        }\n      }\n    }\n    return +((1152921504606847000.0));\n  }\n  return f; })(this, {ff: Object.getPrototypeOf}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [2**53, -0x100000000, 0x100000001, -Number.MIN_VALUE, 0x100000000, Number.MIN_VALUE, -1/0, 2**53-2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, Math.PI, -(2**53), 0x080000001, -Number.MAX_VALUE, -(2**53+2), 0x07fffffff, 1/0, 0x080000000, 1.7976931348623157e308, -0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, -0x100000001, 0.000000000000001, -(2**53-2), -0x0ffffffff, -0x080000000, 0, 2**53+2, Number.MAX_VALUE, -0]); ");
/*fuzzSeed-116066984*/count=644; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=645; tryItOut("t2.set(g1.t2, 4);function ((makeFinalizeObserver('nursery'))).__proto__(a, x = b = Proxy.createFunction(({/*TOODEEP*/})(\"\\u0DA4\"), new RegExp(\".+?|[\\\\x1f\\\\W]?\", \"gi\")), x = (makeFinalizeObserver('tenured')), y, x, x, eval, c =  '' , b, x =  '' , z, x, x, window, e, w, b, c = x, a, \u3056 = /\\2/g, a, NaN, x, b, x, x = \"\\uA989\", d, NaN, x, w, z = 17, x, x = new RegExp(\"\\\\3\", \"i\"), x =  /x/ ) { print(x); } function  x (this.a = x, e) { return Math.max(-0, this) } ");
/*fuzzSeed-116066984*/count=646; tryItOut("/*bLoop*/for (let vqdfib = 0, x = true; vqdfib < 59; ++vqdfib) { if (vqdfib % 54 == 43) { /* no regression tests found */ } else { Array.prototype.reverse.call(a0); }  } ");
/*fuzzSeed-116066984*/count=647; tryItOut("\"use strict\"; /*RXUB*/var r = /((?:\\1))/m; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116066984*/count=648; tryItOut("m2.set(this.b0, h0);");
/*fuzzSeed-116066984*/count=649; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.fround(Math.ceil(Math.fround(Math.fround(mathy1(Math.fround(Math.sin(y)), Math.fround(( ! (Math.atan2(Math.cos((x | 0)), ( - -(2**53+2))) | 0)))))))) * ((((((( ! x) | 0) * Math.fround(x)) | 0) * Math.fround(Math.pow(((x & ( - Math.fround(x))) >>> 0), -0x100000001))) | 0) <= mathy3(((mathy0((x >>> 0), (-0 >>> 0)) >>> 0) >>> 0), (x ^ (((( - 1/0) >>> 0) , (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [2**53, 0x080000000, 0x100000000, -(2**53), 0/0, 1/0, 0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -(2**53-2), Math.PI, -1/0, -0x080000001, 0.000000000000001, 2**53-2, -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, 42, -0, Number.MAX_VALUE, -0x100000001, Number.MIN_VALUE, -0x080000000, 2**53+2, -Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=650; tryItOut("a1.push(s0, \"\\u9E34\");");
/*fuzzSeed-116066984*/count=651; tryItOut("/*RXUB*/var r = /(?!(?!^\\W{0,3}.+(\\W?(?!\\b)|([^\\S\\u919c\\cT])\\B)*))/gm; var s = \"\\n11\\u00d9_\\n\\u7d391\"; print(s.replace(r, '\\u0341', \"im\")); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=652; tryItOut("");
/*fuzzSeed-116066984*/count=653; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o2.g2.g0, s1);");
/*fuzzSeed-116066984*/count=654; tryItOut("mathy0 = (function(x, y) { return ( + Math.fround(( + ((((( ~ (( + Math.hypot((x >>> 0), (Math.fround(Math.trunc(Math.fround(y))) >>> 0))) >>> 0)) >>> 0) | 0) ? (Math.fround(Math.pow(Math.fround((Math.imul(( + y), Math.hypot(( ! x), (1 >>> 0))) | 0)), Math.fround(Math.min(( + ( ~ ( + 2**53-2))), ( + (-0x100000001 >= ( - (Math.fround(Number.MIN_VALUE) , Math.fround(y))))))))) | 0) : (Math.fround(Math.tan(Math.round(Math.fround((((2**53+2 / ( ~ y)) >>> 0) ? Math.exp(0x100000001) : Number.MIN_SAFE_INTEGER))))) | 0)) | 0)))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 2**53-2, -1/0, 0/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, 42, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0, 0x080000001, 0x100000000, -(2**53+2), -0x080000000, 2**53, Math.PI, 1/0, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -(2**53), 2**53+2, -0x0ffffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 0, 1.7976931348623157e308, 0x100000001, 0.000000000000001]); ");
/*fuzzSeed-116066984*/count=655; tryItOut("/*vLoop*/for (var uuidfc = 0; uuidfc < 84; ++uuidfc,  \"\" ) { let c = uuidfc; print(c); } function NaN()eval(\"/* no regression tests found */\", (c) = y)m0 = new WeakMap;");
/*fuzzSeed-116066984*/count=656; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var sqrt = stdlib.Math.sqrt;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      return ((((0x0) >= (((/*FFI*/ff()|0))>>>((0xd3ea0ef8)+((0xba00ab2)))))))|0;\n    }\n    i0 = (/*FFI*/ff(((imul((!(i0)), (0xfc26f994))|0)), ((~~(-3.0))), ((((Int8ArrayView[((0xfcf20f05)-([[1]])) >> 0])) | (-((0x2fe83d6e) >= (((0xffffffff))>>>((0x2b3b3b90))))))), ((1.888946593147858e+22)), ((((-256.0)) % ((-2147483647.0)))))|0);\n    {\n      {\n        {\n          {\n            (Uint32ArrayView[4096]) = (((((!(i0))) << ((((0x0) / (0x3c5fcd0))>>>((0x45a9f770) / (0xe7a81d1b))) % (((0x37ac1a29) % (0x5316ffd3))>>>((0x3543b6fb)+(0xffffffff))))) > (imul((0xfc53070e), (!((((0xf9bd09f2)*0xf5d59) ^ ((0xffffffff))))))|0))+(0xf837716a));\n          }\n        }\n      }\n    }\n    d1 = (d1);\n    (Float64ArrayView[(((0xe174e5d0) != (((0xfed74aa6)-(0xf6e53f31)+(0xd413db84))>>>((0x1557647a))))) >> 3]) = ((d1));\n    d1 = (NaN);\n    d1 = (((28)( /x/ )));\n    i0 = (i0);\n    i0 = (i0);\n    return (((0x52554530) / ((x)|0)))|0;\n    i0 = ((imul((0x7ccb6ac9), (0xffffffff))|0));\n    return ((((+(0.0/0.0)) != (((NaN)) * ((+sqrt((((void shapeOf((yield this))))))))))+(0xfd6cd489)))|0;\n    switch ((~((((0x6c157376)) | ((0xfa0b9cbe))) % (((0xfbeae567)) << ((0x5dc7c780)))))) {\n      default:\n        i0 = (i0);\n    }\n    i0 = (0xe37e47b9);\n    i0 = ((((i0)+(i0))>>>((0xf951520a)-(0xa475bb3b))) < ((((((i0)-((0xfe1e43dc) ? (0xf88635d9) : (0x217e830e))) | (-((0xffd15f2d) ? (0xfc54168d) : (0xf96d7817)))) < ((((0x5415fabb) > (0x6ade5e17))) << (-(0xfdbd1cbc)))))>>>((0xfc6b21f8)-(i0))));\n    i0 = (i0);\n    {\n      (Float64ArrayView[((((0x2ba69528) % (0x8bee50e))>>>((0xffffffff)+(0x92b27393)-(0xc7afdee7))) % (0x24f20b50)) >> 3]) = ((-140737488355329.0));\n    }\n    d1 = (((-7.555786372591432e+22)) * ((+atan2(((1048576.0)), (((+((d1))) + (d1)))))));\n    return (((Int8ArrayView[((0x0) / (0x49bba218)) >> 0])))|0;\n  }\n  return f; })(this, {ff: (let (a =  /x/ )  \"\" )}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x0ffffffff, 0x080000001, 0.000000000000001, -0x100000001, -(2**53), Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, 1, 0, -1/0, 0x100000001, 42, -0x100000000, -(2**53-2), -0, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, -0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -0x080000000, 0x080000000, 0/0, Math.PI, 1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=657; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.min(((( + mathy0(y, (-(2**53-2) | 0))) && ( + mathy0(x, Math.fround(mathy0(((((y | 0) ? (y | 0) : (Math.hypot((Math.round(-(2**53+2)) >>> 0), Math.fround(Math.log2(42))) >>> 0)) | 0) >>> 0), (y >>> 0)))))) >>> 0), ((Math.sqrt(Math.max(( + ( ! 0.000000000000001)), (Math.sign(((( ~ x) ? y : Math.atan2(y, (1.7976931348623157e308 >>> 0))) >>> 0)) >>> 0))) | 0) + ( + (((Math.min((Math.imul(((((x | 0) && Math.fround(x)) | 0) >>> 0), ( + Math.fround(Math.imul(( - x), -(2**53-2))))) >>> 0), (y | 0)) | 0) ? y : (x | 0)) | 0)))); }); ");
/*fuzzSeed-116066984*/count=658; tryItOut("v2 = this.g2.runOffThreadScript();");
/*fuzzSeed-116066984*/count=659; tryItOut("\"use strict\"; a0[11];");
/*fuzzSeed-116066984*/count=660; tryItOut("v2 = g2.runOffThreadScript();");
/*fuzzSeed-116066984*/count=661; tryItOut("\"use strict\"; print(this >>= (4277));");
/*fuzzSeed-116066984*/count=662; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((( + (Math.pow((Math.min((x >>> 0), Math.fround(Math.cosh(Math.fround(x)))) >>> 0), Math.fround(( + (( ~ (((2**53+2 | x) !== -0) | 0)) - Math.min((1 | 0), (( + ( ~ ( + x))) | 0)))))) >>> 0)) >>> 0) !== mathy1(Math.atan2(Math.fround(x), Math.fround(mathy0(Math.PI, (y >>> 0)))), Math.sinh(Math.imul(Math.trunc(y), Math.fround(Math.min(Math.max((y >>> 0), ( + x)), Math.exp((y | 0)))))))); }); testMathyFunction(mathy4, [Number.MAX_VALUE, -(2**53+2), 1, 0x100000001, -1/0, 0, 0.000000000000001, 0x0ffffffff, 0/0, 0x100000000, -(2**53-2), -0x080000000, -0, -0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -Number.MAX_VALUE, 0x080000001, 42, -Number.MIN_VALUE, 2**53+2, -(2**53), Math.PI, -0x080000001, 2**53]); ");
/*fuzzSeed-116066984*/count=663; tryItOut("/*RXUB*/var r = new RegExp(\"((?!+)(?=\\\\W*)|(?:\\\\b|[^\\\\xc3\\u2383\\\\d\\\\s])*|^+?(?=(?!(?=(?=.))))+)\", \"gyim\"); var s = \"\"; print(s.replace(r, /*oLoop*/for (doqfar = 0, \"\\u2F83\"; doqfar < 76; ++doqfar) { (new RegExp(\"[\\\\u00ea\\u00f6]?\", \"gym\")); } --, \"y\")); ");
/*fuzzSeed-116066984*/count=664; tryItOut("if('fafafa'.replace(/a/g, Array.prototype.reverse)) t1.set(g2.t0, 17); else  if ((4277)) {selectforgc(this.g1.o1);print(uneval(p0)); }");
/*fuzzSeed-116066984*/count=665; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! Math.imul((Math.pow(((((y | 0) != ( + -0x100000001)) | 0) >>> 0), (mathy3((x | 0), Math.log(((((y >>> 0) , (y >>> 0)) >>> 0) ? Number.MIN_SAFE_INTEGER : Math.exp(Math.fround(x))))) >>> 0)) >>> 0), (( + mathy2((((y >>> 0) * y) >>> 0), ( + Math.atan2(Math.fround(y), Math.fround(Math.pow((-Number.MIN_SAFE_INTEGER | 0), 0x080000001)))))) >>> 0))); }); ");
/*fuzzSeed-116066984*/count=666; tryItOut("\"use strict\"; ;");
/*fuzzSeed-116066984*/count=667; tryItOut("\"use asm\"; const c = null;o1 = {};");
/*fuzzSeed-116066984*/count=668; tryItOut("\"use strict\"; let (y) { v1.toSource = Math.round; }");
/*fuzzSeed-116066984*/count=669; tryItOut("mathy2 = (function(x, y) { return (Math.max((Math.fround(Math.atanh(Math.fround(((( ~ 2**53-2) >>> 0) ^ ((Math.clz32(mathy0(mathy0(y, y), y)) | 0) >>> 0))))) >>> 0), ((Math.pow(x, (( - (-0x080000000 >>> 0)) >>> 0)) << x) && x)) >= (Math.min(( + (((Math.fround(mathy0(x, Math.fround((y ? ( + -(2**53)) : x)))) | 0) != ((Math.imul(1, x) >>> 0) | 0)) | 0)), x) !== ( ~ ( ! (( ~ (0/0 >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [({valueOf:function(){return '0';}}), (new String('')), (new Boolean(false)), '/0/', NaN, null, '\\0', '0', (new Number(0)), -0, 0, (new Boolean(true)), [0], /0/, (function(){return 0;}), [], (new Number(-0)), undefined, ({toString:function(){return '0';}}), 1, true, objectEmulatingUndefined(), false, '', ({valueOf:function(){return 0;}}), 0.1]); ");
/*fuzzSeed-116066984*/count=670; tryItOut("\"use strict\"; g0.t0.toString = (function(j) { if (j) { v0 + ''; } else { try { i0.next(); } catch(e0) { } neuter(g0.b2, \"change-data\"); } });function z(eval) { \"use strict\"; return /*UUV2*/(c.has = c.log1p) } x = NaN;");
/*fuzzSeed-116066984*/count=671; tryItOut("testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, 2**53+2, -0, 0x080000000, 2**53, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, -Number.MIN_VALUE, Math.PI, 1.7976931348623157e308, 0.000000000000001, 42, -0x080000000, 0x100000001, -0x080000001, -(2**53-2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 1, 0x100000000, 0x080000001, -1/0, Number.MAX_VALUE, 1/0, 0/0, -0x100000001]); ");
/*fuzzSeed-116066984*/count=672; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy0(( + Math.max((Math.asin(Math.fround(( + (( + y) < ( + (((y | 0) << ( + Math.imul((y >>> 0), (-0x0ffffffff >>> 0)))) | 0)))))) | 0), ( + Math.atan2(x, Math.imul(y, y))))), Math.log1p((Math.atanh((mathy0((Math.abs((Math.max(x, y) | 0)) | 0), mathy1(mathy0(Number.MAX_VALUE, -0x0ffffffff), ( - (y >>> 0)))) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy2, [({valueOf:function(){return 0;}}), objectEmulatingUndefined(), undefined, (new Number(0)), (new String('')), NaN, 0.1, (function(){return 0;}), (new Boolean(false)), '\\0', ({toString:function(){return '0';}}), '', (new Boolean(true)), '0', [0], null, false, -0, 1, 0, /0/, true, [], '/0/', ({valueOf:function(){return '0';}}), (new Number(-0))]); ");
/*fuzzSeed-116066984*/count=673; tryItOut("mathy2 = (function(x, y) { return Math.cos(( + ( - ((delete x.a) | 0)))); }); ");
/*fuzzSeed-116066984*/count=674; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (((( + ((( + (( + y) | Math.atan2(Math.fround((x >> ( + x))), y))) != (Math.acosh(( + y)) >= ( + Math.exp(( + y))))) <= ( + mathy3((Math.fround(mathy4((Number.MAX_VALUE ? Math.fround(Math.cosh(Math.fround(y))) : (y | 0)), Math.fround((Math.fround(y) ? Math.fround(( + Math.log2(x))) : (y | 0))))) | 0), Math.fround((Math.fround(x) >> Math.atan(y))))))) | 0) % Math.acos((((( ~ mathy0(x, 0/0)) | 0) < (Math.fround(( - Math.fround((mathy2((x | 0), ((y & x) >>> 0)) | 0)))) | 0)) | 0))) | 0); }); testMathyFunction(mathy5, [2**53, -0x080000000, 0x080000000, 0x080000001, -0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, -(2**53), Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, -0x0ffffffff, -(2**53-2), 1, 0, -0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 0/0, -0x080000001, -0, -0x100000001, -1/0, 1/0]); ");
/*fuzzSeed-116066984*/count=675; tryItOut("for (var v of g2.h0) { try { a0 = g2.a1.filter(this.g1.v1, g0, o2, i2); } catch(e0) { } try { e0.add(this.f0); } catch(e1) { } for (var v of g1) { try { function f2(h1) \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    i2 = ((0x14ea0450));\n    d0 = (-9223372036854776000.0);\n    {\n      (Float32ArrayView[(x) >> 2]) = ((((-(((eval(\"a1.sort(f1)\")))))) * ((2049.0))));\n    }\n    d1 = (d1);\n    return +((Float32ArrayView[1]));\n  }\n  return f; } catch(e0) { } e1.add(v1); } }");
/*fuzzSeed-116066984*/count=676; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.hypot((Math.fround(Math.pow((((Math.atan2((Math.cbrt((y < -(2**53-2))) , -(2**53)), (y >>> 0)) >>> 0) % (( ! ( + x)) >>> 0)) >>> 0), ( + Math.imul(( ! ( ~ x)), x)))) >>> 0), (( ! (( + ( ! ( + x))) - ((Math.fround(Math.exp((x >>> 0))) !== x) | 0))) | 0)); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -0, -1/0, 42, 1, -0x100000001, 2**53, -(2**53-2), -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, 0/0, Math.PI, 0x080000001, 0x080000000, 0.000000000000001, -(2**53+2), -0x080000000, -0x0ffffffff, -(2**53), 0, 0x100000001, -0x100000000, -0x080000001, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-116066984*/count=677; tryItOut("M:for(b in x) {o2.v0 = this.a2.reduce, reduceRight((function(j) { if (j) { for (var p in i1) { try { a2.length = ({valueOf: function() { g1.i2.next();return 1; }}); } catch(e0) { } try { g1.a1.splice(NaN, 9, b,  '' , b0); } catch(e1) { } o2.i1 = new Iterator(o1.b0, true); } } else { try { o0 = Proxy.create(h1, p1); } catch(e0) { } delete h1.has; } })); }");
/*fuzzSeed-116066984*/count=678; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy0((Math.atan2(((((Math.trunc(0x080000001) != (x ? Math.trunc(( + ( ~ y))) : x)) | 0) + (((( + x) ^ (-0x080000000 | 0)) === Math.sinh(y)) | 0)) | 0), ((Math.fround(Math.pow(Math.fround((Math.imul((Number.MAX_SAFE_INTEGER >>> 0), (Math.tan(Math.min(x, x)) >>> 0)) >>> 0)), (Math.sqrt(x) >>> 0))) >>> 0) >>> (y >>> 0))) | 0), (( + ( ~ ( + (( + Math.fround(x)) | 0)))) ? ( ! ((( + -(2**53)) || ( + y)) >>> 0)) : Math.atan2(( + mathy0(( + x), ( + Math.pow((Math.fround(( ! y)) >>> 0), y)))), (Math.pow(y, ( ! (-Number.MIN_VALUE >>> 0))) >>> Math.imul((((y >>> 0) != (-0 >>> 0)) >>> 0), Number.MIN_VALUE))))); }); testMathyFunction(mathy4, [42, 0x100000000, -0x0ffffffff, 0x07fffffff, 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, 2**53, -0x080000000, 0x080000001, 0, -0, Number.MAX_VALUE, -(2**53+2), -0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, -Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, -(2**53-2), 1, 0x080000000, 0x100000001, Math.PI, -1/0, -(2**53), 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=679; tryItOut("\"use strict\"; /*oLoop*/for (let dvgqvo = 0; dvgqvo < 126; ++dvgqvo) { print( '' ); } ");
/*fuzzSeed-116066984*/count=680; tryItOut("\"use strict\"; v0 = this.o0.t1.byteOffset;");
/*fuzzSeed-116066984*/count=681; tryItOut("mathy3 = (function(x, y) { return (( + Math.cosh(( ~ Math.atan2(y, ( + mathy2((y >>> 0), ( + x))))))) ^ (Math.acosh(((Math.pow(Math.imul(Math.fround((mathy2(( + x), 0x0ffffffff) | 0)), y), Math.fround(Math.sign((x >>> 0)))) >>> 0) ? 42 : Math.round(y))) | 0)); }); testMathyFunction(mathy3, [0x100000001, -(2**53-2), -0x080000000, -1/0, -0x07fffffff, Number.MIN_VALUE, -(2**53+2), 2**53+2, 2**53-2, -Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 1.7976931348623157e308, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), 0/0, 1/0, 0x100000000, -0x100000000, 0x080000000, -0x080000001, 0x07fffffff, 2**53, -Number.MIN_VALUE, 0x0ffffffff, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, Math.PI, 1, -Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=682; tryItOut("Array.prototype.shift.apply(a1, []);");
/*fuzzSeed-116066984*/count=683; tryItOut("print(o0);");
/*fuzzSeed-116066984*/count=684; tryItOut("mathy1 = (function(x, y) { return Math.fround(( - Math.atan2(Math.fround((Math.fround(x) !== mathy0(Math.fround(( + Math.atan2(( + ( ~ Math.fround((((y >>> 0) / (Number.MAX_VALUE >>> 0)) >>> 0)))), ( + 1)))), Math.sign(x)))), Math.atan2((Math.atanh(((Math.fround(Math.acosh(x)) | 0) <= Math.atan(y))) | 0), Math.fround((Math.fround(y) + Math.max(Math.fround(( ! Math.fround(x))), Math.atan2(Number.MIN_VALUE, y)))))))); }); ");
/*fuzzSeed-116066984*/count=685; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      d0 = (+abs(((+atan2(((+abs(((+atan2(((Float64ArrayView[1])), ((-140737488355329.0)))))))), ((4503599627370496.0)))))));\n    }\n    switch ((((!(0x55f680ad))+((-2199023255552.0) == (16777217.0)))|0)) {\n      case 0:\n        (Int16ArrayView[0]) = ((0x10e750f3) / (((0xe162d20d)) >> (0x5133e*(i1))));\n      case 0:\n        {\n          i2 = (i2);\n        }\n        break;\n      case -3:\n        switch ((abs((((0x37d18399) / (0x4ce7ebf7)) << ((Int8ArrayView[1]))))|0)) {\n          case -3:\n            i1 = (0xc2fe20ff);\n            break;\n          case -1:\n            i1 = ((0x216ac39b) > (0x768f29dd));\n            break;\n          case 1:\n            i1 = (/*FFI*/ff(((((i1)+(((d0) >= (+abs(((-1099511627775.0))))) ? (0x424310dd) : (0x86fee65a))) >> ((i2)))), ((d0)), ((((i2)) >> (((NaN) >= (+/*FFI*/ff(((+(0xed174ae4))), ((((0x9048d148)) & ((0x2c1d26b5)))))))))), ((+(0x71521d77))), ((((abs((0x15fc379a))|0) / (~((0x80472534)))) ^ ((0x7dc0f344)-((70368744177665.0) < (7.555786372591432e+22))))), ((((0xc04e2bea) % (0x0)) ^ ((0x5d94e6bb)-(/*FFI*/ff(((-8796093022209.0)))|0)))))|0);\n          case -3:\n            d0 = (+(-1.0/0.0));\n            break;\n          default:\n;        }\n        break;\n      case -2:\n        return (((i1)-(((((0x2078ee96) == (((i1)) << ((-0x10f9d68)+(0x970d8a34)))))|0) >= (~((i2)*0x37ad1)))+(i1)))|0;\n        break;\n      case -1:\n        i2 = ((0xcbd98dce));\n        break;\n      case -2:\n        {\n          i2 = (0x8354993);\n        }\n        break;\n      case 0:\n        {\n          i1 = (i1);\n        }\n        break;\n      default:\n        d0 = (d0);\n    }\n    return (((i2)+((-0.015625) <= (d0))))|0;\n  }\n  return f; })(this, {ff: function shapeyConstructor(heewsg){if (heewsg) Object.seal(heewsg);Object.seal(heewsg);heewsg[\"apply\"] = -0x5a827999;heewsg[\"getFloat32\"] = Symbol.for;if (x = \"\\uC787\") heewsg[new String(\"-15\")] =  '' ;heewsg[\"getFloat32\"] = (p={}, (p.z = ((encodeURIComponent).call(Math.cbrt(1), \"\\uA003\")))());return heewsg; }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [undefined, (new Boolean(true)), objectEmulatingUndefined(), (new Number(-0)), [], (function(){return 0;}), true, /0/, '', '/0/', -0, '0', ({valueOf:function(){return 0;}}), '\\0', (new String('')), 0.1, ({valueOf:function(){return '0';}}), null, 1, (new Boolean(false)), false, NaN, [0], (new Number(0)), 0, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-116066984*/count=686; tryItOut("arguments;");
/*fuzzSeed-116066984*/count=687; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.log2(( - Math.log2(( + Math.max(((mathy1((Math.trunc(0x100000001) >>> 0), (y >>> 0)) >>> 0) >>> 0), ( + y)))))); }); testMathyFunction(mathy2, [0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 42, 2**53-2, -(2**53-2), -0x080000000, -0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, -(2**53+2), 0x080000001, 0/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 1, Math.PI, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, -0x100000000, 0x080000000, -0, -0x07fffffff, Number.MAX_VALUE, -(2**53), 0x0ffffffff, -0x080000001, 1/0]); ");
/*fuzzSeed-116066984*/count=688; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.log1p((( + (( + Math.hypot(( + Math.min(-0x100000000, -Number.MAX_VALUE)), ( + x))) >= (( ! (-Number.MAX_SAFE_INTEGER | 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [42, -(2**53-2), -Number.MIN_VALUE, -1/0, -0, -0x100000000, 0x080000000, 0/0, 0.000000000000001, -0x100000001, 2**53-2, 0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, -0x07fffffff, -0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 2**53, -(2**53), Math.PI, 1/0, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, 0x080000001, 2**53+2, -0x080000001, -(2**53+2)]); ");
/*fuzzSeed-116066984*/count=689; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return  \"\" ; }); testMathyFunction(mathy0, [0.000000000000001, -(2**53+2), 0x0ffffffff, 1, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, 42, 1/0, 1.7976931348623157e308, 0x080000001, -1/0, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53, 0/0, -0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, 0x100000000, -(2**53-2), Math.PI, -(2**53), -0, Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000000]); ");
/*fuzzSeed-116066984*/count=690; tryItOut("\"use strict\"; Array.prototype.shift.call(g1.a1, t1);");
/*fuzzSeed-116066984*/count=691; tryItOut("wlxtfi();/*hhh*/function wlxtfi(){print(x);}");
/*fuzzSeed-116066984*/count=692; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.sinh(Math.pow(Math.fround((x ? Math.imul(y, x) : (Math.cos(( + -(2**53))) >>> 0))), (( + (( + y) - Math.min(Math.acos(( ! ( + y))), y))) | 0))); }); ");
/*fuzzSeed-116066984*/count=693; tryItOut("/*RXUB*/var r = /(?!\\1+)/y; var s = \"\\n\\u7d391\\n\\u7d391\\n\\u7d391\\n\\u7d391\\n\\u7d391\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=694; tryItOut("t2 = new Uint16Array(this.g1.b2, 30, new RegExp(\"\\\\d\", \"i\"));");
/*fuzzSeed-116066984*/count=695; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.cbrt(( + ( ! ( + Math.hypot(((Set.prototype.has)((4277), \"\\uD56E\") >>> 0), ( + y))))))); }); testMathyFunction(mathy5, /*MARR*/[[1], arguments, arguments, arguments, arguments, arguments, arguments, arguments]); ");
/*fuzzSeed-116066984*/count=696; tryItOut("\"use asm\"; for (var p in s2) { try { function f2(m0) \"use asm\";   var imul = stdlib.Math.imul;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    return +((+((imul((i0), ((((-0x8000000)+(i0)-(0xffffffff))>>>(0xfffff*((0xfe115f3e) ? (0xb7850c65) : (0xe325b649))))))|0))));\n  }\n  return f; } catch(e0) { } /*ODP-2*/Object.defineProperty(i1, \"x\", { configurable: false, enumerable: true, get: (function(j) { if (j) { try { p1 + ''; } catch(e0) { } try { m2 = this.b2; } catch(e1) { } try { Array.prototype.sort.apply(a1, [(function(j) { if (j) { try { s2 + this.o1.v1; } catch(e0) { } try { this.t0.set(a2, 16); } catch(e1) { } v1 = Array.prototype.reduce, reduceRight.apply(a1, [f1, i1, i0]); } else { try { m0 = new Map(e0); } catch(e0) { } try { v0 = (t0 instanceof b2); } catch(e1) { } a0[v2] = x; } }), h1]); } catch(e2) { } this.o2.s2 += 'x'; } else { f1.valueOf = (function mcc_() { var iavozf = 0; return function() { ++iavozf; if (/*ICCD*/iavozf % 5 == 3) { dumpln('hit!'); try { s2 += 'x'; } catch(e0) { } try { for (var p in o1.i1) { try { o2[\"valueOf\"] = this.v2; } catch(e0) { } let m1 = new Map; } } catch(e1) { } try { (void schedulegc(o0.g0)); } catch(e2) { } s2 = g2.objectEmulatingUndefined(); } else { dumpln('miss!'); try { v2 = Object.prototype.isPrototypeOf.call(v1, s0); } catch(e0) { } try { for (var p in o0.f2) { v0 = g2.eval(\"function f1(f1) \\\"use asm\\\"; b1.toSource = (function() { for (var j=0;j<20;++j) { g1.f1(j%3==0); } });\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    d0 = (d0);\\n    return +((d1));\\n  }\\n  return f;\"); } } catch(e1) { } v2 + this.f1; } };})(); } }), set: (function() { for (var j=0;j<31;++j) { f1(j%3==0); } }) }); }");
/*fuzzSeed-116066984*/count=697; tryItOut("x = (yield window).yoyo(20 >>> window);g0.v1 = Array.prototype.every.apply(a2, [this.f0]);");
/*fuzzSeed-116066984*/count=698; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -17592186044417.0;\n    var i3 = 0;\n    i3 = (((((((0x1b556fd8) ? (0xffffffff) : (-0x2464942))) & ((0xff299560)+(0xf84a85ee)-(0x7f7d7443))) / (((0x21dd37a7)+(i0))|0))>>>(((abs((~~(-9.44473296573929e+21)))|0))+(0x5e99cf53))) <= ((((imul((0xf920d876), (0xe9e4438a))|0))-(0xfab3a839)+(0xffffffff))>>>((i0))));\n    {\n      i0 = (i0);\n    }\n    return (((0x901222b3)+(i3)))|0;\n  }\n  return f; })(this, {ff: /*MARR*/[new String('q'), new String('q'), -Number.MAX_VALUE, 1e81, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_VALUE, new String('q'), 1e81, -Number.MIN_VALUE, -Number.MIN_VALUE, objectEmulatingUndefined(), -Number.MAX_VALUE, -Number.MIN_VALUE, objectEmulatingUndefined(), new String('q'), 1e81, 1e81, -Number.MAX_VALUE, objectEmulatingUndefined(), -Number.MIN_VALUE, objectEmulatingUndefined(), 1e81, -Number.MIN_VALUE, new String('q'), -Number.MIN_VALUE, -Number.MAX_VALUE, 1e81, objectEmulatingUndefined(), objectEmulatingUndefined(), 1e81, new String('q'), objectEmulatingUndefined(), -Number.MIN_VALUE, objectEmulatingUndefined(), new String('q'), new String('q'), 1e81, -Number.MIN_VALUE, 1e81, 1e81, new String('q'), objectEmulatingUndefined(), -Number.MIN_VALUE, -Number.MAX_VALUE, new String('q'), new String('q'), 1e81, new String('q'), -Number.MAX_VALUE, objectEmulatingUndefined(), objectEmulatingUndefined(), 1e81, 1e81, -Number.MIN_VALUE, -Number.MIN_VALUE, 1e81, new String('q'), 1e81].map(Function.prototype.call, (4277))}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000001, -0x080000000, -(2**53), 2**53, 1.7976931348623157e308, 0, -0x100000000, Math.PI, 1, 0x100000000, Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, 0/0, 0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, -(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000001, 42, -0, -Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, 2**53-2, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=699; tryItOut("try { (void schedulegc(g2)); } catch({b: {x: [{a}, , ], x, e: x, eval: [, , x, , ]}} if /.*?|\u40e1?/gy) { for(let z in []); } finally { x.name; } ");
/*fuzzSeed-116066984*/count=700; tryItOut("this.t1[ /x/ .__defineSetter__(\"window\", Date.prototype.setDate)];");
/*fuzzSeed-116066984*/count=701; tryItOut("Array.prototype.shift.apply(a0, []);");
/*fuzzSeed-116066984*/count=702; tryItOut("\"use strict\"; \"use asm\"; f1.valueOf = (function(j) { if (j) { try { for (var v of m1) { v1 = (h2 instanceof f2); } } catch(e0) { } try { o2.v2 = (v1 instanceof v1); } catch(e1) { } try { Array.prototype.reverse.call(this.a0); } catch(e2) { } h2.delete = f2; } else { e2.has(a1); } });");
/*fuzzSeed-116066984*/count=703; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((((((( + ((((Math.exp(Math.log10(Number.MAX_SAFE_INTEGER)) >>> 0) + (( ~ Math.max(y, x)) >>> 0)) | 0) ? Math.fround(Math.atan(((((y ? y : x) >>> 0) | 0) ^ (Math.max((Math.fround((y | 0)) >>> 0), (y >>> 0)) >>> 0)))) : (y >>> 0))) | 0) % ((Math.asinh((( + (x | 0)) >>> 0)) >>> 0) | 0)) | 0) | 0) ** ((( + Math.atan2((Math.atan2((( ! ((-(2**53) == (y | 0)) | 0)) ^ ( - 0x100000000)), ( + (Math.hypot(( ! x), ((((x >>> 0) ^ x) >>> 0) | 0)) | 0))) | 0), Math.sign((Math.acosh(-Number.MIN_SAFE_INTEGER) | 0)))) - ( - Math.fround((Math.fround((Math.fround((Math.cbrt((x >>> 0)) >>> 0)) < 0x080000001)) << Math.fround((y & x)))))) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[(4277), new Number(1), (4277), new Number(1), new Number(1), (4277), (4277), x, new Number(1), new Number(1), new Number(1), (4277), x, x, x, new Number(1), (4277), x, x, x, x, (4277), (4277), x, x, x, x, x, x, x, (4277), new Number(1), x, new Number(1), (4277)]); ");
/*fuzzSeed-116066984*/count=704; tryItOut("\"use strict\"; x, e = /\\u00f2|(?!(?=Q{2,5})?)/, NaN;yield;");
/*fuzzSeed-116066984*/count=705; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -295147905179352830000.0;\n    var d3 = -70368744177665.0;\n    return ((((0xe01c05f7))))|0;\n  }\n  return f; })(this, {ff: WebAssemblyMemoryMode}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000001, 2**53+2, -(2**53+2), 1/0, -0x0ffffffff, Math.PI, 0x100000000, -(2**53), 1, 2**53-2, -0x100000000, -Number.MAX_VALUE, -(2**53-2), -1/0, 0, Number.MAX_VALUE, 0/0, -0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -0, 42, 0x080000000, -0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-116066984*/count=706; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=707; tryItOut("mathy1 = (function(x, y) { return (( ! ( + (Math.atan2((mathy0(( + -1/0), ( + x)) | 0), y) >>> Math.sin(Math.fround(Math.pow(Math.fround(x), ( + Math.log2(x)))))))) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-116066984*/count=708; tryItOut("Array.prototype.shift.call(a1, b1);");
/*fuzzSeed-116066984*/count=709; tryItOut("M:for(let [b, e] = (p={}, (p.z = /*UUV2*/(NaN.trim = NaN.log2))()) in (4277)) t0 + '';");
/*fuzzSeed-116066984*/count=710; tryItOut("\"use strict\"; Array.prototype.push.call(a2, i1, e1, p1, o2.o1.f2, e0);");
/*fuzzSeed-116066984*/count=711; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=712; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    i0 = (0xf878500e);\n    {\n      i1 = ((0x6e7291c7));\n    }\n    return +((((-8796093022208.0)) % ((+(1.0/0.0)))));\n  }\n  return f; })(this, {ff: (runOffThreadScript).bind}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, 0x080000001, -0x0ffffffff, -0x100000000, 42, 0.000000000000001, 0x080000000, 1/0, 2**53, -0x07fffffff, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 0, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, -(2**53-2), 2**53-2, 2**53+2, 1.7976931348623157e308, 0x100000001, -(2**53), -0x100000001, Number.MIN_VALUE, -1/0, 1, -(2**53+2), Math.PI]); ");
/*fuzzSeed-116066984*/count=713; tryItOut("for(let w in []);");
/*fuzzSeed-116066984*/count=714; tryItOut("mathy3 = (function(x, y) { return (((Math.log2(((Math.fround(Math.pow(((( + ( - ( + y))) + y) | 0), ((( ~ (( + -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0) | 0))) < x) >>> 0)) >>> 0) >= ( + ((mathy2(( + Math.hypot(( + (0x0ffffffff > y)), ( + ( + Math.hypot(y, ( + (y - y))))))), Math.hypot(Math.fround(( ~ ( + x))), Math.fround(0x100000000))) && x) || (((Math.fround(mathy0(Math.fround(-0x07fffffff), Math.fround((( ! y) | 0)))) && ( + Math.pow(y, (y >>> 0)))) ? mathy2(( + y), (mathy2((mathy2(y, (Math.imul(2**53+2, (y >>> 0)) >>> 0)) >>> 0), y) >>> 0)) : (Math.hypot((((y > ( + (mathy0(( + 0/0), ( + Math.fround(Math.tan(Math.fround(y))))) >>> 0))) >>> 0) | 0), ( - ( + ( ~ Math.fround(0x080000000))))) | 0)) | 0)))) | 0); }); ");
/*fuzzSeed-116066984*/count=715; tryItOut("");
/*fuzzSeed-116066984*/count=716; tryItOut("h2.set = f2;");
/*fuzzSeed-116066984*/count=717; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 1.9342813113834067e+25;\n    var i3 = 0;\n    {\n      i0 = (0xb5abbf5e);\n    }\n    {\n      (Float32ArrayView[2]) = ((+abs(((1125899906842625.0)))));\n    }\n    i1 = (i3);\n    return +((d2));\n  }\n  return f; })(this, {ff: Math.imul(x, (Math.abs((x | 0)) | 0))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000001, -(2**53+2), 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, -(2**53-2), -0x100000000, -0x07fffffff, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, 1/0, 2**53+2, 0, Math.PI, -(2**53), 0x07fffffff, 0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, -0x0ffffffff, 0/0, -0x100000001, -Number.MIN_VALUE, 1, -0x080000001, -0]); ");
/*fuzzSeed-116066984*/count=718; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.imul(Math.imul((Math.acos((( + (y | 0)) | 0)) | 0), ( + ( ! ( + (Math.pow((( + ( + y)) >>> 0), (y >>> 0)) >>> 0))))), Math.trunc((Math.fround(((Math.atan(x) | 0) % (((x ^ x) >>> 0) | 0))) !== ((Number.MIN_SAFE_INTEGER >> y) != y)))); }); testMathyFunction(mathy0, [-0x0ffffffff, -(2**53), 0x080000000, -0x100000001, -0x07fffffff, 0x080000001, 0/0, 42, 0x07fffffff, -Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, 0x100000001, -0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, -0, 2**53+2, Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, -(2**53+2), -1/0, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -0x100000000, 0.000000000000001, 1.7976931348623157e308, -0x080000000, 1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-116066984*/count=719; tryItOut("L:with((yield (4277))())function shapeyConstructor(dlexnp){if (Symbol(((void shapeOf(window))), this.__defineGetter__(\"a\", Date.prototype.getUTCDate))) this[\"constructor\"] = Object.values;return this; }/*tLoopC*/for (let d of (x for each (w in  \"\" .__defineSetter__(\"x\", runOffThreadScript)) for each (x in /*MARR*/[(0/0), (void 0),  'A' ,  'A' , (void 0), (void 0), (0/0),  'A' , (void 0), new Number(1.5), (void 0), true, new Number(1.5), new Number(1.5),  'A' , (void 0), (0/0), (0/0), (void 0), (0/0), (0/0), (0/0), (void 0), (0/0), new Number(1.5), (0/0), (0/0), new Number(1.5), true, (void 0),  'A' , (0/0), (void 0), true, (void 0), (void 0), new Number(1.5),  'A' , (void 0), (void 0),  'A' , true, (void 0), (void 0), (void 0),  'A' , (void 0),  'A' , (0/0), (void 0), new Number(1.5),  'A' , (0/0),  'A' , new Number(1.5), (0/0), (0/0),  'A' , (0/0), (0/0), (void 0), (0/0), (void 0), true, (0/0),  'A' , new Number(1.5), (0/0), true, (0/0), true, new Number(1.5), true, (0/0)]) for (x of this.unwatch(19) / intern( '' )) if (++a))) { try{let eagzto = shapeyConstructor(d); print('EETT'); g0.s1 += s1;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-116066984*/count=720; tryItOut("\"use strict\"; Array.prototype.unshift.apply(a2, [m0]);");
/*fuzzSeed-116066984*/count=721; tryItOut("\"use strict\"; /*oLoop*/for (kngszv = 0; kngszv < 49; ++kngszv) { (({})); } \ne2.valueOf = (function() { try { for (var p in h2) { try { delete t0[\"e\"]; } catch(e0) { } try { ; } catch(e1) { } h2.get = (function() { try { Object.defineProperty(this, \"m0\", { configurable: false, enumerable: (x % 2 != 1),  get: function() {  return new WeakMap; } }); } catch(e0) { } try { v1 = undefined; } catch(e1) { } Array.prototype.shift.call(a2); return e1; }); } } catch(e0) { } try { g2.g0.h0.delete = f0; } catch(e1) { } for (var p in g0) { /*RXUB*/var r = this.r0; var s = g2.s2; print(s.split(r)); print(r.lastIndex);  } return e1; });");
/*fuzzSeed-116066984*/count=722; tryItOut("/*MXX2*/g0.Math.cosh = this.m1;");
/*fuzzSeed-116066984*/count=723; tryItOut("v0 = t1.length;");
/*fuzzSeed-116066984*/count=724; tryItOut("/*tLoop*/for (let x of /*MARR*/[null, null, x, objectEmulatingUndefined(), x, x, ['z'], new Number(1), objectEmulatingUndefined(), null, null, new Number(1), objectEmulatingUndefined(), new Number(1), null, ['z'], null, new Number(1), ['z'], objectEmulatingUndefined(), null, null, objectEmulatingUndefined(), null, null, x, x, ['z'], null, ['z'], objectEmulatingUndefined(), new Number(1)]) { (14); }");
/*fuzzSeed-116066984*/count=725; tryItOut("mathy5 = (function(x, y) { return Math.min(( + (Math.min((( ! (mathy2(Math.PI, y) | 0)) | 0), (Math.fround((((y >>> 0) , (0 >>> 0)) >>> 0)) >>> Math.max(x, Math.fround(1/0)))) % y)), ((Math.log2(Math.fround(Math.min((Math.acosh((mathy0((Math.max(0/0, x) >>> 0), ((Math.PI * (Math.atan(x) | 0)) >>> 0)) >>> 0)) >>> 0), (Math.fround(Math.clz32(( + (Math.fround(x) !== (x | 0))))) >>> 0)))) >>> 0) | 0)); }); ");
/*fuzzSeed-116066984*/count=726; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=727; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-(2**53), 0x080000000, 42, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, -0x07fffffff, Number.MAX_VALUE, 1, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, 0/0, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), -0x080000000, -0x100000001, 2**53, -Number.MAX_SAFE_INTEGER, Math.PI, -0, -0x080000001, 0.000000000000001, 2**53+2, -0x100000000, 1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, -1/0, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-116066984*/count=728; tryItOut("/*RXUB*/var r = new RegExp(\".|(?:$((?=\\\\B)){4,}|(?:\\\\b)*?)(?:(?=(?=[\\\\W\\\\xA2]){1,}\\\\d).(.)*?)*?\", \"yim\"); var s = \"\\n\"; print(r.exec(s)); ");
/*fuzzSeed-116066984*/count=729; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (NaN);\n    }\n    d1 = (-2.4178516392292583e+24);\n    d1 = (d1);\n    (Float64ArrayView[(((~~(+(1.0/0.0))))+((((d1)) % ((+(0.0/0.0)))) <= (+(0.0/0.0)))) >> 3]) = ((Float64ArrayView[0]));\n    return +((((0x2bbf7d42) ? (-9.0) : ((x) / ((+((+abs(((Float32ArrayView[1]))))))))) + (1.03125)));\n  }\n  return f; })(this, {ff: Math.imul(-1, -4)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [2**53+2, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), -0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 1/0, 1.7976931348623157e308, 0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, Number.MAX_VALUE, Math.PI, 0, -(2**53), -0x07fffffff, 1, -(2**53+2), -0x100000000, Number.MIN_VALUE, 42, -0, 0x100000000, -0x080000000, 2**53, 0x100000001, 0x080000001]); ");
/*fuzzSeed-116066984*/count=730; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.cbrt(mathy2(( + ( + (( + (Math.max(y, (x | 0)) | 0)) ? ( + ( + Math.max(( + x), ( + y)))) : ( + Math.expm1(mathy2(( ~ Math.fround(Number.MIN_VALUE)), x)))))), ( - (Math.atan((2**53 | 0)) | 0))))); }); testMathyFunction(mathy4, [(new Number(-0)), /0/, (new Boolean(true)), '0', 0.1, [], false, true, (new Boolean(false)), 0, ({valueOf:function(){return 0;}}), '/0/', '', 1, null, ({toString:function(){return '0';}}), objectEmulatingUndefined(), undefined, (function(){return 0;}), [0], (new Number(0)), '\\0', NaN, (new String('')), -0, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-116066984*/count=731; tryItOut("testMathyFunction(mathy2, [0x100000001, 2**53+2, -0x100000001, 0, -Number.MIN_VALUE, 0/0, Math.PI, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 0x07fffffff, 0x080000000, -0x100000000, 1/0, -0, 0.000000000000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53, 42, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -1/0, 1, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_VALUE, -0x080000000, 0x100000000, 0x080000001, 0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-116066984*/count=732; tryItOut("mathy3 = (function(x, y) { return ((Math.fround((((((Math.asin(Math.fround(Math.imul(Math.fround(x), (x | 0)))) | 0) >>> 0) ? ( + y) : (Math.fround(Math.clz32((y >>> 0))) >>> 0)) | 0) === (x * Math.abs((((Math.fround(Math.pow((2**53-2 >>> 0), 1)) >>> 0) , (-0x100000000 >>> 0)) >>> 0))))) >= (Math.fround(Math.log1p(Math.fround(Math.exp(-0)))) + (x | ( + Math.acos(( + ( ~ y))))))) | 0); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 0x100000001, -1/0, Number.MIN_VALUE, 42, 0, -(2**53+2), -0x100000000, 0x080000001, 0/0, 0.000000000000001, 0x080000000, -0x080000000, 2**53-2, 0x0ffffffff, -(2**53), -0, -0x0ffffffff, -0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, Math.PI, 1, 2**53, 0x07fffffff, -0x080000001, 1/0, 0x100000000]); ");
/*fuzzSeed-116066984*/count=733; tryItOut("v0 = new Number(4);");
/*fuzzSeed-116066984*/count=734; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-116066984*/count=735; tryItOut("t1 = new Uint8ClampedArray(b2, 4, v1);");
/*fuzzSeed-116066984*/count=736; tryItOut("\"use strict\"; /*infloop*/ for (NaN of //h\n(x.yoyo( /x/ ))) {/*tLoop*/for (let z of /*MARR*/[true, new Number(1.5)]) { new RegExp(\"[^].\\\\s|[^]|o*?(?!\\\\S)+?*?\", \"gi\"); }v2 = g2.runOffThreadScript(); }");
/*fuzzSeed-116066984*/count=737; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.fround(Math.min(Math.sin(x), Math.log1p(Math.fround((x <= Number.MAX_VALUE)))))); }); testMathyFunction(mathy0, [-(2**53), 0, -0x080000000, 0/0, Number.MAX_VALUE, 1, Math.PI, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, 42, Number.MIN_VALUE, -(2**53-2), -Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, -1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53+2), 0x080000000, -0x080000001, 2**53-2, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 2**53, 0.000000000000001, -0x07fffffff, 0x0ffffffff, 0x100000000, 0x100000001, -0]); ");
/*fuzzSeed-116066984*/count=738; tryItOut("this.g2.v1 = g0.g1.runOffThreadScript();");
/*fuzzSeed-116066984*/count=739; tryItOut("{m2.has(h0);o1.s1 + e1; }");
/*fuzzSeed-116066984*/count=740; tryItOut("t0 = Proxy.create(h0, s0);");
/*fuzzSeed-116066984*/count=741; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + ( + Math.atan2((Math.fround(((( ! (x | 0)) | 0) > x)) | x), x))); }); testMathyFunction(mathy0, [2**53-2, 0x0ffffffff, 0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, -1/0, 0x100000000, 0, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, Math.PI, -0, 0/0, Number.MAX_VALUE, 2**53+2, -(2**53+2), 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 0x07fffffff, Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, 0x080000000, 2**53]); ");
/*fuzzSeed-116066984*/count=742; tryItOut("s1 = s2.charAt(12);");
/*fuzzSeed-116066984*/count=743; tryItOut("mathy0 = (function(x, y) { return ((Math.hypot(( + Math.max((Math.acosh((y >>> 0)) >>> 0), ( + (Math.cos(( + (0x100000000 * y))) >>> 0)))), (( - (( + 0/0) + ( + ( ~ ( + (Math.min(Number.MAX_VALUE, (( ! x) >>> 0)) >>> 0)))))) >>> 0)) >>> 0) <= Math.fround(Math.asinh((( + ( + ( - ( + 2**53+2)))) >>> 0)))); }); ");
/*fuzzSeed-116066984*/count=744; tryItOut("mathy4 = (function(x, y) { return (( + ( ~ (Math.fround(Math.log10(x)) ? ( + (( + Math.sign(( + y))) ^ x)) : y))) === Math.fround(( - (((Math.fround((( + ( + x)) - ( + (( + y) || ( + 2**53))))) | 0) || mathy3(((Math.fround(( - 0x100000000)) || (Math.fround(( + ( + x))) >>> 0)) >>> 0), (Math.hypot(y, y) | 0))) | 0)))); }); testMathyFunction(mathy4, [-0x080000001, -0, -0x100000000, 0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, -0x07fffffff, -0x100000001, 0/0, 2**53+2, 2**53, Number.MIN_VALUE, 42, -(2**53), -Number.MAX_VALUE, 1, 0x0ffffffff, 1/0, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, -(2**53-2), -(2**53+2), 0, -Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-116066984*/count=745; tryItOut("mathy0 = (function(x, y) { return Math.min(Math.fround((Math.fround(((x >>> 0) ? x : (x ? ( + x) : x))) - (Math.imul(( + ( + (Math.sin(y) >>> 0))), (Math.abs((Math.imul(Math.fround(x), Math.fround(x)) <= y)) >>> 0)) | 0))), Math.fround((Math.fround(Math.atanh(-0x100000000)) | ((( + (x >>> 0)) >>> 0) | 0)))); }); testMathyFunction(mathy0, /*MARR*/[false, false, false, false, false,  '' ,  '' ,  '' ]); ");
/*fuzzSeed-116066984*/count=746; tryItOut("\"use strict\"; for (var v of i2) { try { t0 = new Int8Array(a0); } catch(e0) { } try { for (var v of s0) { try { g1.v1 = (p2 instanceof e0); } catch(e0) { } m0.get(g0); } } catch(e1) { } try { Array.prototype.forEach.apply(g0.a0, [(function() { for (var j=0;j<45;++j) { f2(j%2==1); } })]); } catch(e2) { } /*MXX3*/g0.SyntaxError.prototype.name = g2.SyntaxError.prototype.name; }");
/*fuzzSeed-116066984*/count=747; tryItOut("let z = false.\"16\" = eval = eval = Proxy.createFunction(({/*TOODEEP*/})( \"\" ), e, eval)\u000c;a1.sort((function(a0, a1) { var r0 = a1 + a0; z = r0 & a1; var r1 = a0 ^ a1; var r2 = x | z; var r3 = r1 ^ 5; var r4 = 1 + 1; var r5 = r0 - 0; var r6 = 9 | r0; r2 = 9 - r1; var r7 = r4 + 6; var r8 = 0 * x; var r9 = 7 & r6; var r10 = r6 & r8; print(a1); var r11 = x ^ r7; a0 = 5 - r3; return z; }));");
/*fuzzSeed-116066984*/count=748; tryItOut("\"use strict\"; \"use asm\"; ;");
/*fuzzSeed-116066984*/count=749; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot((Math.fround(Math.asinh(Math.cos((Math.asin(Math.fround(y)) >>> 0)))) >>> 0), ((Math.trunc(x) * true < ({a2:z2}).throw(( ''  =  \"\" ))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-116066984*/count=750; tryItOut("mathy2 = (function(x, y) { return ((Math.cos((Math.fround((Math.fround((( + Math.fround(x)) >>> 0)) | Math.fround(Math.asinh(x)))) | 0)) | 0) << Math.acos(( + Math.fround(mathy0(Math.fround(x), Math.fround(((Math.fround((( + y) && ( + y))) >>> 0) && (( + ( ~ Math.fround(y))) >>> 0)))))))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 0/0, -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, -1/0, 0x100000001, -0, 2**53+2, -Number.MIN_SAFE_INTEGER, Math.PI, 0, 2**53-2, -(2**53+2), -0x07fffffff, -0x080000000, -0x100000000, -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 1, 0x07fffffff, -Number.MAX_VALUE, 0x100000000, 0x0ffffffff, 0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 42, 2**53, 1/0]); ");
/*fuzzSeed-116066984*/count=751; tryItOut("\"use strict\"; (void version(170));");
/*fuzzSeed-116066984*/count=752; tryItOut("mathy5 = (function(x, y) { return (((((( - (Math.clz32(( + ( + x))) >>> 0)) >>> 0) && (Math.fround(Math.atan2(x, Math.fround(Math.exp((x | 0))))) >>> 0)) >>> 0) << mathy1(y, x)) == Math.min(( + Math.imul(Math.imul(Math.log2(Math.min(x, ( + y))), (Math.expm1(((mathy1(42, (y >>> 0)) >>> 0) | 0)) | 0)), (Math.fround(( - (Math.max((x >>> 0), Math.fround(x)) >>> 0))) | 0))), Math.fround(( + Math.atan(( + (Math.trunc((Math.fround(( ~ y)) | 0)) | 0))))))); }); ");
/*fuzzSeed-116066984*/count=753; tryItOut("throw d;");
/*fuzzSeed-116066984*/count=754; tryItOut("this.v0 = evalcx(\"o2.v0 = Object.prototype.isPrototypeOf.call(e2, t0);\", g0);");
/*fuzzSeed-116066984*/count=755; tryItOut("p2 = g2.objectEmulatingUndefined()\n/*bLoop*/for (var cvddls = 0,  \"\" ; cvddls < 103; ++cvddls) { if (cvddls % 4 == 3) { a2.__proto__ = this.o0.s0; } else { v1 = o2[\"prototype\"]; }  } ");
/*fuzzSeed-116066984*/count=756; tryItOut("\"use strict\"; yield x;(/*UUV1*/(x.getInt16 = Promise));");
/*fuzzSeed-116066984*/count=757; tryItOut("mathy0 = (function(x, y) { return (Math.abs((Math.expm1(Math.fround(Math.acos(Math.fround(Math.fround((( + Math.fround((Math.fround(x) << Math.fround(Math.fround(Math.round(Math.fround(-0x080000001))))))) < Math.clz32(x))))))) | 0)) | 0); }); testMathyFunction(mathy0, [0/0, -(2**53), 0x100000000, 0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, -(2**53-2), -0x100000000, 0x080000001, 0x100000001, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0, 2**53+2, 1, -0x080000001, -0, -(2**53+2), 2**53-2, -Number.MIN_VALUE, 1/0, 2**53, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -1/0]); ");
/*fuzzSeed-116066984*/count=758; tryItOut("\"use strict\"; a1 = Array.prototype.concat.call(a1, o2.g1.t1, a0);");
/*fuzzSeed-116066984*/count=759; tryItOut("f2(h2);");
/*fuzzSeed-116066984*/count=760; tryItOut("\"use strict\"; m1.toSource = new RegExp(\"(?:(?!$\\\\xb9))[]|\\\\W|$+[^]|\\\\t{2,}|[\\udaac-Z]+?|((?:$\\\\1))\", \"i\");");
/*fuzzSeed-116066984*/count=761; tryItOut("\"use strict\"; for (var p in p1) { try { /*MXX3*/g2.Set.prototype.values = g0.Set.prototype.values; } catch(e0) { } try { Array.prototype.sort.call(a2, o2.g2.f1); } catch(e1) { } try { e1.has(g0); } catch(e2) { } m2.has(this.p1); }\n\n");
/*fuzzSeed-116066984*/count=762; tryItOut("selectforgc(o0);");
/*fuzzSeed-116066984*/count=763; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-116066984*/count=764; tryItOut("\"use strict\"; v2 = evalcx(\"function f2(b0)  { return b0 } \", g2);");
/*fuzzSeed-116066984*/count=765; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=766; tryItOut("{var w = \"\\u1CB3\";v1 = t2.length; }");
/*fuzzSeed-116066984*/count=767; tryItOut("\"use strict\"; \"use asm\"; s2 += 'x';this.e1.add(p0);");
/*fuzzSeed-116066984*/count=768; tryItOut("a2 = /*PTHR*/(function() { \"use strict\"; for (var i of /*MARR*/[objectEmulatingUndefined(), null]) { yield i; } })();");
/*fuzzSeed-116066984*/count=769; tryItOut("neuter(b2, \"same-data\");");
/*fuzzSeed-116066984*/count=770; tryItOut("v0 = new Number(NaN);");
/*fuzzSeed-116066984*/count=771; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d1));\n  }\n  return f; })(this, {ff: Math.exp}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [[0], true, 0.1, -0, '/0/', null, ({toString:function(){return '0';}}), false, '\\0', ({valueOf:function(){return '0';}}), [], /0/, 1, objectEmulatingUndefined(), (new Number(-0)), '', 0, undefined, (new String('')), '0', (new Boolean(true)), NaN, (new Boolean(false)), (function(){return 0;}), (new Number(0)), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-116066984*/count=772; tryItOut("for (var v of m0) { try { v2 = evalcx(\"mathy0 = (function(x, y) { \\\"use strict\\\"; return Math.trunc(( ! Math.expm1((Math.log((x >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [2**53-2, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, -0x100000001, -(2**53+2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -0, 1, -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 2**53, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, 0x07fffffff, -Number.MIN_VALUE, 42, -0x100000000, 0x100000000, 1/0, -(2**53-2), 0x080000000, 0x100000001, -1/0, 0.000000000000001, 0/0, 2**53+2]); \", g1); } catch(e0) { } try { v0 = (g1 instanceof f1); } catch(e1) { } Array.prototype.push.apply(g1.a1, [t2]); }");
/*fuzzSeed-116066984*/count=773; tryItOut("\"use strict\"; o1.g2.g1.s1 += s1;");
/*fuzzSeed-116066984*/count=774; tryItOut("let (x) this;");
/*fuzzSeed-116066984*/count=775; tryItOut("\"use strict\"; for(let y in ((4277) for (x of []) for (w of false) for (a in \"\\u64D0\"))) for(let e in /*FARR*/[]) Array.prototype.unshift.apply(a2, [b0, m1]);");
/*fuzzSeed-116066984*/count=776; tryItOut("mathy4 = (function(x, y) { return mathy0(mathy0(Math.acosh(Math.pow(x, mathy3(Math.fround(Math.cos(Math.fround(y))), ((x - ((Math.tanh(y) >>> 0) | 0)) >>> 0)))), Math.hypot((( + x) | 0), ( + Math.min(0/0, ( + Math.atan(x)))))), ( ~ ( + Math.atan2(Math.fround(Math.fround(( ! Math.fround(((( + Math.log2(Math.atan(-Number.MAX_SAFE_INTEGER))) | 0) < x))))), mathy1(y, ((((( + y) + 1.7976931348623157e308) >>> 0) << x) | 0)))))); }); testMathyFunction(mathy4, [0.000000000000001, -0x07fffffff, -0x100000001, 42, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, 2**53+2, -Number.MAX_VALUE, 0/0, -0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, Math.PI, 2**53, 0x080000001, -0, 0, -0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, Number.MIN_VALUE, 1, Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53+2), -0x100000000]); ");
/*fuzzSeed-116066984*/count=777; tryItOut("g1 = evalcx('lazy');");
/*fuzzSeed-116066984*/count=778; tryItOut("x, omfpyi;print(x);");
/*fuzzSeed-116066984*/count=779; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0x16f1e27a)-(((0x34a09331) ? ((0xcb5e423b) ? (0xfab63ee8) : (0xfc9eeed0)) : ((((-33554431.0)) * ((-4398046511105.0))) != (d1))) ? (!(/*FFI*/ff(((~~(d0))))|0)) : (0xd4f2aa1))))|0;\n  }\n  return f; })(this, {ff: Object.setPrototypeOf}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0.000000000000001, 1/0, 0/0, 2**53+2, 0x07fffffff, Math.PI, 0x080000001, -0x100000000, 0x080000000, -(2**53-2), 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, 2**53, -0, 0x100000001, 1.7976931348623157e308, -0x080000001, 42, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, -0x100000001, -Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, -0x07fffffff, Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=780; tryItOut("mathy3 = (function(x, y) { return (Math.atan2(( + Math.clz32(Number.MIN_VALUE)), (Math.fround(((Math.sign(Math.fround(Math.asinh(Math.fround(0.000000000000001)))) >>> 0) ? Math.fround(( + Math.hypot(( + ((-(2**53) == x) + Math.atan2(Math.sin(y), Math.fround(Number.MIN_VALUE)))), (( - -Number.MAX_SAFE_INTEGER) | 0)))) : Math.fround(( + x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, -1/0, 0x100000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, 2**53+2, 2**53-2, -0x100000001, 2**53, 0/0, -Number.MAX_VALUE, -(2**53+2), 0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, -0x080000000, -0, 42, -0x100000000, -0x0ffffffff, 0x080000001, 1/0, -(2**53), 1, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=781; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=782; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=783; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (/*FFI*/ff(((~((!(i1))))), ((((i0)) << ((0x8524ed31)-(0x6bd05494)-((72057594037927940.0) != (16777217.0))))), ((((/*FFI*/ff(((3.094850098213451e+26)), ((((0xcbbda125)) ^ ((-0x8000000)))), ((-1.015625)), ((524289.0)), ((1.25)), ((-0.001953125)), ((-2.0)), ((-1.03125)), ((1125899906842623.0)))|0)-((((0xfee19a1f)) & ((0xc4b92e42))) > (abs((0x64e20b79))|0))-(i1)) & ((i0)))), ((abs((((/*FFI*/ff(((-1.5111572745182865e+23)), ((8589934593.0)), ((8388609.0)), ((-524288.0)), ((-1048575.0)))|0)-((288230376151711740.0) == (513.0))+((0xd931f552) ? (0xf85f7a3b) : (0xea197e2c))) | (-0x5adcf*(i1))))|0)), ((-295147905179352830000.0)), ((-1.015625)), ((+(-1.0/0.0))), ((3.8685626227668134e+25)), ((+/*FFI*/ff(((1073741823.0))))), ((-70368744177665.0)), ((-1048576.0)), ((-134217728.0)))|0);\n    {\n      i0 = ((+/*FFI*/ff((((0x3ee7ec29) ? (-2097151.0) : ((i1) ? ((134217729.0) + (32767.0)) : (1.03125)))), ((((i1)+(!((((-0x8000000)) ^ ((0xfb3d337d)))))) >> ((i1)-(i1)+(i0)))), ((0x6c14465b)), ((36028797018963970.0)), ((137438953471.0)), ((imul((0xf95319be), (0xd2ded65))|0)), ((~~(1.5474250491067253e+26))), ((1.0)), ((33.0)), ((2147483649.0)), ((-2097153.0)), ((2097153.0)), ((-70368744177665.0)), ((-1099511627777.0)), ((2097152.0)), ((256.0)), ((-73786976294838210000.0)), ((-144115188075855870.0)), ((131073.0)), ((9007199254740991.0)), ((6.189700196426902e+26)), ((-6.044629098073146e+23)), ((-1.00390625)), ((-4097.0)), ((-1.5111572745182865e+23)), ((65.0)))) >= (+pow(((131073.0)), ((Float32ArrayView[((0x1b51ce17) % (((0xc28e76be))>>>((0x8e06c0a)))) >> 2])))));\n    }\n    (Float32ArrayView[0]) = ((-549755813889.0));\n    (Float32ArrayView[2]) = ((+(0x434dbf65)));\n    i1 = (i1);\n    i1 = ((((arguments.callee.caller.caller.arguments++)) | (-0xfffff*(i0))));\n    i0 = (i0);\n    i0 = (i1);\n    (Int32ArrayView[(((((-18014398509481984.0))) >> ((i1))) % (0x5ec1f131)) >> 2]) = ((!(i0)));\n    i0 = (i0);\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=784; tryItOut("m0.has(b2);");
/*fuzzSeed-116066984*/count=785; tryItOut("g2.valueOf = (function() { try { t2 = t1.subarray(4); } catch(e0) { } try { b2.__iterator__ = f1; } catch(e1) { } e0 = new Set(h2); return t2; });");
/*fuzzSeed-116066984*/count=786; tryItOut("/*MXX1*/g2.o1 = g2.Math.acosh;");
/*fuzzSeed-116066984*/count=787; tryItOut("\"use strict\"; v2 = (b1 instanceof i1);");
/*fuzzSeed-116066984*/count=788; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ((Math.fround(Math.log2(Math.fround(((((mathy1((y | 0), Number.MIN_VALUE) ** ( + x)) >>> 0) * (y >>> 0)) >>> 0)))) == Math.fround(Math.fround(Math.fround(Math.atanh(Math.fround(x)))))) , ( + (( + (Math.hypot((( - ( + ( ~ -1/0))) | 0), (((x >>> 0) <= (x | 0)) | 0)) ? Math.cos((mathy1(y, (((-(2**53) >>> 0) || Math.asin(y)) | 0)) | 0)) : (( ~ (y | 0)) | 0))) / Math.fround(Math.fround((Math.fround(x) > Math.fround(Math.min(( - x), (y ? ( + x) : (((0x100000000 >>> 0) ? (0/0 | 0) : (x | 0)) | 0)))))))))); }); testMathyFunction(mathy4, [0x07fffffff, Number.MIN_VALUE, 0x080000000, Math.PI, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, -0, -0x100000000, 0x100000001, 0x0ffffffff, -(2**53-2), -0x080000001, Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, 2**53, 0, -(2**53), 42, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2, 0x100000000, 0/0, -(2**53+2), 2**53+2, -1/0, 0x080000001, -0x100000001, -0x080000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=789; tryItOut("x = x ^ x; var r0 = x ^ x; var r1 = x * x; var r2 = 8 ^ r1; print(x); r0 = 6 & r2; ");
/*fuzzSeed-116066984*/count=790; tryItOut("switch(x) { case x: break;  }");
/*fuzzSeed-116066984*/count=791; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=792; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.log10(Math.atan2(((x >>> 0) <= (Math.log2(-0x080000001) >>> 0)), ( - x))) > ((( + ( + ( ~ Math.fround(Math.fround(mathy0((x >>> 0), (Number.MAX_VALUE >>> 0))))))) == ((( + (Math.imul(y, y) >>> (x || 1))) * ( + Math.atan2(x, 0x100000000))) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy5, [1/0, -(2**53+2), 0.000000000000001, -0x080000001, -0, Number.MAX_VALUE, 2**53, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, 2**53+2, -(2**53-2), 0/0, -0x0ffffffff, -Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, -1/0, 0x080000000, -0x100000000, -Number.MIN_VALUE, -0x100000001, 1, 1.7976931348623157e308, 0, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=793; tryItOut("\"use strict\"; this.g1.offThreadCompileScript(\"print(v0);\");");
/*fuzzSeed-116066984*/count=794; tryItOut("\"use strict\"; v0 = g0.runOffThreadScript();");
/*fuzzSeed-116066984*/count=795; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.min(Math.fround(Math.fround(Math.atan2(Math.fround(Math.imul((( + Math.min(( + x), ( + Math.log2(y)))) >>> 0), Math.max(Math.asinh(x), ((((0x080000001 > x) >>> 0) ? Math.max(y, ( - y)) : (( + (y ** 0x080000000)) >>> 0)) >>> 0)))), Math.atan2(( + x), x)))), (Math.atan2((Math.max(Math.min(x, (Math.imul(Math.fround(((x >>> 0) == x)), (1/0 >>> 0)) >>> 0)), (Math.log2((Math.fround(Math.fround(mathy1(Math.fround(Math.tan(x)), Math.fround(x)))) | 0)) | 0)) | 0), (( ! (Math.fround(mathy1((Math.fround(Math.sign(Number.MAX_SAFE_INTEGER)) >>> 0), Math.fround(0x080000000))) ? ( + Math.atan2(( + x), y)) : x)) | 0)) | 0))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1)]); ");
/*fuzzSeed-116066984*/count=796; tryItOut("\"use strict\"; let zewjok, \u3056 = null, x = x;print(v2);");
/*fuzzSeed-116066984*/count=797; tryItOut("\"use strict\"; testMathyFunction(mathy3, [1/0, -Number.MIN_VALUE, 2**53, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, -0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, -0x100000000, -1/0, 2**53+2, 42, -0x080000001, -0x0ffffffff, 0x100000001, 0x080000000, 0x0ffffffff, -0x100000001, -0, 0x080000001, -0x080000000, -(2**53), 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0/0, 0, 0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=798; tryItOut("with({}) let(z) { -17;}");
/*fuzzSeed-116066984*/count=799; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?!\\\\2*))+(?=(?=[^]){4})\\\\2|\\\\u36bE(?!(?!.|\\\\w[^]?)+?\\\\2+?|\\u31e4\\\\u00Ef|\\\\\\u64b4{0,0}|[]*)\", \"gym\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n  a\\udced\\u3ea51\\na\\n\\u5141\\n\\n\\n\\n\\n\\n_\\n\\n\\n\\n_=\\u00ef\\u00ef\\u00ef\\u00ef\\u00ef\"; print(s.replace(r, '', \"yim\")); \n");
/*fuzzSeed-116066984*/count=800; tryItOut("mathy5 = (function(x, y) { return (( ~ Math.max((mathy1((( - y) >>> 0), (y >>> 0)) >>> 0), ( + (( + y) !== ( + (Math.fround(Math.trunc(Math.min(y, (-(2**53+2) | 0)))) && y)))))) >> (( + (( + (( + ( + (y , 1.7976931348623157e308))) + Math.fround(((Math.fround(Math.cbrt((x - -Number.MAX_SAFE_INTEGER))) | 0) << (((((Math.atan2((y >>> 0), (2**53 >>> 0)) >>> 0) >>> 0) <= (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) | 0))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[x, x,  \"use strict\" ,  \"\" , new String('q'),  \"use strict\" , true, x, new String('q'), true,  \"use strict\" , x, new String('q'), new String('q'),  \"\" , x, new String('q'),  \"use strict\" , x,  \"use strict\" , x,  \"\" , new String('q'), true,  \"use strict\" , true, new String('q'), x,  \"use strict\" , x, x,  \"use strict\" , true,  \"\" , x, true, new String('q'), true, x,  \"use strict\" ,  \"use strict\" , x, x]); ");
/*fuzzSeed-116066984*/count=801; tryItOut("print(/*UUV1*/(d.getUint8 = (/*wrap1*/(function(){ print(x);return q => q})()).apply));");
/*fuzzSeed-116066984*/count=802; tryItOut("a0[18] = p1;");
/*fuzzSeed-116066984*/count=803; tryItOut("\"use strict\"; /*iii*/print(x);/*hhh*/function khtqui(){s1 = new String(s0);}");
/*fuzzSeed-116066984*/count=804; tryItOut("g1.s2 += s0;function e(window)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (1);\n    i1 = (i2);\n    return ((((Float64ArrayView[0]))*-0xda825))|0;\n  }\n  return f;v2 = this.a2.length;");
/*fuzzSeed-116066984*/count=805; tryItOut("\"use strict\"; /*iii*/for (var p in t0) { try { Object.prototype.unwatch.call(i0, \"toString\"); } catch(e0) { } try { for (var v of h0) { try { this.a0.sort(neuter); } catch(e0) { } try { e2.has(trbymf); } catch(e1) { } a2 = Array.prototype.map.apply(a2, [f0, g1.o0]); } } catch(e1) { } try { f0 = Proxy.createFunction(h0, this.f1, f0); } catch(e2) { } i1 = new Iterator(o2.g2); }/*hhh*/function trbymf(b = 18, x, x =  '' , x, b, x = z, x, x, x, \u3056, NaN =  \"\" , NaN, b = new RegExp(\"((?:\\\\u0006)\\\\b\\u00a9|[^\\\\D\\\\.-\\\\\\u2dd0][^]*?|(\\\\B)|(?!$){1})+\", \"ym\"), x, w, y =  /x/g , eval, NaN, e, z, y, z, x = \u3056, x, x, y, x, z, x, \u3056, x, b, e =  /x/ , NaN, c, NaN = false, NaN, y, w, e, z, x = this, NaN, b, \u3056, NaN, x, eval, d, z, w, x, w, \u3056, x, c, z = -21, x, x, d = window, y, x, \u3056 = \"\\uEF7A\", NaN, e, eval, \u3056 = window, window,  , this.w, NaN, c, d = window, x, a, x, b, d, x = function ([y]) { }, x, \u3056, w, b, this.x, x){print(x);}");
/*fuzzSeed-116066984*/count=806; tryItOut("\"use strict\"; /*hhh*/function hebiev(...x){a1.splice(NaN, 5);}/*iii*/throw hebiev;h2.get = f0;");
/*fuzzSeed-116066984*/count=807; tryItOut("this.h1 + '';");
/*fuzzSeed-116066984*/count=808; tryItOut("mathy3 = (function(x, y) { return (mathy2((Math.sign(( + Math.sin(( + ((Math.log1p((-0x07fffffff | 0)) | 0) ** (Math.cosh(( + (Math.fround(0/0) & ( + x)))) | 0)))))) | 0), Math.imul(Math.expm1(Number.MIN_VALUE), (Math.cos(y) | 0))) | 0); }); ");
/*fuzzSeed-116066984*/count=809; tryItOut("selectforgc(o1);function \u3056\n(y = let (d) [1,,], b = ({}), ...e) { return -20 } for (var p in e0) { try { var s0 = s1.charAt(19); } catch(e0) { } h1.hasOwn = this.f0; }");
/*fuzzSeed-116066984*/count=810; tryItOut("testMathyFunction(mathy0, /*MARR*/[ '' , {},  \"\" , null, null, null, null, null,  \"\" ,  \"\" , function(){}, {},  '' , function(){},  \"\" , function(){}, {},  '' , function(){},  \"\" , {}, null, {},  '' , function(){},  '' , {}, function(){}, function(){},  \"\" ,  \"\" , null, {}, function(){}, {}, null, {}, null, function(){}, function(){}, function(){}, {},  '' ,  \"\" , function(){}, null, function(){}, {},  '' , function(){}, null, null, function(){}, function(){},  \"\" , function(){}, null, {},  '' , function(){}, function(){},  '' , {},  \"\" ,  \"\" , {}, function(){}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {},  '' , {},  '' , null, null, function(){}, null, null,  \"\" , {}, function(){}, {},  '' , function(){}]); ");
/*fuzzSeed-116066984*/count=811; tryItOut("v1 = undefined;");
/*fuzzSeed-116066984*/count=812; tryItOut("o0.g0.h2 + '';let x = {} =  /x/  |= arguments.callee.caller.arguments = (c) =  \"\" , x = Math.trunc(x), x = (void version(185)), x;/*RXUB*/var r =  \"\" ; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=813; tryItOut("mathy5 = (function(x, y) { return Math.atan2(( + (( ~ (( + Math.fround((Math.atan2((-1/0 | 0), (y | 0)) | 0))) >>> 0)) - (((-Number.MAX_SAFE_INTEGER | 0) ? Math.fround(y) : (x | 0)) | 0))), ( + Math.tan((y > y)))); }); ");
/*fuzzSeed-116066984*/count=814; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\3)|.|((?:\\\\B{1,5}|\\\\B|($).([^])|[\\\\d]{3}|\\\\1))?\", \"m\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-116066984*/count=815; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( ~ ( + Math.max(Math.max(Math.tan(( + mathy2((( + (x + (Math.min((y | 0), (x | 0)) | 0))) | 0), (((x <= (x | 0)) | 0) | 0)))), ((Math.atan2((Math.hypot((Math.fround(-0x100000001) > ((x >>> 0) ? x : (x >>> 0))), (y !== Math.PI)) >>> 0), (( + Math.imul(( + y), ( + y))) >>> 0)) >>> 0) >>> 0)), (( + Math.atan2((Math.atan2((Math.atan2(( ~ 1.7976931348623157e308), x) | 0), (Math.fround((y ? Math.fround(y) : Math.fround(-1/0))) | 0)) >>> 0), (y >>> 0))) + (mathy2(( + Math.pow(( + mathy0(x, y)), (-0x0ffffffff >>> 0))), x) >>> 0))))) | 0); }); ");
/*fuzzSeed-116066984*/count=816; tryItOut("mathy2 = (function(x, y) { return (Math.hypot(Math.fround(Math.max((y !== x), Math.fround((Math.fround(y) || (((( ! Number.MAX_VALUE) <= x) | 0) != -(2**53-2)))))), Math.min((x == ( + ( ! (( - Math.fround(x)) >>> 0)))), (Math.asin(x) >>> 0))) ? Math.log2(Math.fround(( ~ ( + mathy1((0 >>> 0), ( + y)))))) : (mathy0((mathy1(((( ! ((Math.log10((-0 | 0)) >>> 0) | 0)) >>> 0) >>> 0), (x >>> 0)) >>> 0), Math.min((x >>> 0), (Math.imul((Math.fround((0x080000001 | ((Math.fround(Math.fround(Math.sin(( + y)))) < 1) >>> 0))) | 0), (mathy1((( + y) >> ( + Number.MIN_VALUE)), x) | 0)) | 0))) | 0)); }); testMathyFunction(mathy2, [-0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 0x100000000, -(2**53-2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, -1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, -0x100000001, Number.MAX_VALUE, 2**53+2, -0, 0x100000001, -Number.MAX_VALUE, 0x080000001, 0x07fffffff, 1, 0x0ffffffff, -0x07fffffff, -0x0ffffffff, -(2**53+2), 1/0, -(2**53), -Number.MIN_VALUE, 2**53-2, 0/0, 0, -0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=817; tryItOut("g2.offThreadCompileScript(\"v1 = a1.length;\");");
/*fuzzSeed-116066984*/count=818; tryItOut("a = (void options('strict_mode')), {} = window, wmuzlv, d = undefined;(false / NaN--);");
/*fuzzSeed-116066984*/count=819; tryItOut("mathy4 = (function(x, y) { return (Math.fround(Math.hypot(Math.fround((( ~ (Math.fround(( + Math.fround(( + Math.min(( + 1.7976931348623157e308), Math.fround(Math.max(Math.fround(mathy3((x >>> 0), y)), y))))))) >>> 0)) >>> 0)), (( - x) | 0))) === Math.fround(Math.atan2((Math.cbrt((( ! ((Math.min((Math.PI | 0), ( + ( + (( + x) <= ( + x))))) >= x) | 0)) | 0)) >>> 0), ((Math.fround(( - (1 | 0))) - (y + (( ! (Math.hypot(((y > y) >>> 0), (-1/0 >>> 0)) | 0)) | 0))) | 0)))); }); testMathyFunction(mathy4, [0x07fffffff, 1/0, Number.MIN_VALUE, 42, 2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, -0x100000001, Math.PI, -Number.MAX_VALUE, 0x100000000, -0, 2**53, -0x080000001, -1/0, -(2**53-2), 0x080000000, 1, 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x0ffffffff, -(2**53+2), -0x100000000, -0x080000000]); ");
/*fuzzSeed-116066984*/count=820; tryItOut("function shapeyConstructor(sbljcn){Object.preventExtensions(this);this[\"x\"] = new String('');delete this[new String(\"0\")];this[\"x\"] = new Boolean(true);{ with({d: x = Proxy.createFunction(({/*TOODEEP*/})(this), neuter) ? window = \"\u03a0\" : (window.watch(17, /*wrap1*/(function(){ yield this;return Set})()))})m1.get(b1); } Object.freeze(this);if (sbljcn) this[\"d\"] = function(){};if (sbljcn) Object.defineProperty(this, \"find\", ({}));return this; }/*tLoopC*/for (let e of /*MARR*/[x, null, null, false, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, null, false, x, x, x, x, null, false, null, false, null, false, null, false, x, false, false, x, false, false, x, x, x, null, null, null, x, null, null, x, null, x, x, x, null, null, null, x, x, false, null, false, x, false, false]) { try{let hqciyn = shapeyConstructor(e); print('EETT'); /* no regression tests found */}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-116066984*/count=821; tryItOut("a2.splice();");
/*fuzzSeed-116066984*/count=822; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ( - (((1/0 & Math.hypot((x >>> 0), Math.fround(y))) >>> 0) === (Math.sinh(Math.fround(Math.imul(( + Math.imul(y, x)), (Math.fround(mathy1((( ! y) >>> 0), (2**53+2 >>> 0))) ? x : 0x0ffffffff)))) >>> 0)))); }); ");
/*fuzzSeed-116066984*/count=823; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=824; tryItOut("i0 = a2[v0];");
/*fuzzSeed-116066984*/count=825; tryItOut("{ void 0; setGCCallback({ action: \"majorGC\", depth: 14, phases: \"begin\" }); } o1.a0 = r1.exec(s2);");
/*fuzzSeed-116066984*/count=826; tryItOut("\"use strict\"; (/*MARR*/[({}), x, x, x, (0/0), ({}), (0/0), (0/0), function(){}, ({}), ({}), function(){}, ({}), (0/0)].map(function(y) { (( /x/g ).bind).call( '' , let (w) this); }));");
/*fuzzSeed-116066984*/count=827; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.fround(Math.acosh((( ! x) >>> 0))) & ( ~ ((((( - ((Math.pow((x >>> 0), (x >>> 0)) === ( + Math.pow(Math.fround(-0x100000001), Math.fround(x)))) >>> 0)) | 0) | 0) % (( + (x >>> 0)) | 0)) | 0))); }); testMathyFunction(mathy3, [0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0, -(2**53-2), -1/0, 2**53, -Number.MIN_VALUE, -0x080000000, 0x100000001, -(2**53), -0x080000001, -(2**53+2), 0x0ffffffff, 1/0, 1.7976931348623157e308, -0x100000000, 2**53-2, 0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, 2**53+2, 1, 0x100000000, 0/0, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=828; tryItOut("h2.fix = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        d1 = (256.0);\n      }\n    }\n    d1 = (((d1)) / ((d1)));\n    return (((0xfa42541f)))|0;\n    (Uint32ArrayView[((((-0x8000000)) >> ((i0)-(0x2c144a56))) % (abs((allocationMarker()))|0)) >> 2]) = (((0xa6297d9) ? ((((Uint32ArrayView[((-0x8000000)) >> 2])) << ((i0)*-0x21b6d)) <= (new RegExp(\"\\u966b|[^\\\\u7C8f\\\\W\\u4bc3-\\u4c87]\\u96e7|[^](?!.+)*?(?!\\\\W{0,3}\\\\S)|[^]*+?\", \"\"))) : (1))+(i0));\n    (Int8ArrayView[((0xf8bc3699)+((0x55b40a70) ? (0x13869863) : ((0xa4caf1df) ? (0xf84fde7f) : (0x7504984e)))-(0x51f1183f)) >> 0]) = ((((((((1))>>>(0x9dbd8*(0x659f3555))) >= (((Uint32ArrayView[4096]))>>>((0x5588a5e) / (0x32b70fea))))-(i0)+((0xfc7981bf)))>>>((-0x8000000)))));\n    (Uint32ArrayView[((0xcfb0efaa)+(0x3b7fc131)-(0x8e8e6f0c)) >> 2]) = ((i0));\n    return ((((0x3e91e85f) >= (0x0))-(i0)))|0;\n    (Uint32ArrayView[((0xd6a118d4)-(i0)+(0x24853c0f)) >> 2]) = (((Uint32ArrayView[((0xffffffff)+(0x45ca336c)) >> 2])) / (0xa219be3a));\n    {\n      (Float64ArrayView[(-(-0x8000000)) >> 3]) = ((32769.0));\n    }\n    return (((0xfa2bda3f)+(!(0x541f9386))-(1)))|0;\n    {\n      d1 = (-34359738368.0);\n    }\n    d1 = (Infinity);\n    return (((0xfd055c3b)-(i0)-(0x6b59e1c1)))|0;\n    d1 = (d1);\n    i0 = (!(0xf651b3f9));\n    switch ((~~(d1))) {\n      case -3:\n        return (((x)))|0;\n        break;\n      case 1:\n        d1 = (d1);\n        break;\n      case 1:\n        return ((((0x3cf02923))))|0;\n      default:\n        d1 = (17179869183.0);\n    }\n    i0 = ((imul((-0xfd2583), (i0))|0));\n    {\n      d1 = (d1);\n    }\n    {\n      d1 = (d1);\n    }\n    d1 = (+pow(((((9.44473296573929e+21)) - ((void options('strict_mode'))))), ((d1))));\n    d1 = (((-((NaN)))) % ((d1)));\n    {\n      {\n        {\n          {\n            (Float64ArrayView[1]) = ((d1));\n          }\n        }\n      }\n    }\n    return (((i0)))|0;\n    return (((x ^ eval + this)))|0;\n  }\n  return f; });");
/*fuzzSeed-116066984*/count=829; tryItOut("\"use strict\"; (Boolean(\"\\u30EA\"));function x({}, eval)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((+((d1))));\n  }\n  return f;for (var v of p1) { try { g2.toString = (function(j) { if (j) { try { for (var p in m1) { try { s0 += this.s1; } catch(e0) { } try { this.v0 + e2; } catch(e1) { } try { v0 = r1.unicode; } catch(e2) { } a0 = Array.prototype.map.apply(a2, []); } } catch(e0) { } try { a2.pop(e1, p1, m2); } catch(e1) { } try { o0.a2.push(v1, o1, e2, a1, v1); } catch(e2) { } e0 + h1; } else { try { Object.freeze(s2); } catch(e0) { } try { v2 = g1.runOffThreadScript(); } catch(e1) { } try { Object.defineProperty(this, \"v0\", { configurable: (x % 22 == 4), enumerable: window,  get: function() {  return evalcx(\"\\\"use strict\\\"; a1.pop(o1.t2);\", g1); } }); } catch(e2) { } m1.has(this.s1); } }); } catch(e0) { } v2 = evaluate(\"([[1]]);\", ({ global: o2.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: false, element: g1.o0, sourceMapURL: this.s2 })); }");
/*fuzzSeed-116066984*/count=830; tryItOut("v1 = this.t0[yield x];");
/*fuzzSeed-116066984*/count=831; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( + Math.cbrt(( + (Math.fround((x | (y >>> 0))) >> (( - ((Math.asin((y | 0)) >>> 0) >>> 0)) | 0))))) - ( + (( + Math.abs(( + ( ! ( + Math.tan(x)))))) <= ( + (Math.fround(Math.sqrt(( + -(2**53)))) * (mathy3(x, Math.sqrt(x)) >>> 0)))))); }); testMathyFunction(mathy4, [-0x080000000, -(2**53-2), 0x07fffffff, -0x100000001, -0x07fffffff, -(2**53+2), 2**53+2, -(2**53), 0.000000000000001, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, 1/0, 0x080000000, -0x0ffffffff, -0x080000001, 2**53-2, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 0, 1, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, -Number.MIN_SAFE_INTEGER, 42, -1/0, Math.PI, 0x100000000, 0x0ffffffff, 0x100000001, -0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=832; tryItOut("\"use strict\"; /*RXUB*/var r =  /x/g ; var s =  /x/g ; print(s.search(r)); ");
/*fuzzSeed-116066984*/count=833; tryItOut("\"use strict\"; /*infloop*/ for (this.w of this.__defineGetter__(\"x\", SharedArrayBuffer)) f1(a0);");
/*fuzzSeed-116066984*/count=834; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.hypot(( + (( - (Math.atan2((mathy3(((( - (y | 0)) | 0) | 0), (y | 0)) | 0), (0x100000001 % ((-0x080000001 < -0x080000000) >>> 0))) | 0)) | 0)), (Math.ceil(y) >>> 0)) < (Math.trunc(Math.fround(Math.atan2((Math.min((( ! y) >>> 0), Math.fround(Math.min(y, Math.fround(Math.fround(Math.tan(Math.fround(x))))))) >>> 0), Math.exp(Math.max(1/0, ( + Math.max(0x07fffffff, ( + x)))))))) >>> 0)); }); testMathyFunction(mathy5, [0x080000000, Number.MIN_VALUE, 1, Math.PI, 0/0, -0x100000000, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0, -0x080000000, -0x080000001, -(2**53+2), 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, -1/0, -(2**53-2), 42, -0x07fffffff, -0, 2**53-2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, Number.MAX_VALUE, 0x0ffffffff, 2**53+2, 0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-116066984*/count=835; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(( + (Math.ceil(((Math.fround((y / Math.atan2(( + (Math.imul((x >>> 0), (x >>> 0)) >>> 0)), ( + Math.fround((y > x)))))) / ( + ( + ( ~ (( + -0x080000001) >>> 0))))) | 0)) | 0)), ((Math.fround(mathy1(((Math.max((Math.fround((Math.fround(-Number.MAX_SAFE_INTEGER) > Math.fround((x >>> y)))) >>> 0), (-0x07fffffff >>> 0)) >>> 0) | 0), (mathy0(y, Math.exp(y)) | 0))) % Math.cbrt((( + Math.fround(Math.atan2(( + (y ? y : x)), Math.fround(0x100000001)))) ? ( + x) : ( + Math.atan2(Math.fround(((((x | 0) !== (x | 0)) | 0) || x)), ( + ( + ( + -0x100000000)))))))) | 0))); }); testMathyFunction(mathy2, [0x07fffffff, 42, 0x100000000, 0/0, -1/0, 1, 0x080000001, 1.7976931348623157e308, 0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, -0x100000000, -0x07fffffff, -(2**53), 0.000000000000001, 0, 1/0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, -Number.MIN_VALUE, -(2**53-2), 0x100000001, 2**53, Math.PI, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=836; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.pop.apply(o0.a2, [g1.o2, h1, a2, v2, a2]);");
/*fuzzSeed-116066984*/count=837; tryItOut("\"use strict\"; g1 + '';");
/*fuzzSeed-116066984*/count=838; tryItOut("/*RXUB*/var r = /[^\u09b4-\u985a]/i; var s = \"\\u983b\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=839; tryItOut("e0.add(p0);");
/*fuzzSeed-116066984*/count=840; tryItOut("v2 = t2.byteOffset;");
/*fuzzSeed-116066984*/count=841; tryItOut("M:for(var y in ((encodeURI)(('fafafa'.replace(/a/g, URIError))))){s1.valueOf = (function(j) { if (j) { o2.v2 = evaluate(\"Object.defineProperty(NaN, \\\"1\\\", ({}))\", ({ global: g2.g2.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 3 == 2), sourceIsLazy: false, catchTermination: (x % 81 == 49) })); } else { try { Array.prototype.shift.apply(a0, []); } catch(e0) { } i2.next(); } });this.g2.offThreadCompileScript(\"y\"); }");
/*fuzzSeed-116066984*/count=842; tryItOut("mathy2 = (function(x, y) { return ( ! (((Math.hypot((((x ? x : x) != Math.fround(Math.ceil(Math.fround((x * y))))) | 0), Math.min(Math.fround(( + (( + (x > x)) | ( + x)))), Math.log((( + x) >>> 0)))) >>> 0) ? (Math.atanh(Number.MAX_SAFE_INTEGER) >>> 0) : ((Math.fround(( + x)) ? Math.imul(x, ( + ( + y))) : Math.fround(( ! ( + x)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=843; tryItOut("M:with({c: })for(let x in []);c.name;");
/*fuzzSeed-116066984*/count=844; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-(2**53+2), -(2**53-2), 1/0, -0x100000001, 42, 0.000000000000001, -0x100000000, 2**53, -0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -0x080000000, -0x0ffffffff, 0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, Math.PI, 1.7976931348623157e308, -(2**53), Number.MIN_VALUE, 2**53+2, 0x100000001, 0, -0, 1, 2**53-2]); ");
/*fuzzSeed-116066984*/count=845; tryItOut("\"use strict\"; for (var v of f2) { print(m0); }");
/*fuzzSeed-116066984*/count=846; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( ~ (((x ? Math.fround(Math.atan2(( + ( ~ x)), y)) : (Math.fround((y <= x)) <= Math.fround(x))) < Math.acos(( + Math.sin((x | 0))))) , (((((Math.trunc(y) | 0) + (( + x) && y)) < (y | 0)) | 0) ? (Math.ceil((y >>> 0)) >>> 0) : [] > new RegExp(\".\", \"g\")))); }); ");
/*fuzzSeed-116066984*/count=847; tryItOut("mathy2 = (function(x, y) { return (Math.min(Math.fround(Math.min(Math.atan(-Number.MAX_SAFE_INTEGER), x)), Math.fround(mathy1(-0x07fffffff, ( + mathy1((Math.hypot(x, -(2**53-2)) >>> 0), (y >>> 0)))))) === (Math.atan2(( + mathy0(Math.min((( + (x >>> 0)) | 0), Math.fround((Math.sin(y) | 0))), (mathy1(Math.fround(Math.sign(x)), y) >>> 0))), ((x << Math.fround(( ! (mathy1(( - y), x) >>> 0)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=848; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (((( ! ( - y)) | (( ~ (( + mathy2(-0x100000001, (y ** y))) | 0)) >>> 0)) | 0) === ( ~ Math.sign(Math.fround(Math.cbrt(y))))); }); testMathyFunction(mathy5, [-0, 2**53, 0x100000001, 2**53-2, -0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, -1/0, -0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, 0, -(2**53), 0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), 0x100000000, 42, -0x07fffffff, -0x100000000, -0x080000000, 0/0, 2**53+2]); ");
/*fuzzSeed-116066984*/count=849; tryItOut("testMathyFunction(mathy1, ['\\0', false, (function(){return 0;}), objectEmulatingUndefined(), (new Number(0)), null, (new Boolean(true)), '', 0, true, ({toString:function(){return '0';}}), NaN, [0], /0/, undefined, '/0/', (new Boolean(false)), '0', (new Number(-0)), (new String('')), ({valueOf:function(){return 0;}}), 0.1, [], 1, -0, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-116066984*/count=850; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n;    return +((Float32ArrayView[2]));\n  }\n  return f; })(this, {ff: Math.random}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=851; tryItOut("v0 = evalcx(\"function f2(e2)  { /*bLoop*/for (var slqxxg = 0, x; slqxxg < 21; ++slqxxg) { if (slqxxg % 27 == 11) { a2.forEach((function() { try { h2.set = (function() { try { o2.v1 = (s1 instanceof g2.g1); } catch(e0) { } try { o2.g0.v0 = 4.2; } catch(e1) { } try { new RegExp(\\\"(?!(?!(?:[^\\\\\\\\w\\\\\\\\cD])|\\\\\\\\1*?)){1,4}\\\", \\\"g\\\") = this.a2[({valueOf: function() { Array.prototype.unshift.apply(a1, [o0, b2]);return 1; }})]; } catch(e2) { } Array.prototype.forEach.call(a2, (function() { for (var j=0;j<32;++j) { g0.f1(j%3==0); } }), i1, s2, t1); return g2.s2; }); } catch(e0) { } v1 = true; return h2; }), p2); } else { v0 = evalcx(\\\"function f2(e0) (new e2(y = Proxy.createFunction(({/*TOODEEP*/})(undefined),  /x/g , new Function)))\\\", g2); }  }  } \", this.o2.g0);");
/*fuzzSeed-116066984*/count=852; tryItOut("let a, rmchtb, x, y = z - x, lgoewc, [] = let (aiiack, y, z, \u3056, a, e, jbizuj, xtcfso, ftyczh) /*FARR*/[ '' , undefined, 4228964753, \"\\u5282\", window, , ...[]].map(WeakMap.prototype.delete), xnlgvw, tikvkx, x = (4277), pltjll;this.zzz.zzz;try { d = x; } catch(eval if ('fafafa'.replace(/a/g, ( '' )(-28,  '' )))) { this.zzz.zzz; } catch(d if (function(){return;})()) { for(let c of String.prototype.padEnd) throw StopIteration; } catch(d if /*FARR*/[, , this, ].sort(function(y) { m1.get(g0); }, (void options('strict_mode')))) { with({}) try { (true); } finally { (this); }  } catch(a if ({wrappedJSObject: window, /*toXFun*/toString: String.prototype.toLowerCase })) { c = window; } catch(x) { return x; } finally { let(y) ((function(){throw StopIteration;})()); } ");
/*fuzzSeed-116066984*/count=853; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=854; tryItOut("\"use strict\"; /*vLoop*/for (let fgibot = 0; fgibot < 39; ++fgibot) { const z = fgibot; print(z); } ");
/*fuzzSeed-116066984*/count=855; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.max(Math.max(0x0ffffffff, ( - 1/0)), ( + Math.atan2(x, (Math.pow((x | 0), 0x080000001) | 0)))) | ((( + Math.cosh(Math.fround(( - y)))) <= (Math.pow(Number.MIN_SAFE_INTEGER, mathy0(y, -Number.MAX_VALUE)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [Math.PI, -0x100000000, 0.000000000000001, -(2**53-2), -1/0, -Number.MAX_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 0/0, 1, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 2**53, Number.MIN_VALUE, 0x100000000, 0x100000001, 1/0, -0x080000001, 0x080000000, 0x0ffffffff, 0, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, 42, 1.7976931348623157e308, 2**53-2, -(2**53+2)]); ");
/*fuzzSeed-116066984*/count=856; tryItOut("\"use asm\"; v1 = (p0 instanceof b2);");
/*fuzzSeed-116066984*/count=857; tryItOut("mathy4 = (function(x, y) { return ( + mathy0(( + (( + (( - ((( + x) - ( + y)) >= x)) | 0)) % (Math.min(Math.sqrt(y), ((x === ( + mathy3(2**53+2, Math.pow(y, Number.MIN_SAFE_INTEGER)))) === y)) | 0))), (((Math.imul((Math.atan2(( + Math.min(y, (Number.MAX_SAFE_INTEGER === x))), Math.fround(((2**53-2 >>> 0) && ((x ? y : y) >>> 0)))) | 0), (Math.round((Math.hypot(y, x) >>> 0)) | 0)) | 0) === (((Math.sqrt(((Math.fround((( + x) ^ ( + y))) >= Math.fround(1/0)) | 0)) >>> 0) & (y >>> 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-116066984*/count=858; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + Math.min(( + Math.cos(Math.cosh(( + Math.atan((Math.tanh(y) | 0)))))), ( + (( ! (x | 0)) | 0)))) || ( + Math.atan2((Math.imul((x >>> 0), (Math.fround(( + Math.fround(mathy2(x, 0)))) >>> 0)) * (( - (((x | 0) + ( - -Number.MAX_VALUE)) >>> 0)) | 0)), (Math.round((Math.pow(x, mathy0(y, y)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [(function(){return 0;}), null, objectEmulatingUndefined(), 0, NaN, true, (new Boolean(false)), ({toString:function(){return '0';}}), undefined, [0], /0/, -0, (new String('')), (new Boolean(true)), '\\0', '/0/', 0.1, [], '', (new Number(0)), ({valueOf:function(){return 0;}}), '0', 1, false, ({valueOf:function(){return '0';}}), (new Number(-0))]); ");
/*fuzzSeed-116066984*/count=859; tryItOut("h1.getOwnPropertyNames = (function() { for (var j=0;j<18;++j) { f1(j%2==1); } });");
/*fuzzSeed-116066984*/count=860; tryItOut("this.o0.v1 = Object.prototype.isPrototypeOf.call(this.g2.g0, this.s1);");
/*fuzzSeed-116066984*/count=861; tryItOut("var d = \"\\uCD9F\", x, NaN, this.a = /*MARR*/[new Boolean(true), -0xB504F332, -Infinity, -0xB504F332, new Boolean(true), new Boolean(true), -Infinity, -0xB504F332, new Boolean(true), new Boolean(true), -Infinity, new Boolean(true), -0xB504F332, -Infinity, new Boolean(true), new Boolean(true), -Infinity, new Boolean(true), -0xB504F332, -0xB504F332, new Boolean(true), -Infinity, new Boolean(true), new Boolean(true), -Infinity, new Boolean(true), -0xB504F332, -Infinity, -Infinity, -Infinity, -0xB504F332, -Infinity, -0xB504F332, -Infinity, -0xB504F332, new Boolean(true), -Infinity, -0xB504F332, new Boolean(true), new Boolean(true), -Infinity, -0xB504F332].map(/*wrap2*/(function(){ var exgwta = x >>>  ; var wmchjh = Date.prototype.getHours; return wmchjh;})(), ({d: /*UUV1*/(constructor.UTC = (function(x, y) { return -1/0; })), __iterator__: x })), bkhmlz, zuhkbh, jmldvh, y;M:for(let b = x in false) Array.prototype.splice.apply(a2, [NaN, 9]);");
/*fuzzSeed-116066984*/count=862; tryItOut("i0.next();");
/*fuzzSeed-116066984*/count=863; tryItOut("/*tLoop*/for (let d of /*MARR*/[new Number(1.5), {x:3},  \"use strict\" ,  \"use strict\" , new Number(1.5), {x:3}, {x:3}, {x:3},  \"use strict\" , {x:3},  \"use strict\" , new Number(1.5), {x:3}, {x:3}, {x:3},  \"use strict\" ,  \"use strict\" , {x:3},  \"use strict\" , new Number(1.5), new Number(1.5), {x:3}, {x:3}, new Number(1.5),  \"use strict\" , {x:3}, new Number(1.5), {x:3}, {x:3}, {x:3},  \"use strict\" ,  \"use strict\" , {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, new Number(1.5),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Number(1.5), {x:3},  \"use strict\" , new Number(1.5),  \"use strict\" , {x:3}, new Number(1.5),  \"use strict\" , {x:3}, new Number(1.5), {x:3},  \"use strict\" , new Number(1.5)]) { s2 += s2; }");
/*fuzzSeed-116066984*/count=864; tryItOut("with({x: /*RXUE*/new RegExp(\"\\\\3\", \"gi\").exec(\"\")})h2.has = (function() { try { v2 = Infinity; } catch(e0) { } try { a1.forEach((function() { try { v0 = Object.prototype.isPrototypeOf.call(a0, e0); } catch(e0) { } try { a0.forEach(Math.ceil.bind(t0), h2); } catch(e1) { } h2 + i0; return e2; }), v1, p2, s1); } catch(e1) { } try { Array.prototype.reverse.call(a1); } catch(e2) { } /*ODP-3*/Object.defineProperty(e1, \"valueOf\", { configurable: false, enumerable: (x % 24 == 20), writable: window, value: a2 }); return v0; });function x(x) { \"use strict\"; return z } e2.valueOf = f1;");
/*fuzzSeed-116066984*/count=865; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a1, []);function NaN(x) { print(x);\no0.g0.a1 = a1.concat(a0, f0);\n } s1 = Array.prototype.join.call(a1, this.s1, t2, g1, o2);");
/*fuzzSeed-116066984*/count=866; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.min(Math.fround(Math.imul(Math.acosh(y), y)), ( + Math.max(( + Math.tan(Math.cbrt(-0x07fffffff))), ( + x)))) == ( - ( ! Math.fround(( ! y))))); }); testMathyFunction(mathy0, /*MARR*/[new Boolean(true), true, true, true, true, true, new Boolean(true), true, true, true, true, new Boolean(true), true, true, new Boolean(true), true, new Boolean(true), new Boolean(true), true, true, true, new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), new Boolean(true), true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, true, new Boolean(true), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, true, new Boolean(true), true, new Boolean(true), true, true, true, true, true, true, true, new Boolean(true), true, new Boolean(true), true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, true, true, new Boolean(true), true, true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, new Boolean(true), true, new Boolean(true), true, true, new Boolean(true), new Boolean(true), true, true, true, new Boolean(true), true, true, true, true, true, true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), true, true, true, true, new Boolean(true), true, true, true, true, new Boolean(true)]); ");
/*fuzzSeed-116066984*/count=867; tryItOut("o1 = {};");
/*fuzzSeed-116066984*/count=868; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( + (Math.imul(Math.fround((Math.max(y, (Math.max((-Number.MIN_VALUE | 0), (x | 0)) | 0)) < ( + Math.fround(Math.max(((( ! (y >>> 0)) >>> 0) | 0), (y | 0)))))), ( ~ Math.fround(( ~ Math.fround(y))))) > ( + ( - Math.fround(( ! (y >>> 0)))))))); }); testMathyFunction(mathy3, /*MARR*/[\u3056 != x, undefined, objectEmulatingUndefined(), \u3056 != x, \u3056 != x, \u3056 != x, objectEmulatingUndefined(), \u3056 != x, Infinity, objectEmulatingUndefined(), \u3056 != x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, undefined, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, undefined, undefined, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), undefined, Infinity, \u3056 != x, \u3056 != x, objectEmulatingUndefined(), \u3056 != x, objectEmulatingUndefined(), Infinity, \u3056 != x, \u3056 != x, \u3056 != x, Infinity, \u3056 != x, \u3056 != x, objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), Infinity, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-116066984*/count=869; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((( ~ Math.max(((0x0ffffffff >>> 0) - ((((x | 0) & (x | 0)) | 0) | 0)), (((y >>> 0) | ( + -(2**53))) >>> 0))) ? Math.clz32(( + Math.fround(( - ( + Math.cbrt(y)))))) : Math.fround(Math.hypot((Math.imul((x >>> 0), (Math.atanh(y) >>> 0)) >>> 0), (y | 0)))), Math.fround(mathy0(Math.fround(( ! ( + ( - ( + y))))), Math.fround(Math.sinh(Math.sinh(x)))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, -(2**53+2), 0x080000000, 2**53, -0x100000001, 42, -Number.MIN_VALUE, -0, 0x07fffffff, -(2**53-2), 2**53+2, 1.7976931348623157e308, 0x080000001, Math.PI, 0x100000001, 0/0, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 0x0ffffffff, 0x100000000, 1/0, 1, -Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -0x100000000, -Number.MAX_VALUE, -0x080000000, -1/0]); ");
/*fuzzSeed-116066984*/count=870; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=871; tryItOut("t0.valueOf = (function() { for (var j=0;j<17;++j) { f1(j%4==0); } });");
/*fuzzSeed-116066984*/count=872; tryItOut("testMathyFunction(mathy4, [0.000000000000001, -Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), -0x0ffffffff, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, Math.PI, 42, Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 1/0, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000000, -(2**53), -0x100000000, -(2**53+2), -0x07fffffff, 0/0, 2**53-2, 0, -1/0, -0, -0x080000000, Number.MAX_SAFE_INTEGER, 1, 2**53+2, 0x07fffffff, 0x100000000, -0x100000001]); ");
/*fuzzSeed-116066984*/count=873; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s2; print(s.replace(r, '\\u0341')); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=874; tryItOut("for (var v of e0) { try { s1 += s0; } catch(e0) { } t0.set(o1.t0, 4); }");
/*fuzzSeed-116066984*/count=875; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.pow(Math.atan2(Math.imul(( + ( ~ y)), Math.sign(( + 1))), Math.min(Math.pow(0x080000001, Math.sign((x | ( + y)))), ((((( ! (-0x100000001 | 0)) ? y : x) >>> 0) === ( ! x)) >>> 0))), ((((( ~ (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) >>> 0) >> (( + Math.sign(( + ((((Math.fround((mathy1((Math.imul(y, Number.MIN_VALUE) >>> 0), (x >>> 0)) >>> 0)) , Math.fround(x)) >>> 0) ? (Math.sinh((-Number.MAX_VALUE >>> 0)) >>> 0) : Math.pow(( + mathy1(( + (y ? y : Number.MIN_VALUE)), ( + ((y <= x) >>> 0)))), ( + Math.log1p(x)))) >>> 0)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=876; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\"; m0.delete(v2);\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    d0 = (d0);\n    return (((i2)+(0x2cc1e43b)+((((((0x6511532) ? (0xc18a6494) : (0xffffffff)) ? (0xfa92deab) : ((((0x4ce40d46))>>>((-0x5c088d8)))))-((d1) > (d1)))|0))))|0;\n  }\n  return f; })(this, {ff: String.prototype.sup}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [NaN, undefined, false, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), '', (new String('')), 0.1, [0], -0, '0', [], (new Boolean(false)), objectEmulatingUndefined(), (function(){return 0;}), (new Boolean(true)), '\\0', '/0/', (new Number(0)), ({toString:function(){return '0';}}), (new Number(-0)), 1, null, true, 0, /0/]); ");
/*fuzzSeed-116066984*/count=877; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((Math.fround(( + Math.cbrt(x))) >>> 0) % (Math.max(mathy0(Math.fround(( ~ ( + (( + y) < Math.fround(y))))), x), mathy3((( + ( + Math.imul(( + mathy1(((0.000000000000001 & (0x100000000 | 0)) | 0), ( + y))), ( + ( ~ Math.atan2((y | 0), 2**53+2)))))) === y), Math.fround(y))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-116066984*/count=878; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((Int16ArrayView[2])))|0;\n  }\n  return f; })(this, {ff: Promise.race}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=879; tryItOut("/*RXUB*/var r = /(?!(?=(?!(?:(?=^))+?)).|\\b{0}{3,}|\\D{2,}{0,3})/m; var s = (4277); print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=880; tryItOut("\"use strict\"; this.v1 = Object.prototype.isPrototypeOf.call(p1, g2);");
/*fuzzSeed-116066984*/count=881; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atan2(((Math.max((Math.fround(Math.log(2**53)) && Math.fround(y)), Math.pow(y, ( ! 0x100000001))) || Math.fround(Math.fround(mathy0(Math.fround(mathy0(((-0 | ( + Number.MAX_VALUE)) | 0), ( + y))), Math.fround((Math.fround((Math.pow(Math.fround(( + Math.hypot((Number.MAX_VALUE | 0), ( + y)))), Math.fround(0x0ffffffff)) < (( ~ ( + y)) >>> 0))) && (( + (( + y) / ( + mathy0((((y | 0) << x) | 0), 2**53+2)))) | 0))))))) >>> 0), Math.min(Math.fround(( - Math.fround(Math.imul(( + (-0x100000000 & Math.fround(Math.acosh(1.7976931348623157e308)))), Math.pow(x, Math.atan2(( + ( + (x >>> 0))), x)))))), Math.asin(x))); }); testMathyFunction(mathy1, [0x0ffffffff, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, -(2**53+2), -0x100000000, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 1, 0x100000000, 1.7976931348623157e308, 2**53+2, 0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53, Math.PI, -0, 2**53-2, Number.MAX_VALUE, -0x080000001, -0x100000001, 1/0, 0x080000000, 0, 0/0, -0x080000000, 0x080000001]); ");
/*fuzzSeed-116066984*/count=882; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-116066984*/count=883; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.min(Math.atan2((( ! -0x080000001) % ((Math.fround(y) === ( + mathy1(0/0, x))) >>> 0)), ( + ((( ~ y) >>> 0) - Math.fround(mathy0(Math.fround((( - (x | 0)) | 0)), ((( + -Number.MIN_VALUE) ? ( + -Number.MIN_VALUE) : y) >>> 0)))))), Math.sin(Math.atan2(Math.fround(y), (x | Math.expm1(Math.fround(mathy1(( + Math.expm1(Math.fround(Number.MIN_VALUE))), Math.fround(x)))))))); }); ");
/*fuzzSeed-116066984*/count=884; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = ((((-0x8000000) ? (+pow(((((+atan2(((-8589934592.0)), ((6.189700196426902e+26))))) / ((+(0.0/0.0))))), ((d0)))) : (+(-1.0/0.0)))) % ((d1)));\n    d1 = (d0);\n    {\n      d1 = (+((((abs((imul((!(0xfed57437)), ((((0xa9fff702))>>>((0xfc0128c6))) <= (0x3c445dc3)))|0))|0))-(((-0x44ffc94) ? (0xe9fcebc4) : (0xffffffff)) ? (0x82d927a6) : (-0x8000000)))>>>(((((0xf9b438e8)-(0xde30d351)) | ((0xa3d14b15)))))));\n    }\n    return +((-2305843009213694000.0));\n  }\n  return f; })(this, {ff: timeout(1800)}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [2**53+2, -Number.MIN_VALUE, -0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 0/0, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53), 0, Math.PI, 2**53-2, -(2**53+2), -1/0, -0, Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, 1/0, 0x0ffffffff, -0x07fffffff, 42, 0x080000001, 1, 1.7976931348623157e308, 2**53, -Number.MAX_VALUE, 0x100000001, -0x100000000, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=885; tryItOut("testMathyFunction(mathy2, [-(2**53-2), 42, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, Math.PI, 2**53-2, -1/0, -(2**53+2), -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000001, 1/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, 2**53, -0x100000000, 0x100000000, -0, 0x100000001, 0x080000001, 0x080000000, Number.MIN_VALUE, 0/0, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=886; tryItOut("\"use strict\"; e2.has((x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: String.prototype.substring, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: (new Function(\"m0.get(g0.v2);\")), fix: function() { throw 3; }, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: [1], set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: function() { throw 3; }, keys: undefined, }; })((4277)), decodeURI, x)).eval(\"a0 + '';\"));");
/*fuzzSeed-116066984*/count=887; tryItOut("function shapeyConstructor(zhddok){\"use strict\"; Object.freeze(this);if (zhddok) Object.defineProperty(this, \" \", ({get: (/*wrap1*/(function(){ v2 = (m2 instanceof t2);return neuter})()).bind(), set: Function, configurable: (x % 4 != 1)}));if (zhddok) Object.defineProperty(this, \"valueOf\", ({}));this[\"valueOf\"] = new String('');if (new RegExp(\"\\\\b\", \"gy\")) Object.defineProperty(this, \"log1p\", ({get: function  zhddok (b) { \"use strict\"; return \"\\u5406\" } , set: /*MARR*/[(1/0), (1/0), 0.000000000000001, 0.000000000000001, 0.000000000000001, (1/0), 0.000000000000001, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), 0.000000000000001, x, x, 0.000000000000001, 0.000000000000001, x, x, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, (1/0), 0.000000000000001, (1/0), 0.000000000000001, (1/0), 0.000000000000001, 0.000000000000001, (1/0), x, 0.000000000000001, (1/0), (1/0), 0.000000000000001, x, x, 0.000000000000001, x, (1/0), 0.000000000000001, 0.000000000000001, x, x, x, 0.000000000000001, 0.000000000000001, 0.000000000000001, x, (1/0), 0.000000000000001, 0.000000000000001, x, (1/0), (1/0), 0.000000000000001, x, (1/0), (1/0), 0.000000000000001, x, (1/0), 0.000000000000001, x, x, 0.000000000000001, 0.000000000000001, 0.000000000000001, (1/0), x, 0.000000000000001, (1/0), 0.000000000000001, x, x, (1/0), 0.000000000000001, (1/0), x, 0.000000000000001, x, x, x, x, x, x, (1/0), 0.000000000000001, (1/0), x, x, (1/0), (1/0), (1/0), x, (1/0), 0.000000000000001, 0.000000000000001, (1/0), 0.000000000000001, x, 0.000000000000001, x, (1/0)].some(zhddok--.isSafeInteger)(), enumerable: (zhddok % 3 != 0)}));return this; }/*tLoopC*/for (let z of q => q) { try{let yjfqkq = new shapeyConstructor(z); print('EETT'); /*RXUB*/var r = /((?!(?:\\1))(?=\u00ee|\\s{1,}|$+?{2}){1,})|\\b\\2(?=\\\u00e8)+|\\W(?=\\v{2,5}){1,}/ym; var s = \"\\ud172\\ud172\\ud172\\ud172\\ud172\\ud172\\ud172\\ud172\"; print(r.test(s)); }catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-116066984*/count=888; tryItOut("\"use strict\"; with((uneval(/[^]/yim))){s0 += 'x';function x(NaN, x = /*RXUE*/z = x.exec(\"\"), x, NaN, NaN, y, x, a = new RegExp(\"[]|.[^\\\\cK-x\\\\cO-\\\\u89F7\\\\u00Ef\\\\u0077-\\\\0]{0}|\\u008b*+?[]|(?:[\\\\W\\\\S\\\\0\\\\r-\\\\uc6aC])?\", \"y\"),  , true, x, getter, x, eval, w, w, x, window, eval, x, eval, x, this, x, \"289305420.5\", eval, \u3056, w, x, y, w = false, d = false, d = true, w =  /x/ , z, -27, e, ;, x, x, \u3056, c, x, x, d, b = c, b, x, z, c = 4, set, z, \u3056 = 20, w, x, y, x, x, c, x, z = -4, a, b = 12, y, x, d, x, x, yield, \u3056, x, x, x, window, a, x, x, z = 26, x, x, NaN) { /*\n*/return  ''  } print(z = \"\\u3FF0\"); }");
/*fuzzSeed-116066984*/count=889; tryItOut("\"use strict\"; print(x);\n '' ;\n");
/*fuzzSeed-116066984*/count=890; tryItOut("\"use strict\"; offThreadCompileScript;");
/*fuzzSeed-116066984*/count=891; tryItOut("\"use strict\"; o2 + '';");
/*fuzzSeed-116066984*/count=892; tryItOut("g0 = this;");
/*fuzzSeed-116066984*/count=893; tryItOut("mathy0 = (function(x, y) { return Math.max((( ! y) , (( + Math.log1p(( + ( + (x | 0))))) * (Math.atan2((( ! ((y === 0.000000000000001) | 0)) | 0), (Math.hypot(x, ( ! 2**53-2)) >>> 0)) >>> 0))), (Math.fround(((-(2**53-2) && ( ~ x)) << Math.fround(Math.max(-Number.MIN_SAFE_INTEGER, (Math.log1p(Math.fround(( + (( ~ (42 >>> 0)) >>> 0)))) >>> 0))))) < (Math.atan2((( - x) | 0), (Math.atan2(Math.fround(0/0), y) | Math.atan2(( - y), y))) - (((x <= x) <= y) >>> 0)))); }); testMathyFunction(mathy0, [/0/, ({valueOf:function(){return '0';}}), 1, 0, '/0/', ({toString:function(){return '0';}}), (new Number(-0)), objectEmulatingUndefined(), null, (new Boolean(false)), '\\0', (new Number(0)), (function(){return 0;}), '', false, '0', (new Boolean(true)), ({valueOf:function(){return 0;}}), 0.1, -0, undefined, true, [0], [], NaN, (new String(''))]); ");
/*fuzzSeed-116066984*/count=894; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.trunc(Math.min((( + Math.atan2((( - Math.pow(y, x)) | 0), ( + x))) | 0), (Math.asin(y) | 0)))); }); ");
/*fuzzSeed-116066984*/count=895; tryItOut("\"use strict\"; if(false) {return;print(x); }");
/*fuzzSeed-116066984*/count=896; tryItOut("\"use strict\"; e1.__proto__ = o1;");
/*fuzzSeed-116066984*/count=897; tryItOut("mathy2 = (function(x, y) { return ( + ( + (( + ((y === ( + Math.hypot(Math.fround(Math.fround(Math.max(Math.fround(y), x))), ( + (( + Math.max(( + y), x)) >= ( + x)))))) >>> 0)) ** (((( ~ (y >>> 0)) | 0) % (Math.min((x >>> 0), Number.MAX_VALUE) >>> 0)) ** (Math.imul((y | 0), ((Math.clz32(((x !== Math.fround(y)) | 0)) | 0) | 0)) | 0))))); }); testMathyFunction(mathy2, ['\\0', '', 1, (new String('')), [], objectEmulatingUndefined(), -0, '0', undefined, '/0/', ({toString:function(){return '0';}}), false, (new Boolean(true)), ({valueOf:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return 0;}}), 0.1, (new Number(-0)), null, /0/, (new Number(0)), NaN, (new Boolean(false)), 0, [0], true]); ");
/*fuzzSeed-116066984*/count=898; tryItOut("i1.next();");
/*fuzzSeed-116066984*/count=899; tryItOut("Array.prototype.forEach.apply(o0.g0.a2, [(function() { try { v0 = o1.a2.reduce, reduceRight((function() { try { m0.has(b1); } catch(e0) { } try { this.e2 = new Set(m2); } catch(e1) { } try { /*RXUB*/var r = r0; var s = \"j\\n\\n\\n\\n\\n\\n\\n\\na\\njjjjjj\\ufff3\\n\\n\\n\\u00bd\\u00bd\\ufff3\\n\\n\\n\\u00bd\\u00bd\\ufff3\\n\\n\\n\\u00bd\\u00bd\\ufff3\\n\\n\\n\\u00bd\\u00bd\\ufff3\\n\\n\\n\\u00bd\\u00bd\\ufff3\\n\\n\\n\\u00bd\\u00bd\\ufff3\\n\\n\\n\\u00bd\\u00bd\\ufff3\\n\\n\\n\\u00bd\\u00bd\"; print(s.split(r));  } catch(e2) { } o2.v1 = evaluate(\"function f2(p2)  { let (\\u3056 = false, NaN, x, tzfvce, bdgjnx, b, rjgbqj, dqlnnx, qkxvhx, b) { (\\\"\\\\uCF4A\\\"); } } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: (x % 78 != 76), sourceIsLazy: false, catchTermination: false, element: o1, elementAttributeName: s1, sourceMapURL: s2 })); return a2; })); } catch(e0) { } i1.send(o1.o1.a1); return m2; }), v1]);");
/*fuzzSeed-116066984*/count=900; tryItOut("/*RXUB*/var r = /\\2/gim; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=901; tryItOut("s2 += 'x';");
/*fuzzSeed-116066984*/count=902; tryItOut("\"use strict\"; var a =  /x/g , d, eval = /*MARR*/[{x:3}, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), x, x, x, x, x, new String(''), x, new String(''), new String(''), {x:3}, x, x, x, x, {x:3}, new String(''), new String(''), new String(''), x, {x:3}, x, new String(''), new String(''), new String(''), x, {x:3}, x, new String(''), x, x], mwfbwq, [] = window, ksbpih, e = (Math.acos(11)), eval, senuhh, wpnjlh;v0 = evalcx(\"\\\"use strict\\\"; testMathyFunction(mathy0, [Number.MAX_VALUE, 0.000000000000001, -0x100000000, -0, 42, 0x100000001, 0x0ffffffff, 0x080000001, -0x100000001, 0, -0x080000001, Number.MIN_VALUE, 2**53-2, -0x0ffffffff, 2**53, -(2**53-2), 1/0, -Number.MIN_VALUE, -(2**53), 0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, 1, 0/0, Number.MAX_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, -0x07fffffff, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0]); \", g2);");
/*fuzzSeed-116066984*/count=903; tryItOut("\"use strict\"; L:with({d: new (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function(name) { return delete x[name]; }, fix: function() { throw 3; }, has: neuter, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: Function, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { throw 3; }, }; })(z.unwatch(\"toSource\"))})print(d);");
/*fuzzSeed-116066984*/count=904; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.exp((Math.min(Math.fround(Math.max(Math.fround((Math.pow(-1/0, x) | 0)), Math.fround(Math.fround(Math.min(Math.fround(( ! Math.fround(x))), -(2**53)))))), Math.atan2(Math.fround(y), y)) | Math.sinh(0x100000001))); }); testMathyFunction(mathy3, [-(2**53), 1, -(2**53+2), 0x0ffffffff, 0x080000001, -0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -0x100000001, -Number.MIN_VALUE, 2**53-2, 0/0, -(2**53-2), 0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 42, -1/0, -0, 1/0, 2**53+2, -0x080000000, -0x07fffffff, 0x080000000, Math.PI, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=905; tryItOut("Array.prototype.pop.call(a2, g1, b0);");
/*fuzzSeed-116066984*/count=906; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ! ( + mathy0((( + mathy0(( + y), ( + Math.fround(( ~ Math.fround(Math.fround(Math.atan2(Math.fround(-0x100000000), Math.fround(y))))))))) <= ( + Number.MIN_SAFE_INTEGER)), (((Math.fround(Math.fround(Math.max(Math.fround(( + ( - ( + x)))), Math.fround(-0x0ffffffff)))) == Math.fround(x)) >>> 0) , ( + (Math.hypot(( + Math.log1p(( + x))), x) | 0)))))); }); ");
/*fuzzSeed-116066984*/count=907; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=908; tryItOut("\"use strict\"; f0.toString = (function mcc_() { var ufvbyn = 0; return function() { ++ufvbyn; if (/*ICCD*/ufvbyn % 10 == 8) { dumpln('hit!'); v2 = evaluate(\"(function ([y]) { })()\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (yield x), noScriptRval: false, sourceIsLazy: --x, catchTermination: true })); } else { dumpln('miss!'); try { v0 = g2.eval(\"const z = Int8Array();(window)\\n(x);\"); } catch(e0) { } try { e2.add(t0); } catch(e1) { } try { v1 = evaluate(\"(/(?!$|\\u008c+?)*|(?=(?=\\\\uBd67)*)/yi);function x() { \\\"use strict\\\"; yield  /x/g  } print(x);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 6 == 2), sourceIsLazy: false, catchTermination: x, element: o1, sourceMapURL: g1.s2 })); } catch(e2) { } v1 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: ((p={}, (p.z = x)())), catchTermination: false })); } };})();");
/*fuzzSeed-116066984*/count=909; tryItOut("\"use strict\"; yield null;");
/*fuzzSeed-116066984*/count=910; tryItOut("\"use strict\"; /*vLoop*/for (let wemmap = 0; wemmap < 90 && ( /x/ .keyFor((void options('strict')), [z1,,])); ++wemmap) { b = wemmap; a0.splice(7, \"\\u80C0\", o2); } ");
/*fuzzSeed-116066984*/count=911; tryItOut("let (e) { throw z % a; }");
/*fuzzSeed-116066984*/count=912; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return ( + Math.atan2(Math.expm1(( ! 1.7976931348623157e308)), ( ! ( + ( + (x | 0)))))); }); ");
/*fuzzSeed-116066984*/count=913; tryItOut("t2 = t1.subarray(5, x);");
/*fuzzSeed-116066984*/count=914; tryItOut("testMathyFunction(mathy3, [-0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 0, -Number.MIN_VALUE, -(2**53+2), 1/0, 0x100000000, Math.PI, 0.000000000000001, Number.MIN_VALUE, 0x07fffffff, -0x100000001, 1.7976931348623157e308, 0x0ffffffff, -0x080000000, 42, 0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), 2**53-2, 0x100000001, -1/0, 0x080000001, Number.MAX_VALUE, 1, 2**53, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-116066984*/count=915; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.pow((((Math.min(x, Math.cosh(Math.fround(x))) << (( + (mathy1(1, (2**53 | 0)) >>> 0)) | 0)) <= Math.fround(Math.asinh(( + ((Math.log((y >>> 0)) >>> 0) >= (( + (( + x) ? ( + (((x | 0) == (x | 0)) | 0)) : ( + x))) | 0)))))) | 0), Math.fround(( ~ Math.fround((Math.ceil((( + (( + Math.min(Math.fround(x), Math.fround(((2**53+2 ? x : y) * ( + mathy3(( + 0x07fffffff), 0/0)))))) | 0)) | 0)) | 0))))); }); testMathyFunction(mathy4, /*MARR*/[undefined, undefined, ((void options('strict_mode'))), new Boolean(true), new Boolean(true), undefined, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, new Boolean(true), ((void options('strict_mode'))), new Boolean(true), ((void options('strict_mode'))), new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(true), ((void options('strict_mode'))), -Number.MAX_SAFE_INTEGER, ((void options('strict_mode'))), new Boolean(true), new Boolean(false), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, new Boolean(true), undefined, -Number.MAX_SAFE_INTEGER, ((void options('strict_mode'))), ((void options('strict_mode'))), -Number.MAX_SAFE_INTEGER, new Boolean(false), undefined, -Number.MAX_SAFE_INTEGER, undefined, new Boolean(true), new Boolean(true), ((void options('strict_mode'))), ((void options('strict_mode'))), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, ((void options('strict_mode'))), undefined, new Boolean(true), undefined, new Boolean(false), new Boolean(true), undefined, new Boolean(false), -Number.MAX_SAFE_INTEGER, new Boolean(true), ((void options('strict_mode'))), -Number.MAX_SAFE_INTEGER, ((void options('strict_mode'))), new Boolean(true), new Boolean(false), ((void options('strict_mode'))), undefined, undefined, ((void options('strict_mode'))), new Boolean(false), -Number.MAX_SAFE_INTEGER, new Boolean(false), undefined, new Boolean(true), ((void options('strict_mode'))), undefined, -Number.MAX_SAFE_INTEGER, new Boolean(false), -Number.MAX_SAFE_INTEGER, undefined, new Boolean(false), undefined, ((void options('strict_mode'))), new Boolean(false), -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, new Boolean(false), new Boolean(true), undefined, new Boolean(true), ((void options('strict_mode'))), undefined, new Boolean(false), -Number.MAX_SAFE_INTEGER, new Boolean(false), new Boolean(true), undefined, new Boolean(false), ((void options('strict_mode'))), ((void options('strict_mode'))), new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-116066984*/count=916; tryItOut("for (var v of o1) { v2 = o2.b0.byteLength; }");
/*fuzzSeed-116066984*/count=917; tryItOut("\"use strict\"; o2.o2 = t1[(4277)];");
/*fuzzSeed-116066984*/count=918; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + ( ~ ( ! ((Math.imul((y >> x), x) * y) | 0)))); }); testMathyFunction(mathy2, [-1/0, 2**53+2, 2**53-2, 0x07fffffff, 0x100000001, 0x100000000, -(2**53), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), Math.PI, -0, -0x080000001, 42, 0x0ffffffff, Number.MIN_VALUE, 1, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 2**53, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0, Number.MAX_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, 1.7976931348623157e308, 1/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=919; tryItOut("print((x |= z));");
/*fuzzSeed-116066984*/count=920; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(mathy1(((Math.fround(( ~ Math.fround((y >> mathy1(( + (( + Math.fround(( ~ y))) << (x | 0))), (Math.imul(( + x), ( + 2**53)) | 0)))))) && ((Math.fround(x) && Math.fround(( - ( + Math.log10(x))))) ? ( + (( + Math.sqrt(x)) === ( + (Math.imul(y, (y | 0)) | 0)))) : Math.fround(( + Math.atan2(( ~ -0x100000000), x))))) >>> 0), (( + (( - ( + (( + 1) <= ( + x)))) + Math.fround((((x >>> 0) ^ (Math.max(Math.fround(Math.trunc(Math.fround(x))), ( + ( + Math.imul(( + x), ( + y))))) >>> 0)) >>> 0)))) >>> 0))); }); testMathyFunction(mathy4, /*MARR*/[]); ");
/*fuzzSeed-116066984*/count=921; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return (Math.min((Math.max((((Math.cos((y | 0)) | 0) << Math.fround(Math.imul(( + ( ! ( + Math.PI))), y))) | 0), (( + x) >>> 0)) | 0), (( + ((Math.acosh(Math.tanh(( + y))) >>> 0) ? ( + Math.fround(mathy0(Math.log2(Math.min(( + ( - ( + ( + ( ! ( + x)))))), x)), Math.fround(Math.atan2(Math.fround(x), ((( + -0x080000000) >>> 0) >>> 0)))))) : (Math.asinh(y) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, ['', '0', [], (new Boolean(true)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), 1, NaN, (new Number(-0)), false, /0/, '\\0', ({toString:function(){return '0';}}), 0.1, (new Number(0)), -0, (new String('')), true, 0, undefined, null, '/0/', [0], (function(){return 0;}), (new Boolean(false)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-116066984*/count=922; tryItOut("v1 = g2.eval(\"for (var v of g0) { try { a0.shift(e2, h2); } catch(e0) { } /*RXUB*/var r = r2; var s = \\\"\\\\n\\\\n\\\"; print(uneval(r.exec(s))); print(r.lastIndex);  }\");");
/*fuzzSeed-116066984*/count=923; tryItOut("\"use strict\"; for(var e = ((function too_much_recursion(pwkfvk) { ; if (pwkfvk > 0) { ; too_much_recursion(pwkfvk - 1);  } else {  }  })(3)) in  \"\" ) f1 + i2;");
/*fuzzSeed-116066984*/count=924; tryItOut("\"use strict\"; v2 = g1.runOffThreadScript();");
/*fuzzSeed-116066984*/count=925; tryItOut("o0.m2.set(e1, o2);");
/*fuzzSeed-116066984*/count=926; tryItOut("testMathyFunction(mathy0, [0x100000000, -(2**53+2), 2**53+2, 0x080000001, -0x080000000, 0x07fffffff, -0x100000000, -0x100000001, 1/0, 0x080000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 0/0, -(2**53), -0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53, 42, 0x100000001, Math.PI, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, Number.MAX_VALUE, -0x07fffffff, 2**53-2, -1/0, 1]); ");
/*fuzzSeed-116066984*/count=927; tryItOut("\"use strict\"; v1 = (o1 instanceof s2);");
/*fuzzSeed-116066984*/count=928; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (mathy1(( + 1), Math.hypot(( + ( ~ (Math.imul(Math.fround(y), Math.fround(( + Math.asin(( + -0x0ffffffff))))) >>> 0))), (( - Math.expm1(y)) >>> 0))) ** (Math.pow((Math.sign(y) | 0), (Math.max((((Math.fround(( + 0x100000000)) !== (( + mathy1(( + y), ( + y))) | 0)) | 0) >>> 0), (Math.fround(( - (x | 0))) | 0)) | 0)) | 0)); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 2**53-2, 0, -0x080000000, -0x100000001, 0/0, 0.000000000000001, -0x100000000, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, -1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, 2**53, 1/0, Number.MIN_VALUE, 0x080000001, 0x100000001, -(2**53), Number.MAX_VALUE, -(2**53-2), -0, -0x080000001, 0x100000000, 42, -Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-116066984*/count=929; tryItOut("L/*\n*/:if(false) print((4277)); else  if (\"\\u3FD3\") {( /x/g );v1 = (p1 instanceof h2); }");
/*fuzzSeed-116066984*/count=930; tryItOut("throw z;\u0009this.zzz.zzz;");
/*fuzzSeed-116066984*/count=931; tryItOut("\"use strict\"; b2 + b0;");
/*fuzzSeed-116066984*/count=932; tryItOut("try { with({}) with({}) { return; }  } catch(d) { with({}) { for(let c in []); }  } finally { d = window; } ");
/*fuzzSeed-116066984*/count=933; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=934; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h0, o1);\na2.push(b0, f1, this.s2, f0);\n");
/*fuzzSeed-116066984*/count=935; tryItOut("\"use strict\"; (((uneval(window))));");
/*fuzzSeed-116066984*/count=936; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((0x65edb2b2)))|0;\n  }\n  return f; })(this, {ff: (new Function(\"/* no regression tests found */\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [2**53, -0x080000001, 2**53+2, -(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 0x080000001, 0x080000000, -0x0ffffffff, -1/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, 1/0, -(2**53+2), 0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, -0, Number.MAX_VALUE, 42, -0x100000001, -(2**53), 1, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, 2**53-2]); ");
/*fuzzSeed-116066984*/count=937; tryItOut("\"use strict\"; this.v2 = (a1 instanceof s2);");
/*fuzzSeed-116066984*/count=938; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(((Math.pow(y, (( ! mathy3(y, -0x080000000)) | 0)) << Math.fround((( + Math.imul(1.7976931348623157e308, (Math.pow(( + ( + (Math.fround(-Number.MAX_VALUE) >> x))), ( + y)) | 0))) / (-0x100000000 - Math.fround((-0x0ffffffff ? Math.asin(( ! y)) : x)))))) >>> ( - (( ! Math.fround((( ~ ( + y)) | 0))) | 0)))); }); testMathyFunction(mathy4, /*MARR*/[-0x5a827999, new Boolean(false), -Infinity, -Infinity, -Infinity, new Boolean(false), -Infinity, new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, -0x5a827999, new Boolean(false), new Boolean(false), -0x5a827999, -0x5a827999, new Boolean(false), -Infinity, -Infinity, -0x5a827999]); ");
/*fuzzSeed-116066984*/count=939; tryItOut("mathy2 = (function(x, y) { return mathy1(( + (Math.fround(Math.atan2((Math.fround(Math.max(0/0, Math.fround(y))) | 0), x)) > Math.fround(( + ( ! (y | 0)))))), ((((Math.cbrt((( + Math.hypot(( + Number.MAX_VALUE), ( + x))) >>> 0)) >>> 0) >>> 0) <= (Math.fround(Math.imul(Math.fround((( + ( + (Math.min(y, (((x | 0) ** (Math.pow(x, -0x07fffffff) >>> 0)) >>> 0)) | 0))) >>> 0)), x)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=940; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.imul((Math.asinh((Math.fround(Math.acosh(Math.fround((Math.max((x >>> 0), (x >>> 0)) >>> 0)))) | 0)) === Math.asinh((((Math.fround(y) || x) | 0) | Math.fround(x)))), Math.fround(Math.atan2((( + y) >>> 0), Math.clz32(Math.fround(x))))); }); ");
/*fuzzSeed-116066984*/count=941; tryItOut("f0 + '';");
/*fuzzSeed-116066984*/count=942; tryItOut("\"use strict\"; \"use asm\"; o0.p0 + this.f1;");
/*fuzzSeed-116066984*/count=943; tryItOut("\"use strict\"; a0 = new Array;");
/*fuzzSeed-116066984*/count=944; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.asinh((( + (( ! (Math.acos((((x | 0) < (Math.asin(-0x080000000) | 0)) | 0)) % 0)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x0ffffffff, 0x080000001, 0x100000001, 0x080000000, 0x07fffffff, -(2**53), 1.7976931348623157e308, -0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 2**53, 0.000000000000001, 1, -0x07fffffff, 0x100000000, 1/0, -0, Number.MIN_VALUE, 42, 0/0, 0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, -(2**53+2), Math.PI, -0x0ffffffff, 2**53-2, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-116066984*/count=945; tryItOut("( \"\" );");
/*fuzzSeed-116066984*/count=946; tryItOut("\"use strict\"; e1 = t1[x =  \"\" .yoyo((Math.pow(/*UUV1*/(y.setFloat64 = decodeURIComponent), 26)))];");
/*fuzzSeed-116066984*/count=947; tryItOut("for(y in (new ((this(\"\\u5BD3\", (\"\\uE8AB\".eval(\"null\")))))())) {h2.getOwnPropertyNames = f1; }");
/*fuzzSeed-116066984*/count=948; tryItOut("\"use strict\"; i2.next();");
/*fuzzSeed-116066984*/count=949; tryItOut("testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -0, 0, -0x100000001, -1/0, Math.PI, 1, -(2**53), Number.MAX_SAFE_INTEGER, 2**53-2, 42, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53, 0x100000001, 0x080000001, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, -(2**53-2), -(2**53+2), Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 1/0, -0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=950; tryItOut("mathy5 = (function(x, y) { return ( + (( + ( + (Math.pow(( + (Math.cos(( + ( + (( ! x) | 0)))) | 0)), ((Math.pow(y, (Math.min(y, ((y >>> 0) ? -0x100000001 : (-Number.MIN_SAFE_INTEGER >>> 0))) | 0)) != x) >>> 0)) >>> Math.fround((Math.fround(x) ? Math.fround(x) : (Math.fround(( + Math.fround((Math.imul((Math.max(-Number.MIN_SAFE_INTEGER, y) >>> 0), (x >>> 0)) >>> 0)))) | 0)))))) <= ( + Math.log10(Math.fround((Math.fround(Math.atan(0x080000000)) & Math.fround((Math.cos(x) >>> 0)))))))); }); testMathyFunction(mathy5, ['/0/', [0], '0', undefined, NaN, 0.1, '', (new String('')), null, (new Boolean(false)), (new Boolean(true)), ({valueOf:function(){return '0';}}), true, false, (function(){return 0;}), -0, [], objectEmulatingUndefined(), (new Number(-0)), /0/, (new Number(0)), ({toString:function(){return '0';}}), 1, 0, '\\0', ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-116066984*/count=951; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return mathy0(Math.tanh(Math.min(Math.hypot(y, y), Math.fround(( + y)))), Math.atan2((Math.fround(Math.ceil(Math.fround(Math.expm1((Math.sqrt((Math.sinh(y) | 0)) | 0))))) * Math.sin((-Number.MAX_SAFE_INTEGER | 0))), (( + ( + ( + 1))) <= ((Math.fround(Math.fround(( ~ (y >>> 0)))) , y) >>> 0)))); }); testMathyFunction(mathy5, [-0x100000000, 0.000000000000001, 2**53+2, 0, 2**53-2, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, 0x0ffffffff, -(2**53+2), -(2**53-2), 42, 0x100000001, 1, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -(2**53), -0x080000000, -0x0ffffffff, 0x080000001, 2**53, 0x100000000, -0x07fffffff, 0x080000000, -0x100000001, Number.MIN_VALUE, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=952; tryItOut("L:if(false) {print( \"\" );v0 = evaluate(\"\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: this, element: o0, elementAttributeName: s1, sourceMapURL: s0 })); } else {m2.get(v1);/*MXX1*/o0 = g2.Map.prototype.get; }");
/*fuzzSeed-116066984*/count=953; tryItOut("\"use strict\"; g0.i2.send(b2);");
/*fuzzSeed-116066984*/count=954; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((( ! (Math.fround(mathy1(Math.fround(Math.atanh((x ? Math.min(x, Number.MAX_SAFE_INTEGER) : ((x | 0) >> x)))), Math.fround(Math.tanh(Math.pow(( + Math.fround(((((y | 0) < ( + x)) >>> 0) != Math.PI))), y))))) >>> 0)) >>> 0) & ( + (mathy1(y, (( + Math.fround(( + y))) < ( ~ x))) ^ ( - 0x100000001)))); }); testMathyFunction(mathy4, ['', undefined, (new Boolean(false)), '\\0', -0, (new Number(0)), ({toString:function(){return '0';}}), true, false, [], (new Boolean(true)), '/0/', [0], /0/, ({valueOf:function(){return 0;}}), '0', 0, objectEmulatingUndefined(), null, (new Number(-0)), ({valueOf:function(){return '0';}}), (new String('')), NaN, 1, 0.1, (function(){return 0;})]); ");
/*fuzzSeed-116066984*/count=955; tryItOut("\"use asm\"; const x = new  /x/ (), x = \"\\u88B6\";const z = \"\\u9223\";print(\"\\uD721\");");
/*fuzzSeed-116066984*/count=956; tryItOut("{ void 0; void relazifyFunctions('compartment'); }");
/*fuzzSeed-116066984*/count=957; tryItOut("var fobwzz = new SharedArrayBuffer(0); var fobwzz_0 = new Uint8ClampedArray(fobwzz); print(fobwzz_0[4]);");
/*fuzzSeed-116066984*/count=958; tryItOut("\"use strict\"; var uicwgy = new ArrayBuffer(4); var uicwgy_0 = new Float64Array(uicwgy); var uicwgy_1 = new Float32Array(uicwgy); uicwgy_1[0] = -0; var uicwgy_2 = new Int16Array(uicwgy); uicwgy_2[0] = -4; var uicwgy_3 = new Float64Array(uicwgy); print(uicwgy_3[0]); uicwgy_3[0] = 14; var uicwgy_4 = new Uint8ClampedArray(uicwgy); print(uicwgy_4[0]); var uicwgy_5 = new Float32Array(uicwgy); print(uicwgy_5[0]); uicwgy_5[0] = 9; var uicwgy_6 = new Float32Array(uicwgy); uicwgy_6[0] = 8; var uicwgy_7 = new Int32Array(uicwgy); uicwgy_7[0] = -8; var uicwgy_8 = new Uint8Array(uicwgy); print(uicwgy_8[0]); /*MXX1*/Object.defineProperty(this, \"o1\", { configurable: false, enumerable: false,  get: function() {  return this.g2.RegExp.prototype.exec; } });yield;return;Array.prototype.reverse.call(a2, g1.o0, s1, o0, this.b1);this.g1.v1 = Object.prototype.isPrototypeOf.call(v0, i0);(void schedulegc(g1));\"\u03a0\" \"\" ;m1.get(v0);(undefined);");
/*fuzzSeed-116066984*/count=959; tryItOut("m2.delete(t2);");
/*fuzzSeed-116066984*/count=960; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max(( + ( + ((x | 0) >>> (( + x) | 0)))), Math.fround(( ~ Math.fround(Math.fround(( + Math.fround(( + Math.max(( + (Math.imul((Number.MIN_VALUE >>> 0), (x >>> 0)) >>> 0)), ( + y)))))))))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -(2**53-2), 42, 1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 0x080000001, -1/0, 0x100000001, 1, -(2**53), Number.MIN_VALUE, 2**53+2, 0x07fffffff, -0x080000000, -0x07fffffff, -0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, 0x100000000, -0, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, Number.MAX_VALUE, 2**53, 0, -0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-116066984*/count=961; tryItOut("/*ADP-3*/Object.defineProperty(this.a2, 6, { configurable: ((this.isExtensible(\"\\uE15B\"))([z1,,].valueOf(\"number\"))).__defineSetter__(\"NaN\", Date.prototype.setSeconds), enumerable: ((function(x, y) { \"use strict\"; return ((((Math.max(((Math.hypot((Math.acosh((((( + (( + (Math.min(1/0, y) >>> 0)) >>> 0)) >>> 0) % ( - x)) >>> 0)) | 0), ( + ( ~ ((x ? ( + Math.imul(( ~ ( + x)), 1)) : x) | 0)))) | 0) | 0), Math.hypot(Math.min(Math.sign(x), ( + ( ! ( + (Math.asinh((Math.max((Math.imul(Math.fround(( + y)), -0x080000001) | 0), (Math.min(y, Math.fround((((y | 0) << (x | 0)) | 0))) | 0)) >>> 0)) >>> 0))))), (((y * Math.fround(y)) ? ((y ? (( + (( + x) ? x : ( + ( - (Math.atan2(( + y), ( + -Number.MAX_VALUE)) | 0))))) >>> 0) : Math.fround(( - ( + Number.MAX_SAFE_INTEGER)))) >>> 0) : ( + Math.fround(Math.trunc((1.7976931348623157e308 | 0))))) - ( + ( + ( + Math.log2(x))))))) | 0) >>> 0) ? ( ~ Math.fround(Math.asinh(Math.fround((Math.max((Math.atan2(Math.fround(-0x0ffffffff), Math.fround(x)) | (Math.fround(Math.log1p(x)) ? ((( ~ x) >>> 0) !== x) : ( ! x))), Math.trunc(y)) | (Math.min((Math.cos((y < 2**53)) | 0), (-Number.MAX_SAFE_INTEGER | 0)) | 0)))))) : ((((Math.imul(((Math.hypot(x, 0x080000001) , Math.acos(( + Math.atan2((( + Math.cos(Math.fround(-0x080000001))) | 0), (-Number.MAX_SAFE_INTEGER | 0))))) >>> 0), ((Math.fround((( - -0x100000000) >>> 0)) ? Math.fround(Math.atan2(( + ( ! (Math.fround(x) ? ( + ( + Math.max((y | 0), (x | 0)))) : y))), ( + (( ~ (( ~ x) >>> 0)) >>> 0)))) : Math.fround((Math.clz32(( ~ Math.pow(y, y))) === (Math.atan2(y, Math.acos(y)) | 0)))) >>> 0)) >>> 0) | 0) / ((( + Math.min((Math.acosh(x) | 0), ( + ( - (x ? Math.fround(( + (Math.clz32(-Number.MIN_SAFE_INTEGER) | 0))) : y))))) , ( + Math.atan2((( + Math.pow(y, y)) / 0x080000000), ( ~ ( ! Math.fround(x)))))) | 0)) | 0)) >> Math.cos((( ! (( + ( - (( + (((Math.asin((x >>> 0)) >>> 0) <= Math.sign((Math.max((x | 0), ((Math.asin((y >>> 0)) >>> 0) | 0)) | 0))) | 0)) | 0))) >>> 0)) >>> 0))); }).prototype), writable: (x % 2 != 0), value: t0 });");
/*fuzzSeed-116066984*/count=962; tryItOut("v0 = this.a0.every(Uint16Array);");
/*fuzzSeed-116066984*/count=963; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=964; tryItOut("\"use strict\"; e0 = new Set;");
/*fuzzSeed-116066984*/count=965; tryItOut("var \u000czdwfuu, muwmwl, \u3056 = ((function ([y]) { }.eval(\"(-5);\"))++), a = x = Proxy.createFunction(({/*TOODEEP*/})(\"\\uE2DE\"), function(y) { \"use strict\"; yield y; -29;; yield y; }), x, ubsyao, e = ((void options('strict'))), vybxla, ymrhnw, x = window;Object.prototype.watch.call(b1, \"toSource\", f1);");
/*fuzzSeed-116066984*/count=966; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(v1, p1);");
/*fuzzSeed-116066984*/count=967; tryItOut("delete h2.getPropertyDescriptor;");
/*fuzzSeed-116066984*/count=968; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-116066984*/count=969; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=970; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return ( ~ ( + (( + ( ~ (( - (y | 0)) | 0))) ^ ( + ( ~ mathy0(Math.fround(( + Math.fround((( + (y | 0)) | 0)))), ( + mathy0(y, -0x100000001)))))))); }); testMathyFunction(mathy1, [-0x080000001, -Number.MAX_VALUE, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, -1/0, 1/0, -0, -Number.MIN_VALUE, 42, Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 0x100000001, 1, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000, 0x100000000, -(2**53), -(2**53+2), -0x0ffffffff, 0x07fffffff, -0x100000001, 2**53+2, 0, Number.MAX_VALUE, 2**53, 0x080000001, 0x080000000]); ");
/*fuzzSeed-116066984*/count=971; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.min(Math.sqrt((( ! (Math.sign(( + ( ! 0))) >>> 0)) | 0)), Math.fround(( ! (( - (Math.fround(( ~ Math.fround(y))) | 0)) | 0)))) >>> 0); }); testMathyFunction(mathy4, [2**53+2, 42, 0/0, 0x080000001, 1.7976931348623157e308, -0x100000000, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, 1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 0, -(2**53+2), -(2**53), 0x100000000, -1/0, 0x100000001, 2**53-2, 2**53, 0x0ffffffff, 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, -0x080000001, -0, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 0x07fffffff]); ");
/*fuzzSeed-116066984*/count=972; tryItOut("print(x);");
/*fuzzSeed-116066984*/count=973; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=974; tryItOut("\"use strict\"; this.o1.a2.forEach((function() { try { v1 = Object.prototype.isPrototypeOf.call(b0, o2.s1); } catch(e0) { } ; return o1; }), f2, o2);");
/*fuzzSeed-116066984*/count=975; tryItOut("\"use strict\"; for (var p in e1) { selectforgc(o2); }");
/*fuzzSeed-116066984*/count=976; tryItOut("a2[18] =  \"\" ;");
/*fuzzSeed-116066984*/count=977; tryItOut("a0 = arguments;print( /x/g );");
/*fuzzSeed-116066984*/count=978; tryItOut("o1.s2 = a1.join(s0, h0);\nprint(((void options('strict_mode'))));\n");
/*fuzzSeed-116066984*/count=979; tryItOut("{a1.unshift(v2); }");
/*fuzzSeed-116066984*/count=980; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.hypot(( - mathy0(( + mathy0(( + 1.7976931348623157e308), ( + mathy0(y, x)))), y)), Math.pow(( + ( - x)), (Math.tan(-0x07fffffff) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[0x080000000]); ");
/*fuzzSeed-116066984*/count=981; tryItOut("\"use strict\"; a2[17];");
/*fuzzSeed-116066984*/count=982; tryItOut("/*hhh*/function nxlret(){this.v0 = evaluate(\"o1.a0.pop();\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: ((0/0)), noScriptRval: this.zzz.zzz = (Math.acosh(((Math.fround(-Number.MIN_VALUE) ? (Math.sinh((x | 0)) >>> 0) : x) >>> 0)) >>> 0), sourceIsLazy: true, catchTermination: Math.log1p(/*UUV2*/(window.test = window.expm1)), element: o1, sourceMapURL: s0 }));}/*iii*/Array.prototype.pop.apply(a1, [e2]);");
/*fuzzSeed-116066984*/count=983; tryItOut("v0 = a2.reduce, reduceRight(Math.asin.bind(b1));function z(x, c, NaN = (4277).__defineGetter__(\"eval\", offThreadCompileScript), x, x, x, a, x, b = x, x = (4277), y, w = x, d = \"\\u7923\", x, window, x, x, x, eval, x, x, x =  /x/ , w = \"\u03a0\", \u3056, x, x, w, window, z, z, z, x = 8, e, x, y = 14, x, b, x, x, this.eval, d, e, d, x, x, x)\"use asm\";   var Infinity = stdlib.Infinity;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (-9.44473296573929e+21);\n    d1 = (((-147573952589676410000.0)) * ((+(1.0/0.0))));\n    i0 = (i0);\n    {\n      {\n        (Float32ArrayView[(-((((i0)-((4277)))>>>((0xfdc203a6)+(0xd5f49f8b)-(0x849947a7))))) >> 2]) = ((Infinity));\n      }\n    }\n    return +((-1048577.0));\n  }\n  return f;{ if (isAsmJSCompilationAvailable()) { void 0; setIonCheckGraphCoherency(false); } void 0; } g2.offThreadCompileScript(\"\\\"use strict\\\"; mathy3 = (function(x, y) { return ( - Math.tanh((( + Math.fround(Math.atan2(((y >>> 0) * (Math.clz32(y) >>> 0)), Math.min(Math.imul(( + Math.atanh(( + y))), 2**53), 2**53-2)))) | 0))); }); testMathyFunction(mathy3, [0x0ffffffff, 0x100000000, -0, 0/0, 0, 0x07fffffff, Number.MAX_VALUE, 0x100000001, 0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53+2), -0x100000001, 1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, 2**53-2, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -0x0ffffffff, Math.PI, 2**53+2, -1/0, -(2**53), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, 0.000000000000001, -0x080000001, 42, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000]); \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: y in e, noScriptRval: false, sourceIsLazy: [z1], catchTermination: (x % 6 == 5) }));");
/*fuzzSeed-116066984*/count=984; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot((Math.max((Math.min(( ! ( ! Math.expm1(( ! (-(2**53-2) | 0))))), Math.fround((( + ((Math.log1p(y) >>> 0) | 0)) | 0))) | 0), (( ! (Math.fround(Math.sign(y)) >>> 0)) | 0)) | 0), Math.cbrt((Math.acosh(Math.fround(Math.min(x, 0x0ffffffff))) | 0)))); }); testMathyFunction(mathy0, [-(2**53+2), -0, -(2**53), 0x100000000, 0x0ffffffff, Math.PI, 0, 1/0, -0x07fffffff, 0x07fffffff, -0x080000001, -0x100000000, 0x080000000, 1, -(2**53-2), -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000000, -Number.MAX_VALUE, 42, 2**53, 2**53-2, 0x080000001, Number.MIN_VALUE, -1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, 0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=985; tryItOut("\"use strict\"; print(uneval(g0));");
/*fuzzSeed-116066984*/count=986; tryItOut("h1 + o0;");
/*fuzzSeed-116066984*/count=987; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(( + Math.clz32(( + Math.atan2(( + Math.imul(x, (y | 0))), ( ~ y)))))) < (Math.cosh(x) >>> (y == ( + ( + ( - mathy0(-0x080000001, y))))))); }); ");
/*fuzzSeed-116066984*/count=988; tryItOut("i0.next();");
/*fuzzSeed-116066984*/count=989; tryItOut("\"use strict\"; m0.has(g2);");
/*fuzzSeed-116066984*/count=990; tryItOut("selectforgc(o2);const e = eval(\"/* no regression tests found */\");");
/*fuzzSeed-116066984*/count=991; tryItOut("v1 = Object.prototype.isPrototypeOf.call(b0, i1);");
/*fuzzSeed-116066984*/count=992; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( - (Math.hypot(( + Math.cos(-0)), (((0x080000000 << x) >>> Math.min(x, x)) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [[], [0], NaN, 0, (new Number(-0)), ({valueOf:function(){return 0;}}), '', (new Boolean(false)), (new Boolean(true)), '\\0', /0/, objectEmulatingUndefined(), false, null, ({valueOf:function(){return '0';}}), (new String('')), 0.1, '0', true, 1, ({toString:function(){return '0';}}), '/0/', undefined, -0, (function(){return 0;}), (new Number(0))]); ");
/*fuzzSeed-116066984*/count=993; tryItOut("\"use strict\"; /*vLoop*/for (lnzadn = 0; ((arguments.callee.arguments = yield x.watch(\"defineProperties\", decodeURIComponent))) && lnzadn < 21; ++lnzadn) { let c = lnzadn; t0 = o0.t1.subarray(10); } ");
/*fuzzSeed-116066984*/count=994; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116066984*/count=995; tryItOut("h2 + '';");
/*fuzzSeed-116066984*/count=996; tryItOut("/*RXUB*/var r = this.r2; var s = s1; print(r.test(s)); ");
/*fuzzSeed-116066984*/count=997; tryItOut("g2.a2 = Array.prototype.filter.apply(a1, [f1]);");
/*fuzzSeed-116066984*/count=998; tryItOut("\"use strict\"; v1 = g1.runOffThreadScript();");
/*fuzzSeed-116066984*/count=999; tryItOut("t1.__iterator__ = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { var r0 = 0 % a6; var r1 = a8 % 8; var r2 = a4 - a1; var r3 = a9 & a6; a3 = 4 & a11; a8 = r1 / a10; var r4 = a2 * a0; var r5 = 3 + a0; a7 = a2 ^ a1; print(r1); var r6 = a2 * 4; var r7 = 0 % a6; var r8 = 9 * a6; var r9 = 3 | r8; var r10 = a4 / a3; var r11 = a7 + r8; var r12 = r11 & a1; a2 = a8 - x; var r13 = a4 - r11; var r14 = r0 / 7; var r15 = r13 % r8; var r16 = r15 ^ r10; a0 = r16 * r15; var r17 = 0 - 8; var r18 = a11 % 4; var r19 = r2 | 3; var r20 = r10 * 7; var r21 = a8 | r4; var r22 = 4 * r1; var r23 = r4 - 0; r5 = a10 & r1; var r24 = a11 % r9; var r25 = r15 / r15; var r26 = a7 * 6; var r27 = r4 - r1; var r28 = 2 | a6; var r29 = a5 % a2; r6 = r1 & 5; var r30 = r7 ^ r22; var r31 = r22 ^ a10; var r32 = r30 / 3; var r33 = r15 + a7; var r34 = r23 | a8; var r35 = r0 * a5; var r36 = r9 * r34; var r37 = r21 / 0; var r38 = 6 | 4; var r39 = a10 - 0; var r40 = r0 * r36; var r41 = a4 / a6; print(r32); var r42 = r35 * a3; r7 = r5 % a8; var r43 = r9 - r5; var r44 = r16 / 6; var r45 = 1 | 3; a1 = r18 & r9; return a4; });");
/*fuzzSeed-116066984*/count=1000; tryItOut("/*iii*/i2 = new Iterator(h2, true);/*hhh*/function yzhnbc(\u3056, x){a = 21;h2 + '';}");
/*fuzzSeed-116066984*/count=1001; tryItOut("var blwfqe = new ArrayBuffer(2); var blwfqe_0 = new Uint32Array(blwfqe); print(blwfqe_0[0]); blwfqe_0[0] = -0.497; var blwfqe_1 = new Float32Array(blwfqe); blwfqe_1[0] = -6; print((eval(\"/* no regression tests found */\")));");
/*fuzzSeed-116066984*/count=1002; tryItOut("m2.delete(p2);return x;\n(new x( /x/ ));\n");
/*fuzzSeed-116066984*/count=1003; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a0, 14, { configurable: ((function\u0009 (x, window = ( /x/g .yoyo(x)), b, a, window, d, x, a, x = \"\\u0C24\", \u3056, eval, NaN, w, x, a, x =  \"\" , eval, \u3056 = false, NaN = \u3056, x, eval =  /x/ , x, e, NaN, x = /.\\3(?!\\B(.)(?=[^])){0,}|\\1/im, x, z, window, x, x =  \"\" , x, x, NaN, c = 5, eval, y, z, window, e, x, a, z, x, x, x, z, e, y, x, d, window =  /x/g , x, x, eval, x =  /x/ , window, NaN, d, x, e = a, x =  /x/g , x, y, d, x, x, a, a, e, e, x, x = /\\w(\\S(?:[^]*)){4}|(?:(?!\\b))/, x, window, x = \"\\u9BBE\", x, y) { return x = (yield length) } .prototype).watch(\"fontcolor\", function(q) { return q; }) ^= \u0009([] = x)), enumerable: (x % 16 == 6), writable: y, value: o2.a2 });");
/*fuzzSeed-116066984*/count=1004; tryItOut("/*MXX1*/this.o2.o1 = g0.String.prototype.toUpperCase;");
/*fuzzSeed-116066984*/count=1005; tryItOut("e1.has(g2);");
/*fuzzSeed-116066984*/count=1006; tryItOut("m1.__proto__ = v2;");
/*fuzzSeed-116066984*/count=1007; tryItOut("continue ;");
/*fuzzSeed-116066984*/count=1008; tryItOut("mathy3 = (function(x, y) { return ( ~ ((Math.fround(Math.max(( - (((-0x07fffffff >>> 0) >>> (x >>> 0)) >>> 0)), (( + Math.max(( + Math.trunc((( - (Number.MAX_SAFE_INTEGER | 0)) >>> 0))), Math.fround(x))) | 0))) >>> 0) >> Math.sqrt(1.7976931348623157e308))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, 1/0, -0x100000001, 0x07fffffff, 42, -0, -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, 2**53, -0x100000000, 1, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, 0, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, 0x0ffffffff, -(2**53+2), Math.PI, -(2**53-2), 1.7976931348623157e308, 0x100000000]); ");
/*fuzzSeed-116066984*/count=1009; tryItOut("mathy5 = (function(x, y) { return (Math.log(((Math.fround(( ~ Math.fround(y))) >>> Math.fround(Math.hypot(( + (Math.acosh(y) < ( ! Math.max(( + x), ( + y))))), Math.fround(y)))) | 0)) | 0); }); testMathyFunction(mathy5, [0.1, null, [0], (function(){return 0;}), (new Number(-0)), [], ({toString:function(){return '0';}}), '/0/', (new Boolean(true)), /0/, 1, '', false, '0', undefined, (new String('')), 0, true, NaN, objectEmulatingUndefined(), (new Boolean(false)), ({valueOf:function(){return '0';}}), '\\0', ({valueOf:function(){return 0;}}), (new Number(0)), -0]); ");
/*fuzzSeed-116066984*/count=1010; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.min(Math.fround((mathy1(( + ( + ( ! ( ! ( + Number.MAX_VALUE))))), ( + Math.pow(( ~ Math.fround(( ~ Math.fround(-(2**53-2))))), Math.fround(( ~ Math.hypot(Math.fround(x), Math.fround(y))))))) | 0)), mathy0(((( + (x >>> 0)) >>> 0) | 0), ( ! Math.fround(x))))); }); testMathyFunction(mathy2, [0, 0x080000001, -(2**53-2), -0x100000000, -Number.MAX_VALUE, 0x07fffffff, -0, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0, 2**53-2, -(2**53+2), -0x0ffffffff, -0x100000001, 0x0ffffffff, Number.MAX_VALUE, 0x100000000, 2**53, 1/0, 1.7976931348623157e308, 0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, -Number.MIN_VALUE, -0x080000000, 2**53+2, Math.PI, -0x080000001, Number.MIN_VALUE, 1]); ");
/*fuzzSeed-116066984*/count=1011; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    switch ((~~(((+exp(((-5.0))))) / ((+atan2(((-274877906945.0)), ((549755813889.0)))))))) {\n      default:\n        d0 = (-((+abs(((Float32ArrayView[((i1)-((0x3bf268e5) < (((i1))>>>((0xff991180))))) >> 2]))))));\n    }\n    return ((((0x54875c68))-((((0x0) % (0xffffffff)) ^ (-0x84f8e*(0xfede9b0c))))))|0;\n  }\n  return f; })(this, {ff: TypeError}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [true, undefined, (new Boolean(true)), [0], ({valueOf:function(){return '0';}}), (function(){return 0;}), 0.1, ({valueOf:function(){return 0;}}), '\\0', [], 0, '/0/', '', (new Boolean(false)), NaN, -0, /0/, ({toString:function(){return '0';}}), false, (new Number(-0)), objectEmulatingUndefined(), null, 1, (new String('')), '0', (new Number(0))]); ");
/*fuzzSeed-116066984*/count=1012; tryItOut("let (w) { {/*hhh*/function ucfzkw(){print(yield this);}ucfzkw(w); } }");
/*fuzzSeed-116066984*/count=1013; tryItOut("print((NaN = Proxy.create(({/*TOODEEP*/})(\"\\uB0D9\"), undefined)));o0 = o2.h0.__proto__;");
/*fuzzSeed-116066984*/count=1014; tryItOut("\"use strict\"; a0[({valueOf: function() { a2.push(m0, i0);return 3; }})] = e2;function x(/*\n*/NaN, x)\"use asm\";   var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    i4 = (i4);\n    {\n      return +((-((((((-(0x7c7f378a))|0)) ? ((((0xb5dc9aa8))>>>((0x78765ed9)))) : (i1)) ? (-17592186044416.0) : (-18014398509481984.0)))));\n    }\n    (Float64ArrayView[1]) = ((4398046511103.0));\n    return +((((i4)) << ((0x62e0ee72))));\n  }\n  return f;x = window;");
/*fuzzSeed-116066984*/count=1015; tryItOut("a0.unshift(t2);\nfor (var p in h1) { Array.prototype.forEach.apply(a2, [String.prototype.sup]); }\nfunction w(x, x) { /*tLoop*/for (let y of /*MARR*/[new Boolean(true), (void 0), x, x, new Boolean(true), (void 0), (void 0), (void 0), x, x, x, new Boolean(true), new Boolean(true), x, (void 0), (void 0), x, x, x, (void 0), x, (void 0), x, x, x, new Boolean(true), x, new Boolean(true), (void 0), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x, (void 0), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x, (void 0), (void 0), x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x, (void 0), new Boolean(true), (void 0)]) { ; } } this.i1.next();");
/*fuzzSeed-116066984*/count=1016; tryItOut("\"use strict\"; /*RXUB*/var r = /[^\\d]+?/g; var s = \"a\"; print(s.replace(r, '\\u0341', \"ym\")); let a = x;");
/*fuzzSeed-116066984*/count=1017; tryItOut("mathy4 = (function(x, y) { return mathy2(( + Math.fround(((Math.fround(Math.min(Math.fround(2**53+2), Math.fround(Math.fround(Math.min((y | 0), Math.fround(y)))))) >>> 0) ? (Math.fround((Math.fround(y) >> Math.fround((Math.fround(((y | 0) && (y | 0))) ? y : Math.acos(Math.imul(-Number.MAX_SAFE_INTEGER, (y || y))))))) | 0) : (Math.log2(y) | 0)))), (((Math.fround(( ~ (Math.max((Math.max(Math.fround(y), (y | 0)) | 0), ( + Math.pow(x, y))) >>> (y < x)))) >>> 0) < ((mathy3(y, ( + (( + y) != ( + Math.max(mathy2(Math.fround((Math.fround(x) ? Math.fround(y) : y)), y), -0x100000000))))) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 2**53-2, 0/0, -0, -(2**53+2), 42, -Number.MIN_VALUE, 1/0, -0x080000000, 1, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, Math.PI, 0x0ffffffff, -0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 2**53+2, -1/0, 0x100000001, -Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-116066984*/count=1018; tryItOut("\"use strict\"; /*infloop*/for(var c; length; undefined) a0.length = 7;");
/*fuzzSeed-116066984*/count=1019; tryItOut("/*RXUB*/var r = /(?!(?:(?=((?!$)))(?!(\\b)?)+?|[]{8}|${3,5}|[^\\u004E\u2f1b\u75a5\\cD-\u5499]{0,0}*?))/yim; var s = \"\"; print(s.replace(r, neuter, \"i\")); ");
/*fuzzSeed-116066984*/count=1020; tryItOut("mathy3 = (function(x, y) { return ( ! ( ~ (Math.log(y) , (( + (x << Number.MAX_VALUE)) ** ( + Math.acosh((x - -0x100000001))))))); }); testMathyFunction(mathy3, [-(2**53), -(2**53+2), -(2**53-2), 1.7976931348623157e308, 0x100000001, -0x0ffffffff, 2**53, 42, 0x100000000, -Number.MAX_VALUE, 0x07fffffff, Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, -0, 2**53+2, 0x080000000, -0x100000001, 0.000000000000001, 0, -0x100000000, Number.MAX_VALUE, -0x080000000, 0x0ffffffff, -0x080000001, 0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, -1/0, Number.MIN_SAFE_INTEGER, 2**53-2, 1, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1021; tryItOut("mathy4 = (function(x, y) { return Math.pow(Math.max(( ! (y & x)), (( ! (Math.imul(x, Math.acos(x)) >>> 0)) >>> 0)), Math.fround(Math.fround(Math.pow(Math.fround(mathy1(x, Math.hypot(1, Math.fround(Math.fround((( + (y >>> 0)) >>> 0)))))), Math.fround(( ! (mathy2(Math.hypot(x, (x - x)), (y !== x)) | 0))))))); }); testMathyFunction(mathy4, [0/0, 42, 1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -0x080000000, 0x080000000, -Number.MAX_VALUE, 2**53-2, 0x07fffffff, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, -0x080000001, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -0, 0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, -0x100000001, -(2**53), 1, Math.PI, 2**53, 0x080000001, -(2**53+2), -0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1022; tryItOut("\"use strict\"; t1[19] = this.o1.i2;");
/*fuzzSeed-116066984*/count=1023; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0.000000000000001, 0, -(2**53+2), Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, 0x100000000, 1/0, Math.PI, 2**53, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 2**53+2, -0x100000001, -0x100000000, -(2**53-2), 1, 0x080000000, -0x0ffffffff, 0/0, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), 2**53-2, -0x080000001]); ");
/*fuzzSeed-116066984*/count=1024; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.sinh((Math.sin((((Math.acos(Math.fround(( ! ( ! x)))) | 0) !== Math.fround(Math.log(Math.fround(( + Math.trunc(( + y))))))) | 0)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[0x07fffffff, new Number(1.5), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), new Number(1.5), new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false), new Boolean(false), 0x07fffffff, objectEmulatingUndefined(), new Number(1.5), 0x07fffffff, objectEmulatingUndefined(), new Boolean(false), 0x07fffffff, new Boolean(false), new Boolean(false), 0x07fffffff, new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), 0x07fffffff, objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false), 0x07fffffff, new Number(1.5), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x07fffffff, new Number(1.5), 0x07fffffff, new Number(1.5), new Number(1.5), 0x07fffffff, new Boolean(false), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x07fffffff, objectEmulatingUndefined(), new Number(1.5), 0x07fffffff, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), 0x07fffffff, new Number(1.5), objectEmulatingUndefined(), new Boolean(false), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), 0x07fffffff, new Number(1.5), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x07fffffff, new Boolean(false), new Number(1.5), new Number(1.5), 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, new Boolean(false), new Number(1.5), new Boolean(false), new Number(1.5), objectEmulatingUndefined(), 0x07fffffff, new Boolean(false), new Boolean(false), new Number(1.5), 0x07fffffff, new Number(1.5), 0x07fffffff, objectEmulatingUndefined(), 0x07fffffff, new Number(1.5), new Boolean(false), new Number(1.5), new Boolean(false), 0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, 0x07fffffff, new Boolean(false), 0x07fffffff, 0x07fffffff, new Number(1.5), 0x07fffffff, 0x07fffffff, new Number(1.5), objectEmulatingUndefined(), 0x07fffffff, new Boolean(false), 0x07fffffff, 0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Boolean(false), 0x07fffffff, new Boolean(false), new Number(1.5), 0x07fffffff, objectEmulatingUndefined()]); ");
/*fuzzSeed-116066984*/count=1025; tryItOut("\"use asm\"; x;");
/*fuzzSeed-116066984*/count=1026; tryItOut("a2[13] = t2;");
/*fuzzSeed-116066984*/count=1027; tryItOut("\"use strict\"; print(x+=x);");
/*fuzzSeed-116066984*/count=1028; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.expm1(Math.fround((( + Math.max(( + y), ((Math.max(y, (y >>> 0)) >>> 0) ^ Math.cosh(x)))) >>> (((((x | 0) >> (y | 0)) | 0) == x) ^ (Math.max(( + Math.fround(((x <= (x ? y : 0x07fffffff)) >>> 0))), y) >>> 0))))) | 0); }); testMathyFunction(mathy0, [0x080000000, Number.MIN_VALUE, -0x080000000, 1, -0x07fffffff, -1/0, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), -0x100000001, 0x07fffffff, 2**53-2, -Number.MIN_VALUE, 2**53+2, 0x100000001, 0.000000000000001, -0, -0x100000000, -0x0ffffffff, -Number.MAX_VALUE, Math.PI, 0, 0x0ffffffff, 0x100000000, 0/0, 1/0, Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 42, -(2**53-2), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1029; tryItOut("");
/*fuzzSeed-116066984*/count=1030; tryItOut("mathy2 = (function(x, y) { return (Math.cosh(( + (( + ( + mathy0(( + ( + Math.fround(x))), ((Math.tan((x | 0)) | 0) << Math.fround(Math.min(y, Math.fround(x))))))) | 0))) | 0); }); testMathyFunction(mathy2, [-0x0ffffffff, 0x100000001, 0x080000000, 1.7976931348623157e308, 0x080000001, -0x100000000, 1/0, -(2**53+2), 2**53-2, 0.000000000000001, 2**53, Number.MIN_VALUE, -0x080000000, -0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x080000001, -Number.MIN_VALUE, 0x07fffffff, 1, -(2**53), Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, 42, -1/0, 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, 0x100000000, 0]); ");
/*fuzzSeed-116066984*/count=1031; tryItOut("/*tLoop*/for (let c of /*MARR*/[-Infinity, 3/0, x, 3/0, (-1/0), x, x, (-1/0), (-1/0), (-1/0)]) { /*vLoop*/for (zecbii = 0; zecbii < 14; ++zecbii, DataView.prototype.setUint8(this.__defineGetter__(\"x\", function(y) { return -2 }), new y(\u3056, /(?:(?:([^]+?^(?!\\B))+?))/))) { w = zecbii; v2 = g1.runOffThreadScript(); }  }");
/*fuzzSeed-116066984*/count=1032; tryItOut("\"use strict\"; e0.valueOf = (function() { for (var j=0;j<4;++j) { f1(j%3==1); } });");
/*fuzzSeed-116066984*/count=1033; tryItOut("for (var p in f1) { try { e2 + ''; } catch(e0) { } try { m0.toString = f1; } catch(e1) { } a2.splice(-8, v0); }");
/*fuzzSeed-116066984*/count=1034; tryItOut("v2 = new Number(e2);");
/*fuzzSeed-116066984*/count=1035; tryItOut("/*oLoop*/for (let ktgyzl = 0; ktgyzl < 19; new (/*wrap3*/(function(){ \"use strict\"; var zmcfpx = \"\\u7E21\"; (true)(); }))(this, this), ++ktgyzl) { true; } ");
/*fuzzSeed-116066984*/count=1036; tryItOut("mathy4 = (function(x, y) { return (( + Math.fround(mathy0(Math.fround(Math.hypot((x ? (x / -0x080000000) : y), (Math.fround(0) <= x))), ( + ( ! (( ~ (mathy0(Math.fround(( ~ Math.fround(Number.MAX_SAFE_INTEGER))), (Math.imul((y >>> 0), (y >>> 0)) >>> 0)) >>> 0)) >>> 0)))))) - ( + (( + Math.round(( + (((((x >>> 0) * -0x080000000) | 0) & Math.fround(Math.pow(Math.fround(y), ( + x)))) | 0)))) < ( ~ Math.atanh(Math.fround((((-0x080000001 <= x) | 0) <= x))))))); }); testMathyFunction(mathy4, [0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0x080000000, -0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, 1, 0/0, -0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2, 0x100000001, Math.PI, -0x080000001, -0, 0x080000001, -(2**53), -(2**53+2), 2**53, 0x100000000, 0.000000000000001, -0x07fffffff, -0x0ffffffff, 0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 42, -0x100000000, 2**53-2, 1.7976931348623157e308]); ");
/*fuzzSeed-116066984*/count=1037; tryItOut("m0.delete(h1);");
/*fuzzSeed-116066984*/count=1038; tryItOut("o0.s0 = '';");
/*fuzzSeed-116066984*/count=1039; tryItOut("\"use strict\"; h2.iterate = f0;");
/*fuzzSeed-116066984*/count=1040; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + ( ~ mathy1(Math.hypot((y === x), -Number.MIN_VALUE), ( + x)))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 0x100000000, -1/0, -(2**53-2), 0, 42, Math.PI, 1, -0x080000000, 0x080000000, 0.000000000000001, -0x080000001, 2**53+2, 0/0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 1/0, -0x07fffffff, 0x100000001, 2**53-2, -0x100000001, -0, 0x080000001, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 1.7976931348623157e308]); ");
/*fuzzSeed-116066984*/count=1041; tryItOut("mathy4 = (function(x, y) { return (Math.acosh((Math.fround(Math.exp(((-(2**53) <= x) ^ Math.hypot((Math.log1p(y) >>> 0), (x >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -1/0, Math.PI, 0x100000000, -0x07fffffff, 1.7976931348623157e308, 0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000001, 0.000000000000001, 0x07fffffff, 2**53-2, -(2**53+2), 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, 0/0, -0x080000001, -Number.MAX_VALUE, -0, 42, Number.MIN_SAFE_INTEGER, 2**53, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, Number.MAX_VALUE, 0x100000001, -(2**53-2), 1, 0, 2**53+2]); ");
/*fuzzSeed-116066984*/count=1042; tryItOut("/*RXUB*/var r = /\\3+/g; var s = \"\\n\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-116066984*/count=1043; tryItOut("/*RXUB*/var r = new RegExp(\"($)\", \"gyim\"); var s = \"\\n\"; print(r.test(s)); ");
/*fuzzSeed-116066984*/count=1044; tryItOut("mathy0 = (function(x, y) { return ((Math.max(( + (( + (( + y) >>> 0)) | ( + y))), Math.fround(( + x))) !== Math.pow(x, (Math.fround(y) / ( + y)))) < (Math.log2((( - ( ! ( + (Math.acos((x >>> 0)) >>> 0)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=1045; tryItOut("v2 = evalcx(\"function f1(i2) \\\"use asm\\\";   function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var d2 = 4398046511105.0;\\n    return ((-((0xdb2e955d) ? (((((0x3e9cdfa) == (0x3fcde430))) ^ (/*UUV2*/(x.setDate = x.getInt32) instanceof (a)-=(-12 &  /x/g ))) < (-0x8000000)) : (i0))))|0;\\n  }\\n  return f;\", g1.g0.g0);");
/*fuzzSeed-116066984*/count=1046; tryItOut("\"use strict\"; \"use strict\"; /*ADP-3*/Object.defineProperty(a2, o2.v1, { configurable: (x % 4 != 2), enumerable: false, writable:  '' , value: m1 });");
/*fuzzSeed-116066984*/count=1047; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (d0);\n    }\n    {\n      (Int8ArrayView[((0xaf787642)+(0xfa1c6023)) >> 0]) = ((0xf9ce4eb7)+((-7.555786372591432e+22)));\n    }\n    i1 = (0xfa13619b);\n    i1 = (0xffffffff);\n    {\n      i1 = (i1);\n    }\n    {\n      return +((d0));\n    }\n    return +((-2251799813685248.0));\n  }\n  return f; })(this, {ff: (new Function(\"print((this.__defineGetter__(\\\"z\\\", encodeURIComponent)));\"))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=1048; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + Math.max(( + ( + Math.imul((( ~ Math.expm1(mathy3(( ~ 1/0), (Number.MAX_VALUE >>> 0)))) >>> 0), Math.fround(( - Math.fround(( ~ ((Math.atanh((( + (( + (( + -Number.MIN_SAFE_INTEGER) && ( + y))) | ( + y))) | 0)) | 0) | 0)))))))), Math.asin(Math.acos((( ! ( + -0x100000001)) >>> 0))))); }); ");
/*fuzzSeed-116066984*/count=1049; tryItOut("s0 += s1;");
/*fuzzSeed-116066984*/count=1050; tryItOut("let = getter;");
/*fuzzSeed-116066984*/count=1051; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.pow(((Math.atan(( + (mathy4(((((Math.fround(x) >>> 0) + ( + (mathy4((((-Number.MAX_VALUE >>> 0) * x) | 0), (( + Math.fround(Math.hypot(y, -(2**53+2)))) >>> 0)) >>> 0))) >>> 0) | 0), ( ! x)) | 0))) >>> 0) | 0), (Math.fround(Math.tan(Math.fround(Math.fround(Math.abs(Math.atan2(((x >>> 0) <= (y >>> 0)), ( + (Math.cos((x >>> 0)) >>> 0)))))))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[ /x/ , undefined,  /x/ ,  /x/ ,  /x/ , new Number(1), undefined, new Number(1),  /x/ , undefined, new Number(1),  /x/ ,  /x/ , new Number(1), undefined, undefined, new Number(1),  /x/ ,  /x/ ,  /x/ ,  /x/ , undefined, new Number(1), undefined,  /x/ , undefined,  /x/ , undefined, new Number(1),  /x/ , undefined,  /x/ , undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,  /x/ , new Number(1),  /x/ , new Number(1),  /x/ , undefined, new Number(1),  /x/ ,  /x/ , undefined, undefined, new Number(1),  /x/ , undefined,  /x/ ,  /x/ , undefined,  /x/ ,  /x/ , new Number(1), new Number(1), undefined,  /x/ ,  /x/ ,  /x/ , undefined, new Number(1), undefined,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1), undefined,  /x/ ,  /x/ , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  /x/ , new Number(1), new Number(1), undefined, new Number(1), undefined, undefined, undefined, undefined, new Number(1), new Number(1),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1),  /x/ , new Number(1),  /x/ , undefined, undefined,  /x/ , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1), undefined,  /x/ , new Number(1),  /x/ ,  /x/ , new Number(1), new Number(1), new Number(1), new Number(1),  /x/ , undefined,  /x/ , undefined, new Number(1), undefined, undefined, undefined, undefined, new Number(1),  /x/ ,  /x/ ,  /x/ , new Number(1),  /x/ ,  /x/ , undefined, undefined, undefined, undefined, undefined, new Number(1), new Number(1), undefined,  /x/ ,  /x/ ,  /x/ , undefined, new Number(1), undefined, undefined,  /x/ , undefined, undefined, undefined,  /x/ , undefined,  /x/ ,  /x/ ]); ");
/*fuzzSeed-116066984*/count=1052; tryItOut("h0.iterate = (function(j) { f1(j); });");
/*fuzzSeed-116066984*/count=1053; tryItOut("print(x);\nprint(Math.pow(-24, d === -19));\n");
/*fuzzSeed-116066984*/count=1054; tryItOut("(arguments);throw new RegExp(\"h?\", \"gy\");switch(-29) { default: break; case 6: v0 = g0.eval(\"NaN\");break; case 3: break; true;break; case 9: (\"\\uA85D\");break; \"\\uEC52\";p1.__iterator__ = (function() { try { s2 += s2; } catch(e0) { } try { for (var p in t1) { try { v2 = (a1 instanceof t2); } catch(e0) { } s2[\"catch\"] = o0; } } catch(e1) { } try { m2 = new Map(p0); } catch(e2) { } v0 + ''; return i2; });break; case true: print(\"\\u9882\");case 5: break; case \"\\uBFA3\":  }");
/*fuzzSeed-116066984*/count=1055; tryItOut("mathy1 = (function(x, y) { return ( ~ (Math.tan(((Math.imul((Math.sinh(y) | 0), (( ! mathy0(((y || ((( ~ x) >>> 0) >>> 0)) >>> 0), (Math.trunc(( + y)) | 0))) | 0)) | 0) | 0)) | 0)); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, -0x0ffffffff, 2**53-2, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 0.000000000000001, 0/0, 0, 0x080000001, 42, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, Math.PI, -0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), Number.MAX_VALUE, 1/0, -0x080000001, 1, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), 0x07fffffff, -0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-116066984*/count=1056; tryItOut("\"use strict\"; v2 = false;");
/*fuzzSeed-116066984*/count=1057; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.imul(( - (Math.atan((Math.hypot((((y >>> 0) , (y >>> 0)) >>> 0), (( - (x | 0)) | 0)) >>> 0)) >>> 0)), ( + ( - ( ! (mathy3(x, (x | 0)) | 0))))); }); testMathyFunction(mathy5, ['0', objectEmulatingUndefined(), 0, '\\0', NaN, 1, ({valueOf:function(){return '0';}}), null, [], false, ({valueOf:function(){return 0;}}), '/0/', -0, undefined, '', /0/, (new Boolean(false)), (function(){return 0;}), (new Number(-0)), 0.1, (new String('')), true, [0], ({toString:function(){return '0';}}), (new Number(0)), (new Boolean(true))]); ");
/*fuzzSeed-116066984*/count=1058; tryItOut("{ void 0; void relazifyFunctions('compartment'); } v0 = Object.prototype.isPrototypeOf.call(h1, p0);");
/*fuzzSeed-116066984*/count=1059; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.min((((Math.fround(Math.max(x, Number.MIN_VALUE)) ** 2**53) >>> 0) * ((( + mathy1(y, x)) >>> 0) >>> 0)), Math.fround((Math.fround(Math.min(( ! (y >>> 0)), ( + y))) && Math.fround(x)))) ** ( ~ ( + ((( ! (y >>> 0)) >>> 0) === x)))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0x100000000, 1, -0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 1/0, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, 0x080000000, 2**53-2, 0, -0x0ffffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, Number.MAX_VALUE, -0x07fffffff, Math.PI, -(2**53-2), -0x100000000, 0/0, -(2**53), -1/0, 2**53+2, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, 0x100000001, 0.000000000000001]); ");
/*fuzzSeed-116066984*/count=1060; tryItOut("mathy2 = (function(x, y) { return mathy0(Math.exp(((Math.pow((( ~ (( ~ y) >>> 0)) >>> 0), x) * mathy1(( + x), ((( - y) | 0) | Math.max(-0, y)))) | 0)), (Math.fround(Math.max(x, ( + Math.imul(Math.pow(Math.ceil(y), (2**53 >>> 0)), 0x080000001)))) != Math.fround(mathy0(Math.fround((Math.atanh((Math.pow(Math.min(-(2**53-2), ( ! x)), ( - Math.cosh(x))) | 0)) | 0)), Math.fround(( ~ Math.pow((Math.max((y | 0), (y | 0)) | 0), y))))))); }); testMathyFunction(mathy2, [0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, 0/0, 42, -(2**53+2), 2**53+2, -0x080000001, -0, -Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, 0, -0x100000001, -0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -1/0, 0x0ffffffff, 1, -Number.MIN_VALUE, 0x080000001, -(2**53), 2**53-2, 0x100000001, Math.PI]); ");
/*fuzzSeed-116066984*/count=1061; tryItOut("v1 + '';");
/*fuzzSeed-116066984*/count=1062; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.max(( + (Math.tanh((Math.min((x >>> 0), ( ~ 0x080000000)) >>> 0)) ? Math.sinh(2**53-2) : (mathy3(mathy3(Math.exp(Math.imul((1/0 | 0), 1/0)), y), ( + x)) | 0))), (Math.cosh(((Math.fround(mathy1(Math.fround(mathy1((( ! (x >>> 0)) >>> 0), (Math.log((y | 0)) | 0))), Math.sin(y))) && ( + -Number.MIN_VALUE)) | 0)) | 0)); }); testMathyFunction(mathy4, [-0x0ffffffff, -Number.MAX_VALUE, -0, -Number.MIN_VALUE, -(2**53+2), 0x080000001, -0x100000000, Number.MAX_VALUE, 0.000000000000001, 0x100000000, -(2**53-2), 42, 0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53), 0, -0x100000001, 2**53, -1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 2**53-2, 2**53+2, 0/0, Number.MIN_VALUE, 1, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI]); ");
/*fuzzSeed-116066984*/count=1063; tryItOut("\"use strict\"; v2 = a0.length;");
/*fuzzSeed-116066984*/count=1064; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[x, new String('q'), new String('q'), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), x, new String('q'), new String('q'), new String('q'), new String('q'), x, new String('q'), x, new String('q'), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String('q'), new String('q'), x, new String('q'), x, x, new String('q'), new String('q'), new String('q'), x, x, new String('q'), x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q')]) { Array.prototype.reverse.apply(a2, [g2.g2.e2]); }");
/*fuzzSeed-116066984*/count=1065; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.hypot(Math.sign((Math.tanh(x) >> ( - ( + Math.min(y, x))))), ( + Math.pow(((((y >>> 0) ^ ( ~ Math.fround((Math.fround(x) ? Math.fround(Number.MAX_VALUE) : Math.fround(0x080000001))))) >>> 0) != x), (((y , 1/0) >>> 0) >> (Math.sign(x) >= y))))); }); testMathyFunction(mathy3, [0x100000001, 1, 1/0, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53-2), 0/0, -Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, -0, Math.PI, -0x100000001, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, 2**53-2, 0, -0x080000000, Number.MAX_VALUE, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, 0x0ffffffff, 2**53+2, -(2**53), Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1066; tryItOut("mathy2 = (function(x, y) { return Math.pow(Math.fround(( ! (Math.min(0x0ffffffff, Math.fround((Math.fround(mathy0(42, y)) & y))) >>> 0))), ( + Math.fround(Math.imul(Math.fround(Math.pow((mathy1((Math.max(( + y), y) | 0), Number.MAX_SAFE_INTEGER) | 0), (mathy0(Math.imul(Number.MAX_VALUE, Math.round(x)), -Number.MIN_VALUE) | 0))), ((( ~ x) % ( + Math.imul(Math.pow(( + Math.sqrt((x >>> 0))), x), Math.fround(y)))) | 0))))); }); testMathyFunction(mathy2, [0.000000000000001, -0x100000001, -0x080000000, 1/0, 2**53, -(2**53-2), -(2**53+2), 1.7976931348623157e308, 1, 0, 0x0ffffffff, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 2**53+2, -0, 0x100000000, 0x080000001, -0x080000001, Number.MAX_VALUE, 0x07fffffff, -1/0, -0x100000000, 0x080000000, Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 2**53-2]); ");
/*fuzzSeed-116066984*/count=1067; tryItOut("/*oLoop*/for (var ecuvxc = 0; ecuvxc < 24; ++ecuvxc) { t0 = new Float32Array(a0); } ");
/*fuzzSeed-116066984*/count=1068; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\ng1.a2 + g2;    i1 = (0xc0955437);\n    i0 = (Math.min(-20, -19));\n    {\n      switch ((((i0))|0)) {\n        case -3:\n          i1 = (i1);\n          break;\n        case 0:\n          i0 = (i1);\n          break;\n        default:\n          return (((!(i1))+(-0x8000000)+(i1)))|0;\n      }\n    }\n    return (((((i1)-((0x8cc2acd8) != (((0xfdf8d3fa))>>>((0x13a782ba))))+(i0))>>>(((Float64ArrayView[2]))-(i1))) % (0x4b056174)))|0;\n  }\n  return f; })(this, {ff: /*MARR*/[[], window, [], new Number(1), ({x:3}), [], new Number(1), window, ({x:3}), [], window, [], ({x:3}), ({x:3}), ({x:3}), window, ({x:3}), [], window, [], window, new Number(1), [], window, new Number(1), ({x:3}), ({x:3}), ({x:3}), window, new Number(1), [], window, [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], window, new Number(1), window, ({x:3}), ({x:3}), window, ({x:3}), ({x:3}), ({x:3}), window, window].some(b => (this.__defineSetter__(\"x\", eval)), x)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x07fffffff, 0, 0x100000001, 1.7976931348623157e308, -0x100000001, -0x080000001, 1, -1/0, -Number.MIN_SAFE_INTEGER, 0/0, 42, 0x0ffffffff, Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 0x100000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 2**53-2, -0x080000000, 0.000000000000001, 0x080000000, -(2**53+2), Math.PI, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), 2**53, 0x080000001, 2**53+2, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1069; tryItOut("\"use asm\"; /*vLoop*/for (pkdckr = 0; pkdckr < 40; null, ++pkdckr) { c = pkdckr; print(c); } ");
/*fuzzSeed-116066984*/count=1070; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy1(( + Math.exp(( - y))), ( + Math.fround(Math.atan2((((Math.atan2(y, ( + y)) >>> 0) ^ (( - ((Math.atan2(y, y) >>> 0) ** ((x <= 1) >>> 0))) >>> 0)) >>> 0), Math.fround(Math.sin(mathy1(Math.log1p(x), ( ~ 0x100000001)))))))); }); ");
/*fuzzSeed-116066984*/count=1071; tryItOut("{ void 0; void gc(this); }");
/*fuzzSeed-116066984*/count=1072; tryItOut("v0 = this.g0.eval(\"function f0(p0)  { \\\"use strict\\\"; /*hhh*/function reewrj(c = (objectEmulatingUndefined()), \\u3056){e2.add(h1);}/*iii*/m0.set( /* Comment */this <<= eval, o2); } \");");
/*fuzzSeed-116066984*/count=1073; tryItOut("mathy1 = (function(x, y) { return ( - (Math.expm1(Math.imul(Math.atan2(Math.fround(( + ( + y))), Math.fround(x)), (Math.sqrt(( + (Math.fround(y) != x))) | 0))) | 0)); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 0x07fffffff, -0x100000000, -0x07fffffff, -0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, -0, 1, -Number.MIN_SAFE_INTEGER, Math.PI, 42, 1/0, 0x080000001, -Number.MIN_VALUE, -0x100000001, 2**53-2, 0x080000000, -1/0, 0x0ffffffff, -0x080000001, -(2**53+2), 2**53, 0.000000000000001, 0x100000001, -(2**53-2), 0/0, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53)]); ");
/*fuzzSeed-116066984*/count=1074; tryItOut("a0.pop(f2);");
/*fuzzSeed-116066984*/count=1075; tryItOut("");
/*fuzzSeed-116066984*/count=1076; tryItOut("mathy4 = (function(x, y) { return ((( + ( ~ ( + Math.min(( + ( + ( - ( + Number.MIN_VALUE)))), ( + Math.atan2(x, (x >>> 0))))))) , (( - ( ! (Math.fround((42 & Math.fround(((y >>> 0) >>> (y >>> 0))))) ? Math.fround((Math.pow(x, ( + Math.fround(( + y)))) | 0)) : -Number.MAX_VALUE))) | 0)) | 0); }); ");
/*fuzzSeed-116066984*/count=1077; tryItOut("var z = (4277).unwatch(\"revocable\");var eafsrd = new SharedArrayBuffer(12); var eafsrd_0 = new Uint8ClampedArray(eafsrd); print(eafsrd_0[0]); var eafsrd_1 = new Int8Array(eafsrd); var eafsrd_2 = new Int32Array(eafsrd); print(eafsrd_2[0]); var eafsrd_3 = new Uint8Array(eafsrd); eafsrd_3[0] = 22; var eafsrd_4 = new Int8Array(eafsrd); eafsrd_4[0] = 20; var eafsrd_5 = new Int8Array(eafsrd); eafsrd_5[0] = 1738000838.5; for (var p in i0) { Array.prototype.pop.apply(a1, [o2.i1, f1, a0]); }a1.pop();v2 = (g1 instanceof h0);/*infloop*/for(eval in ((neuter)(this)))print(eafsrd_0[1]);h2.delete = (function() { try { i0 + ''; } catch(e0) { } try { this.g1.v1 = Object.prototype.isPrototypeOf.call(h1, s0); } catch(e1) { } try { a2.pop(a0); } catch(e2) { } v2 = g2.eval(\"null\"); return h0; });(NaN);v0 = Object.prototype.isPrototypeOf.call(f1, t1);print(eafsrd);b2 + g1;");
/*fuzzSeed-116066984*/count=1078; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((((Math.atan2(Math.fround(( ~ y)), (Math.atan2(((Math.pow(mathy0(Math.hypot(( + x), ( + 2**53+2)), x), x) | 0) >>> 0), (y >>> 0)) | 0)) >>> 0) >>> 0) && (Math.atan2(Math.max(x, (( - (y | 0)) | 0)), ( - 0x07fffffff)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [1.7976931348623157e308, -Number.MAX_VALUE, 0, -(2**53), 1, 0x100000000, 0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, -0x080000001, 2**53, -0x100000001, -0x100000000, -(2**53+2), -0x080000000, Math.PI, 0/0, -0, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0x080000000, -1/0, Number.MAX_VALUE, 2**53-2, 0.000000000000001, 0x080000001, 1/0, -0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1079; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -70368744177665.0;\n    var d5 = 18014398509481984.0;\n    return +((d4));\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 42, 0x080000001, 2**53, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53-2, -0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 0, -(2**53+2), 0x100000001, 0x100000000, 0x07fffffff, -(2**53), 0x080000000, -0, 1, 1/0, -0x100000000, -0x100000001, 0/0, Number.MIN_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1080; tryItOut("(x--);");
/*fuzzSeed-116066984*/count=1081; tryItOut("s1 += o2.s0;/*ADP-2*/Object.defineProperty(a2, 13, { configurable: false, enumerable: false, get: (function() { try { m2.set( \"\" , window); } catch(e0) { } try { for (var v of b0) { try { s0 += 'x'; } catch(e0) { } try { Array.prototype.splice.apply(this.a2, [NaN, 17, e1, false]); } catch(e1) { } a0[11]; } } catch(e1) { } for (var v of s0) { v1 = (v1 instanceof this.o1.b1); } throw a0; }), set: (function() { e0.delete(e2); return g0; }) });function x(...x)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+((+(0.0/0.0))));\n    {\n      {\n        d1 = (d1);\n      }\n    }\n    return (((0x7fcdddc9)))|0;\n  }\n  return f;(\"\\uA887\");");
/*fuzzSeed-116066984*/count=1082; tryItOut("g0.offThreadCompileScript(\"function f1(b0) (4277)\", ({ global: g1.g1, fileName: null, lineNumber: 42, isRunOnce: (x % 43 != 6), noScriptRval: false, sourceIsLazy: Math.clz32, catchTermination: x }));");
/*fuzzSeed-116066984*/count=1083; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.log1p(Math.atan2((( + x) ^ x), ( + ( - ( + ( + ( ~ ( + Math.fround((Math.fround(y) ? (y | 0) : (y | 0))))))))))); }); ");
/*fuzzSeed-116066984*/count=1084; tryItOut("mathy5 = (function(x, y) { return ( + Math.asinh(((x ? ( + mathy1(( + ( + Math.min(x, y))), Math.fround(( - x)))) : Math.fround(( + Math.fround(-(2**53-2))))) / ((y ** (( ~ x) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [2**53, 0x100000001, -0x100000001, -0, 1, 0/0, 1.7976931348623157e308, 0x080000000, 1/0, 0.000000000000001, -(2**53-2), 0x080000001, 42, -1/0, -(2**53+2), -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -Number.MIN_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-116066984*/count=1085; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return ( ! mathy2((Math.tan(0/0) === ((((x & ( + x)) | 0) <= ((y <= y) >>> 0)) >>> 0)), ( ! ((((x ^ y) > (y | 0)) >>> 0) > ( + Math.min((-0x080000000 >>> 0), ( + x))))))); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 0x100000000, -0x0ffffffff, -0x080000001, -(2**53-2), 1.7976931348623157e308, 0x080000000, Math.PI, 0/0, 0x07fffffff, Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), -0x100000000, 1, 42, -0x080000000, -0x07fffffff, 0x100000001, 2**53+2, 0, 2**53, -1/0, 1/0, -0x100000001, 2**53-2, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1086; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.imul(Math.clz32(Math.fround(Math.atan2(( + x), ( + x)))), ( + (Math.fround(y) != ( + Math.log(-Number.MAX_SAFE_INTEGER))))) === Math.asinh(Math.round(((( ~ (x | 0)) | 0) ? Math.max(x, (y >>> 0)) : ( + (( + Math.pow(Math.imul((0x0ffffffff | 0), (y | 0)), y)) % ( + x))))))); }); testMathyFunction(mathy3, [0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, 1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, 2**53-2, -0x07fffffff, 0, 0x080000001, -0x100000001, -1/0, Number.MIN_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 2**53, Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, -(2**53+2), 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53), 2**53+2, -(2**53-2), -0x100000000, -0, 0x080000000, 0x100000000]); ");
/*fuzzSeed-116066984*/count=1087; tryItOut("var kucksk = new SharedArrayBuffer(0); var kucksk_0 = new Uint8Array(kucksk); var kucksk_1 = new Float32Array(kucksk); var kucksk_2 = new Int32Array(kucksk); s2 += 'x';print(kucksk_0[0]);a2[14] = (\"\\uBF39\")(\"\\u4756\");t2[0] = t1;;(a , window);/* no regression tests found */");
/*fuzzSeed-116066984*/count=1088; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((((( ~ ( + ( ~ ( - (Math.fround((y * ( + x))) >>> 0))))) | 0) | 0) || (Math.fround(( + Math.fround(Math.hypot(((Math.imul(Math.fround(Math.cosh(Math.fround(y))), x) >>> 0) % (( + 0x07fffffff) !== ( + (Math.min(Math.pow(x, (x >>> 0)), Math.fround(x)) | 0)))), ((Math.acos(( + y)) >>> 0) | 0))))) | 0)) | 0); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -(2**53-2), -1/0, 2**53-2, -(2**53+2), -0x080000000, 1.7976931348623157e308, 0, 0x080000000, -0x080000001, 0x080000001, Math.PI, -0x0ffffffff, 0x100000001, -0, 2**53+2, 0x0ffffffff, 1, -0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, 2**53]); ");
/*fuzzSeed-116066984*/count=1089; tryItOut("mathy5 = (function(x, y) { return ((mathy1(Math.fround(( ~ Math.fround(Math.pow(Math.fround((Math.cosh((Math.log2(y) | 0)) | 0)), Math.expm1(( + Math.atan2(x, x))))))), mathy2(Math.clz32(mathy2((Math.expm1(Math.fround(x)) >>> 0), Math.fround(Math.tanh((0x100000000 ? x : x))))), (( + Math.clz32(( + (Math.cos((x | 0)) | 0)))) , x))) >>> 0) && Math.sin(( ~ (Math.hypot((y >>> 0), (x == y)) | 0)))); }); testMathyFunction(mathy5, [-1/0, Math.PI, 0x100000000, 2**53+2, 0x080000000, 2**53, 1/0, 1.7976931348623157e308, -(2**53-2), -(2**53), -0x100000001, 0x0ffffffff, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, 42, 2**53-2, -0x100000000, -0x0ffffffff, 0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -0x080000001, 0, -0, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=1090; tryItOut("b2 = t0[6];");
/*fuzzSeed-116066984*/count=1091; tryItOut("\"use strict\"; (/*FARR*/[...new Array(6), ... /x/  if ((4277)), ((void shapeOf( /x/  =  \"\" ))), .../*PTHR*/(function() { for (var i of decodeURIComponent) { yield i; } })(), (x - x.unwatch(18)), , ].map);");
/*fuzzSeed-116066984*/count=1092; tryItOut("\"use strict\"; /*iii*/neuter(b1, \"change-data\");/*hhh*/function pqgsmu(b, a, x, \u3056, z = true, b, NaN = {}, x, x, z, w = new RegExp(\".\", \"\"), window, e, x = new RegExp(\"\\\\b{4,7}\\\\d^+($)\\\\x26{4,}|[\\\\b\\\\u00CC-\\u7447\\\\S](?:(?!\\\\W^))[](?=[\\\\s\\\\u0067]){1,3}(?:$|(?=\\\\2))?\", \"gy\"), x, a, x, x, \u3056, w, x =  '' , y, x = null, w, a, a, x, x, b, y, x, w, x, d, valueOf, x, b, x, x, z, b, x, eval, x, c, d = 23, z, delete, b, x, y, x, y, x, ...window){print(\"\\u4206\");}");
/*fuzzSeed-116066984*/count=1093; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.log1p(Math.acos(Math.fround(Math.acos(((((y | 0) , ( + Math.round(x))) | 0) >>> 0))))) >>> 0) >= (Math.log1p(Math.log2(Math.acosh(Math.log(( + (y || x)))))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[new Number(1),  /x/ , new String('q'), new String('q'),  /x/ , new String('q'), new String('q'), new String('q'),  /x/ ,  /x/ , new Number(1), new Number(1),  /x/ ,  /x/ , new Number(1),  /x/ , new String('q'), new String('q'),  /x/ ,  /x/ ,  /x/ , new String('q'), new Number(1),  /x/ ,  /x/ , new Number(1), new Number(1),  /x/ , new String('q'), new String('q'),  /x/ , new Number(1), new Number(1), new String('q'), new Number(1),  /x/ , new Number(1),  /x/ , new String('q'),  /x/ , new String('q'),  /x/ , new String('q'),  /x/ , new Number(1),  /x/ , new Number(1),  /x/ , new Number(1), new String('q'),  /x/ ,  /x/ , new String('q'),  /x/ ,  /x/ ,  /x/ , new Number(1),  /x/ , new String('q'), new String('q'), new Number(1),  /x/ , new Number(1),  /x/ , new Number(1),  /x/ , new Number(1), new Number(1), new String('q'), new Number(1), new Number(1), new Number(1),  /x/ ,  /x/ ,  /x/ , new Number(1), new Number(1), new String('q'), new Number(1), new String('q'),  /x/ , new String('q'), new Number(1),  /x/ ,  /x/ ,  /x/ ,  /x/ , new String('q'), new Number(1), new Number(1), new String('q'),  /x/ , new String('q'), new Number(1),  /x/ , new String('q'), new Number(1),  /x/ , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new String('q'), new Number(1), new Number(1), new Number(1), new String('q'), new Number(1),  /x/ , new String('q'), new String('q'), new String('q'), new Number(1), new Number(1), new Number(1), new String('q'),  /x/ , new Number(1), new String('q'), new Number(1), new String('q'),  /x/ ,  /x/ , new String('q'), new Number(1), new Number(1), new String('q'), new String('q'),  /x/ , new String('q'), new Number(1),  /x/ ,  /x/ , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  /x/ , new Number(1),  /x/ , new String('q'), new Number(1), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'),  /x/ ,  /x/ , new Number(1), new String('q'),  /x/ , new String('q'),  /x/ , new String('q'),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1), new Number(1), new String('q'), new String('q'), new String('q'), new String('q'),  /x/ , new String('q'),  /x/ , new String('q'), new Number(1), new String('q'),  /x/ ]); ");
/*fuzzSeed-116066984*/count=1094; tryItOut("for (var p in o1.f1) { try { v0 = (f2 instanceof t2); } catch(e0) { } try { e0.delete(h2); } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(m0, i1); }");
/*fuzzSeed-116066984*/count=1095; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((Math.abs(Math.fround(( - (( ~ x) >>> 0)))) >>> 0) + ( ~ ( + ((((Math.imul(x, x) > ( + ( - ( + x)))) | 0) ? ((x , ( + mathy4(x, ( + Math.atan2(x, y))))) / Number.MAX_VALUE) : (y | 0)) | 0)))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 2**53, Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, 1, -0x100000000, -0x080000000, 0x0ffffffff, 2**53+2, -(2**53+2), -Number.MIN_VALUE, 1/0, 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, -(2**53), -0x080000001, 0x100000001, -0, 0.000000000000001, -0x07fffffff, 42, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1096; tryItOut("\"use strict\"; x.stack;");
/*fuzzSeed-116066984*/count=1097; tryItOut("\"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 72057594037927940.0;\n    d0 = (d0);\n    return (((0xf9f5742f)-(-0x8000000)))|0;\n    {\n      {\n        return ((-(((((-((Float64ArrayView[((0xffffffff)+(-0x8000000)+(0x412f383)) >> 3]))))-(0xfdd53c7b)) ^ ((0xfdb7ee16))) > (0x477536c8))))|0;\n      }\n    }\n    (Uint16ArrayView[1]) = ((0x0) / (0xd801eb86));\n    return (((/*FFI*/ff(((d1)))|0)))|0;\n  }\n  return f; })(this, {ff: new Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53-2), -0x100000001, 0, -0, -Number.MIN_VALUE, -0x100000000, -0x080000001, Number.MAX_VALUE, 0/0, Number.MIN_VALUE, 0x100000000, 0x080000000, 42, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, 0x080000001, 1/0, -0x080000000, -(2**53+2), 1.7976931348623157e308, 2**53, 0x100000001, 0.000000000000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, -0x07fffffff, -1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1098; tryItOut("");
/*fuzzSeed-116066984*/count=1099; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x100000000, -Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, -0x07fffffff, 0x080000000, -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0x080000000, Math.PI, -0, 2**53+2, 2**53-2, -(2**53), 0x100000001, 1/0, 0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1, 42, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 0, -0x080000001, 0x080000001, -0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1100; tryItOut("testMathyFunction(mathy3, [-(2**53), -0x0ffffffff, 0x080000000, 0.000000000000001, 2**53-2, 2**53, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, -0x080000000, -0x100000000, -1/0, -(2**53-2), Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0, 2**53+2, 0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 0x080000001, Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 1, 1.7976931348623157e308, -(2**53+2), 42, -Number.MIN_VALUE, 1/0, -0x100000001, 0x07fffffff, Math.PI]); ");
/*fuzzSeed-116066984*/count=1101; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.atanh(( + mathy3((Math.abs(( + (void [1,,]))) | 0), ((Math.tan(((Math.cbrt((Math.cosh(-0x07fffffff) | 0)) | 0) >>> 0)) >>> 0) != Math.pow(Math.fround(((((y % Number.MAX_SAFE_INTEGER) | 0) >>> (x | 0)) | 0)), Math.fround(Math.min((( - (2**53 | 0)) | 0), Math.atan2((x >>> 0), ( + y)))))))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -1/0, 0x07fffffff, -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, -0x100000001, 1, 0/0, 0x100000001, -0x080000000, 2**53-2, 1/0, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 0x100000000, -(2**53), 2**53, 2**53+2, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 42, 0, -0x100000000, Number.MAX_VALUE, -(2**53+2), 0x080000001, 0x080000000]); ");
/*fuzzSeed-116066984*/count=1102; tryItOut("Array.prototype.push.apply(a0, [m1, t2]);");
/*fuzzSeed-116066984*/count=1103; tryItOut("\"use strict\"; /*RXUB*/var r = x; var s = \"_\"; print(s.match(r)); \na0 = Array.prototype.map.call(a1, f2);\n");
/*fuzzSeed-116066984*/count=1104; tryItOut("\"use strict\"; \"use asm\"; e = ({getter: x});this.g2.m2 + '';");
/*fuzzSeed-116066984*/count=1105; tryItOut("mathy3 = (function(x, y) { return ( ~ (Math.sqrt((let (e=eval) e)) | 0)); }); ");
/*fuzzSeed-116066984*/count=1106; tryItOut("let w = Uint16Array();i0.send(a2);\n(void shapeOf(eval(\"-15\", (({-0.468:  \"\" , w:  /x/  })))));\n");
/*fuzzSeed-116066984*/count=1107; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.exp(Math.fround(Math.fround(( ! Math.trunc(x))))); }); testMathyFunction(mathy1, [-0x07fffffff, -(2**53), 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, 2**53-2, 0.000000000000001, -1/0, 2**53+2, 1/0, 1, 2**53, 0x080000001, 0, -0x100000000, 42, 0x07fffffff, -(2**53-2), -(2**53+2), 0x0ffffffff, 0/0, -0, -Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1108; tryItOut("L: for  each(var b in function(id) { return id }) {/*infloop*/for(b in (x & d)) {;Array.prototype.sort.call(a2, (function(j) { if (j) { try { (void schedulegc(g1)); } catch(e0) { } try { o1.__proto__ = m2; } catch(e1) { } try { for (var p in g1) { (void schedulegc(g1)); } } catch(e2) { } selectforgc(o2); } else { s1 += s1; } }), o1.t0); } }");
/*fuzzSeed-116066984*/count=1109; tryItOut("v2 = evaluate(\"x\", ({ global: o0.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 25 != 1), noScriptRval: x, sourceIsLazy: false, catchTermination: (Promise((delete e.arguments\u0009[\"3\"]), x)), element: o2, elementAttributeName: s2 }));");
/*fuzzSeed-116066984*/count=1110; tryItOut("\"use strict\"; o2.v2 = t2.length;");
/*fuzzSeed-116066984*/count=1111; tryItOut("v1 = o0.a1.length;");
/*fuzzSeed-116066984*/count=1112; tryItOut("v0 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-116066984*/count=1113; tryItOut("\"use strict\"; /*MXX1*/o0 = g2.g2.WeakMap;");
/*fuzzSeed-116066984*/count=1114; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround((((Math.fround((Math.fround(Math.atan2(( + Math.min(y, ( + x))), Number.MIN_VALUE)) >= Math.fround(Math.fround(( + ( + (Math.trunc(y) ? ( + y) : Math.fround(Math.fround((Math.fround(y) >= x)))))))))) >>> 0) ? (( - (x - (Math.atan((( + y) >>> 0)) >>> 0))) >>> 0) : ((mathy2(( + ( + Math.hypot(x, ( + ( ~ y))))), ((Math.pow(x, Math.atan2(-(2**53-2), x)) >>> 0) | 0)) >>> 0) >>> 0)) ? ( + Math.pow(( + (( ~ (( + (( + Math.tanh(-Number.MIN_VALUE)) ? ( + y) : (Math.atan2((Math.imul(y, Math.fround(x)) | 0), (y | 0)) | 0))) | 0)) | 0)), ( + (y >= x)))) : ( + mathy2(((Math.fround((Math.exp(( + 0/0)) | 0)) & (1/0 | 0)) | 0), Math.atan2(y, ( + (( ~ x) << ( ! Math.fround((Math.fround(Math.atan2(Math.fround(0x100000001), x)) || x)))))))))); }); testMathyFunction(mathy4, [Math.PI, -Number.MAX_VALUE, -0x07fffffff, -0x100000000, 2**53-2, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 1/0, 2**53, 1, 0x0ffffffff, 0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, -0x080000001, -0x100000001, -1/0, 2**53+2, -(2**53), 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 42, -0x0ffffffff, 0x080000001, 0x100000000, Number.MAX_VALUE, 0/0, -(2**53+2), 0, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1115; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((mathy2(Math.atan2(x, ( + Math.cbrt(y))), ((Math.fround(x) | 0) | 0)) >>> 0) <= (mathy2(((( ~ -0x080000000) >>> 0) | ( ! ( ~ x))), ((x / ((mathy1(y, Math.fround((y % -Number.MIN_VALUE))) >>> 0) != y)) >>> 0)) & Math.asin((y - y)))); }); testMathyFunction(mathy4, [(function(){return 0;}), ({valueOf:function(){return 0;}}), 0.1, false, true, (new Boolean(false)), (new Number(-0)), /0/, '0', null, objectEmulatingUndefined(), undefined, (new String('')), [], '/0/', (new Boolean(true)), 1, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), -0, 0, NaN, '', [0], (new Number(0)), '\\0']); ");
/*fuzzSeed-116066984*/count=1116; tryItOut("/*infloop*/for(var y; (Math.hypot(-0, window)( /x/  += /\\cB+?(?!\\W{3,7}[^])|(?!(?:$|\\u00f6+?)){1025,}/im, /.{4,7}/im))\n; (4277)) {v2 = Object.prototype.isPrototypeOf.call(p2, v2); }");
/*fuzzSeed-116066984*/count=1117; tryItOut("mathy3 = (function(x, y) { return Math.hypot(( ~ Math.fround(Math.fround(Math.atan2(((x ? Math.round(( - x)) : ( + (Math.fround(Math.asin(Math.fround(y))) ** -(2**53-2)))) | 0), (Math.fround(Math.sinh(Math.fround(y))) >>> 0))))), (Math.tanh((Math.sign((Math.pow(Math.fround(x), ((x * (( ! (x | 0)) | 0)) >>> 0)) >>> 0)) | 0)) | 0)); }); ");
/*fuzzSeed-116066984*/count=1118; tryItOut("/*infloop*/for(var b in ( /x/ )) L:with({z: (x)({})})s2 += s1;");
/*fuzzSeed-116066984*/count=1119; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1120; tryItOut("\"use strict\"; \"use asm\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 134217729.0;\n    var i3 = 0;\n    d2 = (((Infinity)));\n    {\n      {\n        return +((d2));\n      }\n    }\n    return +((((d2)) - ((+(1.0/0.0)))));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MAX_VALUE, 0x0ffffffff, 2**53, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, 2**53+2, 1, -0, -0x0ffffffff, 0, 0x07fffffff, -(2**53-2), 1/0, -0x100000000, Math.PI, 0.000000000000001, 0/0, -0x100000001, -0x080000001, 1.7976931348623157e308, 0x100000000, 0x080000001, 42, 0x100000001, -(2**53+2), 2**53-2, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=1121; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var sin = stdlib.Math.sin;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        i0 = (i0);\n      }\n    }\n    {\n      (Float32ArrayView[(((i0) ? (-0x8000000) : ((0x6e361e20) ? (0x96e3a90) : (0x4568f204)))+(!(i0))-(0x69bac243)) >> 2]) = ((d1));\n    }\n    i0 = ((~(((((+ceil(((-1.5111572745182865e+23))))) / ((-549755813889.0)))))));\n    i0 = (\"\\uEF2E\");\n    {\n      i0 = (!(i0));\n    }\n    switch ((\"\\uA899\" >>  \"\" )) {\n      default:\n        d1 = (+sin((((Infinity)))));\n    }\n    return +((137438953473.0));\n  }\n  return f; })(this, {ff: SyntaxError.prototype.toString}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [1, objectEmulatingUndefined(), ({toString:function(){return '0';}}), '', '0', 0.1, (new Boolean(true)), ({valueOf:function(){return 0;}}), (new Number(0)), (new String('')), (new Boolean(false)), /0/, false, '\\0', undefined, (new Number(-0)), ({valueOf:function(){return '0';}}), NaN, true, [], 0, null, -0, (function(){return 0;}), [0], '/0/']); ");
/*fuzzSeed-116066984*/count=1122; tryItOut("s2 = '';");
/*fuzzSeed-116066984*/count=1123; tryItOut("for (var v of t0) { try { a2.unshift((x = ({eval: delete NaN.x}))); } catch(e0) { } v1 + g2; }");
/*fuzzSeed-116066984*/count=1124; tryItOut("testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 2**53, -0x080000001, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, -1/0, -0x07fffffff, -0x100000000, 0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, 0x100000000, 0x080000000, 2**53+2, Math.PI, 1, 1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -(2**53+2), 0/0, -(2**53-2), 1.7976931348623157e308, -Number.MAX_VALUE, 2**53-2, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, 42, -0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1125; tryItOut("a1.push(f0, t2, p2, g1);");
/*fuzzSeed-116066984*/count=1126; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.pow((Math.exp((Math.hypot((( + (( + 1/0) > ( + ((( ! (-0x100000000 >>> 0)) >>> 0) && x)))) >>> 0), (( ~ ((x >= ( + y)) | 0)) >>> 0)) >>> 0)) | 0), ((Math.atanh((Math.atan2((( + ((y <= -1/0) | 0)) >>> 0), ((((((( - x) ** x) | 0) | 0) <= ((((y | 0) === ( + (y / y))) | 0) | 0)) | 0) >>> 0)) >>> 0)) >>> 0) | 0)) | 0); }); ");
/*fuzzSeed-116066984*/count=1127; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((Math.pow(Math.asin((mathy0(Math.imul(y, x), Math.max((0 | 0), (0x0ffffffff >>> 0))) | 0)), ((y ? ( + ( ~ (x != (x >>> 0)))) : x) , (( + (( ! Math.fround((Math.fround(x) ? ( + x) : (x >>> 0)))) & ( ~ x))) | 0))) >>> 0) - Math.sinh(mathy2(( + mathy1(( - (Math.max(Math.fround((( + y) / y)), y) | 0)), ( + ((Math.fround(( + (Math.sqrt(x) >>> 0))) * x) | 0)))), (Math.fround((( + Math.atan2(x, mathy4(x, 0.000000000000001))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, -(2**53), 0x100000001, -Number.MIN_VALUE, -0x100000000, -0x100000001, 1/0, 0/0, 0x100000000, -1/0, -0x07fffffff, 0x080000001, Math.PI, 1, 42, -0x0ffffffff, 0x0ffffffff, 0, 1.7976931348623157e308, -(2**53+2), -(2**53-2), Number.MAX_VALUE, 0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1128; tryItOut("for(e in ((void options('strict_mode')))) t1 = new Uint8Array(b2, 18, 6);");
/*fuzzSeed-116066984*/count=1129; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[ '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new String(''), (-1/0), new String(''),  '\\0' , new String(''), (-1/0),  '\\0' , new String(''), (-1/0), new String(''), (-1/0), new String(''), new String(''), new String(''), new String(''),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new String(''),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , (-1/0),  '\\0' , (-1/0), (-1/0), new String(''), new String(''), (-1/0),  '\\0' ,  '\\0' , new String(''), (-1/0), new String(''),  '\\0' ,  '\\0' , (-1/0),  '\\0' ,  '\\0' , new String(''), (-1/0), new String(''), new String(''), new String(''), (-1/0),  '\\0' ,  '\\0' , new String(''),  '\\0' ,  '\\0' ,  '\\0' , (-1/0), new String(''),  '\\0' ,  '\\0' , new String(''),  '\\0' ,  '\\0' , new String(''),  '\\0' , (-1/0),  '\\0' ]) { (void schedulegc(g1)); }");
/*fuzzSeed-116066984*/count=1130; tryItOut("\"use strict\"; while((/*MARR*/[new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), Infinity, undefined, new String('q'), undefined, new Boolean(true), new Boolean(true), undefined, new String('q'), new Boolean(true), new String('q'), Infinity, new String('q'), new Boolean(true), new String('q'), new Boolean(true), Infinity, undefined, new String('q'), new Boolean(true), Infinity, new String('q'), new String('q'), new Boolean(true), Infinity, Infinity, new String('q'), undefined, Infinity, new Boolean(true), new String('q'), undefined, new String('q'), Infinity, new Boolean(true), new Boolean(true), new Boolean(true), undefined, Infinity, new String('q'), Infinity, Infinity, new Boolean(true), Infinity, undefined, new Boolean(true), new String('q'), new String('q'), undefined, new String('q'), undefined, Infinity, new String('q'), new String('q'), Infinity, new Boolean(true), undefined, undefined, new Boolean(true), Infinity, new Boolean(true), Infinity, undefined, new Boolean(true), new Boolean(true)].filter.yoyo(undefined << this).__defineGetter__(\"d\", (/*FARR*/[[,]].sort))) && 0){/*bLoop*/for (var hvqxvb = 0; hvqxvb < 36; ++hvqxvb) { if (hvqxvb % 5 == 3) { v2 = Object.prototype.isPrototypeOf.call(o2, m0); } else { print(x); }  }  }");
/*fuzzSeed-116066984*/count=1131; tryItOut("\"use strict\"; a0 = arguments;");
/*fuzzSeed-116066984*/count=1132; tryItOut("this.v0 = g2.a0.length;");
/*fuzzSeed-116066984*/count=1133; tryItOut("print(uneval(o2));");
/*fuzzSeed-116066984*/count=1134; tryItOut("switch(/*UUV2*/(x.atanh = x.findIndex)) { case 8: print(uneval(o2));break; default: Array.prototype.splice.apply(a2, [NaN, 17, s0,  /x/g , v0]);break;  }");
/*fuzzSeed-116066984*/count=1135; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1136; tryItOut("\"use strict\"; v2 = evalcx(\"v0 = true;\", g0);function x(x = (window = this.__defineSetter__(\"e\", [[1]].link)), x = 'fafafa'.replace(/a/g, new RegExp(\".\", \"im\")), NaN, x, x = (-27\n), y, x, x, x, e, x, this.x = \"\\uE181\", z =  /x/g , window, x) { \"use strict\"; m1 = new Map; } e0 = x;");
/*fuzzSeed-116066984*/count=1137; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116066984*/count=1138; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1139; tryItOut("testMathyFunction(mathy5, [-Number.MIN_VALUE, -1/0, 42, 0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000001, Number.MIN_VALUE, -(2**53), -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, 0, -0x100000001, -0x100000000, 2**53, -0, 2**53+2, Math.PI, 0x07fffffff, 1, -0x0ffffffff, 0/0, 0.000000000000001, -0x07fffffff, 1.7976931348623157e308, 0x100000001, 1/0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-116066984*/count=1140; tryItOut("g0.v0 = Object.prototype.isPrototypeOf.call(m1, p1);");
/*fuzzSeed-116066984*/count=1141; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (0xf9462205);\n    (Int8ArrayView[1]) = ((i1)+(i1)+(i1));\n    i0 = (!((i0) ? ((Math.fround(-0))) : (i0)));\n    switch (((0xd960b*((0xe0b50e6e) > (0x0)))|0)) {\n      case 1:\n        (Float64ArrayView[0]) = ((((Float32ArrayView[4096])) - ((144115188075855870.0))));\n      case 0:\n        {\n          (Float32ArrayView[4096]) = ((-18446744073709552000.0));\n        }\n        break;\n      case 0:\n        {\n          (Int8ArrayView[((i1)) >> 0]) = ((!(i0))-(i1));\n        }\n        break;\n      case -3:\n        switch ((imul((i1), (i0))|0)) {\n          case 0:\n            i1 = (i1);\n            break;\n          case -3:\n            (Int32ArrayView[(((+abs(((+(0.0/0.0))))) <= (3.094850098213451e+26))+(i0)-(i0)) >> 2]) = ((i1)-(i0));\n            break;\n        }\n        break;\n      case 0:\n        i1 = (!((((0xfa91fb6c)+(i1)+((0xf805c5bc) ? (0xf03adc97) : (0x23f60d81)))>>>((((((0x44030739) < (0xfcb58a46)))|0) != (~((0xffffffff) % (0x3659ee8))))+((524289.0) != (-4294967297.0)))) >= (0x6d439297)));\n      case -2:\n        i1 = ((~~(-536870912.0)));\n        break;\n      default:\n        return (((0x7f08322a) / (((i1))>>>(((144115188075855870.0) < (-73786976294838210000.0))))))|0;\n    }\n    i0 = (i1);\n    return ((((x))-(i0)))|0;\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ \"use strict\"; var zbnvnk = (4277); var rlfwlx = String.fromCharCode; return rlfwlx;})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53-2), 0x080000000, -1/0, -0x07fffffff, -0, Number.MAX_VALUE, 0x080000001, 0, -0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, 2**53+2, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, -0x100000001, -0x080000001, Math.PI, -0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, -0x100000000, 0x0ffffffff, 1, 2**53-2, -(2**53+2), 1/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1142; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy0(( + Math.pow((Math.fround(Math.hypot((y ? ((( ~ 0x080000000) | 0) | 0) : 1.7976931348623157e308), ( ~ ( - ( + y))))) | 0), ( + mathy2(( + ( + Math.pow(( + Math.pow(1/0, ( + Math.trunc(( + y))))), ( + ( ~ Math.PI))))), Math.fround((Math.fround(y) , Math.fround((( ~ y) | 0)))))))), ( + Math.hypot(( + ( + (Math.cosh((((y | 0) >> (y | 0)) | 0)) < ( + (Math.atan2((( + Math.acosh(((Math.asin(((y && ( + 0x080000001)) | 0)) | 0) | 0))) >>> 0), ((Number.MIN_VALUE ** -(2**53+2)) >>> 0)) >>> 0))))), ( + Math.sinh(x))))); }); testMathyFunction(mathy5, [-(2**53+2), -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), 0, 1/0, -0x100000000, 0.000000000000001, -Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, 1, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -0x0ffffffff, 0/0, 0x0ffffffff, 2**53+2, -0x080000000, 0x080000001, 2**53-2, 0x07fffffff, -0x07fffffff, -(2**53-2), Math.PI, 0x100000001, 2**53, Number.MAX_VALUE, 0x080000000, -1/0]); ");
/*fuzzSeed-116066984*/count=1143; tryItOut(" for  each(let a in undefined) {;yield [1,,]; }");
/*fuzzSeed-116066984*/count=1144; tryItOut("\"use asm\"; L:switch(d = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: undefined, }; })(-20 >>> \"\\uDC21\"), decodeURI)) { case 3: e1.has(o2);break; default: let (e) { throw c; }case 0: for (var v of v1) { Array.prototype.forEach.call(a1, f1); }break;  }");
/*fuzzSeed-116066984*/count=1145; tryItOut("mathy2 = (function(x, y) { return Math.log(mathy0((( - (Math.hypot(mathy1((42 << (( ~ 1.7976931348623157e308) | 0)), (mathy0((Math.max(1, y) | 0), (x | 0)) | 0)), (0x080000001 | 0)) | 0)) | 0), (Math.atan2(( + mathy0(( + Math.fround(( ~ ( + x)))), 1.7976931348623157e308)), ((((Math.pow(0x080000001, y) ^ ( + x)) | 0) / (x >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy2, [-0x100000000, 0x080000001, 0, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, Number.MIN_VALUE, 1, 42, -1/0, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), 0.000000000000001, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, -(2**53), Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, -0x080000000, -0x080000001, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 2**53, -0x07fffffff, -(2**53-2), -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-116066984*/count=1146; tryItOut("g2.offThreadCompileScript(\" '' \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /*MARR*/[(void 0), new Boolean(true), (yield x ? window : x), (void 0), (void 0), (void 0), new Boolean(true), (void 0), (void 0), (void 0), new Boolean(true), (void 0), new Boolean(true), (void 0), (void 0), (yield x ? window : x), (yield x ? window : x), (yield x ? window : x), (yield x ? window : x), (yield x ? window : x), new Boolean(true), (yield x ? window : x), new Boolean(true), (yield x ? window : x), (void 0), new Boolean(true), new Boolean(true), (void 0), new Boolean(true), (void 0), (void 0), (void 0), new Boolean(true), (void 0), (yield x ? window : x), new Boolean(true), new Boolean(true), (yield x ? window : x), (yield x ? window : x), new Boolean(true), (yield x ? window : x), (void 0), new Boolean(true), (yield x ? window : x), new Boolean(true), (yield x ? window : x), new Boolean(true), (yield x ? window : x), (yield x ? window : x), (void 0), new Boolean(true), new Boolean(true), (yield x ? window : x), new Boolean(true), (void 0), new Boolean(true), (yield x ? window : x), new Boolean(true), (yield x ? window : x), new Boolean(true), new Boolean(true), (void 0), (yield x ? window : x), (void 0), (yield x ? window : x), new Boolean(true), (yield x ? window : x), (yield x ? window : x), (yield x ? window : x), (void 0), new Boolean(true), (yield x ? window : x), new Boolean(true), (void 0), (yield x ? window : x), (void 0), new Boolean(true), (yield x ? window : x), new Boolean(true), new Boolean(true), (yield x ? window : x), new Boolean(true), new Boolean(true), (yield x ? window : x), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), (yield x ? window : x), (yield x ? window : x), new Boolean(true), (yield x ? window : x), (yield x ? window : x), new Boolean(true), new Boolean(true), (yield x ? window : x), new Boolean(true), (yield x ? window : x), (yield x ? window : x), new Boolean(true), (yield x ? window : x), new Boolean(true), (yield x ? window : x), (void 0), (void 0), new Boolean(true), (void 0), new Boolean(true), (yield x ? window : x), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true)].filter(x), noScriptRval: (x % 62 == 33), sourceIsLazy: this, catchTermination: false }));");
/*fuzzSeed-116066984*/count=1147; tryItOut("t0[6] = b1;");
/*fuzzSeed-116066984*/count=1148; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.log(((Math.log2(((( + Math.expm1(-1/0)) >>> 0) ^ Math.fround((((-0x100000000 | 0) > (y | 0)) | 0)))) >>> 0) || ( + (( + -0x0ffffffff) ? ( + Math.fround(Math.hypot(Math.fround(x), Math.fround((Math.cbrt((-Number.MIN_VALUE >>> 0)) >>> 0))))) : ( + x)))))); }); testMathyFunction(mathy3, [-0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 42, 0x07fffffff, 0/0, 0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0x080000000, 0, 1, -0, 1/0, -(2**53+2), -(2**53-2), Number.MAX_VALUE, 2**53, 0x100000001, -0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, 0x080000001, Math.PI, 1.7976931348623157e308, 0x0ffffffff, 2**53+2, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-116066984*/count=1149; tryItOut("mathy4 = (function(x, y) { return mathy1(Math.fround((mathy1((( ! Math.hypot(( + ( + Math.asin(( + (( - (x | 0)) | 0))))), x)) >>> 0), (( - 0x100000001) >>> 0)) >>> 0)), (( ~ ( ! (-1/0 | 0))) >>> 0)); }); testMathyFunction(mathy4, [0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, 0, -1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 0.000000000000001, -(2**53), 0x080000001, -0, Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, Math.PI, -(2**53+2), Number.MIN_VALUE, 2**53+2, -(2**53-2), -Number.MIN_VALUE, -0x100000001, -0x080000001, -Number.MAX_VALUE, 42, 2**53, -0x07fffffff, 0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 0x080000000, 0x100000000]); ");
/*fuzzSeed-116066984*/count=1150; tryItOut("mathy4 = (function(x, y) { return ( - (Math.acosh(( + mathy0(y, -(2**53+2)))) | 0)); }); testMathyFunction(mathy4, [-(2**53), 0x100000000, 0x080000000, 0/0, 1.7976931348623157e308, 42, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, 0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 0x100000001, -(2**53-2), 1, -0x080000001, -0x07fffffff, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 0.000000000000001, -1/0, 1/0, Math.PI, 0x080000001, -0x100000001, -(2**53+2), 2**53-2, 2**53, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000]); ");
/*fuzzSeed-116066984*/count=1151; tryItOut("mathy1 = (function(x, y) { return ( + mathy0((0x100000000 >> Math.fround(((Math.max(((( + 0) ? ((y === -(2**53+2)) | 0) : x) >>> 0), x) >>> 0) , mathy0(x, ( + (x >>> y)))))), Math.fround((Math.pow((y >>> 0), y) ? Math.log(Math.fround(Math.tan(Math.fround(x)))) : (( - (y | 0)) >>> 0))))); }); testMathyFunction(mathy1, [-0x07fffffff, 1.7976931348623157e308, 2**53, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 0, -Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), -1/0, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000000, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0x100000000, 0x080000001, Number.MAX_VALUE, 2**53-2, 1, -0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), 0x100000001, -0, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, 42, -0x100000000]); ");
/*fuzzSeed-116066984*/count=1152; tryItOut("\"use strict\"; yield  /x/g ;m1.get(e0);");
/*fuzzSeed-116066984*/count=1153; tryItOut("mathy4 = (function(x, y) { return Math.abs((Math.pow((Math.imul((( ~ (Math.atan2((Math.fround(Math.fround(x)) | 0), 0x0ffffffff) | 0)) | 0), x) | 0), Math.imul(( ~ x), Math.hypot(Math.sin(( + x)), x))) | 0)); }); testMathyFunction(mathy4, [(new Boolean(true)), 0.1, 1, true, ({toString:function(){return '0';}}), /0/, [], (new String('')), '0', undefined, false, 0, objectEmulatingUndefined(), (function(){return 0;}), ({valueOf:function(){return 0;}}), [0], ({valueOf:function(){return '0';}}), (new Boolean(false)), (new Number(-0)), '/0/', '\\0', -0, (new Number(0)), '', null, NaN]); ");
/*fuzzSeed-116066984*/count=1154; tryItOut("\"use strict\"; v1 = a2.length;");
/*fuzzSeed-116066984*/count=1155; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.sign((Math.pow(( ! ( + ((mathy0(2**53-2, x) || -0x07fffffff) ** 2**53+2))), mathy0(( + (x - (( - (y >>> 0)) >>> 0))), (Math.log2(Math.fround(y)) >>> 0))) | 0)); }); testMathyFunction(mathy1, [1, -0x080000000, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53, 0x0ffffffff, -Number.MAX_VALUE, -0x0ffffffff, -0x100000001, Number.MAX_VALUE, 0, 0x080000000, 0x100000000, -0x100000000, 0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, 1/0, 0x07fffffff, Math.PI, Number.MIN_VALUE, -0, 0x080000001, 42, -(2**53-2), -(2**53+2), 1.7976931348623157e308, 0.000000000000001, -0x080000001, -1/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1156; tryItOut("g0.a1.unshift(g0, eval(\"/* no regression tests found */\", [this.__defineGetter__(\"c\", (/*FARR*/[].sort(() =>  \"\" )))]), e1, o2, g2.v2);");
/*fuzzSeed-116066984*/count=1157; tryItOut("/*iii*/var szfhlp = new SharedArrayBuffer(4); var szfhlp_0 = new Int32Array(szfhlp); var szfhlp_1 = new Uint16Array(szfhlp); print(szfhlp_1[0]); var szfhlp_2 = new Uint32Array(szfhlp); szfhlp_2[0] = -12; var szfhlp_3 = new Uint8ClampedArray(szfhlp); print(szfhlp_3[0]); szfhlp_3[0] = 6; /*RXUB*/var r = szfhlp_3[10]; var s = (({d: w + a, 0: szfhlp_0[0] })); print(s.split(r)); print(r.lastIndex); print(szfhlp_2);Array.prototype.pop.apply(o1.a1, [f1, g1.e1]);this;/*hhh*/function vyzuud(window, z = x){s1 += s1;}");
/*fuzzSeed-116066984*/count=1158; tryItOut("L:for([\u0009d, b] = (Math.hypot(-0,  '' )) in ({NaN: 28 })) ;");
/*fuzzSeed-116066984*/count=1159; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(p2, a1);");
/*fuzzSeed-116066984*/count=1160; tryItOut("\"use strict\"; /*bLoop*/for (var gopsms = 0; gopsms < 108; ++gopsms) { if (gopsms % 5 == 0) { v0 = b1[\"y\"]; } else { print( '' ); }  } ");
/*fuzzSeed-116066984*/count=1161; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1162; tryItOut("\"use strict\"; v0 = NaN;{}");
/*fuzzSeed-116066984*/count=1163; tryItOut("mathy1 = (function(x, y) { return (((Math.tanh((Math.min((Math.hypot(y, ( ~ (( ~ (Number.MAX_VALUE >>> 0)) >>> 0))) | 0), (Math.tanh((y != Math.round(-0x100000001))) | 0)) | 0)) | 0) === (( + Math.hypot(( + ((Math.pow(x, x) >= ( + Math.sin(Math.asinh(2**53+2)))) || Math.fround((1/0 === (Math.sqrt(( + y)) >>> 0))))), ( + Math.fround((Math.fround((1 === Math.imul(-0x0ffffffff, 0/0))) & Math.fround(x)))))) | 0)) | 0); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 1/0, -(2**53), 42, 0x100000000, Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, -0x080000001, -0x080000000, 1.7976931348623157e308, 2**53, Math.PI, 0.000000000000001, 0/0, -1/0, Number.MAX_VALUE, -(2**53-2), 1, 0x0ffffffff, 2**53+2, -0x07fffffff, -0x0ffffffff, -0, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, 2**53-2, 0]); ");
/*fuzzSeed-116066984*/count=1164; tryItOut("/*tLoop*/for (let a of /*MARR*/[033, 033, new Number(1), 033, new Number(1), 033, 033, new Number(1), 033, new Number(1), 033, 033, new Number(1), 033, 033, 033, 033, 033, 033, 033, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), 033, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), 033, new Number(1), 033, 033, new Number(1), 033, new Number(1), 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, 033, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), 033, new Number(1), 033, new Number(1), 033, new Number(1), 033, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), 033, 033, new Number(1), 033, 033, 033, 033, new Number(1), new Number(1), new Number(1), 033, 033, new Number(1), new Number(1), 033, 033, 033, new Number(1), new Number(1), 033, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), 033, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), 033, 033, new Number(1), 033, new Number(1), 033, new Number(1), 033, 033, 033, 033, 033, 033, new Number(1), new Number(1), new Number(1), 033, new Number(1), 033, 033, 033, 033, new Number(1), 033, new Number(1), new Number(1), 033, new Number(1), 033, new Number(1), 033, 033, 033, 033, 033, new Number(1), new Number(1), 033, 033, new Number(1), 033, 033]) { /*oLoop*/for (let dyjwrs = 0; dyjwrs < 54; ++dyjwrs) { v2 = (o1.t0 instanceof i2); }  }");
/*fuzzSeed-116066984*/count=1165; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\3)/m; var s = (String( /x/ )); print(r.exec(s)); ");
/*fuzzSeed-116066984*/count=1166; tryItOut("testMathyFunction(mathy0, [-0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, 0/0, 1/0, 0.000000000000001, 1, 0x100000000, Number.MIN_SAFE_INTEGER, -0, -0x080000001, 0, -(2**53), 0x080000000, 1.7976931348623157e308, 42, -0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, -(2**53-2), -1/0, 0x0ffffffff, -Number.MAX_VALUE, 2**53, Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 0x07fffffff, 0x100000001, -0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1167; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ Math.min(( + (( + Math.imul(Math.max(( + (( + Math.log10((y >>> 0))) ? ( + x) : ( + y))), (( ! (( + (( + x) ? 0x100000001 : ( + -(2**53+2)))) >>> 0)) >>> 0)), x)) % ( + Math.sqrt(x)))), Math.atan2(mathy2(( - x), Math.fround(Math.sign(Math.pow(x, Math.fround(x))))), (Math.fround((y >= (Math.asin((( ~ (( + (( + x) ? ( + x) : -0x080000000)) | 0)) | 0)) | 0))) | 0)))); }); ");
/*fuzzSeed-116066984*/count=1168; tryItOut("\"use strict\"; g0.v2 = true;");
/*fuzzSeed-116066984*/count=1169; tryItOut("e0.delete(p0);");
/*fuzzSeed-116066984*/count=1170; tryItOut("\"use strict\"; print((x ? (/\\W*?(?:\\u396E\\b)*?|(?=.|\\w)|(?!.){3,7}|(?!(\\B|\\u1f19+)+)*?/gy + this) : (-0)(-26, x)));\nv1 = a2.every((function(j) { if (j) { try { s0 += this.s1; } catch(e0) { } m2 = new Map(h2); } else { try { o0.i2.next(); } catch(e0) { } try { f2(v0); } catch(e1) { } s2 = o1.a0[16]; } }), s2);\n");
/*fuzzSeed-116066984*/count=1171; tryItOut("\"use strict\"; /*vLoop*/for (var oqbzet = 0; oqbzet < 7; ++oqbzet) { z = oqbzet; print(x); } ");
/*fuzzSeed-116066984*/count=1172; tryItOut("\"use strict\"; v0 = o2.i2[\"8\"];");
/*fuzzSeed-116066984*/count=1173; tryItOut("/*RXUB*/var r = /((?=\\D)|[^\\w]($|\\S)?)|(?=(?!\\2)(\\B|[^]|\u52e8|.{2,4}*?)|.)/gy; var s = \"\\u5786aa\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-116066984*/count=1174; tryItOut("m2.set(delete eval.x, f0);");
/*fuzzSeed-116066984*/count=1175; tryItOut("/*tLoop*/for (let y of /*MARR*/[x, 0x080000000, x, x, 0x080000000, 0x080000000, x, x, 0x080000000, x, x, x, 0x080000000, 0x080000000, x, 0x080000000, x, 0x080000000, x, x, 0x080000000, x, x, x, x, x, x, x, x, x, x, x, 0x080000000, x, 0x080000000, 0x080000000, 0x080000000, x, 0x080000000, 0x080000000, x, 0x080000000, x, 0x080000000, x, 0x080000000, 0x080000000, 0x080000000, x, x, x, x, x, x, 0x080000000, 0x080000000, x, x, 0x080000000, 0x080000000, 0x080000000, x, x, x, x, 0x080000000, x, x, 0x080000000, 0x080000000, x, x, 0x080000000, x, x, x, 0x080000000, 0x080000000, x, x, x, x]) { -11; }function x(x)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 36893488147419103000.0;\n    return +((+(1.0/0.0)));\n  }\n  return f;/*hhh*/function sewknn(NaN){( \"\" );}/*iii*/print(sewknn);");
/*fuzzSeed-116066984*/count=1176; tryItOut("\"use strict\"; /*infloop*/for(var window in ((function shapeyConstructor(qojlnt){\"use strict\"; return this; })(Math.log(2)))){this.m1 + e1; }");
/*fuzzSeed-116066984*/count=1177; tryItOut("t2 = new Uint16Array(a1);");
/*fuzzSeed-116066984*/count=1178; tryItOut("\"use strict\"; /*UUV2*/(x.toString = x.isInteger);");
/*fuzzSeed-116066984*/count=1179; tryItOut("\"use strict\"; v1[\"__count__\"] = g1.b0;");
/*fuzzSeed-116066984*/count=1180; tryItOut("for(let b in []);");
/*fuzzSeed-116066984*/count=1181; tryItOut("\"use strict\"; \"use asm\"; a2[2] = (window.toString(-1125899906842625, this));");
/*fuzzSeed-116066984*/count=1182; tryItOut("p2[\"apply\"] = this.i0;");
/*fuzzSeed-116066984*/count=1183; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xf9ba9719);\n    return (((0x5d2ffe1a)+(-0x8000000)))|0;\n    {\n      d1 = (d1);\n    }\n    return (((0xbefdf428)-((+atan2(((+(-1.0/0.0))), ((d1)))) == (6.044629098073146e+23))-(0xf9882e69)))|0;\n  }\n  return f; })(this, {ff: (encodeURI)(x, (4277))}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000000, 0/0, Math.PI, -0x100000000, -0x0ffffffff, 1, -0x100000001, 2**53, 2**53-2, -0x080000000, -0x07fffffff, -0, -(2**53), -(2**53+2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, -1/0, -(2**53-2), 0.000000000000001, Number.MIN_VALUE, 2**53+2, -0x080000001, 0x080000001, 42, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, 1/0, 0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1184; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.max(Math.cos(Math.acos(( - x))), (Math.acos((( + Math.pow(( + x), ( + ( ~ (Math.fround(( - Math.fround(x))) | 0))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [0x100000000, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001, -0x0ffffffff, -0x080000000, -0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), -(2**53-2), Number.MAX_VALUE, -0, -0x080000001, 0x080000001, Number.MIN_VALUE, 2**53, 2**53+2, -Number.MAX_VALUE, 0x100000001, -0x100000001, 1, -0x100000000, 1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, Number.MIN_SAFE_INTEGER, 0, Math.PI, 42, -(2**53+2)]); ");
/*fuzzSeed-116066984*/count=1185; tryItOut("v1 = (e2 instanceof o2);");
/*fuzzSeed-116066984*/count=1186; tryItOut("\"use asm\"; {Array.prototype.reverse.apply(g2.a0, [p1]);a0.toSource = f0; }");
/*fuzzSeed-116066984*/count=1187; tryItOut("/*oLoop*/for (let hvbeuw = 0; hvbeuw < 126; ++hvbeuw) { o1.t2.set(g0.t0, 3); } ");
/*fuzzSeed-116066984*/count=1188; tryItOut("\"use strict\"; Object.defineProperty(this, \"v0\", { configurable: x, enumerable: arguments[\"log\"] = x.yoyo(\"\\u78B4\"),  get: function() {  return g0.eval(\"d = new RegExp(\\\"(?:(?=[^]))+|((?!(.))\\\\\\\\cH|.{1}|([^]{1,}|[\\\\\\\\d\\\\\\\\x08\\\\\\\\uB38F\\\\u008f-\\\\\\\\u3236]*))?\\\", \\\"g\\\");print((({x: ((function factorial_tail(nithlq, kcdmlj) { ; if (nithlq == 0) { ; return kcdmlj; } ; return factorial_tail(nithlq - 1, kcdmlj * nithlq);  })(\\\"\\\\uE5C1\\\", 1))})));\"); } });");
/*fuzzSeed-116066984*/count=1189; tryItOut("e1.add(h0);");
/*fuzzSeed-116066984*/count=1190; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(Math.cosh(((( + Math.min(( + x), ((Math.imul(Math.fround(x), Math.fround(mathy1(y, 1/0))) >>> 0) - ( + Math.log1p(0/0))))) !== ( + ( + ( + Math.fround(Math.imul(Math.fround(x), ((Math.max((mathy3(( + -Number.MAX_SAFE_INTEGER), x) | 0), x) | 0) | 0))))))) | 0)), (Math.hypot((( ~ (Math.log2((Math.tanh((Math.tanh((y >>> 0)) | 0)) >>> 0)) >>> 0)) >>> 0), ((Math.max(y, (Math.imul(x, ( + Math.tanh((-Number.MIN_VALUE >>> 0)))) | 0)) << ((y && ((Math.cosh(( + y)) | 0) >>> 0)) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1), new Number(1), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1), new Number(1), new Number(1), new Number(1.5), new Number(1), new Number(1.5), new Number(1), new Number(1), new Number(1.5), new Number(1), new Number(1.5), new Number(1), new Number(1.5), new Number(1), new Number(1)]); ");
/*fuzzSeed-116066984*/count=1191; tryItOut("a0.shift(i0);");
/*fuzzSeed-116066984*/count=1192; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.min((Math.atan2(((((( + mathy0(( + ( + Math.max(( + y), Math.fround(y)))), -(2**53-2))) >>> 0) % Math.fround(mathy0(Math.fround(y), Math.fround((Math.hypot((y >>> 0), (x >> y)) >>> 0))))) >>> 0) | 0), ((Math.tanh(( + (mathy0((y >>> 0), (x >>> 0)) | 0))) | 0) | 0)) | 0), ((( ! Math.atan2(y, Math.fround(Math.imul((y | 0), Math.fround(x))))) >>> 0) ** ( + ( + Math.atan(( + ( + Math.trunc(0x080000000)))))))); }); testMathyFunction(mathy1, [2**53, -0x100000001, 0, -0x07fffffff, -1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000, 0x080000001, 42, 0x100000001, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, 0/0, -(2**53), 2**53-2, Number.MIN_VALUE, -0x100000000, Math.PI, -0x0ffffffff, 2**53+2, 1.7976931348623157e308, 1/0, -0x080000001, -0x080000000, 0x100000000, 0x07fffffff, 0x0ffffffff, -0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1193; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.sign(( + Math.imul(( + Math.ceil(( + Math.sin(y)))), Math.expm1(mathy4((mathy3(( + (x != x)), ( + -(2**53-2))) >>> 0), Math.fround(0.000000000000001))))))); }); testMathyFunction(mathy5, [(new Boolean(true)), -0, (function(){return 0;}), undefined, objectEmulatingUndefined(), [], null, '\\0', NaN, (new Number(-0)), 0, (new Boolean(false)), '/0/', ({valueOf:function(){return 0;}}), 0.1, /0/, false, '', (new String('')), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), (new Number(0)), [0], '0', 1, true]); ");
/*fuzzSeed-116066984*/count=1194; tryItOut("with({}) let(x = z = null, d) { let(antjtu, ofelwa, b = undefined, \u3056, hyrzfk, x, zzeqju, b) { let(x) ((function(){\u3056 = \u3056;})());}}");
/*fuzzSeed-116066984*/count=1195; tryItOut("\"use strict\"; o1.m2.toString = (function() { try { /*ODP-3*/Object.defineProperty(g1.g2.m1, \"getMonth\", { configurable: (x % 5 == 1), enumerable: new (Set.prototype.has)(, x), writable: (x % 2 == 1), value: h0 }); } catch(e0) { } i0.send(g0.v2); return e1; });");
/*fuzzSeed-116066984*/count=1196; tryItOut("\"use strict\"; x = (-0.valueOf(\"number\")).watch(x, (1 for (x in []))), x = -13, ihbyqp, twhlxk;o2.toString = f1;");
/*fuzzSeed-116066984*/count=1197; tryItOut("\"use strict\"; [,,z1];");
/*fuzzSeed-116066984*/count=1198; tryItOut("\"use strict\"; a1.unshift(e2, g2, f0);");
/*fuzzSeed-116066984*/count=1199; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+((Float32ArrayView[((i0)*-0x6e630) >> 2]))));\n  }\n  return f; })(this, {ff: Object.prototype.__defineSetter__}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 0x0ffffffff, -0x100000001, -0x07fffffff, -(2**53-2), 1, 0/0, 0x080000001, -0, Number.MAX_VALUE, -0x0ffffffff, 1/0, 1.7976931348623157e308, -0x080000001, 2**53-2, 0x100000001, -Number.MIN_VALUE, -(2**53+2), -(2**53), 2**53+2, -1/0, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, 0, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, 0x07fffffff, -0x100000000]); ");
/*fuzzSeed-116066984*/count=1200; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.fround(( - ( + Math.atan((( + x) + ( + Math.fround(Math.ceil(Math.fround(Math.fround(Math.atan(Math.fround(y))))))))))))); }); testMathyFunction(mathy5, [-1/0, -0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), 1, 0x100000000, -0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, 42, 0/0, -0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 2**53+2, -(2**53+2), 1.7976931348623157e308, 0x080000001, -0x080000000, -Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), -0x100000001, -0x080000001, Math.PI, 0x100000001]); ");
/*fuzzSeed-116066984*/count=1201; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1202; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1203; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.atan2((Math.atan(((Math.cos(Math.atan2(x, Math.fround((Math.fround(Number.MIN_SAFE_INTEGER) !== Math.fround(y))))) | 0) >>> 0)) | 0), Math.fround((Math.atanh((Math.imul((Math.fround((-0x080000001 && x)) - Math.fround(y)), (Math.atan2((y | 0), y) | 0)) >>> 0)) | 0)))); }); testMathyFunction(mathy0, [-1/0, -0x100000000, -Number.MAX_VALUE, 0x100000001, 0.000000000000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, 0/0, -0x07fffffff, -0, 1/0, 0x080000001, 0, Math.PI, 1, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 2**53, Number.MIN_VALUE, 1.7976931348623157e308, 42, Number.MAX_VALUE, 0x0ffffffff, -0x080000001, 0x07fffffff, -0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2]); ");
/*fuzzSeed-116066984*/count=1204; tryItOut("g1.h2.keys = (function mcc_() { var qdxdcv = 0; return function() { ++qdxdcv; if (true) { dumpln('hit!'); try { a2 = /*PTHR*/(function() { for (var i of (function(x, y) { \"use strict\"; return (( + ( ~ (( ! Math.sinh(( ! y))) | 0))) !== Math.fround((Math.sqrt(( ! Math.fround(Math.pow(( - Math.max(( ~ x), x)), y)))) == Math.log1p(((((( ~ (( ! y) >>> 0)) >>> 0) | 0) < (( + Math.sign(Math.sign(x))) | 0)) >>> 0))))); })) { yield i; } })(); } catch(e0) { } try { a2.splice(-4, 16); } catch(e1) { } /*MXX2*/g0.RangeError.prototype = m2; } else { dumpln('miss!'); s0 += 'x'; } };})();");
/*fuzzSeed-116066984*/count=1205; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var asin = stdlib.Math.asin;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var acos = stdlib.Math.acos;\n  var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = ((0x191f8f90) < (0x621f51ba));\n    }\n    i1 = (i1);\n    i0 = (i1);\nprint(uneval(m0));    {\n      i1 = (i1);\n    }\n    {\n      {\n        {\n          i1 = (i1);\n        }\n      }\n    }\n    i1 = (i0);\n    i0 = ((((0x10e4ae9f) / (0xffffffff)) >> (0xfffff*((((0xf8791173)*0xbd4fa) ^ (((-17592186044417.0) < (576460752303423500.0)))) <= ((0xf1ca9*((-1.00390625) == (33554432.0)))|0)))) == (-0x72be325));\n    i0 = (((((+(((0x7d0039fe))>>>((0xd49e437d)))) > (-268435456.0))+(i1)) ^ ((-0x8000000)+(/*FFI*/ff((((i1) ? (-1.125) : (-137438953473.0))), ((((-0x8000000)-(0xff5bb002)) >> ((-0x60a95da)-(0xa1738de0)))), ((~((-0x8000000)+(0xbe4529ae)+(0x80893eaa)))), ((((0xfba5af0c))|0)), ((-68719476737.0)), ((8388607.0)), ((32769.0)), ((1.0009765625)), ((-18446744073709552000.0)), ((-2.4178516392292583e+24)), ((65.0)), ((-1152921504606847000.0)), ((-4503599627370497.0)), ((-549755813889.0)), ((281474976710655.0)), ((1.2089258196146292e+24)), ((34359738369.0)), ((-65.0)), ((-4611686018427388000.0)), ((536870913.0)), ((-16777217.0)), ((-9.44473296573929e+21)), ((-17179869185.0)), ((-2251799813685249.0)), ((-5.0)), ((-4611686018427388000.0)), ((-8796093022209.0)), ((-2.3611832414348226e+21)), ((16777217.0)), ((268435455.0)), ((-16385.0)), ((-281474976710655.0)), ((-288230376151711740.0)), ((-8388609.0)))|0))) < ((((+(1.0/0.0)) > (+asin(((-0.0625)))))) >> ((i0)+((0x1caeb694)))));\n    (Int8ArrayView[((i0)) >> 0]) = (((0x0) < (((i1)+(i0))>>>(((0x4c8d1e6e) <= (0x0))-(i1))))-(i0));\n    {\n      {\n        i1 = (0x3f677159);\n      }\n    }\n    i0 = ((imul((((i0) ? (i1) : (/*FFI*/ff(((8388607.0)), ((-513.0)), ((-18014398509481984.0)), ((-9.671406556917033e+24)), ((-4611686018427388000.0)), ((4294967296.0)), ((-1.0625)), ((35184372088833.0)), ((-67108865.0)), ((-7.555786372591432e+22)), ((576460752303423500.0)))|0)) ? (intern(\"\\uCC63\")) : ((0x9b6e4ba0) > (((0x22fe6d25))>>>((0xfb6b99c1))))), (i1))|0));\n    {\n      (Float64ArrayView[1]) = ((Float32ArrayView[4096]));\n    }\n    {\n      (Float64ArrayView[0]) = ((((-1.015625)) - (((((intern((eval(\"\\\"use strict\\\"; \\\"use asm\\\"; o2.e1.has(o2);\",  /x/ )))\n))) - ((2.4178516392292583e+24))))));\n    }\n    i0 = ((0xe069960b) > (((!(i0)))>>>(-0xfffff*((~(-(i0))) == (((i1)) | ((0xffc2e728)+(0xc94061de)+(0x31284302)))))));\n    i1 = (0xd8bca956);\n    i1 = (i0);\n    {\n      i1 = (/*FFI*/ff((Object.defineProperty(c, \"toString\", ({value: x, writable: false, configurable: false, enumerable: true})).unwatch(\"valueOf\")), ((((i0)-(i1)-(i0)) >> ((i1)))), ((((intern(x%=\n\"\\uE759\"))) - ((+pow(((+acos(((((64.0)) * ((-1025.0))))))), (((-1.03125) + (-2199023255552.0)))))))), ((((/*FFI*/ff(((((0xffffffff)-(0x62f032d9)) ^ ((0xf9bcb834)+(0xfe4df763)-(0xa0b7610b)))), ((295147905179352830000.0)))|0)) >> ((i1)))), ((Infinity)), ((((i1)) << ((/*FFI*/ff(((36893488147419103000.0)), ((2.3611832414348226e+21)), ((4398046511105.0)), ((-2049.0)), ((-9223372036854776000.0)))|0)))), ((imul((/*FFI*/ff(((-1048577.0)), ((-3.777893186295716e+22)), ((147573952589676410000.0)), ((513.0)))|0), (0x9102ac78))|0)), ((abs((((0x4d18af00)) & ((0xfe77e850))))|0)), ((((0xb5f249d4)))), ((1.0)), ((-1.00390625)), ((-4194305.0)), ((281474976710656.0)), ((-35184372088833.0)), ((-1099511627777.0)))|0);\n    }\n    i0 = (0x211dc709);\n    {\n      return ((-((((!(((-0x89262*(i0)))))-((-1152921504606847000.0) == ((32.0) + (-6.189700196426902e+26)))) >> ((i0)+((~~(+abs(((17592186044417.0)))))))))))|0;\n    }\n    i1 = (0x10c8546b);\n    (Int32ArrayView[4096]) = ((Math.pow(-1, (d++ ? window &= a : -7)))+(0xda52ebe8));\n    (Float32ArrayView[4096]) = ((7.555786372591432e+22));\n    return ((0x8c400*((((i1)-(((0x7fffffff) >= (0x32af15fb)) ? ((0xb81b35c5)) : (i0))) | ((i1))))))|0;\n    i0 = (i1);\n    return (((i0)-(i0)))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=1206; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x100000001, 42, -0x080000000, 1/0, -0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, 0/0, -(2**53-2), 2**53, 0x07fffffff, 0x080000000, -(2**53+2), 1.7976931348623157e308, -0, -Number.MAX_VALUE, 1, 0.000000000000001, 0x080000001, -0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, Math.PI, Number.MIN_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, -0x080000001, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1207; tryItOut("mathy1 = (function(x, y) { return ( + (Math.hypot((Math.pow(( + x), ( + Math.fround(Math.max(((((Math.round(y) | 0) === Math.fround(x)) | 0) >>> 0), (( + Math.hypot(( + 0x080000001), ( + ( ~ x)))) | 0))))) | 0), ( + (Math.imul(((Math.atan((Math.fround((( + -(2**53+2)) && ( + x))) | 0)) | 0) >>> 0), (x | 0)) | 0))) * (Math.cbrt(Math.hypot((((Math.round((y | 0)) >>> 0) ? x : (-(2**53) | 0)) | 0), Math.fround(Math.imul(( + Math.round(((( ~ ( + x)) >>> 0) | 0))), 0x0ffffffff)))) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), new Boolean(false)]); ");
/*fuzzSeed-116066984*/count=1208; tryItOut("mathy4 = (function(x, y) { return (((Math.log(Math.clz32(( ! x))) || (Math.fround(Math.trunc(x)) & ( + (((y >>> 0) ** (x >>> 0)) === x)))) ? mathy3(y, ((( + Math.hypot((Number.MAX_SAFE_INTEGER >>> 0), Math.hypot(0, x))) >>> 0) ? ( + mathy1(x, ((0x0ffffffff | 0) || y))) : (Math.log2(((mathy1((Math.log1p(y) | 0), ( + Number.MIN_VALUE)) >>> 0) >>> 0)) >>> 0))) : (( ~ ((( + (( ! (y | 0)) | 0)) | 0) >>> 0)) >>> 0)) ^ Math.atanh(Math.hypot(Math.hypot(Math.fround(( + x)), (Math.fround((Math.fround(Math.pow(Math.fround(x), y)) , Math.fround(y))) ** Math.exp(-0x080000000))), (( ~ ((mathy1((y | 0), (x | 0)) | 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [0x080000000, -0x080000000, 0x100000000, 2**53+2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, 0x080000001, -Number.MAX_VALUE, 2**53, -0x100000000, -0x0ffffffff, 1/0, 0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 42, 0/0, Math.PI, -(2**53+2), 0x100000001, 0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -1/0, Number.MIN_VALUE, -(2**53-2), -0, 1.7976931348623157e308, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1209; tryItOut("\"use strict\"; for (var v of e2) { try { v1 = new (\"\\uB62D\")(true) = ((x) = ((4277) === x)); } catch(e0) { } try { f2 = (function() { for (var j=0;j<30;++j) { f0(j%2==0); } }); } catch(e1) { } t1.set(a1, 2); }");
/*fuzzSeed-116066984*/count=1210; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (((( + Math.atan2(( + Math.cbrt(-Number.MIN_VALUE)), ( ~ (y | 0)))) * (Math.atan2(x, x) <= Math.round((( + ( ! ( + y))) | 0)))) & (( + ((((Math.fround(Math.log10(Math.fround(( ! x)))) | 0) - ( + Math.fround(Math.sqrt(x)))) >>> 0) ? Math.sin(mathy1(1/0, Math.fround(mathy0((y >>> 0), x)))) : ( + ((x >= (0x0ffffffff | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy4, [Math.PI, 0x100000001, 0x080000001, 0x07fffffff, 1/0, -(2**53-2), -0, 1, 0x100000000, 42, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, -0x100000000, Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -0x07fffffff, -0x100000001, -(2**53), -(2**53+2), -1/0, 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 1.7976931348623157e308, 0/0, 0, 0x080000000]); ");
/*fuzzSeed-116066984*/count=1211; tryItOut("for (var p in this.f2) { try { g1.g2 = this; } catch(e0) { } v1 = o1.g2.runOffThreadScript(); }");
/*fuzzSeed-116066984*/count=1212; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ~ (( + Math.min(( + (( ~ (( + Math.log1p((( + Math.fround(-0x080000001)) >>> 0))) >>> 0)) >>> 0)), ( + y))) / Math.fround(Math.atan2(( + ( ! (( ! 0x080000000) | 0))), ( + Math.tanh(( ~ ( + 0x07fffffff)))))))); }); testMathyFunction(mathy1, [0.1, ({toString:function(){return '0';}}), null, 1, '', ({valueOf:function(){return '0';}}), (new String('')), undefined, true, [], 0, '\\0', false, (function(){return 0;}), -0, /0/, '0', [0], objectEmulatingUndefined(), (new Boolean(false)), (new Number(0)), (new Number(-0)), '/0/', (new Boolean(true)), NaN, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-116066984*/count=1213; tryItOut("let (wtsnna, x = (e) = eval = Proxy.createFunction(({/*TOODEEP*/})(this), Number.isNaN, function(q) { \"use strict\"; return q; }), xcdyee) { /*RXUB*/var r = new RegExp(\"\\\\1\", \"yim\"); var s = ((function factorial_tail(ijqjpn, wanexv) { ; if (ijqjpn == 0) { ; return wanexv; } ; return factorial_tail(ijqjpn - 1, wanexv * ijqjpn);  })(61951, 1)); print(uneval(s.match(r))); print(r.lastIndex);  }");
/*fuzzSeed-116066984*/count=1214; tryItOut("/*bLoop*/for (zgqwag = 0; zgqwag < 70; ++zgqwag) { if (zgqwag % 71 == 69) { var a = let (x = x) let (z) window;const z = [1], rriuqd, d = ({}), e, window, npipvq, \u3056, xwmzne;a; } else { e2.has(b1);yield; }  } ");
/*fuzzSeed-116066984*/count=1215; tryItOut("e1.add(o1);");
/*fuzzSeed-116066984*/count=1216; tryItOut("y = ({a2:z2});print(x);");
/*fuzzSeed-116066984*/count=1217; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.sqrt(Math.cbrt(( ! y))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, 0x100000000, -1/0, -(2**53), -(2**53-2), 0x07fffffff, -0x07fffffff, -Number.MIN_VALUE, 1, 1.7976931348623157e308, 42, Number.MAX_VALUE, 0, 2**53+2, 2**53, Math.PI, 0.000000000000001, -0x0ffffffff, 0x080000000, -0x100000000, -Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, -(2**53+2), 0x100000001, -0x080000000, 1/0]); ");
/*fuzzSeed-116066984*/count=1218; tryItOut("o0.v2 = true;");
/*fuzzSeed-116066984*/count=1219; tryItOut("window;");
/*fuzzSeed-116066984*/count=1220; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.pow((Math.pow(Math.cos(Math.tan(( + Math.exp(( + -Number.MAX_SAFE_INTEGER))))), ( + ( + ((( - Math.fround(x)) >>> 0) | 0)))) >>> 0), Math.fround(( + ((Math.acos((Math.pow((Math.fround(Math.clz32(((Math.atanh(x) >>> 0) | 0))) | 0), ( - ( + ( - (x | 0))))) | 0)) | 0) | 0)))); }); testMathyFunction(mathy4, /*MARR*/[4., 4., function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 4., function(){}, function(){}, function(){}, function(){}, function(){}, 4., 4., 4., 4., function(){}, function(){}, function(){}, 4., function(){}, function(){}, function(){}, 4., function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 4., 4., function(){}, 4., 4., function(){}, 4., function(){}, 4., function(){}, 4., 4., 4., 4., function(){}, 4., function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 4., 4., function(){}, 4., 4., 4., function(){}, function(){}, function(){}, 4., 4., function(){}, function(){}, function(){}, function(){}, 4., function(){}, 4., function(){}, 4., function(){}, 4., 4., function(){}, 4., function(){}, function(){}, function(){}, 4., function(){}, 4., 4., 4., 4., 4., 4., 4., 4., function(){}, 4., function(){}, 4., function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 4.]); ");
/*fuzzSeed-116066984*/count=1221; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1222; tryItOut("mathy2 = (function(x, y) { return ( ! (Math.atan2(( + Math.max(Math.fround(Math.hypot(Math.abs(( + x)), Math.atan2(( + Math.fround(Math.atan2(Math.fround(y), (x | 0)))), x))), Math.fround((Math.min(((y ? (0/0 >>> 0) : (x >>> 0)) >>> 0), ((x !== y) < (( - (Math.sqrt(y) >>> 0)) | 0))) | 0)))), (4277)) >>> 0)); }); testMathyFunction(mathy2, [2**53-2, -1/0, 0x100000001, 2**53+2, -0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, -0, -0x080000001, Number.MAX_VALUE, 0/0, 0x080000001, 0, -Number.MIN_VALUE, 0x100000000, 0.000000000000001, -0x07fffffff, -(2**53), 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), 2**53, -0x100000000, -0x080000000, 0x0ffffffff, 42, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1223; tryItOut("h0.has = g0.f0;");
/*fuzzSeed-116066984*/count=1224; tryItOut("\"use strict\"; (timeout(1800));");
/*fuzzSeed-116066984*/count=1225; tryItOut("\"use strict\"; v1 = (h2 instanceof o0);");
/*fuzzSeed-116066984*/count=1226; tryItOut("/*iii*/(new RegExp(\"((?:\\\\1)|(^){1}{16777215})(?!$|\\\\b\\\\b+)\\\\w{4,}\", \"gym\"));/*hhh*/function jlnczo(){m2 = a0[7];}");
/*fuzzSeed-116066984*/count=1227; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy4, [0/0, 42, Math.PI, -Number.MAX_VALUE, -0x100000000, 0x080000000, -1/0, -0x080000000, 2**53-2, Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, 0.000000000000001, -(2**53-2), -0x100000001, 0x100000001, 1.7976931348623157e308, -0, -(2**53), Number.MIN_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -0x0ffffffff, -Number.MIN_VALUE, 1, 0, -(2**53+2), 0x07fffffff, 2**53+2]); ");
/*fuzzSeed-116066984*/count=1228; tryItOut("Array.prototype.shift.call(a1, i1);");
/*fuzzSeed-116066984*/count=1229; tryItOut("testMathyFunction(mathy5, [-0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0, 0x100000001, 1.7976931348623157e308, 0/0, 1/0, Math.PI, 42, 2**53+2, 0x100000000, -1/0, -(2**53+2), 0x07fffffff, 1, -0x100000000, -0x07fffffff, -0x0ffffffff, -0x080000001, -(2**53-2), 0x080000000, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, 2**53-2, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1230; tryItOut("i0.next();o0.s1 = g2.objectEmulatingUndefined();");
/*fuzzSeed-116066984*/count=1231; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116066984*/count=1232; tryItOut("testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, Math.PI, -0x080000000, -0x080000001, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 42, -(2**53), -0x0ffffffff, 0x100000001, -(2**53+2), -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, -0, 1/0, 0, -Number.MAX_VALUE, 0/0, 0x100000000, -1/0, 1, 2**53-2, 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1233; tryItOut("\"use strict\"; var iilubx = new SharedArrayBuffer(0); var iilubx_0 = new Uint16Array(iilubx); iilubx_0[0] = -0; var iilubx_1 = new Uint8Array(iilubx); print(iilubx_1[0]); iilubx_1[0] = 25; var iilubx_2 = new Int16Array(iilubx); iilubx_2[0] = 13; var iilubx_3 = new Int8Array(iilubx); var iilubx_4 = new Uint8ClampedArray(iilubx); /*RXUB*/var r = new RegExp(\"(\\\\B){2,}|.+.(?!(?=[^])+)+(?:(?=\\u00e9|[\\\\n-\\\\cI\\\\x53])|(?=$\\\\W){3}*?)\\\\3{1}|.\\\\B|\\\\f|[^]{4,}+\", \"gi\"); var s = \"\"; print(r.test(s)); const w = (window.yoyo(d\u000c) > /*RXUE*/ /x/ .exec(\"\"));for (var v of i2) { g2.o2.toString = (function mcc_() { var cnzada = 0; return function() { ++cnzada; f1(/*ICCD*/cnzada % 9 == 4);};})(); }g0.s1.toString = (function() { try { v0 = g2.eval(\"v1 = -0;\"); } catch(e0) { } try { g1.v1 = Object.prototype.isPrototypeOf.call(o2.t2, f0); } catch(e1) { } /*RXUB*/var r = this.r0; var s = s0; print(s.match(r)); print(r.lastIndex);  throw i2; });b1 = t0.buffer;a1 = new Array;print(iilubx_4[3]);v2 = evalcx(\"v1 = evaluate(\\\"/* no regression tests found */\\\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: undefined, noScriptRval: false, sourceIsLazy: window, catchTermination: true }));\", g1);print(iilubx_1[2]);");
/*fuzzSeed-116066984*/count=1234; tryItOut("");
/*fuzzSeed-116066984*/count=1235; tryItOut("print(x);m2.has( /x/g );\nm0.delete(f2);\n");
/*fuzzSeed-116066984*/count=1236; tryItOut("\"use strict\"; switch(/(?:(?=(?:\\b)+|[^]{0,}\u8179)+)+/gi) { case 2: /*RXUB*/var r = /(?:(?=\\\u0017{3})|(?:\\D)?\\1)|((?!.))^^{3,7}|\\W\\w|[\\B\u0008]|\\x43\\b+\\1[^]|\\cQ?(.){1,}*?(\\1)\\B/yim; var s = \"\\u0012\\u16a9\\n\\u0012\\u16a9\\n\\u0012\\u16a9\\n\\u0012\\u16a9\\n\\n\\u1584\"; print(s.replace(r,  \"\" )); break; if(false) this.g1.a0 = arguments; else  if ( \"\" ) v2 = null; else {( '' );v0 = a0.length; }case Math.imul(d = x, 15): default:  }");
/*fuzzSeed-116066984*/count=1237; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1238; tryItOut("let ttxbes, c, tsyjks, d = (4277), xnkyzq, e;((yield (window = w)));");
/*fuzzSeed-116066984*/count=1239; tryItOut("\"use asm\"; a0 = arguments;");
/*fuzzSeed-116066984*/count=1240; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(t0, b0);y;");
/*fuzzSeed-116066984*/count=1241; tryItOut("\"use strict\"; a0.shift(m0);");
/*fuzzSeed-116066984*/count=1242; tryItOut("mathy0 = (function(x, y) { return (Math.sqrt(Math.fround(( ! Math.min((y < ( + Math.round(( + (y ? 1 : x))))), Math.log1p((x - x)))))) | 0); }); testMathyFunction(mathy0, [-0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, -Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, 0x100000000, 42, 0/0, 0x100000001, 1/0, Number.MIN_VALUE, 0, -0x07fffffff, -(2**53), 2**53, -1/0, -0x100000001, 0x080000001, 1.7976931348623157e308, 2**53+2, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, -0, 0x07fffffff]); ");
/*fuzzSeed-116066984*/count=1243; tryItOut("\"use asm\"; selectforgc(g1.o1.o1);");
/*fuzzSeed-116066984*/count=1244; tryItOut("mathy1 = (function(x, y) { return (Math.hypot((((Math.fround((Math.fround((((Math.min(-(2**53-2), 1/0) >>> 0) && (y >>> 0)) >>> 0)) ** Math.fround(Math.asin(x)))) >>> 0) || ((( ~ (Math.fround(Math.min(Math.fround(x), Math.fround(Math.min(Math.max(0x100000001, ( + x)), x)))) >>> 0)) >>> 0) >>> 0)) >>> 0), mathy0(Math.pow(x, x), (((Math.hypot(x, ( + x)) | 0) / (y | 0)) | 0))) >> (( ~ (Math.pow((x || 1.7976931348623157e308), Math.fround(( ! (Math.tanh(x) >>> 0)))) >>> 0)) + ( ~ x))); }); testMathyFunction(mathy1, [-0x100000001, 1/0, -1/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -(2**53), 2**53-2, 0x080000001, -0x0ffffffff, -0x080000000, 2**53, -Number.MIN_VALUE, 1, -Number.MAX_VALUE, -0x07fffffff, 0x080000000, Math.PI, 0, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, 0x07fffffff, 0/0, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0, -0x080000001, 0.000000000000001, 2**53+2, -(2**53-2)]); ");
/*fuzzSeed-116066984*/count=1245; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[({}), (0/0)]); ");
/*fuzzSeed-116066984*/count=1246; tryItOut("mathy1 = (function(x, y) { return (( + (Math.fround((Math.fround(((mathy0((Math.log1p(x) >>> 0), Math.fround(42)) >>> 0) >= (((Math.ceil(x) | 0) ^ Math.max(( ~ ( + x)), -1/0)) | 0))) == ( + Math.fround(Math.pow(Math.hypot(y, (-0x100000001 ? ( ! (y | 0)) : -0x100000000)), ((Math.imul(Math.fround((Math.fround(x) >>> Math.fround(x))), -Number.MAX_VALUE) >>> 0) - ((mathy0(1/0, x) == Math.log10(y)) >>> 0))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x100000001, 2**53-2, 2**53+2, -0x0ffffffff, 0.000000000000001, 0x100000000, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, -0x080000000, 1, Number.MIN_VALUE, 0x080000001, -0x100000000, Math.PI, Number.MAX_VALUE, 42, -1/0, 0x0ffffffff, 2**53, -0x100000001, -0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, 1/0, -(2**53+2), -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff, 0/0]); ");
/*fuzzSeed-116066984*/count=1247; tryItOut("\"use strict\"; g2.e2.toSource = (function mcc_() { var fhvyud = 0; return function() { ++fhvyud; f1(/*ICCD*/fhvyud % 8 == 4);};})();");
/*fuzzSeed-116066984*/count=1248; tryItOut("\"use strict\"; b0.__proto__ = h0;");
/*fuzzSeed-116066984*/count=1249; tryItOut("v0 = evalcx(\"a1 + '';\", g0);");
/*fuzzSeed-116066984*/count=1250; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (( + Math.min((((y | 0) < (Math.min(Math.atan2((x , 0/0), Math.fround((Math.expm1((( ! y) | 0)) | 0))), x) | 0)) | 0), Math.min(( + Math.cosh(( + y))), 1/0))) ^ Math.atan2((Math.imul((-0x080000000 >>> 0), ( + (-Number.MAX_SAFE_INTEGER ? x : ( + Math.log2(( + y)))))) >>> 0), Math.tan(Math.fround((Math.fround(y) !== Math.fround(y)))))); }); testMathyFunction(mathy0, [0x080000001, -(2**53), -Number.MIN_VALUE, 2**53, 1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -(2**53+2), 0/0, -0, -0x100000001, -0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 0, 0x080000000, 2**53+2, Number.MIN_VALUE, Math.PI, -0x100000000, 0x07fffffff, -0x0ffffffff, 42, 1, 0x100000000, -1/0, -0x080000001]); ");
/*fuzzSeed-116066984*/count=1251; tryItOut("w = linkedList(w, 741);");
/*fuzzSeed-116066984*/count=1252; tryItOut("/*infloop*/\u0009for(e; (4277); \"\\u059A\") {print((4277));print((4277)); }");
/*fuzzSeed-116066984*/count=1253; tryItOut("mathy2 = (function(x, y) { return Math.atanh((Math.abs(Math.acosh((Math.ceil(y) | 0))) >>> 0)); }); testMathyFunction(mathy2, [-(2**53-2), -0x080000001, 0x0ffffffff, -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 42, -1/0, 1/0, 0x100000001, -0, 0/0, -0x080000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 0x080000001, -0x07fffffff, 0.000000000000001, Math.PI, -0x100000001, -(2**53), 2**53-2, 1, 0, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-116066984*/count=1254; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround((Math.fround(Math.max(Math.round(Math.max(Math.fround(Math.min(Math.fround(Math.fround(Math.max(Math.fround(0x100000000), Number.MIN_SAFE_INTEGER))), Math.fround(Math.PI))), Math.fround(x))), (4277))) && Math.fround(Math.acosh(Math.fround(Math.clz32(( + Math.max(Math.fround((Math.max(y, Math.fround(2**53)) | 0)), Math.fround(Math.min(-0x100000001, ( ! y))))))))))); }); testMathyFunction(mathy0, /*MARR*/[{}, ({}), new Boolean(false), {}, function(){}, new Boolean(false), {}, new Boolean(false), {}, {}, {}, new Boolean(false), {}, {}, function(){}, function(){}, {}, ({}), function(){}, new Boolean(false), ({}), {}, ({}), ({}), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, ({}), {}, ({}), function(){}, new Boolean(false), {}, {}, {}, ({}), {}, ({}), {}, function(){}, {}, {}, function(){}, {}, function(){}, {}, function(){}, function(){}, new Boolean(false), new Boolean(false), {}, new Boolean(false)]); ");
/*fuzzSeed-116066984*/count=1255; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1256; tryItOut("mathy2 = (function(x, y) { return Math.ceil(( ! (Math.abs(Math.min((Math.sign((x >>> 0)) | 0), (Math.atan(-0x100000000) | 0))) | 0))); }); testMathyFunction(mathy2, [-0x07fffffff, -(2**53+2), -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 1/0, 0x07fffffff, -0x080000001, Math.PI, 1, -0x0ffffffff, -0, 0, 0x100000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, 0.000000000000001, -Number.MIN_VALUE, 2**53, 0x100000001, 2**53+2, 42, -1/0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1257; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.ceil((( ! (( ! x) | 0)) | 0)); }); ");
/*fuzzSeed-116066984*/count=1258; tryItOut("var d =  '' ;g2 + f2;");
/*fuzzSeed-116066984*/count=1259; tryItOut("mathy5 = (function(x, y) { return Math.min((( ! (((mathy2(x, Number.MAX_VALUE) >>> 0) ** (x >>> 0)) >>> 0)) | 0), ( + (Math.fround(Math.hypot(Math.fround((( + Math.fround(mathy3(x, Math.PI))) >>> 0)), x)) && Math.fround(Math.tanh(Math.fround(Math.min(mathy0(Number.MAX_VALUE, Math.atan2(x, y)), (mathy4((y | 0), (y | 0)) | 0)))))))); }); testMathyFunction(mathy5, /*MARR*/[.2, x, function(){}, function(){}, x,  \"use strict\" , x, .2, function(){}, -0x100000001,  \"use strict\" , function(){}, .2, -0x100000001,  \"use strict\" , -0x100000001, -0x100000001, x, function(){}, function(){}, x, .2, x, function(){}, .2, -0x100000001, function(){}, function(){}, -0x100000001,  \"use strict\" , -0x100000001, x, x, x,  \"use strict\" , function(){}, -0x100000001, function(){}, function(){}, x, -0x100000001, function(){}, x, x,  \"use strict\" , function(){}, .2, x, x, .2, -0x100000001, x, .2,  \"use strict\" , -0x100000001, .2, .2, function(){}, -0x100000001, -0x100000001, x, .2, function(){}, x, -0x100000001, -0x100000001, .2, -0x100000001, x, -0x100000001,  \"use strict\" , function(){}, .2, function(){}, function(){}, function(){}, x, .2,  \"use strict\" ,  \"use strict\" , function(){}, function(){}, .2, function(){}, x, .2, .2, x,  \"use strict\" , function(){}, function(){}, x, .2, x, -0x100000001, -0x100000001, -0x100000001,  \"use strict\" , .2, -0x100000001,  \"use strict\" , x, .2, .2, .2, function(){}, x, x, x, -0x100000001, x, .2, .2, .2, .2, .2, .2, .2,  \"use strict\" ]); ");
/*fuzzSeed-116066984*/count=1260; tryItOut("/*RXUB*/var r = /(?!(.))?/m; var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-116066984*/count=1261; tryItOut("\"use strict\"; /*ODP-2*/Object.defineProperty(a2, \"trunc\", { configurable: (x % 5 == 1), enumerable: true, get: f0, set: (function() { for (var j=0;j<70;++j) { f0(j%5==1); } }) });");
/*fuzzSeed-116066984*/count=1262; tryItOut("\"use strict\"; print(uneval(g0));");
/*fuzzSeed-116066984*/count=1263; tryItOut("/*MXX3*/g2.Root.name = g1.Root.name;");
/*fuzzSeed-116066984*/count=1264; tryItOut("testMathyFunction(mathy5, /*MARR*/[new String('q'), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new String('q'), new Boolean(true), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-116066984*/count=1265; tryItOut("mathy0 = (function(x, y) { return Math.imul(( + Math.fround((( + Math.tanh(Math.atanh((x >>> 0)))) << Math.fround(Math.imul((y | 0), (Math.atan2(Math.fround((Math.fround(Math.imul(Math.fround(x), y)) << ( + ( + ( + ( + Math.fround(( + x)))))))), ( + Math.atan(( + Math.fround((( ! (y | 0)) >>> 0)))))) | 0)))))), Math.min(Math.pow((-Number.MIN_VALUE > x), Math.max(Math.fround((Math.min((y | 0), (x >>> 0)) >>> 0)), y)), ( + (( - ((((x >>> 0) ? (( - x) >>> 0) : ( + (( ! (x >>> 0)) >>> 0))) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [-0x07fffffff, 2**53+2, -0x100000000, 2**53-2, -Number.MIN_VALUE, 0x0ffffffff, 1, Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, -0x100000001, -0, 0x100000000, -(2**53+2), 2**53, -1/0, Number.MAX_VALUE, 1.7976931348623157e308, -0x0ffffffff, 0x080000000, 0, 0/0, Math.PI, 0.000000000000001, Number.MIN_VALUE, 1/0, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, 0x080000001, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1266; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + (Math.pow(Math.atan2(Math.fround((y >> Math.fround((Math.fround(Math.fround(Math.acos(Math.fround(x)))) , Math.fround(mathy0(Math.fround(x), Math.fround(x))))))), Math.fround(mathy0((Math.cbrt((y | 0)) | 0), (Number.MAX_VALUE >>> y)))), ( + Math.sqrt(( + Math.max(Math.fround(Math.hypot(Math.pow(0.000000000000001, (y >>> 0)), y)), Math.fround(Number.MAX_VALUE)))))) | 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[arguments.callee, function(){}, function(){}, function(){}, arguments.callee, function(){}, function(){}, arguments.callee, arguments.callee, function(){}, arguments.callee, function(){}, function(){}, function(){}, arguments.callee, function(){}, arguments.callee, arguments.callee, arguments.callee, function(){}, arguments.callee, function(){}, function(){}, function(){}, arguments.callee, arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, function(){}, arguments.callee, function(){}, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, function(){}, arguments.callee, function(){}, arguments.callee, function(){}, function(){}, function(){}, function(){}, arguments.callee, function(){}, function(){}, function(){}, arguments.callee, function(){}, function(){}, function(){}, arguments.callee, function(){}, function(){}, function(){}, function(){}, arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, function(){}, function(){}, function(){}, function(){}, arguments.callee, arguments.callee, function(){}, arguments.callee, function(){}, function(){}, function(){}, function(){}, function(){}, arguments.callee, function(){}, arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, arguments.callee, function(){}, arguments.callee, function(){}, arguments.callee, function(){}, arguments.callee, arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, arguments.callee, arguments.callee, function(){}, function(){}, function(){}, function(){}, arguments.callee, function(){}, function(){}, arguments.callee, function(){}, function(){}, arguments.callee, arguments.callee, function(){}, arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, arguments.callee, arguments.callee, function(){}, function(){}, function(){}, arguments.callee, function(){}, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, function(){}, function(){}, arguments.callee, arguments.callee, function(){}]); ");
/*fuzzSeed-116066984*/count=1267; tryItOut("e1.has(m1);");
/*fuzzSeed-116066984*/count=1268; tryItOut("\"use strict\"; /*ODP-2*/Object.defineProperty(g2, \"15\", { configurable: true, enumerable: (uneval((window)( \"\" ))), get: f0, set: (function(j) { if (j) { v1 = g2.runOffThreadScript(); } else { g2.m0.has( /x/ ); } }) });");
/*fuzzSeed-116066984*/count=1269; tryItOut("\"use strict\"; t1.set(a1, 6);");
/*fuzzSeed-116066984*/count=1270; tryItOut("v0 = Array.prototype.some.call(a0, f2, v0);");
/*fuzzSeed-116066984*/count=1271; tryItOut("/*vLoop*/for (var lnaghw = 0, (x == y), a; lnaghw < 9; ++lnaghw) { d = lnaghw; o1.o1.v0 = o1.a0.length; } ");
/*fuzzSeed-116066984*/count=1272; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    i0 = (i0);\n    return +((Infinity));\n  }\n  return f; })(this, {ff: function (x)()}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x0ffffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 0, 2**53+2, 0x07fffffff, -0x080000000, -Number.MAX_VALUE, 0.000000000000001, 0x100000001, -0, Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 2**53-2, Number.MIN_VALUE, Math.PI, 1, -0x100000001, -0x07fffffff, 0x0ffffffff, 2**53, -0x100000000, -1/0, 0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, 0/0, -(2**53+2), 1/0, -(2**53-2), 0x080000001, -(2**53), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1273; tryItOut("\"use strict\"; let (c, d = (4277), vauvbp, e, [] = (4277), rrfyqt) { o2.v2 = g2.runOffThreadScript(); }");
/*fuzzSeed-116066984*/count=1274; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 1, -(2**53), -(2**53+2), Math.PI, -0x07fffffff, -1/0, 0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 0, 42, -0x100000000, -0, 0x080000000, -0x080000000, 2**53, 2**53+2, 0/0, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1275; tryItOut("/*oLoop*/for (zwxppi = 0, x; zwxppi < 56; ++zwxppi) { ( /x/ ); } ");
/*fuzzSeed-116066984*/count=1276; tryItOut("\"use asm\"; a1 = [];");
/*fuzzSeed-116066984*/count=1277; tryItOut("\"use strict\"; v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: {} = ((void shapeOf( /x/ ))).__defineSetter__(\"x\"\u000c, String.prototype.padStart), sourceIsLazy: (x % 3 != 1), catchTermination: true }));");
/*fuzzSeed-116066984*/count=1278; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! ( + ( ! (((Math.fround(( - ((((y >>> 0) ? (Math.atan2(Number.MAX_SAFE_INTEGER, y) >>> 0) : 0.000000000000001) >>> 0) >>> 0))) | 0) ? (y | 0) : ((( ~ (mathy2((x >>> 0), (x >>> 0)) >>> 0)) >>> 0) | 0)) | 0)))); }); ");
/*fuzzSeed-116066984*/count=1279; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (-0x5ea507a);\n    }\n    return +(((+(((i0)) >> ((Int16ArrayView[4096]))))));\n  }\n  return f; })(this, {ff: mathy2}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=1280; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.pow((Math.hypot(( + Math.acos(( + Math.log(Math.fround(y))))), (Math.cbrt(( ! -0x07fffffff)) | 0)) > (x < ( + Math.pow(( + (Number.MAX_SAFE_INTEGER >> y)), (( ~ (1/0 | 0)) | 0))))), (Math.max(((( + mathy0(( + ( ! ( + x))), Math.fround((x << Math.fround((Math.hypot(-0x0ffffffff, -Number.MIN_VALUE) | 0)))))) >>> (Math.fround(-Number.MIN_SAFE_INTEGER) >>> ( + Number.MAX_SAFE_INTEGER))) | 0), (((( + (((x >>> 0) ? (((Math.asin((Number.MIN_VALUE >>> 0)) >>> 0) ** Math.asinh((x >= (2**53 | 0)))) >>> 0) : (y | 0)) >>> 0)) > Math.fround(( - Math.fround(y)))) | 0) | 0)) | 0)); }); testMathyFunction(mathy5, [0x0ffffffff, -0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), 0/0, -0x080000001, 1/0, Number.MIN_VALUE, 0x080000000, 0.000000000000001, -0x100000001, 1.7976931348623157e308, -0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, -0, -0x100000000, 42, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, 2**53-2, Number.MAX_VALUE, Math.PI, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, 0x07fffffff, 2**53+2, 0x100000001, 0x080000001, 0, -Number.MIN_SAFE_INTEGER, -(2**53), -1/0]); ");
/*fuzzSeed-116066984*/count=1281; tryItOut("\"use strict\"; Object.defineProperty(this, \"o1\", { configurable:  '' , enumerable: (((x ?  '' .defineProperties() : /*RXUE*//[^]|5|[^\\W](?=[^]){4}/gyi.exec(\"\\u31fc\")))([] = new (w =>  { \"use strict\"; return -17 } )(), ((x =  '' )) = (let (x = \u000c[,,z1]) window)(this = eval,  /x/ ).yoyo((window = (/*FARR*/[13, (function ([y]) { })(), [1],  \"\" ].sort( /x/ , (w) = [[1]])))))),  get: function() {  return {}; } });");
/*fuzzSeed-116066984*/count=1282; tryItOut(";");
/*fuzzSeed-116066984*/count=1283; tryItOut("testMathyFunction(mathy0, [0x07fffffff, -(2**53), 1.7976931348623157e308, -0x100000000, 42, -0x100000001, -Number.MAX_VALUE, 0.000000000000001, 0, Number.MAX_VALUE, -0x0ffffffff, -1/0, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, Number.MIN_VALUE, 2**53+2, 2**53, -(2**53+2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, 1/0, 0x0ffffffff, 0x100000001, 1, 0x080000001, Number.MIN_SAFE_INTEGER, -0]); ");
/*fuzzSeed-116066984*/count=1284; tryItOut("mathy1 = (function(x, y) { return (Math.atan2(( + Math.atan2((Math.min(2**53, ( + mathy0(y, (mathy0(-0, x) >>> 0)))) > -Number.MIN_SAFE_INTEGER), ( + ( + ( + (mathy0((x < x), (Math.atan(((2**53 >>> 0) ** y)) >>> 0)) >>> 0)))))), ( + ((( ~ (y | 0)) >>> 0) & x))) | 0); }); testMathyFunction(mathy1, [-(2**53), -0x07fffffff, 0/0, 0x0ffffffff, -Number.MAX_VALUE, Math.PI, 2**53-2, -1/0, Number.MAX_VALUE, 0x100000001, -(2**53-2), 42, 0x100000000, 2**53, -0x0ffffffff, 0x080000001, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), 0x080000000, Number.MIN_VALUE, 0, 1/0, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, -0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, -0, 2**53+2, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1285; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1286; tryItOut("v2[\"valueOf\"] = e0;");
/*fuzzSeed-116066984*/count=1287; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53-2, 0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, -(2**53+2), -0x07fffffff, -(2**53), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 0x100000001, -0x080000001, 42, -0x100000000, -0x0ffffffff, -(2**53-2), 0, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, Number.MIN_VALUE, 1/0, -1/0, 2**53, 0x080000000, -0x100000001, 0x100000000, Math.PI, 1, 0/0, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1288; tryItOut("\"use strict\"; v0 = g2.eval(\"function f2(h1)  { return x(Math.abs(-11), /(?!\\\\s\\u5ded)*/gym).unwatch(\\\"0\\\") } \");");
/*fuzzSeed-116066984*/count=1289; tryItOut("\"use strict\"; /*infloop*/for(var b = Math.hypot(x, -1); (eval(\"intern((new  \\\"\\\" (null)))\", (let (x = \"\\u5F2B\") /.|[^]+|\\3+?|(?=\\B){2}[^][^\\S]([^\\s])?+?/gi).__defineSetter__(\"b\", Object.is))); x) Object.freeze(o2.v1);");
/*fuzzSeed-116066984*/count=1290; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ~ (((Math.fround(Math.sqrt(((( + (x > (x >>> 0))) >> y) >>> 0))) | 0) >> (Math.fround(Math.min(( ~ (Math.imul(y, /((?:\\b+?|(?!(?:[^]))*)*?)/y) | 0)), Math.fround(((x >> ( - y)) % (0x080000000 >>> 0))))) | 0)) | 0)); }); testMathyFunction(mathy0, [0/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, -0x100000001, -0, 0x100000000, -0x0ffffffff, 0x100000001, -(2**53+2), 0x080000000, 1, -Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, 42, 2**53-2, 2**53, 1/0, Number.MIN_SAFE_INTEGER, 0, 0.000000000000001, -(2**53), -Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, 2**53+2, 0x07fffffff, -0x07fffffff, -1/0, Number.MAX_VALUE, -0x100000000, 0x080000001]); ");
/*fuzzSeed-116066984*/count=1291; tryItOut("testMathyFunction(mathy2, /*MARR*/[new Number(1.5), [(void 0)], new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [(void 0)], false, (0/0), (0/0), [(void 0)], false, new Number(1.5), false, (0/0), new Number(1.5), new Number(1.5), (0/0), new Number(1.5), (0/0), new Number(1.5), new Number(1.5), [(void 0)], [(void 0)], new Number(1.5), [(void 0)], [(void 0)], (0/0), false, new Number(1.5), (0/0), (0/0), new Number(1.5), new Number(1.5), false, new Number(1.5), new Number(1.5), new Number(1.5), false, [(void 0)], [(void 0)], [(void 0)], new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), (0/0), false, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), false, [(void 0)], false, (0/0), (0/0), [(void 0)], [(void 0)], (0/0), (0/0), false, new Number(1.5), (0/0), [(void 0)], new Number(1.5), new Number(1.5), false, [(void 0)], (0/0), new Number(1.5), new Number(1.5), new Number(1.5), false, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [(void 0)], (0/0), [(void 0)], new Number(1.5), (0/0), false, false, false, false, new Number(1.5), (0/0), false, (0/0), false, new Number(1.5), false, [(void 0)], false, false, new Number(1.5), [(void 0)], new Number(1.5), false, [(void 0)], new Number(1.5), [(void 0)], false, (0/0), new Number(1.5)]); ");
/*fuzzSeed-116066984*/count=1292; tryItOut("const r0 = new RegExp(\"(?=(?!(?!([^]))+?))\", \"yi\");");
/*fuzzSeed-116066984*/count=1293; tryItOut("\"use strict\"; /*infloop*/for(var b = (\"\\u2960\".eval(\"[,,z1]\"))\n; (void shapeOf( /x/g )); ((void version(180)))) m1.set(g0.f0, o1);");
/*fuzzSeed-116066984*/count=1294; tryItOut("this.zzz.zzz;");
/*fuzzSeed-116066984*/count=1295; tryItOut("/*infloop*/M:for(let of in ((decodeURI)((Object.defineProperty(x, \"apply\", ({get: this})))))){-2; }");
/*fuzzSeed-116066984*/count=1296; tryItOut("\"use strict\"; o1.v2.toString = (function() { try { /*ODP-1*/Object.defineProperty(h2, new String(\"9\"), ({value: allocationMarker(), writable: true, enumerable: ((\"setUint32\") = (delete) = (\"\\uD0E8\" != \"\\u3C2E\"))})); } catch(e0) { } try { /*MXX1*/o0 = g2.Math.atan2; } catch(e1) { } b0 = new ArrayBuffer(60); return s1; });");
/*fuzzSeed-116066984*/count=1297; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.fround(Math.tanh(Math.atan2(Math.log((mathy0((x >>> 0), (y >>> 0)) >>> 0)), (( + ( - ( + (2**53 , (Math.imul(0x080000000, y) | 0))))) >>> 0)))); }); ");
/*fuzzSeed-116066984*/count=1298; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.max(Math.tanh(Math.imul(Math.fround((( + Math.hypot(Math.fround((( ~ x) | 0)), (y | 0))) ? x : y)), ( - x))), ( + Math.pow((x > (x !== (Math.exp(0x080000001) | 0))), ( ! ((((Math.cosh((mathy3((y | 0), Math.fround(y)) | 0)) >>> 0) * (Math.hypot(mathy1(-0x07fffffff, x), ( + ( ~ y))) >>> 0)) >>> 0) | 0)))))); }); testMathyFunction(mathy4, [0x0ffffffff, -0x100000001, -(2**53+2), 2**53, -Number.MIN_VALUE, 42, -(2**53-2), 0.000000000000001, -0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 2**53-2, 0, -0x0ffffffff, 1/0, Number.MAX_VALUE, 0x07fffffff, 0x100000000, 0x080000000, -0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0, 2**53+2, Math.PI, 0/0, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001]); ");
/*fuzzSeed-116066984*/count=1299; tryItOut("testMathyFunction(mathy1, [-0x080000001, -1/0, -(2**53), Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 2**53, 0/0, -Number.MIN_VALUE, 1/0, 0x080000001, -0x100000001, 2**53+2, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, 1, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, 0x080000000, 0, -0x100000000, 2**53-2, 0.000000000000001, 0x100000001, 42, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1300; tryItOut("g0.e0.delete(g2.g1);");
/*fuzzSeed-116066984*/count=1301; tryItOut("var jgdveo = new ArrayBuffer(4); var jgdveo_0 = new Uint8ClampedArray(jgdveo); print(jgdveo_0[0]); var jgdveo_1 = new Uint32Array(jgdveo); print(jgdveo_1[0]); jgdveo_1[0] = -4; var jgdveo_2 = new Uint8Array(jgdveo); jgdveo_2[0] = -15; var jgdveo_3 = new Int8Array(jgdveo); print(jgdveo_3[0]); jgdveo_3[0] = 2049; o1.g0.s2 = '';");
/*fuzzSeed-116066984*/count=1302; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((mathy1((Math.max(( + x), ( + Math.sinh(Math.fround(x)))) >>> 0), ( + ( + x))) >>> 0) != Math.fround(Math.fround(( - ((Math.fround(Math.fround(mathy0(x, Math.log(x)))) != (( ~ Math.fround(Math.imul(y, ( + Math.pow(( + -0x100000001), ( + 1.7976931348623157e308)))))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [Math.PI, -(2**53-2), 1, -0x080000000, -(2**53+2), -Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, -1/0, 0, 0/0, 0x100000000, -0x080000001, 1/0, -0, -0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, -(2**53), -0x0ffffffff, 0x080000001, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, 0.000000000000001, 42, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=1303; tryItOut("\"use strict\"; s0 += s2;");
/*fuzzSeed-116066984*/count=1304; tryItOut("i1.send(e2);");
/*fuzzSeed-116066984*/count=1305; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116066984*/count=1306; tryItOut("a0.sort((function() { for (var j=0;j<39;++j) { f2(j%3==1); } }), m2, h2, i2);");
/*fuzzSeed-116066984*/count=1307; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.min(Math.atanh(( ! (x | 0))), ( ! (Math.hypot(Math.pow(x, (((Math.hypot(y, y) | 0) >>> ( + Math.fround(y))) | 0)), (Math.ceil((mathy1(Math.hypot(Math.PI, x), x) >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy2, /*MARR*/[function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}, function(){}, 0x3FFFFFFF, function(){}, 0x3FFFFFFF, 0x3FFFFFFF, function(){}, function(){}, function(){}, 0x3FFFFFFF, function(){}]); ");
/*fuzzSeed-116066984*/count=1308; tryItOut("mathy2 = (function(x, y) { return (Math.tanh(( ! (Math.acos((Math.fround(( - Math.fround(Math.min(Math.fround(x), y)))) === Math.log1p(Math.sin(Math.fround(Math.hypot((0x07fffffff | 0), (x | 0))))))) | 0))) | 0); }); ");
/*fuzzSeed-116066984*/count=1309; tryItOut("\"use strict\"; M:for(y in ((function(y) { yield y; p1 + '';; yield y; })(Math.imul( /x/ , 11)))){Array.prototype.unshift.call(this.a2, g2.h1, f2, i1, i1, i0, m2);delete b0[\"constructor\"]; }");
/*fuzzSeed-116066984*/count=1310; tryItOut("print(uneval(g0.s1));\nh1.set = f0;\n");
/*fuzzSeed-116066984*/count=1311; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[(1/0), new Boolean(true), {}, {}, new Boolean(true), (1/0), (1/0), {}, {}, {}, {}, (1/0), {}, new Boolean(true), {}, new Boolean(true), (1/0), new Boolean(true), (1/0), new Boolean(true), new Boolean(true), {}, new Boolean(true), new Boolean(true), (1/0)]); ");
/*fuzzSeed-116066984*/count=1312; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy3(( + ( ~ ( + ( + ( ! 0x0ffffffff))))), Math.sin(( + (x | 0)))); }); testMathyFunction(mathy4, /*MARR*/[0x40000000, 0x40000000, new Number(1.5), new Number(1.5), 0x40000000, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x40000000, new Number(1.5), 0x40000000, 0x40000000, 0x40000000, 0x40000000, new Number(1.5), new Number(1.5), new Number(1.5), 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, new Number(1.5), 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, new Number(1.5), new Number(1.5), new Number(1.5), 0x40000000, new Number(1.5), 0x40000000, new Number(1.5), 0x40000000, 0x40000000, new Number(1.5), new Number(1.5), 0x40000000, new Number(1.5), new Number(1.5), 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, new Number(1.5), new Number(1.5), 0x40000000, 0x40000000, 0x40000000, 0x40000000, new Number(1.5), new Number(1.5), new Number(1.5), 0x40000000, 0x40000000, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x40000000, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x40000000, 0x40000000, new Number(1.5), 0x40000000, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x40000000, new Number(1.5), new Number(1.5), 0x40000000, 0x40000000, 0x40000000, new Number(1.5), 0x40000000, new Number(1.5), 0x40000000, new Number(1.5), 0x40000000, 0x40000000, new Number(1.5), 0x40000000, new Number(1.5), new Number(1.5), 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-116066984*/count=1313; tryItOut("z;(function ([y]) { })();\n/* no regression tests found */\n");
/*fuzzSeed-116066984*/count=1314; tryItOut("t0[7];");
/*fuzzSeed-116066984*/count=1315; tryItOut("\"use strict\"; v1 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-116066984*/count=1316; tryItOut("print(uneval(f2));");
/*fuzzSeed-116066984*/count=1317; tryItOut("for (var v of m2) { g0.s2 = Array.prototype.join.apply(g0.a1, [s0, f0, this.h2]); }");
/*fuzzSeed-116066984*/count=1318; tryItOut("\"use strict\"; v0 = 0;");
/*fuzzSeed-116066984*/count=1319; tryItOut("/*vLoop*/for (let fedwqo = 0; fedwqo < 49; ++fedwqo) { const e = fedwqo; t1.valueOf = f1; } ");
/*fuzzSeed-116066984*/count=1320; tryItOut("v2 = Object.prototype.isPrototypeOf.call(t1, v1);");
/*fuzzSeed-116066984*/count=1321; tryItOut("/*tLoop*/for (let z of /*MARR*/[0x2D413CCC, 0, 0x2D413CCC, {}, {}, 0x2D413CCC, 0x2D413CCC, {}, 0, 0, 0, {}, 0, 0x2D413CCC, {}, 0x2D413CCC, 0x2D413CCC, 0, 0x2D413CCC, 0, {}, 0, 0x2D413CCC, {}, {}, 0x2D413CCC, {}, 0x2D413CCC, {}, {}, {}, 0x2D413CCC, 0x2D413CCC, 0, 0]) { true; }");
/*fuzzSeed-116066984*/count=1322; tryItOut("\"use strict\"; s0 += s2;");
/*fuzzSeed-116066984*/count=1323; tryItOut("var kvdvnl = new ArrayBuffer(2); var kvdvnl_0 = new Float64Array(kvdvnl); kvdvnl_0[0] = -29; var kvdvnl_1 = new Float64Array(kvdvnl); var kvdvnl_2 = new Uint16Array(kvdvnl); print(kvdvnl_2[0]); kvdvnl_2[0] = -0; var kvdvnl_3 = new Int32Array(kvdvnl); var kvdvnl_4 = new Uint8Array(kvdvnl); print(kvdvnl_4[0]); var kvdvnl_5 = new Float64Array(kvdvnl); kvdvnl_5[0] = 10; var kvdvnl_6 = new Uint16Array(kvdvnl); kvdvnl_6[0] = 188559097.5; var kvdvnl_7 = new Uint32Array(kvdvnl); var kvdvnl_8 = new Int8Array(kvdvnl); var kvdvnl_9 = new Uint8ClampedArray(kvdvnl); var kvdvnl_10 = new Float32Array(kvdvnl); kvdvnl_10[0] = -844166951; this.s1 + '';/*tLoop*/for (let c of /*MARR*/[ /x/ ]) { v0 = (v2 instanceof g0.i0); }/*vLoop*/for (wdvira = 0; wdvira < 17; ++wdvira, window) { const w = wdvira; {} } g1.offThreadCompileScript(\"h0.getPropertyDescriptor = f0;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: [window], noScriptRval: true, sourceIsLazy: true, catchTermination: (this.__defineSetter__(\"\\u3056\", decodeURI)), elementAttributeName: s0 }));L:with({z: kvdvnl_0}){{a0 + '';h1.valueOf = (function() { try { ; } catch(e0) { } /*ODP-3*/Object.defineProperty(p0, \"prototype\", { configurable: d, enumerable: 1267981571.5, writable: true, value: a2 }); return g2; }); }o1 = Object.create(h0); }Array.prototype.shift.apply(a1, []);i0.toString = (function(j) { if (j) { try { f0 + s2; } catch(e0) { } try { this.f2 + g0.s1; } catch(e1) { } try { this.o1.t0[({valueOf: function() { m1.set(e1, h1);return 15; }})] = arguments; } catch(e2) { } v0 = g1.runOffThreadScript(); } else { try { o1.valueOf = (function(j) { if (j) { try { Array.prototype.push.call(a1, p2, m1, i0); } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } a1.pop(e2, s0,  \"\" , b1); } else { v2 = new Number(4.2); } }); } catch(e0) { } v0.__proto__ = i0; } });t0 + '';");
/*fuzzSeed-116066984*/count=1324; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.min((Math.fround(Math.imul((-27 <<= b | y), (((y | 0) ? (mathy0(mathy3(y, (Math.atan2(y, y) >>> 0)), x) >>> 0) : (( ~ 2**53) | 0)) | 0))) ? (((y >>> 0) ** Math.fround(Math.sign(( ~ Math.fround(x))))) >>> 0) : Math.max((( + Math.sqrt(((( - ( + y)) >>> 0) >>> 0))) | 0), x)), ( + (Math.max((mathy1(y, (Number.MIN_SAFE_INTEGER | 0)) | 0), (y | 0)) | 0))); }); testMathyFunction(mathy5, /*MARR*/[null, new String('q'), new String(''), function(){}, null]); ");
/*fuzzSeed-116066984*/count=1325; tryItOut("var ktizra = new ArrayBuffer(0); var ktizra_0 = new Uint8Array(ktizra); /*iii*/print( /x/ );/*hhh*/function uspftm(...window){i2 = new Iterator(g0.g0.e2);}\nprint(ktizra_0[4]);i0.__iterator__ = (function() { for (var j=0;j<7;++j) { this.f2(j%5==0); } });yield;const v1 = o1.a2.reduce, reduceRight(f1, o1.o2, s0, g0.v2, g1.b0);");
/*fuzzSeed-116066984*/count=1326; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.atan2((Math.fround(Math.pow((Math.fround(((x | 0) <= Math.fround(y))) + (Math.sqrt(( + x)) >>> 0)), (Math.expm1((x >>> 0)) >>> 0))) >>> 0), (( - (x >>> 0)) >>> 0)) + (Math.log1p((Math.fround(Math.abs(((((( + Math.atan2(( + x), ( + -Number.MAX_SAFE_INTEGER))) << (Math.atan2(-0x080000000, x) >>> 0)) >>> 0) ? Math.hypot(y, ( + x)) : y) | 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [-0, -0x100000001, -Number.MIN_VALUE, 0x100000000, Number.MIN_VALUE, -0x080000000, 0x080000000, 42, 1, 1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, -0x07fffffff, -(2**53+2), 0x100000001, Math.PI, -1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, 0x080000001, -(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -0x100000000, -(2**53)]); ");
/*fuzzSeed-116066984*/count=1327; tryItOut("/*oLoop*/for (var hiqrbj = 0; hiqrbj < 107; ++hiqrbj) { print( +=window); } ");
/*fuzzSeed-116066984*/count=1328; tryItOut("a1.shift();");
/*fuzzSeed-116066984*/count=1329; tryItOut("mathy2 = (function(x, y) { return Math.abs((( - (Math.log10((x >>> 0)) >>> 0)) ^ ( ! (( + ( - ( + ( ~ Math.fround(x))))) >>> 0)))); }); testMathyFunction(mathy2, [-1/0, -Number.MAX_VALUE, -0x080000001, 0x080000000, 2**53+2, -(2**53-2), 1, Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -0x100000001, 1.7976931348623157e308, 2**53-2, -0x0ffffffff, -0x080000000, 0x07fffffff, 2**53, 42, Math.PI, 0, 0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, 0.000000000000001, -(2**53+2), -0, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1330; tryItOut("delete a1[\"wrappedJSObject\"];");
/*fuzzSeed-116066984*/count=1331; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:[\\r\\W\\u00E8-\u045e\\0-\\x74]|[\\M-\\u0086\\cT\u127e-\\\u00db]+|(?:[^].)|\\1?|(?=\\D))/gm; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-116066984*/count=1332; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.tan(((Number.MAX_VALUE && ((Math.log2(x) >= 42) ? (Math.fround((Math.fround(y) ? x : Math.fround(y))) * (x || Math.fround(Math.exp(Math.fround(x))))) : -1/0)) | 0))); }); ");
/*fuzzSeed-116066984*/count=1333; tryItOut("f0 = (function() { for (var j=0;j<54;++j) { g2.f2(j%4==1); } });");
/*fuzzSeed-116066984*/count=1334; tryItOut("g0.v2 = a0.length;");
/*fuzzSeed-116066984*/count=1335; tryItOut("for (var v of m2) { try { o1 = f2.__proto__; } catch(e0) { } try { m1.get((4277)); } catch(e1) { } try { Array.prototype.reverse.apply(a0, [v1]); } catch(e2) { } m2.set(i1, m2); }");
/*fuzzSeed-116066984*/count=1336; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(Math.atanh(Math.fround(Math.fround(Math.abs(Math.fround(x)))))) * ( + ( ~ ( + Math.pow(( + Math.sign(Math.fround(x))), (( ~ (Math.abs(( + (( + x) | ( + ((x >>> 0) === 42))))) >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-116066984*/count=1337; tryItOut("mathy5 = (function(x, y) { return ( ! ((Math.round(x) / mathy2(x, (((x ? 2**53+2 : mathy3(x, x)) | 0) >>> 0))) === (( + Math.fround(Math.exp(y))) | ( - -0x100000000)))); }); testMathyFunction(mathy5, [0x080000000, 0x0ffffffff, 0x080000001, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), 42, 2**53+2, Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, -0x080000001, -0x080000000, -(2**53-2), 0, 0/0, 1/0, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -0x100000001, -1/0, -(2**53), 2**53, 0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001]); ");
/*fuzzSeed-116066984*/count=1338; tryItOut("\"use strict\"; t0 = this.t1.subarray(1, 5);");
/*fuzzSeed-116066984*/count=1339; tryItOut("v2 = g2.a0.length;");
/*fuzzSeed-116066984*/count=1340; tryItOut("print(x);");
/*fuzzSeed-116066984*/count=1341; tryItOut("v1 = g2.a0.every(function(q) { return q; }, g1.m0);");
/*fuzzSeed-116066984*/count=1342; tryItOut("b2 + h1;");
/*fuzzSeed-116066984*/count=1343; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"^($)|.*?{2}|\\\\xC3[^\\\\cD\\\\W\\\\xAC-\\u0bf7\\\\s]{4,}\", \"y\"); var s = \"\\u00c3\\u00cb\\n\\n\\n\\n\\na\\n\\n\\u0004\\n\\n\\n\\n\\na\\n\\n\\u0004\\n\\n\\n\\n\\na\\n\\n\\u0004\\n\\n\\n\\n\\na\\n\\n\\u0004\\n\\n\\n\\n\\na\\n\\n\\u0004\\u00c3\\u47a7\"; print(r.exec(s)); w = true;");
/*fuzzSeed-116066984*/count=1344; tryItOut("m2.delete(f0);o1 = Object.create(timeout(1800));");
/*fuzzSeed-116066984*/count=1345; tryItOut("/*RXUB*/var r = (4277); var s = \"\\n\\u00a3v\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\u00a3v\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=1346; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-1/0, -(2**53), -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0x07fffffff, -0x100000001, -(2**53-2), 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, 0x100000000, Math.PI, 1/0, Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -0, 0.000000000000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000001, 2**53+2, Number.MIN_VALUE, 42, 2**53-2, 1, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, -(2**53+2), 0]); ");
/*fuzzSeed-116066984*/count=1347; tryItOut("\"use strict\"; with([,] / -1){/*vLoop*/for (let tzaaod = 0; tzaaod < 38; ++tzaaod) { b = tzaaod; m1.get(t1); } print(e2); }");
/*fuzzSeed-116066984*/count=1348; tryItOut("mathy2 = (function(x, y) { return Math.log10(( + (Math.pow(((((( ! (((x >>> 0) + (y >>> 0)) >>> 0)) >>> 0) ? 0x0ffffffff : ((( ! x) >>> 0) >>> 0)) >>> 0) | 0), (( + mathy1(( ! y), (x >>> 0))) | 0)) | 0))); }); testMathyFunction(mathy2, [0x0ffffffff, 0x07fffffff, 0x100000001, 42, -0x0ffffffff, -(2**53+2), Math.PI, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 1, 0.000000000000001, 0x080000000, -0, -0x07fffffff, -1/0, 2**53-2, -0x100000001, 2**53+2, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, 0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 0x100000000, 1/0, -0x080000001, 0/0, -(2**53), -Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1349; tryItOut("mathy5 = (function(x, y) { return Math.max(Math.log((mathy2((mathy4(x, (Math.atan(y) >>> 0)) | 0), Math.clz32(Math.sign(x))) >>> 0)), Math.fround(mathy0(( ~ x), ( - Math.max(x, y))))); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), (function(){return 0;}), (new Boolean(true)), 0.1, (new String('')), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), -0, undefined, (new Number(0)), [], true, (new Number(-0)), (new Boolean(false)), 0, objectEmulatingUndefined(), '\\0', null, [0], NaN, '/0/', 1, '', false, /0/, '0']); ");
/*fuzzSeed-116066984*/count=1350; tryItOut("\"use strict\"; \u0009with((yield ({a1:1})))let this.v0 = evalcx(\"o2.a0[window] = i2;\", g2);");
/*fuzzSeed-116066984*/count=1351; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1352; tryItOut("testMathyFunction(mathy0, [0x100000001, -1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2, -(2**53-2), -0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, 0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, -0x080000000, -0x080000001, 0x080000000, 1/0, -0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_VALUE, Math.PI, 1, -(2**53), 2**53, -0, -0x100000001, 0x080000001, -(2**53+2), -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1353; tryItOut("\"use strict\"; o1.t0[-4172133625] = (void options('strict'));");
/*fuzzSeed-116066984*/count=1354; tryItOut("\"use strict\"; v2 = evaluate(\"function f2(o2) \\\"use asm\\\";   function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    var i3 = 0;\\n    i2 = (0x21171547);\\n    return +((Math.max((String(\\\"\\\\uC394\\\")), 28)));\\n  }\\n  return f;\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 2 != 1) }));");
/*fuzzSeed-116066984*/count=1355; tryItOut("g2.offThreadCompileScript(\"function f2(f2) \\\"use asm\\\";   function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    var i3 = 0;\\n    var d4 = 9223372036854776000.0;\\n    var i5 = 0;\\n    var i6 = 0;\\n    i6 = (i2);\\n    i0 = (i6);\\n    i3 = (0xfe516521);\\n    i0 = (i6);\\n    i3 = (i1);\\n    d4 = (-1.5111572745182865e+23);\\n    {\\n      return +((0.0078125));\\n    }\\n    return +((+(0.0/0.0)));\\n  }\\n  return f;\");");
/*fuzzSeed-116066984*/count=1356; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(o2, \"callee\", ({configurable: w >> \"\\u6138\", enumerable: false}));");
/*fuzzSeed-116066984*/count=1357; tryItOut("/*RXUB*/var r = /\\B|\\W?^|\\x35*?+?/gim; var s = \" \\uaf3a\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=1358; tryItOut("\"use strict\"; { void 0; bailAfter(2); }");
/*fuzzSeed-116066984*/count=1359; tryItOut("a2 = a1.concat();");
/*fuzzSeed-116066984*/count=1360; tryItOut("for (var v of s0) { try { this.a2[({valueOf: function() { /*RXUB*/var r = /(?!.(?!\\B)|\\1*?*)/gim; var s = (/*MARR*/[(-1/0), x, true, x, true, x, true, x, x, x, true, (-1/0), (-1/0), x, x, true, x, (-1/0), true, true, true, true, x, true, true, (-1/0), x, true, (-1/0), true, x].map( /x/ )); print(r.test(s)); print(r.lastIndex); return 1; }})] = i1; } catch(e0) { } try { /*MXX1*/o2.o2 = g0.WebAssemblyMemoryMode; } catch(e1) { } try { (void schedulegc(g2)); } catch(e2) { } selectforgc(o2); }");
/*fuzzSeed-116066984*/count=1361; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.asinh((( + ( + Math.tanh((Math.fround(mathy1(x, y)) | 0)))) >>> 0))); }); testMathyFunction(mathy2, ['/0/', undefined, (new Number(-0)), 1, [0], null, ({toString:function(){return '0';}}), (new Boolean(true)), ({valueOf:function(){return '0';}}), (new String('')), 0.1, 0, objectEmulatingUndefined(), (function(){return 0;}), '\\0', ({valueOf:function(){return 0;}}), (new Boolean(false)), false, '', -0, true, NaN, [], /0/, '0', (new Number(0))]); ");
/*fuzzSeed-116066984*/count=1362; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ! Math.fround((( + Math.max(( + ( ~ x)), ( + (Math.sqrt((x >>> 0)) >>> 0)))) >>> Math.expm1((( + ((Math.clz32(y) >>> 0) | 0)) | 0))))); }); testMathyFunction(mathy0, [false, ({valueOf:function(){return '0';}}), /0/, true, [], 1, 0.1, (new Boolean(true)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), undefined, (function(){return 0;}), -0, null, (new String('')), (new Number(0)), NaN, '', '/0/', '\\0', (new Number(-0)), 0, [0], '0', (new Boolean(false)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-116066984*/count=1363; tryItOut("/*MXX3*/g0.SyntaxError.prototype.constructor = g1.SyntaxError.prototype.constructor;");
/*fuzzSeed-116066984*/count=1364; tryItOut("a2 = g1.a2.slice(NaN, NaN, a2);");
/*fuzzSeed-116066984*/count=1365; tryItOut("this.v1 = (o1 instanceof b2);");
/*fuzzSeed-116066984*/count=1366; tryItOut("mathy5 = (function(x, y) { return ( ! mathy2(( + ( ! (Math.trunc(Math.max(x, (Math.ceil(y) >>> 0))) | 0))), (( - ( + Math.fround((y * (( ~ y) >>> 0))))) | 0))); }); ");
/*fuzzSeed-116066984*/count=1367; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?=\\\\1{0}|$\\\\b?(?=[^]*([\\\\u0E45-\\\\u549d\\\\\\u0083-\\u00e8\\\\d\\\\s])))){2,5}\", \"gi\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116066984*/count=1368; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-116066984*/count=1369; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.log10(( ~ (Math.tan(( + y)) , ( + Math.atanh(( + ( ~ ((((x >>> 0) ? y : (x >>> 0)) >>> 0) | 0)))))))); }); testMathyFunction(mathy0, [-0x080000000, 0x080000001, -(2**53), -0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53+2, -0, Math.PI, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, 1, 42, Number.MIN_VALUE, -Number.MIN_VALUE, 0, 0x07fffffff, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, 0x0ffffffff, 1/0, -0x100000001, 0x080000000, Number.MAX_VALUE, 0x100000001, -(2**53-2), -0x07fffffff, -0x080000001]); ");
/*fuzzSeed-116066984*/count=1370; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.hypot(( + (Math.hypot((( ~ Math.max((x > y), Math.pow(0x0ffffffff, Math.fround(( ! Math.fround(x)))))) | 0), Math.atan2(Math.fround(Math.atan((Math.sqrt((y + x)) >>> 0))), mathy0(Number.MAX_VALUE, ( ~ Math.fround(-0x080000000))))) | 0)), ( + (mathy0(( + ( - ( + (Math.clz32(y) * (( - x) * Math.max(Math.fround(-0x0ffffffff), y)))))), ((Math.pow(-0x100000000, ((((-0x080000001 | 0) , y) >>> 0) >>> 0)) | 0) !== (((Math.pow((x | 0), (mathy0((x >>> 0), (Math.pow(2**53, y) | 0)) >>> 0)) | 0) % mathy0(mathy0(x, ( + x)), y)) >>> 0))) | 0))) >>> 0); }); testMathyFunction(mathy1, [(new Number(0)), '0', (new Number(-0)), NaN, undefined, '/0/', null, '', 1, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (new Boolean(true)), 0, objectEmulatingUndefined(), -0, (function(){return 0;}), (new Boolean(false)), false, true, 0.1, [], /0/, [0], ({valueOf:function(){return 0;}}), '\\0', (new String(''))]); ");
/*fuzzSeed-116066984*/count=1371; tryItOut("\"use strict\"; switch(/*UUV2*/(c.toLowerCase = c.replace)) { case 8: b0 = this.t2.buffer;break; case x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })( /x/ ), new RegExp(\".|(?:\\u00e3{1,}(?!\\\\B{4097,4099}))+?(?:\\\\3)\", \"gm\")): a1.pop(e1);m1.set( '' , h1);\nfunction f0(g1)  { \"use strict\"; print(uneval(s2)); } \n }");
/*fuzzSeed-116066984*/count=1372; tryItOut("\"use strict\"; v0 = (e1 instanceof t0);");
/*fuzzSeed-116066984*/count=1373; tryItOut("testMathyFunction(mathy2, [-Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -0x080000000, -(2**53+2), -0x100000000, 1.7976931348623157e308, 1, -0x07fffffff, 0x080000001, -0x100000001, 0x100000001, 42, -0x0ffffffff, -(2**53), 2**53-2, Math.PI, Number.MIN_VALUE, -1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), 0.000000000000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, 0x100000000, 2**53, -0, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1374; tryItOut("mathy2 = (function(x, y) { return Math.max(Math.ceil((Math.log2((x | 0)) | 0)), ( + (( + (Math.expm1((( + mathy1((2**53 >>> 0), ( + x))) | 0)) ? Math.fround(( - ( + x))) : ((0x100000001 << (y | 0)) | 0))) < ( + ( + (Math.pow(( + Math.cos(((Math.fround(x) ? y : y) | 0))), ( + 1/0)) | 0)))))); }); ");
/*fuzzSeed-116066984*/count=1375; tryItOut("testMathyFunction(mathy4, [-0x100000001, 0x080000001, 2**53, -(2**53-2), -(2**53), 2**53+2, 0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53+2), 0, -0x0ffffffff, 0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 1, -0x07fffffff, -0x100000000, 0x0ffffffff, 0/0, Math.PI, 1/0, -Number.MAX_SAFE_INTEGER, 42, 2**53-2, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, -0x080000001]); ");
/*fuzzSeed-116066984*/count=1376; tryItOut("s1 += 'x';\n(({}));\n");
/*fuzzSeed-116066984*/count=1377; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ! ( + ( ~ ( - y)))); }); testMathyFunction(mathy2, [0x100000000, -0x100000000, 1/0, -(2**53), -Number.MAX_VALUE, -0x0ffffffff, 0x080000000, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, Number.MIN_VALUE, 0x0ffffffff, 42, -1/0, 2**53+2, 2**53-2, 0.000000000000001, -(2**53+2), 0, -Number.MIN_VALUE, -(2**53-2), 2**53, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 1.7976931348623157e308, 1, -Number.MAX_SAFE_INTEGER, -0x080000000, -0, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1378; tryItOut("mathy2 = (function(x, y) { return ( - (( ! ( + Math.sinh(Math.fround(Math.pow(Math.fround(1), Math.fround(( + Math.imul(( ! x), Math.fround(x))))))))) | 0)); }); testMathyFunction(mathy2, [0/0, -0x100000000, 0.000000000000001, -(2**53+2), -Number.MIN_VALUE, 0x07fffffff, 0, -0x080000001, 42, -0x080000000, 0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, -0, 2**53+2, Number.MIN_VALUE, -1/0, 2**53, 0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_VALUE, Math.PI, -(2**53)]); ");
/*fuzzSeed-116066984*/count=1379; tryItOut("/*MXX2*/g1.RegExp.$9 = this.b1;");
/*fuzzSeed-116066984*/count=1380; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1381; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((0x90ff6919))-(-0x8000000)-(((d0) < (+(((~((0xfdb979d2))) % (abs((0x6f092267))|0))>>>(((((-0.0009765625)) * ((512.0))) == (d0)))))))))|0;\n  }\n  return f; })(this, {ff: Number.parseFloat}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[new Number(1), new Number(1), 0x080000001, new Number(1),  /x/ , 0x5a827999, new Number(1), 0x080000001,  /x/ , 0x080000001, 0x5a827999, x, 0x5a827999, new Number(1), new Number(1),  /x/ , 0x5a827999, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-116066984*/count=1382; tryItOut("v0 = o0.g0.runOffThreadScript();");
/*fuzzSeed-116066984*/count=1383; tryItOut("testMathyFunction(mathy2, [0x080000001, 42, 0/0, Number.MIN_VALUE, -0x0ffffffff, 0x100000000, 0x080000000, -0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), -Number.MAX_VALUE, 2**53, 1.7976931348623157e308, -(2**53), -0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, 0.000000000000001, -0x07fffffff, -Number.MIN_VALUE, Math.PI, 2**53-2, -(2**53+2), 2**53+2, -0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, 1, 0x100000001, 0x07fffffff, 0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1384; tryItOut("g0.a1.pop(m2);");
/*fuzzSeed-116066984*/count=1385; tryItOut("Array.prototype.shift.apply(a1, []);");
/*fuzzSeed-116066984*/count=1386; tryItOut("for (var v of o2.t2) { try { if(Object.preventExtensions(new RegExp(\"\\\\W\", \"im\"), null)) {f0 = o0.e1;o2.a1.push(-2, o2.p1, g2, a0, o2.g1, f2, p2, this.f0, f1, p0, o0.h1, o0.f0, g2.p0, e2, b0); } } catch(e0) { } try { delete i1[new String(\"6\")]; } catch(e1) { } for (var v of p2) { g1.offThreadCompileScript(\"for(let a in []);\\n/* no regression tests found */\\n\"); } }");
/*fuzzSeed-116066984*/count=1387; tryItOut("var eaamyy = new SharedArrayBuffer(8); var eaamyy_0 = new Uint32Array(eaamyy); eaamyy_0[0] = 28; var eaamyy_1 = new Uint8ClampedArray(eaamyy); print(eaamyy_1[0]); eaamyy_1[0] = -17; t0 + '';M:switch((URIError).bind()) { case \n(4277)((eaamyy_1) ? ({ set \"-19\"() { return new RegExp(\"(?!\\\\1{0,3})\", \"gyim\") }  }) : eaamyy_1[0]): yield eaamyy_1[5];break; break; case --x: case 3: i2 = new Iterator(v0);break;  }/*RXUB*/var r = r1; var s = \"\"; print(s.match(r)); t0 + this.f1;o1.g0.m2 = a0[13];v1 = a2[e = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: encodeURI, fix: function() { throw 3; }, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { return undefined }, set: undefined, iterate: decodeURIComponent, enumerate: undefined, keys: window, }; })( /x/g ), eaamyy_1[5])];");
/*fuzzSeed-116066984*/count=1388; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(Math.imul(Math.fround((Math.fround(mathy0(Math.abs(1/0), ((((Math.round(Math.fround((( ~ (y >>> 0)) >>> 0))) | 0) | 0) ** (-0x080000001 | 0)) | 0))) ? (Math.pow(x, -1/0) >>> 0) : Math.fround(( + (( + (Math.sin((y >>> 0)) >>> 0)) ? ( + Math.hypot((x >>> 0), Math.fround(x))) : ( + (( + y) << ( + -0x0ffffffff)))))))), Math.fround(Math.hypot(y, Math.min(y, -0x100000001))))) ? (( ! (Math.max(((x & y) | 0), (x | 0)) ? (( ~ (y | 0)) | 0) : (Math.atan2(Math.fround(Math.pow(x, y)), ( + ( + Math.ceil(( + -0x080000000))))) | 0))) | 0) : ( + mathy1(( - Math.fround(Math.fround(( - x)))), (( + (( + (Math.fround(Math.hypot(x, x)) ** y)) & (Math.atan(-(2**53-2)) >>> 0))) & mathy0(Math.ceil(x), (( - y) | 0)))))); }); testMathyFunction(mathy2, [0x100000000, -0, 0x100000001, -0x0ffffffff, -0x07fffffff, 2**53+2, 0/0, 2**53, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, 42, 0x0ffffffff, 0, -(2**53+2), -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 1.7976931348623157e308, 2**53-2, 0.000000000000001, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 0x080000000, 0x07fffffff, Math.PI, -0x100000000, 1, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, -0x100000001, -(2**53-2)]); ");
/*fuzzSeed-116066984*/count=1389; tryItOut("\"use strict\"; if((x % 6 != 1)) { if ((y = (void options('strict_mode'))).charCodeAt(x = x)) {c = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: b =>  { g0 = this; } , delete: function(name) { return delete x[name]; }, fix: undefined, has: undefined, hasOwn: undefined, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(window), (/(?:[^]\uc44e|\\B++?)|(?!\\x1E{1,2147483649}\\2)+|\\b/g)(-5, b)); } else {print(undefined);; }}");
/*fuzzSeed-116066984*/count=1390; tryItOut("\"use strict\"; (Array.prototype.fill(eval , x.yoyo(\"\\u4329\".__defineSetter__(\"w\", d => (SharedArrayBuffer())))));");
/*fuzzSeed-116066984*/count=1391; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.min(( + ((Math.asinh((mathy2((mathy1(x, y) | 0), (( - y) | 0)) | 0)) ? (Math.atan2(((( + 1) / (y | 0)) >>> 0), ( + (Math.imul((((y + x) >>> 0) >>> 0), (((Number.MIN_SAFE_INTEGER | 0) == y) >>> 0)) >>> 0))) >>> 0) : (Math.fround(((((Math.pow((Math.min(x, 0.000000000000001) >>> 0), (x | 0)) | 0) === y) >>> 0) >>> 0)) >>> 0)) >>> 0)), ( + Math.expm1((Math.max(x, x) | 0))))); }); testMathyFunction(mathy3, [-0x07fffffff, 0x080000001, -0x100000001, 1.7976931348623157e308, 0/0, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, 0x100000000, 0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -Number.MIN_VALUE, 42, 1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -Number.MAX_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, 1, -0x100000000, -(2**53+2), -1/0, Math.PI, 2**53-2]); ");
/*fuzzSeed-116066984*/count=1392; tryItOut("/*RXUB*/var r = new RegExp(\"\\u25dd\", \"\"); var s = \"\\u25dd\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116066984*/count=1393; tryItOut("i0.next();/*infloop*/for(x in ((Math.log10)(false.throw( '' )))){ /x/ ; }");
/*fuzzSeed-116066984*/count=1394; tryItOut("/*tLoop*/for (let w of /*MARR*/[\n((makeFinalizeObserver('tenured'))), new Boolean(true), function(){}, function(){}, function(){}, new Boolean(true), \n((makeFinalizeObserver('tenured'))), \n((makeFinalizeObserver('tenured'))), function(){}, new Boolean(true), \n((makeFinalizeObserver('tenured'))), new Number(1.5), new Boolean(true), function(){}, new Number(1.5), new Boolean(true), \n((makeFinalizeObserver('tenured'))), function(){}, new Number(1.5), function(){}, function(){}, \n((makeFinalizeObserver('tenured'))), new Number(1.5), new Boolean(true), new Boolean(true), function(){}, \n((makeFinalizeObserver('tenured'))), function(){}, new Boolean(true), function(){}, new Number(1.5), function(){}, new Number(1.5), new Boolean(true), \n((makeFinalizeObserver('tenured'))), function(){}, function(){}, new Number(1.5), \n((makeFinalizeObserver('tenured'))), \n((makeFinalizeObserver('tenured'))), new Boolean(true), \n((makeFinalizeObserver('tenured'))), new Number(1.5), new Number(1.5), new Number(1.5), \n((makeFinalizeObserver('tenured'))), new Boolean(true), new Number(1.5), function(){}, \n((makeFinalizeObserver('tenured'))), new Boolean(true), \n((makeFinalizeObserver('tenured'))), function(){}, \n((makeFinalizeObserver('tenured'))), new Number(1.5), \n((makeFinalizeObserver('tenured'))), \n((makeFinalizeObserver('tenured'))), \n((makeFinalizeObserver('tenured'))), \n((makeFinalizeObserver('tenured'))), new Number(1.5), \n((makeFinalizeObserver('tenured'))), new Number(1.5), function(){}, function(){}, new Number(1.5), function(){}, \n((makeFinalizeObserver('tenured'))), function(){}, new Number(1.5), function(){}, new Boolean(true), \n((makeFinalizeObserver('tenured'))), new Number(1.5), new Number(1.5), \n((makeFinalizeObserver('tenured'))), function(){}, new Boolean(true), \n((makeFinalizeObserver('tenured'))), function(){}, \n((makeFinalizeObserver('tenured'))), new Number(1.5), function(){}, function(){}, function(){}, new Boolean(true), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(true), new Boolean(true), function(){}, function(){}, new Boolean(true), new Number(1.5)]) { for (var v of h0) { try { v1 = g1.eval(\" \\\"\\\" .valueOf(\\\"number\\\")\"); } catch(e0) { } o2.t0 = new Float32Array(11); } }");
/*fuzzSeed-116066984*/count=1395; tryItOut("\"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -0.25;\n    var d3 = -4.722366482869645e+21;\n    (Int16ArrayView[0]) = ((i0)*0x49fe1);\n    switch (((((0x82de2917) ? (0xe94dce48) : (0x98dbf4cf))) << ((Uint32ArrayView[4096])))) {\n    }\n    i0 = ((Int16ArrayView[1]));\n    {\n      return +((7.555786372591432e+22));\n    }\n;    d2 = (Infinity);\n    i1 = ((((i0)-(0xffffffff)) & (((0xc6604400) == ((((0x7fffffff) == (0x63968c6e))-((0x52d61224) != (0xea83e119)))>>>(((((0xd1a06948)) ^ ((-0x8000000))) >= ((yield  '' )))))))));\n    return +((d2));\n  }\n  return f; })(this, {ff: Uint32Array}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x07fffffff, -Number.MIN_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, -1/0, 42, 1.7976931348623157e308, -0x100000001, 0x080000000, Math.PI, Number.MAX_VALUE, 0x0ffffffff, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 1, 0.000000000000001, 0, -(2**53-2), 2**53, -0x080000000, -(2**53+2), 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, 2**53-2, -0, -0x080000001, 0x100000001, -0x07fffffff, 2**53+2, 0x080000001]); ");
/*fuzzSeed-116066984*/count=1396; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1397; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=1398; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-116066984*/count=1399; tryItOut("for (var v of t1) { v2 = g2.runOffThreadScript(); }");
/*fuzzSeed-116066984*/count=1400; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\3\", \"yi\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=1401; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy4(Math.max(( + ( + ( ~ y))), ( + ( - Math.fround(Math.fround(Math.fround(x)))))), ((((Math.acosh(((( + ( ! ( + ( ~ ((x >>> 0) > (x >>> 0)))))) !== x) >>> 0)) >>> 0) | 0) ? (Math.fround((Math.fround(( + ( ~ Math.atan(x)))) ^ Math.fround((Math.fround((( ~ (( - y) >>> 0)) >>> 0)) + Math.fround((((y >>> 0) ** Math.fround(mathy3((Math.imul((x | 0), (y | 0)) | 0), 0x080000000))) | 0)))))) | 0) : ((((( - y) | 0) ** ( + Math.pow(Math.sinh((Math.fround(Math.trunc(Math.fround(y))) + x)), (Math.cosh((( ~ 0/0) | 0)) | 0)))) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy5, [1/0, -0x080000000, -0x07fffffff, 0x100000000, Number.MAX_VALUE, Math.PI, -0x100000001, 1, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53, -(2**53+2), -0, -(2**53-2), -0x100000000, -(2**53), -0x0ffffffff, 0x080000001, 0x080000000, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, -Number.MAX_VALUE, 2**53-2, 0x100000001, 0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, -1/0, 2**53+2]); ");
/*fuzzSeed-116066984*/count=1402; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( ! ( + ( ! Math.fround((Math.fround(Math.fround(Math.sign(Math.fround(y)))) , Math.fround(Math.imul(Math.fround(((((0.000000000000001 >>> 0) == (x >>> 0)) >>> 0) ? 0.000000000000001 : Math.log2(Math.fround((-0x07fffffff ** Math.fround(x)))))), Math.fround(( ~ y)))))))))); }); testMathyFunction(mathy3, [1/0, -0x080000000, -0x07fffffff, -(2**53-2), 0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, -(2**53+2), 2**53+2, 0.000000000000001, 0/0, 2**53-2, -0x100000001, 0x0ffffffff, -1/0, Math.PI, 0, 0x100000000, 1, -Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, -0, 0x07fffffff]); ");
/*fuzzSeed-116066984*/count=1403; tryItOut("\"use strict\"; var zncewl = new ArrayBuffer(8); var zncewl_0 = new Float32Array(zncewl); print(zncewl_0[0]); var zncewl_1 = new Int16Array(zncewl); print(zncewl_1[0]); zncewl_1[0] = -570605594; i1 = new Iterator(o2.f0, true);");
/*fuzzSeed-116066984*/count=1404; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + ( ~ Math.fround((Math.fround(Math.min(Math.sinh((y >= (y | 0))), ((Math.fround((Math.fround(x) - Math.fround(y))) ? ( + Math.cosh(( + Math.fround(( + y))))) : Math.fround((Math.fround(0.000000000000001) === x))) * ( + Math.pow(y, (((x >>> 0) !== (x | 0)) >>> 0)))))) < Math.fround(( ~ y)))))); }); testMathyFunction(mathy4, [-(2**53+2), -1/0, -0x07fffffff, 1.7976931348623157e308, -0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53), 0/0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, 0.000000000000001, -0x100000000, -0x100000001, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, 0x080000001, -Number.MAX_VALUE, 0x100000000, Math.PI, -0x080000000, 0x0ffffffff, 2**53+2, 0, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, 1]); ");
/*fuzzSeed-116066984*/count=1405; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! Math.hypot((( + y) & ( - x)), Math.max(mathy2(( + ( ! (( ! (2**53 >>> 0)) >>> 0))), ( - -Number.MIN_SAFE_INTEGER)), ( + -Number.MAX_VALUE)))); }); testMathyFunction(mathy4, [-1/0, 2**53, -Number.MIN_VALUE, -0x100000001, Math.PI, -0x080000000, -0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53+2), 1, -0, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, -(2**53), 1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, Number.MAX_VALUE, 0, -0x07fffffff, 0.000000000000001, 42, 0x080000001, -0x080000001, -0x0ffffffff, 0x100000001]); ");
/*fuzzSeed-116066984*/count=1406; tryItOut("/*tLoop*/for (let d of /*MARR*/[true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, ['z'], ['z'], true, true, true, true, true, true, true, true, ['z'], ['z'], true, true, ['z'], true, ['z'], ['z'], true, true, ['z'], ['z'], true, ['z'], ['z'], ['z'], ['z'], true, ['z'], true, ['z'], true, true, true, ['z'], ['z'], ['z'], true, ['z'], ['z'], true, true, true, true, ['z'], ['z'], ['z'], ['z'], true, true, ['z'], true, true, true, true, ['z'], true, true, ['z'], true, ['z'], true, true, true, ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], true, ['z'], ['z'], ['z'], true, true, ['z'], ['z'], ['z'], true, ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], true, ['z'], true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true]) { /*RXUB*/var r = /(?!(\\1)|\\\u07ad+|\\C|$|(?=$(\\W)+|(\\B))\\b)/i; var s = \"\"; print(r.test(s));  }");
/*fuzzSeed-116066984*/count=1407; tryItOut("mathy2 = (function(x, y) { return (mathy1((( + mathy1(( + ( + (( ~ (Math.fround(Math.pow(( + Math.log2(( + 0x080000001))), Math.fround(((x >>> 0) >= (( + Math.max((x >>> 0), ( + y))) >>> 0))))) >>> 0)) >>> 0))), ( + ( - ( + ( + mathy1((x >>> 0), ( + y)))))))) >>> 0), (( + ( - ( + (( + 0x100000001) ? ( + (( ~ (y | 0)) | 0)) : ( + Math.fround(((( - ( + (y < x))) | 0) >>> mathy0(y, 0)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[-Infinity]); ");
/*fuzzSeed-116066984*/count=1408; tryItOut("\"use strict\"; o0.i1.__proto__ = v2;");
/*fuzzSeed-116066984*/count=1409; tryItOut("/*infloop*/for(b = String(function ([y]) { }); new RegExp(\"(((?![\\uef5e\\\\x36-\\\\x52\\\\u006c]?^|[^])(?!\\\\B)+|\\\\B|\\\\b[\\u1820]|\\\\S?))\", \"im\"); (4277)) {/*ADP-2*/Object.defineProperty(a1, ({valueOf: function() { print(x);return 6; }}), { configurable: (b % 3 != 2), enumerable: (x % 46 != 16), get: (function(j) { if (j) { try { s1 = a1.join(s1, \"\\uD0F0\", f0); } catch(e0) { } a2.shift(b1, m0); } else { try { r1 = /\\x42/ym; } catch(e0) { } try { this.o0.f2.toSource = f1; } catch(e1) { } try { s2 + g0; } catch(e2) { } const v2 = r1.sticky; } }), set: (function() { v1 = g2.eval(\"v0 = evaluate(\\\"18;\\\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: window, noScriptRval: false, sourceIsLazy: true, catchTermination: false }));\"); return p0; }) }); }");
/*fuzzSeed-116066984*/count=1410; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((Math.log10((x ? ((Math.pow((y >>> 0), (y >>> 0)) ? ((x | ( + ( + y))) >>> 0) : ( + Math.PI)) >>> 0) : ( + Math.fround(Math.fround((Math.min(y, y) ^ ( + Math.PI))))))) >>> 0) , Math.hypot(( - mathy4(( + mathy4(x, (y | 0))), Math.abs(Math.fround(Math.min((y | 0), (( + (( + -0x0ffffffff) | ( + x))) | 0)))))), Math.atan(y))); }); testMathyFunction(mathy5, [42, -(2**53-2), -Number.MAX_VALUE, 2**53, 0x080000001, -0x080000001, -0x07fffffff, Number.MIN_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, -0x080000000, -0, 2**53-2, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, 0x0ffffffff, -0x100000001, Math.PI, 0/0, -(2**53+2), 1.7976931348623157e308, -Number.MIN_VALUE, -1/0, 0x100000001, 0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000]); ");
/*fuzzSeed-116066984*/count=1411; tryItOut("for (var v of h1) { try { Array.prototype.shift.call(a2, m2); } catch(e0) { } try { for (var v of g1) { try { v0 = new Number(-Infinity); } catch(e0) { } try { a0.push(); } catch(e1) { } e0.has(v1); } } catch(e1) { } Array.prototype.reverse.apply(a2, []); }");
/*fuzzSeed-116066984*/count=1412; tryItOut("(new RegExp(\"\\\\w\\\\D|(?=(?![\\\\S\\u52ab-\\u7f6d]))\", \"g\").watch(\"parse\", Map.prototype.values));a2 = g1.a0.slice(NaN, NaN);");
/*fuzzSeed-116066984*/count=1413; tryItOut("\"use strict\"; this.o2.a2.unshift(b2, g2, m0);");
/*fuzzSeed-116066984*/count=1414; tryItOut("print(x);");
/*fuzzSeed-116066984*/count=1415; tryItOut("/*bLoop*/for (let zvteia = 0; zvteia < 125; ++zvteia) { if (zvteia % 2 == 1) { if(false) print(this); } else { \"\\uB1F8\";\nm1.set(h1, this.h2);\n }  } ");
/*fuzzSeed-116066984*/count=1416; tryItOut("\"use strict\"; {with( '' )new RegExp(\"([^\\\\d]|\\\\b{3,4}|([^\\\\f])[^]{2,}|[\\u6e4a-\\\\0\\u0770])*?\", \"gm\");h2.defineProperty = (function() { try { for (var v of b0) { try { this = t0[13]; } catch(e0) { } try { g1.v1 = t1.length; } catch(e1) { } try { delete o1.h1.get; } catch(e2) { } e1.add(b0); } } catch(e0) { } try { const g0.v1 = t1.byteLength; } catch(e1) { } m0.set(p0, o1.e0); return e1; }); }");
/*fuzzSeed-116066984*/count=1417; tryItOut("\"use strict\"; delete t2[(makeFinalizeObserver('nursery'))];");
/*fuzzSeed-116066984*/count=1418; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.pow(( - ( - mathy1(x, x))), ( - (( ! ((x !== x) | 0)) | 0))); }); ");
/*fuzzSeed-116066984*/count=1419; tryItOut("Array.prototype.shift.call(a1, o1.g1.s1, i2);");
/*fuzzSeed-116066984*/count=1420; tryItOut("print(o1);");
/*fuzzSeed-116066984*/count=1421; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1422; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround(Math.pow(Math.cbrt((42 - y)), Math.fround(Math.fround(mathy1(y, ( ~ mathy0((y | 0), Math.fround((y ? y : Math.fround(y)))))))))) ** Math.fround(Math.round(Math.fround((((Math.atan2((((Math.fround(((-(2**53+2) % y) | 0)) ? Math.fround(Math.trunc(x)) : Math.fround(2**53)) >>> 0) >= y), x) | 0) && ((y > x) | 0)) | 0))))); }); ");
/*fuzzSeed-116066984*/count=1423; tryItOut("e2.delete(o2.g2);");
/*fuzzSeed-116066984*/count=1424; tryItOut("with(((intern((/*wrap3*/(function(){ \"use strict\"; var emtuvj = undefined; (decodeURIComponent)(); })).apply))((4277))))(new Float64Array(d = {}));");
/*fuzzSeed-116066984*/count=1425; tryItOut("\"use strict\"; /*oLoop*/for (var mesqrj = 0, \"\\uEE44\"; mesqrj < 102; ++mesqrj) { window; } ");
/*fuzzSeed-116066984*/count=1426; tryItOut("\"use asm\"; yield;/*MXX1*/o2 = g1.Proxy.revocable;");
/*fuzzSeed-116066984*/count=1427; tryItOut("o0.m2.get(o1);");
/*fuzzSeed-116066984*/count=1428; tryItOut("\"use strict\"; v1 = (e2 instanceof m1);");
/*fuzzSeed-116066984*/count=1429; tryItOut("\"use strict\"; t0[3] = e2;");
/*fuzzSeed-116066984*/count=1430; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (0xfc5d30e8);\n    (Int32ArrayView[(((Int32ArrayView[4096])) % (0xc2c6fdd)) >> 2]) = ((i1)+(/*FFI*/ff(((((((+((-65.0)))) % ((+(((i1))>>>((0x5935edd) / (0x68fa959d))))))) - ((Float64ArrayView[2])))), ((((((i1)) ^ ((0xf8f294c4)-(-0x8000000))) % (((0x960973ac)+(0xb30db5ca)) | ((i0)))) ^ (((((i1)+(i0)) | ((i0))))))))|0));\n    return (((0x117362bf) / (((i0))>>>((i0)-((-4.722366482869645e+21) >= (+((((-1.888946593147858e+22)) % ((9.671406556917033e+24))))))))))|0;\n    return ((((i0) ? (/*FFI*/ff((((0xec37d5b) ? (129.0) : (0.5))), ((+(-1.0/0.0))), ((imul((i1), ((0x225210f) ? (0xeda9b8d5) : (-0x8000000)))|0)), ((NaN)), ((((0xe3bc8d1)) ^ ((0x8625b934)))), ((~~(1073741825.0))), ((1.03125)), ((1.5111572745182865e+23)), ((-5.0)), ((-536870911.0)))|0) : (i0))))|0;\n  }\n  return f; })(this, {ff: Math.atanh}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0x07fffffff, 0x07fffffff, Math.PI, -(2**53+2), 0x100000000, 0x100000001, 2**53-2, -0x100000000, -0x0ffffffff, 0x0ffffffff, 0/0, 0.000000000000001, -0x100000001, 0x080000000, 0x080000001, 0, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 1, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -0, 2**53+2, -(2**53-2), -Number.MIN_VALUE, -(2**53), 1/0, -0x080000001, 2**53, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1431; tryItOut("\"use strict\"; /*hhh*/function ueirda(window, y, 1 = (4277), e, x = [].__defineSetter__(\"x\", (Map.prototype.delete).bind), z, x = -25, x, w, x, e, eval, window, z =  /x/g , x, z, z, x, a, \u3056 = Math, eval, getter, x, e, x, x, x, eval, x, x =  /x/g , window, y, y = -0, x = -17, d, w, x, x, y, \u3056, z, c, x, \"\\u18E7\", a, NaN, \u3056, window, z, \u3056, x, x, x = 0, x){fjhqtr, x, x, nkgilh, \u3056, x, NaN, x;;}ueirda((4277) === (let (a = eval) false), (/*RXUE*//(?!(?=(?!(?:\\s$)))[^]{2,6}|[^]{3})/gym.exec(\"\")));");
/*fuzzSeed-116066984*/count=1432; tryItOut("mathy5 = (function(x, y) { return (Math.clz32(((mathy1((mathy2(Math.min(Math.imul(y, (Math.pow((y >>> 0), (x >>> 0)) >>> 0)), (mathy2(y, (x >>> 0)) | 0)), y) | 0), ((x ** ( + (y ? ( + (Math.acosh(y) | 0)) : Math.imul(x, y)))) >>> 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x0ffffffff, 1.7976931348623157e308, -1/0, -0x0ffffffff, 0x07fffffff, -0, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, 0x080000000, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, 0x100000000, 42, -(2**53-2), 2**53, Number.MIN_SAFE_INTEGER, 0, -0x100000000, Number.MAX_VALUE, 1, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, -0x080000000, -0x100000001, 1/0, 2**53+2, -(2**53)]); ");
/*fuzzSeed-116066984*/count=1433; tryItOut("mathy5 = (function(x, y) { return (Math.pow(Math.abs((Math.fround(Math.pow(Math.pow(x, x), x)) <= Math.fround((0x100000000 | (Math.acosh((( + ( + ( + (2**53-2 ? (x >>> 0) : x)))) | 0)) | 0))))), ( + Math.log2(( + ( ~ -(2**53)))))) | 0); }); ");
/*fuzzSeed-116066984*/count=1434; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( + (Math.hypot((x | 0), ((x !== Math.tanh(2**53+2)) | 0)) | 0)) === (( + (Math.fround(Math.fround(Math.fround(Math.atan2(mathy2(y, ( + (( + 2**53-2) - ( + x)))), Math.fround((Number.MIN_VALUE ** Math.fround(42))))))) | 0)) | 0)); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 1/0, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 42, 0, 1.7976931348623157e308, -(2**53+2), 0x080000001, -(2**53), 2**53, 0x0ffffffff, 0x07fffffff, 0x100000000, 2**53+2, Number.MIN_VALUE, 0/0, 0x080000000, Math.PI, -0, -0x07fffffff, 2**53-2, 0.000000000000001, -0x080000001, -0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-116066984*/count=1435; tryItOut("\"use strict\"; ((forEach).eval(\"'fafafa'.replace(/a/g, /\\\\s|\\\\W(?:\\\\S){0,0}|(?:^){2,}\\\\B*|$+?|((?:$\\\\0*?))/gm)\"));");
/*fuzzSeed-116066984*/count=1436; tryItOut("mathy0 = (function(x, y) { return ( + ( ~ (( ! ((Math.ceil(x) , y) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [0x080000001, 0/0, Math.PI, -0x100000000, 0.000000000000001, 0, -Number.MIN_SAFE_INTEGER, 0x080000000, -0, 2**53+2, Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), 0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000000, 2**53, -(2**53+2), -0x080000001, 1, -0x100000001, 0x100000001, -(2**53), 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 42, -1/0, 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1437; tryItOut("var rshkpt = new SharedArrayBuffer(0); var rshkpt_0 = new Int16Array(rshkpt); var rshkpt_1 = new Uint8Array(rshkpt); print(rshkpt_1[0]); rshkpt_1[0] = -29; var rshkpt_2 = new Int32Array(rshkpt); rshkpt_2[0] = -26; var rshkpt_3 = new Int8Array(rshkpt); rshkpt_3[0] = 29; var rshkpt_4 = new Uint8Array(rshkpt); t1[16] = (Int8Array)( \"\" , ({a2:z2}));");
/*fuzzSeed-116066984*/count=1438; tryItOut("\"use strict\"; /* no regression tests found */;");
/*fuzzSeed-116066984*/count=1439; tryItOut("v2 = (o0 instanceof g0);");
/*fuzzSeed-116066984*/count=1440; tryItOut("\"use strict\"; v2 = (this.g1 instanceof t2);");
/*fuzzSeed-116066984*/count=1441; tryItOut("/*MXX1*/o1 = g1.String.prototype.endsWith;");
/*fuzzSeed-116066984*/count=1442; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1443; tryItOut("mathy1 = (function(x, y) { return Math.atan2((( + (Math.round((mathy0(Math.fround((( + Math.max(x, (y | 0))) ? (Math.imul(0x0ffffffff, (y >>> 0)) >>> 0) : ( + x))), 2**53) >>> 0)) | 0)) * (Math.cos((y ? x : Math.sinh(0x07fffffff))) >>> 0)), ( + Math.clz32(mathy0(Math.fround((( ! (Math.sinh(( + Math.log1p(x))) | 0)) | 0)), (Math.log1p((( + mathy0(y, ( + x))) | 0)) | 0))))); }); testMathyFunction(mathy1, [42, 2**53+2, 0/0, 0x100000000, -1/0, 0x080000000, 1/0, 0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, -0x0ffffffff, -0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), -0, Math.PI, -(2**53+2), Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, -(2**53), 0x0ffffffff, 0, 0x080000001, 1]); ");
/*fuzzSeed-116066984*/count=1444; tryItOut("for (var p in b0) { try { for (var v of e2) { try { print(uneval(o0.t0)); } catch(e0) { } Array.prototype.splice.apply(a0, [a0, f2, b2]); } } catch(e0) { } Object.defineProperty(this, \"v1\", { configurable: false, enumerable: true,  get: function() {  return evalcx(\"/* no regression tests found */\", g2); } }); }");
/*fuzzSeed-116066984*/count=1445; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1446; tryItOut("\"use strict\"; m0.set(m0, o1.v0);");
/*fuzzSeed-116066984*/count=1447; tryItOut("var x, qsmmvz, qrwxle, x, nugyia, eval, gigmle, x, z;yield x;");
/*fuzzSeed-116066984*/count=1448; tryItOut("\"use strict\"; ;");
/*fuzzSeed-116066984*/count=1449; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1450; tryItOut("");
/*fuzzSeed-116066984*/count=1451; tryItOut("v2 = (s1 instanceof g2.h2);");
/*fuzzSeed-116066984*/count=1452; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1453; tryItOut("v2 + '';");
/*fuzzSeed-116066984*/count=1454; tryItOut("/*MARR*/[objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments, arguments, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments, new String('q'), (0/0), (0/0), new String('q'), new String('q'), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), arguments, new String('q'), arguments, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments, arguments, arguments, new String('q'), arguments, new String('q')];");
/*fuzzSeed-116066984*/count=1455; tryItOut("this.v1 = this.g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-116066984*/count=1456; tryItOut("");
/*fuzzSeed-116066984*/count=1457; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-116066984*/count=1458; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-116066984*/count=1459; tryItOut("e2.delete(b2);");
/*fuzzSeed-116066984*/count=1460; tryItOut("testMathyFunction(mathy2, [0, 0x100000001, -1/0, -0x100000001, 1/0, 1.7976931348623157e308, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, 0x080000001, 0/0, 2**53+2, -0x080000001, -(2**53-2), -0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, 0x0ffffffff, Math.PI, 42, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, -0x100000000, -0, 0x100000000, Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-116066984*/count=1461; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + (Math.imul((Math.imul(Math.fround(Math.min(Math.fround(((Math.acosh(y) >>> 0) % ( + Math.fround(( ~ Math.fround(-0x100000000)))))), Math.max(y, mathy3(0x080000000, y)))), Math.fround(Math.acosh(Math.asin(Math.acos((y | 0)))))) >>> 0), (Math.cosh((((((y && x) | 0) ** (Math.max(((Math.hypot(y, ( + Math.fround(( - Math.fround(y))))) | 0) | 0), (y | 0)) | 0)) | 0) >>> 0)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -1/0, 2**53-2, 42, -Number.MIN_VALUE, 0x080000001, -0, -(2**53), -(2**53+2), -0x07fffffff, -0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 0/0, 0x100000001, 0.000000000000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -(2**53-2), 1/0, -Number.MAX_VALUE, 0x100000000, 1, -0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -0x080000001]); ");
/*fuzzSeed-116066984*/count=1462; tryItOut("v0 = Object.prototype.isPrototypeOf.call(e2, o1);");
/*fuzzSeed-116066984*/count=1463; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(b2, e1);");
/*fuzzSeed-116066984*/count=1464; tryItOut("v0 = b2.byteLength;");
/*fuzzSeed-116066984*/count=1465; tryItOut("print(eval(\"\\\"use strict\\\"; mathy3 = (function(x, y) { return Math.fround(Math.sin(Math.fround(Math.fround((Math.fround(Math.sin(Math.fround(Math.log1p(Math.fround(y))))) & Math.fround(((mathy2(x, -(2**53)) && 42) >>> 0))))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 2**53, 42, 0x100000001, 0x080000000, -0x07fffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, -0, Number.MAX_VALUE, Math.PI, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 0.000000000000001, -(2**53-2), 2**53-2, 0, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 0x0ffffffff, -(2**53), -(2**53+2), 0x100000000, 0/0, 0x080000001, -0x0ffffffff, -1/0, 1, -Number.MIN_VALUE, 1.7976931348623157e308]); \") instanceof ((function sum_slicing(qlwxzv) { ; return qlwxzv.length == 0 ? 0 : qlwxzv[0] + sum_slicing(qlwxzv.slice(1)); })(/*MARR*/[undefined, undefined, -(2**53), -(2**53), new Boolean(true), -(2**53), -(2**53), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, new Boolean(true), new Boolean(true), -(2**53), new Boolean(true), undefined, new Boolean(true), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(true), undefined])));\nObject.preventExtensions(g2.s2);\n");
/*fuzzSeed-116066984*/count=1466; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (/*FFI*/ff(((4194305.0)))|0);\n    return (((Int32ArrayView[((0xfb12adeb)) >> 2])))|0;\n  }\n  return f; })(this, {ff: ((({toUpperCase: /*UUV2*/(this.z.setInt8 = this.z.call) }))((p={}, (p.z = true)())))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=1467; tryItOut("\"use strict\"; e0.delete(o2.p1);");
/*fuzzSeed-116066984*/count=1468; tryItOut("\"use strict\"; /*oLoop*/for (var pyhxlz = 0; pyhxlz < 55; ++pyhxlz) {  for  each(b in new Function && let (vyvrev, sabzyq, a)  /x/ ) print(x); } ");
/*fuzzSeed-116066984*/count=1469; tryItOut("L:with({z: Math.imul(-27, (Object.defineProperty(b, \"1\", ({value: x, writable: true}))))})h1.keys = f2;");
/*fuzzSeed-116066984*/count=1470; tryItOut("a0.valueOf = (function() { for (var j=0;j<7;++j) { f2(j%5==1); } });");
/*fuzzSeed-116066984*/count=1471; tryItOut("\"use strict\"; g2.t1.set(this.g2.t0, 12);");
/*fuzzSeed-116066984*/count=1472; tryItOut("\"use asm\"; i0.send(t0);");
/*fuzzSeed-116066984*/count=1473; tryItOut("/*vLoop*/for (zdsphm = 0; zdsphm < 21; ++zdsphm) { let e = zdsphm; o1 = o0.e1.__proto__; } ");
/*fuzzSeed-116066984*/count=1474; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var atan2 = stdlib.Math.atan2;\n  var cos = stdlib.Math.cos;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    (Float32ArrayView[4096]) = ((524289.0));\n    i0 = (i0);\n    d1 = (2305843009213694000.0);\n    d1 = (Infinity);\n    return +((+atan2(((+cos(((+abs(((1.0)))))))), ((-131072.0)))));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x07fffffff, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), -0, -0x100000000, -(2**53+2), -0x07fffffff, 0x100000001, 1, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, Number.MAX_VALUE, 1/0, 2**53+2, Number.MIN_VALUE, 0, 2**53-2, -1/0, 0x080000000, -(2**53), -0x080000001, 2**53, Math.PI, 0.000000000000001, -0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 42, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1475; tryItOut("/*RXUB*/var r = /\\w*(\\s)|\\1/m; var s = [] = {window: x}; print(uneval(r.exec(s))); ");
/*fuzzSeed-116066984*/count=1476; tryItOut("\"use strict\"; with((void version(185))){/* no regression tests found */print(x--); }");
/*fuzzSeed-116066984*/count=1477; tryItOut("/*tLoop*/for (let x of /*MARR*/[ /x/ ,  /x/ ,  /x/ , [1],  /x/ ,  /x/ , [1],  /x/ , [1],  /x/ , [1],  /x/ ,  /x/ , [1],  /x/ , [1],  /x/ ,  /x/ ,  /x/ , [1],  /x/ ,  /x/ ,  /x/ , [1], [1], [1],  /x/ ,  /x/ ,  /x/ , [1],  /x/ , [1],  /x/ ,  /x/ ,  /x/ ,  /x/ , [1],  /x/ , [1]]) { Object.preventExtensions(v1); }");
/*fuzzSeed-116066984*/count=1478; tryItOut("/*vLoop*/for (let ircjjy = 0; ircjjy < 8; ++ircjjy) { const x = ircjjy; /*tLoop*/for (let a of /*MARR*/[\"\\u661E\",  /x/ , \"\\u661E\", [], \"\\u661E\", [], [],  /x/ , [],  /x/ , [], [], [], [], \"\\u661E\", [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [],  /x/ , \"\\u661E\", new String('q'), (void 0)]) { a1[v2] = b2; } } ");
/*fuzzSeed-116066984*/count=1479; tryItOut("\"use strict\"; e1 = new Set(o1);");
/*fuzzSeed-116066984*/count=1480; tryItOut("for (var v of g2) { try { for (var p in g0.s1) { try { h1.iterate = (function() { try { i1.next(); } catch(e0) { } /*RXUB*/var r = r0; var s = \"\\u5200\"; print(r.test(s));  return g1; }); } catch(e0) { } try { Object.defineProperty(this, \"t2\", { configurable: false, enumerable: new function shapeyConstructor(ilnbcy){\"use strict\"; Object.preventExtensions(ilnbcy);ilnbcy[\"getDay\"] = 0/0;{ h0 + ''; } ilnbcy[\"toSource\"] = Number.MIN_VALUE;delete ilnbcy[\"getDay\"];ilnbcy[\"getDay\"] = -(2**53);return ilnbcy; }(),  get: function() {  return Proxy.create(h0, h1); } }); } catch(e1) { } try { Object.defineProperty(this, \"t0\", { configurable: NaN + toString, enumerable: true,  get: function() {  return new Uint16Array(b1); } }); } catch(e2) { } g1.v1 = evalcx(\"v0 = a1.reduce, reduceRight((function() { try { a2 + ''; } catch(e0) { } t0 = t2.subarray(19); return h0; }), h2, a0, e1);\", g0); } } catch(e0) { } Array.prototype.push.apply(a1, [o1.h1, e2, o1.b1]); }");
/*fuzzSeed-116066984*/count=1481; tryItOut("testMathyFunction(mathy3, [0x0ffffffff, -0x07fffffff, -(2**53-2), 1, 1/0, 2**53-2, 0x07fffffff, 0.000000000000001, -0x100000000, 2**53+2, 0/0, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), Math.PI, -(2**53+2), 0x100000000, Number.MAX_VALUE, -0x080000001, -0x0ffffffff, -0, 42, 2**53, -Number.MIN_VALUE, 0, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1482; tryItOut("\"use strict\"; h1.hasOwn = (function() { for (var j=0;j<128;++j) { f0(j%3==1); } });");
/*fuzzSeed-116066984*/count=1483; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + ((Math.atan2(Math.tanh(( ~ Math.fround(Math.cbrt(y)))), Math.trunc(-0x07fffffff)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 1/0, -0x100000000, -0x080000001, -0x07fffffff, 0x080000001, Math.PI, -0, 0, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 0/0, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, 0x100000000, 0x07fffffff, -1/0, -Number.MAX_VALUE, -(2**53+2), 2**53, 1, 0x100000001, 2**53-2, 42, 2**53+2]); ");
/*fuzzSeed-116066984*/count=1484; tryItOut("t2[(void shapeOf(x))] = a0;");
/*fuzzSeed-116066984*/count=1485; tryItOut("f1 + this.a0;");
/*fuzzSeed-116066984*/count=1486; tryItOut("print((Math.cosh( \"\" )));h0.delete = f1;");
/*fuzzSeed-116066984*/count=1487; tryItOut("return x;");
/*fuzzSeed-116066984*/count=1488; tryItOut("/*iii*/if((x % 12 == 6)) { if (let (b) ({b: \"\\u5704\"})) {o2.g1.o2.i2.next();m1.set(o1, v0); }} else {print(x);g0.a0 = g0.o1.t1[15]; }/*hhh*/function eqrbac(y, [\u3056, , , ]){/* no regression tests found */}");
/*fuzzSeed-116066984*/count=1489; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.pow((mathy1((Math.acos((Math.sinh((Math.cosh(x) | 0)) == Number.MAX_SAFE_INTEGER)) | 0), mathy1((1 | 0), x)) >>> 0), Math.imul(Math.fround(( + Math.pow(Math.acos(Math.imul(x, x)), Math.min(( + ((Number.MAX_SAFE_INTEGER | Number.MAX_VALUE) >>> 0)), ((2**53-2 , 2**53-2) >>> 0))))), (Math.imul(((((( + (( + (-0x080000000 != 0x07fffffff)) != ( + x))) | 0) & (( - (( ~ y) >>> 0)) | 0)) | 0) >>> 0), ((((x | 0) ? (( ~ ( + Math.fround(( + 0/0)))) | 0) : Math.fround(( + Math.tan(x)))) | 0) >>> 0)) | 0))); }); testMathyFunction(mathy5, [-(2**53+2), 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), 0x080000000, -1/0, -Number.MIN_VALUE, 0x100000001, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000000, 2**53+2, -(2**53), 2**53-2, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, 2**53, 0x100000000, -0x100000000, 0/0, -0, 1, Math.PI, -0x100000001, 0x0ffffffff, Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1490; tryItOut("v2 = Object.prototype.isPrototypeOf.call(e0, h2);");
/*fuzzSeed-116066984*/count=1491; tryItOut("mathy4 = (function(x, y) { return (((( ~ ((((42 || Math.fround((Math.fround(-Number.MIN_VALUE) / Math.fround(-Number.MAX_SAFE_INTEGER)))) - (( ! (x | 0)) | 0)) | 0) >>> 0)) << ( + (( + (Math.max((y | 0), x) | 0)) && Math.log(0/0)))) >>> 0) !== ( + ( + ( - ( ~ (Math.fround(((x >>> 0) ? y : Math.fround(y))) && ( + x))))))); }); testMathyFunction(mathy4, [42, 0, 0x07fffffff, -1/0, 0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, 0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, Number.MIN_VALUE, -0x07fffffff, 2**53+2, -0x080000000, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, 0x080000001, Math.PI, -Number.MIN_VALUE, -0x100000000, -0, Number.MAX_SAFE_INTEGER, 1, 0x100000000, 2**53-2, -0x080000001, -(2**53-2), -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-116066984*/count=1492; tryItOut("v0 = g2.eval(\"/* no regression tests found */\");");
/*fuzzSeed-116066984*/count=1493; tryItOut("\"use strict\"; /*vLoop*/for (tlnziw = 0; tlnziw < 22; ++tlnziw) { let y = tlnziw; print(this.zzz.zzz = /*MARR*/[ \"\" , 3/0,  \"use strict\" , 3/0, new String('')].map(function shapeyConstructor(sozdbr){\"use strict\"; this[8] = (0/0);Object.defineProperty(this, \"toString\", ({}));Object.preventExtensions(this);Object.defineProperty(this, 8, ({configurable: (x % 5 != 4), enumerable: 14}));return this; }, (4277))); } ");
/*fuzzSeed-116066984*/count=1494; tryItOut("/*infloop*/for(arguments[\"toPrecision\"] in ((function  \u3056 (x, c = x.__defineSetter__(\"x\", function(y) { yield y; i0.send(o1);; yield y; }), y, a, a, y, eval, x =  /x/ , y, x, x, x, a, x, x, z, x, x, z, x, w, x, x, x = \"\u03a0\", y, y, d, e, this, x, x, d, x, x, x, x, window, window, x, x, window, x = new RegExp(\"(?:(?:(\\\\b))){0,4}\", \"g\"), d, eval, window, x, \u3056, x, a, y, b, window, NaN, e,  , multiline, w, w = -15)(OSRExit((c * c))))( \"\" ))){(c) = x;print(uneval(v1)); }");
/*fuzzSeed-116066984*/count=1495; tryItOut("for (var v of g1.v1) { g1.valueOf = (function() { try { this.s1 = Proxy.create(g2.o2.h1, t1); } catch(e0) { } try { v2 = (e0 instanceof o2); } catch(e1) { } try { t1.__proto__ = s2; } catch(e2) { } v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (4277), noScriptRval: window, sourceIsLazy: true, catchTermination: (x % 4 != 1), sourceMapURL: s1 })); return o1; }); }");
/*fuzzSeed-116066984*/count=1496; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + (( + Math.fround((Math.fround(mathy1(x, (( + Math.log2(( + (y < (x >>> 0))))) >>> 0))) , Math.fround(( ~ Math.cosh((((-0x100000001 | 0) > (Math.pow(y, Math.log2(y)) | 0)) | 0))))))) ? ( ~ (( + (( + (((2**53+2 | 0) ** (mathy1(( + y), x) | 0)) | 0)) ** ( + (((y >>> 0) ? (( ! x) >>> 0) : x) >>> 0)))) | 0)) : ((Math.pow(( + Math.log1p(0x080000000)), (((Math.imul((Math.acosh((x >>> 0)) | 0), y) >>> 0) != (y >>> 0)) >>> 0)) ? ( - (Math.exp((x | 0)) | 0)) : ( + ( + mathy1(x, (( + -(2**53-2)) << ( + (-0x100000001 * -Number.MAX_VALUE))))))) | 0))); }); testMathyFunction(mathy2, [42, -(2**53), -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, -0, 0/0, -0x080000001, 2**53+2, Math.PI, 0x080000001, -Number.MAX_VALUE, -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 0x100000001, 1/0, 0x0ffffffff, 1, -(2**53+2), 0x07fffffff, Number.MAX_VALUE, -0x100000001, -0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, 2**53-2, 1.7976931348623157e308, 0.000000000000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1497; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return (Math.log2(Math.fround(Math.acosh(Math.fround((Math.hypot((Math.fround(mathy3(Math.fround(( ~ y)), Math.fround(x))) >>> 0), y) >>> 0))))) >>> ( + Math.log10(( + (Math.min(((Math.hypot((Math.min(y, y) >>> 0), y) == x) | 0), (( ! 1/0) | 0)) >>> 0))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, 0.000000000000001, 2**53, -0x100000000, -Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, -0x100000001, -0, 0x07fffffff, -0x07fffffff, -(2**53-2), 2**53-2, Number.MAX_VALUE, 0x0ffffffff, -0x0ffffffff, 0x080000000, 0x100000001, -(2**53+2), Math.PI, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, 1.7976931348623157e308, 1, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 1/0, 0x100000000, -(2**53), 0]); ");
/*fuzzSeed-116066984*/count=1498; tryItOut("/*tLoop*/for (let x of /*MARR*/[Infinity, Infinity,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , (-1/0), Infinity, Infinity,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0),  /x/ , Infinity, Infinity, Infinity, objectEmulatingUndefined(),  /x/ , (-1/0),  /x/ ,  /x/ , Infinity]) { /*RXUB*/var r = /(?!(?=\\d(\u6c8f)${2,}((?!\\B+|\\1)|\\3\\w?[^\\0-\\u0059])))/m; var s = \"\\u0005\"; print(s.search(r));  }");
/*fuzzSeed-116066984*/count=1499; tryItOut("\"use strict\"; v1 = evalcx(\"function o1.f0(p2)  { \\\"use strict\\\"; return {} } \", g0);");
/*fuzzSeed-116066984*/count=1500; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( ~ (Math.log(( + ( + (( + ( - (y | 0))) < ( + -0x0ffffffff))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x07fffffff, 2**53-2, 1, -1/0, 1/0, 0/0, 0.000000000000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53, 0x100000001, -(2**53), -Number.MAX_VALUE, 0x07fffffff, Number.MAX_VALUE, 0x080000001, -0x0ffffffff, Number.MIN_VALUE, -0, Math.PI, -0x100000000, 0, 0x100000000, 2**53+2, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 1.7976931348623157e308, 0x080000000, -Number.MIN_VALUE, 42, -0x100000001, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1501; tryItOut("o2 = t1.__proto__;");
/*fuzzSeed-116066984*/count=1502; tryItOut("h1.has = (function() { try { for (var p in this.g1) { try { this.v0 = evaluate(\"function f0(i1)  { \\\"use strict\\\"; yield x } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 21 == 18), noScriptRval: (x % 4 == 0), sourceIsLazy: false, catchTermination: false })); } catch(e0) { } t1[v2]; } } catch(e0) { } (void schedulegc(g2)); return a2; });");
/*fuzzSeed-116066984*/count=1503; tryItOut("mathy1 = (function(x, y) { return (( + (((Math.fround((( + ( ! Math.log2(0x080000000))) | ( + ( ! ( + Math.asin(( ! mathy0(y, x)))))))) | 0) << ((( + x) ** ( ! (Math.round(( ! Math.fround(y))) | 0))) | 0)) | 0)) < ( + Math.sinh((( - (Math.hypot(( + x), (x | 0)) | 0)) >>> ( + Math.log10(( + Math.fround(( - Math.fround(x)))))))))); }); testMathyFunction(mathy1, [2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, 0.000000000000001, 0, -Number.MIN_SAFE_INTEGER, 1, Math.PI, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, -Number.MAX_VALUE, -(2**53+2), -(2**53-2), -(2**53), -0x080000001, 42, 2**53+2, -1/0, 1/0, 0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, -0x100000000, 0/0, -0x100000001, Number.MIN_VALUE, -0x080000000, 0x0ffffffff, 0x100000001, 2**53-2, Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1504; tryItOut("\"use strict\"; p1 + '';");
/*fuzzSeed-116066984*/count=1505; tryItOut("Object.freeze(m2);");
/*fuzzSeed-116066984*/count=1506; tryItOut("\"use strict\";  '' ;return undefined;");
/*fuzzSeed-116066984*/count=1507; tryItOut("throw StopIteration;");
/*fuzzSeed-116066984*/count=1508; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + (( + Math.atan2(y, (Math.fround(Math.atan2((-Number.MIN_SAFE_INTEGER | 0), Math.fround(x))) | 0))) ? ( ~ (((x >>> 0) > (0x080000001 >>> 0)) >>> 0)) : ( + Math.min(Math.fround(((1 | Math.atan2(x, 0.000000000000001)) | 0)), Math.fround(( + 0x100000001)))))); }); testMathyFunction(mathy1, [-(2**53+2), 0x100000000, -0, Math.PI, -1/0, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, 2**53, -0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -(2**53), 42, 2**53+2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), -0x100000001, 1/0, 2**53-2, -0x080000001, 0.000000000000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, 1, -0x100000000, -0x080000000, 0/0]); ");
/*fuzzSeed-116066984*/count=1509; tryItOut("\"use strict\"; const e = x;e2.add(f1);");
/*fuzzSeed-116066984*/count=1510; tryItOut("\"use strict\"; testMathyFunction(mathy5, [2**53-2, -0, -Number.MIN_VALUE, 0x100000001, -(2**53+2), 0.000000000000001, -0x100000000, -0x07fffffff, 1/0, -0x080000000, Number.MAX_VALUE, -0x100000001, 0x100000000, 42, 0x07fffffff, -(2**53), Number.MIN_VALUE, 0x080000000, -0x0ffffffff, -1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, 0/0, 2**53, 0x080000001, -(2**53-2), -0x080000001, 0, Math.PI, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-116066984*/count=1511; tryItOut("a1.sort((function() { try { o1.i0.next(); } catch(e0) { } v2 + m2; return b2; }), i2, t2);");
/*fuzzSeed-116066984*/count=1512; tryItOut("{t1.set(o2.t1, 1); }");
/*fuzzSeed-116066984*/count=1513; tryItOut("let (c) { /*vLoop*/for (tqwodx = 0; tqwodx < 43; ++tqwodx) { let c = tqwodx; print((x) = [,,z1]//h\n); }  }");
/*fuzzSeed-116066984*/count=1514; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1515; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return ( + mathy0((( ~ ( ~ Math.clz32(Math.log((((y >>> 0) % (-(2**53-2) >>> 0)) >>> 0))))) >>> 0), (Math.max(Math.ceil((y | 0)), (Math.log(Math.imul(x, Math.fround(( ~ ( + y))))) | 0)) >>> 0))); }); testMathyFunction(mathy5, [0x080000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1/0, 0x080000000, -0, 2**53+2, 2**53, 1, 0x100000000, -(2**53), 0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, 0.000000000000001, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, 2**53-2, 0/0, Number.MAX_VALUE, -0x07fffffff, -1/0, -Number.MIN_VALUE, -0x080000001, Math.PI, 0x100000001, -(2**53+2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1516; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new String('q'), new String('q'), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Number(1), new String('q'), new Boolean(false), new String('q'), (this.__defineGetter__(\"x\", String.fromCharCode)), new Number(1), new Boolean(false), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), new Boolean(false), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), new Number(1), new String('q'), new String('q'), new Number(1), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), new String('q'), new String('q'), new Number(1), new String('q'), (this.__defineGetter__(\"x\", String.fromCharCode)), new Boolean(false), new String('q'), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), new Boolean(false), new Number(1), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), new String('q'), (this.__defineGetter__(\"x\", String.fromCharCode)), new Boolean(false), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), new Boolean(false), new String('q'), new Boolean(false), (this.__defineGetter__(\"x\", String.fromCharCode)), new String('q'), new Number(1), new Number(1), new String('q'), new String('q'), new String('q'), (this.__defineGetter__(\"x\", String.fromCharCode)), new Boolean(false), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new String('q'), new Boolean(false), new Boolean(false), new Number(1), (this.__defineGetter__(\"x\", String.fromCharCode)), new Number(1), new Boolean(false), new String('q'), new Number(1), (this.__defineGetter__(\"x\", String.fromCharCode)), (this.__defineGetter__(\"x\", String.fromCharCode)), new Number(1), (this.__defineGetter__(\"x\", String.fromCharCode)), new String('q')]); ");
/*fuzzSeed-116066984*/count=1517; tryItOut("v1 = evaluate(\"x\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: Math.sinh(-6), catchTermination: (x ** (4277)) }));");
/*fuzzSeed-116066984*/count=1518; tryItOut("mathy2 = (function(x, y) { return ( + Math.sin((( + Math.max(( + Math.clz32(( + ( - y)))), ( + Math.fround(Math.tanh(mathy1((Math.fround((x | (y >>> 0))) >>> 0), ( ! x))))))) >>> 0))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, -0x080000000, 0/0, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), -0x100000000, 0x100000001, -0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 0, Math.PI, -0x07fffffff, 0x080000001, -0x100000001, 2**53-2, 1, -(2**53-2), 0x0ffffffff, 42, -0, 0.000000000000001, 1/0, 2**53+2]); ");
/*fuzzSeed-116066984*/count=1519; tryItOut("(function ([y]) { });");
/*fuzzSeed-116066984*/count=1520; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy0(Math.asin(Math.sign((( + Math.cbrt(x)) && (-0x0ffffffff >>> 0)))), (Math.fround(Math.log(Math.fround(mathy3((Math.sign(Math.max((((x | 0) % (x | 0)) | 0), ( + Number.MAX_SAFE_INTEGER))) | 0), Math.atanh(y))))) | 0)); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0.000000000000001, 0x100000000, -0x080000001, -0, 0x080000001, 1/0, -1/0, Number.MIN_VALUE, 0x100000001, 0x080000000, 1, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -0x100000001, 0/0, -0x100000000, -Number.MAX_VALUE, 2**53-2, 2**53, -(2**53-2), 2**53+2, 1.7976931348623157e308, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, -(2**53+2), -Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-116066984*/count=1521; tryItOut("\"use strict\"; d = \"\\uD9DC\";for (var v of h0) { try { i2 + ''; } catch(e0) { } g1.e1.has(this.h1); }");
/*fuzzSeed-116066984*/count=1522; tryItOut("mathy5 = (function(x, y) { return ((mathy3(( + Math.max(Math.fround(Math.pow(y, (Math.fround(((y >>> 0) > Math.fround(x))) != ( ~ y)))), ( + ((( + y) ? ((( + x) | 0) + x) : ( + x)) | 0)))), (Math.imul((Math.fround(mathy3(Math.fround(0/0), (Math.log2(((Math.max(2**53+2, (-Number.MIN_SAFE_INTEGER | 0)) | 0) >>> 0)) >>> 0))) >>> 0), (mathy0(((x | 0) <= (y | 0)), Math.fround((( ~ Math.fround(x)) | 0))) >>> 0)) | 0)) >>> 0) , (( + Math.min(Math.abs((Math.cos((( + Math.max(( + y), y)) >>> 0)) >>> 0)), Math.pow(( - (Math.tanh((y >>> 0)) >>> 0)), ( + 2**53-2)))) >>> 0)); }); testMathyFunction(mathy5, [objectEmulatingUndefined(), 1, undefined, (new Boolean(true)), ({valueOf:function(){return 0;}}), '\\0', (new Boolean(false)), (new Number(0)), NaN, '/0/', 0.1, 0, '0', true, (function(){return 0;}), [0], (new Number(-0)), /0/, (new String('')), [], ({valueOf:function(){return '0';}}), null, false, '', -0, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-116066984*/count=1523; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.pow((Math.fround(Math.pow(Math.fround((Math.hypot(( + Math.fround(Math.clz32(x))), ( ! y)) ? x : (Math.exp((Math.cbrt((y << x)) >>> 0)) >>> 0))), Math.fround((Math.sin((( + 2**53+2) >>> 0)) >>> 0)))) | 0), (Math.imul(( + Math.hypot(( - Math.fround((Math.fround(42) - Math.fround(Math.min((y >>> 0), y))))), Math.fround((Math.fround(Math.sin(x)) >> Math.fround(Math.fround(Math.max(( + y), ( + ( + ( ~ ( + y))))))))))), Math.hypot(( - ( - -0x080000001)), Math.fround(Math.max(Math.fround(Math.sqrt(Math.imul(x, x))), Math.fround(x))))) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=1524; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.tanh(Math.tan(((((x && x) ** (( ! y) | 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, 2**53-2, 1, 2**53, 0x100000000, 0x07fffffff, -1/0, 42, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, -0, 0/0, 0x080000001, -0x080000000, 0.000000000000001, 2**53+2, Number.MAX_VALUE, -0x0ffffffff, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, -(2**53+2), -(2**53), 0x100000001, -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-116066984*/count=1525; tryItOut("mathy3 = (function(x, y) { return (Math.atan2((Math.exp(y) | 0), mathy1(( + (( + (Math.hypot(0.000000000000001, ((( - ( + x)) >>> 0) | 0)) | 0)) << ( + Math.atan2((Math.max((( ~ x) >>> 0), (0 >>> 0)) >>> 0), x)))), ( + 42))) >> Math.fround(( ! ( - ( + ((mathy2(( + -0x100000000), -Number.MAX_SAFE_INTEGER) | 0) >= (Math.atan2(x, ( ~ ( - y))) | 0))))))); }); testMathyFunction(mathy3, /*MARR*/[-0x07fffffff, new Boolean(true)]); ");
/*fuzzSeed-116066984*/count=1526; tryItOut("print(x);");
/*fuzzSeed-116066984*/count=1527; tryItOut("mathy1 = (function(x, y) { return mathy0(( + Math.asinh(( + ( + (y == ( + Math.hypot(Math.acosh(x), y))))))), Math.max(Math.fround(Math.log10(Math.fround(x))), (Math.ceil(Math.atan2(( - -Number.MIN_VALUE), (mathy0(( + y), Math.fround(mathy0(-0x07fffffff, (mathy0(x, y) | 0)))) >>> 0))) >>> 0))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, -Number.MIN_VALUE, 42, -(2**53-2), 0x080000000, Number.MIN_VALUE, 2**53+2, 0x100000000, 0.000000000000001, -0x080000000, -(2**53+2), 1, 0x07fffffff, Math.PI, 1/0, -0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -(2**53), -0x100000001, 0, 0x100000001, 0/0, 0x0ffffffff, -0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 2**53, 0x080000001]); ");
/*fuzzSeed-116066984*/count=1528; tryItOut("mathy1 = (function(x, y) { return (((((Math.log((( + (( + Math.atanh(-(2**53))) | ( + x))) | 0)) | 0) ? ((( - Math.tan(Math.log2(x))) < (( + ((Number.MAX_SAFE_INTEGER && x) | 0)) & Math.fround((Math.cos((x | 0)) | 0)))) | 0) : ( + Math.cbrt(x))) | Math.pow((Math.atan2((x >>> 0), (( ~ 0x100000001) >>> 0)) | 0), ( + Math.log(((Math.asinh(0.000000000000001) | 0) | 0))))) ? (( - ((Math.hypot((( + (y >>> 0)) >>> 0), y) >>> 0) & x)) >>> 0) : Math.fround(( ~ ( + ( ~ ( + Math.abs(Math.pow(Number.MIN_VALUE, y)))))))) >>> 0); }); testMathyFunction(mathy1, [(new Number(0)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), 1, -0, false, (new Number(-0)), [0], true, ({valueOf:function(){return '0';}}), [], 0, /0/, (new Boolean(true)), (new String('')), null, NaN, '0', ({toString:function(){return '0';}}), (function(){return 0;}), undefined, 0.1, (new Boolean(false)), '', '/0/', '\\0']); ");
/*fuzzSeed-116066984*/count=1529; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return ((((0x4e267c71))*0x143b0))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; v0 = new Number(-0);; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x100000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, 42, 0x080000000, 0x07fffffff, -(2**53+2), 1.7976931348623157e308, 2**53, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, -(2**53), -0x0ffffffff, 2**53-2, -0, Number.MIN_VALUE, 0, 1/0, -0x080000001, -0x080000000, -0x100000000, 0/0, Number.MAX_SAFE_INTEGER, 0x080000001, 1, 2**53+2, 0.000000000000001, Math.PI, 0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1530; tryItOut("for (var v of h2) { try { this.o2.a0[/*FARR*/[(void options('strict')),  \"\" , ...String.prototype.trimRight, .../*FARR*/[Math.cbrt(20), (let (x) ({y: false })), ...(let (\u3056, a, window, x) (4277) for (({}) in \"\\uF28E\") for (x in window !==  /x/g ) for (w in -2) for (x of []) for (y of c)), this, .../*MARR*/[new Boolean(false), null, null, new Boolean(false), null]], /*FARR*/[...[], /[^]/gi, ...[], null, ...[], ...[], ...[], null].map((String.prototype.toString).call).watch(\"unshift\", offThreadCompileScript), Math.pow(yield new RegExp(\"(?=\\\\d)|\\uffb8*?\\\\2(\\u7156)|(?=\\\\1){2,}\", \"y\"), 29), .../*FARR*/[(let (e = (void options('strict'))) z = Proxy.create(({/*TOODEEP*/})(-2), window)), (a = \"\\u6645\" ? this.__defineSetter__(\"w\", function(q) { \"use strict\"; return q; }) : (4277)), .../*FARR*/[], (window\n)], Math.imul(5, window)].some(e => typeof [[1]], Object.defineProperty(x, \"15\", ({get: new Function, configurable: true, enumerable: false})))]; } catch(e0) { } try { for (var p in p1) { try { v0 = r2.global; } catch(e0) { } try { a1 = Array.prototype.filter.apply(g2.a0, [(function(j) { if (j) { try { e2.delete(g0.t1); } catch(e0) { } try { this.o2 = {}; } catch(e1) { } i2.__proto__ = p1; } else { try { v1 = evalcx(\"function f1(f2)  { return this / window += (void version(180)) } \", this.g0); } catch(e0) { } try { /*MXX2*/g1.Object.keys = v0; } catch(e1) { } this.g2.t0[13] = p0; } }), e1]); } catch(e1) { } v0 = t2.byteOffset; } } catch(e1) { } try { m1.set(o2, o0); } catch(e2) { } delete h1[\"keys\"]; }");
/*fuzzSeed-116066984*/count=1531; tryItOut("\"use strict\"; e1.add(p1);");
/*fuzzSeed-116066984*/count=1532; tryItOut("{h1 = ({getOwnPropertyDescriptor: function(name) { h1.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7) { var r0 = a0 % a2; var r1 = 8 / 7; var r2 = 2 + x; var r3 = a6 / 8; var r4 = 5 & 9; var r5 = 8 ^ a1; a5 = r0 & r2; var r6 = 8 ^ 1; var r7 = a1 % a7; var r8 = x / 7; var r9 = r5 | 2; var r10 = a1 | 2; var r11 = r1 / r8; var r12 = 9 - a0; var r13 = 4 | r11; x = 0 + r13; r3 = a1 ^ 0; r11 = r1 - r4; var r14 = 0 ^ a1; var r15 = 2 % r0; var r16 = r0 | r12; var r17 = r7 | r7; var r18 = 6 | 0; var r19 = 9 | 3; var r20 = r11 + r8; var r21 = r20 % 1; var r22 = 0 ^ a0; var r23 = r11 ^ r20; var r24 = r5 | r22; print(r15); a1 = r4 - a5; var r25 = r19 + 8; var r26 = 2 ^ 6; var r27 = r15 / r8; r17 = r5 * 7; var r28 = 1 + 3; r12 = r7 & r9; var r29 = r13 % r14; var r30 = 7 ^ r1; var r31 = 4 + 3; var r32 = 6 / 2; var r33 = r27 % r32; a5 = r28 * r1; r21 = r28 & 9; a5 = 6 | a0; var r34 = r4 * r22; r32 = 4 ^ r11; r8 = 3 & a6; var r35 = r32 - r17; var r36 = r17 | r28; var r37 = r11 / r17; var r38 = r10 * r1; var r39 = r3 - r27; var r40 = r10 & 1; var r41 = r2 & r9; x = r39 | r5; var r42 = r28 / r15; var r43 = 5 + 8; var r44 = r17 ^ a5; a0 = r32 & r19; var r45 = r10 / 3; r16 = 2 - 4; var r46 = a5 / r38; var r47 = a0 ^ r20; r35 = r46 * r5; var r48 = r13 ^ 0; var r49 = r36 | 2; var r50 = 1 + r1; var r51 = r21 + r29; var r52 = r14 & a6; var r53 = 9 | r30; var r54 = 3 * r26; var r55 = r31 - r39; var r56 = r22 - 1; var r57 = r46 / r28; r39 = r29 + r27; var r58 = 9 * r11; var r59 = r37 ^ a6; r41 = r51 ^ r16; var r60 = r52 | r19; var r61 = 9 * 0; var r62 = r3 & r5; var r63 = 1 % 9; r37 = r56 % r1; var r64 = r16 * r37; var r65 = r55 ^ r49; var r66 = r9 & 0; r0 = r55 - r7; print(r30); var r67 = 2 - 1; r60 = 7 | r3; var r68 = r9 / r48; var r69 = r54 - r43; var r70 = r9 % r48; var r71 = r64 / a4; r52 = 5 * 3; var r72 = r34 | r60; var r73 = r27 + r33; x = r11 * r52; var r74 = r62 % r41; var r75 = r4 + r4; var r76 = 8 - r35; var r77 = r0 | 2; var r78 = r9 / 3; r13 = r69 | 0; var r79 = r39 * 5; r57 = r69 - 3; var r80 = 1 | r40; var r81 = r52 ^ r44; x = 3 * 2; r66 = r20 & 9; var r82 = r78 & 6; r42 = r47 / r39; var r83 = r28 | r14; r20 = r54 ^ 4; var r84 = r53 / r24; var r85 = r55 - r43; var r86 = 1 / r22; var r87 = r19 % 9; var r88 = r18 & r26; var r89 = r49 & r82; var r90 = r32 / 9; r68 = r0 / r43; var r91 = r50 * r70; var r92 = r70 & r66; var r93 = r56 ^ r47; var r94 = r2 % r7; r22 = r37 - r6; r30 = 2 - 2; var r95 = 9 / r29; r4 = 2 % 4; var r96 = 4 + r92; var r97 = r7 & 3; var r98 = 0 % r86; var r99 = 4 + r20; return a7; });; var desc = Object.getOwnPropertyDescriptor(g0.t2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { throw g1; var desc = Object.getPropertyDescriptor(g0.t2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { this.i0.send(s2);; Object.defineProperty(g0.t2, name, desc); }, getOwnPropertyNames: function() { a1.reverse();; return Object.getOwnPropertyNames(g0.t2); }, delete: function(name) { (void schedulegc(g1.g0));; return delete g0.t2[name]; }, fix: function() { v2 = g1.runOffThreadScript();; if (Object.isFrozen(g0.t2)) { return Object.getOwnProperties(g0.t2); } }, has: function(name) { t1[17] = this.m1;; return name in g0.t2; }, hasOwn: function(name) { Array.prototype.forEach.call(a2, (function(j) { if (j) { try { a0 = Array.prototype.filter.call(a0, (function mcc_() { var kdzfne = 0; return function() { ++kdzfne; f1(/*ICCD*/kdzfne % 10 == 8);};})()); } catch(e0) { } for (var v of g1.o0.a1) { function g0.f0(g2)  \"\"  } } else { try { g1.offThreadCompileScript(\"x\"); } catch(e0) { } try { for (var v of t0) { try { p2.toString = (function() { try { this.v2 = evaluate(\";\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: eval, noScriptRval: true, sourceIsLazy: false, catchTermination: Math })); } catch(e0) { } try { e0.has(b2); } catch(e1) { } g2.v0 = g1.g0.eval(\"v0 = (o2.t1 instanceof b2);\"); return h2; }); } catch(e0) { } this.a0 + ''; } } catch(e1) { } try { this.o2.m2.has(h0); } catch(e2) { } a1.__proto__ = b1; } }), x);; return Object.prototype.hasOwnProperty.call(g0.t2, name); }, get: function(receiver, name) { e0.toSource = (function() { try { v0 = Object.prototype.isPrototypeOf.call(i0, v1); } catch(e0) { } try { v0 = (f2 instanceof t1); } catch(e1) { } try { e1.delete(p2); } catch(e2) { } this.g0 + o0; return g2; });; return g0.t2[name]; }, set: function(receiver, name, val) { print(uneval(i2));; g0.t2[name] = val; return true; }, iterate: function() { Object.defineProperty(this, \"o1\", { configurable: (x % 37 != 6), enumerable: (x % 53 == 50),  get: function() {  return {}; } });; return (function() { for (var name in g0.t2) { yield name; } })(); }, enumerate: function() { throw e2; var result = []; for (var name in g0.t2) { result.push(name); }; return result; }, keys: function() { this.g1.g2.offThreadCompileScript(\"function f1(h2)  { \\\"use strict\\\"; yield [z1] } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (x % 2 != 1), catchTermination: true }));; return Object.keys(g0.t2); } }); }");
/*fuzzSeed-116066984*/count=1533; tryItOut("\"use strict\"; var auvogz = new SharedArrayBuffer(4); var auvogz_0 = new Uint16Array(auvogz); var auvogz_1 = new Int8Array(auvogz); auvogz_1[0] = 27; var auvogz_2 = new Int32Array(auvogz); print(auvogz_2[0]); auvogz_2[0] = -2506992594; var auvogz_3 = new Uint16Array(auvogz); auvogz_3[0] = -8; var auvogz_4 = new Uint8ClampedArray(auvogz); auvogz_4[0] = 27; s0 += 'x';t0 = t2.subarray(v1, ((4277).yoyo(true >>> {})));print((4277));");
/*fuzzSeed-116066984*/count=1534; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return mathy0(( + (mathy0(x, (( + (x - x)) >>> 0)) - ( + Math.log10(Math.fround((Math.fround(( ! x)) || Math.fround((((x | 0) / (x | 0)) | 0)))))))), ( + ( + mathy1(( + (y % ( - ((Math.atan(Math.fround(Math.fround(Math.pow(y, x)))) >>> 0) | 0)))), ( + ( + Math.sinh((0 >>> 0)))))))); }); testMathyFunction(mathy3, ['/0/', 1, (new String('')), true, /0/, (new Number(0)), null, (new Boolean(true)), ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), objectEmulatingUndefined(), [], (new Boolean(false)), [0], 0.1, (new Number(-0)), false, NaN, (function(){return 0;}), '0', '', 0, -0, '\\0', undefined]); ");
/*fuzzSeed-116066984*/count=1535; tryItOut("mathy2 = (function(x, y) { return (Math.max((Math.log2(((( + (( + (( ~ ((x | 0) ? x : (y | 0))) >>> 0)) >>> ( + y))) ^ ( ~ (((x >>> 0) ? (((x >>> 0) * (0x07fffffff >>> 0)) >>> 0) : (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))) == ((Math.trunc((x | 0)) | 0) >>> 0))) >>> 0), (( + Math.tanh(( + (Math.acosh(x) % Math.fround((Math.fround((Math.round(((( + x) | 0) >>> 0)) >>> 0)) ? Math.fround((Math.imul(mathy0(x, y), 0.000000000000001) | 0)) : Math.fround(x))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0x100000001, -Number.MAX_VALUE, -1/0, 0x07fffffff, 1/0, -Number.MIN_VALUE, -0x07fffffff, Number.MIN_VALUE, -(2**53-2), 0x080000001, 42, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0.000000000000001, Number.MAX_VALUE, -(2**53+2), -0, 1, 2**53, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -(2**53), -0x080000000, 1.7976931348623157e308, -0x100000000, 0/0, Math.PI, 0x100000000, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1536; tryItOut("\"use strict\"; var o2.f1 = m1.get(m0);");
/*fuzzSeed-116066984*/count=1537; tryItOut(";function x(d) /x/g .eval(\"this\")(function(id) { return id });");
/*fuzzSeed-116066984*/count=1538; tryItOut("if(false) { if (this) {this.m1.has(o0.s2); }} else {selectforgc(o2); }");
/*fuzzSeed-116066984*/count=1539; tryItOut("mathy0 = (function(x, y) { return ((( + ( - Math.min(Math.sqrt((y >>> 0)), ( + Math.fround(( + Math.round(x))))))) >>> 0) >>> (Math.round(Math.pow((Math.expm1(Math.asin(y)) | 0), ( ! (Math.abs((y | 0)) | 0)))) >>> 0)); }); testMathyFunction(mathy0, [2**53-2, -0x07fffffff, -0x080000001, -Number.MIN_VALUE, -0x080000000, 0x100000000, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, 0x0ffffffff, 1, 2**53+2, 1/0, 1.7976931348623157e308, -0x0ffffffff, -(2**53-2), 0x07fffffff, 0, -(2**53), 0x080000000, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, -0x100000001, 0/0, 2**53, Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -0, -(2**53+2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1540; tryItOut("\"use strict\"; { void 0; minorgc(true); }");
/*fuzzSeed-116066984*/count=1541; tryItOut("/*infloop*/for(x; (void version(170)); (objectEmulatingUndefined)(let (e) e, [arguments.callee.caller.arguments] = {})) {m1.delete(o2.o0);m2 + ''; }");
/*fuzzSeed-116066984*/count=1542; tryItOut("testMathyFunction(mathy4, [0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, 0.000000000000001, -1/0, -0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0x07fffffff, 0/0, -0x0ffffffff, 1.7976931348623157e308, -0x100000000, 0x080000000, 42, -0x080000001, -Number.MIN_VALUE, -(2**53-2), 0x080000001, Math.PI, Number.MAX_VALUE, -(2**53+2), 2**53, 0x100000000, 0, -0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 1]); ");
/*fuzzSeed-116066984*/count=1543; tryItOut("mathy4 = (function(x, y) { return Math.asinh(( + (mathy1((mathy3((( + Math.max(Math.pow(Math.fround(y), Math.fround(x)), 2**53)) | 0), (( + Math.atan2(Math.fround((Math.atan(( ~ y)) & x)), ( + (Math.max(y, y) * y)))) | 0)) | 0), (Math.fround(( + Math.fround(( + (( + y) ? Math.fround(x) : ( + Math.fround((Math.fround(((y >>> 0) | x)) - Math.fround((( - (2**53 >>> 0)) >>> 0)))))))))) | 0)) | 0))); }); testMathyFunction(mathy4, /*MARR*/[null, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), null, null, objectEmulatingUndefined(), null, null, null, null, null, null, null, null, null, new Number(1.5), null, null, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), null, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, null]); ");
/*fuzzSeed-116066984*/count=1544; tryItOut("\"use strict\"; this.v0 = (b1 instanceof o0.s2);");
/*fuzzSeed-116066984*/count=1545; tryItOut("\"use strict\"; o0 + '';");
/*fuzzSeed-116066984*/count=1546; tryItOut("e1.add(v0);");
/*fuzzSeed-116066984*/count=1547; tryItOut("if(new Error(\"\\uB494\" < /(?:.[^](?:.)*?)/ym.throw([({a2:z2})]))) { if (({ set \"14\" let (a = window, x, a =  \"\" , x, z = [], x, d, b, d, eval, window, x, w = window, y, z, a, \u3056 = new RegExp(\".\", \"y\"), x, window, c = ({}), x, x, eval, x = new RegExp(\"\\\\3\", \"gym\"), x, x, x, y, e, b, d = \"\\u1F5A\", y = undefined, a, x = /\\b/yim, eval, c, x, x, window, eval = new RegExp(\"(?=[^])(\\udc53)(\\u0b14)*|.|\\\\B+*?\", \"gyim\"), w, window = -7, x, x, \u3056, x, eval, x, y, window, \u3056 = -25, x, delete, window = window, w, x, b, c = /[^]\\s{2,}[^]?\\W{2}|(?![^\\d\u22c1\\cA-\\u989f])+?|(?:([^]){1}|(\\\u47fb){67108864}{3}){0,2}/y, x, x, eval, a, e, \u3056, toSource, a, x, x, x, eval, x, d, w, (function(a0, a1, a2, a3, a4, a5, a6, a7) { var r0 = a0 - 3; var r1 = a7 & x; var r2 = a6 ^ 9; var r3 = a7 / 1; var r4 = a2 * a6; a3 = 4 / 5; var r5 = 0 + a7; var r6 = 3 ^ a2; r2 = 8 | r5; var r7 = r1 + r5; var r8 = a5 & 9; var r9 = r3 - 9; a7 = a5 - 6; var r10 = a4 | 6; r2 = r8 ^ a4; var r11 = 7 ^ a4; var r12 = 0 & r5; var r13 = a0 & 0; var r14 = 7 % 7; a7 = a0 | r12; var r15 = 4 - a4; var r16 = 7 | a3; var r17 = r5 - a5; r16 = a2 | 3; r14 = 6 ^ r1; var r18 = a0 + r10; var r19 = x + r4; var r20 = a6 / r13; r2 = a3 * a1; var r21 = a7 - r14; print(a5); print(r15); var r22 = 1 / r21; var r23 = 6 | r0; print(r9); var r24 = r7 % r12; x = 7 % 0; var r25 = r23 / 2; var r26 = 8 ^ r11; r12 = a0 ^ 3; print(r22); var r27 = r6 * 0; var r28 = r20 & a4; r10 = r0 ^ r14; var r29 = r16 ^ r14; var r30 = r27 * 9; var r31 = 7 + r6; r9 = r15 / 0; var r32 = r7 / r0; var r33 = 9 % r20; var r34 = 5 | 5; var r35 = 4 & 2; var r36 = r25 & r2; var r37 = x - r6; r11 = 9 | 3; var r38 = 2 - r13; a5 = 0 % 3; var r39 = a4 * 7; var r40 = r25 + 6; var r41 = r40 ^ r29; r20 = r6 * r27; var r42 = 9 & r34; r19 = a3 / r11; var r43 = 4 ^ a6; r41 = 1 ^ 4; var r44 = r13 * r11; return a2; }), x, x, window, eval, x, eval = [,], x = x, y, x, z = 28, c, x, \u3056, x, c, b) { \"use strict\"; \"use asm\"; print(x); }  })) {/*RXUB*/var r = new RegExp(\"[\\\\s\\ubfdd]*?\", \"gyi\"); var s = undefined; print(s.split(r)); print(r.lastIndex); /* no regression tests found */ }} else {Array.prototype.push.call(this.a2, t2, i1, /*MARR*/[function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}].map(window), a0, v1, h1, o2.a2, m1);/*hhh*/function dmomhw(x, x, z, NaN, eval, z, c, z =  \"\" , x, y, NaN, w, x, x, x, z, NaN = \"\\u5FEE\", x, e, w, x =  '' , x = arguments, x, w, x, a, x, w, x, x, eval, eval, y, y, x, window, x, e, z, x, x, x, y, c =  \"\" , NaN, z, window, w, x, z = x, x, y, x, y = -20, c, x, x, x, window, x, \u3056, d, z, eval = false, y, x, x, NaN, x, z, window, x, x, d, z = \"\\u368D\", x){;}/*iii*/o0.t2.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { var r0 = 8 + 7; var r1 = 6 * dmomhw; var r2 = x / 7; var r3 = a6 ^ 4; var r4 = r0 - 1; var r5 = a2 / dmomhw; a3 = a0 & 4; var r6 = a5 | 7; var r7 = a5 | a1; var r8 = r7 & 1; var r9 = 5 & 9; var r10 = a6 - 9; var r11 = 1 % 9; var r12 = a3 / a5; a1 = a6 / a2; var r13 = a6 - 9; var r14 = 5 % 8; var r15 = 4 % r6; var r16 = r5 + r1; var r17 = a9 / 3; print(a0); var r18 = a11 & 4; var r19 = a2 + a0; a7 = 0 - 1; var r20 = a1 | r6; var r21 = 7 % 6; return a5; }); }");
/*fuzzSeed-116066984*/count=1548; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( ~ (Math.exp(Math.atan2(y, ( ~ (-0x0ffffffff ^ ( + y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-(2**53-2), 0x080000001, 1/0, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, 0, 2**53+2, -(2**53), -0x080000001, Math.PI, 0x100000000, Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, 1, -0x080000000, 2**53, -0x100000000, -(2**53+2), 0x0ffffffff, -Number.MAX_VALUE, -0x0ffffffff, 0/0, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, -Number.MIN_VALUE, -1/0, 2**53-2, -0x07fffffff]); ");
/*fuzzSeed-116066984*/count=1549; tryItOut("mathy4 = (function(x, y) { return Math.fround(( - Math.fround(( ~ Math.fround(mathy3((Math.min((mathy2(1.7976931348623157e308, (( + Math.max((x | 0), x)) | 0)) | 0), Math.fround(Math.tanh(x))) >>> 0), ( + (Math.clz32((( + Math.imul(x, ( + ( + Math.fround(-0x07fffffff))))) | 0)) >>> 0)))))))); }); testMathyFunction(mathy4, [false, [0], /0/, (new Number(-0)), NaN, true, '/0/', (function(){return 0;}), '', (new Boolean(true)), [], ({valueOf:function(){return '0';}}), -0, 0, '\\0', undefined, (new Number(0)), ({toString:function(){return '0';}}), objectEmulatingUndefined(), (new String('')), (new Boolean(false)), 0.1, ({valueOf:function(){return 0;}}), null, '0', 1]); ");
/*fuzzSeed-116066984*/count=1550; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1551; tryItOut("/*RXUB*/var r = /(?!.(?=${0})+?(\\2|[^]){1}*?)/g; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=1552; tryItOut("print(uneval(p2));");
/*fuzzSeed-116066984*/count=1553; tryItOut("print(x);");
/*fuzzSeed-116066984*/count=1554; tryItOut("\"use strict\"; Array.prototype.splice.apply(g1.o1.a1, [2, 15]);");
/*fuzzSeed-116066984*/count=1555; tryItOut("f2.toString = Math.expm1.bind(b2);");
/*fuzzSeed-116066984*/count=1556; tryItOut("\"use strict\"; Object.defineProperty(o1, \"v1\", { configurable: (4277), enumerable: (x % 3 == 1),  get: function() {  return g1.eval(\"(4277);i1 = new Iterator(m2, true);\"); } });");
/*fuzzSeed-116066984*/count=1557; tryItOut("g0.v1 = Object.prototype.isPrototypeOf.call(g1.h1, e1);");
/*fuzzSeed-116066984*/count=1558; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( - (( + Math.min(( - (( ~ (x >>> 0)) >>> 0)), x)) / (0x080000000 != ( + (( + x) >> ( + Math.min(x, y))))))); }); testMathyFunction(mathy5, [-0x080000000, 0/0, 0x0ffffffff, -0x080000001, Math.PI, 42, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, -1/0, 0x080000001, 1.7976931348623157e308, -0, -(2**53+2), -0x100000001, 2**53+2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_VALUE, -0x07fffffff, 1/0, 0, -(2**53-2), 2**53]); ");
/*fuzzSeed-116066984*/count=1559; tryItOut("for (var p in i0) { i0.next(); }");
/*fuzzSeed-116066984*/count=1560; tryItOut("\"use strict\"; i0 = a1.iterator;Array.prototype.shift.call(a2, v0);");
/*fuzzSeed-116066984*/count=1561; tryItOut("/*infloop*/do {var dgwmpm, y = eval(\"true\"), sjqjbg, e = eval = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: this, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { throw 3; }, fix: function() { throw 3; }, has: Array.prototype.toString, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: Date.prototype.getUTCMonth, keys: function() { return Object.keys(x); }, }; })(\"\\u842D\"), d.prototype), y, qabfiy, w = /((?:.)*?)/gyim, x, x, e;undefined; } while(\"17\");");
/*fuzzSeed-116066984*/count=1562; tryItOut("M:if(false) {( /x/ );function x(\u3056, x = intern( \"\" ))\u3056(\"\\uECF7\"); } else  if ((void options('strict_mode'))) {t1[0];function x(window) { print(x); } v0 = t2.length;v2 = Array.prototype.reduce, reduceRight.call(a0, f1, this.b0); } else print(x);");
/*fuzzSeed-116066984*/count=1563; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.asin((Math.pow((mathy0((2**53-2 | 0), ( + Math.log2((x >>> 0)))) | 0), mathy0(x, Math.fround((( - (y | 0)) | 0)))) >> (((((Math.hypot((mathy1(Math.ceil((Math.sinh(x) >>> 0)), y) >>> 0), (y | 0)) | 0) >>> 0) ? Math.log(Math.ceil(( ~ -(2**53-2)))) : ((( + Math.cbrt(x)) || (y ? Math.round((x | 0)) : Math.round(-Number.MIN_SAFE_INTEGER))) >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy2, [0x100000000, 0x07fffffff, -1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 0x080000000, 0x080000001, Number.MAX_VALUE, -(2**53-2), -0x100000000, 0x0ffffffff, -(2**53+2), -0, Math.PI, -0x080000001, 2**53+2, 1.7976931348623157e308, -0x080000000, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 0/0, 0x100000001, 2**53-2, 42, -0x07fffffff, 0, 2**53, -(2**53)]); ");
/*fuzzSeed-116066984*/count=1564; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.atan2((( + (( + (y > Math.hypot(y, x))) ? (x >>> 0) : ( + (x ? ( + mathy2(( + x), ( + ( ~ y)))) : x)))) >>> 0), Math.fround(Math.max((Math.trunc(( + Math.acosh(( + y)))) - Math.log2(1.7976931348623157e308)), y))) ? ((Math.imul((((( + mathy3(( + ( + Math.imul(( + 0x080000000), ( + y)))), ( + -0x100000001))) | 0) !== (( + ( - ( + Math.fround(( - y))))) | 0)) | 0), (x | 0)) | 0) >>> Math.atan2(Math.fround(( ~ ( + Math.max(( ! Math.fround(y)), x)))), ( + mathy0(y, (Math.tanh((x | 0)) | 0))))) : Math.hypot((Math.asin(x) ? Math.fround(Math.atan(Math.pow(x, y))) : y), Math.exp(((( + ( + x)) >>> 0) * ( - x))))); }); ");
/*fuzzSeed-116066984*/count=1565; tryItOut("\"use strict\"; a2.sort(f0, i2, e2, g0, v2);");
/*fuzzSeed-116066984*/count=1566; tryItOut("mathy1 = (function(x, y) { return Math.fround(mathy0((mathy0((Math.tanh(Math.cosh(x)) | 0), (( - Number.MAX_SAFE_INTEGER) | 0)) ? Math.max(mathy0(x, (y & y)), ( + Math.tan(( + mathy0((Math.atan2(y, x) | 0), ( + Math.clz32((Math.imul(Math.PI, (x >>> 0)) >>> 0)))))))) : ( - ( + ( + (Math.fround(x) ? y : (( + (-0x080000000 === x)) >= Math.imul(y, 0x080000001))))))), Math.fround(( ! ( + (x - Math.imul(x, x))))))); }); testMathyFunction(mathy1, [-(2**53), -0, 0/0, -Number.MIN_VALUE, 0.000000000000001, -0x100000001, 0, 1/0, 2**53-2, 42, -1/0, 0x07fffffff, -0x100000000, 0x100000000, -(2**53-2), 0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, -0x080000000, Number.MAX_VALUE, -(2**53+2), 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000001, 1, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1567; tryItOut("\"use strict\"; a2[({valueOf: function() { /*ADP-3*/Object.defineProperty(a2, v1, { configurable: false, enumerable: ((delete x.d) |= x % c), writable: true, value: m2 });return 16; }})] = \"\\u22E8\" <<  /x/g ;");
/*fuzzSeed-116066984*/count=1568; tryItOut("/*vLoop*/for (let ytwbil = 0; ytwbil < 55; ++ytwbil) { const e = ytwbil; /*RXUB*/var r = new RegExp(\"\\\\b\", \"yi\"); var s = \"   1 \"; print(uneval(r.exec(s)));  } ");
/*fuzzSeed-116066984*/count=1569; tryItOut("testMathyFunction(mathy2, [-0, 0.000000000000001, 0x0ffffffff, -0x0ffffffff, -(2**53), 1, 2**53, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 0/0, 0, -(2**53-2), -0x100000001, 2**53-2, 0x080000001, 0x100000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 42, 1/0, Number.MAX_VALUE, -1/0, -0x100000000, 0x100000000, -0x080000000, Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1570; tryItOut("\"use strict\"; o0.g1.v2 = t1.BYTES_PER_ELEMENT;");
/*fuzzSeed-116066984*/count=1571; tryItOut("mathy3 = (function(x, y) { return (Math.hypot((mathy2(Math.hypot(( + (Math.sinh((mathy1((((x | 0) - (x | 0)) | 0), y) | 0)) | 0)), ( + Math.min((( - (Math.min(((( + x) != ( + x)) >>> 0), (x >>> 0)) | 0)) | 0), (((y | 0) << (x | 0)) | 0)))), mathy0(((Math.sign(((( + ( + ( + Number.MIN_VALUE))) | Math.fround(Math.pow(Math.fround(y), y))) | 0)) >>> 0) | 0), ((x >>> 0) ? ((x ? Math.fround(( - (0/0 | 0))) : y) >>> 0) : (mathy0(x, y) >>> 0)))) | 0), (Math.sinh(((((( ! ( + (-(2**53) - -1/0))) >>> 0) || ((mathy0(Math.max(x, 0.000000000000001), ( + Math.asinh(y))) | 0) >>> 0)) >>> 0) | 0)) | 0)) | 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), Number.MIN_VALUE, Math.PI, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, 2**53-2, 0x100000001, 2**53, 2**53+2, -1/0, -0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, 1/0, -0x07fffffff, 1, -0x080000001, 0x080000000, -Number.MIN_VALUE, -0x100000000, 0x080000001, -0x080000000, 0.000000000000001, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, 0x07fffffff, -0, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1572; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; deterministicgc(false); } void 0; }");
/*fuzzSeed-116066984*/count=1573; tryItOut("\"use strict\"; t0 + '';");
/*fuzzSeed-116066984*/count=1574; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((mathy0(((1/0 === ((mathy0((x >>> 0), ((( ! x) | 0) | 0)) | 0) | 0)) | 0), ( + (Math.min((y | 0), (y | 0)) | 0))) >= (Math.atan2((mathy0((Math.fround((( + x) >= (x >>> 0))) >>> 0), (y >>> 0)) | 0), (( + Math.fround((Math.fround(x) >= ((Math.fround(mathy0(x, y)) ? 2**53-2 : Math.fround(Math.atan(y))) | 0)))) | 0)) | 0)) == ((mathy0((Math.log(Math.fround(Math.atan2(Math.fround(x), Math.fround(-0)))) | 0), (Math.fround(Math.min(0, Math.fround((Math.fround(y) | Math.fround(Number.MIN_VALUE))))) >> Math.imul(x, y))) | 0) | ( - (( ! y) | 0)))); }); testMathyFunction(mathy1, [2**53-2, -0x07fffffff, Math.PI, 0x100000000, 2**53, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 0x07fffffff, -0x100000001, -0, 0, 1, 0x0ffffffff, -0x100000000, Number.MAX_VALUE, -0x080000000, 0x080000000, 0x080000001, 0/0, -1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, 1.7976931348623157e308, -0x080000001, 42, -Number.MAX_VALUE]); ");
/*fuzzSeed-116066984*/count=1575; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.log(( + (( + ( ~ (y * -0))) <= (Math.log(y) + 0x080000001))))); }); ");
/*fuzzSeed-116066984*/count=1576; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-116066984*/count=1577; tryItOut("b0[\"eval\"] = i0;");
/*fuzzSeed-116066984*/count=1578; tryItOut("\"use strict\"; m2.delete(e2);");
/*fuzzSeed-116066984*/count=1579; tryItOut("\"use strict\"; /*oLoop*/for (nlreev = 0; nlreev < 132; ++nlreev) { s0 += s0; } \nyield;\nL:for(let x in -19) {yield;throw d; }");
/*fuzzSeed-116066984*/count=1580; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((1.5111572745182865e+23));\n    {\n      i1 = (((((-2147483649.0) <= (+((8796093022209.0)))))>>>((i0))));\n    }\n    i1 = (i1);\n    i0 = ((0x0));\n    i0 = (i0);\n    {\n      i0 = (i0);\n    }\n    (Int8ArrayView[2]) = ((0xa37140e2) % (((i0))>>>((((i0)+(i1)-(/*FFI*/ff(((-9.671406556917033e+24)))|0))|0) / (((i1)*-0xf89d8) << ((Uint16ArrayView[0]))))));\n    return +((((+((+(1.0/0.0))))) - ((-((+atan2(((268435456.0)), ((-134217727.0)))))))));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; yield y; print(([] = ({ set w(...window)true })));; yield y; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53+2), -0x100000001, 0x0ffffffff, -0, 1, 1/0, 0x080000000, 2**53+2, 0x100000001, -0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, -(2**53), -0x0ffffffff, -0x100000000, Number.MAX_VALUE, 0x07fffffff, -1/0, -Number.MAX_VALUE, 2**53-2, 42, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53, 0, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, -0x07fffffff, 0.000000000000001, 0/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1581; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[\\\\W\\\\x93-\\\\n]|.{2,4}\", \"gm\"); var s = \"\\u0094\\u0094\"; print(s.match(r)); ");
/*fuzzSeed-116066984*/count=1582; tryItOut("testMathyFunction(mathy3, /*MARR*/[]); ");
/*fuzzSeed-116066984*/count=1583; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(( ! (( + (( + (( + Math.fround(Math.round(x))) < Math.fround(Math.hypot(Math.fround(( + (y >>> 0))), Math.pow(( + Math.fround(x)), y))))) ? ( + Math.hypot((Math.min((x >>> 0), (( + (( + 0.000000000000001) | ( + x))) >>> 0)) >>> 0), (( + Math.fround((Math.fround(((0/0 >>> 0) && (x >>> 0))) != Math.fround(2**53-2)))) || ((Math.tanh(x) - x) >>> 0)))) : ( + Math.tanh((Math.sqrt((y | 0)) | 0))))) | 0))); }); testMathyFunction(mathy0, /*MARR*/[arguments, arguments, x, x, x, x, arguments, x, null, x, x, arguments, x, x, arguments, arguments, x, x, x, arguments, arguments, x, x, x, null, null, x, arguments, arguments, null, x, x, null, null, arguments, x, x, x, null, null, x, null, x, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, arguments, x, x, null, x, x, x, x, x, x, arguments, arguments, null, x, x, arguments, x, x, arguments, x, x, null, x, null, x, x, x, x, x, x, x, x, x, null, null, x, x]); ");
/*fuzzSeed-116066984*/count=1584; tryItOut("\"use strict\"; /*RXUB*/var r = window && w; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-116066984*/count=1585; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new Number(0)), true, false, 1, ({toString:function(){return '0';}}), 0, null, 0.1, ({valueOf:function(){return 0;}}), /0/, (new Boolean(false)), (new Number(-0)), NaN, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Boolean(true)), -0, (function(){return 0;}), [], '\\0', (new String('')), '/0/', [0], '0', '', undefined]); ");
/*fuzzSeed-116066984*/count=1586; tryItOut("a1.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var log = stdlib.Math.log;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 7.737125245533627e+25;\n;    i2 = (i0);\n    switch ((0x570f3d6f)) {\n      case -2:\n        (Float64ArrayView[(((imul((i2), ( '' ))|0) >= (0x74dfa720))-((0x0))) >> 3]) = ((NaN));\n        break;\n      case -3:\n        d3 = (((-((-2147483649.0))) != (+((((0xacc3e7c4) > (0xba611a09))+(i0)-(i0))|0))) ? (+pow(((7.737125245533627e+25)), ((+log(((536870911.0))))))) : (+((((0xa3f8df5a)) ? (257.0) : (+(~~(((-7.555786372591432e+22)) % ((70368744177665.0)))))))));\n        break;\n      case -2:\n        return +((-576460752303423500.0));\n        break;\n      case 1:\n        i1 = (i2);\n      case -1:\n        {\n          {\n            return +((+/*FFI*/ff(((0x13670c10)))));\n          }\n        }\n        break;\n      case -1:\n        i1 = ((d3) < (+/*FFI*/ff()));\n        break;\n      case -2:\n        (Int32ArrayView[((i0)-((((0x4c1d6b3e) < (0x7fffffff)) ? (562949953421313.0) : (4194304.0)))) >> 2]) = ((-0x8000000)-(-0x8000000));\n        break;\n      case -1:\n        (Float32ArrayView[((0xb60c2265)-(i1)) >> 2]) = (((Int16ArrayView[4096])));\n        break;\n      default:\n        {\n          {\n            i1 = (((((((d3)) / ((-17.0)))) - ((-65537.0))) < (+pow((((4277))), ((+pow((((0xde379c43) ? (33554433.0) : (-1.2089258196146292e+24))), ((-((-4194304.0)))))))))) ? (i1) : (((Int8ArrayView[1])) >= ((((this)(undefined)) = \"\\u6C65\".watch(\"8\",  /x/g ))>>>((0x836ba42b)+(i2)))));\n          }\n        }\n    }\n    i1 = (i2);\n    return +((-8193.0));\n  }\n  return f; })(this, {ff: String.prototype.trimLeft}, new ArrayBuffer(4096));");
/*fuzzSeed-116066984*/count=1587; tryItOut("\"use strict\"; return yield \"\\u1E47\";return;");
/*fuzzSeed-116066984*/count=1588; tryItOut("mathy3 = (function(x, y) { return (( + (( ~ ( ! ((x | 0) ? ((( + x) | ( + x)) | 0) : ((Math.imul((y | 0), (x | 0)) | 0) | 0)))) | 0)) || Math.max((((2**53-2 ? x : Math.fround(( ! Math.fround(y)))) == Math.fround(Math.max(Math.fround(( + (( + ( + ((1/0 , -0x100000001) <= ( + y)))) ? (y | 0) : ( + x)))), (Math.acos(((y ^ x) | 0)) | 0)))) | 0), (Math.min(x, x) - Math.hypot(-0x100000000, ((Math.tan(x) | 0) != y))))); }); testMathyFunction(mathy3, [(new Boolean(true)), '', undefined, 0.1, '0', (new Number(-0)), '/0/', ({valueOf:function(){return 0;}}), (new Boolean(false)), true, (function(){return 0;}), ({toString:function(){return '0';}}), /0/, 1, [0], false, -0, null, [], (new String('')), 0, ({valueOf:function(){return '0';}}), '\\0', objectEmulatingUndefined(), (new Number(0)), NaN]); ");
/*fuzzSeed-116066984*/count=1589; tryItOut("print(x);");
/*fuzzSeed-116066984*/count=1590; tryItOut("\"use strict\"; /*RXUB*/var r = o2.r0; var s = s0; print(uneval(r.exec(s))); ");
/*fuzzSeed-116066984*/count=1591; tryItOut("v2 = g2.runOffThreadScript();");
/*fuzzSeed-116066984*/count=1592; tryItOut("/*bLoop*/for (var pjsfhb = 0; pjsfhb < 40; ++pjsfhb) { if (pjsfhb % 57 == 21) { m2.__proto__ = b1; } else { /*infloop*/L:for(var window(this) in (( /x/ )( /x/g \n)))this.e0.add(t2); }  } ");
/*fuzzSeed-116066984*/count=1593; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.hypot(((((Math.fround(Math.hypot((-(2**53+2) >>> 0), Math.fround(x))) | 0) ? (y >>> 0) : (Math.fround(Math.sin(Math.fround(( - ((Math.fround((Math.log10((x >>> 0)) >>> 0)) ** (Math.min(x, y) | 0)) | 0))))) | 0)) | 0) | 0), Math.acos(((-Number.MIN_VALUE ? ((Math.pow((Math.imul(Math.fround(x), y) >>> 0), x) , Math.fround((x >> x))) >>> 0) : (Math.atan2(y, 0x080000000) | 0)) | 0))) | 0) & ( + Math.cbrt(( + (( + x) ? ( + ( ! Math.hypot((( ! (x >>> 0)) >>> 0), y))) : ( + y)))))); }); testMathyFunction(mathy1, [2**53, 2**53+2, 0x07fffffff, -0x100000001, -(2**53-2), -1/0, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, 0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 42, Number.MIN_VALUE, -0x080000001, 1, -0x100000000, -(2**53), -0, Math.PI, 0/0, 1/0, 0x080000001, 0x0ffffffff, -0x080000000, -0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1594; tryItOut("\"use strict\"; function shapeyConstructor(cqekce){delete cqekce[\"1\"];delete cqekce[\"caller\"];cqekce[\"toSource\"] = /*FARR*/[this].map(ReferenceError, window);return cqekce; }/*tLoopC*/for (let a of (delete z.NaN = \n22) for each (x in (4277)) for (x of x) for (d of  '' ) for (this.zzz.zzz in x) for (e of [])) { try{let fhydps = shapeyConstructor(a); print('EETT'); v0 = a0.reduce, reduceRight(Date.prototype.getTimezoneOffset.bind(h2), p1);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-116066984*/count=1595; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1596; tryItOut("");
/*fuzzSeed-116066984*/count=1597; tryItOut("t2[7] = s2;");
/*fuzzSeed-116066984*/count=1598; tryItOut("s1 = Array.prototype.join.call(a0, s0, a2);");
/*fuzzSeed-116066984*/count=1599; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\W)\", \"yim\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=1600; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = ((((4277))) * ((d1)));\n    d0 = (d1);\n    {\n      (Uint8ArrayView[(((0x45a477a6))) >> 0]) = ((-0x8000000)-(!(0x952005eb))+((0x8f757e0a) <= (0x17d8c188)));\n    }\n    d1 = (((d0)) * (((d1) + (+/*FFI*/ff(((+abs(((+/*FFI*/ff(((~~(+/*FFI*/ff(((+pow(((0.0078125)), ((-3.777893186295716e+22))))), ((2147483649.0)))))), ((d0)), ((+(1.0/0.0))), ((-9223372036854776000.0)), ((8388609.0)))))))))))));\n    (Uint8ArrayView[4096]) = ((0xffffffff)+((+((((d1)) - ((d1))))) >= (-((((0xfaf41d7b)-((/*FFI*/ff(((-68719476736.0)), ((-68719476737.0)), ((-2147483649.0)), ((-1125899906842625.0)), ((-2049.0)), ((-1125899906842623.0)), ((-131073.0)), ((35184372088833.0)), ((-1048577.0)), ((3.094850098213451e+26)), ((36893488147419103000.0)), ((-257.0)), ((-33.0)), ((-73786976294838210000.0)), ((67108865.0)), ((-6.044629098073146e+23)), ((3.022314549036573e+23)), ((536870913.0)), ((32767.0)), ((36028797018963970.0)))|0) ? ((0x47df3904) != (-0x8000000)) : ((0x2029bbda) > (0x5c113f87))))))))+(( '' )));\n    {\n      {\n        {\n          (Int8ArrayView[((0x50fbe0da)) >> 0]) = ((0xe5001c50)+((~(((((Int32ArrayView[1]))>>>((0x3d47ef88)+(0x7de41f7d)+(0xfc8dad9b))))-(0xfbe13ad6))) < (0x5139592))+((d1) <= (+(0x3a486ce6))));\n        }\n      }\n    }\n    {\n      switch ((((0xffffffff)-(0x664576a0))|0)) {\n        default:\n          d1 = (d1);\n      }\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: (Set.prototype.delete).bind()}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116066984*/count=1601; tryItOut("print(x);");
/*fuzzSeed-116066984*/count=1602; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.fround((Math.acos(Math.hypot(x, ( + (x ? (y >>> 0) : 1.7976931348623157e308)))) ? ((x << (((Math.atanh(Math.pow(0x100000001, y)) >>> 0) ^ ((y || Math.fround(Math.min(( + ( - y)), y))) >>> 0)) >>> 0)) | 0) : Math.fround(Math.imul(-0x100000001, (Math.asin(y) | 0)))))) ? ((Math.hypot(( + Math.acosh(Math.atanh((((y | 0) ? (x | 0) : (Math.atan2(Math.max(y, ( + -0x0ffffffff)), ((y + x) >>> 0)) | 0)) | 0)))), ( ~ Math.fround(x))) | 0) | 0) : ((( ~ (Math.log10((( ~ (2**53 >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, Number.MIN_VALUE, 0.000000000000001, -0, 2**53, -Number.MIN_VALUE, Math.PI, 0x07fffffff, 0x100000000, 0/0, 1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000000, -0x100000001, 0x080000001, 2**53+2, 0x080000000, 0x100000001, -0x100000000, -Number.MAX_VALUE, 2**53-2, 1, 0, -(2**53), 1.7976931348623157e308, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1603; tryItOut("\"use strict\"; for (var p in this.e1) { try { Object.defineProperty(this, \"v1\", { configurable: false, enumerable: false,  get: function() {  return evaluate(\"function f1(t0)  { return (Math.max(22, (4277)) && t0).fontsize(intern(e)) } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 2 != 1) })); } }); } catch(e0) { } try { Array.prototype.sort.apply(a2, [g0.f0]); } catch(e1) { } try { t0.valueOf = f0; } catch(e2) { } a2[7] = g0; }");
/*fuzzSeed-116066984*/count=1604; tryItOut("testMathyFunction(mathy4, [-0x0ffffffff, 1, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 42, -0x100000000, 0x100000001, -0x080000000, 1/0, -0, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, -(2**53-2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, 0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -0x080000001, 1.7976931348623157e308, -1/0, 0x080000001, -(2**53), Math.PI, -0x07fffffff, 2**53, 0x080000000, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1605; tryItOut("/*infloop*/M:while(new Set( /x/g ))(\"\\u6D34\");");
/*fuzzSeed-116066984*/count=1606; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround(Math.exp((Math.expm1((x | 0)) | 0))) && Math.fround(Math.fround(Math.log10(Math.fround(Math.max(( + Math.min(( + Math.fround((Math.fround(y) <= Math.fround(( + (y >>> 0)))))), ( + 0x080000001))), ((Math.tan((y >>> 0)) >>> 0) != y))))))); }); testMathyFunction(mathy2, [42, 0x080000000, 0x100000000, -0x100000001, 0.000000000000001, 0, -(2**53-2), Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 1/0, -(2**53+2), 2**53-2, 0x0ffffffff, -(2**53), 1.7976931348623157e308, -0x07fffffff, -0x080000001, 2**53+2, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, 0x07fffffff, Number.MAX_VALUE, 0x080000001, -1/0, -0x080000000, -0, 2**53, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1607; tryItOut("\"use strict\"; (-11);");
/*fuzzSeed-116066984*/count=1608; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return Math.acosh(Math.round((( + (( + y) >> ( + x))) & (mathy0(((((Math.imul(2**53, 2**53-2) >>> 0) & y) >>> 0) | 0), (Math.fround(Math.log10(Math.fround(( + x)))) | 0)) | 0)))); }); testMathyFunction(mathy1, [0/0, -0x0ffffffff, 0x100000001, -0, 1/0, -0x080000001, -Number.MAX_VALUE, Math.PI, -0x100000001, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 0x080000000, -Number.MIN_VALUE, 2**53, -0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, -Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, -0x080000000, 1, 2**53-2, 0x080000001, Number.MIN_VALUE, 42, -(2**53+2), 0.000000000000001, -(2**53-2), 0x100000000]); ");
/*fuzzSeed-116066984*/count=1609; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116066984*/count=1610; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var pow = stdlib.Math.pow;\n  var ceil = stdlib.Math.ceil;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[1]) = ((((-6.189700196426902e+26)) - ((+atan2(((d1)), ((-4096.0)))))));\n    return +((((+pow(((Float32ArrayView[4096])), ((((+(((0x58a58b16)-(0x58b2aaf5)) >> (((-0x8000000)))))) % ((+ceil(((d1)))))))))) / ((Float32ArrayView[((i0)) >> 2]))));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [(new Boolean(true)), '\\0', 0, 1, ({toString:function(){return '0';}}), objectEmulatingUndefined(), '/0/', ({valueOf:function(){return 0;}}), undefined, '0', (new Number(-0)), false, ({valueOf:function(){return '0';}}), null, (new Boolean(false)), (new Number(0)), [], 0.1, (function(){return 0;}), [0], -0, NaN, '', true, (new String('')), /0/]); ");
/*fuzzSeed-116066984*/count=1611; tryItOut("/*RXUB*/var r = /(((?:((?:(^)))))(?:\u6178)+?([^]*?){0,1}*?+?)*/; var s = \"\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\\u6158\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=1612; tryItOut("\"use strict\"; m1.set(h1, m1);");
/*fuzzSeed-116066984*/count=1613; tryItOut("v0.toSource = f2;");
/*fuzzSeed-116066984*/count=1614; tryItOut("/*vLoop*/for (var puvuej = 0; ((yield  /x/ )) && puvuej < 5; ++puvuej) { var a = puvuej; o2.a2 = (Math.atan2(new String('q'), [] = ([[]].valueOf\u000c(\"number\"))))((4277)); } ");
/*fuzzSeed-116066984*/count=1615; tryItOut("this.m2.get(s0);");
/*fuzzSeed-116066984*/count=1616; tryItOut("/*MXX3*/g0.ArrayBuffer.prototype.slice = this.g1.ArrayBuffer.prototype.slice;function x(x)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (i1);\n    return (((!(i2))))|0;\n  }\n  return f;/*infloop*/do {/*RXUB*/var r = /(?!(?=[^\\u0065-\\u008A\\s\\S\\W]\\d+)?|\\b)/gim; var s = \"\"; print(s.replace(r, objectEmulatingUndefined)); v2 = evalcx(\"print(x);v0 = Object.prototype.isPrototypeOf.call(this.p2, g1.a2);\", g0); } while(x);");
/*fuzzSeed-116066984*/count=1617; tryItOut("v2 = Object.prototype.isPrototypeOf.call(t2, t0);");
/*fuzzSeed-116066984*/count=1618; tryItOut("\"use strict\"; a1 = Array.prototype.filter.call(g2.a0);function NaN(\u3056, b)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -35184372088831.0;\n    d0 = (-33.0);\n    d0 = (d0);\n    return ((0xfffff*(i2)))|0;\n  }\n  return f;new RegExp(\".c*?+(?=\\\\D|(?:\\\\b{2,}))+?\", \"i\");");
/*fuzzSeed-116066984*/count=1619; tryItOut("v0 = Object.prototype.isPrototypeOf.call(s2, g1.o1);");
/*fuzzSeed-116066984*/count=1620; tryItOut("m1 = new WeakMap");
/*fuzzSeed-116066984*/count=1621; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var sin = stdlib.Math.sin;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -257.0;\n    var d3 = -9223372036854776000.0;\n    switch (((-((0x68d138f2))) ^ ((i1)))) {\n      case 0:\n        d3 = (+sin(((Float32ArrayView[((0xd11ff539)-(i1)+(i1)) >> 2]))));\n        break;\n      case 1:\n        {\n          {\n            i1 = ((((0xfed6ac67)+(i0))>>>(((0x4349693) < (((0xfa3c4ddf))>>>((0x5b70a3c0))))+((/*FFI*/ff(((3.022314549036573e+23)))|0) ? (i0) : (0x110e1fca))-(((imul((0xf8d44693), ((0xc5cd9f0) <= (0x3aa6a3ff)))|0))))) == (0xb241c243));\n          }\n        }\n        break;\n      case -1:\n        /*FFI*/ff(((undefined)), (((((0x5d013480))) & ((i1)-((0x22c41775))-((3.094850098213451e+26) != (-34359738367.0))))), (((((/*MARR*/[0x5a827999, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER].map))-((0x5c4a1e9f) >= (0x2cea4ff1))) ^ ((i0)))), ((-32767.0)), ((((0xffffffff)*0xd6ffd) & (-(0xfb295ae4)))));\n        break;\n      case -3:\n        return +((-1099511627777.0));\n        break;\n      case -1:\n        i0 = (((((imul((i1), ((0x80e4c639)))|0))-(eval(\"Object.seal(s2);\", (4277) >>>= (new Function(x -= x, this)))))>>>((0xf80b6876) % (0x4d74de7c))) < (0xcd4fe75c));\n        break;\n      case -1:\n        i0 = (0x53942cdf);\n        break;\n      default:\n        d3 = (d2);\n    }\n    i0 = ((((((((-0x8000000)) ^ ((-0x8000000))) == ((Int8ArrayView[1])))) | ((Uint8ArrayView[((0x8986dd21)+(0xc6deb27f)) >> 0]))) > ((((((0x6a75e951))>>>((0xfd92b24a))) < (((0xe7c0448e))>>>((0xfebd7c85))))) ^ (((0xfb3b6c94) ? (-0x6b77a61) : (0xfb0343dd))))) ? ((((i1))>>>((0x66d0c249))) <= ((((0x0) > (0xe4ca1512)))>>>(((1048577.0) < (4097.0))+(0xb1ba461d)-(i1)))) : (0x1b668d2a));\n    i0 = ((+((-3.094850098213451e+26))) == (((d3)) * ((Infinity))));\n    return +((d2));\n  }\n  return f; })(this, {ff: function(y) { b2 + ''; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined()]); ");
/*fuzzSeed-116066984*/count=1622; tryItOut("/*RXUB*/var r = /(\\d){3,5}|(\\1{4,}|\\2(${1,2})*)|\\B(?:\\1{3,7})+?/gy; var s =  /x/g  ? [,,z1] :  /x/g ; print(r.test(s)); ");
/*fuzzSeed-116066984*/count=1623; tryItOut("g2.m2.has(v0);");
/*fuzzSeed-116066984*/count=1624; tryItOut("m0.delete(this.b2);");
/*fuzzSeed-116066984*/count=1625; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.asinh(Math.max((Math.atan2(x, Math.fround(2**53+2)) << ((y >>> 0) , x)), (Math.min(Math.fround(( + (( + x) || ( + y)))), Math.fround(Math.log10(Math.fround(((x >>> 0) | x))))) >>> 0)))); }); ");
/*fuzzSeed-116066984*/count=1626; tryItOut("var r0 = 4 | x; r0 = r0 ^ 2; var r1 = 2 / x; var r2 = x + x; print(x); var r3 = r0 / x; var r4 = 7 * 1; x = 2 + r3; var r5 = r4 * x; var r6 = r4 / r4; var r7 = r5 + r3; print(r0); r6 = r2 / r1; var r8 = r1 ^ 5; var r9 = r8 & r7; var r10 = r5 - r8; r3 = r1 % r6; var r11 = 1 & r3; var r12 = 2 * 3; var r13 = r11 - 5; var r14 = x ^ r12; var r15 = r10 - r0; var r16 = 1 - 3; var r17 = x / 6; var r18 = r17 + 6; var r19 = r1 ^ 6; var r20 = r2 & r10; var r21 = r7 & 1; var r22 = r17 & r1; var r23 = 9 | 2; var r24 = r1 | r15; var r25 = r2 + 5; var r26 = r23 / 7; var r27 = r25 * r25; r8 = r23 - 0; r2 = r3 % 4; r26 = r27 / 2; r6 = r3 / r3; var r28 = r13 % 7; var r29 = r6 * r24; ");
/*fuzzSeed-116066984*/count=1627; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( ! mathy0(Math.acosh(( + (( + Math.fround(Math.log2(((( + (x | 0)) | 0) | y)))) - Math.fround(( + ( + ( + y))))))), (Math.cbrt((x && (x >>> 0))) >>> Math.atan((x || y)))))); }); ");
/*fuzzSeed-116066984*/count=1628; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( + mathy0(( + ( + mathy1(( + ( - x)), ((uneval(w)) ? Math.cosh(( + y)) : (x >>> 0))))), (((y | 0) && y) | 0)))) & Math.fround(( + ( + (((( + (( + (Math.max(x, Math.fround(Math.max(Math.fround((((-(2**53) >>> 0) || (2**53 >>> 0)) | 0)), (Math.atan2((-0 >>> 0), (Number.MAX_VALUE >>> 0)) >>> 0)))) >>> 0)) >>> 0)) ? ( + ((x >>> 0) < (( + (y | 0)) | 0))) : ( + ( + mathy0((Math.fround(mathy1(y, (mathy1((y | 0), (x | 0)) | 0))) >>> 0), y)))) | 0) | 0)))))); }); testMathyFunction(mathy2, [-0, false, 1, [0], '/0/', 0, objectEmulatingUndefined(), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Number(-0)), NaN, '0', (new String('')), (new Number(0)), ({valueOf:function(){return '0';}}), true, '\\0', 0.1, (new Boolean(true)), (new Boolean(false)), (function(){return 0;}), null, [], '', /0/, undefined]); ");
/*fuzzSeed-116066984*/count=1629; tryItOut("mathy2 = (function(x, y) { return Math.atan2(( + Math.min(mathy0((( ~ (( ! Math.atan2(0x080000001, y)) >>> 0)) >>> 0), ( + y)), ( + mathy0(Math.fround(Math.max(Math.fround(Math.acos((Math.fround((y >>> 0)) >>> 0))), Math.fround((Math.PI && x)))), ( + (( + -0x080000000) | 0)))))), Math.expm1(( + ( + Math.min(((Math.acosh((x >>> 0)) | 0) == (mathy1((x >>> 0), (( ~ ( + 0/0)) >>> 0)) >>> 0)), ( + (Math.atan(Math.atan2(-0x100000000, y)) >>> 0))))))); }); testMathyFunction(mathy2, /*MARR*/[2**53+2,  \"\" , -Number.MIN_VALUE, -(2**53-2),  \"\" , new String('q'), new String('q'), -(2**53-2), new String('q'),  \"\" , -(2**53-2), -(2**53-2), 2**53+2, 2**53+2, -(2**53-2), 2**53+2, 2**53+2, new String('q'), new String('q'),  \"\" , 2**53+2, 2**53+2, -(2**53-2),  \"\" , 2**53+2, new String('q'),  \"\" , 2**53+2, -(2**53-2), 2**53+2]); ");
/*fuzzSeed-116066984*/count=1630; tryItOut("\"use asm\"; /*iii*/Array.prototype.push.apply(a1, [t1, this.i2, b0, i2]);/*hhh*/function muawin(x = (x =  \"\" )){print((\"\\uCCB8\"\n));}");
/*fuzzSeed-116066984*/count=1631; tryItOut("for(a\u0009 = let (x = x, efofwl, NaN, yeijxk, x, x, ansbhh, c) x in let (y = \u000cSyntaxError(Math.atan2( /x/g , 12))) (makeFinalizeObserver('tenured'))) {new RegExp(\"(?:\\\\B|[^]|\\\\W\\\\r+?\\u0018|^+*?)+?\", \"gym\");{ void 0; verifyprebarriers(); } }");
/*fuzzSeed-116066984*/count=1632; tryItOut("let o2.v0 = -0;");
/*fuzzSeed-116066984*/count=1633; tryItOut(";");
/*fuzzSeed-116066984*/count=1634; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1.015625;\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: DataView.prototype.setFloat32}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0, 0/0, 0x080000001, 0x07fffffff, -(2**53+2), -0x100000001, -Number.MAX_VALUE, 0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 1, -1/0, Number.MIN_SAFE_INTEGER, 42, 0x100000000, 0.000000000000001, Number.MIN_VALUE, -0x07fffffff, 0, 1/0, 2**53+2, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, 2**53-2, 0x080000000, -(2**53), -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 1.7976931348623157e308, 2**53]); ");
/*fuzzSeed-116066984*/count=1635; tryItOut("\"use strict\"; this.i2.next();");
/*fuzzSeed-116066984*/count=1636; tryItOut("mathy2 = (function(x, y) { return Math.asin((Math.tan((Math.fround(Math.hypot(Math.fround((Math.fround(y) != Math.fround((Number.MIN_VALUE >> y)))), ( + -Number.MIN_SAFE_INTEGER))) | 0)) | 0)); }); testMathyFunction(mathy2, /*MARR*/[-0x5a827999,  \"use strict\" , -0x5a827999,  \"use strict\" , new String('q'), new Boolean(true), new Boolean(true), new Boolean(true), -0x5a827999, new String('q'),  \"use strict\" ,  \"use strict\" ,  '' , new String('q'), new Boolean(true), new Boolean(true),  '' ,  \"use strict\" , new String('q'), -0x5a827999,  '' ,  '' , -0x5a827999,  \"use strict\" ,  '' ,  \"use strict\" ,  \"use strict\" , -0x5a827999, -0x5a827999,  '' , new String('q'), -0x5a827999,  \"use strict\" , new String('q'), new Boolean(true), new String('q'),  \"use strict\" ,  '' , -0x5a827999, new Boolean(true),  '' , new Boolean(true), new Boolean(true),  '' , new String('q'),  '' , -0x5a827999, -0x5a827999, new Boolean(true)]); ");
/*fuzzSeed-116066984*/count=1637; tryItOut("testMathyFunction(mathy2, [-0, -Number.MAX_VALUE, -0x080000000, 2**53, 1.7976931348623157e308, 42, Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, -0x0ffffffff, 0.000000000000001, 0x100000001, -0x080000001, 0x07fffffff, 1, 2**53-2, 0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, 2**53+2, -(2**53-2), -0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, 0, -0x100000000, 1/0, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, Math.PI, -Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1638; tryItOut("/*oLoop*/for (let fpbgup = 0; fpbgup < 73; ++fpbgup) { v2 = evaluate(\"v2 = evaluate(\\\"/* no regression tests found */\\\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: ({a2:z2}), sourceIsLazy: (x % 6 != 2), catchTermination: false }));\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: function(id) { return id }, sourceIsLazy: 9, catchTermination: \"\\u372D\" })); } ");
/*fuzzSeed-116066984*/count=1639; tryItOut("v0 = g0.eval(\"delete c.d\");");
/*fuzzSeed-116066984*/count=1640; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ( ! ( + mathy0((( ! ( + x)) ? ((Math.atan2(( + 0), ( + y)) | 0) - ( + x)) : (-0x0ffffffff >= x)), Math.pow(y, (( ! ( - ((y ? x : x) | 0))) | 0)))))); }); testMathyFunction(mathy3, [0, [], ({toString:function(){return '0';}}), 1, [0], -0, objectEmulatingUndefined(), false, (new Number(0)), '\\0', null, ({valueOf:function(){return 0;}}), (new String('')), /0/, undefined, true, '/0/', (new Boolean(true)), '0', 0.1, (new Number(-0)), '', ({valueOf:function(){return '0';}}), (function(){return 0;}), NaN, (new Boolean(false))]); ");
/*fuzzSeed-116066984*/count=1641; tryItOut("mathy3 = (function(x, y) { return Math.atan2(Math.fround(( ~ Math.fround(Math.cos(Math.abs((Math.sinh((Math.log2(x) >>> 0)) | 0)))))), (( - Math.pow((Math.fround(Math.atan2(Math.fround(0x080000001), Math.fround(y))) | 0), (Math.min(mathy2(( ~ y), (x > ( + Math.min((1 | 0), (x >>> 0))))), (x - (y | 0))) | 0))) | 0)); }); testMathyFunction(mathy3, [-(2**53-2), Math.PI, -Number.MIN_VALUE, 2**53+2, 0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, 0, -0x07fffffff, 0/0, Number.MIN_VALUE, 0x0ffffffff, 42, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 0x07fffffff, 0x100000001, 2**53-2, -0x080000001, -0, -0x080000000, -(2**53), -1/0, 2**53]); ");
/*fuzzSeed-116066984*/count=1642; tryItOut("m0.has(o0);/* no regression tests found */");
/*fuzzSeed-116066984*/count=1643; tryItOut("mathy4 = (function(x, y) { return ( + Math.acos(((mathy3((( ~ mathy2((-0x080000000 >>> 0), Math.fround(( + (y >>> 0))))) >>> 0), (( + ( - (Math.acos(((( - ( + Math.atan(( + (mathy0((1/0 >>> 0), 0/0) | 0))))) | 0) >>> 0)) >>> 0))) >>> 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy4, [-0, -0x100000001, -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, 1, -(2**53-2), 0, 2**53-2, -0x100000000, -0x080000000, Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE, 0x100000001, -0x07fffffff, -Number.MAX_VALUE, 0x100000000, 2**53, 0x080000001, 2**53+2, -0x080000001, 0x080000000, -(2**53+2), 1/0, 0.000000000000001, -0x0ffffffff, Math.PI, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1644; tryItOut("/*tLoop*/for (let y of /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), false, false, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), false, false, new Number(1.5), false, new Number(1.5), false, new Number(1.5), false, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), false, new Number(1.5), new Number(1.5), new Number(1.5), false, false, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5)]) { (\"\\u3B7B\"); }this.h1.defineProperty = f0;");
/*fuzzSeed-116066984*/count=1645; tryItOut("mathy4 = (function(x, y) { return Math.pow(( + Math.max((( - ((( ~ (x | 0)) ? x : y) >>> 0)) >>> 0), ( - Math.pow((( - (-0x080000001 >>> 0)) >>> 0), Math.atan2(( + (x | 0)), ( ! y)))))), (Math.log1p(((y !== y) && ( ! ( + (( + y) >>> ( + y)))))) , Math.asin(x))); }); testMathyFunction(mathy4, [-0x100000000, 0x07fffffff, 0x080000001, 42, -1/0, 0x0ffffffff, Math.PI, 0, Number.MIN_VALUE, -(2**53+2), 0.000000000000001, -0x080000000, 0/0, 0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, Number.MAX_VALUE, -0x080000001, 1, -(2**53), Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, 2**53+2, -0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1646; tryItOut("t0 + '';");
/*fuzzSeed-116066984*/count=1647; tryItOut("mathy0 = (function(x, y) { return (( ! ((( ~ (Math.sqrt(Math.fround((( + Math.sqrt(( + y))) >= Math.fround(Math.log2(( + x)))))) < (y == x))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[(void 0), [1], (void 0), (void 0), [1], [1], [1], [1], [1], [1], [1], (void 0)]); ");
/*fuzzSeed-116066984*/count=1648; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0.000000000000001, 2**53, 0x0ffffffff, -0x080000000, -0x100000000, -1/0, -0x07fffffff, -(2**53-2), 0x100000000, -0x080000001, 2**53+2, -0x0ffffffff, 0/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 2**53-2, 0x080000001, Number.MIN_VALUE, -0, -(2**53+2), 0x07fffffff, Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), Number.MIN_SAFE_INTEGER, 42, 1/0, 0x080000000, Math.PI, 0, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1649; tryItOut("/* no regression tests found */");
/*fuzzSeed-116066984*/count=1650; tryItOut("mathy3 = (function(x, y) { return mathy2((Math.atan2(Math.max(x, Math.pow(Math.sin((mathy2((x >>> 0), (x >>> 0)) >>> 0)), y)), (( - Math.atan2(x, (Math.exp(( + -0x100000001)) >>> 0))) | 0)) | 0), ((Math.pow((Math.fround(Math.max(y, Math.fround(Math.sin(Math.fround(Math.asin(x)))))) | 0), (( - Math.fround(( + (Math.fround(mathy1(Math.fround((Math.atanh((y | 0)) | 0)), Math.fround((((y >>> 0) ** (x >>> 0)) >>> 0)))) << ( + y))))) | 0)) >>> 0) | 0)); }); ");
/*fuzzSeed-116066984*/count=1651; tryItOut("mathy3 = (function(x, y) { return (( + (( + 0x100000000) <= (((mathy1((( - y) | 0), ( + Math.ceil((( + Math.min(( + y), ( + x))) >>> 0)))) >>> Math.fround((Math.fround(( - y)) ? Math.fround((Math.max((Math.fround(Math.log1p((( + (x >>> 0)) >>> 0))) | 0), (x | 0)) | 0)) : (Math.max((x >>> 0), (2**53+2 | 0)) | 0)))) >>> 0) | 0))) >>> 0); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, -Number.MAX_VALUE, 2**53, 0/0, -0x080000001, 0x0ffffffff, -0, -1/0, -0x07fffffff, 0x100000001, -(2**53+2), -0x100000001, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 1.7976931348623157e308, 2**53+2, 0.000000000000001, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, Number.MIN_VALUE, 0x080000001, 1, 0x07fffffff, 42, 0]); ");
/*fuzzSeed-116066984*/count=1652; tryItOut("\"use strict\"; for (var v of s1) { try { g0.offThreadCompileScript(\"x\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (), sourceIsLazy: false, catchTermination: false })); } catch(e0) { } try { a0.shift(); } catch(e1) { } try { for (var v of o0) { try { g1.m0.has(g1.p0); } catch(e0) { } a2.shift(); } } catch(e2) { } v1 = a0.length; }");
/*fuzzSeed-116066984*/count=1653; tryItOut("Object.defineProperty(this, \"m2\", { configurable: (x % 12 != 3), enumerable: false,  get: function() {  return new WeakMap; } });");
/*fuzzSeed-116066984*/count=1654; tryItOut("mathy4 = (function(x, y) { return (( - (( + (( + Math.max((Math.min((Math.max(Math.sign(y), -0x080000001) | 0), ( + ( + ( + -Number.MIN_VALUE)))) | 0), (Math.imul(( + ( + (( ~ ( + x)) ? mathy2(0x07fffffff, y) : y))), Math.fround(( ~ x))) >>> 0))) == ( + ((mathy3(((( + mathy3(x, ( + 2**53+2))) / -Number.MIN_VALUE) >>> 0), (( ~ ( + ( + Math.acos(( + (((0/0 | 0) | x) | 0)))))) >>> 0)) >>> 0) ? Math.fround(Math.atanh(Math.cosh(-0x0ffffffff))) : Math.pow(((x ? y : -0x07fffffff) % x), (((-0x100000001 | 0) >= ((((x >>> 0) && ( + Math.fround(((-Number.MAX_SAFE_INTEGER >>> 0) >>> 2**53-2)))) >>> 0) | 0)) | 0)))))) | 0)) | 0); }); ");
/*fuzzSeed-116066984*/count=1655; tryItOut("p1.toSource = (4277);");
/*fuzzSeed-116066984*/count=1656; tryItOut("\"use strict\"; var tptlle = new SharedArrayBuffer(8); var tptlle_0 = new Uint16Array(tptlle); tptlle_0[0] = -20; yield [z1];return undefined;");
/*fuzzSeed-116066984*/count=1657; tryItOut("testMathyFunction(mathy5, /*MARR*/[x, (-1/0), (-1/0), x, x, x, x, x, (-1/0), x, x, x, x, x, x, x, x, x, x, x, x, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-116066984*/count=1658; tryItOut("x;");
/*fuzzSeed-116066984*/count=1659; tryItOut("\"use strict\"; a2[3];\nprint(x);\n");
/*fuzzSeed-116066984*/count=1660; tryItOut("testMathyFunction(mathy5, [-0x100000000, -(2**53), 1, 0.000000000000001, Math.PI, 1.7976931348623157e308, 0, 42, -0, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 2**53+2, -Number.MAX_VALUE, 0/0, -0x080000000, -Number.MIN_VALUE, 0x080000000, -(2**53-2), -0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, 2**53, 0x100000001, -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001, -0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1661; tryItOut("const e = Math.imul(-3,  '' ) ? ((x === Math.min(0.000000000000001, x)) ? 0x080000000 : Math.acos((( + ( ~ -Number.MIN_SAFE_INTEGER)) | 0))) : function  x (a) { return new RegExp(\"(?!(?:\\\\2)|[\\\\s\\\\v\\u3d35-\\\\u6308]{3}|\\\\B*?)\", \"i\") } , eval, x = Infinity, zjsnyc;for(let b in x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: (e =>  { a0.sort([1,,], a1); } ).call, getPropertyDescriptor: function() { throw 3; }, defineProperty: /*wrap3*/(function(){ var kcqvee = \"\\u2DD3\"; (/*wrap3*/(function(){ var rwyjxw = e; (arguments.callee.caller.caller)(); }))(); }), getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: () =>  { yield  \"\"  } , keys: function() { return Object.keys(x); }, }; })(({x: false })), x)) o1 = f2.__proto__;");
/*fuzzSeed-116066984*/count=1662; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (((Math.atan(Math.fround(Math.log2(Math.fround(( + (((Math.min(Math.ceil(-1/0), (x | 0)) >>> 0) ? (x >>> 0) : (Number.MIN_SAFE_INTEGER >>> 0)) , ( + y))))))) >>> 0) >= Math.fround(( + Math.pow(( + Math.fround(((((( ~ ((-Number.MAX_VALUE === Math.asinh(x)) | 0)) | 0) + Math.sin(y)) | 0) || Math.fround(Math.fround((y ** Math.fround(-0x0ffffffff))))))), (Math.max(( + ( ~ ((x ? 0x07fffffff : (Math.hypot(x, 2**53+2) === y)) >>> 0))), Math.cbrt((mathy1(( + (mathy3((y >>> 0), y) >>> (((-(2**53+2) >>> 0) & (x >>> 0)) >>> 0))), (y / x)) >>> 0))) | 0))))) >>> 0); }); testMathyFunction(mathy5, [42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 0x07fffffff, -0x0ffffffff, 0x100000001, -0x100000001, -0x07fffffff, 0.000000000000001, -(2**53), Number.MAX_VALUE, 2**53+2, 0x0ffffffff, -(2**53+2), 0x100000000, 0x080000001, 2**53-2, Math.PI, 2**53, 1/0, 0/0, -0, -(2**53-2), -Number.MAX_VALUE, Number.MIN_VALUE, -0x100000000, -0x080000001, 1.7976931348623157e308, -0x080000000, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1663; tryItOut("a2.length = 18;");
/*fuzzSeed-116066984*/count=1664; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( + Math.fround(( + Math.trunc(Math.fround((y - Math.fround(Math.imul((-(2**53) | 0), Math.fround(Number.MIN_VALUE)))))))))); }); ");
/*fuzzSeed-116066984*/count=1665; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.min(( + (( - (( + ( ~ ( + x))) >>> 0)) >>> 0)), ( + Math.sqrt(( + ( + Math.min(( + mathy0(-0x0ffffffff, y)), Math.trunc(( + Math.max(( + Math.log2(( + 1/0))), 1.7976931348623157e308))))))))); }); testMathyFunction(mathy3, [0, (new Number(-0)), [], 1, (new Boolean(false)), (function(){return 0;}), (new Number(0)), '/0/', (new Boolean(true)), NaN, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), (new String('')), /0/, undefined, false, -0, '', null, '\\0', ({valueOf:function(){return '0';}}), 0.1, [0], true, ({toString:function(){return '0';}}), '0']); ");
/*fuzzSeed-116066984*/count=1666; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.expm1(Math.fround(mathy0(( ~ (y - Math.fround(Math.log1p(x)))), (((( + Math.round(( + Math.tanh(( + y))))) | 0) - (( + (y ** Math.fround(Math.pow(Math.fround(-0x080000000), Math.fround(x))))) | 0)) | 0))))); }); ");
/*fuzzSeed-116066984*/count=1667; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i0)+(i0)))|0;\n  }\n  return f; })(this, {ff: ({19: ++x,  get length(d, ...x) { yield (eval(\"\\\"use strict\\\"; yield;\")) }  }).toLocaleUpperCase}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, 0.000000000000001, Math.PI, 42, 0x07fffffff, 2**53, -Number.MAX_VALUE, 0x100000001, 0x0ffffffff, Number.MAX_VALUE, 1/0, -(2**53+2), -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, -(2**53), -0x07fffffff, 0x080000001, 1, 0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1668; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + Math.atan2(((Math.fround((Math.fround(Math.fround(-0x080000001)) >> Math.fround(-0))) === (Math.fround((Math.fround(x) / Math.fround(-0))) % 42)) >>> 0), (Math.imul(Math.fround(( - x)), ( + (x > Math.sinh((y | 0))))) | 0))) ? ( + ((Math.imul(x, (Math.atan2(Math.fround(y), (y | 0)) | 0)) >>> 0) && ( - Math.atan2(Math.max(-0x100000001, y), (mathy0((y >>> 0), (x >>> 0)) | 0))))) : (((Math.fround(( + Math.fround(Math.fround(Math.tanh(Math.fround(Math.ceil(y))))))) > Math.max((Math.fround(((Math.sinh(0x100000000) | 0) !== Number.MAX_SAFE_INTEGER)) >>> 0), Math.asinh(x))) >>> 0) >>> 0)); }); testMathyFunction(mathy3, [42, -0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, -0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, 2**53-2, Number.MIN_VALUE, Math.PI, 0x100000001, 0x100000000, 0x0ffffffff, 2**53+2, 1, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000001, -0, -(2**53+2), -1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), 0/0, 0, 0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-116066984*/count=1669; tryItOut("\"use strict\"; let (z) { /*RXUB*/var r = new RegExp(\"(?:((?!\\\\3|[\\\\t-\\u00a2\\\\x36-\\u4ce4\\\\cE].+.*))+?).\", \"gm\"); var s = \"\\n\"; print(uneval(s.match(r))); var x = window.throw(this); }");
/*fuzzSeed-116066984*/count=1670; tryItOut("mathy3 = (function(x, y) { return (Math.cosh(Math.fround(Math.max(Math.hypot((0 - Math.tanh(Math.log1p(x))), (( + (y | 0)) | 0)), (( + (x <= ( + x))) | (Math.sin((mathy1(y, x) % ( + y))) | 0))))) | 0); }); testMathyFunction(mathy3, [0x0ffffffff, 2**53+2, -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, -Number.MIN_VALUE, -(2**53+2), Number.MIN_VALUE, 2**53, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), Math.PI, -(2**53), -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 1, -0x0ffffffff, -0, 2**53-2, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, 0x080000001, 0x100000001, 0, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, 1.7976931348623157e308, 1/0, -0x100000001]); ");
/*fuzzSeed-116066984*/count=1671; tryItOut("this.a1 = arguments;");
/*fuzzSeed-116066984*/count=1672; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; }");
/*fuzzSeed-116066984*/count=1673; tryItOut("\"use asm\"; neuter(b2, \"same-data\");");
/*fuzzSeed-116066984*/count=1674; tryItOut("let x = y = eval, NaN, \u3056 = \"\\u22B4\", \u3056, \u3056;print(x);");
/*fuzzSeed-116066984*/count=1675; tryItOut("mathy2 = (function(x, y) { return ( + (Math.fround((((y & Math.imul(Number.MAX_SAFE_INTEGER, Math.min(y, (y >>> 0)))) >>> 0) - Math.fround((((y + -0x080000000) >>> 0) < ( + Math.atan2(( + (y !== y)), (Math.fround(Math.atan2(Math.fround(x), Math.fround(-0x100000001))) | 0))))))) >>> mathy1(Math.fround(Math.max(Math.imul(mathy1(y, -Number.MIN_SAFE_INTEGER), ( - y)), Math.fround(mathy0(( ! x), Math.hypot(( - x), x))))), (x ? (Math.max(((( + Math.trunc(y)) ? Math.fround((Math.fround(x) | Math.fround(-0))) : y) | 0), (( + (x ? Math.fround(y) : Math.fround(Math.PI))) | 0)) | 0) : ( + Math.asinh(( + -0))))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), -0, 0/0, 0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, 42, -0x080000001, 2**53, -(2**53+2), Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -0x0ffffffff, 0, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, 2**53-2, Number.MIN_VALUE, Math.PI, 0x100000001, 1, -0x07fffffff, 0x100000000]); ");
/*fuzzSeed-116066984*/count=1676; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ! (Math.pow(((Math.sin(((((x | 0) - ((y * (x % x)) | 0)) | 0) | 0)) >>> 0) | 0), (Math.sinh(Math.round(x)) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy3, [2**53-2, -(2**53-2), 0x080000000, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 1, 0.000000000000001, 0x100000000, -(2**53), 2**53+2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, -0x080000000, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, 0x100000001, -0, -0x07fffffff, 0, -Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, -0x100000000, 0/0, Number.MIN_SAFE_INTEGER, -1/0, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1677; tryItOut("m2 = new Map;");
/*fuzzSeed-116066984*/count=1678; tryItOut("mathy5 = (function(x, y) { return Math.min(mathy3(( + (0.000000000000001 == (Math.acos((-0x100000001 | 0)) | 0))), mathy4(( - y), Math.round(Math.acosh(y)))), Math.imul(((Math.log((Math.fround(0) ? y : mathy0(Math.fround(0x080000001), -0x080000001))) ? Math.imul((y | 0), (x >> x)) : ((Math.tan((Math.min(( + Math.fround(Math.expm1(Math.fround(0x080000000)))), (Math.max(x, Number.MAX_SAFE_INTEGER) >>> 0)) | 0)) | 0) >>> 0)) | 0), Math.fround(( ~ Math.exp(Math.min(y, x)))))); }); testMathyFunction(mathy5, [0/0, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, -1/0, -0x100000001, -0x080000000, -Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, 1/0, 2**53-2, -0x100000000, 0x100000001, Number.MAX_VALUE, Math.PI, 2**53, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -0x0ffffffff, 0, 2**53+2, -0x07fffffff, 0x100000000, 0x080000001, Number.MIN_VALUE, -(2**53), 1, 42]); ");
/*fuzzSeed-116066984*/count=1679; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -3.777893186295716e+22;\n    {\n      {\n        d3 = (((-(((new -19( '' )))))) - ((d0)));\n      }\n    }\n    return +((Float32ArrayView[(((d1) >= (d1))-(0xffffffff)-((0x42ae414f))) >> 2]));\n  }\n  return f; })(this, {ff: Number.prototype.toFixed}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0, 1, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 0x100000000, -1/0, 2**53+2, 2**53, 2**53-2, 0x0ffffffff, 1/0, -0x100000000, -0, Number.MIN_VALUE, -(2**53-2), -(2**53+2), 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 0.000000000000001, -(2**53), -Number.MAX_VALUE, -0x0ffffffff, -0x080000001, Math.PI, 0/0, 0x07fffffff, -0x100000001, 0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1680; tryItOut("\"use strict\"; /*vLoop*/for (var ybffiu = 0; ybffiu < 38; ++ybffiu) { var b = ybffiu; v0 = t1.length; } ");
/*fuzzSeed-116066984*/count=1681; tryItOut("\"use strict\"; for (var v of m1) { try { o0.m2.set(h0, o0.h0); } catch(e0) { } try { /*RXUB*/var r = r1; var s = \"\\n\\n\\n\\n\\n\\ucac5\\ucac5\"; print(s.search(r));  } catch(e1) { } t2 + ''; }");
/*fuzzSeed-116066984*/count=1682; tryItOut("\"use strict\"; t2.set(a0, 16);");
/*fuzzSeed-116066984*/count=1683; tryItOut("v2 + o1;");
/*fuzzSeed-116066984*/count=1684; tryItOut("testMathyFunction(mathy1, [2**53-2, 2**53, -0x0ffffffff, -(2**53), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -0x100000000, 0x080000001, 42, 0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x100000001, 0x100000000, -1/0, -0x080000000, 0, -(2**53+2), -0x080000001, 1.7976931348623157e308, Math.PI, 0x0ffffffff, 0x080000000, -0, -Number.MAX_VALUE, 2**53+2, 0/0]); ");
/*fuzzSeed-116066984*/count=1685; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.fround(( - ( + Math.hypot((y >>> 0), (Math.fround((( + 0x080000000) / ( + (Math.fround(y) <= (-0x100000000 | 0))))) >>> 0))))) < Math.fround(mathy4(( - (mathy0(y, Math.fround(Math.imul((x >>> 0), y))) && (x < y))), ((( ~ y) | x) ? this : mathy4(((( + y) + ( + ( ! ((( + -0x080000000) + (y | 0)) | 0)))) | 0), y))))); }); testMathyFunction(mathy5, ['/0/', (function(){return 0;}), (new Boolean(false)), 0.1, true, objectEmulatingUndefined(), (new Number(0)), '\\0', null, (new Number(-0)), ({valueOf:function(){return 0;}}), (new String('')), 0, [0], -0, undefined, ({valueOf:function(){return '0';}}), [], '0', 1, false, /0/, ({toString:function(){return '0';}}), (new Boolean(true)), '', NaN]); ");
/*fuzzSeed-116066984*/count=1686; tryItOut("mathy0 = (function(x, y) { return Math.fround(( ! Math.fround((Math.hypot(((Math.ceil((( - x) | 0)) | 0) >>> 0), (Math.max((y !== y), (((((x ** x) && x) | 0) , ( + (( + y) << ( + Math.fround(Math.fround(Number.MAX_SAFE_INTEGER)))))) >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [2**53+2, Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, 2**53, 0/0, 0.000000000000001, 0x07fffffff, -0x100000001, 0x0ffffffff, Math.PI, Number.MAX_VALUE, -0x080000001, 1/0, 0x100000001, 42, -0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -0x100000000, 0x080000001, Number.MIN_VALUE, -0, -(2**53+2), -0x07fffffff, -1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), 0, -Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1687; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround((Math.max((Math.fround((Math.fround(Math.imul((y >= (y - y)), (y | 0))) & Math.fround(( + mathy2(( + Math.atan(( + mathy2(Number.MIN_SAFE_INTEGER, (mathy3((x >>> 0), (-0x080000000 >>> 0)) >>> 0))))), ( + y)))))) | 0), (( - 1) | 0)) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[Infinity, new String('q'),  /x/ ,  /x/ , Infinity,  /x/ , new String('q'), Infinity,  /x/ , Infinity, function(){},  /x/ ]); ");
/*fuzzSeed-116066984*/count=1688; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return ((( ! Math.fround(Math.min(Math.log(( + 0x07fffffff)), (((Math.fround(Math.atanh(Math.fround((x && 0x100000000)))) ? (Number.MAX_VALUE | 0) : (((0x100000000 & Number.MIN_SAFE_INTEGER) + (Math.acos((-(2**53-2) | 0)) >>> 0)) >>> 0)) | 0) | 0)))) ** ((Math.max((Math.fround(Math.atan(Math.exp(( + (( + x) - ( + y)))))) | 0), (( - (x | 0)) | 0)) | 0) ? Math.pow(( + (((x >>> 0) !== (y >>> 0)) >>> 0)), Math.fround((y ? 0x0ffffffff : (y >> y)))) : (y <= Math.atanh(0x0ffffffff)))) | 0); }); ");
/*fuzzSeed-116066984*/count=1689; tryItOut("this.o2.v0 = undefined;");
/*fuzzSeed-116066984*/count=1690; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( - ((((((((( + -Number.MAX_SAFE_INTEGER) | 0) + Math.fround(y)) % (Math.hypot(((( ~ y) | 0) | 0), ((Math.log1p(-Number.MAX_VALUE) | Math.fround(-(2**53))) | 0)) | 0)) >>> 0) < (y >>> 0)) >>> 0) | 0) > (( + mathy3(( + y), ( + (mathy1((Math.hypot((mathy2((y | 0), y) >>> 0), (y >>> 0)) >>> 0), -0x080000001) - ( ! y))))) | 0))); }); testMathyFunction(mathy5, /*MARR*/[--x, new String('q'), (1/0), --x, new String('q'), new Set()() && (e < window), new String('q'), new String('q'), new Set()() && (e < window), (1/0), --x, (1/0), new String('q'), (1/0), --x, (1/0), --x, (1/0), --x, new String('q'), new Set()() && (e < window), new Set()() && (e < window), (1/0), new String('q'), new String('q'), (1/0), (1/0), (1/0), new String('q'), new String('q'), (1/0), --x, new Set()() && (e < window), --x, (1/0)]); ");
/*fuzzSeed-116066984*/count=1691; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.min(Math.imul(Math.fround((Math.acos(Math.hypot(x, y)) ** (( ~ (Math.trunc((((( + ((x >>> 0) || ( + x))) | 0) , (x | 0)) | 0)) >>> 0)) >>> 0))), ((Math.asin(42) >>> 0) > (Math.trunc((-0x100000001 >>> 0)) >>> 0))), (Math.acos((Math.fround(( ! Math.fround(0x080000001))) >= Math.cos((x | 0)))) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=1692; tryItOut("var ygujya = new ArrayBuffer(4); var ygujya_0 = new Uint16Array(ygujya); var ygujya_1 = new Uint8Array(ygujya); ygujya_1[0] = -3; print(/\\2.\\s|((?:.{0}))|^[^\\cG-\\xFA\\\u008b-\u00ad]*/yi);o2.r1 = new RegExp(\".\", \"gy\");s1 = o2.s0.charAt(11);");
/*fuzzSeed-116066984*/count=1693; tryItOut("m1.delete(b1);");
/*fuzzSeed-116066984*/count=1694; tryItOut("\"use strict\"; tktmlm(((function too_much_recursion(xfbwep) { ; if (xfbwep > 0) { ; too_much_recursion(xfbwep - 1);  } else {  }  })(0)));/*hhh*/function tktmlm({x: [, a, ]}, x = (x.watch(\"apply\", decodeURI)), x, a, x, x, x, x, x, x, x = ({a1:1}), window, x = [[]], x, z, x, y = 22, x, x, x, window, x, e, x, a, NaN, w, eval, eval, x, y, eval, c, e, x, this.x =  /x/ , x, x, c, ...a){ /x/g ;}");
/*fuzzSeed-116066984*/count=1695; tryItOut("\"use strict\"; for (var v of t1) { (void schedulegc(g1)); }");
/*fuzzSeed-116066984*/count=1696; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.pow(Math.atan((Math.min(( + y), 0x100000001) ^ (( + (y === (Math.min((-Number.MIN_VALUE >>> 0), (0x0ffffffff >>> 0)) >>> 0))) | 0))), ((((Math.pow(mathy4(y, (y >>> 0)), (( - 2**53) >>> 0)) % Math.sin((Math.asinh((x ? (y | 0) : x)) | 0))) | 0) ? mathy2(y, ( + ( + y))) : (( ~ x) | 0)) | 0)); }); ");
/*fuzzSeed-116066984*/count=1697; tryItOut("testMathyFunction(mathy3, [0/0, -0x080000001, -Number.MIN_VALUE, -0x100000001, -0x080000000, 0x080000001, 0.000000000000001, 0, Number.MAX_VALUE, 0x07fffffff, 1, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff, -(2**53), -0x0ffffffff, -1/0, 2**53+2, 0x0ffffffff, 2**53-2, 0x100000000, 0x100000001, -0, 0x080000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, Math.PI, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, 42]); ");
/*fuzzSeed-116066984*/count=1698; tryItOut("(/*MARR*/[new Boolean(false)].map);");
/*fuzzSeed-116066984*/count=1699; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - Math.fround((Math.sin(0x080000000) >>> 0))); }); ");
/*fuzzSeed-116066984*/count=1700; tryItOut("/*ADP-1*/Object.defineProperty(a0, (this.__defineGetter__(\"NaN\", decodeURI)), ({enumerable: false}));");
/*fuzzSeed-116066984*/count=1701; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! (Math.cos(mathy1(((((x ** x) | 0) >>> (Math.fround(( - (y | 0))) | 0)) | 0), y)) >>> 0)); }); ");
/*fuzzSeed-116066984*/count=1702; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + mathy3(( + Math.min((mathy1(((Math.acosh((y | 0)) | 0) >>> 0), ((Math.atan2(( ! Math.fround(x)), (Math.fround((x ? Math.clz32(( + y)) : -0x100000001)) | 0)) | 0) >>> 0)) >>> 0), (( - (mathy1(Math.fround(( - x)), y) | 0)) | 0))), ( + (Math.min(( + Math.max(Math.hypot(y, mathy2(x, y)), y)), Math.pow(Math.asin(Math.fround(x)), x)) - (-1/0 >> ( + Math.atan2(( + Math.atan2(x, -0x080000000)), ( + mathy3(Math.fround((-0x100000000 > -1/0)), x))))))))); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 1, 0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, -0x0ffffffff, -(2**53), 0x07fffffff, -0x100000001, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0, 42, 2**53-2, -(2**53+2), -0x100000000, -Number.MAX_VALUE, 0x100000001, 0, -Number.MIN_VALUE, 0x100000000, 2**53+2, Number.MAX_VALUE, 0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, 1/0, 0x080000000, -1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-116066984*/count=1703; tryItOut("v1 = g0.runOffThreadScript();");
/*fuzzSeed-116066984*/count=1704; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max(( + ((( ! ((x == y) >>> 0)) >>> 0) <= ((mathy0(y, (x >>> 0)) >>> 0) * Math.hypot((Math.imul(Math.fround(-0x080000001), Math.fround(x)) <= x), Math.fround(Math.hypot(Math.fround(Math.expm1(( + y))), (Math.imul((x >>> 0), Math.min(x, y)) >>> 0))))))), ( + ( + Math.pow(( + (Math.fround((y + (y >>> 0))) ? ( ! (Math.atan(Math.imul(Math.pow(-0x0ffffffff, x), y)) | 0)) : Math.expm1(( ! (1/0 - Math.fround(Math.log(y))))))), Math.fround(( + ((var r0 = x ^ y; var r1 = 9 ^ x; var r2 = 1 & 9; var r3 = r0 ^ r2; var r4 = r2 - 6; var r5 = r2 * 6; x = 1 | r5; var r6 = r2 & 1; r5 = r2 | x; var r7 = r2 | y; r3 = r6 / 1; var r8 = r7 ^ r0; var r9 = 9 - r8; var r10 = 2 ^ r6; var r11 = 7 + 9; var r12 = 8 % r8; r1 = r5 + 0; var r13 = r0 ^ r0; print(r8); var r14 = r1 - 7; r14 = 3 % r0; var r15 = x ^ 3; var r16 = r1 * r9; print(r1); var r17 = r15 - r11; var r18 = 8 % r10; var r19 = x - r6; var r20 = r3 ^ r15; var r21 = r6 / r17; var r22 = 2 / 4;  >>> 0) , ( + ( + (x | 0)))))))))); }); testMathyFunction(mathy1, [0, 2**53-2, 0x080000000, 1.7976931348623157e308, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, 0x07fffffff, -0x100000001, Math.PI, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, 0x080000001, 0x100000001, 0/0, -0x0ffffffff, Number.MAX_VALUE, 0x100000000, -0x07fffffff, -(2**53), -Number.MAX_VALUE, -0x080000000, 42]); ");
/*fuzzSeed-116066984*/count=1705; tryItOut("let (eval = (eval(\"let (c) undefined\", x)), NaN, x = Math.atan2(9, ({}).throw(null)), ovrecu, eval = Math.log10(((c) = /[^]/gym)), y = ({} = (4277)), NaN) { o1.v2 = g0.runOffThreadScript(); }");
/*fuzzSeed-116066984*/count=1706; tryItOut("s1 += s0;a0 = Array.prototype.concat.call(a0, t0, g1.t0);");
/*fuzzSeed-116066984*/count=1707; tryItOut("v0 = t1.length;");
/*fuzzSeed-116066984*/count=1708; tryItOut("s0 += 'x';");
/*fuzzSeed-116066984*/count=1709; tryItOut("\"use strict\"; this.e1.add(t0);");
/*fuzzSeed-116066984*/count=1710; tryItOut("mathy2 = (function(x, y) { return ((( ~ this = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: runOffThreadScript, delete: function(name) { return delete x[name]; }, fix: function(y) { return b }, has: function(name) { return name in x; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(3), Set, encodeURI)) / (( ! Math.acos(( + ( ~ Math.fround((((Math.imul((42 >>> 0), ((0 - y) >>> 0)) >>> 0) >>> 0) >> (x >>> 0))))))) | 0)) | 0); }); ");
/*fuzzSeed-116066984*/count=1711; tryItOut("\"use strict\"; a1 = a0.concat(t0, this.__defineGetter__(\"z\", arguments.callee) ? Math.atan( \"\" ) : (\u3056%=\"\\u4E95\"), m1);");
/*fuzzSeed-116066984*/count=1712; tryItOut("mathy4 = (function(x, y) { return (Math.fround(mathy0(mathy3(y, ( + x)), Math.ceil((Math.min(((2**53 != (x >>> 0)) >>> 0), ( + Number.MIN_VALUE)) >>> 0)))) & ( - (Math.max(x, ( ~ mathy1(((x >>> 0) != (y >>> 0)), ( + -0x07fffffff)))) | 0))); }); testMathyFunction(mathy4, [0x100000001, -Number.MIN_VALUE, -0x080000000, 2**53, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 1/0, 0, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, -(2**53+2), 0/0, -(2**53), 2**53+2, 0x080000001, -(2**53-2), -1/0, 0x0ffffffff, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 1, Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, -0x07fffffff, 0x100000000, -0x080000001, 42, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1713; tryItOut("\"use strict\"; \"use asm\";  for (a of (Symbol(window,  \"\" ))) { for (let z of undefined) {print(false);for (var v of t0) { ; } } }m0.has(g2);");
/*fuzzSeed-116066984*/count=1714; tryItOut("a1.shift();");
/*fuzzSeed-116066984*/count=1715; tryItOut("a1[11] = function ([y]) { };");
/*fuzzSeed-116066984*/count=1716; tryItOut("\"use strict\"; let x = (Math.atan2(window, 22) >>> (makeFinalizeObserver('tenured'))), e = \"\\uD3FA\", x, x, window, eval, eval = (\"\\uC772\" % null), ozbiid, uummfv;(void schedulegc(o2.g1));");
/*fuzzSeed-116066984*/count=1717; tryItOut("/*vLoop*/for (var ykjevk = 0, this.__defineSetter__(\"w\", arguments.callee); ykjevk < 87; ++ykjevk) { let w = ykjevk; /*oLoop*/for (let fjkhfo = 0,  /x/g ; fjkhfo < 83; ++fjkhfo, \"\\u64B0\") { i1 = new Iterator(this.b2, true); }  } ");
/*fuzzSeed-116066984*/count=1718; tryItOut("v1 = o1.t1.length;");
/*fuzzSeed-116066984*/count=1719; tryItOut("/*bLoop*/for (zqqvlc = 0; zqqvlc < 26; ++zqqvlc) { if (zqqvlc % 4 == 1) { print((/*UUV1*/(x.setInt16 = function shapeyConstructor(svquzz){\"use strict\"; { print(-0); } if (new RegExp(\"(\\\\1{1,4}|(?=(?=\\\\b)\\\\w|\\\\d|$(?=$){1}|\\\\1{2}))\", \"ym\")) Object.seal(this);this[\"eval\"] = Array.prototype.copyWithin;this[\"wrappedJSObject\"] = new Number(1.5);this[\"__parent__\"] = objectEmulatingUndefined();return this; }))); } else { print(x); }  } ");
/*fuzzSeed-116066984*/count=1720; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.exp((((((( ! (((((((x >>> 0) <= (( + (x == -0x080000000)) >>> 0)) >>> 0) >>> 0) > (Math.fround((Math.fround(Math.atan2(x, x)) , Math.fround(-0x100000001))) >>> 0)) >>> 0) | 0)) | 0) | 0) > (( + ( - ((((Math.min((0 | 0), (x >>> 0)) | 0) === Math.fround(y)) ^ ((Math.trunc(x) | 0) >>> 0)) >>> 0))) | 0)) | 0) | 0)); }); testMathyFunction(mathy0, [2**53-2, 1, -0x080000000, -0, 0x07fffffff, 0.000000000000001, 0x080000000, -0x100000000, 2**53+2, 0/0, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, -(2**53-2), 1/0, 2**53, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -1/0, 0, -(2**53), Number.MIN_VALUE, 0x100000000, -Number.MIN_VALUE, -0x080000001, -(2**53+2), 0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-116066984*/count=1721; tryItOut("m2.has(s0);");
/*fuzzSeed-116066984*/count=1722; tryItOut("a0 = a1.concat(a1, a0);");
/*fuzzSeed-116066984*/count=1723; tryItOut("\"use strict\"; Array.prototype.splice.apply(a2, [NaN, x, o2.v1]);");
/*fuzzSeed-116066984*/count=1724; tryItOut("a0 = arguments;");
/*fuzzSeed-116066984*/count=1725; tryItOut("Array.prototype.sort.apply(a2, [intern((this.__defineSetter__(\"e\", y => window)))]);");
/*fuzzSeed-116066984*/count=1726; tryItOut("(4277);");
/*fuzzSeed-116066984*/count=1727; tryItOut("\"use strict\"; a0.pop();");
/*fuzzSeed-116066984*/count=1728; tryItOut("\"use strict\"; var x, [] = null % null.throw(allocationMarker()), nsjowo, yjiyow;print(x);v1 = evaluate(\"function f1(i0)  { \\\"use strict\\\"; return (neuter)(i0, x) } \", ({ global: g1.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 1), noScriptRval: false, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-116066984*/count=1729; tryItOut("if((x % 48 != 26)) e1.has(f2); else  if ((yield Math.hypot((/*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()].filter), 15))) v2 = Object.prototype.isPrototypeOf.call(e1, t1); else {; }");
/*fuzzSeed-116066984*/count=1730; tryItOut("/*infloop*/ for  each(let a in  '' ) Array.prototype.reverse.call(this.a0, h0);function x(window) { \"use strict\"; p2.toString = (function() { try { Array.prototype.pop.call(a1, t0); } catch(e0) { } m0.set(e1, t0); throw h1; }); } /*oLoop*/for (jluwdv = 0; jluwdv < 43 && (false); x || y, ++jluwdv) { print(x); } ");
/*fuzzSeed-116066984*/count=1731; tryItOut("/*RXUB*/var r = (yield function(){}); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-116066984*/count=1732; tryItOut("new RegExp(\".+?\", \"g\");");
/*fuzzSeed-116066984*/count=1733; tryItOut("while(( /x/g ) && 0)( /x/g );");
/*fuzzSeed-116066984*/count=1734; tryItOut("\"use strict\"; s1.__iterator__ = (function(j) { if (j) { try { f2 = Proxy.createFunction(o1.h1, f0, f0); } catch(e0) { } try { p1.valueOf = (function(j) { if (j) { try { h2.fix = String.prototype.link; } catch(e0) { } v2 = t1.length; } else { try { Array.prototype.splice.call(o0.a2); } catch(e0) { } try { e0.has(g0); } catch(e1) { } v2 = (this.h0 instanceof f0); } }); } catch(e1) { } h0.iterate = (function() { for (var j=0;j<92;++j) { f2(j%4==1); } }); } else { try { s0 += s2; } catch(e0) { } for (var p in p1) { try { /*ADP-1*/Object.defineProperty(a1, (NaN & [z1]), ({configurable: (x % 97 == 67), enumerable: (4277)})); } catch(e0) { } try { Array.prototype.sort.call(a1, (function(j) { if (j) { try { /*MXX3*/g1.WeakSet.prototype.has = g1.WeakSet.prototype.has; } catch(e0) { } /*ODP-1*/Object.defineProperty(v0, \"toString\", ({configurable: (x % 6 != 0), enumerable: x})); } else { try { b2.toSource = (function(j) { if (j) { e2.add(b0); } else { try { e1.has(b1); } catch(e0) { } try { e0.add(b0); } catch(e1) { } try { g1 = o1.t1[10]; } catch(e2) { } this.g2.g1.s2 += 'x'; } }); } catch(e0) { } try { v2 = false; } catch(e1) { } try { o0.s0 = o1.a2.join(o0.s0, o2, this.m0, o0.f0); } catch(e2) { } g1.h2 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.forEach.apply(a2, [(function() { try { v0 = g0.eval(\"function f2(g0.e0) \\\"use asm\\\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    i2 = ((((i2)+(1))>>>((((((((33554431.0)) / ((-0.0009765625))))-(x)-(i2))>>>((Uint16ArrayView[((0x19881b96) % (0xf0e77969)) >> 1])))))) == (((0x9bfa05f2))>>>(((i1) ? (i1) : (i1))+((((0x46559555)-(0xa796b86c)+(0xff85b6df))>>>((i1)+(i2)))))));\\n    i1 = (i1);\\n    {\\ng0.i2.next();    }\\n    return +((1.0));\\n  }\\n  return f;\"); } catch(e0) { } a1.pop(s2, i0, this.i2, t2); return g2.t2; })]);; var desc = Object.getOwnPropertyDescriptor(o1.o0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { b0.toSource = (function(j) { f1(j); });; var desc = Object.getPropertyDescriptor(o1.o0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { h1 = ({getOwnPropertyDescriptor: function(name) { a1[10] = v1;; var desc = Object.getOwnPropertyDescriptor(this.t0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { this.g1.b2.toString = (function() { try { v1 = Object.prototype.isPrototypeOf.call(g2, m0); } catch(e0) { } try { f1 = Proxy.createFunction(h0, f0, f2); } catch(e1) { } try { Object.prototype.watch.call(t0, \"apply\", (function mcc_() { var cbtfxa = 0; return function() { ++cbtfxa; f2(/*ICCD*/cbtfxa % 5 == 2);};})()); } catch(e2) { } print(m0); throw p1; });; var desc = Object.getPropertyDescriptor(this.t0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a1.forEach((function() { for (var j=0;j<9;++j) { f1(j%2==0); } }));; Object.defineProperty(this.t0, name, desc); }, getOwnPropertyNames: function() { a1 = arguments;; return Object.getOwnPropertyNames(this.t0); }, delete: function(name) { o1 = i0.__proto__;; return delete this.t0[name]; }, fix: function() { return o2.i0; if (Object.isFrozen(this.t0)) { return Object.getOwnProperties(this.t0); } }, has: function(name) { a0.sort((function() { try { v0 = evalcx(\"function f1(g2.g1) \\\"use asm\\\";   var Uint32ArrayView = new stdlib.Uint32Array(heap);\\n  var Int8ArrayView = new stdlib.Int8Array(heap);\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var d2 = -33.0;\\n    (Uint32ArrayView[4096]) = ((0xffffffff)*-0xceb73);\\n    i1 = (0xe1b95764);\\n    i0 = (i0);\\n    d2 = (d2);\\n    {\\n      (Int8ArrayView[((0xdf17525f) % (0xe00a175f)) >> 0]) = ((/*FARR*/[! /x/g , .../*MARR*/[[undefined], new Number(1.5), [undefined], [undefined], [undefined], new Number(1.5), new Number(1.5), [undefined], new Number(1.5), [undefined], new Number(1.5), [undefined], [undefined], new Number(1.5), new Number(1.5), [undefined], new Number(1.5), [undefined], new Number(1.5), new Number(1.5), [undefined], new Number(1.5), [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], new Number(1.5), [undefined], [undefined], new Number(1.5), new Number(1.5), new Number(1.5), [undefined], new Number(1.5), [undefined], [undefined], new Number(1.5), new Number(1.5), [undefined], [undefined], [undefined], new Number(1.5), [undefined], new Number(1.5), [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], new Number(1.5), new Number(1.5), new Number(1.5), [undefined], new Number(1.5), [undefined], new Number(1.5), [undefined], new Number(1.5), new Number(1.5), new Number(1.5), [undefined], [undefined], [undefined], new Number(1.5), [undefined], new Number(1.5), [undefined], [undefined], new Number(1.5), new Number(1.5), [undefined], [undefined]], .../*MARR*/[NaN,  /x/g ,  /x/g ,  /x/g ,  /x/g , NaN, NaN, NaN, NaN, NaN, NaN,  /x/g , NaN, NaN,  /x/g , NaN, NaN,  /x/g ,  /x/g ,  /x/g , NaN,  /x/g , NaN, NaN, NaN,  /x/g ,  /x/g , NaN, NaN,  /x/g , NaN, NaN]].some((({/*TOODEEP*/})), (e = Proxy.createFunction(({/*TOODEEP*/})(window), Date.prototype.setUTCDate, neuter))))+(0xeef6a457));\\n    }\\nL:with((void options('strict'))){v2 = Infinity;for (var p in o2.f2) { e1.delete(v1); } }    return (((((((i1))|0)) ? ((((0xcfd4661c))>>>((0xfdd89a9c)+(0xf8209a1e)+(0xda01bee5)))) : ((((0xc0cf6fdb)+(0x2f73bcd2)-(0x8cff021d))|0) >= ((\\nb) >> (((0x8b7bd54) != (0x470cfa1a))))))+((~(((0x2fd68321) ? (1) : (0xf061e1cb)))) == (((Int32ArrayView[((i1)+(!(0xfcd8c8ed))) >> 2])) ^ ((((0xffffffff)) | ((0x3a212e70))) / (((0xf861488b)) | ((0xff0359c3))))))-((0x4fc9c347) < ((((((0x7900ccf2))>>>((0xf9131fff))) <= (((-0x8000000))>>>((-0x8000000))))) << ((i1)-(i0))))))|0;\\n  }\\n  return f;\", g1); } catch(e0) { } try { Object.defineProperty(this, \"v1\", { configurable: true, enumerable: -1,  get: function() { this.a1[10] = f2; return new Number(-Infinity); } }); } catch(e1) { } v2 = (e0 instanceof i0); return v0; }), p0);; return name in this.t0; }, hasOwn: function(name) { a0.reverse(g1);; return Object.prototype.hasOwnProperty.call(this.t0, name); }, get: function(receiver, name) { o1.v2 = g0.eval(\"/* no regression tests found */\");; return this.t0[name]; }, set: function(receiver, name, val) { for (var v of a1) { try { Array.prototype.shift.call(a0, b2); } catch(e0) { } g1.g0.o1.a2 + o1.h0; }; this.t0[name] = val; return true; }, iterate: function() { o2 = p1.__proto__;; return (function() { for (var name in this.t0) { yield name; } })(); }, enumerate: function() { throw v0; var result = []; for (var name in this.t0) { result.push(name); }; return result; }, keys: function() { return o1.e0; return Object.keys(this.t0); } });; Object.defineProperty(o1.o0, name, desc); }, getOwnPropertyNames: function() { for (var v of this.p0) { try { p2 = Proxy.create(h1, e2); } catch(e0) { } v1 = (h1 instanceof i0); }; return Object.getOwnPropertyNames(o1.o0); }, delete: function(name) { a2.pop(h0);; return delete o1.o0[name]; }, fix: function() { Array.prototype.reverse.apply(g1.a2, [o1.a1]);; if (Object.isFrozen(o1.o0)) { return Object.getOwnProperties(o1.o0); } }, has: function(name) { v0 = e1[\"toTimeString\"];; return name in o1.o0; }, hasOwn: function(name) { return o2; return Object.prototype.hasOwnProperty.call(o1.o0, name); }, get: function(receiver, name) { v1 = r1.compile;; return o1.o0[name]; }, set: function(receiver, name, val) { for (var v of g0) { try { t0.set(g2.t0, 18); } catch(e0) { } try { b2 = new ArrayBuffer(0); } catch(e1) { } try { a1.splice(NaN, 10); } catch(e2) { } /*RXUB*/var r = r1; var s = s0; print(r.test(s)); print(r.lastIndex);  }; o1.o0[name] = val; return true; }, iterate: function() { e0.add(h0);; return (function() { for (var name in o1.o0) { yield name; } })(); }, enumerate: function() { e1.__proto__ = e2;; var result = []; for (var name in o1.o0) { result.push(name); }; return result; }, keys: function() { a2[\"\\uB2FB\"] = x;; return Object.keys(o1.o0); } }); } }), o0); } catch(e1) { } try { for (var p in m1) { try { Array.prototype.reverse.call(this.a2, (makeFinalizeObserver('nursery')), s2, h2, p2, (4277)); } catch(e0) { } try { g2.s1 = new String(g2.s2); } catch(e1) { } try { v0 = (s1 instanceof g2.b0); } catch(e2) { } for (var v of o0.o2.f2) { a1.push(this.p2); } } } catch(e2) { } /*ADP-3*/Object.defineProperty(a0, 6, { configurable: let ([], x = d = d) (objectEmulatingUndefined())((4277)), enumerable: (4277), writable: false, value: p0 }); } } });");
/*fuzzSeed-116066984*/count=1735; tryItOut("/*RXUB*/var r = window; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-116066984*/count=1736; tryItOut("mathy3 = (function(x, y) { return Math.min(( - (((( + Math.sin(x)) && Math.imul((( ~ y) | 0), 0x07fffffff)) | 0) >>> 0)), mathy2((mathy2((((Math.fround(Math.atan2(Math.fround(y), Math.fround(y))) >>> 0) <= ( + (mathy0((y >>> 0), (( + mathy1(Math.fround(x), Math.fround(-0x100000000))) >>> 0)) >>> 0))) >>> 0), (Math.max(( + ((x >= ( + Math.max(( + -(2**53-2)), ( + 0.000000000000001)))) >>> 0)), (((y >>> 0) || ((((x | 0) >= x) >>> 0) >>> 0)) >>> 0)) | 0)) | 0), (Math.acos(mathy0((-(2**53) | 0), (Math.imul((-Number.MAX_VALUE >>> y), x) | 0))) != ( + ((( ! x) | 0) >= y))))); }); testMathyFunction(mathy3, [0/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, 0.000000000000001, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, -0x100000001, -(2**53-2), 2**53-2, 1.7976931348623157e308, 0x07fffffff, 1/0, -(2**53), -Number.MAX_SAFE_INTEGER, 1, 0x080000000, -0x080000001, 0, 2**53+2, 0x100000000, -0x080000000, 2**53, -0, Number.MIN_SAFE_INTEGER, 0x080000001, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-116066984*/count=1737; tryItOut("with({}) {}");
/*fuzzSeed-116066984*/count=1738; tryItOut("\"use strict\"; /*oLoop*/for (myjqqy = 0, c = window; myjqqy < 32; ++myjqqy) { for (var p in f0) { try { v1 = r1.flags; } catch(e0) { } try { this.a1[v0] = \"\\u91AD\"; } catch(e1) { } try { v2 = g0.eval(\"/* no regression tests found */\"); } catch(e2) { } this.h0.getOwnPropertyNames = Date.prototype.getUTCFullYear; } } ");
/*fuzzSeed-116066984*/count=1739; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?=.))|\\\\b|\\u71b3+|(\\\\b)(?!^)(\\\\r)|\\\\s|[^]|[\\\\0-\\\\\\ud528\\u37b8\\\\W\\\\f-\\u000e]*?*+?|\\\\W.{3,}|([^])[\\\\cE-\\\\u003E\\\\xD9]{65,}+?(?:[^][^]|\\\\b)^|\\\\2{3,7}^|($)*?|[^]+|\\ua0d2?|\\\\W\", \"gym\"); var s = \"\"; print(s.replace(r, /*UUV1*/(window.reject = function(y) { yield y; s0 += s0;; yield y; }))); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=1740; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log(Math.fround((Math.imul(( + Math.atan(( + (Math.max(x, -0x080000001) , (( + y) >>> 0))))), ((Math.max(y, Math.exp(Math.fround(( ! Math.fround(y))))) === y) >>> 0)) ? (((Math.tanh(-1/0) >>> 0) >>> Math.atan2(Math.acosh(y), ( + ( - 0x080000001)))) | 0) : ( - Math.pow((x >>> 0), (y !== x)))))); }); testMathyFunction(mathy3, [-1/0, 0.000000000000001, 0x080000000, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), 0, 0x080000001, 2**53+2, -0x100000001, 1.7976931348623157e308, Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, 2**53-2, 1, 0x0ffffffff, 0x100000001, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, Math.PI, 0/0, -0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), 42, -0x080000001, 0x100000000, 2**53, 1/0]); ");
/*fuzzSeed-116066984*/count=1741; tryItOut("v0 = t0.length;");
/*fuzzSeed-116066984*/count=1742; tryItOut("for (var p in o2) { try { v1 = Infinity; } catch(e0) { } m1.set(g1.b2, g2.m2); }");
/*fuzzSeed-116066984*/count=1743; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x07fffffff, 1, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, -(2**53), 2**53, -(2**53-2), 0, -Number.MAX_VALUE, 42, -0x0ffffffff, 1.7976931348623157e308, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53+2, 1/0, Math.PI, 0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, 0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, -(2**53+2), 0/0, -0x100000000, 0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-116066984*/count=1744; tryItOut("mathy4 = (function(x, y) { return Math.fround(( - Math.fround((Math.sin((Math.max(x, y) >>> 0)) && (( + mathy2(( + mathy0(Math.tan(y), y)), ( + mathy1(Math.fround(Math.fround((Math.fround(Math.acos(Math.fround(x))) / y))), (Math.acosh(Math.imul(y, mathy0((-0x080000000 >>> 0), Math.fround(y)))) | 0))))) >>> 0))))); }); ");
/*fuzzSeed-116066984*/count=1745; tryItOut("{Array.prototype.splice.call(o2.a2, NaN, 18, m0, i0);/*iii*/((null.toString(this,  /x/ )));/*hhh*/function eyazip(window, ...x){h0.getOwnPropertyDescriptor = f1;} }");
/*fuzzSeed-116066984*/count=1746; tryItOut("selectforgc(o2);");
/*fuzzSeed-116066984*/count=1747; tryItOut("v1 = g2.eval(\"function g2.o2.f0(p1)  { return Math.hypot((true << Math === (void options('strict_mode'))), -17) } \");");
/*fuzzSeed-116066984*/count=1748; tryItOut("mathy5 = (function(x, y) { return ( + ( + ( ~ (( ~ (y | 0)) | 0)))); }); ");
/*fuzzSeed-116066984*/count=1749; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.atanh(( + ((((( + Math.round(( + y))) / (Math.atan2(y, (x >>> 0)) >>> 0)) | 0) / (( + (Math.imul(x, ((x !== ( ~ ( + ( ! ( + x))))) >>> 0)) >>> 0)) | 0)) | 0))) >>> 0); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 1, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -0x080000001, 0x100000001, 0x07fffffff, 1.7976931348623157e308, -(2**53), -(2**53-2), 0x080000001, -0x07fffffff, 2**53-2, -0, 2**53+2, 42, Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -0x100000000, 1/0, -0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000]); ");
/*fuzzSeed-116066984*/count=1750; tryItOut("testMathyFunction(mathy4, [Math.PI, 0x080000001, -0x100000001, 0/0, -0x080000000, 0.000000000000001, -0x07fffffff, 42, 0x100000001, -(2**53+2), 0x0ffffffff, 0, 2**53+2, -(2**53-2), 1.7976931348623157e308, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, -0, -Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, 0x080000000, 1, Number.MIN_VALUE, 2**53-2, 2**53, -0x100000000, -1/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116066984*/count=1751; tryItOut("(x);");
/*fuzzSeed-116066984*/count=1752; tryItOut("testMathyFunction(mathy2, [0x100000000, 0x0ffffffff, 1, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 0x080000000, 0, -(2**53+2), 0x07fffffff, Number.MAX_VALUE, -0, Number.MIN_VALUE, 2**53-2, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, -Number.MIN_VALUE, -0x0ffffffff, -1/0, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, Math.PI, 0x080000001, 2**53, -0x07fffffff, -0x100000001, -0x080000001, -(2**53), 42]); ");
/*fuzzSeed-116066984*/count=1753; tryItOut("\"use asm\"; e2.has(g0);");
/*fuzzSeed-116066984*/count=1754; tryItOut("/*RXUB*/var r = /(?:\\B|[\\u0039\\cE-\\xE5\ue78d-\ufc36](?!(?!(?:\\1))))/im; var s = ((makeFinalizeObserver('tenured'))); print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-116066984*/count=1755; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ (( - Math.max(( - ((((Number.MIN_VALUE | 0) ^ (y | 0)) | 0) > Math.fround(( + (-0x100000000 ? (Number.MIN_SAFE_INTEGER >= x) : Math.fround(y)))))), (Math.imul((x | 0), (x | 0)) | 0))) | 0)) | 0); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, -(2**53-2), -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, 42, -(2**53+2), 0x0ffffffff, 0/0, -Number.MIN_VALUE, -(2**53), 2**53-2, -1/0, -0x100000000, -Number.MAX_VALUE, -0x0ffffffff, 0, 0.000000000000001, -0x100000001, 2**53+2, -0x07fffffff, 0x07fffffff, Number.MIN_VALUE, -0, 1/0, 1.7976931348623157e308, -0x080000000, 1]); ");
/*fuzzSeed-116066984*/count=1756; tryItOut("\"use strict\"; o2 = t0[({valueOf: function() { h2.delete = f0;return 13; }})];");
/*fuzzSeed-116066984*/count=1757; tryItOut("Object.defineProperty(this, \"s2\", { configurable: true, enumerable: false,  get: function() {  return new String; } });");
/*fuzzSeed-116066984*/count=1758; tryItOut("var window = (new (/*wrap2*/(function(){ var hcpcpf = (\"\\u691A\".__defineSetter__(\"x\", /*wrap1*/(function(){ o0.i1 = Proxy.create(h2, m2);return function(y) { print(y); }})())); var kucpwc = Math.cbrt; return kucpwc;})())( /x/ ).__defineSetter__(\"NaN\", function(y) { \"use strict\"; yield y; ({} = /\\1{2}|\\3/g);; yield y; })), e, d, x = ((x = (4277))), y = this.__defineSetter__(\"a\", encodeURI)/*\n*/, x = (4277), d = new OSRExit(this.__defineGetter__(\"e\", function  window (b)null).watch(1, eval), (x = Proxy.create(({/*TOODEEP*/})( /x/ ),  /x/g ))), ztdsyv, x = (4277);e0 + v2;");
/*fuzzSeed-116066984*/count=1759; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xc7f83f5a);\n    {\n      d0 = (NaN);\n    }\n    return +((Infinity));\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0, 0x0ffffffff, -0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, -(2**53), 1/0, 0x100000000, -0x100000001, 0x100000001, -1/0, 0x080000000, -Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, -0x080000001, -(2**53+2), -(2**53-2), Math.PI, 0, 42, 0/0, 1]); ");
/*fuzzSeed-116066984*/count=1760; tryItOut("v0 = t0;\n(null);\n");
/*fuzzSeed-116066984*/count=1761; tryItOut("\"use strict\"; ");
/*fuzzSeed-116066984*/count=1762; tryItOut("m1 + h0;");
/*fuzzSeed-116066984*/count=1763; tryItOut("/*RXUB*/var r = /(?:(.)+|^){524287,524288}\\2/m; var s = \"\\n\\n\\n\\n\\n\\u9e52\\n\\n\"; print(s.split(r)); print(r.lastIndex); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
