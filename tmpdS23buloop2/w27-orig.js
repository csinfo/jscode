

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
/*fuzzSeed-45472219*/count=1; tryItOut("print(uneval(p1));");
/*fuzzSeed-45472219*/count=2; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=3; tryItOut("/*RXUB*/var r = /\\3{2}/yi; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=4; tryItOut("mathy5 = (function(x, y) { return (Math.fround(Math.imul(Math.fround(( - Math.fround(mathy1(Math.fround((Math.max((x >>> 0), (y >>> 0)) >>> 0)), Math.fround(Math.expm1(0x0ffffffff)))))), (( ~ (Math.fround(y) >>> 0)) >>> 0))) <= ((Math.atan2((( + mathy0(( + Math.sin(x)), ( + ((x && x) / y)))) | 0), (((( + Math.pow((mathy4(-Number.MAX_VALUE, y) | 0), (Math.cos(x) | 0))) | 0) + (( - x) | 0)) | 0)) >>> 0) ? ((((Math.pow((Math.acos((((Math.fround(0x080000000) ** (x >>> 0)) >>> 0) | 0)) | 0), (-0x080000000 | 0)) | 0) >= Math.imul((((y >>> 0) == (0x100000000 >>> 0)) >>> 0), (( ! (Math.fround(Math.tanh(Math.fround(y))) | 0)) | 0))) | 0) | 0) : Math.atan2((Math.pow((x == -0x080000001), y) | x), (Math.log((( + (y >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[true, true, function(){}, function(){}, function(){}, true, true, true, function(){}, true, function(){}, true, function(){}, true, function(){}, function(){}, true, function(){}, function(){}, true, function(){}, function(){}, function(){}, true, true, true, true, true, true, true, true, true, true, true, true, true, function(){}, true, function(){}, true, function(){}, true, function(){}, function(){}, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, function(){}, function(){}, true, function(){}, function(){}]); ");
/*fuzzSeed-45472219*/count=5; tryItOut("print(x);");
/*fuzzSeed-45472219*/count=6; tryItOut("/*bLoop*/for (imiwoc = 0; imiwoc < 138; ++imiwoc) { if (imiwoc % 18 == 9) { v1 = a2.reduce, reduceRight(Error.prototype.toString); } else { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = fillShellSandbox(newGlobal({ cloneSingletons: true, disableLazyParsing: (x % 7 == 1) })); f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  }  } ");
/*fuzzSeed-45472219*/count=7; tryItOut("");
/*fuzzSeed-45472219*/count=8; tryItOut("");
/*fuzzSeed-45472219*/count=9; tryItOut("print(x);\nprint(x);\n");
/*fuzzSeed-45472219*/count=10; tryItOut("\"use strict\"; this.b2.toString = f1;");
/*fuzzSeed-45472219*/count=11; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy0(Math.asinh((mathy0(Math.fround((Math.pow(y, -0) & x)), x) << 0.000000000000001)), ((Math.fround(mathy0((( + mathy1(y, Math.hypot(( + Math.cos((y >>> 0))), ( + y)))) < mathy0(y, x)), y)) >>> 0) << Math.sign(Math.cosh(( + -0x100000000))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, -Number.MIN_VALUE, 0, 1.7976931348623157e308, 2**53, -(2**53-2), 0x080000000, Math.PI, 0x100000000, -Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, 0x07fffffff, 0x100000001, -0, Number.MIN_VALUE, -(2**53+2), -0x080000001, -(2**53), 42, 2**53+2, 1, Number.MAX_VALUE, 0/0, 0.000000000000001, 2**53-2, -0x0ffffffff, 0x0ffffffff]); ");
/*fuzzSeed-45472219*/count=12; tryItOut("mathy0 = (function(x, y) { return ((Math.min(((Math.hypot((Math.fround(Math.hypot(( + Math.atan2((-Number.MIN_SAFE_INTEGER !== Math.fround((-0x100000000 == y))), (y < y))), Math.fround((( + y) >>> ( + (y !== x)))))) | 0), -0x080000000) | 0) >>> 0), (Math.atan2(x, (Math.fround(Math.trunc(y)) ** x)) >>> 0)) >>> 0) == Math.cosh((Math.max(Math.min((y * y), y), Math.fround((((( ! ( + 0x0ffffffff)) | 0) > (x | 0)) | 0))) | 0))); }); testMathyFunction(mathy0, ['', objectEmulatingUndefined(), 0.1, undefined, [], 0, -0, (function(){return 0;}), (new Number(0)), (new Boolean(true)), 1, (new Boolean(false)), '/0/', NaN, (new Number(-0)), ({valueOf:function(){return 0;}}), '\\0', (new String('')), /0/, '0', null, [0], false, ({toString:function(){return '0';}}), true, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-45472219*/count=13; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! (( + mathy2(( + ( + ((x & Math.cosh(-Number.MAX_SAFE_INTEGER)) % Math.asinh((Math.hypot(( + y), ( + x)) >>> 0))))), Math.fround((((((( - (Math.hypot(x, 0.000000000000001) | 0)) | 0) >>> 0) ? ( - ((1/0 | 0) << x)) : x) >>> 0) ? (mathy1(( + 0x0ffffffff), ((Math.log2((( ! ( + x)) | 0)) | 0) >>> 0)) >>> 0) : Math.asinh(( + -Number.MAX_SAFE_INTEGER)))))) | 0)); }); testMathyFunction(mathy3, /*MARR*/[x]); ");
/*fuzzSeed-45472219*/count=14; tryItOut("o1.i2 + '';");
/*fuzzSeed-45472219*/count=15; tryItOut("M:if(false) Object.defineProperty(g2.o0, \"v0\", { configurable: false, enumerable: a,  get: function() {  return t1.BYTES_PER_ELEMENT; } });");
/*fuzzSeed-45472219*/count=16; tryItOut("\"use strict\"; let z = \"\\u357A\";/*infloop*/ for (var \u3056 of -29) v0 = Object.prototype.isPrototypeOf.call(b2, b1);");
/*fuzzSeed-45472219*/count=17; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(e2, o1);");
/*fuzzSeed-45472219*/count=18; tryItOut("b2 + '';");
/*fuzzSeed-45472219*/count=19; tryItOut("print(x);");
/*fuzzSeed-45472219*/count=20; tryItOut("mathy4 = (function(x, y) { return Math.hypot((mathy1((Math.fround(Math.hypot(Math.fround(x), Math.fround(Math.log2(2**53-2)))) | 0), Math.fround(( + Math.sinh(( + Math.fround(Math.cbrt(( + x)))))))) | 0), mathy3(mathy2(((((2**53 | 0) + (-0 | 0)) | 0) || Math.max(( + (y % ( + -0x100000001))), Math.expm1(Number.MIN_SAFE_INTEGER))), mathy1(Math.fround((( + Math.asinh(( + y))) ? x : x)), x)), Math.imul(y, x))); }); testMathyFunction(mathy4, [-1/0, 0.000000000000001, -0x07fffffff, -0x100000000, 0x100000000, 2**53+2, 0x080000000, 0x07fffffff, -(2**53), Math.PI, -0x080000001, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 0, 0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, -0, 42, -Number.MAX_VALUE, -0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1, Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0]); ");
/*fuzzSeed-45472219*/count=21; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var exp = stdlib.Math.exp;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -4398046511105.0;\n    var d3 = 3.777893186295716e+22;\n    var i4 = 0;\n    var i5 = 0;\n    var d6 = 18446744073709552000.0;\n    var d7 = -8589934593.0;\n    {\n      (Uint16ArrayView[0]) = ((0x59460f1f)-(0x95c62976));\n    }\n    i1 = (i1);\n    d7 = (d6);\n    d3 = (+(-1.0/0.0));\n    {\n      {\n        {\n          {\n            d3 = (8589934593.0);\n          }\n        }\n      }\n    }\n    d0 = (+(0.0/0.0));\n    d0 = (+abs(((-15.0))));\n    {\n      return ((((((((0xffffffff))+(0xfa76e4dc)) >> ((0xe5e43933)+(!(0xdbc1abda)))) != (([] = {}))) ? (0xfb106fac) : (0xfbd6bd9d))-((4277))))|0;\n    }\n    d3 = (-18446744073709552000.0);\n    d0 = (d7);\n    return (((((((-2305843009213694000.0) < (+(-1.0/0.0))))>>>(((((/*FFI*/ff(((-2251799813685248.0)), ((-4097.0)), ((16385.0)), ((1.03125)), ((-8193.0)), ((1.5)), ((-2047.0)), ((-1048576.0)))|0))>>>((-0x8000000)*-0x71e)) < (0x40abc7f8))+(((x)) < (((0xffffffff)+(-0x8000000))>>>((0x9a77954a)+(0x25549175)-(0xffffffff)))))))+(i5)))|0;\n    d3 = (d7);\n    switch ((((0xca43df10) / (0x0)) & ((0x7ebf5f4b) % (0x2b1b0232)))) {\n      case -2:\n        i5 = ((((Int8ArrayView[1]))>>>(-0xfffff*(i1))) == ((-(i5))>>>((i5))));\n        break;\n      default:\n        (Uint32ArrayView[4096]) = ((i5)+(0xffffffff));\n    }\n    i5 = ((0xfab60c1a) ? (i1) : (i4));\n    (Int32ArrayView[((0xccb78df2) / (0xa0ba10d8)) >> 2]) = (((+exp(((+(-1.0/0.0))))) < (d0))-((((((true << intern(b).unwatch(\"entries\")) >> ((0x29da863c) / (0x30d3e3e0))) > (((this.__defineGetter__(\"z\", ((runOffThreadScript).call(\"\\uB067\", ))))) ^ ((0xf8292a31)+(0xffffffff))))+(/*FFI*/ff()|0)) >> ((!((((0xdcc67ddb)-(0x529ef766)-(0xf8130859)) & ((0xff4ca0b8)-(0xc89f26fc)-(0xe1ca2bec)))))-((0x3e149a7f) >= (0xffffffff))))));\n    d7 = (8388608.0);\n    return (((0xfe5e2f54)))|0;\n  }\n  return f; })(this, {ff: eval(\"/* no regression tests found */\",  /x/g )}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-45472219*/count=22; tryItOut("\"use strict\"; for(c = void true in \"\\u2F27\") \nlet (volplf, a = (a = y instanceof \u3056)) { s1 = a2.join(s2); }");
/*fuzzSeed-45472219*/count=23; tryItOut("mathy4 = (function(x, y) { return (( + Math.pow(mathy3(((Math.expm1(( + (y >>> 0))) << 0x100000000) >>> 0), x), (mathy2((y >>> 0), (( + Math.imul(Math.min(y, Math.max((-Number.MAX_VALUE >>> 0), (Number.MIN_SAFE_INTEGER >>> 0))), ( + ( + ( - ((( + 0/0) & y) >>> 0)))))) >>> 0)) >>> 0))) >> ((( + (mathy1(Math.atan2(x, x), Math.imul(Math.imul((( + ( - ( + x))) >>> 0), Math.imul(Math.fround(x), ( + x))), x)) | 0)) | 0) | 0)); }); ");
/*fuzzSeed-45472219*/count=24; tryItOut("v2 = evalcx(\"/*RXUB*/var r = new RegExp(\\\"\\\\\\\\B|((?!\\\\\\\\B)\\\\\\\\b)*|(\\\\\\\\2{1,}).|\\\\\\\\cS\\\", \\\"gim\\\"); var s = \\\"\\\"; print(s.replace(r, false)); \", g1);");
/*fuzzSeed-45472219*/count=25; tryItOut("\"use strict\"; g2 = g2.g1.objectEmulatingUndefined();");
/*fuzzSeed-45472219*/count=26; tryItOut("a0 = Proxy.create(h0, m0);");
/*fuzzSeed-45472219*/count=27; tryItOut("mathy2 = (function(x, y) { return Math.atan2(Math.fround((Math.fround(Math.fround(Math.acos(Math.fround(Math.log1p((y ? Number.MIN_SAFE_INTEGER : (x >>> 0))))))) || Math.fround(Math.atanh(( + Math.fround((((Math.pow((( - x) | 0), (x | 0)) | 0) >>> 0) * (( ! y) >>> 0)))))))), Math.atan2(( ! x), ((((((((y | 0) ? ((( ! (y >>> 0)) >>> 0) | 0) : (Math.atan2(-1/0, x) | 0)) | 0) >>> 0) || (y >>> 0)) >>> 0) === Math.fround(2**53-2)) | 0))); }); testMathyFunction(mathy2, [-(2**53-2), 0x100000001, -Number.MAX_VALUE, 2**53-2, -0x080000000, 0x0ffffffff, 2**53+2, 1/0, -0x0ffffffff, -(2**53), 0/0, Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, 2**53, 1, 0x080000001, 42, -Number.MIN_VALUE, -0x100000001, -0x100000000, 0.000000000000001, -1/0, -0x080000001, Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -0, 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2)]); ");
/*fuzzSeed-45472219*/count=28; tryItOut(";");
/*fuzzSeed-45472219*/count=29; tryItOut(";");
/*fuzzSeed-45472219*/count=30; tryItOut("v2 = a0.length;");
/*fuzzSeed-45472219*/count=31; tryItOut("/*vLoop*/for (var yjvmur = 0; yjvmur < 143; ++yjvmur) { const e = yjvmur; f0 + ''; } ");
/*fuzzSeed-45472219*/count=32; tryItOut("(this.__defineSetter__(\"z\", /*bLoop*/for (var fssjgh = 0; fssjgh < 6; ++fssjgh) { if (fssjgh % 3 == 1) { var ofigwl, [(p={}, (p.z =  \"\" )())] = x, x = (y = ((function sum_indexing(dhecna, acgceg) { ; return dhecna.length == acgceg ? 0 : dhecna[acgceg] + sum_indexing(dhecna, acgceg + 1); })(/*MARR*/[undefined, arguments.callee, undefined, undefined, arguments.callee, arguments.callee, undefined, arguments.callee, undefined, undefined, function(){}, undefined, function(){}, arguments.callee, arguments.callee, this, undefined, this, this, this], 0))), {} = window ** undefined, b = x >> w, x, owpkmx, c, dnmqel, x;t1[18] = x; } else { o1 = this.o1;/*ODP-1*/Object.defineProperty(e2, \"getTimezoneOffset\", ({get: mathy1, set: (String.prototype.codePointAt).apply})); }  } ));");
/*fuzzSeed-45472219*/count=33; tryItOut("{ void 0; void gc(this); }");
/*fuzzSeed-45472219*/count=34; tryItOut("print(x);");
/*fuzzSeed-45472219*/count=35; tryItOut("t0.set(t1, 0);");
/*fuzzSeed-45472219*/count=36; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -4097.0;\n    return ((((0xd7e091d2))+(0xfcb47c37)))|0;\n    return ((((-0x8000000) ? (0xffffffff) : (i0))-(0xfa300813)))|0;\n    d2 = (d1);\n    return ((((0xcad1f91d) > ((((0xa001eb9e) ? (0xa53d0340) : (0x9c10e388))+(0x67955099)+(-0x8000000))>>>((i0))))-(0xde539c2d)))|0;\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1/0, 0/0, 42, -(2**53+2), -0x080000000, 0x080000001, -0x0ffffffff, 0x080000000, 1, Math.PI, 2**53-2, 0, -Number.MAX_VALUE, 0x100000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 2**53, -0, 0x07fffffff, -0x100000000, -0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, Number.MIN_VALUE, 0x100000001]); ");
/*fuzzSeed-45472219*/count=37; tryItOut("\"use strict\"; e2.add(let (e) (4277));");
/*fuzzSeed-45472219*/count=38; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.imul(Math.fround(Math.atan2(Math.fround(mathy0((Math.imul(( + ( ! Math.fround((Math.exp(((((0x100000001 >>> 0) ? (x >>> 0) : (x >>> 0)) >>> 0) | 0)) | 0)))), -Number.MIN_SAFE_INTEGER) >>> 0), (mathy0(Math.fround(0x100000001), ( + Math.ceil(( + 0x07fffffff)))) >>> 0))), Math.fround(mathy0(Math.sinh(((Math.trunc(0) >>> 0) << 2**53-2)), y)))), ( - ( + (Math.imul((((Math.hypot(x, (Math.max(y, 0x100000000) | 0)) | 0) - Math.tanh((((x | 0) ** y) | 0))) | 0), ((Math.cosh((mathy0(Math.cosh((( ~ (-Number.MAX_SAFE_INTEGER | 0)) | 0)), -Number.MIN_VALUE) | 0)) >>> 0) | 0)) | 0)))) | 0); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53+2, 0x07fffffff, 0x100000000, 42, 0x080000001, 1/0, -Number.MAX_VALUE, 0, Math.PI, -(2**53+2), 0/0, -(2**53-2), -0x0ffffffff, 1, -(2**53), 2**53, Number.MAX_VALUE, 0x100000001, 0.000000000000001, 2**53-2, -0x080000000, 0x0ffffffff, -0, -1/0, -0x100000001, -0x100000000, Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-45472219*/count=39; tryItOut("/*RXUB*/var r = /(?:(?=\\3)*?)/gm; var s = \"1\\n\"; print(s.match(r)); ");
/*fuzzSeed-45472219*/count=40; tryItOut("h1 = x;");
/*fuzzSeed-45472219*/count=41; tryItOut("switch( /x/g ) { default: yield;case 4: v0 = new Number(g0.m1);m2.set(a2, i1);t1.set(g2.a2, 16);break; case 8: break; break;  }");
/*fuzzSeed-45472219*/count=42; tryItOut("\"use strict\"; g1.v0 = (g1 instanceof v1);");
/*fuzzSeed-45472219*/count=43; tryItOut("s0 + '';");
/*fuzzSeed-45472219*/count=44; tryItOut("mathy3 = (function(x, y) { return ((Math.abs(( ~ ( + (Math.max(( + Math.imul(( + mathy0(y, y)), ( + y))), ( + (Math.hypot(-0x100000001, y) , (( + ( - ( + x))) >>> 0)))) | 0)))) < (( + (Math.imul(((mathy2(x, (Math.pow(Math.fround(( ~ y)), Math.fround(y)) | 0)) | 0) >>> 0), (Math.log10(( ~ x)) >>> 0)) >>> 0)) - ( + (( + -0x100000000) ^ Math.max(x, x))))) >>> 0); }); testMathyFunction(mathy3, [Number.MAX_VALUE, Math.PI, 42, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, -0, 0, -(2**53-2), 1.7976931348623157e308, 1/0, 0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x100000000, -0x080000001, -(2**53), -Number.MIN_VALUE, 2**53+2, -0x07fffffff, -0x100000001, 2**53-2, 0x100000001, -0x0ffffffff, 2**53, -1/0, Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, -0x080000000, 1]); ");
/*fuzzSeed-45472219*/count=45; tryItOut("\"use strict\"; /*oLoop*/for (let brceiz = 0, w; brceiz < 0; ++brceiz) { const v0 = new Number(0); } function window(a, eval)\"use asm\";   var cos = stdlib.Math.cos;\n  var abs = stdlib.Math.abs;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 1.015625;\n    var d3 = 1.125;\n    {\n      d2 = (9007199254740991.0);\n    }\n    i0 = ((+cos(((-4294967296.0)))) >= (((1.0)) % ((-(((+abs(((((1025.0)) - ((-513.0)))))) + (1.25)))))));\n    return (((((((Float32ArrayView[((Int8ArrayView[((0x72caf028)*-0xbcd28) >> 0])) >> 2])))-(!(0x23e47195)))>>>(((0xf912f00c) ? (0x22fa9871) : (0xff263a41)))) % (((1))>>>((makeFinalizeObserver('tenured'))))))|0;\n  }\n  return f;Array.prototype.push.apply(a0, [this.m2, this.o2, this.i1]);");
/*fuzzSeed-45472219*/count=46; tryItOut("o1.f2.toString = (function() { m1.toSource = (function() { try { this.o0 + b0; } catch(e0) { } try { e2.delete( /x/g ); } catch(e1) { } try { o2.v0 = g1.runOffThreadScript(); } catch(e2) { } t2[16]; return f2; }); return e2; });");
/*fuzzSeed-45472219*/count=47; tryItOut("{ void 0; minorgc(false); }");
/*fuzzSeed-45472219*/count=48; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround(Math.fround(Math.max(Math.fround((Math.fround((Math.fround((y / Math.max(x, -0))) >>> Math.fround(x))) , ((((y , -Number.MIN_VALUE) | 0) / y) == y))), Math.fround(Math.atan2(( + Math.fround((y ? ( ~ 1.7976931348623157e308) : Math.fround(Math.acos(Math.fround((Math.tan(-Number.MAX_VALUE) | 0))))))), ( ! 0x100000001)))))) * Math.fround(( + ( + ( + (Math.imul(1/0, x) >> x))))))); }); testMathyFunction(mathy0, /*MARR*/[x, ['z'], this, x, ['z'], [undefined], ['z'], [undefined], x, [undefined], x, [undefined], [undefined], this, [undefined], ['z'], [undefined], this, this, this, [undefined], this, this, this, [undefined], ['z'], x, x, this, ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], x, this, x, [undefined], this, x, this, ['z'], ['z'], ['z'], [undefined], ['z'], x, x, x, x, ['z'], this, this, this, this, this, this, this, this, this, this, this, this, this, [undefined], x]); ");
/*fuzzSeed-45472219*/count=49; tryItOut("t2[18] = a0;");
/*fuzzSeed-45472219*/count=50; tryItOut("o1.toSource = (function() { o1.valueOf = f1; return o2; });");
/*fuzzSeed-45472219*/count=51; tryItOut("\"use strict\"; o1.m0.delete(o2.o2.e2);");
/*fuzzSeed-45472219*/count=52; tryItOut(";function x(b, \"3878950450\", ...x) { \"use strict\"; a1.shift();\nprint(x);var z = (4277);\n } {}");
/*fuzzSeed-45472219*/count=53; tryItOut("print(uneval(t2));");
/*fuzzSeed-45472219*/count=54; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=55; tryItOut("/*hhh*/function lhdzki(window, x){window;}/*iii*/print(lhdzki);\nnull;\n");
/*fuzzSeed-45472219*/count=56; tryItOut("/*RXUB*/var r = /([^\\t-\\\u743f]*|\\3((?:$))*|\\b*+?)/gyi; var s = \"\\u00e8\\u00e8\"; print(r.test(s)); ");
/*fuzzSeed-45472219*/count=57; tryItOut("Array.prototype.unshift.apply(a1, [this.a2])\n /x/ .unwatch(\"toFixed\");");
/*fuzzSeed-45472219*/count=58; tryItOut("v1 = a1.length;");
/*fuzzSeed-45472219*/count=59; tryItOut("a2.sort((function() { t2 = new Uint8ClampedArray(a1); return g2.f2; }));");
/*fuzzSeed-45472219*/count=60; tryItOut("testMathyFunction(mathy4, [0, Number.MIN_VALUE, -0x100000000, 0x100000001, 0.000000000000001, -0x080000001, Math.PI, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, 1, -1/0, 0x080000000, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, 2**53, 0x07fffffff, Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, -0x07fffffff, -0, -0x100000001, 0x080000001]); ");
/*fuzzSeed-45472219*/count=61; tryItOut("/*oLoop*/for (var ilaslc = 0, {} = decodeURIComponent.prototype; ilaslc < 10; ++ilaslc) { print(x);yield -17; } ");
/*fuzzSeed-45472219*/count=62; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((0xf9292eb2)))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), x,  /x/ , objectEmulatingUndefined(), x, x, x, x, x]); ");
/*fuzzSeed-45472219*/count=63; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.expm1(((Math.hypot((Math.fround(Math.pow(Math.fround(Math.pow(y, y)), ( + Math.round(( + Math.min(x, y)))))) >>> 0), ((Math.round((y | 0)) | 0) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy2, ['', 0.1, NaN, -0, '/0/', undefined, (new Number(0)), ({valueOf:function(){return 0;}}), (new Number(-0)), false, (function(){return 0;}), [0], (new String('')), true, (new Boolean(true)), [], /0/, (new Boolean(false)), ({toString:function(){return '0';}}), '0', objectEmulatingUndefined(), '\\0', 1, 0, ({valueOf:function(){return '0';}}), null]); ");
/*fuzzSeed-45472219*/count=64; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.asin(Math.min((y >= (( + Math.hypot(( + Math.abs(y)), ( + x))) , (-Number.MIN_VALUE >>> 0))), (((Math.pow(mathy0(y, y), (mathy2(( ! x), Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0) ? ((Math.atan(Math.fround(-Number.MIN_SAFE_INTEGER)) | 0) >>> 0) : (((mathy1((-(2**53+2) | 0), Math.fround((x ? x : ( + Math.fround((0x080000001 ** Math.fround(-Number.MIN_SAFE_INTEGER))))))) | 0) & ( + Math.log2(( + x)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -(2**53+2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 0.000000000000001, -0x080000000, -0x0ffffffff, 0x07fffffff, -0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, 0/0, 42, -(2**53-2), 0, -0x100000000, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 0x080000001, 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, 1, 2**53, Number.MAX_VALUE, 0x100000000, 2**53+2, Math.PI, -0x07fffffff, 0x100000001]); ");
/*fuzzSeed-45472219*/count=65; tryItOut("testMathyFunction(mathy1, /*MARR*/[2**53-2, 2**53-2, new Boolean(false), 2**53-2, 2**53-2, new Boolean(false), new Number(1), 2**53-2]); ");
/*fuzzSeed-45472219*/count=66; tryItOut("\"use strict\"; g1 + s2;");
/*fuzzSeed-45472219*/count=67; tryItOut("t2 + '';");
/*fuzzSeed-45472219*/count=68; tryItOut("Object.defineProperty(this, \"s2\", { configurable: (x % 2 != 0), enumerable: (x % 42 != 6),  get: function() {  return s0.charAt((4277)); } });");
/*fuzzSeed-45472219*/count=69; tryItOut("Array.prototype.pop.call(a1);");
/*fuzzSeed-45472219*/count=70; tryItOut("\"use strict\"; o1.a1.splice(o0);");
/*fuzzSeed-45472219*/count=71; tryItOut("/*MXX2*/this.g0.Uint16Array.prototype.BYTES_PER_ELEMENT = s0;");
/*fuzzSeed-45472219*/count=72; tryItOut("\"use strict\"; for (var v of g2) { try { o0.a2.pop(p0, g1.g1); } catch(e0) { } try { s1.toSource = (function(j) { g0.f2(j); }); } catch(e1) { } v0 = g2.eval(\"/* no regression tests found */\"); }");
/*fuzzSeed-45472219*/count=73; tryItOut("o0.f0 = Proxy.createFunction(h1, f1, f2);");
/*fuzzSeed-45472219*/count=74; tryItOut("\"use strict\"; ;");
/*fuzzSeed-45472219*/count=75; tryItOut("\"use strict\"; g0.a0.shift();");
/*fuzzSeed-45472219*/count=76; tryItOut("testMathyFunction(mathy1, [-0x080000001, -(2**53-2), -0x080000000, -0x100000001, 1/0, 0x100000001, -(2**53+2), 2**53, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, Math.PI, 42, Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, -0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, -0x100000000, -0, -0x07fffffff, 1.7976931348623157e308, 0x07fffffff, 0, -Number.MIN_VALUE, 1, -Number.MAX_VALUE, 0/0, Number.MIN_VALUE, 0.000000000000001, 0x080000000]); ");
/*fuzzSeed-45472219*/count=77; tryItOut("g1.v0 = g0.eval(\"s1 += s2;\");");
/*fuzzSeed-45472219*/count=78; tryItOut("t1.set(t2, v2);");
/*fuzzSeed-45472219*/count=79; tryItOut("\"use strict\"; for(var [b, w] = window in  /x/ ) v1 = t0.length;print(x);");
/*fuzzSeed-45472219*/count=80; tryItOut("Object.seal(o2);\nx;\n");
/*fuzzSeed-45472219*/count=81; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\3(?:(?=\\\\1)|(?=\\\\2+)|\\\\b\\u2900|\\\\2|\\\\1+?(?![^])|[^]\\\\d+?((?:(\\\\t){3,5})?))\", \"yim\"); var s = \" \\u6627\"; print(uneval(s.match(r))); ");
/*fuzzSeed-45472219*/count=82; tryItOut("\"use strict\"; /*vLoop*/for (zgsigt = 0; zgsigt < 30; ++zgsigt, \"\\u79CE\") { let y = zgsigt; Array.prototype.sort.apply(a0, [(function() { try { t1 = t0.subarray(2); } catch(e0) { } try { v0.__proto__ = v2; } catch(e1) { } try { /*ODP-2*/Object.defineProperty(a0, \"y\", { configurable: 10, enumerable: true, get: (function(j) { if (j) { try { this.o1 = s2.__proto__; } catch(e0) { } try { Array.prototype.reverse.apply(a1, []); } catch(e1) { } try { s1 += 'x'; } catch(e2) { } p0.__proto__ = this.v0; } else { try { /*MXX3*/g0.Array.name = g1.Array.name; } catch(e0) { } h0.set = f1; } }), set: Symbol.bind(f0) }); } catch(e2) { } g0.offThreadCompileScript(\"g2.g2.v1 = a0.length;\"); return f2; })]); } ");
/*fuzzSeed-45472219*/count=83; tryItOut("\"use asm\"; /*RXUB*/var r = /./im; var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-45472219*/count=84; tryItOut("const \u0009y = x, z = (4277).valueOf(\"number\"), cpnaag, y = (x = new RegExp(\"\\\\3(?!\\\\B|[\\\\D\\\\t-d]*|(?!(?=.)|(?![\\\\\\u25d1])*?))\", \"ym\")), mnunio;e2.toString = (function(j) { this.f1(j); });");
/*fuzzSeed-45472219*/count=85; tryItOut("var shuwwl = new ArrayBuffer(2); var shuwwl_0 = new Uint16Array(shuwwl); print(shuwwl_0[0]); h1.get = (function() { e1 + b1; return f2; });");
/*fuzzSeed-45472219*/count=86; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.imul((( + Math.tan(( + ( + (( + x) - ( + ( + Math.pow(Math.min(x, y), (x >>> 0))))))))) >>> 0), Math.fround(Math.fround(Math.fround((( ~ (y >>> 0)) >>> 0))))) >>> 0); }); testMathyFunction(mathy5, [-(2**53), Number.MIN_VALUE, -0x080000000, -0x0ffffffff, 0x07fffffff, -0x100000000, -1/0, -(2**53+2), 1.7976931348623157e308, 0/0, Math.PI, -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, Number.MIN_SAFE_INTEGER, -0, 0x100000000, 0x0ffffffff, 2**53, 2**53-2, -Number.MIN_VALUE, 2**53+2, 0.000000000000001, 1/0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 42, -0x07fffffff, 0, -0x080000001, 1, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=87; tryItOut("delete e1[\"y\"];");
/*fuzzSeed-45472219*/count=88; tryItOut("\"use asm\"; f1.__proto__ = p1;");
/*fuzzSeed-45472219*/count=89; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return Math.min((( ! ( + (y ? Math.sqrt(y) : Math.fround(2**53)))) >>> 0), Math.imul((x < Math.fround(( - ( ! x)))), Math.fround(( + Math.expm1(x))))); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), \"\\u7800\"\n, ['z'], objectEmulatingUndefined(), ['z'], objectEmulatingUndefined(), objectEmulatingUndefined(), [], ['z'], [], [], objectEmulatingUndefined(), \"\\u7800\"\n, objectEmulatingUndefined(), \"\\u7800\"\n, [], \"\\u7800\"\n, \"\\u7800\"\n, \"\\u7800\"\n, \"\\u7800\"\n, \"\\u7800\"\n, ['z'], [], [], [], \"\\u7800\"\n, [], [], [], \"\\u7800\"\n, ['z'], objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-45472219*/count=90; tryItOut("v0 = (a1 instanceof i2);");
/*fuzzSeed-45472219*/count=91; tryItOut("\"use strict\"; lpqrsm(x, undefined.valueOf(\"number\"));/*hhh*/function lpqrsm({}, ...w){print(x);}");
/*fuzzSeed-45472219*/count=92; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ (Math.fround(Math.log1p(( + Math.max((( ! (y >>> 0)) >>> 0), Math.min(x, Math.fround(Math.imul(Math.fround(x), Math.max(x, 1/0)))))))) | 0)) | 0); }); testMathyFunction(mathy0, [-(2**53+2), Math.PI, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, Number.MIN_VALUE, -0x07fffffff, 1, 42, 0, -1/0, 0x100000001, 2**53+2, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, 0x100000000, 2**53-2, -(2**53), 2**53, -0, 0/0, -0x100000000, 0x0ffffffff, -(2**53-2), -0x080000000, 0x07fffffff, 0x080000001, -0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-45472219*/count=93; tryItOut("for (var p in s0) { try { i1 + ''; } catch(e0) { } try { for (var p in t1) { try { /*MXX1*/var o2 = g2.Uint16Array.BYTES_PER_ELEMENT; } catch(e0) { } a1.push(m0, o1.v1); } } catch(e1) { } try { v0 = evaluate(\"this.o2.s2.toSource = (function(j) { if (j) { try { a2 = r0.exec(s0); } catch(e0) { } Array.prototype.reverse.apply(a2, [({NaN: Math.ceil(-8)}).watch(\\\"__iterator__\\\", /*UUV2*/(b.catch = b.cbrt)), this.o1, p1, p2]); } else { for (var p in h0) { v1 = g0.runOffThreadScript(); } } });\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: (x % 5 == 2), noScriptRval: true, sourceIsLazy: true, catchTermination: false })); } catch(e2) { } a0.pop(o0); }");
/*fuzzSeed-45472219*/count=94; tryItOut("i2.__proto__ = f2;");
/*fuzzSeed-45472219*/count=95; tryItOut("\"use strict\"; /*infloop*/M:for(x = x > x; x; eval(\"mathy2 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var ff = foreign.ff;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var d2 = -1.25;\\n    d0 = (+abs(((Float64ArrayView[((Math.log(x ?  \\\"\\\"  : undefined))) >> 3]))));\\n    switch ((~~(d0))) {\\n      default:\\n        {\\n          d1 = (+(0.0/0.0));\\n        }\\n    }\\n    return (((0x3a1d2980)))|0;\\n    return ((((0x6a2fbbbb) ? (0x6bca5df9) : (0x2cade48b))))|0;\\n  }\\n  return f; })(this, {ff: ((4277)).bind()}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [2**53, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, -0x080000000, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, 0x100000001, 0x0ffffffff, -(2**53+2), -1/0, Number.MIN_VALUE, 1/0, -0x07fffffff, -(2**53-2), 2**53-2, -0x100000001, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, 0/0, 0x080000000, -0x100000000, Math.PI, Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000000, 0, -(2**53), 0x07fffffff]); \", new RegExp(\"[^]*?+?(?=.)+|\\\\b+?|((.{1,})?)|(?!(\\\\2\\\\x67+)){4,8}\", \"gm\"))) {function shapeyConstructor(xodibr){Object.defineProperty(this,  '' , ({}));this[ '' ] = objectEmulatingUndefined();this[\"toString\"] = \"\\u6DD3\";if (\"\\u8998\") this[\"toString\"] = new Function;Object.defineProperty(this,  '' , ({enumerable: false}));{ \"\\u44A2\"; } this[\"toString\"] = -27;return this; }/*tLoopC*/for (let a of /*FARR*/[]) { try{let lptfkq = shapeyConstructor(a); print('EETT'); yield /\\d/gm;}catch(e){print('TTEE ' + e); } } }");
/*fuzzSeed-45472219*/count=96; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - ((Math.fround(Math.sinh(Math.fround((Math.sin((Math.fround(Math.min(Math.fround(Math.PI), Math.fround(((y >>> 0) ? y : ( + 0x0ffffffff))))) | 0)) | 0)))) ** -(2**53)) | ( + (( + (mathy0((( - Math.fround(Math.asin(Number.MAX_VALUE))) | 0), (42 | 0)) | 0)) ? Math.fround(Math.min(2**53, ( + (Math.fround(2**53) != Math.fround(mathy0(Math.fround(x), Math.fround(x))))))) : Math.imul((-0x100000001 >>> 0), (42 >>> 0)))))); }); testMathyFunction(mathy1, [-0, [], true, '/0/', (new Number(0)), '', [0], (new Number(-0)), ({toString:function(){return '0';}}), (function(){return 0;}), NaN, undefined, 0, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), (new String('')), false, '\\0', '0', (new Boolean(false)), 0.1, null, ({valueOf:function(){return '0';}}), /0/, 1, (new Boolean(true))]); ");
/*fuzzSeed-45472219*/count=97; tryItOut("mathy1 = (function(x, y) { return Math.min((Math.acosh(((Math.imul((0 >>> 0), (( ! y) | 0)) >>> 0) >>> 0)) | ( + Math.atan2(( ~ Math.fround(-(2**53-2))), ( + ( - 2**53-2))))), ((( + Math.min(( + Math.cos(((( + (( + Math.exp(y)) < y)) === x) >>> 0))), ( + Math.log1p(Math.min(x, (0/0 & Math.fround((y * x)))))))) >>> 0) ^ ((Math.exp((Math.exp(x) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy1, [-0, -0x080000000, 0x07fffffff, 42, 1.7976931348623157e308, 0x080000001, -0x100000001, 1, 0x080000000, -1/0, Number.MIN_VALUE, Math.PI, 1/0, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 2**53+2, -0x100000000, -0x080000001, -(2**53+2), 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), 2**53-2, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, 0.000000000000001, -(2**53-2), 2**53]); ");
/*fuzzSeed-45472219*/count=98; tryItOut("/*tLoop*/for (let b of /*MARR*/[]) { g1.v2 = (g2 instanceof v2); }");
/*fuzzSeed-45472219*/count=99; tryItOut("v0 + e1;");
/*fuzzSeed-45472219*/count=100; tryItOut("(void schedulegc(this.g1.g2));");
/*fuzzSeed-45472219*/count=101; tryItOut("\"use asm\"; /*vLoop*/for (tcnnuc = 0; tcnnuc < 44; ++tcnnuc) { const b = tcnnuc; print(b);(e, eval) =>  { \"use strict\"; yield x }  } ");
/*fuzzSeed-45472219*/count=102; tryItOut("/*RXUB*/var r = /\\3|.?^{2,5}|\\u006c|[^]{16383}*?{0,2}|[^]|\uf7cb{0,3}{2}./yim; var s = \"\\uf7cb\\uf7cb\\uf7cb\\uf7cb\\uf7cb\\uf7cb\\n\"; print(s.replace(r, String.prototype.charAt)); ");
/*fuzzSeed-45472219*/count=103; tryItOut("const a = d >  '' ;Object.defineProperty(this, \"v1\", { configurable: (a % 5 != 3), enumerable: true,  get: function() {  return evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: \"\\uE549\", catchTermination: 27 })); } });");
/*fuzzSeed-45472219*/count=104; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(( + (Math.atan2(( - y), Number.MIN_VALUE) >>> 0))) !== (( + (Math.min(Math.min((( ! Math.cbrt(y)) >>> Math.fround(Math.pow(Math.fround((( + -Number.MIN_VALUE) >>> 0)), Math.fround(y)))), ( + (Math.fround(( ! ( + x))) >>> Math.max((Math.min(x, (y >>> 0)) >>> 0), x)))), (Math.atanh((-Number.MAX_SAFE_INTEGER | 0)) | 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [-0x080000001, 0x07fffffff, 0x080000001, 0x100000001, Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 2**53+2, 0, 0x0ffffffff, 0x080000000, -(2**53), -1/0, -0x100000001, -0x080000000, 0x100000000, -0x100000000, -0x0ffffffff, Math.PI, Number.MIN_VALUE, 1/0, -0x07fffffff, 42, 0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 1, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-45472219*/count=105; tryItOut("M:if(false) \u0009print((4277)); else e0 + b1;");
/*fuzzSeed-45472219*/count=106; tryItOut("/* no regression tests found */\n/*vLoop*/for (vdiwmv = 0; vdiwmv < 52; ++vdiwmv) { let b = vdiwmv; print(x); } \n");
/*fuzzSeed-45472219*/count=107; tryItOut("print(x);\nallocationMarker();\n");
/*fuzzSeed-45472219*/count=108; tryItOut("this.f1.__proto__ = o1;");
/*fuzzSeed-45472219*/count=109; tryItOut("\"use strict\"; let (w = (22 instanceof window), x = (eval(\"/* no regression tests found */\").eval(\"\\\"use strict\\\"; yield (4277) >= (a = []);\")), e = (\u0009[w, ] = \u3056)) { /*bLoop*/for (ktogqn = 0; ktogqn < 52; ++ktogqn) { if (ktogqn % 10 == 2) { ([]); } else { o0.v1 = Object.prototype.isPrototypeOf.call(o2.o0.o0.o0.g0, o2.g0.i1); }  }  }");
/*fuzzSeed-45472219*/count=110; tryItOut("for (var v of t0) { try { for (var v of s0) { try { print(m2); } catch(e0) { } try { a0.forEach((function() { try { Object.prototype.watch.call(i1, \"isFinite\", (function() { for (var j=0;j<2;++j) { f1(j%5==0); } })); } catch(e0) { } m1.get(s1); return e0; }), p2); } catch(e1) { } try { s1 += g2.o1.s0; } catch(e2) { } o1.a0.pop(f0, f0, m2, m0, s2); } } catch(e0) { } try { t0 = new Uint32Array(t0); } catch(e1) { } v2.toSource = (function() { for (var j=0;j<6;++j) { f0(j%3==1); } }); }");
/*fuzzSeed-45472219*/count=111; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ~ Math.fround(mathy2(Math.fround(( ! ( + ( + (( + Math.atan(Math.min(42, y))) + ( + x)))))), Math.fround(((( ! (y === 1.7976931348623157e308)) == ( + Math.max((( - Math.atan2(( - 0.000000000000001), Math.atan2((Number.MIN_VALUE | 0), (42 | 0)))) >>> 0), x))) | 0))))) >>> 0); }); ");
/*fuzzSeed-45472219*/count=112; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=113; tryItOut("\"use strict\"; o2.m0.set(o1, v2);");
/*fuzzSeed-45472219*/count=114; tryItOut("mathy0 = (function(x, y) { return (Math.cosh((Math.acos(Math.fround((( - (-1/0 ? (Math.acosh(x) >>> 0) : x)) | 0))) | 0)) || ((Math.pow([[]], Math.ceil((((Math.sign(y) ? Math.fround(x) : Number.MIN_VALUE) ? 2**53-2 : (Math.atanh((-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)) | 0))) >>> 0) % ( + (( + x) ? y : ( + (x | 0)))))); }); ");
/*fuzzSeed-45472219*/count=115; tryItOut("\"use strict\"; h1.toSource = (function() { try { o2 = new Object; } catch(e0) { } try { print(m1); } catch(e1) { } v2 = b1.byteLength; return p2; });");
/*fuzzSeed-45472219*/count=116; tryItOut("m0 = new Map;");
/*fuzzSeed-45472219*/count=117; tryItOut("\"use asm\"; /*MXX3*/g0.Int16Array.prototype.BYTES_PER_ELEMENT = g0.Int16Array.prototype.BYTES_PER_ELEMENT;");
/*fuzzSeed-45472219*/count=118; tryItOut("/*oLoop*/for (var ykwklm = 0; ykwklm < 4; ++ykwklm) { g1 = m2.get(e0); } \nvar tojaoo = new SharedArrayBuffer(32); var tojaoo_0 = new Uint8ClampedArray(tojaoo); tojaoo_0[0] = 23; var tojaoo_1 = new Int16Array(tojaoo); print((d));/* no regression tests found */print(tojaoo_1[0]);\n");
/*fuzzSeed-45472219*/count=119; tryItOut("\"use strict\"; print(uneval(f0));");
/*fuzzSeed-45472219*/count=120; tryItOut("/*bLoop*/for (var zxefcc = 0; zxefcc < 91; ++zxefcc) { if (zxefcc % 36 == 2) { {}, z, xfameh, x, b;(4277); } else { t2.set(a0, 3);\nlet t1 = t0.subarray(5);\n }  } ");
/*fuzzSeed-45472219*/count=121; tryItOut("\"use strict\"; e2.has(p1);");
/*fuzzSeed-45472219*/count=122; tryItOut("i1.next();");
/*fuzzSeed-45472219*/count=123; tryItOut("\"use strict\"; for(let c in (((Math.abs(-10)).bind(x, /*RXUE*/new RegExp(\"(?:(?!(\\\\d).)*(\\\\2)|.|$|\\\\b?.[^]\\\\B{2,5}*?\\\\1*)\", \"y\").exec(\"\")))(x)))h2 = x;");
/*fuzzSeed-45472219*/count=124; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(v0, m0);");
/*fuzzSeed-45472219*/count=125; tryItOut("i1.send(s2);");
/*fuzzSeed-45472219*/count=126; tryItOut("\"use strict\"; throw StopIteration;");
/*fuzzSeed-45472219*/count=127; tryItOut("if(true) { if (x) } else o0.v1 = f1[new String(\"8\")];");
/*fuzzSeed-45472219*/count=128; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + Math.fround((Math.fround(( + ( ~ (mathy0(( + mathy0(( + y), ( + x))), ( + y)) >>> 0)))) !== Math.fround(( ~ ( + Math.max(( + x), x))))))) % ( + Math.round(((( + x) << y) | 0))))); }); ");
/*fuzzSeed-45472219*/count=129; tryItOut("\"use strict\"; ");
/*fuzzSeed-45472219*/count=130; tryItOut("v2 = a2.reduce, reduceRight((function mcc_() { var eakeii = 0; return function() { ++eakeii; if (/*ICCD*/eakeii % 7 == 1) { dumpln('hit!'); try { Object.defineProperty(o1, \"t1\", { configurable: (x % 3 != 1), enumerable: (x % 5 == 3),  get: function() {  return new Int32Array(t1); } }); } catch(e0) { } try { o2 = g1.__proto__; } catch(e1) { } try { for (var p in f1) { try { v1.toString = (function() { try { a0.shift(); } catch(e0) { } try { v2 = g1.eval(\"let v2 = t2.BYTES_PER_ELEMENT;\"); } catch(e1) { } m0.get(g0.o1); return this.f2; }); } catch(e0) { } try { v1 = o0.g0.eval(\"b1.valueOf = (function() { f0(this.f2); return g0.h0; });\"); } catch(e1) { } try { v2 = a0.every((function(j) { if (j) { t0 = new Float64Array(new  /x/g (\"\\u97AD\",  /x/g \u000c)); } else { try { v1 = g0.runOffThreadScript(); } catch(e0) { } v0 = r2.test; } }), t1, o2); } catch(e2) { } s1 += this.s1; } } catch(e2) { } g2.o1.h1.get = f1; } else { dumpln('miss!'); g0 = this; } };})(), b0, this.o0.v2);");
/*fuzzSeed-45472219*/count=131; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( ! ( + Math.log1p((Math.imul(x, x) >>> 0))))); }); testMathyFunction(mathy0, [0, 0x0ffffffff, 42, 2**53+2, -Number.MAX_VALUE, 0x100000001, -1/0, 0.000000000000001, -0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, 2**53, 0x100000000, -0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, 0/0, -(2**53), Math.PI, 2**53-2, -(2**53+2), Number.MIN_VALUE, -(2**53-2), 0x07fffffff, -0x100000000]); ");
/*fuzzSeed-45472219*/count=132; tryItOut("\"use strict\"; ");
/*fuzzSeed-45472219*/count=133; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return (Math.hypot(Math.acosh(Math.pow(( + y), Number.MAX_SAFE_INTEGER)), (Math.fround(((Math.atan2(( + (( + y) , ( + ( + ( ! ( + y)))))), (x | 0)) >>> 0) | 0)) | 0)) | (( ~ (Math.sin(( ~ Math.fround((( - x) ? Math.min(x, y) : Math.round(x))))) | 0)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[new Number(1.5), (1/0), new Boolean(false), -0, (1/0), new Number(1.5), RangeError, new Boolean(false), new Number(1.5), (1/0), new Number(1.5), new Boolean(false), new Number(1.5), new Boolean(false), new Boolean(false), new Number(1.5), -0, -0, new Number(1.5), RangeError, new Boolean(false), -0, -0, new Boolean(false), RangeError]); ");
/*fuzzSeed-45472219*/count=134; tryItOut("mathy4 = (function(x, y) { return (( ! ((((y ^ (( + x) ? x : Math.min(y, Math.fround(y)))) >> (mathy3(y, (Math.atan2(x, (Math.expm1(Math.imul((((-0x100000000 | 0) == x) | 0), (y | 0))) >>> 0)) | 0)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[(makeFinalizeObserver('nursery')), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), x, x, new String(''), new String(''), (makeFinalizeObserver('nursery'))]); ");
/*fuzzSeed-45472219*/count=135; tryItOut("var nwhdef = new SharedArrayBuffer(16); var nwhdef_0 = new Uint32Array(nwhdef); nwhdef_0[0] = 11; var nwhdef_1 = new Int16Array(nwhdef); nwhdef_1[0] = 9; var nwhdef_2 = new Uint32Array(nwhdef); var nwhdef_3 = new Int8Array(nwhdef); print(nwhdef_3[0]); var nwhdef_4 = new Uint8Array(nwhdef); var nwhdef_5 = new Int8Array(nwhdef); nwhdef_5[0] = -18; var nwhdef_6 = new Int32Array(nwhdef); nwhdef_6[0] = 29; var nwhdef_7 = new Float32Array(nwhdef); print(nwhdef_7[0]); nwhdef_7[0] = 1994319522.5; var nwhdef_8 = new Uint16Array(nwhdef); nwhdef_8[0] = 0x0ffffffff; var nwhdef_9 = new Float64Array(nwhdef); print(nwhdef_9[0]); return this;Object.defineProperty(this, \"v0\", { configurable: true, enumerable: (nwhdef_3 % 3 != 2),  get: function() {  return evaluate(\"function f1(h2) \\\"use asm\\\";   var NaN = stdlib.NaN;\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    var d3 = -32769.0;\\n    return +((NaN));\\n    return +(x);\\n  }\\n  return f;\", ({ global: this.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: (nwhdef_8 % 9 == 1) })); } });print(nwhdef_3);print(nwhdef_3[0]);v1 = t0.BYTES_PER_ELEMENT;print( /x/  << nwhdef_8);v0 = evalcx(\"function f2(g0)  { return Math.min(6, -21) } \", g1);print(window);");
/*fuzzSeed-45472219*/count=136; tryItOut("\"use strict\"; ");
/*fuzzSeed-45472219*/count=137; tryItOut("\"use strict\"; var v1 = evalcx(\"s2 += g1.s2;\", o1.g1);");
/*fuzzSeed-45472219*/count=138; tryItOut("var r0 = x ^ x; r0 = r0 | r0; var r1 = r0 | 3; var r2 = r0 - r0; var r3 = 5 / 5; var r4 = 2 & r0; r3 = 8 & r1; var r5 = 2 + r2; r2 = r2 % r0; var r6 = r4 | r1; r1 = r2 - r1; var r7 = x / r6; var r8 = 2 / 4; var r9 = r0 % r7; var r10 = x * r0; var r11 = 8 / r0; var r12 = r2 / r10; var r13 = r0 % 8; var r14 = 7 % 0; var r15 = r10 | 9; var r16 = r4 / r0; r3 = 3 / r6; var r17 = r16 / r15; var r18 = r14 % x; r6 = r10 ^ r14; var r19 = 0 + 8; var r20 = x - 4; var r21 = r1 % 0; var r22 = r1 * 7; var r23 = r19 & 2; var r24 = 3 ^ 2; print(r11); var r25 = r22 ^ 8; var r26 = 7 | 4; r6 = r5 | r17; r8 = r17 * r13; var r27 = r2 + r13; var r28 = 2 * r17; var r29 = r7 | r5; print(r8); var r30 = 1 - r14; var r31 = r22 * r26; var r32 = r0 % r7; print(r9); var r33 = r32 % 6; print(r13); var r34 = r21 ^ 0; print(r3); var r35 = 9 & r23; var r36 = 4 % 6; var r37 = r2 / r1; var r38 = 1 | r27; var r39 = 4 | 8; r2 = 9 * r26; var r40 = 2 + 2; r25 = r22 * r23; var r41 = 5 % r28; var r42 = r27 * r37; var r43 = r33 - 3; print(r16); var r44 = r1 * r15; var r45 = 5 | 1; var r46 = r41 - 6; var r47 = r32 ^ r21; var r48 = x % r30; r26 = r4 % r19; var r49 = r8 | r32; var r50 = r12 * r27; r18 = r12 | r0; r6 = r49 ^ r18; print(r20); r11 = 5 | 0; var r51 = r1 & r50; var r52 = r47 & 6; var r53 = 4 & 7; var r54 = x % 7; var r55 = r38 + r12; print(r46); var r56 = r19 / r18; var r57 = r7 % 9; var r58 = r29 ^ r39; var r59 = r49 ^ 7; print(r39); var r60 = r59 % r2; var r61 = 3 % 1; var r62 = 5 ^ r28; r51 = 4 ^ r1; print(r23); var r63 = 2 - r40; var r64 = r9 | r14; r63 = r29 ^ 6; var r65 = 1 % r56; var r66 = r50 / 7; var r67 = r50 | 1; r2 = r37 - r42; var r68 = r15 % r12; r38 = r13 | r5; var r69 = 1 / r12; var r70 = 9 - r66; var r71 = r15 / r13; r37 = r48 - r70; var r72 = 3 + 1; var r73 = r13 | r2; r37 = r20 | r69; var r74 = r7 * 6; var r75 = r44 % r53; var r76 = r47 / r39; var r77 = 6 & r29; var r78 = r13 % r7; print(r1); r27 = 5 % r38; var r79 = r56 + r61; var r80 = 3 / r74; r22 = r15 ^ r31; print(r27); var r81 = r33 | r72; var r82 = r36 ^ r81; var r83 = 3 ^ r24; r57 = r56 & 3; var r84 = r31 % r14; var r85 = r62 | r53; print(r36); var r86 = r17 + r11; var r87 = r83 ^ r9; r47 = r70 - r54; var r88 = r9 % r72; var r89 = r38 + r40; var r90 = 5 / r19; var r91 = r32 | 8; var r92 = 1 - 2; var r93 = r69 + r31; var r94 = r50 & r75; var r95 = 3 + r18; var r96 = 4 - r0; var r97 = r4 / 5; var r98 = r55 % r88; var r99 = r84 ^ 0; var r100 = 4 + 4; r96 = r12 % 8; var r101 = 5 * 4; var r102 = r43 & r79; r32 = r8 * 0; print(r29); var r103 = r31 * r16; var r104 = r16 & r83; var r105 = r99 / r4; var r106 = 3 * r69; var r107 = r4 & 0; var r108 = r41 - r31; print(r27); r85 = r79 & r102; var r109 = 5 - r48; var r110 = 4 ^ r15; var r111 = r50 | 0; r26 = r81 * 9; print(r34); var r112 = r59 - 3; var r113 = r15 - r87; var r114 = r30 - 1; var r115 = 0 / 5; r114 = 0 - 1; var r116 = r58 % r107; var r117 = r83 * r109; var r118 = r72 & r70; var r119 = r45 - r8; var r120 = 7 & r41; var r121 = r81 + r119; var r122 = 0 & 9; var r123 = r111 * r63; var r124 = r64 - r61; r56 = r40 / r13; var r125 = r36 % r105; var r126 = 9 * r53; var r127 = r74 & 3; var r128 = 6 - r38; print(r80); var r129 = r1 % 3; var r130 = 7 + r113; var r131 = r66 ^ r92; var r132 = r3 ^ 5; var r133 = r6 * r98; r86 = r64 + 5; var r134 = r24 % r107; var r135 = r50 - r123; r49 = r46 * 6; var r136 = r103 * r60; r110 = r53 | r44; var r137 = r103 | r26; print(r53); var r138 = r126 & r89; var r139 = r101 | 5; var r140 = 5 - r96; var r141 = 9 + 2; var r142 = 7 * r59; var r143 = r118 * r126; var r144 = r41 / r72; var r145 = r49 % 1; var r146 = 8 ^ 8; var r147 = 6 ^ 4; r47 = 0 ^ 7; var r148 = r35 * 0; var r149 = r36 + r38; var r150 = r135 + 6; var r151 = 0 / r132; var r152 = r95 - r136; var r153 = 5 - 2; print(r122); var r154 = r19 % 9; var r155 = 7 ^ r95; var r156 = r49 + r53; var r157 = 4 % 1; var r158 = r21 | 3; var r159 = 3 / r97; var r160 = r56 * r27; var r161 = r0 & r47; var r162 = 1 / 7; var r163 = r49 * r101; var r164 = 9 ^ r93; var r165 = r69 % r164; var r166 = r92 | 9; var r167 = r8 | r87; var r168 = r65 | 7; var r169 = r38 ^ r74; print(r32); var r170 = r121 / r70; var r171 = r37 - 0; ");
/*fuzzSeed-45472219*/count=139; tryItOut("\"use strict\"; const x = (Array.prototype.copyWithin.prototype), qakjjs, x, window = [[]], wevcxt, y, x, oymvnt, b, x;/*RXUB*/var r = new RegExp(\"[^\\\\0-\\u88d9\\\\cD]|(?!\\\\d(?:.\\\\B)|\\\\B?\\\\B)*\", \"y\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=140; tryItOut("mathy4 = (function(x, y) { return (((mathy0(mathy1((((( + (Math.log10(mathy0(0.000000000000001, y)) << ( + (0x0ffffffff <= x)))) != (y | 0)) | 0) >>> 0), ( + Math.min(( + y), ( + y)))), Math.sqrt((Math.fround(Math.hypot(y, Math.fround(Math.imul(y, ( + mathy1(-(2**53-2), y)))))) >>> 0))) | 0) - (Math.asin((( - x) , Math.fround(y))) | 0)) | 0); }); ");
/*fuzzSeed-45472219*/count=141; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.pow(( ! (( + ((((( - -0x100000000) >>> 0) - (Number.MAX_VALUE >>> 0)) >>> 0) , (y >>> 0))) ? (y >>> 0) : Math.pow((( ~ (-Number.MAX_SAFE_INTEGER | 0)) | 0), 0.000000000000001))), Math.atan2(( + (( + Math.log((Math.sin(y) % 2**53-2))) & ( + Math.pow(Math.fround(Math.atan(Math.fround(Math.clz32(y)))), Math.fround(Math.PI))))), Math.fround(((Math.imul((x | 0), (( + ( ~ (y >>> 0))) | 0)) | 0) < Math.fround((( ~ (( + x) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, -Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE, 2**53, 0/0, 1/0, -0, -0x07fffffff, -(2**53), -0x080000001, -0x100000000, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0, -(2**53+2), 0x080000001, -0x100000001, 1, 0x100000001, -Number.MIN_VALUE, -1/0, -(2**53-2), Number.MAX_VALUE, 42, 0.000000000000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-45472219*/count=142; tryItOut("L: {m1.delete(v0);const y = Math.max(13, 27);; }");
/*fuzzSeed-45472219*/count=143; tryItOut("switch( /x/g ) { default:  }\n");
/*fuzzSeed-45472219*/count=144; tryItOut("testMathyFunction(mathy2, [-0x0ffffffff, -0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -(2**53-2), -1/0, 0, -0x080000001, 0x100000001, 1, 0x0ffffffff, -0x100000001, -0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -0x100000000, -(2**53), Number.MAX_VALUE, 2**53-2, 0x100000000, Math.PI, 2**53, 0/0]); ");
/*fuzzSeed-45472219*/count=145; tryItOut("\"use strict\"; v0 = t0.length;");
/*fuzzSeed-45472219*/count=146; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=147; tryItOut("v2 = g1.runOffThreadScript();");
/*fuzzSeed-45472219*/count=148; tryItOut("this.v1 = Array.prototype.reduce, reduceRight.apply(a1, [(function() { try { for (var v of h0) { try { Object.defineProperty(o0, \"h2\", { configurable: false, enumerable: 'fafafa'.replace(/a/g, (function(q) { return q; }).bind) instanceof (Math.imul([1,,], -19)),  get: function() {  return ({getOwnPropertyDescriptor: function(name) { m1.set(g1, s2);; var desc = Object.getOwnPropertyDescriptor(p2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { s1 = new String(i1);; var desc = Object.getPropertyDescriptor(p2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { f0 = o1.g2.objectEmulatingUndefined();; Object.defineProperty(p2, name, desc); }, getOwnPropertyNames: function() { g1.e2.has(g1.g1);; return Object.getOwnPropertyNames(p2); }, delete: function(name) { o0.o0 = Object.create(o0.g0);; return delete p2[name]; }, fix: function() { delete h1.getOwnPropertyDescriptor;; if (Object.isFrozen(p2)) { return Object.getOwnProperties(p2); } }, has: function(name) { v0 = evalcx(\"neuter(g2.o0.b0, \\\"change-data\\\");\", g0);; return name in p2; }, hasOwn: function(name) { throw s2; return Object.prototype.hasOwnProperty.call(p2, name); }, get: function(receiver, name) { t0[(Uint16Array)( /x/ , false)] = let (d =  /x/g ) /[^]|\\B+|[^\\u1318-\\u0021]|(?=\\s{4,67108867})*+/m;; return p2[name]; }, set: function(receiver, name, val) { e0.add(p0);; p2[name] = val; return true; }, iterate: function() { throw t1; return (function() { for (var name in p2) { yield name; } })(); }, enumerate: function() { for (var p in e1) { try { this.b2 + g2.s1; } catch(e0) { } try { /*ODP-1*/Object.defineProperty(p1, \"\\u9746\", ({writable: true, enumerable: true})); } catch(e1) { } try { f2(g2.h2); } catch(e2) { } a1.sort(); }; var result = []; for (var name in p2) { result.push(name); }; return result; }, keys: function() { Array.prototype.unshift.apply(a1, [v2, i0, g2.v1, m1]);; return Object.keys(p2); } }); } }); } catch(e0) { } try { s2 = p1; } catch(e1) { } v1 = g2.runOffThreadScript(); } } catch(e0) { } try { print(uneval(a0)); } catch(e1) { } try { s0 += s1; } catch(e2) { } this.s1 += this.s2; return g1; })]);");
/*fuzzSeed-45472219*/count=149; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=150; tryItOut("a2[5];");
/*fuzzSeed-45472219*/count=151; tryItOut("\"use asm\"; this.t2 = t2.subarray(({valueOf: function() { o0.s2 += s1;return 17; }}));");
/*fuzzSeed-45472219*/count=152; tryItOut("this.m2.set(g0, this.o1.f0);");
/*fuzzSeed-45472219*/count=153; tryItOut("\"use asm\"; { void 0; gcslice(1); }");
/*fuzzSeed-45472219*/count=154; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x080000000, -(2**53), 0x100000001, -0x100000000, -1/0, 2**53, 0x080000001, 2**53+2, 0/0, -0x080000001, -Number.MAX_VALUE, 42, -0x0ffffffff, Number.MAX_VALUE, 1/0, Math.PI, 1, 1.7976931348623157e308, -0, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000000, -Number.MIN_VALUE, -0x07fffffff, -0x080000000, 0.000000000000001, 0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=155; tryItOut("mathy2 = (function(x, y) { return (((((Math.atan((( ~ (x - ( - y))) >>> 0)) >>> 0) & (((Math.max(((Math.log((Math.exp(x) | 0)) >>> 0) >>> 0), ( + ((0 % ((( + ( + Math.min(( + y), ( + 0x100000000)))) === ( + x)) | 0)) | 0))) >>> 0) && (Math.log1p(y) >>> 0)) | 0)) | 0) ? ((Math.sinh(y) & Math.fround(((x >>> ((( + Math.fround(Math.tan(Math.fround(0x080000000)))) ? y : ( + (Math.log10((Math.PI >>> 0)) >>> 0))) >>> 0)) & (( - Math.min((Math.atan2((x >>> 0), (y >>> 0)) >>> 0), Math.max(0x0ffffffff, ( + Math.PI)))) >>> 0)))) >>> 0) : ((((( + Math.atan(-Number.MAX_SAFE_INTEGER)) === ( - ((Math.tan(Math.fround(y)) | 0) == (( ~ (0x080000000 | 0)) >>> 0)))) | 0) | (Math.imul(y, (y | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x080000000, -(2**53), Number.MAX_VALUE, 0, 0x100000000, 0x080000001, 1.7976931348623157e308, 0x0ffffffff, -1/0, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53-2), 42, 0x07fffffff, 0x100000001, -(2**53+2), Math.PI, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -0x07fffffff, Number.MIN_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -0x0ffffffff, 0.000000000000001, -0, 0x080000000, 1, -0x100000001, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=156; tryItOut("testMathyFunction(mathy4, [true, (new String('')), /0/, objectEmulatingUndefined(), (new Boolean(true)), (new Boolean(false)), [], (new Number(0)), -0, false, 0, null, '', [0], ({valueOf:function(){return 0;}}), '/0/', (function(){return 0;}), NaN, 0.1, undefined, ({toString:function(){return '0';}}), '0', '\\0', 1, ({valueOf:function(){return '0';}}), (new Number(-0))]); ");
/*fuzzSeed-45472219*/count=157; tryItOut("\"use strict\"; { void 0; void gc('compartment'); } e1 + '';");
/*fuzzSeed-45472219*/count=158; tryItOut("v1 = Object.prototype.isPrototypeOf.call(f1, o0.a1);");
/*fuzzSeed-45472219*/count=159; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return +((+/*FFI*/ff(((abs((((i2)+(i2)) >> (((+((0x1d132*(0x77f7de2e)) & ((0x6dd4eeda)-(0xe16c1578)+(-0x8000000)))) < (-1.0)))))|0)), ((-1.125)))));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [1.7976931348623157e308, 0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, -0x100000000, -(2**53+2), Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, 2**53, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53), 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -0x07fffffff, 0x100000001, 1/0, -(2**53-2), -0, -Number.MAX_VALUE, 1, 0x080000001, 0/0, -1/0, 2**53+2, 2**53-2, 0x07fffffff, 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=160; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.cos((Math.atan2((( - ((((((( + (y << y)) | 0) ? (x | 0) : x) | 0) | 0) != y) | 0)) | 0), ((( - (( + Math.trunc(Math.fround(Math.min(Math.fround(x), (( - x) >>> 0))))) >>> 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy3, [Math.PI, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 0x080000001, Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, 0x07fffffff, -0x080000000, 1, -Number.MIN_VALUE, 2**53, Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 0x100000001, -1/0, 0x080000000, -0, 2**53-2, 2**53+2, 1/0, -0x100000001, 42, -(2**53-2), 0x0ffffffff, -(2**53+2), 0]); ");
/*fuzzSeed-45472219*/count=161; tryItOut("for(var x in a = Proxy.create(({/*TOODEEP*/})( /x/ ),  /x/g )) {e2.delete(g2);(new RegExp(\"(\\\\2{2,})\", \"m\")); }");
/*fuzzSeed-45472219*/count=162; tryItOut("mathy3 = (function(x, y) { return (Math.atan((( + Math.hypot(( + Math.min(y, Math.fround(y))), mathy2(Math.cbrt((Math.cbrt(0x100000000) > y)), x))) | 0)) | 0); }); testMathyFunction(mathy3, [0x0ffffffff, -1/0, -0x100000001, -Number.MAX_VALUE, -(2**53), 42, Number.MIN_VALUE, Math.PI, 0, 2**53+2, 0x07fffffff, -0x100000000, 1, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -0x0ffffffff, -0x07fffffff, -0, 0.000000000000001, -(2**53+2), 0x100000000, -(2**53-2), 1.7976931348623157e308, 2**53, -0x080000001, 1/0, -Number.MIN_VALUE, 0x080000000, -0x080000000, 0/0, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=163; tryItOut("\"use strict\"; o1.v2 = new Number(NaN);");
/*fuzzSeed-45472219*/count=164; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?:\\\\B*))|(?:(?!\\\\d+\\\\B\\\\S|.|.*\\\\w{1,}|.(?:\\\\D.)\\\\B(?=[^]?)))*\", \"gi\"); var s = \"000Ba00_\\n\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=165; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((0x5ebac630));\n    return +((-1.03125));\n    i0 = (i0);\n    (Int8ArrayView[4096]) = (((((/*FFI*/ff(((((0xe188ed97) / (0x21a5227)) ^ ((i0)))), ((-4503599627370496.0)), ((imul((0xb22b91c7), (0xffffffff))|0)))|0)*-0xf8efb) | ((0x6eb4417a)+((0xfce56fb0) == (((0xf134175f))>>>((0xffc9c47a)))))) == (0x4f70dd9))+(((z =  /x/g ))));\n    d1 = ((((~~(-2147483647.0)))) - ((((0x734d674) <= (((-0x8000000)+(0xff06a05c))|0)) ? (((-1.1805916207174113e+21)) * ((Float32ArrayView[((0xffffffff)) >> 2]))) : (-((1.9342813113834067e+25))))));\n    i0 = (0x8e6f4862);\n    i0 = (0xfc05e771);\n    i0 = (0x5f831821);\n    (Float32ArrayView[4096]) = ((-3.0));\n    i0 = ((0x0) > ((-0x7475f*(((((-1.25) >= (1023.0)))>>>(-(0x5a4f9172))) == (0xe5625688)))>>>((imul((0xfe48defe), (!(0xb2917727)))|0) % (((/*FFI*/ff(((abs((-0x39b85b5))|0)), ((2199023255553.0)), ((-9007199254740992.0)))|0)*0x92e0d)|0))));\n    d1 = (+(((0x34b5fae5) % (((Int32ArrayView[((0xfe07349b)) >> 2]))>>>((0x6782c42)-((0x133617ba))-(/*FFI*/ff(((34359738369.0)), ((1.0625)), ((295147905179352830000.0)), ((-1.5)), ((-17.0)), ((-4194304.0)), ((1.00390625)), ((32.0)), ((-295147905179352830000.0)), ((-7.555786372591432e+22)), ((-262145.0)), ((-295147905179352830000.0)), ((-576460752303423500.0)), ((-131073.0)), ((-1.5111572745182865e+23)), ((1.1805916207174113e+21)), ((257.0)), ((-7.737125245533627e+25)), ((137438953473.0)), ((72057594037927940.0)), ((-1.1805916207174113e+21)), ((-1152921504606847000.0)), ((1073741825.0)), ((-8589934593.0)), ((72057594037927940.0)), ((268435457.0)), ((-8388609.0)))|0)))) | ((0x37e98018))));\n    return +((((d1)) * ((-2097151.0))));\n  }\n  return f; })(this, {ff: (x) = Function.prototype.getTime}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [2**53, Math.PI, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, 0, 0x0ffffffff, -0x080000001, -1/0, 0x100000001, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 1/0, 42, 0/0, -0x100000000, 0x100000000, 0.000000000000001, -0x100000001, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), -(2**53), Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-45472219*/count=166; tryItOut("\"use strict\";  for  each(var c in  '' ) {s1 += this.s0;m2.set(s0, this.g1); }print(x);var b = (delete y.x);");
/*fuzzSeed-45472219*/count=167; tryItOut("h0.keys = f2;");
/*fuzzSeed-45472219*/count=168; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return (( - (y ? (( ! y) | 0) : ( - y))) | (((((Math.fround(y) % y) | 0) , Math.sign((y >>> ( ! (x >>> 0))))) | 0) > Math.fround(Math.tan(Math.fround((Math.hypot((Math.pow(x, ( + x)) | 0), Math.asinh((y / Math.imul(x, x)))) | 0)))))); }); testMathyFunction(mathy0, [1/0, Math.PI, -0x080000001, 0x100000000, -(2**53), 0x100000001, 0x080000001, -0x0ffffffff, 0.000000000000001, -0x080000000, 42, -Number.MIN_SAFE_INTEGER, 2**53-2, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 1, 0/0, -0x100000000, -(2**53-2), -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, 0, -0x07fffffff, 2**53, -1/0, 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-45472219*/count=169; tryItOut("/*hhh*/function oaqpfb(d, x){yield;}oaqpfb();");
/*fuzzSeed-45472219*/count=170; tryItOut("a2.valueOf = (function() { t1.toSource = (function mcc_() { var bhsqnq = 0; return function() { ++bhsqnq; f2(/*ICCD*/bhsqnq % 5 == 2);};})(); return m2; });");
/*fuzzSeed-45472219*/count=171; tryItOut("testMathyFunction(mathy3, /*MARR*/[true, true, x, x, true]); ");
/*fuzzSeed-45472219*/count=172; tryItOut("/*tLoop*/for (let x of /*MARR*/[1e4, 1e4, 1e4,  'A' ,  'A' , -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, 1e4,  'A' , 1e4,  'A' , 1e4, 1e4, 1e4,  'A' ,  'A' , 1e4,  'A' ,  'A' ,  'A' , -Infinity, 1e4, 1e4, 1e4,  'A' ,  'A' , 1e4,  'A' , 1e4, 1e4, 1e4, -Infinity, 1e4, 1e4,  'A' ,  'A' ,  'A' , -Infinity, 1e4, 1e4,  'A' , 1e4,  'A' , -Infinity,  'A' , -Infinity, -Infinity, -Infinity, 1e4, -Infinity, 1e4,  'A' , 1e4,  'A' ,  'A' , -Infinity, -Infinity, 1e4, 1e4,  'A' , -Infinity, -Infinity]) { (void schedulegc(g0)); }");
/*fuzzSeed-45472219*/count=173; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return ( - (Math.atan((Math.pow((Math.atan(( + Math.sin((Math.cosh((y >>> 0)) >>> 0)))) >>> 0), ((2**53-2 ? (Math.round((0x100000000 | 0)) | 0) : Math.hypot(Math.expm1((y >>> 0)), (( ! (x | 0)) | 0))) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -0x0ffffffff, -0x100000000, Math.PI, 1/0, 0x080000000, -(2**53), 2**53, 0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, 2**53-2, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53+2, -0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, 0, Number.MIN_VALUE, -0, -0x07fffffff, 0x100000001, 0x100000000, 42, -Number.MIN_VALUE, 0/0, 1.7976931348623157e308, -0x080000000, -0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=174; tryItOut("\"use strict\"; Array.prototype.push.call(a1);");
/*fuzzSeed-45472219*/count=175; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(f2, f2);");
/*fuzzSeed-45472219*/count=176; tryItOut("mathy4 = (function(x, y) { return Math.imul(mathy1((( ~ y) | 0), (( ! (x << y)) >= (( - ( - (Math.tan((x >>> 0)) >>> 0))) >>> 0))), Math.round(Math.cbrt(((( ~ (x >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy4, ['', [0], [], objectEmulatingUndefined(), (new Boolean(true)), (new String('')), false, (new Boolean(false)), (new Number(0)), ({valueOf:function(){return 0;}}), /0/, undefined, true, 0, ({valueOf:function(){return '0';}}), null, '/0/', 0.1, '\\0', -0, ({toString:function(){return '0';}}), (new Number(-0)), (function(){return 0;}), '0', 1, NaN]); ");
/*fuzzSeed-45472219*/count=177; tryItOut("let(b) { return;}");
/*fuzzSeed-45472219*/count=178; tryItOut("m1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      (Uint32ArrayView[4096]) = ((-0x8000000)-(i0));\n    }\n    {\n      {\n        i0 = ((~~(+pow((((Math.clz32(0x99)) / ((Float32ArrayView[0])))), ((Float32ArrayView[1]))))));\n      }\n    }\n    return (((!(i0))-((0xd4335fb0) < (((-0x8000000))>>>(((((0x8296531c))) <= (NaN))-(/*FFI*/ff()|0))))))|0;\nt0 = o1.t2.subarray(8, 14);    d1 = (+pow(((((((i0)) >> (((0x188874f4) < (0x4be19b40))))) ? (/*FFI*/ff(((~(((0x7fffffff) != (0xb58acee))+(0x98f97e0a)-((0x0) < (0x24e46881))))), ((((-0x8000000)*0x247db) << ((0x0) % (0x3b589168)))), ((d1)), (((x))), ((9223372036854776000.0)), ((2.3611832414348226e+21)), ((1.9342813113834067e+25)), ((3.022314549036573e+23)), ((17592186044417.0)), ((-288230376151711740.0)), ((131073.0)), ((16777216.0)), ((-274877906945.0)))|0) : (0x9ddbd8ab))), ((Float64ArrayView[(-((+(0.0/0.0)))) >> 3]))));\n    i0 = ((((~~(2251799813685249.0)) / (((0x67d260b7)-(0xdf83b33f)-(-0x8000000)) << (((-0x8000000) != (0xfb3aa))-(i0)))) >> (((((0x224bf298) / (0xfd843ac))>>>((i0))))-((d1) < (-262145.0))-(i0))) != (((i0)+(0xdf873ab0)) >> ((0xfc4954cc)-((((Uint32ArrayView[1])) | (((0x3b2cdfc4) >= (0x0)))))+(((yield x))))));\n    return ((((((0xdba93f58)+(i0)) | (((((-0x8000000)-(0xc7b1810a)-(0x747290cd))>>>((0x403fca81)+(0x2bace774)-(0x1a019371))) < (0x396956cd)))) >= (((i0)-(0xfd009598)+(i0)) & (((0x7122b14d) < (/*FARR*/[...[],  /x/ ].filter(Date.prototype.setMilliseconds, {}).acos(22.valueOf(\"number\"))))+((~((((0x9ca768ee)) << ((0x96b1f7b))) % (((0x563dc724)) << ((0x540ef687)))))))))))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096));");
/*fuzzSeed-45472219*/count=179; tryItOut("v0 = evaluate(\"for (var v of g0) { try { /*MXX1*/Object.defineProperty(this, \\\"o0\\\", { configurable: (x % 4 == 2), enumerable: (x % 3 == 2),  get: function() {  return this.g2.RangeError.prototype.message; } }); } catch(e0) { } try { a0.pop(); } catch(e1) { } try { a2.shift(); } catch(e2) { } neuter(this.b1, \\\"same-data\\\"); }\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 != 1), sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-45472219*/count=180; tryItOut("/*RXUB*/var r = /(?:(?:[]|.|[^][\u00cd-\u0011\\x2e-\\xf3\\\u0086\\r-\u48f2](?!(?=\\cR))*){0,4}|(?:(?![^\\cC-\u00c6\\u00FE\\s])+)(?:(?:(?!(?=$|.))\\D)))/gy; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-45472219*/count=181; tryItOut("\"use strict\"; a2[16];");
/*fuzzSeed-45472219*/count=182; tryItOut("");
/*fuzzSeed-45472219*/count=183; tryItOut("");
/*fuzzSeed-45472219*/count=184; tryItOut("let x, x, wwbbah;o2.a2.splice(NaN, 16);");
/*fuzzSeed-45472219*/count=185; tryItOut("t1.__proto__ = h1;");
/*fuzzSeed-45472219*/count=186; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=187; tryItOut("o2 = new Object;");
/*fuzzSeed-45472219*/count=188; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=189; tryItOut("testMathyFunction(mathy5, [-1/0, 2**53+2, -0x080000000, Math.PI, -0x0ffffffff, 0x100000001, 1/0, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, -0x100000000, 1.7976931348623157e308, 0x0ffffffff, -0, -Number.MIN_VALUE, -(2**53+2), 2**53-2, -Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 1, -(2**53), 42, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, 0x07fffffff, 0/0, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=190; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return ( + (Math.fround((Math.fround(Math.cbrt(Math.fround(Math.sign(x)))) <= Math.fround((Math.log2((((((x >>> 0) <= Math.imul(x, y)) < (y | 0)) >>> 0) | 0)) | 0)))) || (( - Math.fround(Math.hypot(Math.fround((Math.sign(Math.fround(x)) | 0)), Math.fround((Math.sin(x) | 0))))) >>> 0))); }); testMathyFunction(mathy3, [-0x100000000, -Number.MAX_VALUE, -(2**53-2), 0, 0x080000001, 0x07fffffff, -(2**53), 0x080000000, 0x100000000, -0x080000001, -Number.MIN_VALUE, -0x100000001, Math.PI, -(2**53+2), 0x100000001, 1/0, -0x080000000, 2**53-2, 2**53, 42, 1, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 0/0, Number.MIN_VALUE, 0.000000000000001, -0, Number.MAX_VALUE, -0x07fffffff]); ");
/*fuzzSeed-45472219*/count=191; tryItOut(";");
/*fuzzSeed-45472219*/count=192; tryItOut("g0 + e0;");
/*fuzzSeed-45472219*/count=193; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.min(((Math.imul((mathy3(y, (-0x080000001 >>> 0)) | 0), (x | 0)) | 0) ? (Math.atan2(y, (Math.exp(Math.fround(y)) | 0)) << mathy1(Number.MAX_SAFE_INTEGER, (x == y))) : Math.hypot(( + y), (y | 0))), (( + mathy2((y | 0), y)) ^  for ((new RegExp(\"(\\\\W[\\\\u00A6-\\\\u5912]?)|\\\\B?\", \"\").__proto__) in /*FARR*/[...[], new RegExp(\"(?:\\\\b[]{1}|\\\\B*?+)*\", \"gym\"), 16,  /x/g , new RegExp(\"\\\\B\", \"i\"), ].map(objectEmulatingUndefined)) for (\u3056 of mathy0) if (\"\\u0294\"))) << (Math.min(((mathy3((Math.log1p((Math.hypot(( + Math.fround((mathy2(x, x) >>> 0))), Math.log1p(y)) >>> 0)) >>> 0), (( + (x + x)) | 0)) | 0) | 0), (Math.fround(Math.cos(( + Math.pow((y | 0), Math.min(x, (Math.min((( ~ y) >>> 0), ((( + (y >>> 0)) >>> 0) >>> 0)) >>> 0)))))) >>> 0)) | 0)); }); testMathyFunction(mathy5, [0, '', (new Number(0)), objectEmulatingUndefined(), [], true, ({valueOf:function(){return '0';}}), 0.1, (function(){return 0;}), ({valueOf:function(){return 0;}}), '/0/', (new Boolean(true)), (new Number(-0)), ({toString:function(){return '0';}}), null, NaN, undefined, false, (new Boolean(false)), -0, [0], (new String('')), 1, /0/, '\\0', '0']); ");
/*fuzzSeed-45472219*/count=194; tryItOut("mathy1 = (function(x, y) { return ( ~ ( + Math.sign(( + (((Math.cos(( - (-Number.MAX_SAFE_INTEGER | 0))) >>> 0) | 0) % (( + (Math.fround(y) || Math.fround(x))) >>> 0)))))); }); testMathyFunction(mathy1, [-0x100000001, -(2**53), 2**53, -(2**53-2), 42, 0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -Number.MAX_VALUE, -0x0ffffffff, 0x100000000, 0.000000000000001, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, -0x080000000, -1/0, 1/0, 2**53-2, -Number.MIN_VALUE, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, 1, 0x080000000, 0x080000001, 0, -0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=195; tryItOut("a1.length = 9;");
/*fuzzSeed-45472219*/count=196; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use asm\"; return ((Math.cosh((((Math.hypot(Math.fround(( + 0/0)), Math.pow(( + Math.round(( + x))), y)) | 0) && (Math.log10(Math.abs(0x0ffffffff)) | 0)) | 0)) | 0) | Math.fround((Math.fround(((y + (Math.max(Math.pow(Math.fround(Math.fround(Math.sqrt(y))), y), x) >>> 0)) ? Math.fround(Math.log10(y)) : (( - (-Number.MIN_VALUE ? x : Math.min(0, x))) | 0))) >>> Math.fround(Math.max(x, x))))); }); testMathyFunction(mathy0, [2**53+2, -Number.MIN_VALUE, 0, -0x080000001, 42, -(2**53+2), 0x080000001, -0x080000000, 0x100000000, 0x07fffffff, -0, -Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, -(2**53-2), 0x100000001, 0/0, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, -(2**53), 0x0ffffffff, -0x100000001, Math.PI, 2**53-2, Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=197; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return Math.sinh(Math.fround(Math.max(Math.fround(mathy0(( + (Math.atan2((((((y | 0) / (x | 0)) | 0) <= x) | 0), (Math.fround(( ! Math.fround(mathy1(Math.fround(0x100000001), Math.fround(x))))) | 0)) | 0)), ( + ( - (Math.atan2((( - x) | 0), y) | 0))))), (( + Math.pow(( + ( ~ Number.MAX_VALUE)), ( + ( + Math.min(((Math.max((x | 0), -0x100000001) | 0) >>> 0), (( + Math.min((((x >>> 0) ^ (x >>> 0)) >>> 0), ( + y))) >>> 0)))))) >>> 0)))); }); testMathyFunction(mathy2, [-(2**53-2), -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, 1/0, -1/0, -0x080000001, -0x07fffffff, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, 0x100000000, 42, -Number.MIN_VALUE, -(2**53), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, -0x080000000, -0x100000001, -0x0ffffffff, -Number.MAX_VALUE, 0x100000001, 0x080000000, Math.PI, 0x080000001, 0, 0x0ffffffff, 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, 0/0]); ");
/*fuzzSeed-45472219*/count=198; tryItOut("/*MXX2*/g1.Float64Array.BYTES_PER_ELEMENT = m2;");
/*fuzzSeed-45472219*/count=199; tryItOut("o1.valueOf = (function mcc_() { var wozakr = 0; return function() { ++wozakr; if (/*ICCD*/wozakr % 11 != 2) { dumpln('hit!'); try { for (var p in i2) { try { e2.delete(f0); } catch(e0) { } try { Array.prototype.reverse.apply(a2, [v0]); } catch(e1) { } try { v2 = this.g2.t0.byteOffset; } catch(e2) { } e0.has(i0); } } catch(e0) { } print(s0); } else { dumpln('miss!'); v0 = (this.o0.v2 instanceof v1); } };})();");
/*fuzzSeed-45472219*/count=200; tryItOut("a1.sort((function(j) { if (j) { try { h0.set = (function(j) { if (j) { Array.prototype.forEach.apply(a1, [(function(j) { if (j) { try { selectforgc(o1); } catch(e0) { } try { v0 = (p0 instanceof m1); } catch(e1) { } try { this.v1 = t2.length; } catch(e2) { } print(uneval(s1)); } else { try { b1 = g2.t2.buffer; } catch(e0) { } try { t2.valueOf = Object.prototype.__defineSetter__.bind(p2); } catch(e1) { } Array.prototype.forEach.call(this.a1, (function() { try { s0 = new String(s2); } catch(e0) { } try { Array.prototype.unshift.call(a1, h2, p2, e0); } catch(e1) { } try { Array.prototype.shift.call(a2, /(?=\\2\\S\\B|$|(?=.{1})+?)\\D+?{0,2}/g, t2); } catch(e2) { } b1 + ''; return f0; }), f1, e0); } }), v0]); } else { try { v2 = (b0 instanceof s2); } catch(e0) { } try { t2[({valueOf: function() { h2 = o1;return 14; }})] = let (b =  /x/g .__defineSetter__(\"a\", mathy2).__defineSetter__(\"d\", ((new Function).apply).bind)) /*UUV2*/(y.getFullYear = y.setMonth); } catch(e1) { } try { e2 = a2[7]; } catch(e2) { } a0 = []; } }); } catch(e0) { } try { g2.__proto__ = this.f0; } catch(e1) { } print(e2); } else { try { print(h0); } catch(e0) { } v1 = Array.prototype.some.apply(a1, [(function() { try { this.v0 = g0.g0.runOffThreadScript(); } catch(e0) { } try { L: for (x of new RegExp(\"\\\\3+?\", \"gy\")) {print(x);print(x); } } catch(e1) { } try { Array.prototype.sort.apply(this.g1.a0, [a2]); } catch(e2) { } v1 + ''; return i0; }), this.t1]); } }));");
/*fuzzSeed-45472219*/count=201; tryItOut("");
/*fuzzSeed-45472219*/count=202; tryItOut("g1.offThreadCompileScript(\"function f1(o0.b0) \\\"use asm\\\";   var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    (Float64ArrayView[(((((0xffffffff)) >> ((0x8a8dc258))) < (~~(((2.3611832414348226e+21)) * ((-67108864.0)))))-(i1)+(!((((0xfbdc81f2))>>>((0xbe2de75c))) < (0xc2f578f6)))) >> 3]) = ((1.03125));\\n    return +((((+(((i0)-((((Int16ArrayView[2]))>>>((0x8132a150)-(0x1ae0fb61)+(0xff4552d1))) == (({eval: x}) > \\\"\\\\uA348\\\"\\n))) ^ ((({ set -26()x }))+(((((0xfab4cff8) == (0xc0e1e64c)))>>>(((Float64ArrayView[2]))*-0xf02d4)) >= (0xc9c95101))))))));\\n  }\\n  return f;\");");
/*fuzzSeed-45472219*/count=203; tryItOut("Array.prototype.splice.call(a1, NaN, (Math.asinh) ? (let (gowpud, eval, x, d, gcyyjk, lpignx, mbhtdu, rupugt, hvybgf) 18) : Object.defineProperty(x, \"get\", ({writable: -23, configurable: undefined})) >>= let (e = undefined) 1e+81.__proto__ = (4277), a2);");
/*fuzzSeed-45472219*/count=204; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = ((-68719476737.0) < (+/*FFI*/ff(((~~((i1) ? (-1.5111572745182865e+23) : (-2.4178516392292583e+24)))))));\n    i0 = (i0);\n    i2 = (i1);\n    {\n      return +((false));\n    }\n    i1 = ((0x8099b422));\n    return +((((Math.cbrt(x) ? ((Math.hypot(((Math.fround(x) + (x | 0)) | 0), (Math.hypot(Math.min(Number.MAX_VALUE, x), x) | 0)) != ( - x)) <= Math.fround(Math.max(Math.asin(2**53-2), ( - x)))) : Math.sin(Math.hypot(( ~ (0 >>> 0)), x))) >>> 0)));\n  }\n  return f; })(this, {ff: NaN}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, 0x080000000, 42, 0x100000001, -0x100000000, 2**53+2, -0x080000000, -1/0, -(2**53-2), 2**53-2, -0, -0x080000001, 1, Math.PI, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, 2**53, 0/0, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, 0x080000001]); ");
/*fuzzSeed-45472219*/count=205; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return mathy0(mathy0((mathy0(y, ( + (((Math.sin(y) ** (x <= -Number.MIN_SAFE_INTEGER)) >>> 0) < y))) >>> 0), Math.hypot((( + ( - x)) >>> 0), ( ! y))), let(x = (({ get length d ()\"use asm\";   var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    d1 = (d1);\n    {\n      (Int16ArrayView[((0xfa699c33)) >> 1]) = (((function factorial(ykhozs) { ; if (ykhozs == 0) { print((Math.max(4, 2)).eval(\"/* no regression tests found */\"));; return 1; } v1 = Object.prototype.isPrototypeOf.call(this.p0, i0);; return ykhozs * factorial(ykhozs - 1);  })(7160)));\n    }\n    d1 = (d1);\n    return (((i0)-(1)-(/*UUV1*/(x.preventExtensions = function(q) { return q; }))))|0;\n  }\n  return f;, /*toXFun*/toSource: function() { return this; } })).__defineSetter__(\"e\", function shapeyConstructor(aaxyel){\"use strict\"; { print(aaxyel); } this[\"prototype\"] = Math.max(({a1:1}), -9);{ h0.hasOwn = f0; } Object.defineProperty(this, \"prototype\", ({get: neuter, enumerable: false}));this[\"prototype\"] = (-1/0);for (var ytqrtvmoo in this) { }for (var ytqnbzdjy in this) { }return this; }) !== (c) = (eval-=y), eval = y, NaN, NaN = let (x =  '' ) w, b, ebhyft) ((function(){let(a) { with({}) try { let(y = /\\d+(?=.+?)(\u0084)?|\\3[^]/, eval, x, y, y, kcboke, ohvwfk, x) { ( '' );} } catch(y if  \"\" ) { for(let d in /*MARR*/[0x07fffffff, \"\\u83B7\", 0x07fffffff, 0x07fffffff, [undefined], [undefined], NaN, \"\\u83B7\", 0x07fffffff, \"\\u83B7\", [undefined], 0x07fffffff, 0x07fffffff, 0x07fffffff, new Boolean(false), 0x07fffffff, NaN, 0x07fffffff, [undefined], NaN, \"\\u83B7\", [undefined], 0x07fffffff, \"\\u83B7\", [undefined]])  } catch(w) { throw \u3056; } }})());); }); testMathyFunction(mathy1, [-0x0ffffffff, Number.MIN_VALUE, 0x080000000, 2**53, -0x07fffffff, -Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 0/0, 1, 0x0ffffffff, Math.PI, -0, -1/0, 0, 0.000000000000001, 0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 0x080000001, 1/0, 42, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, -0x100000001, -(2**53-2), -0x100000000, 0x100000001, -(2**53), Number.MAX_VALUE, 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-45472219*/count=206; tryItOut("\"use asm\"; o1 = e1.__proto__;print((Math.expm1(-17)));");
/*fuzzSeed-45472219*/count=207; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.max((mathy1((( - Math.fround(Math.ceil(Math.fround(Math.fround(( ~ Math.fround(y))))))) >>> 0), (((Math.sin(mathy2(x, Math.fround(mathy0(Math.fround(x), Math.fround(y))))) | 0) | Math.tan(Math.fround(Math.exp(x)))) >>> 0)) >>> 0), (Math.hypot(Math.asin(Math.fround((Math.fround((0x080000000 & -0x100000001)) >> Math.fround(Math.fround(( - Math.fround((x , y)))))))), (Math.min((Math.fround(( - (( + Math.log10(( + x))) >>> 0))) | 0), Math.trunc(Math.imul((x | 0), Math.fround(x)))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), Math.PI, 0x07fffffff, 0x100000000, 0x080000000, -0x100000000, -Number.MAX_VALUE, 42, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, 0, 2**53, -(2**53), 1.7976931348623157e308, Number.MIN_VALUE, -0x07fffffff, 0/0, 0x080000001, Number.MAX_VALUE, 0x0ffffffff, -0x100000001, 1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, -0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0, 2**53+2, 1]); ");
/*fuzzSeed-45472219*/count=208; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.exp(Math.fround(Math.tanh((0x07fffffff <= mathy4(Math.fround((Math.fround(x) < Math.fround(y))), ( + y)))))) >>> 0); }); ");
/*fuzzSeed-45472219*/count=209; tryItOut("print(a0);");
/*fuzzSeed-45472219*/count=210; tryItOut("{ void 0; fullcompartmentchecks(false); } s0 = g0.g0.t0[18];");
/*fuzzSeed-45472219*/count=211; tryItOut("(x);");
/*fuzzSeed-45472219*/count=212; tryItOut("/*tLoop*/for (let y of /*MARR*/[0x5a827999, 5.0000000000000000000000, objectEmulatingUndefined(), 0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x5a827999, 0x5a827999, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), 0x5a827999, 5.0000000000000000000000, objectEmulatingUndefined(), new Number(1), new Number(1), 0x5a827999, 0x07fffffff, 0x5a827999, 5.0000000000000000000000, 0x5a827999, 0x07fffffff, objectEmulatingUndefined(), 0x5a827999, 0x5a827999, 5.0000000000000000000000, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 0x07fffffff, 5.0000000000000000000000, 0x07fffffff, 0x07fffffff, 5.0000000000000000000000, 0x07fffffff, objectEmulatingUndefined(), 0x5a827999, 5.0000000000000000000000, 0x07fffffff, 0x07fffffff, 5.0000000000000000000000, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x5a827999, new Number(1), 5.0000000000000000000000, new Number(1), 0x5a827999, 0x5a827999, 0x07fffffff]) { print(([[]] =  /* Comment */null)); }");
/*fuzzSeed-45472219*/count=213; tryItOut("\"use strict\"; testMathyFunction(mathy1, [objectEmulatingUndefined(), 1, '0', (new String('')), '\\0', -0, [0], true, false, /0/, (new Number(-0)), (function(){return 0;}), null, [], 0.1, ({toString:function(){return '0';}}), (new Number(0)), ({valueOf:function(){return '0';}}), NaN, (new Boolean(false)), ({valueOf:function(){return 0;}}), '/0/', 0, '', (new Boolean(true)), undefined]); ");
/*fuzzSeed-45472219*/count=214; tryItOut("Object.defineProperty(o2, \"a1\", { configurable: false, enumerable: true,  get: function() {  return Array.prototype.map.call(a0, (function() { for (var j=0;j<10;++j) { f2(j%2==1); } })); } });");
/*fuzzSeed-45472219*/count=215; tryItOut("\"use strict\"; \"use asm\"; var m2 = new Map;");
/*fuzzSeed-45472219*/count=216; tryItOut("var yuizns = new SharedArrayBuffer(16); var yuizns_0 = new Uint8Array(yuizns); var yuizns_1 = new Int32Array(yuizns); yuizns_1[0] = -11; var yuizns_2 = new Float32Array(yuizns); print(yuizns_2[0]); yuizns_2[0] = 18; var yuizns_3 = new Uint32Array(yuizns); print(yuizns_3[0]); var yuizns_4 = new Int8Array(yuizns); yuizns_4[0] = 4; var yuizns_5 = new Uint8ClampedArray(yuizns); var yuizns_6 = new Int16Array(yuizns); print(yuizns_6[0]); var yuizns_7 = new Uint16Array(yuizns); yuizns_7[0] = -9; print(uneval(v1));/*RXUB*/var r = new RegExp(\"(\\\\w)(?!\\\\1){4}+?\", \"gyim\"); var s = \"_\"; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-45472219*/count=217; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.max(Math.atan2(Math.fround(Math.fround(Math.log1p(Math.max(0, x)))), Math.fround((Math.atan(Math.fround((Math.trunc((y >>> 0)) >>> 0))) >>> 0))), Math.fround(( - ((((( + Math.asin(y)) < Math.asin(x)) | 0) >= (( - ((((y | 0) ? (y | 0) : (y | 0)) | 0) >>> 0)) >>> 0)) | 0)))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -0x100000001, 42, 0.000000000000001, 0x080000001, 1/0, -0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0/0, -(2**53-2), -0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, Math.PI, 0, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 2**53, -1/0, 1.7976931348623157e308, Number.MIN_VALUE, 1, -0, -0x100000000, -Number.MAX_VALUE, 2**53+2, 0x100000000, -(2**53+2), 0x080000000, -(2**53)]); ");
/*fuzzSeed-45472219*/count=218; tryItOut("testMathyFunction(mathy2, /*MARR*/[this.__defineGetter__(\"x\", z =>  { return  ''  } ), {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, false, [Math.min(x, 1403930515.5)], false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, {}, {x:3}, {x:3}, {}, [Math.min(x, 1403930515.5)], [Math.min(x, 1403930515.5)], {x:3}, [Math.min(x, 1403930515.5)], [Math.min(x, 1403930515.5)], [Math.min(x, 1403930515.5)], false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, {}, {}, this.__defineGetter__(\"x\", z =>  { return  ''  } ), false, [Math.min(x, 1403930515.5)], {}]); ");
/*fuzzSeed-45472219*/count=219; tryItOut(";");
/*fuzzSeed-45472219*/count=220; tryItOut("mathy3 = (function(x, y) { return (mathy0((Math.fround(Math.sign(y)) * x), ( + Math.atan2((-1/0 > x), ( + (((x | 0) && (((((( + (y & Math.PI)) & Math.fround(( ~ Math.fround(x)))) | 0) == (x | 0)) | 0) | 0)) | 0))))) | ((Math.fround(Math.acosh((Math.exp((Number.MAX_SAFE_INTEGER | 0)) | 0))) / x) <= Math.hypot(( ! Math.log2(0.000000000000001)), Math.fround(mathy0((x ** x), ( + mathy2(( + ( ! x)), ( + (Math.atan(Math.fround(y)) != -(2**53-2)))))))))); }); ");
/*fuzzSeed-45472219*/count=221; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(( + mathy0(( + ( + 2**53+2)), (Math.pow(x, y) | 0)))), Math.fround((Math.min((( + ( + 0)) >>> 0), x) && (Math.pow((-Number.MAX_SAFE_INTEGER >= x), Math.tan((Math.fround(Math.PI) << Math.fround(-Number.MAX_VALUE)))) ? ( ~ (y >>> 0)) : Math.atan2(( ! x), (-(2**53-2) | 0))))))); }); ");
/*fuzzSeed-45472219*/count=222; tryItOut("/*hhh*/function gqaiyh(x, c, x, a = allocationMarker(), x, this, window, [], x, x, x, d, {}, e, x, y =  /x/ , d, d =  /x/g , x, b, x, c, window, e, eval, x =  '' , eval, window, x, e, x, x, x, b = \"\\uF81D\", x, window = new RegExp(\"(?=(?=\\\\1))\", \"gym\"), window, c, y, x = new RegExp(\"\\u2daa\", \"gyi\"), a, x, e, y, x, c, x, a, x, w, a, x, eval, y, w, x = \"\\u38AD\", x, window = \"\\u5241\", w, eval = c, w =  /x/ , x, x, x, e, NaN = d, e, x, x, w, c = -6, w = /\\3+?(.)+?|(?:.){4,4}|\u2847|[^]|\\s*|[^\u0009-\\cM\\u00Da]|\\1(?=\\1+?(?=\\0+?))\\1|.\ucca8{1}{0,4}|\\W|.{1}/y, a, setter, x, NaN, z, a, x = 3263931134, window, x, w, d, b, x, NaN =  /x/ , get, x, y, e = z, e, window, window, this.b, b, x){const a = \"\\u45D6\", fazdxw, shhoey, \u3056 = (Math.imul(false, [1])), x = x, adfpvb, eval = y, uwlrwb;(void schedulegc(g1));}/*iii*/Object.defineProperty(this, \"s0\", { configurable: yield null, enumerable: true,  get: function() {  return new String(v0); } });");
/*fuzzSeed-45472219*/count=223; tryItOut("\"use strict\"; m2.get(o0);");
/*fuzzSeed-45472219*/count=224; tryItOut("{let (azvpsw, w = x = undefined, x = Math.trunc( /x/g ), z = 20, mqbeag) { e0 = Proxy.create(h1, g0); } }");
/*fuzzSeed-45472219*/count=225; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Math.PI, 2**53-2, -0x080000001, 1/0, 0x0ffffffff, 0/0, 0x080000001, 42, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -1/0, 2**53+2, 1.7976931348623157e308, -0x100000001, -(2**53-2), 1, -0x080000000, 0x100000000, 0, 2**53, -(2**53+2), -0, 0x07fffffff, -0x100000000, -0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, 0x080000000]); ");
/*fuzzSeed-45472219*/count=226; tryItOut("/*RXUB*/var r = /\\B|^|\\1{4}3|(?!\\2)+/ym; var s = \"a\\n  1a\\n  1a\\n  1\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=227; tryItOut("\"use strict\"; v1 = this.g1.eval(\"this.m2 = new Map;\");");
/*fuzzSeed-45472219*/count=228; tryItOut("mathy0 = (function(x, y) { return ( + ( ! ( + ( + (( + ( + (( + Math.trunc(Math.fround(Math.hypot((Math.hypot(Number.MAX_SAFE_INTEGER, 0.000000000000001) >>> 0), Math.fround((x >= x)))))) || ( + (Math.sqrt(( + ( + -(2**53)))) | 0))))) , Math.log(((x * y) ** ( + Number.MIN_SAFE_INTEGER)))))))); }); testMathyFunction(mathy0, [(new Number(0)), -0, (new Boolean(true)), '\\0', NaN, (new Number(-0)), (new Boolean(false)), ({valueOf:function(){return '0';}}), false, undefined, [], objectEmulatingUndefined(), '', 0.1, (function(){return 0;}), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), [0], null, true, '/0/', '0', 0, (new String('')), 1, /0/]); ");
/*fuzzSeed-45472219*/count=229; tryItOut("Object.preventExtensions(h0);");
/*fuzzSeed-45472219*/count=230; tryItOut("f1 = (function() { for (var j=0;j<103;++j) { f1(j%4==0); } })\nh0 + m2;\nArray.prototype.pop.apply(a0, [h1]);\nlet x = (\u3056 = new RegExp(\"(?:[^])\", \"\"));");
/*fuzzSeed-45472219*/count=231; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.sign(Math.fround((mathy0((( ! (y | 0)) | 0), ( - -(2**53+2))) >= ( ! mathy1((( + (Math.fround(Math.PI) ? ( + ( + (x == y))) : ( + (( ~ Math.fround(( - x))) | 0)))) >>> 0), Math.fround(Math.exp(y)))))))); }); testMathyFunction(mathy3, [0.1, '0', true, (new Boolean(false)), objectEmulatingUndefined(), (new String('')), (function(){return 0;}), '/0/', 1, null, /0/, ({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return 0;}}), 0, [], '\\0', undefined, (new Boolean(true)), false, (new Number(0)), NaN, ({valueOf:function(){return '0';}}), '', -0, [0]]); ");
/*fuzzSeed-45472219*/count=232; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2\", \"i\"); var s = \"\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\\u0009\"; print(s.match(r)); ");
/*fuzzSeed-45472219*/count=233; tryItOut("a0 = a0.slice(NaN, NaN, o0, o2, s1, a1);");
/*fuzzSeed-45472219*/count=234; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( ! mathy3((Math.max(((((y % (y >>> 0)) << x) == ( ~ mathy3(x, x))) | 0), (Math.min((x >>> 0), ((( ~ (x | 0)) | 0) >>> 0)) >>> 0)) | 0), ((( + (( + x) % ( + y))) != ( + Math.hypot(( + (Math.abs((0x07fffffff >>> 0)) >>> 0)), y))) | 0))); }); testMathyFunction(mathy4, [-(2**53), -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -0, -1/0, -0x080000000, 2**53+2, Math.PI, 2**53-2, -0x100000000, 0x080000001, 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), -Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, 0, -(2**53-2), -0x07fffffff, 1/0, -0x100000001, Number.MIN_VALUE, 0.000000000000001, 2**53, 0x080000000, -Number.MIN_VALUE, -0x080000001]); ");
/*fuzzSeed-45472219*/count=235; tryItOut("\"use strict\"; this.v1 = evalcx(\"L:with({z: /((?!(\\\\u0096)|\\\\u45cB))?+/g}){s0 = new String(this.e0);Object.freeze(e1); }\", g0);");
/*fuzzSeed-45472219*/count=236; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan((Math.max((( + ( + ( + ( + Math.atanh(y))))) | 0), Math.hypot((Math.atan2(( + (x ^ x)), ( + Math.hypot(x, y))) >>> 0), ( + (Math.log1p(x) >>> (x >>> 0))))) | 0))); }); testMathyFunction(mathy5, [2**53-2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, -Number.MAX_VALUE, 0x100000001, 1/0, 0, 0x100000000, Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, -1/0, 2**53+2, -0, -0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -0x100000000, 1, -0x0ffffffff, 0x080000001, -0x080000001, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 42, 0.000000000000001, Math.PI, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -(2**53-2)]); ");
/*fuzzSeed-45472219*/count=237; tryItOut("v1 = Object.prototype.isPrototypeOf.call(this.h1, t2);");
/*fuzzSeed-45472219*/count=238; tryItOut("for (var p in o1.h0) { try { o0 = new Object; } catch(e0) { } try { /*MXX1*/g2.g0.o1 = g2.Object.getOwnPropertySymbols; } catch(e1) { } h2 = {}; }");
/*fuzzSeed-45472219*/count=239; tryItOut("\"use asm\"; v0 = (v2 instanceof p0);");
/*fuzzSeed-45472219*/count=240; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a2, 0, ({value: /(?=(?=^|$|^[^]?\\B){4,})/i, writable: false, configurable: true}));r1 = new RegExp(\"\\\\3+\", \"im\");");
/*fuzzSeed-45472219*/count=241; tryItOut("testMathyFunction(mathy3, [1, false, '\\0', [0], ({valueOf:function(){return '0';}}), (function(){return 0;}), (new Number(0)), '0', (new Number(-0)), (new Boolean(false)), NaN, '', 0, true, /0/, 0.1, objectEmulatingUndefined(), (new Boolean(true)), null, (new String('')), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '/0/', [], -0, undefined]); ");
/*fuzzSeed-45472219*/count=242; tryItOut("/*RXUB*/var r = /\\1/m; var s = \"E\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=243; tryItOut("/*vLoop*/for (let jhxtbq = 0; jhxtbq < 13; ++jhxtbq, [[1]]) { var d = jhxtbq; e0.delete(t2); } ");
/*fuzzSeed-45472219*/count=244; tryItOut("/*RXUB*/var r = /\\cN{0}[\\S\\B-\\xa4\\d]**?|(?=\\B|[^]+\\B*?)|\\2*?/g; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-45472219*/count=245; tryItOut("\"use strict\"; /*vLoop*/for (nkaccn = 0; nkaccn < 94; ++nkaccn) { let y = nkaccn; m1.set(m0, g2.i1); } ");
/*fuzzSeed-45472219*/count=246; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return ((( ! ( + Math.pow((x % x), ( + ( ! ( + y)))))) >>> 0) - Math.fround(( + Math.pow(( - (Math.atan((-0x080000000 | 0)) | 0)), (1 ? ( + Math.imul(( + x), ( + -Number.MIN_SAFE_INTEGER))) : ( - x)))))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 1, -0x080000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 42, 0x07fffffff, 0.000000000000001, 2**53+2, -Number.MAX_VALUE, 1.7976931348623157e308, -0, -0x100000001, 2**53, -0x100000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -0x080000000, -Number.MIN_VALUE, -(2**53-2), 0/0, 2**53-2, 0x100000000, Number.MIN_VALUE, -0x0ffffffff, -1/0, 0x080000000, 0, 1/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-45472219*/count=247; tryItOut("o2.v1 = Object.prototype.isPrototypeOf.call(e2, p1);");
/*fuzzSeed-45472219*/count=248; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+((+sqrt(((9007199254740992.0))))));\n    {\n      {\n        i1 = (!(i1));\n      }\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: let (c = this) false}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [1.7976931348623157e308, 1/0, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, -0x100000001, 0, 2**53-2, -0x07fffffff, Math.PI, -Number.MAX_VALUE, 0x100000001, -0x080000000, -0x100000000, -0, 0.000000000000001, 0x07fffffff, 1, Number.MAX_VALUE, 0x0ffffffff, -0x0ffffffff, 2**53, -1/0, -Number.MIN_VALUE, 0/0, 2**53+2, -(2**53+2), 42, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=249; tryItOut("for (var p in t2) { try { /*MXX2*/g0.Date.prototype.getDay = o1; } catch(e0) { } try { let v1 = evalcx(\"/*MXX1*/o0 = g2.Date.prototype.setFullYear;\\nm2 + '';\\n\", g1); } catch(e1) { } x = this.m0; }");
/*fuzzSeed-45472219*/count=250; tryItOut("new encodeURI();");
/*fuzzSeed-45472219*/count=251; tryItOut("testMathyFunction(mathy1, [({valueOf:function(){return 0;}}), undefined, ({toString:function(){return '0';}}), [0], (function(){return 0;}), (new Number(-0)), NaN, [], (new String('')), '0', 0.1, (new Boolean(false)), (new Number(0)), '', 0, -0, true, 1, '\\0', ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '/0/', null, /0/, (new Boolean(true)), false]); ");
/*fuzzSeed-45472219*/count=252; tryItOut("s0 += o2.s1;");
/*fuzzSeed-45472219*/count=253; tryItOut("\"use strict\"; testMathyFunction(mathy2, [1, 0x100000001, -(2**53-2), -1/0, Number.MAX_VALUE, 42, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -0, 0x080000001, 0x100000000, Math.PI, 0/0, 2**53+2, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -(2**53+2), -0x080000000, -Number.MIN_VALUE, 0x07fffffff, 0, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 0.000000000000001, -0x100000001, 1/0, 2**53]); ");
/*fuzzSeed-45472219*/count=254; tryItOut("print(null);function x({}, x = new RegExp(\"((.^+){2,2})\", \"\") &=  \"\" , x, x, e, x = new RegExp(\"(?=((\\\\B[^](?=[]))(?![^Z-\\\\x4f]).|\\\\cN+?[^]{1,32770}))\", \"i\"), c, y, x, b =  /x/g , b, a) { yield x++ } m1.has(b2);");
/*fuzzSeed-45472219*/count=255; tryItOut("return [].eval(\"(void options('strict'))\");");
/*fuzzSeed-45472219*/count=256; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(g0, h2);");
/*fuzzSeed-45472219*/count=257; tryItOut("m0 + m2;");
/*fuzzSeed-45472219*/count=258; tryItOut("/*vLoop*/for (dulxev = 0; dulxev < 138; ++dulxev) { let e = dulxev; h0.set = (function() { try { this.v2 = a1.length; } catch(e0) { } Object.defineProperty(this, \"v0\", { configurable: y, enumerable: /*UUV1*/(NaN.trimRight =  /x/ ),  get: function() { s1 += this.s2; return t1.length; } }); return a2; }); } ");
/*fuzzSeed-45472219*/count=259; tryItOut("e2.add(t2);/*bLoop*/for (var igybwk = 0; igybwk < 21; ++igybwk) { if (igybwk % 3 == 2) { o0.s2 += 'x'; } else { h0.getPropertyDescriptor = (function() { try { o1.v0 = this.g1.runOffThreadScript(); } catch(e0) { } try { g0.m0.get(p2); } catch(e1) { } try { for (var v of b1) { try { o0.a2[({valueOf: function() { print(28);return 0; }})]; } catch(e0) { } o1.o2.m0.get(\"\\u8C4E\"); } } catch(e2) { } print(o2); return g0; }); }  } ");
/*fuzzSeed-45472219*/count=260; tryItOut("testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 42, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, -Number.MIN_VALUE, -0x080000001, Number.MIN_VALUE, 0x07fffffff, 1/0, 0.000000000000001, -0x100000000, 0x100000001, 2**53, 2**53-2, 0, 0x080000001, 1.7976931348623157e308, 0x0ffffffff, 1, -0, Math.PI, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, 0/0, 0x080000000, -(2**53+2), 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-45472219*/count=261; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=262; tryItOut("var sxtyse = new SharedArrayBuffer(16); var sxtyse_0 = new Int16Array(sxtyse); var sxtyse_1 = new Float64Array(sxtyse); i2.next();print(sxtyse);f2 = (function() { try { t0[2] = []; } catch(e0) { } try { t2.toString = f0; } catch(e1) { } Array.prototype.reverse.apply(a0, [p2]); return h2; });");
/*fuzzSeed-45472219*/count=263; tryItOut("g1.offThreadCompileScript(\"function f2(h0) (/*RXUE*/new RegExp(\\\"(\\\\\\\\B.\\\\\\\\1{127,}|\\\\\\\\b)(\\\\\\\\b?)(?![^]{2})+?|[^]*\\\", \\\"\\\").exec(\\\"\\\"))()\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: Math.sqrt(x), noScriptRval: (x % 3 == 1), sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-45472219*/count=264; tryItOut("\"use strict\"; m2.set(o2.e2, i1);");
/*fuzzSeed-45472219*/count=265; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.log10(mathy1(Math.atan2(-(2**53+2), -0x080000001), y)) - Math.hypot(Math.fround(( ! Math.fround(Math.clz32(((-0x07fffffff | (Number.MAX_SAFE_INTEGER == (-0x100000000 ^ (0x100000000 | 0)))) >>> 0))))), Math.fround(( ~ ( + (mathy1((Math.clz32(( + Math.log10(((x ? (this >>> 0) : (x >>> 0)) >>> 0)))) | 0), (1 | 0)) | 0)))))); }); testMathyFunction(mathy2, [1, -(2**53), Number.MIN_SAFE_INTEGER, 0, 1/0, -0x080000001, -0x0ffffffff, 0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0x080000000, 2**53-2, 0x07fffffff, -1/0, 2**53, 42, -(2**53-2), Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 1.7976931348623157e308, 2**53+2, 0/0, 0x100000001, -Number.MAX_VALUE, Math.PI, -0x100000001, 0.000000000000001, -0, -0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=266; tryItOut("print(x);");
/*fuzzSeed-45472219*/count=267; tryItOut("\"use strict\"; v1 = t1.length\nreturn;");
/*fuzzSeed-45472219*/count=268; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( + ( - ( + (y !== mathy3(mathy3(( + x), ( + x)), (( ~ Math.fround(y)) | 0)))))) === Math.tan(Math.max((((((Math.fround(Math.fround(Math.fround((x === y)))) | 0) && (Math.atan2(( + x), (x | 0)) | 0)) | 0) ** (Math.fround(x) !== y)) >>> 0), y))); }); ");
/*fuzzSeed-45472219*/count=269; tryItOut("with({}) for(let a in new Array(20)) this.zzz.zzz;");
/*fuzzSeed-45472219*/count=270; tryItOut("for (var v of e1) { try { v2 = Array.prototype.every.apply(a2, [(function() { try { v0 = (t2 instanceof v0); } catch(e0) { } m2.has(f1); throw p2; }), t1]); } catch(e0) { } try { h1.delete = f2; } catch(e1) { } selectforgc(o2); }");
/*fuzzSeed-45472219*/count=271; tryItOut("o2.m0 = new Map(p2);");
/*fuzzSeed-45472219*/count=272; tryItOut("mathy2 = (function(x, y) { return (Math.max((Math.fround(Math.min(Math.fround(Math.fround(Math.atan2(( + -(2**53+2)), Math.fround((2**53+2 | ( ~ (x | 0))))))), Math.fround(Math.imul(Math.fround(( ! Math.min((x < x), x))), Math.fround(Math.fround((Math.fround((( - (( ! x) | 0)) | 0)) / -Number.MAX_SAFE_INTEGER))))))) >>> 0), ((((mathy0((Math.hypot(((x <= ( + mathy1(( + x), ( + (( - (-(2**53-2) | 0)) | 0))))) | 0), (x | 0)) | 0), Math.imul(x, y)) | 0) === Math.fround(Math.cos((x <= x)))) | 0) | 0)) >>> 0); }); testMathyFunction(mathy2, [0x100000000, -0x100000001, -0x080000000, 0x080000001, 2**53-2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000001, 0.000000000000001, 0, -(2**53-2), -0, 0x07fffffff, 1/0, Math.PI, -0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), -Number.MIN_VALUE, 42, -0x100000000, 0x0ffffffff, -1/0, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53)]); ");
/*fuzzSeed-45472219*/count=273; tryItOut("mathy2 = (function(x, y) { return ( + mathy0(( + mathy0(((((( + Math.exp(( + ( + (0x0ffffffff >>> 0))))) >>> 0) <= Math.asin(y)) >>> 0) == Math.abs(( ~ y))), Math.atan2((Math.hypot(0x080000000, x) | 0), (( ~ x) | 0)))), ( + (Math.max((((( + ( ! -Number.MIN_VALUE)) ? x : Math.hypot(-0x080000000, y)) * ((Math.log((y >>> 0)) >>> 0) ? ( - y) : y)) >>> 0), mathy0(Math.fround(Math.fround(Math.sqrt((y >>> 0)))), Math.fround(Math.expm1(x)))) % ( + mathy1(( + Math.fround(Math.log2((0x080000000 >>> 0)))), ( + Math.ceil(Number.MAX_SAFE_INTEGER)))))))); }); testMathyFunction(mathy2, [0x100000000, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, 0, -(2**53+2), Number.MIN_VALUE, -0x07fffffff, -0x080000000, Number.MAX_VALUE, 0x080000000, -0, -Number.MAX_VALUE, 1, 42, 2**53-2, -0x100000001, 2**53, -0x080000001, 2**53+2, -Number.MIN_VALUE, Math.PI, 0.000000000000001, 0x100000001, 0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), 1/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-45472219*/count=274; tryItOut("\"use strict\"; print(f2)\nprint(x);");
/*fuzzSeed-45472219*/count=275; tryItOut("x.constructor;");
/*fuzzSeed-45472219*/count=276; tryItOut("\"use strict\"; \"use asm\"; v1 = t1.length;");
/*fuzzSeed-45472219*/count=277; tryItOut("\"use strict\"; a2 = o2.t2[6];t0.set(t2, x ^= c);");
/*fuzzSeed-45472219*/count=278; tryItOut("mathy2 = (function(x, y) { return /*oLoop*/for (cnpfsw = 0; cnpfsw < 75; ++cnpfsw) { print((Math.imul(-25, 16))); } ; }); ");
/*fuzzSeed-45472219*/count=279; tryItOut("\"use strict\"; {x = b0;print(x); }");
/*fuzzSeed-45472219*/count=280; tryItOut("m1.has(g0);let (d =  /x/ , wrfptp, y) { print(x); }\ng0.v1 = g0.runOffThreadScript();\n");
/*fuzzSeed-45472219*/count=281; tryItOut("h1 = ({getOwnPropertyDescriptor: function(name) { i1.next();; var desc = Object.getOwnPropertyDescriptor(o1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { o1.i2.next();; var desc = Object.getPropertyDescriptor(o1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { b0.toSource = Object.keys.bind(e2);; Object.defineProperty(o1, name, desc); }, getOwnPropertyNames: function() { g1.v1 = this.o0.g0.objectEmulatingUndefined();; return Object.getOwnPropertyNames(o1); }, delete: function(name) { h1.iterate = f0;; return delete o1[name]; }, fix: function() { /*MXX1*/o2 = g2.String.prototype.toLocaleUpperCase;; if (Object.isFrozen(o1)) { return Object.getOwnProperties(o1); } }, has: function(name) { e0.add(e0);; return name in o1; }, hasOwn: function(name) { a2.unshift(t0, o1, t0);; return Object.prototype.hasOwnProperty.call(o1, name); }, get: function(receiver, name) { this.s2 += s2;; return o1[name]; }, set: function(receiver, name, val) { i1.send(o1);; o1[name] = val; return true; }, iterate: function() { a0[11] = /*MARR*/[[1], (-1/0), {}, (-1/0), (0/0), [1], (-1/0), [1], [1], [1], [1], [1], [1], (0/0), {}, (-1/0), {}, (0/0), [1], (0/0), [1], (-1/0), {}, {}, (0/0), (-1/0), (0/0), (-1/0), {}, {}, {}, [1], [1], [1], [1], (-1/0), (0/0), [1], (0/0), (0/0), (-1/0), (-1/0), [1], (0/0), [1], {}, (0/0), (-1/0), (-1/0), (0/0), {}, [1], (0/0), (-1/0), {}, (-1/0), (0/0), [1], {}, {}, (-1/0), {}, {}, (0/0), [1], [1], {}, (0/0), (-1/0), (-1/0), [1], {}, (0/0), [1], [1], (0/0), [1], [1]].sort(\"\\u9489\");; return (function() { for (var name in o1) { yield name; } })(); }, enumerate: function() { throw a2; var result = []; for (var name in o1) { result.push(name); }; return result; }, keys: function() { s1 + '';; return Object.keys(o1); } });");
/*fuzzSeed-45472219*/count=282; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=283; tryItOut("mathy2 = (function(x, y) { return (((mathy0((Math.pow((((x >>> 0) !== ((mathy0(Math.fround(x), (x | 0)) | 0) >>> 0)) >>> 0), (Math.acos(1) >>> 0)) >>> 0), (Math.pow(((y ? 0/0 : (x >>> 0)) ? y : x), ( + Math.acosh(( - y)))) >>> 0)) >>> 0) > ((Math.pow((( - Math.fround(Math.fround(( ! ( + Math.hypot(( + ( + (y >>> 0))), ( + -0x100000001))))))) >>> 0), (Math.acos(Math.asin(2**53)) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x07fffffff, 0/0, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 1/0, 1.7976931348623157e308, 2**53+2, 1, 0, -0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53, -(2**53-2), -1/0, -Number.MIN_VALUE, -0x0ffffffff, -(2**53), 0x0ffffffff, Math.PI, 0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, -0x080000001, -0x080000000, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 0x100000001]); ");
/*fuzzSeed-45472219*/count=284; tryItOut("v2 + '';v0 = evalcx(\"false;\", g2);\nfor (var p in t0) { g1.toString = (function() { for (var j=0;j<3;++j) { f0(j%4==0); } }); }\n");
/*fuzzSeed-45472219*/count=285; tryItOut("\"use strict\"; a0.push(f0);");
/*fuzzSeed-45472219*/count=286; tryItOut("m2.get(i0);");
/*fuzzSeed-45472219*/count=287; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 281474976710657.0;\n    var i3 = 0;\n    return +((() / ((d0))));\n    return +((Infinity));\n  }\n  return f; })(this, {ff: ([window])}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [Math.PI, 0x080000001, 0x080000000, -0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, -(2**53-2), Number.MAX_VALUE, -0x100000001, 42, 1, 0/0, -0x0ffffffff, -0x080000001, Number.MIN_VALUE, -(2**53), 2**53, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, -0, 2**53-2, 0x0ffffffff, 0x07fffffff, -(2**53+2), -1/0, 0x100000000, 1/0, -0x100000000, -0x07fffffff]); ");
/*fuzzSeed-45472219*/count=288; tryItOut("\"use strict\"; L: /*RXUB*/var r = -24; var s = \"\\n\\ub353\\nQ\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-45472219*/count=289; tryItOut("v0 = -0;");
/*fuzzSeed-45472219*/count=290; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.log10((Math.tanh(((( ! (x >>> 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy4, [null, NaN, (new Boolean(true)), '', '\\0', [], objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), /0/, -0, true, '0', ({valueOf:function(){return 0;}}), (new String('')), (new Boolean(false)), '/0/', 0, [0], 1, 0.1, false, (function(){return 0;}), (new Number(0)), undefined, (new Number(-0)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-45472219*/count=291; tryItOut("{ void 0; void relazifyFunctions('compartment'); }");
/*fuzzSeed-45472219*/count=292; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.cosh(Math.fround(mathy1(Math.fround(Math.atan2((Math.fround(( ~ (x | 0))) | 0), Math.fround(Math.imul(Math.fround((( ~ Math.asinh(( + ( - x)))) >>> 0)), x)))), ( + Math.pow((y - ( + Math.fround(( + mathy4(( + y), ( + 0x080000000)))))), ( + Number.MIN_VALUE))))))); }); testMathyFunction(mathy5, [Math.PI, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, -0x0ffffffff, -(2**53-2), 0, 1, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, -1/0, 2**53, -0x080000001, -0x100000000, 2**53-2, 0/0, -(2**53), 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, -(2**53+2), 0x080000000, -0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, 0x080000001, 1/0, 42, 0x100000000, -0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-45472219*/count=293; tryItOut("a0.unshift(s2, t2, this.a0);");
/*fuzzSeed-45472219*/count=294; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.cbrt(mathy3(Math.fround(Math.atan2(x, y)), (( + (0 >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-45472219*/count=295; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.hypot(Math.fround((Math.fround(mathy0(mathy0((-Number.MAX_SAFE_INTEGER / Math.fround(x)), ((Math.exp((x | 0)) | 0) & x)), Math.fround(( ~ ((((Math.exp(x) | 0) ^ (((y ** Math.fround(x)) | 0) | 0)) | 0) >>> 0))))) !== (( - Math.expm1(Number.MIN_SAFE_INTEGER)) >>> 0))), ((mathy0(Math.atan2(( ! ( - Math.fround((y * y)))), Math.fround((y >> Math.fround(0x100000001)))), (1.7976931348623157e308 - ((((y >>> 0) <= (Number.MIN_VALUE >>> 0)) >>> 0) >> x))) | 0) >> (((( + Math.acos(( + x))) >>> 0) ? (x >>> 0) : (((Math.cosh(x) >>> 0) === (x >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [-0, -0x080000000, -0x07fffffff, -(2**53-2), 0/0, -0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, 0, 0x080000001, -1/0, 1, 0x080000000, -0x100000001, 0x0ffffffff, 0x100000001, 2**53-2, Number.MAX_VALUE, 0.000000000000001, 0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 2**53+2, 1/0, 2**53, -(2**53), 1.7976931348623157e308]); ");
/*fuzzSeed-45472219*/count=296; tryItOut("a1 = r2.exec(s1);");
/*fuzzSeed-45472219*/count=297; tryItOut("b2.toString = (function mcc_() { var xrxvrd = 0; return function() { ++xrxvrd; if (/*ICCD*/xrxvrd % 7 == 0) { dumpln('hit!'); try { ; } catch(e0) { } g2.v0 = Object.prototype.isPrototypeOf.call(a0, b2); } else { dumpln('miss!'); selectforgc(o2); } };})();");
/*fuzzSeed-45472219*/count=298; tryItOut("selectforgc(o2);const c = (Math.expm1((-0x100000000 | 0)) | 0);");
/*fuzzSeed-45472219*/count=299; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-1/0, 0x07fffffff, -(2**53-2), 0.000000000000001, -0x07fffffff, 0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, 0, Math.PI, -0, -0x0ffffffff, -0x080000001, 1, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), 2**53+2, 0x080000000, 2**53-2, 42, 0x100000000, 1/0, Number.MIN_VALUE, 0x100000001, 2**53, -Number.MAX_VALUE, -0x100000001]); ");
/*fuzzSeed-45472219*/count=300; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.fround((Math.min((( + Math.log1p(Math.hypot(y, x))) | 0), ( ~ Math.tan(y))) ^ Math.max(Math.min(( + (x === -Number.MAX_VALUE)), (( ! ( + y)) | 0)), Math.imul(Math.fround(mathy1(Math.fround(0x080000001), Math.fround((Math.atan2(x, x) | 0)))), ( + ( ~ ( + x))))))); }); testMathyFunction(mathy3, [2**53, -1/0, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53-2), -Number.MAX_VALUE, -0x080000001, 1/0, -0x100000001, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, -0, -0x07fffffff, 0.000000000000001, 0x100000001, Number.MIN_VALUE, 0, 0x07fffffff, 42, -0x080000000, 0/0, 1, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -0x0ffffffff, 2**53-2, -0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-45472219*/count=301; tryItOut("let (c) { o1.v0 = g1.a1.reduce, reduceRight((function(a0, a1, a2, a3, a4, a5, a6) { c = 0 + 2; var r0 = a3 & a3; var r1 = 0 % x; x = a3 ^ a5; var r2 = a5 - a6; print(a2); var r3 = 2 + a6; var r4 = a1 & x; var r5 = a5 ^ a4; var r6 = 9 ^ 6; r4 = 5 ^ 7; print(r0); var r7 = r6 - 4; a3 = r5 * r2; r7 = 2 & a4; var r8 = x - r7; var r9 = 1 * 4; var r10 = c / r6; var r11 = r9 & a5; r7 = r6 ^ 5; var r12 = r3 + 4; r11 = r5 | c; r8 = 7 / a3; a2 = a4 * a0; r7 = a3 & x; var r13 = 2 / r4; var r14 = 9 - r9; var r15 = 1 & r7; r1 = r13 + r15; var r16 = c + r0; r3 = r4 + a0; var r17 = r4 / 9; var r18 = 1 / 6; var r19 = r1 - r12; print(r15); var r20 = r11 * r18; var r21 = 8 & 2; var r22 = r16 + a2; var r23 = a2 | r3; var r24 = r13 + r4; var r25 = r4 ^ 7; r6 = r17 * 9; var r26 = 3 & r3; var r27 = r26 ^ 0; r26 = 8 - r20; r20 = r12 & 4; var r28 = 7 & x; var r29 = r26 - c; var r30 = 9 + r16; var r31 = r13 % r4; var r32 = 0 - 1; var r33 = r26 % a2; r7 = r18 | r30; var r34 = r0 - r19; a4 = 6 | 1; var r35 = a0 + r6; var r36 = r6 ^ r35; var r37 = r2 | r18; var r38 = r20 - 7; r38 = r10 * 9; var r39 = a5 % 4; var r40 = a0 | r7; var r41 = r37 * r23; var r42 = r28 - r23; var r43 = 5 + 1; var r44 = r6 | 4; var r45 = 3 % r7; r13 = r35 / 1; var r46 = r31 ^ r17; var r47 = 9 - r16; var r48 = r7 ^ 0; var r49 = r5 & r44; var r50 = r41 & r1; r49 = r38 % r27; r9 = r45 + 9; var r51 = r5 | 1; var r52 = r12 ^ 7; var r53 = 0 - r50; var r54 = a0 + r6; var r55 = 4 ^ 3; r28 = r52 | r14; r29 = 6 / 8; var r56 = r29 - r43; var r57 = r26 % r12; var r58 = 0 / 2; var r59 = 7 % 6; var r60 = 9 | r54; var r61 = 6 * r0; var r62 = r51 % r8; r52 = 3 & r58; var r63 = 6 ^ r3; var r64 = r19 + r10; var r65 = r24 % r44; r37 = 1 - 3; var r66 = r4 / r9; r3 = 8 * r55; r48 = r15 + r32; var r67 = 4 % 0; var r68 = 6 + a5; var r69 = r52 * 0; var r70 = a0 / 9; var r71 = a4 ^ r3; var r72 = r27 % r60; r63 = r17 % 1; var r73 = r17 - 7; var r74 = a4 ^ r28; var r75 = r9 % 6; r74 = r71 / r66; var r76 = 0 | r67; r40 = r44 / 1; r61 = a4 ^ r59; r62 = 9 - 9; var r77 = r28 * r68; var r78 = r33 % 1; r44 = r59 + 8; var r79 = 3 / r13; var r80 = r18 * a4; var r81 = 7 - r9; var r82 = r56 * r68; var r83 = r13 * 5; var r84 = 9 - 7; var r85 = r84 * r84; var r86 = r38 | 7; var r87 = a0 + r9; r11 = r47 + a0; r1 = 8 & r40; var r88 = r30 + 4; r53 = r1 * 3; var r89 = 2 & r67; print(r43); var r90 = 0 & 1; var r91 = r87 * r28; var r92 = r34 - r72; var r93 = 7 % a2; var r94 = r48 / r67; print(r75); var r95 = r5 * r84; var r96 = r76 / 6; var r97 = r50 / r35; var r98 = r35 + x; var r99 = 2 - r4; var r100 = 3 % r64; a3 = r99 / 2; r100 = 0 | r34; var r101 = r57 / r44; var r102 = r45 & 6; var r103 = 5 / r85; var r104 = r46 ^ r93; var r105 = r1 & r23; var r106 = r49 / r49; r57 = r96 % 1; var r107 = 4 + 1; var r108 = 2 | r85; r91 = r61 % r74; var r109 = r39 - c; r90 = 9 % r102; r89 = r23 - r11; var r110 = r36 - r67; r99 = r26 & 4; var r111 = r13 & 4; var r112 = r41 * r49; var r113 = 5 * x; var r114 = 4 & c; var r115 = r95 * 7; r28 = 0 | r73; return a3; }), i2, b1, g0.e0, f1); }");
/*fuzzSeed-45472219*/count=302; tryItOut("\"use strict\"; pvpslh();/*hhh*/function pvpslh(){print(x);}");
/*fuzzSeed-45472219*/count=303; tryItOut("\"use strict\"; ;");
/*fuzzSeed-45472219*/count=304; tryItOut("i2 = new Iterator(i0, true);");
/*fuzzSeed-45472219*/count=305; tryItOut("\"use strict\"; v0 = (h0 instanceof v1);");
/*fuzzSeed-45472219*/count=306; tryItOut("\"use strict\"; s1 = new String(g0.o0.t1);");
/*fuzzSeed-45472219*/count=307; tryItOut("/*RXUB*/var r = r2; var s = s0; print(uneval(r.exec(s))); ");
/*fuzzSeed-45472219*/count=308; tryItOut("\"use strict\"; e0.add(p2);");
/*fuzzSeed-45472219*/count=309; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, 0x100000001, 1/0, 0.000000000000001, 0x080000000, -0x080000001, 0/0, 0, Math.PI, 2**53, -(2**53-2), -0x0ffffffff, -(2**53), Number.MIN_VALUE, 2**53+2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, -0, Number.MAX_VALUE, 2**53-2, -1/0, 0x100000000, 0x07fffffff, 1, 42]); ");
/*fuzzSeed-45472219*/count=310; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.max(( + Math.fround(Math.hypot(((((y == ((x >>> 0) + y)) ? (Math.acosh(-0x080000000) >>> 0) : -0x080000000) | 0) >> (Math.fround(( - y)) | 0)), Math.imul((( ! Math.fround(Math.imul(0/0, ( + Math.cbrt(Number.MIN_SAFE_INTEGER))))) ? x : (y >>> y)), Math.log(((mathy3(0x07fffffff, Math.fround(x)) ** (( + (x >>> 0)) >>> 0)) | 0)))))), ( + Math.fround(( + (( ! ((( ! (y | 0)) + y) >>> 0)) | 0)))))); }); testMathyFunction(mathy5, [0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, Number.MAX_VALUE, 0x080000000, -0x080000001, -(2**53), -1/0, 42, -0, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, 1/0, 0/0, Number.MIN_VALUE, 0, 2**53, 2**53+2, 0x0ffffffff, 0x07fffffff, -(2**53+2), 1, 2**53-2, 0.000000000000001, -0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-45472219*/count=311; tryItOut("print(x);");
/*fuzzSeed-45472219*/count=312; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -1.0078125;\n    var d4 = 4398046511103.0;\n    d3 = (+(((i0)) << ((((i1)*-0x20ecc) & (((4294967296.0) < (+(-1.0/0.0))))) % (imul(((((-0x8000000)) ^ ((0xfc3283e6)))), ((((0x46dbf4b6))>>>((0xf5a68d51))) != (((-0x8000000))>>>((0x5e7485fb)))))|0))));\n    i1 = (i1);\n    (Float32ArrayView[((i1)-(/*FFI*/ff(((+(0.0/0.0))), ((~((0x19733b90) % (0x8a5b0640)))))|0)-((((0xfbdc9b3a)) >> ((0x133af351))) < (0x5782bf5b))) >> 2]) = ((Infinity));\n    return ((((((i2) ? ((0xc716edb6) >= (((!(0x4a4145a3)))>>>(0xb1393*(0xfae167e2)))) : (i0))) != (d3))))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-45472219*/count=313; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [[0], 0.1, 1, objectEmulatingUndefined(), null, [], '\\0', '/0/', (new Number(-0)), true, ({valueOf:function(){return 0;}}), /0/, 0, '', undefined, -0, (new Boolean(true)), ({valueOf:function(){return '0';}}), (new String('')), '0', NaN, ({toString:function(){return '0';}}), (new Boolean(false)), (function(){return 0;}), (new Number(0)), false]); ");
/*fuzzSeed-45472219*/count=314; tryItOut("\"use strict\"; i0.toString = f1;");
/*fuzzSeed-45472219*/count=315; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.imul((Math.fround(Math.pow(( + Math.expm1((Math.sqrt(Math.imul(-0, x)) >>> 0))), Math.fround(Math.imul(((((((Math.atan2(x, 2**53) | 0) ? (x | 0) : (42 | 0)) | 0) | 0) + Math.fround((Math.fround(x) , Math.fround(((y ** x) | Math.sign(x)))))) | 0), x)))) >>> 0), Math.fround((Math.fround(( + Math.ceil(( + Math.atan2((x | x), y))))) ? Math.round((Math.max(x, y) | 0)) : Math.fround(( - ( + Math.imul(( + x), ( + Math.min((Math.pow(x, ( + y)) | 0), ( + Math.fround(y))))))))))); }); testMathyFunction(mathy0, /*MARR*/[ '' ,  '' , true,  '' ,  '' , NaN,  '' , NaN,  '' ,  '' , true,  '' , NaN, true, true, true,  '' , true, true,  '' ,  '' , true,  '' , true, true,  '' , true,  '' , true, true,  '' , true,  '' , NaN, true, NaN,  '' ,  '' , true, true, NaN, NaN, NaN, NaN, NaN, NaN,  '' ,  '' , NaN, true,  '' ,  '' , true,  '' ,  '' , NaN, true, true, true,  '' ,  '' ,  '' ,  '' , NaN,  '' , NaN, NaN,  '' , NaN, NaN, NaN, NaN, true, NaN, true, true,  '' , NaN, NaN,  '' ,  '' ,  '' , true,  '' ,  '' ,  '' ,  '' , NaN, NaN,  '' ]); ");
/*fuzzSeed-45472219*/count=316; tryItOut("\"use strict\"; function f1(o0) [1]");
/*fuzzSeed-45472219*/count=317; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (mathy0(( + mathy0(-(2**53+2), ( + x))), ( + (( + x) < Math.tan(Number.MAX_VALUE)))) & (Math.max((Math.fround((Math.fround(( + Math.min(Math.ceil(y), ( + y)))) / Math.fround(( ! (2**53 ** (( ~ y) | 0)))))) | 0), ( + Math.hypot((x - ((Math.fround(x) == x) | 0)), (( + (( + y) | ( + x))) >>> 0)))) | 0)); }); testMathyFunction(mathy3, [-0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, Math.PI, 42, 1, 0x080000001, 2**53-2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, 0, 0x100000001, 0.000000000000001, -0x100000000, -0x07fffffff, 0x07fffffff, 0/0, -0x080000000, -Number.MIN_VALUE, -0, 2**53+2, Number.MAX_VALUE, 2**53, 0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, -(2**53), 0x080000000, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=318; tryItOut("\"use strict\"; Object.prototype.watch.call(this.g0, \"__iterator__\", f0);");
/*fuzzSeed-45472219*/count=319; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 33.0;\n    var d3 = -7.737125245533627e+25;\n    (Int32ArrayView[((!(0x34162e29))+((~~(d2)) > (abs((((0xffffffff)) & ((0xfc3e46d4))))|0))) >> 2]) = ((0x69359894)+(i1));\n    return (((0xffffffff)+((d0) > (+(((0xffffffff))>>>(((0x0))))))-((0x39c9250f) ? (!(((-0x644a5*((0xa121e7a5) < (0xd2ab2538)))|0))) : (((((0xffffffff)) ? (allocationMarker()) : (i1))-(i1))))))|0;\n  }\n  return f; })(this, {ff: (new Function).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [2**53+2, -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, Number.MIN_VALUE, 0, 42, 0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, -0x100000000, 0x100000001, -(2**53+2), -1/0, -(2**53-2), 0.000000000000001, 2**53, 0x0ffffffff, -0x100000001, -0x0ffffffff, 1/0, Number.MAX_VALUE, 0x100000000, 1, Math.PI, -0, 0x080000001, -Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-45472219*/count=320; tryItOut("var gfyzaa, y = Object.defineProperty(x, \"toFixed\", ({value: -23, enumerable: true})), ynpama, x =  /x/ , siloch, x, sydmdu, a, d, x;/*tLoop*/for (let e of /*MARR*/[0x3FFFFFFE, \"\\uC36B\", Number.MAX_SAFE_INTEGER, \"\\uC36B\", Number.MAX_SAFE_INTEGER, (void 0), Number.MAX_SAFE_INTEGER, (void 0), (-1/0), (void 0), (void 0), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, (void 0), 0x3FFFFFFE, Number.MAX_SAFE_INTEGER]) {  '' ; }");
/*fuzzSeed-45472219*/count=321; tryItOut("const a = x;a2.push(m2, this.a2, {a} =  /* Comment */(p={}, (p.z = \"\\uBBDE\")()),  \"\" .__defineSetter__(\"b\", a));");
/*fuzzSeed-45472219*/count=322; tryItOut("a0.sort((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15) { var r0 = 5 % 7; print(a12); var r1 = a5 / 7; var r2 = a2 | a3; var r3 = a2 | a10; a10 = 3 - 8; var r4 = a13 | 6; var r5 = 6 - r3; var r6 = a5 | a15; var r7 = a7 * r1; r2 = 4 + a10; r3 = a6 ^ r2; var r8 = r3 / r0; var r9 = a10 * r8; print(a2); var r10 = a15 - a13; var r11 = a10 + r7; print(a7); var r12 = 0 + a3; var r13 = r7 | 6; a7 = r13 + a11; var r14 = a5 / 2; var r15 = 7 * r6; var r16 = x * a4; var r17 = 9 + 2; var r18 = a3 & r2; var r19 = a6 - r6; var r20 = 5 / r4; var r21 = 0 ^ a13; var r22 = a12 * 1; r21 = r18 / r19; a9 = r18 % r17; var r23 = r1 & a9; var r24 = r22 & a9; a15 = r23 / a2; var r25 = r8 ^ a14; r1 = 7 | 0; r2 = 2 & 5; var r26 = r5 & a7; r21 = r0 * r15; var r27 = 2 | a0; var r28 = 0 - a4; var r29 = a4 * r8; var r30 = 8 + r23; var r31 = a5 / a14; var r32 = r2 & x; var r33 = 5 * 2; r18 = a11 | r20; var r34 = 0 ^ r29; var r35 = 9 - 0; var r36 = r9 & a4; var r37 = 9 + a10; var r38 = r33 - 3; var r39 = r30 * r21; var r40 = a5 - r37; var r41 = 2 * r10; var r42 = r6 & 2; var r43 = 2 - r36; return a12; }));");
/*fuzzSeed-45472219*/count=323; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"(([, {x, b, x, eval: []}, {c}] = x))\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: Math.pow(eval != x, (void version(170))).yoyo(yield Math) }));");
/*fuzzSeed-45472219*/count=324; tryItOut("testMathyFunction(mathy4, [-0x100000000, 0x100000001, -Number.MAX_VALUE, 0x100000000, 2**53+2, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, -0, -0x100000001, 2**53, -1/0, 0/0, 1, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, -0x080000001, 42, 2**53-2, 1/0, 0, -(2**53), 1.7976931348623157e308, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000]); ");
/*fuzzSeed-45472219*/count=325; tryItOut("\"use strict\"; a0 = arguments.callee.caller.caller.caller.caller.arguments;");
/*fuzzSeed-45472219*/count=326; tryItOut("\"use strict\"; /*hhh*/function wrfeel(){/*MXX2*/g0.RegExp.$7 = e0;}wrfeel(({c: allocationMarker(), \"20\": (z = \"\\u78E6\") }));");
/*fuzzSeed-45472219*/count=327; tryItOut("v0 = (b0 instanceof e1);");
/*fuzzSeed-45472219*/count=328; tryItOut("/*RXUB*/var r = /\\1{1,4}/im; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=329; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.cbrt(((( - ( + mathy1(( + (Math.sign((Math.max((( ! 2**53-2) >>> 0), (x >>> 0)) | 0)) | 0)), Math.fround(( ! Math.atan2(Math.fround(Math.fround(Math.cbrt(( + y)))), mathy1(( + x), 2**53-2))))))) >>> 0) | 0)); }); testMathyFunction(mathy4, [0, 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 1, -0, -0x080000000, 0x100000001, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 2**53, 0x100000000, -(2**53+2), 1.7976931348623157e308, 2**53+2, 2**53-2, 0x080000000, Math.PI, -Number.MAX_VALUE, -0x100000001, -(2**53-2), 0/0, 0x0ffffffff, -0x080000001, 42, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff]); ");
/*fuzzSeed-45472219*/count=330; tryItOut("/*RXUB*/var r = r0; var s = s0; print(s.split(r)); ");
/*fuzzSeed-45472219*/count=331; tryItOut("\"use strict\"; for (var p in b1) { try { for (var p in this.v0) { try { m2.delete(o2.i1); } catch(e0) { } try { f1 = Proxy.createFunction(h2, f2, o0.f1); } catch(e1) { } try { x = g0; } catch(e2) { } i2.next(); } } catch(e0) { } v0 = v0[\"getPrototypeOf\"]; }");
/*fuzzSeed-45472219*/count=332; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(g0, h2);function x() { yield Math.imul((/*UUV2*/(x.entries = x.tan)), 28) } /*tLoop*/for (let c of /*MARR*/[true, d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,]), new String('q'), true, d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,]), d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,]), new String('q'), true, true, (void shapeOf(undefined)), d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,]), new String('q'), d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,]), true, (void shapeOf(undefined)), new String('q'), new String('q'), (void shapeOf(undefined)), d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,]), d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,]), new String('q'), (void shapeOf(undefined)), (void shapeOf(undefined)), true, d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,]), true, d = Proxy.create(({/*TOODEEP*/})([[1]]), [z1,,])]) { /*ODP-1*/Object.defineProperty(m2, 5, ({configurable: (x % 8 != 0), enumerable: \"\\u9CC3\"})); }");
/*fuzzSeed-45472219*/count=333; tryItOut("\"use strict\"; e1.delete(g2.f1);");
/*fuzzSeed-45472219*/count=334; tryItOut("s1 = '';");
/*fuzzSeed-45472219*/count=335; tryItOut("o0.v0 = a2[new String(\"6\")];");
/*fuzzSeed-45472219*/count=336; tryItOut("h2 = g0.objectEmulatingUndefined();");
/*fuzzSeed-45472219*/count=337; tryItOut("mathy4 = (function(x, y) { return (Math.min((Math.fround((Math.hypot(( + x), (( ~ x) | 0)) && Math.sqrt((x !== ((( + x) % (((y >>> 0) ** (Math.sinh(-Number.MAX_VALUE) >>> 0)) >>> 0)) >>> 0))))) >>> 0), (Math.fround(Math.clz32(Math.fround(Math.pow(1.7976931348623157e308, ( - x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-1/0, -Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, 2**53+2, -0x080000000, 0, -0x080000001, -(2**53+2), 0x07fffffff, -0x100000000, 2**53-2, Number.MIN_VALUE, 0x0ffffffff, 1, Number.MAX_VALUE, 1.7976931348623157e308, 1/0, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 0x100000001, -(2**53-2), Math.PI, -0, 2**53, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 42, 0x080000000, 0x080000001, 0x100000000, 0.000000000000001]); ");
/*fuzzSeed-45472219*/count=338; tryItOut("/*infloop*/while(x | y = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: objectEmulatingUndefined, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return true; }, get: mathy5, set: function() { return true; }, iterate: undefined, enumerate: function(y) { return  \"\"  }, keys: function() { return []; }, }; })(\"\\u15FD\"), function(y) { s1 + ''; })){selectforgc(o1); }");
/*fuzzSeed-45472219*/count=339; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.log1p(((Math.atan2((( ! Math.sinh(( + Math.atan2(( + Math.clz32(Number.MAX_VALUE)), ( + x))))) >>> 0), ((((Number.MAX_SAFE_INTEGER - x) | 0) >= Math.log2(((Math.fround(x) / (Math.fround(( - Math.fround(Number.MAX_SAFE_INTEGER))) >>> 0)) >>> 0))) | 0)) >>> 0) | 0)); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, 2**53, -Number.MIN_VALUE, Math.PI, 0x080000000, 2**53-2, -0x100000000, 0x0ffffffff, 0/0, 0x07fffffff, -(2**53-2), 42, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, Number.MAX_VALUE, -1/0, 1.7976931348623157e308, 0, -0x080000000, -(2**53+2), -0x100000001, -0x0ffffffff, 1, -0, -0x07fffffff, 1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-45472219*/count=340; tryItOut("/*oLoop*/for (var kcqnlf = 0; kcqnlf < 25; ++kcqnlf) {  for (x of (4277)) {s2 += 'x'; } } ");
/*fuzzSeed-45472219*/count=341; tryItOut("o0.i2.send(this.v0);");
/*fuzzSeed-45472219*/count=342; tryItOut("{ void 0; bailAfter(2); } const o0.o2.v1 = evaluate(\"b1.__proto__ = f2;\\\"\\\\u4289\\\";\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 3 != 0), sourceIsLazy: 16, catchTermination: (x % 49 != 22) }));");
/*fuzzSeed-45472219*/count=343; tryItOut("\"use asm\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -9.671406556917033e+24;\n    return +((+/*FFI*/ff()));\n    d2 = (+abs(((Float32ArrayView[((0x67d788a1)+((0xdb7d2e1d) ? ((1.0078125) > (-68719476737.0)) : (0x2246020))-((((0xffffffff)) ^ (0x6a6fd*(0x6f656a75))))) >> 2]))));\n    return +((+((d0))));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000000, -(2**53-2), 2**53, 0x080000001, 2**53-2, -1/0, 0x100000000, 2**53+2, -0x0ffffffff, -0x080000000, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, 0x0ffffffff, -(2**53+2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0, 1, 0x100000001, 1.7976931348623157e308, -0, 0/0, 0.000000000000001, -0x080000001, 0, Number.MAX_VALUE, -Number.MAX_VALUE, Math.PI, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=344; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.max(( ! (Math.max((Math.fround((x >>> 0)) >>> 0), ( + y)) != mathy0(( + (( + (( + ( - 0x080000001)) | 0)) | 0)), ( + mathy2(x, (Math.fround((( + x) ? (x | 0) : Math.fround(0x100000000))) | 0)))))), (( ! (( - (mathy2(Math.PI, -0x0ffffffff) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [0x100000001, 0x100000000, -0x080000001, 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, 2**53, -0x07fffffff, Math.PI, -1/0, -(2**53-2), 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 0, 1/0, Number.MAX_VALUE, 42, -(2**53), -0x100000001, -Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, 1]); ");
/*fuzzSeed-45472219*/count=345; tryItOut("\"use strict\"; m0.set(g0.g1, o1.m1);");
/*fuzzSeed-45472219*/count=346; tryItOut("\"use strict\"; v0 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-45472219*/count=347; tryItOut("\"use strict\"; v2 = (i0 instanceof p1);");
/*fuzzSeed-45472219*/count=348; tryItOut("print(x);\ng2.toString = (function() { this.m2.set(this.m2, g1.h2); return o1; });\nvar c = x;");
/*fuzzSeed-45472219*/count=349; tryItOut("/*tLoop*/for (let z of /*MARR*/[ /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){}, function(){},  /x/ , function(){},  /x/ ,  /x/ ,  /x/ , function(){},  /x/ , function(){},  /x/ ,  /x/ ,  /x/ , function(){},  /x/ , function(){}, function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){}, function(){},  /x/ ,  /x/ , function(){}, function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){}, function(){},  /x/ , function(){}, function(){}, function(){}]) { /*oLoop*/for (poovde = 0; poovde < 72; ++poovde) { (26); }  }");
/*fuzzSeed-45472219*/count=350; tryItOut("print(uneval(t1));");
/*fuzzSeed-45472219*/count=351; tryItOut("testMathyFunction(mathy4, [0.000000000000001, -0x0ffffffff, 0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -0x07fffffff, -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, Math.PI, 0, 0/0, -(2**53-2), -0x100000001, -0, 0x080000001, Number.MAX_SAFE_INTEGER, 42, 1, 0x07fffffff, 1/0, 0x080000000, -0x100000000, -1/0]); ");
/*fuzzSeed-45472219*/count=352; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=353; tryItOut("print(((window) = x));");
/*fuzzSeed-45472219*/count=354; tryItOut("i1 = new Iterator(p2, true);");
/*fuzzSeed-45472219*/count=355; tryItOut("let this.v1 = t1.byteOffset;print(uneval(o0));");
/*fuzzSeed-45472219*/count=356; tryItOut("\"use strict\"; t0 + f0;");
/*fuzzSeed-45472219*/count=357; tryItOut("o1.h1.enumerate = f2;");
/*fuzzSeed-45472219*/count=358; tryItOut("mathy2 = (function(x, y) { return (( ~ (Math.clz32(Math.fround(Math.hypot(( + (( + y) ^ (mathy1((x | 0), x) == y))), ( + mathy1(x, x))))) | 0)) >>> 0); }); testMathyFunction(mathy2, [-0x07fffffff, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000000, -(2**53), -0x0ffffffff, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -1/0, 2**53, -0, -0x080000001, Number.MIN_VALUE, -(2**53+2), 0, -0x080000000, 42, 0/0, Number.MAX_VALUE, 0x080000001, -(2**53-2), 0x0ffffffff]); ");
/*fuzzSeed-45472219*/count=359; tryItOut("mathy3 = (function(x, y) { return Math.imul(Math.sinh((( + (-0x100000000 - ( + Math.fround(Math.fround(( + Math.acos((x >>> 0)))))))) > ( + y))), Math.clz32(( + (( ! ((Math.pow(x, x) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -1/0, 42, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, -0x080000001, 1, 1/0, -0, 0/0, 0, 0x0ffffffff, 0.000000000000001, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, Number.MAX_VALUE, 0x080000001, 0x100000000, 0x07fffffff, 2**53, -Number.MIN_VALUE, -0x07fffffff, -(2**53), Number.MIN_VALUE, -0x0ffffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, 0x100000001]); ");
/*fuzzSeed-45472219*/count=360; tryItOut("...x");
/*fuzzSeed-45472219*/count=361; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(b1, g1);");
/*fuzzSeed-45472219*/count=362; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + Math.hypot(( + (Math.hypot((Math.fround(Math.imul(( + Math.ceil(2**53-2)), Math.clz32(y))) ? Math.atan2(-0x100000001, y) : Math.fround(( + Math.tanh((y | 0))))), x) <= (Math.pow(( + (( - (( + mathy0(( + x), ( + x))) >>> 0)) >>> 0)), ( - ( + ( + Math.log1p(Math.fround(x)))))) * (-0 | 0)))), (((( ! (Math.fround((Math.fround((mathy0(x, x) & y)) , Math.fround(y))) | 0)) | 0) * (( + Math.fround(( + (( ! ((Math.tanh(Math.fround(0x07fffffff)) ? -(2**53) : 0x080000000) | 0)) | 0)))) | 0)) | 0))); }); testMathyFunction(mathy1, [-0x080000000, -0, -1/0, 0.000000000000001, 2**53-2, 1.7976931348623157e308, 0, -(2**53-2), -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, 2**53, 1/0, Number.MIN_VALUE, -(2**53), 0x100000001, 0/0, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), Math.PI, 42, 1, Number.MIN_SAFE_INTEGER, 0x080000001, 0x080000000, 2**53+2, -0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-45472219*/count=363; tryItOut("\"use strict\"; e2.add(e2);");
/*fuzzSeed-45472219*/count=364; tryItOut("");
/*fuzzSeed-45472219*/count=365; tryItOut("mathy3 = (function(x, y) { return (( + (Math.imul((( ! y) >>> 0), ((Math.atan((0x100000000 | 0)) | 0) >>> 0)) >>> 0)) ? ( + Math.clz32(( + (mathy2((y >>> 0), Math.fround(mathy0((Math.tan((mathy1((((x | 0) || (-(2**53) | 0)) | 0), x) | 0)) | 0), (mathy0((x | 0), (0x080000000 | 0)) | 0)))) >>> 0)))) : mathy2(/*UUV2*/(z.trim = z.keys), (Math.tanh(((( + Math.max((Number.MIN_VALUE ** y), ( + ( ! 2**53-2)))) ? (x >>> 0) : y) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [-0x080000000, 0x07fffffff, Math.PI, 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000001, -0x07fffffff, 42, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, 2**53+2, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, 0, -(2**53-2), 1/0, -0x100000000, -0x100000001, 0x100000000, 0x100000001, 0x080000000, 2**53, 1, -(2**53)]); ");
/*fuzzSeed-45472219*/count=366; tryItOut("\"use asm\"; g0.o0.i2.next();");
/*fuzzSeed-45472219*/count=367; tryItOut("e2.add(e0);");
/*fuzzSeed-45472219*/count=368; tryItOut("testMathyFunction(mathy3, [-0x100000000, 0.000000000000001, -0, 1, 2**53+2, 0/0, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, 0x080000000, -0x07fffffff, -0x080000001, -(2**53+2), 2**53-2, 2**53, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff, 0x0ffffffff, 0, 1/0, Number.MAX_VALUE, Math.PI, 0x080000001, 42, 0x07fffffff, -0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=369; tryItOut("mathy0 = (function(x, y) { return ( + ( + ( + Math.log2((( + ( + Math.max(Math.fround(( + (( + x) && ( + (((Math.fround(Math.sqrt(Math.fround(42))) | 0) ** (x | 0)) | 0))))), ( + ( - y))))) | 0))))); }); testMathyFunction(mathy0, [0x080000000, -0x080000001, 1/0, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, 0x080000001, -1/0, 0.000000000000001, 0x100000000, -0, -0x100000001, 0, -Number.MAX_VALUE, 1, 0/0, -(2**53+2), 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 42, -(2**53), 0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, Math.PI, -0x100000000]); ");
/*fuzzSeed-45472219*/count=370; tryItOut("\"use strict\"; this.zzz.zzz;");
/*fuzzSeed-45472219*/count=371; tryItOut("/*MXX2*/g0.RegExp.prototype.compile = b1;");
/*fuzzSeed-45472219*/count=372; tryItOut("/*oLoop*/for (var ymfmpq = 0, /*RXUE*//(?:.)|[^\\b-\u3bf5\\r-\u008e\u00ce-\\t]?.+?|\\r|([^]*)+?|\\1**/gim.exec(\"\\u000d\"); ymfmpq < 14; ++ymfmpq) { this;(window); } ");
/*fuzzSeed-45472219*/count=373; tryItOut("{ void 0; void relazifyFunctions(this); } t1 = new Int32Array(b0);");
/*fuzzSeed-45472219*/count=374; tryItOut("mathy5 = (function(x, y) { return Math.fround(( - (Math.asinh(-0x080000000) ^ Math.cos((((1 >>> 0) || ( + (((Math.max((y , y), Math.fround(0x0ffffffff)) | 0) < (y | 0)) | 0))) >>> 0))))); }); testMathyFunction(mathy5, [0/0, 0x100000001, 2**53, 2**53-2, 1/0, 0, 0x0ffffffff, Math.PI, -1/0, 0.000000000000001, 42, Number.MAX_VALUE, 2**53+2, -0x100000000, -(2**53+2), Number.MIN_VALUE, 0x100000000, -(2**53-2), -Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000001, 1, 0x080000000, -0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -0, -(2**53), -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=375; tryItOut("s0 += this.s1;");
/*fuzzSeed-45472219*/count=376; tryItOut("\"use strict\"; print(new RegExp(\"([^])*|(?:(?:(?![^])+?))\", \"yi\"));/\u0008?|(?:(?:[]))|((\\b).{2,}|\\d$+)*?/g;");
/*fuzzSeed-45472219*/count=377; tryItOut("/*MXX2*/g0.g0.String.prototype.lastIndexOf = s1;");
/*fuzzSeed-45472219*/count=378; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return ((Math.fround(((((mathy0(x, y) | 0) ? -0x0ffffffff : x) == ( - (y >>> 0))) != Math.fround(Math.hypot(x, (Number.MIN_SAFE_INTEGER , x))))) - ((mathy0((y | 0), (y | 0)) | 0) >>> 0)) - Math.tan(Math.fround((( ! Math.fround(((-0x100000001 | 0) / (x | 0)))) ? Math.fround((Math.fround((( - (Math.min(y, ((x | (y >>> 0)) | 0)) >>> 0)) | 0)) ? Math.fround(( + Math.tanh(y))) : Math.fround(x))) : -1/0)))); }); testMathyFunction(mathy1, [0x100000000, 1.7976931348623157e308, 0.000000000000001, Math.PI, -(2**53+2), 0x07fffffff, -0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, 1/0, 0, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, -0x07fffffff, Number.MAX_VALUE, -(2**53), -0, -0x0ffffffff, 2**53-2, 0x100000001, 0/0, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, -0x100000001, 1, -1/0, 42, Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=379; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=380; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = new RegExp(\"[^]{3}\", \"im\"); var s = \"\\n\\ufad9\\n\\n\"; print(s.replace(r, '\\u0341', \"m\")); ");
/*fuzzSeed-45472219*/count=381; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround((Math.pow(Math.atan2(y, Math.min(Math.fround(Math.exp(Math.fround(Math.abs(x)))), y)), Math.acosh((( + ( + -Number.MAX_SAFE_INTEGER)) | 0))) % Math.fround(( + Math.pow((Math.atan(Math.max(Math.log1p(y), (( ~ ( + ( ! y))) >>> 0))) | 0), ( + Math.atan2(Math.sin(x), Math.min(x, (Math.atan2((Math.imul((Number.MIN_VALUE | 0), 42) | 0), (( - x) | 0)) | 0))))))))); }); testMathyFunction(mathy0, /*MARR*/[function(){}, false, false, function(){}, false, 0xB504F332, function(){}, 0xB504F332, false, 0xB504F332, false, false, function(){}, 0xB504F332, false, function(){}, 0xB504F332, false, false, 0xB504F332, false, function(){}, 0xB504F332, function(){}, 0xB504F332, 0xB504F332, 0xB504F332, false, false, 0xB504F332, false, false, 0xB504F332, function(){}, 0xB504F332, 0xB504F332, function(){}, function(){}, false, function(){}, false, function(){}, false, function(){}, 0xB504F332, function(){}, false, function(){}, function(){}, function(){}, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, function(){}, false, 0xB504F332, 0xB504F332, false, 0xB504F332, 0xB504F332, function(){}, false, function(){}, function(){}, 0xB504F332, false, false, 0xB504F332, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, 0xB504F332, function(){}, function(){}, function(){}, function(){}, function(){}, 0xB504F332, false, function(){}, function(){}, false, false, function(){}, 0xB504F332, 0xB504F332, function(){}, 0xB504F332, false, 0xB504F332, 0xB504F332, false, false, false, false, false, false, false, false, false, function(){}, 0xB504F332, function(){}, 0xB504F332, false, false, 0xB504F332, function(){}, function(){}, false, false, false, 0xB504F332, false, function(){}, 0xB504F332, 0xB504F332, 0xB504F332, function(){}, false, false, function(){}, function(){}, false, 0xB504F332, false, function(){}, function(){}, 0xB504F332, function(){}, 0xB504F332, false, false, false, false, false, false, false, false, false, false, false, false, false, 0xB504F332, 0xB504F332, 0xB504F332, function(){}, 0xB504F332, false, function(){}, 0xB504F332, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 0xB504F332, function(){}, false, 0xB504F332, 0xB504F332, 0xB504F332, false, 0xB504F332, 0xB504F332, function(){}, 0xB504F332, false, function(){}, false, function(){}, function(){}, function(){}, false, 0xB504F332, false]); ");
/*fuzzSeed-45472219*/count=382; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((d0));\n  }\n  return f; })(this, {ff: ({}, x) => \"use asm\";   var Infinity = stdlib.Infinity;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 70368744177663.0;\n    {\n      i1 = (0x43276cad);\n    }\n    (Int8ArrayView[4096]) = ((((((i1) ? (i0) : (0xe8e4f1d8))-(((new -1(x, (Math.pow(null,  /x/ ))))>>>( \"\" .throw(intern((x) = ({})))))))>>>((i0)))));\n    i0 = (0xfd8f392b);\n    i0 = (i1);\n    return (((i1)*-0x3f01b))|0;\n    i1 = ((1152921504606847000.0) >= (((+(-1.0/0.0))) * ((Infinity))));\n    d2 = (-1125899906842625.0);\n    {\n      return ((((0xf86b2cd6) ? (i0) : (i1))))|0;\n    }\n    i1 = (i0);\n    return (((0xe5885d39)))|0;\n    {\n      i0 = ((0xc370101));\n    }\n    return ((0x8a5c4*(0x82bff774)))|0;\n  }\n  return f;}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [true, [], '0', undefined, -0, (new Boolean(true)), (new Boolean(false)), ({toString:function(){return '0';}}), objectEmulatingUndefined(), 0.1, false, NaN, '\\0', 1, (function(){return 0;}), null, '', ({valueOf:function(){return 0;}}), /0/, '/0/', (new String('')), (new Number(-0)), [0], (new Number(0)), ({valueOf:function(){return '0';}}), 0]); ");
/*fuzzSeed-45472219*/count=383; tryItOut("\"use strict\"; /*infloop*/for(17; undefined; new RegExp(\"(?!\\\\D+|.(?:.){0,})|(?:(?=\\\\W|(?=[^])))*?\", \"yim\")) {e0.has(g1.a0);x; }");
/*fuzzSeed-45472219*/count=384; tryItOut("/*oLoop*/for (var kuvcyk = 0; kuvcyk < 98; ++kuvcyk) { (new (allocationMarker().getMonth)(x)); } ");
/*fuzzSeed-45472219*/count=385; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 33554433.0;\n    i2 = (i1);\n    return +((d3));\n  }\n  return f; })(this, {ff: ArrayBuffer}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, 42, Number.MAX_VALUE, -(2**53), 0x0ffffffff, -(2**53-2), 1.7976931348623157e308, Math.PI, 2**53+2, -0x0ffffffff, 1/0, -0x100000000, -Number.MIN_VALUE, 0x07fffffff, -0x100000001, 0/0, -0x080000000, -(2**53+2), 2**53, -0x080000001, 2**53-2, Number.MIN_VALUE, 0x080000001, -0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, 1, 0x100000001, -0, -1/0]); ");
/*fuzzSeed-45472219*/count=386; tryItOut("testMathyFunction(mathy5, [0/0, 0.000000000000001, 42, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, 0x080000001, 0x080000000, -0x080000000, 2**53-2, -Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, -0x0ffffffff, -(2**53), -1/0, 2**53, 0, 0x100000001, Number.MIN_SAFE_INTEGER, 1, 1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), -0x100000001, -(2**53+2), Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-45472219*/count=387; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-45472219*/count=388; tryItOut("\"use strict\"; /*MXX1*/o0 = g0.String.prototype.substr;");
/*fuzzSeed-45472219*/count=389; tryItOut("for (var p in b1) { try { let s1 = Array.prototype.join.apply(a1, [s1]); } catch(e0) { } a0.unshift(s1); }");
/*fuzzSeed-45472219*/count=390; tryItOut("testMathyFunction(mathy0, [-0x100000000, 2**53+2, 0/0, Math.PI, 0x080000000, 1/0, -0x100000001, -Number.MAX_VALUE, 0x100000000, 1, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -0x080000001, 0x080000001, -0x07fffffff, -1/0, 42, 0.000000000000001, 0x0ffffffff, 0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0, -0x0ffffffff, -0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-45472219*/count=391; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.log2((mathy0((( + ( - ( + ( ~ x)))) >>> 0), (Math.fround(Math.sqrt(Math.fround(( + (x == (Math.atan2(((( + (mathy0(( + 2**53), ( + x)) >>> 0)) ** y) >>> 0), ((( ~ x) >>> 0) >>> 0)) >>> 0)))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 0, -0x080000001, -0x080000000, 0x07fffffff, -(2**53+2), -(2**53-2), 1/0, -0x07fffffff, -(2**53), 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_VALUE, -0, -Number.MAX_VALUE, 1, -0x0ffffffff, -0x100000000, -1/0, Math.PI, 0x080000001, -0x100000001, 2**53, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, 0x100000001, 42, 2**53-2, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=392; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=393; tryItOut("(\"\\uCE4F\");function x(x, x, z, set = \"\\u5949\", x, b = -27, eval, eval, b = 1, x, y, x = true, x, x, x, e, \u3056, x = null, z = w, d, d, window, window = window, get = [,], eval, x, w, x, e, x = window, a = b, e, yield, getter, a, eval, x, window, a, z, NaN, NaN, x, window, x, x, d =  /x/ , x, x, c, w, x = -20, x = null, \u3056, eval, x = -14, x, x, x, b, z =  '' , w, x, x, x, x, y, x = [,,], x, w, y, NaN, x, z = \"\\uDFF0\", x, w, z, x, x, z =  \"\" , x, x, a, w =  /x/g , of, w, z, a =  /x/g , x, -0.055) { print(x); } t2[15] = m2;");
/*fuzzSeed-45472219*/count=394; tryItOut("mathy5 = (function(x, y) { return Math.fround(((Math.pow((( ! Math.fround((2**53 >>> 0))) | 0), (Math.max(x, Math.fround(( ~ (( - Math.fround(x)) >>> 0)))) | 0)) && Math.atan2(Math.fround(Math.log((y | 0))), Math.abs(Math.fround(y)))) % (((((y | 0) == Math.fround(mathy1(Math.fround((x ? (-0x080000000 | 0) : (((y | 0) & (y | 0)) >>> 0))), Math.fround(Math.exp(Math.fround(( + mathy1((0x080000001 | 0), y)))))))) >>> 0) + (( - ((Math.max((42 >>> 0), y) >>> 0) >>> y)) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [2**53-2, 0x100000000, 2**53+2, -(2**53+2), 0x0ffffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -Number.MAX_VALUE, 1, -0, 42, 1/0, -0x100000001, -(2**53-2), Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, -0x07fffffff, 0x080000000, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 0, Number.MIN_SAFE_INTEGER, 0/0, -1/0, Math.PI, 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, 2**53]); ");
/*fuzzSeed-45472219*/count=395; tryItOut("testMathyFunction(mathy5, /*MARR*/[ /x/ , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), this, this, new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), this, true, this, new Number(1.5), new Number(1.5), new Number(1.5), true, true, new Number(1.5),  /x/ , new Number(1.5),  /x/ , this, true, true, new Number(1.5), new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), this, new Number(1.5), true, new Number(1.5), true, new Number(1.5), new Number(1.5), true, new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), true, true,  /x/ , true, this, this, true, true, this, this, this,  /x/ , new Number(1.5), new Number(1.5), this, this, new Number(1.5), new Number(1.5), new Number(1.5),  /x/ , new Number(1.5), new Number(1.5), new Number(1.5), true, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), this, new Number(1.5), new Number(1.5), this, new Number(1.5), true, new Number(1.5), true, new Number(1.5), new Number(1.5), this, new Number(1.5), new Number(1.5), this, new Number(1.5), new Number(1.5), true, true, this,  /x/ , this, new Number(1.5), new Number(1.5), this, this]); ");
/*fuzzSeed-45472219*/count=396; tryItOut("s0 + m2;");
/*fuzzSeed-45472219*/count=397; tryItOut("\"use strict\"; v1 = evaluate(\"testMathyFunction(mathy1, [0x100000001, -0x080000000, 0, -0x100000000, 2**53, -(2**53+2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, 1/0, Number.MIN_VALUE, -(2**53-2), 0.000000000000001, 0x080000000, 0x100000000, -0, -Number.MAX_VALUE, 0x080000001, 42, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), Number.MAX_VALUE, 1, Math.PI, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0x07fffffff]); \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (x % 27 != 8), catchTermination: (x % 7 != 5) }));for (var v of a0) { try { p2 + p1; } catch(e0) { } g2.g2.offThreadCompileScript(\"t2 = new Uint8ClampedArray(b2, 14, allocationMarker());\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 81 == 43), catchTermination: NaN = (4277) })); }");
/*fuzzSeed-45472219*/count=398; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (0xf8fda22a);\n    }\n    i0 = (((imul((!((((-0x8000000)) & ((0xfca987b0))) < (((0xfddb8f5c))|0))), (0xe48342))|0)) ? ((0xa178f928)) : (0x5dede4d2));\n    (Float64ArrayView[(-(!(i0))) >> 3]) = ((+(0.0/0.0)));\n    d1 = (d1);\n    {\n      d1 = (((Float64ArrayView[1])) % ((3.094850098213451e+26)));\n    }\n    return ((-0xe999f*(/*FFI*/ff(((d1)), ((((0xb12bcfb7)-(!((+((2147483649.0))) <= (33.0)))) | ((i0)))), ((((0x88721fb5)-((\"\\u9D41\".__defineSetter__(\"w\", decodeURI) |= window) < (4503599627370497.0))) << (((0xad565022) ? (0xb00036d3) : (0xfdc3c920))+(/*FFI*/ff(((+(((0xffffffff))>>>((0xf981b573))))))|0)))), (((((((0xfd5608f6)) << ((-0x8000000))) > (((0xffffffff)) >> ((0xe9b2ecdd))))-((0x2cee112c) >= (((0x669772bc))>>>((0xfa8b2b77)))))|0)), ((0x21d95eb2)))|0)))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ \"use strict\"; \"use asm\"; v1 = Object.prototype.isPrototypeOf.call(p0, v2);return x =>  { yield this.eval(\" '' ;\") } })()}, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[ /x/g , true, true,  /x/  ? \"\\uBCFE\" : undefined,  'A' ,  /x/  ? \"\\uBCFE\" : undefined,  /x/g ,  /x/  ? \"\\uBCFE\" : undefined,  'A' ,  /x/g ,  /x/  ? \"\\uBCFE\" : undefined,  /x/g ,  /x/g ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  /x/g ,  /x/g ,  /x/  ? \"\\uBCFE\" : undefined,  /x/g ,  /x/g ,  'A' ,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/g ,  /x/g ,  'A' ,  /x/g ,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/g ,  /x/g ,  'A' , true, true,  /x/g , true,  /x/  ? \"\\uBCFE\" : undefined, true,  /x/  ? \"\\uBCFE\" : undefined, true, true,  'A' ,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  'A' ,  /x/g , true,  /x/g ,  /x/g ,  /x/g , true,  /x/  ? \"\\uBCFE\" : undefined, true,  /x/  ? \"\\uBCFE\" : undefined, true,  /x/g , true,  /x/  ? \"\\uBCFE\" : undefined,  /x/g ,  'A' ,  /x/  ? \"\\uBCFE\" : undefined,  /x/  ? \"\\uBCFE\" : undefined,  /x/g , true,  /x/  ? \"\\uBCFE\" : undefined, true,  'A' ,  /x/  ? \"\\uBCFE\" : undefined, true,  /x/g ,  /x/g ,  /x/  ? \"\\uBCFE\" : undefined]); ");
/*fuzzSeed-45472219*/count=399; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.max((( + Math.max(x, Math.imul(Math.fround(y), x))) >>> 0), (( + Math.fround(( + Math.tanh(( + Math.imul(y, x)))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-45472219*/count=400; tryItOut("with(1322809226){( '' );print(this); }");
/*fuzzSeed-45472219*/count=401; tryItOut("/*RXUB*/var r = /\\B{1}/gym; var s = \"\\u2864\"; print(s.replace(r, (-1/0))); ");
/*fuzzSeed-45472219*/count=402; tryItOut("\"use strict\"; { void 0; try { startgc(6, 'shrinking'); } catch(e) { } } print( ''  ? [,,z1] : \"\\u9855\");");
/*fuzzSeed-45472219*/count=403; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( - Math.acosh(Math.min((-(2**53) | 0), (Math.ceil(( + (( + (Math.min(-0x100000000, -0x07fffffff) >>> 0)) | 0))) >>> 0)))) >>> ( ~ ( ! (mathy0(-(2**53), ( ~ ( + mathy2(x, (x >>> 0))))) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[new Number(1.5), NaN, NaN, new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new String(''), new Number(1.5), new String(''), NaN, new String(''), new String(''), new Number(1.5), new String(''), NaN, new Number(1.5), new Number(1.5), new Number(1.5), NaN, new String(''), new Number(1.5), new Number(1.5), NaN, new String(''), new Number(1.5), new String(''), NaN, new String(''), new String(''), new String(''), NaN, NaN, new String(''), new Number(1.5), new String(''), new String(''), NaN, NaN, new String(''), new String(''), new String(''), new Number(1.5), new String(''), NaN, new Number(1.5), NaN, new String(''), new String(''), new String(''), new String(''), new Number(1.5), NaN, new Number(1.5), NaN, new Number(1.5), new Number(1.5), new String(''), NaN, new Number(1.5), new Number(1.5), NaN, NaN, new Number(1.5), new String(''), new Number(1.5), NaN, new String(''), new Number(1.5), new Number(1.5), NaN, new Number(1.5), NaN, new Number(1.5), NaN, new Number(1.5), new String(''), new String(''), new Number(1.5), NaN, NaN, new String(''), new Number(1.5), new String(''), new Number(1.5), new String(''), NaN, new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), NaN, new Number(1.5), new Number(1.5), new String(''), new String(''), new String(''), NaN, NaN, NaN, new Number(1.5), new Number(1.5), NaN, NaN, new Number(1.5), NaN, new String(''), new String(''), new Number(1.5), new Number(1.5), NaN]); ");
/*fuzzSeed-45472219*/count=404; tryItOut("\"use strict\"; v0 = evalcx(\"w = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: /*MARR*/[(x = -19), (x = -19), -Infinity, (x = -19), new String(''), new String(''), new String(''), new String(''), {}, {}, new String(''), {}, new String(''), {}, {}].map(DataView.prototype.getInt32, /*UUV1*/(x.toString = (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: encodeURI, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: false, }; }))), set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: Array.prototype.concat, keys: function() { throw 3; }, }; })(g0.offThreadCompileScript(\\\"print( '' );\\\")), (4277))\", g2.g1);");
/*fuzzSeed-45472219*/count=405; tryItOut(" for  each(let y in new (false)(this)) v1 = g1.eval(\"o1.t0.set(t0, 19);\");");
/*fuzzSeed-45472219*/count=406; tryItOut("h0.getOwnPropertyNames = o2.f0;");
/*fuzzSeed-45472219*/count=407; tryItOut("\"use strict\"; if(true) print((\n[z1])); else  if ((4277)) print(x); else h2 = a0[v2];");
/*fuzzSeed-45472219*/count=408; tryItOut("a2 + h2;var x = x;print(/\\1/im);");
/*fuzzSeed-45472219*/count=409; tryItOut("\"use strict\"; g2.e0.add(f0);");
/*fuzzSeed-45472219*/count=410; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=411; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return mathy3(Math.expm1(Math.imul(Math.fround((( + (y | 0)) | 0)), Math.fround(Math.ceil(y)))), (( - Math.log1p(Math.fround(Math.hypot((x | 0), mathy2(x, x))))) & (Math.sqrt((Math.acos((Math.asin((y | 0)) | 0)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-45472219*/count=412; tryItOut("{print(x); }");
/*fuzzSeed-45472219*/count=413; tryItOut("var {} = ([] ? /*UUV1*/(e.seal = function(q) { return q; }) : z - -16), \u3056 = x, dnredy, jjdhdv, yhkoue, x;(new Element(window));");
/*fuzzSeed-45472219*/count=414; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (d1);\n    d1 = (d1);\n    d1 = (d0);\n    {\n      return +((+(((0x1e55cfef) % (~~(+abs(((NaN)))))) >> (((0x0))))));\n    }\n    (Int16ArrayView[0]) = ((0x721a9ce7));\n    {\n      {\n        d1 = (1.5474250491067253e+26);\n      }\n    }\n    d1 = (d0);\n    d1 = (+pow(((d1)), ((d0))));\n    {\n      /*FFI*/ff((((((0x3e1adb5d))+(0x5c5a428b)) | ((0xfd937215)-(0xfe17301b)))), ((d0)), ((+(((0x12b1b364)+((void shapeOf(({}) = x)))+(0xdb6a6950))|0))));\n    }\n    {\n      (Uint8ArrayView[1]) = (((0xffffffff) ? (0xbba0168a) : (0x5a92ccab))*0xfffff);\n    }\n    {\n      d1 = (d0);\n    }\n    d0 = (d1);\n    d1 = (+((d0)));\n    (Uint16ArrayView[4096]) = ((((((((0xf40b398a)+(0xbb85d404)-(-0x8000000)) << ((0xffffffff)-(0xffffffff))))) & (((((Uint16ArrayView[((-0x8000000)) >> 1])) | ((0xa2de959a) / (0xf0a5e1a8)))))) >= ((((((0xfbd09ed9)) << ((-0x594c1ce))) > (((0xfaf1da86)) >> ((0xfc0a5601))))-((0x85e5381a))+((0x1644f902) < (~~(1099511627777.0)))) << ((0xcc674b6d)-((d0) >= (d0)))))*0xd7a0c);\n    /*FFI*/ff(((17592186044417.0)), ((d0)), ((~(((0xc3d12999))))), ((0x4c089636)), ((d1)), ((d1)), ((-((-15.0)))));\n    return +((d0));\n  }\n  return f; })(this, {ff: (void version(180))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, 1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x07fffffff, 0x080000000, 0x080000001, -(2**53+2), 0x100000000, Number.MIN_VALUE, -(2**53), -Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, 42, -0x100000001, 0, 2**53, 1, -Number.MAX_VALUE, -(2**53-2), -0x080000001, -0x080000000, 0.000000000000001, -0x0ffffffff, 2**53-2, 0/0, -0, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-45472219*/count=415; tryItOut("Array.prototype.reverse.apply(a0, [t0]);");
/*fuzzSeed-45472219*/count=416; tryItOut("a0.unshift(m2);");
/*fuzzSeed-45472219*/count=417; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.log2(( + Math.expm1(( + (Math.max((Math.max(mathy0(y, x), ( ! Math.fround(x))) >>> 0), (( + ((Math.min(y, (mathy0((-(2**53-2) >>> 0), (-0x080000000 >>> 0)) >>> 0)) >>> (Math.imul((-0x0ffffffff >= (y | 0)), (-(2**53+2) >>> 0)) | 0)) | 0)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy1, /*MARR*/[new Boolean(true), {}, {}, {}, {}, new Boolean(true), this, this, x, {}, this, {}, {}, this, x, new Boolean(true), this, new Boolean(true), {}, {}, new Boolean(true), x, new Boolean(true), this, x, {}, this, {}, {}, {}, this, this, this, new Boolean(true), this, {}, x]); ");
/*fuzzSeed-45472219*/count=418; tryItOut("\"use strict\"; function(y) { \"use strict\"; i2 + ''; }\np1.toSource = (function(j) { if (j) { try { t0 = new Int32Array(t2); } catch(e0) { } try { i1.next(); } catch(e1) { } try { this.s2 + s1; } catch(e2) { } print(o1.h1); } else { try { a0.push(g0, p0); } catch(e0) { } try { m1.set([,], t1); } catch(e1) { } try { g1.v1 = Object.prototype.isPrototypeOf.call(o1.a0, i1); } catch(e2) { } v2 = (p0 instanceof this.e0); } });\n");
/*fuzzSeed-45472219*/count=419; tryItOut(";");
/*fuzzSeed-45472219*/count=420; tryItOut("this.p2 = t1;");
/*fuzzSeed-45472219*/count=421; tryItOut("mathy0 = (function(x, y) { return (( ~ ((Math.fround(( ! ( + ((Math.fround(x) % (y | 0)) | 0)))) >>> (y > y)) & ( - (( ! (Math.tanh(x) | 0)) | 0)))) == ((Math.hypot(Math.fround(Math.hypot(y, Math.fround((x + (x >>> 0))))), (Math.fround(Math.tanh(Math.fround(x))) >>> 0)) >>> 0) ? Math.log2(( + Math.sin(( + x)))) : Math.atan2(Math.hypot(x, x), (Math.atan2((Math.atan2((y | 0), ((x > (y >>> 0)) | 0)) | 0), 0x080000000) & 0x100000000)))); }); ");
/*fuzzSeed-45472219*/count=422; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (!(i1));\n    }\n    i0 = ((((!(i0))-(i0))|0));\n    (Uint8ArrayView[(x) >> 0]) = ((i1));\n    (Float32ArrayView[4096]) = ((1125899906842624.0));\n    {\n      i0 = (i0);\n    }\n    i1 = (i1);\n    {\n      i0 = (i0);\n    }\n    i0 = (i0);\n    i1 = (i1);\n    i1 = (i0);\n    (Uint32ArrayView[0]) = ((Uint16ArrayView[2]));\n    /*FFI*/ff(((((i0)) | ((i1)))), ((295147905179352830000.0)), ((((17592186044417.0)) / ((1.0078125)))));\n    {\n      i1 = ((i0) ? (i1) : (i0));\n    }\n    {\n      switch ((((/*FFI*/ff(((((-4503599627370495.0)) / ((-4503599627370497.0)))))|0)) << ((i1)+((0x2ec1c900) ? (0xfb66b4ea) : (-0x8000000))))) {\n        case 0:\n          (Float32ArrayView[((i0)) >> 2]) = ((140737488355329.0));\n          break;\n        default:\n          i0 = (!((~~(4.722366482869645e+21)) <= (0x291338)));\n      }\n    }\n    switch ((0x32bad083)) {\n      case 0:\n        (Float32ArrayView[0]) = ((34359738369.0));\n        break;\n      case 0:\n        switch ((((0x333f9e87) / (0x6da8c8ae)) | ((0xffffffff)+(0x81ed7b9c)-(-0x8000000)))) {\n          case -1:\n            (Float64ArrayView[0]) = ((-2305843009213694000.0));\n            break;\n          case 1:\n            (Uint16ArrayView[((~~(((-((4503599627370497.0)))) / ((18014398509481984.0)))) % (((i0)) & (((0x0))))) >> 1]) = ((i1)-(i0));\n            break;\n        }\n        break;\n      default:\n        (Uint16ArrayView[1]) = ((i1));\n    }\n    {\n      (Int8ArrayView[4096]) = ((x)-(/*FFI*/ff(((imul(((-17592186044416.0) >= (Infinity)), (i0))|0)))|0)+(i1));\n    }\n    return +(((((((((((-0x8000000)) >> ((0xff19a53d)))) >= (((0xfadde7cb)) | ((0xfb9d9842)))) ? (-((-7.737125245533627e+25))) : (+(((0xf96c318e))>>>((-0x8000000)))))) % ((Float64ArrayView[(((0x1646c74b))-(i1)) >> 3])))) * ((-1.9342813113834067e+25))));\n    i1 = (i0);\n    return +((-16777216.0));\n  }\n  return f; })(this, {ff: ((Math.min(-27, -25))).apply}, new ArrayBuffer(4096)); ");
/*fuzzSeed-45472219*/count=423; tryItOut("mathy4 = (function(x, y) { return Math.fround(( + Math.sqrt(( - (Math.hypot((Math.cbrt(x) >>> 0), 1) >>> 0))))); }); testMathyFunction(mathy4, [1/0, 0/0, 2**53, 0, -(2**53), 1.7976931348623157e308, -Number.MAX_VALUE, 2**53+2, 0x100000000, 42, -1/0, -0x100000000, -0x07fffffff, 0x080000000, 1, -(2**53+2), 0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -0x080000000, Math.PI, 0x100000001, 0x0ffffffff, -0x100000001, 2**53-2, -(2**53-2), Number.MIN_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=424; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.pow(Math.fround(mathy1(( + Math.hypot((Math.pow(y, y) >>> 0), (-Number.MAX_VALUE | 0))), ( + ((Math.min(y, Math.fround((Math.atan((y >>> 0)) >>> 0))) == x) << Math.fround(Math.min(Math.fround(x), Math.fround(Math.max(Math.fround(Math.imul(x, x)), mathy1((( + ( - ( + -0x100000001))) >>> 0), x))))))))), Math.fround(mathy1(Math.imul(( + Math.asin(( + y))), Math.atan2((x >>> 0), Math.abs(( - 1.7976931348623157e308)))), ( ! ( + y)))))); }); testMathyFunction(mathy2, [-(2**53-2), 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 0x100000000, -Number.MIN_VALUE, -0, -0x080000000, -0x080000001, Number.MAX_VALUE, 2**53+2, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0, -1/0, 0x080000001, -Number.MAX_VALUE, 1/0, 42, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, 0x0ffffffff, -0x0ffffffff, 0x080000000, 0.000000000000001, Math.PI, 1, Number.MIN_VALUE, 0/0, 2**53-2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-45472219*/count=425; tryItOut("b0.toString = (function(j) { if (j) { try { Array.prototype.reverse.call(a2, b0, yield x); } catch(e0) { } try { m1.has(o1.a0); } catch(e1) { } try { o1.e1.add(this.a2); } catch(e2) { } this.b2 = new SharedArrayBuffer(18); } else { try { a2[18]; } catch(e0) { } try { h1 + ''; } catch(e1) { } try { v1 = a2.length; } catch(e2) { } a2.pop(t1); } });");
/*fuzzSeed-45472219*/count=426; tryItOut("mathy1 = (function(x, y) { return Math.min(Math.atan((Math.ceil((((Math.min(x, (Math.fround(x) | Math.fround(( - y)))) | 0) === (Math.atan2(y, -0x080000001) | 0)) | 0)) >>> 0)), Math.cbrt(Math.cosh(( + ( - Math.fround(Math.cosh(( + Math.max(y, ( ~ x)))))))))); }); testMathyFunction(mathy1, /*MARR*/[0x080000000, 0x080000000,  /x/g ,  /x/g ,  /x/g , 0x080000000, 0x080000000,  /x/g , 0x080000000, 0x080000000, 0x080000000, 0x080000000,  /x/g ,  /x/g , 0x080000000, 0x080000000, 0x080000000, 0x080000000,  /x/g , 0x080000000, 0x080000000,  /x/g ,  /x/g ,  /x/g ,  /x/g , 0x080000000, 0x080000000, 0x080000000]); ");
/*fuzzSeed-45472219*/count=427; tryItOut("\"use strict\"; for(let y in yield (4277)) {var e, pspiad, rbgluu, ubzesb, sckozf, y, dmtuhj;t0[17] = m1; }");
/*fuzzSeed-45472219*/count=428; tryItOut("i2 = new Iterator(a0, true);");
/*fuzzSeed-45472219*/count=429; tryItOut("a1.reverse();");
/*fuzzSeed-45472219*/count=430; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.min(((Math.asin((((((x | 0) << ( + ( + Math.fround(x)))) | 0) * ( ~ Math.fround(mathy1(x, x)))) >>> 0)) ? ( ! (Math.asin(((y !== x) >>> 0)) >>> 0)) : Math.max(Math.hypot(mathy3(( + x), Math.fround(( ! ( + Number.MIN_VALUE)))), x), (x > ( + mathy4(( + y), ( + Math.min((y >>> 0), (-1/0 | 0)))))))) | 0), (Math.min(mathy3(Math.hypot(Math.fround(Math.max(Math.fround(x), Math.fround(y))), (y + y)), ( + ( + ( + (mathy4(0/0, y) ? x : y))))), (( + ( - ( + Math.fround(Math.hypot(Math.fround((Math.pow((y | 0), ((Math.exp(-0) >>> 0) | 0)) | 0)), Math.fround((Math.fround(x) == ( + Number.MAX_SAFE_INTEGER)))))))) >>> 0)) | 0)); }); testMathyFunction(mathy5, [-0x07fffffff, 1/0, 0x100000000, Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -1/0, -(2**53+2), 0/0, 0.000000000000001, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x100000000, 0, Number.MIN_VALUE, -0x0ffffffff, 0x100000001, -(2**53-2), 0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, 0x080000000, 0x07fffffff, 1, -0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, -0]); ");
/*fuzzSeed-45472219*/count=431; tryItOut("/*infloop*/M: for (x of Math.exp(([]).yoyo(((this)(new RegExp(\"(?:\\\\B(?!\\\\B)^|$|\\\\W)^?\\\\3.{2,}$|[^\\\\0]|\\\\B?[^\\\\W\\\\\\u52d6-\\\\r\\\\xd5]*\", \"gy\"))))).throw(null)) let (x) { v0 = Object.prototype.isPrototypeOf.call(h1, m2); }");
/*fuzzSeed-45472219*/count=432; tryItOut("mathy0 = (function(x, y) { return (Math.fround(Math.fround(( ~ Math.fround(Math.fround(( ~ (( + Math.pow(( + (( + x) <= Math.fround(( + (( + (Math.min((x >>> 0), (0x080000000 >>> 0)) >>> 0)) != ( + y)))))), (y >>> 0))) | 0))))))) ? (( ! Math.fround((((((Math.asin(y) >>> (Math.hypot((( ! x) >>> 0), ((y && y) >>> 0)) >>> 0)) | 0) >= (Math.min(y, Math.sign(y)) - ((0 == x) | 0))) | 0) ^ (Math.tan((Math.cbrt(1/0) >>> 0)) >>> 0)))) | 0) : ( + (((Math.sinh(( ~ (y | 0))) >>> 0) <= (( + Math.fround(Math.acos(( + (((y >>> 0) || (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[ \"\" , objectEmulatingUndefined(), ({x:3}), objectEmulatingUndefined(), Math.pow((encodeURI), -11), ({x:3}), ({x:3}),  \"\" , Math.pow((encodeURI), -11), Math.pow((encodeURI), -11),  \"\" , objectEmulatingUndefined(),  \"\" ,  \"\" , Math.pow((encodeURI), -11),  \"\" , objectEmulatingUndefined(),  \"\" , Math.pow((encodeURI), -11), objectEmulatingUndefined(), objectEmulatingUndefined(), ({x:3}),  \"\" , Math.pow((encodeURI), -11), ({x:3}), objectEmulatingUndefined(), ({x:3}),  \"\" , Math.pow((encodeURI), -11), Math.pow((encodeURI), -11), ({x:3}), Math.pow((encodeURI), -11), ({x:3}), objectEmulatingUndefined(), objectEmulatingUndefined(), Math.pow((encodeURI), -11), Math.pow((encodeURI), -11), ({x:3}), objectEmulatingUndefined(), ({x:3}), ({x:3}), ({x:3}), Math.pow((encodeURI), -11), ({x:3}), Math.pow((encodeURI), -11), objectEmulatingUndefined(), ({x:3}), Math.pow((encodeURI), -11), Math.pow((encodeURI), -11),  \"\" , ({x:3}),  \"\" , Math.pow((encodeURI), -11), ({x:3}),  \"\" , ({x:3})]); ");
/*fuzzSeed-45472219*/count=433; tryItOut("v0.valueOf = (function() { try { Array.prototype.forEach.call(a0, f1); } catch(e0) { } ; return g0.b2; });");
/*fuzzSeed-45472219*/count=434; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(\\\\3*?|((?!(?!\\\\x51)){4,5})))\", \"gi\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-45472219*/count=435; tryItOut("\"use asm\"; /*infloop*/while(this.__defineSetter__(\"NaN\", (offThreadCompileScript).bind)){p1.__proto__ = p1;o0.v0 = g0.eval(\"/* no regression tests found */\"); }");
/*fuzzSeed-45472219*/count=436; tryItOut("\"use strict\"; e0 = new Set;");
/*fuzzSeed-45472219*/count=437; tryItOut("mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.fround((( + ( ~ ( + ((x ? ( ! ( ~ (Math.sqrt(y) >= Math.fround(y)))) : Math.pow(( ~ (Math.fround(Math.imul(Math.fround(y), Math.fround(y))) >>> 0)), (( + Math.asinh(( + x))) + x))) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[function(){}, 0x50505050, 0x50505050, [] = [], [] = [], function(){}, [] = [], 0x50505050,  '\\0' , function(){}, function(){}, [] = [], function(){}, [] = [],  '\\0' ,  '\\0' , x,  '\\0' , function(){},  '\\0' , x, x, [] = [], x, x, x, x, x, x, [] = [], [] = [], function(){}, x, function(){}, function(){}, [] = [],  '\\0' , function(){}, [] = [], 0x50505050, function(){}, 0x50505050, 0x50505050, function(){}, 0x50505050, x, function(){},  '\\0' , 0x50505050, function(){}, x, x, 0x50505050, 0x50505050, [] = [], x, 0x50505050, function(){},  '\\0' , x, function(){},  '\\0' ,  '\\0' , x, function(){},  '\\0' , x, [] = [], x,  '\\0' , x,  '\\0' , [] = [],  '\\0' , 0x50505050, x, 0x50505050, x, function(){}, [] = [], x, x, [] = [], x,  '\\0' ]); ");
/*fuzzSeed-45472219*/count=438; tryItOut("\"use strict\"; b1.toSource = (function mcc_() { var aakbru = 0; return function() { ++aakbru; if (true) { dumpln('hit!'); try { Array.prototype.pop.call(a2); } catch(e0) { } /*RXUB*/var r = r0; var s = g1.o2.s1; print(s.replace(r, ''));  } else { dumpln('miss!'); try { print(uneval(b0)); } catch(e0) { } try { s2 += 'x'; } catch(e1) { } m0 = new Map(p1); } };})();");
/*fuzzSeed-45472219*/count=439; tryItOut("\"use strict\"; for (var v of a0) { try { g2.offThreadCompileScript(\"/*ADP-1*/Object.defineProperty(a1, 14, ({}));\"); } catch(e0) { } try { for (var v of m1) { try { o1.m1 = new WeakMap; } catch(e0) { } try { s1 += this.s1; } catch(e1) { } try { a0.sort((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((0x5f8b4ce3) == ((((((0xec586b45))>>>((0x1aa0be77))))-(i0))>>>((i0))))+((x = [,,]))+((0xcfb29482))))|0;\n    i0 = ((~( /x/g )) != ((((~(((0x968791e4) == (0x0))+((((0x7125c57c))>>>((0x9be13526))))-(i0))))) | (-(i1))));\n    (Float32ArrayView[(-(i0)) >> 2]) = ((+(-1.0/0.0)));\n    return ((\u3056 >> a))|0;\n  }\n  return f; })(this, {ff: (Date.prototype.getDay).apply}, new SharedArrayBuffer(4096)), m2, o1, e0); } catch(e2) { } a0.reverse( /x/ , v1, o1); } } catch(e1) { } this.o2 + o2; }\nprint(x);\n");
/*fuzzSeed-45472219*/count=440; tryItOut("mathy2 = (function(x, y) { return Math.tan(Math.fround(Math.atan2((mathy0((( ~ y) >>> 0), (mathy1(Math.sin(y), (( ~ y) | x)) >>> 0)) >>> 0), Math.fround(( ~ ((Math.log1p((Math.hypot((x + x), y) >>> 0)) >>> 0) | 0)))))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -Number.MIN_VALUE, -0, -0x07fffffff, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 2**53-2, 2**53+2, 0x07fffffff, 0/0, 0x080000000, Number.MAX_VALUE, -(2**53), -0x100000001, 42, Number.MIN_SAFE_INTEGER, 0x100000001, 1, 0x0ffffffff, -0x0ffffffff, -(2**53+2), -0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 2**53, -1/0, 0x100000000, 1.7976931348623157e308, 0, 0x080000001, -0x080000001]); ");
/*fuzzSeed-45472219*/count=441; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-1.2089258196146292e+24));\n  }\n  return f; })(this, {ff: (q => q).call}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0x080000000, 0x080000001, -0, -(2**53+2), -(2**53-2), 2**53, Math.PI, 0.000000000000001, -0x100000000, 2**53+2, 42, -1/0, 0x100000001, -(2**53), -0x080000000, 0x100000000, -0x07fffffff, -0x0ffffffff, 1/0, 0/0, 1, -Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, -0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-45472219*/count=442; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.fround((Math.fround((Math.cosh((Math.log(( ! (( + x) | 0))) | 0)) | 0)) % Math.fround(mathy2((( - ((x + Math.atan2(x, x)) >>> 0)) >>> 0), (( ! Math.cbrt(Math.clz32(mathy1(y, x)))) | 0))))) | 0) ? (Math.fround(Math.imul(( + ((void options('strict')))), (( - Math.fround(Math.atan2(( + (( + y) != x)), x))) >>> 0))) | 0) : (( - (( ~ (mathy2(x, ( + ( + Math.abs(( + y))))) >>> 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy3, /*MARR*/[{x:3}, (0/0), new Number(1), false, {x:3}, {x:3}, new Number(1), (0/0), false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, Number.MAX_VALUE, {x:3}, false, false, {x:3}, {x:3}, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), false, Number.MAX_VALUE, {x:3}, new Number(1), {x:3}, new Number(1), (0/0), (0/0), {x:3}, {x:3}, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, new Number(1), Number.MAX_VALUE, (0/0), new Number(1), Number.MAX_VALUE, {x:3}, (0/0), {x:3}, false, false, Number.MAX_VALUE, {x:3}, {x:3}, new Number(1), Number.MAX_VALUE, Number.MAX_VALUE, false, (0/0), new Number(1), false]); ");
/*fuzzSeed-45472219*/count=443; tryItOut("mathy0 = (function(x, y) { return ( ~ (Math.imul(Math.fround(( + -0x100000000)), ( + Math.cosh(( + Math.min(-0, (y | 0)))))) | 0)); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 1/0, 0/0, 1.7976931348623157e308, 0x100000000, 0x07fffffff, -1/0, Number.MIN_VALUE, 1, Math.PI, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, 0, 2**53+2, 0x080000001, -0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, -(2**53+2), -0x080000001, 0x080000000, -0x07fffffff, -0x100000001, -0, 0x100000001, -(2**53-2)]); ");
/*fuzzSeed-45472219*/count=444; tryItOut("/*RXUB*/var r = new RegExp(\"((?:(?:([\\\\cZ\\\\x5E-\\\\u008A\\\\f]{4})){1,3}\\\\D))|(?!(?:(?:\\\\s+))**){1}\", \"i\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-45472219*/count=445; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - ( + Math.min((Math.imul((( - Math.asinh(y)) | 0), (y | 0)) | 0), (((((((( + x) | 0) & (( + (( + 1.7976931348623157e308) ? (-0x080000001 | 0) : ( + (Math.log2(x) >>> 0)))) | 0)) | 0) | 0) == (x | 0)) | 0) | 0)))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, 1/0, -0x0ffffffff, 2**53-2, 0, -Number.MIN_VALUE, -0x100000001, Math.PI, 0x080000001, 2**53+2, 1, -(2**53-2), -0x07fffffff, 0/0, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, -(2**53), 0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, 2**53, 42, -0x080000001, 0x07fffffff, -0, 0x080000000, -0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=446; tryItOut("let x = NaN = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(y) { print(window); }, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: String.prototype.padEnd, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { throw 3; }, iterate: undefined, enumerate: function() { return []; }, keys: undefined, }; })( '' ),  /x/g );t2.__proto__ = f2;");
/*fuzzSeed-45472219*/count=447; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + ( ~ ( + (( + ( + Math.max(((x | y) >>> 0), (y << y)))) - Math.round(Math.pow(-0x080000000, (0.000000000000001 / y))))))); }); ");
/*fuzzSeed-45472219*/count=448; tryItOut("hoaoba(x, window);/*hhh*/function hoaoba(){m1.get(this.h0);}");
/*fuzzSeed-45472219*/count=449; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3?\", \"m\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-45472219*/count=450; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=451; tryItOut("e0.toString = (function() { a2[14] = m0; return t2; });");
/*fuzzSeed-45472219*/count=452; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((((( - (Math.fround(Math.min(Math.log1p(( ~ (y | 0))), Math.fround(( - Math.fround(( ! y)))))) >>> 0)) >>> 0) >>> 0) % (mathy1((Math.atan2(Math.fround((Math.cos(Math.fround(x)) | 0)), (Math.log1p(( - ((x | 0) < x))) / ((( + Math.atan(x)) ? (y | 0) : (y | 0)) | 0))) | 0), Math.fround(((-Number.MIN_SAFE_INTEGER | (Math.atan2(y, 2**53) | 0)) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x080000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, -0x080000001, 1, 0x080000001, Number.MAX_VALUE, 42, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, 0x100000000, -0x100000000, 0.000000000000001, -0x100000001, 2**53+2, Math.PI, 0, 0x100000001, -(2**53+2), -0x0ffffffff, -1/0, -0, 0x080000000, 0/0, 1/0, Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-45472219*/count=453; tryItOut("h1 + '';print(uneval(g0.p2));");
/*fuzzSeed-45472219*/count=454; tryItOut("testMathyFunction(mathy5, [0x07fffffff, -(2**53-2), -(2**53), 2**53+2, 0.000000000000001, -0x0ffffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), -0x080000001, -0x100000001, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 0x100000001, 2**53, -0x080000000, -Number.MIN_VALUE, -1/0, -0, 42, 0/0, 0, Number.MIN_VALUE, -0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-45472219*/count=455; tryItOut("o0 + g2.g1;");
/*fuzzSeed-45472219*/count=456; tryItOut("/*MXX2*/g0.Boolean = g1.i2;");
/*fuzzSeed-45472219*/count=457; tryItOut("h1.getOwnPropertyDescriptor = (function() { try { Array.prototype.sort.apply(o0.o1.a1, [(function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((0x2dfa6649) == (0x233f2460));\n    return ((((((i0))>>>(((imul((0xffffffff), (0x32e86bd1))|0) != (((0xffffffff)) << ((0xf9fe0953))))+((0x3f2f4e44) >= (((0x7ba9c33d))>>>((0x8bc3c6c4))))-((-0x8000000) ? (0xffffffff) : (0xfa1296ad)))))-(i0)-((-1.5111572745182865e+23) >= (+(1.0/0.0)))))|0;\n  }\n  return f; }), p1]); } catch(e0) { } print(g2); return i2; });");
/*fuzzSeed-45472219*/count=458; tryItOut("mathy2 = (function(x, y) { return (( + Math.imul(((( + ((x ? Math.atan2((y % Number.MAX_VALUE), Number.MAX_VALUE) : y) | 0)) <= Math.fround(Math.min(( + (Math.log(y) | 0)), (y | 0)))) >>> 0), ((( ! Math.sinh(y)) >>> 0) >>> 0))) !== Math.fround(mathy1(mathy1((Math.expm1((( + Math.pow(( + -Number.MIN_SAFE_INTEGER), (y | 0))) | 0)) | 0), (y | 0)), Math.fround(Math.clz32(y))))); }); ");
/*fuzzSeed-45472219*/count=459; tryItOut("v2 = this.g1.runOffThreadScript();");
/*fuzzSeed-45472219*/count=460; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! (( + (Number.MIN_SAFE_INTEGER ? ( + ( + Math.sign(( + x)))) : ( + (x & (0.000000000000001 + x))))) == Math.clz32((mathy3((( + Math.atanh(x)) !== -Number.MIN_VALUE), 0x080000001) >>> 0)))); }); ");
/*fuzzSeed-45472219*/count=461; tryItOut("\"use strict\"; /*bLoop*/for (let ddejup = 0; ddejup < 3; ++ddejup) { if (ddejup % 3 == 0) { print(x); } else { v0 = a0.length; }  } ");
/*fuzzSeed-45472219*/count=462; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + ( + Math.cosh(( + ( + Math.cosh(( + ((( - (1.7976931348623157e308 | 0)) | 0) ^ 0x080000000)))))))); }); testMathyFunction(mathy5, [-0x100000000, 2**53, 0x100000000, -0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, 0/0, 42, -Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, Number.MIN_VALUE, -0, -(2**53+2), Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, -(2**53-2), 2**53-2, 0x100000001, -1/0, 0, 0x07fffffff, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, 1, 0.000000000000001, 0x080000000, -0x080000000]); ");
/*fuzzSeed-45472219*/count=463; tryItOut("testMathyFunction(mathy3, [-0x080000000, 1.7976931348623157e308, 2**53, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, -(2**53+2), -(2**53), 0/0, 1, Number.MAX_VALUE, -(2**53-2), 0.000000000000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -0, 42, -1/0, 2**53+2, 0, -Number.MIN_VALUE, -0x0ffffffff, -0x080000001, 0x100000000, Math.PI, 0x080000000, -0x100000000]); ");
/*fuzzSeed-45472219*/count=464; tryItOut("/*vLoop*/for (let lthusl = 0; lthusl < 29; ++lthusl) { let a = lthusl; o0.s2 = t1[({valueOf: function() { {}return 13; }})]; } ");
/*fuzzSeed-45472219*/count=465; tryItOut("\"use strict\"; if((x % 28 == 5)) /*MXX2*/g1.Object.prototype.toLocaleString = i0; else  if (Math.pow(13,  /x/ .yoyo(20))) a else o2.t0[11] = yield  '' ;");
/*fuzzSeed-45472219*/count=466; tryItOut("mathy0 = (function(x, y) { return ( ! Math.cbrt(Math.min((((( + Math.log(y)) | 0) * (x | 0)) | 0), ( + (y === ( ~ y)))))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, 1/0, Number.MIN_VALUE, 0x100000001, 1.7976931348623157e308, 0x080000001, 2**53, -0x100000001, 42, 0/0, 0.000000000000001, -0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0, 0x0ffffffff, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, -0, -1/0, 0x100000000, Math.PI, -(2**53-2), 2**53-2, 1, 0x07fffffff, -0x080000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=467; tryItOut("e1.delete(a0);");
/*fuzzSeed-45472219*/count=468; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 0x080000000, -0x080000000, -(2**53+2), 0x080000001, -(2**53), 1.7976931348623157e308, -0x07fffffff, 0x07fffffff, 1, 0x0ffffffff, -Number.MAX_VALUE, -0x080000001, Math.PI, Number.MIN_VALUE, 0/0, 2**53+2, -0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, -(2**53-2), 0x100000000, 42, -0, -0x100000001, Number.MAX_VALUE, 2**53, 0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=469; tryItOut("mathy0 = (function(x, y) { return Math.ceil((Math.cbrt(((Math.fround(( ~ y)) | (Math.max((x >>> 0), y) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[function(){}, function(){}, function(){}, function(){}, null, Number.MAX_SAFE_INTEGER, function(){}, (-1/0), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=470; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    switch ((0x6ed0ce1b)) {\n    }\n    d1 = (+/*FFI*/ff((((((~((+(((i0) ? (-1.2089258196146292e+24) : (d1)))))))) & ((i0)-(i0))))));\n    i0 = ((0xffffffff));\n    return +((Infinity));\n  }\n  return f; })(this, {ff: decodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x0ffffffff, 42, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), 2**53, 0, -0x100000000, 2**53-2, -(2**53+2), 0/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53+2, Math.PI, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, -Number.MIN_VALUE, 0x080000000, 0.000000000000001, Number.MAX_VALUE, 0x100000001, -1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, -0, 0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-45472219*/count=471; tryItOut("/*RXUB*/var r = r1; var s = s1; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=472; tryItOut("y = (new Int16Array( /x/ ));Object.seal(g2);");
/*fuzzSeed-45472219*/count=473; tryItOut("{b0 = t1.buffer;\nm1.delete(e0);\nh1.get = f0; }/*MXX3*/g0.DataView.prototype.buffer = g0.DataView.prototype.buffer;");
/*fuzzSeed-45472219*/count=474; tryItOut("mathy0 = (function(x, y) { return (Math.atan((y >= y)) || (Math.atan2(Math.fround(Math.min(Math.cosh(x), x)), (((Math.cosh(Math.cbrt(Math.fround((Math.acosh((y | 0)) | 0)))) | 0) ^ Math.fround(Math.cos((Math.atan2(-Number.MIN_SAFE_INTEGER, 0/0) | 0)))) | 0)) + Math.log1p((Math.round(x) ^ Math.fround(Math.acos(x)))))); }); ");
/*fuzzSeed-45472219*/count=475; tryItOut("");
/*fuzzSeed-45472219*/count=476; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-45472219*/count=477; tryItOut("var r0 = x / x; var r1 = r0 ^ x; var r2 = r0 / r0; var r3 = r0 - 8; var r4 = r1 + x; var r5 = x ^ 6; r5 = r4 & 1; print(r4); var r6 = 4 / 3; var r7 = 1 & r4; r2 = r4 / r5; var r8 = r7 | r1; var r9 = r2 - x; var r10 = 5 - r8; r5 = r4 * r0; var r11 = r4 ^ 0; print(r10); var r12 = 4 + r0; var r13 = r9 & r2; var r14 = 1 / r3; var r15 = 6 ^ 0; var r16 = x - r6; var r17 = 7 / r6; r4 = r16 + 6; var r18 = x / 6; print(r12); var r19 = 4 / r16; ");
/*fuzzSeed-45472219*/count=478; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy1(((( + Math.log10(( + ( ! ( + mathy2(y, x)))))) ? ( + (( + mathy2(( + Math.exp(y)), y)) / ((((Math.max(( - y), (( ! x) >>> 0)) >>> 0) % ((Math.log(y) >>> 0) >>> 0)) >>> 0) & Math.pow(Math.ceil(( + 0x100000000)), y)))) : ( + Math.max(( + (( + y) >> (mathy2((y | 0), (x | 0)) | 0))), ( + (Math.round(( + Math.min(2**53-2, ( + (Math.min((( + Math.log2(x)) >>> 0), (0x100000001 >>> 0)) >>> 0))))) >>> 0))))) >>> 0), (Math.abs(( - Math.max((-0 - ((x < y) << Math.fround(x))), Math.fround((Math.fround(y) ? Math.fround(0x100000000) : Math.fround(x)))))) >>> 0)); }); testMathyFunction(mathy4, /*MARR*/[{}, -0x100000001, {}, {}, /((?!(@)){1073741823,}|.{0}\\b{2}\\3){0}/im, objectEmulatingUndefined(), {}, /((?!(@)){1073741823,}|.{0}\\b{2}\\3){0}/im, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, {}, -0x100000001, objectEmulatingUndefined(), /((?!(@)){1073741823,}|.{0}\\b{2}\\3){0}/im, {}, /((?!(@)){1073741823,}|.{0}\\b{2}\\3){0}/im, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {}, /((?!(@)){1073741823,}|.{0}\\b{2}\\3){0}/im, objectEmulatingUndefined(), /((?!(@)){1073741823,}|.{0}\\b{2}\\3){0}/im, {}, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001]); ");
/*fuzzSeed-45472219*/count=479; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (mathy0((Math.fround((( + (( ! (mathy2(x, y) >>> 0)) ? ( + Math.imul(-Number.MAX_VALUE, Math.fround(Math.imul(y, x)))) : ( + Math.pow(Math.atan2(( + x), y), ( + (0x100000000 | 0)))))) >>> 0)) | 0), (( ! Math.max((Math.pow(-0x100000001, 1/0) | 0), y)) >>> 0)) || (mathy1(Math.fround(Math.expm1(Math.fround(( - ((y | 0) <= (Math.atan(( + x)) >>> 0)))))), y) > (( + Math.fround(( ! x))) >>> 0))); }); testMathyFunction(mathy5, [-0x080000001, 0, -1/0, -(2**53-2), -Number.MAX_VALUE, Math.PI, -0x0ffffffff, 0x07fffffff, -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 42, 0x100000000, -0, -(2**53), 0/0, 2**53-2, -0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 0x0ffffffff, 2**53, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1, 1/0]); ");
/*fuzzSeed-45472219*/count=480; tryItOut("\"use strict\"; Array.prototype.pop.call(a1, t1, o2, m0, b0);");
/*fuzzSeed-45472219*/count=481; tryItOut("s2 + f1;");
/*fuzzSeed-45472219*/count=482; tryItOut("mathy1 = (function(x, y) { return (Math.sin((Math.sign(( + (Math.hypot(((Math.imul((((Math.fround(((x >>> 0) > (Number.MIN_VALUE >>> 0))) ** Math.PI) >>> 0) >>> 0), y) >>> 0) >>> 0), ((((Math.fround(( + Math.max((Math.atan((42 >>> 0)) >>> 0), -Number.MIN_SAFE_INTEGER))) >>> 0) ^ (((( + x) >>> Math.fround(-0x0ffffffff)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000000, 0x100000001, -0x07fffffff, -0x100000000, -0x100000001, -0, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, 42, 1, -Number.MIN_VALUE, -0x080000000, 0x0ffffffff, 2**53+2, Number.MIN_VALUE, 1/0, 0x080000001, 0/0, 0, 1.7976931348623157e308, -(2**53-2), 2**53-2, Math.PI, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=483; tryItOut("/*RXUB*/var r = g2.r0; var s = \"0\"; print(uneval(s.match(r))); \ng1.e1.add(m1);a0[19];");
/*fuzzSeed-45472219*/count=484; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((( - (( ~ Math.fround((Math.fround(0x100000001) ? ( ! y) : -Number.MIN_SAFE_INTEGER))) >>> 0)) >>> 0) >= (Math.acosh(Math.fround(( + Math.min(( ! ( + x)), ( + ((Math.fround((Math.log((-0x080000001 >>> 0)) >>> 0)) || Math.fround((( + Math.exp(y)) >> x))) >>> 0)))))) >>> 0)); }); ");
/*fuzzSeed-45472219*/count=485; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return ((( + Math.hypot(( + (( - y) | 0)), (Math.fround(x) ? Math.fround(( + y)) : Math.fround(-Number.MAX_VALUE)))) | 0) && ( - Math.acosh(( + Math.min(x, Math.hypot((0x100000001 | 0), y)))))); }); testMathyFunction(mathy0, [0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, 42, Math.PI, -Number.MAX_VALUE, 0x080000000, 0x0ffffffff, 1/0, 1, -0x080000001, Number.MIN_VALUE, 2**53+2, 0, -(2**53-2), -(2**53+2), 0x100000000, -0x100000001, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, -0x080000000, -(2**53), 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0, 2**53, 0/0]); ");
/*fuzzSeed-45472219*/count=486; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!(?=\\\\1+$+?){2})((?!(?:(?!([^\\\\x20\\\\v\\\\S]|.)+?))*?))\", \"gym\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-45472219*/count=487; tryItOut("\"use strict\"; e1.add(m1);");
/*fuzzSeed-45472219*/count=488; tryItOut("\"use strict\"; e2.add(g2.a1)\n");
/*fuzzSeed-45472219*/count=489; tryItOut("mathy3 = (function(x, y) { return (( ! ((((( + (((-Number.MIN_SAFE_INTEGER | 0) != (x | 0)) | 0)) | 0) > (Math.sqrt(( ~ Math.fround((Math.fround(Math.min(y, x)) ? Math.fround(x) : y)))) >>> 0)) | 0) | 0)) | 0); }); ");
/*fuzzSeed-45472219*/count=490; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=491; tryItOut("");
/*fuzzSeed-45472219*/count=492; tryItOut("\"use strict\"; e2.has(m1);");
/*fuzzSeed-45472219*/count=493; tryItOut("/*tLoop*/for (let w of /*MARR*/['fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' , function(){},  '\\0' , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, [undefined], [undefined],  '\\0' ,  '\\0' ,  '\\0' , [undefined],  '\\0' ,  '\\0' , function(){}, 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , function(){},  '\\0' ,  '\\0' , [undefined],  '\\0' ,  '\\0' , function(){}, 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' , function(){},  '\\0' , function(){},  '\\0' ,  '\\0' ,  '\\0' , 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' ,  '\\0' , 'fafafa'.replace(/a/g, Date.prototype.getMonth), 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' ,  '\\0' ,  '\\0' , 'fafafa'.replace(/a/g, Date.prototype.getMonth), function(){}, 'fafafa'.replace(/a/g, Date.prototype.getMonth), function(){}, 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' , 'fafafa'.replace(/a/g, Date.prototype.getMonth), 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' ,  '\\0' , function(){}, [undefined],  '\\0' , 'fafafa'.replace(/a/g, Date.prototype.getMonth), 'fafafa'.replace(/a/g, Date.prototype.getMonth), 'fafafa'.replace(/a/g, Date.prototype.getMonth), [undefined], [undefined],  '\\0' , [undefined], [undefined], 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' , function(){},  '\\0' , 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' , function(){}, 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , function(){}, 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' , [undefined],  '\\0' ,  '\\0' , [undefined], function(){},  '\\0' , 'fafafa'.replace(/a/g, Date.prototype.getMonth),  '\\0' , function(){}]) { print(uneval(s2)); }");
/*fuzzSeed-45472219*/count=494; tryItOut("mathy0 = (function(x, y) { return (((Math.log(( + Math.asinh(( + x)))) >>> 0) ? ( + Math.atan2(( + ((y * ((x >>> 0) > (Math.exp(Math.log(2**53-2)) >>> 0))) >>> 0)), ( + ((( - Math.fround(x)) | 0) < Math.log10(((x + x) | 0)))))) : Math.cos(-0.__defineGetter__(\"y\", Object.freeze))) ** (( ~ ( + Math.imul((( + ( + ((Math.cos(Math.fround(Math.fround(( + y)))) * 0) >>> 0))) | 0), -Number.MAX_VALUE))) | 0)); }); ");
/*fuzzSeed-45472219*/count=495; tryItOut("mathy5 = (function(x, y) { return Math.atan2(( + Math.cbrt(((((mathy0(((( + y) < 2**53) >>> 0), -0x080000000) >>> 0) > Math.hypot((x >> Math.atan2(x, ( + y))), ((Math.sign((x | 0)) | 0) | 0))) >>> 0) << (( + Math.sin(( + (y - ((-Number.MAX_SAFE_INTEGER == (x >>> 0)) >>> 0))))) >>> 0)))), (mathy3((mathy1((y | 0), (( + Math.atan(( + -(2**53+2)))) | 0)) | 0), Math.log10(y)) ? Math.fround((mathy1((x | 0), (Math.fround((Math.hypot((y | 0), (Math.log1p(x) | 0)) | 0)) | 0)) | 0)) : (( + (mathy2((Math.expm1(x) >>> 0), (( + ( ~ ( + y))) | 0)) >>> 0)) | 0))); }); testMathyFunction(mathy5, [0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -0x100000001, 1/0, 0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), Number.MAX_VALUE, 0x100000001, -0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, 2**53, -Number.MAX_VALUE, -(2**53), 1, Math.PI, Number.MIN_VALUE, 42, 2**53-2, -Number.MIN_VALUE, -0x080000001, -(2**53+2), 0, 2**53+2, -1/0, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff]); ");
/*fuzzSeed-45472219*/count=496; tryItOut("testMathyFunction(mathy0, [-0x07fffffff, -1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), 0.000000000000001, 1.7976931348623157e308, 0x0ffffffff, 0, 1, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 0x080000000, 2**53, 0/0, -0x100000000, 0x100000000, 0x100000001, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -0, -0x080000000, -Number.MIN_VALUE, 42, -(2**53+2), 0x080000001, -0x100000001, -0x080000001, -(2**53-2), 2**53-2]); ");
/*fuzzSeed-45472219*/count=497; tryItOut("mathy4 = (function(x, y) { return ( + Math.hypot(Math.tanh((( + y) != ( + Math.max(x, (Math.cosh(((Math.fround(x) || y) >>> 0)) >>> 0))))), ( + Math.pow((Math.sinh((mathy1((mathy2((Math.fround(y) >>> 0), -0x0ffffffff) >>> 0), ( - y)) >>> 0)) | 0), ( - (Math.max(( + y), ((Math.sin(y) | 0) >>> 0)) | 0)))))); }); ");
/*fuzzSeed-45472219*/count=498; tryItOut("g1.a0[17] = ();");
/*fuzzSeed-45472219*/count=499; tryItOut("\"use strict\"; this.b2 + '';");
/*fuzzSeed-45472219*/count=500; tryItOut("t2 = new Uint8Array(a2);");
/*fuzzSeed-45472219*/count=501; tryItOut("\"use strict\"; yield null;function b()/.\\3{4,}/mselectforgc(o1);");
/*fuzzSeed-45472219*/count=502; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=503; tryItOut("\"use strict\"; /*hhh*/function wngkbf(){throw this;}/*iii*/Object.seal(g0.i0);");
/*fuzzSeed-45472219*/count=504; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=505; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[new String(''), (1/0), (1/0), (1/0), new Boolean(false), new String('q'), new String(''), new String('q'), (1/0), (1/0), new String('q'), new String(''), new String(''), new String('q'), new String(''), new String(''), new Boolean(false), (1/0), new String(''), new String('q'), new Boolean(false), new String(''), new String(''), new String(''), new String('q'), (1/0), new Boolean(false), new Boolean(false), new String('q')]) { ( /x/g ); }");
/*fuzzSeed-45472219*/count=506; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2((( + (Math.fround(mathy2(Math.fround(mathy1((Math.sqrt((x >>> 0)) | 0), Math.fround((Math.fround(x) ^ Math.fround(Math.log((x >>> 0))))))), Math.fround(Math.acos((x | 0))))) >>> 0)) >>> 0), ( + Math.cos(( + x)))); }); ");
/*fuzzSeed-45472219*/count=507; tryItOut("/*RXUB*/var r = /((?=\\1{17179869183,}|[^]{2,}\\2*|(.){3,}[\\\u00ce\\s]*)?)/gi; var s = \"\\n\\n_\\n\\n\\n\\n\\n\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=508; tryItOut("s0 += 'x';");
/*fuzzSeed-45472219*/count=509; tryItOut("mathy4 = (function(x, y) { return ( ~ Math.log(Math.fround(Math.exp((( - (y | 0)) | 0))))); }); testMathyFunction(mathy4, /*MARR*/[new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1)]); ");
/*fuzzSeed-45472219*/count=510; tryItOut("\"use strict\"; s0 += s0;");
/*fuzzSeed-45472219*/count=511; tryItOut("\"use strict\";   = eval(\"\\\"use strict\\\"; mathy1 = (function(x, y) { return Math.acos(mathy0(Math.fround(( + Math.exp(( + (( ~ x) >>> 0))))), (( ! ( + ((Math.fround(( ~ Math.fround(( + (Math.asin(x) | 0))))) >>> 0) < (( ! x) | 0)))) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, arguments.caller, arguments.caller]); \", (4277)), eval = (4277), jdwjsh;print(15);");
/*fuzzSeed-45472219*/count=512; tryItOut("\"use strict\"; \"use strict\"; { void 0; void relazifyFunctions(this); }");
/*fuzzSeed-45472219*/count=513; tryItOut("\"use strict\"; m0.delete(b2);");
/*fuzzSeed-45472219*/count=514; tryItOut("v0 = Object.prototype.isPrototypeOf.call(o1.p2, f1);");
/*fuzzSeed-45472219*/count=515; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.min(( + ( + ( ~ ( + Math.ceil(Math.asin(2**53-2)))))), ( + ( + (Math.fround(( + (y >>> -(2**53-2)))) >>> 0)))); }); testMathyFunction(mathy4, [2**53, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -0x100000001, Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, 0/0, -1/0, 42, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, 0x080000001, -0x080000000, 2**53+2, -(2**53+2), 1, 1/0, 0x100000001, 0x07fffffff, 0x080000000, 0, -Number.MAX_VALUE, 2**53-2, -(2**53), 0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -0, -0x080000001]); ");
/*fuzzSeed-45472219*/count=516; tryItOut("v2 = g0.eval(\"/* no regression tests found */\");this.v2 = new Number(f0);");
/*fuzzSeed-45472219*/count=517; tryItOut("\"use asm\"; f1(f0);const z = \"\\u9A87\";");
/*fuzzSeed-45472219*/count=518; tryItOut("\"use strict\"; v1 = a1.length;");
/*fuzzSeed-45472219*/count=519; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=520; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"\\\\w\", \"gim\"); var s = \"`\"; print(s.split(r)); ");
/*fuzzSeed-45472219*/count=521; tryItOut("mathy0 = (function(x, y) { return (( + (( ~ ( + (((( + x) | ( + 0)) | 0) / ( + x)))) | 0)) || ((Math.log1p((( + Math.sin(( + Math.exp(x)))) >>> 0)) >>> 0) | 0)); }); ");
/*fuzzSeed-45472219*/count=522; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return (( + (( ! (mathy0(( + ( ! ( + ( + ( ~ y))))), x) >>> 0)) >>> 0)) < (Math.min((( + Math.trunc(mathy0(y, x))) | 0), ((( - Math.abs((y , ( ! -(2**53-2))))) | 0) | 0)) | 0)); }); testMathyFunction(mathy1, [Math.PI, 1/0, -1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, 2**53+2, 1.7976931348623157e308, -(2**53+2), 0x0ffffffff, 0x07fffffff, -0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, 2**53-2, -0x07fffffff, 0x080000000, 1, -0x080000001, -(2**53), Number.MAX_VALUE, 0x100000001, 0, -Number.MIN_VALUE, 0/0, -0]); ");
/*fuzzSeed-45472219*/count=523; tryItOut("\"use strict\"; g2.e2.toString = Array.prototype.indexOf.bind(g0);");
/*fuzzSeed-45472219*/count=524; tryItOut("return (eval = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"(?!(.|\\\\s.?\\\\s?)*?)\", \"g\")), /*wrap1*/(function(){ \"use strict\"; p0 = h2;return this})(), decodeURIComponent)) += (makeFinalizeObserver('tenured'));");
/*fuzzSeed-45472219*/count=525; tryItOut("o2.m0.get(this.m0);");
/*fuzzSeed-45472219*/count=526; tryItOut("mathy4 = (function(x, y) { return (( + ( ! ( + ( + Math.clz32(Math.fround((( ! Math.acosh(( + Math.clz32(mathy0(y, y))))) | 0))))))) ? Math.hypot((mathy1(( + x), (Math.fround((( ! Math.clz32(( + -0x100000001))) | 0)) | 0)) | 0), ((Math.asin(((Math.max(x, mathy3((0/0 | 0), (-(2**53-2) | 0))) ? Math.fround(( + (Math.pow(x, 0x080000000) >>> 0))) : Math.fround(Math.sin(Math.fround(x)))) | 0)) >>> 0) | 0)) : ( ! ( + (Math.min((x >>> 0), (y >>> 0)) - Math.min((1 >>> 0), y))))); }); testMathyFunction(mathy4, [Math.PI, -(2**53+2), 42, -0x0ffffffff, -(2**53-2), 1.7976931348623157e308, -0x07fffffff, 1/0, 0x080000001, 2**53, -0, 0x07fffffff, 0, 2**53-2, 0/0, -(2**53), 0x100000001, -0x100000000, -1/0, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, -0x080000001, Number.MAX_VALUE, 2**53+2, -0x100000001, 0x100000000, 0x0ffffffff, 0.000000000000001, 0x080000000]); ");
/*fuzzSeed-45472219*/count=527; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = ((((((!(0x941adaf5))+(0x525bf11e)+((0x1418e5e8) ? ((-8388609.0) < (513.0)) : ((imul((0x9ef0bdf2), (-0x8000000))|0)))) << ((-1.5111572745182865e+23))))));\n    }\n    return +((+(0.0/0.0)));\n    return +((-295147905179352830000.0));\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ p2 = t1[9];return objectEmulatingUndefined})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53), 0x100000000, 1/0, -0x100000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 2**53-2, 0x080000000, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -0x080000000, 0x07fffffff, 1, -0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, Number.MAX_SAFE_INTEGER, 42, 0, -0, 0x080000001, Number.MAX_VALUE, Math.PI, -(2**53+2), -0x100000001, -0x0ffffffff, 0x100000001, -0x07fffffff, 0.000000000000001, 2**53]); ");
/*fuzzSeed-45472219*/count=528; tryItOut("\"use strict\"; do {/((?![^]))*|\\D|(?:\\b)|[\\D\\ufD1f-\\x43\\S]+?*?{4}|(?!.){4,}|.*?/ym;/(?!(?:\\3){4}){2,}/yim; } while((Math.pow(16, arguments)) && 0);");
/*fuzzSeed-45472219*/count=529; tryItOut("/*RXUB*/var r = /[^]/; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=530; tryItOut("\"use strict\"; with(this)switch(timeout(1800)) { case (for (var p in g2) { try { v0 = a0.length; } catch(e0) { } try { selectforgc(o1); } catch(e1) { } try { /*ADP-1*/Object.defineProperty(g2.a1, 2, ({writable: (x % 43 != 8)})); } catch(e2) { } f0.__proto__ = o0; }): default: g2.offThreadCompileScript(\"function this.f1(t0)  { \\\"use strict\\\"; \\\"use asm\\\"; return window } \", ({ global: o1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 != 5), noScriptRval: false, sourceIsLazy: true, catchTermination: [[]] }));\nprint(x);\n }");
/*fuzzSeed-45472219*/count=531; tryItOut("\"use strict\"; this.t1 = a2[0];");
/*fuzzSeed-45472219*/count=532; tryItOut("\"use strict\"; e1 = new Set;");
/*fuzzSeed-45472219*/count=533; tryItOut("var x = (4277);s0 = new String;");
/*fuzzSeed-45472219*/count=534; tryItOut("\"use strict\"; let d = ;Array.prototype.forEach.call(a1, (function() { for (var j=0;j<54;++j) { f0(j%5==1); } }), s1, f2);");
/*fuzzSeed-45472219*/count=535; tryItOut("t1.set(a2, 14);");
/*fuzzSeed-45472219*/count=536; tryItOut("testMathyFunction(mathy4, [2**53-2, -(2**53+2), -(2**53-2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, 0/0, Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, Number.MAX_VALUE, -0, 0x100000001, -0x07fffffff, 0x080000000, 42, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53, -0x100000001, 0x080000001, 0x100000000, Math.PI, -Number.MIN_VALUE, 1/0, 0, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000000, -(2**53), -0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53+2]); ");
/*fuzzSeed-45472219*/count=537; tryItOut("return;let(e) ((function(){for(let w in []);})());");
/*fuzzSeed-45472219*/count=538; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3(?:\\\\B)(?=(?=\\\\W))+?\", \"im\"); var s = \"\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=539; tryItOut("\"use strict\"; with({b: new RegExp(\"\\\\s|$\\\\d{3,}+?{0,}\", \"i\")}){Array.prototype.reverse.call(g0.a2, f1, t0, b1); }");
/*fuzzSeed-45472219*/count=540; tryItOut("testMathyFunction(mathy2, [-0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, 0x100000001, 1, 0x080000000, Number.MIN_VALUE, -0x100000000, 1/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, -(2**53+2), -0x07fffffff, 2**53, Number.MAX_VALUE, -1/0, 0x080000001, -(2**53-2), 0x0ffffffff, -0x0ffffffff, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, -0, 0, 0x100000000, 0x07fffffff, 42, -Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-45472219*/count=541; tryItOut("\"use strict\"; a0.shift(b0);o1.o1.h1 = f0;");
/*fuzzSeed-45472219*/count=542; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-45472219*/count=543; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[0x3FFFFFFE, false, false, 0x3FFFFFFE, function(){}, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, new String('q'), new String('q'), 0x3FFFFFFE, {}, false, function(){}, false, new String('q'), 0x3FFFFFFE, new String('q'), false, function(){}, function(){}, function(){}, function(){}, false, 0x3FFFFFFE, function(){}, new String('q'), function(){}, function(){}, function(){}, 0x3FFFFFFE, {}, function(){}, false, new String('q'), {}]); ");
/*fuzzSeed-45472219*/count=544; tryItOut("{ void 0; bailout(); }");
/*fuzzSeed-45472219*/count=545; tryItOut("\"use strict\"; for (var v of t1) { try { v1 = evaluate(\"function f1(b0) ({b0, b: {x, d: {}}, x: {x: [{b0: arguments}], x: {}}} = x)\", ({ global: o1.g2, fileName: null, lineNumber: 42, isRunOnce: (x % 6 != 0), noScriptRval: true, sourceIsLazy: false, catchTermination: true })); } catch(e0) { } try { g2.v1 = this.m2.get(a0); } catch(e1) { } try { /*ADP-1*/Object.defineProperty(a0, g2.v2, ({enumerable: false})); } catch(e2) { } p1 + ''; }");
/*fuzzSeed-45472219*/count=546; tryItOut(";");
/*fuzzSeed-45472219*/count=547; tryItOut("mathy4 = (function(x, y) { return (( + mathy2(( + Math.log2((x % y))), Math.tanh((((Math.fround(-Number.MAX_SAFE_INTEGER) * Math.fround(/* no regression tests found */)) | 0) >>> 0)))) ? Math.fround(Math.asinh(Math.fround(( - (Math.clz32((mathy3(x, (mathy1(((Number.MIN_SAFE_INTEGER ? x : y) >>> 0), (y >>> 0)) >>> 0)) >>> 0)) >>> 0))))) : (({split: new RegExp(\"\\\\1+?\", \"gyim\") })) %= y); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0, 42, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, Number.MIN_VALUE, 2**53, 0x080000001, 0x07fffffff, -0x0ffffffff, 0/0, Math.PI, 0x100000000, 0, 1, 0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000000, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53+2), -1/0, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-45472219*/count=548; tryItOut("v1 = Object.prototype.isPrototypeOf.call(f0, f1);");
/*fuzzSeed-45472219*/count=549; tryItOut("M:for([x, e] = NaN || x in new function(y) { \"use strict\"; return undefined }(\"\\u8E58\",  \"\" )) p0.valueOf = (function() { f2.valueOf = function  x (a)\"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (((1.0)) / ((((!((0x409dd8d6)))-((~((0x445cb943)+(0xffffffff)+(0xa5379abc))) != (imul(((0xffffffff) ? (-0x8000000) : (0xfa11a258)), ((-257.0) == (1.0078125)))|0))) & (((((0xbc754d4c))>>>((0x86c650aa))) == (0xc42130a5))+(0xffdf53f4)-((((0x57054b6a)) >> ((0xf951bd00)+(0x95e19914))))))));\n    d0 = (+abs(((Infinity))));\n    d0 = (+(0xdbb13ff0));\n    return +((let (b = (makeFinalizeObserver('tenured'))) /(?!(\\w|^){2,})/gi.__defineGetter__(\"b\", function(y) { this; })));\n  }\n  return f;; return s0; });");
/*fuzzSeed-45472219*/count=550; tryItOut("v2 = a2.length;");
/*fuzzSeed-45472219*/count=551; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x080000000, -Number.MAX_VALUE, 0x07fffffff, -(2**53), -0x07fffffff, -0x100000001, 42, -Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, -0x080000001, 2**53-2, 0x0ffffffff, -(2**53-2), 0x080000000, 0/0, 0x100000001, 2**53, -0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, -(2**53+2), 1, Math.PI, 0.000000000000001, 1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=552; tryItOut("\"use strict\"; m0.has(g2);");
/*fuzzSeed-45472219*/count=553; tryItOut("\"use asm\"; testMathyFunction(mathy0, [1/0, 2**53-2, 0, 0x080000001, -0x080000000, 1.7976931348623157e308, -0x100000000, 42, Number.MAX_VALUE, -(2**53-2), 0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, -0x0ffffffff, 1, 0x100000001, -(2**53+2), 0x0ffffffff, 0x100000000, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -0, 0x080000000, -0x100000001, -1/0, -0x07fffffff, 2**53]); ");
/*fuzzSeed-45472219*/count=554; tryItOut("let (y) { /*oLoop*/for (var tjkcdu = 0; tjkcdu < 30; ++tjkcdu) { -0; }  }");
/*fuzzSeed-45472219*/count=555; tryItOut("/*bLoop*/for (let azbmbq = 0; azbmbq < 0; ++azbmbq) { if (azbmbq % 4 == 0) { var hjypfj = new SharedArrayBuffer(4); var hjypfj_0 = new Int16Array(hjypfj); print(hjypfj_0[0]); hjypfj_0[0] = 2; i0.send(a1);h1.set = f0;o0 + f2;print(null);print(x); } else { a2.forEach((function() { try { o1.i2.toString = (function() { try { for (var p in p0) { m2.set(g1, ({a2:z2})); } } catch(e0) { } try { ({}); } catch(e1) { } try { /*RXUB*/var r = r0; var s = s0; print(uneval(s.match(r))); print(r.lastIndex);  } catch(e2) { } for (var v of h1) { v0 = r1.flags; } throw m1; }); } catch(e0) { } try { f1 + b0; } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(m1, this.o1); return e2; }), i1); }  } ");
/*fuzzSeed-45472219*/count=556; tryItOut("\"use strict\"; M: for (b of 1) {eval-28; }");
/*fuzzSeed-45472219*/count=557; tryItOut("testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000000, -0x0ffffffff, -0x07fffffff, -(2**53-2), -0x080000000, 1.7976931348623157e308, 0x100000000, 0x100000001, 0x080000001, 0x07fffffff, 0, 1/0, Math.PI, Number.MAX_VALUE, 0/0, 1, 0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -0, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 2**53, 0x0ffffffff, 42, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, -(2**53+2)]); ");
/*fuzzSeed-45472219*/count=558; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy2((Math.max((Math.cbrt(x) >>> 0), ( + Math.fround(mathy1(Math.acosh((( - (( + x) | 0)) | 0)), (( ~ mathy0(x, y)) | 0))))) | 0), (( - (Math.hypot(-0x0ffffffff, x) <= ( + (( + (( ~ ( + x)) | 0)) + ( + 0x100000001))))) | 0)); }); testMathyFunction(mathy4, [-0, 2**53-2, -0x080000001, -(2**53-2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000000, -0x100000000, -(2**53), 1/0, -1/0, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, Math.PI, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000001, -(2**53+2), 1, 0/0, 0.000000000000001, 2**53, 0, 0x100000000, 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-45472219*/count=559; tryItOut("h0.enumerate = f2;o1.m1.delete(m1);function eval(e, b) { \"use strict\"; return x } v0 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-45472219*/count=560; tryItOut("licmgz((4277) <<= (((void version(185))) <<=  /x/ ));/*hhh*/function licmgz(x)\u000c{if( '' ) { if ((((p={}, (p.z = z)()) = (4277)).throw(x))) {function f2(g0)  { \"use strict\"; yield (--(NaN)).watch(\"isFinite\", /*wrap1*/(function(){ s2 = a2.join(s0);return function(y) { var p2 = Proxy.create(h2, this.a0); }})()) }  }} else print(h2);}");
/*fuzzSeed-45472219*/count=561; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var pow = stdlib.Math.pow;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    switch ((abs((((0xf8d9a622)-(0x9070aad2)-(0xaf67f35d)) | ((0x7848a2be)-(0x60f3fbb5)+(0x471faa04))))|0)) {\n      default:\n        i4 = (i4);\n    }\n    d0 = (Infinity);\n    return (((/*FFI*/ff(((~~(+((+pow((((((2147483648.0) + (-65.0))) % ((void options('strict_mode'))))), ((1023.0)))))))), ((imul(((0x2841a8ae)), (i4))|0)), ((+(-1.0/0.0))), ((Infinity)), ((((0x245b7b79) % (-0x5dc74cc)) ^ ((i4)))))|0)+((imul(((abs((0x4dc923c4))|0) < (((0xfb720a84)-(0xbcb3193d)-(0x54d8351f)) << ((-0x8000000) / (0xd9bcf7b)))), (i2))|0))+(i3)))|0;\n    return (((i2)*0xfffff))|0;\n    return ((((i2) ? (i2) : (i2))))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function() { return false; }, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: decodeURI, }; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53), 2**53+2, 0x100000000, 0x080000001, 42, 2**53-2, -0, -0x100000001, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, -Number.MAX_VALUE, Math.PI, 0/0, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, 0x0ffffffff, 1.7976931348623157e308, 0.000000000000001, 1, -(2**53-2), -(2**53+2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 0, -Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 1/0]); ");
/*fuzzSeed-45472219*/count=562; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((( + Math.max(( + mathy1(Math.fround(y), y)), ((y ? ( + Math.tan(( + y))) : ( - x)) | 0))) + ( - Math.hypot(y, Math.fround((y ? x : ( + x)))))) >>> Math.fround(Math.min(( - Math.tanh(( + (Math.acosh((0x080000000 >>> 0)) >>> 0)))), (Math.imul((x | 0), (Math.atan2(Math.fround(Math.fround(Math.cos(Math.fround(x)))), Math.fround((((x | 0) ? (y | 0) : (0.000000000000001 | 0)) ** (x >>> 0)))) | 0)) | 0)))); }); testMathyFunction(mathy5, [2**53-2, 0/0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x0ffffffff, Math.PI, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 1, -0x100000001, Number.MIN_VALUE, -0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, 42, -(2**53+2), -(2**53-2), 0.000000000000001, 0, 1/0, 0x100000000, -1/0, -0, -0x100000000, 1.7976931348623157e308, 0x080000001, -Number.MIN_VALUE, 2**53+2, 0x07fffffff, 0x100000001]); ");
/*fuzzSeed-45472219*/count=563; tryItOut("s1 += s0;");
/*fuzzSeed-45472219*/count=564; tryItOut("\"use strict\"; a0[10] = ( /x/ )();");
/*fuzzSeed-45472219*/count=565; tryItOut("\"use strict\"; with({w: function shapeyConstructor(wntgyf){this[\"getMilliseconds\"] =  /x/g ;for (var ytqvkzwdk in this) { }for (var ytqwrqrii in this) { }return this; }.prototype}){Array.prototype.splice.call(a2, -5, 5, t2, \"\\u5B7E\", g0);m1 = g2.h2; }");
/*fuzzSeed-45472219*/count=566; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-45472219*/count=567; tryItOut("(true);g0.g2.v1 = evalcx(\"function f1(this.t2)  { \\\"use strict\\\"; return \\\"\\\\uD600\\\" } \", g2);");
/*fuzzSeed-45472219*/count=568; tryItOut("v2 = Object.prototype.isPrototypeOf.call(g2, o0);\nthis.a2 + o2;\n");
/*fuzzSeed-45472219*/count=569; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( - (Math.hypot((Math.sinh(y) >>> 0), (( ! ((((Math.cbrt(((( + x) % Math.fround(x)) | 0)) | 0) < y) | 0) | 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53, -Number.MIN_VALUE, -(2**53+2), -0x07fffffff, Number.MIN_VALUE, 0x080000000, 1/0, -0x080000000, 1, 2**53+2, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, -0, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, 42, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0, 0x100000001, 1.7976931348623157e308, -0x100000001, 2**53-2, 0/0, -0x0ffffffff, -1/0, Math.PI, -Number.MAX_VALUE, -0x100000000, 0x080000001]); ");
/*fuzzSeed-45472219*/count=570; tryItOut("v2.toString = (function(j) { if (j) { try { o0.a0.shift(o2); } catch(e0) { } try { print(a0); } catch(e1) { } v1 = g2.runOffThreadScript(); } else { s2 = Array.prototype.join.apply(a2, [g2.s0, h0]); } });");
/*fuzzSeed-45472219*/count=571; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.hypot(Math.log1p(((( + mathy0(Math.PI, ( + (y < ( + x))))) === ((Number.MAX_SAFE_INTEGER + ( + Math.fround((y < Math.fround(0x080000000))))) | 0)) | 0)), (( + ( + x)) >>> 0)); }); ");
/*fuzzSeed-45472219*/count=572; tryItOut("\"use strict\"; Array.prototype.splice.apply(g1.a1, [NaN, 7, x]);w = x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: undefined, }; })(null), (x ? (NaN = -13.__defineSetter__(\"x\", (neuter).bind(window,  /x/g ))) : (x\n)));");
/*fuzzSeed-45472219*/count=573; tryItOut("var d = window;const s0 = '';");
/*fuzzSeed-45472219*/count=574; tryItOut("testMathyFunction(mathy4, [-0x080000000, 2**53-2, -0, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, -(2**53-2), 0x100000000, 0x080000001, -Number.MAX_VALUE, 0x07fffffff, 2**53, 0x0ffffffff, 0/0, 1, 1/0, -0x100000001, 42, -0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -(2**53), -0x07fffffff, -1/0, 0, -0x080000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=575; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.sin(Math.fround(( + (( + (y | 0)) | 0))))); }); ");
/*fuzzSeed-45472219*/count=576; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((((this for (x of this) for (x of this)))-(((-((([[1]])>>>((0x194ea380)))))>>>((this.__defineSetter__(\"c\", (Math.hypot((\"\\uE7E6\".watch(\"getUTCDay\", (arguments.callee.caller.caller.caller).bind( \"\" ))), [1])))))))))|0;\n  }\n  return f; })(this, {ff: WeakSet}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [42, 0/0, 1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, Math.PI, -0x07fffffff, 0x07fffffff, 0, -(2**53), 2**53, -0, Number.MIN_VALUE, 2**53-2, -1/0, 2**53+2, -0x0ffffffff, 0x100000001, 0x080000001, -0x080000001, 1, -0x080000000, Number.MAX_VALUE, 0.000000000000001, -0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-45472219*/count=577; tryItOut("\"use strict\"; x.lineNumber;throw StopIteration;");
/*fuzzSeed-45472219*/count=578; tryItOut("/*RXUB*/var r = /(?!(?:(?=[^\u974f-\\u0044\\cZ-\\0\\d]))*?|(?!\ud76b{3,}))[\u7df3\\D\\b-\u4adf\\r-\\xc5]|(?!(?:\\D|\\D?\\1))+/i; var s = \"\\u00aa\"; print(s.search(r)); ");
/*fuzzSeed-45472219*/count=579; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2(( ! Math.atan2(y, y)), Math.fround(mathy0(Math.fround(Math.fround((( + Math.min(( + (y + (Math.atan(y) >>> 0))), Math.asinh(-1/0))) ? Math.fround(Math.fround(Math.pow(((x >= (x % -0x080000000)) | 0), Math.fround(mathy2((y | 0), (x && -0x080000000)))))) : Math.fround(y)))), Math.fround(Math.log(y))))) ? (Math.sqrt(( - ( + ((Math.pow((y | 0), (( + (y >> y)) | 0)) | 0) && ( + Math.pow(-(2**53), ((( - ((Math.min((0x080000000 | 0), (y | 0)) | 0) | 0)) | 0) >>> 0))))))) >>> 0) : (Math.asin((( - (Math.imul(Math.sqrt(y), ( - -1/0)) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x100000000, 2**53, -0x07fffffff, 0.000000000000001, 0x080000001, -0x080000001, 1, -(2**53-2), 0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, 2**53+2, 0x07fffffff, 1/0, 0/0, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_VALUE, -0x100000001, -0x0ffffffff, 0x080000000, -0x100000000, 1.7976931348623157e308, 0, Math.PI, -(2**53), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=580; tryItOut("{ void 0; minorgc(true); } t2 = new Int16Array(b0, 10, ({valueOf: function() { print(g0);return 9; }}));\no2 = Object.create(v1);\n");
/*fuzzSeed-45472219*/count=581; tryItOut("h2.valueOf = (function(j) { if (j) { try { s1 += 'x'; } catch(e0) { } try { for (var v of m1) { try { a0.unshift(h1, g2.g2, s0, i2, t2, this.i1); } catch(e0) { } try { /*RXUB*/var r = r0; var s = this.s1; print(r.exec(s));  } catch(e1) { } try { /*RXUB*/var r = o1.r1; var s = s0; print(s.match(r));  } catch(e2) { } /*MXX2*/g0.Math.tanh = f0; } } catch(e1) { } try { /*ODP-2*/Object.defineProperty(g1.m0, new String(\"11\"), { configurable: (x % 21 != 6), enumerable: true, get: neuter, set: (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[(((!((0x731ce274) ? (-0x8000000) : (0xf5c930cc))))-(0xa370d62b)-((((0xfdd02046))>>>((0x62dc3339))) <= (((0xd72548a6))>>>((0xa378b8de))))) >> 2]) = ((d1));\n    d1 = (+(1.0/0.0));\n    return ((((d1) < (((-68719476737.0)) / ((+(0x120b8eb7)))))))|0;\n  }\n  return f; }) }); } catch(e2) { } m1 = new WeakMap; } else { try { /*ADP-1*/Object.defineProperty(a0, ({valueOf: function() { v1 = Object.prototype.isPrototypeOf.call(g2.g1.v1, this.p0);/*bLoop*/for (var owqzee = 0; owqzee < 115 && (/(?:[^\\s])|[\\w]/gy); ++owqzee) { if (owqzee % 69 == 35) { /*RXUB*/var r = /(\\cM)*/y; var s = \"\\uffed\"; print(r.exec(s));  } else { print(x); }  } return 19; }}), ({set: /*wrap2*/(function(){ var zzlykt =  '' ; var jwkomc = eval(\"print(0);\", x = x); return jwkomc;})(), configurable: (x % 11 == 6)})); } catch(e0) { } try { m1.has(x); } catch(e1) { } v2 = t2.byteLength; } });");
/*fuzzSeed-45472219*/count=582; tryItOut("o1.a0[12];\n/*vLoop*/for (let yiahtb = 0, zunhoc, x; yiahtb < 30; ++yiahtb) { let b = yiahtb; p1.valueOf = (function() { for (var j=0;j<156;++j) { f2(j%5==1); } }); } \n");
/*fuzzSeed-45472219*/count=583; tryItOut("mathy4 = (function(x, y) { return Math.log1p(Math.fround(Math.imul(Math.fround(((x | 0) > Math.hypot(( - Math.log10(x)), Math.fround(Math.cbrt(((( ~ y) >>> 0) | 0)))))), ( + ( + Math.imul(( + (((x || ( ~ (x | 0))) ? (((Math.fround(mathy3(y, -0x080000001)) != Math.fround(y)) ? x : ( + (( + (1/0 < -(2**53-2))) ^ (x | 0)))) | 0) : (( ! ( ! (x | 0))) >>> 0)) >>> 0)), ( - 0x080000000))))))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, -0x080000000, 0, Number.MIN_VALUE, -(2**53), -(2**53+2), -(2**53-2), -0x080000001, 2**53, -1/0, -0x100000000, 0/0, Number.MAX_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, 1, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, 0x100000000, 0.000000000000001, 42, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, 0x07fffffff, -0]); ");
/*fuzzSeed-45472219*/count=584; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + ( ! Math.hypot(Math.fround(Math.log10(Math.fround(Math.clz32((Math.asin(x) | 0))))), Math.pow(Math.fround((Math.exp((y | 0)) | 0)), Math.fround(Math.max(y, Math.fround(( ~ Math.fround(Math.fround((Math.fround(( - Math.fround(1))) > (x >>> 0)))))))))))); }); testMathyFunction(mathy3, [2**53+2, -0x080000000, -0, 1, -(2**53-2), -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, -0x100000000, -Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 0/0, 0x080000001, -0x080000001, -(2**53), 0x07fffffff, Math.PI, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, 1/0, 2**53, Number.MIN_VALUE, 42, 0.000000000000001, 0x0ffffffff, -1/0, 0x100000001]); ");
/*fuzzSeed-45472219*/count=585; tryItOut("\"use strict\"; ;");
/*fuzzSeed-45472219*/count=586; tryItOut("v0 = (m2 instanceof t1);");
/*fuzzSeed-45472219*/count=587; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.expm1(( + Math.log(( + Math.atan2(( + ( - ( + Math.fround(Math.atan2(Math.fround(x), Math.fround(y)))))), ((Math.atan2(x, 2**53-2) ^ Math.tan(x)) | 0)))))); }); testMathyFunction(mathy0, [-0x080000001, -0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1, -0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -(2**53-2), -0x100000001, 42, 2**53, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53+2, 0x080000000, 2**53-2, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, 0, -0x080000000, 1/0, 0x100000001, Number.MIN_VALUE, -(2**53+2)]); ");
/*fuzzSeed-45472219*/count=588; tryItOut("((timeout(1800)));");
/*fuzzSeed-45472219*/count=589; tryItOut("\"use strict\"; print(b2);");
/*fuzzSeed-45472219*/count=590; tryItOut("mathy5 = (function(x, y) { return ( ~ (( ~ x) - (Math.log1p((Math.hypot(0x0ffffffff, y) | 0)) | 0))); }); testMathyFunction(mathy5, [-(2**53), Number.MAX_VALUE, -(2**53+2), -0x080000000, Math.PI, -0x07fffffff, 0, 2**53, -Number.MIN_VALUE, 0x080000001, 2**53+2, -0x100000000, -1/0, 0x0ffffffff, 2**53-2, -Number.MAX_VALUE, 0/0, 0.000000000000001, 42, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, -0x080000001, -(2**53-2), 1/0, 0x100000001, -0, -0x100000001, 1.7976931348623157e308, 0x100000000, 0x080000000]); ");
/*fuzzSeed-45472219*/count=591; tryItOut("print((4277))");
/*fuzzSeed-45472219*/count=592; tryItOut("/*infloop*/L:for(/*vLoop*/for (var paegen = 0; paegen < 63; ++paegen) { var b = paegen; v0 = evalcx(\"t0[4] = this;\", g2); } ; this; true) {t0 = new Float64Array(t2);/*RXUB*/var r = r0; var s = s2; print(r.test(s));  }");
/*fuzzSeed-45472219*/count=593; tryItOut("/*vLoop*/for (vdicts = 0; vdicts < 58; ++vdicts) { let w = vdicts; /*bLoop*/for (fjjaic = 0; fjjaic < 8; ++fjjaic) { if (fjjaic % 83 == 50) { Array.prototype.shift.call(o1.a1, p0); } else {  }  }  } ");
/*fuzzSeed-45472219*/count=594; tryItOut("o2.v2 = (t2 instanceof m2);");
/*fuzzSeed-45472219*/count=595; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2/yi; var s = \"\\uffed\"; print(s.search(r)); ");
/*fuzzSeed-45472219*/count=596; tryItOut("for (var v of g2) { try { a1.push(g1.o2, o0, a1, b1, g2, m2, t1, i2, f2); } catch(e0) { } try { s2 += 'x'; } catch(e1) { } try { m0 + ''; } catch(e2) { } t2[10] = this.__defineSetter__(\"x\", arguments.callee); }");
/*fuzzSeed-45472219*/count=597; tryItOut("\"use strict\"; x = p0;");
/*fuzzSeed-45472219*/count=598; tryItOut("/*oLoop*/for (var rjxzik = 0; rjxzik < 37; ++rjxzik) { print(14); } let b = Math.asin(-14);");
/*fuzzSeed-45472219*/count=599; tryItOut("o0 = Object.create(o1);");
/*fuzzSeed-45472219*/count=600; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround((Math.fround(Math.tan(( ~ ( + Math.atan2(y, y))))) > Math.hypot(mathy2(Math.cos(Math.sinh(( + (1/0 >>> 0)))), (( ! ( + x)) >>> 0)), Math.tan((Math.pow((x | 0), (y | 0)) == y))))); }); testMathyFunction(mathy4, /*MARR*/[(void 0), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Boolean(true), objectEmulatingUndefined(), (void 0), new Boolean(true), objectEmulatingUndefined(),  /x/g ,  /x/g , new Boolean(true),  /x/g , objectEmulatingUndefined(), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), (void 0), new Boolean(true), (void 0)]); ");
/*fuzzSeed-45472219*/count=601; tryItOut("return undefined;");
/*fuzzSeed-45472219*/count=602; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=603; tryItOut("var lhkhkq = new ArrayBuffer(12); var lhkhkq_0 = new Uint8Array(lhkhkq); var lhkhkq_1 = new Int16Array(lhkhkq); print(lhkhkq_1[0]); lhkhkq_1[0] = -2; var lhkhkq_2 = new Uint32Array(lhkhkq); print(lhkhkq_2[0]); var lhkhkq_3 = new Uint8Array(lhkhkq); var lhkhkq_4 = new Int16Array(lhkhkq); print(lhkhkq_4[0]); lhkhkq_4[0] = -19; var lhkhkq_5 = new Int32Array(lhkhkq); lhkhkq_5[0] = -22; /*RXUB*/var r = new RegExp(\"(?=((?!(?=.{4})|(?:.).){137438953472,}))\", \"yim\"); var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=604; tryItOut("a0.toString = (function() { try { a2 = Array.prototype.slice.call(a2, NaN, 7, i0, f2); } catch(e0) { } v0 = evalcx(\"t1[({valueOf: function() { this.g1.valueOf = (function(j) { if (j) { v1 = evaluate(\\\"v0 = evalcx(\\\\\\\"/* no regression tests found */\\\\\\\", g2);\\\", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 8 == 1), sourceIsLazy: (x % 6 != 0), catchTermination: (x % 3 == 1) })); } else { try { const v1 = new Number(-Infinity); } catch(e0) { } a2[v1]; } });return 18; }})] = this.e0;\", g0); return a1; });");
/*fuzzSeed-45472219*/count=605; tryItOut("mathy1 = (function(x, y) { return Math.min(Math.min((((Math.fround(Math.atan2(Math.fround(0), Math.fround(( ~ (Math.atan((y >>> 0)) >>> 0))))) >>> 0) >= (Math.expm1(( + x)) >>> 0)) >>> 0), Math.min(Math.fround(Math.imul(Math.fround(Math.imul((y >>> 0), Math.fround(( ~ Math.fround(y))))), Math.fround((y & x)))), Math.fround(( + Math.round(-(2**53-2)))))), (Math.min(Math.fround(Math.imul(y, Math.atan2(x, y))), Math.fround(( ! ((Math.fround(Number.MAX_VALUE) < (x | 0)) | 0)))) | 0)); }); testMathyFunction(mathy1, /*MARR*/[0x50505050, (4277), 0x50505050, \"\\u84AB\", \"\\u84AB\", 0x50505050, 0x50505050, 0x50505050, \"\\u84AB\", \"\\u84AB\", (4277), 0x50505050, \"\\u84AB\", (4277), 0x50505050, 0x50505050, (4277), (4277), (4277), (4277), 0x50505050, 0x50505050, \"\\u84AB\", (4277), \"\\u84AB\", \"\\u84AB\", (4277), (4277), (4277), \"\\u84AB\", 0x50505050, \"\\u84AB\", 0x50505050, \"\\u84AB\", \"\\u84AB\", (4277), (4277), (4277), \"\\u84AB\", (4277), (4277), \"\\u84AB\", \"\\u84AB\", (4277), \"\\u84AB\", \"\\u84AB\", (4277), 0x50505050, (4277), \"\\u84AB\", (4277)]); ");
/*fuzzSeed-45472219*/count=606; tryItOut("o2.t2.set(t1, 18);");
/*fuzzSeed-45472219*/count=607; tryItOut("\"use strict\"; /*RXUE*/new RegExp(\"\\u3493\\\\3+\", \"i\").exec(\"\\u3493\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u3493\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u3493\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u3493\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\")");
/*fuzzSeed-45472219*/count=608; tryItOut("\"use strict\"; Array.prototype.shift.apply(a0, []);");
/*fuzzSeed-45472219*/count=609; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (mathy1(( + (( + (Math.max(x, Math.pow(-(2**53+2), mathy2(x, x))) ** x)) ? (( - 0) >>> 0) : (x == y))), Math.fround(((((mathy0((Math.min((x | 0), (( + mathy1(( + x), ( + y))) | 0)) >>> 0), (2**53 | 0)) | 0) >>> 0) === (Math.hypot(-(2**53-2), Math.cbrt((Math.acos(x) | 0))) >>> 0)) >>> 0))) ^ (((Math.max(( + Math.expm1(((( - mathy0((y | 0), -(2**53))) | 0) | 0))), Math.acos((( - x) | 0))) >>> 0) ? (mathy2(x, Math.fround(Math.hypot(y, (mathy2(0x0ffffffff, y) | 0)))) >>> 0) : ((((Math.fround(Math.hypot(Math.fround(Math.log(y)), (x ? x : Math.fround(Math.atan2(Math.fround(x), (Math.fround(( - Math.fround(x))) | 0)))))) | 0) % (y << (Math.max((x >>> 0), (( + (( + y) * ( + -(2**53)))) | 0)) >>> 0))) | 0) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-45472219*/count=610; tryItOut("\"use asm\"; function shapeyConstructor(esqubq){if (esqubq) { switch([z1]) { case 9: print(/*MARR*/[false, 1, (void 0), new Boolean(true), new Boolean(true), (void 0), false, 1, false, (void 0), false, (void 0), false, 1, (void 0), new Boolean(true), false, 1, (void 0), 1, new Boolean(true), 1, (void 0), false, false, (void 0), false, 1, new Boolean(true), new Boolean(true), false, false, 1, new Boolean(true), 1, new Boolean(true), false, false, (void 0), 1, new Boolean(true), false, (void 0), new Boolean(true), false, 1, 1, 1, 1, new Boolean(true), 1, 1, (void 0), (void 0), (void 0), (void 0), new Boolean(true), false, (void 0), 1, new Boolean(true), 1, 1, new Boolean(true), false, 1, new Boolean(true), (void 0), new Boolean(true), 1, 1, (void 0), false, new Boolean(true), (void 0), 1, 1, 1, false, false, (void 0), 1, 1, (void 0), new Boolean(true), (void 0), 1, 1, new Boolean(true), new Boolean(true), false, (void 0), new Boolean(true), (void 0), 1, new Boolean(true), 1, 1, false, false, (void 0)].filter);break; break; default: v0 = Array.prototype.some.apply(this.a0, [(function mcc_() { var zlawqw = 0; return function() { ++zlawqw; if (zlawqw > 5) { dumpln('hit!'); try { m1.delete(a2); } catch(e0) { } e2.has(null); } else { dumpln('miss!'); try { v2 = (h0 instanceof b2); } catch(e0) { } try { t1[18] = \"\\u7E4F\"; } catch(e1) { } try { v0 = evaluate(\"yield esqubq;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: window, catchTermination: false })); } catch(e2) { } const a2 = r0.exec(this.g1.s2); } };})(), o2.p1, this.e1]);break; case \"\\u1CAD\" && window: print(x);case 4: break; case window: break;  } } this[\"toString\"] = (eval(\"\\\"use strict\\\"; mathy2 = (function(x, y) { \\\"use strict\\\"; return (( ! (Math.log2(( ~ (( - ( + Number.MAX_SAFE_INTEGER)) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [null, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), 0, '0', '\\\\0', [], (new Number(-0)), true, (new Boolean(true)), '', objectEmulatingUndefined(), (new Boolean(false)), (new Number(0)), false, 0.1, (new String('')), ({valueOf:function(){return '0';}}), -0, /0/, NaN, (function(){return 0;}), 1, '/0/', [0], undefined]); \"));for (var ytqpofifh in this) { }this[\"toString\"] = -0x100000001;this[\"apply\"] = -0x0ffffffff;this[\"toSource\"] = x;this[\"apply\"] = x;{ { void 0; void gc(this); } } return this; }/*tLoopC*/for (let e of /*MARR*/[x]) { try{let vcpzvf = shapeyConstructor(e); print('EETT'); /* no regression tests found */}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-45472219*/count=611; tryItOut("mathy4 = (function(x, y) { return Math.atan2(this &&  /x/ , Math.min(Math.fround(Math.tan(((y ? ((2**53+2 !== ( + Math.acosh(( + y)))) >>> 0) : ( ! Math.pow(x, x))) | 0))), Math.imul((y | 0), ( + (( ! Math.fround(y)) | 0))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, -0x080000000, 2**53, 2**53+2, 0x07fffffff, -0x080000001, 2**53-2, 0x100000001, 0x100000000, -0x07fffffff, -0x100000000, 1, -Number.MIN_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 0, -0x100000001, -0x0ffffffff, Math.PI, 0/0, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 42, -(2**53-2), -(2**53+2), 0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, 1/0, Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-45472219*/count=612; tryItOut("L:if(x) g2.o2.h1 + v0; else  if (x.yoyo( /* Comment */ \"\" )) {/* no regression tests found */ }");
/*fuzzSeed-45472219*/count=613; tryItOut("\"use strict\"; \"use asm\"; wuscbf, \u3056, NaN, eval, attupr, fblggu, this.x;break L;(/(?=\\s)/gi |  /x/g \u000c);function x(NaN, ...c) { return ((function fibonacci(wrvbyw) { ; if (wrvbyw <= 1) { ; return 1; } ; return fibonacci(wrvbyw - 1) + fibonacci(wrvbyw - 2);  })(2)) } e1.__proto__ = b1;");
/*fuzzSeed-45472219*/count=614; tryItOut("p1 + '';");
/*fuzzSeed-45472219*/count=615; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var acos = stdlib.Math.acos;\n  var cos = stdlib.Math.cos;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 536870912.0;\n    d1 = (d0);\n    {\nnew new RegExp(\"(?:(?!.)|\\\\xb0|(?=\\\\D)|[^]\\\\W{3}|.\\\\xa3?\\\\B|([^]){4,})?\", \"yi\")();    }\n    d1 = (-((+acos((((d0) + (+(-1.0/0.0))))))));\n    {\n      {\n        d0 = (d2);\n      }\n    }\n    (Uint8ArrayView[4096]) = (((void options('strict'))));\n    d2 = (+/*FFI*/ff(((((Uint32ArrayView[((0x4411aaf5)) >> 2])) >> ((((((0x94af57c4))>>>((0x73ae1f87))) / (((0xfb1e6a82))>>>((0x9c3988a3))))>>>(((Function.prototype)))) % (0x1ce7735d))))));\n    (Uint32ArrayView[(((0x850a47))) >> 2]) = (((0x2385e038) >= ((((+(-1.0/0.0)) > (+cos(((d1))))))>>>((0x2778d46))))*-0xe994e);\n    d0 = (d0);\n    return ((((((0x2602bd14))>>>((((-0x8000000))>>>(([x])+(0x9b45f737))) % ((((0x1b5bfb8a))+(0xe200e3ae))>>>(((0x17cc2416) == (0xb722d79))-(0x96c7cd87))))) >= (((0x4fbdd39c))>>>((0xf9447fae)+(/*FFI*/ff(((0x7fffffff)), ((imul((0x17d7583e), (!(0xf8427281)))|0)), ((Float64ArrayView[((0x5e59f85d)) >> 3])), ((~((0x2adc6afd)))), ((6.189700196426902e+26)), ((9223372036854776000.0)), ((2049.0)), ((-4.722366482869645e+21)), ((-65537.0)), ((4097.0)))|0))))))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return (( ! (Math.fround(-0) | 0)) | 0); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [42, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, Number.MAX_VALUE, -0x0ffffffff, 2**53, 0x080000000, 1.7976931348623157e308, 2**53-2, 1, -0x07fffffff, 1/0, 0x080000001, 0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, -0, -0x080000001, 0x100000001, -(2**53-2), 0x0ffffffff, -1/0, 0x07fffffff, Math.PI, -0x100000000, 0.000000000000001, 0x100000000, -(2**53+2), -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=616; tryItOut("print(uneval(p2));");
/*fuzzSeed-45472219*/count=617; tryItOut("\"use strict\"; let (a) { /* no regression tests found */ }\ns0 = new String(this.t1);\n");
/*fuzzSeed-45472219*/count=618; tryItOut("e2 + i0;");
/*fuzzSeed-45472219*/count=619; tryItOut(" '' ;");
/*fuzzSeed-45472219*/count=620; tryItOut("testMathyFunction(mathy3, [2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, -0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, -0x080000000, -(2**53), -0, Math.PI, 2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, 1/0, -0x100000001, -Number.MAX_VALUE, 2**53, 0, 42, -1/0, -0x100000000, Number.MAX_VALUE, 0/0, Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff]); ");
/*fuzzSeed-45472219*/count=621; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + Math.max((( ! ( + (( + ((-Number.MIN_SAFE_INTEGER || y) / x)) >= ( + (mathy1((x | 0), (x | 0)) | 0))))) | 0), ( + Math.pow(( + (( + y) ? ( + y) : ( + -1/0))), ( + ( + (( + ( ~ ( + Math.acos(x)))) - -0x07fffffff))))))) ? ( + (Math.tanh(( ~ (( + Number.MIN_SAFE_INTEGER) >>> 0))) | 0)) : ( + ( + (Math.pow(Math.imul((( + (Math.log1p(y) >>> 0)) >>> 0), Math.pow(( + ( ! y)), Math.fround(x))), Math.pow(Math.fround(Math.imul((x >>> 0), x)), (-0x080000001 >>> 0))) | 0)))); }); testMathyFunction(mathy2, [-(2**53), 0x07fffffff, 0.000000000000001, 0, -(2**53+2), 0/0, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), -0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, -0, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53, 0x100000001, 0x100000000, 2**53+2, 42, -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, Math.PI, -0x0ffffffff, -1/0, 2**53-2, -Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, -0x100000001, 1, 0x080000000]); ");
/*fuzzSeed-45472219*/count=622; tryItOut("/*MXX1*/o2 = g1.Math.atan2;");
/*fuzzSeed-45472219*/count=623; tryItOut("with({}) let(ydixos, window = (new RegExp(\"(\\\\B){2,}|\\ud319|[^]|\\\\W|[^]?\", \"ym\") >>> new RegExp(\"\\\\1\", \"gi\")), x, x, jjzzjo, \u3056, x, okjapr) { return Math.imul(-27, null);}/*ODP-1*/Object.defineProperty(o1.f1, \"__parent__\", ({value: (4277), writable: x}));");
/*fuzzSeed-45472219*/count=624; tryItOut("g0.a0[2] = s1");
/*fuzzSeed-45472219*/count=625; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 2251799813685248.0;\n    d0 = (((-128.0)) / ((+abs(((+(1.0/0.0)))))));\n    d0 = (+(-1.0/0.0));\n    return (((0x68b8411e)))|0;\n    switch ((((0x1f4c1968)) | ((Int16ArrayView[4096])))) {\n      case 0:\n        (Float64ArrayView[((0xab481f37)) >> 3]) = ((576460752303423500.0));\n        break;\n      case -1:\n        d0 = (((d2)) - ((((Float64ArrayView[2])) - ((((4277)) / ((d2)))))));\n      case 0:\n        i1 = (-0x8000000);\n      case 0:\n        {\n          {\n            (Float64ArrayView[2]) = ((d2));\n          }\n        }\n        break;\n      default:\n        {\n          return ((((((0x3889d1b8)))>>>((0x3dccffb2) % (0x36e3fbe3))) / ((((((0x37f90bac) != (0x662d0ee7))) >> (((-274877906945.0) < (536870913.0)))) / (((/*FFI*/ff(((8796093022207.0)), ((-9007199254740992.0)), ((-17592186044417.0)), ((-274877906945.0)), ((-268435457.0)), ((-7.555786372591432e+22)), ((-513.0)), ((-281474976710656.0)), ((8192.0)), ((268435456.0)), ((7.555786372591432e+22)), ((-140737488355329.0)), ((1025.0)), ((73786976294838210000.0)), ((4294967297.0)), ((-3.777893186295716e+22)), ((-73786976294838210000.0)), ((18014398509481984.0)), ((268435457.0)))|0)+((0xf5b9645a))) ^ (((0x6a7182c7))+(-0x8000000))))>>>((0xc0f02a84)-(i1)-(0xffffffff)))))|0;\n        }\n    }\n    {\n      d0 = (+(1.0/0.0));\n    }\n    d0 = ((0x1014aed1));\n    (Int16ArrayView[0]) = (((6)>>>((0xcf0ba598))) / (0x74e6372e));\n    d0 = (1048577.0);\n    switch ((((-0x17064e8) % (0x7cb7e7cf)) & ((/*FFI*/ff(((3.094850098213451e+26)), ((134217729.0)), ((1.5)), ((-131073.0)))|0)+(\"\u03a0\")))) {\n      default:\n        switch ((((Uint16ArrayView[2])) | ((i1)))) {\n          case -3:\n            d2 = (d2);\n            break;\n        }\n    }\n    return ((0x8df62*((new Math.round(this)(x)))))|0;\n  }\n  return f; })(this, {ff: new Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [1.7976931348623157e308, 1/0, 2**53, -Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, 0.000000000000001, 0x080000001, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 2**53+2, -1/0, Number.MAX_VALUE, 0x07fffffff, Math.PI, Number.MIN_VALUE, -0x07fffffff, 0, 42, 2**53-2, 0x080000000, -(2**53), -(2**53+2), -0, 0x100000000, -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-45472219*/count=626; tryItOut("h0.__proto__ = b0;");
/*fuzzSeed-45472219*/count=627; tryItOut("var meldix = new SharedArrayBuffer(8); var meldix_0 = new Uint32Array(meldix); meldix_0[0] = -12; var meldix_1 = new Uint8ClampedArray(meldix); a2.forEach((function() { for (var j=0;j<0;++j) { f2(j%3==1); } }), g1);;v2 = a0.length;/*vLoop*/for (let gsvqvc = 0, this; gsvqvc < 11; ++gsvqvc) { var w = gsvqvc; e1.has(m1); } {}return (yield (z = x));s0 = new String(a1);");
/*fuzzSeed-45472219*/count=628; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return (Math.abs(Math.atan2(y, (y >>> 0))) ? ((Math.asinh(Math.fround((Number.MAX_VALUE - Math.fround(Math.imul(Math.fround(y), Math.fround(( + Math.tan(y)))))))) >>> 0) != Math.imul(( + ( ! Math.fround(y))), (y >>> 0))) : Math.min((y && x), ( ~ ( ~ ((y > x) >>> 0))))); }); ");
/*fuzzSeed-45472219*/count=629; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0x39d309a6);\n    return (((((((((0x34848fab) <= (0x649b832a))-(0x4c2e965b))>>>((i0)+(yield x))) >= (((0x1e53ded3) / (-0x3999d03))>>>((0xb9f63361) % (0xa9a093d4))))) ^ ((((((-0x8000000) != (0x16d14c75))+(0xfdd57777)) << (((((0xffffffff))>>>((0x51999af7)))))) <= ((((0x1d868c5b) != (0x351c1178))-(i0))|0)))) / (((Uint8ArrayView[(((((Int32ArrayView[0])) >> ((Int16ArrayView[4096]))))) >> 0])) & ((-0x8000000)-(-0x8000000)))))|0;\n  }\n  return f; })(this, {ff: mathy2}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [true, -0, (new Number(0)), false, undefined, ({toString:function(){return '0';}}), 0, [0], ({valueOf:function(){return 0;}}), (new Boolean(true)), null, (function(){return 0;}), NaN, ({valueOf:function(){return '0';}}), 1, (new Boolean(false)), '0', (new Number(-0)), '', 0.1, '/0/', objectEmulatingUndefined(), /0/, (new String('')), [], '\\0']); ");
/*fuzzSeed-45472219*/count=630; tryItOut("v1 = m2[\"setFloat32\"];");
/*fuzzSeed-45472219*/count=631; tryItOut("if(false) { if ( /x/g ) {Array.prototype.forEach.call(a2, (function(j) { if (j) { try { /*ODP-3*/Object.defineProperty(f2,  '' , { configurable: (x % 3 != 1), enumerable: \"\\u0EC7\", writable: false, value: i2 }); } catch(e0) { } a2[({valueOf: function() { a1.shift();return 9; }})] = false; } else { try { a0.forEach((function() { try { m1.get(o1); } catch(e0) { } v1 = evaluate(\"print(x);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 4 == 1), sourceIsLazy: (x % 18 == 8), catchTermination: x })); return o2; }), e0, g2.v2, t1, m1, g0, o2.t2); } catch(e0) { } o2.a2 = Array.prototype.filter.call(a1, (function() { try { i2.send(o0); } catch(e0) { } try { f1 = (function() { try { v1 = Object.prototype.isPrototypeOf.call(this.m2, this.p2); } catch(e0) { } try { /*MXX1*/o2 = g0.Date.prototype.getSeconds; } catch(e1) { } Array.prototype.splice.call(a2, 9, ({valueOf: function() { ( /x/g );return 4; }})); return f2; }); } catch(e1) { } for (var p in i1) { try { print(uneval(m2)); } catch(e0) { } try { ; } catch(e1) { } h0 = m2; } return i2; })); } }), this.b2); } else print( \"\" );}");
/*fuzzSeed-45472219*/count=632; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(((mathy1(Math.fround(( ~ Math.fround(( ~ y)))), ((( + ( ~ y)) , ( + ( + Math.log10(x)))) | 0)) || mathy4(mathy3(( + x), ( + x)), mathy4((Math.fround(Math.hypot(( + -0x07fffffff), Math.fround(( ! -0x080000000)))) >>> 0), (0x0ffffffff !== Math.imul(y, ( + y)))))) ? Math.atan2((( + Math.cbrt((( + ( ~ (mathy2((x | 0), (y | 0)) | 0))) ? ( + y) : ( + x)))) >>> 0), Math.log10((( - x) | 0))) : Math.fround(mathy2(Math.clz32((Math.log((-Number.MIN_VALUE >>> 0)) >>> 0)), Math.tanh((mathy2((Math.sinh(y) | 0), y) >>> 0)))))); }); ");
/*fuzzSeed-45472219*/count=633; tryItOut(" '' ;");
/*fuzzSeed-45472219*/count=634; tryItOut("\"use strict\"; o2.v0 = 0;");
/*fuzzSeed-45472219*/count=635; tryItOut("v2 = g2.eval(\"mathy5 = (function(x, y) { return Math.max(Math.sin(( + x)), Math.min((Math.log(Math.fround((y && (( ~ ((Math.atan2(2**53, y) | 0) >>> 0)) >>> 0)))) | 0), (mathy3(Math.min(x, (((Math.log10(x) | 0) + Math.fround(x)) | 0)), ( - x)) | 0))); }); testMathyFunction(mathy5, /*MARR*/[new Boolean(false),  /x/g ,  /x/g , new String(''), new String(''), new String(''), new Boolean(false), new String(''), new Boolean(false), new Boolean(false),  /x/g , new String(''), new String(''), new Boolean(false), new String(''), new String(''), new String(''), new String(''), new String(''),  /x/g , new Boolean(false), new Boolean(false),  /x/g , new Boolean(false), new String(''), new String(''), new String(''), new Boolean(false),  /x/g ,  /x/g , new String(''), new String(''),  /x/g , new Boolean(false),  /x/g , new Boolean(false),  /x/g , new Boolean(false), new String(''), new Boolean(false),  /x/g , new String(''),  /x/g , new Boolean(false), new Boolean(false), new String(''), new String(''), new String(''), new String(''), new String(''), new Boolean(false),  /x/g ,  /x/g , new Boolean(false),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new String(''), new String(''), new Boolean(false), new String(''), new Boolean(false), new String(''), new Boolean(false),  /x/g , new String(''), new Boolean(false), new Boolean(false), new String(''), new String(''), new String(''),  /x/g , new Boolean(false), new Boolean(false),  /x/g , new Boolean(false),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new String(''),  /x/g ,  /x/g ,  /x/g , new String(''), new Boolean(false), new String(''), new String(''),  /x/g , new String(''), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  /x/g ,  /x/g , new String(''), new Boolean(false), new Boolean(false), new String(''),  /x/g , new Boolean(false), new Boolean(false), new String(''), new String(''),  /x/g , new String(''), new Boolean(false),  /x/g ,  /x/g , new Boolean(false), new String(''),  /x/g , new String(''), new String(''), new Boolean(false), new Boolean(false), new Boolean(false),  /x/g , new String(''), new Boolean(false),  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), new String(''), new Boolean(false), new String(''), new String(''), new Boolean(false),  /x/g ,  /x/g , new Boolean(false), new String(''),  /x/g , new String(''), new Boolean(false), new String(''),  /x/g , new String(''),  /x/g ,  /x/g ,  /x/g ,  /x/g , new String(''),  /x/g , new String(''), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new String('')]); \");");
/*fuzzSeed-45472219*/count=636; tryItOut("testMathyFunction(mathy1, [1/0, -(2**53-2), -0, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, -1/0, -(2**53), 0x07fffffff, -0x0ffffffff, -0x100000001, 0x100000001, 0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, 42, -0x080000000, 0x0ffffffff, 0x080000000, -0x100000000, -(2**53+2), 2**53-2, 0x100000000, 2**53, 1, -0x080000001, Math.PI]); ");
/*fuzzSeed-45472219*/count=637; tryItOut("mathy3 = (function(x, y) { return Math.atan2((( ~ Math.fround(Math.tanh(((Math.fround(( - (((y , Math.fround(Number.MAX_VALUE)) | 0) >>> 0))) >>> 0) ? x : y)))) >>> 0), ((Math.pow((Math.pow(( ~ y), -(2**53)) | 0), (mathy1(y, ( ! y)) | 0)) >>> 0) | 0)); }); testMathyFunction(mathy3, [-0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0, 1/0, -1/0, -0, 0x100000000, Number.MIN_VALUE, 0x080000001, -0x100000001, -0x080000000, 2**53+2, 0/0, -(2**53+2), 0x0ffffffff, 0x100000001, 42, 2**53, -(2**53), 0x080000000, Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -0x100000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, 2**53-2]); ");
/*fuzzSeed-45472219*/count=638; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atan2(Math.fround((( ~ ((Math.hypot((((Math.fround(((x >>> 0) % x)) >>> 0) , (-(2**53-2) >>> 0)) >>> 0), Math.log(x)) | 0) && Math.fround((mathy0((Math.acos(y) | 0), x) | 0)))) | 0)), Math.fround((((Math.max(Math.fround((Math.fround(0/0) ? Math.fround((((y | 0) >>> (Math.fround(Math.pow(Math.fround(y), Math.fround(x))) | 0)) | 0)) : Math.fround(x))), Math.fround(((x | 0) ? ((( + x) >> -Number.MAX_VALUE) | 0) : (x | 0)))) | 0) <= ((((x ? (( ~ y) >>> 0) : x) + (( + Math.exp(Math.fround(( ~ Math.fround(-1/0))))) | 0)) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy1, [-0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, -0x0ffffffff, Math.PI, Number.MAX_VALUE, -(2**53), 42, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, -(2**53+2), 1/0, 2**53, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, 0x0ffffffff, -0, 1, 0.000000000000001, Number.MIN_VALUE, -0x080000000, -1/0, Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, 0]); ");
/*fuzzSeed-45472219*/count=639; tryItOut("o1.g2.offThreadCompileScript(\"/*RXUB*/var r = new RegExp(\\\"(?![^]{3,}(?=(?![^]))(?!\\\\\\\\B)|(.+?).|\\\\\\\\3*?)\\\", \\\"gyi\\\"); var s = (/*wrap3*/(function(){ var psddno = null; (Array.prototype.shift)(); })).bind( /* Comment */window, null); print(uneval(s.match(r))); \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 8 != 3), element: o0 }));");
/*fuzzSeed-45472219*/count=640; tryItOut("var qjlmvr = new ArrayBuffer(8); var qjlmvr_0 = new Uint32Array(qjlmvr); /*tLoop*/for (let x of /*MARR*/[-Infinity, (void 0), (void 0), (void 0), -Infinity, -Infinity, -0x100000000,  /x/ ,  /x/ , -Infinity, 0x20000000, -0x100000000, 0x20000000, 0x20000000, -Infinity, -Infinity, -0x100000000, -0x100000000,  /x/ , (void 0), -Infinity, 0x20000000,  /x/ , 0x20000000, 0x20000000, -Infinity, -0x100000000, -0x100000000,  /x/ , -0x100000000, 0x20000000, -Infinity, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0),  /x/ , (void 0), (void 0), -Infinity,  /x/ , -0x100000000, -0x100000000, (void 0), -0x100000000, -0x100000000, (void 0), 0x20000000, -0x100000000, 0x20000000, -0x100000000, (void 0), -Infinity, -Infinity, -Infinity, (void 0), (void 0),  /x/ , -0x100000000, -0x100000000, -Infinity, 0x20000000, -0x100000000, 0x20000000, -Infinity, -0x100000000, (void 0)]) {  '' ; }print(this);this.m2.toString = f2;print(qjlmvr_0[0]);");
/*fuzzSeed-45472219*/count=641; tryItOut("\"use strict\"; ;");
/*fuzzSeed-45472219*/count=642; tryItOut("/*RXUB*/var r = /(?!(?:(?=.|\u00cb+?))+){3,7}/yim; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=643; tryItOut("\"use strict\"; {print(/(?:(\u00cd))*?/gi); }var jnimqq = new SharedArrayBuffer(0); var jnimqq_0 = new Uint16Array(jnimqq); jnimqq_0[0] = -6; var jnimqq_1 = new Int16Array(jnimqq); jnimqq_1[0] = 1417004997.5; var jnimqq_2 = new Int16Array(jnimqq); print(jnimqq_2[0]); w;m0.set(this.e0, g1);([,]);continue ;");
/*fuzzSeed-45472219*/count=644; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(( ~ (Math.fround(Math.fround(Math.atan2(Math.fround(Math.fround(Math.pow(Math.fround(y), Math.fround((mathy0((y >>> 0), ((( ~ (2**53+2 >>> 0)) >>> 0) | 0)) | 0))))), Math.fround(x)))) >>> ( + ((( - Math.expm1(( + mathy0(( + x), ( + x))))) >>> 0) ^ x)))), ( + Math.max(( - x), Math.fround((-0x07fffffff ? (x | 0) : (Math.atan2(Math.fround(-(2**53)), mathy0(Math.fround(y), 42)) >>> 0)))))); }); ");
/*fuzzSeed-45472219*/count=645; tryItOut("\"use strict\"; if((void options('strict'))) print(x); else  if (this.__defineGetter__(\"c\", Uint32Array)) print(new RegExp(\"$\", \"gm\").slice(x));");
/*fuzzSeed-45472219*/count=646; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + (( + (Math.cos((Math.min(x, ( ~ Math.fround(x))) | 0)) | 0)) | 0)) !== ( + Math.pow((mathy1((( ~ ((Math.tan((mathy1((Math.exp(y) >>> 0), (( - y) >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0), Math.fround((Math.fround(Math.imul(x, mathy0(-Number.MIN_VALUE, -(2**53)))) / Math.fround(-Number.MAX_VALUE)))) | 0), (Math.min((Math.fround(mathy0(Math.fround(( - y)), Math.fround(Math.sqrt(-0x0ffffffff)))) | 0), (x | 0)) | 0)))); }); testMathyFunction(mathy2, [Math.PI, Number.MAX_SAFE_INTEGER, -0x100000001, 42, -0x07fffffff, 0, 0x080000001, 2**53+2, 0x080000000, 2**53, -0x0ffffffff, -0x080000000, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, -(2**53-2), 0x100000000, 2**53-2, -0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 0.000000000000001, -(2**53), 0/0, -Number.MAX_VALUE, 0x0ffffffff, 1, -1/0, 0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2)]); ");
/*fuzzSeed-45472219*/count=647; tryItOut("yield;function of(c) { \"use strict\"; yield yield x &= eval } /*RXUB*/var r = r1; var s = s1; print(r.test(s)); ");
/*fuzzSeed-45472219*/count=648; tryItOut("testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, -0, -0x100000001, 42, 0.000000000000001, -Number.MAX_VALUE, -(2**53+2), 0, -(2**53), Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -1/0, 1.7976931348623157e308, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, -(2**53-2), 0x080000001, 0x100000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 1, 0x080000000, 0x100000001, 1/0, 2**53, -0x100000000, -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-45472219*/count=649; tryItOut("m1 = new Map(t1);");
/*fuzzSeed-45472219*/count=650; tryItOut("g1.v2 = g2.a2.every();");
/*fuzzSeed-45472219*/count=651; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = (i2);\n    }\n    (Int32ArrayView[2]) = ((0xf1b708da) % ((((-6) ? (i2) : (0xfd61a322))+(i2))>>>((~((((0x9bf7a0e4)) | ((0x13c82235))) % (~((-0x8000000))))) / (imul((i1), (i2))|0))));\n;    {\n      return (((0xffffffff) / (0x75a1f0f0)))|0;\n    }\n    {\n      i2 = ((((Float64ArrayView[(((((0x8efb72b0))>>>((0x3f7deb1c))) < (0xf8c54b3a))-(((0xfebe5ff2) < (0xdabfaa3e)) ? (i2) : (0x666e6374))-(i1)) >> 3]))) == (0x25980b03));\n    }\n    (Uint32ArrayView[((Uint16ArrayView[((0x78b756c0) % (0x955140fe)) >> 1])) >> 2]) = (((0x3009649) == (((!(((i2)+(0x81804620)-(i2))))-((((yield  /x/g )) ^ (0xfffff*(0x31de9419))) != ((((0x43103f03))) >> ((0x3e1debef)+(0x77197cb6))))) ^ ((((((-9.671406556917033e+24) == ((((0x3e42851a)) ^ ((0xffffffff))))))>>>(((0xd9a6487a) < (0xabf3caaa))-(/*FFI*/ff(((((0xf9d6477a)) << ((0x6cd9d4c1)))), ((4611686018427388000.0)), ((-1048575.0)), ((18014398509481984.0)), ((-147573952589676410000.0)), ((-33.0)), ((-144115188075855870.0)), ((17592186044417.0)), ((2.0)), ((268435457.0)), ((-134217728.0)), ((-9.44473296573929e+21)))|0))))))));\n    {\n      {\n        {\n          i1 = (0xedcbff63);\n        }\n      }\n    }\n    {\n      i2 = (([]) = new \"\\u7822\"(this));\n    }\n    (Float64ArrayView[(((!(0x5171fbb5)) ? (i1) : (/*FFI*/ff(((-1.0625)), ((6.189700196426902e+26)))|0))-(0xffffffff)-(i2)) >> 3]) = ((+(-1.0/0.0)));\n    (Uint16ArrayView[(-0xfffff*((((0x2937fc64))>>>((i1))) == (((0xb7e4ce3f)-(0x9820aaba)+(-0x8000000))>>>((0x441dd603)*-0x1d61a)))) >> 1]) = ((/*FFI*/ff(((((-0x8000000)) & ((i2)+(0xd2565e72)))), ((((!(i2))) ^ ((abs((abs((~((0x2fbbe33d))))|0))|0) / (((i1)) >> ((0x5bedfa26) % (0x18411f08)))))), ((((Int32ArrayView[((0x323c959f)-(0x5bd67f5b)-(0xfce77504)) >> 2])) ^ ((i1)))), ((d0)), ((imul((i1), (0xa0642959))|0)), ((18014398509481984.0)), ((imul((0xd8281074), (0xcd771d3c))|0)), ((2.3611832414348226e+21)), ((3.777893186295716e+22)), ((288230376151711740.0)), ((-4.722366482869645e+21)), ((562949953421313.0)), ((9223372036854776000.0)), ((-4503599627370497.0)), ((268435456.0)), ((-2.3611832414348226e+21)), ((-3.022314549036573e+23)), ((-1073741825.0)), ((-17179869185.0)), ((-8193.0)), ((8388607.0)), ((7.737125245533627e+25)))|0)+((((((((0xbb606b9d)) ^ ((-0x8000000))) / (abs((0xbcb1d12))|0)) & (((((0xfd815fcc))>>>((0xfbc6bae9))))))) + ((-73786976294838210000.0) + (+atan2(((8796093022207.0)), ((+((-17592186044417.0)))))))) != (((+(1.0/0.0))) - ((((-1.1805916207174113e+21)) % ((1.1805916207174113e+21)))))));\n    {\n      {\n        /*FFI*/ff(((((((-0x8000000)-(i2)) >> ((i2)*0x7d411)) / (~~(-2199023255552.0)))|0)), ((9.0)), ((+abs(((d0))))), (((((18014398509481984.0) <= (-33554433.0))+((((0xf140290a))>>>((0x237ea380)))))|0)));\n      }\n    }\n    i1 = (0x6c806117);\n    i2 = (0xfc2c2207);\n    i1 = (-0x8000000);\n    d0 = (-257.0);\n    {\n      return (((0xfd7d3634)))|0;\n    }\n    i2 = ((-1.5474250491067253e+26) > (+((+/*FFI*/ff(((+(0xf078c950))), ((~(((((!(0xfd4c4b31))) << (((0xc8d0d51b)))))))), ((-1099511627776.0)), ((+abs(((d0))))))))));\n    switch (((w = [z1]))) {\n      case -3:\n        i1 = ((0xf66d4a30) > (0xd1c32b0));\n    }\n    {\n      d0 = (d0);\n    }\n    i1 = (((((262145.0) >= (+((Float32ArrayView[0]))))) & ((0xfc1670d8))) > (((i2)) & (((((i2)) >> ((0xfc22dbc8)-(0xf9bea162)+(0xd25b1d5a))) != ((((0x4f412cf2) ? (0x939d30f4) : (0xe523dc84))-([[1]])) >> ((i2)))))));\n    i2 = (i2);\n    return (((0x44fb5339)-(!(i1))))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 0x100000001, 2**53+2, Math.PI, 0x07fffffff, 1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, -1/0, 0.000000000000001, -0, -0x080000001, -0x080000000, 0x080000001, 1.7976931348623157e308, -0x0ffffffff, -0x07fffffff, -0x100000001, 1, -(2**53+2), Number.MAX_VALUE, -(2**53), 0x100000000, Number.MIN_VALUE, 0, -0x100000000]); ");
/*fuzzSeed-45472219*/count=652; tryItOut("/*oLoop*/for (var xdoddh = 0; xdoddh < 54; ++xdoddh) { const a1 = arguments.callee.caller.arguments; } ");
/*fuzzSeed-45472219*/count=653; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\3|\\B+?)*?/gym; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=654; tryItOut("t1.set(a0, 14);function x(c = ((yield new RegExp(\"((((?![^\\\\cV\\\\v-\\\\b\\\\u00f5-\\u64c4\\\\d]\\\\t))|[^\\\\s\\\\u00B3\\ud412][^]))|\\\\D|(?![^]*?|(?=[^\\\\d])|\\\\B){3,3}\", \"g\"))), b, e =  /x/g , z, -9 = NaN, x, y, x, c, z, d, \u3056, y = \"\\uB431\", b, eval = \"\\uDBBA\", x, x, x, window = new RegExp(\"(?:(?=\\\\b{1}){3,}|\\\\cX|\\\\W\\\\b*?.?)\", \"g\"), x, window, x, d, eval, b, NaN, ...yield) ''  /x/ ;\no1.r1 = new RegExp(\"${0}\", \"im\");\n");
/*fuzzSeed-45472219*/count=655; tryItOut("\"use strict\"; g0.v2 = Object.prototype.isPrototypeOf.call(h2, f1);");
/*fuzzSeed-45472219*/count=656; tryItOut("b1 = new ArrayBuffer(6);");
/*fuzzSeed-45472219*/count=657; tryItOut("print(m0);");
/*fuzzSeed-45472219*/count=658; tryItOut("Array.prototype.splice.call(a2, 15, 19);");
/*fuzzSeed-45472219*/count=659; tryItOut("\"use strict\"; var ryiohp = new SharedArrayBuffer(6); var ryiohp_0 = new Uint32Array(ryiohp); var ryiohp_1 = new Uint16Array(ryiohp); ryiohp_1[0] = -7; var ryiohp_2 = new Int32Array(ryiohp); var ryiohp_3 = new Int8Array(ryiohp); var ryiohp_4 = new Int16Array(ryiohp); ryiohp_4[0] = 15; {print(g0);const c = this.__defineGetter__(\"ryiohp_4[0]\", (q => q).apply); }i2.send(o2.t0);");
/*fuzzSeed-45472219*/count=660; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ((Math.fround(Math.max(( - x), Math.fround(Math.min(Math.min((mathy1(y, (y >>> 0)) | 0), Math.clz32(y)), 2**53)))) || ((((( - ( ! x)) | 0) >>> 0) / ((Math.min(Math.pow(0.000000000000001, (( ~ (x | 0)) | 0)), (x >= ( + ( - ( + y))))) >>> 0) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0x080000001, -Number.MIN_VALUE, -(2**53-2), 0/0, 0x07fffffff, -0, -0x0ffffffff, 0.000000000000001, -1/0, 0, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -(2**53), -0x100000001, 0x0ffffffff, Number.MAX_VALUE, 2**53+2, 0x100000001, -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, 2**53-2, -0x080000000, -Number.MAX_VALUE, Math.PI, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, 1, 42, -(2**53+2)]); ");
/*fuzzSeed-45472219*/count=661; tryItOut("e0.has(a2);");
/*fuzzSeed-45472219*/count=662; tryItOut("Array.prototype.sort.call(a2, (function mcc_() { var kgbkvy = 0; return function() { ++kgbkvy; if (/*ICCD*/kgbkvy % 9 != 4) { dumpln('hit!'); try { v2 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 29 != 27), noScriptRval: (x % 12 != 11), sourceIsLazy: (allocationMarker()), catchTermination: true })); } catch(e0) { } i1 = x; } else { dumpln('miss!'); try { print(uneval(p1)); } catch(e0) { } try { g1.e1.delete(g0); } catch(e1) { } i1 = t2[5]; } };})());");
/*fuzzSeed-45472219*/count=663; tryItOut("/*RXUB*/var r = /(?!(?:\\B|(?:\\w|[^])+?)|[^\\\u0019-\u00fd\\b-\ue963\\d\u00ef]?)/ym; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-45472219*/count=664; tryItOut("i1 = new Iterator(b1);");
/*fuzzSeed-45472219*/count=665; tryItOut("testMathyFunction(mathy3, /*MARR*/[ \"\" , NaN,  \"\" , objectEmulatingUndefined(), new Number(1), x, x, NaN, new Number(1), objectEmulatingUndefined(), new Number(1), x,  \"\" , NaN, x, new Number(1), x,  \"\" , objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(),  \"\" ,  \"\" , NaN,  \"\" , new Number(1),  \"\" , objectEmulatingUndefined(), x,  \"\" ,  \"\" , x, objectEmulatingUndefined(), NaN, new Number(1),  \"\" , objectEmulatingUndefined(), new Number(1), x, x, objectEmulatingUndefined(), x, NaN, new Number(1), new Number(1), objectEmulatingUndefined(), x, objectEmulatingUndefined(),  \"\" , objectEmulatingUndefined(), new Number(1), new Number(1), NaN, x, x, new Number(1), objectEmulatingUndefined(), new Number(1), x, NaN, new Number(1), new Number(1), x, objectEmulatingUndefined(), new Number(1), NaN, NaN, x, NaN, x, x,  \"\" , x, NaN, new Number(1), x, new Number(1), new Number(1),  \"\" , objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, objectEmulatingUndefined(), NaN, new Number(1), NaN, objectEmulatingUndefined(),  \"\" , x, NaN, new Number(1), objectEmulatingUndefined(), x, x,  \"\" , objectEmulatingUndefined(), NaN, x,  \"\" , x, NaN,  \"\" , objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(),  \"\" , NaN]); ");
/*fuzzSeed-45472219*/count=666; tryItOut("mathy4 = (function(x, y) { return (( - mathy3(Math.fround((Math.fround(b = function(id) { return id }, z = new RegExp(\"(\\\\2(?=(?=[\\\\u80b7\\\\u00Ea\\\\t-\\\\cT]\\\\cG*)|\\\\B.*?{0}))\", \"gi\"), tvgcgk, y, b, y, NaN, joydwb, y) >>> Math.fround(y))), ((Math.imul(Math.fround(mathy0(Math.fround(x), ( + x))), Math.acosh(Math.fround((y % Math.fround(y))))) + ( + y)) >>> 0))) >>> 0); }); testMathyFunction(mathy4, [0x100000000, -0x100000000, -0, -(2**53+2), -1/0, -0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, 2**53-2, 1/0, 42, Number.MAX_VALUE, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 0/0, 2**53+2, 0x100000001, 0x080000001, -(2**53-2), -0x07fffffff, -0x100000001, 0.000000000000001, Number.MIN_VALUE, Math.PI, -0x0ffffffff, 0]); ");
/*fuzzSeed-45472219*/count=667; tryItOut("o2.v1 = g0.eval(\"i2.toSource = (function() { p2.toString = (function mcc_() { var doexlv = 0; return function() { ++doexlv; if (/*ICCD*/doexlv % 3 == 2) { dumpln('hit!'); try { /*ADP-1*/Object.defineProperty(this.a0, 0, ({enumerable: this})); } catch(e0) { } try { function f0(this.p0)  { \\\"use strict\\\"; yield [({a1:1})] }  } catch(e1) { } s2 = ''; } else { dumpln('miss!'); try { v2 = a2.length; } catch(e0) { } s2 += 'x'; } };})(); throw g0; });\");for (var v of p2) { try { v2 = g2.eval(\"function f1(p2)  { return (4277) } \"); } catch(e0) { } Array.prototype.reverse.apply(a2, []); }");
/*fuzzSeed-45472219*/count=668; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=669; tryItOut("");
/*fuzzSeed-45472219*/count=670; tryItOut("testMathyFunction(mathy2, [2**53+2, -0x080000000, 0x100000001, -(2**53), -Number.MAX_VALUE, -0x080000001, 0x07fffffff, -Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, 42, 2**53-2, Number.MIN_VALUE, 0x080000000, -0, 1, 0/0, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, 0, -0x0ffffffff, 2**53, -(2**53-2), -0x100000001]); ");
/*fuzzSeed-45472219*/count=671; tryItOut("for(let c in []);x.stack;");
/*fuzzSeed-45472219*/count=672; tryItOut("\"use strict\"; Array.prototype.push.apply(a0, [b1, s1, f0]);");
/*fuzzSeed-45472219*/count=673; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.fround((Math.sinh((((((( + (Math.atan2(y, (x | 0)) | 0)) , (mathy1(x, 2**53) >>> 0)) >>> 0) | 0) / Math.fround(Math.imul(x, ( - Math.fround(x))))) | 0)) ? Math.fround(Math.hypot(( ~ Math.exp((((x << -Number.MIN_SAFE_INTEGER) | 0) != ( + ( + y))))), (Math.round(((y === x) | 0)) >>> 0))) : Math.fround(( + Math.max(( + (Math.imul(((( ! (x >>> 0)) >>> 0) >>> 0), (( - Math.fround(Math.imul((x ? y : 42), ( + ( + ( + x)))))) >>> 0)) >>> 0)), Math.imul(x, x)))))); }); testMathyFunction(mathy5, [-1/0, Math.PI, -0x100000001, -0, 0x100000001, -0x07fffffff, Number.MAX_VALUE, 0x100000000, 0x080000001, 2**53, 0/0, -Number.MIN_VALUE, -0x080000000, 0x080000000, 2**53-2, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, 42, 1, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, -0x080000001, Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, 0, -0x100000000, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=674; tryItOut("\"use strict\"; b1 = new ArrayBuffer(40);");
/*fuzzSeed-45472219*/count=675; tryItOut("Array.prototype.splice.call(a2, NaN, 17);");
/*fuzzSeed-45472219*/count=676; tryItOut("\"use strict\"; a1 = Array.prototype.map.call(a2, (function(j) { if (j) { try { t1 + s0; } catch(e0) { } try { print(m1); } catch(e1) { } try { b0 = o2.t2.buffer; } catch(e2) { } Array.prototype.forEach.apply(a0, [f1, o0, v1, g0, a1, b0]); } else { try { for (var v of g2) { this.o2.__iterator__ = (function() { for (var j=0;j<5;++j) { f1(j%2==1); } }); } } catch(e0) { } try { a1.push(o2, b0, v1); } catch(e1) { } try { m2.has(f2); } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(t1, f2); } }), a2);");
/*fuzzSeed-45472219*/count=677; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.imul((Math.imul(Math.hypot(( + ( - ( + ( ! ( ! mathy1(y, x)))))), mathy0(Math.cbrt(( + x)), -(2**53))), ( + ( + Math.sinh((( ~ (Math.trunc(Math.fround(x)) >>> 0)) ** ( + Math.atan2((((y >>> 0) & Math.fround(-0x100000000)) | 0), Math.round(y)))))))) >>> 0), ( ! mathy1(( + Math.pow((y ? Math.fround(x) : Math.max(Math.fround(x), y)), ( + Math.imul(y, y)))), ( + mathy1(( + ( + Math.pow(y, ( + (Math.atan2(( + 0x07fffffff), (y | 0)) >>> 0))))), ( + (((y | 0) - y) >>> 0))))))); }); ");
/*fuzzSeed-45472219*/count=678; tryItOut("/*RXUB*/var r = /(?=([^].|(.)*?)?)(\\1*)(?=(?:\\\u0015))+/gym; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-45472219*/count=679; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[new Number(1), new Number(1), function(){}, false, false, new Number(1), function(){}, false, false, function(){}, function(){}, new Number(1), new Number(1), false, function(){}, false, false, new Number(1), false, new Number(1), false, false, false, false, new Number(1), new Number(1), false, new Number(1), new Number(1), new Number(1), false, new Number(1), function(){}, function(){}, false, new Number(1), new Number(1), false, function(){}, new Number(1), new Number(1), function(){}, false, new Number(1), function(){}, new Number(1), function(){}, false, false]) { zjjkmk(new (new Proxy())(b, \"\\u6A90\"), \"\\uA868\");/*hhh*/function zjjkmk(x, window){print( /x/g  ^= \"\\u1A02\");} }");
/*fuzzSeed-45472219*/count=680; tryItOut("\"use asm\"; let \n(w) {  /x/ ;\no1.toSource = (function() { try { x = e2; } catch(e0) { } try { this.g2.b1 = new SharedArrayBuffer(24); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(s1, o2.e0); } catch(e2) { } a2 = arguments; throw o0; });\n }");
/*fuzzSeed-45472219*/count=681; tryItOut("v1 = this.t2.length;");
/*fuzzSeed-45472219*/count=682; tryItOut("mathy1 = (function(x, y) { return ( + Math.acosh(Math.fround(mathy0((Math.fround(mathy0(Math.fround(Math.ceil(Math.fround((y ? 0x100000000 : Math.fround(Math.expm1(Number.MIN_SAFE_INTEGER)))))), Math.fround(x))) | 0), ((Math.atan2(( ! x), (Math.fround(( + Math.fround(-0x07fffffff))) >>> 0)) >>> 0) - (( ! ( + ( - ( - y)))) | 0)))))); }); ");
/*fuzzSeed-45472219*/count=683; tryItOut("\"use strict\"; let x, eval, x = this, x = (x === x);v1 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 4 != 2) }));");
/*fuzzSeed-45472219*/count=684; tryItOut("\"use strict\"; const y = let (c) delete z.x, \u3056, [{x: []}] = \"\\u6956\", \u3056, z = intern(null);var jenxut = new SharedArrayBuffer(12); var jenxut_0 = new Uint8ClampedArray(jenxut); jenxut_0[0] = Number.MIN_VALUE; var jenxut_1 = new Uint8ClampedArray(jenxut); var jenxut_2 = new Float64Array(jenxut); var jenxut_3 = new Uint16Array(jenxut); jenxut_3[0] = -12; var jenxut_4 = new Float64Array(jenxut); print(jenxut_4[0]); jenxut_4[0] = -6; var jenxut_5 = new Int8Array(jenxut); jenxut_5[0] = -2; a2 = new Array;/*tLoop*/for (let d of /*MARR*/[false, false, false, false, -(2**53+2), false, -(2**53+2), -(2**53+2), -(2**53+2), false, -(2**53+2), false, -(2**53+2), -(2**53+2), false, false, false, -(2**53+2), false, -(2**53+2), -(2**53+2), false, -(2**53+2), -(2**53+2), -(2**53+2), false, false, false, false, false, -(2**53+2), false, -(2**53+2), -(2**53+2), false, -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), false, false, -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), false, false, false, false, -(2**53+2), -(2**53+2), -(2**53+2), -(2**53+2), false, false, false, false]) { false; }");
/*fuzzSeed-45472219*/count=685; tryItOut("/*ODP-3*/Object.defineProperty(i2, new ((((function handlerFactory(x) {return {getOwnPropertyDescriptor: this, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: Object.create, getOwnPropertyNames: undefined, delete: function() { throw 3; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { throw 3; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: eval, }; })).call((Math.tanh(x)), )))(), { configurable: (x % 2 != 0), enumerable: (x % 18 == 9), writable: true, value: s1 });");
/*fuzzSeed-45472219*/count=686; tryItOut("let x = eval(\"/*MXX3*/g0.Array.prototype.entries = g2.Array.prototype.entries;\",  '' ) &= \u3056, x = (((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: mathy5, keys: function() { return []; }, }; })).bind([1,,])), x = (void options('strict')), e, w, y = \"\\u8886\".eval(\"f1 = Proxy.createFunction(h2, this.f1, this.f2);\");/*tLoop*/for (let x of /*MARR*/[{}, {}, {}, {}, {}, ({}), {}, {}, ({}), ({}), ({}), {}, {}, {}, {}, {}, ({}), ({}), {}, {}, ({}), ({}), ({}), ({}), ({}), ({}), {}, {}, {}, {}, ({}), {}, ({}), {}, ({}), ({}), ({}), {}, ({}), ({}), {}, {}, {}, {}, ({}), ({}), ({}), ({}), ({}), ({}), {}, ({}), {}, {}, ({}), {}, {}, ({}), ({}), {}, {}, ({}), {}, {}, ({}), ({}), {}, ({}), {}, ({}), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, ({}), {}, {}, {}, ({}), {}, {}, {}, ({}), ({}), ({}), {}, {}, ({}), ({}), {}, {}, ({}), ({}), {}, {}, ({})]) { o1.f0(o0.v0); }");
/*fuzzSeed-45472219*/count=687; tryItOut("mathy0 = (function(x, y) { return (Math.hypot(( + ((Math.fround((Math.fround(( + (( + Math.pow(y, x)) >= -0x080000001))) >>> Math.fround((( ! (x | 0)) | 0)))) ? Math.fround(Math.asin(Math.fround(0.000000000000001))) : this) & (Math.pow((x % Math.hypot(Math.asin((y >>> 0)), y)), ((Math.min(Math.atan2(2**53-2, (x * x)), (-0x07fffffff >>> 0)) >>> 0) | 0)) >>> 0))), (( - Math.cbrt(( + (((( + Math.hypot(( + x), (x | 0))) / -(2**53-2)) >>> 0) > 2**53)))) | 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[['z'], ['z'], function(){}, arguments, arguments, function(){}, arguments, arguments, Math.PI, ['z'], function(){}]); ");
/*fuzzSeed-45472219*/count=688; tryItOut("testMathyFunction(mathy4, [-0, 0x0ffffffff, -Number.MIN_VALUE, 1/0, -0x100000001, Number.MIN_SAFE_INTEGER, 42, 0x080000000, 0, -0x0ffffffff, -0x100000000, Math.PI, -0x07fffffff, 2**53-2, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, -(2**53-2), -Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, 1, -0x080000001, 2**53, 0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, 0.000000000000001, 0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=689; tryItOut("\"use strict\"; /*bLoop*/for (var voaizm = 0; voaizm < 88; ++voaizm) { if (voaizm % 2 == 1) { /*tLoop*/for (let x of /*MARR*/[function(){}, {}, {}, {}, function(){}, {}, {}, {}, function(){}, function(){}, {}, function(){}, {}, {}, function(){}, function(){}, {}, function(){}, {}, {}, {}, function(){}, function(){}, function(){}, {}, {}, {}, function(){}, function(){}, function(){}, {}, function(){}, function(){}, function(){}, function(){}, function(){}, {}, function(){}, {}, {}, {}, function(){}, function(){}, function(){}, {}, function(){}, function(){}, function(){}, {}, {}, function(){}, function(){}, {}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, {}, function(){}, {}, {}, {}, function(){}, {}, {}, {}, function(){}, {}, function(){}, {}, {}, {}, {}, {}, function(){}, {}, {}, {}, {}, {}, {}, {}, {}, {}, function(){}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, function(){}, {}, {}, function(){}, {}, {}, {}, {}, {}, {}, function(){}, function(){}, function(){}, function(){}, {}, {}, {}, {}, function(){}, {}, {}, function(){}, {}, {}, {}, {}, function(){}, function(){}, {}, {}, {}]) { ((x = NaN)); } } else { v1 = g2.runOffThreadScript(); }  } ");
/*fuzzSeed-45472219*/count=690; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=691; tryItOut("var v2 = evaluate(\"function this.f2(s0) \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: (void options('strict')), catchTermination: false }));");
/*fuzzSeed-45472219*/count=692; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.sign(( + Math.imul(( + Math.cbrt(-0x100000001)), Math.fround(( + Math.fround(x)))))) >>> (Math.trunc(((Math.fround(mathy0(Math.fround((( ! Math.fround(x)) !== -0x080000000)), Math.fround(x))) * Math.fround(mathy0(( + x), (Math.max(x, x) >>> ( + Math.atan2(( + y), x)))))) >>> 0)) | 0)); }); testMathyFunction(mathy1, [-0x100000001, -1/0, -0x080000001, 42, 0x07fffffff, 2**53-2, -0x07fffffff, 2**53+2, -Number.MIN_VALUE, 0x080000001, 1/0, -(2**53), 0x080000000, -0, 0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, Number.MAX_VALUE, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, Math.PI, -(2**53-2), 0x100000001, 1, -0x100000000, -0x0ffffffff, Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-45472219*/count=693; tryItOut("\"use strict\"; g2.v2 = Object.prototype.isPrototypeOf.call(g2, b2);");
/*fuzzSeed-45472219*/count=694; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      return (((0xfe68b277)+(((0x2efaf828)) < (d0))))|0;\n    }\n    return (((!(0x7af46577))))|0;\n  }\n  return f; })(this, {ff: (e, this.z = x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function(name) { return delete x[name]; }, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(\"\\u5A5E\"), (encodeURI).bind()), e, y, x = this, x, b, x =  /x/ , eval, x, x, a, c, x, eval, x, z, c = function(id) { return id }, eval, w, x, x, x, x, x, \u3056 = new RegExp(\".\", \"gi\"), x = arguments, y, x = x, x, e, eval, y, w = \"\\uDEB3\",  , x, \u3056, NaN, w, x, eval, y, e, c, x = Math, e, y = \"\\u67D4\", x, eval = this, \u3056 = \"\\u6726\", NaN, c, x, x, d, NaN, x, \u3056, window, x, NaN, x, a, y, ...x) =>  { return /*FARR*/[, 14, \"\\u8563\", , true, this, (function ([y]) { })(), 16].map(function (w) { \"use asm\"; return  ''  } ) } }, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53+2, -Number.MAX_VALUE, -(2**53+2), -0x100000001, 1/0, -(2**53), 0/0, Number.MAX_SAFE_INTEGER, 1, Math.PI, 0x100000001, -0x07fffffff, Number.MIN_VALUE, 0, 2**53-2, -0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -0x080000001, -1/0, 0x100000000, -Number.MIN_VALUE, 0x080000000, -(2**53-2), 0.000000000000001, Number.MAX_VALUE, 42, 0x07fffffff, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -0x080000000, 0x080000001]); ");
/*fuzzSeed-45472219*/count=695; tryItOut("delete h2.getOwnPropertyNames;");
/*fuzzSeed-45472219*/count=696; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.tan((( + ( + ( + Math.fround(Math.min(Math.fround((Math.max((y >>> 0), (Math.imul(2**53-2, Math.fround(Math.atan2(( + -(2**53-2)), -Number.MAX_SAFE_INTEGER))) >>> 0)) >>> 0)), Math.fround((Math.acosh((Math.exp(x) >>> 0)) >>> 0))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x080000001, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -(2**53-2), 1/0, Number.MIN_VALUE, Math.PI, -0x080000001, 1, 0, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, 42, -0, 2**53-2, -Number.MIN_VALUE, -0x07fffffff, -0x100000000, -(2**53), 0x100000000, 0x100000001, -0x0ffffffff, -1/0, 2**53, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2]); ");
/*fuzzSeed-45472219*/count=697; tryItOut("t2 = a1[17];");
/*fuzzSeed-45472219*/count=698; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.round(Math.max(Math.clz32(Math.fround(-Number.MIN_VALUE)), (( - x) && Math.sin(Math.asinh(x))))) ? (Math.hypot(Math.fround(Math.log1p((Math.atan(Math.fround(Math.fround(Math.sqrt(Math.fround(Math.acosh((-Number.MAX_SAFE_INTEGER | 0))))))) >>> 0))), (Math.min(( + -0x0ffffffff), Math.hypot((Math.log((y | 0)) | 0), x)) , mathy0(Math.fround(Math.atan2(x, Math.fround(-0))), mathy2(Math.expm1((Math.imul(([] >>> 0), (42 >>> 0)) | 0)), y)))) >>> 0) : ((Math.max((Math.hypot((x >>> 0), (Math.trunc(-Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0), (Math.atan2(( + mathy1((Math.expm1(( + x)) | 0), y)), ( ! y)) | 0)) <= Math.atan((((Math.log10(Number.MAX_SAFE_INTEGER) | 0) / ( ! (( + y) > y))) | 0))) >>> 0)); }); ");
/*fuzzSeed-45472219*/count=699; tryItOut("/*infloop*/M:for(a in ((ArrayBuffer.prototype.slice)(\n /x/g ))){print(x); }");
/*fuzzSeed-45472219*/count=700; tryItOut("this.a1.unshift(g0.s1);");
/*fuzzSeed-45472219*/count=701; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[new String('q'), new String('q'), eval, new String('q'), window, window, new String('q'), eval, new String('q'), window, eval, new String('q'), eval, new String('q'), window, new String('q'), eval, eval, new String('q'), window, eval, eval, window, eval, eval, eval, eval, new String('q'), new String('q'), window, eval, eval, new String('q'), new String('q'), new String('q'), eval, new String('q'), new String('q'), eval, new String('q'), new String('q'), window, window, new String('q'), new String('q'), eval, window, window, eval, new String('q'), window, eval, eval, new String('q'), eval, new String('q'), new String('q'), window, new String('q'), eval, new String('q'), eval, window, new String('q'), new String('q'), new String('q'), new String('q'), window, eval, eval, new String('q'), eval, eval, new String('q'), new String('q'), new String('q'), eval, window, new String('q'), window, new String('q'), new String('q'), eval, eval, eval, window, eval, new String('q'), new String('q'), window, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), eval, new String('q'), new String('q'), new String('q'), new String('q'), window, eval, new String('q'), eval, eval, eval, window, eval, new String('q'), new String('q'), new String('q'), eval, window, eval, new String('q'), window, eval, eval, window, eval, new String('q'), new String('q'), window, eval, eval]) { print(e); }");
/*fuzzSeed-45472219*/count=702; tryItOut("");
/*fuzzSeed-45472219*/count=703; tryItOut("var y = x;for (var p in h2) { try { Object.seal(g0); } catch(e0) { } t2 = new Uint8Array(10); }");
/*fuzzSeed-45472219*/count=704; tryItOut("o2.v2 = evalcx(\"x = \\\"\\\\u2410\\\"\", g2);");
/*fuzzSeed-45472219*/count=705; tryItOut("\"use strict\"; m1.delete(this.o0.o0.o1.b0);");
/*fuzzSeed-45472219*/count=706; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.hypot((( ~ ( + Math.acos(( + Math.fround((Math.fround(-Number.MIN_SAFE_INTEGER) & ( + ( - (x >>> 0))))))))) | 0), (((( ! y) | 0) >> mathy0((( ~ (x >>> 0)) & (Math.atan2(y, y) | 0)), ( + ( - y)))) | 0)) | 0); }); ");
/*fuzzSeed-45472219*/count=707; tryItOut("do {var atdpat = new SharedArrayBuffer(8); var atdpat_0 = new Int32Array(atdpat); a2[1] =  '' ;\n(-3);\nlet (wkbtff) { String.prototype.trimLeft }v1 = (x % 19 == 4);print(x);m2 = new Map(e0); } while(((void options('strict'))) && 0);");
/*fuzzSeed-45472219*/count=708; tryItOut("i0.send(a0);");
/*fuzzSeed-45472219*/count=709; tryItOut("mathy1 = (function(x, y) { return ( + Math.pow(( - ( - Math.fround(((x | 0) ^ (((Math.ceil(y) >>> 0) , mathy0((y << x), (y | 0))) | 0))))), (mathy0((Math.fround(Math.sinh(mathy0(( + Math.min(1.7976931348623157e308, (( ! -0x07fffffff) >>> 0))), ( + Math.fround(( - Math.fround(x))))))) ^ y), (Math.expm1(( + Math.tanh(( + Math.cbrt(x))))) >>> 0)) | 0))); }); testMathyFunction(mathy1, [-(2**53-2), 0x080000001, 2**53+2, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, -(2**53), Math.PI, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0, -0x080000001, 0x07fffffff, -0, 0x100000000, 0/0, 2**53-2, 1/0, Number.MAX_SAFE_INTEGER, 0x100000001, 1, -Number.MAX_VALUE, -0x07fffffff, -0x080000000, 42, -0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53, -1/0]); ");
/*fuzzSeed-45472219*/count=710; tryItOut("mathy3 = (function(x, y) { return (((Math.atan2(Math.fround(Math.fround((Math.fround(x) ? Math.fround(0x080000000) : Math.fround(Math.fround(Math.cosh(mathy0(Math.fround(( - y)), Number.MIN_SAFE_INTEGER))))))), Math.min((x << x), Math.exp(x))) >>> 0) && (mathy1(Math.cbrt(mathy1((Math.hypot(x, (y | 0)) >>> 0), Math.min(x, y))), (mathy2((((( ! Math.fround(mathy0(y, 42))) | 0) ? (mathy1((y >>> 0), x) >>> 0) : (mathy0(Math.fround(Math.hypot(Math.fround(( + (2**53-2 ? ( + x) : ( + y)))), Math.fround(Math.cos(1.7976931348623157e308)))), (( - x) | 0)) >>> 0)) >>> 0), x) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, -(2**53+2), 1.7976931348623157e308, Math.PI, 42, 0, -0x100000000, -0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, 0x100000000, 0x080000000, -0x100000001, -Number.MAX_VALUE, 1/0, -Number.MIN_VALUE, -(2**53-2), 2**53, 2**53-2, Number.MAX_VALUE, -(2**53), 1, 0.000000000000001, 0x07fffffff, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -0]); ");
/*fuzzSeed-45472219*/count=711; tryItOut("g1.a0.forEach((function() { for (var j=0;j<110;++j) { f1(j%5==0); } }));");
/*fuzzSeed-45472219*/count=712; tryItOut("\"use strict\"; /*vLoop*/for (let sjaueq = 0; sjaueq < 2; (let (e = window)  '' ), ++sjaueq) { let d = sjaueq; v2 = t1.length; } ");
/*fuzzSeed-45472219*/count=713; tryItOut("for (var p in b1) { try { v1 = (a1 instanceof e1); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(o2, t2); } catch(e1) { } try { h1.getOwnPropertyDescriptor = f0; } catch(e2) { } v0 + v1; }");
/*fuzzSeed-45472219*/count=714; tryItOut("\"use strict\"; /*infloop*/ for  each(let z in ({a2:z2}).__defineGetter__(\"get\", this)) a0[12] = a0;");
/*fuzzSeed-45472219*/count=715; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var acos = stdlib.Math.acos;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    switch ((imul(((0x3752488a) ? (0xe2d56847) : (0xffffffff)), (i0))|0)) {\n      case 1:\n        {\n          i0 = (0x36e4a3fc);\n        }\n        break;\n      case 0:\n        switch ((((!(0xf956e829))-((-0x2ebc6d7) > (0x7fffffff))) & ((0x201c47d1)))) {\n          case -3:\n            (Int32ArrayView[((((-0x8000000)-(i0)-((0x1a198cd5))))) >> 2]) = ((Int8ArrayView[((abs((~((/*FFI*/ff(((makeFinalizeObserver('nursery')) != (eval(\"a\", [z1]))), ((((0x6a4fec0c)) << ((0xaa018f66)))), ((+/*FFI*/ff(((-73786976294838210000.0)), ((9.671406556917033e+24)), ((1125899906842625.0)), ((-0.0009765625)), ((274877906945.0)), ((-70368744177665.0))))), ((4398046511105.0)), ((-65537.0)))|0))))|0) / (((!(i0))) >> ((i0)*-0xd471d))) >> 0]));\n            break;\n          case -1:\n            d1 = (+acos(((d1))));\n            break;\n          default:\n            d1 = (+sqrt(((2199023255553.0))));\n        }\n      case -1:\n        i0 = (0x1b457dc2);\n    }\n    {\n      d1 = (+(0.0/0.0));\n    }\n    return +((+abs(((-((+(-1.0/0.0))))))));\n  }\n  return f; })(this, {ff: Promise}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000001, 2**53-2, 2**53, -0, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0.000000000000001, -(2**53+2), 0, 0x100000000, Math.PI, 0x080000001, 1, Number.MAX_VALUE, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, 42, -0x0ffffffff, 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 1.7976931348623157e308, -1/0, -Number.MIN_VALUE, -(2**53), Number.MIN_VALUE, 0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-45472219*/count=716; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a1, 12, { configurable: /$[\\W\\0]|^+?\\W|[^]|[^](?=(?=(\\B))[^])(?:\\W)*?|\\2{2}/g, enumerable: true, get: (function() { for (var j=0;j<40;++j) { f1(j%3==1); } }), set: (function() { try { s2 = a2[16]; } catch(e0) { } try { Array.prototype.shift.call(a1,  /x/g , o1.t1); } catch(e1) { } v2.toString = (function mcc_() { var ddyegm = 0; return function() { ++ddyegm; if (false) { dumpln('hit!'); try { /*MXX3*/g0.EvalError.prototype.name = g2.EvalError.prototype.name; } catch(e0) { } try { Array.prototype.shift.apply(a2, [v2]); } catch(e1) { } /*MXX2*/this.g1.RegExp.$` = o1.m1; } else { dumpln('miss!'); try { for (var v of m0) { try { /*RXUB*/var r = r1; var s = s2; print(r.test(s)); print(r.lastIndex);  } catch(e0) { } try { v1 = (e0 instanceof m1); } catch(e1) { } try { m2.set(h2, this.h1); } catch(e2) { } v2 = -Infinity; } } catch(e0) { } try { let o0.v2 = evalcx(\"Math.acos(({}))\", g0); } catch(e1) { } v1 = t2.byteOffset; } };})(); throw i1; }) });");
/*fuzzSeed-45472219*/count=717; tryItOut("\"use strict\"; v2 = g2.eval(\"o0.__proto__ = f1;\");");
/*fuzzSeed-45472219*/count=718; tryItOut("\"use strict\"; a1 = /*MARR*/[ \"use strict\" , (void 0), objectEmulatingUndefined(), (void 0), x, x, (void 0), function(){}, x, function(){}, x, function(){}, objectEmulatingUndefined(), function(){}, function(){}, (void 0), objectEmulatingUndefined(), x, x, x, (void 0), (void 0), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(),  \"use strict\" , x, function(){}, function(){}, x, function(){},  \"use strict\" , (void 0), x, x, objectEmulatingUndefined(), (void 0), function(){},  \"use strict\" , (void 0), x, (void 0), (void 0), x, x];");
/*fuzzSeed-45472219*/count=719; tryItOut("(x);\nx;\n");
/*fuzzSeed-45472219*/count=720; tryItOut("var uttsmg = new ArrayBuffer(0); var uttsmg_0 = new Uint32Array(uttsmg); uttsmg_0[0] = 19; var uttsmg_1 = new Int8Array(uttsmg); uttsmg_1[0] = -14; var uttsmg_2 = new Uint8ClampedArray(uttsmg); var uttsmg_3 = new Float32Array(uttsmg); print(uttsmg_3[0]); var uttsmg_4 = new Uint8Array(uttsmg); print(uttsmg_4[0]); print(uttsmg_1[0]);h2.defineProperty = f2;print(uttsmg_2[7]);Array.prototype.forEach.call(a2, (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xed47dcba);\n    i0 = (1);\n    i0 = (0xb531ad92);\n    return +((d1));\n  }\n  return f; }));print((uneval(({a2:z2}))));print( '' .unwatch(\"asin\"));");
/*fuzzSeed-45472219*/count=721; tryItOut("\"use strict\"; { void 0; minorgc(true); }");
/*fuzzSeed-45472219*/count=722; tryItOut("\"use strict\"; Array.prototype.pop.apply(a2, [v1]);");
/*fuzzSeed-45472219*/count=723; tryItOut("v2 = (a2 instanceof t2);");
/*fuzzSeed-45472219*/count=724; tryItOut("i1.send(b1);");
/*fuzzSeed-45472219*/count=725; tryItOut("a1.forEach((function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var acos = stdlib.Math.acos;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (/*FFI*/ff(((+abs(( '' )))), ((~((!(i0))-((i0) ? (!(-0x8000000)) : ((0x163c8c99) != (0xd0840eff)))-(i0)))), ((-9.671406556917033e+24)), ((imul((!(eval(\"e0.delete(o1);\"))), (i1))|0)))|0);\n    {\n      switch ((0x11f53bc0)) {\n        case -1:\n          i0 = (i0);\n        case 1:\n          {\n            i1 = (i0);\n          }\n          break;\n        case 1:\n          i1 = (i1);\n          break;\n        default:\n          {\n            {\n              i1 = (i1);\n            }\n          }\n      }\n    }\n    i1 = (i0);\n    (Float32ArrayView[((Math.max( /x/ , -13))) >> 2]) = ((Float32ArrayView[1]));\n    i0 = (i1);\n    i1 = (!(i0));\n    i1 = ((1.5474250491067253e+26) > (-16777217.0));\n    i0 = ((abs((abs((((((-(i0))>>>((0x1869f07d) / (-0x8000000))))) >> ((((0x7d0e3433) % (0x3557453)) >> ((Int8ArrayView[0]))) % ((((0x237f4914))*-0xfffff)|0))))|0))|0));\n    (Float32ArrayView[4096]) = ((((33554433.0)) - ((-4095.0))));\n    i1 = (i0);\n    i1 = (i1);\n    {\n      i1 = (/*FFI*/ff(((-1125899906842623.0)), ((((((~((i1)))))) ? (-4097.0) : (((-((1.9342813113834067e+25)))) * ((+acos(((Float64ArrayView[((0xcc9cb9ae)) >> 3])))))))), ((16.0)))|0);\n    }\n    {\n/*ADP-1*/Object.defineProperty(g1.a0, v1, ({value: (10.__defineSetter__(\"window\", ({/*TOODEEP*/}))), writable: (x % 5 != 1)}));    }\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return (((Math.fround(( - Math.fround(( + (( + ( + ( - (Math.log2(Math.log2((((Math.hypot((x >>> 0), (x >>> 0)) >>> 0) >= -0x080000001) | 0))) < (((Math.atan2((( + Math.fround(( ~ Math.fround(y)))) >>> 0), y) >>> 0) - y) ^ Math.trunc(( + (Math.atan2((y | 0), -1/0) | 0)))))))) * ( + ( + Math.imul(( + Math.expm1(Math.fround((Math.atan2(y, ( + y)) + (x >>> 0))))), ( + (Math.atan2(Number.MAX_SAFE_INTEGER, Math.log1p(y)) >= ( - ( + y)))))))))))) | 0) <= (Math.hypot(Math.hypot(( + ( - ((( ! (( ! (((x ** (Math.log2((y >>> 0)) >>> 0)) , ((Math.ceil(( + 0x080000000)) | 0) >>> 0)) >>> 0)) | 0)) | 0) >>> 0))), Math.atan2((( + ((Number.MAX_SAFE_INTEGER ? (y >>> 0) : (Math.log10((Math.sqrt(( + Math.fround((y | 0)))) >>> 0)) >>> 0)) >>> 0)) >>> ( ~ (x >>> 0))), (((( + Math.sinh(( + y))) / (y >>> 0)) != ((( ~ y) | 0) == -Number.MIN_VALUE)) | ( + (-Number.MAX_SAFE_INTEGER ? (y === -0x080000001) : -0))))), Math.min((( + ((( ! x) | (Math.trunc(((-Number.MIN_SAFE_INTEGER || Math.fround(-Number.MAX_VALUE)) >>> 0)) >>> 0)) >>> 0)) >>> 0), Math.fround((((Math.fround((Math.fround(Math.atanh(Math.fround(Math.clz32(x)))) != Math.fround(( - Math.hypot(y, (0/0 !== ( + (y + x)))))))) | 0) >= ((( - (Math.fround(((( + (( + ( + (Math.log(y) | 0))) ? ( + ((y & y) >>> 0)) : ( + ( + x)))) | 0) ? (Math.atan2((Math.fround(Math.min(Math.fround(y), (x | 0))) != (((Math.fround(x) << x) | 0) | 0)), Number.MAX_SAFE_INTEGER) | 0) : (y | 0))) >>> 0)) >>> 0) | 0)) | 0)))) >>> 0)) >>> 0); })}, new ArrayBuffer(4096)));");
/*fuzzSeed-45472219*/count=726; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s1; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=727; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.imul(mathy4(Math.sign(Math.min(( + y), (( - (( ~ (Math.max((y | 0), (x | 0)) | 0)) >>> 0)) >>> 0))), (Math.hypot(Math.log1p((0x07fffffff - -(2**53-2))), (x | 0)) | 0)), (Math.fround(mathy2(Math.fround(( ! (Math.fround((Number.MAX_SAFE_INTEGER || (x >>> 0))) << Math.imul(y, (x | 0))))), Math.fround(Math.min(Math.fround(Math.acosh(2**53+2)), Math.fround(Math.imul(( ~ Math.asinh((2**53 | 0))), (( ~ (0x07fffffff >>> 0)) >>> 0))))))) | 0)); }); testMathyFunction(mathy5, [0.000000000000001, 0x080000000, -0x080000000, 0/0, 0, -Number.MAX_VALUE, -1/0, 42, Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0x100000000, -(2**53), -0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 0x0ffffffff, 1, -(2**53+2), Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, 2**53, Math.PI, 1.7976931348623157e308]); ");
/*fuzzSeed-45472219*/count=728; tryItOut("\"use strict\"; /*vLoop*/for (let urhdug = 0; urhdug < 34; ++urhdug) { let z = urhdug; ( /x/ ); } ");
/*fuzzSeed-45472219*/count=729; tryItOut("\"use strict\"; t1[11] = p0;");
/*fuzzSeed-45472219*/count=730; tryItOut("mathy2 = (function(x, y) { return mathy1(Math.max(((Math.asin((x >>> 0)) >>> 0) >>> 0), (( ! (mathy0(1.7976931348623157e308, (0x100000000 >>> 0)) >>> 0)) | 0)), ( + Math.fround(Math.cosh((Math.fround(( + Math.max(Math.sin((( + Math.sin(( + 0x080000000))) | y)), mathy1(Math.atan2((x >= -Number.MIN_SAFE_INTEGER), y), x)))) | 0))))); }); testMathyFunction(mathy2, [-(2**53+2), -0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 0.000000000000001, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, -0x080000001, 42, -(2**53), -0x080000000, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, 1/0, 0x0ffffffff, 1, -1/0, -Number.MIN_VALUE, 0x080000000, -0x100000001, -0, -(2**53-2), 0, 2**53+2]); ");
/*fuzzSeed-45472219*/count=731; tryItOut("\"use strict\"; i2.toString = (function mcc_() { var votgdz = 0; return function() { ++votgdz; if (/*ICCD*/votgdz % 10 == 4) { dumpln('hit!'); v0 = (t0 instanceof f0); } else { dumpln('miss!'); try { selectforgc(o1); } catch(e0) { } try { print(uneval(this.g2)); } catch(e1) { } Array.prototype.pop.apply(a1, [this.b0, t2]); } };})();");
/*fuzzSeed-45472219*/count=732; tryItOut("\"use strict\"; o2 + o0;");
/*fuzzSeed-45472219*/count=733; tryItOut("b2 + '';");
/*fuzzSeed-45472219*/count=734; tryItOut("mathy0 = (function(x, y) { return ( + ( + ( ! (y | 0)))); }); testMathyFunction(mathy0, [1, 0, 0.000000000000001, -Number.MAX_VALUE, 0x080000000, 0x100000000, 2**53+2, -(2**53), 0/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, 1.7976931348623157e308, 1/0, 42, -0, -0x07fffffff, -(2**53-2), Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0x080000001, 0x07fffffff, -0x080000000, Math.PI, 0x100000001]); ");
/*fuzzSeed-45472219*/count=735; tryItOut("mathy0 = (function(x, y) { return Math.pow(Math.fround(Math.fround(( ! Math.cos((((y | 0) ? (x | 0) : (Math.round(( ! Math.log2(Number.MIN_VALUE))) | 0)) | 0))))), Math.fround((Math.log1p(Math.fround((Math.fround(Math.fround(Math.max(y, Math.fround(0x0ffffffff)))) / Math.fround((((x >>> 0) === y) >>> 0))))) | 0))); }); ");
/*fuzzSeed-45472219*/count=736; tryItOut("s0 = i1;");
/*fuzzSeed-45472219*/count=737; tryItOut("g1 + '';");
/*fuzzSeed-45472219*/count=738; tryItOut("Array.prototype.unshift.apply(a2, [e2, h1, p1, g0.v1]);");
/*fuzzSeed-45472219*/count=739; tryItOut("testMathyFunction(mathy0, [-(2**53-2), -0x07fffffff, -0x100000000, -0x080000001, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -(2**53+2), -0, 0x080000000, 0x100000000, 0x080000001, 1, 0/0, 0, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 42, 2**53, -1/0, 0x100000001, -0x100000001, -0x0ffffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, Number.MAX_VALUE, -0x080000000, -Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-45472219*/count=740; tryItOut("\"use strict\"; testMathyFunction(mathy5, ['/0/', (new Number(0)), [0], true, 0.1, 1, '\\0', ({toString:function(){return '0';}}), false, (new Boolean(true)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '0', '', ({valueOf:function(){return 0;}}), (function(){return 0;}), [], (new String('')), /0/, null, (new Boolean(false)), NaN, -0, 0, undefined, (new Number(-0))]); ");
/*fuzzSeed-45472219*/count=741; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-45472219*/count=742; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.max(( + mathy2(( + ( ! ( + (Math.fround((Math.hypot((y >>> 0), x) | 0)) << y)))), Math.fround(( ! ( + Math.atan2((( - (-0x0ffffffff >>> 0)) >>> 0), ( + Math.imul((x ** Math.hypot(0x100000001, y)), y)))))))), ((Math.fround(Math.clz32(Math.sinh(( + mathy0(( + -0x100000000), ( + x)))))) - Math.fround(Math.min(( + (( + x) ? ( + x) : ((0x07fffffff >> y) >>> 0))), ( + x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 0, -1/0, 1.7976931348623157e308, 2**53+2, -0x100000000, -0, -(2**53+2), -Number.MAX_VALUE, Math.PI, -0x080000000, -0x080000001, 42, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0x0ffffffff, 1, -0x07fffffff, 0x080000000, -0x100000001, -Number.MIN_VALUE, 0x100000000, 1/0, 2**53-2, 0x080000001, 2**53, 0x07fffffff, -(2**53)]); ");
/*fuzzSeed-45472219*/count=743; tryItOut("mathy4 = (function(x, y) { return (( + Math.hypot((Math.asin(((y | ( + x)) | 0)) | 0), (Math.fround(( ~ (((w >>> 0) ^ (0.000000000000001 >>> 0)) >>> 0))) >>> 0))) | 0); }); testMathyFunction(mathy4, /*MARR*/[(void 0), 0x2D413CCC, 0x2D413CCC, [(void 0)], (void 0), 0x2D413CCC, 0x2D413CCC, [(void 0)], [(void 0)], (void 0), [(void 0)], 0x2D413CCC, (void 0), null, 0x2D413CCC, (void 0), 0x2D413CCC, (void 0), null, null, [(void 0)], [(void 0)], null, null, 0x2D413CCC, [(void 0)], (void 0), null, (void 0), null, [(void 0)], null, [(void 0)], (void 0), [(void 0)], [(void 0)], [(void 0)], [(void 0)], (void 0), 0x2D413CCC, null, 0x2D413CCC, (void 0), 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, null, (void 0), 0x2D413CCC, [(void 0)], null, (void 0), [(void 0)], (void 0), null, (void 0), (void 0), 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, [(void 0)], [(void 0)], 0x2D413CCC, (void 0), null, 0x2D413CCC, null, null, null, 0x2D413CCC, [(void 0)], null, (void 0), (void 0), 0x2D413CCC, [(void 0)], null, (void 0), null, (void 0), (void 0), 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, null, (void 0), (void 0), [(void 0)], null, 0x2D413CCC, (void 0), [(void 0)], null, (void 0), [(void 0)], (void 0), null, (void 0), [(void 0)], 0x2D413CCC]); ");
/*fuzzSeed-45472219*/count=744; tryItOut("\"use strict\"; s2 = x;");
/*fuzzSeed-45472219*/count=745; tryItOut("v2 = (t1 instanceof b1);");
/*fuzzSeed-45472219*/count=746; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 1.5474250491067253e+26;\n    i0 = ((0x81530b6b) != (0xf4f5e6d1));\n    return ((((((i0)-((abs((abs((0x2913a149))|0))|0) <= (new RegExp(\"(?:(?:[\\\\\\u7f23\\\\S]+))\\\\B\\\\1|(?:\\\\d+?)+?|\\\\u00d6{1}\", \"yim\"))))>>>((Math.imul(Math.max( '' , 29) ? eval = 18 : delete x, /((?!.){2,})?/m ? \"\\u850B\" : false)))))-(i1)+(/*FFI*/ff(((+atan2(((+(1.0/0.0))), ((+floor(((+abs((((0xfa263087) ? (7.737125245533627e+25) : (-2.4178516392292583e+24)))))))))))), ((4398046511105.0)), ((((/*FFI*/ff(((+(0.0/0.0))), ((-268435457.0)), ((-32768.0)))|0)+(0xa292c984)) << ((x)+(i1)))), ((-549755813889.0)), ((-134217729.0)), ((d2)))|0)))|0;\n  }\n  return f; })(this, {ff: ((p={}, (p.z = x)()))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, -(2**53-2), 0x100000001, 0x07fffffff, 2**53+2, Math.PI, -0, 2**53, 1/0, 2**53-2, 0, 1.7976931348623157e308, 0x080000001, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -0x080000000, -0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, -0x080000001, 0x100000000, -(2**53), -0x100000000, 0x080000000, -Number.MIN_VALUE, 1, 0/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=747; tryItOut("mathy2 = (function(x, y) { return ((((mathy0(((( + Math.atan2(( + x), ( + (( + (y >> -Number.MAX_SAFE_INTEGER)) !== Math.fround(Math.atan2(x, (( ~ (x >>> 0)) | 0))))))) & Math.fround((Math.fround((Math.log(y) > y)) >> Math.fround(Math.max(y, x))))) | 0), ((Math.hypot((( - (Math.pow((mathy1((( ~ ( + x)) | 0), (y | 0)) | 0), y) >>> 0)) | 0), ((Math.fround(y) ? Math.fround(x) : Math.fround(Math.atan(0x080000000))) | 0)) | 0) | 0)) | 0) >>> 0) <= ((Math.abs(-Number.MIN_VALUE) !== (y >>> 0)) || Math.tanh(x))) >>> 0); }); testMathyFunction(mathy2, [-0, Math.PI, -0x080000000, 0x0ffffffff, -0x080000001, -(2**53), -0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, 2**53, -0x07fffffff, 0/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, 0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, 1, -(2**53+2), 0.000000000000001, 0x080000000, 0x100000000, 42, Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, 1/0, -0x100000000, -(2**53-2), 0x100000001]); ");
/*fuzzSeed-45472219*/count=748; tryItOut("with({a:  '' }){a1.reverse(b2, s0, t0, o0.i2, p2); }");
/*fuzzSeed-45472219*/count=749; tryItOut("m1.has(b2);");
/*fuzzSeed-45472219*/count=750; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = /\\1/; var s = \"\\u00f1\\u3c93\\n\\u00f1\\u00f1\"; print(s.replace(r, 'x', \"gym\")); ");
/*fuzzSeed-45472219*/count=751; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((( + Math.pow(Math.sqrt(Math.pow(Math.fround((Math.fround(y) ? (((y >>> x) >>> 0) ? 0/0 : Math.fround(( ~ x))) : Math.fround(-(2**53-2)))), mathy0(x, (x | 0)))), (((( + Math.cos((((( - y) >>> 0) >>> 0) ** (( ~ (x >>> 0)) >>> 0)))) ? (( + mathy0(Math.fround(y), ( + x))) | 0) : -Number.MAX_SAFE_INTEGER) | 0) | 0))) >>> 0), Math.atan2((Math.fround(Math.fround(Math.clz32((y | 0)))) | 0), Math.atan(0.000000000000001))); }); testMathyFunction(mathy1, [1/0, -0x080000000, Math.PI, 0x080000001, 0x0ffffffff, 2**53+2, 0/0, -(2**53-2), -0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -(2**53+2), -(2**53), -0x100000000, 2**53-2, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, 42, 1.7976931348623157e308, 0, 0x100000000, 2**53, -1/0, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-45472219*/count=752; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return Math.fround((Math.fround((((Math.max((mathy1(Math.fround((x << Math.fround(x))), y) ** -(2**53+2)), Math.pow(1.7976931348623157e308, ( ~ Math.fround((y | Number.MAX_VALUE))))) > Math.fround(mathy0(-(2**53-2), (( + (( + (((y | 0) % (y | 0)) | 0)) == ( + x))) >>> 0)))) * ((mathy0(Math.fround(Math.tanh((( ! (y >>> 0)) >>> 0))), (( - (Number.MAX_VALUE >>> 0)) | 0)) | 0) | 0)) | 0)) ? Math.fround(Math.fround(((( + Math.ceil(( + x))) % (( + (( + ( + x)) , x)) | 0)) >>> 0))) : Math.hypot(((( + (( + (x >>> 0)) >>> 0)) | 0) | 0), Math.fround(Math.ceil(((Math.fround(( + y)) != -Number.MIN_SAFE_INTEGER) | 0)))))); }); testMathyFunction(mathy2, [2**53, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, -0x100000001, -0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, 2**53-2, -(2**53-2), 1.7976931348623157e308, 0x100000000, -0x080000001, Number.MIN_VALUE, 0.000000000000001, 0, 0x080000001, 0x0ffffffff, -1/0, -0, -(2**53+2), 0x100000001, 1, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, -0x0ffffffff, 1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-45472219*/count=753; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s1; print(r.exec(s)); ");
/*fuzzSeed-45472219*/count=754; tryItOut("\"use strict\"; { void 0; setIonCheckGraphCoherency(true); }");
/*fuzzSeed-45472219*/count=755; tryItOut("v1 = o0.a2.length;");
/*fuzzSeed-45472219*/count=756; tryItOut("t1 + '';");
/*fuzzSeed-45472219*/count=757; tryItOut("v2 = Array.prototype.some.call(a2, f2);");
/*fuzzSeed-45472219*/count=758; tryItOut("\"use strict\"; /*MXX1*/o2 = g1.Number.prototype.valueOf;");
/*fuzzSeed-45472219*/count=759; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.clz32(( ~ ( + (mathy0((mathy2(mathy2(y, (( ~ (x | 0)) | 0)), x) <= Math.fround(Math.atan2(0/0, y))), mathy0(Math.fround(y), Math.fround(x))) >>> 0)))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -0x07fffffff, 1, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0x07fffffff, 0/0, -0x100000000, -0, Math.PI, 0x100000000, Number.MAX_VALUE, 2**53-2, 42, 2**53+2, -(2**53), 0.000000000000001, -0x080000000, 0x080000001, -Number.MIN_VALUE, 2**53, 0x080000000, -(2**53-2), -0x100000001, 0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=760; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=761; tryItOut("\"use asm\"; /*infloop*/ for  each(x in (w) = x) {print(x); }");
/*fuzzSeed-45472219*/count=762; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x100000001, 2**53, -0x0ffffffff, 0x0ffffffff, 0/0, 2**53+2, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), 42, Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, Number.MAX_VALUE, 0.000000000000001, -0, 2**53-2, -Number.MAX_VALUE, -(2**53), 0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0x100000000, 0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, -0x080000001, -Number.MIN_VALUE, -0x07fffffff, -0x100000000, -0x080000000, 0x080000000]); ");
/*fuzzSeed-45472219*/count=763; tryItOut("print((x%=b%=null));");
/*fuzzSeed-45472219*/count=764; tryItOut("/*MXX1*/o0 = g2.ArrayBuffer.prototype.slice;");
/*fuzzSeed-45472219*/count=765; tryItOut("v0 = -Infinity;\nfor (var v of b2) { try { f1.toSource = (function() { try { /*MXX2*/g1.Map.prototype = this.o1.g2; } catch(e0) { } try { s2 + ''; } catch(e1) { } try { i0 = e0.entries; } catch(e2) { } m0 = new WeakMap; return o2; }); } catch(e0) { } try { for (var p in v0) { try { t2 + t0; } catch(e0) { } try { e2.add(a0); } catch(e1) { } try { m1 = new WeakMap; } catch(e2) { } h0 = Proxy.create(h1, m2); } } catch(e1) { } g1.o1.t0.set(a1, 8); }\n");
/*fuzzSeed-45472219*/count=766; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?!((?=$)+?))+?){0}\", \"gi\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=767; tryItOut("o2.m1.set(p2, m1)\nfunction x(x) { return z-- } f1.valueOf = f1;");
/*fuzzSeed-45472219*/count=768; tryItOut("\"use strict\"; for (var v of o1.a1) { v0 = Object.prototype.isPrototypeOf.call(e2, h2); }");
/*fuzzSeed-45472219*/count=769; tryItOut("testMathyFunction(mathy2, [1.7976931348623157e308, 1, 0x100000000, 0x080000001, -0x080000000, -0x100000000, -0x100000001, -(2**53-2), -1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 2**53, Math.PI, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, 0x100000001, -0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, -(2**53+2), 0, -0, 0x0ffffffff, 0/0, -0x080000001, 2**53-2, -Number.MAX_VALUE, 2**53+2, 1/0, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=770; tryItOut("/*RXUB*/var r = /\\3{2,5}*?/i; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-45472219*/count=771; tryItOut("g1.t1 = new Int8Array(a2);");
/*fuzzSeed-45472219*/count=772; tryItOut("\"use strict\"; a1 + m2;");
/*fuzzSeed-45472219*/count=773; tryItOut("mathy2 = (function(x, y) { return Math.tan(Math.fround(Math.clz32(Math.fround(( ! (((x >>> 0) >= (2**53 >>> 0)) >>> 0)))))); }); testMathyFunction(mathy2, [0x100000001, -(2**53-2), -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 0, -(2**53+2), -0, -1/0, 0x080000001, 0/0, 2**53+2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0x080000000, -0x080000000, -Number.MAX_VALUE, -0x100000001, -0x100000000, -(2**53), 2**53-2, 1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, -0x07fffffff, 42, 2**53, 0.000000000000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=774; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.ceil(mathy1(( + ( + (( + (1 << (((( + (((x >>> 0) ? (Number.MIN_VALUE >>> 0) : (-0x0ffffffff >>> 0)) >>> 0)) >>> 0) >> x) | 0))) >> (Math.fround(mathy4(Math.fround(y), Math.fround(((( + ((2**53 >>> 0) >> (x >>> 0))) >>> 0) | 2**53-2)))) | 0)))), Math.fround(( - ((mathy1(( + Math.max((y | 0), Math.fround(((((Math.min(( + y), -0x0ffffffff) | 0) >>> 0) >= (-0x080000001 >>> 0)) >>> 0)))), (Math.fround((( ~ y) >>> 0)) >>> 0)) >>> 0) | 0))))); }); testMathyFunction(mathy5, ['\\0', [], (new String('')), (new Number(-0)), true, false, NaN, /0/, 0.1, '0', objectEmulatingUndefined(), '', null, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), 0, '/0/', 1, (new Boolean(false)), -0, (function(){return 0;}), [0], (new Number(0)), undefined, ({valueOf:function(){return 0;}}), (new Boolean(true))]); ");
/*fuzzSeed-45472219*/count=775; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var floor = stdlib.Math.floor;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((+(-1.0/0.0)));\n    {\n      return +((d1));\n    }\n    {\n      d0 = (d0);\n    }\n    {\n      (Float32ArrayView[1]) = ((Float32ArrayView[(0xec4b7*(0xc6d52ef2)) >> 2]));\n    }\n    {\n      d0 = (+floor(((((d0)) % ((((d0)) / ((-1.0078125))))))));\n    }\n    d0 = (((d0)) - ((d1)));\n    d0 = (NaN);\n    return +((d1));\n  }\n  return f; })(this, {ff: DFGTrue(( \"\"  ? new RegExp(\"\\\\uF4ee{0}\", \"g\") : undefined),  /x/g )}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [1, -0x07fffffff, -0x080000001, Number.MIN_VALUE, 2**53+2, -1/0, 0, 42, 0x07fffffff, 0x100000001, 0x080000000, 0x100000000, Number.MAX_VALUE, -0x080000000, -(2**53-2), 1/0, -(2**53+2), 0/0, -0x100000001, 0x0ffffffff, 2**53, -0, -Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, Math.PI, 2**53-2, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-45472219*/count=776; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return Math.log(Math.fround((Math.fround(( + Math.asinh(( + Math.fround(Math.round(Math.fround((((y >>> 0) > (y >>> 0)) >>> 0)))))))) & (( ! ((( - x) | 0) >>> 0)) | mathy0((Math.exp(y) >>> 0), ((42 >>> 0) ? (y >>> 0) : Math.fround(x))))))); }); ");
/*fuzzSeed-45472219*/count=777; tryItOut("a2[1] = ({a1:1});");
/*fuzzSeed-45472219*/count=778; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (i0);\n    i0 = (i1);\n    (Uint32ArrayView[1]) = (((0x605e225b))+(i0));\n    return (((i1)+(i0)-(i0)))|0;\n  }\n  return f; })(this, {ff: (new Function(\"a0.pop();\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -1/0, Math.PI, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 2**53-2, -Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -0, 42, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, 0, -0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, -0x080000000, 0x100000000, 0x080000001, 0x0ffffffff, 0x080000000, 1, 1/0, -0x100000001, -0x100000000, 2**53+2, 0x07fffffff, -(2**53+2), Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-45472219*/count=779; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0x4d429cf0)+(0xa263c519)))|0;\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_VALUE, -(2**53-2), 0x100000000, 2**53, -(2**53), -Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, -0x07fffffff, -0x100000001, 0.000000000000001, -(2**53+2), 1/0, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 0x0ffffffff, 0x080000001, 0x07fffffff, -0, -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, 42, 0, 0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-45472219*/count=780; tryItOut("mathy2 = (function(x, y) { return (((Math.cosh(( ~ -0x07fffffff)) >>> 0) >>> mathy1((( ! (y === ( + Math.pow(( + 2**53-2), x)))) | 0), ( ~ Math.acos(( + (( + x) && ( + x))))))) || (Math.atan2(( + Math.atan2(( - (-Number.MIN_SAFE_INTEGER | 0)), ( + (y + x)))), (( + (( + Math.fround(mathy1(((x || x) >>> 0), (( + Math.min(( + ( ~ (-0x0ffffffff | 0))), ( + 1.7976931348623157e308))) | 0)))) + ( + ( ! y)))) | 0)) | 0)); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), x, new String('q'), new String('q'), x, x, x, x, x, x, x, x, x, x, x, x, x, [], x, x, x]); ");
/*fuzzSeed-45472219*/count=781; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=782; tryItOut("\"use strict\"; h1 = ({getOwnPropertyDescriptor: function(name) { throw g1; var desc = Object.getOwnPropertyDescriptor(o0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { e1.add(g0);; var desc = Object.getPropertyDescriptor(o0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { print(uneval(o1));; Object.defineProperty(o0, name, desc); }, getOwnPropertyNames: function() { v2 = o1.r2.compile;; return Object.getOwnPropertyNames(o0); }, delete: function(name) { o2.v0 = g1.eval(\"{g1.offThreadCompileScript(\\\"print(\\\\\\\"\\\\\\\\uB88D\\\\\\\");\\\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: false, element: o2 })); for (a of /$|\\\\u0098\\ud06a./y) }\");; return delete o0[name]; }, fix: function() { /*MXX2*/g2.Symbol.toStringTag = g0.t1;; if (Object.isFrozen(o0)) { return Object.getOwnProperties(o0); } }, has: function(name) { print(b2);; return name in o0; }, hasOwn: function(name) { /*RXUB*/var r = r2; var s = s2; print(r.exec(s)); ; return Object.prototype.hasOwnProperty.call(o0, name); }, get: function(receiver, name) { for (var v of this.v0) { try { /*tLoop*/for (let z of (4277)) { h2.enumerate = DataView.prototype.getInt16.bind(g0.o2.m2); } } catch(e0) { } try { Object.defineProperty(this, \"o2.p0\", { configurable: (x % 5 != 2), enumerable: false,  get: function() {  return m0.get(v1); } }); } catch(e1) { } try { m2.delete(t1); } catch(e2) { } t1 + g2; }; return o0[name]; }, set: function(receiver, name, val) { this.e0.toSource = f1;; o0[name] = val; return true; }, iterate: function() { t2.toSource = (function() { for (var j=0;j<23;++j) { f1(j%3==0); } });; return (function() { for (var name in o0) { yield name; } })(); }, enumerate: function() { this.v2 = a0.reduce, reduceRight((function(j) { if (j) { try { g2.s1 += s2; } catch(e0) { } try { m0.set(o1, x); } catch(e1) { } a0.reverse(m2); } else { try { Array.prototype.push.call(a1, o2.a0, x, g2); } catch(e0) { } try { delete b2[6]; } catch(e1) { } try { o1.v0 = a1.reduce, reduceRight((function() { for (var j=0;j<89;++j) { f1(j%2==0); } })); } catch(e2) { } g0.offThreadCompileScript(\"\\\"use strict\\\"; \\\"use asm\\\"; Array.prototype.splice.call(a2, NaN, 1);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 5 != 0), sourceIsLazy: true, catchTermination: true })); } }), g1);; var result = []; for (var name in o0) { result.push(name); }; return result; }, keys: function() { for (var p in a2) { try { v2 = g1.runOffThreadScript(); } catch(e0) { } try { /*MXX1*/let o0 = g0.RegExp.$`; } catch(e1) { } try { v1 = r2.unicode; } catch(e2) { } Array.prototype.pop.call(a1); }; return Object.keys(o0); } });");
/*fuzzSeed-45472219*/count=783; tryItOut("\"use strict\"; i0.send(a2);");
/*fuzzSeed-45472219*/count=784; tryItOut("\"use strict\"; h0.fix = f2;");
/*fuzzSeed-45472219*/count=785; tryItOut("o1.o0 + g0.v0;");
/*fuzzSeed-45472219*/count=786; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=787; tryItOut("\"use strict\"; Array.prototype.pop.apply(this.a2, [o1]);");
/*fuzzSeed-45472219*/count=788; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ! (( ~ Math.fround((Math.fround(Math.fround((y / Math.fround(Math.atan2(y, y))))) ** Math.fround(( + ((Math.round(Math.sqrt(y)) | 0) - ( + (( + y) | 0)))))))) | 0)) | 0); }); ");
/*fuzzSeed-45472219*/count=789; tryItOut("/*hhh*/function jwzuui(){/*RXUB*/var r = new RegExp(\"[^]|((?![^]))|(?:\\u2d0b){4,}\", \"ym\"); var s = \"\\n\\n\"; print(s.search(r)); print(r.lastIndex); }/*iii*/print(jwzuui);");
/*fuzzSeed-45472219*/count=790; tryItOut("(new function(q) { return q; }(delete x.x, let (e) /(?=\\1)/gyi));");
/*fuzzSeed-45472219*/count=791; tryItOut("testMathyFunction(mathy2, [-Number.MAX_VALUE, -(2**53-2), -0x080000001, -(2**53+2), 0x100000001, -0x07fffffff, 0x0ffffffff, -1/0, -0, -Number.MIN_SAFE_INTEGER, 42, -(2**53), Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, 2**53, -0x100000001, Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001, 1.7976931348623157e308, 0x080000001, 2**53+2, 0x080000000, 0, -0x100000000, Number.MAX_VALUE, -0x080000000, 0x07fffffff, -Number.MIN_VALUE, 1/0, -0x0ffffffff]); ");
/*fuzzSeed-45472219*/count=792; tryItOut("let (b) { i0.next(); }");
/*fuzzSeed-45472219*/count=793; tryItOut("\"use strict\"; L:\u000cwith((4277)){a1.push(f2, x); }");
/*fuzzSeed-45472219*/count=794; tryItOut("testMathyFunction(mathy5, [0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, 0x080000000, Number.MAX_VALUE, -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, 42, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, -0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), -0, 0x07fffffff, -0x080000000, 0x0ffffffff, 2**53+2, 1/0, -1/0, 0.000000000000001, -(2**53+2), 2**53, 0x080000001, -Number.MAX_VALUE, 2**53-2, -0x080000001, 0x100000000, 0]); ");
/*fuzzSeed-45472219*/count=795; tryItOut("/*RXUB*/var r = [(Math.acosh(-14))]; var s = \"aa\\n\\u1f5aa\"; print(s.match(r)); ");
/*fuzzSeed-45472219*/count=796; tryItOut("");
/*fuzzSeed-45472219*/count=797; tryItOut("\"use strict\"; v0 = (v0 instanceof a1);");
/*fuzzSeed-45472219*/count=798; tryItOut("\"use strict\"; var x, x, c = (d|=w), NaN =  /x/g .__proto__++;Array.prototype.shift.call(a1, i1);");
/*fuzzSeed-45472219*/count=799; tryItOut("g0.offThreadCompileScript(\"function this.f1(this.h2)  { \\\"use strict\\\"; return this.h2 } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 5 != 2), sourceIsLazy: false, catchTermination: (x % 92 == 18) }));");
/*fuzzSeed-45472219*/count=800; tryItOut("g1.h1.set = Date.prototype.getTimezoneOffset.bind(o1);");
/*fuzzSeed-45472219*/count=801; tryItOut("\"use strict\"; /*MXX1*/o0 = this.o1.g1.Uint16Array;");
/*fuzzSeed-45472219*/count=802; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.abs(Math.min(( ! ( + (( - (-1/0 >>> 0)) >>> 0))), (( - y) | 0))); }); testMathyFunction(mathy4, [-0x100000001, 0x100000001, Math.PI, -1/0, -(2**53+2), 0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 0.000000000000001, -0x080000001, -Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), 0/0, Number.MIN_VALUE, 0x07fffffff, 0x100000000, 42, -Number.MIN_SAFE_INTEGER, 1/0, -0, 0x080000001, 0, 2**53-2, -(2**53-2)]); ");
/*fuzzSeed-45472219*/count=803; tryItOut("/*RXUB*/var r = r2; var s = \"_\\n0_\\n00\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=804; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + (mathy0(( - (mathy4(x, (x >= ( + 2**53-2))) >>> 0)), ( ! Math.tan(y))) >>> 0)); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return 0;}}), (new Number(0)), (function(){return 0;}), (new Boolean(false)), (new String('')), objectEmulatingUndefined(), NaN, 0.1, true, null, '0', /0/, false, 0, [], '', ({valueOf:function(){return '0';}}), '/0/', undefined, 1, '\\0', (new Boolean(true)), -0, [0]]); ");
/*fuzzSeed-45472219*/count=805; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\3|(?=\\\\s|[^].*?+?(?=$*?)|\\\\d*?)\\\\b+?((([^\\\\cY\\u00ab\\\\cM-\\\\xcd\\\\u8753-\\\\xDF])|[^])\\\\3)[\\\\u23e2-\\\\u8A98\\\\\\u000f-\\\\x8c\\\\cV4]|\\\\s+?{3,}|(?:[^]{2,1027})((?=[^\\\\S\\\\w\\u5f6e\\\\S]))|\\\\1|[^]|(?!(?=(?=(?!(?=[^\\\\W\\\\s])))|\\\\t+\\\\w{4})(?=\\\\u0045)(?=((?=(?:[^][^]))))+)\", \"g\"); var s = \"0\\n0_\\n0\\u008c\\u8a97\\n\\n\\n\\n\\n\\n\\n\\n\\n\\na\"; print(s.replace(r, (w = 21))); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=806; tryItOut("/*RXUB*/var r = r2; var s = \"\\n,,\\n,\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=807; tryItOut("Array.prototype.forEach.apply(a0, [this.f1, s0, o2]);");
/*fuzzSeed-45472219*/count=808; tryItOut("\"use strict\"; let (\u3056, x, x, dxfklr, jfaoln, a, w, b, cgdllb, oldrrn) {  }");
/*fuzzSeed-45472219*/count=809; tryItOut("for(let x of x) this.zzz.zzz;");
/*fuzzSeed-45472219*/count=810; tryItOut("\"use strict\"; o1.valueOf = Float32Array;");
/*fuzzSeed-45472219*/count=811; tryItOut("\"use strict\"; v2 = evalcx(\"f1 + '';\", g0);");
/*fuzzSeed-45472219*/count=812; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! Math.pow(( + mathy2((((Math.cos((x | 0)) | 0) & (/\\1|^{1,}|\\3/m | 0)) | 0), (Math.max(((Math.fround(-0) && ( ! x)) <= 0x07fffffff), (x >>> 0)) >>> 0))), ( + (( + Math.pow(2**53, y)) ? 0x100000000 : Math.log10(Math.abs(( + x))))))); }); testMathyFunction(mathy3, ['0', (new Number(-0)), 0.1, '/0/', [], 0, (new String('')), (new Boolean(true)), (function(){return 0;}), '', objectEmulatingUndefined(), (new Number(0)), -0, ({toString:function(){return '0';}}), true, (new Boolean(false)), false, undefined, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), /0/, 1, '\\0', [0], NaN, null]); ");
/*fuzzSeed-45472219*/count=813; tryItOut("\"use strict\"; o2.o0.v2 = evaluate(\"function f0(s0)  '' \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: true }));let w = window;let(y) { yield ((\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+(0x712d6a91));\n    d1 = (+((((~(-(0xc05dbf60))))+(((((0x3b2a8e6b) ? (0x9af5bf9d) : (0xedc4034d))-(/*FFI*/ff(((((0xd0236f86)) << ((0xffffffff)))), ((((0xeeb30d59)) >> ((0x84adf1de)))), ((4.722366482869645e+21)), ((-1.125)), ((268435457.0)), ((67108865.0)), ((-34359738368.0)), ((536870913.0)), ((1024.0)), ((35184372088833.0)), ((1.015625)), ((-2305843009213694000.0)), ((1.015625)), ((281474976710657.0)), ((-524287.0)), ((-32769.0)), ((4.722366482869645e+21)), ((7.555786372591432e+22)), ((1.0625)), ((-9007199254740992.0)), ((2251799813685249.0)), ((-64.0)), ((1.25)), ((4096.0)), ((1.001953125)), ((5.0)), ((1.9342813113834067e+25)))|0))>>>((0x3be2b5c7)))))|0));\n    d0 = (d1);\n    (Float32ArrayView[((0xffffffff)-(0xf461358e)+(!(0x903401da))) >> 2]) = ((((Float32ArrayView[((0x61dc0abe)+(-0x8000000)-((((((0x8cff683e)))) >> ((0xecd65a9d)-(0xfe1d4fd7)-(0x5c31da13))))) >> 2])) % ((d1))));\n    d0 = (d1);\n    {\n      return (((imul((0x6e003f2), (((abs((0x28b762ea))|0) < (~~(4294967295.0))) ? (0x328848cb) : (!(0xffffffff))))|0) % (~((-0x8000000)-((~~(d0)) > ((((((0x3d35699e) ? (5.0) : (-2097153.0))))+((4294967297.0) == (-1.5111572745182865e+23))) >> (((32.0) > (-17179869184.0))+(0x65a665b3))))))))|0;\n    }\n    (Uint8ArrayView[0]) = ((0xf9405246));\n    d0 = (d0);\n    return ((((0x9f66825c))))|0;\n  }\n  return f; })(this, {ff: String.prototype.substr}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, -(2**53-2), -0x080000000, 0.000000000000001, 0x100000001, 2**53, 0x080000001, -Number.MIN_VALUE, -0x100000001, 0/0, -0x07fffffff, 2**53-2, 1/0, -(2**53), 0x0ffffffff, -0, Number.MIN_VALUE, 0x100000000, 2**53+2, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, 0, 42, Number.MAX_VALUE]);  = null));}");
/*fuzzSeed-45472219*/count=814; tryItOut("testMathyFunction(mathy0, [-0, -0x07fffffff, 0x07fffffff, Math.PI, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, Number.MAX_VALUE, -0x080000001, 0x080000000, -Number.MAX_VALUE, -1/0, -0x0ffffffff, 1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, -(2**53), 0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, -(2**53+2), 0, 0.000000000000001, -0x100000000, 2**53-2, -0x100000001, 0x0ffffffff, 42, 0/0, 2**53+2, 1.7976931348623157e308]); ");
/*fuzzSeed-45472219*/count=815; tryItOut("g1.v1 = o2.a1.length;");
/*fuzzSeed-45472219*/count=816; tryItOut("L:with(x.__defineSetter__(\"\\u3056\", encodeURIComponent)){print( /x/g  ?  /x/  :  /x/g ); }");
/*fuzzSeed-45472219*/count=817; tryItOut("return;throw  /x/g ;");
/*fuzzSeed-45472219*/count=818; tryItOut("testMathyFunction(mathy3, [0x0ffffffff, -(2**53-2), 0.000000000000001, 42, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, -Number.MAX_VALUE, 0/0, 0x07fffffff, 0x080000001, 2**53, -(2**53), -0, -0x080000000, 2**53+2, -0x07fffffff, 1.7976931348623157e308, 0x080000000, -0x100000001, Number.MAX_VALUE, -(2**53+2), 0, Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, -1/0, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 1, 2**53-2]); ");
/*fuzzSeed-45472219*/count=819; tryItOut("mathy5 = (function(x, y) { return Math.min(Math.atanh((( - ((( + ( + ( ! (Math.atanh(x) >>> 0)))) < ( ! (((y | 0) | y) | 0))) >>> 0)) | 0)), mathy4(((( + ( ~ ( + x))) / (y >>> 0)) >>> 0), Math.fround(Math.acosh((( + (( + x) * ( + Math.fround(Math.cos(x))))) | 0))))); }); testMathyFunction(mathy5, [-0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, 0, -0x07fffffff, Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 0x080000001, 0x0ffffffff, -0, 0/0, -0x0ffffffff, 42, 1, -0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, -1/0, Math.PI, 2**53-2, -(2**53), -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-45472219*/count=820; tryItOut("\"use strict\"; new RegExp(\"(?=(?!\\\\S))|(?!(?=[^]\\\\w).)|((\\\\B)){0,}\\\\b*?(\\\\B)|[\\\\xfE](?:\\\\B)?{65536}\", \"y\");");
/*fuzzSeed-45472219*/count=821; tryItOut("neuter(this.b0, \"change-data\");");
/*fuzzSeed-45472219*/count=822; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[new Number(1), NaN, NaN, function(){}, new Number(1), new Number(1), NaN, NaN, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (0/0), NaN, NaN, function(){}, new Number(1), new Number(1), new Number(1), (0/0), new Number(1), new Number(1), function(){}, (0/0), new Number(1)]); ");
/*fuzzSeed-45472219*/count=823; tryItOut("t1 = m1.get(g2.f0);");
/*fuzzSeed-45472219*/count=824; tryItOut("\"use strict\"; /*hhh*/function mwunjs(\u3056, a = \"\\uFBCD\", x, x, \u3056, z, x, z, window, c = new RegExp(\"((?!$){1})\", \"\"), x, \u3056, x =  \"\" , y, y, e, x = getter, a, d, x, x, x, x, eval, NaN, NaN, x, d, x, x, x, c = 20, c, x = x, NaN, x =  \"\" , e = new RegExp(\"[^]{2,5}|(?!(?=(?!\\\\d{0,1})+))*?\", \"gy\"), z, window, d, \u3056, z, b, a, e =  '' , window, b, window, \"-3\", a, window, \u3056, set, x, NaN, w, NaN, eval =  '' , x = ({a2:z2}),  '' , window, c, eval, eval, d, x, eval, eval, c, window, b, x = true, e, e, x, get, b, x, x = {}, x, x, x, \"24\", w, x =  '' , NaN = /(?=${274877906943}){0,}(?:\\S|\\u93Bc)|(?!i)^+?|(\\W)|\\d|(?=\\b)[^]*/i, x, d, NaN, window, NaN, d, x, z, NaN, NaN, x = /[]/m, window, \u3056){v2 = Object.prototype.isPrototypeOf.call(b2, s0);}mwunjs(7);");
/*fuzzSeed-45472219*/count=825; tryItOut("(/*FARR*/[(x =  /x/g ), (x = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), 0, runOffThreadScript)), ...d = x, x, (x) =  '' ,  ''  /= \"\\u8050\", \"\\u2E25\" >>>= ({a1:1})].valueOf(\"number\"));");
/*fuzzSeed-45472219*/count=826; tryItOut("\"use strict\"; s2 = x;");
/*fuzzSeed-45472219*/count=827; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=828; tryItOut("mathy1 = (function(x, y) { return (Math.hypot((( ! ((y > ( + (Math.fround(x) || y))) <= Number.MAX_SAFE_INTEGER)) >>> 0), ((x === y) >>> 0)) ? Math.sqrt(( ! ( ! (Math.sin((Math.max(( + x), y) >>> 0)) | 0)))) : Math.exp((Math.min((( ~ ( + Math.imul(y, -0x080000000))) >>> 0), (Math.ceil(Math.imul(42, x)) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-45472219*/count=829; tryItOut("/*tLoop*/for (let e of /*MARR*/[ '' , false,  '' , false,  /x/ , false]) { let e = undefined;; }");
/*fuzzSeed-45472219*/count=830; tryItOut("mathy0 = (function(x, y) { return ( ~ (Math.fround(Math.atanh(((-0x100000001 == (( + (x | 0)) | 0)) ** Math.fround(( - ( + Math.log10(y))))))) === Math.fround(Math.pow((Math.log2((((-(2**53+2) | 0) < Math.fround((x | y))) | 0)) >>> 0), y)))); }); testMathyFunction(mathy0, [0x100000000, -0x07fffffff, 1, -0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0, 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 2**53, 42, -(2**53+2), -0x100000000, Math.PI, -0x0ffffffff, 0/0, -(2**53-2), -0x080000000, 0.000000000000001, 1/0, 0x080000000, 0x0ffffffff, Number.MAX_VALUE, -(2**53), 2**53-2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, -1/0]); ");
/*fuzzSeed-45472219*/count=831; tryItOut("\"use strict\"; e0.has(e0);");
/*fuzzSeed-45472219*/count=832; tryItOut("f1 = Proxy.createFunction(h0, f1, f1);");
/*fuzzSeed-45472219*/count=833; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 1.5;\n    switch ((((/*FFI*/ff(((1099511627776.0)), ((-2251799813685248.0)), ((-257.0)), ((-64.0)), ((5.0)))|0)-((0xffffffff) <= (0x0))-(i0))|0)) {\n      case -1:\n        {\n          i2 = (i1);\n        }\n        break;\n      default:\n        i0 = (0xd362e771);\n    }\n    return +((((0x11105ca2)) ? (1.00390625) : (-549755813889.0)));\n  }\n  return f; })(this, {ff: (DataView.prototype.getInt16).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, -(2**53), Number.MAX_VALUE, -0x080000001, 0x07fffffff, Number.MIN_VALUE, -1/0, -0x080000000, 0x080000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -(2**53+2), -(2**53-2), 1, 0.000000000000001, 42, -0, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 1.7976931348623157e308, -0x07fffffff, 2**53+2, Math.PI, 0x080000001, 0x100000000, 0x100000001, -0x100000001, 0/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=834; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.round((Math.fround((mathy0(Math.fround(Math.sign((((Math.max((-Number.MAX_SAFE_INTEGER >>> 0), (x >>> 0)) >>> 0) ? y : Math.expm1(x)) | 0))), x) !== x)) | 0)); }); ");
/*fuzzSeed-45472219*/count=835; tryItOut("\"use strict\"; Array.prototype.sort.call(a1, (function(j) { f2(j); }), o1.b0);");
/*fuzzSeed-45472219*/count=836; tryItOut("\"use strict\"; a1[17];");
/*fuzzSeed-45472219*/count=837; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + Math.max(Math.acos(Math.atan((Math.max((y | 0), (y | 0)) | 0))), (mathy2((((mathy3(Math.hypot(x, mathy1(x, Math.fround(y))), (0/0 | 0)) | 0) === ( ! x)) >>> 0), (( + ( ~ ( + ( + Math.atan(Math.fround((2**53+2 ? 1 : -0x080000001))))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, /*MARR*/[ /x/ , x, x, x, x, x, x, 2**53+2,  /x/ ,  '' ,  /x/ , -0x080000000,  /x/ ]); ");
/*fuzzSeed-45472219*/count=838; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=839; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((( - (Math.log(mathy1(1, (x >>> 0))) >>> 0)) * ((Math.pow((x >>> 0), (( + x) >>> 0)) >>> 0) / (( + Math.imul(x, y)) ? (x | 0) : 0.000000000000001))) & (Math.sqrt((Math.clz32((Math.fround(mathy2(( + ( + ( - ( + -0x080000001)))), Math.fround(Math.fround(( ~ Math.fround(y)))))) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-0, -0x100000001, -0x100000000, 2**53-2, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0, 1/0, -1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53-2), 0/0, -(2**53), -0x07fffffff, -Number.MIN_VALUE, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, Number.MAX_VALUE, Math.PI, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, 0x080000001, -0x080000000, 42, 0x080000000, 1, 0.000000000000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-45472219*/count=840; tryItOut(".2;");
/*fuzzSeed-45472219*/count=841; tryItOut("\"use strict\"; s2 = new String;");
/*fuzzSeed-45472219*/count=842; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=843; tryItOut("\"use asm\"; /*RXUB*/var r = /(((\\S)|(?=[]|\\s)|\\3*?)?)/gyim; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=844; tryItOut("eval = linkedList(eval, 5456);");
/*fuzzSeed-45472219*/count=845; tryItOut("L: for (let x of (Math.hypot( \"\" , -27))) \"use strict\"; print(x);");
/*fuzzSeed-45472219*/count=846; tryItOut("\"use strict\"; m2.has(this.a0);");
/*fuzzSeed-45472219*/count=847; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(g0.s1, this.b1);");
/*fuzzSeed-45472219*/count=848; tryItOut("\"use strict\"; v0 = 4;");
/*fuzzSeed-45472219*/count=849; tryItOut("/*bLoop*/for (let vxabbr = 0; vxabbr < 56 && ((delete x.x)); ++vxabbr) { if (vxabbr % 5 == 4) { i1 + h0; } else { const b = new RegExp(\"(?!\\\\1)\", \"gyi\"), b, bdyziz, eval, mlccew, nqdecj, window, ahfsbq, qxgqaw, lbtosx;m1 = t2[17]; }  } ");
/*fuzzSeed-45472219*/count=850; tryItOut("p2 + '';");
/*fuzzSeed-45472219*/count=851; tryItOut("\"use strict\"; const d = let (e = x) /*RXUE*/new RegExp(\"(?:\\\\d)\\\\xFC*$|$|(?=\\\\b?[^\\\\u00E4-\\ueaea\\\\D\\\\D,-U])((?![\\\\s\\\\D\\\\u514E\\\\D]){2,})+?\", \"gyi\").exec(\"\");for(var c in ((encodeURIComponent)( '' ))){e2.has(o2.m2); }");
/*fuzzSeed-45472219*/count=852; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + (( + Math.hypot(( + ( ! 0x080000000)), ( + Math.hypot(( + x), x)))) ** Math.fround(Math.ceil(( + ( ~ ( + (((y >>> 0) << (y >>> 0)) >>> 0)))))))) ^ Math.max((Math.fround(Math.round(Math.acos(x))) ? ( + ((-Number.MAX_SAFE_INTEGER | 0) < ( + y))) : Math.atan2(Math.fround(0x100000001), (Math.atan2((x | 0), (x | 0)) | 0))), (Math.round((y >>> 0)) >>> 0))); }); ");
/*fuzzSeed-45472219*/count=853; tryItOut("/*vLoop*/for (var qqwoxs = 0; qqwoxs < 2; ++qqwoxs) { x = qqwoxs; { void 0; void relazifyFunctions('compartment'); } } ");
/*fuzzSeed-45472219*/count=854; tryItOut("mathy3 = (function(x, y) { return Math.asin((Math.fround((Math.acosh(y) >>> 0)) && (( ! ( + Math.abs((y >>> 0)))) / (Math.min((y >>> 0), (x >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [-0x07fffffff, -Number.MAX_VALUE, 0.000000000000001, -0x080000001, -0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 2**53, -(2**53+2), 0x0ffffffff, -0x100000000, 1.7976931348623157e308, 0/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, 0, -(2**53-2), -0, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 2**53+2, -0x100000001, -1/0, 1, 0x100000001, Math.PI]); ");
/*fuzzSeed-45472219*/count=855; tryItOut("(x--);");
/*fuzzSeed-45472219*/count=856; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.max(Math.atanh(((( ~ (( ! mathy0((( + Math.cosh((x | 0))) | 0), (y | 0))) >>> 0)) >>> 0) >>> 0)), ( + (( + (( + (( + ( ! (Math.clz32(y) | 0))) << ( + ((((((-0x07fffffff >>> 0) == (0x080000000 >>> 0)) >>> 0) >>> 0) === (Math.min(((y >= (Math.atan2(y, x) | 0)) | 0), (Math.fround(( - (x >>> 0))) >>> 0)) >>> 0)) >>> 0)))) | 0)) | 0))); }); testMathyFunction(mathy1, ['0', objectEmulatingUndefined(), null, '', [0], -0, 0, 1, true, NaN, '/0/', ({toString:function(){return '0';}}), (new String('')), [], (new Boolean(false)), ({valueOf:function(){return 0;}}), (new Number(-0)), false, (new Number(0)), (new Boolean(true)), '\\0', ({valueOf:function(){return '0';}}), /0/, undefined, (function(){return 0;}), 0.1]); ");
/*fuzzSeed-45472219*/count=857; tryItOut("/* no regression tests found */");
/*fuzzSeed-45472219*/count=858; tryItOut("print(x);");
/*fuzzSeed-45472219*/count=859; tryItOut("\"use asm\"; v0 = (a2 instanceof t1);");
/*fuzzSeed-45472219*/count=860; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = this.s0; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-45472219*/count=861; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0x25c5f8c);\n    (Int16ArrayView[((!((-144115188075855870.0)))-(i0)) >> 1]) = (((i0) ? (0xffffffff) : ((0x3dc1b654) <= (0xf6ef4046))));\n    return +((d1));\n  }\n  return f; })(this, {ff: Number.isInteger}, new ArrayBuffer(4096)); ");
/*fuzzSeed-45472219*/count=862; tryItOut("\"use strict\"; /*RXUB*/var r = /[\\cJ\uc117\u0011-\u0089\uf8e8]{4,6}|\\3(?![^].|\\b|\\t|\\1).|[^\\x8b\\D]{2}|.{4}/gym; var s = \"\\uf8e8\\uf8e8\"; print(s.split(r)); ");
/*fuzzSeed-45472219*/count=863; tryItOut("do v0 = this.t0.BYTES_PER_ELEMENT; while((this) && 0);");
/*fuzzSeed-45472219*/count=864; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((Math.min(Math.fround(mathy3(Math.fround(( ! (((x >>> 0) + Math.fround((Number.MIN_VALUE << 2**53+2))) >>> 0))), Math.fround(y))), (Math.fround(mathy3(( ~ Math.fround((((y >>> 0) ? y : y) >>> 0))), (x !== y))) >>> 0)) >>> 0) , ((( + ( + ((mathy1(( + mathy1(( + y), ( + y))), ( + 0x080000001)) | 0) * Math.fround(( - Math.fround(( - mathy2(x, -1/0)))))))) >>> 0) >>> 0)); }); testMathyFunction(mathy4, [-0x080000000, 0x080000001, 0x0ffffffff, 1, 1.7976931348623157e308, 0x080000000, -0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x07fffffff, 2**53-2, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, Number.MIN_VALUE, 0/0, -(2**53-2), 0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, 0.000000000000001, 0, 0x100000001, -(2**53+2), -0x080000001, -0x0ffffffff, 42, -0x07fffffff, -Number.MAX_VALUE, -(2**53), -0x100000000, 2**53, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-45472219*/count=865; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.atan2(-0x080000001, (y ? (( - ( - x)) ? Math.min(Math.fround(( + x)), Math.fround(2**53+2)) : -(2**53)) : 0)) > Math.log10(Math.max(x, -(2**53-2)))) < ( + Math.imul(( + (Math.atan((Math.round(Math.imul(y, x)) | 0)) | 0)), ( + ((( + Math.pow(( + (Math.atan(( + ( + (( + y) ? ( + y) : ( + x))))) | 0)), ( + x))) >>> 0) <= (Math.atan(Math.expm1(x)) >>> 0)))))); }); testMathyFunction(mathy0, [1, 0x080000001, -0, -0x100000001, -Number.MIN_VALUE, 0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 0x100000001, -(2**53-2), 2**53-2, Number.MIN_VALUE, 0x080000000, 0/0, 2**53, -Number.MAX_VALUE, 0x100000000, -0x100000000, 1/0, -0x07fffffff, 2**53+2, -1/0, 42, -0x0ffffffff, -(2**53+2), 0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, 0, -0x080000000]); ");
/*fuzzSeed-45472219*/count=866; tryItOut("testMathyFunction(mathy1, [undefined, 0, 1, (new Number(-0)), [], (new Boolean(false)), (new String('')), /0/, null, ({valueOf:function(){return '0';}}), '/0/', '0', false, true, (new Boolean(true)), '', (new Number(0)), '\\0', 0.1, ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), -0, NaN, objectEmulatingUndefined(), [0], (function(){return 0;})]); ");
/*fuzzSeed-45472219*/count=867; tryItOut("/*infloop*/ for  each(let a in  /x/g ) {v1 = new Number(this.s1); }");
/*fuzzSeed-45472219*/count=868; tryItOut("mathy5 = (function(x, y) { return Math.min(Math.fround(Math.fround(( + Math.fround(Math.asinh(( + Math.asin(Math.fround(((x >>> 0) === ((( ~ (-0x100000001 | 0)) | 0) >>> 0)))))))))), Math.fround(( ! (((( + (( + Math.imul(x, y)) < ( + y))) | 0) < ( + mathy1(x, Math.expm1(x)))) | 0)))); }); testMathyFunction(mathy5, [0, [0], (new Boolean(false)), [], (new String('')), '\\0', false, ({toString:function(){return '0';}}), /0/, (new Boolean(true)), null, undefined, '', objectEmulatingUndefined(), NaN, -0, ({valueOf:function(){return '0';}}), (function(){return 0;}), true, '/0/', (new Number(0)), ({valueOf:function(){return 0;}}), 0.1, (new Number(-0)), '0', 1]); ");
/*fuzzSeed-45472219*/count=869; tryItOut("t2[4];");
/*fuzzSeed-45472219*/count=870; tryItOut("{ void 0; setIonCheckGraphCoherency(false); }");
/*fuzzSeed-45472219*/count=871; tryItOut("\"use strict\"; \"use asm\"; /*vLoop*/for (wfhpjv = 0; wfhpjv < 132; ++wfhpjv) { e = wfhpjv; a2.sort((function mcc_() { var nocvzp = 0; return function() { ++nocvzp; if (/*ICCD*/nocvzp % 7 == 6) { dumpln('hit!'); try { o1.e2.has(f2); } catch(e0) { } try { a1.pop(); } catch(e1) { } try { o0 + o2.o1; } catch(e2) { } a2.push(f1, e2); } else { dumpln('miss!'); try { o0.a2.splice(16, \"\\u9539\", v0, f1); } catch(e0) { } try { /*ADP-3*/Object.defineProperty(g0.g1.a2, 12, { configurable: (x % 19 == 10), enumerable: true, writable: true, value: t0 }); } catch(e1) { } e2.delete(h1); } };})()); } ");
/*fuzzSeed-45472219*/count=872; tryItOut("h1.delete = this.f2;");
/*fuzzSeed-45472219*/count=873; tryItOut("\"use strict\"; with(x){/*tLoop*/for (let b of /*MARR*/[]) { print(x); } }");
/*fuzzSeed-45472219*/count=874; tryItOut("/*vLoop*/for (var vdcpho = 0; vdcpho < 12; ++vdcpho) { let x = vdcpho; print( \"\" ); } ");
/*fuzzSeed-45472219*/count=875; tryItOut("m1.get(h0);");
/*fuzzSeed-45472219*/count=876; tryItOut("return");
/*fuzzSeed-45472219*/count=877; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.cosh(Math.hypot(Math.round((( ! ((y - Math.max((((y >>> 0) * y) >>> 0), x)) | 0)) | 0)), (Math.acosh((42 != y)) >>> 0))); }); testMathyFunction(mathy0, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, -0x080000000, 2**53+2, 2**53-2, -(2**53), 0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, -Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 2**53, 0, 1/0, Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, 42, 0/0, 0x100000000, Math.PI, -(2**53+2), 1]); ");
/*fuzzSeed-45472219*/count=878; tryItOut("mathy2 = (function(x, y) { return ( + ( + Math.pow((( + (y >>> 0)) >>> 0), (Math.clz32(Math.fround((Math.fround(x) | Math.fround(Math.fround(Math.min(((2**53+2 | 0) != x), 0/0)))))) | 0)))); }); testMathyFunction(mathy2, [2**53+2, 42, -(2**53), -0x080000000, -0x080000001, -(2**53+2), -0x100000001, Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, 0x080000000, 0x100000001, 0x100000000, 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53, 0x07fffffff, 0.000000000000001, 1/0, -1/0, -0, -(2**53-2), Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, Math.PI, Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-45472219*/count=879; tryItOut("v1.__proto__ = a1;");
/*fuzzSeed-45472219*/count=880; tryItOut("testMathyFunction(mathy1, [0, 2**53, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, 0x100000001, 1, 0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, 0.000000000000001, 0x100000000, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), -0x100000000, -0, 2**53-2, -(2**53-2), -0x080000001, -0x080000000, -1/0, 0x080000000, 42, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, 1.7976931348623157e308, -0x0ffffffff]); ");
/*fuzzSeed-45472219*/count=881; tryItOut("i1.send(o1.i1);");
/*fuzzSeed-45472219*/count=882; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.fround(Math.cos((Math.tanh(x) | 0)))); }); ");
/*fuzzSeed-45472219*/count=883; tryItOut("(yield (/*UUV1*/(x.isFrozen = arguments.callee)));const a = (Object.defineProperty(NaN, new String(\"11\"), ({writable:  \"\" , enumerable: x})));");
/*fuzzSeed-45472219*/count=884; tryItOut("/*bLoop*/for (let ihrcnd = 0; ihrcnd < 22; ++ihrcnd) { if (ihrcnd % 21 == 16) { s2 += 'x';function y(...x) { \"use strict\"; print(x); } for (var p in g1.g2.e0) { try { m0.set(g0, b1); } catch(e0) { } try { Array.prototype.shift.call(g0.a2); } catch(e1) { } try { t0.set(a0, 2); } catch(e2) { } e2.has(a0); } } else { a2 = a0.concat(a0, o2.a1, t1)\n }  } ");
/*fuzzSeed-45472219*/count=885; tryItOut("\"use strict\"; g1.e0.add(h1);");
/*fuzzSeed-45472219*/count=886; tryItOut("mathy0 = (function(x, y) { return Math.cos(Math.sin((Math.fround(( ! Math.fround(y))) ? ( + Math.atan2(( + 0/0), ( + ( + Math.sinh(x))))) : y))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, 42, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, 0x100000000, -(2**53), 0x080000000, -0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -1/0, 1, -0, 0x100000001, 0, -0x07fffffff, -(2**53+2), -(2**53-2), 2**53+2, 2**53, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0/0, 2**53-2, -0x0ffffffff, -0x100000001, -Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-45472219*/count=887; tryItOut("for(var c in  \"\" ) h2.keys = f2;");
/*fuzzSeed-45472219*/count=888; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-45472219*/count=889; tryItOut("\"use strict\"; t0 = t1.subarray(({valueOf: function() { v1 = (h1 instanceof g1);return 16; }}), v0);const a =  /* Comment */ '' ;");
/*fuzzSeed-45472219*/count=890; tryItOut("\"use strict\"; a2 + v1;");
/*fuzzSeed-45472219*/count=891; tryItOut("o1 = {};");
/*fuzzSeed-45472219*/count=892; tryItOut("/*iii*/a1[12] = t2;/*hhh*/function fglgtw(y){v0 = Object.prototype.isPrototypeOf.call(h1, o0.m1);}");
/*fuzzSeed-45472219*/count=893; tryItOut("\"use strict\"; \"use asm\"; let ((function a_indexing(ynuori, cpqyas) { ; if (ynuori.length == cpqyas) { ; return a = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: function() { throw 3; }, keys: function() { return []; }, }; })(null), function(y) { \"use strict\"; const xulitw, x, y, cpqyas, z, d;break ; }); } var jkfduf = ynuori[cpqyas]; var vmpzls = a_indexing(ynuori, cpqyas + 1); return  '' ; })(/*MARR*/[null, undefined,  /x/ , undefined, undefined, null, null,  /x/ , null, undefined, undefined,  /x/ , undefined, null, null, undefined,  /x/ , null,  /x/ ,  /x/ , undefined, null, undefined,  /x/ ,  /x/ , undefined,  /x/ , undefined, undefined,  /x/ , undefined, undefined, null, undefined, null, null, null, null, undefined, null, undefined, undefined,  /x/ , null,  /x/ ,  /x/ , null,  /x/ , undefined, null, null,  /x/ , null, null, null,  /x/ ,  /x/ , null, undefined,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , null, undefined, null, null, null], 0)).NaN = \"\\u85D2\", window = new String.prototype.small(17, \"\\u80E4\"), e = (yield Math.imul(4, new RegExp(\"((?!(?=[^])))*\", \"gm\"))), d = (objectEmulatingUndefined)(-36893488147419103000), x =  /x/ , x, e, \u3056, cgdipy;throw eval(\"\\\"use strict\\\"; b2.toString = neuter;\", new RegExp(\"(?!\\\\3*?)\", \"gi\"));");
/*fuzzSeed-45472219*/count=894; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-45472219*/count=895; tryItOut("(4277);");
/*fuzzSeed-45472219*/count=896; tryItOut("v0 = g2.eval(\"NaN = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: /*wrap1*/(function(){ print(([,,z1] >=  \\\"\\\" ));return /*wrap1*/(function(){ return;return \\\"\\\\uC93C\\\"})()})(), getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: function() { return false; }, get: undefined, set: function() { return true; }, iterate: Array.prototype.fill, enumerate: offThreadCompileScript, keys: function() { return []; }, }; })(x), new /(?!(?!((?=(?=\\\\B)){8}))[^\\\\w\\\\cC-\\\\u00d4\\\\D])/m(), Uint8ClampedArray)\");");
/*fuzzSeed-45472219*/count=897; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.sin(Math.fround((Math.atan2((( + (Math.imul(y, Math.max(y, y)) || Math.fround(((x >>> 0/0) >>> 0)))) | 0), (( ~ Math.fround(Math.atan2((1 % x), y))) | 0)) | 0)))); }); testMathyFunction(mathy3, [-0x080000000, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -0x0ffffffff, 0x100000001, -1/0, 0x100000000, -0, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, 42, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE, 2**53-2, 0, 1, 2**53, 0.000000000000001, Number.MAX_VALUE, 2**53+2, -(2**53), 0/0, -Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, Math.PI, -0x100000001]); ");
/*fuzzSeed-45472219*/count=898; tryItOut("v1 = g0.runOffThreadScript();");
/*fuzzSeed-45472219*/count=899; tryItOut("s1 += s2;");
/*fuzzSeed-45472219*/count=900; tryItOut("/*RXUB*/var r = /(?!\\2+?)|[\\uf77e\ucd55\\xD9-!\\D]\uf0e4+?{0}+?\\1/g; var s = \"0\"; print(s.match(r)); ");
/*fuzzSeed-45472219*/count=901; tryItOut("mathy1 = (function(x, y) { return (((( - ( + (Math.log1p((y >>> 0)) >>> 0))) | 0) != (Math.tanh(Math.expm1(x)) | 0)) | 0); }); ");
/*fuzzSeed-45472219*/count=902; tryItOut("mathy5 = (function(x, y) { return Math.log1p(Math.atan2(Math.fround(( ! ( + Math.imul((y | 0), (( + (( + x) && ( + ( ! y)))) | 0))))), ( + mathy3(( + ( ~ ( + Math.max(0x100000000, y)))), Math.fround((Math.fround(1) ? y : Math.fround(( ~ ( + mathy3(( + (( ~ (y >>> 0)) >>> 0)), ( + 1/0))))))))))); }); testMathyFunction(mathy5, [-(2**53+2), -Number.MAX_SAFE_INTEGER, -0, -0x080000000, 0x0ffffffff, 42, -(2**53), Number.MIN_SAFE_INTEGER, 0/0, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, 2**53, -1/0, 0, 0x100000000, Math.PI, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, Number.MAX_VALUE, 0x080000001, Number.MIN_VALUE, 0x100000001, -(2**53-2), -0x100000001, 2**53-2, 0.000000000000001, 2**53+2, -0x100000000, -Number.MIN_VALUE, -0x080000001, 1]); ");
/*fuzzSeed-45472219*/count=903; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!\\\\cE|.{4}){0}((?!\\\\w{4,})){33554431,}\", \"gim\"); var s = \"\\n\\n\\n\\n\\n\\n\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9:\\n\\n\\n\\n\\n\\n0000a\\u69f1:a\\u69f1\\u69f1\\u69f1\\u514a\\u69f1\\n\\n\\n\\n\\n\\n\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9:\\n\\n\\n\\n\\n\\n\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9:\\n\\n\\n\\n\\n\\n\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9:\\n\\n\\n\\n\\n\\n\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9:\\n\\n\\n\\n\\n\\n\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9:\\n\\n\\n\\n\\n\\n\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9:\\n\\n\\n\\n\\n\\n\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9\\u3ea9:\"; print(s.match(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
