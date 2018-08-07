

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
/*fuzzSeed-246262462*/count=1; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -16385.0;\n    var d3 = 0.5;\n    var i4 = 0;\n    return +((36893488147419103000.0));\n    (Float32ArrayView[4096]) = ((Infinity));\n    i0 = (i4);\n    return +((4503599627370497.0));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [Math.PI, 0x0ffffffff, -0, -Number.MAX_VALUE, 0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, 0x080000000, -0x0ffffffff, -0x100000000, -(2**53+2), -1/0, 0/0, -0x07fffffff, -(2**53-2), 1, -(2**53), -0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 0x080000001, 0x100000000, 42, 2**53-2, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, 2**53+2]); ");
/*fuzzSeed-246262462*/count=2; tryItOut("this.t1[12];");
/*fuzzSeed-246262462*/count=3; tryItOut("x.lineNumber;");
/*fuzzSeed-246262462*/count=4; tryItOut("i0 = a1[({valueOf: function() { this.e1.toString = (function mcc_() { var bvkkyk = 0; return function() { ++bvkkyk; if (/*ICCD*/bvkkyk % 10 != 2) { dumpln('hit!'); try { e0 = new Set; } catch(e0) { } try { s2 += s2; } catch(e1) { } try { s2 += 'x'; } catch(e2) { } t0 + ''; } else { dumpln('miss!'); m0.has(v1); } };})();return 1; }})];");
/*fuzzSeed-246262462*/count=5; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround((Math.fround((( ! Math.sign(Math.fround(-0x100000000))) >> ((Math.imul(( ~ -0x0ffffffff), y) || ( + ( + ( + (x << Math.fround(( + Math.pow(Math.fround(Math.sin(x)), Math.fround(x))))))))) | 0))) & Math.fround((( ~ Math.fround(( + (Math.asinh(( + x)) | 0)))) / (( ~ x) || ( ~ ( ! x))))))); }); testMathyFunction(mathy0, [0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, 2**53, Math.PI, -0x100000001, 0/0, 1/0, 0, -Number.MAX_VALUE, -(2**53), 0x080000001, 1, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 42, -(2**53-2), -0x0ffffffff, 0x07fffffff, -0x080000000, -1/0, 0.000000000000001, 0x080000000, -0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=6; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy1(( - ((( - ( - (((-Number.MIN_SAFE_INTEGER >>> 0) ** (y >>> 0)) >>> 0))) >>> 0) != Math.imul(( + 1/0), ( + ((( + y) ? y : Math.fround(((y | 0) ? Math.fround(y) : Math.fround(x)))) >>> 0))))), ( - ((Math.hypot((y | 0), (y >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 2**53-2, 1/0, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, -(2**53+2), -0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, 42, 2**53+2, -0x100000001, 2**53, -0, 0/0, -(2**53), 0x0ffffffff, -0x100000000, 0x100000001, 0x080000001, Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, 1, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, Math.PI, 0]); ");
/*fuzzSeed-246262462*/count=7; tryItOut("jzohng( /* Comment */null, eval(\"a1.splice(NaN, \\\"\\\\uDA93\\\");\",  \"\" ));/*hhh*/function jzohng(x = x){print(Math.imul(('fafafa'.replace(/a/g, encodeURIComponent)), ()));}");
/*fuzzSeed-246262462*/count=8; tryItOut("mathy4 = (function(x, y) { return (((Math.min(( + ( ~ (mathy2(x, x) - Math.imul(x, ( ! x))))), (( + (y >> ( + x))) >> Math.fround(Math.acosh(Math.fround(Math.max(Math.fround(( ! x)), (-0x080000001 | 0))))))) >>> 0) / (mathy0(( + Math.atan2(y, (Math.sinh(-(2**53-2)) | 0))), x) | ( + mathy3(( + Math.imul(( + x), (x * ( + x)))), mathy2(Math.fround((42 ^ x)), ( ! y)))))) | 0); }); testMathyFunction(mathy4, /*MARR*/[]); ");
/*fuzzSeed-246262462*/count=9; tryItOut("mathy0 = (function(x, y) { return Math.asin((( ~ ( ! (Math.pow(x, ( + Math.atanh(-0x07fffffff))) | 0))) + (Math.cos((Math.pow(Math.log((x | 0)), ((-Number.MAX_VALUE ? ( + x) : Math.fround(( ! Math.fround(y)))) | 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [[], [0], true, 0, ({valueOf:function(){return 0;}}), /0/, (new String('')), ({valueOf:function(){return '0';}}), NaN, null, -0, 1, '', ({toString:function(){return '0';}}), '/0/', '0', (new Number(-0)), objectEmulatingUndefined(), (function(){return 0;}), '\\0', (new Number(0)), false, undefined, (new Boolean(true)), 0.1, (new Boolean(false))]); ");
/*fuzzSeed-246262462*/count=10; tryItOut("p2 = t0[17];");
/*fuzzSeed-246262462*/count=11; tryItOut("mathy2 = (function(x, y) { return (Math.min(( + ((((y >>> 0) | ( + mathy1(y, ( ! x)))) >>> 0) | 0)), (((( ~ Math.fround(( ! ( - (y >>> 0))))) >>> 0) ? (( - (mathy1((x >>> 0), (Math.acosh(y) >>> 0)) >>> 0)) | 0) : Math.imul(2**53, (mathy1((( ! ( + y)) >>> 0), (y >>> 0)) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-246262462*/count=12; tryItOut("h1.keys = (function() { for (var j=0;j<42;++j) { f1(j%4==0); } });print(x+=true);");
/*fuzzSeed-246262462*/count=13; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return (((0x71417040) % (((0x5e948bf7)+((imul((i3), ((0xfbc13fb4) != (0x6218f0f2)))|0)))>>>((i2)))))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return ( + Math.atan(y)); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, 42, -(2**53-2), 0x100000001, 2**53-2, -(2**53+2), 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, -(2**53), -0x080000001, 0x0ffffffff, 2**53, -0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, -0, -0x100000001, 1.7976931348623157e308, 1, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 0, -0x100000000, -Number.MAX_VALUE, 0/0, 2**53+2, Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-246262462*/count=14; tryItOut("\"use strict\"; g2 + '';");
/*fuzzSeed-246262462*/count=15; tryItOut("v1 = evalcx(\"/*RXUE*/new RegExp(\\\"((?=[^\\\\\\\\d\\\\\\\\cS\\\\\\\\cM-\\\\ubcdc\\\\u00f5-\\\\u00f0](\\\\\\\\w))+?(?=\\\\\\\\2)+^)\\\", \\\"gm\\\").exec( \\\"\\\" )\", g1);");
/*fuzzSeed-246262462*/count=16; tryItOut("let (e) { v1 = Object.prototype.isPrototypeOf.call(g0.m2, h0);\u000c }");
/*fuzzSeed-246262462*/count=17; tryItOut("\"use strict\"; for (var v of m2) { try { v2 = evalcx(\"this.o2 = Object.create(t2);\", g0); } catch(e0) { } Array.prototype.push.apply(a0, [o2.g0, o0]); }");
/*fuzzSeed-246262462*/count=18; tryItOut("/*vLoop*/for (let afzkwx = 0, (4277); afzkwx < 15; ++afzkwx) { var b = afzkwx; /*tLoop*/for (let z of /*MARR*/[objectEmulatingUndefined()]) { print(z); } } ");
/*fuzzSeed-246262462*/count=19; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (mathy1((((Math.abs((Math.max(( + (((Math.fround(y) ? Math.fround(Math.pow(x, Math.fround(x))) : x) >>> 0) + (( + x) >>> 0))), x) >>> 0)) >>> 0) << Math.fround(( - Math.fround(( + Math.sign(( + -Number.MIN_SAFE_INTEGER))))))) | 0), ((Math.imul(Math.min(Math.hypot((Math.fround(( - (( + Math.max(y, (((x >>> 0) ? y : (1/0 >>> 0)) | 0))) | 0))) | 0), (((x >>> 0) ? x : ( + ( ~ (y >>> 0)))) >>> 0)), Math.fround(( + 0x080000001))), ( + mathy4(( + ((x >>> 0) + mathy3(-0x100000000, 42))), ( + ( ~ ( ! x)))))) | 0) >>> 0)) | 0); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 0x0ffffffff, -1/0, -(2**53-2), Number.MIN_VALUE, 2**53, -(2**53+2), Number.MIN_SAFE_INTEGER, 0/0, -0, -0x100000001, -0x07fffffff, 0.000000000000001, 2**53+2, -Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 42, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), 0x07fffffff, -0x0ffffffff, 0x100000000, 0, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, 0x080000001, Math.PI, 2**53-2, 1, 1.7976931348623157e308, 0x080000000]); ");
/*fuzzSeed-246262462*/count=20; tryItOut("\"use strict\"; new RegExp(\"(?!(?!\\\\u0048)\\\\D\\\\1[^\\\\W\\\\s\\\\s]*?(?:(.))|(?=[^])(.*?(?!\\\\D)*))\", \"gi\");this;");
/*fuzzSeed-246262462*/count=21; tryItOut("testMathyFunction(mathy3, [-(2**53), 42, -0x080000000, -0x100000000, 0x080000000, -0x07fffffff, -1/0, 0.000000000000001, Math.PI, Number.MIN_SAFE_INTEGER, 1, 2**53, -Number.MIN_VALUE, -(2**53+2), -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -0x080000001, 1.7976931348623157e308, 0/0, 0, Number.MIN_VALUE, 0x0ffffffff, 0x080000001, 2**53-2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, -0]); ");
/*fuzzSeed-246262462*/count=22; tryItOut("testMathyFunction(mathy2, [0/0, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 1.7976931348623157e308, -1/0, 2**53, 1, -(2**53-2), -0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, 0, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, -(2**53), -Number.MIN_VALUE, 0x080000000, Math.PI, -0x100000001, 2**53-2, 0.000000000000001, 1/0, 0x100000000, 42, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=23; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    return +((i0));\n  }\n  return f; })(this, {ff: mathy3}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [2**53+2, Number.MIN_VALUE, Math.PI, 0x0ffffffff, 0x100000001, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, 1, 42, 0.000000000000001, 2**53-2, 0/0, 1.7976931348623157e308, -0x0ffffffff, -(2**53+2), -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, -0x080000000, -Number.MAX_VALUE, 0x080000000, -0x100000001, -(2**53-2), 1/0, -0x080000001, 2**53, -(2**53)]); ");
/*fuzzSeed-246262462*/count=24; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=25; tryItOut("\"use strict\"; f2.toString = f2;");
/*fuzzSeed-246262462*/count=26; tryItOut("v0 = new Number(m2);function x(x = new  \"\"  - undefined(false, this), c)\n /x/ v2 = m1;");
/*fuzzSeed-246262462*/count=27; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ! Math.fround(( + (( + mathy4((Math.atan2(( ! (y ? y : Math.fround(y))), ((( + Math.atan2(1/0, (mathy3(Math.fround(x), y) | 0))) > ( + y)) >>> 0)) >>> 0), x)) | 0)))); }); ");
/*fuzzSeed-246262462*/count=28; tryItOut("\"use strict\"; /*RXUB*/var r = /[^](?=(\\3)[^]\\b|(?=.)|.|\\dP{4294967295,}|\\*?|(?![^]{0,1})(?!\\d*?)+)/m; var s = \"\\na\"; print(uneval(s.match(r))); ");
/*fuzzSeed-246262462*/count=29; tryItOut("\"use strict\"; Array.prototype.splice.apply(a1, [-7, 10]);");
/*fuzzSeed-246262462*/count=30; tryItOut("a0 = (new (((void version(170))))(((function(y) { \"use strict\"; return ({e: /*UUV2*/(x.setUint16 = x.entries) }) })()), Object.defineProperty(c, \"18\", ({configurable:  '' , enumerable: Math.pow(11, (((-0x100000001 | 0) ^ (Math.abs((x >>> 0)) | 0)) | 0))}))) for each (setter in (void options('strict_mode'))) for (x of /*MARR*/[['z'],  /x/ , new Boolean(false),  /x/ ,  \"use strict\" , new Boolean(false),  /x/ , new Boolean(false),  /x/ ,  /x/ ,  \"use strict\" ,  \"use strict\" , new Number(1.5),  /x/ , new Boolean(false),  /x/ ,  \"use strict\" , ['z'],  /x/ ,  \"use strict\" , new Boolean(false),  \"use strict\" ,  \"use strict\" , new Number(1.5),  \"use strict\" , new Boolean(false),  \"use strict\" , new Boolean(false), new Number(1.5), ['z'],  /x/ , new Number(1.5), ['z'],  /x/ ,  \"use strict\" , ['z'],  \"use strict\" ,  /x/ , new Boolean(false),  \"use strict\" , new Number(1.5),  \"use strict\" , new Number(1.5),  /x/ , new Number(1.5),  \"use strict\" ,  /x/ , ['z'], ['z'],  \"use strict\" , new Boolean(false), ['z'],  /x/ ,  /x/ ,  /x/ , new Boolean(false),  /x/ , new Boolean(false), ['z'], new Number(1.5),  /x/ ,  /x/ , ['z'], new Number(1.5), new Boolean(false),  /x/ ,  /x/ ,  /x/ , new Number(1.5), ['z'],  \"use strict\" , new Boolean(false), ['z'],  \"use strict\" , new Boolean(false),  /x/ , new Number(1.5), new Boolean(false),  /x/ , new Number(1.5),  \"use strict\" ]) for each (x in /*FARR*/[...(function() { yield (delete x.x); } })(), /* no regression tests found */(x, new  '' ), ((function sum_indexing(ibhnko, fepace) { neuter(b1, \"same-data\");; return ibhnko.length == fepace ? 0 : ibhnko[fepace] + sum_indexing(ibhnko, fepace + 1); })(/*MARR*/[{}, false, new Boolean(true), {}, false, {}, {}, false, false, false, {}], 0)), undefined]) if (x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: eval, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { throw 3; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: String, }; })((new RegExp(\"(?![^\\\\x3b-\\u0093\\u0008-\\\\\\u259d\\\\w])*?(?=\\\\3)\", \"yim\").__proto__) = ++e), (4277))));");
/*fuzzSeed-246262462*/count=31; tryItOut("mathy1 = (function(x, y) { return Math.fround(( - Math.fround(( + ( - ( ! (y >>> 0))))))); }); testMathyFunction(mathy1, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5)]); ");
/*fuzzSeed-246262462*/count=32; tryItOut("g0.g2.i2.next();\nv1 = (o2.g1.t0 instanceof f2);\n");
/*fuzzSeed-246262462*/count=33; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot((Math.fround((Math.fround(Math.sqrt(Math.fround(((y >>> 0) <= Math.fround(-Number.MAX_SAFE_INTEGER))))) / Math.cos((( + (( ! (x | 0)) >>> 0)) >>> 0)))) >>> (Math.max((Math.exp((x >>> 0)) >>> 0), mathy2(Math.cosh(-(2**53)), Math.cbrt(y))) >>> Math.tanh(Math.asinh(x)))), mathy2(Math.max((timeout(1800) | 0), y), Math.log2(( + Math.fround((Math.fround((y <= x)) , Math.fround(0x080000001))))))); }); testMathyFunction(mathy3, [0x0ffffffff, 2**53-2, 1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, 0.000000000000001, 0x080000000, -0, 0x080000001, -(2**53-2), 1.7976931348623157e308, Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, -(2**53), 0x100000001, Number.MAX_VALUE, 0/0, 42, -0x080000001, 0, 2**53+2, -(2**53+2), -0x100000001, -0x100000000, 1]); ");
/*fuzzSeed-246262462*/count=34; tryItOut("\"use strict\"; const y = x;/*hhh*/function rslgqb(x, NaN, x, eval, c, y, x, 0, x, c, NaN, x, w, x, NaN, a, e, eval, x = /*vLoop*/for (let lzfqav = 0; lzfqav < 77; ++lzfqav) { const w = lzfqav; print(window); } , c, d, b, e, x = \"\\u4EB0\", d, x, w, d, x, x, x, b, x, x, x, x, y, x, x, NaN, x, x, eval, x, d, NaN, x, x = x, x = true, x = undefined, x, x, x, x, c, x, b, w, x, b, [,,z1], eval, x, eval = {}, y = x, c = /\\d.?(\\w\\W|(?!\\uDf79){1,4})?/gm, eval, x, a =  '' , this.x, d, x, NaN, \u3056, x = \"\\uA0F8\", x, x, z, c, \u3056 = new RegExp(\"((?!\\\\B){4,})|(?:\\\\W)[^#-\\u00c0\\\\S]{1,4}|\\u3072.|[^\\u0a17-\\u8198]|(?:\\\\s)+?|\\\\1(?:[^]|[^])?\", \"gim\"), eval, NaN = function(id) { return id }, x =  /x/ , b = [1], x, \u3056, x, NaN, NaN, eval, x){function f2(p0) \"\\u9FF0\"}rslgqb();");
/*fuzzSeed-246262462*/count=35; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + ( + ( + ((Math.imul(Math.fround(( + Math.fround(((x << (( ! ( + -1/0)) | 0)) | 0)))), (x ? -0x080000001 : x)) != (( + mathy4((mathy3(y, y) >>> 0), ( + Math.fround((x % Math.fround(( + Math.min(( + y), ( + -(2**53-2)))))))))) & Math.fround(Math.imul(y, ( - Math.fround(mathy4(Math.fround(x), Math.fround(y)))))))) >>> 0)))); }); ");
/*fuzzSeed-246262462*/count=36; tryItOut("t0[6];");
/*fuzzSeed-246262462*/count=37; tryItOut("for(let a = allocationMarker().yoyo(/*RXUE*//(?=(?!\\b[^]*?){274877906945}.|[^]+?)/gim.exec(\"\")) in NaN += eval) {/*tLoop*/for (let z of /*MARR*/[{}, true, (1/0), true, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), {}, {}, true, true, (1/0), true, true, (1/0), {}, {}, (1/0), (1/0), (1/0), true, {}, true, {}, {}, {}, {}, true, {}, (1/0), true, true]) { let (x, z, zqevse, w, ifpcuz, kvussm, a, e, \u3056) { print(this); } } }");
/*fuzzSeed-246262462*/count=38; tryItOut("\"use strict\"; v1 = a0.length;");
/*fuzzSeed-246262462*/count=39; tryItOut("\"use strict\"; \"use asm\"; with({d: this})print(x);");
/*fuzzSeed-246262462*/count=40; tryItOut("t0 = new Int8Array(t0);");
/*fuzzSeed-246262462*/count=41; tryItOut("\"use strict\"; for (var v of f0) { v0 = (this.v1 instanceof this.o1.m0); }");
/*fuzzSeed-246262462*/count=42; tryItOut("h1.defineProperty = (function() { try { h2.defineProperty = f0; } catch(e0) { } try { v0 = t0.length; } catch(e1) { } try { o1.m1.set(m0, g2.o0.t2); } catch(e2) { } for (var v of b0) { try { e1.toString = (function mcc_() { var ivokwv = 0; return function() { ++ivokwv; f0(false);};})(); } catch(e0) { } x = m0; } throw o2; });");
/*fuzzSeed-246262462*/count=43; tryItOut("\"use strict\"; v0 = t2.byteOffset;");
/*fuzzSeed-246262462*/count=44; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - ( + ( ! Math.pow(( ! mathy2(Math.atan2(x, x), 0x07fffffff)), (( + ((y , (Math.atan2(-1/0, x) | 0)) | 0)) | 0))))); }); testMathyFunction(mathy4, [1/0, -0x080000000, -0, 0x080000001, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff, -0x100000000, 2**53, -Number.MAX_VALUE, 42, Number.MIN_VALUE, -(2**53-2), -(2**53+2), 0, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, 2**53-2, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -0x080000001, -0x0ffffffff, 0/0, 0x080000000, 0.000000000000001, -1/0, 2**53+2, Math.PI, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-246262462*/count=45; tryItOut("\"use strict\"; var fprqws = new ArrayBuffer(8); var fprqws_0 = new Int16Array(fprqws); fprqws_0[0] = 24; /*RXUB*/var r = r1; var s = \"\\nQ\\n\\n\\n\\n\\nQ\\n\\n\\n\\n\\nQ\\n\\n\\n\\n\\nQ\\n\\n\\n\\n\\nQ\\n\\n\\n\\n\\nQ\\n\\n\\n\\n\\nQ\\n\\n\\n\\n\"; print(s.search(r)); o1 = m0.get(m2);m0.set(e0,  \"\" );-15;print(fprqws_0[0]);return fprqws_0[7];i1.send(o2.p1);\"\\u532A\";s0 += 'x';( /x/ );function fprqws_0[7](x, ...d)\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    (Int32ArrayView[0]) = (((i0) ? ((((i2)-(i2))|0) >= (((((((0xac09705))>>>((0x93c96a21)))))-(1))|0)) : ((((((0x70bafacb)) << ((-0x8000000))) / (((0xd717afa8)) | ((0xf91ffa68)))) << ((i1)-(0xffffffff))))));\n    switch ((0xd77d877)) {\n      case 1:\n        (Int32ArrayView[4096]) = ((i2));\n      case 1:\n        {\n          i0 = (i2);\n        }\n        break;\n      case -3:\n        {\n          i0 = ((+(0.0/0.0)) > (1.015625));\n        }\n      case -2:\n        i2 = (i0);\n        break;\n      case 1:\n        i0 = (i0);\n      default:\n        i1 = ((4.722366482869645e+21) <= (-131073.0));\n    }\n    {\n      i2 = (i1);\n    }\n    i0 = ((~~(-147573952589676410000.0)));\n    return (((i1)+((((i0)+((-6.044629098073146e+23) >= (+atan2(((1.0)), ((-70368744177663.0)))))) >> ((i1)-((0xffffffff) <= (((-0x8000000))>>>((0xfc0e71dc))))+(i0))))))|0;\n  }\n  return f;for (var p in g0.f1) { try { /*RXUB*/var r = r2; var s = s2; print(s.search(r));  } catch(e0) { } g1.h0.fix = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\nw    return (((0x7988ad20)-((((-0x6910ab2)+(0xbe20b0c6))|0) > (0x12fec1b5))))|0;\n  }\n  return f; })(this, {ff: Object.seal}, new SharedArrayBuffer(4096)); }");
/*fuzzSeed-246262462*/count=46; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul(Math.atan(Math.asinh(((x !== y) | 0))), (Math.max((( ! (y & Math.fround((mathy0(Math.fround((y | 0)), (( ~ x) >>> 0)) >>> 0)))) | 0), Math.fround(Math.pow((( ~ y) * (Math.atan2(y, (y | 0)) ? Math.PI : Math.expm1(Math.fround(x)))), (Math.log10(y) ^ (Math.hypot(-Number.MIN_SAFE_INTEGER, ((Math.imul((2**53-2 | 0), (y | 0)) | 0) >>> 0)) >>> 0))))) | 0)); }); ");
/*fuzzSeed-246262462*/count=47; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((Math.fround((( ~ Math.log(0x0ffffffff)) | 0)) | 0), ( + (((((mathy0(y, Math.fround((mathy0((x >>> 0), (x >>> 0)) | 0))) >>> 0) + (( + ( - ( + y))) >>> 0)) >>> 0) / Math.fround(( + (( + x) <= x)))) | 0))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, 0x080000001, 0.000000000000001, 42, -Number.MAX_VALUE, 2**53+2, 1/0, 0, 0x0ffffffff, 0x100000001, -0x080000001, -0x100000000, Math.PI, -0, -0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 0x100000000, -0x0ffffffff, 1]); ");
/*fuzzSeed-246262462*/count=48; tryItOut("\"use strict\"; for(let x in []);with({}) with({}) \u3056.name;");
/*fuzzSeed-246262462*/count=49; tryItOut("\"use strict\"; \"use asm\"; s0 += 'x';");
/*fuzzSeed-246262462*/count=50; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.hypot(((mathy0((x | 0), (mathy2((y >>> 0), y) | 0)) | 0) + Math.fround(Math.imul(Math.fround(Math.fround(( - Math.tan(x)))), x))), ((( + (mathy0((y >>> 0), ((Math.sinh((( ! ( + Math.pow(Math.fround(y), ( + y)))) | 0)) | 0) >>> 0)) >>> 0)) < y) % Math.acos(y))); }); testMathyFunction(mathy4, [1, 0/0, -0x080000001, -(2**53), 2**53+2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 1/0, 0, 0.000000000000001, -0x07fffffff, -0x100000001, 0x100000000, 0x100000001, 0x080000001, -(2**53-2), -Number.MIN_VALUE, 42, -(2**53+2), -0x100000000, 0x080000000, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, -0, 0x07fffffff, Math.PI]); ");
/*fuzzSeed-246262462*/count=51; tryItOut("let (e) { b2.toString = WeakMap.prototype.has.bind(this.t0); }");
/*fuzzSeed-246262462*/count=52; tryItOut("Array.prototype.forEach.apply(a1, [(function() { for (var j=0;j<82;++j) { f0(j%5==1); } }), new RegExp(\"(?!(?=\\\\1)|(.|\\u27c8.{2}){0,})\", \"gyim\"), this.m0]);a2 + '';function d(e, setter, x, x, x, x, b, c, /(?:(.\\b)[^\\x5f\\w\\S\\xE1]|$.{1}){3,}|\\cN+/gyim, e, \u3056, x, a, NaN, d = window, b, x = this, x, b, \u3056, z = x, y, c, set, \u3056 =  '' , x, \u3056, get, x, x =  '' , x, d, x, w = window, z, y, b, x, x, x, NaN, b, x, window, x = undefined, x, x, x = window, x, x, x = window, a, x, z, \u3056, eval, b, x, window, eval, x, eval, x, x, z =  '' , window, c, b, d, x, eval, c, x, x, x, x = 4., NaN, eval, w, x, y, x, x, eval, y =  '' , x, NaN, x, eval = false, y, c, x)x.yoyo(  = Proxy.createFunction(({/*TOODEEP*/})([,]), Uint32Array))/*RXUB*/var r = new RegExp(\"(?!\\\\b)\", \"gm\"); var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=53; tryItOut("/*infloop*/M: for  each(var ((new RegExp(\"(?!(([^]{0,3})))\", \"gyi\").unwatch(8)))(Math.imul(true, -4)) in false <<=  '' \u000c ? -0 : new ((...x) =>  { return [,,z1] } ).call()((Math.tan(21)), x)) {a1[1] = x; }");
/*fuzzSeed-246262462*/count=54; tryItOut("\"use strict\"; throw StopIteration;");
/*fuzzSeed-246262462*/count=55; tryItOut("\"use strict\"; v2 = evaluate(\"timeout(1800)\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: Math.pow(/(?!$)/gi, (yield  \"\" )), noScriptRval: window, sourceIsLazy: (x % 24 == 23), catchTermination: (x % 62 == 52) }));");
/*fuzzSeed-246262462*/count=56; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return (((i3)+(0xfd17944b)))|0;\n    return (((((((((0xfbfade3e))>>>((0xffffffff))) < (((0x494a6bf5))>>>((0x8981b196))))*-0xfffff) << (((0x7ce5c323) <= (((-0x8000000))>>>((0x4897ed2b)))))) > (-0x37a793a))-(i3)-(((((((-1048577.0)) * ((257.0)))) % ((-549755813888.0))) + (Infinity)) >= (((+(1.0/0.0))) - ((-562949953421312.0))))))|0;\n  }\n  return f; })(this, {ff: function(y) { g0 + o2.p1; }}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-246262462*/count=57; tryItOut("testMathyFunction(mathy5, [2**53+2, 0.000000000000001, Number.MAX_VALUE, 1/0, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 0x100000001, -0x07fffffff, 0x0ffffffff, -0, -0x0ffffffff, 2**53-2, 0x07fffffff, 2**53, -1/0, -(2**53-2), Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 42, 1.7976931348623157e308, -0x100000001, 0x100000000, 0/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0, 0x080000000, -Number.MAX_VALUE, 1, -0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=58; tryItOut("a1.push(t1, s1);");
/*fuzzSeed-246262462*/count=59; tryItOut("h1.getPropertyDescriptor = f2;");
/*fuzzSeed-246262462*/count=60; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x080000001, 0, -Number.MIN_SAFE_INTEGER, 0x080000000, -0, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, 1/0, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000000, -(2**53), 0x100000001, -(2**53+2), Math.PI, 1.7976931348623157e308, -1/0, -0x0ffffffff, 1, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, 42, -(2**53-2), 2**53+2, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, -Number.MAX_VALUE, 0x07fffffff, 0/0, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=61; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    return (((imul((!(/*FFI*/ff(((~~(+(0.0/0.0)))))|0)), (i4))|0) / (~~(+((4294967297.0))))))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [1/0, -0x07fffffff, -(2**53), -(2**53+2), -0x080000001, -0x100000000, Math.PI, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, -0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -(2**53-2), 0/0, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 0x080000001, 1, 2**53-2, 0x080000000, 42, Number.MAX_VALUE, 0x100000000, -1/0, -0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=62; tryItOut("mathy4 = (function(x, y) { return Math.max((Math.abs((Math.asin(y) !== Math.sqrt((x != 0x100000000)))) | 0), ((( + (x ? (y >>> 0) : ( + mathy1(( + (( + (2**53+2 | 0)) >>> 0)), ( + (y * (x | 0))))))) ? ((mathy2((( ~ Math.imul(Number.MAX_SAFE_INTEGER, x)) / ( + 2**53-2)), x) ? ((( + (( + Math.atanh(( + (y > 0x100000000)))) >>> 0)) >>> 0) >>> 0) : (x >>> 0)) >>> 0) : ((((Math.cos((y >>> 0)) >>> 0) && (y >>> 0)) >>> 0) || Math.pow(Math.hypot(x, x), Math.log10(( + -0))))) >>> 0)); }); testMathyFunction(mathy4, [0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x100000001, 0.000000000000001, Number.MAX_VALUE, 2**53, 0x07fffffff, 0, 1/0, 0x080000001, -0, -1/0, -0x0ffffffff, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, -0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53-2, -Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, Math.PI, -0x100000000]); ");
/*fuzzSeed-246262462*/count=63; tryItOut("mathy4 = (function(x, y) { return mathy2(( + Math.acosh(((Math.log1p(Math.sinh(Math.max(( + mathy0(x, y)), y))) | 0) | 0))), (Math.asin(Math.fround((Math.fround(Math.fround(Math.pow(x, x))) << Math.fround(Math.exp(y))))) / Math.tanh(( + (( + ( + y)) | 0))))); }); testMathyFunction(mathy4, [-(2**53), -0x0ffffffff, 1.7976931348623157e308, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, -(2**53-2), -0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, -1/0, -0, Number.MAX_SAFE_INTEGER, 2**53, 1, 0x0ffffffff, 0x080000000, 0x100000000, -(2**53+2), 0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, Math.PI, -0x080000001, -Number.MAX_VALUE, 0x07fffffff, 42, 0, 1/0]); ");
/*fuzzSeed-246262462*/count=64; tryItOut("/*oLoop*/for (rquumq = 0; rquumq < 0; ++rquumq) { ((function ([y]) { })()); } ");
/*fuzzSeed-246262462*/count=65; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=66; tryItOut("t1.set(t0, 13);");
/*fuzzSeed-246262462*/count=67; tryItOut("Array.prototype.shift.call(a1);");
/*fuzzSeed-246262462*/count=68; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=69; tryItOut("s2 += s1;");
/*fuzzSeed-246262462*/count=70; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.asin(Math.fround((( - ( ~ ((( ! Math.fround(-0x080000001)) | 0) >>> 0))) | 0))); }); testMathyFunction(mathy3, [2**53-2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 0x100000000, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), -0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, -0x100000000, 2**53+2, 2**53, -0x0ffffffff, Number.MIN_VALUE, 0/0, 0, -1/0, Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, -(2**53-2), 1, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, 0x080000001, -Number.MAX_VALUE, -0x07fffffff, 42, -(2**53)]); ");
/*fuzzSeed-246262462*/count=71; tryItOut("a2[({valueOf: function() { o2.s0 = new String;return 5; }})] = g1.o0;for (var p in e2) { try { i2.send(this.a1); } catch(e0) { } a2 = Array.prototype.concat.apply(g0.a0, [a1, t0]); }");
/*fuzzSeed-246262462*/count=72; tryItOut("/*tLoop*/for (let a of /*MARR*/[new String('q'), new String('q'), new String('q'), ['z'], new String('q'), new String('q'), ['z'], new String('q'), ['z'], new String('q'), ['z'], new String('q'), ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], new String('q'), new String('q'), ['z'], new String('q'), new String('q'), new String('q'), ['z'], new String('q'), ['z'], new String('q'), new String('q'), new String('q'), new String('q'), ['z'], new String('q'), ['z'], new String('q'), ['z'], ['z'], ['z'], new String('q'), ['z'], new String('q'), new String('q'), new String('q'), ['z'], ['z'], new String('q'), new String('q'), ['z'], new String('q'), ['z'], new String('q'), ['z'], ['z'], ['z'], new String('q'), new String('q'), ['z'], new String('q'), ['z'], new String('q'), ['z'], new String('q'), new String('q'), ['z'], new String('q'), new String('q'), ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], new String('q'), ['z'], ['z'], new String('q'), ['z'], new String('q'), new String('q'), new String('q'), ['z'], ['z'], ['z'], ['z'], new String('q'), ['z'], ['z'], ['z'], ['z'], new String('q'), new String('q'), new String('q'), ['z'], new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), ['z'], new String('q'), new String('q'), ['z'], new String('q'), ['z'], new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), ['z'], new String('q'), ['z'], ['z'], ['z'], new String('q'), ['z'], new String('q'), ['z'], new String('q'), ['z'], ['z'], ['z'], new String('q'), ['z'], ['z'], ['z'], new String('q'), new String('q'), ['z'], new String('q'), ['z'], new String('q'), ['z'], new String('q'), new String('q'), ['z']]) { let ebfvlt, x, a = 24, dklumi, thogig, jgzalq, vsoanq, x, uasnck;Array.prototype.sort.call(a1, (function(j) { f1(j); }), p0, b2); }");
/*fuzzSeed-246262462*/count=73; tryItOut("m0.get(i1);");
/*fuzzSeed-246262462*/count=74; tryItOut("/*tLoop*/for (let y of /*MARR*/[Infinity, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined()]) { Array.prototype.sort.call(a2, (function() { try { m0.has(s2); } catch(e0) { } try { v0 = g2.t2[\"getYear\"]; } catch(e1) { } v2 = NaN; return t0; })); }");
/*fuzzSeed-246262462*/count=75; tryItOut("var yaoppl = new ArrayBuffer(4); var yaoppl_0 = new Uint32Array(yaoppl); yaoppl_0[0] = -17; var yaoppl_1 = new Float32Array(yaoppl); yaoppl_1[0] = 4; g2.v2 = a1.length;print(this);Array.prototype.forEach.call(a0);");
/*fuzzSeed-246262462*/count=76; tryItOut("for (var v of g2.s2) { try { e2.add(g1.s0); } catch(e0) { } e2.add(this.g2.i1); }");
/*fuzzSeed-246262462*/count=77; tryItOut("v2 = this.g0.runOffThreadScript();");
/*fuzzSeed-246262462*/count=78; tryItOut("\"use strict\"; m2.has(/(?=\\B)/gym);");
/*fuzzSeed-246262462*/count=79; tryItOut("x;");
/*fuzzSeed-246262462*/count=80; tryItOut("\"use strict\"; /*RXUB*/var r = o0.r0; var s = s1; print(s.search(r)); ");
/*fuzzSeed-246262462*/count=81; tryItOut("Array.prototype.reverse.call(a1, x);");
/*fuzzSeed-246262462*/count=82; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ( '' );\n    d1 = (d1);\n    d1 = (1125899906842623.0);\n    (Float32ArrayView[((i0)*-0xd371d) >> 2]) = ((+(1.0/0.0)));\n    i0 = ((+/*FFI*/ff((((-0x6ba91*(/*FFI*/ff(((+(((((-4194304.0)) % ((1073741823.0))) + (d1))))), ((0x4dc5a67)), ((+(0.0/0.0))), ((d1)), ((((0x89a78730)) >> ((0xffffffff)))), ((-576460752303423500.0)), ((36028797018963970.0)))|0)) & ((Uint32ArrayView[4096])))), ((d1)), ((((((d1)) / ((-2.4178516392292583e+24)))) * ((((16777217.0)) % ((9223372036854776000.0)))))), ((+(-1.0/0.0))), ((abs((~~(-((+abs(((((-70368744177665.0)) * ((8388609.0))))))))))|0)), ((((+(1.0/0.0))) - ((((1.888946593147858e+22)) * ((-1.0078125)))))))));\n    i0 = (0x6d93af9f);\n    return ((0xe4ba3*(/*FFI*/ff(((abs(((((d1) == (+((d1))))-(0x2766c61f)) << ((((Math.clz32((( - Math.fround(((Math.abs((x >>> 0)) >>> 0) ? Math.fround(-0x0ffffffff) : Math.fround(x)))) | 0)) - x)) & ((Uint16ArrayView[0]))) % (((0x47043daa)+(0x4cc70c45)) & ((0x7fffffff) / (0x49ee6608))))))|0)), ((((0xb40074d)) ^ ((0xfbdd28c9)))), ((262143.0)), ((((-0x8000000)) << ((!(i0))))), (((((0x64f0ae3d))*0x64836) & ((/*FFI*/ff(((0.001953125)), ((-2.4178516392292583e+24)), ((-144115188075855870.0)))|0)*0x83443))), ((+(-1.0/0.0))), ((~~(d1))))|0)))|0;\n  }\n  return f; })(this, {ff: String.prototype.toLocaleUpperCase}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000000, 0.000000000000001, -0x080000001, -Number.MAX_VALUE, 1/0, 0x0ffffffff, -0x100000001, 42, Number.MAX_VALUE, -0, 2**53-2, -(2**53), 0/0, 2**53, -0x080000000, -0x07fffffff, Number.MIN_VALUE, 0, -(2**53-2), -0x100000000, 1.7976931348623157e308, -1/0, 0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x0ffffffff, 2**53+2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-246262462*/count=83; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x0ffffffff, Math.PI, -0x080000001, -0, 0x080000001, Number.MIN_VALUE, -1/0, 0x100000001, -Number.MAX_VALUE, 1/0, 1.7976931348623157e308, -(2**53-2), -0x100000000, 0x0ffffffff, 2**53+2, 0x100000000, 0x080000000, -(2**53), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 0, -0x100000001, 0.000000000000001, -(2**53+2), -0x07fffffff, -0x080000000, 0/0, 1, 2**53, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=84; tryItOut("g2 + '';");
/*fuzzSeed-246262462*/count=85; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( +  /x/g (NaN)); }); testMathyFunction(mathy4, /*MARR*/[ \"\" ,  \"\" , z, z,  \"\" , z, z, z, true, (void options('strict_mode')),  \"\" ,  \"\" , true,  \"\" , z, (void options('strict_mode')), (void options('strict_mode')), true, z, true, (void options('strict_mode')), z, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, (void options('strict_mode')), true,  \"\" ,  \"\" , true, z, true, z, (void options('strict_mode')), true, true,  \"\" , true, true,  \"\" , z, z, (void options('strict_mode')), (void options('strict_mode')), (void options('strict_mode')),  \"\" ,  \"\" , (void options('strict_mode')), (void options('strict_mode')), true, true, (void options('strict_mode')), z, (void options('strict_mode')), (void options('strict_mode')), (void options('strict_mode')),  \"\" , z, z, true, (void options('strict_mode')), z, z, true, z, true, z,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , z, z, z, (void options('strict_mode')), true, (void options('strict_mode')), z,  \"\" ]); ");
/*fuzzSeed-246262462*/count=86; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[false,  \"\" , new Number(1.5), new String(''), false,  \"\" ,  \"\" , false, false, new Number(1.5),  \"\" , false,  \"\" ,  \"\" , new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new Number(1.5), new String(''),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new Number(1.5),  \"\" , new String(''),  \"\" ,  \"\" , false, new String('')]) { {} }");
/*fuzzSeed-246262462*/count=87; tryItOut("s2 += 'x';");
/*fuzzSeed-246262462*/count=88; tryItOut("/*MXX3*/g1.o1.g2.Uint16Array.prototype = this.g0.Uint16Array.prototype;");
/*fuzzSeed-246262462*/count=89; tryItOut("var ermdvl = new ArrayBuffer(12); var ermdvl_0 = new Uint8Array(ermdvl); print(ermdvl_0[0]); ermdvl_0[0] = -6; var ermdvl_1 = new Int32Array(ermdvl); print(ermdvl_1[0]); var ermdvl_2 = new Int8Array(ermdvl); ermdvl_2[0] = -28; var ermdvl_3 = new Uint8ClampedArray(ermdvl); print(ermdvl_3[0]); ermdvl_3[0] = -0; var ermdvl_4 = new Int8Array(ermdvl); g2.g1 = fillShellSandbox(evalcx('lazy'));v1 = Array.prototype.some.apply(a1, [(function() { for (var j=0;j<16;++j) { f2(j%2==0); } })]);function eval(e, x)\"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        (Float32ArrayView[((i1)-(0x4fb74d18)+(0xccb88534)) >> 2]) = ((((NaN)) % ((x))));\n      }\n    }\n    {\n      return +((-144115188075855870.0));\n    }\n    i1 = (!(((((intern( '' )))+((0x8eccf405) <= (0x28906911)))>>>((!(1))))));\n;    return +((+(((((0x7dca614f)-(i1))>>>((-0x149b17)+(i1))) % (((imul((0x171df9d3), (-0x8000000))|0) / (((0x914934ae))|0))>>>((0xad0a08da))))>>>((i1)+(i1)-((0xff1ab28f) ? ((-1.2089258196146292e+24) >= (3.094850098213451e+26)) : (!(0xfe703742)))))));\n  }\n  return f;\u3056;function c(...e) { print(x); } t1.set(a0, 9);");
/*fuzzSeed-246262462*/count=90; tryItOut("a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-246262462*/count=91; tryItOut("this.a1.reverse(t0, f2, i1);");
/*fuzzSeed-246262462*/count=92; tryItOut("for (var p in t0) { try { for (var p in m1) { try { Object.defineProperty(this, \"a2\", { configurable: true, enumerable: ([]),  get: function() {  return new Function; } }); } catch(e0) { } try { g0.t2 = t2.subarray(13, 5); } catch(e1) { } Array.prototype.forEach.apply(a1, [(function() { try { o2.o2.v2 = g2.eval(\"v0 = o2.o1.r1.multiline;\"); } catch(e0) { } try { this.v1 = (s2 instanceof f1); } catch(e1) { } try { m2.has(i2); } catch(e2) { } v1 = (h2 instanceof o2.s1); return s1; }), this.s2]); } } catch(e0) { } try { v2 = r0.global; } catch(e1) { } try { g2.offThreadCompileScript(\"/* no regression tests found */\"); } catch(e2) { } selectforgc(o1); }");
/*fuzzSeed-246262462*/count=93; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( + Math.fround(mathy0((Math.atan2(Math.max(((((( ~ y) >>> 0) >>> 0) && 0x100000000) >>> 0), y), (Math.imul(0x080000000, (( + mathy1(( + x), ( + x))) >>> 0)) >>> 0)) | 0), (Math.min((( + ( + ( + (Math.min(y, y) | 0)))) >>> 0), (Math.exp((y | 0)) | 0)) | 0)))) >>> 0); }); testMathyFunction(mathy3, [0/0, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, 0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0, -(2**53-2), 2**53+2, 1, -0x07fffffff, -1/0, 2**53-2, -0x080000001, -0x100000001, -(2**53+2), Number.MIN_VALUE, 2**53, 1/0, 0x07fffffff, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, 42, -0x080000000, Math.PI, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=94; tryItOut("\"use strict\"; window = (4277).eval(\"/* no regression tests found */\"), cjnzkt, qduevj, x = [] = {eval};e1.delete(g2);let y =  /x/g ;");
/*fuzzSeed-246262462*/count=95; tryItOut("v2 = (e0 instanceof o2);");
/*fuzzSeed-246262462*/count=96; tryItOut("(\"\\u18BB\");\n/*RXUB*/var r = /([^])((?=(.|\\d)|(?:((\\W)))|\\b))\\B/gm; var s = \"\\n\"; print(r.exec(s)); \n");
/*fuzzSeed-246262462*/count=97; tryItOut("mathy3 = (function(x, y) { return mathy2(((Math.fround(( ~ ((x || ( + mathy1(Math.imul(Number.MAX_SAFE_INTEGER, y), x))) | 0))) || (Math.atan2((x >> ( + (Math.hypot(42, x) + x))), mathy2(y, (Math.sin((y >>> 0)) >>> 0))) | 0)) | 0), ( + (( + Math.pow((mathy0(((mathy0((x >>> 0), Math.pow(-0x100000000, ((( + (x | 0)) | 0) >>> 0))) >>> 0) >>> 0), Math.pow((( + (( + y) ? ( + y) : ( + y))) >>> 0), ( + Math.atanh(y)))) >>> 0), ( + ( ! x)))) ^ ( + Math.max(Math.fround(mathy2(y, y)), Math.fround((Math.fround(( + mathy1(Math.fround(y), ( + -(2**53+2))))) == Math.fround(( ~ (( + ( - (y >>> 0))) | 0)))))))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 1, 0x100000001, 1/0, -0x07fffffff, -(2**53), 1.7976931348623157e308, 2**53+2, -Number.MAX_VALUE, -1/0, Number.MAX_VALUE, -0, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 42, -0x080000000, 0, Math.PI, 0x100000000, -0x0ffffffff, 0x080000001, 2**53-2, 0x080000000, 0.000000000000001, 2**53, -(2**53-2), -0x080000001]); ");
/*fuzzSeed-246262462*/count=98; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + (Math.min((( - (( ! y) | 0)) | 0), Math.max(( + Math.sign(mathy0(x, Math.pow(y, x)))), ( + (Math.round((0x100000001 >>> 0)) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [1/0, 0/0, -0x0ffffffff, 1, -0x100000000, 0x100000000, Math.PI, 0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, -(2**53-2), -Number.MIN_VALUE, 2**53, -0, 0x080000001, 2**53-2, -(2**53+2), Number.MAX_VALUE, 0x0ffffffff, 0x080000000, 42, -0x080000000, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, -0x080000001]); ");
/*fuzzSeed-246262462*/count=99; tryItOut("mathy2 = (function(x, y) { return (Math.imul((Math.min((Math.log((Math.atan2(y, x) | 0)) | 0), (( + (( + ( - y)) > ( + (( ~ (mathy1(( + Math.pow(Math.fround(-Number.MIN_SAFE_INTEGER), -0)), x) >>> 0)) >>> 0)))) | 0)) | 0), (Math.cos(( + ( + Math.log(( + ( ! (Math.fround(Math.pow(Math.fround(Math.fround(mathy0(( + x), -Number.MAX_SAFE_INTEGER))), ( + y))) | 0))))))) | 0)) | 0); }); testMathyFunction(mathy2, [Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, -0x080000000, 2**53-2, 1/0, 42, 1.7976931348623157e308, 0x080000001, -0, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, 0, -(2**53-2), 0/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, 1, -0x080000001, 2**53+2, 0x0ffffffff, -1/0, -0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, 2**53, Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=100; tryItOut("mathy3 = (function(x, y) { return ( + mathy1(Math.pow(( + (Math.fround(Math.min(x, (Math.max((( - ( + x)) | 0), (-0x0ffffffff | 0)) >>> 0))) ? ( + -0x080000001) : (mathy0((( ! (Math.fround(( ~ (y | 0))) >>> 0)) | 0), (((x | 0) == (Math.fround(Math.imul(Math.fround(x), Math.fround(( + (( + y) / ( + x)))))) | 0)) | 0)) | 0))), (mathy2(1, ((Math.sin(y) > (Math.max(x, (Number.MAX_VALUE - -1/0)) | 0)) | 0)) | 0)), (( ~ ((( ~ ((Math.max(x, y) !== x) >>> 0)) >>> 0) % ( - (1.7976931348623157e308 ? (y | 0) : y)))) | 0))); }); testMathyFunction(mathy3, [2**53, 0.000000000000001, 0x100000000, 1.7976931348623157e308, 42, -(2**53-2), 2**53-2, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, -1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, 0x080000001, 0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, 0x080000000, Number.MIN_VALUE, 0/0, -0x100000001, -0x0ffffffff, -0, Math.PI, -(2**53), 0, 0x0ffffffff, -Number.MIN_VALUE, -(2**53+2)]); ");
/*fuzzSeed-246262462*/count=101; tryItOut("v2 = (g0.g1 instanceof p2);");
/*fuzzSeed-246262462*/count=102; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.pow(( + Math.min((Math.fround((Math.fround(( + Math.hypot(( + y), ( + y)))) == Math.fround(y))) >>> 0), ( ~ Math.log1p(y)))), ( + Math.pow(( ! y), (Math.atan2(((( ~ ( + y)) | 0) | 0), (y >>> 0)) | 0)))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -1/0, 2**53, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), 0x100000001, -0x080000000, -(2**53), 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 1, -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, 0x100000000, -0x080000001, -0, 42, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, -0x100000000, 1/0, 0, -(2**53-2), 0x07fffffff, Math.PI, -Number.MIN_VALUE, 0/0, 0x0ffffffff, 2**53-2, Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=103; tryItOut("for (var p in s2) { m1.delete(g1); }");
/*fuzzSeed-246262462*/count=104; tryItOut("\"use strict\"; /*RXUB*/var r = ((function a_indexing(zjzgpj, klgiev) { ; if (zjzgpj.length == klgiev) { ; return x; } var jtwben = zjzgpj[klgiev]; var pgzybo = a_indexing(zjzgpj, klgiev + 1); yield (4277); })(/*MARR*/[(0/0), (0/0), (1/0), (1/0)], 0)); var s = \"\\na\\na\"; print(s.replace(r, [])); ");
/*fuzzSeed-246262462*/count=105; tryItOut("testMathyFunction(mathy3, [-(2**53-2), 1, 0x100000000, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 1/0, 0x07fffffff, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, 0, 0x080000000, -(2**53+2), 2**53+2, 0.000000000000001, 0x080000001, -0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, 0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, -0, -(2**53), -0x100000000, 0/0, 2**53, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-246262462*/count=106; tryItOut("a0.length = 10;");
/*fuzzSeed-246262462*/count=107; tryItOut("\"use strict\"; /*RXUB*/var r = /.|(.)+?/gm; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=108; tryItOut("\"use strict\"; /*oLoop*/for (let kzhgez = 0, x = (4277); kzhgez < 14; ++kzhgez) { a1.splice(NaN, v1, i0, v0, a1); } ");
/*fuzzSeed-246262462*/count=109; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.fround((Math.min(Math.fround(x), (Math.atan2(-Number.MAX_VALUE, (( - (Math.sinh((( + Math.pow(( + x), ( + 2**53-2))) | 0)) | 0)) | 0)) | 0)) | 0))); }); testMathyFunction(mathy4, /*MARR*/[new Boolean(true), false, new Boolean(true), x, x, new Boolean(true), false, false, false, false, false, new Boolean(true), new Boolean(true), new Boolean(true), x, x, x, false, x, new Boolean(true), x, x, new Boolean(true), x, x, x, x, false]); ");
/*fuzzSeed-246262462*/count=110; tryItOut("/*hhh*/function onverm(x){var dzsdqh = new SharedArrayBuffer(8); var dzsdqh_0 = new Uint8ClampedArray(dzsdqh); dzsdqh_0[0] = -1; var dzsdqh_1 = new Uint8Array(dzsdqh); dzsdqh_1[0] = 29; var dzsdqh_2 = new Uint32Array(dzsdqh); dzsdqh_2[0] = -27; var dzsdqh_3 = new Uint32Array(dzsdqh); dzsdqh_3[0] = -25; v1 = evalcx(\"/* no regression tests found */\", g1);}onverm();");
/*fuzzSeed-246262462*/count=111; tryItOut("/*MXX1*/o0 = g0.g1.WeakMap.prototype.has;");
/*fuzzSeed-246262462*/count=112; tryItOut("o2.o0.o1 + '';");
/*fuzzSeed-246262462*/count=113; tryItOut("/*hhh*/function kaumme(x, x, {x: [[], x, , ], z: x.[1,,], d, x: this.z, c: {x, d: {x: {x}}, window: [], x: [NaN, x, [[], , , [{ }, x, (c)]]]}, b: {}, z: eval}, x, b, x, x = ([] = []), {}, [], x, w, NaN, z, b, x, d, y, NaN, x, x = function(id) { return id }, w = \"\\u4695\", w = ({a1:1}), x, y, b, eval = x, w = this, x, w, \u3056 = new RegExp(\"(.|(?:([^\\\\x8a\\\\cX\\\\d\\\\W])?)([^])\\u2eb7?)\", \"gm\"), x, x, e =  '' , this, c, w, w, x, x, x = x, \u3056){switch(this.c = w) { default: break;  }}/*iii*//*RXUB*/var r = new RegExp(\"(?:(?=\\\\D))\\\\S?\", \"m\"); var s = \"0\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-246262462*/count=114; tryItOut("\"use asm\"; /*RXUB*/var r = /(?=(?=\\{4,})+)/yi; var s = \"hhhhhh\\\\hhhhhh\\\\\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=115; tryItOut("for (var v of s2) { try { a1.sort((function() { try { (void schedulegc(g0)); } catch(e0) { } try { /*RXUB*/var r = r0; var s = s1; print(uneval(r.exec(s))); print(r.lastIndex);  } catch(e1) { } try { a1.unshift(); } catch(e2) { } for (var p in g0.i2) { try { selectforgc(o2); } catch(e0) { } e1.delete(g1.f0); } return t2; }), o1); } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(g0, m1); }");
/*fuzzSeed-246262462*/count=116; tryItOut("Array.prototype.splice.call(g2.a0, NaN, 5, g0, f2, (String.prototype.split( /x/  , /(((?!$?))|\\s|(\\W)|(?:\\w\\cJ)(?:.)?)*/g.throw(((function fibonacci(feeoed) { ; if (feeoed <= 1) { print(x);; return 1; } ; return fibonacci(feeoed - 1) + fibonacci(feeoed - 2);  })(3))))), m1, o1);");
/*fuzzSeed-246262462*/count=117; tryItOut("\"use strict\"; i2 + f1;");
/*fuzzSeed-246262462*/count=118; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + (( + (( ! (Math.acos(((Math.fround(y) == ( ! 0x080000000)) >>> 0)) >>> 0)) / ( + true))) <= ( ~ (Math.imul(( + x), ((( + Math.hypot(( + 42), ( + Math.fround((Math.fround(2**53+2) ? Math.fround(-0x080000001) : (0x100000001 | 0)))))) !== (Math.atan2((Math.min(x, ( + ( ! y))) | 0), 1) | 0)) | 0)) | 0)))); }); testMathyFunction(mathy2, /*MARR*/[(1/0), x, false, false, false, x, false, false, false, (1/0), false, false, false, (1/0), x, x, (1/0), x, false, x, false, false, false, x, false, (1/0), (1/0), x, x, (1/0), (1/0), x, (1/0), x, x, false, (1/0), x, (1/0), false, false, x, x, false, x, false, false, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), x, x, false, false, x, false, (1/0), false, false, false, false, false, x, (1/0), (1/0), false, (1/0), (1/0), x, false, (1/0), x, x, false, x, (1/0), (1/0), x, false, x, x, (1/0), (1/0), x, x, (1/0), x, (1/0), x, false, x, false, (1/0), (1/0), false, false, false, x, (1/0), (1/0), false, (1/0), (1/0), (1/0), (1/0), (1/0), false, x]); ");
/*fuzzSeed-246262462*/count=119; tryItOut("print(true);let x = x;");
/*fuzzSeed-246262462*/count=120; tryItOut("g2.m2.__proto__ = a2;");
/*fuzzSeed-246262462*/count=121; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=122; tryItOut(";");
/*fuzzSeed-246262462*/count=123; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ ( - (Math.imul((x | 0), Math.imul(( + (x + Math.max((x | 0), x))), ( + ( + Math.asin(y))))) >>> 0))) | 0); }); testMathyFunction(mathy0, [0, 0x100000001, -0x080000000, -0x100000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, Math.PI, 0.000000000000001, 1, -0x0ffffffff, -(2**53-2), 0x080000000, -(2**53), 2**53+2, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 0x080000001, 42, 1/0, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, -(2**53+2), 2**53, -0x100000000, -0x080000001, 2**53-2, -0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=124; tryItOut("e0.add(e1);");
/*fuzzSeed-246262462*/count=125; tryItOut("/*infloop*/for(var d in ((objectEmulatingUndefined)(((yield new RegExp(\"\\\\1[^\\\\u00A2\\\\D\\\\w\\u00ff]|[^]*|((?:\\\\1))|\\\\S?|\\u273e?{0,}\", \"gim\"))))))Object.defineProperty(this, \"v1\", { configurable: undefined, enumerable: /(?!(?:(?![^]([^\u0013-\\u0044\u87c1-\ube10\\b-\\t\\u0068]{1})*?)))/gi,  get: function() {  return a1.length; } });");
/*fuzzSeed-246262462*/count=126; tryItOut("\"use strict\"; o0.g1.v1 = evaluate(\"\\u3056 = e = Math.hypot(19, 26)\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 39 == 0), noScriptRval: false, sourceIsLazy: false, catchTermination: true(-12, \"\\u6D0D\") }));");
/*fuzzSeed-246262462*/count=127; tryItOut("/*vLoop*/for (var zmmwfx = 0; zmmwfx < 13; ++zmmwfx) { b = zmmwfx; var gntsgb = new SharedArrayBuffer(4); var gntsgb_0 = new Int32Array(gntsgb); gntsgb_0[0] = -25; /*MXX3*/g1.Math.PI = g0.g2.Math.PI; } ");
/*fuzzSeed-246262462*/count=128; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-246262462*/count=129; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.imul(( + (((( + ( ~ ( + (Math.hypot(( - 2**53-2), y) >>> 0)))) >>> 0) % (Math.pow(y, y) >>> 0)) >>> 0)), Math.fround((x | Math.log1p((x << y))))) != (( + Math.atan2((Math.acosh(((mathy0(0x080000000, y) <= 2**53+2) >>> 0)) | 0), ((( - (Math.PI | 0)) | 0) | 0))) | 0)); }); ");
/*fuzzSeed-246262462*/count=130; tryItOut("\"use strict\"; m0.get(f2);");
/*fuzzSeed-246262462*/count=131; tryItOut("/*tLoop*/for (let y of /*MARR*/[new ( /x/g )(), undefined, new ( /x/g )(), false, false, false, undefined, objectEmulatingUndefined(), [(void 0)], undefined, new ( /x/g )(), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, new ( /x/g )(), objectEmulatingUndefined(), new ( /x/g )(), [(void 0)], new ( /x/g )(), new ( /x/g )(), undefined, [(void 0)], false, objectEmulatingUndefined(), undefined, [(void 0)], new ( /x/g )(), new ( /x/g )(), new ( /x/g )(), false, objectEmulatingUndefined(), [(void 0)], new ( /x/g )(), [(void 0)], new ( /x/g )(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), [(void 0)], false, new ( /x/g )(), undefined, objectEmulatingUndefined()]) { /* no regression tests found */ }");
/*fuzzSeed-246262462*/count=132; tryItOut("\"use strict\"; L:switch(({w: {x: x, x: {}, d: \u3056}}) = \n /x/g ) { default: break; case (( /* Comment */x)(new (x => \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 0.0009765625;\n    var d3 = 131073.0;\n    var i4 = 0;\n    var i5 = 0;\n    i5 = (1);\n    return ((this.__defineGetter__(\"b\", x)))|0;\n  }\n  return f;)())): v1 = (f2 instanceof p0)\nprint(x);break;  }function x(z, ...eval)(p={}, (p.z =  /x/ )())e2.delete(i2);");
/*fuzzSeed-246262462*/count=133; tryItOut("{(void schedulegc(g0));/*RXUB*/var r = /\\2|([^])|(?!\\\u1a09)\ua81c?/m; var s = \"\\u77c2\\u77c2\\u77c2\"; print(s.match(r));  }");
/*fuzzSeed-246262462*/count=134; tryItOut("({add:  /x/  });");
/*fuzzSeed-246262462*/count=135; tryItOut("/*bLoop*/for (var ggqkbu = 0; ggqkbu < 30; ++ggqkbu) { if (ggqkbu % 3 == 1) { t1.set(a1, 0); } else { /*tLoop*/for (let x of /*MARR*/[c, c, c, new Number(1), new Number(1), new Number(1), c, c, c, c, c, c, c, new Number(1), c, new Number(1), new Number(1), c, new Number(1), c, c, c, new Number(1), c, new Number(1), c, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), c, new Number(1), c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, c, new Number(1), new Number(1), c, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), c, c, c, c, new Number(1), new Number(1)]) { t0 = new Uint8Array(b0, 17, ({valueOf: function() { print(x);return 4; }})); } }  } ");
/*fuzzSeed-246262462*/count=136; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.fround(Math.fround(( + Math.cosh(Math.fround(Math.trunc(x)))))) >>> (((Math.fround(( ! (x & (Math.hypot(Math.asin(( + x)), (-(2**53-2) | 0)) | 0)))) >>> 0) >= y) >>> 0)) % ( ~ ((Math.cos((-0x080000000 | 0)) | 0) ^ Math.cbrt(( - (y >>> 0)))))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0, -0x100000000, 2**53-2, -Number.MAX_VALUE, -1/0, 0x100000001, -0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000, -0, Number.MAX_VALUE, 2**53+2, 0x0ffffffff, -(2**53-2), -0x080000001, -0x0ffffffff, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 1, 0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 42, 0x100000000, -Number.MIN_VALUE, -(2**53+2), 1/0, Math.PI, -0x07fffffff]); ");
/*fuzzSeed-246262462*/count=137; tryItOut("\"use strict\"; /*bLoop*/for (let fndkhj = 0; fndkhj < 79; ++fndkhj) { if (fndkhj % 3 == 0) { /*MXX3*/g2.g1.Float32Array.name = this.g0.Float32Array.name; } else { Array.prototype.shift.call(o2.a1); }  } ");
/*fuzzSeed-246262462*/count=138; tryItOut("mathy2 = (function(x, y) { return (((Math.hypot(-1/0, ( ! Math.fround(Math.sqrt((y | 0))))) | 0) != Math.fround(Math.atanh(-0x0ffffffff))) === (( + Math.fround(Math.cos(( + ( + ( + ( + Math.max((( - (y | 0)) | 0), ( + Number.MAX_SAFE_INTEGER))))))))) >>> 0)); }); testMathyFunction(mathy2, [0.000000000000001, 0x0ffffffff, Number.MIN_VALUE, Math.PI, -(2**53-2), -0, -(2**53+2), 0/0, 0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1, -0x100000001, 0x080000000, 0, 2**53, 1/0, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, -0x080000001, 2**53+2, 1.7976931348623157e308, 2**53-2, -0x100000000, 42, -Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-246262462*/count=139; tryItOut("\"use strict\"; if(true) function f0(p2)  { return x } ");
/*fuzzSeed-246262462*/count=140; tryItOut("mathy5 = (function(x, y) { return mathy1(((((y >= ((Math.min(Math.fround(0x080000001), Math.fround(Math.hypot((x | 0), (y >>> 0)))) | 0) >>> 0)) | 0) - Math.atan2(x, (((x | 0) ? (y | 0) : (x | 0)) | 0))) == mathy0(((mathy0((Math.hypot(Math.fround(Math.tan(y)), Math.fround(Math.fround(Math.exp(Math.atan(x))))) | 0), (y | 0)) | 0) >>> 0), y)), (( + ( + (( - ( + mathy2(x, ( + x)))) | 0))) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[++6.__proto__, new Number(1), new Number(1),  \"\" , function(){}]); ");
/*fuzzSeed-246262462*/count=141; tryItOut("mathy2 = (function(x, y) { return (((Math.fround(Math.acos(mathy1((( - y) | 0), Math.fround(Math.imul(( + ( ~ ( + y))), Math.PI))))) !== ( + Math.max(mathy0(( + ( + ( + 0))), (mathy1((0x100000001 >>> 0), (( - y) | 0)) | 0)), (y >>> 0)))) >>> 0) < (((Math.cosh((x | 0)) | 0) >>> (( + (Math.hypot(((y && 1) | 0), (x | 0)) <= (((x >>> 0) ? ( + ( ~ ( + y))) : (Math.pow(-(2**53-2), Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0))) | 0)) >>> Math.atan2(Math.fround(Math.fround(Math.cosh((y >>> 0)))), ((Math.fround(Math.asinh((Math.imul(y, y) >>> 0))) ^ (42 | 0)) | 0)))); }); ");
/*fuzzSeed-246262462*/count=142; tryItOut("fzinab, \u3056 = null, x, x, lwcxne, eval, jxsrxf;print(x);");
/*fuzzSeed-246262462*/count=143; tryItOut("g2.g1.offThreadCompileScript(\"this.i2 = new Iterator(b0, true);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: true, element: o2, elementAttributeName: s0 }));");
/*fuzzSeed-246262462*/count=144; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return ((((0x0) >= (0xa209c055))*-0xdd176))|0;\n  }\n  return f; })(this, {ff: mathy2}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-246262462*/count=145; tryItOut("print(x);");
/*fuzzSeed-246262462*/count=146; tryItOut("/*vLoop*/for (var cctmqm = 0; cctmqm < 15; ++cctmqm) { let b = cctmqm; this.m2.set(b1, a0); } ");
/*fuzzSeed-246262462*/count=147; tryItOut("mathy2 = (function(x, y) { return Math.tan(mathy1(Math.pow(( + ( + ( + Math.fround((Math.fround(((Math.acos(x) | 0) << (x ^ 1))) ? Math.fround(Math.tan(0x07fffffff)) : (-0x080000001 >>> 0)))))), ( + Math.max(Math.pow((0x080000001 >>> 0), x), Math.fround((((( + (x ? ( + x) : ( + x))) | 0) ? (( + ( + y)) | 0) : x) | 0))))), mathy0(Math.cbrt(Math.fround(( - Math.fround((( + Number.MAX_VALUE) >>> 0))))), (Math.ceil((x | 0)) | 0)))); }); ");
/*fuzzSeed-246262462*/count=148; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -2305843009213694000.0;\n    {\n      {\n        {\n          i0 = (i0);\n        }\n      }\n    }\n    return +((((+abs(((d2))))) / ((8388608.0))));\n  }\n  return f; })(this, {ff: function(y) { return NaN }}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -(2**53+2), -(2**53), -0x100000001, 1, 0x100000001, 0/0, 0x080000001, 42, -0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, 0, 2**53, -0x07fffffff, Number.MAX_VALUE, -(2**53-2), 0x100000000, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, -0x0ffffffff, Number.MIN_VALUE, -0x080000001, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=149; tryItOut("\"use asm\"; v1 = t2.length;");
/*fuzzSeed-246262462*/count=150; tryItOut("a2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 0.015625;\n    return ((0xc8e54*(0xf8ade758)))|0;\n  }\n  return f; });");
/*fuzzSeed-246262462*/count=151; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.abs(( + ((Math.fround(Math.pow(Math.fround(Math.fround(Math.tanh(Math.fround(Number.MIN_VALUE)))), ( + ( ~ ( + -1/0))))) | 0) | (Math.hypot(Math.atan2(((y != x) | 0), (y ^ y)), (Math.expm1(x) | 0)) | 0)))); }); ");
/*fuzzSeed-246262462*/count=152; tryItOut("for (var p in g0.f1) { Array.prototype.shift.apply(a1, [o0]); }");
/*fuzzSeed-246262462*/count=153; tryItOut("mathy2 = (function(x, y) { return (Math.fround(Math.imul(Math.atan2(( ~ mathy1(x, x)), Math.log2(y)), (mathy0(Math.log10(x), Math.fround(Math.hypot(x, ( + ((y >>> 0) != ( + x)))))) >>> 0))) > (Math.fround(( + Math.cosh(Number.MAX_VALUE))) ^ Math.fround(( + Math.expm1((mathy1((-0x100000000 + y), ( + ((0x0ffffffff + (y >>> 0)) >>> 0))) ^ Math.acos(-Number.MIN_SAFE_INTEGER))))))); }); testMathyFunction(mathy2, [0x080000000, -0x100000001, Number.MAX_VALUE, -0x100000000, 0/0, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), Math.PI, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x0ffffffff, -0x080000001, 1/0, -Number.MAX_VALUE, 1, Number.MIN_VALUE, 0, -(2**53-2), 2**53-2, 1.7976931348623157e308, -1/0, Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, 0.000000000000001, -0x080000000, 42, -(2**53+2), 2**53, -0]); ");
/*fuzzSeed-246262462*/count=154; tryItOut("\"use strict\"; with((false).call(arguments.callee.caller, \n /x/ ,  '' ) != (NaN = true)){(window);\nprint(g1);\nm2.has(f0); }");
/*fuzzSeed-246262462*/count=155; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=156; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((Math.min(x, Math.fround(Math.atan(Math.fround(y)))) + mathy0(y, (((-(2**53-2) >> Math.min(x, x)) >>> 0) >>> 0))) % ( ! ( ~ Math.fround(x)))); }); ");
/*fuzzSeed-246262462*/count=157; tryItOut("s0 += s0;");
/*fuzzSeed-246262462*/count=158; tryItOut("\"use strict\"; print(x); var r0 = x + x; var r1 = r0 & x; r0 = x * r0; r1 = x * 4; x = r1 * x; var r2 = r1 | r1; var r3 = r1 ^ r0; var r4 = r0 * r3; var r5 = r0 & r3; var r6 = r4 - 6; r4 = 5 % r2; print(r1); r3 = r0 ^ 1; var r7 = r0 % r6; var r8 = r2 * r5; r1 = x + r0; var r9 = r0 / 9; var r10 = 1 + 0; var r11 = r5 % r0; var r12 = r9 % r2; var r13 = 1 - 1; var r14 = r12 / r12; print(r11); print(r14); print(r10); var r15 = r12 & r3; var r16 = 2 | r7; var r17 = r12 / r6; r0 = r4 * r12; var r18 = r5 * r6; var r19 = r12 % r7; var r20 = r17 ^ r11; var r21 = r16 | 8; var r22 = r10 - r8; var r23 = r3 & 1; var r24 = r22 | r9; r13 = r10 * r6; print(r19); var r25 = r17 | 9; var r26 = r14 | r23; r14 = 7 + r14; var r27 = x + 8; var r28 = r25 - r6; var r29 = 0 | r8; var r30 = r21 + r2; r6 = r29 & r25; var r31 = 8 * r8; var r32 = r23 / 0; var r33 = 9 / r27; var r34 = r0 + r27; var r35 = r19 & 2; var r36 = x - r8; var r37 = r35 - r20; var r38 = 7 | r3; var r39 = r38 ^ r5; var r40 = r33 + r4; var r41 = r7 % 1; var r42 = r26 / r15; var r43 = r2 / r16; r13 = r26 * r38; var r44 = r18 + r10; var r45 = 5 ^ r5; r10 = r38 * r45; var r46 = r33 ^ r39; var r47 = 3 | 9; r17 = 1 % r35; var r48 = r18 & 8; var r49 = 8 | r4; var r50 = 9 | 0; var r51 = r43 | r38; r10 = r50 % 9; var r52 = r2 & r26; var r53 = r41 - r4; r44 = r18 ^ r14; var r54 = r41 / r53; var r55 = r19 ^ 6; var r56 = r3 % r23; var r57 = r55 - r50; r31 = r40 * r48; var r58 = r3 / 9; var r59 = r0 % 4; var r60 = r36 - r44; print(r37); ");
/*fuzzSeed-246262462*/count=159; tryItOut("\"use strict\"; ");
/*fuzzSeed-246262462*/count=160; tryItOut("L:for(let d in ((((function(x, y) { return ( ~ ( + ( ! x))); })).call)(print([this])))){o0 = g0.__proto__;return; }");
/*fuzzSeed-246262462*/count=161; tryItOut("mathy2 = (function(x, y) { return Math.atan2((Math.asinh((y ? x : (Number.MIN_VALUE | 0))) >>> 0), (((Math.min((Math.acos( \"\" )), x))()) >>> 0)); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 0, 0/0, -(2**53-2), -0x100000001, 0x100000001, -0x080000000, 0x100000000, -0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), -0x080000001, 1, 2**53+2, Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, 1/0, -1/0, 0x080000000, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, -(2**53), -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=162; tryItOut("/*ODP-1*/Object.defineProperty(s1, \"toString\", ({writable: true, enumerable: let (d) (4277)}));");
/*fuzzSeed-246262462*/count=163; tryItOut("mathy3 = (function(x, y) { return (Math.hypot(Math.log10(( + (y < x))), Math.ceil(x)) ? Math.pow(Math.fround(mathy0(( + (((y >>> 0) >= ((( + (y | 0)) | 0) >>> 0)) >>> 0)), x)), ( ! (Math.tanh((y | 0)) | 0))) : (Math.sign(((Math.atan((mathy1((x | 0), (-0x080000000 | 0)) | 0)) | 0) | 0)) >>> 0)); }); testMathyFunction(mathy3, [0, -(2**53), -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 0x080000001, 0x100000001, 42, 0x07fffffff, 2**53-2, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53+2, 1, 0x080000000, -0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, 2**53, 1/0, -(2**53-2), Number.MIN_VALUE, -0x100000001, 0/0, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, -0, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-246262462*/count=164; tryItOut("/*tLoop*/for (let w of /*MARR*/[new String(''), new String(''), new String(''), NaN, true, NaN, new String('q'), new String(''), new String(''), true]) { for (var v of o1) { try { m1.has(m1); } catch(e0) { } try { f2.toString = f1; } catch(e1) { } try { this.s2 + v1; } catch(e2) { } e2.has(y); } }");
/*fuzzSeed-246262462*/count=165; tryItOut("/*UUV2*/(z.startsWith = \u0009z.log);");
/*fuzzSeed-246262462*/count=166; tryItOut("/*oLoop*/for (fisjsf = 0; fisjsf < 55; ++fisjsf) { for (var v of p0) { try { v0 = this.a2.length; } catch(e0) { } v0 = f2[\"toString\"]; } } ");
/*fuzzSeed-246262462*/count=167; tryItOut("for (var p in m0) { print(f1); }");
/*fuzzSeed-246262462*/count=168; tryItOut("b2 = t0[v2];");
/*fuzzSeed-246262462*/count=169; tryItOut("\"use strict\"; { void 0; void relazifyFunctions(); } switch(\"\\uC190\") { case true: g2.s2 += 'x';break; default: break;  }");
/*fuzzSeed-246262462*/count=170; tryItOut("\"use strict\"; f1 + '';");
/*fuzzSeed-246262462*/count=171; tryItOut("\"use strict\"; a0.length = 13;");
/*fuzzSeed-246262462*/count=172; tryItOut("mathy2 = (function(x, y) { return (( + (( - x) == Math.hypot(y, Math.hypot(x, Math.min(Math.fround(1.7976931348623157e308), y))))) ? (Math.min(Math.atan2(Math.fround((((Number.MAX_VALUE | 0) && (( - (Math.exp((((y | 0) + (y | 0)) | 0)) >>> 0)) | 0)) | 0)), Math.fround(((( - x) | 0) , x))), (Math.pow(((y >> y) >>> 0), (( ~ ( + ((( + x) >>> 0) ? x : 0/0))) >>> 0)) >>> 0)) >>> 0) : Math.cosh((Math.atan2(( ! Math.log(x)), (Math.cbrt((y >>> 0)) || y)) | 0))); }); testMathyFunction(mathy2, [-1/0, 0, -Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, 2**53+2, -0x080000000, -0x080000001, -(2**53-2), -(2**53), -(2**53+2), 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, 42, 0.000000000000001, 2**53, 0x100000000, 2**53-2, 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 0x07fffffff, -0x100000001, 0x080000001, 0x100000001, -0, -Number.MAX_VALUE, -0x100000000, 1/0]); ");
/*fuzzSeed-246262462*/count=173; tryItOut("g0.a2 = new Array;");
/*fuzzSeed-246262462*/count=174; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.max(Math.atan2(Math.trunc((Math.fround((x | 0)) >>> 0)), (mathy3(y, (( ~ ( ! Math.fround(x))) | 0)) | 0)), Math.fround((Math.fround(( - ((( ! ( + 0.000000000000001)) >>> 0) ? Math.cos(( + 0x0ffffffff)) : Math.fround(Math.atan2(( ! y), Math.fround(-0x100000001)))))) ? Math.fround(Math.atan2(Math.fround(((((Math.imul((x | 0), Number.MAX_SAFE_INTEGER) | 0) | 0) + (x | 0)) | 0)), Math.fround(Math.pow((mathy2(y, y) | 0), mathy0(((y ? (y | 0) : Math.fround(x)) | 0), (x * y)))))) : Math.hypot((((Math.fround(Math.min(y, -(2**53-2))) ? (((y >>> 0) < (2**53 | 0)) >>> 0) : (mathy4(-Number.MAX_VALUE, x) >>> 0)) >>> 0) | 0x080000000), (x | 0))))); }); testMathyFunction(mathy5, [-(2**53), 0.000000000000001, 1, -0x0ffffffff, 0x100000000, 0x0ffffffff, Math.PI, -0x080000001, -0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, -0x080000000, 0/0, Number.MIN_SAFE_INTEGER, 0x080000000, 42, 0x07fffffff, -0x100000001, -1/0, 0x080000001, -(2**53+2), 2**53-2, 2**53+2, -0x07fffffff, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 2**53, -Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-246262462*/count=175; tryItOut("delete x.x;");
/*fuzzSeed-246262462*/count=176; tryItOut("e0.has(e2);");
/*fuzzSeed-246262462*/count=177; tryItOut("\"use strict\"; this.a2.sort((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -33.0;\n    var d4 = -2.3611832414348226e+21;\n    var i5 = 0;\n    d4 = (d3);\n    return ((0x34cef*((4277))))|0;\n  }\n  return f; })(this, {ff: Promise.all}, new SharedArrayBuffer(4096)));");
/*fuzzSeed-246262462*/count=178; tryItOut("print(x);");
/*fuzzSeed-246262462*/count=179; tryItOut("e0.has(this.g1);");
/*fuzzSeed-246262462*/count=180; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]\", \"gi\"); var s = true; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=181; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0, -Number.MIN_VALUE, -0x07fffffff, 0, -(2**53-2), 2**53-2, 0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 0.000000000000001, 1.7976931348623157e308, -0x100000001, 0x100000001, 0x080000001, 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, 2**53+2, -(2**53+2), 0x080000000, 2**53, 42, Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, Math.PI, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, -0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-246262462*/count=182; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions(this); } void 0; }");
/*fuzzSeed-246262462*/count=183; tryItOut("/*MXX1*/g2.o1 = g2.g1.Symbol.replace;");
/*fuzzSeed-246262462*/count=184; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy2(Math.fround((( + (((Math.max(( - 0x080000001), x) / Math.fround(x)) | 0) ? ( + (x ^ (( + ( ~ (Math.min((y | 0), 0x080000001) >>> 0))) >>> 0))) : ( + Math.fround(( ! ( - x)))))) % ( + mathy4(Math.hypot((Math.max(Math.fround(-0x100000000), ( + ( + (((Math.atan((x >>> 0)) | 0) >>> 0) != Math.fround(-Number.MAX_VALUE))))) | 0), 0x07fffffff), x)))), ( + mathy0(( + Math.fround(Math.imul(Math.fround((Math.hypot((x | 0), (( + ( ~ y)) | 0)) | 0)), (( + Math.fround((Math.fround(y) || -0x0ffffffff))) | 0)))), ((Math.max(( + ( - Math.fround(x))), ( + y)) !== (((Math.min((Math.log10(Math.fround(Math.cbrt(x))) | 0), mathy0(mathy0(2**53+2, 0x100000001), y)) >>> 0) > (Math.atan(Math.fround((mathy3(Math.fround(1.7976931348623157e308), y) | 0))) >>> 0)) >>> 0)) | 0)))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, -0, 2**53-2, Number.MAX_VALUE, 0/0, Math.PI, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 0, 2**53, 1.7976931348623157e308, -0x080000001, -0x100000001, 2**53+2, 0x080000000, -1/0, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 0x080000001, -0x100000000, 0.000000000000001, 1, 42, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=185; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2((Math.fround(Math.imul((( + (y ? Math.min((((y | 0) <= (y | 0)) | 0), Math.fround(x)) : (x | 0))) | 0), Math.fround(mathy1(mathy0((2**53+2 >>> 0), (x >>> 0)), -1/0)))) ** Math.max(x, (Math.fround(Math.hypot(Math.fround(y), Number.MIN_SAFE_INTEGER)) >> 2**53-2))), (( + Math.cosh(( + (((((Math.tan(y) >>> 0) >>> 0) != (( + (Math.asin(y) | 0)) >>> 0)) >>> 0) && y)))) ? Math.cbrt(( + Math.hypot(( + (y ? (Math.atan(y) | 0) : x)), ( + x)))) : Math.fround((Math.sinh((Math.max(( + -0x080000001), ( + x)) >>> 0)) ? Math.fround((Math.hypot((x | 0), ( + y)) | 0)) : (Math.sin((2**53-2 >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [0x080000001, 0, 1, -(2**53), 2**53+2, 2**53-2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 0x100000000, -0, 42, -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0/0, 0x100000001, -(2**53-2), -0x100000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, -(2**53+2), -1/0, Math.PI, -Number.MIN_VALUE, -0x100000001, 0.000000000000001, 2**53, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=186; tryItOut("{ void 0; try { gcparam('sliceTimeBudget', 2); } catch(e) { } } Object.defineProperty(this, \"v2\", { configurable: (x % 5 == 3), enumerable:  /x/g ,  get: function() {  return t1.length; } });");
/*fuzzSeed-246262462*/count=187; tryItOut(";");
/*fuzzSeed-246262462*/count=188; tryItOut("\"use strict\"; print(uneval(m0));");
/*fuzzSeed-246262462*/count=189; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.log((mathy2(Math.pow(Math.ceil((Math.expm1(2**53+2) >>> 0)), Math.sin(Math.fround(mathy1(y, (Math.atan2((x >>> 0), -Number.MIN_VALUE) | 0))))), (Math.max(Math.fround(Math.imul((-Number.MIN_VALUE | 0), Math.fround((( + (Number.MAX_VALUE | 0)) | 0)))), (Math.fround(Math.fround(Math.log2(Math.fround(0x100000000)))) | 42)) >>> 0)) | 0)); }); ");
/*fuzzSeed-246262462*/count=190; tryItOut("for (var p in s1) { try { Array.prototype.shift.call(a0); } catch(e0) { } try { a0 = new Array; } catch(e1) { } o0 = Object.create(p0); }");
/*fuzzSeed-246262462*/count=191; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log2(Math.fround(Math.fround(( - ( + Math.pow(y, Math.fround(y))))))); }); testMathyFunction(mathy1, /*MARR*/[new String(''), new String(''), true, true, true, true, new String(''), true, new String(''), true, true, true, true, new String(''), true, true, true, true, true, true, new String(''), new String(''), new String(''), true, new String(''), new String(''), new String(''), true, new String(''), true, true, true, true, true, new String(''), new String(''), true, true, true, new String(''), new String(''), true, new String(''), true, new String(''), new String(''), new String(''), true, true, new String(''), new String(''), true, true, new String(''), new String(''), new String(''), true, new String(''), true]); ");
/*fuzzSeed-246262462*/count=192; tryItOut("g2.f2(this.v1);");
/*fuzzSeed-246262462*/count=193; tryItOut("v0 = g2.b2.byteLength;");
/*fuzzSeed-246262462*/count=194; tryItOut("\"use strict\"; g2.t1 = new Uint8Array(b1);");
/*fuzzSeed-246262462*/count=195; tryItOut("s0 += g1.s1;");
/*fuzzSeed-246262462*/count=196; tryItOut("L: {M:while((this.__defineGetter__(\"d\", Object.prototype.valueOf)) && 0){this.f1(f0); } }");
/*fuzzSeed-246262462*/count=197; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.cos((Math.pow(Math.fround(mathy0(((2**53 == y) | 0), (((Math.fround(( + ( - ( + y)))) / (x | 0)) % 0x100000001) | 0))), ( ~ x)) >>> 0)) >>> 0) || ((Math.acos(x) , Math.sqrt((Math.log1p(( + x)) | 0))) | 0)) | 0); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, 1, 0x07fffffff, 0x100000000, -0, 0, Math.PI, -0x080000001, Number.MAX_VALUE, 42, -(2**53), -Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 2**53+2, 0/0, -0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, -0x100000001, 0x080000001, 2**53-2, -(2**53+2), 0x080000000, 0x0ffffffff, 0x100000001, 2**53, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=198; tryItOut("testMathyFunction(mathy1, [-0x100000001, 0, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0x07fffffff, -(2**53+2), 42, 1/0, -0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, 2**53+2, 2**53, -1/0, -0, 0x100000000, Math.PI, -(2**53-2), Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 1, 0/0, 0x080000000, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=199; tryItOut("\"use strict\"; v2 = -0;");
/*fuzzSeed-246262462*/count=200; tryItOut("v1 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-246262462*/count=201; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var cos = stdlib.Math.cos;\n  var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      i2 = (0xff44c979);\n    }\n    /*FFI*/ff((yield this), ((((i2))|0)), ((((0xffffffff)) ^ ((((0xfbebbf6d))>>>((0x77aca36b))) % (((-0x8000000))>>>((0x9399b4a)))))), ((+((((0x432f0fe)))>>>((0xfe52bd66)-(0xaa0e8c92))))), ((((0x87970050)+(0x60672c35)) | ((0x57ad18ea)+(0xf916dd7e)))), ((d1)), ((d1)), ((-1.001953125)));\n    {\n      {\n        d0 = (d0);\n      }\n    }\n    d0 = (Infinity);\n    return ((((-((+cos(((-((-1.125)))))))) == (-590295810358705700000.0))+((abs((~~(134217729.0)))|0) > ((([yield  /x/g ])-((((0x44cf7667))>>>((0x1eed11b9))))) >> ((/*FFI*/ff(((((0x5c6bd132)) & ((0xf92a4cd9)))), ((((0xfb887799)) & ((0xe817ef14)))), ((1.00390625)), ((7.555786372591432e+22)), ((72057594037927940.0)), ((-1.2089258196146292e+24)))|0)-(/*FFI*/ff(((d1)), ((-73786976294838210000.0)), ((-4.722366482869645e+21)))|0))))+(!((~(((288230376151711740.0) == (+atan2(((-128.0)), ((4294967297.0)))))-(0xfc756899)-((((0x4759b3d1))>>>((0x9e8ea6a2))))))))))|0;\n  }\n  return f; })(this, {ff: function  eval (y) { print(x , x); } }, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-246262462*/count=202; tryItOut(" for  each(let e in  /x/ ) {print(x); }");
/*fuzzSeed-246262462*/count=203; tryItOut("Object.preventExtensions(v2);");
/*fuzzSeed-246262462*/count=204; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MAX_VALUE, 0.000000000000001, -0x080000000, -Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -(2**53), 2**53, 2**53-2, -0x100000001, 1, Number.MIN_VALUE, -0x07fffffff, -Number.MIN_VALUE, Math.PI, -0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, 0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 2**53+2, -0x100000000, 0x100000001, 1/0, 0x080000001]); ");
/*fuzzSeed-246262462*/count=205; tryItOut("mathy1 = (function(x, y) { return mathy0((( + (( + (( + mathy0(( + x), ( + x))) , Math.fround(x))) || ( + (Math.exp(x) >>> 0)))) | 0), Math.fround((Math.fround((Math.asin(x) - y)) | Math.fround((Math.atan2(Math.tanh(x), y) !== Math.fround(0)))))); }); ");
/*fuzzSeed-246262462*/count=206; tryItOut("/*bLoop*/for (var fzlseo = 0; fzlseo < 4 && (false *=  \"\"  **= /*FARR*/[...[], false].filter(Float32Array)\u000d); ++fzlseo) { if (fzlseo % 9 == 0) { print((let (z) [1,,])); } else { with(( /* Comment */ \"\" ))v0 = a2.every((function() { try { /*MXX2*/o0.g2.Promise.prototype.then = this.i0; } catch(e0) { } try { print(x); } catch(e1) { } h0 = {}; return v1; })); }  } function y(w, window)(({x: true}))this.o0.m1.has(h1);");
/*fuzzSeed-246262462*/count=207; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( ! ( + ( + ( - ( + (Math.fround(Math.atan2(Math.fround(x), Math.fround(( ! x)))) <= Math.tanh((Math.sin((y >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy5, [false, [0], ({toString:function(){return '0';}}), (new Number(0)), ({valueOf:function(){return '0';}}), '', 0.1, (function(){return 0;}), (new Number(-0)), [], '0', null, '\\0', '/0/', (new String('')), (new Boolean(false)), undefined, objectEmulatingUndefined(), 0, NaN, (new Boolean(true)), true, ({valueOf:function(){return 0;}}), /0/, 1, -0]); ");
/*fuzzSeed-246262462*/count=208; tryItOut("m1.set(v0, a2);");
/*fuzzSeed-246262462*/count=209; tryItOut("/*RXUB*/var r = /(?=([^]|(?!\\d+?)))|(.){2,2147483650}/gym; var s = \"\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=210; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.hypot(( + Math.fround(Math.pow(((Math.imul(-Number.MAX_SAFE_INTEGER, Math.min(x, -(2**53+2))) | (( ! Math.exp((x | 0))) | 0)) >>> 0), ((( ~ Math.acosh(Math.fround(Math.fround(Math.atan2((Math.imul(x, Math.imul(Math.fround(x), Math.fround(y))) | 0), (x | 0)))))) >>> 0) >>> 0)))), (( + (Math.fround((Math.pow((y | 0), ( + (((Math.max((( + ((x | 0) - (x | 0))) >>> 0), (((x >>> 0) ^ x) >>> 0)) | 0) | 0) << Math.max((Math.log10(Math.asinh(x)) >>> 0), y)))) | 0)) % Math.fround(y))) >>> 0))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 0, Number.MAX_VALUE, -1/0, 2**53-2, 0.000000000000001, -0x0ffffffff, 0x100000001, -0x100000001, -(2**53+2), 0x100000000, -0x080000001, 1.7976931348623157e308, Math.PI, -(2**53-2), -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, -Number.MAX_VALUE, 42, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 0x080000000, 1, -0x080000000, 2**53, -0, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-246262462*/count=211; tryItOut("{ void 0; void relazifyFunctions(); }");
/*fuzzSeed-246262462*/count=212; tryItOut("if( /x/ ) { if ((/*FARR*/[...[], ...[], d, ...[], x, ...[], ...[], ].map)) {(x ^ (4277)); } else /*iii*/g1.__proto__ = p0;/*hhh*/function hjhepl(w, x){m1.get(g2);}}");
/*fuzzSeed-246262462*/count=213; tryItOut("v0 = (this.a2 instanceof this.o2);");
/*fuzzSeed-246262462*/count=214; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-246262462*/count=215; tryItOut("\"use strict\"; testMathyFunction(mathy5, [/0/, (new String('')), -0, (new Boolean(true)), false, NaN, 0.1, (new Number(-0)), (function(){return 0;}), 0, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '0', true, '', objectEmulatingUndefined(), (new Number(0)), '\\0', (new Boolean(false)), null, '/0/', undefined, [0], 1, ({valueOf:function(){return 0;}}), []]); ");
/*fuzzSeed-246262462*/count=216; tryItOut("print(uneval(g2.m0));");
/*fuzzSeed-246262462*/count=217; tryItOut("\"use strict\"; this.v2 = g1.runOffThreadScript();\nv2 = evaluate(\"(/*wrap3*/(function(){ \\\"use strict\\\"; var mfwkmn =  '' ; (window)(); })()((/*RXUE*/new RegExp(\\\"(?![^])+|(?:${2,}|(?:[^])|$(?=[^\\\\\\\\s\\\\ucf47-\\\\u25f1]))(?!^)${0,}+{137438953471}{3,}\\\", \\\"gym\\\").exec(\\\"\\\\n\\\\n\\\\n\\\")), ((function sum_slicing(pprjom) { ; return pprjom.length == 0 ? 0 : pprjom[0] + sum_slicing(pprjom.slice(1)); })(/*MARR*/[Infinity, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, Infinity, objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, Infinity]))))\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 19 == 15), noScriptRval: (x % 3 != 0), sourceIsLazy: false, catchTermination: (x % 6 != 5) }));\n");
/*fuzzSeed-246262462*/count=218; tryItOut("o0 = Object.create(g1);");
/*fuzzSeed-246262462*/count=219; tryItOut("m0.has(s1);function w()new Boolean(false)o0.b0 = o2.t0.buffer;\u0009\nprint(x);\nprint(({length: undefined, name: false }));\n\n");
/*fuzzSeed-246262462*/count=220; tryItOut("e2 = new Set(this.v0);");
/*fuzzSeed-246262462*/count=221; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max(mathy0(Math.acos(( + Math.asin(( + (Math.max(( + -Number.MIN_VALUE), y) | 0))))), Math.fround((Math.fround(x) && Math.fround(x)))), ((Math.min(x, ( + (y >>> 0))) | 0) ? Math.hypot((Math.min((Math.atanh((y | 0)) >>> 0), Math.max(x, y)) >>> 0), Math.atan2(Math.hypot(x, ( + (y ? -0x080000000 : ( + (-0x100000001 + x))))), Math.fround((Math.fround(x) >= Math.fround((( + (y | 0)) | 0)))))) : Math.tan(Math.tan((Math.min(x, x) | 0))))); }); testMathyFunction(mathy1, [-0x080000000, 1, 0x100000000, 2**53, 0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, Math.PI, -0x100000000, 42, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, -0x080000001, 1/0, 0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE, -0, -0x07fffffff, -(2**53-2), -1/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, 0x080000001, 2**53+2, 0.000000000000001]); ");
/*fuzzSeed-246262462*/count=222; tryItOut("\"use strict\"; for (var v of v1) { try { Array.prototype.sort.call(a2, (function() { for (var j=0;j<7;++j) { f2(j%3==0); } }), s1, this.g0); } catch(e0) { } v0 = o0.a0.reduce, reduceRight((function() { try { const t2 = t2.subarray(9); } catch(e0) { } try { Object.prototype.unwatch.call(m0, \"window\"); } catch(e1) { } a1 = Array.prototype.concat.apply(a2, [a0]); return b0; }), t2, a1, m1, p0, b1, e0); }");
/*fuzzSeed-246262462*/count=223; tryItOut("\"use strict\"; print(uneval(g0));");
/*fuzzSeed-246262462*/count=224; tryItOut("e1.has(i1);");
/*fuzzSeed-246262462*/count=225; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.fround(Math.atan2(Math.fround(Math.log10(( + Math.tan(( + (Math.hypot((x >>> 0), 0x0ffffffff) >>> 0)))))), Math.fround(Math.log(( + ( ~ x)))))) << Math.fround(Math.tan(Math.fround(Math.fround((( + ( ! Math.fround(( - Math.hypot(y, 0x080000000))))) % ( + Math.fround(Math.fround(((mathy3((x | 0), x) >>> 0) <= x)))))))))); }); testMathyFunction(mathy5, [0x100000000, 1, -(2**53-2), -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, 2**53, -0x080000000, 1.7976931348623157e308, 0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), -0x100000001, 0x080000001, 0x080000000, -0, -0x07fffffff, 0x0ffffffff, -0x0ffffffff, 42]); ");
/*fuzzSeed-246262462*/count=226; tryItOut("(new (function(q) { \"use strict\"; return q; })(x%=this, null));\nv2 = g2.runOffThreadScript();\n");
/*fuzzSeed-246262462*/count=227; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - Math.fround(Math.min(Math.fround(Math.asinh(Number.MAX_VALUE)), Math.fround(Math.cbrt(( ! (Math.fround(Math.imul(Math.fround(y), ( + y))) >>> 0))))))); }); testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), (new Boolean(false)), null, 0.1, '', objectEmulatingUndefined(), 0, [], /0/, (new Number(0)), ({toString:function(){return '0';}}), [0], '\\0', (new Boolean(true)), (new Number(-0)), '/0/', 1, (function(){return 0;}), -0, true, NaN, undefined, '0', false, (new String('')), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-246262462*/count=228; tryItOut("\"use strict\"; e2.has((4277));function x(\u3056 = (this.__defineGetter__(\"w\", encodeURIComponent)))\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-562949953421313.0));\n  }\n  return f;;");
/*fuzzSeed-246262462*/count=229; tryItOut("\"use strict\"; /*oLoop*/for (var qhjpvz = 0, x = (Math.log10(-28)); qhjpvz < 1; ({a2:z2}), ++qhjpvz) { for(let c in []); } ");
/*fuzzSeed-246262462*/count=230; tryItOut("\"use strict\"; /*oLoop*/for (ryvkmu = 0; ryvkmu < 59; (void options('strict')), ++ryvkmu) { print({} = window); } ");
/*fuzzSeed-246262462*/count=231; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ~ ((mathy2(( + (mathy3((Math.log2(Math.max((x ? y : 0), x)) | 0), (( - Math.log1p(y)) <= y)) >>> 0)), Math.fround(( + (-(2**53-2) | 0)))) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, 0x0ffffffff, 0x07fffffff, 42, -0, -0x080000000, -0x07fffffff, -(2**53), 2**53-2, 1/0, -(2**53-2), 0x100000001, 0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 0x100000000, -0x100000000, 2**53, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, 0/0, -0x0ffffffff, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), 1, 0x080000000]); ");
/*fuzzSeed-246262462*/count=232; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.hypot((( + (( + mathy1(Math.fround(( ~ Math.fround(x))), -0x080000000)) || Math.atan2(( ! (-0 >>> 0)), Math.atan2(((y | 0) | (x >>> 0)), x)))) >>> ( + mathy1(( + x), 1/0))), ( ~ Math.asinh(( + Math.cosh(Math.acos((mathy0((y >>> 0), y) >>> 0))))))); }); testMathyFunction(mathy2, /*MARR*/[undefined, NaN, 1.7976931348623157e308, undefined, function(){}, undefined, function(){}, NaN, NaN, NaN, 1.7976931348623157e308, function(){}, undefined, undefined, 1.7976931348623157e308, NaN, undefined, NaN, undefined, NaN, 1.7976931348623157e308, undefined, 1.7976931348623157e308, undefined, undefined, NaN, undefined, undefined, 1.7976931348623157e308, function(){}, undefined, undefined, undefined, undefined, undefined, undefined, undefined, NaN, NaN, 1.7976931348623157e308, 1.7976931348623157e308, function(){}, undefined, NaN, function(){}, function(){}, NaN, 1.7976931348623157e308, 1.7976931348623157e308, function(){}, NaN, undefined, 1.7976931348623157e308, NaN, undefined, function(){}, 1.7976931348623157e308, function(){}, 1.7976931348623157e308, function(){}, function(){}, undefined, function(){}, undefined, NaN, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, NaN]); ");
/*fuzzSeed-246262462*/count=233; tryItOut("a0 = Array.prototype.slice.call(a0, NaN, -8, (4277));");
/*fuzzSeed-246262462*/count=234; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.pow(Math.ceil(( + -Number.MAX_VALUE)), (( + Math.min(( + -(2**53-2)), ( + Math.imul(x, y)))) | 0)) , Math.atan2(( + y), (-0x0ffffffff != ( + Math.imul(x, (Math.asin(x) || (( + mathy2(( + Number.MAX_SAFE_INTEGER), x)) >>> 0))))))); }); testMathyFunction(mathy5, [0x080000000, Math.PI, 1, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, 0x100000000, -Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 1.7976931348623157e308, -0, Number.MIN_VALUE, Number.MAX_VALUE, -1/0, -0x0ffffffff, -(2**53+2), -(2**53-2), -0x100000001, 0/0, 0.000000000000001, 0x07fffffff, -Number.MIN_VALUE, 1/0, -(2**53), 0, 0x080000001, -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-246262462*/count=235; tryItOut("b0 = a0[11];");
/*fuzzSeed-246262462*/count=236; tryItOut("i2 + i1;");
/*fuzzSeed-246262462*/count=237; tryItOut("s0 = x;");
/*fuzzSeed-246262462*/count=238; tryItOut("/*tLoop*/for (let w of /*MARR*/[new Number(1.5),  /x/g ,  /x/g ,  /x/g , new Number(1.5), new Number(1.5),  /x/g , new Number(1.5),  /x/g , new Number(1.5), new Number(1.5), new Number(1.5),  /x/g ,  /x/g , new Number(1.5),  /x/g , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/g ,  /x/g , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/g , new Number(1.5), new Number(1.5),  /x/g ,  /x/g , new Number(1.5), new Number(1.5), new Number(1.5)]) { print(w); }");
/*fuzzSeed-246262462*/count=239; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\2{0,})\", \"gyim\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=240; tryItOut("testMathyFunction(mathy5, [1, 0/0, 0x100000001, Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, 42, -0x100000000, -(2**53-2), 2**53+2, -Number.MIN_VALUE, 1/0, 0x080000001, 0x080000000, -(2**53+2), -0x080000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, 2**53-2, -0x080000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -1/0, 2**53, -Number.MAX_VALUE, -0x100000001, 0, 0x07fffffff, -(2**53)]); ");
/*fuzzSeed-246262462*/count=241; tryItOut("\"use strict\"; g2.__proto__ = p1;/*tLoop*/for (let y of /*MARR*/[0x080000000, new Boolean(true), x, new Boolean(false), new Boolean(false), 0x080000000, x, new Boolean(false), 0x080000000, 0x080000000, null, x, x, 0x080000000, x, null, x, new Boolean(true), new Boolean(false), new Boolean(false), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, new Boolean(false), x, new Boolean(false), x, null, 0x080000000, x, x, x, new Boolean(false), null, null, x, x, new Boolean(false), null, x, new Boolean(true), new Boolean(true), new Boolean(true), x, new Boolean(false), 0x080000000, null, x, 0x080000000, new Boolean(false), new Boolean(true), null, null, 0x080000000, 0x080000000, x, new Boolean(true), x, x, new Boolean(true), null, x, null, new Boolean(false), x, x, 0x080000000, null, null, 0x080000000, x, null, 0x080000000, null, 0x080000000, 0x080000000, 0x080000000, new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(true), null, new Boolean(true), x, x, x, new Boolean(false), x, 0x080000000, new Boolean(false), new Boolean(true), 0x080000000, new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(false), x, 0x080000000, null, x, new Boolean(false), 0x080000000, new Boolean(false), null, new Boolean(true), null, new Boolean(true), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]) { /* no regression tests found */ }");
/*fuzzSeed-246262462*/count=242; tryItOut("/*RXUB*/var r = new RegExp(\"[^]?|(?![^\\u00e5])*?\", \"gi\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-246262462*/count=243; tryItOut("\"use strict\"; print(x); '' ;");
/*fuzzSeed-246262462*/count=244; tryItOut("mathy1 = (function(x, y) { return Math.fround((( + Math.sin(( + (Math.max(Math.hypot(y, (Math.hypot((x >>> 0), (-0x100000001 >>> 0)) >>> 0)), Math.min((1.7976931348623157e308 >>> 0), (Math.expm1((( + ( + y)) >>> 0)) | 0))) ? (Math.hypot((((y | 0) << ( ! x)) >>> 0), (y >>> 0)) >>> 0) : Math.hypot(x, (Math.pow(( + (((y | 0) && 0x0ffffffff) | 0)), ( + y)) | 0)))))) == (mathy0(( - ( + (( - ( + 2**53)) ? ( + Math.fround(((x & x) % x))) : ( + x)))), (Math.tanh(Math.log((( + Math.fround(mathy0(Math.fround(x), Math.fround(x)))) >>> 0))) | 0)) | 0))); }); ");
/*fuzzSeed-246262462*/count=245; tryItOut("var sgwjkv = new ArrayBuffer(16); var sgwjkv_0 = new Int32Array(sgwjkv); sgwjkv_0[0] = 16; var sgwjkv_1 = new Int8Array(sgwjkv); sgwjkv_1[0] = 21; var sgwjkv_2 = new Int32Array(sgwjkv); yield;");
/*fuzzSeed-246262462*/count=246; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ! Math.fround(( + Math.cosh((( ~ Math.cos(( + ( ~ ( + x))))) >>> 0))))) | 0); }); ");
/*fuzzSeed-246262462*/count=247; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((((Math.ceil((Math.hypot(x, Math.exp((( ~ (0x100000000 >>> 0)) >>> 0))) >>> 0)) <= (Math.pow(x, (Math.atanh((( + Math.max(Math.clz32(y), ( + x))) | 0)) | 0)) >>> 0)) >>> 0) ** ((( + Math.pow(( + Math.min((( + x) | 0), (Math.imul((( ! y) | 0), x) | 0))), ( + 42))) ? (Math.cbrt((( ~ y) >>> 0)) >>> 0) : Math.cbrt((( + (y >>> 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[function(){}, {x:3}, function(){}, function(){}, function(){}, {x:3}, (0/0), function(){}, {x:3}, function(){}, {x:3}, {x:3}, {x:3}, {x:3}, function(){}, {x:3}, (0/0)]); ");
/*fuzzSeed-246262462*/count=248; tryItOut("\"use strict\"; \"use asm\"; L: for  each(d in a) {e0 + i2;; }");
/*fuzzSeed-246262462*/count=249; tryItOut("selectforgc(g2.o2);");
/*fuzzSeed-246262462*/count=250; tryItOut("/*RXUB*/var r = new RegExp(\".[^\\u4afd-\\u001c\\\\Sz\\\\w]*(?=(?!\\\\s){4,})(?!$)*?|(?![^]){4,6}{0}|(?!(?:\\\\B){3,5}|((\\\\d))(\\\\u00A5*)\\\\\\u00c6)(?:\\\\b|\\\\1+*?)+?\", \"gy\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-246262462*/count=251; tryItOut("v1 = r0.unicode;");
/*fuzzSeed-246262462*/count=252; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.min(Math.fround(Math.clz32(Math.max(Math.fround(Math.fround(Math.min(Math.fround((((( + (-Number.MAX_VALUE >>> 0)) >>> 0) ** (Math.atan2(y, 1) << Math.fround(( - y)))) | 0)), Math.fround(Math.sqrt(x))))), Math.atan2((Math.trunc((y == y)) >>> 0), x)))), Math.fround(( ~ Math.fround(0x080000000))))); }); ");
/*fuzzSeed-246262462*/count=253; tryItOut("-5;var y = x;");
/*fuzzSeed-246262462*/count=254; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-246262462*/count=255; tryItOut("\"use strict\"; m1 = new Map;");
/*fuzzSeed-246262462*/count=256; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float64ArrayView[4096]) = ((Float64ArrayView[((((d1)))+(0xffc8473c)-(0x862b9edc)) >> 3]));\n    {\n      (Int16ArrayView[1]) = ((0xffd6d769));\n    }\n    (Uint8ArrayView[((0xfc173f07)-(0x629cae3f)-((0x5ab431a7) ? (0xfdbcdc3e) : ((0x9cd8f6d8) <= (0xfa278fcb)))) >> 0]) = ((Int16ArrayView[1]));\n    {\n      d1 = (d0);\n    }\n    d0 = ((+/*FFI*/ff()) + (d1));\n    d0 = (d0);\n    return +((((d1)) - ((Float64ArrayView[4096]))));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; /*bLoop*/for (let acaxhg = 0, x; acaxhg < 125;  \"\" , ++acaxhg) { if (acaxhg % 55 == 26) { g0.a1.splice(NaN, 4, t0, t1, this.o2); } else { /*MXX2*/g1.g2.Int16Array.name = this.o2; }  }  }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0, (new Boolean(false)), (new Boolean(true)), ({valueOf:function(){return 0;}}), null, NaN, 0.1, true, 1, (new Number(-0)), undefined, ({valueOf:function(){return '0';}}), (new String('')), [], 0, false, ({toString:function(){return '0';}}), '/0/', /0/, '', (new Number(0)), [0], (function(){return 0;}), '0', objectEmulatingUndefined(), '\\0']); ");
/*fuzzSeed-246262462*/count=257; tryItOut("\"use strict\"; { void 0; selectforgc(this); } v0 = g1.runOffThreadScript();");
/*fuzzSeed-246262462*/count=258; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    i1 = (i1);\n    i1 = (/*FFI*/ff(((+/*FFI*/ff((((0xfffff*(i0))|0)), ((((i0)) ^ (((~~(-32768.0)))))), (((((1125899906842624.0))) >> (-0x1d49a*(i0)))), ((-65537.0)), ((+(((0xfcd9fe3a)-(0x753a9134)-(0x3d07fd6))>>>((0x321c6570)+(0x41f63af))))), (((-(0x46946993)) ^ ((0x921f24b) / (0x2b6d9f43)))), ((590295810358705700000.0)), ((Math.fround(Math.log((( + Math.hypot(( + x), ( + x))) >>> 0))))), ((-281474976710656.0))))), ((0x1195d39)), ((274877906945.0)), (((+(1.0/0.0)) + (((((1.0078125)) - ((-8388608.0)))) - ((1.888946593147858e+22))))), ((-2048.0)))|0);\n    i1 = (i1);\n    {\nv1 = evaluate(\"v1 = a0.some((function() { try { delete h0.delete; } catch(e0) { } try { for (var p in s2) { p1 = x; } } catch(e1) { } m1.delete(this); return p1; }));\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 == 1), noScriptRval: (x % 10 != 2), sourceIsLazy: new RegExp(\"(?!(?![^]*?[^])*?|[^]|\\\\S|\\\\w^+)\", \"ym\"), catchTermination: (x % 3 != 0) }));    }\n    (x) = ((i1)+(0xc8285209));\n    {\n      i1 = (i1);\n    }\n    return +((7.555786372591432e+22));\n  }\n  return f; })(this, {ff: String.prototype.padEnd}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x07fffffff, 0/0, 1, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53, 2**53+2, -0x080000001, 0x0ffffffff, -0x080000000, 1.7976931348623157e308, 2**53-2, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), -0, -1/0, -0x100000001, -0x100000000, 42, 0, 0x080000001, 0.000000000000001, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-246262462*/count=259; tryItOut("\"use asm\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: x.valueOf(\"number\")}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, ['', ({toString:function(){return '0';}}), (new Boolean(true)), (new Number(-0)), (new Boolean(false)), [], '\\0', 1, 0.1, [0], '/0/', -0, true, false, /0/, ({valueOf:function(){return '0';}}), NaN, (new Number(0)), '0', null, (function(){return 0;}), ({valueOf:function(){return 0;}}), 0, objectEmulatingUndefined(), undefined, (new String(''))]); ");
/*fuzzSeed-246262462*/count=260; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1/0, 0.000000000000001, 0x080000000, -0x080000000, 2**53-2, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 0x080000001, 0x0ffffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, 0/0, -(2**53+2), -(2**53-2), 42, Number.MAX_VALUE, -0x080000001, -1/0, -0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53+2, 0, 1, -0]); ");
/*fuzzSeed-246262462*/count=261; tryItOut("/*MXX3*/g0.DataView.prototype.setUint16 = g0.DataView.prototype.setUint16;");
/*fuzzSeed-246262462*/count=262; tryItOut("\"use strict\"; for (var v of p2) { try { m2 = new WeakMap; } catch(e0) { } f1(m2); }");
/*fuzzSeed-246262462*/count=263; tryItOut("mathy2 = (function(x, y) { return ( + ((Math.hypot(mathy1((Math.imul((( + ( ~ y)) | 0), x) >>> 0), (Math.log1p(( + ( - (0x080000001 >>> 0)))) >>> 0)), ((( ! ( + (Math.min(( + ( ~ (y >>> 0))), ( + y)) >>> 0))) | 0) >>> 0)) >>> 0) > ( + ( + (( + (( - x) != mathy0((y | 0), Math.fround(Math.pow(y, ((0x080000001 | 0) >= y)))))) == (( + ( - (x >>> 0))) | 0)))))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1.5), new Number(1), new Number(1.5), new Number(1.5), new Number(1),  /x/ , new Number(1)]); ");
/*fuzzSeed-246262462*/count=264; tryItOut(" for  each(var c in x) Array.prototype.unshift.apply(a0, [o1.m1, g2.o1, this.s0]);\n\n");
/*fuzzSeed-246262462*/count=265; tryItOut("\"use strict\"; for (var p in m0) { try { a2.length = 9; } catch(e0) { } Object.defineProperty(this, \"this.g1.e0\", { configurable: true, enumerable: (x % 3 != 1),  get: function() {  return new Set(t0); } }); }");
/*fuzzSeed-246262462*/count=266; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.pow(Math.atan2((Math.tanh((Math.sin(Math.asinh(x)) | 0)) | 0), Math.log1p(0x080000001)), (((( + (( + (Math.atan((y | 0)) | 0)) , Math.tan(2**53))) >>> 0) !== ((Math.fround(Math.hypot(((-Number.MIN_VALUE === x) >>> 0), (y & ( + Math.fround(( + x)))))) - Math.fround((Math.fround(( - Math.fround(Math.imul(Math.fround(Number.MAX_SAFE_INTEGER), Math.fround(x))))) , Math.fround(x)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 42, -Number.MIN_VALUE, 0x080000000, 0x0ffffffff, -0x100000001, 0.000000000000001, 2**53-2, 0x100000000, -0x100000000, Number.MAX_VALUE, 0, -0x080000000, -0, -Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), 2**53+2, -0x080000001, -(2**53-2), 0x100000001, -1/0, 1.7976931348623157e308, Math.PI, 0/0, 0x07fffffff, 1/0, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-246262462*/count=267; tryItOut("for (var v of this.i0) { try { v1 = (p0 instanceof i1); } catch(e0) { } try { print(uneval(v0)); } catch(e1) { } a2[window]; }");
/*fuzzSeed-246262462*/count=268; tryItOut("/*RXUB*/var r = /(?=[^]){0}/gyi; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-246262462*/count=269; tryItOut("\"use strict\"; /*hhh*/function mkehja(y){/*RXUB*/var r = /(\\3)/yi; var s = \"_\"; print(s.replace(r, null)); }/*iii*/L:switch(Math.tan(x)) { default: ;i0 = f1;break; case 2: (b);(true);break; case 2: break;  }const w = arguments = Math.atan2(-11, ( \"\" .setUTCMilliseconds([]).valueOf(\"number\")));");
/*fuzzSeed-246262462*/count=270; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=271; tryItOut("o1.v0 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-246262462*/count=272; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ( - ((Math.fround(Math.max((Math.atan2((x | 0), Math.fround(Math.atan2(( ! y), ( ~ -0x080000001)))) | 0), (( + ( + ( ~ y))) | 0))) - (( ~ (y >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [0x07fffffff, -(2**53+2), 0/0, 0x080000000, Number.MIN_VALUE, -0x080000001, -(2**53-2), 1.7976931348623157e308, 2**53, 2**53+2, Math.PI, -0, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, -0x100000001, 0x100000001, 1, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, 2**53-2, -1/0, 0.000000000000001, -0x080000000, 42, -(2**53), 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=273; tryItOut("\"use strict\"; v1 = a1.some((function(j) { if (j) { try { ; } catch(e0) { } try { Object.defineProperty(this, \"v2\", { configurable: (x % 4 != 2), enumerable: true,  get: function() {  return g1.runOffThreadScript(); } }); } catch(e1) { } e2 = new Set(v2); } else { try { for (var v of o2.t1) { try { t1 = new Int8Array(b0, 96, v0); } catch(e0) { } try { b2.toString = (function() { try { function f0(this.i2) /*UUV1*/(eval.indexOf = Set.prototype.keys) } catch(e0) { } v2 = t1.byteLength; return e1; }); } catch(e1) { } print(uneval(b0)); } } catch(e0) { } Array.prototype.pop.apply(a0, [o1.s1, s1, s1]); } }), v2);");
/*fuzzSeed-246262462*/count=274; tryItOut("if(Math.fround(((Math.fround((( + ((Math.fround(( ~ Math.fround(((x - ( ~ x)) | 0)))) < Math.fround(( + Math.round((Math.log10((((1 | 0) % (x >>> 0)) >>> 0)) >>> 0))))) >>> 0)) >>> 0)) >>> 0) ^ ((((Math.log10((( + ( - x)) >>> 0)) >>> 0) % Math.sqrt(((Math.fround(( ~ Math.fround(x))) << Math.fround(Math.fround(Math.max(Math.fround(0.000000000000001), Math.fround(((Math.hypot((0/0 | 0), (x | 0)) | 0) < Math.fround((Math.fround(x) ? Math.fround(0x080000001) : Math.fround(x))))))))) >>> 0))) >>> 0) | 0)))) {/*RXUB*/var r = new RegExp(\"\\\\1(?:.)|^(?=(?!\\\\t))|\\udd44|\\u1542+|\\\\s*\\\\S+{4}|(?=\\\\B)+??|(?=\\\\\\u0b31|[\\\\f-\\udc7d].*|\\\\d*|^\\\\B\\\\1{2}+)\", \"i\"); var s = \"\"; print(r.test(s)); print(r.lastIndex);  } else  if (x) {v2 = (this.m1 instanceof this.s1); } else t1[0] = t2;");
/*fuzzSeed-246262462*/count=275; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! ( + (( + (Math.fround(y) | 0)) ? ( + Math.fround((( + ((((Math.sqrt(y) >>> 0) ? (x >>> 0) : (-0x080000000 >>> 0)) >>> 0) / ( ! ( + Math.fround((Math.fround(1.7976931348623157e308) / Math.fround(y))))))) * ( + Math.fround(Math.tan((x == ((x & x) | 0)))))))) : ( + ((Math.imul(x, Math.min(((y ? x : x) >>> 0), 0/0)) >>> 0) >> ((-1/0 ** Math.log1p(y)) >>> 0)))))); }); testMathyFunction(mathy3, [0.000000000000001, 1, -0x0ffffffff, -(2**53), -0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, 0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53-2), 2**53, 0x0ffffffff, -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000001, 2**53+2, 0/0, 0x080000001, -0, 0x080000000, 0, -0x080000000, -Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, 1/0, -Number.MIN_VALUE, 1.7976931348623157e308, -1/0, -0x080000001]); ");
/*fuzzSeed-246262462*/count=276; tryItOut("if((x % 5 != 3)) v0 = evalcx(\"h1 = {};\", g0.g1); else  if ((4277)) {o0.valueOf = (function() { try { Object.preventExtensions(g0.g1.a0); } catch(e0) { } try { v1 + this.o2; } catch(e1) { } a0 = arguments; return o1; });{print(new RegExp(\"(?=[^]^\\\\S+?)+|(?!\\\\W)+?\", \"yi\"));v2 = g2.eval(\"/* no regression tests found */\"); } } else /* no regression tests found */");
/*fuzzSeed-246262462*/count=277; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xcf6fa151);\n    {\n      d0 = (NaN);\n    }\n    d0 = (-((1099511627775.0)));\n    (Float32ArrayView[4096]) = ((+/*FFI*/ff(((((-0x8000000)*0xce90a) ^ ((/*FFI*/ff()|0)))), ((~~(549755813889.0))), ((-281474976710657.0)), ((~(((((i1)) << ((0x1de3cf7c) % (0xfcf5320))))))), ((+((-4611686018427388000.0)))))));\n    i1 = ((0xffffffff));\n    return +((-1.25));\n  }\nfor (var v of b0) { try { /*MXX3*/g2.String.prototype.blink = g1.g1.String.prototype.blink; } catch(e0) { } h1.enumerate = f0; }function y(c, window = intern(-1).yoyo([undefined]), c, a, x, d, x, let, x, x, window = \"\\u330C\", x, \u3056, window, x, x, x =  \"\" , window = /$|(?=$)\\d+/gi, \u3056, w = \"\\uB68C\", x, this.this.x = \"\\u1C80\", d, z =  /x/ , eval = x, x, x,  , let, eval = \"\\u1AF9\", x, x = ({a1:1}), z = c, x, c, window, get, b, c, z, x =  /x/ , x, NaN, \u3056, window, window = this, a, x, x = new RegExp(\"(?=[^\\u00f7])(?:(?:(?:.)+?|(?!\\u00dd)?){0,})\", \"ym\"), x, a = new RegExp(\"\\\\2\", \"gym\"), e, z, b, x, \u3056, window, NaN = \"\\u3103\", \u3056, z, y, e, y, x, x, c, NaN, x, x, d) { return x } print(m2);\n  return f; })(this, {ff: (Math.expm1).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53-2), 0x080000001, 2**53, 0x0ffffffff, -0, -0x080000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, 1, 2**53-2, 0, -0x080000001, 1.7976931348623157e308, 1/0, Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -1/0, -(2**53+2), -0x07fffffff, -0x100000001, -0x100000000, 0x07fffffff, 0.000000000000001, -0x0ffffffff, 0x080000000, -Number.MAX_VALUE, 42, -Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-246262462*/count=278; tryItOut("\"use strict\"; ( \"\" );\np1.toString = (function() { try { t1.set(a0, 13); } catch(e0) { } g2.m2.delete(o2); return g0.g1; });\nObject.defineProperty(this, \"v0\", { configurable: true, enumerable: this,  get: function() {  return a2.reduce, reduceRight(); } });");
/*fuzzSeed-246262462*/count=279; tryItOut("g1.m1.get(this.f1);");
/*fuzzSeed-246262462*/count=280; tryItOut("\"use strict\"; this.a2.shift(v2, i2, s1, g0);\no1.s2 + '';\n");
/*fuzzSeed-246262462*/count=281; tryItOut("\"use strict\"; /*MXX2*/g1.Math.sinh = g0;");
/*fuzzSeed-246262462*/count=282; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (((Math.hypot(( + Math.imul((x ? ( + y) : Math.min(Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE)), Math.min((Math.log1p(x) | 0), Math.fround(( - y))))), ( + ( + Math.atan2(Math.fround(Math.min((0x080000000 >>> 0), ((Math.atan2((Number.MIN_SAFE_INTEGER >>> 0), y) >>> 0) >>> 0))), Math.fround((Math.fround((((Math.min((x >>> 0), (x >>> 0)) >>> 0) >>> 0) | (( + ((y >>> 0) >>> (y | 0))) >>> 0))) + y)))))) >>> 0) != ((0x0ffffffff % x) - Math.fround((Math.fround(Math.pow(Math.asinh(-(2**53+2)), Math.min(Number.MIN_SAFE_INTEGER, ( + Math.atan2(x, x))))) >= Math.fround((Math.exp(( + x)) | 0)))))) > ( + ( - (( ! ( ~ -0x080000000)) | 0)))); }); testMathyFunction(mathy0, [-1/0, 2**53+2, 2**53-2, 0/0, 2**53, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, -0x100000000, Math.PI, -(2**53+2), 0x080000000, -0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, Number.MAX_VALUE, -0x080000001, -(2**53), 42, -0x100000001, 0x100000001, -(2**53-2), 0.000000000000001, 1, 1/0, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-246262462*/count=283; tryItOut("print(x);");
/*fuzzSeed-246262462*/count=284; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( ~ (Math.clz32(( + Math.fround((Math.fround(Math.log1p(y)) - Math.fround(y))))) | 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53+2), -0, 1.7976931348623157e308, 0, -(2**53), -Number.MAX_SAFE_INTEGER, 42, 0x100000001, Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -0x080000001, -1/0, 0/0, 0x080000000, Math.PI, -0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, 1, 0x100000000, 0x0ffffffff, 1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 2**53+2, -Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-246262462*/count=285; tryItOut("\"use strict\"; for(var [x, c] = Math.asinh(x) in x) {/*RXUB*/var r = r0; var s = g2.s2; print(r.exec(s));  }");
/*fuzzSeed-246262462*/count=286; tryItOut("/*RXUB*/var r = /.?/yi; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-246262462*/count=287; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-246262462*/count=288; tryItOut("{let (z\u000c) { print(this); }h2.enumerate = (function() { for (var j=0;j<61;++j) { f1(j%4==1); } }); }");
/*fuzzSeed-246262462*/count=289; tryItOut("\"use strict\"; v2 = Array.prototype.reduce, reduceRight.apply(a1, [Object.getOwnPropertyDescriptors.bind(a2), i2]);");
/*fuzzSeed-246262462*/count=290; tryItOut("mathy1 = (function(x, y) { return (( + (( ! (mathy0(x, Math.fround(Math.log2(x))) | 0)) >>> 0)) | 0); }); testMathyFunction(mathy1, [-0x0ffffffff, 2**53+2, 0x07fffffff, 0.000000000000001, 1/0, Number.MIN_VALUE, -0x080000001, -0, 0, -0x100000001, 0/0, Math.PI, 1.7976931348623157e308, 0x100000001, Number.MAX_VALUE, 0x080000001, 0x080000000, -(2**53-2), -(2**53+2), 0x100000000, -0x07fffffff, 2**53, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, -1/0, -0x080000000, 1, 42, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=291; tryItOut("\"use strict\"; g2.v2 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-246262462*/count=292; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log2(Math.max(Math.fround(( ~ ( + ( - Math.fround(42))))), Math.log10((x >>> 0)))); }); testMathyFunction(mathy1, [2**53-2, -0, -0x080000000, 0x100000000, 1.7976931348623157e308, Math.PI, -0x0ffffffff, -Number.MIN_VALUE, -(2**53-2), 1/0, 0x080000001, 0x07fffffff, Number.MIN_VALUE, -0x100000001, -0x100000000, -(2**53+2), 0x100000001, 2**53+2, -Number.MAX_VALUE, 0.000000000000001, 1, 0/0, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 0, -(2**53), -0x080000001, 0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-246262462*/count=293; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-246262462*/count=294; tryItOut("this.m0.set(e2, p2);");
/*fuzzSeed-246262462*/count=295; tryItOut("\"use strict\"; m0.get(g0);");
/*fuzzSeed-246262462*/count=296; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    d0 = ((d0) + (+(1.0/0.0)));\n    return (((0xffe6c9e4)))|0;\n  }\n  return f; })(this, {ff: (x = \u3056)}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[ '\\0' , new String('q'),  /x/g ,  '\\0' , (void 0), new String('q'), new String('q'),  /x/g ,  '\\0' , (void 0), (void 0), (void 0),  /x/g , new String('q'),  /x/g , (void 0),  '\\0' ,  '\\0' , new String('q'), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new String('q'), new String('q'),  '\\0' ,  '\\0' , new String('q'),  /x/g ,  /x/g , (void 0),  '\\0' , (void 0),  '\\0' ,  '\\0' , new String('q'), (void 0),  '\\0' , (void 0),  /x/g ,  /x/g , (void 0)]); ");
/*fuzzSeed-246262462*/count=297; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( ~ (( - (Math.min(( - y), ( + Math.hypot(x, Math.log10((x >>> 0))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [[], true, 0.1, '/0/', (new Number(0)), (new Number(-0)), false, NaN, objectEmulatingUndefined(), ({toString:function(){return '0';}}), '', ({valueOf:function(){return '0';}}), '0', 1, '\\0', -0, [0], (new String('')), ({valueOf:function(){return 0;}}), 0, (new Boolean(false)), (new Boolean(true)), null, /0/, undefined, (function(){return 0;})]); ");
/*fuzzSeed-246262462*/count=298; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.round(( ! (((( + Math.fround(y)) | 0) == (Math.atan2(y, Math.log10(Math.fround(mathy2(( + -0), Math.fround(mathy1(x, -0x080000000)))))) | 0)) | 0))); }); testMathyFunction(mathy5, [0x080000001, 0x100000001, 1/0, -Number.MAX_VALUE, -0x0ffffffff, 2**53+2, -0x080000001, -(2**53+2), -0x07fffffff, 0x080000000, -1/0, -0x100000001, 0x100000000, -(2**53-2), Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, Number.MAX_VALUE, 0, -0x080000000, 2**53-2, 0x0ffffffff, -0x100000000, 0/0, Number.MAX_SAFE_INTEGER, -0, 1, 0.000000000000001, 42, -Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-246262462*/count=299; tryItOut("testMathyFunction(mathy3, [(new Boolean(false)), -0, 0, ({toString:function(){return '0';}}), (new Boolean(true)), '0', (function(){return 0;}), 0.1, ({valueOf:function(){return 0;}}), /0/, (new Number(-0)), NaN, undefined, [0], (new String('')), '\\0', 1, null, [], '/0/', '', true, ({valueOf:function(){return '0';}}), false, objectEmulatingUndefined(), (new Number(0))]); ");
/*fuzzSeed-246262462*/count=300; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float32ArrayView[1]) = ((d0));\n    d0 = (+abs(((Float64ArrayView[((/*FFI*/ff(((((0x54865bc7)) | ((i1)*0x5c704))), ((((Math.imul((4277), 19))) ^ (((72057594037927940.0) <= (513.0))-((0x412249a5) ? (0x65645767) : (0xadd10f9b))))), ((~~(d0))), ((((i1)) >> (((0xfdde222e) ? (0xfc4f9a15) : (0x295e7a64))))), ((({}))))|0)) >> 3]))));\n    return ((((((!(i1))) & (((+(-0x8000000)) != (1.0078125))+(i1))))+(0x8f6b042b)))|0;\n  }\n  return f; })(this, {ff: Math.sinh}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -0x07fffffff, -0x0ffffffff, 0x080000001, -0x080000000, -(2**53+2), 0x100000000, -0, 0.000000000000001, -(2**53), 0, Number.MIN_VALUE, 2**53, 2**53+2, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), -0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 1, 42, 0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0x080000000, 0/0, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=301; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (mathy3((mathy1(mathy3(Math.fround(Math.fround(Math.sinh(((Math.abs(y) | 0) >> Math.pow(x, (Math.tanh((x >>> 0)) | 0)))))), Math.fround((((Math.atan2((mathy0(-0x080000000, (Number.MIN_VALUE | 0)) | 0), ( + (mathy3((y >>> 0), -0x07fffffff) >>> 0))) | 0) ? (y | 0) : (Math.pow(Math.fround(0x080000001), y) | 0)) | 0))), (((x >>> 0) , ( + mathy2(Math.fround(0x100000000), ( + Math.imul(Math.min((y == 2**53), 2**53-2), Math.fround(Math.cosh(Math.fround(0x080000001)))))))) >>> 0)) | 0), (Math.fround(((Math.hypot((Number.MAX_VALUE | 0), Math.sinh((( ~ y) >>> 0))) | 0) >= Math.tanh(Math.fround(( + Math.fround((( + y) > y))))))) === Math.clz32((( - y) >>> 0)))) | 0); }); ");
/*fuzzSeed-246262462*/count=302; tryItOut("\"use strict\"; /*bLoop*/for (var mcgzxu = 0; mcgzxu < 3; ++mcgzxu) { if (mcgzxu % 6 == 4) { b;m2.has(this.i0); } else { /*ADP-3*/Object.defineProperty(a0, 12, { configurable: NaN, enumerable: new \"\\u8E0D\"(), writable: (x % 3 != 1), value: \"\\uEC22\" &= /(\\D|(?=(?=(?!.)))*)/yim }); }  } ");
/*fuzzSeed-246262462*/count=303; tryItOut("\"use strict\"; g1.v1 = a1.length;");
/*fuzzSeed-246262462*/count=304; tryItOut("\"use strict\"; v2 = b0.byteLength;");
/*fuzzSeed-246262462*/count=305; tryItOut("/*vLoop*/for (vtutia = 0, e, ++a; vtutia < 6; ++vtutia, Int32Array) { let e = vtutia; print(((function sum_slicing(pezhsl) { ; return pezhsl.length == 0 ? 0 : pezhsl[0] + sum_slicing(pezhsl.slice(1)); })(/*MARR*/[-0x5a827999, -0x5a827999, new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, new Boolean(false), new Boolean(false), -0x5a827999, -0x5a827999, new Boolean(false), -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, -0x5a827999, new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, -0x5a827999, new Boolean(false), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(false), new Boolean(false), -0x5a827999, -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, new Boolean(false), -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, new Boolean(false), -0x5a827999, new Boolean(false), new Boolean(false), new Boolean(false), -0x5a827999, -0x5a827999]))); } ");
/*fuzzSeed-246262462*/count=306; tryItOut("\"use strict\";  /x/ ;");
/*fuzzSeed-246262462*/count=307; tryItOut("(function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })");
/*fuzzSeed-246262462*/count=308; tryItOut("\"use strict\"; mathy0 = /*MARR*/[objectEmulatingUndefined(), true, objectEmulatingUndefined(), true, true, true, objectEmulatingUndefined()]; testMathyFunction(mathy0, [-(2**53), 0x080000000, 0/0, 0, -0x080000000, -0, 0x07fffffff, -Number.MIN_VALUE, -0x080000001, Number.MIN_VALUE, 2**53+2, 0x100000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 1, 2**53-2, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000000, -0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, Math.PI, 0x080000001, 0x100000001, -1/0, 2**53, -(2**53+2), 42, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=309; tryItOut("mathy0 = (function(x, y) { return ( ! ( - ((((Math.min((Math.tan((Math.log((x >>> 0)) >>> 0)) | 0), y) >>> 0) | 0) >> (( + Math.clz32(( + x))) | 0)) | 0))); }); testMathyFunction(mathy0, [0/0, 0x080000000, 0x080000001, Number.MAX_VALUE, -0x100000000, -0x07fffffff, 1, -Number.MAX_VALUE, -0x0ffffffff, 2**53+2, 0, 0x100000000, Math.PI, -1/0, 0.000000000000001, -0, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), 42, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001, 0x0ffffffff, -0x080000001, 2**53, Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, 1/0, 1.7976931348623157e308]); ");
/*fuzzSeed-246262462*/count=310; tryItOut("\"use strict\"; Array.prototype.reverse.call(a1, o1.f2);");
/*fuzzSeed-246262462*/count=311; tryItOut("o0.v2 = this.t1[0];");
/*fuzzSeed-246262462*/count=312; tryItOut("mathy1 = (function(x, y) { return (((Math.pow((( - ((mathy0((x >>> 0), ((Math.imul((y >>> 0), Math.cosh(Number.MIN_VALUE)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0), (( ~ Math.fround((( ~ x) >>> 0))) ** Math.imul(x, Math.fround(x)))) | 0) !== Math.fround((( - ((((x | 0) % (Math.fround(mathy0(x, (Math.fround(x) & Math.fround(x)))) | 0)) | 0) | 0)) | 0))) | 0); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -Number.MAX_VALUE, 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, Math.PI, -0, 0x080000001, -Number.MIN_VALUE, 1/0, 0x080000000, 42, Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 2**53, -0x0ffffffff, 0x100000001, -(2**53), 1, -0x100000000, -0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), 0x100000000, -1/0, 0x07fffffff, 0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-246262462*/count=313; tryItOut("testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 0.000000000000001, -Number.MAX_VALUE, -0, 2**53+2, -(2**53), 0, 2**53-2, -0x080000000, -Number.MIN_VALUE, -0x0ffffffff, 1/0, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER, 1, 2**53, -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, 42, 0x080000000, Number.MAX_VALUE, -0x100000000, -0x07fffffff, 1.7976931348623157e308, 0/0, -0x100000001, -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0]); ");
/*fuzzSeed-246262462*/count=314; tryItOut("mathy3 = (function(x, y) { return Math.atanh(Math.atan2(Math.hypot((( + ( ~ (( + mathy0(( + 0x080000001), ( + -Number.MIN_SAFE_INTEGER))) | 0))) | 0), (x >>> 0)), Math.imul(( ~ ((Math.max(0x080000000, y) < x) | 0)), ( + ( + ( + ((( + y) - ( + y)) > 0x080000000))))))); }); testMathyFunction(mathy3, [0, null, [], (function(){return 0;}), ({valueOf:function(){return '0';}}), 0.1, (new Boolean(true)), '\\0', -0, '/0/', 1, false, /0/, true, '0', (new String('')), ({valueOf:function(){return 0;}}), (new Boolean(false)), ({toString:function(){return '0';}}), (new Number(-0)), [0], undefined, NaN, objectEmulatingUndefined(), '', (new Number(0))]); ");
/*fuzzSeed-246262462*/count=315; tryItOut("mathy2 = (function(x, y) { return (Math.min((Math.fround(( - Math.hypot(((mathy1(y, y) / y) | 0), y))) >>> 0), (Math.cbrt(( ~ Math.log1p((y | 0)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-246262462*/count=316; tryItOut("\"use strict\"; for(a in (x = false)) {g1.v0 = Object.prototype.isPrototypeOf.call(e0, p0);var gqhfjh = new ArrayBuffer(0); var gqhfjh_0 = new Float32Array(gqhfjh); gqhfjh_0[0] = 11; ( /x/g ); }");
/*fuzzSeed-246262462*/count=317; tryItOut("/*RXUB*/var r = r1; var s = o2.s0; print(s.replace(r, 'x')); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=318; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.min(( + ( ! (Math.max((Math.atan2(x, Math.fround(Math.log10(Math.fround(x)))) >>> 0), ( + (Math.fround(( ! Math.exp(2**53))) , ( + (Math.clz32(-0x080000001) !== Math.imul(y, y)))))) >>> 0))), Math.log2((y == (( ~ x) | 0)))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000001, -Number.MAX_VALUE, 1/0, -(2**53), -0x080000000, -0x100000000, 0x100000000, 42, 0x0ffffffff, -0x100000001, -(2**53-2), 2**53, 0x100000001, -0x0ffffffff, 0x080000001, -(2**53+2), 2**53+2, Math.PI, -0, 0x07fffffff, 0/0, 0.000000000000001, -1/0, 0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-246262462*/count=319; tryItOut("for (var p in s0) { try { g1 + this.o2.o2.h1; } catch(e0) { } try { a2[x] = (this !=  '' )(x, this.__defineSetter__(\"x\", function  z (x)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((i0)))|0;\n  }\n  return f;)).yoyo(([] = a |= e)); } catch(e1) { } try { a0.forEach((function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -34359738369.0;\n    d1 = (d1);\n    d1 = (d2);\n    return (((abs((abs(((((Float64ArrayView[((0xfab24c9b)-(0xfed35027)) >> 3])) % ((-(0xfd5884e8)) << (((0x64d45439) == (0x56f5a3c1)))))|0))|0))|0) % (((0xf92fc6d9)) | (-((0xba067ed0) < (((0xe48f3eb3)*0xced0e)>>>((0xdf865d65))))))))|0;\n  }\n  return f; })); } catch(e2) { } e2 + s1; }");
/*fuzzSeed-246262462*/count=320; tryItOut("v1 = evaluate(\"/*RXUB*/var r = r1; var s = s0; print(s.match(r)); \", ({ global: o0.g0, fileName: null, lineNumber: 42, isRunOnce: \nnew (x) = new RegExp(\"(?:[\\\\n])|(?!\\\\2|(?:[^]){2,4})*\", \"gyi\")(c =  '' ), noScriptRval: Math.tan(15), sourceIsLazy: false, catchTermination: (x % 10 == 8), element: o1, elementAttributeName: s0, sourceMapURL: s0 }));");
/*fuzzSeed-246262462*/count=321; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.imul((((Math.acosh(( + Math.max(( + -Number.MAX_VALUE), Math.fround((Math.fround(y) ^ Math.fround(x)))))) | 0) + ( + (Math.cbrt((Math.min(Math.fround(-Number.MIN_SAFE_INTEGER), Math.fround(Math.imul(Math.fround(x), Math.fround(y)))) | 0)) | 0))) >>> 0), (Math.atan2(( + (Math.pow(Math.log(( + y)), Math.min(y, (Math.ceil((Number.MIN_SAFE_INTEGER >>> 0)) >>> 0))) | 0)), ( + Math.min(Math.fround(Math.max(x, x)), ( + ((Number.MIN_SAFE_INTEGER != y) ? ( - y) : -Number.MIN_VALUE))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x080000000, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), -0x100000000, 0x080000001, Number.MIN_VALUE, -0, -0x0ffffffff, 2**53, -Number.MAX_SAFE_INTEGER, 0, 0x100000001, -1/0, Number.MAX_VALUE, 1/0, 0.000000000000001, Math.PI, 1.7976931348623157e308, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0/0, -(2**53), -0x07fffffff, 2**53-2, -0x080000000, 42, -0x080000001, -0x100000001, 0x0ffffffff, -Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-246262462*/count=322; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -18446744073709552000.0;\n    var d3 = 16384.0;\n    var d4 = -4398046511103.0;\n    var d5 = 129.0;\n    var i6 = 0;\n    return +((d3));\n  }\n  return f; })(this, {ff: arguments.callee}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000001, 0x07fffffff, -(2**53), 1, Number.MIN_SAFE_INTEGER, 0/0, -0, Number.MAX_VALUE, -0x100000000, 2**53-2, 42, 2**53, -1/0, 1/0, 2**53+2, -(2**53+2), -0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -(2**53-2), -0x100000001, Math.PI, 0.000000000000001, 0, -Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=323; tryItOut("\"use strict\"; for (var p in g0.o1.o1) { try { Array.prototype.reverse.call(a0); } catch(e0) { } try { Object.defineProperty(this, \"v0\", { configurable: (yield Array(null, -28)) && ((p={}, (p.z = arguments)())), enumerable: true,  get: function() {  return Array.prototype.reduce, reduceRight.apply(a0, [(function() { try { print(uneval(e0)); } catch(e0) { } o0.valueOf = f0; return i0; }), a2]); } }); } catch(e1) { } ; }");
/*fuzzSeed-246262462*/count=324; tryItOut("testMathyFunction(mathy2, [-(2**53-2), -0x080000001, -0, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, -0x07fffffff, 1/0, 2**53, 0x0ffffffff, 2**53-2, -0x100000000, 0.000000000000001, -(2**53+2), Math.PI, -Number.MIN_VALUE, -0x100000001, 42, 0/0, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, 0x07fffffff, -0x080000000, 0x100000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, 0, -(2**53), 2**53+2]); ");
/*fuzzSeed-246262462*/count=325; tryItOut("for (var p in g1.o1) { try { /*MXX3*/g1.Number.MIN_SAFE_INTEGER = this.g2.Number.MIN_SAFE_INTEGER; } catch(e0) { } for (var p in v1) { try { v0 = a1.reduce, reduceRight((function(j) { if (j) { f1.__proto__ = i0; } else { try { h2.__proto__ = b2; } catch(e0) { } try { a1 = arguments; } catch(e1) { } try { print(e1); } catch(e2) { } a0[14] = o0.s2; } }), o2, (x--.valueOf(\"number\") >= (4277))); } catch(e0) { } try { g0.t2.set(t1, v1); } catch(e1) { } for (var v of a0) { try { this.a2.__proto__ = this.g0; } catch(e0) { } o1.v0.toString = (function() { Array.prototype.shift.call(a2, o2.s1, f1); return g1; }); } } }");
/*fuzzSeed-246262462*/count=326; tryItOut("mathy4 = (function(x, y) { return ( + Math.cos(( + Math.fround(Math.atan2((Math.tan(Math.fround(x)) | 0), ((Math.fround(( ! Math.fround((Math.acosh(((mathy0(2**53, (( + (x | 0)) | 0)) >>> 0) >>> 0)) | 0)))) <= ((((( + mathy0(( + x), y)) | 0) * (Math.pow(Number.MAX_SAFE_INTEGER, ( + (Number.MAX_SAFE_INTEGER ^ -(2**53)))) | 0)) | 0) >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-246262462*/count=327; tryItOut("/*RXUB*/var r = /\\w[^]*?.?|[^\\d\uc352-\\xcB\\x01-1]{0}|(?:(.[\\xE2-\\~\u0004-\u0014])){2,}(?!\\1|\\S*|.(?:^))|\\B|[^](\\3?)(?:(?:([\\b\ub59f])))|[\\S\\W\u00d5\\W]|(?![\\xC0\\\ucb58-\\uB3f6]|\\b\\3|(\\B)|.\\B)(?:\\u00dE+?([^\\\u0002])*+?)?|[^]((?=${2,}))*?*/; var s = \"I\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\\u0002\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=328; tryItOut("\"use strict\"; Object.defineProperty(o2, \"v2\", { configurable: this, enumerable: true,  get: function() { o1.o0 = {}; return t2.BYTES_PER_ELEMENT; } });");
/*fuzzSeed-246262462*/count=329; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.cos(Math.fround(Math.cbrt(Math.fround(( - Math.hypot(((x | x) | 0), x)))))); }); testMathyFunction(mathy1, [-0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, -0, -0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, Math.PI, 1/0, Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, -0x100000000, 0x07fffffff, 2**53-2, 0x080000000, -Number.MIN_VALUE, -1/0, 0, 0.000000000000001, -(2**53-2), -(2**53+2), 0x100000001, Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, 2**53+2, 0x100000000, 2**53]); ");
/*fuzzSeed-246262462*/count=330; tryItOut("this.h0.set = f0;");
/*fuzzSeed-246262462*/count=331; tryItOut("mathy3 = (function(x, y) { return Math.pow(Math.min(Math.log2(Math.pow(x, ( - 0x100000001))), ( + ( + ((y >>> 0) != Math.sinh(((mathy1((-0x080000000 >>> 0), (x | 0)) | 0) >>> 0)))))), Math.fround((Math.sqrt((Math.fround(( - (( ~ (( ~ (-0 | 0)) | 0)) >>> 0))) | 0)) | 0))); }); ");
/*fuzzSeed-246262462*/count=332; tryItOut("\"use strict\"; h2 + m0;");
/*fuzzSeed-246262462*/count=333; tryItOut("mathy1 = (function(x, y) { return ((x) = (eval(\"/* no regression tests found */\", new RegExp(\"$\\\\s+\", \"yim\").throw({})))); }); testMathyFunction(mathy1, [0.1, '0', '\\0', ({valueOf:function(){return 0;}}), (new Boolean(false)), true, undefined, (new Number(-0)), (new Number(0)), /0/, (new String('')), ({valueOf:function(){return '0';}}), [], (new Boolean(true)), [0], ({toString:function(){return '0';}}), '/0/', objectEmulatingUndefined(), null, 1, (function(){return 0;}), false, NaN, 0, '', -0]); ");
/*fuzzSeed-246262462*/count=334; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.hypot(( ! (y <= ( - y))), mathy1(( + (( + Math.fround(mathy1(Math.atan2(Math.fround((Math.log1p(( + (Math.min((-0x0ffffffff | 0), (x | 0)) | 0))) | 0)), x), Math.fround(Math.fround(( ~ Math.fround((Math.ceil(x) | 0)))))))) + ( + mathy2(( + x), ( + (y !== x)))))), (Math.hypot((((Math.fround(Math.hypot(y, Math.fround(( - x)))) | 0) << ((x >= y) > Number.MAX_VALUE)) | 0), (((((Math.atan2(Math.cbrt(x), x) | 0) | 0) ^ ((Math.log10(y) ? (y >>> 0) : y) >>> 0)) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0x080000000, -1/0, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, Math.PI, 1, -(2**53), 2**53, 0x100000001, -(2**53+2), 2**53-2, 0, -0x080000000, -(2**53-2), 1.7976931348623157e308, 0/0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 0x07fffffff, -0x080000001, Number.MAX_VALUE, -0x100000001, 42, 0.000000000000001, 0x0ffffffff, 0x080000001, -0x07fffffff, Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-246262462*/count=335; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return Math.atanh(( - Math.fround(( + ( + (Math.max(((y | 0) < (y | 0)), y) >>> (Math.imul((Math.log2(( + Math.max(x, ( + x)))) | 0), Math.fround(y)) | 0))))))); }); testMathyFunction(mathy2, [-0x100000001, 0.000000000000001, 0x100000000, -(2**53-2), 1, 2**53-2, 0/0, -1/0, Number.MIN_VALUE, -0x0ffffffff, 2**53+2, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, 0x07fffffff, 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, -(2**53), -Number.MIN_VALUE, Math.PI, 0x080000001, 1.7976931348623157e308, 0x100000001, -0x080000001, 0]); ");
/*fuzzSeed-246262462*/count=336; tryItOut("mathy4 = (function(x, y) { return ( + Math.min(( + ( + ( + ( + (Math.fround(( + ( + x))) ^ (Math.ceil(((((( + Number.MAX_VALUE) / ( + ((-0 % x) >>> 0))) | 0) % Math.fround((x === x))) >>> 0)) | 0)))))), ( + ( + (( + Math.asinh(Math.cos(x))) % ( + ( - ( + Math.fround(Math.acos(Math.fround(( ~ 2**53)))))))))))); }); testMathyFunction(mathy4, [42, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53, 2**53+2, 1/0, -Number.MAX_VALUE, 0, -0x100000001, 0x100000001, 0x080000000, 0/0, -(2**53), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, 1, -(2**53+2), -0x100000000, -Number.MIN_VALUE, -(2**53-2), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, -0x080000001, 2**53-2, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 0x07fffffff, -0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-246262462*/count=337; tryItOut("function shapeyConstructor(wrlkbb){\"use strict\"; for (var ytqawrysz in wrlkbb) { }delete wrlkbb[0];if (this) Object.freeze(wrlkbb);if (Math.hypot(w = Proxy.create(({/*TOODEEP*/})(/(?=[^]*?){2,}/gy), \"\\uAD20\"), 8)) Object.freeze(wrlkbb);wrlkbb[0] = (void shapeOf((4277)));for (var ytqxoktfa in wrlkbb) { }if ( '' ) Object.defineProperty(wrlkbb, true, ({}));Object.defineProperty(wrlkbb, 0, ({set: mathy1, configurable: true}));if (((void options('strict_mode')))) delete wrlkbb[0];for (var ytqxwgstp in wrlkbb) { }return wrlkbb; }/*tLoopC*/for (let z of /*FARR*/[(uneval(/(?:(?:[v\\u0053])|[^\\S\\xF9][^'-\\u001A\\x75\\r-\ud41d\\u6c0A-\u9dbc](?=^){0,4}|(?:[\u00d1\ue6b7\\dG-\\u1a63]){3,4}|(?=\\W))/ym)), ((new Function(\"continue ;\"))).call(-16,  '' ).throw(let (x) window), , , .../*FARR*/[]]) { try{let pwhvwb = shapeyConstructor(z); print('EETT'); -0;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-246262462*/count=338; tryItOut("\"use asm\"; for (var v of g2) { try { print(uneval(i0)); } catch(e0) { } s2 += 'x'; }");
/*fuzzSeed-246262462*/count=339; tryItOut("r2 = /(?=\\3^+)/yim;");
/*fuzzSeed-246262462*/count=340; tryItOut("if((x % 5 != 1)) for (var p in e1) { try { m1.delete(e2); } catch(e0) { } try { for (var p in o2) { try { a0 + ''; } catch(e0) { } for (var v of a1) { for (var p in g0) { try { s1.toString = (function mcc_() { var zecfsu = 0; return function() { ++zecfsu; f1(/*ICCD*/zecfsu % 3 == 2);};})(); } catch(e0) { } try { this.i1.__proto__ = b1; } catch(e1) { } try { v1 = g2.runOffThreadScript(); } catch(e2) { } v0 = 0; } } } } catch(e1) { } s1 += s2; } else  if (Math.min(10, 2)) with(22)throw  '' ;");
/*fuzzSeed-246262462*/count=341; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.sin(Math.sqrt((y < mathy1(x, y)))); }); ");
/*fuzzSeed-246262462*/count=342; tryItOut("function o2.f2(m2) ((this.__defineSetter__(\"m2\", Promise.prototype.catch)) for (eval of new Array(-19)) for each (\u3056 in []) for (m2 of []) for each (x in []))");
/*fuzzSeed-246262462*/count=343; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.sinh(( - (Math.min((x ** (Math.max(0x100000000, (Math.clz32((x | 0)) | 0)) | 0)), (2**53+2 | 0)) ? (Math.trunc((y >>> 0)) >>> 0) : ( + Math.atan(x)))))); }); testMathyFunction(mathy1, [0x080000001, -(2**53-2), -(2**53), 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, 2**53, 2**53-2, Number.MAX_VALUE, 0, 1, 0x07fffffff, 42, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 0x080000000, Math.PI, -Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, -1/0, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, 0x100000000, 2**53+2, -0x100000001]); ");
/*fuzzSeed-246262462*/count=344; tryItOut("mathy2 = (function(x, y) { return ( + (( + Math.pow(( + Math.pow(( + y), Math.exp(y))), (mathy0(Math.atan2((Math.max((y * x), ( + (y ? x : Math.fround(x)))) >>> 0), ( + -0x0ffffffff)), -Number.MAX_SAFE_INTEGER) >>> 0))) !== ( + (Math.sinh((( + Math.imul(( + ( + ( ~ ( + ( + mathy0((x !== x), 1)))))), ( + ( + Math.imul(-0x07fffffff, (((y >>> 0) >> (x >>> 0)) >>> 0)))))) | 0)) | 0)))); }); ");
/*fuzzSeed-246262462*/count=345; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.cbrt(Math.fround(mathy0(((mathy2(0x0ffffffff, Math.fround(Math.clz32(x))) && ( + (y / ( + y)))) && Math.fround(( + Math.atan2(( + y), Math.hypot(( + ( - ( + x))), y))))), Math.hypot(x, y))))); }); testMathyFunction(mathy3, [0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, -Number.MAX_VALUE, -0x100000000, 2**53+2, 2**53-2, 0/0, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0, -0x080000000, -0, 1/0, 2**53, 0x07fffffff, 0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, 42, Number.MAX_VALUE, 1.7976931348623157e308, 1, -(2**53-2), -0x0ffffffff, 0x100000001, -0x07fffffff, 0x080000000, 0x100000000]); ");
/*fuzzSeed-246262462*/count=346; tryItOut("\"use strict\"; /*iii*/var r0 = 6 | x; nlfahm = nlfahm - 6; var r1 = 2 | 4; r0 = 0 * r0; var r2 = r1 | 9; var r3 = x & 0; r1 = r0 % r2; var r4 = 9 - 7; var r5 = r0 + r3; x = 8 / 5; var r6 = 2 % x; var r7 = 0 % r1; var r8 = 4 / r4; r7 = 8 % r2; var r9 = 1 / r5; var r10 = 5 * 3; var r11 = 1 * nlfahm; var r12 = 4 + 4; var r13 = r11 + r2; var r14 = nlfahm - r13; var r15 = 8 ^ r4; var r16 = r15 + r14; var r17 = r4 * 8; r1 = r10 | 3; var r18 = 4 & 8; print(r11); var r19 = r11 - r15; r11 = nlfahm - 2; print(r15); r7 = 7 ^ x; var r20 = 4 | 3; var r21 = r4 % r15; var r22 = 1 | 6; r18 = nlfahm | 7; var r23 = r20 + r19; var r24 = r22 * r12; var r25 = r12 / r20; var r26 = 3 / r20; var r27 = 7 ^ 8; var r28 = r12 + r5; var r29 = 2 * r16; r22 = r3 / 6; var r30 = r21 / x; var r31 = r20 / 0; print(r22); var r32 = r2 % 9; r30 = 6 % r8; var r33 = r12 ^ 8; var r34 = 8 ^ r3; var r35 = r13 | 4; r30 = r31 & r25; var r36 = 6 * r6; var r37 = 4 | 0; var r38 = r3 % r29; var r39 = 3 % 2; var r40 = 1 | r23; var r41 = r9 + r3; var r42 = r33 ^ 9; var r43 = r32 - r8; var r44 = 4 + r40; r5 = r29 ^ 8; var r45 = 2 | 4; var r46 = 1 % r29; var r47 = 5 * r37; var r48 = 3 & 7; var r49 = r7 ^ r32; var r50 = r19 - r37; r12 = 6 % r50; var r51 = r37 * r27; print(r26); var r52 = 7 * r18; var r53 = r31 & r46; var r54 = r19 & r49; var r55 = r1 * 2; var r56 = r31 - r0; var r57 = r43 * r19; r55 = 8 - r28; var r58 = r47 % r8; var r59 = 1 - r35; var r60 = 5 - r46; var r61 = r47 % r26; var r62 = 3 | r10; var r63 = r32 * 7; x = 6 + r29; r12 = r17 / r62; var r64 = 1 * r40; var r65 = r56 * nlfahm; var r66 = 0 / r10; var r67 = r50 / 2; r46 = r18 ^ r63; var r68 = r47 | r10; var r69 = r3 - r63; var r70 = r29 & 5; var r71 = r27 * r1; var r72 = r25 % 2; r39 = 7 % 6; var r73 = r27 + r45; print(r39); var r74 = r37 ^ 2; print(r31); var r75 = r26 + 7; var r76 = r63 ^ r15; var r77 = 7 ^ 9; var r78 = r26 + 6; var r79 = 2 + r3; var r80 = 8 ^ r50; var r81 = 6 / r19; var r82 = 4 ^ r49; r62 = 5 + r53; var r83 = r80 * 5; print(r35); var r84 = 8 & r21; var r85 = r8 * r54; r34 = r72 / r28; var r86 = r56 ^ 3; var r87 = r26 | r45; var r88 = r84 ^ r61; var r89 = 9 + r10; var r90 = 2 + r19; r41 = r70 ^ r60; var r91 = r9 + r80; var r92 = r33 & r47; var r93 = 9 * 0; var r94 = 6 ^ 4; var r95 = r70 / r47; r41 = r38 - r21; var r96 = r29 - r55; var r97 = r37 + r55; var r98 = r54 | 5; r3 = r65 / 2; r91 = r37 - r71; var r99 = r60 / r78; var r100 = r55 % r70; var r101 = r5 + r55; var r102 = r22 ^ r23; var r103 = 1 * r101; r30 = 9 + 0; var r104 = r49 ^ 1; var r105 = r44 + r41; r61 = r60 / r46; var r106 = r50 | 5; var r107 = r72 ^ r53; var r108 = r91 ^ r6; var r109 = r89 - r96; r72 = r92 & nlfahm; var r110 = 0 - 3; var r111 = r38 % r30; r78 = 4 ^ 5; var r112 = r45 % r20; var r113 = 4 + r109; var r114 = r26 / r99; var r115 = r110 / x; var r116 = r110 | 6; var r117 = 2 & r53; var r118 = 6 & 1; var r119 = r51 - r10; var r120 = r7 + r64; var r121 = r91 - r92; var r122 = r108 / r66; r9 = r92 | r109; var r123 = r41 + r40; r5 = r70 + r115; var r124 = 5 % r60; r61 = r46 | r66; var r125 = r54 | 2; /*hhh*/function nlfahm(\u3056, a = (this.__defineSetter__(\"d\", mathy0)), x, this.d, y =  /x/g , \u3056, ...eval){print(allocationMarker());}");
/*fuzzSeed-246262462*/count=347; tryItOut("\"use strict\"; /*infloop*/while((x < x))i1 + '';");
/*fuzzSeed-246262462*/count=348; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?:(?=.)*)(?!(?:([^]|[^\\S])))(?:\u5a32[*-\\n\u289a-\u9d0e]*?)*)*?/yim; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-246262462*/count=349; tryItOut("a0[4] = o1.v1;");
/*fuzzSeed-246262462*/count=350; tryItOut("mathy2 = (function(x, y) { return ( + Math.abs(( ! (Math.log10((y >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [0x100000001, 0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000, -1/0, 42, 2**53-2, -0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, -Number.MIN_VALUE, 2**53+2, 1, 0x080000000, -0x100000000, 1/0, 0x07fffffff, 1.7976931348623157e308, -(2**53+2), 0.000000000000001, -0x07fffffff, -0x100000001, -Number.MAX_VALUE, 0/0, Number.MIN_VALUE, -(2**53), 2**53, -0x080000001, -0]); ");
/*fuzzSeed-246262462*/count=351; tryItOut("/*ODP-1*/Object.defineProperty(m2, \"__proto__\", ({}));");
/*fuzzSeed-246262462*/count=352; tryItOut("\"use strict\"; { void 0; try { (enableSingleStepProfiling()) } catch(e) { } } i0 = o1;");
/*fuzzSeed-246262462*/count=353; tryItOut("g0.i2 + p2;\nv1 = g2.runOffThreadScript();function x(...b) { yield 24 } for (var p in g2) { try { s1[\"big\"] = o1; } catch(e0) { } try { m2.get(v2); } catch(e1) { } try { g1.e2.has(this.s0); } catch(e2) { } g0.h1.set = f0; }\n");
/*fuzzSeed-246262462*/count=354; tryItOut("mathy3 = (function(x, y) { return (( + Math.cbrt(( + ( - Math.fround(Math.fround(( + x))))))) ** mathy2(mathy1(Math.sqrt(x), (y != (x | 0))), ((Math.fround(Math.cosh(Math.fround(( + (y ? x : (y | 0)))))) < Math.fround((Math.acos(y) >>> 0))) | 0))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53, Number.MIN_VALUE, 0, -0x07fffffff, 42, 0x100000001, 2**53-2, 1/0, 0/0, -(2**53), 2**53+2, -Number.MIN_VALUE, -0x080000001, 1, -0x0ffffffff, -Number.MAX_VALUE, -0, -0x100000000, 0.000000000000001, 0x100000000, -1/0, 0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -(2**53+2), 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=355; tryItOut("print(uneval(b2));");
/*fuzzSeed-246262462*/count=356; tryItOut("Array.prototype.sort.apply(a0, []);");
/*fuzzSeed-246262462*/count=357; tryItOut("\"use strict\"; /*vLoop*/for (var wgpujv = 0, (yield (new RegExp(\"(?!(?=[^][^]*)?\\\\3)\", \"i\"))(\"\\u794E\", window)); wgpujv < 0; ++wgpujv) { e = wgpujv; v0 = g2.m1.get(s0); } ");
/*fuzzSeed-246262462*/count=358; tryItOut("s0 += s1;");
/*fuzzSeed-246262462*/count=359; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - Math.sign((Math.log(Math.fround(Math.ceil(((((y | 0) !== x) | 0) || ((Math.hypot((y >>> 0), -0x0ffffffff) | 0) < Math.fround(y)))))) >>> 0))); }); testMathyFunction(mathy3, [0x080000000, 0/0, 0x100000000, 1.7976931348623157e308, -0x07fffffff, -0x100000000, 42, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, -0, -1/0, 1, Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, 0x0ffffffff, -0x080000001, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, 2**53+2, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0, Number.MIN_VALUE, 2**53, -0x080000000, 0x080000001]); ");
/*fuzzSeed-246262462*/count=360; tryItOut("\"use strict\"; for(y in ((eval)(true)))print(uneval(this.o1));");
/*fuzzSeed-246262462*/count=361; tryItOut("\"use strict\"; e1.has(b1);");
/*fuzzSeed-246262462*/count=362; tryItOut("mathy5 = (function(x, y) { return Math.hypot((( + (( + (mathy3(x, y) >>> 0)) && ((( ~ x) | 0) < (Math.fround(( ~ (-1/0 % x))) | 0)))) | 0), (mathy1(Math.fround((( + (Math.hypot(x, x) <= ( ! y))) < Math.fround(Math.fround(((x | 0) === (( + (( + ( + x)) ? (( - (y | 0)) >>> 0) : ( + (Math.hypot(Math.fround(y), Math.fround(x)) | 0)))) | 0)))))), Math.atan2(Math.fround((y , ( + y))), y)) >>> 0)); }); testMathyFunction(mathy5, [42, -0x100000001, 0/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, -(2**53), -0x080000000, 0x0ffffffff, 1, Math.PI, 0x080000001, -0x100000000, 0, 0x07fffffff, -Number.MIN_VALUE, 2**53+2, 2**53-2, -0, 2**53, -1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, -0x080000001, 1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=363; tryItOut("let (e)\u000c { ( /x/ ); }");
/*fuzzSeed-246262462*/count=364; tryItOut("\"use strict\"; e1.has(p0);");
/*fuzzSeed-246262462*/count=365; tryItOut("var x, b = /(?=\\1([^])+?)|\\2/yim & /\\S/gi, e = Math.atan2(x, -25), eval =  \"\" , jxkbmi, poynak;print(x);");
/*fuzzSeed-246262462*/count=366; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot(( + (mathy0(((Math.min((( ~ ( + ( + ( + (mathy0((Math.max((x >>> 0), (-(2**53-2) >>> 0)) >>> 0), (x >>> 0)) >>> 0))))) >>> 0), ( - mathy0(Math.fround(mathy0((x >>> 0), Math.fround(y))), 0x080000001))) | 0) >>> 0), ((Math.fround((Math.sin(( + ((y >>> 0) ** (Math.log10(x) >>> 0)))) >>> 0)) ? ( + x) : Math.fround(Math.cbrt((y >>> 0)))) >>> 0)) >>> 0)), ( + (Math.cosh(( + Math.atan2(( + Math.ceil(2**53-2)), ( + y)))) >>> 0)))); }); testMathyFunction(mathy2, [[0], '\\0', (function(){return 0;}), undefined, ({valueOf:function(){return 0;}}), 0, NaN, 1, (new String('')), -0, (new Number(0)), '', true, [], 0.1, null, /0/, (new Boolean(true)), (new Boolean(false)), ({valueOf:function(){return '0';}}), false, ({toString:function(){return '0';}}), '0', '/0/', objectEmulatingUndefined(), (new Number(-0))]); ");
/*fuzzSeed-246262462*/count=367; tryItOut("\"use strict\"; this.v2 = g2.runOffThreadScript();");
/*fuzzSeed-246262462*/count=368; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.expm1(Math.fround(Math.fround((( + ( ~ Math.pow(((( + (Math.hypot(y, (x | 0)) | 0)) ? (( ~ (( - x) >>> 0)) | 0) : (y | 0)) | 0), y))) >>> Math.max((0x07fffffff | 0), x))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 0, 1, -0x080000000, Number.MIN_VALUE, 2**53, -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, Math.PI, 2**53+2, 1/0, -1/0, 0x07fffffff, -0x07fffffff, 0x080000000, 2**53-2, -0x100000001, 42, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), -0x0ffffffff, 0/0, 0x080000001, 0x0ffffffff, Number.MAX_VALUE, -0]); ");
/*fuzzSeed-246262462*/count=369; tryItOut("/*ODP-2*/Object.defineProperty(g2.e0, \"this.x\", { configurable: intern((new new SimpleObject()(allocationMarker(), allocationMarker()))), enumerable: (x % 6 != 1), get: function  x (b) { \"use strict\"; \"use asm\"; /*MXX1*/Object.defineProperty(this, \"o2\", { configurable: true, enumerable: false,  get: function() {  return this.g0.Date.prototype.setUTCMilliseconds; } }); } , set: (function(j) { if (j) { try { m2.has(g0); } catch(e0) { } v0 = Object.prototype.isPrototypeOf.call(i1, f2); } else { try { selectforgc(o0); } catch(e0) { } this.h0.fix = f1; } }) });");
/*fuzzSeed-246262462*/count=370; tryItOut("v2 = Object.prototype.isPrototypeOf.call(g2, m0);");
/*fuzzSeed-246262462*/count=371; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=372; tryItOut("x = p1;");
/*fuzzSeed-246262462*/count=373; tryItOut("m2.delete(e0);");
/*fuzzSeed-246262462*/count=374; tryItOut("(eval(\"-3\"));\nObject.freeze(t2);\n");
/*fuzzSeed-246262462*/count=375; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 4.722366482869645e+21;\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: \"\\u6C89\"}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [0x080000000, -0x100000001, 0, -0, 0.000000000000001, -0x080000001, 0x080000001, -1/0, 1, Number.MAX_VALUE, -0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 1/0, 0/0, -0x0ffffffff, -0x07fffffff, -0x100000000, 2**53-2, 0x100000000, Number.MIN_VALUE, 0x100000001, -(2**53+2), 2**53, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=376; tryItOut("\"use strict\"; function f2(this.p0) \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 512.0;\n    d2 = (+abs(((-32769.0))));\n    (Float32ArrayView[(((((i1)+(0xffa21160)) << (-0xfffff*(0x3b05b587))))*-0xfffff) >> 2]) = ((((((+((Infinity)))) % ((144115188075855870.0)))) % ((-4398046511105.0))));\n    d2 = (+(((0xa96491bf)*0xfffff)|0));\n    i1 = (i1);\n    d2 = (+abs(((1.0))));\n    return +(((Uint8ArrayView[2])));\n    return +((+((+(1.0/0.0)))));\n    i1 = (i1);\n    return +((d2));\n  }\n  return f;");
/*fuzzSeed-246262462*/count=377; tryItOut("/*oLoop*/for (let nbtvht = 0; nbtvht < 1; ++nbtvht) { print(let (z)  \"\" ); } ");
/*fuzzSeed-246262462*/count=378; tryItOut("/*oLoop*/for (let pawooc = 0; pawooc < 13; ++pawooc) { print((/*FARR*/[].map(\"\\u247E\"))); } \nb2.valueOf = (function() { try { t2 = t0.subarray(({valueOf: function() { (function  x (a) { return window } .prototype);return 10; }})); } catch(e0) { } try { g0.b0 + ''; } catch(e1) { } try { t0 = new Uint32Array(b0); } catch(e2) { } t2.set(t0, 7); return h2; });\n");
/*fuzzSeed-246262462*/count=379; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.min(Math.tan((Math.asinh(( + mathy2(x, Math.fround(x)))) | 0)), Math.log10((((((x | 0) < (x | 0)) | 0) , (((( ! ( + ( + x))) | 0) << Math.fround(y)) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [0x100000000, 0x07fffffff, Number.MIN_VALUE, 0x080000000, 2**53, 0, -0x080000001, 42, -0x07fffffff, 0/0, 2**53+2, 1, 0x100000001, -0x100000001, 0x080000001, -Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, -(2**53-2), -(2**53), -0x0ffffffff, -0, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-246262462*/count=380; tryItOut("var r0 = x & x; var r1 = x * r0; var r2 = 5 * r1; var r3 = 8 % 7; var r4 = r2 - r0; r4 = 2 | r0; var r5 = r4 - r3; r1 = r0 & r0; r3 = 8 / r1; var r6 = x / r3; var r7 = 0 & 0; var r8 = x - r1; var r9 = r3 | r0; var r10 = 2 | 8; var r11 = 6 | r9; var r12 = r3 % r5; r12 = r0 % r5; var r13 = 7 - 5; var r14 = r12 - 1; x = r4 & x; var r15 = r8 + r11; var r16 = r3 + x; var r17 = 8 - r16; var r18 = r11 | 5; print(r10); var r19 = 2 % 2; var r20 = r5 + r5; print(r4); var r21 = 8 / 2; var r22 = r2 / x; r7 = 4 ^ 2; var r23 = 7 / x; var r24 = r10 & 5; r5 = r6 + r13; var r25 = 3 + r23; var r26 = r23 ^ r9; var r27 = r14 % r4; var r28 = x ^ 7; var r29 = r10 ^ r9; var r30 = 1 & r29; r9 = 0 ^ r9; var r31 = 2 ^ r8; var r32 = r16 & r11; print(r0); var r33 = 2 & r8; var r34 = 6 & r5; var r35 = r6 | r19; var r36 = r12 & 7; var r37 = r32 - r32; var r38 = r12 ^ 1; var r39 = r18 | 2; var r40 = r3 | 3; r29 = 0 * r27; Object.defineProperty(this, \"this.v1\", { configurable: false, enumerable: [z1,,].__lookupSetter__(this),  get: function() {  return g1.eval(\"function f2(s0)  { \\\"use strict\\\"; m1.delete(b2); } \"); } });");
/*fuzzSeed-246262462*/count=381; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      switch ((~((i1)+(i2)))) {\n        case 0:\n          (Uint8ArrayView[(0x514fc*(!(!(i1)))) >> 0]) = ((0xdfcf6627)-(i2)+(i1));\n        default:\n          d0 = (-((7.555786372591432e+22)));\n      }\n    }\n    i2 = (i1);\n    d0 = (d0);\nArray.prototype.reverse.call(this.a2, this.s1);    (Int16ArrayView[((!((0xdaa9869a)))*0xfffff) >> 1]) = (((-(0xfeb23a7a))>>>((0xfe1b72b2))) / (((((0xaf93fdc0) <= (0x0)) ? (i1) : (/*FFI*/ff(((imul((0xf92d7501), (0xfbb0ce5a))|0)))|0))-(0xfe53d25b))>>>((i2))));\n    return +((Float32ArrayView[(0xfffff*(!(/*FFI*/ff(((d0)))|0))) >> 2]));\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[ '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '' ,  '' ,  '' ,  '\\0' ,  '' ,  '\\0' ,  '' ,  '\\0' ,  '\\0' ,  '' ,  '' ,  '\\0' ,  '\\0' ,  '\\0' ,  '' ,  '\\0' ,  '' ,  '\\0' ,  '' ,  '' ,  '' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '' ,  '' ,  '\\0' ,  '' ,  '\\0' ]); ");
/*fuzzSeed-246262462*/count=382; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(g2, c, ({}));\ng1.offThreadCompileScript(\" /x/ \");\n");
/*fuzzSeed-246262462*/count=383; tryItOut("mathy3 = (function(x, y) { return ( + ( + (( + ( + (( + Math.fround(( ! Math.fround(x)))) || ( + Math.atan2(x, Math.sinh((((x ** (x | 0)) >>> 0) >>> 0))))))) ? ( + ((( + Math.fround(Math.atan2(x, Math.fround(Math.trunc(y))))) & Math.fround(x)) & (Math.max((Math.atan2((x >>> 0), y) >>> 0), ( + x)) | 0))) : ( + ( ! (Math.sin(y) | 0)))))); }); testMathyFunction(mathy3, [1, 0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, 0.000000000000001, Number.MIN_VALUE, Math.PI, 0x07fffffff, 2**53-2, -0, 0x100000001, 42, 0x100000000, 1/0, -Number.MAX_VALUE, -0x100000000, -0x100000001, 2**53, -0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), 0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, -(2**53), 2**53+2]); ");
/*fuzzSeed-246262462*/count=384; tryItOut("\"use strict\"; Array.prototype.shift.apply(this.o0.a2, []);");
/*fuzzSeed-246262462*/count=385; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.atan2((( ~ ((mathy0((Math.min(( + -(2**53+2)), Math.fround((-(2**53+2) || y))) >>> 0), ( + Math.sinh(0x100000001))) >>> 0) >>> 0)) >>> 0), (( ! ( + ((Math.fround(( - x)) < (Math.sqrt((y | 0)) | 0)) | 0))) >>> 0)); }); testMathyFunction(mathy1, [-0x07fffffff, -Number.MAX_VALUE, -(2**53), -0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000000, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, -0, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -(2**53-2), 0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 42, 0x080000000, 0x07fffffff, 1, -0x0ffffffff, -0x100000001, 1.7976931348623157e308, 2**53-2, 0x100000001, 2**53, 0/0, 0, -0x080000000, -(2**53+2)]); ");
/*fuzzSeed-246262462*/count=386; tryItOut("\"use asm\"; if(this) switch(true) { case this: {}break; default: a2.reverse(t0, a2);case 1: case [1,,]: Array.prototype.sort.apply(a0, [(function() { for (var j=0;j<17;++j) { this.f0(j%3==1); } }), i2, a2, h0]);break;  } else  if (/[^\\s\\t-\\cJ\\\u00b9]|\\b?|[^]+?|[^]*?{4}/gm) {g0.toString = (function() { try { v0 = (f0 instanceof g0.g0.o1.h1); } catch(e0) { } i0.send(i0); return v0; }); }\nvar wawmzo, w, x, cmtjuj, y, a;m2.get(o1);\n");
/*fuzzSeed-246262462*/count=387; tryItOut("mathy3 = (function(x, y) { return ((( + Math.acosh(Math.fround(mathy0((((((Math.expm1(x) | 0) - (Math.fround(( ! Math.fround(x))) | 0)) | 0) | 0) ? ( - y) : ( ! -0x080000000)), (mathy0((( + ( - (x | 0))) | 0), Math.fround(( - (Math.imul(( + Math.cosh(( + y))), (x | 0)) >>> 0)))) | 0))))) | 0) ^ (Math.fround(( - (mathy0(y, -(2**53)) | 0))) | 0)); }); testMathyFunction(mathy3, [-0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -1/0, -Number.MAX_VALUE, 1, 2**53-2, -0x100000000, 0x080000001, -0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 0, 0x100000000, 1/0, 0x080000000, -0x07fffffff, 0x100000001, 2**53, Number.MAX_VALUE, -(2**53), -(2**53-2), Math.PI, -0x100000001, 1.7976931348623157e308, 0.000000000000001, Number.MIN_VALUE, 0/0, 0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-246262462*/count=388; tryItOut("\"use strict\"; \"use asm\"; h2 = ({getOwnPropertyDescriptor: function(name) { t1 = new Int16Array(this.b0, 12, 17);; var desc = Object.getOwnPropertyDescriptor(m1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { this.g2.e0.has(b0);; var desc = Object.getPropertyDescriptor(m1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v0 = g0.runOffThreadScript();; Object.defineProperty(m1, name, desc); }, getOwnPropertyNames: function() { this.i1 + '';; return Object.getOwnPropertyNames(m1); }, delete: function(name) { f2 + e0;; return delete m1[name]; }, fix: function() { throw v2; if (Object.isFrozen(m1)) { return Object.getOwnProperties(m1); } }, has: function(name) { m1.set(s2, m1);; return name in m1; }, hasOwn: function(name) { Array.prototype.sort.call(a0, (function() { for (var j=0;j<48;++j) { f2(j%5==0); } }), this.f2);; return Object.prototype.hasOwnProperty.call(m1, name); }, get: function(receiver, name) { o0 = new Object;; return m1[name]; }, set: function(receiver, name, val) { g2.v1.toSource = (function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function shapeyConstructor(dbquyi){this[\"apply\"] = x;Object.preventExtensions(this);for (var ytqykxezp in this) { }{ {t2 = new Int16Array(a0); } } { print(x); } this[\"-19\"] = (yield \"\\uEB7E\").bind;{ print(x); } Object.defineProperty(this, \"apply\", ({}));{ this.o1.m0.set(this.p1, o1.g1); } delete this[\"apply\"];return this; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: Float32Array, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; });; m1[name] = val; return true; }, iterate: function() { h2.valueOf = f1;; return (function() { for (var name in m1) { yield name; } })(); }, enumerate: function() { v1 = Object.prototype.isPrototypeOf.call(m2, o2.f1);; var result = []; for (var name in m1) { result.push(name); }; return result; }, keys: function() { for (var v of e1) { try { /*MXX2*/g2.SharedArrayBuffer.name = o0; } catch(e0) { } try { Object.prototype.watch.call(t2, \"caller\", (function() { p0 = a2[({valueOf: function() { print((encodeURIComponent).call(window,  /x/ , [z1,,]));return 7; }})]; return m0; })); } catch(e1) { } try { o0.v1 = a0.length; } catch(e2) { } for (var p in h1) { try { for (var v of e0) { try { t1.toString = (function() { v2 = t2.length; return t1; }); } catch(e0) { } try { v0 = g2.eval(\"/* no regression tests found */\"); } catch(e1) { } b2 + v0; } } catch(e0) { } try { Array.prototype.pop.call(a0, m1, g0, g2.e2); } catch(e1) { } print(e1); } }; return Object.keys(m1); } });");
/*fuzzSeed-246262462*/count=389; tryItOut("/*RXUB*/var r = /\\u00A5/im; var s = \"\\u00a5\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=390; tryItOut("\"use strict\"; v2 = t0.length;");
/*fuzzSeed-246262462*/count=391; tryItOut("\"use asm\"; var gqxuhu = new SharedArrayBuffer(2); var gqxuhu_0 = new Int8Array(gqxuhu); gqxuhu_0[0] = 1; /*RXUB*/var r = r1; var s = this.s1; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=392; tryItOut("print((new Boolean(false)));");
/*fuzzSeed-246262462*/count=393; tryItOut("for (var p in f2) { try { /*MXX3*/g1.Uint8ClampedArray.length = g0.g1.Uint8ClampedArray.length; } catch(e0) { } try { e0.delete(t0); } catch(e1) { } Array.prototype.sort.apply(a2, [f1, f2]); }");
/*fuzzSeed-246262462*/count=394; tryItOut("print(f2);");
/*fuzzSeed-246262462*/count=395; tryItOut("\"use asm\"; /*ADP-2*/Object.defineProperty(a2, 16, { configurable: true, enumerable: (x % 41 != 8), get: (function() { try { v2 = Object.prototype.isPrototypeOf.call(p2, h0); } catch(e0) { } try { s0 += 'x'; } catch(e1) { } v0 = a1.length; return o0; }), set: f2 });");
/*fuzzSeed-246262462*/count=396; tryItOut("mathy1 = (function(x, y) { return ( + Math.sin(Math.fround(( + Math.log((( - Math.fround(( + ( ! x)))) >>> 0)))))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), -(2**53-2), -0x07fffffff, 0, 2**53-2, -Number.MIN_VALUE, 1, -0x100000001, -(2**53), -0x080000000, 2**53, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 2**53+2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -0, 1/0, -0x0ffffffff, 0x100000000, 0x080000001, Number.MAX_VALUE, 0/0, -0x100000000]); ");
/*fuzzSeed-246262462*/count=397; tryItOut("");
/*fuzzSeed-246262462*/count=398; tryItOut("\"use strict\"; {/*infloop*/L:for(\u3056 in ((Function)(x))){/*MXX2*/g1.WeakSet.length = p2; } }");
/*fuzzSeed-246262462*/count=399; tryItOut("s2 += 'x';");
/*fuzzSeed-246262462*/count=400; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(( ~ ( + y)), (( + Math.cbrt((Number.MAX_SAFE_INTEGER | 0))) ? ( + Math.fround(Math.max(Math.fround((Math.fround(Math.imul(x, y)) && (y >>> 0))), ( + Math.hypot(((Math.sign(0x0ffffffff) >>> 0) >>> 0), ( - ( + 0/0))))))) : ( + ( + ( - 0x07fffffff))))); }); testMathyFunction(mathy1, [0x100000000, 2**53+2, -0x080000001, -(2**53+2), Number.MIN_VALUE, 0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, 1, -(2**53), 0x100000001, Math.PI, 0.000000000000001, -0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 0, -0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, 1/0, -1/0, -(2**53-2), 0x0ffffffff, 2**53-2, -0x07fffffff, 42, 2**53, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-246262462*/count=401; tryItOut("o0.g1.b0 + g0.a0;a2 = new Array;");
/*fuzzSeed-246262462*/count=402; tryItOut("return;");
/*fuzzSeed-246262462*/count=403; tryItOut("\"use strict\"; v2 = g2.eval(\"mathy4 = (function(x, y) { \\\"use strict\\\"; return ( ~ Math.abs(Math.log1p(((Math.imul(x, (x >>> 0)) >>> 0) <= (((( + (( + y) * ( + x))) | 0) >>> (( ! ( + y)) | 0)) | 0))))); }); testMathyFunction(mathy4, [1.7976931348623157e308, 2**53, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -0x100000001, Number.MIN_VALUE, 0x100000001, 0x0ffffffff, -1/0, -0x080000001, 0/0, -Number.MIN_VALUE, -0, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53), 0, 1, -0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -(2**53+2), 0.000000000000001, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, 1/0, 42, 0x080000001, 2**53+2]); \");");
/*fuzzSeed-246262462*/count=404; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (/*FFI*/ff(((Uint16ArrayView[4096])), ((((0xa3112bc9)) << ((0x41c793d2) % ((((0x2a37f4) != (0x5e5bc028))-((0xfa968a40) ? (0x326216cb) : (0xcef1ea9a))) ^ ((0x27e99e1d)+(0xef55836e)-(-0x8000000)))))), ((+abs(((d0))))), ((((i1)-((0x467e4b13) ? (0xde51bee) : (-0x8000000))) ^ ((Uint32ArrayView[((i2)+(i2)) >> 2])))), ((+(imul((0xfc69ec8f), (i1))|0))), ((((/*FFI*/ff(((70368744177665.0)), ((d0)), ((-562949953421313.0)), ((-1.125)), ((1.888946593147858e+22)), ((2.3611832414348226e+21)), ((0.001953125)), ((257.0)))|0))|0)))|0);\n    /*FFI*/ff();\n    return +((d0));\n    {\n      d0 = (6.044629098073146e+23);\n    }\n    switch ((((i2)+(0xffffffff)) | ((i2)+((72057594037927940.0) != (68719476737.0))))) {\n    }\n    i1 = ((i1) ? (((-0xe9700*(i1)) | ((i1)+(/*FFI*/ff()|0)))) : ((((Float32ArrayView[((i1)) >> 2])) / ((Float64ArrayView[((Float64ArrayView[0])) >> 3]))) == (d0)));\n    return +((-4503599627370497.0));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var ovcalt = z = eval = new [[]](); var svcvfo = let (e)  /x/g ; return svcvfo;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [[], '/0/', '0', ({valueOf:function(){return '0';}}), null, objectEmulatingUndefined(), 0, 1, ({valueOf:function(){return 0;}}), undefined, true, /0/, -0, NaN, (new Number(0)), '', 0.1, (new Boolean(false)), '\\0', [0], (new String('')), false, (function(){return 0;}), ({toString:function(){return '0';}}), (new Boolean(true)), (new Number(-0))]); ");
/*fuzzSeed-246262462*/count=405; tryItOut("Array.prototype.sort.call(a0, (function mcc_() { var yuzlnn = 0; return function() { ++yuzlnn; if (/*ICCD*/yuzlnn % 8 == 2) { dumpln('hit!'); try { this.a2 = []; } catch(e0) { } try { t0 = new Uint8Array(a2); } catch(e1) { } a1.shift(b0, p2); } else { dumpln('miss!'); /*MXX2*/o0.o2.g2.DataView.BYTES_PER_ELEMENT = g2; } };})(), b1);");
/*fuzzSeed-246262462*/count=406; tryItOut("h2 = ({getOwnPropertyDescriptor: function(name) { v0 = evaluate(\";\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 1), noScriptRval: (x % 8 != 5), sourceIsLazy: (x % 4 != 2), catchTermination: true, element: g0.o2, elementAttributeName: s2 }));; var desc = Object.getOwnPropertyDescriptor(p1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { o0.v0 = undefined;; var desc = Object.getPropertyDescriptor(p1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { i2 + '';; Object.defineProperty(p1, name, desc); }, getOwnPropertyNames: function() { v1 = evaluate(\"h2.enumerate = (function mcc_() { var pvosoi = 0; return function() { ++pvosoi; if (/*ICCD*/pvosoi % 3 == 2) { dumpln('hit!'); try { o2.v0 = null; } catch(e0) { } try { i0.__proto__ = a2; } catch(e1) { } Array.prototype.pop.call(a2, t2, g1, [(this(null, 6).valueOf(\\\"number\\\"))], p2, (eval(\\\"g2.a0[13];\\\")), a0, e1); } else { dumpln('miss!'); try { v0 = (this.t1 instanceof f2); } catch(e0) { } v2 = g2.g2.eval(\\\"function f1(m0)  { return \\\\\\\"\\\\\\\\u94E6\\\\\\\" } \\\"); } };})();\", ({ global: o1.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 == 1), noScriptRval: true, sourceIsLazy: (x % 6 != 0), catchTermination: true }));; return Object.getOwnPropertyNames(p1); }, delete: function(name) { this.g0.v1 = (m0 instanceof f0);; return delete p1[name]; }, fix: function() { v2 = Infinity;; if (Object.isFrozen(p1)) { return Object.getOwnProperties(p1); } }, has: function(name) { v2 = 4.2;; return name in p1; }, hasOwn: function(name) { print(h2);; return Object.prototype.hasOwnProperty.call(p1, name); }, get: function(receiver, name) { i2 + '';; return p1[name]; }, set: function(receiver, name, val) { v0 = evaluate(\"if(true) { if (x) {e2.delete(e2); }} else {f0 + o0.e2;o0.v2 = Array.prototype.some.apply(a0, [function shapeyConstructor(xexhde){if (new RegExp(\\\"(?=(?=.)){4,}|(?=(.))+|[^]?|[^]|^*|\\\\\\\\B(?!\\\\\\\\b)+\\\", \\\"i\\\")) for (var ytqtwaojn in this) { }for (var ytqrpjlrw in this) { }this[\\\"callee\\\"] = \\\"\\\\uD55A\\\";if (xexhde) delete this[ \\\"\\\" ];this[ \\\"\\\" ] = Math.atanh;this[\\\"callee\\\"] =  \\\"use strict\\\" ;for (var ytqxivcsn in this) { }this[ \\\"\\\" ] = false;for (var ytqfzsyzd in this) { }return this; }, this.e0, p1, this.o1, this, g2, f1, a0]); }\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (timeout(1800)), noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 61 == 29) }));; p1[name] = val; return true; }, iterate: function() { v0 = r1.toString;; return (function() { for (var name in p1) { yield name; } })(); }, enumerate: function() { throw o2; var result = []; for (var name in p1) { result.push(name); }; return result; }, keys: function() { m0 = a1[v0];; return Object.keys(p1); } });");
/*fuzzSeed-246262462*/count=407; tryItOut("var xnbstn = new ArrayBuffer(0); var xnbstn_0 = new Uint16Array(xnbstn); xnbstn_0[0] = 4503599627370495; h2 = g2.objectEmulatingUndefined();");
/*fuzzSeed-246262462*/count=408; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ! (Math.fround(mathy0(Math.fround(( ~ mathy2(Math.fround(y), Math.fround((Math.pow((y >>> 0), (Math.PI | 0)) >>> 0))))), Math.cos((Math.fround((( ! x) < Math.fround(x))) | 0)))) | 0)) | 0); }); ");
/*fuzzSeed-246262462*/count=409; tryItOut("\"use asm\"; \"use strict\"; (x);");
/*fuzzSeed-246262462*/count=410; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[0x40000000, ({}), ({}),  /x/g , true,  /x/g ,  /x/g , 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, 0x40000000, ({}), true, true, 0x40000000,  /x/g ]) { t2[arguments]; }");
/*fuzzSeed-246262462*/count=411; tryItOut("testMathyFunction(mathy0, [0, -0, '\\0', [0], objectEmulatingUndefined(), (new Boolean(true)), 0.1, (new Number(0)), false, '', (function(){return 0;}), true, (new Boolean(false)), NaN, ({valueOf:function(){return '0';}}), (new Number(-0)), 1, [], ({valueOf:function(){return 0;}}), undefined, '/0/', (new String('')), null, ({toString:function(){return '0';}}), /0/, '0']); ");
/*fuzzSeed-246262462*/count=412; tryItOut("const [] = x, e =  \"\" , d, lypvet, rwljyh;v2 = evalcx(\"/* no regression tests found */\", g0);");
/*fuzzSeed-246262462*/count=413; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.imul(( + (Math.cos(Math.pow((Math.log10((Math.tanh(y) | 0)) | 0), 42)) | 0)), ( + ( + (( + Math.max(Math.clz32((Math.expm1((Math.acosh(y) >>> 0)) >>> 0)), (x & (( - (x | 0)) | 0)))) >> ( + (( + (mathy1(y, y) | 0)) | 0))))))); }); testMathyFunction(mathy3, [2**53-2, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1/0, -1/0, -0x080000000, Number.MIN_VALUE, -(2**53), Number.MAX_VALUE, 0.000000000000001, 0x100000001, 42, -Number.MIN_VALUE, -(2**53-2), -0x100000001, 0x07fffffff, -0x080000001, 0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, 0, -0x0ffffffff, 0x080000001, -0, -0x07fffffff, 1, 0/0, Math.PI, 2**53, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=414; tryItOut("/*tLoop*/for (let c of /*MARR*/[false, false, false, false, false, false, false, false,  /x/g ,  /x/g ,  /x/g , Number.MIN_VALUE, Number.MIN_VALUE,  /x/g , window,  /x/g , false,  /x/g , Number.MIN_VALUE, Number.MIN_VALUE, window, window]) { print(x); }");
/*fuzzSeed-246262462*/count=415; tryItOut("o1.g2.a2 = r1.exec(s0);");
/*fuzzSeed-246262462*/count=416; tryItOut("/*tLoop*/for (let x of /*MARR*/[ '\\0' , new String('q'), true, true, true, new String('q'), new String('q'),  '\\0' ,  '\\0' , true,  '\\0' , true, new String('q'), new String('q'),  '\\0' , true, true, new String('q'), new String('q'),  '\\0' , new String('q'),  '\\0' , true, new String('q'),  '\\0' , new String('q'),  '\\0' ,  '\\0' ,  '\\0' , true, new String('q'), true, new String('q'), new String('q'),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new String('q'),  '\\0' , new String('q'), true, true, new String('q'), true,  '\\0' ,  '\\0' , true, true, new String('q'),  '\\0' , new String('q'), new String('q'), new String('q'), new String('q'),  '\\0' , new String('q'),  '\\0' , new String('q'), true, true,  '\\0' , true, true,  '\\0' , true, new String('q'),  '\\0' , true,  '\\0' ,  '\\0' , true,  '\\0' ,  '\\0' , new String('q'), true, new String('q'),  '\\0' ,  '\\0' , true,  '\\0' , new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), true, true, true,  '\\0' , new String('q'),  '\\0' , true,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , true, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'),  '\\0' , new String('q'),  '\\0' ,  '\\0' , new String('q'),  '\\0' , true, new String('q'),  '\\0' ,  '\\0' , new String('q'), true, true, new String('q'), new String('q'), new String('q'), new String('q'),  '\\0' , new String('q'),  '\\0' ,  '\\0' , true, new String('q'), true,  '\\0' , new String('q'), true, true, new String('q'),  '\\0' , true]) { a1[\"\\u7A85\"] =  /x/g ; }");
/*fuzzSeed-246262462*/count=417; tryItOut("mathy4 = (function(x, y) { return (Math.fround(Math.atan2(Math.fround(Math.sin(0)), Math.fround((Math.fround((Math.imul((Math.sin(x) >>> 0), ( ~ x)) >>> 0)) ? ( ! ( + Math.pow(y, Math.pow(0x100000000, x)))) : (Math.min(x, ( + Math.hypot(( + 0x0ffffffff), Math.fround(Math.min((Number.MIN_VALUE | 0), Math.fround(x)))))) | 0))))) > ( + Math.min(( + ( ! ((mathy0(x, x) >>> 0) >>> (Math.min(( + y), ( + 1)) <= Math.fround(y))))), ( + Math.fround((Math.fround((Math.trunc((( + (((x | 0) === (Math.tanh(-0x080000001) | 0)) | 0)) ? ((x % (x | 0)) | 0) : x)) | 0)) % Math.max(( ! -0x07fffffff), Math.hypot(-0x080000000, y)))))))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -Number.MIN_VALUE, 0, 1, 0/0, 42, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, 0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, -Number.MAX_VALUE, -(2**53+2), -1/0, -(2**53), Math.PI, 0x100000001, 1/0, -(2**53-2), 2**53+2, 2**53-2, -0x080000000, -0]); ");
/*fuzzSeed-246262462*/count=418; tryItOut("mathy0 = (function(x, y) { return Math.atan((Math.log10(Math.fround(((Math.imul((Math.fround(Math.max(( + x), Math.fround(Math.fround(Math.PI)))) | 0), (Math.imul(( + Math.atan2(( + x), ( + x))), x) | 0)) | 0) ? y : x))) | 0)); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, -0, -0x080000001, 42, Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, 0, -(2**53), -1/0, -0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, Math.PI, 0x0ffffffff, -(2**53+2), -(2**53-2), -Number.MIN_VALUE, 0x07fffffff, 1/0, 0.000000000000001, 0x080000000, Number.MIN_SAFE_INTEGER, 1, -0x100000001, 1.7976931348623157e308, 0x080000001, Number.MAX_VALUE, 0x100000001, -0x100000000, 0/0, -0x080000000]); ");
/*fuzzSeed-246262462*/count=419; tryItOut("\"use strict\"; var gseswz = new ArrayBuffer(16); var gseswz_0 = new Float32Array(gseswz); var gseswz_1 = new Uint8ClampedArray(gseswz); print(gseswz_1[0]); gseswz_1[0] = 20; var gseswz_2 = new Float32Array(gseswz); print(gseswz_2[0]); gseswz_2[0] = -1289787602.5; o2 = new Object;;print(gseswz_1[0]);print(window);/*RXUB*/var r = function(id) { return id }; var s = \"\"; print(s.split(r)); print(r.lastIndex); print(gseswz_1[5]);");
/*fuzzSeed-246262462*/count=420; tryItOut("/*tLoop*/for (let z of /*MARR*/[x, x, {x:3}, x, x, x, x, x, {x:3}, {x:3}, {x:3}, {x:3}, x, x, {x:3}, x, x, {x:3}, x, x, {x:3}, {x:3}, x, x, x, x, x, x, x, x, x, x, x, x, x, x, {x:3}, x, {x:3}, x, x, x, x, x, x, x, {x:3}, x, x, {x:3}, {x:3}, {x:3}, x, x, {x:3}, x, x, x, {x:3}, {x:3}, {x:3}, x, {x:3}, {x:3}, x, x, {x:3}, x, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, x, {x:3}, {x:3}, x, {x:3}, {x:3}, x, {x:3}, x, x, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, x, x, {x:3}, x, {x:3}, x, {x:3}, x, {x:3}, {x:3}, x, {x:3}, {x:3}, x, x, x, {x:3}, {x:3}, {x:3}, x, {x:3}, {x:3}, {x:3}, x, x, {x:3}, {x:3}, {x:3}, x, x]) { h2.toString = ArrayBuffer.bind(b1); }");
/*fuzzSeed-246262462*/count=421; tryItOut("[Math.pow((x **= (4277)), 25)];");
/*fuzzSeed-246262462*/count=422; tryItOut("b1.toSource = (function(a0, a1) { var r0 = a1 - x; print(a0); r0 = 7 / 1; var r1 = x ^ a1; print(a0); r1 = a0 % 7; print(r0); var r2 = 7 % 1; var r3 = 1 & r2; var r4 = 9 % x; var r5 = r3 | x; var r6 = 4 - x; r5 = 5 ^ r2; a1 = r4 + r2; var r7 = r4 % r0; var r8 = r6 & a0; var r9 = 1 / 3; var r10 = a0 + r3; r3 = a0 / r1; var r11 = r1 - r9; var r12 = r10 - r10; var r13 = r5 / r0; var r14 = 8 / r7; var r15 = r5 ^ r14; var r16 = r12 - 8; var r17 = 5 | r2; var r18 = 1 / r4; r6 = r1 & r5; var r19 = 0 & r18; print(r1); var r20 = r4 * r2; var r21 = r1 & 4; var r22 = 1 & r3; var r23 = 2 + 7; var r24 = r22 | 7; var r25 = r17 ^ r13; var r26 = r12 & r18; var r27 = r2 ^ r15; var r28 = a0 / r22; var r29 = r2 | r7; var r30 = 9 * r10; var r31 = 9 % 2; var r32 = r8 ^ x; var r33 = r0 + r28; var r34 = r10 / r10; var r35 = r26 | r21; return x; });");
/*fuzzSeed-246262462*/count=423; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.asin(( + ((Math.fround(Math.imul(( + y), mathy1(y, ( + (mathy1(y, y) >>> 0))))) / ( ~ Math.fround((Math.fround((((y | 0) || (y | 0)) | 0)) & Math.fround(Math.atanh(0/0)))))) >>> 0)))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 1, Math.PI, 2**53, Number.MAX_VALUE, 2**53-2, -(2**53-2), 0.000000000000001, -0x100000000, -0, 2**53+2, 0/0, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0x100000001, 0, -Number.MIN_VALUE, 0x0ffffffff, -(2**53), -0x100000001, 0x080000001, -0x080000001, -1/0, 0x100000000, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-246262462*/count=424; tryItOut("testMathyFunction(mathy3, [-0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, Math.PI, 0/0, 2**53, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), -(2**53-2), 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, -0x100000001, 0, -(2**53+2), -0x080000000, 0x0ffffffff, -0x07fffffff, -0, 0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, 42, -0x100000000, 0x07fffffff, 1, 1/0]); ");
/*fuzzSeed-246262462*/count=425; tryItOut("for (var p in t0) { try { /*MXX1*/o1 = g0.Math.log; } catch(e0) { } /*MXX1*/o1 = g1.Int8Array.prototype; }");
/*fuzzSeed-246262462*/count=426; tryItOut("t1.set(a2, 18);");
/*fuzzSeed-246262462*/count=427; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=428; tryItOut("this.s2 = new String(o1.v0);");
/*fuzzSeed-246262462*/count=429; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.fround(Math.fround((Math.fround((Math.fround(x) | Math.fround(Math.pow(mathy3(y, -0x080000000), Math.imul(2**53-2, y))))) << ( + ( ~ (( + (( + Math.fround(Math.pow(Math.fround((( + (y >>> 0)) | 0)), Math.fround(y)))) <= ( + y))) | 0)))))) === ( + (Math.abs(Math.sinh((x | 0))) >>> 0))); }); testMathyFunction(mathy5, [Math.PI, Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, 0, 0x0ffffffff, -0x0ffffffff, -(2**53+2), 1, -0, 2**53-2, 2**53, 0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_VALUE, -0x080000000, 0/0, -(2**53), 0.000000000000001, 0x080000001, -0x07fffffff, -0x100000000, 2**53+2, 0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=430; tryItOut(" for  each(y in window) {; }");
/*fuzzSeed-246262462*/count=431; tryItOut("/*vLoop*/for (let bqzfdr = 0; bqzfdr < 52; ++bqzfdr) { const b = bqzfdr; for (var p in this.o0.b2) { try { selectforgc(g1.o2); } catch(e0) { } try { v2 = (e1 instanceof t0); } catch(e1) { } try { v1 = g1.eval(\"v2 = Object.prototype.isPrototypeOf.call(p1, g2.p0);\"); } catch(e2) { } o1 = x; } } ");
/*fuzzSeed-246262462*/count=432; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=433; tryItOut("this.m0 + '';");
/*fuzzSeed-246262462*/count=434; tryItOut("( \"\" );x;");
/*fuzzSeed-246262462*/count=435; tryItOut("/*RXUB*/var r = new RegExp(\"[^]\", \"y\"); var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-246262462*/count=436; tryItOut("\"use strict\"; delete g1.h0.iterate;");
/*fuzzSeed-246262462*/count=437; tryItOut("/*RXUB*/var r = /(?:^{4,}|(?![^]{4})+)*?/gy; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=438; tryItOut("");
/*fuzzSeed-246262462*/count=439; tryItOut("/*bLoop*/for (var ukrzqq = 0; ukrzqq < 11; ++ukrzqq) { if (ukrzqq % 4 == 2) { (/((\ube75){2,6})*?|(?:(?!\\B))*?|(?!(?![^-\uf763\\u00E6-\ube81\\xa5\\d]+?){0,}|\\1)?/g); } else { continue ; }  } ");
/*fuzzSeed-246262462*/count=440; tryItOut("\"use strict\"; o2 = new Object;");
/*fuzzSeed-246262462*/count=441; tryItOut("mathy1 = (function(x, y) { return ( + ( ! ( + Math.fround(Math.max(Math.fround(Math.min(( ! x), x)), Math.fround((mathy0(( + Math.hypot((( ! (0.000000000000001 >>> 0)) >>> 0), (y | 0))), ( + ( - (Math.tan((x | 0)) | 0)))) | 0))))))); }); testMathyFunction(mathy1, [42, -(2**53+2), -0x100000000, 0, 0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, 2**53, -0x080000000, 1, -0x100000001, -1/0, 1.7976931348623157e308, -0x080000001, 0x080000001, 0.000000000000001, 1/0, -(2**53), 0x080000000, 0/0, 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, -0x0ffffffff, 0x0ffffffff, -(2**53-2), -Number.MIN_VALUE, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=442; tryItOut("mathy3 = (function(x, y) { return Math.min(Math.fround(( - ( ! (x / 2**53-2)))), Math.fround(Math.hypot(Math.fround(Math.fround(Math.max(Math.fround(Math.log(( - (y | x)))), y))), Math.fround((Math.round(( + (Math.fround((x | 0)) | 0))) | 0))))); }); testMathyFunction(mathy3, [-0x080000000, 0x100000001, 0/0, 2**53+2, -(2**53-2), 0x07fffffff, -(2**53+2), -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -1/0, 0x080000001, Number.MIN_SAFE_INTEGER, 42, -0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -0x100000000, -(2**53), -Number.MIN_VALUE, -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, 1, 0, 2**53, 1/0, 0x100000000, Math.PI, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-246262462*/count=443; tryItOut("");
/*fuzzSeed-246262462*/count=444; tryItOut("/*oLoop*/for (var yxplzt = 0; yxplzt < 21; ++yxplzt) { selectforgc(o1); } ");
/*fuzzSeed-246262462*/count=445; tryItOut("\"use strict\"; a1 + s2;");
/*fuzzSeed-246262462*/count=446; tryItOut("\"use strict\"; s2 = new String;");
/*fuzzSeed-246262462*/count=447; tryItOut("{ void 0; void gc(this); }\nlet (\u000dy, c, swmiuw) { print(c **= window); }\n");
/*fuzzSeed-246262462*/count=448; tryItOut("\"use strict\"; /*RXUB*/var r = /\\s/gym; var s = \"0\"; print(uneval(s.match(r))); ");
/*fuzzSeed-246262462*/count=449; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=450; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=451; tryItOut("/*RXUB*/var r = true; var s = \"\\u000c\\u000c\\u000c\\u000c\\u000c\\n\\u000c\\ud023\\n\\u000c\\ud023\\n\\u000c\\ud023\\n\\u000c\\ud023\\n\\u000c\\ud023\\n\\u000c\\ud023\\n\\u000c\\ud023\\n\\u000c\\u000c\\u000c\\u000c\\u000c\\n\\u000c\\u000c\\u000c\\u000c\\u000c\\n\"; print(s.search(r)); ");
/*fuzzSeed-246262462*/count=452; tryItOut("testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0, -(2**53+2), 1/0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 0/0, 42, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, 2**53-2, -(2**53-2), 0x080000000, -(2**53), -0x100000001, Number.MAX_VALUE, 0, 0x07fffffff, 2**53+2, -Number.MIN_VALUE, 2**53, -0x080000000, -0x0ffffffff, 1.7976931348623157e308, 0x100000000, 0x100000001, 0x0ffffffff, 1, -0x07fffffff, -0x080000001, Math.PI]); ");
/*fuzzSeed-246262462*/count=453; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ ( + Math.fround(( ! ( + (0 > ( + Math.sin((x | 0))))))))); }); testMathyFunction(mathy1, [-0x080000000, -0x100000001, Math.PI, -(2**53), 1.7976931348623157e308, 0x080000000, 2**53+2, 2**53, -0x080000001, 0x0ffffffff, -(2**53-2), 0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 1/0, 0x100000001, 0/0, -Number.MAX_VALUE, 0x07fffffff, -0x100000000, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0]); ");
/*fuzzSeed-246262462*/count=454; tryItOut("\"use strict\"; ;function x(x, x)((function a_indexing(bbwgus, aaxhji) { ; if (bbwgus.length == aaxhji) { ; return [z1,,]; } var qxugzx = bbwgus[aaxhji]; var ocoqbl = a_indexing(bbwgus, aaxhji + 1); return \"\\u2150\"; })(/*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, new Boolean(true), new Boolean(false), window, new Boolean(true), new Boolean(false), new Boolean(true), function(){}, function(){}, window, true, true, window, window, window, new Boolean(false), new Boolean(false), window, true, window, function(){}, function(){}, window, new Boolean(true), new Boolean(false), new Boolean(true), true, function(){}, window, window, new Boolean(false), true, new Boolean(false), true, true, true, true, new Boolean(true), new Boolean(true), true, true, true, true, true, true, true, function(){}, function(){}, new Boolean(false), new Boolean(true), new Boolean(false), true, function(){}, window, new Boolean(true), window, window, new Boolean(false), function(){}, new Boolean(true), new Boolean(true), true, new Boolean(false), window, function(){}, window, true, new Boolean(false), true, window, new Boolean(false), function(){}, new Boolean(false), true, window, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, true, window, window, true, new Boolean(true), window, new Boolean(false), new Boolean(false), new Boolean(false), true, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, true, new Boolean(true), function(){}, true, new Boolean(true), window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, function(){}, window, true, new Boolean(true), new Boolean(true), true, new Boolean(false), true, function(){}, function(){}, true, new Boolean(true), window, new Boolean(false), new Boolean(false), window, function(){}, new Boolean(true), function(){}, new Boolean(true), function(){}, function(){}, function(){}, true, true, new Boolean(true), function(){}, new Boolean(true), new Boolean(true), window, true, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(false), window, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, new Boolean(false), true, window, window, new Boolean(false), new Boolean(true), true, true, new Boolean(false), window, new Boolean(true), function(){}, true, new Boolean(true), new Boolean(true), true, new Boolean(true), function(){}, function(){}, window, new Boolean(false), function(){}, window, new Boolean(false), new Boolean(true), new Boolean(true)], 0)) &= xprint((4277));");
/*fuzzSeed-246262462*/count=455; tryItOut("s0 += 'x';");
/*fuzzSeed-246262462*/count=456; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3\", \"i\"); var s = x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })(\"\\u712E\"), x); print(r.test(s)); ");
/*fuzzSeed-246262462*/count=457; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.pow(Math.sqrt((-Number.MIN_VALUE & mathy3(( - x), Math.max(x, x)))), ( + (Math.pow((Math.fround(( ! Math.fround((0x080000000 + Math.fround(x))))) >>> 0), (((Math.sinh(((((((Math.fround(x) ** (x >>> 0)) >>> 0) >>> 0) << (0x080000001 >>> 0)) >>> 0) , Math.fround(Math.log(Math.fround(( - x)))))) >>> 0) == x) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy4, [({valueOf:function(){return 0;}}), '0', 1, null, ({toString:function(){return '0';}}), '', false, true, undefined, (new Boolean(false)), 0, (new String('')), /0/, NaN, 0.1, (new Boolean(true)), (function(){return 0;}), '/0/', objectEmulatingUndefined(), [], (new Number(0)), '\\0', [0], -0, (new Number(-0)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-246262462*/count=458; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[new Boolean(true), -Number.MAX_VALUE, ['z'], -Number.MAX_VALUE, -Number.MAX_VALUE, ['z'], -Number.MAX_VALUE, new Boolean(true), -Number.MAX_VALUE, ['z'], -Number.MAX_VALUE, new Boolean(true), -Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=459; tryItOut("\"use strict\"; /*bLoop*/for (iyjayb = 0, []; iyjayb < 50; ++iyjayb) { if (iyjayb % 22 == 8) { /*MXX1*/Object.defineProperty(this, \"o0\", { configurable: false, enumerable: (x % 6 != 5),  get: function() {  return g0.Set.prototype.has; } }); } else {  /x/g ; }  } ");
/*fuzzSeed-246262462*/count=460; tryItOut("v0 = Object.prototype.isPrototypeOf.call(m1, b1);");
/*fuzzSeed-246262462*/count=461; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.tan(((Math.fround(Math.exp((( ! (x >>> 0)) >>> 0))) >>> Math.fround((( ! x) < Math.cbrt(y)))) !== Math.tan(((Math.cosh(x) | 0) | 0)))); }); testMathyFunction(mathy5, [2**53, 1/0, -0x080000000, 0/0, Number.MAX_VALUE, 0x0ffffffff, 0x080000001, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, 2**53-2, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, -0x080000001, -0x07fffffff, 0x100000001, -Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0x100000001, 0x080000000, -0x100000000, 0x100000000, 0x07fffffff, -0, 0, 42, Math.PI]); ");
/*fuzzSeed-246262462*/count=462; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.clz32((Math.fround(Math.pow(Math.fround(Math.tanh(( + ( + ( ~ 2**53+2))))), ( ~ y))) | (Math.cosh((y >>> 0)) | 0)))); }); testMathyFunction(mathy5, [-0x07fffffff, 1, 1/0, -0x080000001, -Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -0, Math.PI, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), 0x0ffffffff, 2**53+2, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, 0, 2**53, -0x100000000, Number.MAX_VALUE, 0x100000001, -0x0ffffffff, -(2**53-2), 42, 2**53-2, -1/0, 0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=463; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { \"use asm\"; return (((((Math.hypot(Math.atan2(y, (((( + x) == ( + y)) | 0) && (( ! y) >>> 0))), Math.min(x, x)) ? (Math.pow(y, x) >>> 0) : 0x080000000) | 0) >> Math.pow((Math.max(0x100000000, x) >>> 0), (Math.sqrt((y ** (Math.cbrt(Math.fround(x)) >>> 0))) || x))) | 0) | Math.imul(Math.round(Math.acos(( + (y ? x : -0x100000001)))), Math.asinh(((( ~ Math.fround(Math.fround((0.000000000000001 >>> x)))) | 0) ? y : (((((x >>> 0) <= y) | 0) ? (Math.cosh(2**53+2) | 0) : ((Math.pow((0x100000000 | 0), ((x - y) | 0)) | 0) | 0)) | 0))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 2**53, -0x080000000, -0x0ffffffff, 1.7976931348623157e308, -(2**53), 2**53+2, -0x07fffffff, 0.000000000000001, 42, -0, 2**53-2, Number.MIN_VALUE, -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, 1/0, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 0x080000001, -0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, -(2**53+2), 0]); ");
/*fuzzSeed-246262462*/count=464; tryItOut("m1.get(i2);");
/*fuzzSeed-246262462*/count=465; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.asinh((( + mathy2(Math.max(Math.fround(( ! ( ! Math.sinh(( + (( + y) ^ ( + x))))))), (Math.min(0.000000000000001, -(2**53)) | 0)), Math.fround((( + (( + Math.min(( + ( + Math.max(( + 2**53+2), ( + x)))), Math.fround(-0x080000000))) % ( + (x << y)))) ? ( + (( + Math.cos(Math.fround((x == y)))) && (y >>> 0))) : Math.hypot((( + ((y * (0/0 >>> 0)) | 0)) | 0), (((( + 42) >>> 0) <= ( + ((y , x) | 0))) | 0)))))) >>> 0)); }); testMathyFunction(mathy4, [-(2**53+2), 2**53-2, -(2**53-2), Number.MIN_SAFE_INTEGER, 42, 0, 0x100000001, 1/0, 2**53+2, -0x0ffffffff, 0.000000000000001, -0, -Number.MAX_VALUE, -0x080000000, -0x07fffffff, -0x080000001, Math.PI, 0x100000000, 2**53, 1.7976931348623157e308, -0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, 0x080000001, 0x0ffffffff, Number.MIN_VALUE, -(2**53), -0x100000000, 1, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=466; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (NaN);\n    return +((2.3611832414348226e+21));\n  }\n  return f; })(this, {ff: q => q}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0.1, 0, false, ({toString:function(){return '0';}}), '0', (new Number(0)), (function(){return 0;}), ({valueOf:function(){return 0;}}), undefined, null, (new Boolean(false)), ({valueOf:function(){return '0';}}), 1, true, [0], [], (new String('')), -0, '/0/', /0/, objectEmulatingUndefined(), '', (new Boolean(true)), '\\0', NaN, (new Number(-0))]); ");
/*fuzzSeed-246262462*/count=467; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.atan2((( + ( + Math.atan2(Math.fround(1/0), Math.fround(Math.fround(Math.acosh(x)))))) >= Math.fround((Math.atan2(Math.fround(Math.cbrt(Math.fround(y))), ((( + Math.fround((-0x080000000 | 0))) === ( + ((Math.atan2(-0x100000000, y) | (y | 0)) >>> 0))) >>> 0)) - Math.fround((Math.max(( + -0x100000000), ((Math.atanh(Math.fround(Math.sign(x))) ? (Math.atan((-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) : y) >>> 0)) >>> 0))))), ( + Math.cosh(( + (Math.imul(((( + Math.atan2((Math.fround(x) ^ Math.fround(-Number.MAX_VALUE)), (x >>> 0))) ? ( + x) : Math.fround(x)) | 0), (Math.max(y, ( + y)) | 0)) == ((Math.cos((y | 0)) | 0) >>> 0)))))); }); testMathyFunction(mathy1, [0.000000000000001, 2**53-2, -0, -Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, 1/0, 0x100000001, 0x080000000, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -0x100000000, 42, -Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 1, 0x100000000, -0x080000000, 0x080000001, 0/0, -(2**53-2), -0x080000001, Number.MIN_VALUE, 0x07fffffff, -1/0, -Number.MAX_VALUE, 2**53, -(2**53+2), -0x100000001, 0, Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-246262462*/count=468; tryItOut("g1.f2.toString = URIError.prototype.toString.bind(e1);");
/*fuzzSeed-246262462*/count=469; tryItOut("print(yield ({a1:1}));");
/*fuzzSeed-246262462*/count=470; tryItOut("e2.toSource = f0;");
/*fuzzSeed-246262462*/count=471; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.imul((( ~ Math.min(Math.asin(x), ( + (( + ( + (Math.fround(y) , (x != x)))) ** ( + Math.abs(( ! y))))))) >>> 0), Math.hypot((Math.atan((Math.fround(((x == ((y | 0) != (Math.tan(( + 0/0)) | 0))) ? (((Math.max((y >>> 0), (0x080000001 >>> 0)) >>> 0) | 0) | ((( ~ (y >>> 0)) >>> 0) | 0)) : x)) | 0)) | 0), (( - ( + (Math.imul((x >>> 0), y) >>> 0))) >>> 0))); }); ");
/*fuzzSeed-246262462*/count=472; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((0x3edc9cd8) > ((delete x.caller)>>>((i1))));\n    (Float32ArrayView[2]) = ((Float64ArrayView[2]));\n    return (((((((0xfd21a020)-(0xfd95346c)-(0x730ed87b))>>>(((-0x8000000) ? (0x7b08f72e) : (0x1c5722e0))+(i1))) % (((i0)+(i0))>>>((i0)+(i1)))) | ((abs(((0xfffff*(i0))|0))|0) % ((((0x5b447825) >= (0x58161eaa))*0xb8ea5) | ((!(0x1919a827))+(i1))))) % (((((i0))|0) % (((!(0x24d2ba6))-((+atan2(((-4611686018427388000.0)), ((-17179869184.0)))))) >> ((0x9782a1d5) / (0x0)))) >> (((((x)) << (((0x6f25b467))+(i1))))+(i0)))))|0;\n  }\n  return f; })(this, {ff: Math.min}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, -0x100000001, 0x100000001, Number.MIN_VALUE, 0x080000001, -(2**53-2), 0, 0x07fffffff, 2**53+2, -0x0ffffffff, 0.000000000000001, 42, 0x0ffffffff, -1/0, -(2**53), -0, 1.7976931348623157e308, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, 0x080000000, -0x080000000, -0x080000001, 2**53-2, 2**53, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1/0, -0x07fffffff]); ");
/*fuzzSeed-246262462*/count=473; tryItOut("var a = x;p2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((i1) ? ((((i1))>>>((i1)))) : (1))-(i1)))|0;\n    i0 = (i0);\n    return (((i1)))|0;\n  }\n  return f; });");
/*fuzzSeed-246262462*/count=474; tryItOut("mathy2 = (function(x, y) { return (Math.clz32(Math.expm1(Math.fround(Math.hypot(Math.fround(( + (( - (0.000000000000001 >>> 0)) >>> 0))), Math.fround(( + ( ~ ( + (Math.hypot(((( + x) & x) | 0), (y | 0)) | 0))))))))) >>> 0); }); testMathyFunction(mathy2, [1/0, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 0.000000000000001, -1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, 0x100000001, -0x100000001, 0, Math.PI, -(2**53+2), 1, Number.MAX_VALUE, 0x0ffffffff, 0/0, -0x080000001, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -(2**53), -Number.MAX_VALUE, 0x07fffffff, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53+2, 42]); ");
/*fuzzSeed-246262462*/count=475; tryItOut("\"use strict\"; /*MXX1*/o1 = g0.RegExp.leftContext;");
/*fuzzSeed-246262462*/count=476; tryItOut("\"use strict\"; a2.forEach((function mcc_() { var cgejen = 0; return function() { ++cgejen; if (/*ICCD*/cgejen % 2 == 1) { dumpln('hit!'); try { g2.__proto__ = b1; } catch(e0) { } Object.freeze(this.h0); } else { dumpln('miss!'); try { this.h0.getOwnPropertyNames = f0; } catch(e0) { } print(o1.h1); } };})(), t1, a1);");
/*fuzzSeed-246262462*/count=477; tryItOut("L:\u000cfor(let b in \"\\u7E70\") selectforgc(o1);");
/*fuzzSeed-246262462*/count=478; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + mathy2(( + Math.round(( - (x >>> 0)))), ( + Math.fround((Math.fround(Number.MIN_VALUE) ? Math.fround(x) : Math.fround(( + Math.fround(( + ( ~ 1/0)))))))))) >= Math.imul((((x % x) | 0) <= ( + y)), (( ~ Math.expm1(x)) !== ( + Math.cos((-0 >>> 0)))))); }); testMathyFunction(mathy5, ['/0/', 0, objectEmulatingUndefined(), '', (new Number(-0)), 1, ({valueOf:function(){return 0;}}), undefined, -0, '0', true, ({valueOf:function(){return '0';}}), null, '\\0', 0.1, false, (function(){return 0;}), (new Boolean(true)), (new String('')), NaN, /0/, (new Number(0)), (new Boolean(false)), [0], [], ({toString:function(){return '0';}})]); ");
/*fuzzSeed-246262462*/count=479; tryItOut("print(this.g2.t0);");
/*fuzzSeed-246262462*/count=480; tryItOut("\"use strict\"; i1.send(m2);var hwubzs = new ArrayBuffer(8); var hwubzs_0 = new Uint32Array(hwubzs); print(hwubzs_0[0]); hwubzs_0[0] = -0; print(hwubzs_0[8]);(new RegExp(\"(?!(?=[^])|(?=\\\\r)\\\\3|.{3}|[\\\\W\\u0013-\\\\u646a\\\\S](?:(?=[\\\\d]|\\\\B)(?=(?:[^\\\\cQ-\\u37a5\\\\W\\\\B]))))\", \"gyi\") += this);");
/*fuzzSeed-246262462*/count=481; tryItOut("print(/(?=\\2){1}/g <<= (4277));");
/*fuzzSeed-246262462*/count=482; tryItOut("{ void 0; void schedulegc(20); }function \u3056(x = -2)/*FARR*/[, , \"\\u4D4E\", ...[], -22, new RegExp(\"(?:(?=\\\\S|$|.{15,}^))\\\\3\", \"\"),  /x/g , ...[]].some(\u3056, eval)selectforgc(o0);");
/*fuzzSeed-246262462*/count=483; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=484; tryItOut("m0 = new Map;");
/*fuzzSeed-246262462*/count=485; tryItOut("");
/*fuzzSeed-246262462*/count=486; tryItOut("mathy0 = (function(x, y) { return Math.fround((((Math.cbrt((Number.MAX_VALUE | 0)) | 0) ? Math.round(( + ( - ( + Math.fround(( - Math.fround(y))))))) : Math.fround(( - Math.fround((Math.fround(((Math.sin(( + x)) >>> 0) >>> ( - x))) - y))))) !== Math.fround(( ! ( + ((Math.hypot((Math.log2(Math.min(( ~ x), x)) | 0), (x | 0)) | 0) !== ( + (Math.sqrt((1/0 >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy0, [-0x0ffffffff, -(2**53), 0/0, -0x07fffffff, 0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), -0x100000001, -Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 1.7976931348623157e308, 0x100000001, 42, 0.000000000000001, 0x07fffffff, 0, 0x080000000, 0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, -0, Number.MIN_VALUE, 1, 2**53, 0x080000001, -0x080000000]); ");
/*fuzzSeed-246262462*/count=487; tryItOut("mathy2 = (function(x, y) { return (Math.cos(( + ( + ( ~ ((y >>> 0) < ( + x)))))) >>> 0); }); ");
/*fuzzSeed-246262462*/count=488; tryItOut("print(x)\n");
/*fuzzSeed-246262462*/count=489; tryItOut("\"use strict\"; f2 + '';");
/*fuzzSeed-246262462*/count=490; tryItOut("print(let (c) /(?:\\3|((\\v*?))?)/gyi);");
/*fuzzSeed-246262462*/count=491; tryItOut("/*RXUB*/var r = /\\1/im; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=492; tryItOut("\"use strict\"; f0(m0);");
/*fuzzSeed-246262462*/count=493; tryItOut("v1 = Object.prototype.isPrototypeOf.call(this.v1, v0);");
/*fuzzSeed-246262462*/count=494; tryItOut("for(b in  /x/g ) {a0 = Array.prototype.map.call(a0, f2);let (ngdxjd) { v1 = (o1.p1 instanceof h0); } }");
/*fuzzSeed-246262462*/count=495; tryItOut("mathy5 = (function(x, y) { return Math.tan((( + (( + y) >>> 0)) | 0)); }); ");
/*fuzzSeed-246262462*/count=496; tryItOut("t2.set(a2, 2);");
/*fuzzSeed-246262462*/count=497; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.min((( + (mathy0(Math.log10(0), ( + (( + (((-0x080000001 | 0) && ((Math.min((x | 0), (-0x0ffffffff | 0)) | 0) | 0)) | 0)) < ( + y)))) >>> 0)) >>> 0), Math.fround((mathy0(((x ? (x >>> 0) : (((( ! y) >>> 0) ? x : -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0), Math.fround(mathy0((( - 0) | 0), ( + (Math.imul(Math.fround(x), ( ~ y)) >>> 0))))) | 0))); }); testMathyFunction(mathy1, [2**53-2, 0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, -0x07fffffff, Math.PI, 1/0, -(2**53-2), -0x100000000, 0, -1/0, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 2**53, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 0.000000000000001, Number.MIN_VALUE, -0x100000001, -Number.MIN_VALUE, -0x080000000, 1, 0x080000001, 0x080000000]); ");
/*fuzzSeed-246262462*/count=498; tryItOut("with({}) { throw StopIteration; } y.fileName;");
/*fuzzSeed-246262462*/count=499; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(( ! (Math.fround(Math.fround(mathy3(Math.fround(Math.imul((( ~ y) | 0), (( - (x | 0)) | 0))), Math.fround(x)))) & Math.fround(( + Math.fround(( + (( + x) < x)))))))); }); testMathyFunction(mathy5, [-Number.MIN_SAFE_INTEGER, -0, -(2**53), -(2**53-2), 0/0, 0x080000000, 0x07fffffff, 0x100000000, -0x100000000, -Number.MIN_VALUE, 2**53, -1/0, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, Math.PI, -0x07fffffff, 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -(2**53+2), 1, -0x080000000, 0x100000001, Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, 0x080000001, 1/0, -0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-246262462*/count=500; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.asin(mathy0(( ! 0x07fffffff), ( - ( + ( - ( + y)))))); }); ");
/*fuzzSeed-246262462*/count=501; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.imul(( ! (Math.max((y + Math.pow(( ~ Math.atan2(x, y)), ((( + (y | 0)) | 0) | 0))), (Math.log2(Math.fround(y)) | 0)) >>> 0)), Math.fround(( + (( + Math.atan2((( - (Math.atan2((( + Math.tanh(y)) | 0), ( - Math.ceil(-Number.MIN_SAFE_INTEGER))) | 0)) | 0), ((Math.fround(0.000000000000001) << Math.tan(0)) >>> 0))) < ( + ( ~ Math.atan2(Math.fround(( - Math.fround(( - Math.fround((Math.atan2((y | 0), (y | 0)) | 0)))))), ( + (Math.abs(Number.MAX_SAFE_INTEGER) ? 0 : ( + y)))))))))); }); testMathyFunction(mathy0, [1/0, -0, 42, 0x100000001, 0x080000001, -0x080000000, Math.PI, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 1, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0, -0x100000000, Number.MIN_VALUE, 0x07fffffff, -(2**53), -0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0/0, -1/0, -0x07fffffff, 2**53, 0x100000000, 2**53-2, -(2**53+2)]); ");
/*fuzzSeed-246262462*/count=502; tryItOut("\"use strict\"; o0 + f0;");
/*fuzzSeed-246262462*/count=503; tryItOut("\"use strict\"; print(this);;");
/*fuzzSeed-246262462*/count=504; tryItOut("\"use strict\"; a2[1];");
/*fuzzSeed-246262462*/count=505; tryItOut("print(x);\nprint(x);\nfunction x(d, x)\"use asm\";   var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1.0078125;\n    switch ((0x6660cde2)) {\n      case -3:\n        {\n          (Float64ArrayView[((((0xc511d8a0)*-0xfffff) ^ ((0x1883e44c) / (0x53277064))) % (~~(d2))) >> 3]) = ((d2));\n        }\n      case 1:\n        {\n          return (((!(0x7097411f))-(i0)-(i0)))|0;\n        }\n        break;\n      case -1:\n        d2 = (((d2)) - ((-16777217.0)));\n        break;\n      default:\n        {\n          i0 = ((-262144.0) == (d1));\n        }\n    }\n    d1 = (d2);\n    return (((((-4)*-0xb266f)>>>((0x8db35fe8) / (0x936556ea))) % (0xffffffff)))|0;\n    d1 = (d2);\n    (Uint8ArrayView[((-0x8000000)+(0x62aa0c9b)-(0xffffffff)) >> 0]) = (((+(((-0x8000000)-(!(1)))|0)))+((((((-6.044629098073146e+23) != (-3.777893186295716e+22))-(!(0x5caa0b8f)))>>>(((0xfbb615cc) ? (0xa021cd55) : (0xcad9392c))))) ? (i0) : (0xca6b3347))+(i0));\n    d2 = (d1);\n    switch ((abs((0x101f4a5a))|0)) {\n    }\n    {\n      i0 = (0x70b5acfb);\n    }\n    (/*MARR*/[Number.MIN_SAFE_INTEGER].map(Math.min(/[^]{2,}((?=\\B))|(^)+|(?=.)/im, 2))) = ((i0)+((0xb5496e43))-(new this.__defineGetter__(\"x\", function(q) { \"use asm\"; return q; })(x, \n '' )));\n    d1 = (((4277) & (void options('strict_mode'))));\n    d2 = ((0xf9740acb) ? ((((d2)) - ((Float32ArrayView[((0xfe499aed)*0xfffff) >> 2]))) + (((1.0078125)) % ((+(0x5e96ca31))))) : (((d2)) - ((4.835703278458517e+24))));\n    i0 = (0xfbfca425);\n    {\n      i0 = (-0x8000000);\n    }\n    d2 = (d2);\n    return (((0x2b48750e)-(i0)))|0;\n  }\n  return f;for(let e in  /x/g ) {m1 + o0;; }");
/*fuzzSeed-246262462*/count=506; tryItOut("var sadthb = new ArrayBuffer(2); var sadthb_0 = new Float64Array(sadthb); sadthb_0[0] = -18; var sadthb_1 = new Uint8ClampedArray(sadthb); print(sadthb_1[0]); sadthb_1[0] = -14; var sadthb_2 = new Int8Array(sadthb); var sadthb_3 = new Int16Array(sadthb); timeout(1800);var s1 = '';((sadthb_3 = length));/*RXUB*/var r = new RegExp(\"[^](?=(?=(\\\\2)))\", \"gy\"); var s = e; print(uneval(s.match(r))); print(r.lastIndex); f1 + '';v1 = Object.prototype.isPrototypeOf.call(g1, this.f0);o2.toString = f2;print((e++));");
/*fuzzSeed-246262462*/count=507; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-246262462*/count=508; tryItOut("/*infloop*/for([1,,]; (eval(\"(\\\"\\\\uE82D\\\");\")); ((function factorial_tail(qrkziz, mlnabq) { ; if (qrkziz == 0) { h2 + '';; return mlnabq; } v0 = g1.eval(\"/\\\\B/gim\");; return factorial_tail(qrkziz - 1, mlnabq * qrkziz);  })(3, 1))) ;");
/*fuzzSeed-246262462*/count=509; tryItOut("m0.has(g0);");
/*fuzzSeed-246262462*/count=510; tryItOut("testMathyFunction(mathy3, [-0x080000001, 0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, -(2**53), -(2**53+2), Math.PI, 1, -0x080000000, -Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, 0x07fffffff, 0x080000000, 0x100000001, 2**53, 42, -(2**53-2), Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, -1/0, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, 2**53+2, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-246262462*/count=511; tryItOut("mathy0 = (function(x, y) { return (((( - ( + Math.log1p((Math.atan(((x ** Math.PI) >>> 0)) >>> 0)))) >>> 0) | 0) - Math.cosh(( ~ Math.atan2(Math.fround(( + -Number.MAX_VALUE)), ((Math.cbrt((y | 0)) | 0) | 0))))); }); testMathyFunction(mathy0, [0x080000001, 0x100000001, -0x100000000, Number.MAX_VALUE, 0x080000000, -(2**53+2), 2**53+2, 0x100000000, -Number.MAX_VALUE, 0x0ffffffff, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, -(2**53-2), 1, 0/0, -0x080000000, -(2**53), -0, -0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 0, 0x07fffffff, -0x080000001, 42, -1/0, -Number.MIN_VALUE, 2**53-2, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=512; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.shift.call(a0);");
/*fuzzSeed-246262462*/count=513; tryItOut("s2 = '';");
/*fuzzSeed-246262462*/count=514; tryItOut("\"use strict\"; c;");
/*fuzzSeed-246262462*/count=515; tryItOut("/*tLoop*/for (let a of /*MARR*/[0.000000000000001, 0.000000000000001]) { g2.e0 + f1; }");
/*fuzzSeed-246262462*/count=516; tryItOut("\"use strict\"; o1.o2.e0.add(b1);");
/*fuzzSeed-246262462*/count=517; tryItOut("let f0 = Proxy.createFunction(h1, f0, f0);");
/*fuzzSeed-246262462*/count=518; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return Math.exp((mathy0((((mathy2((((y | 0) >> (-0x0ffffffff | 0)) | 0), ( ! -Number.MAX_SAFE_INTEGER)) >>> 0) , ( + (1/0 ? ( + x) : ( + Math.pow(( + ( ! y)), Math.fround(mathy2(x, x))))))) >>> 0), ( + (Math.imul(((( + (( + (Number.MAX_VALUE || 1.7976931348623157e308)) * ( + -1/0))) | 0) / x), Math.acosh(Math.sign(2**53+2))) | 0))) >>> 0)); }); ");
/*fuzzSeed-246262462*/count=519; tryItOut("if(true) {yield (4277);with({}) for(let z in /*FARR*/[]) yield /\\1/gi; } else  if (/*RXUE*/new RegExp(\"(\\\\v)?\", \"yi\").exec(\"\")) {for (var v of f1) { for (var v of this.s2) { try { g0.o0.g2.a0.forEach((function() { for (var j=0;j<66;++j) { f0(j%2==1); } })); } catch(e0) { } try { v2 = (this.m1 instanceof this.i0); } catch(e1) { } try { ; } catch(e2) { } this.o1.a1[2] = f0; } } } else v0.toString = Date.prototype.toUTCString.bind(o2);");
/*fuzzSeed-246262462*/count=520; tryItOut("\"use strict\"; let(eval = (x) = (4277), NaN, NaN = (this.__defineSetter__(\"x\", function  x (c) { yield -6 } ))) ((function(){for(let w in []);})());");
/*fuzzSeed-246262462*/count=521; tryItOut("/*RXUB*/var r = r0; var s = s1; print(uneval(r.exec(s))); print(r.lastIndex); ([,]);new RegExp(\"[^]|((^{0,4}+?|[^]|\\\\B[^]*|\\\\w{4}))\", \"\");");
/*fuzzSeed-246262462*/count=522; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=523; tryItOut("\"use strict\"; g1.i1 = this.a1[18];");
/*fuzzSeed-246262462*/count=524; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ (((Math.hypot(Math.fround(Math.cos((y | 0))), Math.sin(-(2**53-2))) ? ((Math.pow((y >>> 0), (((Math.min((x | 0), (Number.MIN_SAFE_INTEGER | 0)) | 0) ? (0/0 | 0) : y) >>> 0)) >>> 0) | 0) : Math.expm1(x)) | 0) ** (((Math.sqrt((y >>> 0)) >= ( + Math.expm1(Math.fround(Math.pow(x, -0x080000001))))) >>> 0) ? ((Math.tanh((((( + 0x080000000) > ((( ~ y) >>> 0) >>> 0)) >>> 0) | 0)) | 0) >>> 0) : (y >>> 0)))); }); testMathyFunction(mathy0, [(function(){return 0;}), NaN, '', 0, (new Boolean(true)), (new String('')), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '\\0', null, undefined, [], ({valueOf:function(){return 0;}}), true, (new Boolean(false)), false, /0/, (new Number(0)), -0, (new Number(-0)), 0.1, [0], 1, ({toString:function(){return '0';}}), '/0/', '0']); ");
/*fuzzSeed-246262462*/count=525; tryItOut("\"use strict\"; m2.set(this.o2, o0.o0.g1.s2);");
/*fuzzSeed-246262462*/count=526; tryItOut("o0.s0 = a0.join(this.s0);");
/*fuzzSeed-246262462*/count=527; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(mathy3(((Math.fround(Math.fround(Math.clz32(Math.fround(y)))) + ((((Math.fround((((Number.MAX_SAFE_INTEGER | 0) & (-0x07fffffff | 0)) | 0)) ? Math.fround(Math.log1p(y)) : Math.fround(Math.log1p((x ^ x)))) >>> 0) < (Math.acos(-(2**53-2)) >>> 0)) >>> 0)) | 0), ((((( + (( + Math.log10(( + y))) === ( + ( + (x ? x : (( ~ ( + ( ! Math.fround(x)))) >>> 0)))))) ^ Math.fround(Math.min(Math.fround(0x080000001), Math.fround(42)))) | 0) <= (Math.acos((( + ( + ( + x))) >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0/0, Math.PI, Number.MIN_VALUE, 0x080000001, 2**53, -Number.MAX_VALUE, 0x100000000, -0x080000001, -0x100000000, 1, Number.MAX_VALUE, 0x100000001, 0, -1/0, 2**53+2, -0x0ffffffff, 42, -0x100000001, Number.MAX_SAFE_INTEGER, 1/0, 0x080000000, 0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, -0x080000000, -0, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-246262462*/count=528; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, -(2**53+2), 42, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 2**53+2, 1/0, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, -1/0, -0x100000000, 0, -Number.MIN_SAFE_INTEGER, 1, 0x100000000, 1.7976931348623157e308, 2**53-2, -(2**53-2), 2**53, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, Math.PI, 0x080000000, -0, Number.MAX_VALUE, -0x080000001, -0x07fffffff]); ");
/*fuzzSeed-246262462*/count=529; tryItOut("v1 = g0.runOffThreadScript();");
/*fuzzSeed-246262462*/count=530; tryItOut("\"\\u7F06\";");
/*fuzzSeed-246262462*/count=531; tryItOut("/*ADP-2*/Object.defineProperty(o2.a0, v2, { configurable: /*FARR*/[].some, enumerable: true, get: (function() { for (var j=0;j<5;++j) { f0(j%3==0); } }), set: (function() { try { v2 = g0.eval(\"Object.defineProperty(g1, \\\"g1.e1\\\", { configurable: true, enumerable: (x % 6 != 2),  get: function() {  return new Set(e2); } });\"); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(t1, g0); } catch(e1) { } try { e = x, e, d = false\n;/*RXUB*/var r = [,,]; var s = \"\\n\\n\"; print(s.match(r)); print(r.lastIndex);  } catch(e2) { } g2.h0.__proto__ = f0; return b1; }) });");
/*fuzzSeed-246262462*/count=532; tryItOut("o2.a0 + this.t1;");
/*fuzzSeed-246262462*/count=533; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=534; tryItOut("\"use strict\"; o0.o0.f2(h1);");
/*fuzzSeed-246262462*/count=535; tryItOut("a2[(4277)] = a1;");
/*fuzzSeed-246262462*/count=536; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ ( + (( + ( ~ ( + -(2**53-2)))) ** (Math.fround(( ! ( + (( ! (-1/0 | 0)) | 0)))) < ( + (( + y) ? ( + ( + Math.atan2(0x100000000, x))) : x)))))) | 0); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -0x100000000, 0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -0, 2**53, -(2**53), 0x0ffffffff, 0x100000001, 0x100000000, 1, 0.000000000000001, -0x080000001, Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0/0, 1/0, 0x07fffffff, -Number.MIN_VALUE, -1/0, 42, -0x100000001, 0x080000001]); ");
/*fuzzSeed-246262462*/count=537; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.asinh(Math.fround(( ~ Math.pow(Math.fround(x), ( + ( ! (Math.expm1((x >>> 0)) >>> 0))))))); }); ");
/*fuzzSeed-246262462*/count=538; tryItOut("Array.prototype.sort.apply(a2, [Promise.prototype.then.bind(p1), s1]);");
/*fuzzSeed-246262462*/count=539; tryItOut("\"use strict\"; ");
/*fuzzSeed-246262462*/count=540; tryItOut("\"use strict\"; b1 = new ArrayBuffer(136);");
/*fuzzSeed-246262462*/count=541; tryItOut("Array.prototype.unshift.call(a2, h0, s0);");
/*fuzzSeed-246262462*/count=542; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ mathy0(( + Math.fround((Math.fround(( ! ( + -0x080000001))) !== Math.fround(Math.fround(( + Math.fround(((this % (y >>> 0)) >>> 0)))))))), ( + (( + (( + (Math.imul((Math.log(x) >>> 0), ((( ~ (y | 0)) | 0) >>> 0)) >>> 0)) >= ( + y))) ? ( ~ ( + 2**53)) : ((( ~ (mathy0(Math.fround(mathy0(Math.fround(-0x100000000), 42)), Number.MIN_VALUE) | 0)) >>> 0) | 0))))); }); testMathyFunction(mathy1, [-(2**53+2), 0x080000001, 1.7976931348623157e308, -0x100000000, -(2**53-2), 1/0, 42, 2**53+2, -Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 2**53-2, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, 1, 0x0ffffffff, Math.PI, 0x100000001, 0x07fffffff, 0x080000000, -0x100000001, 0x100000000, -0x07fffffff, Number.MAX_VALUE, 2**53, -1/0, 0, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-246262462*/count=543; tryItOut("v1 = t0.length;");
/*fuzzSeed-246262462*/count=544; tryItOut("\"use strict\"; v2 = (f2 instanceof f2);");
/*fuzzSeed-246262462*/count=545; tryItOut("/*infloop*/for(let (x( /x/ )) in ((objectEmulatingUndefined)((eval(\"/* no regression tests found */\")))))a1.pop(g1.i1);function w(this.eval) { o2 = v0.__proto__; } o0 + '';");
/*fuzzSeed-246262462*/count=546; tryItOut("o1.s1 += s1;");
/*fuzzSeed-246262462*/count=547; tryItOut("Array.prototype.splice.call(a0, NaN, 6, v1, m2);");
/*fuzzSeed-246262462*/count=548; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + mathy0(( + Math.log2((( + (Math.acos((y | 0)) | 0)) !== y))), ( + (Math.fround(((mathy1(Math.max(x, y), x) >>> 0) == ((Math.fround(Math.asinh(Math.fround(Math.tan(Math.fround(Math.atan(Math.fround(y))))))) | 0) === ((((Math.atanh(-(2**53-2)) >>> 0) ^ (0x100000000 >>> 0)) >>> 0) | 0)))) >> ( - (Math.min(x, x) >>> 0)))))); }); ");
/*fuzzSeed-246262462*/count=549; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x100000000, 0x080000000, 0.000000000000001, 2**53-2, 0x07fffffff, 0/0, 0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, 0, -Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -0x07fffffff, 0x080000001, 2**53, 42, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000001, -Number.MIN_VALUE, 2**53+2, -0, -(2**53), -0x0ffffffff, 1/0, -(2**53+2)]); ");
/*fuzzSeed-246262462*/count=550; tryItOut("\"use strict\"; e2 = new Set(a2);a1.forEach(f0);");
/*fuzzSeed-246262462*/count=551; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2\", \"gyi\"); var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-246262462*/count=552; tryItOut("\"use asm\"; v1 = Array.prototype.reduce, reduceRight.call(a2, (function(j) { if (j) { try { v2 = evalcx(\"if(false) print(window); else {i1.valueOf = f0;v1 = (g0 instanceof p2); }\", g2); } catch(e0) { } Array.prototype.reverse.apply(a2, []); } else { try { s0 += s2; } catch(e0) { } try { a0 = (x for (x in new (x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: Array.from, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: /*wrap2*/(function(){ \"use strict\"; var sulied = -18; var gglbgo = /*wrap1*/(function(){ \"use strict\"; \"use asm\"; (new RegExp(\"(?:\\ucb41|\\\\w)+?((?:[^]))*?|^(?=\\\\w{3,7})*([^])\\\\xd2\\\\3*?\\u00b0\\\\W+?+?\", \"m\"));return Set})(); return gglbgo;})(), fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: d =>  { \"use strict\"; return x } , set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(\"\\u6798\"), x ? (4277) : new RegExp(\"(?=[^\\\\u0018-\\\\\\uf4db\\\\f\\\\cG])+?\", \"i\")).throw((4277)))())\u0009 if ( \"\" )); } catch(e1) { } try { v0 = this.a2.length; } catch(e2) { } Object.freeze(g1); } }), g2, p1, o1.p1, s2, g2, t2, this.e2);");
/*fuzzSeed-246262462*/count=553; tryItOut("\"use strict\"; v1 = (v0 instanceof h0);");
/*fuzzSeed-246262462*/count=554; tryItOut("\"use strict\"; v2 = 4.2;");
/*fuzzSeed-246262462*/count=555; tryItOut("m2.has(o0);");
/*fuzzSeed-246262462*/count=556; tryItOut("\"use strict\"; a1.splice();");
/*fuzzSeed-246262462*/count=557; tryItOut("\"use strict\"; this.v1 = 0;");
/*fuzzSeed-246262462*/count=558; tryItOut("/*bLoop*/for (shwdmd = 0; shwdmd < 67; ++shwdmd) { if (shwdmd % 2 == 1) { /*RXUB*/var r = /\\2|(?=\\B|(?=[^])+?)/gi; var s = \"\"; print(r.test(s));  } else { const x = new RegExp(\"(?!\\\\1)+\", \"m\"), y, xtyxfx, epiibm, ixcqsy, nosbii;v0 = Object.prototype.isPrototypeOf.call(this.t1, m0); }  } ");
/*fuzzSeed-246262462*/count=559; tryItOut("const kuefyj, window =  \"\" , b = \"\\u02EA\", x, wenlpa, xbewgp, x, vjmndn, taoodw;( '' );");
/*fuzzSeed-246262462*/count=560; tryItOut("for (var v of s2) { try { for (var p in i0) { /*RXUB*/var r = r1; var s = \"\\n\"; print(s.split(r)); print(r.lastIndex);  } } catch(e0) { } s2 += 'x'; }");
/*fuzzSeed-246262462*/count=561; tryItOut("g2.offThreadCompileScript(\"(4277)\");");
/*fuzzSeed-246262462*/count=562; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"a2.push(t1, g1.o1.a0);\", ({ global: g2.g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 4 == 2) }));");
/*fuzzSeed-246262462*/count=563; tryItOut("testMathyFunction(mathy1, [1/0, 0x080000001, 0.000000000000001, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, -(2**53+2), 0x100000001, -0x080000000, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, -0x100000000, 2**53+2, -1/0, 0x100000000, 0, 0/0, 1, -(2**53), 42, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=564; tryItOut("v0 = (e1 instanceof e2);function x(eval) { \"use strict\"; v0 = a1.length; } /*vLoop*/for (bnzuby = 0; bnzuby < 11; ++bnzuby) { const z = bnzuby; this.g0.v1 = a2.some((function() { try { v1 = (m2 instanceof t0); } catch(e0) { } try { v0 = t2.BYTES_PER_ELEMENT; } catch(e1) { } try { m0.set(s0, o1); } catch(e2) { } v2 = (m0 instanceof this.m1); throw i1; })); } ");
/*fuzzSeed-246262462*/count=565; tryItOut("\"use strict\"; t2 = new Uint32Array(b1);");
/*fuzzSeed-246262462*/count=566; tryItOut("\"use strict\"; let window;/*infloop*/for(x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: Math.min, getPropertyDescriptor: Promise.reject, defineProperty: function(){}, getOwnPropertyNames: function() { throw 3; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: undefined, set: function() { return false; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: Uint8Array, keys: function() { return []; }, }; })(undefined), [].throw(\"\\u81E3\")); ( /x/g .valueOf(\"number\")).eval(\"o0.i0 = new Iterator(h0);\");  \"\" ) m1 = new WeakMap;");
/*fuzzSeed-246262462*/count=567; tryItOut("mathy2 = (function(x, y) { return ( + Math.log10(Math.fround((( + ((Math.clz32(x) ? y : x) == (Math.sign((mathy1(0, ( - (y >>> 0))) >>> 0)) >>> 0))) + Math.imul(( + y), ((Math.min(Math.cbrt((x >>> 0)), (( + (x && y)) | 0)) !== (mathy1(-0x080000000, ((y << (-0x100000001 | 0)) | 0)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy2, /*MARR*/[[1], [1],  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , [1], [1],  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , [1], [1],  /x/g , [1],  /x/g ,  /x/g , [1],  /x/g , [1], [1], [1],  /x/g , [1],  /x/g , [1], [1], [1],  /x/g , [1],  /x/g , [1],  /x/g , [1], [1],  /x/g ,  /x/g , [1], [1],  /x/g , [1],  /x/g , [1], [1],  /x/g , [1],  /x/g , [1],  /x/g ,  /x/g ,  /x/g , [1], [1],  /x/g ,  /x/g , [1],  /x/g ]); ");
/*fuzzSeed-246262462*/count=568; tryItOut("\"use strict\"; var ouruxi = new ArrayBuffer(0); var ouruxi_0 = new Uint8ClampedArray(ouruxi); print(ouruxi);print((4277));for (var v of e1) { try { s0 += s1; } catch(e0) { } Object.defineProperty(this, \"b1\", { configurable: (ouruxi_0[0] % 3 == 2), enumerable: false,  get: function() {  return t1.buffer; } }); }let (z) { print(x); }");
/*fuzzSeed-246262462*/count=569; tryItOut("var zvugdn, e = (eval(\"/* no regression tests found */\")), z, {of, a, d: []} = (c), e = (eval(\"\\\"use strict\\\"; mathy0 = (function(x, y) { \\\"use strict\\\"; return (Math.log1p((( - x) << Math.imul(( ~ (Math.acosh((x | 0)) | 0)), ( ~ x)))) != (Math.pow(( + Math.acos(((( ! (y | 0)) | 0) * y))), Math.pow((Math.sin(-0x07fffffff) >>> ((((0 | 0) ? (y | 0) : (y | 0)) | 0) + x)), y)) >>> 0)); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, 1.7976931348623157e308, -1/0, 2**53-2, -0x0ffffffff, 0x080000001, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 42, -0x080000001, -Number.MAX_VALUE, 1/0, -0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, 0x07fffffff, -0x100000001, 0/0, 0x100000000, -(2**53+2), 1, -(2**53), -(2**53-2), 0, 2**53, Number.MIN_VALUE, -0x07fffffff, -0, -Number.MIN_SAFE_INTEGER]); \", runOffThreadScript)), b, window = (uneval(true)), {} = ({arguments: this });for (var p in o2) { try { /*RXUB*/var r = r2; var s = s2; print(r.exec(s));  } catch(e0) { } a0.shift(s1); }");
/*fuzzSeed-246262462*/count=570; tryItOut("let (z) { { void 0; selectforgc(this); }\u000c }");
/*fuzzSeed-246262462*/count=571; tryItOut("\"use strict\"; v1 = g2.eval(\"print( '' );\");v1 = (s0 instanceof g0);");
/*fuzzSeed-246262462*/count=572; tryItOut("/*tLoop*/for (let e of /*MARR*/[NaN, arguments.callee, NaN, NaN, NaN, arguments.callee, NaN, arguments.callee, NaN, NaN, arguments.callee, arguments.callee, NaN, arguments.callee, arguments.callee, arguments.callee, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, NaN, NaN, NaN, arguments.callee, NaN, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, NaN, NaN, NaN, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, arguments.callee, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, arguments.callee, arguments.callee, NaN, NaN, arguments.callee, arguments.callee, NaN, arguments.callee, arguments.callee, NaN, arguments.callee, NaN, NaN, NaN, arguments.callee, arguments.callee, arguments.callee, NaN, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, NaN, NaN, arguments.callee, NaN, NaN, NaN, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, NaN, arguments.callee, NaN, NaN, arguments.callee, arguments.callee, NaN, NaN, NaN, arguments.callee, NaN, arguments.callee, NaN, arguments.callee, NaN, NaN, arguments.callee]) { print(e0); }");
/*fuzzSeed-246262462*/count=573; tryItOut("a0.shift(p2, g2, this.b1, this.o0, f2, this.m2, o2, p1, b1);");
/*fuzzSeed-246262462*/count=574; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ! (Math.fround(Math.hypot(Math.fround(((x , (Math.tanh((Math.trunc((y | 0)) | 0)) >>> 0)) >>> 0)), Math.fround(( + (( + ( + y)) >>> 0))))) != ( + (Math.fround(Math.hypot(Math.max(Math.fround(Math.min(0x080000000, x)), Math.fround(y)), (Math.round((y >>> 0)) >>> 0))) ** x)))); }); testMathyFunction(mathy1, [0.000000000000001, -1/0, -Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, -0x0ffffffff, 42, -(2**53), -0, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, -0x100000000, 0x100000001, Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, 0x080000000, 0x0ffffffff, -0x100000001, -0x080000000, Math.PI, 0, -(2**53-2), -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-246262462*/count=575; tryItOut("mathy2 = (function(x, y) { return Math.max(Math.imul(Math.cosh(Math.abs(((x ^ Math.fround((( + 1.7976931348623157e308) === y))) | 0))), Math.atanh((Math.acos((x | 0)) | 0))), Math.sinh((Math.fround(( + ((((y >>> 0) === (x >>> 0)) >>> 0) | 0))) | 0))); }); testMathyFunction(mathy2, [0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, 0, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, 42, -(2**53-2), 0x100000000, 2**53, 0x0ffffffff, -(2**53), 0.000000000000001, 1, 2**53-2, -Number.MIN_VALUE, 1.7976931348623157e308, -0, -0x07fffffff, 0x080000001, Math.PI, 2**53+2, -0x0ffffffff, -0x100000001, -0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-246262462*/count=576; tryItOut("print(/\\1(?=$|.\u00a0{1,1}|(?=[^]){0}{3,})/yim);var z =  /x/g ;");
/*fuzzSeed-246262462*/count=577; tryItOut("\"use asm\"; a2 = a1.slice(NaN, -2);");
/*fuzzSeed-246262462*/count=578; tryItOut("\"use strict\"; t0[1] = (x =  /x/g ) |= ([] =  '' );\nArray.prototype.unshift.call(a2, p0, h2, b1);\n");
/*fuzzSeed-246262462*/count=579; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + Math.imul(( + ((-0x100000001 || ( + (( + ( ! y)) % x))) | (Math.fround(( + Math.max(y, 0x07fffffff))) >= (( - Math.min(( + ( ~ ( + y))), ((x == (y | 0)) | 0))) >>> 0)))), ( + Math.acos((Number.MAX_VALUE - y))))) % Math.fround(( - ( ! y)))); }); testMathyFunction(mathy0, [-0x080000001, -(2**53+2), 0x080000000, -0x0ffffffff, 1/0, -0x07fffffff, -1/0, -0x100000001, 1, -(2**53-2), -(2**53), 42, 0/0, Math.PI, -0, 0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, Number.MIN_VALUE, 2**53+2, 0x100000001, 2**53, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001]); ");
/*fuzzSeed-246262462*/count=580; tryItOut("mathy3 = (function(x, y) { return ((Math.fround(Math.fround(Math.exp(Math.hypot(( + y), mathy1((x | 0), (y | y)))))) ? (Math.imul(( + Math.atan2((Math.sign((x ** Math.fround((Math.fround(Math.fround(( ~ y))) < Math.fround(x))))) >>> 0), Math.fround(( ! Math.fround(Math.fround(Math.asin(( + Math.fround(( + ( - x))))))))))), (Math.atan(((Math.abs(y) || Math.fround(Math.max(Math.PI, Math.fround(Math.max(y, y))))) | 0)) | 0)) >>> 0) : (((Math.fround(mathy1(( + (( + ( ~ Math.fround(y))) || y)), (((x | 0) ? (y | 0) : ((x | x) | 0)) | 0))) + ((( + (x >>> 0)) >>> 0) == a)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, objectEmulatingUndefined(), -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=581; tryItOut("\"use strict\"; v1 = false;");
/*fuzzSeed-246262462*/count=582; tryItOut("\"use strict\"; a2.forEach((function(j) { if (j) { try { Array.prototype.reverse.call(a2); } catch(e0) { } try { v1 = b1.byteLength; } catch(e1) { } for (var p in g0.i0) { try { h1 + v0; } catch(e0) { } try { m0.set(e1, g0.a0); } catch(e1) { } try { t2.set(a2, this.v0); } catch(e2) { } this.o0.g1 = a0[17]; } } else { try { a0 = Array.prototype.concat.call(a1, a0, a1); } catch(e0) { } try { var this.b1 = m0.get(h2); } catch(e1) { } try { g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 == 0), noScriptRval: x, sourceIsLazy: (x % 5 != 2), catchTermination:  })); } catch(e2) { } for (var p in g1.v1) { try { a2.shift(p0, p2); } catch(e0) { } print(uneval(m2)); } } }));");
/*fuzzSeed-246262462*/count=583; tryItOut("/*infloop*/ for  each(var x in /*UUV1*/(x.indexOf = /*wrap2*/(function(){ var vfuimk = x; var mfuzhg = decodeURIComponent; return mfuzhg;})())) {Array.prototype.push.apply(a1, []);/*RXUB*/var r = new RegExp(\"(?:(?!\\u3c79)|(\\\\b*?))\", \"y\"); var s = \"\"; print(s.search(r));  }");
/*fuzzSeed-246262462*/count=584; tryItOut("switch(( || (makeFinalizeObserver('nursery')) ** (break ))) { case e = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return []; }, }; })(((yield this.x) == (4277))), (uneval(/(?=(?=\u009c+)[^]|\\3{274877906944,}{3}?)/gi))): break; this.t2.__proto__ = o0;break;  }\n/*tLoop*/for (let d of /*MARR*/[ /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(true),  /x/ ,  /x/ , new Boolean(true),  /x/ ,  /x/ ,  /x/ , new Boolean(true), new Boolean(true),  /x/ , new Boolean(true),  /x/ , new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(true),  /x/ ,  /x/ , new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(true), new Boolean(true),  /x/ ,  /x/ ,  /x/ ,  /x/ ]) { (/\\b/gim); }\n");
/*fuzzSeed-246262462*/count=585; tryItOut("print(x.__defineGetter__(\"w\", Function).__defineSetter__(\"y\", offThreadCompileScript));");
/*fuzzSeed-246262462*/count=586; tryItOut("Object.defineProperty(this, \"b2\", { configurable: false, enumerable: true,  get: function() {  return t2.buffer; } });");
/*fuzzSeed-246262462*/count=587; tryItOut("testMathyFunction(mathy4, ['/0/', objectEmulatingUndefined(), /0/, -0, (new Number(0)), ({valueOf:function(){return '0';}}), (new String('')), (new Boolean(true)), [], (function(){return 0;}), [0], null, '', (new Number(-0)), ({valueOf:function(){return 0;}}), (new Boolean(false)), '0', 1, undefined, 0.1, ({toString:function(){return '0';}}), false, 0, NaN, true, '\\0']); ");
/*fuzzSeed-246262462*/count=588; tryItOut("t2[0] = p0;");
/*fuzzSeed-246262462*/count=589; tryItOut("mathy2 = (function(x, y) { return ((Math.sqrt(Math.fround((Math.imul((mathy0(Number.MAX_VALUE, x) >>> 0), ((( - (Math.min(Math.log(-(2**53)), x) | 0)) | 0) >>> 0)) >>> 0))) | 0) && (( + Math.expm1(( + mathy1((( + ((y < Math.fround(x)) >>> 0)) | 0), Math.fround((( + Math.abs((Math.cosh(( + 2**53+2)) | 0))) << Math.fround(Math.log10(Math.fround(Math.atanh(Math.fround((Math.fround(x) && y)))))))))))) | 0)); }); testMathyFunction(mathy2, [1, -(2**53-2), 0.000000000000001, 0x100000001, 42, -0x07fffffff, 2**53, 1.7976931348623157e308, Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 0, -(2**53+2), 2**53+2, -1/0, 0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 1/0, 0/0, -Number.MAX_VALUE, 2**53-2, -0x100000000, -0]); ");
/*fuzzSeed-246262462*/count=590; tryItOut("f0(f1);");
/*fuzzSeed-246262462*/count=591; tryItOut("/*vLoop*/for (var smarbb = 0; smarbb < 102; ++smarbb) { var x = smarbb; v2 = -0; } ");
/*fuzzSeed-246262462*/count=592; tryItOut("/*RXUB*/var r = r0; var s = s0; print(uneval(s.match(r))); ");
/*fuzzSeed-246262462*/count=593; tryItOut("a2 = a2.map((function mcc_() { var qytomz = 0; return function() { ++qytomz; if (/*ICCD*/qytomz % 9 == 3) { dumpln('hit!'); try { v2 = t1.BYTES_PER_ELEMENT; } catch(e0) { } try { a2.pop(); } catch(e1) { } try { v2 = (p0 instanceof f2); } catch(e2) { } for (var p in m0) { /*ADP-2*/Object.defineProperty(a2, v1, { configurable: false, enumerable: true, get: (function mcc_() { var ehgkkn = 0; return function() { ++ehgkkn; if (/*ICCD*/ehgkkn % 10 == 5) { dumpln('hit!'); try { h2 = ({getOwnPropertyDescriptor: function(name) { v0 = Array.prototype.reduce, reduceRight.call(a0, (function() { for (var j=0;j<45;++j) { f0(j%4==0); } }));; var desc = Object.getOwnPropertyDescriptor(g1.e1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { print(uneval(p2));; var desc = Object.getPropertyDescriptor(g1.e1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { return p0; Object.defineProperty(g1.e1, name, desc); }, getOwnPropertyNames: function() { v0 = (t1 instanceof v2);; return Object.getOwnPropertyNames(g1.e1); }, delete: function(name) { ;; return delete g1.e1[name]; }, fix: function() { t2 = t2.subarray(v2, ({valueOf: function() { v2 = 11;return 1; }}));; if (Object.isFrozen(g1.e1)) { return Object.getOwnProperties(g1.e1); } }, has: function(name) { v2 = g2.eval(\"this\");; return name in g1.e1; }, hasOwn: function(name) { Array.prototype.pop.call(this.a0);; return Object.prototype.hasOwnProperty.call(g1.e1, name); }, get: function(receiver, name) { a0[7];; return g1.e1[name]; }, set: function(receiver, name, val) { m1 = new Map(v2);; g1.e1[name] = val; return true; }, iterate: function() { a0 = arguments;; return (function() { for (var name in g1.e1) { yield name; } })(); }, enumerate: function() { i1.__iterator__ = String.prototype.match;; var result = []; for (var name in g1.e1) { result.push(name); }; return result; }, keys: function() { /*RXUB*/var r = r2; var s = \"\\u0019\\u0019\\u0019__\\n\\n\\n\\n\\n\\n\\n\\n\\n\\ucf30\\n\\n\\n\\u08b4\\n\\ucf30\\n\\n\\n\\u08b4\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\ucf30\\n\\n\\n\\u08b4\\n\\ucf30\\n\\n\\n\\u08b4\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\ucf30\\n\\n\\n\\u08b4\\n\\ucf30\\n\\n\\n\\u08b4\\n\\n\\na\\n\\u0019\\u0019\\u0019__\\n\\n\\n\\n\\n\\n\\n\\n\\n\\ucf30\\n\\n\\n\\u08b4\\n\\ucf30\\n\\n\\n\\u08b4\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\ucf30\\n\\n\\n\\u08b4\\n\\ucf30\\n\\n\\n\\u08b4\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\ucf30\\n\\n\\n\\u08b4\\n\\ucf30\\n\\n\\n\\u08b4\\n\\n\\na\\n\"; print(uneval(s.match(r))); ; return Object.keys(g1.e1); } }); } catch(e0) { } o0 + ''; } else { dumpln('miss!'); try { v1 = NaN; } catch(e0) { } /*RXUB*/var r = g0.r0; var s = \"\"; print(s.search(r)); print(r.lastIndex);  } };})(), set: Date.prototype.setFullYear.bind(s1) }); } } else { dumpln('miss!'); try { o0.m0 = new WeakMap; } catch(e0) { } a0[15] = ((e) = z); } };})());");
/*fuzzSeed-246262462*/count=594; tryItOut("v1 = t1.length;");
/*fuzzSeed-246262462*/count=595; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((Math.min((( + (( + x) / Math.fround((Math.log1p((x | 0)) | 0)))) >>> 0), (Math.asinh(y) | 0)) >>> 0) ? Math.ceil(( + (Math.pow((( + (x ? (((-0x100000001 >>> 0) << (y >>> 0)) >>> 0) : Math.atan2(x, Math.hypot((mathy0(x, x) | 0), Math.fround(x))))) >>> 0), (( - ( + Math.atan2(( + 0/0), ( + ( ! (x >>> 0)))))) >>> 0)) >>> 0))) : (( - Math.fround(((Math.atan2(y, x) >>> 0) , Math.expm1(( ~ y))))) | 0)) | 0); }); testMathyFunction(mathy2, [-0x07fffffff, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0.000000000000001, 1/0, -(2**53-2), -0x080000000, 2**53, -0x0ffffffff, 0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 0x100000000, 2**53-2, -0x100000000, -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, -(2**53+2), 0x080000001, Number.MAX_VALUE, 0x100000001, Math.PI, 2**53+2, 42, -Number.MIN_VALUE, -0, 1, -1/0, 1.7976931348623157e308, 0x07fffffff]); ");
/*fuzzSeed-246262462*/count=596; tryItOut("Array.prototype.splice.apply(a1, [-1, 12]);");
/*fuzzSeed-246262462*/count=597; tryItOut("/*iii*/x = linkedList(x, 1014);/*hhh*/function pxkurw(x){/*infloop*/for(var x in ((Function)(x))){v1 = (h1 instanceof f0); }}");
/*fuzzSeed-246262462*/count=598; tryItOut("\"use strict\"; v1 = this.t1.length;function x(x = x)\"use asm\";   var NaN = stdlib.NaN;\n  var sqrt = stdlib.Math.sqrt;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -274877906945.0;\n    var i4 = 0;\n    {\n      i0 = ((Float64ArrayView[(((((NaN) >= (9007199254740992.0)))>>>((i4))) % ((-0xf04e9*(i1))>>>(-0xfffff*((0x1356ef55) > (0x350d4557))))) >> 3]));\n    }\n    {\n      d3 = (+sqrt(((+(((~((i2)*0x3910e)) / (abs((imul(((this\u000c.__defineGetter__(\"e\",  '' .watch(\"caller\", /\\2|\\w|\\D{2097153,}(?:[^\u00d4\\d\\W]{1})+/m)))), ((0xe86ad2e1) >= (0x1bb77fc2)))|0))|0)) >> ((((0xfe430dee)+(0x7a21fa65)-(-0x8000000))>>>(((0x0) == (0x6cd2a3b0))-(-0x8000000))) % (((i4)+(-0x8000000))>>>((-0x8000000)+(0xafefe786)+(0xa8f7b661)))))))));\n    }\n    i1 = (0x474fad3a);\n    {\n      {\n        d3 = (+(-1.0/0.0));\n      }\n    }\n    {\n      i1 = (0xacf9382e);\n    }\n    {\n      d3 = (1.0);\n    }\n    i4 = ((-4.722366482869645e+21) < (-0.00390625));\n    return +((yield  '' ) === x &= x);\n  }\n  return f;(/(?!(?:\\b)(?!\\D|\\b|\u00c8)[^].[\\uaa16\\x2c-\u0088\\s]|(?=[^]){0}{4})/yi);{}");
/*fuzzSeed-246262462*/count=599; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=600; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-246262462*/count=601; tryItOut("\"use strict\"; /*RXUB*/var r = /$/; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=602; tryItOut("let(x = x, vbdfup, x, x, \u3056) { return ArrayBuffer.prototype;}");
/*fuzzSeed-246262462*/count=603; tryItOut("mathy1 = (function(x, y) { return (Math.min(( + Math.atan((Math.fround(Math.atan(y)) ^ y))), (Math.fround(( ~ Math.fround(((( + x) >= (((y >>> 0) - x) >>> 0)) >>> 0)))) | 0)) | 0); }); ");
/*fuzzSeed-246262462*/count=604; tryItOut("\"use strict\"; M:while(((y = x)(let (x =  /x/g , c, cbxepm, nvpqgl, x, vuzdwu, z, pprlmy, x) \"use strict\"; v1 = t2.length;, ((objectEmulatingUndefined).bind)({})) <= (d(new RegExp(\"\\\\b\", \"\")) = ({x: /^{4,8}[\ud2fa\\W\\w]?*|.[^]{5,5}[^]{1,}*/im !== null}))) && 0){for (var v of o2.v2) { try { o2.o1.o0.f2 = Proxy.createFunction(h0, f1, f1); } catch(e0) { } try { m0.valueOf = (function() { for (var j=0;j<7;++j) { f2(j%3==1); } }); } catch(e1) { } a0[({valueOf: function() { v2 = r1.global;return 13; }})] = b1; }/*infloop*/L: for  each(x in  '' ) v0 = evalcx(\"\\\"\\\\uF75D\\\"\", g1); }");
/*fuzzSeed-246262462*/count=605; tryItOut("\"use strict\"; h1.getOwnPropertyNames = f1;");
/*fuzzSeed-246262462*/count=606; tryItOut("print(x);");
/*fuzzSeed-246262462*/count=607; tryItOut("/*MXX3*/g1.Root = this.g2.Root;");
/*fuzzSeed-246262462*/count=608; tryItOut("\"use strict\"; s0 = '';");
/*fuzzSeed-246262462*/count=609; tryItOut("a2.sort();;");
/*fuzzSeed-246262462*/count=610; tryItOut("mathy0 = (function(x, y) { return Math.hypot(Math.max(( + Math.log1p(( + Math.hypot(((Math.max(y, 2**53) !== ( + Math.tan((x >>> 0)))) | 0), (Math.min(Math.exp(x), Math.fround(Math.max(Math.fround((( ~ (x | 0)) | 0)), Math.fround(y)))) | 0))))), Math.hypot(Math.hypot(( + (( + y) !== ( + y))), y), Math.cbrt(Math.fround(Math.hypot(( + y), ( + y)))))), (((Math.log2(Number.MIN_SAFE_INTEGER) | 0) * (Math.max(Math.max(y, ( ~ y)), Math.imul(( + Math.imul(x, (0x07fffffff | 0))), ( ~ x))) | 0)) | 0)); }); testMathyFunction(mathy0, [(function(){return 0;}), ({toString:function(){return '0';}}), '\\0', /0/, '/0/', objectEmulatingUndefined(), '0', ({valueOf:function(){return '0';}}), (new Number(-0)), undefined, '', 0, (new Number(0)), [0], null, (new String('')), NaN, [], (new Boolean(false)), -0, false, 0.1, ({valueOf:function(){return 0;}}), (new Boolean(true)), 1, true]); ");
/*fuzzSeed-246262462*/count=611; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.atan2((Math.fround((Math.fround(Math.sign((( ~ y) | 0))) / Math.fround(y))) & (Math.ceil(( + Math.log2(( + mathy4((( + x) == y), x))))) | 0)), Math.fround(Math.atan2(Math.fround((Math.min((2**53+2 | 0), ((Math.atanh(((( ! (y >>> 0)) >>> 0) | 0)) | 0) | 0)) | 0)), Math.fround(( ~ (Math.fround((Math.fround(y) | (( + ( - y)) ? (y | 0) : (( + Math.pow(x, ( + ( + Math.min(( + y), ( + x)))))) | 0)))) >>> 0))))))); }); ");
/*fuzzSeed-246262462*/count=612; tryItOut("with({}) { throw StopIteration; } ");
/*fuzzSeed-246262462*/count=613; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.atanh(Math.fround(Math.max(Math.fround((Math.max((Math.fround(Math.sign(x)) >>> 0), (y >>> 0)) >>> 0)), (Math.acos(( - mathy0(-0x080000000, Math.PI))) >>> 0))))); }); testMathyFunction(mathy3, [2**53+2, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, 0/0, 1.7976931348623157e308, 0, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, 1/0, 0x080000001, -0x080000001, -(2**53+2), -(2**53-2), -0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53, -0, 1, -0x100000000, -0x0ffffffff, 0x07fffffff, 42, -(2**53), 0x100000001, -1/0, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=614; tryItOut("\"use strict\"; var jayxrk = new SharedArrayBuffer(0); var jayxrk_0 = new Int32Array(jayxrk); jayxrk_0[0] = -18; (\"\\u1188\");t0[8];");
/*fuzzSeed-246262462*/count=615; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( ! (( + (y >>> 0)) >>> 0)) && Math.fround(Math.fround(Math.max((Math.fround(-0x07fffffff) | 0), (Math.min((Math.max(( + Math.imul(x, y)), (( + Math.hypot(x, y)) ? x : x)) >>> 0), (((Math.fround((((x >>> 0) === x) >>> 0)) | Math.fround((Math.min(( + x), (-1/0 >>> 0)) >>> 0))) | 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [0x080000001, -Number.MAX_VALUE, -1/0, 0x100000000, Number.MIN_VALUE, -0x080000001, 42, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 1, -Number.MIN_VALUE, -(2**53-2), -0x100000000, 2**53-2, -(2**53), -0x100000001, 2**53, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, -0x07fffffff, -0x0ffffffff, Math.PI, 0x100000001, 0.000000000000001, -0x080000000, 0x07fffffff, 2**53+2, 0x0ffffffff, 0]); ");
/*fuzzSeed-246262462*/count=616; tryItOut("pbzeow, e, x, z = e =>  { yield (this\n) } , xapuut, NaN, w = ( \"\"  +=  /x/ ).__defineSetter__(\"w\", (({/*TOODEEP*/})).call), eval = x.__defineGetter__(\"x\", /(?!\\b)/gym), x;t0.set(g0.t2, -5);");
/*fuzzSeed-246262462*/count=617; tryItOut("/*iii*/i1 = x;function c(x, ...txsohi) { yield  /x/g  } (Math);/*hhh*/function txsohi(z, x){Array.prototype.shift.apply(a0, [this.o2]);}");
/*fuzzSeed-246262462*/count=618; tryItOut("this.a2.shift(g2);");
/*fuzzSeed-246262462*/count=619; tryItOut("v1 = a0.length;");
/*fuzzSeed-246262462*/count=620; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0, -Number.MAX_VALUE, Math.PI, 2**53+2, -0x07fffffff, -0x100000001, 2**53, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, 0x0ffffffff, 0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -0x080000000, 0/0, Number.MIN_VALUE, -(2**53+2), 1/0, 0.000000000000001, 1.7976931348623157e308, 2**53-2, -1/0, -(2**53-2), 42, 1, -0, 0x100000000]); ");
/*fuzzSeed-246262462*/count=621; tryItOut("v2 = false;");
/*fuzzSeed-246262462*/count=622; tryItOut("Array.prototype.unshift.call(a0, m1, a1, v2, b0);");
/*fuzzSeed-246262462*/count=623; tryItOut("/*MXX1*/g2.o1 = g2.Symbol;");
/*fuzzSeed-246262462*/count=624; tryItOut("for (var v of e1) { o1 = {}; }");
/*fuzzSeed-246262462*/count=625; tryItOut("i0 = new Iterator(m0);");
/*fuzzSeed-246262462*/count=626; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(((((( ~ (mathy3((x >>> 0), ( + Math.cosh(( + x)))) >>> 0)) | 0) * ((Math.acos(y) >>> 0) ? Math.fround(Math.trunc(Number.MAX_VALUE)) : Math.log10(x))) | 0) ? mathy2(((Math.round(Math.clz32(( + (mathy3(1/0, x) | 0)))) | 0) ? ( ! (( ! x) | 0)) : ((-0 ? ( - ( - y)) : x) | 0)), y) : ( + Math.tan(Math.fround(mathy4(x, Math.fround(( + Math.sqrt(( + -0x0ffffffff)))))))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, -0x080000001, 0x100000000, 0x080000000, Math.PI, 2**53-2, 0, -(2**53+2), 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, 2**53, 1.7976931348623157e308, 0/0, 42, -1/0, -0, -0x100000001, Number.MAX_VALUE, -0x07fffffff, -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 2**53+2]); ");
/*fuzzSeed-246262462*/count=627; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.atan2(mathy0(Math.fround((x & Math.fround(( + x)))), Math.tanh(-(2**53+2))), ((((( + Math.max(( + x), ( + mathy0(0, x)))) | 0) ? (Math.log2(( + Math.pow(-Number.MIN_SAFE_INTEGER, x))) | 0) : (Math.fround((x - x)) | 0)) | 0) < ( + (( + y) ? ( + (( + (Math.fround(mathy0((y | 0), Math.fround(0/0))) >>> 0)) >>> 0)) : (x == y))))) | 0) ? Math.sign(Math.fround(Math.log1p(Math.fround(( + ( - (y | 0))))))) : ( * (Math.fround(Math.sin(Math.fround((( + (x >>> 0)) >>> 0)))) | 0))); }); testMathyFunction(mathy1, [0x100000001, -0x07fffffff, 0x080000000, 0, 42, 0x080000001, Math.PI, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, -(2**53-2), 1, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, -0x100000001, 1/0, -(2**53), Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, 0x0ffffffff, 1.7976931348623157e308, 0x100000000, -0, 0.000000000000001, 2**53, 0x07fffffff, 2**53-2, -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=628; tryItOut("\"use strict\"; var whzuqq = new SharedArrayBuffer(8); var whzuqq_0 = new Int16Array(whzuqq); whzuqq_0[0] = 2; var whzuqq_1 = new Int32Array(whzuqq); whzuqq_1[0] = -17; var whzuqq_2 = new Int16Array(whzuqq); print(whzuqq_2[0]); whzuqq_2[0] = -6; var whzuqq_3 = new Int16Array(whzuqq); whzuqq_3[0] = -12; var whzuqq_4 = new Uint8ClampedArray(whzuqq); var whzuqq_5 = new Int32Array(whzuqq); whzuqq_5[0] = -17; ([,,z1]);\nprint( '' );\nwith(-27){m2.has(a2);for (var p in e2) { try { v2 = this; } catch(e0) { } try { x = i1; } catch(e1) { } try { s1 += s0; } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(g1, t1); } }v0 = evalcx(\"print(uneval(f1));\", g1);");
/*fuzzSeed-246262462*/count=629; tryItOut("\"use strict\"; for (var v of e2) { try { e1 + b2; } catch(e0) { } try { s2 += o2.s2; } catch(e1) { } try { g0.i2.valueOf = (function() { try { o1.t1.set(g1.a2, 9); } catch(e0) { } try { Array.prototype.shift.apply(a2, []); } catch(e1) { } try { a0 = arguments.callee.caller.caller.arguments; } catch(e2) { } /*MXX3*/g0.Symbol.prototype.valueOf = g0.Symbol.prototype.valueOf; return p2; }); } catch(e2) { } o1 = a1; }");
/*fuzzSeed-246262462*/count=630; tryItOut("print(x);function x(w, x, x = this, x, eval, x, e, x, x, x, \u3056, \u3056 =  \"\" , \u3056, x, x, z, eval, NaN, b, c, x, b, \u3056, x, x, b, x, d, x, w, \u3056 = true, NaN = x, x, x, d, w, a = this, z, \u3056, d, x, x, eval, NaN, d, a, d, y, c, window, x, x, x, e = 6, x, y, window =  /x/ , c, w = NaN, x, x, eval, x, w, x, x, this.x, x = w, b = window, setter = -14, x, eval, d, w, c, eval = \"\\u450B\", \u3056, z, d) { \"use strict\"; (void schedulegc(g0)); } for (var v of g2.e2) { try { for (var p in a1) { try { /*ODP-1*/Object.defineProperty(s2, \"arguments\", ({get: Date.prototype.setUTCSeconds, enumerable: true})); } catch(e0) { } try { function f2(f1) \"use asm\";   var abs = stdlib.Math.abs;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 1.5474250491067253e+26;\n    (Uint8ArrayView[((1)+(-0x8000000)) >> 0]) = (((((i0)*-0xfffff)|0) == (abs((((i0)-(0x59b3448b)) << ((i0)+(-0x8000000))))|0))+(([] = x))-(!((((Uint16ArrayView[2]))>>>(((((0x8a9157da)) | ((0xfb4ad47c)))))) <= (0x0))));\n    return +((d2));\n  }\n  return f; } catch(e1) { } v2 = (m2 instanceof a0); } } catch(e0) { } try { Array.prototype.forEach.call(a2, (function mcc_() { var crbmsm = 0; return function() { ++crbmsm; if (/*ICCD*/crbmsm % 6 == 5) { dumpln('hit!'); try { Array.prototype.reverse.call(a0); } catch(e0) { } try { print(uneval(s0)); } catch(e1) { } a0[\"\\u14DF\"]; } else { dumpln('miss!'); try { v0 = evaluate(\"/*RXUB*/var r = r0; var s = s0; print(uneval(r.exec(s))); print(r.lastIndex); \", ({ global: g1.g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: -22, elementAttributeName: s1, sourceMapURL: s1 })); } catch(e0) { } try { f2 = Proxy.createFunction(h0, f0, f0); } catch(e1) { } v0 = t2.byteOffset; } };})()); } catch(e1) { } try { t1 = t0.subarray(\"\\u1716\", 10); } catch(e2) { } Array.prototype.forEach.call(a2, (function(j) { if (j) { try { Object.defineProperty(this, \"v0\", { configurable:  \"\" , enumerable:  /x/ ,  get: function() {  return false; } }); } catch(e0) { } try { m0.delete(NaN); } catch(e1) { } return; } else { a2.splice(NaN, 13, v2); } })); }");
/*fuzzSeed-246262462*/count=631; tryItOut("t1.toString = ((1 for (x in []))).bind();(this);");
/*fuzzSeed-246262462*/count=632; tryItOut("\"use strict\"; t1[\"call\"] = v0;");
/*fuzzSeed-246262462*/count=633; tryItOut("mathy1 = (function(x, y) { return ((Math.sqrt(( + (Math.pow(Math.fround(x), Math.acos(mathy0(y, mathy0((Math.fround(( + Math.fround(y))) | 0), (y | 0))))) >>> 0))) | 0) | Math.sinh(Math.hypot(( + (x & ( + Math.fround(( + (( + (Math.tan(Number.MIN_VALUE) >> ( + y))) >>> 0)))))), Math.exp(Math.min(( + (( + y) + y)), Math.fround(x)))))); }); testMathyFunction(mathy1, [NaN, (new String('')), null, false, 0.1, '', [0], /0/, (new Boolean(true)), true, undefined, -0, ({toString:function(){return '0';}}), 1, '0', objectEmulatingUndefined(), '\\0', ({valueOf:function(){return 0;}}), (new Boolean(false)), (new Number(0)), (function(){return 0;}), 0, [], (new Number(-0)), '/0/', ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-246262462*/count=634; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy0(((( ! mathy0(x, (( + ((Math.atanh(x) | 0) | 0)) | 0))) | 0) >>> 0), Math.fround(( ! (( + (Math.ceil(y) << y)) !== (Math.fround(Math.trunc(x)) >> Math.fround(((-Number.MIN_SAFE_INTEGER >>> 0) % Math.fround(Math.fround(Math.pow(Math.fround(y), Math.fround(0x0ffffffff))))))))))) >>> 0); }); testMathyFunction(mathy2, [0.000000000000001, -0x100000001, -0x0ffffffff, -(2**53+2), 2**53-2, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, -(2**53-2), 0x080000001, 0x080000000, -0x080000001, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0/0, -Number.MAX_VALUE, 0, -0x07fffffff, -1/0, Math.PI, 2**53+2, -0, 2**53, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 0x100000001]); ");
/*fuzzSeed-246262462*/count=635; tryItOut("e1.has(s1);");
/*fuzzSeed-246262462*/count=636; tryItOut("var NaN, \u3056, x =  '' .__defineSetter__(\"toString\", Object.prototype.toString), [, []] = [,], btriym, a =  /x/ , window;for (var v of m0) { try { /*bLoop*/for (ilsbmz = 0; ilsbmz < 40; ++ilsbmz) { if (ilsbmz % 6 == 1) { print(this.g1); } else { (d); }  }  } catch(e0) { } try { s0 += s2; } catch(e1) { } try { e2 + ''; } catch(e2) { } a1[19] =  /x/ .__defineGetter__(\"a\", (({/*TOODEEP*/})).apply) , ((x = ({a2:z2}))); }");
/*fuzzSeed-246262462*/count=637; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.min(Math.fround(( - Math.hypot(((Math.fround((Math.fround(x) * -0x080000000)) ? (Number.MIN_VALUE << Math.fround(( + (( + y) == y)))) : x) ? Math.fround(y) : Math.atan2(Math.fround((( ! Math.fround(y)) >>> 0)), Math.fround(y))), Math.max(Number.MAX_SAFE_INTEGER, Math.trunc(y))))), Math.fround(((Math.fround(( ! Math.fround(( ~ y)))) << (mathy0(((( - (mathy0(y, (Math.pow((y >>> 0), x) >>> 0)) >>> 0)) >>> 0) >>> 0), (Math.imul(42, Math.atan2(Math.fround(y), Math.fround(y))) >>> 0)) >>> 0)) >>> (Math.abs(mathy0(x, ( + Math.trunc(( + y))))) - (Math.fround((Math.fround(y) > x)) / ( - x))))))); }); testMathyFunction(mathy1, ['/0/', 0.1, true, false, [0], [], (new Number(-0)), NaN, '0', ({valueOf:function(){return '0';}}), (new Number(0)), -0, 1, ({valueOf:function(){return 0;}}), (new String('')), (function(){return 0;}), (new Boolean(true)), '', undefined, objectEmulatingUndefined(), ({toString:function(){return '0';}}), '\\0', 0, (new Boolean(false)), /0/, null]); ");
/*fuzzSeed-246262462*/count=638; tryItOut("mathy0 = (function(x, y) { return Math.min(Math.max((Math.asinh(((Math.max((Math.log10(Math.fround(-0x0ffffffff)) | 0), (x | 0)) | 0) >>> 0)) >>> 0), ((((((Math.atan2((x | 0), Math.atan2(x, Math.min(x, y))) | 0) >>> 0) | (( + (-0 | 0)) >>> 0)) >>> 0) >= (((Math.tan(( + mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -2251799813685248.0;\n    var d3 = 1.9342813113834067e+25;\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: x.reject}, new ArrayBuffer(4096)); )) >>> 0) | 0) ? (x | 0) : Math.cos(((-0 && -Number.MAX_SAFE_INTEGER) | 0)))) >>> 0)), (Math.fround(Math.hypot(Math.fround(Math.fround(Math.ceil(( + Math.max((Math.sin(1.7976931348623157e308) | 0), -0x100000000))))), Math.pow(y, x))) < ( - ( + ( - x))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0x080000000, 0x0ffffffff, -0x080000001, -(2**53+2), 0/0, -0x100000001, -1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0.000000000000001, 0, Number.MAX_VALUE, -0x07fffffff, Math.PI, 0x100000001, Number.MIN_VALUE, 2**53-2, 42, 2**53, -0, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, 1.7976931348623157e308, 0x080000001, -0x100000000, -(2**53-2), 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=639; tryItOut("this.v0 = a1.length;");
/*fuzzSeed-246262462*/count=640; tryItOut("\"use strict\"; v0 = g1.runOffThreadScript();/*infloop*/M:for([] = /*MARR*/[-Infinity, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, objectEmulatingUndefined(), -Infinity, new Boolean(false), new Boolean(false), new Boolean(true), new Boolean(true), new Boolean(true), -Infinity, new Boolean(false), new Boolean(true), -Infinity, new Boolean(false), new Boolean(true), -Infinity, new Boolean(false), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), new Boolean(false), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Boolean(false), new Boolean(true), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false)].filter; (p={}, (p.z = [[]] ? a : \"\\u24FF\")()); -9) i0.send(p2);\u000d");
/*fuzzSeed-246262462*/count=641; tryItOut("/*ADP-2*/Object.defineProperty(a0, 6, { configurable: true, enumerable: x, get: f2, set: f0 });");
/*fuzzSeed-246262462*/count=642; tryItOut("\"use strict\"; \"use asm\"; print(m0);");
/*fuzzSeed-246262462*/count=643; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-246262462*/count=644; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?:((?!\\\\W+)))+\\\\b)*\", \"gyi\"); var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=645; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 1.00390625;\n    var i4 = 0;\n    i2 = (i1);\n    (Uint16ArrayView[4096]) = (((0xc0ee528c) ? (0xffffffff) : (!(i2))));\n    i4 = (0x3d31a9e9);\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [1.7976931348623157e308, 42, 1, -0, 0, -0x100000001, 0/0, -(2**53), -(2**53+2), -0x0ffffffff, Math.PI, 0x080000000, 0x100000000, -0x080000001, 1/0, Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53, 0x07fffffff, 0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, 0.000000000000001, 0x0ffffffff, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, -Number.MAX_VALUE, 2**53-2, Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=646; tryItOut("/*tLoop*/for (let c of /*MARR*/[x, function(){}, x, new String(''), new Number(1), new Number(1), function(){}, x, null, x, x, new Number(1), null, null, x, function(){}, new Number(1), function(){}, null, new Number(1), x, x, function(){}, function(){}, new Number(1), new String(''), new String(''), x, new Number(1), null, x, new Number(1), function(){}, new Number(1), function(){}, null, new Number(1), new Number(1), x, null, new String(''), new String(''), new String(''), new Number(1), new Number(1), function(){}, null, null, null, function(){}, new Number(1), null, new String(''), function(){}, new Number(1), new Number(1), x]) { print((timeout(1800))); }");
/*fuzzSeed-246262462*/count=647; tryItOut("for (var p in b2) { m2.toSource = (function() { for (var j=0;j<1;++j) { f1(j%3==1); } }); }");
/*fuzzSeed-246262462*/count=648; tryItOut("\"use strict\"; a0.valueOf = (function() { t1 = t1.subarray(({valueOf: function() { s2 += s2;return 3; }}), 17); return p1; });");
/*fuzzSeed-246262462*/count=649; tryItOut("/*tLoop*/for (let b of /*MARR*/[[undefined], ['z'], ['z'], ['z'], eval(\"{null;h0.fix = f2; }\", (yield (allocationMarker()))), ['z'], eval(\"{null;h0.fix = f2; }\", (yield (allocationMarker())))]) { m1 = new Map(b0); }");
/*fuzzSeed-246262462*/count=650; tryItOut("v1 = Object.prototype.isPrototypeOf.call(m1, p0);");
/*fuzzSeed-246262462*/count=651; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0xa9f8e68)))|0;\n    d0 = (+((((((0x4dc70676) / (0x9db35976))>>>(-(0x9e65f4c))) >= ((-(0x4ba34c42))>>>((0xffffffff)-(0xfaafdfb0))))-((0x873e801b) <= (((0x7695e7dd)-(0xfccb0ab7))>>>((0xfbd5b416))))+(0xfe238c51))>>>((0xffffffff))));\n    d0 = (d1);\n    {\n      d0 = (d1);\n    }\n    (Float64ArrayView[((((((0x290158a7) < (0xe36a937e))-(0xfc0effe3))>>>(((-129.0) != (274877906945.0))+(0xf9e04403)-(((0xffffffff)-(0x8bc9a6b2)+(0xd63c878d))))))) >> 3]) = ((+(-1.0/0.0)));\n    (Float32ArrayView[2]) = ((-((+/*FFI*/ff((((((0x17b3c09c) ? ((0x0) < (0x8c9f7e41)) : (0x73964c61))+(0xa32c87a4)+((d1))) << (((0x3bd35e69) <= (((0x563f6309) / (0x7fffffff)) << ((Int8ArrayView[2]))))+(0x209aede7)))), (((((d0) >= (d1))) & (((0x6edd3919))+(0x82d21afb)+(0x55161d60)))), ((d0)), ((+abs(((d1))))), ((+((((-1.0078125) < (-16777215.0))+(0xfa0215c0))|0))), ((((0x3f67bb95) / (0x3d0b64e7)) >> ((0x22eee588)+(0xc56ad17b)-(0xeca37f60)))), ((d0)))))));\n    d0 = (d0);\n    {\n      {\n        d1 = (d0);\n      }\n    }\n    (Float64ArrayView[(((((0x2a5e0a4d))*0x995ab)>>>( '' )) % (0xc34fdeef)) >> 3]) = ((Float64ArrayView[(((0x0) != ((((uneval(\"\\u4CF6\")).__defineSetter__(\"b\", Array.from)))>>>((-0x8000000)-(0xfe4bc0f8)-((0xfadc9a94) <= (0x0)))))+(0x83e845fd)) >> 3]));\n    (Float64ArrayView[0]) = ((Infinity));\n    (Int32ArrayView[1]) = ((0x51990660)+(!(0x7eaa40d1))-(0x77c57482));\n    d1 = (((((+(1.0/0.0))) % ((d1)))) - ((Float64ArrayView[1])));\n    return (((0x83fd243e)*-0x900d0))|0;\n  }\n  return f; })(this, {ff: q => q}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-246262462*/count=652; tryItOut("o2.v0 = Object.prototype.isPrototypeOf.call(p1, i2);");
/*fuzzSeed-246262462*/count=653; tryItOut("let v0 = true;");
/*fuzzSeed-246262462*/count=654; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.log(( + mathy0((Math.pow(y, x) >>> 0), Math.imul(x, 0/0))))); }); testMathyFunction(mathy1, [-(2**53), -1/0, -(2**53+2), -Number.MAX_VALUE, Number.MAX_VALUE, 1, 0x100000000, -0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, Math.PI, 1.7976931348623157e308, 0x080000001, 1/0, 42, 2**53+2, 0, Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, 0.000000000000001, 2**53, -0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, -0x080000001, -0, -(2**53-2), 0x0ffffffff, 0x07fffffff, -0x080000000]); ");
/*fuzzSeed-246262462*/count=655; tryItOut("mathy0 = (function(x, y) { return Math.atan2((Math.atan2((Math.atan2((Math.atanh((((y >>> 0) - (x >>> 0)) >>> 0)) | 0), ( + Math.abs(x))) | 0), ((Math.atan2((Math.trunc((Math.fround(((x >>> 0) === Math.fround(Math.log1p(x)))) | 0)) | 0), (Math.min(y, 0x080000000) | 0)) !== Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0), ( + Math.asin((( ! ((y < x) | 0)) | 0)))); }); testMathyFunction(mathy0, [2**53+2, 1.7976931348623157e308, 0/0, -0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, 1, Math.PI, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -1/0, 0x100000000, 42, 0, 0x07fffffff, -0x100000000, 2**53, -(2**53+2), -0, 1/0, -0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -0x100000001, 2**53-2, -0x080000001, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=656; tryItOut("\"use strict\"; i1.toSource = (function() { this.a1.__proto__ = b2; return v2; });");
/*fuzzSeed-246262462*/count=657; tryItOut("mathy4 = (function(x, y) { return (((( + (Math.clz32(Math.clz32(x)) ** ((Math.sign(x) >>> 0) >>> 0))) | 0) ? (Math.atan2((( - Math.min(x, Math.min(x, ( + Math.fround(-(2**53-2)))))) | 0), ( + ( + (((Math.log((y + y)) | 0) ? ((Math.hypot(( + (2**53-2 || 1/0)), ( + ( + 0x0ffffffff))) >>> 0) | 0) : (y | 0)) | 0)))) | 0) : ((Math.abs((Math.asinh(Math.sign(((x ? (1 >>> 0) : (( + (x , y)) >>> 0)) >>> 0))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, ['/0/', null, (new Number(0)), '\\0', (function(){return 0;}), ({valueOf:function(){return '0';}}), NaN, (new Boolean(true)), ({toString:function(){return '0';}}), 0.1, [0], -0, undefined, (new String('')), ({valueOf:function(){return 0;}}), '0', [], /0/, 1, '', (new Number(-0)), 0, objectEmulatingUndefined(), true, (new Boolean(false)), false]); ");
/*fuzzSeed-246262462*/count=658; tryItOut("p0.__proto__ = g0;");
/*fuzzSeed-246262462*/count=659; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.asinh(((Math.max(Math.clz32(y), (Math.fround((y | 0)) | 0)) >>> 0) ? Math.fround((( + x) ^ Math.imul((((Math.fround(Math.atan2(Math.fround(x), Math.fround(42))) >= (((y | 0) ^ (42 | 0)) | 0)) | 0) ^ y), ( + Math.imul(y, ((( ~ -0x080000000) >>> 0) | 0)))))) : ((( + ( + ( + Math.min(Math.expm1(x), x)))) >>> 0) != (Math.max(( + Math.atan2(x, y)), Number.MIN_SAFE_INTEGER) >>> 0)))); }); testMathyFunction(mathy0, [-(2**53-2), 0x100000001, Math.PI, 1, 1/0, -Number.MAX_VALUE, 2**53+2, 0/0, 2**53, 0.000000000000001, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, -0x07fffffff, -0x100000001, 0x080000000, -1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -0x080000000, -Number.MIN_SAFE_INTEGER, 0, -0x080000001, 0x100000000, -0, 0x080000001, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-246262462*/count=660; tryItOut("print(/*MARR*/[x, this, this,  /x/g , this, x, this, this, this, this, x, this, this,  /x/g ,  /x/g , x, this,  /x/g , x, x,  /x/g , x, x, this,  /x/g ,  /x/g , this,  /x/g , this, this].sort(neuter,  '' ));");
/*fuzzSeed-246262462*/count=661; tryItOut("\"use strict\"; s2 += s0;");
/*fuzzSeed-246262462*/count=662; tryItOut("mathy4 = (function(x, y) { return Math.clz32(Math.fround(Math.imul((Math.max(x, Number.MIN_VALUE) ? (( + ( ~ ( ! ( + ((-Number.MIN_VALUE | 0) || (x | 0)))))) >>> 0) : mathy3(y, ((-(2**53+2) || (( ! ( + y)) >>> 0)) >>> 0))), ((((y >>> 0) ** ( + Math.max(-Number.MIN_SAFE_INTEGER, ( + (((y >>> 0) ^ x) >>> 0))))) | 0) >>> Math.sqrt(( + mathy3(( + x), ( + Math.ceil(x))))))))); }); testMathyFunction(mathy4, [0, -Number.MIN_VALUE, 2**53, 42, -0x100000001, 1, -(2**53+2), 1.7976931348623157e308, Math.PI, -0x080000001, 0x080000001, 0x100000001, -0x07fffffff, 0x0ffffffff, -0x080000000, Number.MIN_VALUE, 2**53-2, 2**53+2, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, 0.000000000000001, -(2**53), -1/0, -(2**53-2), 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=663; tryItOut("mathy3 = (function(x, y) { return (mathy0((( + ( - Math.max((( + ((Math.fround(y) ^ Math.fround(y)) - Number.MIN_SAFE_INTEGER)) >= ( + Math.atan2(0x100000000, -0x07fffffff))), (Math.imul(x, x) | 0)))) | 0), Math.fround(( ! Math.fround((y && Math.fround(( + Math.atan2(y, Math.fround(Math.log(Math.fround(y))))))))))) | 0); }); testMathyFunction(mathy3, [-0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000001, -0x100000000, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, Number.MAX_VALUE, 2**53+2, 0x07fffffff, 0x100000000, 0x100000001, -Number.MIN_VALUE, 42, -1/0, -(2**53), 2**53, 0/0, 0, 2**53-2, 1/0, 1, 0x080000001, Number.MIN_VALUE, 0.000000000000001, Math.PI, -0x080000001, 1.7976931348623157e308, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=664; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\3+?)\", \"gm\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=665; tryItOut("mathy3 = (function(x, y) { return (((Math.fround(mathy2(( + ((mathy1(Math.acosh(x), x) === (mathy0((Math.pow(y, x) | 0), mathy0((mathy2((y >>> 0), x) >>> 0), (Math.min((( + Math.log2(( + x))) >>> 0), (x >>> 0)) >>> 0))) >>> 0)) >>> 0)), ( + (Math.imul(((( - (( ~ Math.pow(x, y)) >>> 0)) >>> 0) | 0), Math.max(Math.fround((Math.fround(y) % Math.fround(y))), ( + (( + Math.log2(1.7976931348623157e308)) ? ( + y) : ( + y))))) >>> 0)))) >>> 0) ? (Math.asin((((( ! (( + Math.log10(y)) >>> 0)) >>> 0) % -(2**53)) >>> 0)) >>> 0) : (Math.log2(((2**53+2 << Math.imul(x, x)) ? Math.hypot(x, 0x0ffffffff) : Math.acosh(Math.abs((y ? -(2**53) : 0x07fffffff))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[ \"use strict\" , new Boolean(false), (void 0),  \"use strict\" ,  \"use strict\" , new Boolean(false), (void 0), 0x99, (void 0), new Boolean(false), (void 0), 0x99, 0x99,  \"use strict\" , 0x99, new Boolean(false), (-1/0),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Boolean(false), (void 0), 0x99, 0x99, (void 0),  \"use strict\" , 0x99, (-1/0), (void 0),  \"use strict\" , (-1/0), new Boolean(false), (void 0), new Boolean(false), (-1/0), new Boolean(false), new Boolean(false), 0x99,  \"use strict\" , new Boolean(false), 0x99, (-1/0), (-1/0), (void 0), 0x99, (-1/0), new Boolean(false), new Boolean(false), (void 0), (-1/0), (void 0), 0x99, new Boolean(false), (void 0), (void 0), (void 0), (-1/0), new Boolean(false), new Boolean(false), new Boolean(false), (-1/0), 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  \"use strict\" ,  \"use strict\" , new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (-1/0),  \"use strict\" , (void 0), 0x99, (void 0),  \"use strict\" , 0x99,  \"use strict\" , 0x99, (-1/0),  \"use strict\" , (void 0),  \"use strict\" , (void 0), (void 0), 0x99,  \"use strict\" , (-1/0),  \"use strict\" , new Boolean(false), (-1/0), new Boolean(false),  \"use strict\" , (-1/0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (-1/0), new Boolean(false), new Boolean(false), (-1/0), (-1/0)]); ");
/*fuzzSeed-246262462*/count=666; tryItOut("for (var v of v1) { try { delete h0.getOwnPropertyDescriptor; } catch(e0) { } try { v0 = evaluate(\"print(p1);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: 7, noScriptRval: (4277), sourceIsLazy: let (y = x) (4277), catchTermination: /*RXUE*//(?:\\W(?=([^\u5f24]){2,}).\\1|(?:^)\\2+?)/ym.exec(\"a\") })); } catch(e1) { } /*MXX2*/g1.String.prototype.fixed = m2; }");
/*fuzzSeed-246262462*/count=667; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=668; tryItOut("var v0 = null;");
/*fuzzSeed-246262462*/count=669; tryItOut("\"use strict\"; for(var b = (/*UUV1*/(z.all =  '' .for)) in -25) function this.f1(m1) \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    d0 = (-((d1)));\n    return (((0xf9f50df7)+((((0x4c07daaf)) | (((0xffffffff)))) < (abs((((0xfcef67ac)+(0xffffffff)-(0xc1eb5964)) & (((((0x2f630444) / (0xffffffff)) ^ (-0xfffff*(0x2aa03fa5)))))))|0))))|0;\n    d0 = (d0);\n    (Float64ArrayView[(-(0x25bfc4c7)) >> 3]) = ((+(1.0/0.0)));\n    d0 = (+pow(((d1)), ((+(-1.0/0.0)))));\n    d0 = (((-((d1)))) / (this.__defineGetter__(\"x\", objectEmulatingUndefined)));\n    d1 = (d1);\n    {\n      (Uint8ArrayView[(-0xbfabd*(1)) >> 0]) = ((-0x8000000)+((((0xffffffff)+(1))|0) <= (abs((((Int16ArrayView[4096])) >> ((~~(NaN)) / (((0xc403364f)) & ((0x35d71b25))))))|0)));\n    }\n    (Uint8ArrayView[0]) = ((((Float32ArrayView[0]))));\n    d1 = (d1);\n    d0 = (+(0.0/0.0));\n    d1 = (d0);\n    d1 = (+(-1.0/0.0));\n    return ((((((-0x732bf91)+((imul((0xfece5443), (0xf9040ff8))|0) >= (~((0xfbc827e3)-(0xffffffff))))+(1))>>>(((imul((0x70be105d), (0x714f92cd))|0) > ((((imul((-0x8000000), (0x59ace0bb))|0))) ^ ((0xfa42618b)+(0xffffffff)-(0xf9c75865)))))) <= (0xcc665811))))|0;\n    (Float32ArrayView[((0xd3c8c9d) / (((0x59757279)-(0x9ca94ff4)-(-0x8000000))>>>((0xfcd99f78)+(0xf98377d7)))) >> 2]) = ((d1));\n    d1 = (d1);\n    d0 = (((+(~((!(0x36557e))-(offThreadCompileScript.prototype)+(0xfe1d3413))))) / (((((Infinity)) / (((+(((0xfd7c9261))>>>((0x24d255dd)))) + (1.0)))) + ((0xfdceb058) ? (d1) : (d1)))));\n    d1 = (d0);\n    d1 = (d0);\n    return (((Uint16ArrayView[4096])))|0;\n  }\n  return f;");
/*fuzzSeed-246262462*/count=670; tryItOut("mathy1 = (function(x, y) { return (((Math.fround(Math.sign(-Number.MIN_SAFE_INTEGER)) / x) >>> (( ! (( - Math.fround(( + ( + (Math.PI >>> 0))))) | 0)) | 0)) < (( + (( + (y >>> 0)) ? (Math.fround(Math.hypot(-(2**53), Math.fround(y))) - (y && x)) : ( + ( ~ ( + mathy0(( + ( + y)), y)))))) || Math.log(Math.fround(mathy0((x >>> y), x))))); }); testMathyFunction(mathy1, [Math.PI, 1.7976931348623157e308, 2**53+2, 2**53, Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, -0x07fffffff, -(2**53-2), 0x080000001, Number.MAX_VALUE, -1/0, -(2**53+2), -0, -Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, -0x080000001, 0.000000000000001, 1/0, Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, 1, 0x100000001, -0x100000000, Number.MIN_VALUE, -0x080000000, 42, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=671; tryItOut("\"use strict\"; var yfqrek = new SharedArrayBuffer(12); var yfqrek_0 = new Int16Array(yfqrek); yfqrek_0[0] = 22; var yfqrek_1 = new Float64Array(yfqrek); yfqrek_1[0] = 0; var yfqrek_2 = new Uint8ClampedArray(yfqrek); print(yfqrek_2[0]); yfqrek_2[7];/*MXX2*/g0.RangeError.prototype.name = m2;");
/*fuzzSeed-246262462*/count=672; tryItOut("this.a2[9] = x;");
/*fuzzSeed-246262462*/count=673; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + Math.asin(( + (( + Math.fround(Math.imul((Math.pow(-(2**53), (x >>> 0)) >>> 0), (Math.acosh((0 | 0)) | 0)))) == Math.fround(Math.log(Math.fround(y))))))); }); testMathyFunction(mathy4, /*MARR*/[-0x080000001, -0x080000001, {}, -0x080000001, 0x080000001,  /x/g , {},  /x/g ,  'A' , -0x080000001,  'A' , -0x080000001, 0x080000001, -0x080000001, -0x080000001, {}, 0x080000001, {},  /x/g ,  /x/g , 0x080000001, -0x080000001, 0x080000001, 0x080000001,  /x/g , {}, -0x080000001,  /x/g , {}, -0x080000001]); ");
/*fuzzSeed-246262462*/count=674; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.sign(Math.fround(Math.tan((( + ( ~ -0x100000000)) | Math.cosh((( ! x) - (y >>> 0)))))))); }); testMathyFunction(mathy0, [0x100000000, 0/0, -(2**53+2), -0x080000000, 2**53, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 1/0, 1, Math.PI, 0, 0x080000001, -0x07fffffff, -0x100000001, 0x100000001, 1.7976931348623157e308, 0x07fffffff, -0x080000001, -(2**53-2), 2**53+2, 42, -1/0, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -0]); ");
/*fuzzSeed-246262462*/count=675; tryItOut("e = a;");
/*fuzzSeed-246262462*/count=676; tryItOut("/*RXUB*/var r = new RegExp(\"$\", \"i\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-246262462*/count=677; tryItOut("var d = (Array.prototype.reduce.prototype);t1.set(a2, ({valueOf: function() { Array.prototype.sort.apply(a2, [(function(j) { if (j) { try { g0.v1 = Object.prototype.isPrototypeOf.call(m1, s2); } catch(e0) { } v0 = Object.prototype.isPrototypeOf.call(b2, this.t2); } else { try { a0 = new Array; } catch(e0) { } /*ADP-1*/Object.defineProperty(a2, let (w = ({a2:z2}), xuuijs, tsjapy, a, d, x, sqsnjm) (4277), ({enumerable: (d % 2 != 1)})); } })]);return 2; }}));");
/*fuzzSeed-246262462*/count=678; tryItOut("\"use strict\"; M:if((x % 12 != 5)) { if (x) {m2.delete(v0); }} else print(x);");
/*fuzzSeed-246262462*/count=679; tryItOut("mathy3 = (function(x, y) { return ( + Math.pow(( + ( ! (( + Math.imul((( - (y | 0)) | 0), ( ! Math.min(( + y), y)))) ? Math.atan2((0x080000000 | 0), (Math.ceil((( ! y) | 0)) | 0)) : (Math.min((Math.hypot(-0x100000001, Number.MIN_SAFE_INTEGER) > x), x) < -0x080000001)))), Math.hypot(Math.fround((( + Math.fround((((((y | 0) ? x : x) | 0) | 0) == ((( ~ Math.fround(y)) | 0) | 0)))) >>> 0)), (( + (Math.atan2((Math.min(x, y) >>> 0), (y >>> 0)) >>> 0)) ? ((( + x) !== ( + y)) | 0) : Math.fround(Math.atan2(Math.fround(Math.pow(Math.imul(Math.fround(Math.atan2(Math.fround(x), Math.fround(y))), x), Math.imul(y, y))), ((Math.fround(mathy1(Math.fround(y), x)) ? Number.MIN_SAFE_INTEGER : (x >>> 0)) | 0))))))); }); ");
/*fuzzSeed-246262462*/count=680; tryItOut("for (var v of o1.g1.i2) { this.s1.toSource = (function mcc_() { var jyxqfz = 0; return function() { ++jyxqfz; if (jyxqfz > 0) { dumpln('hit!'); try { /*MXX2*/g2.Math.exp = g0; } catch(e0) { } try { v2 = evalcx(\"/* no regression tests found */\", g2); } catch(e1) { } s0 += 'x'; } else { dumpln('miss!'); try { Array.prototype.pop.apply(a0, [e2]); } catch(e0) { } a0.reverse(); } };})(); }");
/*fuzzSeed-246262462*/count=681; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.tan(Math.cosh(( - (-(2**53+2) >>> 0)))); }); testMathyFunction(mathy0, [-0x100000001, 2**53+2, -0, 0/0, Number.MAX_VALUE, 1, 0x080000000, Math.PI, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 2**53-2, 0x100000001, -0x080000001, -(2**53), 42, 0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 1/0, 1.7976931348623157e308, -(2**53+2), 2**53, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000000, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=682; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-246262462*/count=683; tryItOut("g0.v2 = Object.prototype.isPrototypeOf.call(s2, p2);");
/*fuzzSeed-246262462*/count=684; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.acosh(( + ( - x))) != mathy3((1.7976931348623157e308 >>> 0), ( ~ Math.hypot(y, y)))) || Math.acos((( ~ (( + ((Math.pow(((0x100000001 ? -0x07fffffff : y) | 0), x) | 0) > mathy2(( + (( + Math.max(-(2**53), y)) , Math.fround(0))), (x >>> 0)))) | 0)) | 0))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, 0, -0x080000001, 42, 0x100000001, -1/0, -0, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, 2**53, -(2**53-2), 0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, 2**53-2, -(2**53+2), Math.PI, 0/0, -Number.MAX_VALUE, 0x080000001, 1, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -0x080000000]); ");
/*fuzzSeed-246262462*/count=685; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.sort.call(a1, neuter);");
/*fuzzSeed-246262462*/count=686; tryItOut("i0.send(o2.i2);");
/*fuzzSeed-246262462*/count=687; tryItOut(";");
/*fuzzSeed-246262462*/count=688; tryItOut("v2 = false;");
/*fuzzSeed-246262462*/count=689; tryItOut("\"use strict\"; /*MXX2*/g0.Error.length = t1;");
/*fuzzSeed-246262462*/count=690; tryItOut("mathy3 = (function(x, y) { return ( - Math.imul(( + (Math.atan2(Math.fround(( ! ((x >>> 0) || x))), /*RXUE*/new RegExp(\"((?:[])|([^])*){2}|[^]{3}($(\\\\2))|(?![^])|\\\\B+?{1,}|\\\\B+\", \"ym\").exec(\"\")) < Math.log1p(Math.imul((y | 0), ( + ( ~ y)))))), ( + ((mathy1(((( ! y) >>> 0) | 0), Math.fround(Math.acosh(( + y)))) | 0) ** Math.cosh(mathy2(( ~ -Number.MAX_SAFE_INTEGER), (y >>> 0))))))); }); testMathyFunction(mathy3, [-0x080000000, 2**53-2, 0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -0x07fffffff, -0x080000001, 0x100000000, -1/0, -Number.MIN_VALUE, 1, 0.000000000000001, 1/0, -0x100000000, Math.PI, -0, 0/0, Number.MIN_VALUE, 42, Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -(2**53), 0x080000000, 0x080000001, -(2**53+2), -0x100000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=691; tryItOut("mathy3 = (function(x, y) { return Math.sqrt((Math.trunc((Math.log2(Math.fround(mathy0(x, mathy1(Math.fround(( ~ Math.fround(y))), (y ? -0x080000000 : x))))) | 0)) | 0)); }); testMathyFunction(mathy3, [0x0ffffffff, 0.000000000000001, -(2**53+2), 0, 2**53-2, -Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000001, 2**53, 42, -0x100000000, 0x100000001, 0x07fffffff, -0x100000001, -(2**53), Math.PI, -(2**53-2), -1/0, -0, 0x100000000, 1, Number.MAX_VALUE, Number.MIN_VALUE, 0/0, 0x080000001, 1/0, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=692; tryItOut("\"use strict\"; var x = (b = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: runOffThreadScript, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function(name) { return delete x[name]; }, fix: \"\\u1B9C\", has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: undefined, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: encodeURI, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })([1,,]), encodeURIComponent, decodeURI)), x = ({ get -8 x (x = NaN, y, x, x, c, NaN, a, y, x, NaN, this.c, x, a, eval, c = -6, \u3056, x = null, x, window, \u3056, eval = this, window, x =  '' , x, x, x, 1, x, w, b, x, \u3056, eval, x, b, w, w = \"\\u1290\", a, x, x, b, x, x, c, \u3056 = /(\\b|\\B)/y,  /x/ , x, x, d = \"\\u39DF\", x, \"\\u4204\", d, \"17\", x, x = ({a1:1}), x = window, a, 22, d, x, x, \u3056, x, c, x, e,  , w, yield = new RegExp(\"(?=(?=(?:\\\\1)*?))(?=\\\\3[^]\\\\3)\", \"yi\"), x, NaN, x, w =  '' , x, x, x, x, d, ...e) { o2.v2 = evaluate(\"i0 = new Iterator(o0.h0);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: -1, noScriptRval: (x % 27 == 12), sourceIsLazy: 7, catchTermination: (x % 2 == 0) })); }  }), x = x, NaN = x, x, d, mibhzr, x, c, w;a1.push(a2, o0, e1, o1);");
/*fuzzSeed-246262462*/count=693; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( + ( - ( ! Math.trunc((Math.cbrt(x) | 0))))) ? Math.fround(Math.max((((( ! ( + y)) | 0) !== (y | 0)) | 0), Math.log2(( + x)))) : Math.atan2(((( ! x) | 0) , Math.fround(Math.max(Math.fround((x >> 0x080000001)), Math.fround(x)))), mathy0(((Math.hypot((x >>> 0), y) >>> 0) | 0), ((x ? (x ? (Math.min((y >>> 0), y) >>> 0) : Math.fround(-1/0)) : (x >>> 0)) | 0)))); }); testMathyFunction(mathy3, [(new Number(0)), true, '', '\\0', (new Number(-0)), (new Boolean(false)), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), null, -0, ({valueOf:function(){return '0';}}), false, 1, 0.1, (new String('')), [], NaN, (new Boolean(true)), [0], undefined, objectEmulatingUndefined(), 0, /0/, '0', '/0/', (function(){return 0;})]); ");
/*fuzzSeed-246262462*/count=694; tryItOut("for (var v of f1) { try { Object.defineProperty(this, \"a0\", { configurable: (4277), enumerable: true,  get: function() {  return /*MARR*/[[], Number.MAX_VALUE, [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], Number.MAX_VALUE, Number.MAX_VALUE, [], Number.MAX_VALUE, Number.MAX_VALUE, [], [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], Number.MAX_VALUE, [], [], [], [], [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], [], Number.MAX_VALUE, Number.MAX_VALUE, [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], [], [], [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], [], [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], Number.MAX_VALUE, [], [], Number.MAX_VALUE, [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], [], [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], Number.MAX_VALUE, [], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, [], []]; } }); } catch(e0) { } try { /*RXUB*/var r = g1.g0.r1; var s = s1; print(s.match(r));  } catch(e1) { } try { /*ADP-3*/Object.defineProperty(a0, this.v1, { configurable: false, enumerable: (x % 5 == 1), writable: true, value: o0 }); } catch(e2) { } e2.delete(f0); }");
/*fuzzSeed-246262462*/count=695; tryItOut("(new (Function).bind( /* Comment */new RegExp(\"(?:(?:[\\\\u0098\\u00c3\\\\cK-\\\\u0057]))\", \"gy\"))((/*MARR*/[].some(function(y) { \"use asm\"; return 0 })), (z = NaN)));");
/*fuzzSeed-246262462*/count=696; tryItOut("testMathyFunction(mathy4, [0x100000001, -0x080000001, 1.7976931348623157e308, 2**53+2, 1, 2**53, -Number.MIN_VALUE, 2**53-2, Math.PI, 0x080000001, -0x100000001, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -1/0, Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, -0x080000000, -0x07fffffff, -(2**53-2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000000, 1/0, 42, 0x080000000, -0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0]); ");
/*fuzzSeed-246262462*/count=697; tryItOut("\"use strict\"; o0.m1.get(f0);");
/*fuzzSeed-246262462*/count=698; tryItOut("testMathyFunction(mathy0, [0.000000000000001, Number.MAX_VALUE, 1/0, 0x080000001, Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -1/0, 2**53-2, 2**53+2, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000001, -0, Math.PI, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, 0x07fffffff, -0x100000000, 0x080000000, 2**53, 1.7976931348623157e308, -Number.MAX_VALUE, 1, 0x0ffffffff, -(2**53), 0, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=699; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.imul(((((((Math.max((x | 0), (( + ( ~ ( + ( + Math.atan2(( + y), ( + y)))))) | 0)) | 0) === ( + Math.fround((x != y)))) == (Math.pow(y, ((Math.min(Math.fround(( + ( ! Number.MAX_VALUE))), (x >>> 0)) | 0) >>> 0)) >>> 0)) >>> (Math.hypot(mathy3(1, x), (Math.pow(((( + (((y >>> 0) / y) != y)) ? x : (y | 0)) | 0), y) | 0)) | 0)) >>> 0) >>> 0), mathy0(( + ( - ( + ( + ( + Math.sin(y)))))), ( + mathy2(Math.fround(Math.ceil(x)), Math.abs(x))))) >>> 0); }); testMathyFunction(mathy4, [42, -(2**53+2), -0x100000001, -Number.MIN_VALUE, Math.PI, 0, 2**53-2, -0x080000000, 0x0ffffffff, 1/0, 0/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -0x07fffffff, 0x080000000, -1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, 0x07fffffff, 2**53+2, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, 1, 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), -0x0ffffffff, -0, -(2**53)]); ");
/*fuzzSeed-246262462*/count=700; tryItOut("/*MXX3*/g1.Date.prototype.getUTCMilliseconds = g0.Date.prototype.getUTCMilliseconds;");
/*fuzzSeed-246262462*/count=701; tryItOut("NaN = linkedList(NaN, 1530);");
/*fuzzSeed-246262462*/count=702; tryItOut("mathy0 = (function(x, y) { return (Math.sin(((( ~ ((( + x) <= y) >>> 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -(2**53+2), -Number.MAX_VALUE, 2**53+2, 42, -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, 0, 1, 0x100000001, -1/0, -(2**53-2), 2**53-2, -0, -0x080000000, 0x100000000, -0x100000001, Math.PI, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -(2**53), 2**53, 0.000000000000001, 0x07fffffff, 0x080000000]); ");
/*fuzzSeed-246262462*/count=703; tryItOut("g0.a0.push(g0, a0);");
/*fuzzSeed-246262462*/count=704; tryItOut("\"use strict\"; let (c) { s2.toSource = this.f0; }");
/*fuzzSeed-246262462*/count=705; tryItOut("/*tLoop*/for (let x of /*MARR*/[(void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (-1), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(true), (void 0), new Boolean(true), (void 0), (void 0), (-1), (void 0), (-1), (void 0), (void 0), (void 0), x, (void 0), new Boolean(true), (void 0), (-1), x, (void 0), x, (void 0), x, x, (void 0), (-1), new Boolean(true), x, x, x]) { print(/*FARR*/[x, , (new \"\\uB6F8\"(x,  /x/g ))].filter(String.prototype.blink, new (({/*TOODEEP*/}))(this).valueOf(\"number\"))); }");
/*fuzzSeed-246262462*/count=706; tryItOut("var dkloiw = new SharedArrayBuffer(16); var dkloiw_0 = new Uint16Array(dkloiw); print(dkloiw_0[0]); dkloiw_0[0] = 5; var dkloiw_1 = new Float32Array(dkloiw); dkloiw_1[0] = -2; var dkloiw_2 = new Int32Array(dkloiw); dkloiw_2[0] = -16; var dkloiw_3 = new Uint32Array(dkloiw); print(dkloiw_3[0]); dkloiw_3[0] = -12; var dkloiw_4 = new Uint8Array(dkloiw); dkloiw_4[0] = -28; var dkloiw_5 = new Uint32Array(dkloiw); print(dkloiw_5[0]); var dkloiw_6 = new Int8Array(dkloiw); var dkloiw_7 = new Float32Array(dkloiw); var dkloiw_8 = new Int8Array(dkloiw); dkloiw_8[0] = -6; Array.prototype.push.call(o2.o2.a0, (Math.hypot(\"\\uEB5F\", 0.873)), this.i1);(void schedulegc(g2));print(dkloiw_5);switch(x) { default: throw -25; }m1.has(m0);for (var v of p2) { try { t2 = t0.subarray(v2); } catch(e0) { } try { /*MXX3*/g2.Float32Array.prototype.BYTES_PER_ELEMENT = g1.Float32Array.prototype.BYTES_PER_ELEMENT; } catch(e1) { } a0.unshift(this); }print(dkloiw_0[0]);");
/*fuzzSeed-246262462*/count=707; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul(Math.fround(Math.atan2((((y | 0) / (Math.max(( + Math.atan2(( + ((x >>> 0) ? (Number.MAX_SAFE_INTEGER >>> 0) : (x >>> 0))), ( + 0x07fffffff))), (( ~ (y | 0)) | 0)) | 0)) | 0), Math.fround((Math.log10(Math.fround(( ! ( ! y)))) >>> 0)))), (Math.cosh((Math.fround((Math.fround(mathy0(x, x)) <= Math.fround(Math.fround(((Math.fround(var rbkybv = new ArrayBuffer(2); var rbkybv_0 = new Float64Array(rbkybv); print(rbkybv_0[0]); y;) ? (Math.abs((y >>> 0)) >>> 0) : ( + ( + ( + 0x080000001)))) + ( + x)))))) | 0)) | 0)); }); testMathyFunction(mathy1, [2**53+2, 0, 42, -0x080000001, 2**53-2, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 1/0, -Number.MAX_VALUE, Number.MAX_VALUE, 1, -(2**53), -1/0, Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -Number.MIN_VALUE, -(2**53+2), 2**53, -0x100000001, 0.000000000000001, -0x0ffffffff, 0x080000001, Number.MIN_VALUE, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, 1.7976931348623157e308, 0x080000000, -0x07fffffff, 0x07fffffff]); ");
/*fuzzSeed-246262462*/count=708; tryItOut("v1 = (o1.p2 instanceof h2);");
/*fuzzSeed-246262462*/count=709; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.cos((( ~ ( + -0x080000001)) >>> 0))); }); testMathyFunction(mathy5, [42, -0x080000001, -0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, 0x100000001, 0x0ffffffff, Math.PI, -0x100000000, -(2**53), Number.MAX_VALUE, -Number.MAX_VALUE, 2**53-2, 0.000000000000001, -1/0, 1/0, 1.7976931348623157e308, 1, -(2**53+2), -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, 0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, -Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, -0x100000001, -0, Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=710; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-246262462*/count=711; tryItOut("\"use strict\"; o0.toSource = (function() { for (var j=0;j<71;++j) { f1(j%2==1); } });");
/*fuzzSeed-246262462*/count=712; tryItOut("\"use strict\"; this.o0.h0.set = (function(j) { if (j) { try { m1 = g2.objectEmulatingUndefined(); } catch(e0) { } for (var v of g1.v1) { try { p0.toString = (function() { for (var j=0;j<2;++j) { f1(j%2==1); } }); } catch(e0) { } print(m2); } } else { try { v2 = (m2 instanceof m1); } catch(e0) { } try { g2.m2.get(s0); } catch(e1) { } try { neuter(b1, \"change-data\"); } catch(e2) { } Array.prototype.unshift.apply(this.a0, [b1, g0, this.b1,  '' ]); } });");
/*fuzzSeed-246262462*/count=713; tryItOut("f1.valueOf = (function(j) { if (j) { try { m1.get(i0); } catch(e0) { } Object.defineProperty(this, \"a0\", { configurable: ((x =  '' )), enumerable: (x % 46 != 18),  get: function() {  return [(x - ()) for each (x in /*MARR*/[(void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), (void 0), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0), ((4277) ? (uneval(\"\\uF926\")) : let (a) w), (void 0), (void 0)]) for each (y in (4277)) for (x of /*FARR*/[(p={}, (p.z = new true(false))()), [ /x/ ], , ([] = x), \u3056 = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: \"\\u3ACC\", getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: undefined, has: decodeURIComponent, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })((uneval(\"\\uE0D0\"))), new window)]) for (x of (w) = -(2**53) += {}.yoyo(c)) if (eval(\"for (var v of o2) { try { i2 + ''; } catch(e0) { } for (var v of t1) { try { a0.forEach((function() { try { a0.push(\\\"\\\\u67F8\\\", p1, i2, g2.s0, h2, this.p1, t2, v0, a0); } catch(e0) { } try { for (var v of s2) { g1 + ''; } } catch(e1) { } try { a0 = Array.prototype.concat.call(a1, t0, t1); } catch(e2) { } Array.prototype.unshift.call(a2, a1, v0, f2, m2); return h2; }), g0.f1); } catch(e0) { } try { i1 + ''; } catch(e1) { } ; } }\"))]; } }); } else { try { g1.v1 = g0.eval(\"function f1(i1)  { return i1 } \"); } catch(e0) { } try { v1 = (g1.e1 instanceof o0); } catch(e1) { } /*MXX3*/g0.Float64Array.prototype.BYTES_PER_ELEMENT = g2.Float64Array.prototype.BYTES_PER_ELEMENT; } });");
/*fuzzSeed-246262462*/count=714; tryItOut("\"use strict\"; var lldsev = new ArrayBuffer(2); var lldsev_0 = new Float32Array(lldsev); print(lldsev_0[0]); var lldsev_1 = new Int8Array(lldsev); lldsev_1[0] = 25; Array.prototype.pop.call(a0);t1[7] = lldsev_0[10];b2 = new ArrayBuffer(48);f2 + g0;/*RXUB*/var r = r2; var s = s0; print(uneval(r.exec(s))); print(r.lastIndex); \nlet (jnhmsg, jbywoc, jiviol, zwkero) { o2 + ''; }\n");
/*fuzzSeed-246262462*/count=715; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy1((Math.fround((Math.asinh(Math.trunc(x)) ^ Math.fround(mathy1(( + Math.fround(Math.log10(Math.fround(x)))), y)))) >>> 0), ((( ! (Math.fround(Math.ceil(Math.min((x | 0), Math.fround((Math.fround(x) | Math.fround(Math.atan2(x, y))))))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [({toString:function(){return '0';}}), 0, (new Number(-0)), (new Boolean(true)), undefined, (new Boolean(false)), '0', null, /0/, -0, true, ({valueOf:function(){return 0;}}), false, '', ({valueOf:function(){return '0';}}), '/0/', [0], (function(){return 0;}), (new String('')), NaN, (new Number(0)), [], 1, objectEmulatingUndefined(), '\\0', 0.1]); ");
/*fuzzSeed-246262462*/count=716; tryItOut("mathy2 = (function(x, y) { return mathy1((( + ((( ~ x) | 0) != Math.fround(y))) | 0), Math.fround(mathy1(( + Math.hypot(Math.fround(( ~ Math.fround(Math.asin((((mathy0(y, x) <= x) | 0) >>> 0))))), ( ~ ( - -Number.MAX_VALUE)))), (Math.pow((( - Math.fround(x)) >>> 0), (((Math.sign((Math.fround(Math.max(y, ( + y))) >>> 0)) >>> 0) >= ( + Math.tan((y >>> 0)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [1, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 0x07fffffff, -0x080000001, 2**53-2, -0x080000000, Number.MIN_VALUE, 2**53, Math.PI, -0x07fffffff, 0, -0, -0x0ffffffff, -(2**53-2), 0/0, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), 0x080000001, -Number.MIN_VALUE, 0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -1/0, -(2**53), -Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-246262462*/count=717; tryItOut("e2.add(m0);");
/*fuzzSeed-246262462*/count=718; tryItOut("");
/*fuzzSeed-246262462*/count=719; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.atanh(Math.fround(Math.sqrt((((( ~ Math.fround((( + ((y !== x) >>> 0)) >>> 0))) | 0) * ( + Number.MIN_VALUE)) >>> 0)))); }); ");
/*fuzzSeed-246262462*/count=720; tryItOut("Array.prototype.splice.apply(this.a2, [NaN, 1]);");
/*fuzzSeed-246262462*/count=721; tryItOut("v0 = (this.b2 instanceof p0);");
/*fuzzSeed-246262462*/count=722; tryItOut("b2.toString = (function(j) { f1(j); });");
/*fuzzSeed-246262462*/count=723; tryItOut("/*oLoop*/for (let ctcsxx = 0; ctcsxx < 86; ++ctcsxx, [1,,]) { Object.prototype.unwatch.call(this.b1, \"NaN\"); } ");
/*fuzzSeed-246262462*/count=724; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return Math.clz32(Math.sinh(Math.fround((Math.min(y, ( + ( - ( + 0x080000001)))) % (x === Math.sinh(( + -Number.MAX_VALUE))))))); }); ");
/*fuzzSeed-246262462*/count=725; tryItOut("\"use strict\"; /*infloop*/for(let x = x; (this.__defineSetter__(\"w\", function (y) { return new RegExp() } )); x) {i2 = new Iterator(g1);switch(length) { default: ;break;  } }let x = ((function factorial_tail(dxzzmf, vgjixv) { ; if (dxzzmf == 0) { ; return vgjixv; } a2.reverse(m1, g0.m0, f1);; return factorial_tail(dxzzmf - 1, vgjixv * dxzzmf); /*tLoop*/for (let z of /*MARR*/[(-1/0), -0x2D413CCC, (-1/0), true, -0x2D413CCC, (-1/0), true, (void 0), (void 0), -0x2D413CCC, -0x2D413CCC, Number.MIN_VALUE, (-1/0), (void 0), (void 0), (-1/0), Number.MIN_VALUE, (-1/0), (-1/0), (void 0), Number.MIN_VALUE, (-1/0), Number.MIN_VALUE, true, (void 0), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, (void 0), true, true, -0x2D413CCC, true, Number.MIN_VALUE, -0x2D413CCC, -0x2D413CCC, (void 0), (void 0), (-1/0), -0x2D413CCC, Number.MIN_VALUE, true, (void 0), (-1/0), true, Number.MIN_VALUE, -0x2D413CCC, Number.MIN_VALUE, -0x2D413CCC, (void 0), (void 0), true, (-1/0), -0x2D413CCC, -0x2D413CCC, Number.MIN_VALUE, Number.MIN_VALUE, -0x2D413CCC, -0x2D413CCC, Number.MIN_VALUE, (void 0), true, (void 0), -0x2D413CCC, (void 0), Number.MIN_VALUE, (-1/0), Number.MIN_VALUE, (void 0), (-1/0), (-1/0), -0x2D413CCC, (-1/0), Number.MIN_VALUE, (void 0), -0x2D413CCC, Number.MIN_VALUE, (-1/0), true, Number.MIN_VALUE, -0x2D413CCC]) { ( /x/g ); } })(32046, 1));a2[16] = s1;");
/*fuzzSeed-246262462*/count=726; tryItOut("print((p={}, (p.z = \ntrue)()));a = let (a = (yield \"\\uD040\")) (makeFinalizeObserver('tenured'));");
/*fuzzSeed-246262462*/count=727; tryItOut("mathy0 = (function(x, y) { return ( - Math.fround(Math.log10(Math.fround(((( + Math.tan(y)) & ((x && ( + ( + (y >>> 0)))) | 0)) | 0))))); }); ");
/*fuzzSeed-246262462*/count=728; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + ( + ((((((( + (( ~ Math.fround(x)) >>> 0)) | 0) ? ((Math.sqrt(x) >>> 0) | 0) : Math.fround(Math.cosh((-Number.MAX_SAFE_INTEGER | 0)))) | 0) | 0) == (Math.exp(2**53+2) | 0)) | 0))); }); testMathyFunction(mathy0, [42, 0, 1/0, 0/0, -0x0ffffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -0x080000001, Math.PI, 0.000000000000001, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), -0x100000001, 2**53+2, -(2**53-2), 0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, 0x080000000, 0x100000000, 2**53, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, 1, 2**53-2, -1/0, -(2**53), Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-246262462*/count=729; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-((+(-1.0/0.0)))));\n  }\n  return f; })(this, {ff: ((decodeURIComponent)(true,  /x/ )).apply}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, 42, -0x100000001, -1/0, 0.000000000000001, Math.PI, -0x080000000, 1.7976931348623157e308, 1/0, -0x07fffffff, 2**53+2, 0x100000000, Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, -0, -Number.MAX_VALUE, 0, 0x080000000, 0x0ffffffff, -(2**53+2), 0x07fffffff, -(2**53), 0x080000001, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 0x100000001, -0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-246262462*/count=730; tryItOut("\"use strict\"; print(x);\nprint(x);\n");
/*fuzzSeed-246262462*/count=731; tryItOut("for(let e of /*FARR*/[]) for(let y in /*MARR*/[new String(''), undefined, undefined, undefined,  /x/ , undefined, new String(''), undefined, undefined, new String(''),  /x/ ,  /x/ ,  /x/ , new String(''),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new String(''), new String(''),  /x/ , undefined, undefined, new String(''),  /x/ , new String(''),  /x/ , new String(''), new String(''), new String(''), new String(''), new String(''), undefined, new String(''), undefined,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ]) let(z) ((function(){with({}) { return Math.atanh( /x/ ); } })());let(a) { let(b) ((function(){b.stack;})());}");
/*fuzzSeed-246262462*/count=732; tryItOut("\"use strict\"; Array.prototype.push.apply(a1, [f0, f0]);");
/*fuzzSeed-246262462*/count=733; tryItOut("print(uneval(f2));");
/*fuzzSeed-246262462*/count=734; tryItOut("/*RXUB*/var r = new RegExp(\"[\\\\\\u95d6\\\\w\\\\w].(?:(\\\\1)|(\\\\2)|\\\\2[\\\\u684B-\\u74ae\\\\S])\", \"gi\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-246262462*/count=735; tryItOut("with({w: [,]}){h0.delete = f1; }");
/*fuzzSeed-246262462*/count=736; tryItOut("\"use strict\"; a2.pop(i0, h1);");
/*fuzzSeed-246262462*/count=737; tryItOut("mathy3 = (function(x, y) { return ( + (( + Math.hypot(mathy2(Math.fround((Math.fround(( + Math.clz32(y))) <= Math.fround(1.7976931348623157e308))), (x | 0)), (Math.abs(((((( + (( + (Math.atanh(0x080000001) | 0)) ? ( + ( + Math.trunc(y))) : (( + (y | 0)) >>> 0))) | 0) / ( + ( + Math.min(( + (0x080000001 ** y)), ( + ((Math.fround(y) - ( + Math.exp(y))) >>> 0)))))) | 0) | 0)) | 0))) !== ( + (Math.min(((Math.atan2(y, (mathy1(y, x) | 0)) & ((Math.atan2(mathy1((y >>> 0), Math.fround(y)), (Math.cbrt(2**53-2) | 0)) | 0) | 0)) >>> 0), ((Math.tan(Math.fround(Math.log10(Math.fround((x && mathy1((((-Number.MAX_VALUE >>> 0) * (0x100000000 >>> 0)) >>> 0), y)))))) >>> 0) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-246262462*/count=738; tryItOut("mathy1 = (function(x, y) { return (( + (((( - (Math.min(((-1/0 ? Math.fround(-0x100000001) : Math.fround(mathy0(y, x))) >>> 0), x) | 0)) >>> 0) >>> 0) - Math.fround((Math.max((-Number.MIN_VALUE >>> 0), (x >>> 0)) >>> 0)))) >>> ( + (( + (( + (( + Math.imul(( - 0x07fffffff), ( ! -1/0))) * ( + mathy0(x, ( + Math.PI))))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-246262462*/count=739; tryItOut("v0 = g1.g2.eval(\"var iuoqtw = new ArrayBuffer(0); var iuoqtw_0 = new Int32Array(iuoqtw); print(iuoqtw_0[0]); iuoqtw_0[0] = 4; var iuoqtw_1 = new Int16Array(iuoqtw); iuoqtw_1[0] = -9; m0 = m0.get(iuoqtw_1);/* no regression tests found */\");");
/*fuzzSeed-246262462*/count=740; tryItOut("\"use strict\"; Object.prototype.watch.call(f1, new String(\"9\"), Set.prototype.entries.bind(s0));");
/*fuzzSeed-246262462*/count=741; tryItOut("e2.delete(i1);");
/*fuzzSeed-246262462*/count=742; tryItOut("\"use strict\"; g1.a0 = a2.concat(({ get multiline(w, \u3056, x, window, x = -8, z = window, z, NaN, window, x, window = \"\\uD8E9\", window, x = x, x, 12, y =  /x/ , d, x, e, NaN, x = new RegExp(\"\\\\2\\\\D{0}.|\\\\b+?|\\\\2(?:($))\", \"gyi\"), b, x, z, x, d =  '' , x, x, z = [1], b, \u3056, NaN, a, c, x, b, \u3056, x, x, x, eval, b, y, \u3056, d, y = eval, x, w,  , e, x, w, d, x, d, x, b, x = /\\2/yim, \u3056, b, x, x, x, window, x, NaN, x, x = false, x = ({a2:z2}), NaN, b, c, x, \u3056 = \"\\uCC69\", this) { yield (p={}, (p.z = (({getUTCDay: b })))()) }  }));");
/*fuzzSeed-246262462*/count=743; tryItOut("L:with({z: (4277)})a0.forEach((function mcc_() { var wfnmye = 0; return function() { ++wfnmye; if (/*ICCD*/wfnmye % 3 == 1) { dumpln('hit!'); try { i0 = o1.t2[15]; } catch(e0) { } try { this.s1 += 'x'; } catch(e1) { } a1.shift(); } else { dumpln('miss!'); ; } };})());");
/*fuzzSeed-246262462*/count=744; tryItOut("");
/*fuzzSeed-246262462*/count=745; tryItOut("print(x);");
/*fuzzSeed-246262462*/count=746; tryItOut("");
/*fuzzSeed-246262462*/count=747; tryItOut("Object.seal(t2);\nprint(x);\n");
/*fuzzSeed-246262462*/count=748; tryItOut("a0.shift(b2);");
/*fuzzSeed-246262462*/count=749; tryItOut("\"use strict\"; Array.prototype.shift.apply(a0, []);");
/*fuzzSeed-246262462*/count=750; tryItOut("\"use strict\"; a1.unshift(i0, i2, e1);");
/*fuzzSeed-246262462*/count=751; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return (( ! (Math.pow(Math.hypot(Math.min(2**53+2, x), ( + (Math.sign(x) && (-Number.MIN_VALUE <= 0x07fffffff)))), ( + Math.min(( + Math.fround(( ! Math.fround(Math.log1p(Math.fround(x)))))), ( + y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[new Number(1.5),  /x/g ,  /x/g , null,  /x/g , null,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Number(1.5),  /x/g ,  /x/g , new Number(1.5), null, new Number(1.5), null, new Number(1.5), null,  /x/g , new Number(1.5), new Number(1.5), null, new Number(1.5),  /x/g ,  /x/g , null, new Number(1.5)]); ");
/*fuzzSeed-246262462*/count=752; tryItOut("e1.add(f1);");
/*fuzzSeed-246262462*/count=753; tryItOut("/*RXUB*/var r = r1; var s = s1; print(s.match(r)); ");
/*fuzzSeed-246262462*/count=754; tryItOut("\"use strict\"; (((void version(180))));");
/*fuzzSeed-246262462*/count=755; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h0, f2);s0 = new String;\no0.h1.keys = f2;\n");
/*fuzzSeed-246262462*/count=756; tryItOut("for(y = (Math.atan(18)) in  '' ) m1.has(p0);");
/*fuzzSeed-246262462*/count=757; tryItOut("print(h1);");
/*fuzzSeed-246262462*/count=758; tryItOut("/*bLoop*/for (var vbnsnp = 0; vbnsnp < 21; ++vbnsnp) { if (vbnsnp % 17 == 13) { do {throw  /x/ ; } while((15) && 0); } else { /*RXUB*/var r = /(?=[\\u00c6\\cH-\u5e4c\\cH-\\cP]|[\\w\\b-u!-\u0e9b]|($[^]{1,})*?**?)/m; var s = \"\"; print(s.search(r));  }  } ");
/*fuzzSeed-246262462*/count=759; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?:\\\\ueA4E{2,}|$))\", \"\"); var s = \"1\\n\\n\\n\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-246262462*/count=760; tryItOut("mathy3 = (function(x, y) { return (Math.sqrt(((Math.expm1(Math.max(Math.max((Math.log1p((x >>> 0)) >>> 0), x), 0x07fffffff)) && ( + Math.round(( + Math.atan2(( + 0), ( + y)))))) | 0)) | 0); }); testMathyFunction(mathy3, [2**53+2, -Number.MAX_VALUE, 2**53, -1/0, 1, Math.PI, Number.MIN_SAFE_INTEGER, 0x080000000, 0/0, -(2**53), Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000000, 0, 0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, 0x100000001, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, -0x100000000, -0, 1/0, -0x080000001, -0x07fffffff, 2**53-2, -0x100000001]); ");
/*fuzzSeed-246262462*/count=761; tryItOut("\"use strict\"; m2.set(a1, this.f2);");
/*fuzzSeed-246262462*/count=762; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.ceil(( + Math.max(( + (Math.atan2(((((y >>> 0) / (( + (( + print(new URIError( /x/ ));) >= ( + Math.asinh((x >>> 0))))) >>> 0)) >>> 0) | 0), (x | 0)) | 0)), Math.fround((Math.fround(( - ( + ( + ((( + x) | 0) - x))))) === (Math.fround(Math.ceil(Math.fround(x))) <= Math.atan(y)))))))); }); ");
/*fuzzSeed-246262462*/count=763; tryItOut("/*RXUB*/var r = /[^]|(([\\W\\cB])(?:[^]\\s\\b)|(?![^])*?$|\\2*){16383,16386}/; var s = ((Array.prototype.copyWithin).bind)(); print(uneval(s.match(r))); ");
/*fuzzSeed-246262462*/count=764; tryItOut("\"use strict\"; t0.toSource = (function() { try { v1.toSource = (function() { try { Object.defineProperty(this, \"this.g2.v0\", { configurable: false, enumerable: true,  get: function() {  return o0.t1.byteOffset; } }); } catch(e0) { } try { a2.shift(); } catch(e1) { } try { v1 = this.g1.g1.g1.runOffThreadScript(); } catch(e2) { } a1 + p0; return h2; }); } catch(e0) { } try { m0.get(s2); } catch(e1) { } try { p0.toSource = (function() { try { function f0(p0)  { e1 = g1.g1.a2[8]; }  } catch(e0) { } try { neuter(b2, \"change-data\"); } catch(e1) { } /*ADP-1*/Object.defineProperty(a2, 10, ({configurable: true, enumerable: false})); return g2.e2; }); } catch(e2) { } neuter(b2, \"change-data\"); return s2; });");
/*fuzzSeed-246262462*/count=765; tryItOut("testMathyFunction(mathy0, [-Number.MAX_VALUE, 0x07fffffff, Number.MAX_VALUE, 1/0, Math.PI, 2**53-2, -0, 0x080000001, 0, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, -0x07fffffff, -(2**53-2), 0/0, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, 0x080000000, -0x080000001, -1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0x100000000, -(2**53), -0x100000001, 42, 2**53+2]); ");
/*fuzzSeed-246262462*/count=766; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - Math.log2(( + Math.min(Math.log(y), Math.fround(Math.pow(y, x)))))) | 0); }); testMathyFunction(mathy5, [0.000000000000001, Number.MAX_VALUE, -0x100000001, 0x100000001, 0x100000000, 1, -(2**53+2), -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), -1/0, 0, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000000, 0/0, -0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, 1.7976931348623157e308, -0x080000000, 2**53+2, Number.MIN_VALUE, -0, -(2**53-2), 0x07fffffff, 0x0ffffffff, -0x0ffffffff, -Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-246262462*/count=767; tryItOut("testMathyFunction(mathy2, [42, -1/0, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), -(2**53), -0x0ffffffff, 0x100000000, -(2**53+2), 2**53+2, -Number.MIN_VALUE, Number.MIN_VALUE, 1/0, -0x100000001, -Number.MAX_VALUE, 0x080000000, 0x080000001, 1.7976931348623157e308, 0x0ffffffff, -0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, 0, 0.000000000000001, 2**53, Number.MAX_VALUE, -0, -0x100000000, 0x07fffffff, 1]); ");
/*fuzzSeed-246262462*/count=768; tryItOut("h2.getOwnPropertyNames = (function(j) { if (j) { a1[(4277)]; } else { try { m2.toSource = (function() { try { v0 = r1.multiline; } catch(e0) { } try { o2.a2 = a1.concat(this.a2, p1); } catch(e1) { } try { i1.toSource = (function() { try { g2 = this; } catch(e0) { } try { Array.prototype.reverse.apply(o2.a0, [t2]); } catch(e1) { } for (var p in g2.f1) { try { Array.prototype.forEach.call(a0, (function() { v2 = g2.runOffThreadScript(); throw t2; }), m1, o2); } catch(e0) { } try { g2.e0 = new Set; } catch(e1) { } try { v1 + ''; } catch(e2) { } g0.v2 = Array.prototype.reduce, reduceRight.call(a0, (function(j) { f2(j); }), e2, t0, o1.m1, e0, i1, f1, o2.o0.f1, b2); } return o0; }); } catch(e2) { } v2 = (b0 instanceof s2); return s2; }); } catch(e0) { } try { /*RXUB*/var r = r0; var s = \"`\"; print(s.replace(r, (((uneval((4277)))).watch(\"log2\", NaN | 576460752303423500)), \"gi\")); print(r.lastIndex);  } catch(e1) { } try { for (var p in p1) { try { let t2 = new Int8Array(b2); } catch(e0) { } try { o0.t1[6] = undefined; } catch(e1) { } try { Array.prototype.forEach.apply(a2, [(function() { try { e0.has(h0); } catch(e0) { } t2[9] = ((function sum_slicing(yikarr) { ; return yikarr.length == 0 ? 0 : yikarr[0] + sum_slicing(yikarr.slice(1)); })(/*MARR*/[arguments.caller, 0x0ffffffff, arguments.caller, null, null, null,  'A' ,  'A' , 0x0ffffffff, 0x0ffffffff,  'A' , arguments.caller, arguments.caller, 0x0ffffffff, 0x0ffffffff, arguments.caller,  'A' , null, 0x0ffffffff,  'A' , null, 0x0ffffffff, 0x0ffffffff, null, arguments.caller, 0x0ffffffff, null, arguments.caller, null, arguments.caller, 0x0ffffffff, 0x0ffffffff,  'A' , null, 0x0ffffffff, null,  'A' , 0x0ffffffff,  'A' , null,  'A' , null,  'A' , arguments.caller, arguments.caller, null, null, null, arguments.caller,  'A' , 0x0ffffffff,  'A' ,  'A' , 0x0ffffffff,  'A' , null, null,  'A' , arguments.caller, arguments.caller, null, arguments.caller, arguments.caller, null, null, null, 0x0ffffffff, null,  'A' , null, null, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, null, arguments.caller, arguments.caller, null, arguments.caller, arguments.caller, null, arguments.caller, 0x0ffffffff, arguments.caller,  'A' , 0x0ffffffff,  'A' , 0x0ffffffff, 0x0ffffffff,  'A' , arguments.caller])) < x; return t0; })]); } catch(e2) { } a0 = arguments; } } catch(e2) { } /*MXX3*/g1.Promise = g0.Promise; } });");
/*fuzzSeed-246262462*/count=769; tryItOut("mathy1 = (function(x, y) { return ((Math.hypot((Math.abs((( + Math.atanh(y)) | 0)) | 0), Math.fround(Math.imul(y, Math.atan2((Math.exp((y | 0)) | 0), y)))) - (( + (( + 0x0ffffffff) >= (y ? (Math.imul((x | 0), ( + x)) , x) : ( + Math.hypot(( + y), ( + x)))))) | 0)) / ((Math.fround((( + ( + ( - ( + Math.fround(( ~ Number.MAX_VALUE)))))) >>> 0)) >> ( - (Math.fround(Math.hypot(Math.fround(x), ( + Math.abs(( + y))))) ** Math.atanh(y)))) >>> 0)); }); testMathyFunction(mathy1, ['0', ({valueOf:function(){return '0';}}), (new Boolean(true)), false, '\\0', null, ({toString:function(){return '0';}}), objectEmulatingUndefined(), -0, (new Number(-0)), (new Boolean(false)), 1, 0, 0.1, [], true, undefined, '', ({valueOf:function(){return 0;}}), (new Number(0)), NaN, '/0/', /0/, [0], (function(){return 0;}), (new String(''))]); ");
/*fuzzSeed-246262462*/count=770; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(e2, i0);");
/*fuzzSeed-246262462*/count=771; tryItOut("\"use strict\"; { void 0; setJitCompilerOption('ion.warmup.trigger', 2); } let (x = (y), b =  /x/ , y, [[, ], ] = allocationMarker(), x, w, kjtdzx) { o1.h0 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.shift.call(a0, g1.o0, f2);; var desc = Object.getOwnPropertyDescriptor(t1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { t2[7];; var desc = Object.getPropertyDescriptor(t1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { f0 = Proxy.create(h2, o1);; Object.defineProperty(t1, name, desc); }, getOwnPropertyNames: function() { s0 += s0;; return Object.getOwnPropertyNames(t1); }, delete: function(name) { return a2; return delete t1[name]; }, fix: function() { print(uneval(g0.f1));; if (Object.isFrozen(t1)) { return Object.getOwnProperties(t1); } }, has: function(name) { g1.offThreadCompileScript(\"function f1(a2)  { yield (a2 <= y ==  /x/g ) } \", ({ global: this.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 72 == 48), sourceIsLazy: \n\"\\u4108\", catchTermination: false, element: o0 }));; return name in t1; }, hasOwn: function(name) { neuter(o1.b0, \"same-data\");; return Object.prototype.hasOwnProperty.call(t1, name); }, get: function(receiver, name) { g1.e0.add(f1);; return t1[name]; }, set: function(receiver, name, val) { /*MXX1*/o2 = g1.Float32Array.name;; t1[name] = val; return true; }, iterate: function() { throw p1; return (function() { for (var name in t1) { yield name; } })(); }, enumerate: function() { e0 = new Set;; var result = []; for (var name in t1) { result.push(name); }; return result; }, keys: function() { i2 = new Iterator(e2, true);; return Object.keys(t1); } }); }");
/*fuzzSeed-246262462*/count=772; tryItOut("");
/*fuzzSeed-246262462*/count=773; tryItOut("f0(t0);");
/*fuzzSeed-246262462*/count=774; tryItOut("var w = x, x = , {} = [1,,], w = x instanceof 29 % window, a, x = (makeFinalizeObserver('nursery')), uttalp, [, , ] = x =  '' ;for(var y = Math.hypot( \"\" , 26) in window) yield;if((x % 40 != 37)) { if (/*RXUE*/new RegExp(\"[^]\", \"gyim\").exec(Object.defineProperty\n(x, \"call\", ({configurable: (x % 6 == 1)})))) var cevsnv = new SharedArrayBuffer(2); var cevsnv_0 = new Uint8Array(cevsnv); print(cevsnv_0[0]); cevsnv_0[0] = 22; i2.send(o1.o1); else this.v0 = g0.runOffThreadScript();}");
/*fuzzSeed-246262462*/count=775; tryItOut("{;{v1 = g1.runOffThreadScript();s0 += 'x'; } }");
/*fuzzSeed-246262462*/count=776; tryItOut("p1 = t0[16];");
/*fuzzSeed-246262462*/count=777; tryItOut("v0 = true;");
/*fuzzSeed-246262462*/count=778; tryItOut("mathy2 = (function(x, y) { return mathy0(Math.fround(Math.pow((Math.fround((Math.fround(y) > ( + y))) >= (Math.min((Math.fround((y == ( + -0x100000001))) >>> 0), ((y !== y) >>> 0)) >>> 0)), ( ~ x))), Math.fround(Math.min(( + (Math.min((( ~ Math.sin(Math.fround(Math.ceil(( + y))))) | 0), ((((Math.atan2((y >>> 0), (mathy0(x, y) >>> 0)) >>> 0) >>> 0) !== ( + (( + Math.expm1(y)) > ( + y)))) >>> 0)) | 0)), ( + mathy1(mathy0((mathy1(-0x100000001, y) | 0), (Math.cos(0.000000000000001) | 0)), ((( + (x >>> 0)) >>> 0) | 0)))))); }); testMathyFunction(mathy2, [[0], (new Number(-0)), [], true, '0', (new Number(0)), (function(){return 0;}), -0, 0.1, 1, ({valueOf:function(){return '0';}}), /0/, false, undefined, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), NaN, 0, null, '', (new Boolean(false)), '/0/', (new Boolean(true)), ({toString:function(){return '0';}}), (new String('')), '\\0']); ");
/*fuzzSeed-246262462*/count=779; tryItOut("mathy2 = (function(x, y) { return Math.min(Math.atan2(((mathy0(( + (( + y) >>> (x | 0))), (((y | 0) >= (( ! x) | 0)) | 0)) ** Math.fround((Math.pow((y | 0), (y | 0)) | 0))) | 0), Math.atan(Math.fround((Math.PI != Math.fround(Math.cosh(Math.fround((( + -0x07fffffff) >>> (x >>> 0))))))))), Math.fround((Math.fround((Math.cosh((( - x) | 0)) >>> 0)) && (Math.fround(Math.hypot(Math.fround((y <= x)), (Math.min(((Math.ceil(((Math.log2(-0x100000000) + x) >>> 0)) >>> 0) >>> 0), (x >>> 0)) >>> 0))) | 0)))); }); ");
/*fuzzSeed-246262462*/count=780; tryItOut("with({y: ~undefined})Array.prototype.pop.call(a0, o0, g0);for(let d in /*FARR*/[, (window), .../*FARR*/[Array.prototype.every((void shapeOf(17)), this), ]]) with({}) { try { this.zzz.zzz; } finally { set.lineNumber; }  } for(let z of (function() { yield (function(q) { return q; }); } })()) return;");
/*fuzzSeed-246262462*/count=781; tryItOut("mathy2 = (function(x, y) { return (( ! ( - (Math.hypot((Math.ceil(0x080000001) >>> 0), (Math.pow(x, (mathy0(0x080000000, Math.sin(-0x080000001)) >>> 0)) >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy2, [-(2**53+2), -0, 1, 42, 1.7976931348623157e308, -(2**53-2), 0/0, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), 0x100000000, 0, 2**53-2, 2**53, -Number.MAX_VALUE, Math.PI, 0x07fffffff, 1/0, -0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, 0x080000001, -0x100000000, 0.000000000000001, 2**53+2, -0x100000001, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=782; tryItOut("/*MXX1*/Object.defineProperty(this, \"o2\", { configurable: false, enumerable: false,  get: function() {  return g0.String.prototype.link; } });");
/*fuzzSeed-246262462*/count=783; tryItOut("\"use strict\"; g0.t2[({valueOf: function() { if(false) { if (()) /*infloop*/ for  each(x in x) {v2 = (i2 instanceof s1); }} else {print(x);Math.atan2( /x/ , -9); }return 9; }})] = (new Function(\"v0 = (s2 instanceof m2);\"))();");
/*fuzzSeed-246262462*/count=784; tryItOut("v2 = r0.flags;");
/*fuzzSeed-246262462*/count=785; tryItOut("mathy4 = (function(x, y) { return mathy0(( + Math.fround(Math.log2(( + (mathy0((-Number.MAX_SAFE_INTEGER | 0), y) >>> 0))))), ( + Math.pow((( + ((( + mathy2(x, x)) % ( + -Number.MAX_VALUE)) % -0x100000000)) % ( + (mathy3((((x >>> y) == (x >>> 0)) >>> 0), mathy0((( + ( ! -1/0)) >>> 0), Math.fround(Math.min(Math.fround(x), Math.fround(-0))))) , (Math.atanh((y >>> 0)) >>> 0)))), ( ! (x >>> 0))))); }); testMathyFunction(mathy4, [2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 42, 2**53, -0, -0x080000000, 2**53-2, 0x100000001, 0, -0x100000000, -0x080000001, 0x07fffffff, -1/0, 1/0, 1.7976931348623157e308, 0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000001, Math.PI, -(2**53-2), 0x080000001, 0/0, -0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=786; tryItOut("this.g0.m0.delete(e1);");
/*fuzzSeed-246262462*/count=787; tryItOut("\"use strict\"; var d, b, eval, a;v0 = a2.length;");
/*fuzzSeed-246262462*/count=788; tryItOut("mathy1 = (function(x, y) { return Math.expm1(Math.imul(Math.cbrt(( + ( + (Math.fround((Math.min(y, Math.imul(y, x)) - Math.fround(((( + (( + -(2**53+2)) ? y : 0.000000000000001)) ** (-0x07fffffff | 0)) | 0)))) ? Math.fround(Math.cos(Math.fround(0))) : y)))), mathy0(( + ( + ( + ( + Math.max(y, (( + x) | 0)))))), ( + Math.max(Math.pow(x, (((x | 0) ? x : x) >>> 0)), ( + (( + ( ~ x)) ? (( + y) ? y : (-(2**53) | 0)) : ( + 0/0)))))))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, -(2**53+2), Number.MIN_VALUE, 2**53-2, -0x080000001, 0x0ffffffff, -0x100000000, -0x080000000, -0x100000001, Number.MAX_VALUE, 0x080000000, 0x080000001, -0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, 1, 0x100000001, -(2**53-2), 42, 2**53+2, 2**53, -(2**53), -Number.MIN_SAFE_INTEGER, 0, 1.7976931348623157e308, -0x07fffffff, 0x100000000, -0, -Number.MAX_VALUE, Math.PI, 0/0]); ");
/*fuzzSeed-246262462*/count=789; tryItOut("{print(x);a0.shift(); }");
/*fuzzSeed-246262462*/count=790; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.clz32(Math.fround(Math.pow(( + ( ~ (( + ( - Math.log1p(0x100000000))) >>> (y | 0)))), ( + mathy3(( + Math.cbrt(( + ( + Math.log(( + 0)))))), ( + ( + y)))))))); }); ");
/*fuzzSeed-246262462*/count=791; tryItOut("\"use asm\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((/*FFI*/ff(((imul((0xa59fcd52), (0xe9769f5c))|0)), ((d0)), ((d0)), (((-0x7f794*((0xee54d410) != (0x428c4ab2))) | ((!(0x308dc638))-(0xade5f3f5)))), ((d0)), ((-((d1)))), ((d1)), ((70368744177665.0)), ((18446744073709552000.0)), ((4503599627370496.0)), ((-1.25)), ((68719476737.0)), ((3.8685626227668134e+25)), ((-255.0)), ((-4503599627370497.0)), ((4.722366482869645e+21)), ((-1023.0)), ((-1099511627777.0)), ((-2199023255553.0)), ((5.0)), ((-73786976294838210000.0)), ((268435455.0)), ((-4503599627370497.0)), ((2.4178516392292583e+24)), ((4.835703278458517e+24)), ((4294967296.0)))|0)-(0xffffffff)-((~((Int32ArrayView[1]))) != (((0xf415cee2)+((b = (function(y) { v2 = h0[\"sin\"]; }).call(x, timeout(1800))))) >> ((0x374e8927))))))|0;\n  }\n  return f; })(this, {ff: ((-27)().eval(\"/* no regression tests found */\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0x07fffffff, 2**53-2, 0.000000000000001, -(2**53-2), -Number.MIN_VALUE, 1, 1/0, -(2**53+2), 0/0, -0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 42, -0x100000000, Number.MIN_VALUE, -0, -(2**53), -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, -0x07fffffff, 0x0ffffffff, -0x0ffffffff, 0x100000001, 0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, 2**53+2, Math.PI, 1.7976931348623157e308, 0, Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=792; tryItOut("this.zzz.zzz = x;");
/*fuzzSeed-246262462*/count=793; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new String('')), 1, -0, objectEmulatingUndefined(), 0.1, [], '\\0', NaN, '0', (function(){return 0;}), /0/, false, (new Number(-0)), null, '', ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Number(0)), (new Boolean(false)), (new Boolean(true)), undefined, 0, true, ({valueOf:function(){return '0';}}), '/0/', [0]]); ");
/*fuzzSeed-246262462*/count=794; tryItOut(";");
/*fuzzSeed-246262462*/count=795; tryItOut("\"use strict\"; g1.v1 = t0.byteOffset;");
/*fuzzSeed-246262462*/count=796; tryItOut("v0 = this.r2.exec;");
/*fuzzSeed-246262462*/count=797; tryItOut("M:switch(0) { default: case 1: break; o1.v2 = 4.2;break; case  /x/ :  }");
/*fuzzSeed-246262462*/count=798; tryItOut("print(uneval(i0));");
/*fuzzSeed-246262462*/count=799; tryItOut("\"use strict\"; e2.has(f0);");
/*fuzzSeed-246262462*/count=800; tryItOut("for (var v of m1) { try { v2 = r2.global; } catch(e0) { } try { e1.add(e1); } catch(e1) { } try { b0 = t0.buffer; } catch(e2) { } v1 = NaN; }");
/*fuzzSeed-246262462*/count=801; tryItOut("g1.offThreadCompileScript(\"\\\"use strict\\\"; (((4277))) = t0[v1];\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (delete z.x), noScriptRval: Math.imul(-26, 4), sourceIsLazy: timeout(1800), catchTermination: (x % 6 == 1) }));");
/*fuzzSeed-246262462*/count=802; tryItOut("var r0 = x - x; r0 = r0 / x; var r1 = x + x; var r2 = r0 | r1; r2 = 1 - r2; var r3 = r2 % x; var r4 = r2 % 3; x = 3 / 5; ");
/*fuzzSeed-246262462*/count=803; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((Math.trunc((((Math.min(Math.fround(((Math.pow((y >>> 0), 42) >>> 0) != ( + Math.fround(1.7976931348623157e308)))), (Math.asinh((( - Math.fround(x)) >>> 0)) >>> 0)) >>> 0) < (( + (( + Math.expm1((y < x))) , ( + 0x080000000))) >>> 0)) >>> 0)) >>> 0) + ((Math.max(( + Math.max(( + x), ( + Math.log1p(Math.PI)))), ( + Math.fround(0x100000000))) == (( + y) && Math.fround((Math.fround(Math.fround(Math.pow(Math.fround(-0x080000000), ( + -0)))) , (( + (( - 1) | 0)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy3, [1, 0x080000000, 1.7976931348623157e308, 0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -0, 0x080000001, 0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, 2**53-2, 0.000000000000001, 2**53, 0, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 42, Number.MAX_VALUE, -(2**53), -(2**53+2), 2**53+2, 0x100000001, 1/0, 0/0, Math.PI, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, -0x100000000]); ");
/*fuzzSeed-246262462*/count=804; tryItOut("v2 = evaluate(\"testMathyFunction(mathy4, /*MARR*/[new Boolean(true), Infinity, NaN, new Boolean(true), NaN, new Boolean(true), new Boolean(true), Infinity, new Boolean(true), Infinity, new Boolean(true), Infinity, new Boolean(true), new Boolean(true), Infinity, Infinity, new Boolean(true), NaN, new Boolean(true), NaN, NaN, NaN, Infinity, Infinity, new Boolean(true), NaN, new Boolean(true), NaN, Infinity, NaN, NaN, NaN, Infinity, Infinity, new Boolean(true), new Boolean(true), new Boolean(true), NaN, NaN, NaN, new Boolean(true), NaN, Infinity, NaN, new Boolean(true), Infinity, new Boolean(true), new Boolean(true), Infinity, NaN]); \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: x, sourceIsLazy: \"\\u1430\", catchTermination: (x % 2 == 0) }));print(x);");
/*fuzzSeed-246262462*/count=805; tryItOut("\"use strict\"; /*oLoop*/for (wgomjo = 0; wgomjo < 113; ++wgomjo) { o2.a2[10] = h2; } ");
/*fuzzSeed-246262462*/count=806; tryItOut("M:for([x, x] =  \"\"  in NaN) g2.e2.delete(s1);");
/*fuzzSeed-246262462*/count=807; tryItOut("testMathyFunction(mathy4, [-(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, -0x100000001, 0x080000001, 0x100000001, -0x0ffffffff, 0x080000000, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, -0x100000000, 1/0, -0x07fffffff, 2**53-2, 0x07fffffff, 2**53, Number.MIN_VALUE, -1/0, -0, -0x080000000, 2**53+2, 42, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -0x080000001, 1, 0x0ffffffff, 0x100000000, 0/0]); ");
/*fuzzSeed-246262462*/count=808; tryItOut("mathy2 = (function(x, y) { return Math.log10(( + Math.max(( + ((x - (mathy1(( - (Number.MIN_SAFE_INTEGER >>> 0)), 0x080000000) | 0)) | 0)), ( + Math.pow(mathy0((( ~ (mathy0(0x080000000, y) % y)) | 0), (( ~ Math.sqrt(2**53+2)) | 0)), y))))); }); testMathyFunction(mathy2, [-0x100000000, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 1, -(2**53+2), -1/0, -(2**53), 1.7976931348623157e308, 42, -0x100000001, 0x080000000, 0/0, 2**53-2, -0x0ffffffff, -0, 0x100000001, 0x080000001, -(2**53-2), 0x100000000]); ");
/*fuzzSeed-246262462*/count=809; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-246262462*/count=810; tryItOut("mathy0 = (function(x, y) { return ( + Math.log2((Math.log10((Math.imul(Math.atan2(( - (( + Math.asin((y | 0))) ? -0 : ( + Math.tan(( + x))))), x), ( ! x)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [1/0, 0/0, 0x07fffffff, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), -0x100000001, -0, -Number.MIN_SAFE_INTEGER, 1, -0x080000001, Number.MAX_VALUE, -(2**53+2), 2**53+2, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, 42, 1.7976931348623157e308, -0x0ffffffff, -0x07fffffff, 0x0ffffffff, 0x080000000, 0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, 0, 0.000000000000001]); ");
/*fuzzSeed-246262462*/count=811; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return Math.fround((Math.fround(( ~ ( + ( - ( + ( + Math.hypot(( + x), ( + (((-Number.MAX_SAFE_INTEGER | 0) ** (x | 0)) | 0))))))))) >= Math.fround(Math.trunc(Math.fround(((((x >>> 0) * mathy0((Math.ceil(( + (y << -Number.MAX_VALUE))) >>> 0), y)) >>> 0) > ( + x))))))); }); testMathyFunction(mathy1, [0, Number.MIN_VALUE, 0.000000000000001, 1/0, -0, -Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, 42, -0x07fffffff, 0x100000000, 0x080000001, -(2**53-2), 1.7976931348623157e308, 0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1, -0x100000000, 2**53-2, 0x100000001, -0x080000001, -(2**53), -Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, 0/0, 2**53+2, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-246262462*/count=812; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return Math.atan2(( - Math.atan2((((Math.asinh(x) >>> 0) < (Math.acos(Math.fround(y)) | 0)) | 0), Math.fround((Math.cosh((( ~ (x | 0)) | 0)) | 0)))), (((( + Math.log2(( + Math.log(-Number.MAX_VALUE)))) | 0) == (Math.fround(( - Math.fround(-0x100000000))) >>> 0)) | 0)); }); ");
/*fuzzSeed-246262462*/count=813; tryItOut("this.p2 = o1.t0[5];");
/*fuzzSeed-246262462*/count=814; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.min(( + (( ! (((y ? Math.sinh(y) : (Math.min(( ~ (x | 0)), (Math.atan2((y >>> 0), y) | 0)) >>> 0)) * Math.fround(Math.fround(Math.fround(x)))) | 0)) | 0)), ( + Math.hypot((mathy2(mathy3((Math.fround(Math.atan2(Math.fround(x), y)) != Math.max(y, (Number.MIN_SAFE_INTEGER | 0))), mathy2(x, x)), (mathy0((y >>> 0), Number.MIN_VALUE) >>> 0)) | 0), (((Math.ceil(Math.imul(x, y)) >>> 0) >>> (Math.pow(((Math.fround((Math.clz32((y >>> 0)) >>> 0)) % (y >>> 0)) >>> 0), (((0x100000001 , (x | 0)) | 0) >>> 0)) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-246262462*/count=815; tryItOut("\"use strict\"; /*RXUB*/var r = /./y; var s = \"\\n\"; print(s.replace(r, ArrayBuffer, \"g\")); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=816; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=817; tryItOut("\"use strict\"; ");
/*fuzzSeed-246262462*/count=818; tryItOut("v0 = (o2.a2 instanceof v2);");
/*fuzzSeed-246262462*/count=819; tryItOut("\"use strict\"; o0.v1.toString = (function() { try { o1.toString = String.raw; } catch(e0) { } try { o0.v0 = a2.length; } catch(e1) { } try { m2.set(g0.a2, i2); } catch(e2) { } e0.add(g2); throw a1; });");
/*fuzzSeed-246262462*/count=820; tryItOut("\"use strict\"; e0.delete(t1);");
/*fuzzSeed-246262462*/count=821; tryItOut("m1.delete(a2);");
/*fuzzSeed-246262462*/count=822; tryItOut("\"use strict\"; /*MXX2*/g0.String.prototype.normalize = this.i1;");
/*fuzzSeed-246262462*/count=823; tryItOut("\"use strict\"; print(x);/*RXUB*/var r = new RegExp(\"(?:(?:\\\\B))(?=$(?!(?:(?:\\\\cY)[^\\u6efa\\\\x56-\\ufa14]))*?)\", \"gm\"); var s = \"\\n\\n\\n\\u0019\\u6efa\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-246262462*/count=824; tryItOut("\"use strict\"; x.stack;");
/*fuzzSeed-246262462*/count=825; tryItOut("\"use strict\"; m2 = new Map(g2);");
/*fuzzSeed-246262462*/count=826; tryItOut("e2.has(e0);\n/*oLoop*/for (var qgktcc = 0, ( /* Comment */(x) = \"\\u2E96\"); qgktcc < 32; ++qgktcc) { print(uneval(m0)); } \n");
/*fuzzSeed-246262462*/count=827; tryItOut("v0 = a0.length;");
/*fuzzSeed-246262462*/count=828; tryItOut("e1 = new Set(g0);");
/*fuzzSeed-246262462*/count=829; tryItOut("\"use strict\"; g1.m1.set(h1, m2);");
/*fuzzSeed-246262462*/count=830; tryItOut("mathy4 = (function(x, y) { return Math.atan2(mathy3(Math.fround(Math.imul(Math.fround((Math.fround(Math.imul(0x080000001, Math.fround(y))) ? Math.fround((y + y)) : Math.fround((( ! x) % y)))), (mathy3(Math.fround((Math.fround(y) || ((( + Math.fround(y)) | 0) >>> 0))), Math.fround(Math.fround(( ~ Math.fround(0))))) | 0))), ( + Math.fround((Math.fround(x) >> Math.fround(Math.fround(( + (x >= 0x080000000)))))))), Math.fround(Math.atan2(Math.fround(Math.fround(Math.atan2(( + (((mathy0(Math.exp(x), ((x >= Math.sqrt(x)) >>> 0)) >>> 0) >>> 0) ? mathy1(Math.fround(x), mathy0((y | 0), y)) : x)), ( - (0 << y))))), Math.fround(Math.min((( ! Math.fround(mathy0(( + x), y))) >>> 0), mathy0(y, y)))))); }); ");
/*fuzzSeed-246262462*/count=831; tryItOut("\"use strict\"; L:for(let b in ((Object.getOwnPropertyDescriptors)(x//h\n)))/* no regression tests found */");
/*fuzzSeed-246262462*/count=832; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( + ((Math.log2(( - ( + x))) | 0) | 0)) >>> 0); }); testMathyFunction(mathy4, [1.7976931348623157e308, 1/0, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 0x080000001, -(2**53-2), 2**53+2, 0x080000000, 0x100000001, -0x100000000, Number.MAX_VALUE, 0x07fffffff, -(2**53+2), 0, -0x0ffffffff, Math.PI, -0, -(2**53), -0x07fffffff, -Number.MIN_SAFE_INTEGER, -1/0, 2**53, 42, -0x080000001, Number.MIN_VALUE, 2**53-2, -0x100000001, -Number.MAX_VALUE, 0.000000000000001, 0/0, -Number.MIN_VALUE, 0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-246262462*/count=833; tryItOut("");
/*fuzzSeed-246262462*/count=834; tryItOut("\"use strict\"; /*hhh*/function spluis(z){igaxne();/*hhh*/function igaxne(window, z, \u3056, a, z, \u3056, window, w = true, w = /\\2?/gyi, x = window, z, NaN, c, z, NaN, z, w, x, NaN, w, z, x, window, c, b, x, NaN, d, e, \u3056, a =  /x/ , b, b, x, w, y, x, z, z,  , z, b, x, x, \"isArray\", z = 17, d, x = ({a2:z2}), x = x, x, a, x, b, z, z, b, x, z,  , c = \"\\u7267\", e, z, eval, z, \u3056, eval, x, constructor, a, y, z, \u3056 = -3, x, z = 4){print(z);}}spluis(/*RXUE*/new RegExp(\"$\", \"yi\").exec(\"\"), undefined);");
/*fuzzSeed-246262462*/count=835; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((abs(((((((0x6067799c) < (0x137842fb)))>>>((0xb963698d))) % (0x0))|0))|0) % (~~(-73786976294838210000.0))))|0;\n  }\n  return f; })(this, {ff: () =>  { (x); } }, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, 1/0, 0x100000000, -0x080000001, -0x07fffffff, -(2**53+2), 0/0, -0x080000000, 0x080000000, -(2**53-2), 0, 0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 42, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53, -(2**53), -0x100000001, -Number.MIN_VALUE, 2**53+2, Math.PI, Number.MAX_VALUE, 2**53-2, -0x100000000, -1/0, -0]); ");
/*fuzzSeed-246262462*/count=836; tryItOut("\"use strict\"; v0 = a1.length;");
/*fuzzSeed-246262462*/count=837; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.max(((Math.fround(Math.atanh(Math.fround(Math.fround(y)))) || Math.pow(Math.sqrt((Math.trunc((x | 0)) | 0)), x)) >> Math.sin(Math.fround((x | Math.fround(-0x100000001))))), Math.pow(Math.fround(Math.fround(((((( + ( ~ -(2**53+2))) * Math.fround(x)) | 0) && y) >>> ((y * (Math.acosh(-Number.MIN_SAFE_INTEGER) >> ((Math.imul((y >>> 0), (y >>> 0)) >>> 0) >>> 0))) ? ( - ( + Math.trunc(( + Math.acosh(x))))) : x)))), Math.fround(( + Math.atan2(2**53+2, (Math.min((Math.atan2(( ~ y), y) >>> 0), ( + Math.hypot(Math.max(x, ( + (x | 0))), x))) >>> 0)))))); }); testMathyFunction(mathy0, [2**53-2, -Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, Math.PI, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, -(2**53), 0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000001, -0, 1, -0x100000000, 0x100000001, Number.MAX_VALUE, 0, -0x080000001, 0x07fffffff, 0x100000000, -0x080000000, -Number.MIN_VALUE, 1/0, 0.000000000000001, -1/0, 2**53+2, 2**53, Number.MIN_SAFE_INTEGER, 42, -0x100000001, -(2**53-2), 0/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=838; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=839; tryItOut("\"use strict\"; f0 = Proxy.createFunction(h2, f0, f0);");
/*fuzzSeed-246262462*/count=840; tryItOut("\"use strict\"; a1[v1] = x;");
/*fuzzSeed-246262462*/count=841; tryItOut("/*RXUB*/var r = /\\3(?![^\\S\\W\u9058\\w]){2}\ubaff*|\\w{4,}{4}/; var s = \"a\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"a\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"a\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"a\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=842; tryItOut("\"use strict\"; let(uitnxr, 14, window = \"\\uC3D1\", vkvzqy, mbzfrp, e, hargbi, b, pszgta, x) { let(\u3056 = x, wetbjy, aqfuzd, mohmtf, qlsmfo) { yield (w) = function ([y]) { };}}try { with({}) yield x; } catch(x) { new RegExp(\"(\\\\3)|(?=^(?=\\\\xBe+)\\u000e)\", \"gm\").fileName; } ");
/*fuzzSeed-246262462*/count=843; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -2049.0;\n    d0 = (-((d2)));\n    {\n      (Float64ArrayView[(new runOffThreadScript()) >> 3]) = ((Float32ArrayView[((!(/*FFI*/ff()|0))) >> 2]));\n    }\n    d2 = (-67108864.0);\n    {\n      i1 = ((0x7feea40a) != (((i1)*0xd41bb)>>>((((0xf8c6668d)+((0xbf345225) ? (-0x8000000) : (0xcc245b49)))>>>((0x9fa65fb0)-(-0x8000000)-(0x9a021b0c))) / (((/*FFI*/ff(((((17.0)) * ((2199023255552.0)))), ((-1125899906842625.0)), ((2.3611832414348226e+21)))|0))>>>((0x9048a49) % (0x310fa8f6))))));\n    }\n    d2 = (Infinity);\n    return +((+((d2))));\n  }\n  return f; })(this, {ff: Uint8ClampedArray}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-246262462*/count=844; tryItOut("i2 + '';");
/*fuzzSeed-246262462*/count=845; tryItOut("switch([,]) { case (/*FARR*/[ \"\" ].map( '' ) ? (4277) : timeout(1800) ?  \"\"  : x): v1 = g2.eval(\"/* no regression tests found */\");break; case (makeFinalizeObserver('tenured')): print((this.__defineSetter__(\"x\", eval)));break; e1 = new Set(m2);break;  }");
/*fuzzSeed-246262462*/count=846; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=\\\\b*)|[\\\\w\\u76f2\\\\d\\\\W][\\\\S\\\\D\\\\s]*|(?![]*?)\\\\s|(?:.|\\\\b|(?:(?!.)))*?\", \"gim\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-246262462*/count=847; tryItOut("b1 + '';");
/*fuzzSeed-246262462*/count=848; tryItOut("\"use strict\"; t0 = new Int32Array(14);");
/*fuzzSeed-246262462*/count=849; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.acosh((Math.fround(Math.tanh((Math.log1p((Math.asin(y) | 0)) != Math.fround(( - Math.fround(-(2**53))))))) | 0))); }); ");
/*fuzzSeed-246262462*/count=850; tryItOut("var cbrazv = new ArrayBuffer(2); var cbrazv_0 = new Float64Array(cbrazv); cbrazv_0[0] = -23; print(x);Object.defineProperty(this, \"i2\", { configurable: false, enumerable: true,  get: function() {  return m2.values; } });");
/*fuzzSeed-246262462*/count=851; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2+\", \"gyi\"); var s = \"0000_00\"; print(r.test(s)); print(r.lastIndex); function x(window, eval, \u3056, \u3056, z, x, x, x, e, c, eval, x, \u3056, x,  '' , x, d = new RegExp(\"(?=\\\\3([^])?\\\\u0076?)*?\", \"gim\"), y, b =  '' , window, x, z, x, x = true, e, y, set, x, a = \"\\u800A\", x, x, x = false, y, x =  /x/ , x = \"\\u3A40\", a = null, x, x, x = 0, x, x, e, w, w, x = \"\\u158E\", y, x, x, \u3056, a, y, x, x, x, x, y, c, new RegExp(\"(?=[^])(?!(?!$|$\\\\D))*?+\", \"i\"), x, a, this.-851793072.5, NaN, c, eval, w, window, z, NaN, d, x, x, x, x, x = \"\\uB8A4\", a = window, set, c, y, x, x = null, b, \u3056)/*UUV2*/(x.setMonth = x.random)a2.pop();");
/*fuzzSeed-246262462*/count=852; tryItOut("b0 = new ArrayBuffer(40);");
/*fuzzSeed-246262462*/count=853; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((Math.cosh((((((Math.acosh(Math.fround(0)) * y) << Math.cbrt(-0x100000000)) >>> 0) >> Math.fround(( ~ -0x100000000))) | 0)) | 0) ? ( + ( ! Math.hypot(x, Math.fround(Math.log10(( + Math.acos(y))))))) : Math.fround(((mathy3((mathy2((mathy0((x >>> 0), (( ~ 1.7976931348623157e308) >>> 0)) >>> 0), (y ? y : x)) >>> 0), (Math.tanh(Math.fround(x)) >>> 0)) >>> 0) * mathy0((Math.atan2(Math.atan(Number.MIN_VALUE), Math.cbrt(Math.fround(42))) >>> 0), mathy0(y, ( + Math.min(-0x07fffffff, ( ~ x)))))))); }); testMathyFunction(mathy4, [0x080000000, -0x100000000, Math.PI, -0x080000000, -Number.MIN_SAFE_INTEGER, -1/0, 1, -(2**53+2), 0x0ffffffff, -0x080000001, 1/0, -0x0ffffffff, 42, -(2**53), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, -0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, 0x080000001, Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, 2**53-2, 1.7976931348623157e308, 0.000000000000001, Number.MAX_VALUE, 0, Number.MIN_VALUE, 0x100000000, 0x100000001, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-246262462*/count=854; tryItOut("\"use strict\"; let x = new (([x]))(new ((makeFinalizeObserver('nursery')) ** (4277)())(x)), x, \u3056, uifcbs, ( + Math.ceil(Math.fround(Math.hypot((x >>> 0), Math.fround(( + (( + Math.fround((Math.fround(x) ? ( + Math.pow(x, ( + x))) : Math.fround(x)))) * ( + ( + x))))))))), w;;");
/*fuzzSeed-246262462*/count=855; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! Math.sqrt(( - 42))); }); testMathyFunction(mathy0, [0.1, (new Number(0)), ({valueOf:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return 0;}}), undefined, [0], (new Boolean(true)), false, objectEmulatingUndefined(), '\\0', 1, (new Boolean(false)), 0, -0, null, /0/, '0', (function(){return 0;}), '', '/0/', [], true, NaN, ({toString:function(){return '0';}}), (new String(''))]); ");
/*fuzzSeed-246262462*/count=856; tryItOut("\"use strict\"; var zekmlq = new SharedArrayBuffer(0); var zekmlq_0 = new Int32Array(zekmlq); zekmlq_0[0] = 18; h0 = ({getOwnPropertyDescriptor: function(name) { function this.f2(s1)  { \"use strict\"; o2 = new Object; } ; var desc = Object.getOwnPropertyDescriptor(g1.o1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { /*MXX3*/g1.ReferenceError.prototype.constructor = this.g0.ReferenceError.prototype.constructor;; var desc = Object.getPropertyDescriptor(g1.o1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a0 = new Array;; Object.defineProperty(g1.o1, name, desc); }, getOwnPropertyNames: function() { o1.a2.reverse();; return Object.getOwnPropertyNames(g1.o1); }, delete: function(name) { this.o2 + '';; return delete g1.o1[name]; }, fix: function() { selectforgc(this.g2.o0);; if (Object.isFrozen(g1.o1)) { return Object.getOwnProperties(g1.o1); } }, has: function(name) { m1.toSource = (function() { try { Object.prototype.watch.call(s0, \"zekmlq\", (function() { try { v1 = r2.global; } catch(e0) { } try { v1 = this.g1.eval(\"mathy3 = (function(x, y) { return ((( + (Math.fround((Math.ceil(x) > Math.fround((Math.hypot(1/0, x) | 0)))) >>> 0)) >>> 0) != Math.fround(Math.min(Math.max(((x === x) >>> 0), (y >>> 0)), ((Math.max((1 >>> 0), (Math.fround(Math.log10(Math.fround(x))) >>> 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy3, [-0x100000001, -0x100000000, 1, 0x080000001, 0, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, 42, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 0.000000000000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, -(2**53-2), -0x080000001, -(2**53), -Number.MIN_VALUE, -0, 0x07fffffff, 1/0, 2**53+2, -0x0ffffffff, 0x100000001, 0/0, 0x0ffffffff, 2**53-2]); \"); } catch(e1) { } e1.add(this.a0); return b1; })); } catch(e0) { } v0 = evalcx(\"/* no regression tests found */\", g1); return v2; });; return name in g1.o1; }, hasOwn: function(name) { throw o2; return Object.prototype.hasOwnProperty.call(g1.o1, name); }, get: function(receiver, name) { g2.g0.offThreadCompileScript(\"function o2.f1(o1.g1.e1)  { \\\"use strict\\\"; \\\"use asm\\\"; continue M; } \", ({ global: o2.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: arguments, noScriptRval: true, sourceIsLazy: window, catchTermination: x }));; return g1.o1[name]; }, set: function(receiver, name, val) { i2.send(h2);; g1.o1[name] = val; return true; }, iterate: function() { for (var v of this.o1) { try { m0.has(g0.b1); } catch(e0) { } Array.prototype.sort.apply(a1, [-24.filter]); }; return (function() { for (var name in g1.o1) { yield name; } })(); }, enumerate: function() { h0 + g2;; var result = []; for (var name in g1.o1) { result.push(name); }; return result; }, keys: function() { /*RXUB*/var r = r2; var s = s1; print(s.split(r)); ; return Object.keys(g1.o1); } });\nv2 = t2.length;\n");
/*fuzzSeed-246262462*/count=857; tryItOut("for (var p in g0.g0) { try { for (var p in o0) { try { a2 = arguments.callee.caller.caller.caller.arguments; } catch(e0) { } try { s0 += 'x'; } catch(e1) { } v2 = new Number(-0); } } catch(e0) { } o0.valueOf = f1; }");
/*fuzzSeed-246262462*/count=858; tryItOut("testMathyFunction(mathy1, [0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, -0, 2**53-2, 2**53, 1/0, Math.PI, 0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -Number.MIN_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, 1, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, Number.MAX_VALUE, 0/0, -0x0ffffffff, -(2**53), 0x100000001, 0, -(2**53-2), -0x07fffffff, -0x100000001, 1.7976931348623157e308, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-246262462*/count=859; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.atan2(( + (Math.log10(( - x)) ^ ( ! Math.fround((x * x))))), ( + Math.min(( + ( ! (0 | 0))), ((((y | 0) ? ((Math.imul((x | 0), Math.fround(1.7976931348623157e308)) | 0) | 0) : -1/0) | 0) >>> 0)))) * (( + ( ! (x || (Math.hypot((y | 0), ((Math.asin((x | 0)) | 0) | 0)) | 0)))) , ( + ( - (Math.max((Math.sqrt(( + x)) >>> 0), Math.hypot(( + y), (((y | 0) | Math.hypot(x, -Number.MAX_VALUE)) | 0))) | 0))))); }); testMathyFunction(mathy0, /*MARR*/[]); ");
/*fuzzSeed-246262462*/count=860; tryItOut("m2.set(m1, a0);");
/*fuzzSeed-246262462*/count=861; tryItOut("/*bLoop*/for (var vmoanw = 0, [WebAssemblyMemoryMode(/*MARR*/[new String(''), new String(''), new String(''), new String(''), true, new String('q'), new String(''), new String(''), new String(''), [(void 0)], new String(''), new String(''), new String(''), new String('q'), true, true, new String(''), new String('q'), new String('q'), new String('q'), new String('q'), [(void 0)], new String('q'), [(void 0)], new String(''), new String('q'), new String(''), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, [(void 0)], true, new String(''), new String(''), new String(''), new String(''), true, true, new String(''), [(void 0)], new String('q'), true, new String(''), new String(''), new String(''), new String('q'), true, true, new String(''), true, [(void 0)], new String(''), new String(''), new String('q'), new String(''), new String(''), new String('q'), [(void 0)], new String(''), [(void 0)], new String('q'), new String(''), [(void 0)], new String(''), new String('q'), new String('q'), new String(''), [(void 0)], [(void 0)], [(void 0)], new String(''), true, new String('q'), new String(''), new String(''), new String(''), new String(''), new String(''), new String('')].sort(Math.min,  '' ), (4277))]; vmoanw < 8; ++vmoanw) { if (vmoanw % 5 == 3) { /*vLoop*/for (var rtqywh = 0, [x, {x, x, w}, ] = /[^](?!\\D)+?\\3|((?=\\b))|.+?\\D*|(?![^]$?*?)(?!([^\\x37-\\f\\S]{33554433,}))*/gy, x = function ([y]) { }.get(false); rtqywh < 32; ++rtqywh, x) { x = rtqywh; this.r0 = /\\2/gim; }  } else { v2 = (g1 instanceof t2); }  } ");
/*fuzzSeed-246262462*/count=862; tryItOut("\"use strict\"; akdeoq, ruruem, x, oystgm, x, window, sbweyf, zayoqo, eval;yield;");
/*fuzzSeed-246262462*/count=863; tryItOut("\"use strict\"; var paddgd = new ArrayBuffer(8); var paddgd_0 = new Float64Array(paddgd); paddgd_0[0] = 29; var paddgd_1 = new Uint8ClampedArray(paddgd); paddgd_1[0] = 19; var gbqynr = new ArrayBuffer(8); var gbqynr_0 = new Uint16Array(gbqynr); return \"\\u6AAD\";;e1.add(f0);\u000c{}print((eval(\"\\\"use strict\\\"; (\\\"\\\\u0859\\\");\")));\"\\u8F47\";");
/*fuzzSeed-246262462*/count=864; tryItOut("((({y: (w), x} = ( /* Comment */(let (z = \u0009x) z)))));");
/*fuzzSeed-246262462*/count=865; tryItOut("{v1 = evalcx(\"e0.__proto__ = t2;\", g2);/*bLoop*/for (ezujso = 0; ( \"\" ) && ezujso < 105; ++ezujso) { if (ezujso % 4 == 1) { selectforgc(o0); } else { print(x); }  }  }");
/*fuzzSeed-246262462*/count=866; tryItOut("\"use strict\"; v1 = evaluate(\"o2.g0.e2.has(x);\", ({ global: g1.g2, fileName: null, lineNumber: 42, isRunOnce: (x % 3 != 0), noScriptRval: (x % 2 == 1), sourceIsLazy: (x % 61 != 24), catchTermination: (4277), elementAttributeName: s1 }));");
/*fuzzSeed-246262462*/count=867; tryItOut("/*tLoop*/for (let d of /*MARR*/[({x:3}), new Boolean(false), (void options('strict_mode')), new Boolean(true), (void options('strict_mode')), (void options('strict_mode')), ({x:3})]) { o0.g2.v2 = (t0 instanceof a2); }");
/*fuzzSeed-246262462*/count=868; tryItOut("/*oLoop*/for (var wnhlai = 0; wnhlai < 13; ++wnhlai) { p1 + ''; } ");
/*fuzzSeed-246262462*/count=869; tryItOut("mathy3 = (function(x, y) { return mathy1((Math.fround((Math.fround(Number.MAX_SAFE_INTEGER) ^ Math.fround(Math.fround(Math.trunc((mathy1(( - ( + y)), y) >>> 0)))))) - (( + (Math.atan2(y, -Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0)), Math.fround(Math.asin(( ~ mathy0(( + ((-0x080000000 >>> 0) + y)), ( + 0/0)))))); }); testMathyFunction(mathy3, [2**53, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, 1, -0x080000001, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 1/0, -(2**53-2), 0x07fffffff, 2**53-2, 0x0ffffffff, 0/0, -0x100000000, 0x100000000, Number.MAX_VALUE, -0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, -1/0, 0, -(2**53), 0x100000001]); ");
/*fuzzSeed-246262462*/count=870; tryItOut("print(uneval(o1.t2));");
/*fuzzSeed-246262462*/count=871; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (-((0.0078125)));\n    return +((x));\n  }\n  return f; })(this, {ff: b => \"use asm\";   var imul = stdlib.Math.imul;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i0 = (i0);\n    return ((((((!((((0xffffffff)) | ((0x78b48ba6))) > (((131073.0)))))) >> (((((0xa46ee549)) ^ ((-0x8000000))) != (imul((0xdb9098cf), (0xfe825d4d))|0)))) <= (imul((i2), ((x) ? (i2) : ((-0x8000000) ? (0x301d1bbe) : (0xc5536467))))|0))+((((+(1.0/0.0))) * ((Float32ArrayView[((!(-0x8000000))-(i1)) >> 2]))) != (-9007199254740992.0))+(i0)))|0;\n  }\n  return f;}, new ArrayBuffer(4096)); ");
/*fuzzSeed-246262462*/count=872; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), ((4277).unwatch(\"link\")), function(){}, function(){}, objectEmulatingUndefined(), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), ((4277).unwatch(\"link\")), function(){}, objectEmulatingUndefined(), ((4277).unwatch(\"link\")), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, ((4277).unwatch(\"link\")), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, ((4277).unwatch(\"link\")), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), function(){}, ((4277).unwatch(\"link\")), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, new Boolean(false), function(){}, new Boolean(false), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), ((4277).unwatch(\"link\"))]); ");
/*fuzzSeed-246262462*/count=873; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=874; tryItOut("w = linkedList(w, 748);");
/*fuzzSeed-246262462*/count=875; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( ! ((( + mathy0(( ! Math.imul(x, (((mathy0(x, x) >>> 0) > mathy0(y, y)) >>> 0))), -0x100000001)) === Math.min(( + -0), (1.7976931348623157e308 >= (y ^ (((2**53-2 | 0) ? ((mathy0((Number.MAX_SAFE_INTEGER >>> 0), 0) >>> 0) | 0) : (y | 0)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy1, [2**53+2, Number.MIN_VALUE, Math.PI, -0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53, 1, -1/0, 0x07fffffff, 0x0ffffffff, -0x100000001, 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, 0, 1/0, -0x080000001, 0.000000000000001, 2**53-2, 0x100000001, 1.7976931348623157e308, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, -0x100000000, 0x080000000]); ");
/*fuzzSeed-246262462*/count=876; tryItOut("a2.sort(Date.prototype.getTime.bind(o2));");
/*fuzzSeed-246262462*/count=877; tryItOut("let c, window = x, {} = (e%=x), window = window = -29, y = 0, thpkpr;print((eval(\"[1]\") >>> x));");
/*fuzzSeed-246262462*/count=878; tryItOut("if(false) {h2.delete = (function() { try { s2 += 'x'; } catch(e0) { } r1 = new RegExp(\"\\\\1+?\", \"ym\"); return v0; });var x = x;o0 = this.s0.__proto__; }");
/*fuzzSeed-246262462*/count=879; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( ! Math.fround(( - Math.imul((Math.atan2(Number.MAX_SAFE_INTEGER, y) | 0), ( + Math.imul(Math.ceil(Math.fround((x > x))), (mathy1((((Math.fround(-0x0ffffffff) ? Math.fround(x) : Math.fround(x)) | 0) | 0), Math.fround(x)) ? -0x100000000 : Math.pow(y, y)))))))); }); testMathyFunction(mathy5, [0, 42, -1/0, Math.PI, 1.7976931348623157e308, 2**53, -(2**53+2), 0x080000000, Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, 1, -(2**53-2), -0, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 0x0ffffffff, -Number.MAX_VALUE, 1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 0x100000001, -0x100000000, 0x07fffffff, 0x080000001, 0x100000000, 2**53+2, -0x080000000, 0.000000000000001, -0x080000001]); ");
/*fuzzSeed-246262462*/count=880; tryItOut("mathy0 = (function(x, y) { return (Math.log((Math.max((Math.fround(( + Math.acos(( + y)))) === (( ! ( + Math.max(( + (0x07fffffff , y)), ( + x)))) >>> 0)), Math.log(Math.clz32(x))) | 0)) | 0); }); testMathyFunction(mathy0, [-(2**53), 0x100000001, 0x0ffffffff, Math.PI, 0x080000001, -Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, Number.MAX_VALUE, -0x100000000, 1/0, 2**53+2, -0x07fffffff, -1/0, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, 0.000000000000001, 1.7976931348623157e308, 1, -(2**53+2), 42, 0x100000000, -0x080000001, 0]); ");
/*fuzzSeed-246262462*/count=881; tryItOut("g2.a2.sort((function() { try { s1 = s1.charAt((+this)); } catch(e0) { } try { g1.m0.get(/\\1{0,}/gyim << false); } catch(e1) { } try { b1 = this.g1.t1.buffer; } catch(e2) { } selectforgc(this.o2); return o0; }), g1.s0, i2);");
/*fuzzSeed-246262462*/count=882; tryItOut("\"use asm\"; for (var p in b0) { try { i1 = new Iterator(s1); } catch(e0) { } for (var v of v0) { s0 += s2; } }");
/*fuzzSeed-246262462*/count=883; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s0; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=884; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - Math.acosh((mathy0(( + Math.max(Math.atan(Math.fround(Math.PI)), 0x07fffffff)), (y | 0)) >>> 0))); }); testMathyFunction(mathy4, [Number.MAX_VALUE, 0x100000001, Math.PI, -(2**53+2), -Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, 1/0, 42, -0x07fffffff, -(2**53), 1.7976931348623157e308, -0x100000000, -0x100000001, 2**53-2, 0x0ffffffff, 0/0, 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, -0x080000001, -0x0ffffffff, 0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0, -1/0, -0x080000000, 0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=885; tryItOut("(function(x, y) { return ( + Math.pow(( + Math.fround(Math.pow(Math.fround(( + Math.hypot(((( + Math.max(Math.sign(Math.log1p((Math.atan2(((( + (Math.cosh(Math.cosh(( + (( + x) ? ( + Math.pow(x, y)) : ( + (Math.max((y | 0), y) | 0)))))) | 0)) >>> 0) >>> 0), Math.fround(( ~ Math.fround((Math.hypot((x >>> 0), (((y | 0) + (y | 0)) | 0)) | ((Math.min((Math.sin(x) >>> 0), ((x | ( + y)) >>> 0)) >>> 0) >>> 0)))))) >>> 0))), ( + (((Math.pow((( ~ (Math.fround(Math.asin(Math.fround(Math.sign(( + (( + 0/0) && ( + y))))))) >>> 0)) >>> 0), (Math.cbrt(Math.max(Math.fround(Math.atan(( ~ -Number.MAX_SAFE_INTEGER))), (Math.min((Math.hypot(x, (Math.round(( + Math.min(x, x))) | 0)) | 0), (( - (Math.trunc(Math.fround(0x07fffffff)) | 0)) | 0)) | 0))) >>> 0)) >>> 0) ? ( + (Math.acosh(((( ~ (( + Math.pow(( + Math.hypot(x, y)), ( + ((y >>> 0) >>> (( ~ (y | 0)) | 0))))) | 0)) | 0) | 0)) | 0)) : Math.tan((((x >>> 0) - ( + ((( - y) >>> 0) ? y : Math.PI))) ? Math.log(Math.fround(y)) : Math.fround(Math.tanh((Math.acosh(Math.fround(((42 | 0) - (x % y)))) | 0)))))) >= (Math.fround(Math.acos(Math.fround(Math.fround(Math.ceil(Math.hypot((Math.exp(y) | 0), ( ! Math.fround(Math.hypot(y, ( + -(2**53-2))))))))))) ^ (( + (( + (Math.expm1(y) - (x % -Number.MIN_SAFE_INTEGER))) == ( + ( + Math.sin(Math.min(( + x), (Math.cos((x | 0)) | 0))))))) >= Math.asin(Math.tanh(-0x0ffffffff)))))))) % ((((Math.atan2(( + ( + (( + Math.imul(y, -0x07fffffff)) >>> ( + Math.clz32(x))))), Math.pow(( ~ (Math.fround((y | 0)) | 0)), ((((((Math.atan2((Math.max(x, x) | 0), ( + (y ? ( + x) : ( + -0)))) | 0) || ( ! y)) * Math.acosh((( ~ (x | 0)) | 0))) >>> 0) + ( + (Math.imul((Math.atan2(Number.MIN_SAFE_INTEGER, y) | 0), x) | 0))) >>> 0))) << (Math.pow(((Math.fround((Math.fround(( + -0x080000001)) && Math.fround(Math.max((Math.atanh((Math.sin(x) | 0)) | 0), Math.fround(x))))) | 0) - Math.fround(Math.fround(( + ( + Math.tan((( + ( + Math.fround(y))) >>> 0))))))), ( ~ (Math.max(( + Math.tanh(( + ( ~ x)))), (Math.fround((Math.fround(y) !== Math.fround(((y | 0) === Math.imul(Math.atan2(x, Math.PI), x))))) && y)) | 0))) >>> 0)) | 0) ** (( ! ((Math.fround(((Math.asinh((( ~ Math.acosh((( + ((Math.min((-Number.MAX_SAFE_INTEGER | 0), Math.atan2(0x07fffffff, y)) | 0) | 0)) | 0))) >>> 0)) >>> 0) << ( ~ (( ! (Math.max(Number.MAX_SAFE_INTEGER, (( + Math.asin(( + x))) | 0)) == y)) & Math.pow((Math.tanh((Math.hypot(Number.MIN_SAFE_INTEGER, -(2**53)) >>> 0)) | 0), ((( + (x && y)) % x) | 0)))))) >= ((( - ( + Math.log(y))) >>> Math.hypot(Math.fround(( - Math.pow(( ~ Math.fround((Math.fround(x) !== Math.fround(x)))), ( + x)))), Math.fround((( ! (Math.abs(( + (Math.fround(y) & (x | 0)))) | 0)) , Math.round(Math.asinh(y)))))) | 0)) | 0)) | 0)) | 0)) < (Math.imul((Math.abs((Math.round((Math.atan2(Math.fround(( ~ Math.asin(Math.pow((Math.max((x | 0), (0 | 0)) | 0), (x ? ((x + (( + ( - ( + 0x080000000))) | 0)) | 0) : (2**53-2 ? y : Math.fround(Math.acos(Math.fround(Math.atan2(x, y)))))))))), Math.fround((( + Math.fround(Math.max(( ~ (x ? (y === Number.MAX_SAFE_INTEGER) : x)), Math.pow(x, (Math.fround(Math.log10(Math.fround((Math.pow((y | 0), (y | 0)) | 0)))) >>> 0))))) ? Math.fround(((Math.clz32(y) ^ Math.max((x >>> 0), Math.fround(x))) | 0)) : Math.fround(Math.fround(( ! (Math.tanh(( + ((y ^ y) <= y))) >>> 0))))))) | 0)) | 0)) >>> 0), ((Math.hypot((Math.pow((( + (( + Math.fround(Math.atan2((( + Math.min(Math.atan2((y >>> 0), (y >>> 0)), ( + ( ~ ( ~ -0))))) | 0), (Math.max((( + (( - (x | 0)) | 0)) | ( + -(2**53))), Math.imul(Math.atan(y), (y | y))) | 0)))) >= ( + (( ! ( ! Math.fround(Math.max(( - x), y)))) >>> 0)))) | 0), ( ! Math.hypot(Math.pow(( + (( + (y | 0)) >>> 0)), Math.fround(Math.fround(( ! Math.fround(( - y)))))), (Math.atan2((Math.pow(Math.atan2(0.000000000000001, Math.cosh(Math.fround(Number.MAX_VALUE))), y) >>> 0), (Math.min((y | 0), (((( + y) >>> Math.fround(y)) >>> 0) | 0)) >>> 0)) >>> 0)))) | 0), Math.fround(Math.acosh((( - (Math.acosh((Math.min(( ~ Math.atanh((y | 0))), y) | 0)) | 0)) | 0)))) >> ( + Math.abs(Math.fround(( - Math.sign((Math.hypot(((( + (x >>> 0)) >>> 0) >>> 0), Math.hypot(x, (-(2**53) >>> 0))) / ((Math.fround(Math.sqrt(Math.fround(Math.atanh(y)))) - -Number.MIN_VALUE) >>> 0)))))))) >>> 0)) >>> 0)), ( ! (( + (Math.tan(Math.atan(((Math.log10((Math.fround(Math.expm1(Math.min((( + ( + (( + y) || ( + Number.MAX_VALUE)))) | 0), ( ~ Number.MIN_SAFE_INTEGER)))) <= Math.fround(Math.imul(Math.fround(( + Math.pow(( + ( + ( + Math.clz32(Math.fround(y))))), ( + (y || x))))), ((Math.fround((Math.fround(Math.cos(y)) | Math.fround(0x07fffffff))) & ((Math.cosh((x | 0)) | 0) ** Math.fround(( ~ x)))) >>> 0))))) >>> 0) >>> 0))) | 0)) | 0))))), Math.fround((Math.min(((( + ( ! Math.imul(( + Math.atan(( + Math.atan2(((Math.min((((( + (( - ( + ( + ( + (Math.clz32(y) ? x : Math.fround(y)))))) >>> 0)) | 0) % (( + Math.atan(Math.imul(( ~ ( ! Math.fround(y))), y))) | 0)) >>> 0), ((((Math.min((Math.pow(Math.fround(x), Math.fround(y)) >>> 0), (( + (Math.fround(( - ( - x))) >>> 0)) >>> 0)) | 0) | 0) * Math.log10(Math.fround(Math.sin(((-0x0ffffffff == (Math.trunc((x >= -0x080000001)) >>> 0)) - (y >>> Math.imul(Number.MIN_SAFE_INTEGER, x))))))) >>> 0)) >>> 0) >>> 0), (Math.fround(Math.sin(Math.atan2((((Math.exp((Math.max(x, (-0x07fffffff | 0)) << (Math.fround(-Number.MIN_VALUE) , Math.pow((y | 0), y)))) >>> 0) , (( - x) >>> 0)) >>> 0), Math.acos(Math.min((-0x07fffffff % (y >>> 0)), (( ! (y | 0)) | 0)))))) >>> 0))))), Math.fround(Math.hypot(Math.fround((Math.fround((Math.tan((Math.imul((Math.asin(((Math.fround(Math.round(x)) | (x || y)) | 0)) | 0), 0x080000001) < Math.max(Math.fround(Math.sin(( + ((y , (( ! x) >>> 0)) === Math.sqrt(y))))), Math.asinh(y)))) < ((( ~ (Math.acosh((Math.atan2((( + (0x100000000 ** ( + Math.fround(Math.hypot(y, 1/0))))) | 0), ((((x >>> 0) ^ (x | 0)) | 0) | 0)) | 0)) >>> 0)) >>> 0) | 0))) , (( + ( - (( + ((Math.imul((( ! (x | 0)) | 0), (( - y) | 0)) | 0) ** ( + ((Math.expm1((( - x) >>> 0)) | 0) != x)))) >>> 0))) ? (Math.min(Math.imul(( + Math.log1p(( + Math.log1p(Math.tanh(x))))), ( + Math.fround(Math.imul((Math.round(y) ? y : y), (((-0x080000000 | 0) >>> -0) | 0))))), Math.hypot(Math.sinh(Math.hypot((Math.atanh(y) | 0), (Math.pow(y, y) | 0))), (Math.asinh((Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))) >= Math.hypot(( + Math.min(( + ((( - (x >>> 0)) === ( + (x | 0))) | 0)), ( + Math.tan(x)))), ((Math.hypot((y >>> 0), ( + ( + Math.pow(( + y), ( + -(2**53+2)))))) | 0) + Math.hypot(Math.pow(x, Math.fround(Math.hypot(Math.fround((Number.MIN_SAFE_INTEGER + x)), y))), Math.cosh((Math.fround(Math.max(Math.fround(x), Math.fround(x))) >>> 0)))))) : Math.imul(Math.fround(Math.sign(Math.fround(Math.fround(Math.abs(( + ( ~ (Math.tanh(x) >>> 0)))))))), Math.fround(Math.log(( ! Math.expm1(( ! Number.MIN_SAFE_INTEGER))))))))), ( + Math.sqrt(( + (( + Math.fround(( ~ Math.fround(Math.acosh(Math.atan2((new RegExp(\"[^]\", \"m\") | 0), 0x07fffffff)))))) << ( ~ Math.fround(Math.exp((Math.acos(( + Math.hypot(( + x), ( + Math.log2((x | 0)))))) >>> 0))))))))))))) != Math.hypot(Math.fround((( - ( ~ ( + Math.atan(( + ( + ( - (( - (( + Math.imul(y, Math.fround(( - Math.fround(y))))) | 0)) | 0)))))))) << (Math.exp(( + ( ~ (( + ((( + (( ! (Math.max(( + Math.fround(Math.asin((-Number.MIN_SAFE_INTEGER | 0)))), ( + x)) | 0)) >>> 0)) >>> 0) | 0)) | 0)))) | 0))), Math.hypot(Math.atan2(Math.log10(( ~ ((( + Math.atan2(((((Math.tanh(( ! y)) ? ( + Math.asin(x)) : x) | 0) ? ((Math.min((Math.hypot(x, Number.MAX_VALUE) << (x % 0x07fffffff)), Math.atan(( ~ y))) | 0) | 0) : ( + Math.fround((((( ! ((( ~ ( + x)) >>> 0) | 0)) | 0) | 0) > Math.fround(Math.sign((( + (y + ( + ( + Math.fround(y))))) | 0))))))) >>> 0), (( ! Math.fround(Math.imul(y, y))) >>> 0))) >>> 0) >>> Math.max((Math.imul((Math.min(Math.hypot(Math.asin(y), x), (((x | 0) == (x | 0)) | 0)) | 0), (Math.fround(( - Math.fround(y))) | 0)) | 0), Math.acos(( + ( + ( + Math.sinh(x))))))))), ( + (( + Math.atan2(Math.fround(Math.pow((Math.ceil((y >>> 0)) / Math.min(( + ( + ( + ( + Math.clz32(Math.fround(Math.pow(Math.fround(Math.min(-Number.MIN_VALUE, x)), Math.fround(-Number.MAX_VALUE)))))))), Math.fround(Math.fround(x)))), ( + Math.fround((Math.fround(( + (y ? (Math.min((y >>> 0), (Number.MIN_VALUE >>> 0)) >>> 0) : Math.max(y, (Math.tanh(( + y)) | 0))))) >= ( + ( ~ ( + ( ~ ((( + (Number.MAX_VALUE | 0)) | 0) >>> 0)))))))))), ((Math.min((((Math.clz32(Math.fround(Math.fround(Math.cbrt(Math.fround(y))))) >>> ( ~ ( ~ y))) >>> 0) | 0), (Math.fround(Math.sinh(Math.fround(( + (Math.fround(Math.atan2(y, ( + 0x100000001))) % Math.fround((Math.fround(Math.pow(Math.pow(y, -0x07fffffff), (y | 0))) ? (1 == y) : Math.log2((-1/0 >>> 0))))))))) | 0)) | 0) < ( + (((Math.round(Math.log(((Math.min(x, -Number.MAX_VALUE) >>> 0) >>> 0))) > Math.fround((Math.fround(Math.fround(x)) === Math.fround(( ! ( + y)))))) >>> 0) ? Math.cbrt(( + Math.atan2(x, (( + ((y | 0) ? (( + x) | 0) : -Number.MAX_SAFE_INTEGER)) | 0)))) : ( ! y)))))) << ( + ( ! ( + ( + Math.expm1(( + (Math.fround((( ! ((((0x07fffffff ? Math.fround(y) : x) ? Math.min(Math.fround(Math.fround(( + Math.fround(((Number.MAX_VALUE == -1/0) >>> 0))))), Math.fround(x)) : 0x100000000) >>> 0) >>> 0)) >>> 0)) >>> Math.fround(Math.asin((((x >= Math.hypot(x, ( + Math.min(y, ( + 0))))) | 0) >>> 0))))))))))))), (( ~ (((Math.fround(Math.exp((Math.fround((( + Math.cosh(( + x))) ? Math.imul(2**53, Math.sin(( ~ (y >>> 0)))) : Math.sqrt(( + ( ~ Math.min((Math.imul((Number.MAX_SAFE_INTEGER >>> 0), (y >>> 0)) >>> 0), (-(2**53-2) >>> 0))))))) >>> 0))) ^ ( + Math.fround(( + Math.tanh(( + ((((((Math.atan2((y | 0), (y | 0)) | 0) >>> 0) || (y >>> 0)) >>> 0) >>> 0) - Math.fround((( + Math.tanh((y | 0))) !== Math.hypot(Math.pow(y, 42), -Number.MIN_VALUE)))))))))) % (Math.hypot(((Math.expm1(( + ( ~ ( + (((0x100000001 >>> 0) >>> ((Math.cbrt(y) | 0) / (-0x080000000 | 0))) >>> 0))))) | 0) ? Math.fround(((( + ( - -(2**53-2))) >>> 0) <= Math.fround(Math.fround(Math.asinh(Math.fround(Math.tan(y))))))) : (Math.pow((( + (Math.fround((x > Math.fround(y))) << ( + Math.fround(( ! ((Math.fround(y) == x) | 0)))))) | 0), (y | 0)) >>> ((Math.round((Math.asinh(0) >>> 0)) >>> 0) <= Math.log((Math.hypot(-(2**53+2), (x | 0)) | 0))))), ( + Math.cosh(Math.sin((Math.atan2((Math.pow((Math.pow((x >>> 0), y) >>> 0), x) | 0), Math.max(( - -0x100000001), x)) | 0))))) >>> 0)) >>> 0)) >>> 0)))) | 0), (( + ( ! ( + Math.fround(( ~ ( + Math.pow(Math.max(((((Math.asin((Math.min(Math.expm1(( + Math.log10(y))), Math.fround(( ~ ( + Math.sign(( + Math.fround(( - x)))))))) | 0)) | 0) >>> 0) ** (Math.fround((Math.log10(((( ~ ((x | ( + (y ^ x))) >>> 0)) >>> 0) % ((((Math.pow((y | 0), (Math.tanh(x) | 0)) >>> 0) | 0) % ((( ~ y) >>> 0) | 0)) >>> 0))) ? Math.fround(( ! Math.fround(( - Math.acos((Math.fround(( ~ y)) & x)))))) : Math.fround(( + (Math.trunc(Math.expm1(Math.hypot(-0x0ffffffff, x))) + ( - ( + (1.7976931348623157e308 << Number.MIN_SAFE_INTEGER)))))))) >>> 0)) >>> 0), ( ~ ( ~ (( ~ (Math.imul(( ~ (( + (((y | 0) ? (x | 0) : (y | 0)) | 0)) >> ( + (( + ( ~ (Math.cos(y) >>> 0))) || ( + -Number.MAX_VALUE))))), Math.fround(Math.trunc((((( - Math.fround(Math.sqrt(Math.acosh(x)))) >>> 0) , ( + (x | 0))) | 0)))) >>> 0)) >>> 0)))), Math.fround((Math.atanh(Math.fround((Math.fround(Math.imul((Math.tanh(((( ! ( ! Math.fround(y))) > (((Math.acos(((2**53+2 ** y) | 0)) >>> 0) ^ (-(2**53) >> 2**53+2)) | 0)) | 0)) | 0), (Math.imul(( + ( ! Number.MIN_SAFE_INTEGER)), Math.fround(Math.acosh((( - Math.fround(Math.imul(Math.min(y, y), Math.fround(Math.hypot(y, ( + (( ~ (y >>> 0)) >>> 0))))))) | 0)))) | 0))) == Math.fround((Math.imul(((Math.log(Math.fround((Math.fround(-(2**53)) >> Math.fround(y)))) - (( + (y >>> 0)) >>> 0)) >>> 0), ((( + -0x100000001) >>> Math.fround((42 != -Number.MIN_SAFE_INTEGER))) >>> ( + (Math.fround(Math.min(x, x)) | 0)))) >>> 0))))) << (Math.fround((Math.fround(( ! ( - Math.fround(( + ((Math.log10((Math.round(y) >>> 0)) >>> 0) , ( + y))))))) && Math.fround(( + Math.imul(Math.hypot((((x !== y) | 0) === Math.fround((((Math.hypot((Math.fround((Math.fround(0) / Math.fround(y))) >>> 0), 1.7976931348623157e308) | 0) ? 1.7976931348623157e308 : y) === Math.fround(((Math.clz32(-Number.MAX_VALUE) ? (x | 0) : (y >>> 0)) || Math.ceil(y)))))), ( + (( + ( ! y)) << ( + -Number.MIN_VALUE)))), (( ~ Math.fround((Math.fround(Math.log2(Math.max(Number.MIN_SAFE_INTEGER, x))) | Math.fround(x)))) | 0)))))) - (Math.fround(Math.atan2(Math.fround((Math.fround(Math.min(Math.fround((( ! y) * Math.atanh(( + Math.PI)))), (((Math.round(0x080000001) | 0) + (y | 0)) | 0))) + ( + ( ~ ( + Math.fround(Math.log2(((x | 0) ? (( - 0/0) | 0) : (Math.fround(( - Math.fround(( + (( + y) & ( + 2**53-2)))))) | 0))))))))), Math.trunc(((Math.fround(Math.fround(( + Math.fround(-0x080000001)))) != ( + Math.atanh(Math.fround(Math.min(Math.fround((( + x) | 0)), Math.fround(x)))))) | 0)))) - Math.atan(Math.pow(( ! ((( + ( ~ ((x % Math.PI) >>> 0))) || (0x080000001 | 0)) | 0)), (Math.atan2((Math.fround(Math.hypot(Math.fround(x), ( + (( ~ (( + (( + y) & Math.fround(-0))) >>> 0)) >>> 0)))) >>> 0), (x >>> 0)) >>> 0)))))))))))))) | 0)) | 0))))), ( + Math.fround(Math.abs(( + (Math.fround((Math.fround(( + Math.fround((((((((Math.fround((( + Math.atan2(Math.exp(y), (( + Math.fround(( ~ ( + -0x100000000)))) >> x))) < (Math.hypot((y / x), ( + -0x0ffffffff)) >>> 0))) > Math.fround((( ~ Math.fround(Math.fround(x))) | 0))) >>> 0) | 0) ? (( + (Math.fround(( ! ((((Math.max(( - -Number.MIN_VALUE), ( + Math.fround((Math.fround(y) >= x)))) | 0) >>> 0) % Math.max((Math.max((Math.PI >>> 0), (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0), (Math.imul(y, (Math.min(x, x) >>> 0)) >>> 0))) >>> 0))) , ( + ( + (( + Math.cosh(((Math.fround((( - ((((x >>> 0) / (-0x0ffffffff | 0)) >>> 0) >>> 0)) >>> 0)) >= (Math.fround((Math.fround(x) / Math.fround(( + (Math.fround(x) & x))))) | 0)) | 0))) + ( + Math.fround(((x | 0) == (((Math.atan2(( + y), (x | 0)) ? ((Math.log2(0x080000000) >>> 0) | 0) : ( + (Math.min((Math.abs((y >>> 0)) >>> 0), x) | 0))) | 0) >>> 0))))))))) | 0) : (((Math.trunc(Math.max(Math.fround(Math.hypot(( + ((x * y) >>> 0)), ( + Math.fround(( ! Math.fround(x)))))), (( - -(2**53)) >>> 0))) >>> 0) && ((( ! (((((((x ? ((-0x0ffffffff >>> 0) >>> Math.fround(x)) : y) | 0) != Math.log((( ~ (x | 0)) | 0))) | 0) & (( + Math.expm1(Math.fround((Math.pow(x, y) | 0)))) | 0)) | 0) | 0)) | 0) >>> 0)) | 0)) >> (( + ((( + Math.min(( ! Math.atan2(-Number.MIN_VALUE, (Math.sin(Math.abs(y)) | 0))), ( + ( + (( + Math.fround(Math.trunc(-Number.MAX_VALUE))) == Math.hypot(x, Math.sqrt(( + ( ! 1/0))))))))) >>> 0) ? (( + (( + ((Math.pow(Math.pow((Math.hypot(y, x) == y), y), ( + y)) >>> 0) ? (x >>> 0) : (Math.imul(Math.fround(((y | 0) >>> Math.fround((((1 >>> 0) ? y : -0x100000000) >>> 0)))), 0x07fffffff) >>> 0))) / ( + (((Math.exp((Math.max((x >>> 0), (Math.imul(y, Math.fround((Math.fround(Number.MIN_SAFE_INTEGER) + Math.fround(x)))) >>> 0)) >>> 0)) >>> 0) > (( ~ 0x07fffffff) >>> 0)) >>> 0)))) >>> 0) : (Math.fround(Math.imul((Math.atan2(Math.atan2(Math.max((1.7976931348623157e308 ? y : ( + (x && (-0x100000000 >>> 0)))), y), Math.hypot((((y >>> 0) - (( ~ x) | 0)) >>> 0), Math.exp(y))), ( ! x)) >>> 0), (Math.hypot((x < Math.sinh((x >>> 0))), ( + -(2**53+2))) | 0))) | 0))) ? ( + Math.hypot(((Math.fround(Math.fround(( ! Math.fround((( ! ((x ? Math.asinh(((x < x) | 0)) : y) | 0)) >>> 0))))) ? ((Math.round((( - x) >>> 0)) | 0) >>> 0) : ( ! Math.tan(Math.fround(x)))) >>> 0), ((Math.fround(Math.log2(Math.fround(( - Math.fround(( + Math.fround(( + y)))))))) && ( + ((((x >>> y) >>> 0) && Math.fround((Math.imul(y, (Math.sin(y) >>> 0)) >>> 0))) >>> 0))) ? Math.fround(Math.log2(Math.acosh(Math.fround(Math.atan2((0x080000001 >>> 0), ((Math.sin(y) >>> 0) >>> 0)))))) : ((x >>> 0) + ( + ((Math.pow(y, ( + ( ~ ( + 0.000000000000001)))) & ( + x)) >= (Math.tanh((Math.sin(y) | 0)) | 0))))))) : Math.exp(( ~ (Math.tan(Math.imul(( + ((x | 0) > x)), (x >>> 0))) | 0))))) & ( ~ ( + Math.fround(Math.exp(Math.fround(((1 >>> (((y << Math.min(y, x)) !== (( ! (( ~ y) >>> 0)) >>> 0)) >>> 0)) > (((( ~ (( ! Math.fround(( - x))) | 0)) | 0) >>> 0) ? Math.fround(Math.atan2(-0x100000001, Math.exp(y))) : (-0x080000000 != Math.imul(x, (Math.min((x >>> 0), (Math.atanh(( + 0x07fffffff)) >>> 0)) >>> 0))))))))))) >>> 0)))) >>> 0)) << ( + (Math.hypot((Math.sin(( ~ ( + Math.pow(( + Math.ceil(((Math.asinh(( ! (((-1/0 | 0) | x) | 0))) | 0) == Math.atan2(( + ( + (x ? (x | 0) : (x >>> 0)))), Math.fround(Math.asin((y | 0))))))), ( + ( - ((Math.imul(x, (( ~ (Math.cos(-Number.MIN_SAFE_INTEGER) | 0)) | 0)) != (Math.atan2(Math.fround(( - x)), ((Math.trunc(0.000000000000001) ? (Math.log10(x) ? y : x) : x) | 0)) | 0)) >= (Math.log1p(Math.fround(Math.fround(Math.pow(Math.atan2(x, Math.atan(x)), y)))) | 0)))))))) >>> 0), (((( + ( ~ ( + (( + Math.sinh(( + (( + ( ! ( ! Math.expm1(-Number.MIN_VALUE)))) / Math.cosh(Math.hypot(x, x)))))) + (Math.atan2(( + (( + (Math.fround(Math.min((( + ((y >>> 0) << ( + ( - y)))) | 0), (( ! (-0x0ffffffff | 0)) | 0))) / ( ~ Math.min(y, (x | 0))))) < x)), ( + ( + ((Math.fround(( ! Math.fround(-Number.MAX_SAFE_INTEGER))) >>> (( + ( - ( + Math.min(( + Math.tan((x | 0))), Math.fround(Math.sinh(0/0)))))) | 0)) >>> 0)))) | 0))))) >>> 0) ? Math.fround(( ~ Math.fround(Math.atan2(Math.cosh((((Math.asin(((( + (( - y) | 0)) | 0) | 0)) | 0) ? (Math.imul(Math.fround((( - (( ~ (2**53+2 , (Math.fround(Math.min(Math.fround(x), x)) ? Math.tanh((Math.PI | 0)) : y))) >>> 0)) | 0)), (Math.fround((( + Math.imul(Math.imul(y, (( ! 1.7976931348623157e308) >>> 0)), x)) ^ Math.fround(((Math.acosh(x) !== (( + Math.pow(( + x), ((Math.hypot((0 >>> 0), (y >>> 0)) >>> 0) | 0))) | 0)) | 0)))) >>> 0)) >>> 0) : ( - (( ~ (Math.fround(Math.asin(Math.fround(( ~ (( + y) <= x))))) | 0)) | 0))) >>> 0)), ( ~ Math.imul(Math.fround(( + ( ~ (((( + ((y | 0) < (x | 0))) | 0) ? ((Math.fround(x) ** Math.fround(Math.fround((Math.fround(Math.PI) ** x)))) | 0) : (( + Math.log1p(( + ( + (x >> ( + (Math.tan(x) !== x))))))) | 0)) | 0)))), Math.log10((( + ((x > x) >>> 0)) >>> 0)))))))) : (Math.atan2(Math.fround(( + Math.fround(Math.trunc(((( ! ( + (Math.log(Math.fround(( + x))) | 0))) / Math.fround((Math.fround(( + Math.log1p(( + ((Math.min((x | (( + x) ? ( + Number.MIN_SAFE_INTEGER) : ( + x))), -0x100000000) >>> 0) != y))))) | ( + Math.atan2(((((Math.imul(Math.sinh(x), y) | 0) && (0x080000001 | 0)) | 0) >>> 0), Math.min(-(2**53-2), y)))))) | 0))))), (( ! (( + Math.abs((( + ( + ( ! ( + ((Math.pow(( + ((Math.atan2((Math.round((2**53 >>> 0)) >>> 0), (x | 0)) | 0) ? x : (Math.hypot((y >>> 0), (-(2**53-2) >>> 0)) | 0))), (( + (( + x) * ( + (( + y) ? y : y)))) | 0)) | 0) + (Math.hypot((y | 0), Math.fround(x)) | 0)))))) >>> 0))) >>> 0)) >>> 0)) >>> 0)) | 0)) | 0))))))))); })");
/*fuzzSeed-246262462*/count=886; tryItOut("var [] = x, window = (c ^= x), ialynf, x = (window) =  /x/g , z = (4277).eval(\"mathy3 = (function(x, y) { \\\"use strict\\\"; return Math.sign(Math.fround(mathy1(( + -Number.MAX_SAFE_INTEGER), Math.fround((Math.fround((Math.fround(x) >= Math.fround(0))) < x))))); }); \");/*MXX2*/g1.String.prototype.startsWith = b2;");
/*fuzzSeed-246262462*/count=887; tryItOut("\"use strict\"; h0.enumerate = (function() { for (var j=0;j<44;++j) { o1.f2(j%2==0); } });");
/*fuzzSeed-246262462*/count=888; tryItOut(";");
/*fuzzSeed-246262462*/count=889; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.atan2(Math.hypot(Math.atan(Number.MAX_VALUE), (( ! Math.round(Math.fround(-(2**53)))) >>> 0)), ( + Math.fround(( - Math.fround(Math.sinh(x)))))) + Math.atanh((mathy2((Math.imul(((x | 0) | (y | 0)), ((( + (( + x) ** Math.fround(y))) | 0) ? Math.fround(Math.max(y, x)) : Math.fround(y))) >>> 0), ( - Math.fround(( + y)))) >>> 0))); }); testMathyFunction(mathy4, [0x0ffffffff, 0x100000001, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 0x100000000, 1/0, 2**53, Number.MIN_SAFE_INTEGER, 0/0, -0, Math.PI, -Number.MAX_VALUE, 0, -0x100000001, -Number.MIN_VALUE, 1, -0x100000000, 42, -(2**53-2), 2**53-2, 0.000000000000001, -1/0, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000000, 0x080000001]); ");
/*fuzzSeed-246262462*/count=890; tryItOut("\"use strict\"; var anrkhs = new ArrayBuffer(4); var anrkhs_0 = new Uint32Array(anrkhs); anrkhs_0[0] = 27; var anrkhs_1 = new Int32Array(anrkhs); anrkhs_1[0] = 23; var anrkhs_2 = new Float64Array(anrkhs); var anrkhs_3 = new Uint16Array(anrkhs); var anrkhs_4 = new Uint16Array(anrkhs); print(anrkhs_4[0]); anrkhs_4[0] = -28; var anrkhs_5 = new Uint8ClampedArray(anrkhs); print(anrkhs_5[0]); anrkhs_5[0] = -15; var anrkhs_6 = new Float64Array(anrkhs); anrkhs_6[0] = -20; ((x =  /x/g ));for (var v of h0) { e2.has(window); }yield yield this;print(anrkhs_3[0]);(\u0009anrkhs_1[0]);print(x);/* no regression tests found */");
/*fuzzSeed-246262462*/count=891; tryItOut("mathy3 = (function(x, y) { return ( ~ Math.atan((((( + Math.min(Math.atanh(( + -0x080000001)), x)) ? ((mathy2((-0x100000000 | 0), (Math.fround(y) << Math.fround(Math.fround((0.000000000000001 ? (x | 0) : 0.000000000000001))))) | 0) >>> 0) : (Math.hypot(( ~ y), x) >>> 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy3, [2**53+2, 2**53-2, -0x07fffffff, 0, -0x080000000, 1/0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, 0x080000001, -0x100000000, 0x100000000, 0x080000000, 2**53, -1/0, Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, Math.PI, -0, 0.000000000000001, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff]); ");
/*fuzzSeed-246262462*/count=892; tryItOut("e1.add(v2);");
/*fuzzSeed-246262462*/count=893; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=894; tryItOut("mathy1 = (function(x, y) { return Math.hypot(Math.max(Math.fround((Math.asin(((( - mathy0(x, (( + 2**53-2) >>> 0))) | 0) >>> 0)) >>> 0)), ( + Math.pow(( + x), ( + (Math.hypot(x, ( + -0x0ffffffff)) == (x >>> 0)))))), Math.ceil(Math.log((( ~ -0x100000000) === (( ~ (( + x) >>> 0)) | 0))))); }); testMathyFunction(mathy1, [0x07fffffff, -Number.MIN_VALUE, -0x080000001, 42, 2**53+2, 2**53-2, 0x080000000, Math.PI, 1/0, -Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, -1/0, -0x080000000, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 0x080000001, 2**53, -0x100000001, Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -(2**53+2), 1, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, -0, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), -(2**53-2), 0x100000000]); ");
/*fuzzSeed-246262462*/count=895; tryItOut("\"use strict\"; e2.add(b0);");
/*fuzzSeed-246262462*/count=896; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 2147483647.0;\n    (Int32ArrayView[4096]) = ((/*FFI*/ff()|0));\n    return ((((((i1))) >= (((0xfaf31566)+(0xc8670780))>>>((0xfec29f5b))))-(i0)+(/*FFI*/ff(((+(-1.0/0.0))), ((((i1)-(!(0xffffffff))) >> ((i1)))), ((abs((~~(-3.094850098213451e+26)))|0)), ((-65.0)), ((+atan2(((d2)), ((+(1.0/0.0)))))), ((-((-2251799813685248.0)))), ((d2)), ((-17.0)), ((-144115188075855870.0)), ((-32769.0)), ((-73786976294838210000.0)), ((1.5474250491067253e+26)), ((8589934593.0)), ((274877906945.0)))|0)))|0;\n    i1 = (i0);\n    d2 = (1.03125);\n    return (((i1)-(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x0ffffffff, 42, -0x080000000, -0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -(2**53+2), -(2**53-2), -Number.MAX_VALUE, 2**53-2, 0.000000000000001, Number.MIN_VALUE, -0x07fffffff, 0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, -0, -1/0, 0, 0/0, 1, 1/0, 0x07fffffff, 2**53, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 0x100000000, 0x080000001, -0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=897; tryItOut("selectforgc(o2);m1 + '';");
/*fuzzSeed-246262462*/count=898; tryItOut("const eval = ([] = \"\\uFBC7\");/*RXUB*/var r = new RegExp(\"((.)+)?\", \"gyi\"); var s = x; print(r.exec(s)); ");
/*fuzzSeed-246262462*/count=899; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.round(Math.hypot((Math.min((x | 0), y) | 0), x))); }); testMathyFunction(mathy4, /*MARR*/[false, false, [undefined], objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), [undefined], objectEmulatingUndefined(), [undefined], objectEmulatingUndefined(), [undefined], false, objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, false, false, false, false, false, false, false, false, false, false, false, objectEmulatingUndefined(), [undefined], false, [undefined], false, [undefined], [undefined]]); ");
/*fuzzSeed-246262462*/count=900; tryItOut("/*tLoop*/for (let b of /*MARR*/[ '\\0' , new Boolean(false), new Boolean(false), new Boolean(false),  '\\0' , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  '\\0' ,  '\\0' , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  '\\0' , new Boolean(false),  '\\0' ,  '\\0' ,  '\\0' , new Boolean(false),  '\\0' , new Boolean(false),  '\\0' ,  '\\0' , new Boolean(false),  '\\0' ,  '\\0' , new Boolean(false),  '\\0' , new Boolean(false), new Boolean(false), new Boolean(false),  '\\0' ,  '\\0' ,  '\\0' , new Boolean(false)]) { g2.v0 = Array.prototype.every.call(a1, this.f2, b2, o0); }");
/*fuzzSeed-246262462*/count=901; tryItOut("(void schedulegc(g2.g2));");
/*fuzzSeed-246262462*/count=902; tryItOut("/*MXX2*/g2.Uint8Array.prototype = e1;");
/*fuzzSeed-246262462*/count=903; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=904; tryItOut("testMathyFunction(mathy2, [true, '0', '\\0', undefined, /0/, [0], false, (new Boolean(false)), 0, 0.1, (new Boolean(true)), objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), (function(){return 0;}), ({toString:function(){return '0';}}), NaN, (new String('')), -0, '', (new Number(0)), [], null, (new Number(-0)), 1, ({valueOf:function(){return '0';}}), '/0/']); ");
/*fuzzSeed-246262462*/count=905; tryItOut("mathy4 = (function(x, y) { return Math.max((Math.log(Math.fround(( + ((Math.fround(Math.max(Math.fround(Math.asinh(y)), x)) ** x) % y)))) | 0), Math.pow(Math.max((Math.atan2((Math.fround(Math.hypot(Math.fround(Math.max(Math.fround(-Number.MAX_VALUE), Math.fround(x))), Math.fround(x))) | 0), ((y ? Math.fround(y) : (y | 0)) | 0)) | 0), Math.atan2(Math.fround((Math.log(-(2**53-2)) >>> 0)), Math.fround(( - Math.sinh(y))))), (Math.tan((x >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [0x0ffffffff, -0, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), 0x080000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000001, -1/0, 1, 1/0, 0, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 42, 0/0, Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, -0x07fffffff, 2**53, 1.7976931348623157e308, -0x100000000, -0x080000000, 2**53+2, -(2**53), -0x100000001, -(2**53+2), 0.000000000000001, -0x0ffffffff, 0x07fffffff, 0x100000000]); ");
/*fuzzSeed-246262462*/count=906; tryItOut("f1.valueOf = (function() { a2 = []; return b2; });");
/*fuzzSeed-246262462*/count=907; tryItOut("e1.add(p2);");
/*fuzzSeed-246262462*/count=908; tryItOut("Array.prototype.reverse.apply(a1, [o2, b2]);");
/*fuzzSeed-246262462*/count=909; tryItOut("/*infloop*/ for  each(let window in (makeFinalizeObserver('tenured'))) print(this.__defineGetter__(\"x\", new Function));");
/*fuzzSeed-246262462*/count=910; tryItOut("mathy5 = (function(x, y) { return (mathy0(((( + (((Number.MAX_VALUE >>> 0) === (y >>> 0)) >>> 0)) !== ((( ! (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) | 0)) | 0), Math.fround(mathy0(Math.fround(Math.atan2(( + mathy2(( + ( + Math.atan2(( + -Number.MAX_SAFE_INTEGER), ( + x)))), (Math.hypot(y, y) >>> 0))), (Math.hypot((( ~ y) | 0), (Math.trunc(Math.fround(mathy3(((0x080000001 >>> 0) ? x : y), x))) | 0)) | 0))), Math.fround((Math.min((Math.fround(Math.exp((Math.sinh((y | 0)) | 0))) >>> 0), ((Math.trunc((y | 0)) | 0) >>> 0)) >>> 0))))) >>> 0); }); testMathyFunction(mathy5, [-1/0, Number.MAX_VALUE, -0x100000000, -(2**53), 42, Math.PI, 0, -Number.MAX_VALUE, 0x080000001, 0x100000000, -0x080000001, -(2**53+2), 2**53+2, 1/0, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, 1, 0/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000, 1.7976931348623157e308, 0.000000000000001, Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, -0, -0x0ffffffff, 2**53, -0x100000001]); ");
/*fuzzSeed-246262462*/count=911; tryItOut("\"use asm\"; Array.prototype.reverse.call(a0, g2, g2);");
/*fuzzSeed-246262462*/count=912; tryItOut("var e = x, window, z;t2 + g2.s0;");
/*fuzzSeed-246262462*/count=913; tryItOut("\"use strict\"; g0.offThreadCompileScript(\";\", ({ global: o1.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 5 == 4), catchTermination: false }));");
/*fuzzSeed-246262462*/count=914; tryItOut("for(var c in x) {v0 = evalcx(\"o2 = {};\", g2);g0 + ''\n }");
/*fuzzSeed-246262462*/count=915; tryItOut("\"use asm\"; const x = false | window, arguments = (w\n).__defineSetter__(\"window\", eval), dodjqz, x, x = (x = w), x = window, b, fuspfm, sjwatj, lonnqa;/*RXUB*/var r = r0; var s = s1; print(s.search(r)); function b(\u3056, NaN =  /x/g , y, a, eval, d, a, y, e, NaN, x = 9, b, x, x, NaN, x = new RegExp(\"(?=\\\\x4F){3,7}|(?![^])\", \"gyim\"), x, x, a, x) { yield arguments } g2.a2 = [];");
/*fuzzSeed-246262462*/count=916; tryItOut("try { let(e) ((function(){x.fileName;})()); } catch(d if x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(a || ({ set NaN x ({}, ...x)\"use asm\";   var abs = stdlib.Math.abs;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (i0);\n    }\n    d1 = (+(0xa261cecd));\n    {\n      i0 = (1);\n    }\n    d1 = (+abs((((((({} = (4277))) - ((d1)))) - ((16777217.0))))));\n    (Int32ArrayView[2]) = ((0x20ec5978)+(0xffffffff));\n    {\n      (Float32ArrayView[1]) = ((262143.0));\n    }\n    return +((-3.777893186295716e+22));\n  }\n  return f; })), function shapeyConstructor(roojqd){{ Array.prototype.unshift.apply(a1, [a2, h0, m2, g2, (makeFinalizeObserver('nursery')), t2, p1]); } roojqd[\"log10\"] =  \"use strict\" ;if (roojqd) Object.seal(roojqd);if (roojqd) { yvlvlc(x);/*hhh*/function yvlvlc(w = -24){print((x = new RegExp(\"[^]\", \"y\")) > (void options('strict')));} } return roojqd; }, Float32Array)) { with({}) { for(let c of /*PTHR*/(function() { for (var i of (function() { \"use strict\"; yield (Math.sign(-11)); } })()) { yield i; } })()) let(a) { return (print(a));} }  } throw StopIteration;");
/*fuzzSeed-246262462*/count=917; tryItOut("mathy4 = (function(x, y) { return ( + Math.sinh(( + (( ~ Math.fround(( + Math.hypot(( + ( + (( + Math.atan(x)) ^ ( + ( ! y))))), (Math.atan2(Math.fround(x), Math.fround(( ! x))) >>> 0))))) >>> 0)))); }); ");
/*fuzzSeed-246262462*/count=918; tryItOut("Array.prototype.splice.call(g2.o0.a1, NaN, ([, {eval: {y: {x: eval}, x: {x}, e: {}, b: {x: x, x}}, ((4277) ===  /x/ ): [{}, {c: {this, w}, x: [], this}, ], x: [, \u0009[]], window: [, ]}, ]) = this.zzz.zzz = (4277));");
/*fuzzSeed-246262462*/count=919; tryItOut("s0 += s1;");
/*fuzzSeed-246262462*/count=920; tryItOut("v0 = (b0 instanceof o1.e0);");
/*fuzzSeed-246262462*/count=921; tryItOut("v0 = o2.g0.runOffThreadScript();");
/*fuzzSeed-246262462*/count=922; tryItOut("f2(s0);");
/*fuzzSeed-246262462*/count=923; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Uint8ArrayView[((0x956e9f7a)) >> 0]) = ((i0));\n    switch ((0x40938ec3)) {\n      case -3:\n        i0 = (i0);\n        break;\n      default:\n        i0 = ((~~(-((+abs(((((Float64ArrayView[0])) + (-1.0625)))))))) == (~~(1099511627775.0)));\n    }\n    i1 = (/*FFI*/ff(((((Float64ArrayView[((!(i1))-((((0x56a56c62)*0x915e0)|0))+(/*FFI*/ff()|0)) >> 3])) / ((6.189700196426902e+26)))), ((((new (WeakMap)(\"\\u9BCC\" <= window, false)) >>>= /(?!\\W){4}$/ym) >> ((i1)+(i0)+(0xccc3d033)))), ((((((/*FFI*/ff(((-70368744177665.0)), ((+abs(((-1.015625))))))|0)+(i0))|0) % (abs((0x7fffffff))|0)))), ((((i0)+(i1)) >> (((0x16d0ae73))-((0x9ca20e76) == (0xe43eca06))))), ((abs((~(((((0x5bea37a))>>>((-0x56e739f))) <= (0x98e103d5)))))|0)), ((~~(-33.0))), ((-4.835703278458517e+24)))|0);\n    i1 = (i0);\n    switch ((((0x9c307c4c) / (0x24b19c03)) << ((0x1ca3f4ef) / (0xd60960b)))) {\n      case 0:\n        i1 = (i0);\n        break;\n    }\n    {\n      {\n        {\n          return (((/*FFI*/ff()|0)))|0;\n        }\n      }\n    }\n    i0 = (i0);\n    {\n      return (((-0x8000000)+(/*FFI*/ff(((~~(((+(((0xf6d48292)+(0x93f07c11))>>>((0x148ad392)+(0x58ef6110)-(0xb3e9a008))))) % ((-6.189700196426902e+26))))), ((((0x1fbd2727)+(((null)))) | ((i1)))), (((i1) ? (36028797018963970.0) : (+abs(((1.0078125)))))))|0)+(0xa5d9579c)))|0;\n    }\n    {\n      i0 = (i0);\n    }\n    i0 = (i1);\n    (Float64ArrayView[((0x296355bc) % ((((+(0.0/0.0)))))) >> 3]) = ((-2147483647.0));\n    i1 = (!((i0) ? (i0) : (i0)));\n    {\n      switch ((0x6a967222)) {\n        case 1:\n          (Float32ArrayView[2]) = ((((i0))));\n          break;\n        case 1:\n          i0 = (!(i0));\n        case 1:\n          {\n            i0 = ((i1) ? (i0) : (i1));\n          }\n        default:\n          i1 = (-0x8000000);\n      }\n    }\n    i1 = (i0);\n    i1 = (i1);\n    return (((((((Int8ArrayView[((i0)) >> 0])) >> ((i1)))) ? (/*FFI*/ff(((7.737125245533627e+25)), ((-268435456.0)), ((144115188075855870.0)))|0) : (i0))-((abs((~~((i1) ? (+pow(((+abs(((-65535.0))))), ((+atan2(((-16385.0)), ((4.835703278458517e+24))))))) : (3.8685626227668134e+25))))|0))))|0;\n    i1 = ((144115188075855870.0) <= (+((Int16ArrayView[1]))));\n    i1 = (i1);\n    return ((((0xffffffff) > (((-0x5069f4c))>>>(((0x314dc2cf))+(i1))))))|0;\n  }\n  return f; })(this, {ff: eval(\"a0.splice(-7, 16, i1);\", (4277))}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 2**53, 0x080000000, -0x100000000, -0, -0x080000000, -(2**53+2), 1, -(2**53-2), -Number.MIN_VALUE, 42, 0x100000001, Math.PI, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, 2**53+2, 0x0ffffffff, 0, 2**53-2, 0x080000001, 1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x07fffffff, -0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-246262462*/count=924; tryItOut("\"use strict\"; \"use asm\"; t1 = new Int8Array(o1.b0, 0, ({valueOf: function() { v2 = (s2 instanceof i2);return 9; }}));\nv1 = Object.prototype.isPrototypeOf.call(t0, h0);\n");
/*fuzzSeed-246262462*/count=925; tryItOut("/*vLoop*/for (kkckeb = 0, 'fafafa'.replace(/a/g, Math.log); kkckeb < 11; ++kkckeb) { var a = kkckeb; with((eval(\"\\\"use strict\\\"; mathy5 = (function(x, y) { return Math.cosh(Math.fround(Math.min(Math.fround(((( + (( + Math.trunc((x >= 1))) && ( + Math.fround(Math.sign(Math.fround(x)))))) << (( ~ ((y ? ( + ( ! (Number.MIN_VALUE >>> 0))) : ( + ( + 0))) >>> 0)) >>> 0)) | 0)), Math.fround(( + Math.max(( + -Number.MIN_VALUE), ( + (( ~ ((Math.fround(Math.fround(Math.max(y, Math.fround(x)))) << ( + Math.max(( + -Number.MAX_SAFE_INTEGER), ( + y)))) >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy5, [2**53+2, -Number.MAX_VALUE, 2**53, -0x07fffffff, 1, 1.7976931348623157e308, 0x100000001, -0, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -0x080000001, 0, 0x080000001, Number.MIN_VALUE, 0/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x080000000, Number.MAX_VALUE, -1/0, 2**53-2, -(2**53-2), 0.000000000000001, Math.PI, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, 0x100000000, -0x100000001]); \"))){o0.o1 = {}\n\u000d/*RXUB*/var r = /\\3{2,}/gim; var s = \"aa\"; print(uneval(r.exec(s))); print(r.lastIndex);  } } ");
/*fuzzSeed-246262462*/count=926; tryItOut("for (var v of g1.m2) { try { x = a0; } catch(e0) { } try { v0 = this.t1.length; } catch(e1) { } try { o0.v2 = new Number(Infinity); } catch(e2) { } s2 += 'x'; }");
/*fuzzSeed-246262462*/count=927; tryItOut("print(x);");
/*fuzzSeed-246262462*/count=928; tryItOut("\"use strict\"; a0 = new Array;");
/*fuzzSeed-246262462*/count=929; tryItOut("( '' );function eval(c) { yield  /x/g  } print(x);");
/*fuzzSeed-246262462*/count=930; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x080000001, 0x080000000, 2**53, -(2**53), -(2**53+2), 0x100000001, 2**53-2, -0x080000000, 42, -0, 0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 1/0, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, 0/0, -1/0, 0x100000000, 1, 0, -0x100000000, -0x07fffffff, -0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, 2**53+2]); ");
/*fuzzSeed-246262462*/count=931; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.fround(Math.atanh(Math.fround(mathy0((y | 0), (Math.fround(y) | 0)))))); }); testMathyFunction(mathy2, [null, false, true, '0', (new Number(-0)), objectEmulatingUndefined(), (function(){return 0;}), (new Number(0)), [], -0, (new Boolean(true)), '', 0.1, '/0/', ({toString:function(){return '0';}}), undefined, ({valueOf:function(){return '0';}}), 0, (new Boolean(false)), /0/, NaN, (new String('')), 1, ({valueOf:function(){return 0;}}), [0], '\\0']); ");
/*fuzzSeed-246262462*/count=932; tryItOut("mathy5 = (function(x, y) { return ( + Math.hypot(( + (Math.fround((((Math.atan2(Math.fround(x), (( - Math.sin(y)) | 0)) | 0) >>> 0) !== y)) >> (( + (( + Math.hypot(y, x)) * ( + Math.fround(Math.imul(Math.fround(( ! y)), Math.fround((Math.atanh((1.7976931348623157e308 >>> 0)) >>> 0))))))) ? ( + Math.fround(( ! -0x07fffffff))) : (y % ( + Math.ceil(( + (y ^ Math.PI)))))))), ( + (x || (Math.fround((Math.fround(Math.fround(( - Math.fround(x)))) | Math.fround(Math.acosh(y)))) >>> 0))))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, Number.MIN_VALUE, 0/0, -0x0ffffffff, -1/0, -(2**53), 1/0, 0x100000000, 2**53, -0x100000001, 1.7976931348623157e308, 0.000000000000001, 0x080000001, -0x080000001, 0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, -(2**53-2), 2**53+2, -0x080000000, 42, Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, 1]); ");
/*fuzzSeed-246262462*/count=933; tryItOut("let (y) { /*infloop*/M: for  each(var NaN(({a1:1})) in x = null) print(x); }");
/*fuzzSeed-246262462*/count=934; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.imul(( + Math.trunc(((Math.imul(((Math.max(Math.fround(0x100000001), (x >>> 0)) >>> 0) | 0), y) >>> 0) | 0))), (Math.imul(x, Math.sin(Math.acos(x))) | 0))); }); ");
/*fuzzSeed-246262462*/count=935; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (/(?=(?=\\b$|(?=\\D))|..{2,}[^]{2}+?{2,5})/gm &= /(\\r{2})*?/gy) ? y = Proxy.create(({/*TOODEEP*/})( /x/g ), new RegExp(\"^|.|(\\\\cC)*((?!(\\\\n)*?))|.|\\\\x31|\\\\b\\\\B|\\\\S|\\\\1[\\\\d\\\\v\\\\W]-\\\\\\uab27]*?(?![\\\\D\\\\D])+|[^]|(\\\\b){0,}\", \"gy\")) : /*FARR*/[ /x/g , ...[]].filter(Boolean.prototype.valueOf); }); testMathyFunction(mathy3, [-0x07fffffff, -0x080000000, 0, 0x080000000, Number.MIN_SAFE_INTEGER, 0/0, 2**53, -(2**53-2), -0x0ffffffff, 2**53+2, Number.MAX_VALUE, -1/0, -0x100000000, -0, -(2**53+2), 1/0, -Number.MIN_VALUE, 0x100000001, 0x07fffffff, -0x100000001, 1, 0x100000000, 0.000000000000001, 42, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 1.7976931348623157e308, Number.MIN_VALUE, 0x080000001, 2**53-2, -0x080000001, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=936; tryItOut("testMathyFunction(mathy3, [Number.MIN_VALUE, 1/0, -0x07fffffff, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -0x100000000, 1.7976931348623157e308, -0x080000001, -(2**53-2), 0x100000001, -1/0, -0x100000001, 1, -Number.MIN_VALUE, 0, 2**53+2, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, 2**53-2, 42, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, -Number.MAX_VALUE, -0, 0x07fffffff]); ");
/*fuzzSeed-246262462*/count=937; tryItOut("/*vLoop*/for (var qyekzb = 0, (Proxy).call({} === window, ); qyekzb < 57; ++qyekzb) { let a = qyekzb; allocationMarker(); } ");
/*fuzzSeed-246262462*/count=938; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.hypot(Math.acosh(mathy2(( ! Math.fround(0x0ffffffff)), ( - (x | 0)))), (Math.log10(y) == ( + ( - ( + 0x080000001)))))); }); testMathyFunction(mathy3, [-(2**53+2), -0x080000001, -0x100000000, 1/0, -(2**53-2), -Number.MAX_VALUE, 0x080000000, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, 0x100000001, 1.7976931348623157e308, -0x07fffffff, 0x080000001, 2**53, 0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, 1, 42, 2**53-2, 0/0, Number.MAX_VALUE, Number.MIN_VALUE, -0, 2**53+2, -1/0, Math.PI, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-246262462*/count=939; tryItOut("s0 = a2;");
/*fuzzSeed-246262462*/count=940; tryItOut("var dznecz = new ArrayBuffer(2); var dznecz_0 = new Uint8Array(dznecz); dznecz_0[0] = -0; var dznecz_1 = new Uint8ClampedArray(dznecz); print(dznecz_1[0]); dznecz_1[0] = -1; var dznecz_2 = new Int8Array(dznecz); dznecz_2[0] = 15; Array.prototype.unshift.call(a1, t0, t1, o1, this.g1);window;v1 = (o0.v1 instanceof g1.o1);");
/*fuzzSeed-246262462*/count=941; tryItOut("\"use asm\"; v1 = (e1 instanceof o2);");
/*fuzzSeed-246262462*/count=942; tryItOut("print((yield /\\b*?|[\\x32-\\u0057\u00b1-\\xB3\\uc235-\\u0018]$|[^]\\b.?\ue0b0$*?*\\3/ym <<= /*MARR*/[objectEmulatingUndefined(), 2**53, new Number(1.5), undefined, new Number(1.5),  /x/ , new Number(1.5), undefined, objectEmulatingUndefined(), new Number(1.5), 2**53, new Number(1.5), objectEmulatingUndefined(), undefined, 2**53, undefined,  /x/ , objectEmulatingUndefined(),  /x/ , undefined,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), 2**53, objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), undefined, new Number(1.5), new Number(1.5), undefined, undefined,  /x/ , new Number(1.5), objectEmulatingUndefined(), 2**53, undefined, 2**53, 2**53, new Number(1.5), 2**53, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), undefined, objectEmulatingUndefined(), objectEmulatingUndefined(), 2**53, new Number(1.5), 2**53, new Number(1.5),  /x/ ,  /x/ , undefined, 2**53, new Number(1.5),  /x/ , new Number(1.5), objectEmulatingUndefined(), new Number(1.5), 2**53, undefined, undefined, objectEmulatingUndefined(),  /x/ , new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), 2**53, undefined,  /x/ , new Number(1.5), objectEmulatingUndefined(), 2**53, 2**53, new Number(1.5),  /x/ , new Number(1.5), 2**53, new Number(1.5), undefined, new Number(1.5), new Number(1.5),  /x/ , 2**53, undefined, objectEmulatingUndefined(), undefined,  /x/ , 2**53, new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, undefined, 2**53,  /x/ , new Number(1.5),  /x/ ,  /x/ ,  /x/ , undefined, 2**53, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , undefined, objectEmulatingUndefined(),  /x/ , undefined, new Number(1.5), undefined, new Number(1.5),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5),  /x/ , 2**53, 2**53,  /x/ , objectEmulatingUndefined(), 2**53,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5),  /x/ , new Number(1.5), undefined, undefined, objectEmulatingUndefined()].map));");
/*fuzzSeed-246262462*/count=943; tryItOut("testMathyFunction(mathy1, [0x080000001, -0x07fffffff, 0x100000001, 0x07fffffff, Number.MAX_VALUE, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, -Number.MAX_VALUE, 0/0, 1.7976931348623157e308, 1, -0, 42, 0, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53+2), -0x080000000, -1/0, 0.000000000000001, -Number.MIN_VALUE, -0x080000001, 2**53+2, -(2**53), -0x0ffffffff, 2**53-2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=944; tryItOut("mathy4 = (function(x, y) { return ( + Math.acosh(( + Math.sign((mathy1((Math.pow((Math.clz32(( + ( + (( + x) & Math.fround(x))))) >>> 0), (Math.fround(((x >>> 0) === (x >>> 0))) >>> 0)) >>> 0), ((( + Math.trunc(( + x))) ? -1/0 : (x | 0)) * -0x07fffffff)) >>> 0))))); }); testMathyFunction(mathy4, [Number.MAX_VALUE, -(2**53+2), -1/0, 0.000000000000001, -0, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -0x100000000, 1, Math.PI, 0x080000000, -0x07fffffff, 0x100000001, 1/0, 2**53, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, 2**53+2, 0x07fffffff, 0x0ffffffff, -0x100000001, Number.MIN_VALUE, 2**53-2, -(2**53), 0, 0x100000000, 0/0]); ");
/*fuzzSeed-246262462*/count=945; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.min((Math.asin(Math.fround(Math.imul(Math.fround(mathy1((mathy1((y >>> 0), (((x || 1/0) | 0) >>> 0)) >>> 0), ( + Math.log2(( + x))))), ( ~ (Math.atan2(0, y) >>> 0))))) >>> 0), ((mathy0((((y ? ( + x) : ((y | (y >>> 0)) >>> 0)) >>> 0) >>> 0), x) * (mathy0(((Math.expm1(((mathy1((x | 0), -(2**53+2)) | 0) | 0)) | 0) >>> 0), (x >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [1/0, 2**53, Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -0, 0x080000001, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, 0x100000000, 42, -(2**53-2), 1.7976931348623157e308, 0x0ffffffff, -0x080000000, 0x080000000, 0, 0/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, -1/0, 1]); ");
/*fuzzSeed-246262462*/count=946; tryItOut("print(Math.abs(this));");
/*fuzzSeed-246262462*/count=947; tryItOut("\"use strict\"; /*bLoop*/for (let idnqwv = 0; idnqwv < 7 && ((new (( /x/  < \"\\u93BC\"))(yield \n\"\\u0204\"))); ++idnqwv) { if (idnqwv % 10 == 1) { print(x); } else { /*vLoop*/for (var nkspht = 0; nkspht < 21; ++nkspht) { let d = nkspht; print(uneval(i0)); }  }  } ");
/*fuzzSeed-246262462*/count=948; tryItOut("for (var v of t0) { try { for (var p in g0.a1) { try { e1.delete(a2); } catch(e0) { } try { v1 = Array.prototype.reduce, reduceRight.apply(a0, [(function mcc_() { var hysxjo = 0; return function() { ++hysxjo; if (/*ICCD*/hysxjo % 3 == 1) { dumpln('hit!'); x = o0.o1.a2; } else { dumpln('miss!'); try { v2 = g0.eval(\"v0 = (b2 instanceof h2);\"); } catch(e0) { } try { print(eval); } catch(e1) { } try { this.i2.valueOf = (function() { try { (void schedulegc(g0)); } catch(e0) { } /*MXX2*/g2.Array.length = this.h2; return b1; }); } catch(e2) { } v0 = (b1 instanceof f2); } };})()]); } catch(e1) { } t0[({valueOf: function() { s2 += 'x';return 0; }})] = g0; } } catch(e0) { } try { this.o1.v0 = (m2 instanceof a2); } catch(e1) { } try { let v0 = t1.byteLength; } catch(e2) { } v2 = (f1 instanceof e0); }\nprint((/*MARR*/[eval, new Boolean(false), eval, eval, new Boolean(false), new Boolean(false), new Boolean(false), eval, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), eval, new Boolean(false), eval, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), eval, new Boolean(false), new Boolean(false), eval, new Boolean(false), new Boolean(false), new Boolean(false), eval, new Boolean(false), new Boolean(false), eval, new Boolean(false), new Boolean(false), eval, eval, eval, eval, eval].sort));\n");
/*fuzzSeed-246262462*/count=949; tryItOut("\"use strict\"; ");
/*fuzzSeed-246262462*/count=950; tryItOut("b1 + g0;");
/*fuzzSeed-246262462*/count=951; tryItOut("\"use strict\"; t2 + '';");
/*fuzzSeed-246262462*/count=952; tryItOut("\"use strict\"; let (e) { g2.v0 = this.t1[14]; }");
/*fuzzSeed-246262462*/count=953; tryItOut("a0 = Array.prototype.filter.call(a0, (function() { try { t2[yield ((true)(\"\\uF77C\"))]; } catch(e0) { } try { for (var p in this.g2) { try { h2 + a0; } catch(e0) { } try { g1.v2 = g1.runOffThreadScript(); } catch(e1) { } try { o0.m2 = new Map; } catch(e2) { } i1 = new Iterator(h1, true); } } catch(e1) { } try { f2(a1); } catch(e2) { } m0.delete(b1); return o1.b0; }), i2);");
/*fuzzSeed-246262462*/count=954; tryItOut("while(((this.__defineSetter__(\"z\",  /x/g ))) && 0)this.e1.add(a0);");
/*fuzzSeed-246262462*/count=955; tryItOut("\"use strict\"; /*iii*/print(\u3056 = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: Date.prototype.getDay, delete: function(name) { return delete x[name]; }, fix: function(y) { return ({a2:z2}) }, has:  '' , hasOwn: undefined, get: Object.prototype.valueOf, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: (new Function(\"arguments;\")), keys: function() { throw 3; }, }; })( /x/g ), Function));/*hhh*/function lcyitv(y = x /= e, ...\"\u03a0\"){p2 + o0;}");
/*fuzzSeed-246262462*/count=956; tryItOut("\"use strict\"; let (y) { ;\u0009 }");
/*fuzzSeed-246262462*/count=957; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + (( + Math.atan2(Math.fround(( + (y >= ( + y)))), ( + ( + (x | 0))))) % ( + ((Math.fround((Math.log2((( ~ Math.sqrt((y | 0))) | 0)) | 0)) ** Math.fround(Math.atan2(( + ( + ( + (( + -0x080000001) , Math.fround((( ! (x | 0)) | 0)))))), Math.fround(Math.atan2(( + (( + (Math.pow(x, Math.fround(y)) === (-0x100000000 ^ y))) , 0x100000001)), (Math.acosh(y) != (y >>> 0))))))) >>> 0)))); }); testMathyFunction(mathy1, [Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, 0.000000000000001, 0x100000001, -(2**53), 2**53-2, -0x0ffffffff, 0/0, 0x0ffffffff, 0x100000000, -0x080000001, -0x100000001, 0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, 1, -0, 0x080000000, -(2**53-2), -Number.MAX_VALUE, -(2**53+2), -0x100000000, -1/0, -0x080000000, 1/0, 2**53]); ");
/*fuzzSeed-246262462*/count=958; tryItOut("s0 += 'x';");
/*fuzzSeed-246262462*/count=959; tryItOut("g1.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-246262462*/count=960; tryItOut("testMathyFunction(mathy5, [-1/0, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, 1, 0x100000000, -(2**53-2), -0x07fffffff, -0, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, -(2**53), 0.000000000000001, 0/0, -0x100000001, 2**53, 0x0ffffffff, 42, -(2**53+2), 0, 1.7976931348623157e308, -0x100000000, 1/0, Math.PI, 0x07fffffff, 2**53+2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-246262462*/count=961; tryItOut("\"use strict\"; var rgfwmo = new ArrayBuffer(4); var rgfwmo_0 = new Uint32Array(rgfwmo); rgfwmo_0[0] = -10; var rgfwmo_1 = new Uint32Array(rgfwmo); rgfwmo_1[0] = 4; DateArray.prototype.push.call(a0, t1);( /x/g );[,,];print(function(id) { return id });");
/*fuzzSeed-246262462*/count=962; tryItOut("\"use strict\"; this.v0 = t2.byteLength;");
/*fuzzSeed-246262462*/count=963; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"s1 += s0;\", ({ global: g1.o1.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: ((void options('strict'))), noScriptRval: (this.__defineSetter__(\"x\", d =>  { \"use strict\"; g1.offThreadCompileScript(\"x = f2;\"); } )), sourceIsLazy: true, catchTermination: (x % 105 == 17) }));");
/*fuzzSeed-246262462*/count=964; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[objectEmulatingUndefined(), -0x5a827999, new Number(1), function(){}, function(){}, new String(''), function(){}, function(){}, objectEmulatingUndefined(), new String(''), -0x5a827999, objectEmulatingUndefined(), -0x5a827999, new String(''), new Number(1), function(){}, new String(''), new Number(1), function(){}, -0x5a827999, function(){}, function(){}, function(){}, function(){}, -0x5a827999, function(){}, new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, new String(''), function(){}, new Number(1), -0x5a827999, -0x5a827999, function(){}, -0x5a827999, new String(''), new String(''), function(){}, objectEmulatingUndefined(), new Number(1), new Number(1), -0x5a827999, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), new String(''), objectEmulatingUndefined(), -0x5a827999, function(){}, objectEmulatingUndefined(), function(){}, new Number(1), -0x5a827999, new Number(1), -0x5a827999, objectEmulatingUndefined(), function(){}, new Number(1)]) { v2 = Object.prototype.isPrototypeOf.call(p2, g1);\nprint(d);\n }");
/*fuzzSeed-246262462*/count=965; tryItOut(";");
/*fuzzSeed-246262462*/count=966; tryItOut("/*RXUB*/var r = /[^\\\u0005\uc702\\0]/ym; var s = \"\\u2b74\"; print(s.search(r)); ");
/*fuzzSeed-246262462*/count=967; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (mathy3((( ! ( + (y && ( + ((Math.asin((y >>> 0)) >>> 0) / Math.fround((x & (Math.hypot(x, ( ~ y)) >>> 0)))))))) >>> 0), (mathy4(Math.fround((( - (Math.atan(Math.PI) | 0)) | 0)), ((x ** (Math.fround((Math.fround((Math.atan2((-0x100000001 | 0), ((mathy4((x | 0), (y | 0)) | 0) | 0)) | 0)) * Math.fround(Math.imul((y | 0), y)))) >>> (y >>> 0))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-(2**53), -0x100000001, Number.MIN_VALUE, 0, 1.7976931348623157e308, 2**53-2, 1, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 2**53+2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, 0/0, 0x0ffffffff, -0x0ffffffff, -0x07fffffff, 0x080000001, -0x080000001, 0x100000000, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), -0x080000000, -Number.MAX_VALUE, -0, 2**53, 0x100000001, 0x080000000, 1/0, Math.PI, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=968; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround((((mathy0(Math.fround((Math.max(y, y) == Math.atan2(x, y))), ((y >>> 0) ? y : (( + ( - x)) >> Math.expm1(y)))) | 0) ** ( + (( + (( + y) < ( + (y ^ y)))) ** Math.tanh((Math.fround(mathy3(x, Math.pow(-Number.MAX_SAFE_INTEGER, -(2**53-2)))) + (Math.tanh((y >>> 0)) >>> 0)))))) | 0)); }); testMathyFunction(mathy4, [false, objectEmulatingUndefined(), '/0/', (function(){return 0;}), (new String('')), '0', ({valueOf:function(){return '0';}}), -0, [0], true, 0, 0.1, (new Boolean(true)), 1, '', (new Boolean(false)), '\\0', undefined, [], ({toString:function(){return '0';}}), (new Number(-0)), NaN, /0/, (new Number(0)), ({valueOf:function(){return 0;}}), null]); ");
/*fuzzSeed-246262462*/count=969; tryItOut(" for  each(w in (4277)) {(true);o2.m2.has(p2); }\nfunction shapeyConstructor(bkfcxi){\"use strict\"; for (var ytqkndfhw in this) { }if (/./im) this[\"caller\"] =  /x/ ;Object.defineProperty(this, \"isInteger\", ({set: 8}));Object.defineProperty(this, \"toLocaleDateString\", ({value: /(?:.|[^Ns-\\cC-5\u001f-\u0099]+?|[^\\f=-\u00d2\u0019]|\u0001|\\B|(?:[\\x39\\r-\\u00AA\\wH-\\u5d3f])|\\B[\\n-\\cN]|(?=(?=.))*)/, writable: false, enumerable: false}));{ Array.prototype.reverse.call(a2); } if ( /x/ ) Object.defineProperty(this, \"prototype\", ({value: -29, writable: (bkfcxi % 5 == 3)}));this[\"isInteger\"] = this;return this; }/*tLoopC*/for (let a of window) { try{let bionvn = new shapeyConstructor(a); print('EETT'); print(uneval(o2.f0));}catch(e){print('TTEE ' + e); } }\n");
/*fuzzSeed-246262462*/count=970; tryItOut("f2 + '';");
/*fuzzSeed-246262462*/count=971; tryItOut("\"use strict\"; g0.o2 = {};");
/*fuzzSeed-246262462*/count=972; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.sign(( + (Math.sin(( + Math.hypot(Math.PI, x))) < Math.fround(( - x))))) ? (Math.fround((Math.atan2(mathy0((Math.max(Math.pow(y, y), (( + mathy0(( + y), ( + x))) >>> 0)) >>> 0), Number.MAX_VALUE), ((( - (-0x07fffffff | 0)) | 0) ? (Math.cosh((Math.pow(x, mathy0(( + x), Number.MAX_VALUE)) | 0)) | 0) : ( + Math.min((Math.imul(y, -(2**53+2)) | 0), x)))) >>> 0)) >>> 0) : ( ! Math.log2(Math.fround(( ! (((( + mathy2(x, -Number.MAX_SAFE_INTEGER)) <= Math.fround(Math.PI)) ? (0/0 | 0) : 1) | 0)))))); }); testMathyFunction(mathy3, [({toString:function(){return '0';}}), [], false, 0.1, -0, (new Number(-0)), (new Number(0)), (function(){return 0;}), objectEmulatingUndefined(), true, [0], /0/, null, (new String('')), '', 1, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '\\0', NaN, 0, '0', (new Boolean(false)), '/0/', undefined, (new Boolean(true))]); ");
/*fuzzSeed-246262462*/count=973; tryItOut("");
/*fuzzSeed-246262462*/count=974; tryItOut("v2 = t2.length;");
/*fuzzSeed-246262462*/count=975; tryItOut("\"use strict\"; print(s1);");
/*fuzzSeed-246262462*/count=976; tryItOut("o2 + o0;");
/*fuzzSeed-246262462*/count=977; tryItOut("Array.prototype.splice.call(a2, NaN, 2);");
/*fuzzSeed-246262462*/count=978; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    return +((+/*FFI*/ff(((-((+(((i1)) << (((((0xed031260))>>>((0xc0f1a948))) < (((0xffffffff))>>>((0xfb35eb4e))))+(i1))))))))));\n  }\n  return f; })(this, {ff: (new Function(\";\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000001, 2**53, -0, 2**53+2, 0, -1/0, 0x100000000, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, 0x07fffffff, -0x100000001, 1/0, -0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, -(2**53+2), 0/0, 0.000000000000001, -0x080000000, 2**53-2, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -0x080000001]); ");
/*fuzzSeed-246262462*/count=979; tryItOut("testMathyFunction(mathy5, [Math.PI, -Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0, 0x100000000, 1, 0x080000000, Number.MIN_VALUE, 0x0ffffffff, 0x080000001, 2**53-2, 0, 0/0, -Number.MIN_VALUE, 2**53, -(2**53), 1/0, -0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, 42, -0x100000000, 2**53+2, 0x100000001, -Number.MAX_VALUE, -(2**53+2), -0x080000000, 1.7976931348623157e308, -0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=980; tryItOut("\"use strict\"; /*oLoop*/for (let ppiddu = 0, zqputh; ppiddu < 24; ++ppiddu, ({window: \u3056} = Math.min(-15, 26))) { print((4277)); } ");
/*fuzzSeed-246262462*/count=981; tryItOut("");
/*fuzzSeed-246262462*/count=982; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.ceil(Math.ceil(( ~ ( + ( ! ( + y)))))); }); testMathyFunction(mathy5, [Math.PI, 0x100000000, 0x080000000, 0, 2**53, 1.7976931348623157e308, 42, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -Number.MAX_VALUE, -0x080000000, -0x100000001, 2**53-2, 1, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, -0x100000000, -(2**53+2), -(2**53), -Number.MIN_VALUE, Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, 0/0, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 0x07fffffff, -0x080000001, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-246262462*/count=983; tryItOut("\"use strict\"; M:while((new ('fafafa'.replace(/a/g, eval) << (void options('strict')))()) && 0){/* no regression tests found */ }");
/*fuzzSeed-246262462*/count=984; tryItOut("\"use strict\"; v1 = this.b0.byteLength;");
/*fuzzSeed-246262462*/count=985; tryItOut("a0 = Array.prototype.map.apply(a0, [(function() { for (var j=0;j<76;++j) { g1.o1.f0(j%2==1); } })]);");
/*fuzzSeed-246262462*/count=986; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((( + mathy0(((((Math.exp(Math.fround(Math.abs(x))) >>> 0) >>> 0) | ((( ~ ((mathy2(( + y), (x | 0)) | 0) | 0)) >>> 0) >>> 0)) >>> 0), ( ~ ((((Math.imul((y | 0), x) >>> 0) >>> 0) ? (Math.sin(y) >>> 0) : y) >>> 0)))) !== (mathy2(( - Math.fround(Math.imul(( ~ ( + y)), ( ! Math.imul(x, (y | 0)))))), -Number.MAX_SAFE_INTEGER) >>> 0)) & ( + ( ~ (( ~ (Math.max(Math.fround((mathy0(((-Number.MAX_VALUE + (( + (( + y) & x)) >>> 0)) >>> 0), (y | 0)) >>> 0)), Math.fround(((mathy2(y, x) | 0) ? Math.fround((( ~ (y | 0)) | 0)) : Math.fround((y > 0))))) | 0)) >>> 0)))); }); testMathyFunction(mathy3, [-0x100000000, -Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 0x100000000, 1, -0x080000000, -0x080000001, -1/0, 2**53, -0x100000001, -(2**53+2), 0x100000001, 0x07fffffff, Number.MAX_VALUE, 42, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, 2**53+2, -0, 1/0, -0x0ffffffff, 0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 0, 1.7976931348623157e308, -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-246262462*/count=987; tryItOut("mathy2 = (function(x, y) { return ( ~ (((( ! Math.fround((Math.acosh((Math.atan2(x, x) | 0)) | 0))) >>> 0) + (((Math.min(Math.hypot(x, (Math.fround(y) <= x)), (y % ( + Math.fround(Math.imul(Math.fround(y), Math.fround(y)))))) ** (-0x07fffffff | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 0/0, 1.7976931348623157e308, -1/0, 0x080000001, -0x07fffffff, -0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), 2**53+2, 42, -0x0ffffffff, 1/0, -0x080000000, Math.PI, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, -0x100000001, 0, -0x080000001, -(2**53-2), 0x0ffffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 0x100000000, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=988; tryItOut("/*RXUB*/var r = r2; var s = s2; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=989; tryItOut("mathy4 = (function(x, y) { return (Math.acos(((((y >>> 0) && (x >>> 0)) ^ Math.max(Math.fround(y), ( - y))) | 0)) % Math.fround(Math.hypot(Math.fround(Math.pow((x | 0), ( + ((y * x) | 0)))), (x >= mathy0((( ! -1/0) , y), Math.clz32(( + Number.MIN_VALUE))))))); }); ");
/*fuzzSeed-246262462*/count=990; tryItOut("\"use strict\"; a0 = Array.prototype.filter.call(a2, v2);");
/*fuzzSeed-246262462*/count=991; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( ~ (Math.sign(Math.fround(x)) | 0)) , Math.fround(Math.atan2(Math.fround((( - (Math.clz32((y >>> 0)) >>> 0)) ? ( ~ Math.fround(Math.imul(x, x))) : (mathy2((Math.sqrt(x) >>> 0), Number.MAX_VALUE) >= ( + mathy4(( + y), ( + Math.acosh(y))))))), Math.fround(( ! (( ~ Math.fround((Math.fround(x) <= ( + y)))) >>> 0)))))); }); testMathyFunction(mathy5, [0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, 0, -0x100000000, -Number.MAX_VALUE, 2**53+2, 1, -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, -(2**53), -0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -0x07fffffff, 0x080000000, -1/0, -0x100000001, -0x0ffffffff, -(2**53+2), 42, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, 2**53, 0/0, Math.PI, 2**53-2, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=992; tryItOut("mathy0 = (function(x, y) { return (( ! ( + Math.fround(( ~ Math.fround(Math.max((Math.clz32((Math.tanh(( + y)) >>> 0)) >>> 0), 2**53+2)))))) >>> 0); }); testMathyFunction(mathy0, /*MARR*/[{x:3},  'A' ,  'A' , {x:3}, {x:3},  'A' ,  'A' ,  'A' , {x:3}, {x:3},  'A' ,  'A' , {x:3}]); ");
/*fuzzSeed-246262462*/count=993; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s1; print(uneval(s.match(r))); ");
/*fuzzSeed-246262462*/count=994; tryItOut("o0.valueOf = (function() { function f1(i0)  { return true }  return a1; });print(x);");
/*fuzzSeed-246262462*/count=995; tryItOut("{ void 0; try { startgc(416472); } catch(e) { } }");
/*fuzzSeed-246262462*/count=996; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + (( + (Math.min((( + Math.pow((Math.log(x) | 0), Math.fround(Math.trunc(((( ! Math.fround(x)) >>> 0) >>> 0))))) >>> 0), ((mathy2(((( + mathy1((y >>> 0), ( + mathy2(y, x)))) ? (y ? x : ( ~ y)) : (-Number.MAX_SAFE_INTEGER | 0)) >>> 0), (( ! y) >>> 0)) >>> 0) >>> 0)) >>> 0)) * ( + ((((Math.fround(Math.log((Math.log2((Math.imul(Math.fround(y), Math.fround(Math.fround(Math.tan(Math.fround(-0x0ffffffff))))) >>> 0)) >>> 0))) << Math.acosh(0x100000000)) | 0) + ((x && Math.fround(( ! (mathy1(((( ! (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) >>> 0), (x >>> 0)) >>> 0)))) | 0)) | 0)))); }); testMathyFunction(mathy3, /*MARR*/[ '\\0' , 0x3FFFFFFF,  /x/g ,  '\\0' , x, 0x3FFFFFFF,  '\\0' , x, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF,  /x/g , x,  /x/ ,  /x/ ,  /x/ ]); ");
/*fuzzSeed-246262462*/count=997; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (((Math.trunc(Math.hypot(mathy3(Math.fround(Math.trunc(Math.fround(( - -0x080000000)))), Math.log(x)), ( + -0x0ffffffff))) >>> 0) >>> 0) != ((Math.fround((Math.fround(Math.min((x != ( - 2**53-2)), mathy2(Math.fround(mathy3(Math.fround(y), Math.fround(-0x080000001))), 1/0))) !== mathy1(( + (-(2**53-2) <= Math.fround(Math.max(-(2**53+2), (Math.min((0x080000000 | 0), (x | 0)) | 0))))), ( + 42)))) / Math.fround((Math.acosh((Math.fround(Math.min(Math.fround(Math.imul(((x >>> x) | 0), ( - (y >>> 0)))), (Number.MAX_SAFE_INTEGER | 0))) && Math.fround(Math.asinh(y)))) | 0))) >>> 0)); }); testMathyFunction(mathy4, [-(2**53+2), -Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 42, 0x100000001, 0x100000000, 2**53, Number.MAX_VALUE, 0, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53), -1/0, 1.7976931348623157e308, -(2**53-2), -0, 1/0, -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 1, -Number.MIN_VALUE, -0x100000001, 2**53+2, 2**53-2, Number.MIN_VALUE, 0/0, -0x07fffffff, 0x080000001, 0.000000000000001]); ");
/*fuzzSeed-246262462*/count=998; tryItOut("mathy4 = (function(x, y) { return ( ~ Math.asin((x % Math.fround(mathy0(Math.fround(( + ( ! Math.fround(y)))), Math.fround((-(2**53-2) * x))))))); }); testMathyFunction(mathy4, [-0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0, -1/0, 2**53-2, 0/0, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -(2**53), -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 1/0, 0x0ffffffff, 0.000000000000001, -0x100000001, Number.MIN_VALUE, 0x080000001, -0x080000000, 2**53+2, -0x080000001, 1, -0x07fffffff, 42, 0x07fffffff, -(2**53+2), -Number.MAX_VALUE, -(2**53-2), 0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=999; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((Math.fround(Math.log10(Math.tan(Math.fround((Math.min(( + -Number.MIN_SAFE_INTEGER), ( + (( ~ x) && (x >>> 0)))) | 0))))) >>> 0) || Math.trunc((( ! (( + mathy0(( + Math.sin(-Number.MAX_SAFE_INTEGER)), -Number.MIN_VALUE)) * (x >>> 0))) === Math.fround(x)))); }); testMathyFunction(mathy2, [-(2**53-2), Number.MAX_VALUE, -0x080000000, 0, 0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 1/0, 0x080000000, Math.PI, -0, -Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, 0x0ffffffff, 0x100000000, -(2**53+2), 1, -0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, -0x080000001, -1/0, -0x100000000, 2**53, -Number.MAX_VALUE, 0.000000000000001, 0x100000001]); ");
/*fuzzSeed-246262462*/count=1000; tryItOut("/*UUV1*/(eval.toLowerCase = /*wrap3*/(function(){ \"use strict\"; var xcvutg = x >>> x; (mathy1)(); }));");
/*fuzzSeed-246262462*/count=1001; tryItOut("mathy5 = (function(x, y) { return Math.max(Math.tanh((Math.atan(( + Math.log1p(x))) | 0)), Math.cbrt(Math.fround(( + (Math.atan2(Math.fround(( ! Math.fround(-Number.MAX_SAFE_INTEGER))), y) <= ( + ((( + (x ^ x)) !== (-Number.MAX_VALUE | 0)) - x))))))); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), '0', undefined, objectEmulatingUndefined(), (new String('')), '/0/', [], /0/, ({valueOf:function(){return '0';}}), true, 0.1, -0, (function(){return 0;}), ({valueOf:function(){return 0;}}), null, NaN, (new Number(-0)), (new Boolean(false)), false, '', '\\0', [0], 0, (new Number(0)), 1, (new Boolean(true))]); ");
/*fuzzSeed-246262462*/count=1002; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (i0);\n    return +(((65.0) + (+abs(((-((-262145.0))))))));\n  }\n  return f; })(this, {ff: function shapeyConstructor(hvdqle){\"use strict\"; if (hvdqle) this[\"constructor\"] = (this).bind(hvdqle);this[\"constructor\"] = arguments.callee;this[(x++)] = new String('q');this[(x++)] = String.prototype.italics;if (x) for (var ytqsncmof in this) { }{ print(x); } return this; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0.000000000000001, -0x080000001, 1, Math.PI, 0x07fffffff, 0x100000000, 0/0, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 1/0, 0x080000000, -0x100000001, 1.7976931348623157e308, 2**53, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, -1/0, -0x100000000, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, -(2**53), 2**53-2, 42, Number.MAX_VALUE, 0x100000001, 0, Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-246262462*/count=1003; tryItOut("\"use strict\"; let v1 = evaluate(\"h1.iterate = (function mcc_() { var gleqyr = 0; return function() { ++gleqyr; if (/*ICCD*/gleqyr % 7 == 4) { dumpln('hit!'); try { g0.offThreadCompileScript(\\\"function f1(o1.s0) \\\\\\\"use asm\\\\\\\"; s1 += s1;\\\\n  function f(i0, i1)\\\\n  {\\\\n    i0 = i0|0;\\\\n    i1 = i1|0;\\\\n    {\\\\n      {\\\\n        i1 = (i0);\\\\n      }\\\\n    }\\\\n    {\\\\n      {\\\\n        {\\\\n          i0 = (i0);\\\\n        }\\\\n      }\\\\n    }\\\\n    i0 = (i0);\\\\n    return (((i0)))|0;\\\\n  }\\\\n  return f;\\\"); } catch(e0) { } try { s0 += 'x'; } catch(e1) { } try { m0.get(a2); } catch(e2) { } m2[\\\"__count__\\\"] = /*UUV2*/(toSource.getUTCHours = toSource.search); } else { dumpln('miss!'); try { v0 = g2.r2.sticky; } catch(e0) { } try { t0 = new Uint32Array(({valueOf: function() { m1.valueOf = (function() { try { for (var p in e1) { try { p1 + m2; } catch(e0) { } try { for (var v of s1) { o0.v2 = o1.r0.unicode; } } catch(e1) { } Array.prototype.splice.call(a1, NaN, new RegExp(\\\".(?:\\\\\\\\2)?\\\", \\\"i\\\"), h2); } } catch(e0) { } try { Array.prototype.splice.apply(a2, [NaN, 9, g2.m1]); } catch(e1) { } a2.push(m2); throw this.m0; });return 11; }})); } catch(e1) { } try { g1.t1 = t1.subarray(v1); } catch(e2) { } print(uneval(h1)); } };})();\", ({ global: g1.o2.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x, noScriptRval: /*UUV1*/(d.reject = String.prototype.small), sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-246262462*/count=1004; tryItOut("\"use strict\"; /*MXX2*/g2.Promise.prototype.then = h0;");
/*fuzzSeed-246262462*/count=1005; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.cosh((Math.fround(( ~ Math.sin((((Math.pow(x, (y >>> 0)) | 0) ** (( - -0) | 0)) | 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[['z'], (0/0), (0/0), ['z'], (0/0), (void 0), ['z'], (void 0), (0/0), (0/0), (void 0), (0/0), (0/0), (void 0), ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], (0/0), ['z'], (void 0), (void 0), (void 0), (0/0), ['z'], (void 0), (void 0), (void 0), ['z'], (void 0), (0/0), (void 0), (0/0), ['z'], (0/0), ['z'], (0/0), (0/0), ['z'], (void 0), (0/0), ['z'], (void 0), (0/0), (void 0), ['z'], ['z'], ['z'], ['z'], (0/0), ['z'], (void 0), ['z'], (0/0), (0/0), ['z'], (0/0), (void 0), (0/0), ['z'], ['z'], ['z'], (0/0), (void 0), (void 0), ['z'], (0/0), (0/0), (0/0), ['z'], (0/0), (void 0), (0/0), (0/0), (0/0), (0/0), (void 0), ['z'], (0/0), ['z'], ['z'], (void 0), (0/0), ['z'], ['z'], (void 0), ['z'], (0/0), (void 0), (0/0), (void 0), (void 0), ['z'], (0/0), ['z'], (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (0/0), (void 0), ['z'], ['z'], (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), ['z'], (void 0), ['z'], ['z'], (0/0), ['z'], ['z'], (void 0), (0/0), (0/0), (0/0), (void 0), (0/0), (0/0), (0/0), (void 0), (0/0)]); ");
/*fuzzSeed-246262462*/count=1006; tryItOut("mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.asinh((Math.atan2(( ! (Math.cosh((mathy1((y | 0), ((((( + Math.max(( + y), ( + y))) >>> 0) ^ y) >>> 0) >>> 0)) >>> 0)) >>> 0)), Math.trunc(( + Math.min(Math.fround(Math.hypot(-1/0, x)), Math.fround(( + y)))))) | 0)); }); testMathyFunction(mathy2, [-0, 1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0, Number.MAX_VALUE, 2**53+2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -0x100000000, -0x0ffffffff, -0x100000001, 1, -Number.MAX_VALUE, -0x080000001, 2**53, Math.PI, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 42, 0x100000001, 0.000000000000001, -(2**53), -(2**53+2), 0/0, 2**53-2, -1/0, 0x080000000, 0x080000001, -0x07fffffff, -0x080000000]); ");
/*fuzzSeed-246262462*/count=1007; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-246262462*/count=1008; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s1; print(r.exec(s)); \n/*tLoop*/for (let a of /*MARR*/[(1/0), -0x100000001, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), -0x100000001, (1/0), (1/0), -0x100000001, (1/0), (1/0), (1/0), (1/0), -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, -0x100000001, (1/0), -0x100000001, -0x100000001, -0x100000001, (1/0), -0x100000001, -0x100000001, -0x100000001, (1/0), -0x100000001, -0x100000001, (1/0), (1/0), (1/0), (1/0), -0x100000001, -0x100000001, -0x100000001, (1/0), (1/0), -0x100000001, -0x100000001, -0x100000001, (1/0)]) { a1 + ''; }\n");
/*fuzzSeed-246262462*/count=1009; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.sinh((( - Math.pow((Math.asinh((( ! (y >>> 0)) >>> 0)) > (x >>> 0x080000000)), Math.imul(((-(2**53+2) & 0x07fffffff) * y), ((Math.fround(x) & Math.fround(y)) | 0)))) >>> 0)); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -0x07fffffff, 0/0, -(2**53), -0x080000001, -(2**53-2), Number.MAX_VALUE, 2**53-2, 2**53+2, 0x07fffffff, -Number.MIN_VALUE, 0x100000001, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000000, 42, -0, 1/0, 2**53, -Number.MAX_VALUE, Math.PI, 0x100000000, -1/0, 1, 0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, -(2**53+2), -0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=1010; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return mathy1(Math.imul((x >> (( + ( - ( + y))) & x)), (Math.sin(( + Math.hypot(( + y), y))) | 0)), Math.atan2(((mathy3((x >>> 0), ( + (Math.sin((x >>> 0)) >>> 0))) >>> 0) >>> 0), Math.hypot(( + Math.asinh(((Math.fround(( ~ ( + y))) | 0) ? x : (Math.pow(( + x), ( + 2**53+2)) >>> 0)))), mathy2(Math.fround(Math.round(Math.fround(( + (Math.fround(y) <= Math.fround(x)))))), ((Math.log(Math.sinh(x)) >>> 0) | 0))))); }); testMathyFunction(mathy5, [-0x100000001, 0/0, 42, 0x0ffffffff, 2**53+2, 0x080000001, 0x100000000, -(2**53+2), 0x080000000, -Number.MAX_VALUE, -(2**53-2), 0x07fffffff, 0, Number.MAX_SAFE_INTEGER, 1/0, 1.7976931348623157e308, -0x080000000, -0, -(2**53), -0x0ffffffff, -0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -0x07fffffff, 2**53-2, 0.000000000000001, 0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53, 1]); ");
/*fuzzSeed-246262462*/count=1011; tryItOut("i1.next();");
/*fuzzSeed-246262462*/count=1012; tryItOut("\"use strict\"; \"use asm\"; s2 = s1.charAt(16);\u000d");
/*fuzzSeed-246262462*/count=1013; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return Math.fround(Math.acosh(( + ( ~ ( + 0x0ffffffff))))); }); ");
/*fuzzSeed-246262462*/count=1014; tryItOut("mathy5 = (function(x, y) { return Math.tanh((Math.imul((Math.atanh((((Math.hypot(((Math.min((-(2**53) >>> 0), (x >>> 0)) >>> 0) >>> 0), Math.round((y | 0))) | 0) ^ ((Math.fround(1/0) << Math.fround((Math.max(y, (Number.MAX_VALUE | 0)) | 0))) | 0)) | 0)) >>> 0), (Math.expm1(( + (x / Math.tan(x)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [0x080000000, 2**53-2, -(2**53+2), 2**53+2, -0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -(2**53), -0x080000000, 0x100000000, 42, 2**53, Number.MAX_SAFE_INTEGER, -0, 0x100000001, -1/0, -0x07fffffff, -0x100000000, 0x080000001, -(2**53-2), Number.MIN_VALUE, 1/0, -0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, 0/0, 0, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=1015; tryItOut("s2 += s2;");
/*fuzzSeed-246262462*/count=1016; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.log10(mathy0(( ~ y), (( + Math.pow((0x080000000 > Math.atan2(x, Math.fround(y))), mathy0(Math.expm1(y), y))) - x))) >>> 0); }); testMathyFunction(mathy4, [-0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, 2**53, 1.7976931348623157e308, -(2**53-2), 0x080000000, Math.PI, -0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, 2**53-2, 0, 0x080000001, 2**53+2, 0x07fffffff, -Number.MIN_VALUE, 1/0, -0x100000000, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -0x080000001, Number.MAX_VALUE, 0x0ffffffff, 1, -(2**53+2), -0x080000000, -0, 0.000000000000001]); ");
/*fuzzSeed-246262462*/count=1017; tryItOut("print(uneval(s1));");
/*fuzzSeed-246262462*/count=1018; tryItOut("a0.reverse(e2);");
/*fuzzSeed-246262462*/count=1019; tryItOut("\"use asm\"; ");
/*fuzzSeed-246262462*/count=1020; tryItOut("s2 = s0.charAt(({valueOf: function() { t0[9] = ({callee: \u3056 });\n/* no regression tests found */\nreturn 16; }}));");
/*fuzzSeed-246262462*/count=1021; tryItOut("for (var p in h2) { try { v0 = Object.prototype.isPrototypeOf.call(this.o1, o2.e1); } catch(e0) { } try { i0.next(); } catch(e1) { } try { Object.prototype.watch.call(v1, new String(\"19\"), (function() { for (var j=0;j<85;++j) { f2(j%5==0); } })); } catch(e2) { } a0[v1] = x; }let a = x.throw((4277));");
/*fuzzSeed-246262462*/count=1022; tryItOut("o0.f0 = Proxy.createFunction(h1, f0, f1)\nprint(x);");
/*fuzzSeed-246262462*/count=1023; tryItOut("m2 = new Map(g0.f2);");
/*fuzzSeed-246262462*/count=1024; tryItOut("for (var p in i1) { try { Array.prototype.push.call(a1, s2, i0, p2); } catch(e0) { } t0[2] = ( /* Comment */(4277)); }");
/*fuzzSeed-246262462*/count=1025; tryItOut("\"use strict\"; x = linkedList(x, 4644);");
/*fuzzSeed-246262462*/count=1026; tryItOut("var dbzkfa = new SharedArrayBuffer(4); var dbzkfa_0 = new Float32Array(dbzkfa); this.a1 + v0;");
/*fuzzSeed-246262462*/count=1027; tryItOut("v0 = Object.prototype.isPrototypeOf.call(i2, m0);");
/*fuzzSeed-246262462*/count=1028; tryItOut("\"use strict\"; t1 = new Uint8ClampedArray(4);");
/*fuzzSeed-246262462*/count=1029; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy2((( ! (( + Math.pow(((y || x) | 0), ( + (( - (( - (mathy2(y, 0) >>> 0)) >>> 0)) >>> 0)))) >>> 0)) >>> 0), (Math.pow(x, Math.fround((Math.fround((x % ( - -0x080000001))) ? y : Math.fround((Math.atan2((0.000000000000001 | 0), ((( - (y | 0)) | 0) | 0)) | 0))))) * ( - Math.fround(mathy0(Math.fround(0), Math.fround(y)))))); }); testMathyFunction(mathy5, [2**53+2, 1, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 1.7976931348623157e308, -Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, 0x07fffffff, 0, -0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, -0x07fffffff, 2**53, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), -0x080000000, -0x100000000, Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, 42, 0x100000000, 0x100000001, 2**53-2, 0x080000000, 0/0]); ");
/*fuzzSeed-246262462*/count=1030; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.acos((Math.hypot(Math.fround((Math.fround(y) ? ( + y) : Math.fround(Math.atan2(y, -0x100000000)))), ((y || Math.asin(0/0)) | 0)) | 0))); }); testMathyFunction(mathy4, /*MARR*/[(Int16Array), (Int16Array), (Int16Array), (Int16Array), 1e+81, 1e+81, (Int16Array), (0/0), 1e+81, (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), (Int16Array), -Infinity, (Int16Array), 1e+81, 1e+81, (Int16Array), -Infinity, 1e+81, (0/0), (Int16Array), -Infinity, (Int16Array), (0/0), (0/0), (Int16Array), 1e+81, 1e+81, (Int16Array), -Infinity, -Infinity, -Infinity, (Int16Array), 1e+81, (Int16Array), (Int16Array), (0/0), -Infinity, (Int16Array), -Infinity, 1e+81, 1e+81, (0/0), (Int16Array), (0/0), (0/0), -Infinity, (Int16Array), 1e+81, 1e+81, (Int16Array), 1e+81, (Int16Array), -Infinity, (0/0), 1e+81, (0/0), -Infinity, (0/0), (0/0), 1e+81, 1e+81, -Infinity, (0/0), (Int16Array), (Int16Array), 1e+81, (0/0), (Int16Array), (0/0), 1e+81, (0/0), -Infinity, -Infinity, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, -Infinity, -Infinity, 1e+81, -Infinity, (0/0), 1e+81, (Int16Array), 1e+81, (0/0), 1e+81, (Int16Array), 1e+81, (0/0), (0/0), (Int16Array), (0/0), 1e+81, 1e+81, 1e+81, (0/0)]); ");
/*fuzzSeed-246262462*/count=1031; tryItOut("\"use strict\"; m0 = new Map;");
/*fuzzSeed-246262462*/count=1032; tryItOut("\"use strict\"; g2.g2.v2 = -0;");
/*fuzzSeed-246262462*/count=1033; tryItOut("for (var v of a0) { try { o1.v2 = Object.prototype.isPrototypeOf.call(e2, this.p2); } catch(e0) { } try { t0 = new Uint16Array(5); } catch(e1) { } this.s2 = new String; }");
/*fuzzSeed-246262462*/count=1034; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.ceil(((((( + 2**53+2) / Math.fround(Math.min(-0x080000000, x))) | 0) >= ( + (((Math.hypot(x, y) | 0) ? y : x) | 0))) ? (( + ( + mathy1(x, (y >>> 0)))) ? (( - (((x >>> 0) % (-0x100000000 >>> 0)) | 0)) | 0) : ( + ( - (x >>> 0)))) : ( + ((0/0 & -0x100000001) ? (Math.pow(( + mathy0(( + y), ( + y))), y) >>> 0) : y)))) / (Math.cos(((Math.round((y != y)) >>> 0) >>> Math.fround(( ~ Math.fround(mathy0(x, ( + Math.hypot(1.7976931348623157e308, 0x080000000)))))))) | 0)); }); ");
/*fuzzSeed-246262462*/count=1035; tryItOut("s1 += 'x';");
/*fuzzSeed-246262462*/count=1036; tryItOut("v0.__proto__ = p2;");
/*fuzzSeed-246262462*/count=1037; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.fround((Math.fround(((mathy1(( + Math.atan2(x, 0x080000001)), ( + Math.sin((Math.pow(y, x) | 0)))) >>> 0) == Math.fround(Math.hypot(( + Number.MAX_VALUE), Math.fround((Math.log2((x >>> 0)) >>> 0)))))) == Math.fround(( + ((x | 0) << (Math.log1p(y) | 0)))))) / ( - Math.fround(( + Math.imul(((( + Math.fround(x)) === Math.fround(y)) ? x : x), Math.hypot((( ~ -0x100000001) | 0), Math.fround(x))))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, -0, -0x100000000, 0, -(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, 2**53+2, 0.000000000000001, 1/0, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, 0/0, 1, -(2**53-2), -0x080000000, 2**53-2, 42, Number.MAX_VALUE, 0x100000000, 0x080000000, -0x07fffffff, 1.7976931348623157e308, -1/0, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-246262462*/count=1038; tryItOut("x;{}");
/*fuzzSeed-246262462*/count=1039; tryItOut("m2.has(m2)\n");
/*fuzzSeed-246262462*/count=1040; tryItOut("let (a) { this.v0 = Object.prototype.isPrototypeOf.call(o1.v0, p2); }");
/*fuzzSeed-246262462*/count=1041; tryItOut("/*infloop*/M: for  each(this.zzz.zzz in new true()) this.v2 = r1.compile;print(x);");
/*fuzzSeed-246262462*/count=1042; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-(2**53+2), -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, 1, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, 1/0, Math.PI, 0x080000000, 0x07fffffff, 2**53-2, 0x100000000, 1.7976931348623157e308, -0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -0x080000001, 0x080000001, 42, -0x07fffffff, 0/0, -Number.MAX_VALUE, 0x0ffffffff, 0, -0, 2**53+2, -1/0, -(2**53), -(2**53-2), -Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=1043; tryItOut("mathy3 = (function(x, y) { return Math.log1p((Math.hypot(( + (y ? ( + x) : (Math.hypot(x, x) >>> 0))), (mathy0(Math.imul(Math.min(-Number.MIN_SAFE_INTEGER, Math.hypot(-Number.MIN_VALUE, (( - (x >>> 0)) | 0))), (((Math.fround(Math.min(Math.tanh((x >>> 0)), x)) | 0) <= (( + Math.asinh(( + -Number.MAX_VALUE))) | 0)) | 0)), ( + (( - 2**53+2) + Number.MAX_VALUE))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-246262462*/count=1044; tryItOut("\"use strict\"; g2.t2 = new Uint16Array(t2);");
/*fuzzSeed-246262462*/count=1045; tryItOut("testMathyFunction(mathy5, [-(2**53-2), -Number.MAX_VALUE, -0x07fffffff, Number.MAX_VALUE, 1/0, -0x080000001, 0/0, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000000, Number.MIN_VALUE, 2**53-2, -(2**53), -0x0ffffffff, -0x100000000, 1.7976931348623157e308, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, -0, -0x080000000, 0, -1/0, -Number.MIN_VALUE, 42, 1, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53]); ");
/*fuzzSeed-246262462*/count=1046; tryItOut("a2 = r2.exec(s2);");
/*fuzzSeed-246262462*/count=1047; tryItOut("/*RXUB*/var r = /\\3|$[^\\s][g-\u008e]|\\w+|(?=\\3)|(?!(?=\\\u4174{2,})){137438953471,137438953471}\\1[^]?|(?=$)+?{1,5}/gm; var s = \"\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\n\\ua35b\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u00ca\\u00aeo\\n\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\\u4174\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=1048; tryItOut("this.a2.splice(7, ({valueOf: function() { print(p2);return 2; }}), b, v0);");
/*fuzzSeed-246262462*/count=1049; tryItOut("mathy3 = (function(x, y) { return ( + Math.exp((((Math.fround(mathy2(Math.fround(x), mathy2((0x0ffffffff > (y | 0)), Math.fround(Math.atan2(Math.fround(x), Math.fround(-0x080000001)))))) + (Math.trunc(x) >>> 0)) >> (mathy1((( ~ ( + x)) | 0), ( - x)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-246262462*/count=1050; tryItOut("v0 = g2.eval(\"f1(e2);\");t0 = t1.subarray(({valueOf: function() { /*MXX2*/this.g2.Date.prototype.setSeconds = e2;return 5; }}));");
/*fuzzSeed-246262462*/count=1051; tryItOut("\"use strict\"; v1 = m0[\"__proto__\"];");
/*fuzzSeed-246262462*/count=1052; tryItOut("{for (var p in g0) { s1 += 'x'; } }");
/*fuzzSeed-246262462*/count=1053; tryItOut("\"use asm\"; testMathyFunction(mathy3, [1, -0x07fffffff, -0x080000001, 0x100000000, -(2**53+2), -0x100000000, -0x0ffffffff, -1/0, -0, 2**53-2, 0x0ffffffff, 0.000000000000001, 0/0, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, Math.PI, 1.7976931348623157e308, 1/0, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, -0x100000001, 0, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), 0x080000001, 0x100000001, 2**53]); ");
/*fuzzSeed-246262462*/count=1054; tryItOut("\"use strict\"; g0.f1 + '';");
/*fuzzSeed-246262462*/count=1055; tryItOut("/*ADP-1*/Object.defineProperty(a1, v1, ({configurable: true, enumerable: ({prototype: x,  get length(x, ...x) { \"use strict\"; return (++x) }  })}));");
/*fuzzSeed-246262462*/count=1056; tryItOut("mathy3 = (function(x, y) { return Math.log1p((( ~ Math.fround(( - (mathy1((Math.atan2(0.000000000000001, (mathy2(0, (x | 0)) | 0)) >>> 0), x) | 0)))) >>> 0)); }); ");
/*fuzzSeed-246262462*/count=1057; tryItOut("L:if(true) e2.has(b0); else  if (x) print(((p={}, (p.z = -22)())));let d = x;");
/*fuzzSeed-246262462*/count=1058; tryItOut("m0 = new Map;");
/*fuzzSeed-246262462*/count=1059; tryItOut("/*tLoop*/for (let w of /*MARR*/[(--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x), (--([])).prototype( \"\" , x),  /x/ , (--([])).prototype( \"\" , x),  /x/ , (--([])).prototype( \"\" , x), new Boolean(true), new Boolean(true),  /x/ , this,  /x/ , new Boolean(true), this,  /x/ ]) { try { with({}) (new RegExp(\"(?=(?!(?:[^])|[]|\\\\t*?|[^]^[\\\\\\u0016]?))\", \"gyi\")); } catch(x if (function(){return \"\\u3D88\".unwatch(\"0\")\u0009;})()) { let(a = new RegExp(\"(?=\\\\r\\\\S+?\\\\2|\\\\b)\", \"im\"), naiagl, x, dibaun, w, e, djsrup, a) ((function(){x;})()); } let(w) { for(let a in []);} }");
/*fuzzSeed-246262462*/count=1060; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!\\B{1,}\\2+?|\\s\\b**?\\u002C|[^]\\v?*)(?!$)/gyi; var s = \"\\n\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-246262462*/count=1061; tryItOut("\"use strict\"; f1 = (function() { for (var j=0;j<81;++j) { f2(j%4==0); } });");
/*fuzzSeed-246262462*/count=1062; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.hypot(mathy1(( + Math.cbrt(( + (x + Math.fround(Math.asinh(x)))))), Math.fround(Math.imul(mathy4(-Number.MIN_VALUE, Math.atan2(Math.fround(y), mathy3(Math.imul(x, ( + x)), y))), (( - (( + Math.max(( + Math.hypot(( + y), ( + y))), ((( ~ (x | 0)) | 0) > y))) | 0)) | 0)))), ((Math.fround(Math.acos((Math.fround(mathy0(Math.fround(y), (Math.min(Number.MIN_SAFE_INTEGER, (( + (y | 0)) | 0)) | 0))) >>> 0))) , ( ! ( ~ (( + Math.sinh(y)) ? x : x)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-246262462*/count=1063; tryItOut("Array.prototype.reverse.call(a0, m1);");
/*fuzzSeed-246262462*/count=1064; tryItOut("a2 = arguments.callee.arguments;");
/*fuzzSeed-246262462*/count=1065; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=1066; tryItOut("/*ODP-3*/Object.defineProperty(e0, \"trimLeft\", { configurable: (x % 13 != 0), enumerable: (x % 11 == 3), writable: true, value: p1 });");
/*fuzzSeed-246262462*/count=1067; tryItOut("mathy1 = (function(x, y) { return Math.fround(mathy0(Math.log2((( + x) , ( + (mathy0(mathy0(y, Math.max(y, -Number.MIN_VALUE)), x) >= Math.fround(( + Math.fround((Math.log1p(( + y)) >>> 0)))))))), ((( + ((((mathy0(( + ((y | 0) ? y : x)), x) >>> 0) < x) >>> 0) >>> 0)) >>> 0) | Math.min(( ! y), ((Math.atan2(( + Math.fround((Math.fround(Math.fround(x)) >> Number.MAX_SAFE_INTEGER))), ( + (x <= ( + 0x07fffffff)))) | 0) >= x))))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53-2, -0x100000000, -(2**53-2), 1, -Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, Number.MAX_VALUE, -(2**53+2), 0x100000001, -0, 0x080000000, -(2**53), Math.PI, 2**53+2, 1/0, -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0/0, -1/0, 0x080000001, -0x100000001, 0x0ffffffff, -0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-246262462*/count=1068; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    (Float32ArrayView[((i2)+(i0)+(i2)) >> 2]) = (((0xa35a7e4e) ? (((-6.189700196426902e+26))) : (NaN)));\n    return ((((Int16ArrayView[((0x297d5c2f)+(i2)) >> 1]))+(i2)+(0xf9b03903)))|0;\n  }\n  return f; })(this, {ff: arguments.callee}, new ArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[x, false, x, x, false, x, x, false, false, x, false, x, false, false, x, x, false, x, false, false, false, false, false, false, false, x, x, x, false, false, x, x, x, x, x, x, x, false, x, x, x, x, x, false, false, false, false, x, false, x, x, false, false, x, false, false, x, x]); ");
/*fuzzSeed-246262462*/count=1069; tryItOut("\"use strict\"; v0 = (this.s0 instanceof p1);\ntry { (x\u0009); } finally { ; } \n");
/*fuzzSeed-246262462*/count=1070; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (makeFinalizeObserver('nursery')); }); ");
/*fuzzSeed-246262462*/count=1071; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    d0 = (d0);\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: new RegExp(\"\\\\uB5BC*\", \"gy\") >>= {}}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [2**53, -(2**53-2), 0, 1, 0x07fffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, 42, 2**53+2, 0x080000001, -0x080000001, 2**53-2, 1/0, -0x0ffffffff, -0, -0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, 0.000000000000001, Math.PI, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, -1/0, -(2**53+2), 0x100000000]); ");
/*fuzzSeed-246262462*/count=1072; tryItOut("\"use asm\"; b2 + '';");
/*fuzzSeed-246262462*/count=1073; tryItOut("v2 = r0.sticky;");
/*fuzzSeed-246262462*/count=1074; tryItOut("\"use strict\"; ");
/*fuzzSeed-246262462*/count=1075; tryItOut("print(p1);");
/*fuzzSeed-246262462*/count=1076; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ( ! ( ! (Math.max((Math.tan((y | 0)) | 0), ( + ((((Math.log(x) >>> 0) >>> Math.fround(x)) | 0) << Math.imul(Math.fround(Math.asinh(Math.fround(-0x07fffffff))), y)))) >>> 0))); }); testMathyFunction(mathy0, [1/0, 1, -0x100000001, 42, -(2**53), 0/0, 0x100000000, 0x0ffffffff, 0x100000001, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -(2**53-2), -(2**53+2), 0x080000000, -0x080000000, Math.PI, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53, -0x07fffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, 0.000000000000001, -1/0, Number.MAX_VALUE, 0, 1.7976931348623157e308, 2**53+2, -0x100000000, -0, -0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=1077; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    {\n      {\n        i3 = (0x8f1fa897);\n      }\n    }\n    return +((+((d1))));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[(1/0), undefined, (1/0), [], (1/0), [], (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), undefined, undefined]); ");
/*fuzzSeed-246262462*/count=1078; tryItOut("t0.toString = f0;");
/*fuzzSeed-246262462*/count=1079; tryItOut("v1 = (g1.v2 instanceof g2);");
/*fuzzSeed-246262462*/count=1080; tryItOut("f0(p2);");
/*fuzzSeed-246262462*/count=1081; tryItOut("/*RXUB*/var r = /[^]{2,}|((?:.|s+?(?!(?![^]))|[^\\f-\\u00d2]+|(.)))/gyim; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-246262462*/count=1082; tryItOut("o0.r0 = new RegExp(\"${2,4}(?=(?!\\\\3+?))*(^|\\\\b)?\", \"gyim\");");
/*fuzzSeed-246262462*/count=1083; tryItOut("mathy0 = (function(x, y) { return ( + ((( + (Math.max(0.000000000000001, (Math.fround(( ! Math.fround(y))) | 0)) & (( ! (((Math.min(-(2**53-2), y) | 0) * y) | 0)) | 0))) >>> 0) ? (Math.min((Math.trunc((( + (( + ( + Math.fround(( + (Math.pow(x, (y >>> 0)) >>> 0))))) ? ( + y) : ( + (( + y) & x)))) | Math.atan2(0x07fffffff, y))) | 0), ((( + Math.atanh(Math.hypot(( ! x), (Number.MIN_VALUE || Math.fround(y))))) >>> 0) >= (((Math.atanh((0x07fffffff | 0)) | 0) > (Math.fround(y) ? Number.MAX_SAFE_INTEGER : y)) >>> 0))) >>> 0) : ((Math.trunc((Math.imul((( + (Math.fround(-Number.MIN_SAFE_INTEGER) && (( + ( + (x | 0))) ? ( + y) : ( + (Math.clz32(((y || y) | 0)) | 0))))) | 0), (( + Math.round(( + x))) | 0)) | 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, 0x080000001, Number.MIN_VALUE, 0x100000000, Math.PI, -0, -1/0, -(2**53), -(2**53+2), 1, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, 2**53+2, -0x080000001, 0x100000001, -(2**53-2), 2**53, 0/0, -Number.MAX_VALUE, 42, -0x07fffffff, 0x080000000, 1.7976931348623157e308, 2**53-2, 0.000000000000001, -0x100000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-246262462*/count=1084; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.log10((Math.pow(Math.atan2((y ** ( + ( + ( + x)))), Math.fround(( ! ( + Math.min(-Number.MAX_SAFE_INTEGER, y))))), (((( ~ Math.sqrt(y)) | 0) >= Math.fround(((mathy0(Math.fround(Math.sinh(Math.fround(( ! (y >>> 0))))), y) | 0) == y))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [({valueOf:function(){return 0;}}), false, 1, (new Number(0)), (function(){return 0;}), objectEmulatingUndefined(), '', 0.1, null, ({toString:function(){return '0';}}), undefined, (new Number(-0)), (new Boolean(true)), -0, 0, (new String('')), NaN, ({valueOf:function(){return '0';}}), '/0/', [], '\\0', /0/, '0', (new Boolean(false)), [0], true]); ");
/*fuzzSeed-246262462*/count=1085; tryItOut("return (x = w);function x(y = x, d, window, x, a, z, x = \"\\u9E9C\", NaN, NaN, e, z = \"\\u26FD\", x, x, b, NaN, x, x, NaN, eval, x, x, x, x)/*\n*/ { \"use strict\"; o2.a1[11] = true; } v1 = Object.prototype.isPrototypeOf.call(s2, p2);");
/*fuzzSeed-246262462*/count=1086; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    return +((Float32ArrayView[1]));\n    {\n      i0 = (i1);\n    }\n    (Uint32ArrayView[0]) = ((~~(-1.0)) % (~~(-1099511627777.0)));\n    return +((+abs(((-35184372088831.0)))));\n  }\n  return f; })(this, {ff: Function.prototype.bind}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, Math.PI, -(2**53-2), 2**53+2, -0x100000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -0, 2**53, 42, 0x100000001, -(2**53+2), Number.MIN_VALUE, 0, -1/0, -Number.MIN_VALUE, -0x080000000, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53), 0x0ffffffff, 1, -0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000000, 1/0, 2**53-2, 0/0]); ");
/*fuzzSeed-246262462*/count=1087; tryItOut("testMathyFunction(mathy0, [-(2**53-2), -0x07fffffff, Math.PI, -0x0ffffffff, 0x100000000, 42, 1.7976931348623157e308, 0x0ffffffff, 0.000000000000001, 0, 0/0, 2**53, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, 0x080000001, 0x100000001, -0x080000000, 0x080000000, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, -0x080000001, 1/0, -(2**53+2), -Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, 2**53+2, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=1088; tryItOut("\"use strict\"; /*oLoop*/for (let dmkder = 0; dmkder < 72; ++dmkder) { let (w) { ( /* Comment */++w); } } ");
/*fuzzSeed-246262462*/count=1089; tryItOut("mathy4 = (function(x, y) { return Math.log(Math.acos(((Math.min(x, ( - y)) < (mathy1((y ? ( + x) : x), Math.pow(( + Math.atan(y)), Math.min(Math.fround(y), Math.fround(mathy1(y, y))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [-0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, 0x080000000, 2**53-2, -0x080000000, -0x080000001, -Number.MAX_VALUE, -0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, 0x100000000, 0/0, 1/0, 0.000000000000001, 0x07fffffff, -Number.MIN_VALUE, 2**53, 42, 2**53+2, 0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), 0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, 1, -(2**53), 1.7976931348623157e308, Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=1090; tryItOut("a1.length = ({valueOf: function() { o2.m2.has(a2);return 17; }});\no2.o2.i1 = g2.objectEmulatingUndefined();\n");
/*fuzzSeed-246262462*/count=1091; tryItOut("mathy4 = (function(x, y) { return ( + Math.pow(( + (((((y | 0) ? (y | 0) : ((( - 0.000000000000001) >>> 0) | 0)) >> Math.fround(Math.ceil(Math.fround(2**53+2)))) << ( - Math.imul(Math.imul(Math.min(y, y), y), y))) >>> 0)), ( + (( - (( + Math.trunc(Math.fround(( - x)))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-246262462*/count=1092; tryItOut("for(e = (Math.pow(-5, 25)) in window) {Array.prototype.sort.call(a2, (function() { for (var j=0;j<79;++j) { f1(j%4==1); } }));t2 + ''; }");
/*fuzzSeed-246262462*/count=1093; tryItOut("o1.s1 += 'x';");
/*fuzzSeed-246262462*/count=1094; tryItOut("mathy4 = (function(x, y) { return ( - ( ~ ( ~ ( + Math.asin((Math.tan(1.7976931348623157e308) >>> 0)))))); }); testMathyFunction(mathy4, [false, true, ({toString:function(){return '0';}}), NaN, 0.1, (new Number(-0)), /0/, (new Boolean(false)), 0, null, -0, '/0/', ({valueOf:function(){return '0';}}), '\\0', ({valueOf:function(){return 0;}}), [0], undefined, '', (function(){return 0;}), [], (new String('')), (new Number(0)), '0', 1, (new Boolean(true)), objectEmulatingUndefined()]); ");
/*fuzzSeed-246262462*/count=1095; tryItOut("o0.i2.send(h2);");
/*fuzzSeed-246262462*/count=1096; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.pow((((-Number.MIN_VALUE != Math.tanh(x)) == Math.pow(Math.fround(Math.acosh(( + Math.atan2(( + y), ( + y))))), Math.fround(Math.log1p(Math.fround((Math.fround(Math.trunc(Math.sin(x))) ? Math.fround(-0x080000001) : (( ~ ( + y)) >>> 0))))))) >>> 0), (Math.fround(Math.tan(Math.fround((Math.fround(mathy2(Math.fround(Math.round((((Math.sinh(y) >>> 0) == (x + ( + y))) >>> 0))), (Math.fround(( ~ mathy1(0.000000000000001, Math.fround(x)))) >>> 0))) ? Math.fround(( ~ (x / (Math.ceil((y | 0)) | 0)))) : Math.fround(Math.min(Math.hypot(( + ( ! x)), Math.imul(Math.fround((y >= 1)), Math.fround(y))), (-Number.MIN_VALUE != (x | 0)))))))) | 0)) >>> 0); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return '0';}}), (new Number(0)), NaN, 0, '/0/', 1, [0], undefined, null, -0, objectEmulatingUndefined(), 0.1, (new Boolean(false)), '', true, '0', false, /0/, (new Boolean(true)), '\\0', (function(){return 0;}), (new String('')), ({valueOf:function(){return 0;}}), []]); ");
/*fuzzSeed-246262462*/count=1097; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(Math.imul(Math.fround(Math.fround(( + ((Math.max(( + (( + ( ! ( + x))) ? ( + y) : ( + (Math.atan2((x | 0), (x | 0)) >>> 0)))), y) == (( ~ (( - (x >>> 0)) >>> 0)) | 0)) >>> 0)))), Math.fround((Math.pow((( - Math.log2((( - (-Number.MAX_SAFE_INTEGER | 0)) | 0))) | 0), (Math.imul(((( ! y) ^ Math.fround(mathy1(Math.fround(0x100000000), Math.fround((((y | 0) ? (x | 0) : (x | 0)) | 0))))) ^ (Math.fround(Math.min(x, x)) >>> 0)), (Math.sinh((( ! x) | 0)) | 0)) | 0)) | 0)))); }); testMathyFunction(mathy3, [0x100000001, 1.7976931348623157e308, -0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_VALUE, -0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 0x07fffffff, -(2**53+2), 1, 0.000000000000001, Number.MIN_VALUE, Math.PI, -1/0, -0, 2**53-2, -(2**53), 2**53, 2**53+2, 1/0, 0x080000001, -0x0ffffffff, -0x080000000, 42, 0x080000000, -(2**53-2), -Number.MIN_VALUE, 0]); ");
/*fuzzSeed-246262462*/count=1098; tryItOut("\"use strict\"; o1.v1 = g0.runOffThreadScript();");
/*fuzzSeed-246262462*/count=1099; tryItOut("f1 = Proxy.createFunction(o0.h2, f2, f2);");
/*fuzzSeed-246262462*/count=1100; tryItOut("\"use strict\"; for(let b in ((new Function)((uneval(new new RegExp(\"(?=(\\\\2)*)\", \"yim\")( /x/g )))))){v1 = o1.g2.eval(\"(4277)\"); }");
/*fuzzSeed-246262462*/count=1101; tryItOut("\"use strict\"; e2.delete(t2);");
/*fuzzSeed-246262462*/count=1102; tryItOut("/*infloop*/for(Math.hypot(x, 27); x++; .valueOf(\"number\")) print(x);");
/*fuzzSeed-246262462*/count=1103; tryItOut("for (var p in i2) { try { /*MXX2*/g1.g0.String.prototype.trim = s0; } catch(e0) { } i0.send(g2.b2); }");
/*fuzzSeed-246262462*/count=1104; tryItOut("\"use strict\"; t2 = new Uint8ClampedArray(b2);");
/*fuzzSeed-246262462*/count=1105; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + Math.sign(( + ( + ( + (x ? x : y)))))), (Math.fround(mathy0((( + Math.asinh(( + Math.max(( ~ x), ( + Math.log10(( + x))))))) | 0), (Math.pow(Math.fround(Math.max(( ! y), Math.fround(( + (( + (( + x) << x)) == -1/0))))), (y ? (Math.min(((y | 0) ^ x), ( + y)) >>> 0) : x)) | 0))) | 0))); }); ");
/*fuzzSeed-246262462*/count=1106; tryItOut("f0(g0);");
/*fuzzSeed-246262462*/count=1107; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(( - (Math.log2((( + Math.pow((( + (( + ( + ( + x))) ? ( + x) : ( + (y > y)))) ? Math.asinh(42) : (x | 0)), (Math.imul((Math.ceil(( + y)) >>> 0), (x >>> 0)) >>> 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [2**53, 0/0, 0x080000001, 1, 0x100000000, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, 0, -(2**53-2), 2**53-2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000000, -0x080000001, 0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0x07fffffff, -0x100000000, Number.MIN_VALUE, -0, Math.PI, 0.000000000000001, 42, -0x07fffffff, 2**53+2, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0]); ");
/*fuzzSeed-246262462*/count=1108; tryItOut("/*oLoop*/for (let llwqsf = 0, x; llwqsf < 6; ++llwqsf) { selectforgc(o1); } ");
/*fuzzSeed-246262462*/count=1109; tryItOut("\"use strict\"; const this.x = -5.watch(16, (function (y, y)\"use asm\";   var abs = stdlib.Math.abs;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -4194305.0;\n    var d4 = 33.0;\n    var d5 = -6.189700196426902e+26;\n{}    d3 = (d4);\n    {\n      i2 = (1);\n    }\n    i1 = ((~((0x206486c0))) != (((0x20eef235)-(i2)) | (((((0xf8f609bf)) ^ ((0xfed2d676)+((0xffffffff) <= (0x0)))) > (abs((((0x152551a5) % (0x1de195a9)) ^ ((0xfee2da16)-(0x40fb0951))))|0)))));\n    i2 = ((~((0xffffffff) / (0x0))) > (~((Uint8ArrayView[1]))));\nt1 = new Int32Array(19);    (Uint8ArrayView[((0xffffffff)-(0x79d488c0)-(0xfdf3c14c)) >> 0]) = (-(((((i2) ? (i0) : ((-0x8000000) ? (0xfc37b071) : (0xff153fbb)))-(0x31641ba8)) | ((i2)))));\n    d3 = (1.5474250491067253e+26);\n    i1 = (0xa6f297d3);\n    return +((d3));\n  }\n  return f;).bind), lupbiu, spjoox, e = -22, c = \u3056, eval = 22.isNaN, jqatpt, hkyrsv, x;/*tLoop*/for (let d of /*MARR*/[(0/0), new Number(1)]) { v1 = r0.multiline; }");
/*fuzzSeed-246262462*/count=1110; tryItOut("s0 += s1;");
/*fuzzSeed-246262462*/count=1111; tryItOut("\"use strict\"; with({e: \"\\uE8D6\"()})function(id) { return id };");
/*fuzzSeed-246262462*/count=1112; tryItOut("\"use strict\"; { void 0; deterministicgc(true); } Array.prototype.forEach.call(a0, function(y) { v2 = evaluate(\"for (var v of o0) { v1 = a2.some((function() { try { /*MXX3*/this.g2.Math.atanh = this.g0.Math.atanh; } catch(e0) { } try { this.e2 + ''; } catch(e1) { } a0.push(v2, \\\"\\\\u845A\\\"); return b1; })); }\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (y % 60 != 51), catchTermination: true })); }, x);");
/*fuzzSeed-246262462*/count=1113; tryItOut("mathy2 = (function(x, y) { return Math.min((Math.atan2(((((Math.fround(Math.hypot((Math.max(Math.atan2(x, -0x080000001), Math.fround((Math.fround(x) ? Math.fround(-(2**53)) : Math.fround(y)))) | 0), x)) ? (((y >>> 0) === (( + Math.asin(( + y))) >>> 0)) >>> 0) : Math.pow(0.000000000000001, (((((x | 0) << (x | 0)) | 0) | 0) * (y >>> 0)))) | 0) || ( + mathy0((( + mathy1(( + x), ( + mathy0(x, y)))) | 0), (Math.fround(Math.hypot(( + y), ( + Math.expm1(x)))) | 0)))) >>> 0), Math.imul(( + -(2**53+2)), (Math.atan2(((Math.imul((((Math.fround(Math.min(Math.fround(-Number.MIN_VALUE), Math.fround(0/0))) >>> 0) | (y | 0)) | 0), (x | 0)) | 0) | 0), (mathy0(-0x07fffffff, x) | 0)) | 0))) >>> 0), ((( - Math.atan2((Math.exp(Math.pow(x, Math.fround(y))) | 0), y)) | 0) >>> 0)); }); testMathyFunction(mathy2, [-0x100000001, Number.MIN_SAFE_INTEGER, 1/0, -(2**53), -0x080000001, 0/0, Math.PI, 0x100000001, -0x0ffffffff, 2**53+2, 0.000000000000001, -0x100000000, 0, 0x080000000, -Number.MAX_VALUE, 0x100000000, -(2**53+2), -Number.MIN_VALUE, 0x07fffffff, -(2**53-2), -0x080000000, 42, -0, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, 2**53, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, 1]); ");
/*fuzzSeed-246262462*/count=1114; tryItOut("a2 = (null for each (b in eval(\"a2 = Array.prototype.filter.apply(a0, [(function(j) { if (j) { try { v2 = a1.length; } catch(e0) { } try { print(g2); } catch(e1) { } g2.i0.send(i1); } else { try { f0 + ''; } catch(e0) { } g1.toSource = (function(j) { if (j) { try { v1 = (b2 instanceof i2); } catch(e0) { } try { for (var p in m1) { try { m2 = a2[v0]; } catch(e0) { } try { v0 = evalcx(\\\"undefined\\\", g0); } catch(e1) { } e0.has(m0); } } catch(e1) { } try { t0.set(t2, 9); } catch(e2) { } /*MXX1*/o2 = g0.Object.prototype.__proto__; } else { try { t0 = a0[({valueOf: function() { for (var p in f2) { try { v1 = a2.length; } catch(e0) { } e0.add(t2); }return 15; }})]; } catch(e0) { } try { t2.set(a2, v2); } catch(e1) { } try { h2.toSource = (function() { try { o2.v1.__iterator__ = (function(j) { if (j) { g0.m0 + ''; } else { try { v0 = evalcx(\\\"window\\\", g2); } catch(e0) { } v1 = (v2 instanceof v0); } }); } catch(e0) { } try { g2.a2.push(o1.t0, o2, a2, a2, b2); } catch(e1) { } a2.pop(); return h0; }); } catch(e2) { } Array.prototype.reverse.apply(a1, []); } }); } })]);\").__defineSetter__(\"z\", runOffThreadScript)) for (arguments.callee.caller.arguments in /*RXUE*/new RegExp(\"(?=(?=\\uad45|\\\\B^)*){0}|(?!.){0,3}\", \"gi\").exec(\"\")) for each (eval in /*FARR*/[]));");
/*fuzzSeed-246262462*/count=1115; tryItOut("/*iii*/( /x/ );/*hhh*/function kwfeot(c, a = /((?=\\3)+?)*?/yi){e2 + '';}v0 = (s0 instanceof i0);");
/*fuzzSeed-246262462*/count=1116; tryItOut("var rwjwug = new SharedArrayBuffer(4); var rwjwug_0 = new Int32Array(rwjwug); rwjwug_0[0] = 25; var rwjwug_1 = new Uint8Array(rwjwug); print(rwjwug_1[0]); print(rwjwug_0[0]);");
/*fuzzSeed-246262462*/count=1117; tryItOut("\"use strict\"; s0 + h1;");
/*fuzzSeed-246262462*/count=1118; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return Math.pow(Math.acos(Math.fround((Math.acosh((( ! x) | 0)) | 0))), ( + ( + ( ~ Math.clz32(( - x)))))); }); testMathyFunction(mathy2, /*MARR*/[0x40000001,  \"\" , arguments.caller, arguments.caller, arguments.caller, 0x40000001, arguments.caller,  \"\" ,  \"\" , arguments.caller,  \"\" ,  \"\" ,  \"\" ,  \"\" , arguments.caller,  \"\" , arguments.caller, 0x40000001, arguments.caller,  \"\" , arguments.caller]); ");
/*fuzzSeed-246262462*/count=1119; tryItOut("mathy4 = (function(x, y) { return (( + Math.tan(Math.fround(( + Math.min(Math.fround(Math.imul(( + Math.ceil(x)), x)), Math.log1p((-0 >>> 0))))))) >> ( ~ ( + Math.acosh(Math.fround(Math.hypot(Math.fround(y), Math.fround(Math.fround(Math.min(((x ? 0.000000000000001 : y) >>> 0), Math.fround(x)))))))))); }); testMathyFunction(mathy4, /*MARR*/[function(){}, function(){}, new Number(1.5), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x100000000, new Number(1.5), function(){}, objectEmulatingUndefined(), x, objectEmulatingUndefined(), function(){}, function(){}, new Number(1.5), x, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, x, x, new Number(1.5), objectEmulatingUndefined(), x, x, 0x100000000, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), x, x, 0x100000000, function(){}, function(){}, x, function(){}, function(){}, x, x, function(){}, function(){}, function(){}, x, 0x100000000, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), x, function(){}, new Number(1.5), new Number(1.5), new Number(1.5), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), x]); ");
/*fuzzSeed-246262462*/count=1120; tryItOut("/*tLoop*/for (let b of /*MARR*/[new String(''), ({}), (-1/0), ({}), ({}), ({}), (-1/0), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), ({}), new String(''), (-1/0), ({}), ({}), ({}), new String(''), new String(''), ({}), ({}), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), ({}), ({}), (-1/0), new String(''), new String(''), ({}), new String(''), ({}), ({}), new String(''), new String(''), new String(''), (-1/0)]) { let v1 = r1.toString; }");
/*fuzzSeed-246262462*/count=1121; tryItOut("\"use strict\"; a0[19] = (4277);");
/*fuzzSeed-246262462*/count=1122; tryItOut("L:switch(delete \"26\".x) { default: case 7: case 4: print(x);break; case 19: s1 += 'x'; }");
/*fuzzSeed-246262462*/count=1123; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return mathy0((Math.sqrt((Math.fround((( + (((y >>> 0) % (Math.trunc((-Number.MAX_SAFE_INTEGER | 0)) >>> 0)) >>> 0)) - Math.fround((Math.atan2(( + y), ( + -0)) >= ( ! x))))) | 0)) | 0), ( ~ (Math.acos(Math.fround(( + (( + mathy0(-0x07fffffff, y)) ? ( + (x ? x : Math.log1p((y | 0)))) : ( + ( ! Math.asin(Math.fround(y)))))))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[x\n, false, false, x\n, new Number(1.5), NaN]); ");
/*fuzzSeed-246262462*/count=1124; tryItOut("\"use strict\"; i0 + p1\n");
/*fuzzSeed-246262462*/count=1125; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=1126; tryItOut("for (var v of this.i0) { try { for (var p in s1) { try { this.o0.g1.b1 = new SharedArrayBuffer(3); } catch(e0) { } t0[17] = x; } } catch(e0) { } try { e0.valueOf = (function() { try { g1.a2 = arguments.callee.caller.caller.arguments; } catch(e0) { } t0 = t1.subarray(6); return t0; }); } catch(e1) { } try { v2 = Array.prototype.reduce, reduceRight.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (((0xfffff*(0x95ecd2e))|0));\n    d1 = (x);\n    {\n      d1 = (d1);\n    }\n    i0 = (0x631c6262);\n    {\n      d1 = ( \"\" );\n    }\n    d1 = (+(0.0/0.0));\n    d1 = (1099511627776.0);\n    return +((d1));\n  }\n  return f; }), a0, h0, s1]); } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(p2, i0); }");
/*fuzzSeed-246262462*/count=1127; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.pow(( + (((((Math.fround(( ~ Math.fround(( ! x)))) <= ((x || ( + x)) | 0)) | 0) >>> 0) ** Math.fround((Math.asinh(y) && Math.hypot(y, ( + Math.fround(Math.imul(Math.fround((( + Number.MAX_VALUE) >>> 0)), Math.fround(( + Math.cbrt(Math.fround(-0x100000001))))))))))) >>> 0)), (Math.fround(Math.atan2(( ! ((y | 0) < (y | 0))), Math.min(y, ( + mathy0(( + Math.abs(Math.fround(2**53+2))), ( + y)))))) | 0)) >>> 0); }); testMathyFunction(mathy1, [-0, Math.PI, 1, 42, 2**53+2, 0x080000000, -0x100000000, -1/0, 0/0, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 0, 1/0, -(2**53+2), 1.7976931348623157e308, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), -0x07fffffff, -0x100000001, -Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=1128; tryItOut("\"use strict\"; let judxfe, x = new RegExp(\"\\\\D\", \"g\");/*RXUB*/var r = r2; var s = s2; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=1129; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -9.671406556917033e+24;\n    var d3 = -147573952589676410000.0;\n    {\n      {\n        d0 = ((0xfcb0b1fc) ? (-((d2))) : (((d0)) - ((Float32ArrayView[4096]))));\n      }\n    }\n    return ((((Int8Array(((void options('strict_mode'))))) ? (/*FFI*/ff(((0x642fb2ba)), ((((i1)) << ((i1)-(0xeff3405f)))), ((d3)))|0) : (0xbfaee5c9))))|0;\n  }\n  return f; })(this, {ff: function (y) { v0 = Object.prototype.isPrototypeOf.call(s2, h1); } }, new ArrayBuffer(4096)); ");
/*fuzzSeed-246262462*/count=1130; tryItOut("d = x;o2.a0.sort((function() { for (var j=0;j<64;++j) { f1(j%5==0); } }));");
/*fuzzSeed-246262462*/count=1131; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=1132; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, 2**53, -0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -(2**53-2), Math.PI, 1, 42, 0x100000001, -Number.MAX_VALUE, -0x100000000, -0x0ffffffff, 0x080000000, 0, -0, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000001, -(2**53), 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=1133; tryItOut("print(uneval(g2.m0));");
/*fuzzSeed-246262462*/count=1134; tryItOut("testMathyFunction(mathy4, [-1/0, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53+2), 42, 1.7976931348623157e308, 0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53, 0x0ffffffff, 0.000000000000001, -(2**53), 0x100000000, 1/0, 0, 0x080000000, Number.MIN_VALUE, 1, -Number.MIN_VALUE, -0, -(2**53-2), Number.MAX_VALUE, 0/0, -0x080000001, -Number.MAX_VALUE, 0x080000001, 2**53-2, 2**53+2, 0x07fffffff, -0x100000000]); ");
/*fuzzSeed-246262462*/count=1135; tryItOut("\"use strict\"; /*iii*/m0.toSource = (function() { h0.valueOf = (function() { try { this.h1.delete = (function(j) { if (j) { try { s1 + ''; } catch(e0) { } a2.unshift(f0); } else { try { Object.defineProperty(this, \"o2.v0\", { configurable: new RegExp(\".\", \"i\"), enumerable: /(?:\\2)/m,  get: function() {  return g2.eval(\"function f1(s0)  { \\\"use strict\\\"; \\\"use asm\\\"; return Math } \"); } }); } catch(e0) { } this.v0 + g2.s1; } }); } catch(e0) { } try { g2.m1.delete(\"\\u8AD3\"); } catch(e1) { } i2.next(); return m2; }); return g1.v1; });/*hhh*/function gizcgv(false = x *=  /x/ ){t1[7] = i2;}");
/*fuzzSeed-246262462*/count=1136; tryItOut("mathy3 = (function(x, y) { return mathy1(mathy0((mathy2(mathy2(((-Number.MIN_SAFE_INTEGER >>> 0) ? Math.fround(Math.imul(Math.fround(y), Math.fround(-1/0))) : 2**53), mathy2(x, Math.min((( ~ Math.fround(y)) >>> 0), y))), Math.log1p(x)) | 0), Math.hypot(-Number.MAX_VALUE, ((y >= ((Math.imul(((( + 1/0) % x) >>> 0), (-0x100000000 >>> 0)) >>> 0) + Math.log1p(x))) | 0))), (Math.pow(Math.asinh(0x0ffffffff), ((( + (( ~ x) << x)) ? Math.fround(mathy1(Math.fround(( + (x ? x : 0x07fffffff))), Math.fround(y))) : y) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [1, -0x100000001, 0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 0x07fffffff, 0, -0x080000000, -0x07fffffff, -(2**53+2), 2**53, 0.000000000000001, 2**53+2, 0x0ffffffff, 42, 0/0, -(2**53-2), 2**53-2, -0x080000001, 1/0, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000000]); ");
/*fuzzSeed-246262462*/count=1137; tryItOut("v0 = t0.length;");
/*fuzzSeed-246262462*/count=1138; tryItOut("\"use strict\"; a2 = new Array;");
/*fuzzSeed-246262462*/count=1139; tryItOut("\"use strict\"; var zxudic = new SharedArrayBuffer(0); var zxudic_0 = new Uint32Array(zxudic); zxudic_0[0] = -17; var zxudic_1 = new Uint8ClampedArray(zxudic); print(zxudic_1[0]); zxudic_1[0] = -15; var zxudic_2 = new Float32Array(zxudic); zxudic_2[0] = -17; var zxudic_3 = new Int32Array(zxudic); zxudic_3[0] = 24; b2 + '';");
/*fuzzSeed-246262462*/count=1140; tryItOut("\"use strict\"; let (x = Math.hypot(-15, new b()), npvmpi, rrkkjn, c =  /x/ , oueavi, nqmdys, nuudwl) { Date.prototype.toJSON }");
/*fuzzSeed-246262462*/count=1141; tryItOut("s0 = new String(m0);");
/*fuzzSeed-246262462*/count=1142; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var floor = stdlib.Math.floor;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var sin = stdlib.Math.sin;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.0009765625;\n    var d3 = -6.189700196426902e+26;\n    var d4 = -7.555786372591432e+22;\n    return (((!(/*FFI*/ff(((+atan2(((d3)), ((-8388609.0))))), ((+(~~(+floor(((b == ((makeFinalizeObserver('tenured')))))))))), ((~~(d4))), ((d0)))|0))))|0;\n    return ((((0xfd8a8ac3) ? (/*FFI*/ff(((imul((i1), (0x2d520c7a))|0)))|0) : (((((0x1659e520) >= (0x540716c5))+(/*FFI*/ff(((((0xffffffff)) ^ ((0x22ddba5)))), ((1073741825.0)))|0)) << (((((0x4303ec01)) ^ ((0xfb971786))) != (((0xe9c9f757)) >> ((0x2f1838b5)))))) == (imul((0x32305b85), (/*FFI*/ff(((+abs((x < c)))), ((+sin(((-8388607.0))))), ((-36028797018963970.0)), ((-36028797018963970.0)), ((3.022314549036573e+23)), ((-16385.0)))|0))|0)))))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -0, -(2**53), 0x100000000, 1, -(2**53-2), 42, -0x07fffffff, 0.000000000000001, -(2**53+2), -1/0, 0/0, -0x080000000, 2**53-2, 0x080000000, 0, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, -0x100000001, 1.7976931348623157e308, 0x07fffffff, 2**53+2, Math.PI, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=1143; tryItOut("\"use strict\"; v0 = evaluate(\"m2 = Proxy.create(h2, i2);function y(this.eval\\u000c)(uneval(({/*toXFun*/toString: function() { return this; } })))Array.prototype.reverse.call(a2);\", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: (x % 77 != 76), noScriptRval:  /x/g , sourceIsLazy: (x % 5 != 3), catchTermination: true }));");
/*fuzzSeed-246262462*/count=1144; tryItOut("x = linkedList(x, 2755);");
/*fuzzSeed-246262462*/count=1145; tryItOut("o1.i2 = new Iterator(i2);\nv1 = (o2 instanceof o0);\n");
/*fuzzSeed-246262462*/count=1146; tryItOut("");
/*fuzzSeed-246262462*/count=1147; tryItOut("\"use strict\"; eval = x;");
/*fuzzSeed-246262462*/count=1148; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (((Infinity)) % ((Int32ArrayView[2])));\n    }\n    d1 = (d1);\n    return +((((3.0)) / ((((d1)) % ((Float64ArrayView[(-(i0)) >> 3]))))));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var gzvaci = ({NaN: x[\"__count__\"]}); var sylenl = Set.prototype.clear; return sylenl;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53), Math.PI, 42, -1/0, 0/0, -0x0ffffffff, -0x07fffffff, 2**53, 2**53-2, 0.000000000000001, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), 0, -0, 0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -0x080000001, 0x080000000, -0x100000001, 0x100000000, 1/0, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-246262462*/count=1149; tryItOut("");
/*fuzzSeed-246262462*/count=1150; tryItOut("if(false) s0 += 'x'; else  if (eval(\"/* no regression tests found */\",  /x/g )) window\u0009; else print(\"\\uF3E5\");");
/*fuzzSeed-246262462*/count=1151; tryItOut("Array.prototype.reverse.apply(o0.a2, []);");
/*fuzzSeed-246262462*/count=1152; tryItOut("for (var p in p2) { try { v2 = r1.compile; } catch(e0) { } g2.t0[12] = g0.m1; }");
/*fuzzSeed-246262462*/count=1153; tryItOut("");
/*fuzzSeed-246262462*/count=1154; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return ((Math.round((Math.fround(( - Math.fround(( + x)))) + (Math.round((Math.acosh(Math.atanh((y | 0))) >>> 0)) == Math.pow(y, ( - x))))) | 0) >>> (( + ( ~ Math.fround((((Math.imul(Math.fround(x), ((Math.acosh((Math.atanh(0x100000000) >>> 0)) >>> 0) | 0)) >>> 0) >>> 0) & ( + Math.cosh(Math.ceil(y))))))) * ( + ( ~ ( + ( ! (Math.fround(x) >>> Math.min(2**53+2, y)))))))); }); testMathyFunction(mathy1, [({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), null, '', 1, '/0/', '\\0', (new Boolean(false)), (new String('')), NaN, 0, (new Number(-0)), false, -0, '0', (new Number(0)), (new Boolean(true)), [0], true, objectEmulatingUndefined(), 0.1, [], undefined, /0/, ({toString:function(){return '0';}}), (function(){return 0;})]); ");
/*fuzzSeed-246262462*/count=1155; tryItOut("m0.has(a0);");
/*fuzzSeed-246262462*/count=1156; tryItOut("{ void 0; void schedulegc(this); }");
/*fuzzSeed-246262462*/count=1157; tryItOut("v1 = r0.exec;");
/*fuzzSeed-246262462*/count=1158; tryItOut("print(timeout(1800));");
/*fuzzSeed-246262462*/count=1159; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x100000001, -0, 0x100000000, 1/0, Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, 2**53-2, -1/0, -(2**53+2), 0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, 2**53+2, 0, -0x07fffffff, Math.PI, 42, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), 0x0ffffffff, 0.000000000000001, 0x080000000, -0x080000000, 1]); ");
/*fuzzSeed-246262462*/count=1160; tryItOut("\"use strict\"; for (var p in b0) { try { f2.toSource = (function mcc_() { var vdmszf = 0; return function() { ++vdmszf; if (/*ICCD*/vdmszf % 11 != 1) { dumpln('hit!'); try { a0 = /*MARR*/[3, 3, function(){},  /x/g , 3, 3,  /x/g , 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, function(){}]; } catch(e0) { } try { Object.defineProperty(this, \"v0\", { configurable: false, enumerable: (x % 5 != 1),  get: function() { a2.reverse(s0, f0, i1); return t2.byteLength; } }); } catch(e1) { } h0 = m0.get(i1); } else { dumpln('miss!'); try { f2.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[1]) = ((Float32ArrayView[((0x64402a1f)+(1)) >> 2]));\n    return ((((( /x/g ) | ((0xe9aaf03c))) <= (~(((i0) ? (0x2ba75ce4) : ((((-0x8000000))>>>((0xcf6781cd)))))-(!((~(-0xa55b9*(0xcdfe6ea8))) > (~(((0x326f0d21) == (0x4cc34cfb))-((-1.5) != (-2147483649.0)))))))))))|0;\n  }\n  return f; }); } catch(e0) { } delete h2.fix; } };})(); } catch(e0) { } /*MXX1*/var o1 = g0.String.prototype.lastIndexOf; }");
/*fuzzSeed-246262462*/count=1161; tryItOut("s2 += s2;");
/*fuzzSeed-246262462*/count=1162; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((0xffffffff)-((0xfe7ec01f) ? (/*FFI*/ff(((-0x8000000)), ((~~(+/*FFI*/ff(((+(-1.0/0.0))))))), ((abs((abs((((0xddbe0056)) | ((0xfd25498d))))|0))|0)), ((((0xf951bb1b)) >> ((0x907397b8)))), ((imul((0xfafc7ed0), (0x9a65a080))|0)), ((33.0)), ((147573952589676410000.0)), ((-590295810358705700000.0)), ((36028797018963970.0)))|0) : (i1))))|0;\n    i1 = (i1);\n    d0 = (+((-((d0)))));\n/* no regression tests found */    i1 = (0xb3bb266);\n    return (((((0xffffffff))|0) / (((/*FFI*/ff(((((i1)+(!(0xddddacb7))-(0x58cb2a49)) >> ((/*FFI*/ff(((-0x2364ae1)), ((NaN)), ((63.0)), ((-590295810358705700000.0)), ((3.8685626227668134e+25)), ((-17.0)), ((-65.0)), ((-144115188075855870.0)), ((-9007199254740992.0)), ((-4611686018427388000.0)), ((1.00390625)), ((-35184372088831.0)), ((33554433.0)), ((-281474976710656.0)), ((-8.0)), ((1.9342813113834067e+25)), ((-147573952589676410000.0)), ((4503599627370496.0)), ((4.835703278458517e+24)), ((-1125899906842625.0)), ((16777217.0)), ((524288.0)), ((18014398509481984.0)), ((-1048577.0)), ((-1.2089258196146292e+24)), ((-134217729.0)), ((1.0009765625)), ((-590295810358705700000.0)), ((0.5)), ((-64.0)), ((-4194304.0)), ((-8796093022208.0)))|0)))))|0)+(i1))|0)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.valueOf}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [(new Number(-0)), [0], ({toString:function(){return '0';}}), (new String('')), (new Number(0)), ({valueOf:function(){return 0;}}), null, 0.1, (new Boolean(true)), (new Boolean(false)), 0, NaN, '/0/', undefined, '\\0', (function(){return 0;}), '0', -0, '', [], /0/, true, 1, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), false]); ");
/*fuzzSeed-246262462*/count=1163; tryItOut("testMathyFunction(mathy2, [0x080000000, 0x100000001, -0x080000000, Number.MAX_VALUE, 2**53, -(2**53-2), 0x080000001, -0, -Number.MAX_VALUE, 2**53-2, Math.PI, 0x0ffffffff, 42, 2**53+2, -1/0, 1, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, 1/0, 0, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53+2), 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=1164; tryItOut("\"use strict\"; v2 = evaluate(\"function f0(b2)  { return \\u0009x % b2 } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-246262462*/count=1165; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.hypot(( ~ (Math.acosh(( + (((y >>> 0) / Math.fround(( ! Math.fround(y)))) >>> 0))) >>> 0)), Math.min(( ! (((0 | 0) !== Math.fround(Math.min(y, x))) >>> 0)), (x <= (Math.fround((( ~ y) | 0)) >> mathy2(42, (42 >>> 0)))))) > Math.pow(( + (y != (( - ((Math.trunc((y | 0)) >>> 0) | 0)) | 0))), (Math.atan((( ~ /* no regression tests found */) >>> 0)) | 0))); }); testMathyFunction(mathy3, [0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0x07fffffff, -0, -(2**53-2), 0, 0x100000001, -(2**53), -0x0ffffffff, -Number.MAX_VALUE, 2**53, Math.PI, -(2**53+2), -0x100000001, 2**53+2, 1/0, 1, 0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 42, 0x0ffffffff, 2**53-2, -0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -1/0]); ");
/*fuzzSeed-246262462*/count=1166; tryItOut("mathy5 = (function(x, y) { return ( ! (Math.log1p((Math.fround(Math.trunc(Math.fround(Math.fround(Math.log(( ! Math.fround((x | y)))))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-246262462*/count=1167; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.atan2(Math.fround(mathy3(Math.fround(( + ( - (mathy3(( ! ( ! y)), ( - x)) | 0)))), Math.fround((( ! (y >>> 0)) >>> 0)))), (( + ( + Math.hypot((Math.imul(x, y) | 0), Math.exp(x)))) | 0)); }); ");
/*fuzzSeed-246262462*/count=1168; tryItOut("mathy5 = (function(x, y) { return (Math.atanh((( - Math.fround(Math.asinh(Math.fround((mathy4((Math.imul((( ~ x) & y), Math.fround(y)) >>> 0), mathy1(Math.fround((Number.MIN_SAFE_INTEGER !== Math.fround(x))), -0x0ffffffff)) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy5, [0, undefined, NaN, (new Boolean(false)), false, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), (function(){return 0;}), '', objectEmulatingUndefined(), (new String('')), true, /0/, 1, [], '\\0', 0.1, (new Number(-0)), '0', [0], -0, (new Boolean(true)), '/0/', (new Number(0)), null, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-246262462*/count=1169; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + (Math.pow((x ** (mathy3(Math.acosh(x), -(2**53+2)) < ( ~ y))), ( + Math.hypot((((Math.fround((Math.imul(1.7976931348623157e308, y) - x)) >>> 0) * 1/0) >>> 0), (Math.pow((y | 0), (Math.cosh(( + Math.min(x, x))) | 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy4, [/0/, true, objectEmulatingUndefined(), (new String('')), [0], '\\0', 0, (function(){return 0;}), '/0/', 0.1, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), '', 1, false, ({toString:function(){return '0';}}), undefined, NaN, (new Boolean(false)), (new Number(-0)), [], (new Number(0)), (new Boolean(true)), null, '0', -0]); ");
/*fuzzSeed-246262462*/count=1170; tryItOut("mathy2 = (function(x, y) { return ((mathy1((Math.hypot(y, ((-(2**53-2) == (x >>> 0)) >>> 0)) >>> 0), Math.atan2(y, ( + ( + ( + Math.max(x, (x | 0))))))) >>> 0) < (( - ( + Math.min((( ! (y | 0)) | 0), ( ~ Math.fround(( ! Math.fround((( + y) , (x >>> 0))))))))) >>> 0)); }); testMathyFunction(mathy2, [0x07fffffff, Number.MAX_VALUE, 2**53-2, 1/0, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, 42, 0x100000001, -(2**53), 2**53+2, Number.MIN_SAFE_INTEGER, 1, 0x100000000, -1/0, 0.000000000000001, 1.7976931348623157e308, -0x07fffffff, 0, 0/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -0, -(2**53-2), -0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-246262462*/count=1171; tryItOut("((NaN = (void shapeOf(true))));");
/*fuzzSeed-246262462*/count=1172; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2*|(?!(?:(?=[^]))*|(?:([^]))(?=\\\\S?))|(?:\\\\1){1}+?\", \"m\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-246262462*/count=1173; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((Math.trunc(( ~ y)) >>> 0) * (Math.fround(Math.cbrt(Math.fround(((Math.cos(((Math.fround(0x080000000) === Math.fround(-Number.MIN_VALUE)) >= ( ~ ( + y)))) >>> 0) && x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), new String('q'),  \"\" ,  \"\" ,  \"\" ,  \"\" , new String('q'),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new String('q'), new String('q'),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new String('q'), new String('q'), new String('q'),  \"\" ,  \"\" , new String('q'), new String('q'),  \"\" , new String('q'), new String('q'), new String('q'), new String('q'), new String('q'),  \"\" ,  \"\" ,  \"\" ,  \"\" , new String('q'),  \"\" ,  \"\" , new String('q'),  \"\" , new String('q'), new String('q'),  \"\" , new String('q'),  \"\" ,  \"\" , new String('q'),  \"\" , new String('q'), new String('q'), new String('q'), new String('q'),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new String('q'),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new String('q'),  \"\" ,  \"\" , new String('q'), new String('q'),  \"\" , new String('q'), new String('q'),  \"\" ,  \"\" ,  \"\" , new String('q'), new String('q'),  \"\" ,  \"\" , new String('q'), new String('q'), new String('q'),  \"\" ,  \"\" , new String('q'), new String('q'), new String('q'),  \"\" , new String('q'),  \"\" , new String('q'),  \"\" , new String('q'),  \"\" , new String('q'),  \"\" , new String('q'), new String('q'),  \"\" ,  \"\" , new String('q'),  \"\" , new String('q'),  \"\" ,  \"\" , new String('q'), new String('q'), new String('q'), new String('q'), new String('q'),  \"\" ]); ");
/*fuzzSeed-246262462*/count=1174; tryItOut("\"use strict\"; {(void schedulegc(g2));s0.__iterator__ = (function(j) { f1(j); }); }");
/*fuzzSeed-246262462*/count=1175; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.fround(( + Math.fround((y < Math.pow((Math.min(( - x), (y >>> 0)) >>> 0), Math.min(y, y)))))) >>> 0) , (Math.max((0.000000000000001 > x), ( ! ((Math.sign(( + y)) | 0) >>> 0))) - ( + ( ~ Math.fround(Math.hypot(x, (((-(2**53) >>> 0) >= x) >>> 0))))))); }); testMathyFunction(mathy0, /*MARR*/[null, null, x ^ x, null, null, x ^ x, x ^ x, x ^ x, null, x ^ x, x ^ x, null, null, null, x ^ x, null, null, x ^ x, null, null, null, null, x ^ x, null, null, x ^ x, null, x ^ x, null, null, x ^ x, null, x ^ x, null, null, x ^ x, x ^ x, x ^ x, null, x ^ x, x ^ x, null, null, null, null, x ^ x, x ^ x, x ^ x, null, x ^ x, null, x ^ x, x ^ x, null, x ^ x, x ^ x, x ^ x, x ^ x, null, null, null, null, null, null, null, null, null, null, x ^ x, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, null, null, null, null, null, null, null, null, x ^ x, null, x ^ x, null, null, null, null, x ^ x, null, null, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, null, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, x ^ x, null, x ^ x, x ^ x, x ^ x, null, null]); ");
/*fuzzSeed-246262462*/count=1176; tryItOut("mathy5 = (function(x, y) { return (Math.atan2((Math.sin(((y - ((Math.fround((Math.fround(x) / Math.fround(Math.imul(( + x), x)))) % ( + (( + y) > ( + Math.acos(x))))) | 0)) >>> 0)) >>> 0), (( - (((Math.fround(Math.sqrt(-0x100000000)) * (Math.fround(mathy0(Math.fround((Number.MAX_VALUE ? -Number.MIN_SAFE_INTEGER : y)), Math.fround((( ! (x >>> 0)) >>> 0)))) | 0)) | 0) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000000, 42, 0x100000001, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53+2), 0/0, 0x080000001, -(2**53-2), 2**53+2, -Number.MIN_VALUE, 2**53, -(2**53), -0x080000001, 0, 1, -0x080000000, 1/0, -0, -0x100000001, -0x07fffffff, 2**53-2, 0x07fffffff]); ");
/*fuzzSeed-246262462*/count=1177; tryItOut("o0.h2.fix = f1;");
/*fuzzSeed-246262462*/count=1178; tryItOut("\"use strict\"; /*hhh*/function eybduv(((function factorial_tail(hovvzb, lefjag) { {}; if (hovvzb == 0) { ; return lefjag; } ; return factorial_tail(hovvzb - 1, lefjag * hovvzb); (13); })((d) =  /x/ , 1))){m1.has(o0.o2);}/*iii*/a0[1] = o2;");
/*fuzzSeed-246262462*/count=1179; tryItOut("mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return ((((mathy1(((( - (Math.atan(mathy1(-Number.MAX_SAFE_INTEGER, (Math.log10((y >>> 0)) >>> 0))) >>> 0)) >>> 0) >>> 0), (( - (mathy0(Math.asinh((Number.MAX_VALUE | 0)), Math.fround(( ~ (( + Math.min(( + y), y)) | 0)))) | 0)) >>> 0)) >>> 0) | 0) && (Math.expm1((Math.imul((Math.min(y, x) >>> 0), ( + y)) >>> 0)) | 0)) | 0); }); ");
/*fuzzSeed-246262462*/count=1180; tryItOut("{ void 0; void schedulegc(298); }");
/*fuzzSeed-246262462*/count=1181; tryItOut("print(uneval(p1));");
/*fuzzSeed-246262462*/count=1182; tryItOut("Object.seal(this.e2);");
/*fuzzSeed-246262462*/count=1183; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 3.022314549036573e+23;\n    (Float32ArrayView[2]) = ((512.0));\n    return +((+((d2))));\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0, -0x07fffffff, 0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, 1, Math.PI, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, 0x100000001, -Number.MIN_VALUE, -0, 0/0, 0x0ffffffff, 0x07fffffff, -0x0ffffffff, 1.7976931348623157e308, 1/0, 0x080000001, Number.MIN_VALUE, 0x080000000, 2**53, -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), 42, -(2**53), 2**53-2, 2**53+2, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-246262462*/count=1184; tryItOut("\"use strict\"; true = a0[19];\u0009\nthis.h1.keys = (function() { Array.prototype.pop.apply(a0, [i1]); throw e1; });\n\nprint(uneval(a0));\n");
/*fuzzSeed-246262462*/count=1185; tryItOut("this.v2 = g2.eval(\"for (var p in o1.o2) { t1[5] = this.m0; }\");");
/*fuzzSeed-246262462*/count=1186; tryItOut("\"use strict\"; s0 = new String(t2);");
/*fuzzSeed-246262462*/count=1187; tryItOut("\"use strict\"; ;");
/*fuzzSeed-246262462*/count=1188; tryItOut("\"use strict\"; t1 = new Uint16Array(v1);");
/*fuzzSeed-246262462*/count=1189; tryItOut("h1 = ({getOwnPropertyDescriptor: function(name) { return p2; var desc = Object.getOwnPropertyDescriptor(t2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { h0.get = f2;; var desc = Object.getPropertyDescriptor(t2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { /*MXX1*/o0 = g0.Set.prototype.has;; Object.defineProperty(t2, name, desc); }, getOwnPropertyNames: function() { return h2; return Object.getOwnPropertyNames(t2); }, delete: function(name) { this.g1.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8) { a6 = 7 & a6; var r0 = 0 | a7; var r1 = 3 / 7; var r2 = a1 | 1; a3 = 9 + a6; a1 = a3 + 4; var r3 = 7 ^ 3; var r4 = a7 & 5; a4 = a2 / a6; var r5 = a1 ^ 7; var r6 = a8 | 1; r5 = 5 % a0; var r7 = a3 | a1; var r8 = 6 - 7; print(a0); x = a5 * r4; var r9 = r6 | r0; a8 = r6 / r2; a1 = x * r5; var r10 = r4 + r0; var r11 = a2 | 7; var r12 = r4 + 5; var r13 = a8 * 5; a6 = 6 | r11; print(a6); var r14 = a1 + a6; var r15 = r3 % 4; var r16 = 1 % a3; var r17 = r13 / 5; var r18 = 3 + 5; var r19 = 0 | r15; var r20 = r2 / r17; a1 = 0 + a5; var r21 = r8 % 9; var r22 = r2 * r1; var r23 = a0 | a1; var r24 = r20 & r0; var r25 = a2 ^ a4; var r26 = 1 - a6; x = 5 ^ 4; r12 = r20 - 1; var r27 = r21 ^ 2; r15 = a3 / 9; var r28 = r20 & 2; var r29 = r13 & r22; r14 = r4 & r7; var r30 = r14 | a8; var r31 = 7 - 8; r11 = a5 * r26; var r32 = 0 % 2; var r33 = a3 * 2; r13 = 8 / r8; var r34 = r31 * r12; var r35 = 6 & r15; var r36 = r1 / a0; var r37 = r29 ^ 6; var r38 = 2 ^ 4; r10 = r27 * 5; var r39 = r38 ^ r9; var r40 = r22 - r20; var r41 = r25 / 8; var r42 = r41 ^ r5; var r43 = 2 & r36; var r44 = 1 - r19; return a0; });; return delete t2[name]; }, fix: function() { t0[4];; if (Object.isFrozen(t2)) { return Object.getOwnProperties(t2); } }, has: function(name) { this.v1 = evaluate(\"m0 = new Map;\", ({ global: g1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 6 == 5), sourceIsLazy: ((x) =  ''  -= (void options('strict_mode')).__defineSetter__(\"x\", ( ) =  /x/ )), catchTermination: false }));; return name in t2; }, hasOwn: function(name) { v1 = new Number(4.2);; return Object.prototype.hasOwnProperty.call(t2, name); }, get: function(receiver, name) { h1.hasOwn = f0;; return t2[name]; }, set: function(receiver, name, val) { g2.t0 = new Float32Array(t2);; t2[name] = val; return true; }, iterate: function() { for (var v of h2) { try { v1 = undefined; } catch(e0) { } try { this.a1 = new Array; } catch(e1) { } e0.delete(b1); }; return (function() { for (var name in t2) { yield name; } })(); }, enumerate: function() { /*RXUB*/var r = r0; var s = \"\\n\\n\\n\\naa\"; print(s.split(r)); print(r.lastIndex); ; var result = []; for (var name in t2) { result.push(name); }; return result; }, keys: function() { this.o1.v1 = g1.runOffThreadScript();; return Object.keys(t2); } });");
/*fuzzSeed-246262462*/count=1190; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return ( - Math.fround(Math.max(Math.atanh((( + (Math.min(( + -1/0), ( + ((x + x) | 0))) | 0)) | 0)), (Math.sign(((( - (x | 0)) | 0) | 0)) | 0)))); }); testMathyFunction(mathy3, [0.000000000000001, 0x100000000, 1.7976931348623157e308, -0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, Number.MAX_VALUE, 0x07fffffff, 0x080000001, 0x100000001, -0, -Number.MIN_VALUE, 0, -0x0ffffffff, -0x080000001, 2**53+2, 1, 0x0ffffffff, 0/0, -0x100000000, 2**53-2, 2**53, Number.MIN_VALUE, -(2**53), 1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0]); ");
/*fuzzSeed-246262462*/count=1191; tryItOut("f1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      d1 = (d1);\n    }\n    i0 = (i0);\n    i2 = (i2);\n    switch (((((1048575.0) < (16777217.0))*-0x822c9) ^ ((0x973271d3)-(0x70fd3b9a)-(0x7bd32a9d)))) {\n      case 0:\n        return +((((NaN)) % ((Float32ArrayView[1]))));\n        break;\n      case -1:\n        {\n          (Float64ArrayView[1]) = ((+atan2(((+/*FFI*/ff(((((4277)) | ((i2)))), (((((d1))) << ((0x630e75a3) % (w = x.yoyo(([window])))))), (((-128.0) + (d1))), (((34359738367.0) + (-3.094850098213451e+26)))))), ((d1)))));\n        }\n        break;\n      case 1:\n        d1 = (-6.189700196426902e+26);\n        break;\n      case -2:\n        d1 = (d1);\n        break;\n      default:\n        i2 = (i0);\n    }\n    i2 = (/*FFI*/ff(((((((i0) ? (i0) : ((17179869184.0) == (-1.2089258196146292e+24))) ? (i0) : (0xfb751d7a)))|0)), ((0x5712d706)))|0);\n    return +((+(((((i0))>>>(((0x82284edd) == (((0x9c1e81e0))>>>((-0x7c6a193)))))) / (((0x56c21b08)+(i2))>>>((-0x8000000))))>>>(((new Symbol((\u3056 = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: arguments.callee, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return []; }, delete: function(name) { return delete x[name]; }, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return []; }, }; })(this), encodeURI)))) != (((!(i2))+(i2)) ^ ((((0xf3c3029b)) ^ ((-0x8000000))) / (((0x904284cc)) | ((0xf92b105f))))))))));\n    {\n      d1 = (-16385.0);\n    }\n    i2 = ((-1.9342813113834067e+25) <= (+(((i0)) & ((0xf9abaf36)-(i2)-(0x8463cd6b)))));\n    return +((-((d1))));\n    i0 = (i0);\n    i0 = (0xad728e80);\n    i0 = (0xfb0840b4);\n    return +((NaN));\n  }\n  return f; })(this, {ff: Math.tanh}, new SharedArrayBuffer(4096));");
/*fuzzSeed-246262462*/count=1192; tryItOut("\"use strict\"; ;");
/*fuzzSeed-246262462*/count=1193; tryItOut("v2 = Array.prototype.reduce, reduceRight.call(a2, a0, (offThreadCompileScript));");
/*fuzzSeed-246262462*/count=1194; tryItOut("");
/*fuzzSeed-246262462*/count=1195; tryItOut("o2.m0 = new Map(h1);");
/*fuzzSeed-246262462*/count=1196; tryItOut("\"use strict\"; /*iii*/{ if (isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions(); } void 0; }/*hhh*/function xjkqub(window = (timeout(1800)), ...window){v0 = m0[\"call\"];function x() { print(x); } v2 = t0.length;}");
/*fuzzSeed-246262462*/count=1197; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((Math.max(Math.abs(( + ( - (0/0 | 0)))), ( + Math.exp(( + (1.7976931348623157e308 !== ( - ( + x))))))) | 0) | (( ~ (mathy3((( + Math.sign(( + (( + Math.hypot(( + y), ( + x))) ? y : y)))) | 0), (((( + (Math.clz32(( + 0x100000000)) >>> 0)) * ( + ( ! y))) >>> 0) | 0)) | 0)) | 0)); }); ");
/*fuzzSeed-246262462*/count=1198; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.acos(Math.fround(((( + Math.asinh(( + ( ! ( + 0.000000000000001))))) & ( + ( ! x))) >>> 0)))); }); testMathyFunction(mathy5, [-1/0, Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 1/0, 2**53, 0/0, 0x0ffffffff, 0x100000000, Number.MAX_VALUE, 42, Number.MIN_VALUE, 0x080000001, 0x100000001, 2**53+2, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -0x07fffffff, 0x080000000, 0x07fffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1, 2**53-2, 0, -0x100000000, -Number.MAX_VALUE, -0, 0.000000000000001, -0x100000001, Math.PI]); ");
/*fuzzSeed-246262462*/count=1199; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, 0x100000000, -(2**53+2), -0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, 2**53, 0.000000000000001, 0x0ffffffff, Number.MAX_VALUE, -(2**53-2), -0x07fffffff, 0x080000001, 0/0, -(2**53), Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 1/0, 0, 0x07fffffff, 1, 2**53-2, 0x080000000, -0, -0x080000000, 42, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=1200; tryItOut("mathy3 = (function(x, y) { return (mathy0(( + Math.log2((( ~ (Math.atan2(x, -0) | 0)) | 0))), ( ! Math.min((Math.max(((x >= (x + (mathy0((Number.MAX_SAFE_INTEGER >>> 0), (x >>> 0)) >>> 0))) | 0), ((( + (x >>> 0)) | 0) | 0)) | 0), ((Math.expm1((Math.cosh(x) | 0)) | 0) | 0)))) | 0); }); testMathyFunction(mathy3, /*MARR*/[false, false, false, false, 4., false, false, false, false, false, false, 4., false, 4., 4., false, 4., 4., 4., false, 4., false, false, false, false, 4., 4., false, false, 4., 4., false, false, 4., false, 4., 4., 4., 4., 4., 4., 4., 4., 4., 4., false, false, 4., false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, 4., false, false, false, 4., false, false, false, false, 4., false, false, false, false, false, 4., false, false, false, false, 4., false, 4., false, 4., false, false, 4.]); ");
/*fuzzSeed-246262462*/count=1201; tryItOut("a0.shift(o0, v2, m2);");
/*fuzzSeed-246262462*/count=1202; tryItOut("mathy1 = (function(x, y) { return Math.atan2(( + mathy0((Math.cosh(Math.atan2(Math.fround(Math.cos(( + x))), Math.fround(( + Math.fround(y))))) | 0), (((y >>> 0) >= (( + Math.hypot(( + Math.imul(x, x)), ( + y))) | 0)) | 0))), ((0/0 << mathy0(y, 0x07fffffff)) < ( ~ ((( ~ (y >>> 0)) >>> 0) | 0)))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -0x080000001, -(2**53-2), 42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, 0/0, 0x100000001, 1, 0x100000000, -0x100000001, 1/0, 2**53, -(2**53), -0x0ffffffff, -1/0, -0x080000000, 0x07fffffff, 2**53+2, -(2**53+2), 2**53-2, 0x0ffffffff, -Number.MAX_VALUE, 0x080000000, -0x07fffffff, -0x100000000, 0.000000000000001, -Number.MIN_VALUE, -0]); ");
/*fuzzSeed-246262462*/count=1203; tryItOut("\"use strict\"; var xtulpr, x = (x <= (Math.expm1(let (b = 15) -5 &= (4277)).yoyo(x)) >= (z = x)), y = new RegExp(\"([])*\", \"g\").__defineSetter__(\"x\", DataView), eval, gsiotx, a = ((of | b) < x), elrydg;o0 = {};");
/*fuzzSeed-246262462*/count=1204; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    {\n      i0 = ((((0xe2072008) % (0xa9facc41))>>>((((0xbffb552) % (0x2999863e)) ^ ((i0)+(i0))) % (imul((/*FFI*/ff(((~((0xd998c79c)))), ((-2047.0)), ((4611686018427388000.0)), ((-36028797018963970.0)), ((-1.1805916207174113e+21)), ((-1.015625)), ((8388609.0)), ((-2199023255553.0)), ((1048577.0)), ((-3.094850098213451e+26)), ((-8796093022209.0)), ((-2251799813685249.0)), ((-1.5111572745182865e+23)), ((-9.44473296573929e+21)), ((-1.888946593147858e+22)), ((-144115188075855870.0)), ((576460752303423500.0)))|0), ((0x63a7a4e) < (0xc96cd80f)))|0))) >= (0xa9081291));\n    }\n    return (((i0)+(0xffffffff)))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy3, ['0', '/0/', -0, '', (new Number(0)), 1, ({toString:function(){return '0';}}), (new Boolean(false)), '\\0', false, objectEmulatingUndefined(), 0.1, [], null, NaN, (function(){return 0;}), ({valueOf:function(){return '0';}}), 0, [0], ({valueOf:function(){return 0;}}), /0/, (new Boolean(true)), (new Number(-0)), undefined, true, (new String(''))]); ");
/*fuzzSeed-246262462*/count=1205; tryItOut("mathy4 = (function(x, y) { return ( + ((Math.imul((Math.fround(Math.hypot(((x % x) | 0), (((y == Math.fround(Number.MAX_SAFE_INTEGER)) | 0) | 0))) >>> 0), ((Math.fround(Math.expm1((( - ((x != ( + x)) >>> 0)) || (y !== y)))) - ( + ( + 1/0))) >>> 0)) >>> 0) === ( + ( - Math.fround(Math.acos(Math.fround(Math.cos(Math.fround(-Number.MIN_SAFE_INTEGER))))))))); }); testMathyFunction(mathy4, [Math.PI, 0.000000000000001, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, 42, 1, 0, 0x07fffffff, 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 2**53, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, 0/0, -0x100000000, 0x080000000, -(2**53-2), -0x0ffffffff, 0x080000001, 0x100000001, 2**53-2, -(2**53+2), -Number.MAX_VALUE, 0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-246262462*/count=1206; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return (((((((Math.pow(((((((x >>> 0) & (y >>> 0)) >>> 0) ? x : -0) !== y) >>> 0), (y >>> 0)) >>> 0) | 0) >> ((Math.pow((Math.hypot(y, x) >>> 0), ((x && Math.min(( ~ x), Math.PI)) >>> 0)) >>> 0) >>> 0)) | 0) >>> 0) , (mathy1(Math.trunc(Math.fround(Math.hypot(Math.hypot(( - (Math.clz32(x) | 0)), -1/0), ( + Math.clz32(Math.fround(x)))))), (Math.fround(((Math.log1p(x) >= Math.fround(x)) , y)) | 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-246262462*/count=1207; tryItOut("s0 = a2[3];");
/*fuzzSeed-246262462*/count=1208; tryItOut("\"use strict\"; /*RXUB*/var r = /\\b+/; var s = \"1\\u00ab\"; print(s.match(r)); ");
/*fuzzSeed-246262462*/count=1209; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( ~ (( + (( + Math.imul(Math.hypot(( + x), ( + ( ~ Math.fround(Math.pow(Math.fround(mathy0(x, x)), ( + x)))))), Math.log2(mathy0((y >>> 0), (x >>> 0))))) >= ( + Math.hypot(Math.fround(((y >>> 0) + (Math.fround(Math.pow(Math.fround(y), Math.fround(y))) ? y : Math.fround((x << y))))), (( - (-0 | 0)) | 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[undefined, undefined, x, undefined, x, {}, {}, x, x, undefined, x, undefined, undefined, {}, {}, undefined]); ");
/*fuzzSeed-246262462*/count=1210; tryItOut("\"use strict\"; b1 = new ArrayBuffer(12);");
/*fuzzSeed-246262462*/count=1211; tryItOut("a0.__proto__ = v0;");
/*fuzzSeed-246262462*/count=1212; tryItOut("\"use asm\"; g2.offThreadCompileScript(\"mathy0 = (function(x, y) { return Math.sign(( + ( ~ Math.max(y, ( ~ ( + ( ! ( + Math.fround(( + Math.fround(2**53-2))))))))))); }); testMathyFunction(mathy0, [0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, -0x07fffffff, 0x080000001, 1/0, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, -(2**53), 0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x100000000, 0x100000001, -(2**53-2), 0.000000000000001, Number.MIN_VALUE, 1, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000001, -0, -0x080000000, -0x100000001, 0/0, 0x100000000, -Number.MIN_VALUE, -1/0, 0x0ffffffff, Math.PI]); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 28 == 20), noScriptRval: false, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-246262462*/count=1213; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.max(Math.fround(( - ((y - y) >>> 0))), ((( + Math.max(42, -0x07fffffff)) ? ((x >> ( + -0x0ffffffff)) <= Math.cosh(x)) : (Math.atan2((Math.fround(Math.imul(Math.fround(((( - (x >>> 0)) >>> 0) === x)), Math.fround((Math.sinh(Math.imul(x, y)) | 0)))) | 0), (( + y) | 0)) | 0)) | 0))); }); ");
/*fuzzSeed-246262462*/count=1214; tryItOut("/*RXUB*/var r = this.r0; var s = s0; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=1215; tryItOut("x = (4277), x = \"\\uEA8F\", z = window, x, x = y - c, zwsrfq;v0 = (this.i0 instanceof s0);");
/*fuzzSeed-246262462*/count=1216; tryItOut("\"use strict\"; /*RXUB*/var r = /.|([^\u00fc\\S]\\b\ubaf9$)+(?!(?!(?!\uc46e)))*?{2,}(\\3)[^]+\\1\\w|\\3*{3}|[\\\u00d5-\\\u189e\u2562\\u2AAF-\ufdcd]|(?:(?!\\b|\\D|(?=\\B)).)/gyi; var s = \"\\n\\uc46e\\uc46e\\n\\uc46e\\uc46e\\n\\uc46ePPa\\ubaf9\\n0aaaaa\"; print(s.search(r)); ");
/*fuzzSeed-246262462*/count=1217; tryItOut("\"use strict\"; { void 0; try { (enableSingleStepProfiling()) } catch(e) { } }");
/*fuzzSeed-246262462*/count=1218; tryItOut("{a2.unshift(b1); }");
/*fuzzSeed-246262462*/count=1219; tryItOut("mathy3 = (function(x, y) { return Math.exp((Math.fround(( + Math.max(( + x), ( + Math.sinh(1))))) & Math.fround(Math.max(( + (( + y) % ( + x))), ((Number.MAX_VALUE / (( + x) | ( + x))) ^ (mathy2(y, ( + Math.sign(y))) <= Math.cosh(y))))))); }); testMathyFunction(mathy3, [-(2**53-2), 1/0, 1.7976931348623157e308, -0x100000001, Number.MIN_VALUE, 0x080000001, -0, 0x100000001, -0x0ffffffff, 1, 2**53-2, -(2**53+2), -0x080000001, 0x100000000, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, -Number.MAX_VALUE, 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, Math.PI, -1/0, 0/0, 2**53, Number.MIN_SAFE_INTEGER, 0.000000000000001, 42]); ");
/*fuzzSeed-246262462*/count=1220; tryItOut("print({} = (makeFinalizeObserver('nursery')));");
/*fuzzSeed-246262462*/count=1221; tryItOut("print( /x/ );\n4;\n");
/*fuzzSeed-246262462*/count=1222; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log((Math.min((Math.fround(( + 0/0)) | 0), ( + Math.cbrt(Math.hypot((y >>> 0), (y >>> 0))))) | 0)); }); testMathyFunction(mathy3, [-0x07fffffff, 2**53+2, 0.000000000000001, -0x0ffffffff, 42, 0x100000000, -0, -(2**53-2), -Number.MIN_VALUE, Math.PI, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, -0x100000000, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, -0x100000001, 0x080000001, -0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 0x0ffffffff, 0, -(2**53), 0x07fffffff, 0x080000000, -(2**53+2), 1, 0x100000001, 0/0, Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=1223; tryItOut("a1.reverse();");
/*fuzzSeed-246262462*/count=1224; tryItOut("for([w, e] = true in (NaN = window).yoyo(function  NaN (y, eval) { yield  ''  } .prototype)) {v2 = a1.length; }");
/*fuzzSeed-246262462*/count=1225; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x080000000, 0.000000000000001, 0x080000001, -0, -0x080000001, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, 0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0, 1, 2**53-2, Math.PI, -(2**53), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0x0ffffffff, 2**53+2, -(2**53+2), 42, 1/0, Number.MIN_VALUE, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 0x100000000, 0/0, -0x080000000]); ");
/*fuzzSeed-246262462*/count=1226; tryItOut("/*infloop*/for((4277); true;  '' ) Object.defineProperty(this, \"v2\", { configurable: \"\\u60E3\", enumerable: (x % 55 != 23),  get: function() {  return g1.runOffThreadScript(); } });");
/*fuzzSeed-246262462*/count=1227; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[[(void 0)], (window.w+=(window = undefined)), (void 0), (void 0), eval, eval, eval,  /x/g , (void 0), eval,  /x/g , [(void 0)]]) { /*MXX1*/o1 = g0.SyntaxError.prototype.toString; }");
/*fuzzSeed-246262462*/count=1228; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.abs(Math.max(( ~ (Math.max((((( - Math.expm1(x)) >>> 0) / ((( + (( + x) >= ( + y))) > y) >>> 0)) >>> 0), (y !== x)) >>> 0)), ( + Math.atanh(Math.fround(( + (( + x) && ( + y)))))))); }); testMathyFunction(mathy4, /*MARR*/[2**53+2, true, true,  /x/ , true, true, 2**53+2, x, x, x, 2**53+2, new Number(1.5), true, new Number(1.5), new Number(1.5), x,  /x/ , 2**53+2, true, true, 2**53+2, x, true, 2**53+2, true,  /x/ , 2**53+2, true,  /x/ , 2**53+2,  /x/ , 2**53+2, 2**53+2,  /x/ , true, new Number(1.5), true, true, 2**53+2, new Number(1.5), new Number(1.5), true, 2**53+2,  /x/ , 2**53+2, new Number(1.5),  /x/ , x, new Number(1.5), new Number(1.5), 2**53+2,  /x/ , true,  /x/ , 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, x, x, new Number(1.5), true,  /x/ ,  /x/ , x, x, 2**53+2, true, x,  /x/ ,  /x/ , new Number(1.5), true, 2**53+2, true, 2**53+2, true, 2**53+2, x, new Number(1.5),  /x/ , 2**53+2, 2**53+2, x, new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , x,  /x/ , 2**53+2, 2**53+2, true,  /x/ , 2**53+2, new Number(1.5)]); ");
/*fuzzSeed-246262462*/count=1229; tryItOut("mathy4 = (function(x, y) { return (mathy1(Math.hypot(Math.hypot(( + x), ( + (Math.atan2((x | 0), Math.fround(Math.fround(Math.fround((y != Math.fround(x)))))) >>> 0))), Math.min((Math.cbrt((( ! ( + (( + Math.fround(( + Math.fround(y)))) % x))) >>> 0)) >>> 0), x)), (Math.acos((Math.tan((Math.fround((Math.fround(y) << Math.fround(Math.sinh(y)))) >>> 0)) >>> 0)) >= (Math.cosh((x >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, -0, Number.MIN_VALUE, 0x080000001, 1/0, -0x080000001, -0x080000000, -0x100000001, 0x100000000, -1/0, -Number.MIN_VALUE, -0x100000000, 2**53, 0x07fffffff, 0.000000000000001, 42, -(2**53+2), 1.7976931348623157e308, 0, 0x080000000, -(2**53-2), 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), 2**53+2, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, 0x100000001, 1, Math.PI]); ");
/*fuzzSeed-246262462*/count=1230; tryItOut("\"use strict\"; for(var [a, w] = (4277) in (this.zzz.zzz) = /*UUV1*/(z.unshift = Array.prototype.toString)) e0.add(g1.b2);");
/*fuzzSeed-246262462*/count=1231; tryItOut("g1 = this;");
/*fuzzSeed-246262462*/count=1232; tryItOut("x = (x ^= x), xiqdyr, w, setter, x, sjdkab, yxyfcn, x;(\"\\uA8A8\");");
/*fuzzSeed-246262462*/count=1233; tryItOut("\"use strict\"; yield this.__defineSetter__(\"\\\"-1399179295\\\"\", new RegExp(\"$\\\\b|.|\\\\u3A20{2,}|(?!\\\\b{4}|(?:\\\\S))|([^]){0,2}+\", \"yim\"));");
/*fuzzSeed-246262462*/count=1234; tryItOut("g0.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 4 != 0), noScriptRval: this.__defineSetter__(\"x\", Math.log1p), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-246262462*/count=1235; tryItOut("print(12);\n/(?:\\2)/y;\n");
/*fuzzSeed-246262462*/count=1236; tryItOut("v1.toString = (function() { for (var j=0;j<26;++j) { f1(j%3==1); } });");
/*fuzzSeed-246262462*/count=1237; tryItOut("v2 = t2.byteLength;");
/*fuzzSeed-246262462*/count=1238; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((((( + Math.asin(( + ( - ( + ( ~ ( + x))))))) | 0) | (Math.round(mathy0(-0x07fffffff, Math.tanh((Math.ceil(x) >>> 0)))) | 0)) | 0) <= ((((Math.ceil((((((y | 0) == (x | 0)) | 0) * 2**53) | 0)) | 0) ? ( + y) : Math.tanh((-Number.MAX_SAFE_INTEGER | 0))) / (Math.fround(x) >> (Math.min(x, ((Math.tan(x) >>> 0) >>> 0)) >>> 0))) ? Math.ceil((( ~ ( + Math.hypot((-Number.MIN_VALUE | 0), (( ! (y >>> 0)) | 0)))) >>> 0)) : Math.asin((-0x07fffffff * 1)))); }); testMathyFunction(mathy1, [-0x080000000, 2**53-2, 1.7976931348623157e308, 0x100000000, Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, -(2**53+2), -0, -0x100000000, -1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, -(2**53), -0x080000001, -Number.MIN_VALUE, 2**53+2, 42, 0, 0x080000001, 2**53, Math.PI, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000001, -(2**53-2), 0x0ffffffff, Number.MAX_VALUE, 0x07fffffff, 0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=1239; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy0(Math.max(( + ((Math.atan(((x >= (x | 0)) | 0)) | 0) % mathy1((Math.asinh(x) >>> 0), 2**53-2))), (y ** ( ~ (y | 0)))), ( + ( + Math.fround(((( + (( - y) * x)) >>> 0) ? (Math.sinh(( - Math.fround(( ! Number.MIN_VALUE)))) >>> 0) : ( + (Math.pow(mathy1((y | 0), x), Math.fround(Math.log(Math.fround(y)))) - x))))))); }); testMathyFunction(mathy2, /*MARR*/[x, function(){},  'A' ]); ");
/*fuzzSeed-246262462*/count=1240; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return ( + mathy4(( + Math.max(( + ( ! (y >>> 0))), Math.fround((Math.min(x, (((Math.max(x, y) | 0) ? y : (y << ( + Number.MAX_VALUE))) >>> 0)) >>> 0)))), Math.fround(Math.log1p(Math.fround(( + Math.pow(-Number.MIN_SAFE_INTEGER, Math.sin(y)))))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, -0x07fffffff, -0x0ffffffff, 0/0, 0x080000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -1/0, 0.000000000000001, 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, -0, -(2**53+2), -0x100000000, 2**53-2, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, -(2**53-2), 1, 42, -0x080000001, 0x100000001, 2**53+2, Math.PI, -(2**53)]); ");
/*fuzzSeed-246262462*/count=1241; tryItOut("mathy4 = (function(x, y) { return mathy2(Math.min(( + Math.atan2(Math.fround(Math.min(Math.fround((( + ((( + (x | 0)) | 0) | 0)) | 0)), Math.fround(y))), (1/0 / ( + -0x0ffffffff)))), ( + Math.acos(( + ((((x >> (x | 0)) | 0) >>> 0) || mathy0(0x100000000, -0x100000000)))))), (( ~ Math.max((y < Math.cosh(x)), (Math.fround(Math.cbrt(Math.fround((( + y) > 2**53-2)))) , Math.fround(Math.min(x, 42))))) >>> 0)); }); ");
/*fuzzSeed-246262462*/count=1242; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - Math.log2(( ! ((((1.7976931348623157e308 >> (Math.tanh(Math.fround(Math.asinh(Math.fround(x)))) >>> 0)) >>> 0) < (1 ? (-0x07fffffff >>> 0) : (Math.fround(Math.ceil(-0x100000001)) >>> 0))) >>> 0)))); }); testMathyFunction(mathy0, [0.000000000000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000001, -0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), 0, -0x07fffffff, 0x07fffffff, 1.7976931348623157e308, -(2**53), 0x080000000, 2**53, 1/0, 2**53+2, -Number.MAX_VALUE, -0x100000000, -0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_VALUE, 0/0, -0x100000001, -1/0, 42, Math.PI, 0x100000000]); ");
/*fuzzSeed-246262462*/count=1243; tryItOut("m0 + b1;");
/*fuzzSeed-246262462*/count=1244; tryItOut("\"use strict\"; ");
/*fuzzSeed-246262462*/count=1245; tryItOut("/*RXUB*/var r = /(?!(?:.))|\\cY+|..(?=\\B*?\\B)|^*|(?:\\3{2,})*?[^]|$|((?!\\B)?)|[^]/gi; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-246262462*/count=1246; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( - ( + ( ! ( + (mathy0((Number.MIN_VALUE | 0), (Math.atan2((y ^ x), Math.sin(Math.fround(7))) | 0)) | 0))))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, -(2**53+2), Math.PI, 1/0, 0.000000000000001, 0x100000001, -0, 0/0, 1, 0x080000001, -0x0ffffffff, -0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 42, -(2**53), Number.MIN_VALUE, 2**53+2, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 0, 2**53, 0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-246262462*/count=1247; tryItOut("/* no regression tests found */");
/*fuzzSeed-246262462*/count=1248; tryItOut("/*tLoop*/for (let d of /*MARR*/[new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), {}, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), {}, {}, new Number(1.5), {}, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, objectEmulatingUndefined(), {}, new Number(1.5), new Number(1.5), {}, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), {}, {}, {}, {}, new Number(1.5), new Number(1.5), {}, new Number(1.5), {}, new Number(1.5), {}, {}, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), {}, new Number(1.5), {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), {}, {}, new Number(1.5), {}, {}, {}, new Number(1.5), objectEmulatingUndefined(), {}, {}, new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), {}, new Number(1.5), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {}, {}, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), {}, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), {}]) { print(x); }");
/*fuzzSeed-246262462*/count=1249; tryItOut("(\u3056 = c & x);");
/*fuzzSeed-246262462*/count=1250; tryItOut("f0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var atan = stdlib.Math.atan;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 2.0;\n    var d3 = -4097.0;\n    {\n      /*FFI*/ff(((((i0)-((d1) < (d1)))|0)), ((((i0)) | ((!(0x1f8a14f8))+(i0)))));\n    }\n    i0 = ((((!(/*FFI*/ff(((d1)), ((Infinity)), ((((0xffffffff)) ^ ((0xa86e4faa)))), ((3.022314549036573e+23)), ((17179869185.0)))|0))+((((+(-1.0/0.0)) + (+atan(((Float32ArrayView[0])))))))) | (((i0) ? (i0) : ((((0xfe2c4963))>>>((0xf981a6d0))))))) < (((((-(0x9c03c6e))>>>((0xc5fce7f)-(0x21498a4f)+(0xedda06d9))) <= (((-0x8000000)+(0xc0a18a25))>>>((i0))))-((((0xd4fee1c9)+(0xfc264f6e))>>>((0xf169229))) != ((0xfffff*(0xffffffff))>>>((-0x8000000)+(0xffffffff))))) & ((d1))));\n    return (((i0)+(i0)))|0;\n  }\n  return f; })(this, {ff: ([(new Function.prototype)] & (timeout(1800)))}, new ArrayBuffer(4096));");
/*fuzzSeed-246262462*/count=1251; tryItOut("/*infloop*/for(NaN in  \"\" ) s2 + '';");
/*fuzzSeed-246262462*/count=1252; tryItOut("\"use strict\"; t0.set(t0, 11);delete h2.enumerate;");
/*fuzzSeed-246262462*/count=1253; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.imul(Math.fround(( + (( + ( + mathy0(( + Math.atan(x)), ( + x)))) >> ( + ( - x))))), Math.fround(Math.tan((Math.asinh((Math.fround(mathy1(Math.min(x, Number.MAX_SAFE_INTEGER), y)) | 0)) | 0))))); }); testMathyFunction(mathy3, [1/0, 0x080000000, -(2**53+2), -0, -0x100000001, 42, -0x07fffffff, 0x100000000, -1/0, Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, -0x100000000, -Number.MAX_VALUE, 2**53+2, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 0x080000001, 1.7976931348623157e308, 1, -(2**53), -0x080000000, 0.000000000000001, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 2**53, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=1254; tryItOut("mathy5 = (function(x, y) { return ( + ( + Math.max(Math.max(((Math.atan2(0x100000000, (Math.fround(mathy2((x | 0), y)) >>> 0)) >>> 0) >>> 0), (( ! Math.atan2(x, 42)) >>> 0)), mathy3(Math.fround(Math.fround((Math.fround(Math.imul(2**53+2, (Math.min(((Math.atanh((y >>> 0)) >>> 0) | 0), (x | 0)) | 0))) | Math.fround(mathy2(y, -(2**53-2)))))), (Math.cbrt(( + 2**53-2)) != x))))); }); ");
/*fuzzSeed-246262462*/count=1255; tryItOut("\"use asm\"; this.f2(v1);");
/*fuzzSeed-246262462*/count=1256; tryItOut("v0 = Array.prototype.every.apply(a2, [h1, this.b2, a2, this.g2.o1.s2, m2]);");
/*fuzzSeed-246262462*/count=1257; tryItOut("\"use strict\"; a1 = new Array;");
/*fuzzSeed-246262462*/count=1258; tryItOut("mathy4 = (function(x, y) { return Math.cbrt(Math.fround(Math.hypot(Math.fround((Math.log(((( ~ mathy2(x, (-Number.MIN_VALUE | 0))) | 0) >>> 0)) >>> 0)), ((y != Math.imul((( - (Number.MAX_VALUE ? y : Math.fround(2**53+2))) | 0), x)) >>> 0)))); }); testMathyFunction(mathy4, [-0x100000001, 0, 2**53, 0x100000001, -0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1, 42, -Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, 1/0, 0.000000000000001, -(2**53), -0x0ffffffff, 0x07fffffff, 0x100000000, -(2**53+2), 2**53-2, -0x080000000, -0, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, -0x080000001, -1/0, -0x07fffffff, -(2**53-2), Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-246262462*/count=1259; tryItOut("a0.forEach((function(a0) { var r0 = x % a0; print(r0); var r1 = a0 - x; var r2 = a0 & r1; var r3 = r1 | x; var r4 = 9 / r3; var r5 = 4 | r0; r5 = 0 + r1; var r6 = 6 / 0; var r7 = 9 + 1; var r8 = r6 * r2; r3 = 2 % r3; var r9 = 1 & r1; var r10 = r2 | 2; var r11 = 7 ^ r6; x = 3 % 8; var r12 = 7 | r10; r6 = r10 % 2; var r13 = r10 ^ r12; print(r2); var r14 = r11 + 6; r0 = r6 % r11; var r15 = 1 % r4; var r16 = r14 ^ r14; var r17 = r11 + a0; var r18 = r9 & r1; var r19 = r6 ^ r5; r14 = 2 | r4; var r20 = r17 - r9; var r21 = 2 & r13; var r22 = 4 % 6; r14 = r16 ^ r3; var r23 = r3 % r8; var r24 = x ^ r0; var r25 = r18 + r4; var r26 = 9 & 8; var r27 = r19 % 0; var r28 = r3 + 8; r7 = x * r14; var r29 = 8 ^ r12; var r30 = 2 % 7; r9 = r9 * 9; var r31 = r13 - r4; var r32 = x | 4; var r33 = 4 | 8; var r34 = 3 - r25; r4 = 9 & r6; var r35 = 3 & a0; var r36 = r28 + 8; var r37 = r0 * r12; r6 = 7 - r33; var r38 = r20 & r2; var r39 = r35 - r12; var r40 = 1 + 2; print(r9); print(r2); var r41 = r0 - r20; var r42 = r9 * r10; a0 = r10 * r4; var r43 = r31 - 9; var r44 = r5 + r33; var r45 = r39 / r10; var r46 = r23 | 6; var r47 = 7 - r38; var r48 = r14 | r39; var r49 = r15 / r42; r25 = r49 * 9; var r50 = r25 + r9; r1 = r24 ^ r20; var r51 = 0 + r12; var r52 = r10 / 4; var r53 = r7 + r39; var r54 = r53 & r25; var r55 = r42 % r37; var r56 = r27 % 9; var r57 = r41 & r55; r7 = r50 * r29; var r58 = 8 | r8; r22 = r32 & r37; var r59 = 1 / r9; r13 = 7 % r17; var r60 = r53 % 9; var r61 = r15 - 2; var r62 = r34 & r35; var r63 = r15 / 2; var r64 = r9 / r14; var r65 = r54 | r63; var r66 = r57 - 6; var r67 = 1 ^ r33; var r68 = r4 + r37; var r69 = 5 - r37; r44 = r30 % 8; var r70 = r62 + r59; r20 = r5 * r11; print(r16); print(r67); var r71 = r41 * r41; r7 = r40 | r27; r46 = 1 - r43; var r72 = r7 / r37; var r73 = r37 | 4; r8 = r3 % r73; var r74 = r18 - r56; var r75 = r17 | r12; print(r53); var r76 = r13 * r11; var r77 = r44 ^ r56; var r78 = r8 / 8; var r79 = r53 / r21; r45 = r63 + 7; var r80 = 3 * r55; r8 = 6 + r12; r18 = r47 | r50; var r81 = r73 + r75; var r82 = 1 | r8; var r83 = 7 ^ r25; var r84 = r11 - r48; r81 = r54 / 8; var r85 = r64 & r8; var r86 = r38 + r75; var r87 = 3 / 2; r53 = r46 & 9; var r88 = 4 * 9; r42 = r10 / r49; var r89 = r50 | r43; var r90 = r57 + x; r16 = r63 + r85; var r91 = r79 & r88; var r92 = r2 ^ r66; var r93 = r17 & r72; var r94 = r80 - 4; var r95 = 0 + r54; print(r5); var r96 = r61 | r19; var r97 = 5 * 3; r22 = r93 / 8; var r98 = 9 | r65; return a0; }), /*UUV1*/(x.isSafeInteger = encodeURIComponent)());");
/*fuzzSeed-246262462*/count=1260; tryItOut("\"use strict\"; let (d) { with({}) return (uneval(window)); }");
/*fuzzSeed-246262462*/count=1261; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(Math.sqrt(( + (( + -(2**53)) >>> ( - mathy0((( + Math.hypot((y | 0), Math.expm1(( + x)))) >>> 0), ( + Math.clz32(x)))))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -0, -0x100000000, 0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, Math.PI, 0x0ffffffff, -Number.MIN_VALUE, 2**53, 0.000000000000001, 2**53-2, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 1/0, 0x100000001, 1, -1/0, -(2**53+2), Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, -0x080000000, -0x07fffffff, -0x0ffffffff, 0, 0x080000001, -0x100000001, -(2**53-2), 42, -(2**53), 2**53+2]); ");
/*fuzzSeed-246262462*/count=1262; tryItOut("\"use strict\"; ((Object.defineProperty(y, \"__proto__\", ({configurable: (x % 5 == 0), enumerable: true}))));");
/*fuzzSeed-246262462*/count=1263; tryItOut("mathy2 = (function(x, y) { return Math.fround(mathy0(Math.fround(Math.exp((((mathy1((((x >>> 0) != (y >>> 0)) >>> 0), y) | 0) , (Math.log10((((mathy0(x, y) | 0) !== mathy0((( ! x) >>> 0), x)) >>> 0)) | 0)) | 0))), Math.fround(Math.acos(Math.fround((( ~ ((Math.min((Math.fround(( ~ Math.fround(x))) | 0), (x | 0)) | 0) | 0)) >>> 0)))))); }); testMathyFunction(mathy2, [0x100000000, 1, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 2**53-2, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, 42, 2**53+2, 0x080000000, -(2**53), -0, 0/0, -0x100000001, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, 0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, -1/0, 0, 2**53, -0x07fffffff, 0x100000001, 0x080000001]); ");
/*fuzzSeed-246262462*/count=1264; tryItOut("s0 += 'x';");
/*fuzzSeed-246262462*/count=1265; tryItOut("testMathyFunction(mathy2, [42, 1, -(2**53-2), 0x07fffffff, Number.MIN_VALUE, 0x080000000, -0, -0x07fffffff, 0x080000001, 1/0, 2**53+2, 0x100000001, -0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, -0x080000001, 0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, 0/0, Number.MAX_VALUE, 2**53-2, -0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -0x100000000, Math.PI, 0x0ffffffff, 1.7976931348623157e308, 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=1266; tryItOut("a2.__proto__ = f0;");
/*fuzzSeed-246262462*/count=1267; tryItOut("\"use strict\"; /*bLoop*/for (let fbsgow = 0, pjuxol; fbsgow < 27; ++fbsgow) { if (fbsgow % 62 == 17) { /*tLoop*/for (let y of /*MARR*/[new String('q'), new String('q'), false,  '\\0' , objectEmulatingUndefined(),  '\\0' ,  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), false, objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(),  '\\0' , new String('q'), false, new String('q'), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, objectEmulatingUndefined(),  '\\0' , new String('q'), new String('q'), new String('q'),  '\\0' , new String('q'), objectEmulatingUndefined(),  '\\0' ,  '\\0' , new String('q'), new String('q'),  '\\0' ,  '\\0' , new String('q'), false,  '\\0' , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'),  '\\0' ,  '\\0' , new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , new String('q'), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]) { {} } } else { delete p1[\"setSeconds\"]; }  } ");
/*fuzzSeed-246262462*/count=1268; tryItOut("testMathyFunction(mathy2, [-0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, -0x100000000, 2**53-2, 0x080000001, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, -(2**53-2), 1.7976931348623157e308, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, 0x100000000, 0x07fffffff, 1, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 0/0, 0.000000000000001, 1/0, -0x080000001, 2**53, -(2**53+2), -0x080000000, -0x0ffffffff, 0x080000000, 0]); ");
/*fuzzSeed-246262462*/count=1269; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + Math.ceil((( ~ (Math.pow(x, ( + Math.min(( + Math.abs(Math.fround(y))), ( + y)))) >>> 0)) >>> 0))) , (Math.pow(( + Math.acosh((Math.pow((x | 0), (x | 0)) | 0))), Math.cos((-0x080000000 & ( + -(2**53-2))))) ? (Math.tanh(( ! ( + 0x07fffffff))) / ((Math.fround(Math.atan2(y, Math.fround((x , y)))) || Math.pow(Math.sqrt((Math.fround(( ! Math.fround(Math.PI))) >>> 0)), x)) >>> 0)) : ( + ( - ( + ((x ^ Math.fround((mathy1((Math.fround((-Number.MIN_SAFE_INTEGER - x)) | 0), (-Number.MIN_VALUE | 0)) | 0))) >>> 0))))))); }); testMathyFunction(mathy2, [-1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, -0x080000000, -0x07fffffff, 0, -(2**53+2), -0x0ffffffff, 2**53+2, 2**53-2, 0/0, 1.7976931348623157e308, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, 0x100000001, 42, -0, -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 1, Number.MAX_VALUE, -(2**53-2), 1/0, -(2**53), 0x080000001, 2**53, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=1270; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?:\\\\1))\", \"gy\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-246262462*/count=1271; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - Math.hypot(Math.asinh((y && (Math.exp(x) >>> 0))), ( + ( + Math.imul(( + y), ( + x)))))); }); testMathyFunction(mathy0, [-(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, -(2**53-2), Math.PI, 2**53, 0/0, -Number.MAX_VALUE, -0x0ffffffff, 42, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53-2, -(2**53), Number.MAX_VALUE, 0x100000001, -0x080000001, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, -0, -0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 1, -1/0, 0.000000000000001, 0x0ffffffff, 0x080000001, 1/0, -0x07fffffff, 0]); ");
/*fuzzSeed-246262462*/count=1272; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i1, o2);");
/*fuzzSeed-246262462*/count=1273; tryItOut("SyntaxError.prototype.name = a;x = e;");
/*fuzzSeed-246262462*/count=1274; tryItOut("o1.h1.__proto__ = t0;\nt0 = o0.a0[13];\n");
/*fuzzSeed-246262462*/count=1275; tryItOut("Object.defineProperty(this, \"v0\", { configurable: false, enumerable: false,  get: function() {  return a1.length; } });");
/*fuzzSeed-246262462*/count=1276; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.acosh(Math.min(( + mathy1(Math.fround(Math.sinh(Math.fround(Math.cos(x)))), Math.log10(mathy1(Math.fround(y), Math.fround(y))))), ((( + Math.pow(-Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER)) ? (mathy0(Math.fround(x), Math.acosh(x)) | 0) : y) | 0))); }); testMathyFunction(mathy4, [-(2**53+2), -0x0ffffffff, 1/0, 2**53+2, -(2**53), -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, -0x080000001, -0x080000000, 0x07fffffff, -1/0, 0x100000000, 0x080000001, -Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -0x100000000, -0x07fffffff, 0x100000001, 0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53, Math.PI, 2**53-2, 0/0, -(2**53-2), -0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-246262462*/count=1277; tryItOut("\"use strict\"; x = linkedList(x, 5621);");
/*fuzzSeed-246262462*/count=1278; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + Math.pow(( + Math.atanh((Math.max(Math.atan2(((y >>> 0) == (x >>> 0)), Math.imul(y, Math.fround(( + (y * x))))), (( + (Math.max((x | 0), (x | 0)) | 0)) | 0)) | 0))), ( + ( ! ((Math.atan2((2**53+2 | 0), (Math.cbrt(Math.fround((y <= Math.fround(x)))) | 0)) | 0) | 0))))) % Math.imul((((Math.clz32(Math.cosh(Math.fround(( ! Math.fround((((Number.MAX_SAFE_INTEGER >>> 0) * 0x07fffffff) >>> 0)))))) | 0) ? (Math.pow(x, Math.cosh(x)) | 0) : (Math.fround(Math.asin(0/0)) ? x : (Math.min(( + y), (x >>> 0)) >>> 0))) | 0), (((Math.min((( - y) >>> 0), (x >>> 0)) >>> 0) ? (Math.expm1(x) >>> 0) : (Math.pow(y, ( - (x >>> 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [-(2**53-2), -Number.MIN_VALUE, 0x100000000, 0/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 1, Math.PI, 0, -1/0, 2**53-2, 1/0, 0.000000000000001, -(2**53+2), 0x0ffffffff, 0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, 42, 1.7976931348623157e308, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 0x100000001, -0, Number.MAX_VALUE, -0x080000000, 0x080000001, -0x100000001]); ");
/*fuzzSeed-246262462*/count=1279; tryItOut("mathy5 = (function(x, y) { return (Math.acos(( + (( + Math.imul(( ~ Math.sinh(x)), Math.atan2(y, Math.fround(( ~ Math.fround(-0)))))) !== (((y >>> 0) ? (Math.fround(Math.exp(Math.fround(((y !== ((Math.log(-(2**53+2)) >>> 0) | 0)) | 0)))) >>> 0) : (mathy0(x, y) >>> 0)) >>> 0)))) >>> 0); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 2**53-2, -0, 1/0, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, 1.7976931348623157e308, 2**53, 0x07fffffff, -Number.MAX_VALUE, -0x100000001, -0x0ffffffff, 0x100000000, 1, 0x080000000, 0/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, -0x100000000, 2**53+2, -0x080000000, 0x0ffffffff, 0x080000001, -(2**53+2), 0x100000001, 0.000000000000001, 0, -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-246262462*/count=1280; tryItOut("t1[3] = --e;");
/*fuzzSeed-246262462*/count=1281; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.expm1(x); }); testMathyFunction(mathy5, /*MARR*/[(-1/0), (-1/0), new String(''), x, new String('')]); ");
/*fuzzSeed-246262462*/count=1282; tryItOut("\"use asm\"; for (var p in o2.t1) { try { o0.v1 = Object.prototype.isPrototypeOf.call(i2, o0.a0); } catch(e0) { } try { a2.unshift(g2.i1, p1); } catch(e1) { } a1 + f1; }");
/*fuzzSeed-246262462*/count=1283; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-246262462*/count=1284; tryItOut("\"use asm\"; /*infloop*/L: for (let NaN of \"\\uA0C0\") f1.toString = (function() { try { b0 + v1; } catch(e0) { } try { h2 = ({getOwnPropertyDescriptor: function(name) { v0 = (g1.v1 instanceof t0);; var desc = Object.getOwnPropertyDescriptor(o1.f1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { for (var v of a2) { (void schedulegc(this.g2)); }; var desc = Object.getPropertyDescriptor(o1.f1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v2 = (g1.a1 instanceof a0);; Object.defineProperty(o1.f1, name, desc); }, getOwnPropertyNames: function() { t2[1] = \"\\uDF08\";; return Object.getOwnPropertyNames(o1.f1); }, delete: function(name) { g1.g1.a2.shift(g1.p0, this.g0);; return delete o1.f1[name]; }, fix: function() { i2 + h2;; if (Object.isFrozen(o1.f1)) { return Object.getOwnProperties(o1.f1); } }, has: function(name) { v0 = a2.length;; return name in o1.f1; }, hasOwn: function(name) { return i0; return Object.prototype.hasOwnProperty.call(o1.f1, name); }, get: function(receiver, name) { v1 = Object.prototype.isPrototypeOf.call(o1, g1);; return o1.f1[name]; }, set: function(receiver, name, val) { g0.v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 3), noScriptRval: x, sourceIsLazy: false, catchTermination: (x % 4 != 1) }));; o1.f1[name] = val; return true; }, iterate: function() { Array.prototype.splice.apply(o0.a0, [NaN, 6, e0, i0, this.m2, g1.v2]);; return (function() { for (var name in o1.f1) { yield name; } })(); }, enumerate: function() { o1.v0 = evalcx(\";\", g1);; var result = []; for (var name in o1.f1) { result.push(name); }; return result; }, keys: function() { this.a1.sort((function() { try { Object.prototype.unwatch.call(p1, \"test\"); } catch(e0) { } try { /*RXUB*/var r = r2; var s = this.o2.s0; print(s.search(r));  } catch(e1) { } Object.seal(o1.s1); return o2; }), a0, t0, o2.t1);; return Object.keys(o1.f1); } }); } catch(e1) { } try { print(b1); } catch(e2) { } g0 = this; return g2.g1.o2; });");
/*fuzzSeed-246262462*/count=1285; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.max(Math.fround(Math.min(Math.fround(((( + ( ! ( + x))) ** Math.fround(( + Math.pow(( + ( + ( + Math.fround(y)))), ( + Math.log10((Math.ceil(y) | 0))))))) - y)), Math.fround(Math.atan2(( + Math.sinh(( + ( + mathy1(( + -Number.MAX_SAFE_INTEGER), Math.log1p(y)))))), Math.fround(x))))), Math.hypot(mathy1(x, Math.pow(Math.atan2(x, Math.asinh(((y >>> 0) != -(2**53+2)))), (( - y) || -0x100000000))), mathy0((Math.trunc((( ~ (y | 0)) | 0)) & y), x))); }); ");
/*fuzzSeed-246262462*/count=1286; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-246262462*/count=1287; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=1288; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var cos = stdlib.Math.cos;\n  var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    d1 = (-((+abs(((+abs(((Float64ArrayView[2])))))))));\n    {\n      i0 = (0xd64cbfe8);\n    }\n    d1 = (65.0);\n    d1 = (-8796093022209.0);\n    (Uint16ArrayView[2]) = ((0xfdf42248)+((+cos(((+(((0xf7ff481e))|0))))) >= (9.0))+(-0x8000000));\n    (Int8ArrayView[((0xffffffff)) >> 0]) = (((+((1.5474250491067253e+26))) <= (NaN))+(i0));\n    /*FFI*/ff((((i0) ? (d1) : (d1))), ((d1)), ((-262143.0)), ((-6.044629098073146e+23)), ((~~(+(((0x4f983e5)) & ((0x18b92799)))))), ((+(1.0/0.0))), ((((0xfd2c158e)) << ((0xffffffff)))), ((536870913.0)));\n    d1 = (-36028797018963970.0);\n    d1 = ((((((0xffdc012b)+((imul((i0), ((0x546a5e11) != (0x787a57f0)))|0))-(!(i0))) << (()-(i0))) < (abs(((((~((i0)-(i0))) > (abs(((0xfffff*(0x888f4ee5)) & ((0x76efbf9a)-(0x73789bef))))|0)))|0))|0))));\n    d1 = (+(1.0/0.0));\n    i0 = (0xb99e8808);\n    return (((!(i0))-(0x44de918)))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-246262462*/count=1289; tryItOut("{ void 0; void gc('compartment', 'shrinking'); }");
/*fuzzSeed-246262462*/count=1290; tryItOut("v2 = Object.prototype.isPrototypeOf.call(m2, i2);");
/*fuzzSeed-246262462*/count=1291; tryItOut("testMathyFunction(mathy0, [(new Number(-0)), /0/, ({toString:function(){return '0';}}), undefined, '\\0', -0, ({valueOf:function(){return '0';}}), (new String('')), [0], false, ({valueOf:function(){return 0;}}), '0', objectEmulatingUndefined(), '/0/', null, NaN, (new Boolean(true)), (new Number(0)), 0.1, 0, '', (function(){return 0;}), true, (new Boolean(false)), [], 1]); ");
/*fuzzSeed-246262462*/count=1292; tryItOut("\"use strict\"; \"use asm\"; let (a) { ; }");
/*fuzzSeed-246262462*/count=1293; tryItOut("\"use strict\"; ({x, x}) = /((?:(?=(?!(?=\\1)))|.))/g;");
/*fuzzSeed-246262462*/count=1294; tryItOut("\"use strict\"; print(uneval(s2));");
/*fuzzSeed-246262462*/count=1295; tryItOut("\"use strict\"; v1 = evalcx(\"o0 = Object.create(o0.m2);\", g1);");
/*fuzzSeed-246262462*/count=1296; tryItOut("a1 = (function() { yield ((p={}, (p.z = \"\\uD965\")()))(); } })();");
/*fuzzSeed-246262462*/count=1297; tryItOut("print(x);");
/*fuzzSeed-246262462*/count=1298; tryItOut("mathy5 = (function(x, y) { return mathy2(Math.imul(( + ( ! -(2**53+2))), Math.cos(-Number.MIN_SAFE_INTEGER)), ( + Math.round(( + ( - (((-Number.MIN_SAFE_INTEGER | 0) << x) | 0)))))); }); ");
/*fuzzSeed-246262462*/count=1299; tryItOut("/*RXUB*/var r = new RegExp(\"(?:[\\\\u006a\\\\u1AC2\\u00e5-\\u0f9b]|\\\\3+?*)\", \"gim\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-246262462*/count=1300; tryItOut("mathy2 = (function(x, y) { return ( ! ( + Math.hypot(( + Math.atan2((((Math.hypot(x, (x << y)) >>> 0) < ( + (( + y) & y))) >>> 0), x)), ( + Math.hypot(Math.fround(mathy0(Math.fround(y), Math.fround(y))), mathy1(-(2**53+2), Math.min(y, -Number.MAX_VALUE))))))); }); testMathyFunction(mathy2, [0x080000000, -0, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000000, 0.000000000000001, 2**53+2, Number.MAX_VALUE, 0x100000001, 1/0, -(2**53+2), 0x100000000, 0x080000001, 0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 42, 2**53-2, -0x100000000, 1, -(2**53-2), 0x07fffffff, -0x080000001, -0x100000001, -(2**53), -1/0, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-246262462*/count=1301; tryItOut("testMathyFunction(mathy1, [0x0ffffffff, -0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, -(2**53-2), -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 1/0, 2**53-2, 0x100000001, 0x100000000, -0x080000001, 1.7976931348623157e308, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), -0x100000001, 0x080000000, 0x07fffffff, 1, -0x07fffffff, -Number.MAX_VALUE, -0x080000000, 0/0, -0, 0x080000001, 2**53, 42]); ");
/*fuzzSeed-246262462*/count=1302; tryItOut("\"use strict\"; let (y, b, x = (makeFinalizeObserver('nursery')), a, b) { a0.unshift(this.g1, p1); }");
/*fuzzSeed-246262462*/count=1303; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((mathy0(( - Math.min(x, x)), ( + (( + Math.min(y, (Math.min(( + x), y) | 0))) == ( + ( + Math.hypot(x, mathy0(-0, Math.max(Math.expm1(0x0ffffffff), x)))))))) >>> 0) === ((Math.fround(mathy0(( + mathy0((y == y), (-0x080000001 + Math.max(x, y)))), ( + ( ! x)))) >= ( + ( ~ Math.fround(y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -(2**53), 0x080000001, -0x100000000, 2**53-2, 0, Number.MIN_VALUE, 0/0, 0x100000001, 1, -0x100000001, -0, -0x0ffffffff, 0x100000000, -(2**53+2), 1/0, -(2**53-2), 42, 2**53, 0.000000000000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-246262462*/count=1304; tryItOut("g0.m0.set(e0, e2);");
/*fuzzSeed-246262462*/count=1305; tryItOut("a1.length = v2;");
/*fuzzSeed-246262462*/count=1306; tryItOut("{ void 0; verifyprebarriers(); }");
/*fuzzSeed-246262462*/count=1307; tryItOut("Array.prototype.pop.apply(a2, []);a0.unshift(a2);");
/*fuzzSeed-246262462*/count=1308; tryItOut("mathy5 = (function(x, y) { return (( + ( - (mathy2((( ~ x) | 0), ( ~ (Math.fround(( - x)) , Math.fround(Math.cos(y))))) | 0))) >> (( ~ (((( + ((Math.fround(Math.pow(y, Math.fround(y))) !== y) ? Math.fround(Math.log(Math.fround(Math.hypot(x, x)))) : (y | 0))) ** Math.ceil(0x080000001)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [0x0ffffffff, -Number.MIN_VALUE, 0x07fffffff, -0x100000000, -(2**53), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, 1, -(2**53+2), Number.MIN_VALUE, 42, 0x080000000, 0, 0x100000001, 0/0, -(2**53-2), -0x100000001, 0.000000000000001, -1/0, -0x07fffffff, -Number.MAX_VALUE, 0x100000000, -0x080000000, Math.PI, 2**53-2, Number.MAX_VALUE, 0x080000001, -0x080000001, 1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, -0]); ");
/*fuzzSeed-246262462*/count=1309; tryItOut("i2.toSource = (function() { try { /*MXX1*/o2 = g1.ReferenceError; } catch(e0) { } try { i1 + ''; } catch(e1) { } ; return o0; });");
/*fuzzSeed-246262462*/count=1310; tryItOut("\nthis.t1.toSource = (function(j) { if (j) { /*ODP-2*/Object.defineProperty(o1, \"small\", { configurable: (x % 3 != 2), enumerable: false, get: (function mcc_() { var mimods = 0; return function() { ++mimods; f2(/*ICCD*/mimods % 3 == 0);};})(), set: (function mcc_() { var mkzzmo = 0; return function() { ++mkzzmo; if (/*ICCD*/mkzzmo % 8 == 7) { dumpln('hit!'); try { h0[\"map\"] = this.t1; } catch(e0) { } try { m0.delete(g0.p1); } catch(e1) { } g2.h1.set = f1; } else { dumpln('miss!'); /*MXX1*/o0 = g2.g2.Error.prototype; } };})() }); } else { try { for (var v of f0) { selectforgc(o1); } } catch(e0) { } try { ( '' ); } catch(e1) { } try { i1.send(this.f0); } catch(e2) { } s1 += s0; } });\n");
/*fuzzSeed-246262462*/count=1311; tryItOut("if(false) \u0009{this.v2 = this.g0.b0.byteLength;this.y = new RegExp(\"\\\\S\", \"y\"), c = ((Math.expm1(11)))( \"\" .throw(window)), pcqfyz, \u3056 = x, c = null, yoyakd, dxwwmd, c, ctgdjx;a2.shift(); } else  if ((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0xf9d5449f)))|0;\n  }\n  return f; })(this, {ff: (WeakSet).call}, new ArrayBuffer(4096))) {Array.prototype.splice.apply(a1, [0, 18]);/*infloop*/for([] = new (true)(this); \"\\uB6D3\"; \"\\uE404\" + true(x)) {h0.iterate = (function() { try { a1.length = z; } catch(e0) { } try { m2.has(o1.o0.f1); } catch(e1) { } function o2.f2(i1) \"use asm\";   var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Int32ArrayView[1]) = ((Uint8ArrayView[1]));\n    d0 = (d0);\n    d0 = (((d1)) - ((d1)));\n    return +((d1));\n  }\n  return f; return o1.s0; }); } }");
/*fuzzSeed-246262462*/count=1312; tryItOut("/*infloop*/M: for (([]) of Math.max(6, 16).toTimeString(4, (z) = \"\\uF48C\")) {new RegExp(\"(?:$(?=(?:\\\\f|\\\\D)))\", \"gm\"); }");
/*fuzzSeed-246262462*/count=1313; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    switch ((((0xfa3ebd2a)) << (-(0xc371c0f8)))) {\n      default:\n        i2 = (i2);\n    }\n    return (((!(i1))-(i2)))|0;\n  }\n  return f; })(this, {ff: (c | a)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -0x100000001, 1.7976931348623157e308, 1, -(2**53+2), 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, -0, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, -1/0, -0x100000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53, 0x100000000, -0x080000000, Number.MAX_VALUE, 2**53-2, 0x100000001, 42, 1/0, -Number.MAX_SAFE_INTEGER, Math.PI, 0, 0x080000000, -(2**53), Number.MIN_VALUE, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-246262462*/count=1314; tryItOut("/*RXUB*/var r = r1; var s = s0; print(s.replace(r, b => ((((4277) * r))(((function sum_slicing(qbyrdl) { ; return qbyrdl.length == 0 ? 0 : qbyrdl[0] + sum_slicing(qbyrdl.slice(1)); })(/*MARR*/[1e+81,  '\\0' , 1e+81,  '\\0' , 1e+81,  '\\0' ,  '\\0' , 1e+81,  '\\0' , 1e+81,  '\\0' , 1e+81,  '\\0' ,  '\\0' ,  '\\0' , 1e+81,  '\\0' ,  '\\0' , 1e+81, 1e+81,  '\\0' ,  '\\0' , 1e+81, 1e+81,  '\\0' , 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81,  '\\0' , 1e+81, 1e+81, 1e+81,  '\\0' , 1e+81,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , 1e+81,  '\\0' , 1e+81,  '\\0' , 1e+81,  '\\0' , 1e+81,  '\\0' ,  '\\0' ,  '\\0' , 1e+81,  '\\0' , 1e+81,  '\\0' ,  '\\0' , 1e+81])), 'fafafa'.replace(/a/g, false.isFinite))), \"im\")); ");
/*fuzzSeed-246262462*/count=1315; tryItOut("this.v1 = (m0 instanceof p1);");
/*fuzzSeed-246262462*/count=1316; tryItOut("/*RXUB*/var r = /(\\1*?)/; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-246262462*/count=1317; tryItOut("let(e) ((function(){for(let a in []);})());window.name;");
/*fuzzSeed-246262462*/count=1318; tryItOut("\"use strict\"; \"use asm\"; mathy1 = (function(x, y) { return ((mathy0((Math.imul(Math.fround(0x100000000), Math.fround((x & x))) >>> 0), ((((Math.expm1(-(2**53-2)) | 0) ? (Math.sinh(x) | 0) : (Math.asin(Math.asin(Math.fround(( ! y)))) | 0)) | 0) >>> 0)) >>> 0) ? Math.log2(Math.log1p(Math.fround(Math.atan((Number.MAX_SAFE_INTEGER >>> 0))))) : (Math.max(Math.fround(Math.round(( + Math.pow(Math.fround((Math.min((Math.sqrt(x) >>> 0), (-(2**53+2) >> ( + y))) ? Number.MIN_SAFE_INTEGER : (1.7976931348623157e308 >>> 0))), (x | 0))))), (( + ( - ( + -0))) < (mathy0((mathy0(((1 << ( + Math.asin(( + y)))) | 0), (x | 0)) >>> 0), Math.fround(Math.sin(Math.fround(x)))) | 0))) | 0)); }); testMathyFunction(mathy1, [-(2**53-2), -0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 0, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, -1/0, Number.MIN_VALUE, 2**53-2, -0x07fffffff, 0x080000000, 0.000000000000001, 0x080000001, -0x100000000, 2**53+2, -0, -(2**53), 2**53, 1, 42, 0x100000001, 0/0, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-246262462*/count=1319; tryItOut("\"use strict\"; v1 = o2.g0.runOffThreadScript();");
/*fuzzSeed-246262462*/count=1320; tryItOut("\"use strict\"; for(let e = (new Uint8ClampedArray(\"\\uD120\")) in \"\\u604F\") h0.getOwnPropertyNames = f1;");
/*fuzzSeed-246262462*/count=1321; tryItOut("a0.pop();");
/*fuzzSeed-246262462*/count=1322; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[ '' , {x:3}, 0x3FFFFFFE, false, 0x3FFFFFFE,  '' , {x:3},  '' , {x:3},  '' , {x:3}, 0x3FFFFFFE, false, {x:3}, false,  '' , 0x3FFFFFFE, {x:3}, false, 0x3FFFFFFE, 0x3FFFFFFE, {x:3},  '' , 0x3FFFFFFE,  '' ]); ");
/*fuzzSeed-246262462*/count=1323; tryItOut("/*bLoop*/for (let gbejdu = 0; gbejdu < 6; ++gbejdu) { if (gbejdu % 6 == 1) { Array.prototype.sort.call(a1); } else {  }  } ");
/*fuzzSeed-246262462*/count=1324; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1.0078125;\n    return +((+/*FFI*/ff((((((/*MARR*/[(0/0), {x:3}, function(){}, function(){}, function(){}, (0/0), function(){}, (0/0), (0/0), (0/0), {x:3}, {x:3}, (0/0), function(){}, (0/0), (0/0), (0/0), new Number(1.5), new Number(1.5), function(){}, (0/0), function(){}, function(){}, {x:3}, function(){}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, (0/0), {x:3}, new Number(1.5), (0/0), (0/0), {x:3}, (0/0), new Number(1.5), (0/0), new Number(1.5), function(){}, function(){}, {x:3}, new Number(1.5), (0/0), (0/0), {x:3}, function(){}, function(){}, (0/0), function(){}, function(){}, {x:3}, {x:3}, (0/0), {x:3}, function(){}, new Number(1.5), new Number(1.5), function(){}, (0/0), new Number(1.5), (0/0), (0/0), new Number(1.5), {x:3}, new Number(1.5), (0/0), {x:3}, {x:3}, {x:3}, {x:3}, function(){}, (0/0), new Number(1.5), function(){}, new Number(1.5), new Number(1.5), function(){}, {x:3}, function(){}, (0/0), {x:3}, (0/0), {x:3}, (0/0), (0/0), {x:3}, function(){}, {x:3}, function(){}, {x:3}, new Number(1.5), (0/0), new Number(1.5), (0/0), function(){}, new Number(1.5), function(){}, {x:3}, {x:3}, function(){}, new Number(1.5), {x:3}, (0/0), function(){}, (0/0), function(){}, {x:3}, {x:3}, {x:3}, function(){}, {x:3}, {x:3}, {x:3}, {x:3}, (0/0), (0/0), function(){}, {x:3}, {x:3}, (0/0), (0/0), (0/0), {x:3}, {x:3}, function(){}, new Number(1.5), {x:3}, new Number(1.5), (0/0), {x:3}, (0/0), function(){}, new Number(1.5), new Number(1.5), new Number(1.5), (0/0), (0/0), function(){}].sort))*0xfffff) ^ (((((((0x8bc0e007))>>>((0x42b24f02))) < (((0xffffffff))>>>((0x4c89fb8c))))-(/*FFI*/ff()|0))|0) % (0x2b306a78)))))));\n  }\n  return f; })(this, {ff: function(y) { a0.push(o2.s0, m1); }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MIN_VALUE, 2**53+2, -0, 0.000000000000001, 0/0, 0x080000001, Number.MIN_VALUE, 0x100000001, 42, -0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 0, 1/0, Math.PI, 0x07fffffff, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, -(2**53), -(2**53+2), -1/0, -0x080000000, 2**53-2, 1.7976931348623157e308, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000, 1, -Number.MAX_VALUE, 0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=1325; tryItOut("mathy3 = (function(x, y) { return ( + ( - Math.fround((((Math.pow((Math.fround((Math.fround(Math.cbrt(x)) === Math.fround((x <= 0x100000001)))) | 0), (Math.max(Math.fround(x), Math.fround(( ~ Math.fround(x)))) | 0)) | 0) | 0) == Math.imul(Math.fround((Math.trunc((y | 0)) | 0)), x))))); }); testMathyFunction(mathy3, [-0x07fffffff, 0x07fffffff, 0/0, -0x100000001, 2**53, -(2**53+2), 0x0ffffffff, 0x100000001, Number.MIN_VALUE, 1, -Number.MIN_VALUE, 2**53+2, -0, -0x080000000, -Number.MAX_VALUE, -0x100000000, 0x080000001, 0x080000000, 0.000000000000001, -1/0, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), -(2**53), -0x0ffffffff, Math.PI, -0x080000001, 42, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-246262462*/count=1326; tryItOut("\"use strict\"; var r0 = x * 5; ");
/*fuzzSeed-246262462*/count=1327; tryItOut("this.h0.__proto__ = h0;v0 = Array.prototype.reduce, reduceRight.apply(a0, [f1, this.h1]);function NaN(e = (void shapeOf( \"\" )))\"use asm\";   var abs = stdlib.Math.abs;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1152921504606847000.0;\n    var d3 = -1.0009765625;\n    var d4 = 7.555786372591432e+22;\n    var i5 = 0;\n    return (((0xffffffff)))|0;\n    {\n      {\n        {\n          {\n            d3 = (+(abs(((((((0x8698d29b)*-0x348ae) & ((0x4cc9a632) % (0x7fffffff))))-(!(1))+(i5)) & (((0xe53db959))+(x.__defineSetter__(\u000d\"x\", (eval(\"\\\"use strict\\\"; mathy0 = (function(x, y) { \\\"use strict\\\"; return Math.tanh(((((Math.pow((( - y) | 0), Math.fround((Math.tanh(Math.fround(Math.max(( + ( ! 0x100000000)), (x >>> 0)))) >>> 0))) | 0) >>> 0) >>> (( + ( + Math.fround(( + 0x080000001)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-0x07fffffff, -(2**53+2), -(2**53-2), 0x0ffffffff, 2**53, Number.MIN_VALUE, 1, -Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, 42, Math.PI, Number.MIN_SAFE_INTEGER, 0, -0x080000000, -0x100000000, Number.MAX_VALUE, 0x100000000, -0x080000001, -0, 0x07fffffff, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), 1/0, -0x100000001, -1/0, 0/0, 1.7976931348623157e308, 0x100000001, -0x0ffffffff]); \")))))))|0));\n          }\n        }\n      }\n    }\n    return (((0xb0587317)-(0xffffffff)+(0xfe6a8c1c)))|0;\n  }\n  return f;i0.send(i0);");
/*fuzzSeed-246262462*/count=1328; tryItOut("mathy0 = (function(x, y) { return ( + ( + ( + Math.cosh(Math.hypot(( ! y), 1.7976931348623157e308))))); }); ");
/*fuzzSeed-246262462*/count=1329; tryItOut("this.o2.v1 = g0.g0.runOffThreadScript();/*wrap3*/(function(){ \"use strict\"; \"use asm\"; var esabiw = x; (function(q) { \"use strict\"; return q; })(); })");
/*fuzzSeed-246262462*/count=1330; tryItOut("Array.prototype.splice.apply(a0, [-22, 8]);/* no regression tests found */");
/*fuzzSeed-246262462*/count=1331; tryItOut("\"use strict\"; a2[({valueOf: function() { b1 = t0.buffer;return 2; }})] = g2.m1;");
/*fuzzSeed-246262462*/count=1332; tryItOut("\"use strict\"; var faxshl = new ArrayBuffer(4); var faxshl_0 = new Int8Array(faxshl); var faxshl_1 = new Uint8ClampedArray(faxshl); faxshl_1[0] = -5; var faxshl_2 = new Int32Array(faxshl); print(faxshl_2[0]); faxshl_2[0] = 1e81; e = new RegExp(\"(?:(?!.)(?:[^]{1,})|(?!(?:.))|(?=\\\\x2e)*?){4,4}\", \"im\") ** 10, faxshl_1[0] = faxshl_2, knbzah, imlqbh, faxshl_2[0];break M;NaN.stack;a0[(e *= y)] = o0.s1;o0 = this.a2[g1.v2];Array.prototype.shift.apply(a2, [g2.e1]);print(uneval(m0));");
/*fuzzSeed-246262462*/count=1333; tryItOut("testMathyFunction(mathy3, [/0/, (new Number(-0)), ({valueOf:function(){return '0';}}), (new Boolean(true)), false, 0, ({toString:function(){return '0';}}), [0], '', '\\0', [], '/0/', (new String('')), NaN, 1, true, (new Number(0)), null, undefined, '0', objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), (new Boolean(false)), (function(){return 0;}), -0]); ");
/*fuzzSeed-246262462*/count=1334; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return (( + Math.fround(Math.sinh(Math.fround((( + (( - ( + ( + ( + 0/0)))) | 0)) ? x : Math.fround(( ~ ( + x)))))))) | 0); }); testMathyFunction(mathy0, ['/0/', /0/, (new Boolean(true)), '0', 0, 1, ({valueOf:function(){return 0;}}), [0], -0, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), NaN, [], 0.1, true, null, '\\0', undefined, ({toString:function(){return '0';}}), (new String('')), false, (function(){return 0;}), (new Number(-0)), '', (new Number(0)), (new Boolean(false))]); ");
/*fuzzSeed-246262462*/count=1335; tryItOut("\"use strict\"; o1.h2 = ({getOwnPropertyDescriptor: function(name) { v0 = a0.length;; var desc = Object.getOwnPropertyDescriptor(g0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { print(uneval(s2));; var desc = Object.getPropertyDescriptor(g0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v2 = (x % 5 == 0);; Object.defineProperty(g0, name, desc); }, getOwnPropertyNames: function() { Object.seal(this.o1);; return Object.getOwnPropertyNames(g0); }, delete: function(name) { this.m1.get(i2);; return delete g0[name]; }, fix: function() { t2[v0] = (eval(\"o1 = o0.g0.i2.__proto__;\"));; if (Object.isFrozen(g0)) { return Object.getOwnProperties(g0); } }, has: function(name) { /*ODP-1*/Object.defineProperty(b0, \"max\", ({value: (4277), configurable: (x % 5 == 3), enumerable: true}));; return name in g0; }, hasOwn: function(name) { v0 = evaluate(\"function this.f0(a2)  { \\\"use strict\\\"; yield (x = Math.tan( /x/ ) for each (b in /*FARR*/[]) for (a2 of (void shapeOf( /x/g ))) for (window of []) for each (e in []) for (x of [])) } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  /x/g , noScriptRval: /*MARR*/[new Boolean(true),  '' ,  '' ,  '' ,  '' , [z1,,], ({}), 0.1, 0.1,  '' , ({}), [z1,,], 0.1, new Boolean(true), 0.1, ({}), 0.1, ({}), new Boolean(true), new Boolean(true),  '' ,  '' , [z1,,], 0.1, ({}), new Boolean(true), new Boolean(true),  '' , [z1,,],  '' , [z1,,], ({}),  '' ,  '' , ({}), [z1,,], ({}), 0.1,  '' , new Boolean(true), 0.1, new Boolean(true), ({}), ({}), ({}), 0.1,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , new Boolean(true), new Boolean(true), 0.1, new Boolean(true), new Boolean(true), 0.1, new Boolean(true), new Boolean(true), ({}), 0.1, new Boolean(true), ({}),  '' ,  '' , 0.1, new Boolean(true), [z1,,], [z1,,], 0.1, new Boolean(true),  '' ,  '' , 0.1, [z1,,], [z1,,], new Boolean(true), [z1,,],  '' ,  '' , ({}), 0.1, ({}), ({}), new Boolean(true), 0.1, [z1,,], [z1,,],  '' ,  '' , new Boolean(true)].filter / [[1]] ? 11 : ({a: /*MARR*/[arguments.callee, new Number(1), arguments.callee, new Number(1), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), NaN]\u0009.sort}), sourceIsLazy: (x % 2 == 1), catchTermination: x }));; return Object.prototype.hasOwnProperty.call(g0, name); }, get: function(receiver, name) { for (var p in a0) { try { v2 = (p0 instanceof t1); } catch(e0) { } try { g2.__proto__ = g1.g0; } catch(e1) { } Array.prototype.reverse.apply(g2.a1, [o0.v1]); }; return g0[name]; }, set: function(receiver, name, val) { g2.o1 = {};; g0[name] = val; return true; }, iterate: function() { Array.prototype.sort.apply(a0, [(function() { try { e2[\"includes\"] = f1; } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(s2, e0); } catch(e1) { } i2.send(e1); return f0; })]);; return (function() { for (var name in g0) { yield name; } })(); }, enumerate: function() { a0 = new Array;; var result = []; for (var name in g0) { result.push(name); }; return result; }, keys: function() { t2 = t0.subarray(3, 17);; return Object.keys(g0); } });");
/*fuzzSeed-246262462*/count=1336; tryItOut("\"use strict\"; (runOffThreadScript)( \"\" )\n;");
/*fuzzSeed-246262462*/count=1337; tryItOut("\"use strict\"; print(g2);function \u3056(x, x, ...y) { ; } (/(?:\\1|\\b{2}\\B)|(\\1)?|\\2|\\b*\\D|\\3+?|(?!\\2|[^]{1})|(?:\\w{1})/yi);");
/*fuzzSeed-246262462*/count=1338; tryItOut("\"use strict\"; x;f1 = t0[19];");
/*fuzzSeed-246262462*/count=1339; tryItOut("\"use strict\"; Array.prototype.splice.call(a0, NaN, Date.prototype.setUTCMilliseconds = x & y(), m2);");
/*fuzzSeed-246262462*/count=1340; tryItOut("\"use strict\"; v2 = t1.length;\nprint(x);\n");
/*fuzzSeed-246262462*/count=1341; tryItOut("mathy1 = (function(x, y) { return (Math.log2(Math.fround(( + mathy0(((-(2**53-2) ^ y) ? Math.fround(( ! x)) : (Math.min((( - Math.fround(x)) | 0), (Math.cosh((-(2**53-2) ^ x)) | 0)) | 0)), ((Math.abs((Math.min(Math.max(Math.fround((Math.pow((x | 0), (x | 0)) | 0)), mathy0(y, ( + y))), ((( ! x) | 0) ^ x)) | 0)) | 0) | 0))))) >>> 0); }); testMathyFunction(mathy1, [-0x080000001, 0, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1, 0x100000000, -0x100000000, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0, -(2**53+2), Math.PI, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -(2**53-2), 0x100000001, -0x07fffffff, 2**53, 0.000000000000001, 2**53+2, -0x080000000, -(2**53), 42, Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, -0, 2**53-2, -0x100000001, 0/0, 0x080000000]); ");
/*fuzzSeed-246262462*/count=1342; tryItOut("mathy2 = (function(x, y) { return Math.cos(((Math.imul(x, y) | 0) ? Math.sin((( + x) | 0)) : (Math.expm1(Math.hypot((y && -0x100000000), Math.imul((Math.sign((y | 0)) | 0), (( + 1/0) <= y)))) >>> 0))); }); testMathyFunction(mathy2, [0x07fffffff, -0x07fffffff, 2**53, -1/0, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2, -0x100000000, 0x100000000, 0x080000000, 0x0ffffffff, -(2**53), 0/0, Number.MIN_SAFE_INTEGER, Math.PI, 0, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -0x080000000, 0.000000000000001, -0x100000001, 1, 0x100000001, -Number.MAX_VALUE, 42, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000001, -(2**53+2), -0x0ffffffff]); ");
/*fuzzSeed-246262462*/count=1343; tryItOut("g0.a1.push();");
/*fuzzSeed-246262462*/count=1344; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.imul(( + Math.max(mathy0((Math.clz32((y | 0)) | 0), (-0x100000000 >>> 0)), y)), ( ~ ( + ( ! ( + Math.max(1, ( + x))))))); }); testMathyFunction(mathy1, [0x100000000, 2**53-2, -0, -0x080000000, -(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER, 1, 0x080000001, 2**53+2, 0x100000001, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, 0x0ffffffff, 0/0, 42, Math.PI, -0x0ffffffff, -0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, -0x080000001, 0, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, -1/0]); ");
/*fuzzSeed-246262462*/count=1345; tryItOut("m2 + b0;");
/*fuzzSeed-246262462*/count=1346; tryItOut("\"use strict\"; this.v1 = (m0 instanceof m2);");
/*fuzzSeed-246262462*/count=1347; tryItOut("L:switch((NaN) = c = [[]]) { default: /* no regression tests found */break; case (4277): case 8: Array.prototype.shift.call(a1, v1);break; case x.prototype: break; h0 + f1;const a = ((new Function(\"print(x);\"))).call(y, );(w); }");
/*fuzzSeed-246262462*/count=1348; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-246262462*/count=1349; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan((Math.imul(Math.sqrt(( + Math.sign(((mathy1(y, Math.sin(x)) >>> 0) >>> 0)))), Math.acosh(Math.fround(( ! Math.fround(x))))) | 0)); }); ");
/*fuzzSeed-246262462*/count=1350; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x080000000, 0x07fffffff, -0x100000000, 0/0, 0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, 0x080000001, Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, -0, -1/0, -Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, Number.MAX_VALUE, 0x100000000, 2**53-2, -0x100000001, -0x080000000, -0x07fffffff, -(2**53+2), 1/0, 42, 0.000000000000001, 2**53, -0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=1351; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( + (( + Math.fround(Math.abs(Math.fround(Math.min(( + 2**53-2), ( - x)))))) || ( + (Math.hypot(( + Math.min(Math.sqrt((-0 >>> 0)), Math.log10(Math.acosh(y)))), Math.fround((42 < y))) | 0)))) ? Math.fround(( ~ Math.fround(Math.min(x, x)))) : Math.pow(Math.ceil(Math.fround(x)), Math.fround(Math.max(y, x)))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, Math.PI, 1, -0x100000000, 0x080000001, 0x100000001, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, -0x100000001, 0x080000000, -1/0, 0x07fffffff, Number.MAX_VALUE, 2**53, -0x07fffffff, -0, 0, Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, 0/0, -0x080000001, 2**53+2, 2**53-2, -Number.MAX_VALUE]); ");
/*fuzzSeed-246262462*/count=1352; tryItOut("\"use strict\"; throw z;selectforgc(o0);");
/*fuzzSeed-246262462*/count=1353; tryItOut("\"use strict\"; var rxywhn = new SharedArrayBuffer(12); var rxywhn_0 = new Uint8ClampedArray(rxywhn); print(rxywhn_0[0]); 15;continue L;print(new rxywhn_0[0]( \"\" , false));print(rxywhn_0[4]);throw \"\\uC19D\";o0.g0.toString = (function mcc_() { var uaisvy = 0; return function() { ++uaisvy; if (/*ICCD*/uaisvy % 3 == 2) { dumpln('hit!'); try { g0.m0.get(g2.a0); } catch(e0) { } try { e1.has(v2); } catch(e1) { } g1.offThreadCompileScript(\"/\\\\3|(?!\\\\u1e9d|(\\\\B))|\\\\S^{4,262149}|.(?=$){1}+/gim\"); } else { dumpln('miss!'); try { a0.push(m0); } catch(e0) { } try { s0 = ''; } catch(e1) { } try { for (var p in o2) { try { Array.prototype.reverse.call(a2, e0, v0,  \"\" , h2); } catch(e0) { } try { /*MXX3*/this.g1.String.prototype.slice = this.g2.String.prototype.slice; } catch(e1) { } try { for (var p in g1) { p2.toSource = f0; } } catch(e2) { } o2 + ''; } } catch(e2) { } a2 = Array.prototype.slice.call(g1.a0, NaN, 3); } };})();;print(rxywhn_0[4]);");
/*fuzzSeed-246262462*/count=1354; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"e2 = new Set(b0);\\ndelete h1.keys;\\n\");");
/*fuzzSeed-246262462*/count=1355; tryItOut("\"use asm\"; delete o0.h2.hasOwn;");
/*fuzzSeed-246262462*/count=1356; tryItOut("mathy1 = (function(x, y) { return (( + ((((( - (y == Math.fround(Math.atan2(Math.fround(y), Math.fround(2**53-2))))) | 0) >> (x === Math.tanh((mathy0(y, mathy0((0.000000000000001 | 0), x)) >>> 0)))) >>> 0) <= ( + (( + y) != Math.fround(Math.max(x, ( ! y))))))) < mathy0(( + (((Math.pow(( + (( + x) >>> 0)), ( + x)) | 0) << (( + ( ! x)) | 0)) | 0)), ( + (( - Math.fround((y < y))) >>> 0)))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, Math.PI, -0x100000000, -(2**53), -Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, 2**53, 1, 0x100000001, -0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, -(2**53-2), -1/0, -0x080000001, 0x07fffffff, 2**53+2, 2**53-2, -(2**53+2), 0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, -0, -Number.MIN_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-246262462*/count=1357; tryItOut("this.v2 = a2.some((function(j) { if (j) { try { s1 + v2; } catch(e0) { } try { b1 + ''; } catch(e1) { } try { f0.valueOf = (function(j) { f2(j); }); } catch(e2) { } Array.prototype.splice.apply(a2, [-10, 17]); } else { try { this.h2 = {}; } catch(e0) { } try { Array.prototype.splice.apply(a2, [-4, 6, f0]); } catch(e1) { } try { v2 = new Number(4.2); } catch(e2) { } o2.v1 = (g0 instanceof t1); } }));");
/*fuzzSeed-246262462*/count=1358; tryItOut("\"use strict\"; t1 = t1.subarray(6, 13);");
/*fuzzSeed-246262462*/count=1359; tryItOut("mathy3 = (function(x, y) { return ((Math.sinh(( + Math.clz32(((((Math.max(Math.fround(( ~ x)), x) >>> 0) ** (-(2**53-2) >>> 0)) >>> 0) >>> 0)))) >>> 0) && Math.fround((Math.hypot(mathy2((((( - x) | 0) && (x | 0)) | 0), (y ** (( ! -0x07fffffff) || y))), y) ? Math.fround(Math.sign(Math.fround(Math.fround(Math.pow(Math.fround(x), Math.fround(Math.sqrt(mathy2(( + Math.exp(Math.fround(y))), Math.PI)))))))) : (Math.acosh((( ! ( + ( ~ y))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [-0x07fffffff, -0x100000001, 0x07fffffff, 0.000000000000001, -Number.MAX_VALUE, 0/0, -(2**53-2), 0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0, 0x080000000, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, Number.MAX_VALUE, 0x080000001, 42, Number.MIN_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 2**53-2, 1, -1/0, -(2**53), -0, -0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, 1/0, Math.PI]); ");
/*fuzzSeed-246262462*/count=1360; tryItOut("/*RXUB*/var r = /((?!(?!\\w)){2049,}){2147483647}(?!(?=\\2)(?![\\w\\D\\xBA-\u3147\\\u6b46]){1,2}|(?:\\b){3,5})?/gyi; var s = \"aaaaaaaaaa0aaaaaaaaaa\"; print(s.split(r)); print(r.lastIndex); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
