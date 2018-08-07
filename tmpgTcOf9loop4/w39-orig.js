

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
/*fuzzSeed-71289653*/count=1; tryItOut("mathy3 = (function(x, y) { return (( + ( + Math.min(Math.fround(Math.sinh(Math.fround(x))), Math.fround(Math.abs((Math.cbrt((x | 0)) | 0)))))) | Math.exp(( + Math.log1p(Math.fround(mathy2(Math.fround(x), (Math.max(( + y), (y | 0)) >>> 0))))))); }); testMathyFunction(mathy3, [-0x100000001, -Number.MIN_VALUE, 42, Math.PI, 0x100000000, -(2**53+2), 0, -0x080000001, 0/0, -0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 0x0ffffffff, -0x0ffffffff, 2**53, -1/0, -(2**53-2), 0x100000001, -0x07fffffff, -(2**53), 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, 1, 1/0, 0x07fffffff, -0x100000000, Number.MAX_VALUE, 0x080000000]); ");
/*fuzzSeed-71289653*/count=2; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x080000001, 0.000000000000001, 2**53+2, -Number.MAX_VALUE, -0x07fffffff, 2**53-2, 0/0, -(2**53), 1/0, -0, 0x080000000, 0x100000001, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 0x100000000, Number.MAX_VALUE, -0x100000001, -0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, 2**53, -(2**53+2), -1/0, 42, -0x0ffffffff, -0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-71289653*/count=3; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(Math.min((Math.log((Math.imul((mathy0(1.7976931348623157e308, y) >>> 0), 1) + ((x + x) >>> 0))) | 0), Math.fround(Math.expm1(( + Math.acosh(Math.fround(Math.fround(Math.sinh(( + -0x07fffffff)))))))))); }); testMathyFunction(mathy1, [42, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, -1/0, 0x080000000, Math.PI, 0x100000001, -(2**53+2), 1/0, 2**53-2, -0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 1, -0x100000001, 2**53, 0, -Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, -0x100000000, 0x080000001, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=4; tryItOut("\"use strict\"; var lwwctq = new SharedArrayBuffer(4); var lwwctq_0 = new Float64Array(lwwctq); print(false);");
/*fuzzSeed-71289653*/count=5; tryItOut("mathy2 = (function(x, y) { return Math.fround(mathy1(( + Math.pow((Math.log2((y | 0)) | 0), Math.pow((( + ( ! x)) >>> 0), -1/0))), Math.fround(( + mathy1(( + Math.asin((Math.fround((mathy0(1, (x | 0)) | 0)) ? (x == x) : ( + (x ? (y >>> 0) : x))))), (( + Math.imul((Math.imul(x, Math.max(0x100000001, x)) >>> 0), ((mathy1(((mathy0(Math.fround((mathy1((y | 0), ( + (( + Math.PI) ? ( + y) : /*vLoop*/for (let olnsjg = 0, w; olnsjg < 41 && (window); ++olnsjg) { var x = olnsjg;  '' ; } ))) | 0)), (mathy1(-Number.MIN_VALUE, y) | 0)) | 0) >>> 0), ((( ! 0.000000000000001) | 0) ** y)) >>> 0) >>> 0))) >>> 0)))))); }); testMathyFunction(mathy2, [0x100000001, -0, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, -1/0, 42, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -(2**53-2), 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1, 0/0, 0x080000000, 2**53-2, Math.PI, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, -0x080000001, -0x100000000, 1/0, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -0x100000001]); ");
/*fuzzSeed-71289653*/count=6; tryItOut("/*iii*/v2 = o1.o0.g0.a0.length;/*hhh*/function vurkbp(w, x, x, a = Math.log10((-(2**53+2) >>> 0)), c, eval, eval, x = let (e) this, e, x, d, getter, b, b, x, d, \u3056, \u3056, x, d, x =  \"\" , x, x, w, d, x =  /x/ , e, y = \u3056, x, z, x, eval, window, \u3056, x = new RegExp(\"(?!\\\\n?|.|[^]\\\\b|\\\\d|^|\\u00c8)|$|[^]\\\\D(?:.)\\u00c5*.|..{3}+\", \"ym\"), x = \"\\u9580\", x, x, x =  '' , window, a, d =  '' , x, e =  /x/ , e, c = 27, x, x, w, x, getter, y, x, x, x, x, x, window,   = \"\\u9717\", x, b,  , eval, b, \u3056, \u3056 = undefined, x, x, x, eval, length, x, eval = x, window, x, window, this.d, x, x, \u3056, x, x, x, eval, w, x, x, w, eval, x,  , window, eval, x =  \"\" , z, b, eval, x = [[1]], x){m0.set(this.g1.i1, m2);}");
/*fuzzSeed-71289653*/count=7; tryItOut("let(a) { for(let z in /*MARR*/[ /x/g , x, x, x,  /x/g , x,  /x/g ,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x,  /x/g ,  /x/g , x, x, x,  /x/g , x, x, x,  /x/g , x, x, x, x, x,  /x/g ,  /x/g , x,  /x/g ,  /x/g , x,  /x/g , x,  /x/g ,  /x/g ,  /x/g , x,  /x/g ,  /x/g , x,  /x/g , x, x,  /x/g , x, x, x,  /x/g ,  /x/g , x,  /x/g , x, x, x, x,  /x/g , x,  /x/g , x,  /x/g , x, x, x,  /x/g ,  /x/g , x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  /x/g ]) return;}a = x;");
/*fuzzSeed-71289653*/count=8; tryItOut("mathy0 = (function(x, y) { return Math.pow(( ! Math.exp(Math.fround((Math.atan2((Math.atan((1 < -0x0ffffffff)) | 0), ((( + Math.fround(Math.pow((y | 0), Math.fround(y)))) + Math.fround(Math.ceil(2**53-2))) | 0)) | 0)))), ( - (Math.max(x, x) >>> 0))); }); testMathyFunction(mathy0, [-(2**53), 0x080000000, -0x100000000, -(2**53+2), -0x0ffffffff, 2**53, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, 1/0, -(2**53-2), 42, -1/0, 0x07fffffff, -Number.MIN_VALUE, -0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, -0x100000001, Math.PI, -0x080000000, Number.MAX_VALUE, 0x100000000, 0x100000001, -0, Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 1, 0/0]); ");
/*fuzzSeed-71289653*/count=9; tryItOut("mathy5 = (function(x, y) { return ( ! mathy3((mathy1(Math.min(mathy0(y, ( ! x)), Math.log1p(y)), (0x100000000 <= (2**53+2 < Math.fround(( - 0x07fffffff))))) >>> 0), Math.fround(Math.atan2(mathy0(( + mathy1(( + (0x0ffffffff | 0)), mathy4(x, ((x ? (-Number.MIN_SAFE_INTEGER >>> 0) : x) | 0)))), ( ! ( + y))), (Math.atan2((y >>> 0), (y >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [0x100000001, 0x07fffffff, 1, -0x100000001, 0x100000000, 0x080000000, -0x0ffffffff, -0x080000001, -1/0, -(2**53-2), 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, 0.000000000000001, 2**53-2, -(2**53+2), Math.PI, Number.MIN_SAFE_INTEGER, 2**53+2, 42, -0x07fffffff, 1.7976931348623157e308, -0, -(2**53), 1/0, 0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=10; tryItOut("/*oLoop*/for (ksxwhv = 0; ksxwhv < 78; ++ksxwhv) { with((Uint8Array).call(\"\\uD0D3\", false))print( '' ); } ");
/*fuzzSeed-71289653*/count=11; tryItOut("\"use strict\"; /*MXX2*/g1.g2.ArrayBuffer.prototype.slice = o2;");
/*fuzzSeed-71289653*/count=12; tryItOut("mathy0 = (function(x, y) { return ( + (( + Math.hypot((Math.atan(((( ! y) >>> 0) ? ( - ((Math.min(Math.fround(y), (y | 0)) | 0) | 0)) : Math.fround(-0x100000001))) >>> 0), ((Math.fround(Math.fround(Math.imul(Math.fround(((Math.fround(Math.sign(Math.fround(y))) & (Number.MAX_VALUE >>> Math.fround(-Number.MIN_SAFE_INTEGER))) % ( + Math.atan2((Math.round((x | 0)) | 0), 1.7976931348623157e308)))), Math.fround(((( + Math.max(y, 0x100000000)) >>> 0) ? Math.fround(Math.ceil(Math.fround(x))) : y))))) - ( ~ y)) >>> 0))) | ( + (( ! (Math.asinh((((Math.atan2(1/0, Number.MAX_VALUE) | Math.sinh(y)) | 0) >>> (( + (1.7976931348623157e308 >>> 0)) | 0))) | 0)) | 0)))); }); ");
/*fuzzSeed-71289653*/count=13; tryItOut("o1.v0 = Object.prototype.isPrototypeOf.call(h1, v0);(Math);\na2 + m0;\n");
/*fuzzSeed-71289653*/count=14; tryItOut("t1 = new Uint8ClampedArray(this.o0.a1);");
/*fuzzSeed-71289653*/count=15; tryItOut("\"use strict\"; m0 = new Map;");
/*fuzzSeed-71289653*/count=16; tryItOut("v0 = e1[\"log2\"];");
/*fuzzSeed-71289653*/count=17; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ((Math.log(Math.fround((( - (x | 0)) | 0))) >>> 0) < Math.hypot(( ! (y | 0)), (( + (Math.expm1(Math.atan2(x, x)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [1, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -0x080000001, -0x100000001, 1/0, Number.MIN_VALUE, 0, -(2**53+2), -Number.MIN_VALUE, 0.000000000000001, 42, -Number.MAX_VALUE, 0x100000001, 2**53, 0x080000001, -(2**53-2), -1/0, 0x080000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -0, 2**53+2, 0x100000000, Math.PI, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53)]); ");
/*fuzzSeed-71289653*/count=18; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.max((mathy1((( ~ -0x080000001) >>> 0), Math.pow(Math.fround(x), ( + (( + (((((( + mathy0(0, ( + y))) >> -(2**53-2)) >>> 0) | 0) < (y | 0)) | 0)) > ( + Math.asinh(x)))))) | 0), ((Math.tanh(Math.fround(( - (2**53-2 >>> 0)))) | 0) != (Math.asin((0.000000000000001 | 0)) | 0))); }); testMathyFunction(mathy4, [-1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -(2**53), Math.PI, 0/0, 2**53-2, 0x080000001, 42, -0x100000000, -0, -Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), 0x07fffffff, -Number.MAX_VALUE, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, Number.MIN_VALUE, 2**53+2, 1/0, 0x100000000, -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000000, 1.7976931348623157e308, 0]); ");
/*fuzzSeed-71289653*/count=19; tryItOut("for(var x = /\\B/y in ((function factorial(edqmrv) { ; if (edqmrv == 0) { ; return 1; } g2.v2 = (g2 instanceof o0.i0);let y = /*UUV2*/(x.trimRight = x.getUTCDate) ? Math.min(-15, ((uneval( '' )))) : \"\\u5064\";; return edqmrv * factorial(edqmrv - 1);  })(24690))) f0 = (function() { try { Array.prototype.shift.call(g2.a2, a2, s1, g0.s0); } catch(e0) { } try { p0 + ''; } catch(e1) { } Object.freeze(f0); return v2; });print(g1);");
/*fuzzSeed-71289653*/count=20; tryItOut("t1 = new Int8Array(t2);");
/*fuzzSeed-71289653*/count=21; tryItOut("for (var p in a1) { try { e0.delete(this.g2); } catch(e0) { } try { this.v1 = a2.length; } catch(e1) { } g2.e0.has(m1); }");
/*fuzzSeed-71289653*/count=22; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -562949953421311.0;\n    {\n      i2 = (i0);\n    }\n    {\n      i1 = (i1);\n    }\n    /*FFI*/ff(((-((+/*FFI*/ff(((3.022314549036573e+23)), ((((+((NaN)))) % ((((-4611686018427388000.0)) / ((-2.3611832414348226e+21)))))), ((~( /x/g ))), ((-257.0)), ((((0xff4f23d2))|0)), ((4.835703278458517e+24)), ((-1152921504606847000.0))))))), ((~~(+(1.0/0.0)))), ((imul((!(([] = Date.prototype))), ((((0xffffffff))>>>((0x83542f89))) == (0xbfe139ce)))|0)), (x));\n    i2 = (i3);\n    i0 = (i3);\n    i3 = (i1);\n    return +((262144.0));\n  }\n  return f; })(this, {ff: Symbol}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 0.000000000000001, -(2**53), 2**53+2, -(2**53-2), 2**53-2, -0x100000000, -1/0, -0, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, -0x0ffffffff, 0x100000000, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 1, 0x080000000, -0x100000001, 2**53, 0, 0x07fffffff, 0x080000001, 0/0, -0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, 1/0, 42]); ");
/*fuzzSeed-71289653*/count=23; tryItOut("this.s0 += 'x';const w = x;");
/*fuzzSeed-71289653*/count=24; tryItOut("\"use strict\"; Object.defineProperty(this, \"v0\", { configurable: true, enumerable: false,  get: function() {  return true; } });");
/*fuzzSeed-71289653*/count=25; tryItOut("p1.toSource = (function(j) { if (j) { /*MXX2*/g2.Symbol.prototype.constructor = s1; } else { try { g2.a1.toSource = (function mcc_() { var imnhmi = 0; return function() { ++imnhmi; if (/*ICCD*/imnhmi % 2 == 0) { dumpln('hit!'); try { o0.g2.i1 = new Iterator(v2); } catch(e0) { } try { for (var v of v1) { /*MXX2*/g1.Int32Array = s0; } } catch(e1) { } Array.prototype.sort.call(a2, Math.random.bind(o2)); } else { dumpln('miss!'); try { v1 = Object.prototype.isPrototypeOf.call(o2.b0, s1); } catch(e0) { } selectforgc(o0); } };})(); } catch(e0) { } try { v2 = evaluate(\"for (var p in g0.b1) { try { g1.o2.v2 = (this.t2 instanceof g1.v0); } catch(e0) { } try { s2 += o1.o0.s2; } catch(e1) { } try { b0.toString = (function mcc_() { var ntugya = 0; return function() { ++ntugya; if (false) { dumpln('hit!'); b0 = o0.g0.objectEmulatingUndefined(); } else { dumpln('miss!'); try { a0.reverse(); } catch(e0) { } try { i0 = a0.entries; } catch(e1) { } try { for (var v of i0) { try { (void schedulegc(g1)); } catch(e0) { } for (var v of v0) { try { e2.has(h1); } catch(e0) { } try { g1.m1.delete(i1); } catch(e1) { } s2 += 'x'; } } } catch(e2) { } /*ODP-3*/Object.defineProperty(t2, \\\"-11\\\", { configurable: true, enumerable: (x % 3 == 2), writable: (x % 14 == 13), value: p1 }); } };})(); } catch(e2) { } Object.defineProperty(this, \\\"v0\\\", { configurable: {} = x, enumerable: true,  get: function() {  return a0.length; } }); }\", ({ global: this.g1, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 0), noScriptRval: (x % 36 != 6), sourceIsLazy: -21, catchTermination: (x % 55 != 17), element: o0 })); } catch(e1) { } try { i0 = new Iterator(h1); } catch(e2) { } v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: (x % 3 != 0), catchTermination: true })); } });");
/*fuzzSeed-71289653*/count=26; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.exp((((( ~ (((Math.exp(( + ( + x))) | 0) ^ (( - y) | 0)) | 0)) || ((Math.cos((x >>> 0)) | 0) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [({valueOf:function(){return '0';}}), -0, '\\0', [0], '/0/', '', [], (function(){return 0;}), undefined, (new Number(-0)), ({toString:function(){return '0';}}), (new Boolean(false)), objectEmulatingUndefined(), '0', true, (new String('')), 0.1, NaN, null, 1, false, 0, ({valueOf:function(){return 0;}}), (new Number(0)), (new Boolean(true)), /0/]); ");
/*fuzzSeed-71289653*/count=27; tryItOut("/*MXX2*/this.g1.Map.length = f2;");
/*fuzzSeed-71289653*/count=28; tryItOut("\"use strict\"; t1 = new Uint8ClampedArray(a1);");
/*fuzzSeed-71289653*/count=29; tryItOut("testMathyFunction(mathy5, [0/0, 0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, -Number.MAX_VALUE, 0x100000001, 2**53+2, 0, 0.000000000000001, -0x0ffffffff, -1/0, -(2**53), 1/0, 42, 0x100000000, -0x100000000, -Number.MIN_VALUE, 0x080000000, -0, 0x0ffffffff, -0x100000001, -0x080000001, 1, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), 2**53, -0x07fffffff, 0x080000001, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=30; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround(Math.cosh(Math.fround((mathy0((Math.min(x = x, (Math.fround(Math.tanh(y)) >>> 0)) | 0), (( + (1/0 << Math.sin(y))) | 0)) | 0)))))); }); testMathyFunction(mathy2, [-0x080000000, 0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, 1/0, 1.7976931348623157e308, -0x100000001, 2**53-2, 2**53+2, -Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, Math.PI, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0, -(2**53-2), Number.MIN_VALUE, -0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, 1, 0x07fffffff, 0x100000000, 0x100000001, -(2**53+2), 0x080000000, 0, 0/0, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=31; tryItOut("switch(Math.max(-22, [])) { default:  }");
/*fuzzSeed-71289653*/count=32; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround(Math.fround(( ! ((Math.min((Math.min(( + Math.pow(y, (y >>> ( + x)))), -0x080000000) >>> 0), (((Math.fround((Math.tan(x) >>> 0)) ? Math.fround(Math.fround(( + y))) : Math.fround(( ~ (-0x080000000 | 0)))) >>> 0) >>> 0)) >>> 0) | 0)))) & (Math.fround(mathy2(( + mathy0(Math.asinh((2**53+2 | 0)), 0x080000001)), Math.fround(Math.min((Math.fround((Math.fround(x) ? y : (y | 0))) ? x : x), y)))) ? Math.fround(( ! Math.log(mathy0((y | 0), ((((y | 0) >> (( + y) | 0)) | 0) | 0))))) : Math.fround((Math.min(( + 2**53-2), y) >> Math.asin(Math.fround(Math.fround(mathy2((y | 0), (y >>> 0))))))))); }); testMathyFunction(mathy3, [42, 1/0, -0x100000001, -0, Number.MAX_VALUE, 0, 2**53+2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 0x080000001, -0x080000001, -0x100000000, -(2**53-2), 0.000000000000001, -0x0ffffffff, -1/0, 2**53-2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 0x100000001, -(2**53), Math.PI, -(2**53+2), 0x080000000, 0/0, 2**53, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=33; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.tan(Math.atan2(( + (Math.asinh((((( ~ x) >>> 0) | 0) | x)) - (y >>> 0))), Math.fround(Math.cos(Math.log10(( + y)))))); }); testMathyFunction(mathy0, [objectEmulatingUndefined(), (new Number(0)), '/0/', '0', [0], (new Boolean(false)), undefined, '\\0', (new Number(-0)), ({valueOf:function(){return '0';}}), (new Boolean(true)), ({toString:function(){return '0';}}), 1, 0, false, [], (new String('')), ({valueOf:function(){return 0;}}), /0/, (function(){return 0;}), '', null, true, -0, 0.1, NaN]); ");
/*fuzzSeed-71289653*/count=34; tryItOut("\"use asm\"; switch(x ^= null.valueOf(\"number\")(\"\\uC993\")) { case 0: break; L: for (var d of eval) m0.set(e1, g0.t1);break;  }");
/*fuzzSeed-71289653*/count=35; tryItOut("mathy2 = (function(x, y) { return Math.fround((Math.pow((Math.sqrt(( + ( - y))) >>> 0), (Math.hypot(Math.fround(( ~ ( + Math.min(( + x), ( + y))))), Math.fround((Math.imul((Math.hypot((((y >>> 0) || (x >>> 0)) >>> 0), ( + -(2**53))) >>> 0), -(2**53-2)) >>> 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [0x100000000, 0x0ffffffff, 2**53, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000001, 1, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), Number.MIN_VALUE, -0, 2**53-2, -0x080000000, -(2**53-2), 0x100000001, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, -1/0, 1.7976931348623157e308, 0x07fffffff, 0.000000000000001, -0x0ffffffff, 0, 42, -Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, -Number.MAX_VALUE, -(2**53+2), 0x080000000]); ");
/*fuzzSeed-71289653*/count=36; tryItOut("e2 = this.m0.get(i0);");
/*fuzzSeed-71289653*/count=37; tryItOut("mathy0 = (function(x, y) { return Math.atan2(((Math.imul((( + (Number.MAX_VALUE % 0x100000000)) >>> 0), x) & (Math.max(Math.atan2(Math.atan2((y | 0), y), Math.fround(( ~ Math.fround(y)))), y) >>> 0)) ^ (Math.atan2((( + (Math.fround((( + y) % y)) >= ( + -(2**53)))) >>> 0), (Math.log2((x >>> 0)) >>> 0)) >>> 0)), ( + (Math.atan2(Math.clz32(Math.atan2(Math.fround(y), Math.hypot(y, (y >>> 0)))), x) | (Number.MIN_SAFE_INTEGER <= 1/0)))); }); testMathyFunction(mathy0, [42, -(2**53-2), 0x07fffffff, 0/0, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -0, 2**53-2, -0x100000001, Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000000, -1/0, 0x100000000, 2**53, -0x07fffffff, Math.PI, -(2**53), 2**53+2, 0.000000000000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0, 1, -0x080000001]); ");
/*fuzzSeed-71289653*/count=38; tryItOut("\"use strict\"; ");
/*fuzzSeed-71289653*/count=39; tryItOut("\"use strict\"; this.e2.delete(t2);");
/*fuzzSeed-71289653*/count=40; tryItOut("let b, z = 24, x = (void shapeOf(window)), window, \u3056 =  \"\" , twrvnd, lxvqbb;g0.g1.g0.v0 = t0.length;");
/*fuzzSeed-71289653*/count=41; tryItOut("\"use strict\"; /*bLoop*/for (fkmuwq = 0; fkmuwq < 42; ++fkmuwq) { if (fkmuwq % 4 == 2) { e0.has(i1); } else { v2 = (b2 instanceof this.g1); }  } ");
/*fuzzSeed-71289653*/count=42; tryItOut("\"use strict\"; p2.valueOf = (function mcc_() { var unqpqk = 0; return function() { ++unqpqk; if (/*ICCD*/unqpqk % 5 == 4) { dumpln('hit!'); try { (void schedulegc(g1)); } catch(e0) { } try { p2.__proto__ = o0; } catch(e1) { } e0.delete(e0); } else { dumpln('miss!'); s1 += 'x'; } };})();");
/*fuzzSeed-71289653*/count=43; tryItOut("for (var v of p2) { m0.set(p0, e0); }");
/*fuzzSeed-71289653*/count=44; tryItOut("\"use strict\"; \"use asm\"; e1.has(v2);");
/*fuzzSeed-71289653*/count=45; tryItOut("v1 = r2.unicode;");
/*fuzzSeed-71289653*/count=46; tryItOut("mathy3 = (function(x, y) { return Math.log1p(Math.log10(( + (( + (Math.cos(0x080000001) >>> 0)) >= Math.atan2(x, 0.000000000000001))))); }); ");
/*fuzzSeed-71289653*/count=47; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=48; tryItOut("this.e1.has(x);");
/*fuzzSeed-71289653*/count=49; tryItOut("\"use strict\"; /*infloop*/M:for(d; (let (x) this); ({x: window}))  /x/g ;");
/*fuzzSeed-71289653*/count=50; tryItOut("g2.v1 = (a2 instanceof s1);");
/*fuzzSeed-71289653*/count=51; tryItOut("{/*bLoop*/for (let jrmgik = 0; jrmgik < 25; ++jrmgik) { if (jrmgik % 6 == 2) { a2[15]; } else { (window); }  } { void 0; void relazifyFunctions('compartment'); } }");
/*fuzzSeed-71289653*/count=52; tryItOut("mathy2 = (function(x, y) { return (( ! Math.min(( + Math.cbrt(y)), y)) != (Math.log2(((Math.imul(( - (x | 0)), x) | 0) | 0)) | 0)); }); ");
/*fuzzSeed-71289653*/count=53; tryItOut("\"use strict\"; e0.has(m0);");
/*fuzzSeed-71289653*/count=54; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    i3 = (i0);\n    i2 = (0xffffffff);\n    return (((i2)))|0;\n    return ((((((0xfc01c9e0))))))|0;\n    i3 = (i2);\n    return ((-(((((-18446744073709552000.0)) / ((-8193.0)))))))|0;\n  }\n  return f; })(this, {ff: (4277)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, 1/0, 0, -0x100000001, -0x100000000, 42, -1/0, -Number.MIN_VALUE, 2**53-2, 0x080000001, -0x07fffffff, 1, 2**53, Math.PI, -(2**53-2), 0x100000001, 2**53+2, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), -0x0ffffffff, -0, 1.7976931348623157e308, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 0x07fffffff, -0x080000000]); ");
/*fuzzSeed-71289653*/count=55; tryItOut("\"use strict\"; m0.get(o0.v1);");
/*fuzzSeed-71289653*/count=56; tryItOut("mathy0 = (function(x, y) { return (Math.imul(((Math.clz32((((Math.fround(( + (((x / x) | 0) ? Math.fround(x) : x))) >>> 0) ? (Math.imul((Math.sinh(y) >>> 0), x) >>> 0) : (y >>> 0)) >>> 0)) >>> 0) << Math.fround(Math.pow((((Math.atanh(y) ? y : (( + (y | x)) >>> 0)) >>> 0) >>> 0), (( + Math.fround(Math.min(-0x080000000, y))) > ( + Math.max((x | 0), (y | 0))))))), Math.fround(Math.log1p(( + Math.asinh(y))))) | 0); }); testMathyFunction(mathy0, [-0x07fffffff, -0x080000001, 1.7976931348623157e308, -0, 2**53, -1/0, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 1, 0x0ffffffff, -0x100000000, -(2**53-2), -Number.MAX_VALUE, 2**53-2, Number.MAX_VALUE, -0x0ffffffff, -0x100000001, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53), 0x100000000, Number.MIN_VALUE, 1/0, 0, 42, 0x080000000, 2**53+2]); ");
/*fuzzSeed-71289653*/count=57; tryItOut("/*oLoop*/for (var icjhhn = 0; icjhhn < 26; ++icjhhn) { print(uneval(h0)); } ");
/*fuzzSeed-71289653*/count=58; tryItOut("/*RXUB*/var r = /(^\\b{3,}.+*)+/; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=59; tryItOut("g0.a1.__proto__ = f0;");
/*fuzzSeed-71289653*/count=60; tryItOut("print(arguments);\n/*infloop*/for(var w in (((Date.prototype.getUTCDate).bind( '' ))(new RegExp(\"^|[^]{0}\", \"gyim\")))){(13);print(\"\\uE104\"); }\n");
/*fuzzSeed-71289653*/count=61; tryItOut("h2.set = (function() { try { v1 = s2; } catch(e0) { } delete g2.p1[\"0\"]; return s0; });");
/*fuzzSeed-71289653*/count=62; tryItOut("e0.delete(f1);");
/*fuzzSeed-71289653*/count=63; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1((Math.min(( + (( + mathy1(0x100000001, (Math.atan2(x, (y | 0)) | 0))) | 0)), Math.hypot(x, ( + (( + -(2**53+2)) !== ( + ( ! Math.pow((y >>> 0), y))))))) >>> 0), ((( ~ Math.fround(Math.asin(y))) == ( + y)) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[x, (1/0), x, (1/0), x, x, x, (1/0), (1/0), x, (1/0), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, (1/0), x, (1/0), x, x, x, x, (1/0), x, x, (1/0), x, x, (1/0), x, x, x, x, (1/0), x, (1/0), x, x, (1/0), x, x, x, x, x, x, x, (1/0), (1/0), (1/0), (1/0), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, (1/0), (1/0), x, x, x, (1/0), x, x, (1/0), x, (1/0), x, x, (1/0), (1/0), x, x, x, (1/0), (1/0), x, x, (1/0), (1/0), x, x, (1/0), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-71289653*/count=64; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -17179869185.0;\n    var d4 = 1025.0;\n    var i5 = 0;\n    var d6 = 1.001953125;\n    var i7 = 0;\n    (Float64ArrayView[((i2)+(i1)) >> 3]) = (( /x/g ));\n    d3 = (8796093022209.0);\n    (Float64ArrayView[1]) = ((-1073741825.0));\n    (Float32ArrayView[(((0x8717b6fe) ? ((-16777217.0) >= (-65.0)) : (i1))+(0x62e5070a)) >> 2]) = ((-((+abs(((-((Float32ArrayView[2])))))))));\n    {\n      {\n        (Float64ArrayView[4096]) = ((d0));\n      }\n    }\n    i5 = ((Uint32ArrayView[1]));\n    i2 = (i1);\n    i1 = (((((0x434a2ad7) ? (((x = x) ^= x)) : ((((0x96026fe8))|0)))-(-0x8000000)+((73786976294838210000.0) == (d0))) >> ((0xd51d5141))) > (((0xdd077da7)-(-0x8000000)+(i1)) ^ (((((0x3f48cba0)-(0xffffffff))>>>((0xfee58fd3)-(0x48d16d95))))-(i1)-(0xfc8c2303))));\n    return +((+pow(((((((+((Float64ArrayView[((0x459624af)*-0x806ed) >> 3])))))) * ((Float32ArrayView[((0xf803f951)+((0x2adf8a8c) >= (0x66e81418))-(-0x8000000)) >> 2])))), ((((((d4)) - ((+atan2(((+/*FFI*/ff(((abs((0x21480885))|0))))), ((+(1.0/0.0)))))))) % ((((1073741825.0)) * ((Float32ArrayView[((0x55670906)+((0x408ac376) <= (0x64fff201))) >> 2])))))))));\n  }\n  return f; })(this, {ff: (d =>  { g0.g2.__proto__ = m1; } ).bind([])}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, 2**53-2, 1.7976931348623157e308, -0x07fffffff, -0x100000000, -0, 42, 0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, 0x080000001, 0x100000001, -0x100000001, 0.000000000000001, 0x07fffffff, 0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 2**53, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x0ffffffff, -(2**53-2), -(2**53+2), -1/0, Number.MAX_VALUE, 2**53+2, Math.PI]); ");
/*fuzzSeed-71289653*/count=65; tryItOut("t0.set(a1, 6);");
/*fuzzSeed-71289653*/count=66; tryItOut("testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x080000000, 0/0, -(2**53-2), Number.MIN_VALUE, -0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 2**53, -(2**53), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0x080000001, -0x0ffffffff, 0, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 0x0ffffffff, 0x080000001, -0, -0x080000000, -Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, -0x100000000, 0x07fffffff, 42, 1, Math.PI]); ");
/*fuzzSeed-71289653*/count=67; tryItOut("Object.defineProperty(this, \"this.v1\", { configurable: (x % 6 == 2), enumerable: (x % 6 == 0),  get: function() { /*MXX1*/o0 = g0.RegExp.multiline; return g1.eval(\"\\\"use strict\\\"; testMathyFunction(mathy4, [0/0, -1/0, -(2**53), -0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), 2**53-2, 0.000000000000001, -0x100000000, 1, -0x100000001, -0x080000001, 2**53, 0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, -0, 2**53+2, -(2**53+2), -0x07fffffff, Math.PI, -Number.MIN_VALUE, -0x0ffffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, 0x100000000, 0, 0x080000000, -Number.MAX_VALUE]); \"); } });");
/*fuzzSeed-71289653*/count=68; tryItOut("var e = (x)(x, (( /x/g ).call(-0, /(?=([\\D]|.+(?!(?:[^])))?\\2)/gyi))), x = (4277), [] = (4277), x, y = (yield [1]);/*infloop*/for(var NaN in ((WebAssemblyMemoryMode)( \"\" )))/*ADP-3*/Object.defineProperty(o1.g0.a0, 0, { configurable: true, enumerable: false, writable: false, value: s0 });for (var v of f2) { try { g0.a2.shift(a2, t0, i0, f0); } catch(e0) { } try { v0 = b2.byteLength; } catch(e1) { } try { for (var v of b0) { try { Array.prototype.forEach.apply(a0, [Int16Array]); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(o0.v1, s1); } catch(e1) { } selectforgc(g1.o0); } } catch(e2) { } t1[17] =  \"\" ; }");
/*fuzzSeed-71289653*/count=69; tryItOut("/*tLoop*/for (let d of /*MARR*/[ /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ]) { i1.next(); }");
/*fuzzSeed-71289653*/count=70; tryItOut("\"use strict\"; \"use asm\"; ");
/*fuzzSeed-71289653*/count=71; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround((( + Math.max(((x === Math.log2((x ? y : x))) >>> 0), mathy2((( + (Math.fround((Math.fround(Math.expm1(y)) && x)) >>> 0)) >>> 0), ( ! (Math.log((-1/0 | 0)) >>> 0))))) <= (((( + ( + (y >>> 0))) | 0) === Math.fround(( - Math.cos((0 | 0))))) | 0))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, 0x07fffffff, -0x07fffffff, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, -0, 42, 2**53+2, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, 2**53-2, -0x100000000, 2**53, Math.PI, -(2**53-2), -(2**53), 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0, 1, 0x080000000, 0x100000000, -(2**53+2), 1/0]); ");
/*fuzzSeed-71289653*/count=72; tryItOut("v0 = Object.prototype.isPrototypeOf.call(v1, t2);");
/*fuzzSeed-71289653*/count=73; tryItOut("L:with({d: x})(void schedulegc(g1));");
/*fuzzSeed-71289653*/count=74; tryItOut("\"use strict\"; {e0.__proto__ = f0;/*oLoop*/for (let cjtpcn = 0; cjtpcn < 24; x, ++cjtpcn) { (w); }  }");
/*fuzzSeed-71289653*/count=75; tryItOut("b1.valueOf = (function() { for (var j=0;j<4;++j) { f1(j%4==1); } });");
/*fuzzSeed-71289653*/count=76; tryItOut("\"use strict\"; h0.has = f1;");
/*fuzzSeed-71289653*/count=77; tryItOut("g0.e1 + i0;");
/*fuzzSeed-71289653*/count=78; tryItOut("v0 = evaluate(\"Array.prototype.forEach.call(a2);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 41 != 12), noScriptRval: (x % 4 == 0), sourceIsLazy: (x % 12 == 9), catchTermination: (x % 34 != 17) }));");
/*fuzzSeed-71289653*/count=79; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (mathy2(( + (Math.atanh(((x | 0) ^ Math.atan(y))) >>> 0)), ( ~ Math.imul(( - Math.tanh(Math.fround(((y >>> 0) >>> x)))), Math.atan2(Math.fround((x & 0x080000000)), ( ! y))))) >>> 0); }); ");
/*fuzzSeed-71289653*/count=80; tryItOut("a0 = Array.prototype.filter.apply(a1, [String.prototype.normalize.bind(m1)]);Array.prototype.unshift.apply(this.a2, [m2, m1]);");
/*fuzzSeed-71289653*/count=81; tryItOut("function f1(this.o1)  { \"use strict\"; return timeout(1800) } ");
/*fuzzSeed-71289653*/count=82; tryItOut("\"use strict\"; m1.get(v0);");
/*fuzzSeed-71289653*/count=83; tryItOut("v0 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-71289653*/count=84; tryItOut("\"use strict\"; testMathyFunction(mathy2, [false, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '', NaN, -0, '\\0', (new String('')), '0', ({toString:function(){return '0';}}), 0.1, (new Number(-0)), 0, undefined, '/0/', null, /0/, 1, (new Boolean(true)), [], ({valueOf:function(){return 0;}}), (new Boolean(false)), (new Number(0)), (function(){return 0;}), [0], true]); ");
/*fuzzSeed-71289653*/count=85; tryItOut("\"use strict\"; with({w: yield null})a1[(this.__defineGetter__(\"b\", offThreadCompileScript))] = [z1,,];");
/*fuzzSeed-71289653*/count=86; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - ( + Math.pow(Math.fround(( + Math.min(( + ((((( - (y >>> 0)) >>> 0) >>> 0) !== ((Math.max(x, (x | 0)) >>> 0) >>> 0)) >>> 0)), Math.fround(((mathy1((( ! (x >>> 0)) >>> 0), y) << (( + ( - ( + x))) | 0)) | 0))))), (Math.asin((( ! y) || x)) | 0)))); }); testMathyFunction(mathy3, [0.1, undefined, 0, true, [0], null, (new Boolean(false)), (new Number(-0)), /0/, '/0/', [], '\\0', '', ({valueOf:function(){return 0;}}), (new Number(0)), NaN, ({toString:function(){return '0';}}), (new Boolean(true)), (function(){return 0;}), false, objectEmulatingUndefined(), (new String('')), 1, -0, ({valueOf:function(){return '0';}}), '0']); ");
/*fuzzSeed-71289653*/count=87; tryItOut("i0 = a0.entries;");
/*fuzzSeed-71289653*/count=88; tryItOut("mathy2 = (function(x, y) { return mathy1(( - ( + ( + (({e: window}) ? ((Math.fround(( + Math.fround(y))) >>> y) >>> 0) : ( + x))))), ( + Math.imul((Math.max(( + y), Math.fround(mathy1(Math.fround((Math.clz32(2**53) , y)), Math.fround((( + y) + (y | 0)))))) | 0), ((( - Math.fround(y)) < Math.fround(Math.min(Math.fround(Math.imul(Math.fround((x ? y : x)), Math.fround(y))), -Number.MIN_SAFE_INTEGER))) | 0)))); }); testMathyFunction(mathy2, [42, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -(2**53+2), -Number.MAX_VALUE, Math.PI, 0x07fffffff, 0x100000001, -0x0ffffffff, 0x080000001, -0, 0x080000000, -1/0, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53), 1/0, -0x080000001, 0/0, 0x100000000, -Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, -0x100000000, -(2**53-2), -0x080000000, 2**53, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=89; tryItOut("\"use asm\"; s0 += s0;");
/*fuzzSeed-71289653*/count=90; tryItOut("b1.toSource = (function() { for (var j=0;j<10;++j) { f1(j%5==0); } });");
/*fuzzSeed-71289653*/count=91; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.imul(((( + Math.cosh(( + Math.fround(Math.tan((y & Math.max(x, (x + -Number.MAX_SAFE_INTEGER)))))))) !== mathy1(y, (x ^ Math.fround(Math.min(Math.fround(1.7976931348623157e308), (y | 0)))))) | 0), ((Math.log1p((( ~ 2**53) >>> 0)) >>> 0) | 0)) | 0); }); ");
/*fuzzSeed-71289653*/count=92; tryItOut("/*tLoop*/for (let d of /*MARR*/[(void 0), new Number(1.5), objectEmulatingUndefined(), (void 0), new Number(1.5), (void 0), (void 0), objectEmulatingUndefined(), new Boolean(true), (void 0), new Boolean(true), (void 0), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), (void 0), (void 0), new Boolean(true), new Boolean(true), (void 0), x, new Number(1.5), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Boolean(true), new Number(1.5), new Number(1.5), x, objectEmulatingUndefined(), x, new Number(1.5), new Boolean(true), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), x, objectEmulatingUndefined(), new Number(1.5), x, (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), (void 0), (void 0), new Number(1.5), objectEmulatingUndefined(), (void 0), new Number(1.5), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), new Number(1.5), x, (void 0), new Number(1.5), (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), x, (void 0), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), x, new Number(1.5), x, (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), x, (void 0), x, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), new Boolean(true), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Number(1.5), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), new Number(1.5), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Boolean(true), objectEmulatingUndefined()]) { /*ADP-3*/Object.defineProperty(g1.a2, 8, { configurable: true, enumerable: false, writable: false, value: i2 }); }");
/*fuzzSeed-71289653*/count=93; tryItOut("\"use strict\"; m0.has(f0);");
/*fuzzSeed-71289653*/count=94; tryItOut("\"use strict\"; /*oLoop*/for (let vmkiqf = 0; vmkiqf < 14; ++vmkiqf) { /*RXUB*/var r = new RegExp(\"\\\\2|(?=[^\\\\u00d1\\\\f])(?=\\u757f{1,3})?\\\\s{4}\", \"m\"); var s = \"\"; print(s.search(r));  } ");
/*fuzzSeed-71289653*/count=95; tryItOut("o1.a0 = r2.exec(s2);");
/*fuzzSeed-71289653*/count=96; tryItOut("g0.offThreadCompileScript(\"e0.delete(/*UUV1*/(x.getOwnPropertyDescriptors = Function));\\nprint(x = Proxy.createFunction(({/*TOODEEP*/})(this), neuter, Math.log2));\\n\");");
/*fuzzSeed-71289653*/count=97; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.cos(Math.fround(Math.hypot(Math.fround((mathy2(y, 0) !== ((mathy4(((((y === Math.fround(y)) , mathy1(( + ( + x)), x)) | 0) >>> 0), (mathy4(y, -0x07fffffff) >>> 0)) >>> 0) >>> 0))), ( ~ (Math.trunc(( + (Math.round((x | 0)) | 0))) >>> 0)))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), 2**53, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -0, 0x100000001, -1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, Math.PI, 0, 0x080000001, 1/0, 1, -0x080000001, 2**53+2, 0x07fffffff, 2**53-2, 42, -Number.MAX_VALUE, Number.MIN_VALUE, -0x100000000, -0x07fffffff, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=98; tryItOut("mathy3 = (function(x, y) { return (Math.sin((( ! (Math.min(Math.clz32(Math.fround(Math.trunc(Math.fround(mathy0(Math.fround(y), Math.fround(y)))))), Math.pow((y >>> 0), y)) | 0)) | 0)) || Math.cbrt(( - 1))); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), '0', (function(){return 0;}), /0/, 0.1, [0], true, undefined, (new Boolean(false)), ({toString:function(){return '0';}}), 1, '', 0, null, (new Number(0)), [], (new String('')), false, (new Number(-0)), -0, objectEmulatingUndefined(), (new Boolean(true)), ({valueOf:function(){return 0;}}), '\\0', NaN, '/0/']); ");
/*fuzzSeed-71289653*/count=99; tryItOut("\"use strict\"; testMathyFunction(mathy1, [false, true, 0.1, undefined, [0], objectEmulatingUndefined(), '\\0', ({valueOf:function(){return '0';}}), (new Boolean(false)), ({valueOf:function(){return 0;}}), 0, null, (new Number(0)), '/0/', [], NaN, '', (new String('')), 1, (function(){return 0;}), /0/, ({toString:function(){return '0';}}), '0', (new Number(-0)), (new Boolean(true)), -0]); ");
/*fuzzSeed-71289653*/count=100; tryItOut("print(o0.g0.o2);");
/*fuzzSeed-71289653*/count=101; tryItOut("m1.has(v2);function window(arguments.callee.arguments, e = (new Function)(w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { throw 3; }, get: (Object.getOwnPropertyDescriptors).bind(this), set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: undefined, }; })(28), Math.floor), x))({x: [(this)((z = w))], (4277): []}) = (4277)/*RXUB*/var r = x; var s = \"\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=102; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(h1, t0);");
/*fuzzSeed-71289653*/count=103; tryItOut("\"use strict\"; s0 += s1;");
/*fuzzSeed-71289653*/count=104; tryItOut("testMathyFunction(mathy5, [Math.PI, 1.7976931348623157e308, 2**53-2, -(2**53), 2**53, 0/0, 0, -Number.MIN_VALUE, 0x100000000, 1/0, 0x080000001, 0x0ffffffff, 42, 1, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x080000000, 0x07fffffff, -0x0ffffffff, -0x100000001, -(2**53+2), -(2**53-2), -0x07fffffff, Number.MIN_VALUE, 0x100000001, -0x100000000, -0, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-71289653*/count=105; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.sqrt(( - ( + Math.tanh(y)))); }); testMathyFunction(mathy0, [true, false, NaN, '', ({toString:function(){return '0';}}), 0.1, (new Boolean(false)), 0, (function(){return 0;}), -0, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), '0', (new String('')), /0/, null, 1, '/0/', (new Boolean(true)), (new Number(-0)), undefined, [], (new Number(0)), '\\0', [0], objectEmulatingUndefined()]); ");
/*fuzzSeed-71289653*/count=106; tryItOut("t2 = new Uint16Array(o2.b0, 32, 17);");
/*fuzzSeed-71289653*/count=107; tryItOut("mathy2 = (function(x, y) { return ( + Math.max(( + ( ! (( ~ (x >>> 0)) >>> 0))), ( + Math.acos(((x && y) ? Math.fround(Math.atan(Math.fround(y))) : ( ~ Math.atan2(x, x))))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, -(2**53-2), -(2**53), 2**53, -0x100000000, 0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 0/0, 42, 2**53-2, -0, -Number.MIN_VALUE, 0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, -0x100000001, 0x0ffffffff, -1/0, 0, 1, 1.7976931348623157e308, Math.PI, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, -0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=108; tryItOut("e1 = new Set(m0);");
/*fuzzSeed-71289653*/count=109; tryItOut("mathy4 = (function(x, y) { return ((Math.imul((Math.imul(( + (( ! Math.fround(x)) >>> 0)), Math.tan(( + y))) >>> 0), ((2**53+2 % mathy3(( - y), (y * Math.sin(1.7976931348623157e308)))) >>> 0)) >>> 0) ? (( ~ ((( - (x | 0)) | 0) >>> 0)) | 0) : ( - (( ~ ( + ( ~ ( + Math.pow(2**53-2, y))))) >>> 0))); }); testMathyFunction(mathy4, [(new Number(0)), (function(){return 0;}), '', '/0/', -0, (new Boolean(false)), 0, '0', /0/, ({toString:function(){return '0';}}), [0], (new String('')), 1, ({valueOf:function(){return '0';}}), false, objectEmulatingUndefined(), 0.1, undefined, NaN, (new Boolean(true)), '\\0', true, ({valueOf:function(){return 0;}}), (new Number(-0)), null, []]); ");
/*fuzzSeed-71289653*/count=110; tryItOut("\"use strict\"; h0 = ({getOwnPropertyDescriptor: function(name) { throw a0; var desc = Object.getOwnPropertyDescriptor(e1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { this.m1.delete(f1);; var desc = Object.getPropertyDescriptor(e1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { /*MXX3*/g1.Element.name = g2.Element.name;; Object.defineProperty(e1, name, desc); }, getOwnPropertyNames: function() { h0.fix = o0.f1;; return Object.getOwnPropertyNames(e1); }, delete: function(name) { t2 = g1.o1.t1.subarray((([] = this.__defineSetter__(\"x\", mathy1))));; return delete e1[name]; }, fix: function() { var s0 = new String;; if (Object.isFrozen(e1)) { return Object.getOwnProperties(e1); } }, has: function(name) { v0 = g2.runOffThreadScript();; return name in e1; }, hasOwn: function(name) { v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 5 != 1), catchTermination: true }));; return Object.prototype.hasOwnProperty.call(e1, name); }, get: function(receiver, name) { m2.get(this.f1);; return e1[name]; }, set: function(receiver, name, val) { g2 + '';; e1[name] = val; return true; }, iterate: function() { i1.send(o0.v2);; return (function() { for (var name in e1) { yield name; } })(); }, enumerate: function() { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = fillShellSandbox(newGlobal({ sameZoneAs: x, cloneSingletons: true, disableLazyParsing: (x % 3 == 0) })); f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ; var result = []; for (var name in e1) { result.push(name); }; return result; }, keys: function() { h0.getOwnPropertyDescriptor = f2;; return Object.keys(e1); } });");
/*fuzzSeed-71289653*/count=111; tryItOut("testMathyFunction(mathy5, [0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, 0x080000000, 0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, -(2**53+2), -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), 2**53, 0x07fffffff, 0, 1.7976931348623157e308, -(2**53), 42, Number.MIN_VALUE, 1/0, -Number.MIN_VALUE, Math.PI, -0x0ffffffff, -0x07fffffff, 0x100000001, -0x100000001, -1/0, 0/0, 1, 2**53+2, -0]); ");
/*fuzzSeed-71289653*/count=112; tryItOut("a1 = r1.exec(this.s1);");
/*fuzzSeed-71289653*/count=113; tryItOut("o2 = Object.create(b0);");
/*fuzzSeed-71289653*/count=114; tryItOut("/*oLoop*/for (var calkgf = 0; calkgf < 89; ++calkgf) { m0.has(f0); } ");
/*fuzzSeed-71289653*/count=115; tryItOut("testMathyFunction(mathy0, [-0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, 0/0, Math.PI, 2**53+2, -1/0, 0x080000000, 0.000000000000001, 0x0ffffffff, 42, 0x100000001, 1/0, 0x07fffffff, -Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, 2**53-2, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), 2**53, 1, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0, 1.7976931348623157e308, 0x100000000]); ");
/*fuzzSeed-71289653*/count=116; tryItOut("g1.f1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    i0 = (i1);\n    return (((0xfe6d2101)))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096));");
/*fuzzSeed-71289653*/count=117; tryItOut("this.v2 = Object.prototype.isPrototypeOf.call(p0, o0);");
/*fuzzSeed-71289653*/count=118; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((( + (Math.trunc((((x << y) !== ( ! Math.fround(y))) - (( + x) , 1))) > (Math.sinh(((Math.min((((( - x) | 0) >> x) >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0))) > Math.min(Math.imul(((Math.exp(( + ( ! ( + x)))) | 0) ? mathy0((x | 0), (y | 0)) : x),  /x/g ), Math.fround(Math.hypot(( + (( + (x ? x : 2**53-2)) ? ( + Math.atanh(x)) : ( + y))), Math.fround(( - (( ! Math.fround((y / y))) >>> 0))))))) | 0); }); testMathyFunction(mathy3, [1.7976931348623157e308, 0x100000001, 42, Number.MIN_VALUE, 2**53+2, 0x0ffffffff, 2**53-2, 0x080000001, 0x080000000, -1/0, -0x0ffffffff, -Number.MIN_VALUE, -0x080000000, 0/0, -0x080000001, Math.PI, 2**53, -0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, -(2**53), 1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53-2), -0x100000001, 0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -0]); ");
/*fuzzSeed-71289653*/count=119; tryItOut("window = eval;");
/*fuzzSeed-71289653*/count=120; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-71289653*/count=121; tryItOut("yield (new ((\nwindow)())());");
/*fuzzSeed-71289653*/count=122; tryItOut("Array.prototype.pop.call(a0);");
/*fuzzSeed-71289653*/count=123; tryItOut("\"use strict\"; /*MXX3*/g0.DataView.prototype.getInt16 = this.g0.DataView.prototype.getInt16;");
/*fuzzSeed-71289653*/count=124; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.max(Math.fround(( ! mathy2(Number.MAX_SAFE_INTEGER, (( + x) + -(2**53))))), Math.pow(Math.sinh(x), Math.sinh(y)))); }); testMathyFunction(mathy4, [2**53, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_VALUE, 1/0, -0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, 0x080000001, 1, -0x07fffffff, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 0, 2**53+2, Number.MAX_VALUE, -1/0, -0x080000001, 0.000000000000001, -0x0ffffffff, 0x100000001, 0x07fffffff, 0x0ffffffff, -0x080000000, 42, -0, 0x100000000]); ");
/*fuzzSeed-71289653*/count=125; tryItOut("\"use asm\"; if(true) {print(false);print(v0); }");
/*fuzzSeed-71289653*/count=126; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\\\\3\", \"im\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.search(r)); ");
/*fuzzSeed-71289653*/count=127; tryItOut("testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53, 0, -0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 2**53-2, -0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, -Number.MAX_SAFE_INTEGER, 1, 0x100000001, Number.MIN_VALUE, -(2**53), -Number.MAX_VALUE, -0x100000000, 0.000000000000001, 0x080000000, 0x100000000, 42, 0x080000001, Math.PI, 2**53+2, -1/0, 1/0, -0x07fffffff, 1.7976931348623157e308, 0/0, -(2**53+2), -0x080000001]); ");
/*fuzzSeed-71289653*/count=128; tryItOut("L:switch(arguments.caller) { default: break; Object.defineProperty(this, \"s2\", { configurable: new Date( /x/ ), enumerable: false,  get: function() {  return s1.charAt(v2); } });break; case 4: (new RegExp(\"\\\\B{3,3}\\\\uf355{2,}(\\\\W.{2}\\\\2)(?!^|(?:\\\\w)[^]|[\\\\x36-\\\\n\\\\u007D]\\\\\\u1a92|\\\\S{2097151,})+\", \"gym\") >>= 7);case (uneval((4277))): { if (isAsmJSCompilationAvailable()) { void 0; validategc(true); } void 0; } }\ni0.send(b1);\n");
/*fuzzSeed-71289653*/count=129; tryItOut("\"use strict\"; var wqhhda = new ArrayBuffer(0); var wqhhda_0 = new Uint8ClampedArray(wqhhda); wqhhda_0[0] = 26; print(1);return  /x/g ;(undefined);");
/*fuzzSeed-71289653*/count=130; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MAX_VALUE, Number.MIN_VALUE, -1/0, 2**53, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, -(2**53), 0/0, -0x100000000, 0x080000000, 0x0ffffffff, 0x07fffffff, 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, -Number.MAX_VALUE, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, -0x07fffffff, -0x100000001, 1, -Number.MIN_VALUE, 2**53+2, 0x100000000, 0.000000000000001, -0x080000001, 0, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-71289653*/count=131; tryItOut("((p={}, (p.z = x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get: function(receiver, name) { return x[name]; }, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { return []; }, keys: function() { return Object.keys(x); }, }; })({}), new Uint16Array()))()));");
/*fuzzSeed-71289653*/count=132; tryItOut("a2 = g2.objectEmulatingUndefined();");
/*fuzzSeed-71289653*/count=133; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.tan(( + ( - Math.fround((Math.fround(y) ? Math.fround(y) : Math.pow((mathy1((0x080000000 >>> 0), (mathy0((y >>> 0), y) >>> 0)) >>> 0), x)))))) <= Math.sqrt(Math.acosh((((Math.expm1(y) & (( + x) | 0)) >>> 0) | 0)))); }); testMathyFunction(mathy2, [2**53, Math.PI, -0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 0x0ffffffff, -(2**53-2), 1, Number.MIN_VALUE, 0/0, -0x100000001, -0x100000000, 2**53-2, -(2**53), 2**53+2, -0x080000000, 0x080000000, Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, 0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, 0.000000000000001, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, 0x080000001, 42, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=134; tryItOut("L: {o2.t1 = new Uint16Array(t0); }");
/*fuzzSeed-71289653*/count=135; tryItOut("\"use strict\"; h1.iterate = (function(a0, a1, a2, a3, a4, a5, a6, a7) { var r0 = 6 | 7; var r1 = 2 - 6; var r2 = a5 % 5; var r3 = x ^ a0; print(a2); var r4 = 5 % 2; var r5 = a6 - a7; print(r1); var r6 = 5 * 2; var r7 = 6 % a7; var r8 = r2 & r6; var r9 = a6 + 3; var r10 = a0 % 1; var r11 = 2 ^ r1; var r12 = r3 / a1; var r13 = r12 * a7; var r14 = a2 ^ 0; var r15 = x - r5; a7 = x % a1; var r16 = 7 / 6; var r17 = a6 | 2; r10 = 7 - 0; print(r8); var r18 = r0 ^ a6; var r19 = r8 ^ 8; var r20 = r5 % r6; var r21 = r20 % r19; var r22 = 1 ^ r10; var r23 = r10 | r15; r18 = 7 & a7; var r24 = r7 % 1; var r25 = 0 - 9; var r26 = r1 - a7; var r27 = a7 + a4; r0 = a2 ^ r0; print(r1); var r28 = 6 | 8; var r29 = r6 | r26; var r30 = r13 % r10; var r31 = r3 ^ r6; var r32 = 4 * r3; var r33 = 0 - r27; var r34 = r23 ^ 7; var r35 = r19 + r13; var r36 = 9 % r12; var r37 = r11 - a0; var r38 = r4 * r33; r24 = a3 | 6; var r39 = r6 & a1; var r40 = a7 & r10; var r41 = r34 & r32; var r42 = 3 * r2; var r43 = r23 * 8; r43 = r18 | 8; var r44 = r5 | 2; var r45 = r2 / r41; var r46 = r33 ^ r25; var r47 = r6 | r41; var r48 = 8 % a0; r12 = 7 ^ 9; var r49 = 4 * r7; print(a0); var r50 = r9 % r33; var r51 = 1 | r45; var r52 = 0 | r18; var r53 = 9 % a4; var r54 = r33 ^ r24; var r55 = 6 % 9; var r56 = 4 | r28; var r57 = r0 ^ r11; return a6; });");
/*fuzzSeed-71289653*/count=136; tryItOut("\"use strict\"; ;");
/*fuzzSeed-71289653*/count=137; tryItOut("/*infloop*/for(c; (w = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: undefined, has: Array.prototype.pop, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: (String.prototype.charAt).bind(x), }; })( /x/  >>>  '' ), Object.is, Uint32Array));  \"\" ) o1.v0 = Object.prototype.isPrototypeOf.call(this.g0.h1, s2);");
/*fuzzSeed-71289653*/count=138; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul(( + (( + ( + (Math.atan2(Math.sin(y), -0x07fffffff) >>> 0))) >>> 0)), ( + ((( ! ( + (( + Math.cos((((y >>> 0) == y) >>> 0))) > ( + ( + Math.atan2((y | 0), ( + (( + Math.PI) >>> 0)))))))) >>> 0) >> (Math.fround(Math.min(( + Math.exp(( + 0x07fffffff))), Math.fround(Math.fround((Math.fround((Math.tanh((((y && x) >>> 0) | 0)) | 0)) >= y))))) >>> 0)))); }); testMathyFunction(mathy0, /*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 9, 9, 9, 9, function(){}, function(){}, 9, function(){}, 9, function(){}, function(){}, function(){}, 9, 9, 9, 9, function(){}, 9, function(){}, 9, function(){}, 9, 9, 9, function(){}, 9, 9, function(){}, 9, 9, function(){}, 9, function(){}, function(){}, 9, function(){}, function(){}, 9, function(){}, function(){}, 9, function(){}, 9, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 9, function(){}, 9, function(){}, function(){}, 9, 9, function(){}, 9, 9, 9, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-71289653*/count=139; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((0xc1ad6037) == (((~~(1.5111572745182865e+23)) % (((/*FFI*/ff(((-2199023255552.0)), ((0.25)), ((-1.125)), ((144115188075855870.0)), ((-131072.0)), ((2305843009213694000.0)), ((65.0)))|0)-(i0)) | ((i0)+(i0))))>>>((i0))));\n    (Float32ArrayView[4096]) = ((Infinity));\n    d1 = (d1);\n    d1 = (+(1.0/0.0));\n    return +((NaN));\n    (Float32ArrayView[((Uint8ArrayView[2])) >> 2]) = ((2199023255553.0));\n    return +((+((-1.5474250491067253e+26))));\n  }\n  return f; })(this, {ff: mathy2}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, -1/0, 0x080000001, 1.7976931348623157e308, 0x07fffffff, 0, 1, -Number.MAX_SAFE_INTEGER, 2**53, 42, -Number.MIN_VALUE, -0x080000001, -Number.MAX_VALUE, -0, Number.MAX_VALUE, 2**53+2, -0x100000000, Number.MIN_VALUE, 1/0, -0x100000001, 0.000000000000001, 2**53-2, -0x0ffffffff, -0x080000000, -(2**53+2), -(2**53), 0x100000000, -(2**53-2), 0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=140; tryItOut("\"use strict\"; a0.forEach((function() { this.m0.delete(g1); return o0.o1; }));");
/*fuzzSeed-71289653*/count=141; tryItOut("\"use strict\"; m2 = new WeakMap;");
/*fuzzSeed-71289653*/count=142; tryItOut("o1.a1 = [];");
/*fuzzSeed-71289653*/count=143; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.log2(Math.max((( + x) !== ( + ((( ~ (((x >>> 0) >= (y >>> 0)) | 0)) | (Math.fround(Math.abs(y)) >>> 0)) >>> 0))), ((0/0 ? (x >>> 0) : (( + Math.pow(( + (x == x)), ( + ( - y)))) >>> 0)) >>> 0))) ? ( ~ ( ~ 2**53+2)) : Math.fround(Math.tanh(Math.fround((x ^ ( ~ Math.fround(x))))))); }); testMathyFunction(mathy1, [-0x080000001, -0x0ffffffff, 42, 0x080000000, -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 0x080000001, -Number.MIN_VALUE, 1, 1/0, -0, 0, Math.PI, 0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, -0x080000000, 0/0, 0x100000000, 2**53-2, 0x07fffffff, 2**53+2, -(2**53-2), -0x100000001, 1.7976931348623157e308, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-71289653*/count=144; tryItOut("e2.add(e2);");
/*fuzzSeed-71289653*/count=145; tryItOut("mathy4 = (function(x, y) { return Math.expm1(( + mathy2(Math.log((Math.log10((mathy2(((Math.imul((y | 0), (Math.fround((y >>> Math.fround(x))) | 0)) | 0) | 0), (Math.fround((( + y) | x)) | 0)) | 0)) >>> 0)), ((((y === (y | 0)) + (Math.cbrt(Number.MIN_SAFE_INTEGER) || y)) || ( ! (Math.pow(((Math.fround(Number.MIN_VALUE) <= x) >>> 0), (x >>> 0)) >>> 0))) >>> 0)))); }); testMathyFunction(mathy4, [-(2**53-2), -0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 1, 0x0ffffffff, Math.PI, 0/0, 2**53, 0.000000000000001, -1/0, 0, 0x100000001, 2**53-2, 0x080000000, 42, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, 1/0, -Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, 0x080000001, -0, -Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-71289653*/count=146; tryItOut("\"use strict\"; v1 = evaluate(\"/*RXUB*/var r = r0; var s = s0; print(uneval(s.match(r))); \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (/(\\D{3})((?=\u8549)+)*?/gyi = 3).yoyo(eval(\"print(x);\", x)), noScriptRval: x = /(?!(?!\\2*?){0,})/gyi, sourceIsLazy: (x % 114 == 106), catchTermination: (x % 3 != 0) }));");
/*fuzzSeed-71289653*/count=147; tryItOut("mathy5 = (function(x, y) { return (Math.imul((Math.atan2(42, y) ** ( + (Math.fround(Math.sqrt(Math.fround(y))) ? 0x0ffffffff : 1.7976931348623157e308))), (mathy0((( + (( + (((Math.fround(( ! Math.fround(( - y)))) | 0) << ((y << ( ~ x)) >>> 0)) | 0)) <= ( + Math.fround(Math.cosh((Math.imul(y, (y >>> 0)) >>> 0)))))) >>> 0), (( + Math.sqrt(x)) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy5, [(new String('')), (function(){return 0;}), ({toString:function(){return '0';}}), (new Number(0)), NaN, '', (new Number(-0)), false, (new Boolean(true)), /0/, '0', '/0/', ({valueOf:function(){return '0';}}), 0, (new Boolean(false)), [], objectEmulatingUndefined(), 1, null, undefined, -0, 0.1, [0], true, ({valueOf:function(){return 0;}}), '\\0']); ");
/*fuzzSeed-71289653*/count=148; tryItOut("mathy2 = (function(x, y) { return Math.cbrt(( + ( - Math.max(Math.fround(( - Math.tan(x))), (Math.fround(Math.expm1(Math.fround(y))) <= x))))); }); ");
/*fuzzSeed-71289653*/count=149; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=150; tryItOut("/*bLoop*/for (gwexfm = 0, zokujg, qnbrcg; gwexfm < 94; ++gwexfm) { if (gwexfm % 2 == 1) { print(x); } else { a0[({valueOf: function() { this.v2 = Array.prototype.some.call(a1, (function(j) { f2(j); }));return 4; }})] = o0.t2; }  } ");
/*fuzzSeed-71289653*/count=151; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -0.0625;\n    var d3 = 4.722366482869645e+21;\n    return ((((((i0) ? (i0) : (0x3118ee36))-((0x4550e01a))) ^ ((0xfdfb5d83)+(i0)+((imul((-0x8000000), ((((0xe59a3cf6))>>>((0x35fb67ab)))))|0)))) % ((((abs((~~(((d1)) % ((Float64ArrayView[2])))))|0))+((-0x8000000) ? ((0x8a6d922b) < (0x5a801d49)) : (!(0x633dabf2))))|0)))|0;\n    return ((x))|0;\n    i0 = (i0);\n    return (((i0)+(0xfbf9ba16)))|0;\n  }\n  return f; })(this, {ff: Math.atan}, new ArrayBuffer(4096)); ");
/*fuzzSeed-71289653*/count=152; tryItOut("for (var v of i2) { for (var p in t0) { try { o0 = new Object; } catch(e0) { } try { print(uneval(e2)); } catch(e1) { } try { /*MXX3*/g2.DataView.prototype.byteLength = g0.DataView.prototype.byteLength; } catch(e2) { } g1 = this; } }function x() { return \"\\u2DD5\" } Array.prototype.shift.call(a1, g2.i1);function b(NaN = (let (w) x), ...window) { \"use strict\"; \"use asm\"; return ((function too_much_recursion(ejouis) { ; if (ejouis > 0) { /*RXUB*/var r = /(?:((?=(\\B|[^]{3})))+?(?![^\u00e6-\u6185])|\\3**?.*?+)/y; var s = \"\"; print(s.replace(r, (( /x/ )(x)), \"g\")); ; too_much_recursion(ejouis - 1);  } else {  } /*infloop*/for(w; allocationMarker(); [[z1,,]]) {v0 = (o0 instanceof this.a0); } })(50929)) } var rkuctu = new ArrayBuffer(16); var rkuctu_0 = new Uint32Array(rkuctu); o1.e1.delete(false ^ undefined);v1 = b2.byteLength;print( '' );");
/*fuzzSeed-71289653*/count=153; tryItOut("\"use asm\"; t2 + m2;");
/*fuzzSeed-71289653*/count=154; tryItOut("\"use strict\"; for(let c in undefined) t2.__proto__ = t0;");
/*fuzzSeed-71289653*/count=155; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (Math.sqrt((Math.cos(( + Math.hypot(mathy0(-0x080000001, ( ! -0x0ffffffff)), Math.pow(( + ( - ( + x))), x)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [0, -Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 1, -0, 0x0ffffffff, 0x100000001, -(2**53), 0x080000001, Number.MAX_VALUE, 0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, 1/0, 0x100000000, Math.PI, -0x07fffffff, -0x080000001, 0.000000000000001, -Number.MAX_VALUE, 42, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, -0x100000000, 2**53, -(2**53+2)]); ");
/*fuzzSeed-71289653*/count=156; tryItOut("mathy3 = (function(x, y) { return ((( + Math.acosh(( + (((0.000000000000001 >>> 0) ** Math.cbrt(x)) >>> 0)))) ? (Math.atan2(( + ( - ( + Math.log2(Math.max((( + ( ! ( + -(2**53)))) | 0), (x | 0)))))), (Math.fround((mathy2((Math.tanh((( ! x) | 0)) | 0), (x | 0)) && ( - Math.fround((y & Math.fround(x)))))) | 0)) | 0) : Math.clz32(Math.expm1(( - x)))) | 0); }); testMathyFunction(mathy3, [-0, Math.PI, -0x080000001, -1/0, 42, 0, 2**53, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000001, -(2**53-2), -(2**53), 0x0ffffffff, 0x100000000, 0x080000001, 1/0, -(2**53+2), 2**53+2, 2**53-2, 0/0, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=157; tryItOut("print(x);");
/*fuzzSeed-71289653*/count=158; tryItOut("v1 = g0.runOffThreadScript();");
/*fuzzSeed-71289653*/count=159; tryItOut("mathy1 = (function(x, y) { return Math.min(Math.hypot(Math.imul(( + ( + Math.sinh(x))), y), Math.atan2(( ~ (( ! ( + x)) | 0)), y)), ((((x >>> 0) / mathy0(y, ( + ( ! x)))) >>> 0) ^ Math.exp(x))); }); testMathyFunction(mathy1, [/0/, (new Number(0)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), 0.1, '/0/', 0, (new Boolean(true)), false, (function(){return 0;}), NaN, true, null, '', (new String('')), objectEmulatingUndefined(), 1, (new Boolean(false)), -0, [], '0', [0], (new Number(-0)), '\\0', undefined, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-71289653*/count=160; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.atan2(Math.fround((( + ( ~ ( + Math.atan(2**53)))) >>> ((y < ( + Math.round((x >>> 0)))) / ( + Math.sqrt((x >>> 0)))))), Math.fround(Math.imul(Math.imul((Math.pow(x, ( + y)) ** Math.fround(x)), ((( + (Math.hypot(x, -0x080000000) | 0)) | 0) !== (Math.PI | 0))), ( + Math.exp(Math.sin((( ~ (1 | 0)) | 0))))))); }); testMathyFunction(mathy0, [-1/0, 2**53+2, Math.PI, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, 1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, 42, 1, -(2**53), -0, 2**53-2, 0.000000000000001, 2**53, -(2**53+2), 0/0, -0x080000001, 0x0ffffffff, 0x080000000, 0x080000001, 0, -0x100000001, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, 0x100000000, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=161; tryItOut("\u3056.x = x\u0009;");
/*fuzzSeed-71289653*/count=162; tryItOut("\"use asm\"; e1.__proto__ = v0;");
/*fuzzSeed-71289653*/count=163; tryItOut("o0.g2.g2 + this.o2.m1;\nthrow false;\n");
/*fuzzSeed-71289653*/count=164; tryItOut("g1.a2.reverse(o2);");
/*fuzzSeed-71289653*/count=165; tryItOut("mathy0 = (function(x, y) { return (Math.cos(( + ((Math.asinh((( + Math.cosh(( + 42))) | 0)) | (( + Math.atan(Math.atan2((((x >>> 0) ? (x | 0) : Math.fround(x)) | 0), x))) ? (Math.log10(Math.fround(y)) | 0) : Math.fround(y))) ** Math.hypot(Math.fround(Math.fround((Math.fround(0x0ffffffff) ^ Math.fround(((((Math.sqrt((Math.sin(( + x)) >>> 0)) >>> 0) | 0) ? (( ! 2**53+2) | 0) : (x | 0)) | 0))))), (( + Math.sinh(-0x07fffffff)) >>> 0))))) >>> 0); }); testMathyFunction(mathy0, [1/0, 2**53+2, 2**53, -(2**53+2), 0.000000000000001, 0/0, 0x0ffffffff, 0, -0x07fffffff, -0x080000001, -0, Number.MIN_VALUE, 1, -Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, 0x100000001, 2**53-2, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), -(2**53-2), Math.PI, 0x07fffffff, 0x100000000, -0x080000000, 1.7976931348623157e308, -1/0, 42, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=166; tryItOut("/*RXUB*/var r = /(?=\\3\\B*{2,3})(?!((\\B))|[\\W\\][^\\\u0009-\\uaDE0\\w\\D]*)|.+?|\\u6983*\\S(?=[\\W\\t-\\cT\\\u00a0-\u00cb\\s]\\0)|(?=(?:[^\\cG\\W\u27c1-\\u00f0]))|(?=\\B*){1,}{4,}/gy; var s = \"\\n\\n\\n\\naa\\n\\n\\n\\naa\\n\\n\\n\\naa\\n\\n\\n\\naa_00a\\n\\n\\n\\naa\\n\\n\\n\\naa\\n\\n\\n\\naa\\n\\n\\n\\naa_00a\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=167; tryItOut("/*oLoop*/for (wwiijw = 0; wwiijw < 58; x, ++wwiijw) { g2.v2.__proto__ = p1; } ");
/*fuzzSeed-71289653*/count=168; tryItOut("Object.defineProperty(g1, \"this.t1\", { configurable: false, enumerable: (x % 3 == 0),  get: function() {  return new Uint16Array(g1.b1, 48, v2); } });");
/*fuzzSeed-71289653*/count=169; tryItOut(";");
/*fuzzSeed-71289653*/count=170; tryItOut("");
/*fuzzSeed-71289653*/count=171; tryItOut("print(o0);");
/*fuzzSeed-71289653*/count=172; tryItOut("switch(new RegExp(\"^|\\\\s+?|(?=(?:[^]|[\\u00df\\\\x74-\\u00c0\\\\xb0-\\uc60b]+?+?)*)\", \"gym\")) { default: print(x);\ni0.next();\n }");
/*fuzzSeed-71289653*/count=173; tryItOut("\"use strict\"; /*vLoop*/for (pyhmwt = 0; pyhmwt < 42; ++pyhmwt) { y = pyhmwt; o2.toSource = (function() { try { Array.prototype.sort.apply(a1, [f2]); } catch(e0) { } this.v1 = evalcx(\"b2 = new ArrayBuffer(0);\", g2); return o1; }); } ");
/*fuzzSeed-71289653*/count=174; tryItOut("/*oLoop*/for (var ymfcml = 0; ymfcml < 23; ++ymfcml) { a0 = a2.concat(g1.t1, a1); } ");
/*fuzzSeed-71289653*/count=175; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(p2, g0.i0);");
/*fuzzSeed-71289653*/count=176; tryItOut("\"use strict\"; Array.prototype.shift.apply(a2, []);");
/*fuzzSeed-71289653*/count=177; tryItOut("let sddsjo, c, x, yalqrd, pmsrmk, a, uinxko, x, e, tusswu;print(x);");
/*fuzzSeed-71289653*/count=178; tryItOut("Array.prototype.pop.call(a2);");
/*fuzzSeed-71289653*/count=179; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.imul(( + (Math.max((Math.log2(Math.fround((y < Math.fround(Math.min(Math.min(Math.sin(-0x080000000), Math.pow(x, y)), Math.fround((Math.fround(( + mathy0((Number.MAX_SAFE_INTEGER | 0), ( + y)))) != Math.fround(x)))))))) | 0), ((Math.trunc(Math.ceil(y)) >>> 0) | 0)) | 0)), Math.max(( + Math.sign((Math.fround((Math.fround(x) >> Math.fround(x))) % ( - y)))), ( ~ Math.imul(( + (y ? (Math.imul(x, (y >>> 0)) >>> 0) : -Number.MIN_VALUE)), ( + Math.imul((x | 0), (Math.fround(( + Math.fround(( - y)))) | 0))))))); }); testMathyFunction(mathy1, [-0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -0, 0, 1/0, 0x080000001, 2**53-2, -1/0, 0x100000000, 2**53, -0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, 2**53+2, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 42, 0.000000000000001, -(2**53+2), Number.MIN_VALUE, 1, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, 0x100000001, 0/0, Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=180; tryItOut("mathy3 = (function(x, y) { return ((Math.fround((Math.hypot(( + Math.tan(( - x))), ( + ( ~ y))) , (y * (((Math.max((y | 0), (( ~ 0x080000000) | 0)) | 0) >>> (( + (y >>> 0)) >>> 0)) >>> 0)))) && Math.fround((Math.fround(( + Math.fround(Math.fround(( ! Math.fround(( + mathy2(( + ( + Math.imul(( + y), ( + y)))), Math.hypot(Math.fround(x), (1/0 | 0)))))))))) != Math.fround((( + ( ! x)) >= ((y ? ( + Math.sign((y * Math.fround(Math.abs(Math.fround(y)))))) : (((( + (( + x) * ( + x))) >>> 0) >= 0.000000000000001) >>> 0)) | 0)))))) >>> 0); }); testMathyFunction(mathy3, [2**53, -0x100000000, -(2**53), Number.MAX_VALUE, 0.000000000000001, 0x080000001, -(2**53+2), -(2**53-2), 1/0, 0x100000000, 0/0, 1.7976931348623157e308, 2**53+2, Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, 2**53-2, 1, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -0, -Number.MAX_VALUE, 0x080000000, -0x0ffffffff, 0x0ffffffff, 42, -0x080000000, -1/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=181; tryItOut("\"use strict\"; this.v2 = ((4277) &= x)(x = NaN, x);");
/*fuzzSeed-71289653*/count=182; tryItOut("mathy2 = (function(x, y) { return Math.hypot(Math.fround(( ~ ((( ~ ((( ! (Math.sign(x) | 0)) | 0) >> (Math.acos(( + 0x07fffffff)) >>> 0))) >>> 0) >>> 0))), mathy0(((( - Math.hypot(( + mathy0(( ~ y), Math.sinh(-Number.MAX_VALUE))), Math.pow((( ~ (-0x100000000 >>> 0)) >>> 0), ((y | 0) != (((x >>> 0) % (x >>> 0)) >>> 0))))) | 0) | 0), (mathy0((((( + x) > (Math.exp(Math.fround(( + (x * ( + x))))) | 0)) | 0) >>> 0), (mathy0(((decodeURI).bind)( \"\" ), y) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [Math.PI, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, -0x100000000, -(2**53), 1/0, -0x100000001, Number.MAX_VALUE, 2**53, 0x080000001, -0, 0/0, -(2**53+2), -Number.MIN_VALUE, 0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, -0x0ffffffff, 0.000000000000001, -(2**53-2), -0x080000001, 2**53-2, -0x080000000, 42, 0x0ffffffff, 2**53+2, 1.7976931348623157e308, 0x100000000, 0x100000001]); ");
/*fuzzSeed-71289653*/count=183; tryItOut("v0 = (o0.t1 instanceof h1);");
/*fuzzSeed-71289653*/count=184; tryItOut("/*vLoop*/for (var jozwpf = 0; jozwpf < 69; ++jozwpf) { y = jozwpf; print(f0); } ");
/*fuzzSeed-71289653*/count=185; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=186; tryItOut("{ void 0; void schedulegc(this); }");
/*fuzzSeed-71289653*/count=187; tryItOut("\"use strict\"; let a, -8, bkpxnq, btazku, ahtdfh, x, rqoifl, window; \"\" ;let a =  \"\" ;");
/*fuzzSeed-71289653*/count=188; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.atanh(((Math.log(((Math.acosh((Math.fround(mathy0(Math.fround(Math.imul(Math.atan2(x, Number.MIN_SAFE_INTEGER), y)), Math.fround(x))) | 0)) | 0) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy1, [-0x07fffffff, -Number.MAX_SAFE_INTEGER, 0, 1, -1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, Number.MIN_VALUE, 0x100000001, -0x100000001, Math.PI, 0.000000000000001, -0x0ffffffff, -0, 1/0, 0x100000000, -0x080000000, 42, -(2**53), 2**53+2, 0x07fffffff, Number.MAX_VALUE, 2**53-2, 0x080000000, -0x100000000, -0x080000001, -(2**53+2), 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, 2**53, 0x0ffffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=189; tryItOut("v2 = Array.prototype.every.apply(a0, [(function() { try { this.a1.unshift(g1, b1, this.v2, this.a0, o1.h1); } catch(e0) { } try { a2 = Array.prototype.slice.apply(a2, [NaN, 0]); } catch(e1) { } ((void options('strict'))) = t2[1]; return v1; }), g1, o0.b2, s2]);\ne1.add(t2);\n");
/*fuzzSeed-71289653*/count=190; tryItOut("let (w) { /* no regression tests found */ }");
/*fuzzSeed-71289653*/count=191; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.exp(((( + Math.fround((Math.fround(Math.atanh(-Number.MAX_SAFE_INTEGER)) , Math.fround(( ! ((((x | 0) <= (x | 0)) | 0) > (Math.atan2(Math.fround(Math.imul(Number.MIN_VALUE, Math.fround(x))), (0x100000000 | 0)) | 0))))))) !== ( + (y ? ( + ( + Math.atanh(( + ( + Math.max(Math.fround(y), Math.fround(1.7976931348623157e308))))))) : Math.min(y, Number.MAX_VALUE)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, -0x0ffffffff, -Number.MIN_VALUE, 1/0, 2**53+2, -(2**53+2), -(2**53-2), -Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, 0x07fffffff, -1/0, 1, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), -0, 42, 0/0, -0x100000001, 0x080000001, 2**53, 2**53-2, 0x100000000, 0x080000000, 0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000]); ");
/*fuzzSeed-71289653*/count=192; tryItOut("g2.a0 = m0.get(e1);");
/*fuzzSeed-71289653*/count=193; tryItOut("/*bLoop*/for (sedihs = 0; sedihs < 18; ++sedihs) { if (sedihs % 4 == 0) { for (var v of v2) { try { o2.h1.get = f0; } catch(e0) { } try { Object.defineProperty(this, \"s2\", { configurable: false, enumerable: false,  get: function() {  return Array.prototype.join.apply(a2, [s1, h1]); } }); } catch(e1) { } try { Array.prototype.shift.call(a0); } catch(e2) { } /*MXX3*/g2.Date.prototype.getHours = g1.Date.prototype.getHours; } } else { e0.add(c); }  } ");
/*fuzzSeed-71289653*/count=194; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.imul((Math.asinh(Math.pow(mathy3(Math.expm1(((Math.fround((( + x) * Math.fround(x))) ? y : Math.fround(-0x07fffffff)) | 0)), x), (y ^ -0x100000001))) | 0), (Math.asinh(Math.atanh((Math.pow(y, (y | 0)) >>> 0))) | 0)); }); testMathyFunction(mathy5, /*MARR*/[[undefined], x, x, [undefined], x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, [undefined], [undefined], x, [undefined], x, [undefined], x, x, [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], x, [undefined], x, x, x, [undefined], x, [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], x, [undefined], x, [undefined], [undefined], [undefined], x, [undefined], x, x, x, x, x, x, x, [undefined], x, x, x, [undefined], [undefined], [undefined], x, x, x, x, x, [undefined], x, [undefined], [undefined], x, x, [undefined], x, x, x, x, x, [undefined], x, x, x]); ");
/*fuzzSeed-71289653*/count=195; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=196; tryItOut("x = x, eval, x, z = \"\\uBB61\" ||  '' , c;o2.s2 = new String;");
/*fuzzSeed-71289653*/count=197; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[Math.PI, function(){}, Math.PI, Math.PI, function(){}, Math.PI, function(){}, new Number(1.5), Math.PI, function(){}, new Number(1.5), function(){}, function(){}, new Number(1.5), true, new Number(1.5), Math.PI, true, true, Math.PI, true, true, true, true, true, true, Math.PI, new Number(1.5), Math.PI, Math.PI, new Number(1.5), new Number(1.5), Math.PI, new Number(1.5), true, function(){}, true, true, new Number(1.5), true, Math.PI, new Number(1.5), Math.PI, new Number(1.5), true, function(){}, true, function(){}, true, Math.PI, true, Math.PI, Math.PI, Math.PI, Math.PI, true, Math.PI]); ");
/*fuzzSeed-71289653*/count=198; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-1/0, 0x100000001, 0x080000001, -0x100000001, -0x080000001, 42, -0, -0x07fffffff, -0x100000000, 1.7976931348623157e308, 0x080000000, Math.PI, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53, 1/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, -0x080000000, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, 0/0, 0.000000000000001, 0x07fffffff, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=199; tryItOut("m2.set(b0, v2);");
/*fuzzSeed-71289653*/count=200; tryItOut("v2 = true;");
/*fuzzSeed-71289653*/count=201; tryItOut("const x = 'fafafa'.replace(/a/g, window), x, window = Math.hypot(-10, x), obcqjq, getter, x = ((e = w).__defineSetter__(\"a\", false)), NaN = x, x = x, ojxkep, ohpddq;print(x);");
/*fuzzSeed-71289653*/count=202; tryItOut("/*bLoop*/for (var gxkcit = 0; gxkcit < 49; ++gxkcit) { if (gxkcit % 6 == 0) { v0 = evalcx(\"(intern((p={}, (p.z = \\\"\\\\u14F3\\\")())))\", g2); } else { /*tLoop*/for (let z of /*MARR*/[ 'A' , true,  'A' ,  'A' ,  'A' , true,  'A' ,  'A' ,  'A' ,  'A' , true,  'A' , true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,  'A' ,  'A' ,  'A' ,  'A' , true, true, true, true,  'A' , true,  'A' ,  'A' , true, true, true,  'A' , true, true,  'A' , true, true, true, true, true,  'A' , true,  'A' ,  'A' ,  'A' , true, true,  'A' ,  'A' , true,  'A' , true,  'A' , true,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , true,  'A' , true,  'A' , true, true]) { a1.shift(h1, i0); } }  } ");
/*fuzzSeed-71289653*/count=203; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=204; tryItOut("mathy4 = (function(x, y) { return Math.atan2((Math.atan2(Math.hypot(Math.fround(Math.hypot(Math.fround(( - Math.fround(( ~ -0x080000000)))), Math.fround((Math.round(( + y)) >>> 0)))), Math.fround(mathy1(0x100000000, Math.fround(2**53+2)))), Math.atan2(Math.trunc(y), (( + y) <= x))) | 0), Math.fround(((Math.fround(( ! x)) ^ ((( + ((-0x07fffffff << -0x07fffffff) === Math.abs(-0x100000001))) && ( + mathy1(Math.fround(y), (Math.fround(y) ? -(2**53) : x)))) | 0)) | 0))); }); testMathyFunction(mathy4, /*MARR*/[ '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , (-1/0),  '\\0' ,  '\\0' , ({x:3}),  '\\0' , (-1/0), ({x:3}), (-1/0), (-1/0), (-1/0), (-1/0),  '\\0' , ({x:3}), ({x:3}), ({x:3}),  '\\0' , ({x:3}), (-1/0), ({x:3}), ({x:3}), ({x:3}),  '\\0' , ({x:3}), (-1/0), ({x:3}), ({x:3}), ({x:3}),  '\\0' , (-1/0), (-1/0),  '\\0' , (-1/0), ({x:3}),  '\\0' , (-1/0),  '\\0' ,  '\\0' ,  '\\0' , ({x:3}), (-1/0), ({x:3}), (-1/0), ({x:3}),  '\\0' , ({x:3}), (-1/0),  '\\0' , (-1/0), ({x:3}),  '\\0' ,  '\\0' ,  '\\0' , ({x:3}), ({x:3}),  '\\0' ]); ");
/*fuzzSeed-71289653*/count=205; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return mathy2(Math.pow((Math.fround(( ~ x)) ** Math.fround((( ~ x) >>> 0))), (Math.min((( + (y ? x : x)) === Math.fround(( - ( + y)))), ( + (( + Math.pow(( + (x ^ y)), -(2**53))) ^ ( + y)))) % ( + Math.max(Math.fround(Math.round(Math.fround(( + ( - y))))), Math.fround(Math.max((( ! (-Number.MAX_SAFE_INTEGER | 0)) | 0), (mathy2(( + (( + y) >>> 0)), Math.fround(y)) >>> 0))))))), ( + (((( ~ Math.imul(( + (( + (( ! (x >>> 0)) >>> 0)) === ( + ( + y)))), y)) | 0) >>> 0) - ((Math.fround((( ! (Math.sinh(x) >>> 0)) >>> 0)) , Math.fround((mathy0(((mathy1(( + Math.pow(y, (( - y) | 0))), (x | 0)) | 0) | 0), Math.fround(-(2**53))) | 0))) >>> 0)))); }); testMathyFunction(mathy3, [Math.PI, 0x100000000, -1/0, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0x080000001, 2**53+2, 1/0, 0x07fffffff, -Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, 2**53, 0, Number.MAX_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), Number.MIN_VALUE, 0x0ffffffff, -0x100000001, 0x100000001, -(2**53-2), 2**53-2, 0x080000001, -0, -Number.MAX_VALUE, 0/0, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=206; tryItOut("mathy2 = (function(x, y) { return mathy0((Math.ceil(((Math.pow((((((mathy1(y, (Math.fround((Math.fround(Number.MAX_VALUE) === y)) >>> 0)) >>> 0) != x) >>> 0) != (mathy0(((Math.atan2(( + x), (-0x080000001 >>> 0)) | 0) >>> 0), Math.fround(y)) >>> 0)) >>> 0), (( + Math.acosh(( + x))) >>> 0)) >>> 0) | 0)) >>> 0), ( - Math.acosh(Math.hypot(Math.fround(Math.cosh(Math.fround(0x100000000))), Math.fround((( ~ x) | 0)))))); }); ");
/*fuzzSeed-71289653*/count=207; tryItOut("print(x);");
/*fuzzSeed-71289653*/count=208; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -1.5111572745182865e+23;\n    var d5 = 274877906943.0;\n    var i6 = 0;\n    d5 = (d4);\n    i6 = ((i0) ? ((+(((0x2a7fe744)-(i6))|0)) >= (x)) : (!(!(((0x9e0d8591) > (0x15a81cb6)) ? ((0xe8998334)) : (0xa2ee75f5)))));\n    d4 = (268435457.0);\n    d4 = (7.737125245533627e+25);\n    i0 = ((i1) ? (i3) : (i2));\n    {\n      i3 = (0xb666a167);\n    }\n    d4 = (+abs(((d5))));\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: function shapeyConstructor(grysbz){\"use strict\"; for (var ytqvwxonu in grysbz) { }grysbz[\"hypot\"] = (void 0);{ for (var v of v2) { try { this.v1 = a1[\"call\"]; } catch(e0) { } try { this.g2.m0.toString = g1.f0; } catch(e1) { } b0 = new SharedArrayBuffer(68); } } delete grysbz[\"hypot\"];delete grysbz[\"hypot\"];delete grysbz[\"hypot\"];grysbz[\"hypot\"] = (arguments || [1]).__defineSetter__(\"(Object.getPrototypeOf)\", grysbz);return grysbz; }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, 0x100000001, 1/0, 42, -0x100000000, -0, -(2**53), Number.MIN_VALUE, -Number.MIN_VALUE, -0x0ffffffff, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, -1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, -(2**53+2), 0, 0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, 0x100000000, 1, Number.MAX_VALUE, 0x07fffffff, 2**53, 1.7976931348623157e308, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=209; tryItOut("\"use strict\"; \"use asm\";  for (b of (yield ({0: 24 }))) if((x % 84 == 42)) { if (-13)  \"\" ; else {print(x);print(this); }}");
/*fuzzSeed-71289653*/count=210; tryItOut("for (var p in g2.o1.e1) { try { o0.t2 = this.t1.subarray(2, 5); } catch(e0) { } try { for (var v of a0) { m2.set(b2, f2); } } catch(e1) { } g2.p0 = t2[15]; }");
/*fuzzSeed-71289653*/count=211; tryItOut("{/*ADP-3*/Object.defineProperty(a1, Object.defineProperty(x, \"cosh\", ({writable: Math.atan2(4,  /x/ ), configurable: false})), { configurable: (++eval), enumerable:  /* Comment */e = Proxy.createFunction(({/*TOODEEP*/})(22), y =>  { return  \"\"  } , (function(x, y) { \"use strict\"; return x; })), writable: (x % 2 != 1), value: b0 }); }");
/*fuzzSeed-71289653*/count=212; tryItOut("v2 = evaluate(\"function f1(o1) \\\"use asm\\\";   function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    d1 = ((-((d1))) + (d1));\\n    i0 = (i0);\\n    return ((((((0x2ab33fd5)-(!(i0)))>>>((0x6cf5bd97)+(0xffffffff)-((((0x1d855761)) & ((0xffffffff))) == (~((0xffffffff)-(0xffffffff)))))) >= (((i0)-(1))>>>((i0))))))|0;\\n  }\\n  return f;\", ({ global: o0.g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: timeout(1800), sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-71289653*/count=213; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (( ~ Math.fround(( ~ x))) ? ( ~ (Math.max(( + Math.min((x | 0), x)), (y | 0)) | 0)) : ((Math.fround(( - Math.fround(y))) ? (Math.hypot((( ! ( + ( + Math.min(Math.fround(Math.fround(Math.sign(Math.fround(-0x07fffffff)))), ( - (x | 0)))))) >>> 0), ((Math.max(x, (Math.fround(Math.tanh((( + (x & x)) | 0))) | 0)) | 0) >>> 0)) >>> 0) : (y ? ( + ( + y)) : y)) >>> 0))); }); testMathyFunction(mathy5, [-0x07fffffff, Number.MIN_VALUE, Math.PI, 0, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 0/0, -0x080000001, 2**53-2, 1/0, -(2**53-2), 1, 0x07fffffff, 42, 0x0ffffffff, -1/0, 0x100000000, 2**53, -0x100000000, -(2**53+2), -0x080000000, -0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -0, 0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=214; tryItOut("");
/*fuzzSeed-71289653*/count=215; tryItOut("g0.a2 = arguments.callee.caller.caller.arguments;");
/*fuzzSeed-71289653*/count=216; tryItOut("e2 = new Set(i0);");
/*fuzzSeed-71289653*/count=217; tryItOut("testMathyFunction(mathy4, [-Number.MIN_VALUE, -0, 0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 2**53, 2**53+2, 0.000000000000001, -0x100000001, 0x100000001, 0x0ffffffff, -(2**53-2), 1.7976931348623157e308, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, 0x080000000, 0/0, -(2**53+2), 2**53-2, 0x080000001, 42, Math.PI, -0x080000001, -(2**53), -0x07fffffff, -1/0, 1, Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=218; tryItOut("mathy5 = (function(x, y) { return Math.max((Math.acosh((Math.imul((Math.exp((( - -Number.MIN_VALUE) | 0)) | 0), ((Math.round(( ! (x | 0))) | 0) | 0)) | 0)) | 0), (Math.sinh(Math.min(( + Math.fround(( ! Math.exp(2**53+2)))), ( + ( - ( + x))))) | 0)); }); ");
/*fuzzSeed-71289653*/count=219; tryItOut("\"use strict\"; this.t2 = new Int32Array(v2);if((x % 33 == 21)) { if ((Set.prototype.clear.prototype)) print((arguments) =  /x/ );} else \u0009a0[NaN] = t0;");
/*fuzzSeed-71289653*/count=220; tryItOut("M:with(x)/*ODP-1*/Object.defineProperty(i1, -2, ({value: 'fafafa'.replace(/a/g, offThreadCompileScript), writable: Math.throw( /x/g )}));");
/*fuzzSeed-71289653*/count=221; tryItOut("\"use strict\"; /*MXX3*/g2.Object.isExtensible = g0.Object.isExtensible;");
/*fuzzSeed-71289653*/count=222; tryItOut("h0.toSource = f0;");
/*fuzzSeed-71289653*/count=223; tryItOut("((makeFinalizeObserver('nursery')));");
/*fuzzSeed-71289653*/count=224; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[-0x07fffffff, ({x:3}), function(){}, ({x:3}), ({x:3}), -0x07fffffff, -0x07fffffff, function(){}, ({x:3}), function(){}, -0x07fffffff, ({x:3}), function(){}, -0x07fffffff, function(){}, function(){}, ({x:3}), -0x07fffffff, function(){}, -0x07fffffff, ({x:3}), ({x:3}), -0x07fffffff, -0x07fffffff, ({x:3}), ({x:3}), ({x:3}), ({x:3}), -0x07fffffff, -0x07fffffff, -0x07fffffff, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, -0x07fffffff, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, ({x:3}), function(){}, -0x07fffffff, ({x:3}), ({x:3}), ({x:3}), -0x07fffffff, function(){}]) { Array.prototype.push.apply(a0, [f2, this.g0.o2.m0, t2, t0,  \"\" , m0]); }");
/*fuzzSeed-71289653*/count=225; tryItOut("let(x, x, d = (\u3056 = b), jnltbu, b = ({x:  /x/ }) > (4277)) { return \"\\uAE8F\";}");
/*fuzzSeed-71289653*/count=226; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-71289653*/count=227; tryItOut("v2 = (m2 instanceof g0.b0);");
/*fuzzSeed-71289653*/count=228; tryItOut("e1 + b0;");
/*fuzzSeed-71289653*/count=229; tryItOut("function f0(g0)  { \"use strict\"; s1 += 'x';v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (g0 % 6 == 4), sourceIsLazy: (g0 % 4 == 1), catchTermination: false })); } ");
/*fuzzSeed-71289653*/count=230; tryItOut("\"use strict\"; v0 = g0.runOffThreadScript();");
/*fuzzSeed-71289653*/count=231; tryItOut("mathy1 = (function(x, y) { return (Math.hypot((( + (( + Math.pow((( + ( - 0/0)) | 0), (Math.clz32(( - Math.asin(-1/0))) | 0))) ? ( + (Math.sign(Math.acos(Math.sinh(Number.MIN_SAFE_INTEGER))) >>> 0)) : ( - (Math.fround(mathy0(Math.fround(( ! x)), Math.fround(Math.hypot((y >>> 0), (x >>> 0))))) | 0)))) | 0), (( + ( - ( + Math.tanh((Math.exp((Math.atan2(((y >>> (Math.atanh((x >>> 0)) >>> 0)) >>> 0), (x | 0)) >>> 0)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy1, [[0], (new Number(-0)), (new String('')), [], ({toString:function(){return '0';}}), (new Number(0)), /0/, '0', 1, true, '', (function(){return 0;}), false, (new Boolean(false)), (new Boolean(true)), ({valueOf:function(){return 0;}}), null, 0, '/0/', undefined, NaN, objectEmulatingUndefined(), -0, ({valueOf:function(){return '0';}}), 0.1, '\\0']); ");
/*fuzzSeed-71289653*/count=232; tryItOut("mathy5 = (function(x, y) { return ( + (( + ( + ( ! mathy3((Math.atan2((Math.asin(Math.fround((Math.tanh((y | 0)) | 0))) >>> 0), ((Math.ceil((y | 0)) | 0) ^ ( + ( ~ ( + y))))) | 0), ( - (((x || (( + 1.7976931348623157e308) | 0)) | 0) | 0)))))) , Math.max(( + Math.fround((Math.fround((((Math.hypot(Math.ceil((0x0ffffffff >>> 0)), (Math.imul((y | 0), (y >>> 0)) >>> 0)) >>> 0) !== (y >>> 0)) >>> 0)) > Math.fround(Math.atan2(y, (Math.atan2(Math.fround(x), (y >>> 0)) >>> 0)))))), (( + x) >>> x)))); }); testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-71289653*/count=233; tryItOut("testMathyFunction(mathy5, /*MARR*/[new Boolean(false), new Boolean(false), new Boolean(false), [1], [1], [1], new Boolean(false), [1], new Boolean(false), [1], [1], new Boolean(false), [1], [1], [1], new Boolean(false), [1], new Boolean(false), new Boolean(false), [1], new Boolean(false), [1], new Boolean(false), new Boolean(false), [1], new Boolean(false), new Boolean(false), [1], new Boolean(false), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new Boolean(false), [1], new Boolean(false), [1], new Boolean(false), new Boolean(false), new Boolean(false), [1], [1], new Boolean(false), [1]]); ");
/*fuzzSeed-71289653*/count=234; tryItOut("(null);\n(11);\n");
/*fuzzSeed-71289653*/count=235; tryItOut("\"use strict\"; e2.add(p0);");
/*fuzzSeed-71289653*/count=236; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MIN_VALUE, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 0/0, -0x0ffffffff, 0.000000000000001, Number.MAX_VALUE, 1/0, 0x0ffffffff, -Number.MIN_VALUE, 0x07fffffff, 2**53, 0x080000001, -0x07fffffff, -(2**53), -0x100000000, -0, 2**53+2, -0x080000000, 0x080000000, -0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 2**53-2, 42, Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-71289653*/count=237; tryItOut("o2.g1.offThreadCompileScript(\"/* no regression tests found */\");\nprint(m2);\n");
/*fuzzSeed-71289653*/count=238; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.hypot(( ! Math.exp((Math.tanh((Math.acosh((Math.fround((Math.fround(-1/0) << Math.fround(0/0))) | 0)) | 0)) >>> 0))), Math.fround(Math.log1p(Math.fround((((Math.fround(( + x)) >>> 0) * ((y == (x | 0)) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-71289653*/count=239; tryItOut("let (e) { switch(window.yoyo(26)) { default: break; case 1: print(x);g1.offThreadCompileScript(\"g0.v1 = Object.prototype.isPrototypeOf.call(v0, g2);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 28 == 17), catchTermination: true }));break; case ({a1:1}): selectforgc(o0); } }");
/*fuzzSeed-71289653*/count=240; tryItOut("/*bLoop*/for (vsnxlq = 0; vsnxlq < 0; ++vsnxlq) { if (vsnxlq % 2 == 1) { e1.delete(f0); } else { a1 = a0.map(new RegExp(\"(?:\\\\xf6){2}\", \"gm\").race, m0, h0, i0, f0); }  } ");
/*fuzzSeed-71289653*/count=241; tryItOut("e1 = this.g2.objectEmulatingUndefined();");
/*fuzzSeed-71289653*/count=242; tryItOut("f1 + t0;");
/*fuzzSeed-71289653*/count=243; tryItOut("\"use strict\"; e0 + '';");
/*fuzzSeed-71289653*/count=244; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((Math.fround(Math.imul(( ! Math.pow((mathy0((-Number.MAX_SAFE_INTEGER | 0), (1/0 | 0)) | 0), Math.fround(( + (x | 0))))), Math.fround(mathy0(Math.fround(Math.fround(mathy0(Math.fround(mathy0(y, y)), x))), Math.fround(y))))) >>> 0), (Math.asin(Math.fround((mathy0(( ~ Math.fround(Math.pow((y | 0), Math.fround(( ~ y))))), y) >> (Math.max((x >>> 0), Math.max((2**53 | 0), (y | 0))) & y)))) >>> 0)); }); testMathyFunction(mathy1, [Math.PI, 1, 0x0ffffffff, Number.MIN_VALUE, -0x100000001, 0/0, 0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, 2**53, -1/0, 0.000000000000001, 0, 0x07fffffff, 42, 1.7976931348623157e308, 2**53+2, -(2**53), -Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), -0, 2**53-2, 0x100000000, 1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=245; tryItOut("testMathyFunction(mathy0, [-0x07fffffff, Math.PI, -(2**53), 0x100000000, -(2**53+2), 1/0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, -1/0, -0x100000000, 2**53-2, -0, 2**53, 1, 2**53+2, 0x0ffffffff, 0x07fffffff, -0x100000001, 0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 42, 0x100000001, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=246; tryItOut(";const z = x;");
/*fuzzSeed-71289653*/count=247; tryItOut("mathy0 = (function(x, y) { return (Math.hypot(Math.fround(( ~ Math.fround((Math.fround(Math.trunc((Math.tanh(x) >>> 0))) ? Math.fround(x) : (Math.fround(Math.cbrt(Math.fround(-0x080000001))) >>> 0))))), Math.fround(Math.cosh(Math.fround(Math.fround(( - Math.fround(( ! Math.sign(Math.fround(x)))))))))) * Math.fround((Math.log2(Math.atan2(( + ( + (Math.min(x, (-(2**53-2) | 0)) >>> 0))), y)) !== Math.min((Math.fround(x) ? ( ! (y >>> 0)) : x), Math.fround(( ! Math.fround((( ! ( + y)) | 0)))))))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, 0/0, 2**53+2, 0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_VALUE, -0, 1/0, 0x080000000, -0x080000000, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000001, -(2**53-2), -(2**53+2), 2**53, -(2**53), 0x080000001, 0.000000000000001, Math.PI, -0x100000001, 42, 1, 0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-71289653*/count=248; tryItOut("\"use strict\"; Object.seal(s0);");
/*fuzzSeed-71289653*/count=249; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -4611686018427388000.0;\n    (Float64ArrayView[((i1)+(i0)+(0xffffffff)) >> 3]) = ((Float64ArrayView[0]));\n    {\n      return +(this.__defineGetter__(\"NaN\", decodeURI));\n    }\n    d2 = ((i0) ? (+(-1.0/0.0)) : (d2));\n    switch ((((0x451bb5da)-((0x9dda44d2) >= (0x4d0aeefe))) | ((i0)))) {\n      case -1:\n        d2 = (Infinity);\n        break;\n    }\n    return +((NaN));\n  }\n  return f; })(this, {ff: ArrayBuffer.isView}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MAX_VALUE, 2**53, 0.000000000000001, 0x100000001, -1/0, -(2**53-2), 0x080000000, 1/0, 0, 0x0ffffffff, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), -0x0ffffffff, -(2**53+2), -0x100000001, -Number.MIN_VALUE, 0/0, Number.MAX_VALUE, 0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, 42, 1.7976931348623157e308, -0x100000000, -0x080000001, 2**53+2, -0x080000000]); ");
/*fuzzSeed-71289653*/count=250; tryItOut("\"use strict\"; a2.forEach((function() { for (var j=0;j<89;++j) { f0(j%4==0); } }));");
/*fuzzSeed-71289653*/count=251; tryItOut("\"use asm\"; /*RXUB*/var r = r2; var s = o0.s1; print(r.exec(s)); function [, [, b, , , eval], , , [, \u3056, , [, , e, , , , {c: {a: {eval: [{x: x, NaN}, , {w}], \u3056: [{}, [], ]}}, e: [[c]], x}], ], [, , , get], , y]() { return Proxy() } do this.v1 = (this.e1 instanceof e0); while((d =>  { return /*UUV1*/(window.big = \u0009/*wrap3*/(function(){ var vqxjqj =  '' ; ((DataView.prototype.getFloat64).bind)(); })) } .prototype) && 0);");
/*fuzzSeed-71289653*/count=252; tryItOut("\"use strict\"; \"use asm\"; /*tLoop*/for (let c of /*MARR*/[ /x/ ,  /x/ , [],  /x/g , [], [] = e, objectEmulatingUndefined(), objectEmulatingUndefined(), [], [] = e, [], objectEmulatingUndefined(), [] = e, [] = e, [] = e, objectEmulatingUndefined(), [],  /x/g ,  /x/ , [] = e,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), [], [],  /x/ , [] = e, [] = e,  /x/g ,  /x/ ,  /x/g ,  /x/ ,  /x/g , [] = e,  /x/ , [], [] = e, objectEmulatingUndefined(),  /x/ ,  /x/g ,  /x/g ,  /x/ ,  /x/g ,  /x/ , [] = e,  /x/g , [] = e, [],  /x/g ,  /x/ , objectEmulatingUndefined(),  /x/g ,  /x/g , objectEmulatingUndefined(),  /x/ , [], [] = e, [] = e, [], [] = e, [] = e, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [],  /x/g ,  /x/g ,  /x/g , [] = e,  /x/ , objectEmulatingUndefined(), [], objectEmulatingUndefined(),  /x/g ,  /x/g , objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/g , [], [] = e, [] = e, [], [],  /x/g ,  /x/g , [] = e,  /x/ ,  /x/g , objectEmulatingUndefined(),  /x/g , [] = e,  /x/ , [] = e, [], [],  /x/ , [], [] = e,  /x/g , [],  /x/g ]) { { void 0; bailAfter(39); } }");
/*fuzzSeed-71289653*/count=253; tryItOut("\"use strict\"; testMathyFunction(mathy3, [2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, 0x080000000, -0, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), -(2**53+2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -0x080000000, -0x100000001, -0x07fffffff, 0.000000000000001, 1, 0x100000000, -0x100000000, 0x100000001, 42, Math.PI, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 1/0, -0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 2**53, 0]); ");
/*fuzzSeed-71289653*/count=254; tryItOut("/*infloop*/for(arguments.callee.caller.caller.arguments in (((eval, x) => x)(x))){Object.prototype.unwatch.call(this.s1, \"isSealed\");t0[6]; }");
/*fuzzSeed-71289653*/count=255; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((Math.round(( + Math.imul((( ! x) >>> 0), y))) ^ (( + x) >>> 0)) >>> 0) ? ((Math.exp((( - (Math.atan2(42, ((( + x) >>> 0) + (y >>> 0))) >>> 0)) >>> 0)) | 0) | 0) : (Math.pow((((mathy0((x | 0), ( ! -0x100000001)) >= (( + ( ~ y)) | 0)) | 0) >>> 0), Math.max((Math.fround(Math.cos(( + Math.exp(( + x))))) | 0), ( + Math.max(( + x), (x ? 0x080000001 : Math.fround(x)))))) >>> 0)); }); ");
/*fuzzSeed-71289653*/count=256; tryItOut("/*infloop*/for(window[\"toLocaleUpperCase\"] in ((x)(x))){(void options('strict'));const r2 = /(?:\\3\\B{0,}{0,})/y; }");
/*fuzzSeed-71289653*/count=257; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow(Math.pow(Math.fround((Math.asin((y | 0)) || Math.fround((Math.min((x | 0), (Math.fround(Math.hypot(y, Math.imul(x, (Math.log((y | 0)) | 0)))) | 0)) >>> 0)))), Math.pow(( + Math.pow(( + ( - (y >>> 0))), ( + Math.fround((Math.fround(-1/0) != Number.MIN_SAFE_INTEGER))))), (Math.fround(y) !== Math.fround(Math.atan2(x, 0x0ffffffff))))), Math.clz32(((y >>> 0) > y))); }); testMathyFunction(mathy0, /*MARR*/[new Number(1), x, ({x:3}), new String(''), ({x:3}), x, new String(''), new String(''), new String(''), [], ({x:3}), new String(''), ({x:3}), [], [], x, x, x, x, x, x, x, x, x, x, new String(''), ({x:3}), new Number(1), x, x, new Number(1), new String(''), new String(''), new String(''), new String(''), [], x, x, new String(''), ({x:3}), ({x:3}), new Number(1), new String(''), ({x:3}), new String(''), [], x, ({x:3}), x, new Number(1), new String(''), new String(''), new String(''), x, [], new String(''), x, ({x:3}), x, ({x:3}), [], new String(''), x, x, new Number(1), x, x, [], new Number(1), ({x:3}), new String('')]); ");
/*fuzzSeed-71289653*/count=258; tryItOut("\"use strict\"; (void schedulegc(g1));");
/*fuzzSeed-71289653*/count=259; tryItOut("v1 = (e1 instanceof o1.v0);");
/*fuzzSeed-71289653*/count=260; tryItOut("\"use strict\"; /*infloop*/for(let c = null; 'fafafa'.replace(/a/g, decodeURIComponent); true) /*bLoop*/for (cmxrik = 0; cmxrik < 45; ++cmxrik) { if (cmxrik % 73 == 40) { t0 = new Uint16Array(9); } else { a0 = r0.exec(s1); }  } ");
/*fuzzSeed-71289653*/count=261; tryItOut("\"use strict\"; for (var v of t2) { try { a2.toString = f0; } catch(e0) { } function f0(h1)  /x/g  }");
/*fuzzSeed-71289653*/count=262; tryItOut("/*tLoop*/for (let d of /*MARR*/[function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}]) { return; }");
/*fuzzSeed-71289653*/count=263; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - Math.fround(Math.hypot((( + Math.trunc(( + ( + Math.cosh(( + Math.fround(Math.imul(Math.fround(0x07fffffff), x)))))))) >>> 0), mathy0(( + (( + (( ! y) >>> 0)) + ( + Math.fround((( + (( ! (x >>> 0)) >>> 0)) <= Math.fround(mathy3(x, ( + x)))))))), (y === ( + mathy0((Number.MIN_SAFE_INTEGER | 0), (0x07fffffff | 0)))))))); }); ");
/*fuzzSeed-71289653*/count=264; tryItOut("{print(\"\\u821A\");print(x); }");
/*fuzzSeed-71289653*/count=265; tryItOut("{ void 0; gcPreserveCode(); }");
/*fuzzSeed-71289653*/count=266; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2(( + (( + ((( + (((0x100000000 < y) - ( + mathy0(Math.fround((Math.max((y | 0), (y | 0)) | 0)), Math.fround(x)))) >>> 0)) ** Math.atan(mathy2(x, x))) | 0)) | 0)), ( ~ Math.fround(((( + ((( + y) >>> 0) === (-(2**53+2) >>> 0))) && y) - Math.pow((x >>> 0), ( + Math.log(y))))))); }); testMathyFunction(mathy3, [-0x080000001, -0x080000000, 1/0, 2**53, -Number.MIN_SAFE_INTEGER, 1, Math.PI, -1/0, -0, 0, -Number.MIN_VALUE, -(2**53-2), 0/0, Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 0x080000000, -0x100000000, 0x07fffffff, 42, 0x0ffffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, -(2**53), -0x0ffffffff, 0.000000000000001, -(2**53+2)]); ");
/*fuzzSeed-71289653*/count=267; tryItOut("\"use asm\"; Array.prototype.forEach.call(a2, (function() { for (var j=0;j<1;++j) { f1(j%4==0); } }), x, o2, m1);");
/*fuzzSeed-71289653*/count=268; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      {\n        i0 = ((!(i0)) ? ((i0) ? ((0xd4903fb0) != (((0x2758d77b))>>>((0x2065d619)))) : ((0xa7881521) ? (0xf823b46b) : ((-32768.0) <= (281474976710657.0)))) : ((((i2)) & (-0xfffff*((((0xfb72c352))>>>((-0x8000000)))))) < (((i0)*-0x5b8b4)|0)));\n      }\n    }\n    return ((((~~(-6.044629098073146e+23)))))|0;\n    {\n      i0 = (!(i0));\n    }\n    i0 = (i0);\n    {\n      i2 = ((((i0)-(0x3215fd9e)+(!((0xafaf8feb) < (((0xb38dc9ea))>>>((0xe20bc26b)))))) | ((!((+abs(((+(0xcd4b8416))))) == (7.555786372591432e+22))))));\n    }\n    (Float64ArrayView[1]) = ((+(((!(/*FFI*/ff(((+atan2(((+atan2(((((4.835703278458517e+24)) / ((-1.0009765625)))), ((+(1.0/0.0)))))), ((Float32ArrayView[((0xfd042b88)-(-0x3a21e37)) >> 2]))))), ((4277)), ((((0x80d31107)*-0xc8cd8) ^ ((0xd78944e7) / (0xb20b892d)))), ((0x8e50d84)), ((d1)), ((73786976294838210000.0)), ((7.555786372591432e+22)), ((-73786976294838210000.0)), ((-0.0009765625)), ((1.9342813113834067e+25)))|0))) ^ (((((i0) ? (d1) : (+(1.0/0.0))))) % (((0x41ed0a8e)-((0x0) >= (0xfa0cb5d8))+(i2)) << ((0x9e16b791)))))));\n    (Float32ArrayView[0]) = ((-1.00390625));\n    return ((((1.5111572745182865e+23) <= (+((-144115188075855870.0))))-(0xb306454d)-(i2)))|0;\n    d1 = ((i0) ? (-2.4178516392292583e+24) : ((/(?=[^]+?(?:(?=\\b\\b{64}))\\3|[\\s\\t\\K-\\v\\x1a]\\b)/g)));\n    (Float32ArrayView[1]) = ((d1));\n    i2 = (0x98d46a9);\n    {\n      d1 = (((140737488355329.0)) % (((y %= x) ? (+(0.0/0.0)) : (-7.0))));\n    }\n    i0 = (i2);\n    d1 = (d1);\n    i2 = (0xc6e0a9bf);\n    return (((0x32e53dce) % (~~(-18014398509481984.0))))|0;\n    return ((-0xeb336*(i2)))|0;\n    i0 = ((~~(+(~~((-((-137438953473.0))) + (+(1.0/0.0)))))) <= ((((-0xb92e4*(i2)) & ((-0x8000000)+(0x94744683)+(0x8cca381c))) / (((!(!(0xd35383d9))))|0)) & ((((0xffffffff) >= (((-0x8000000))>>>((-0x3cc2658)))) ? (0xe7fea3a) : (i2)))));\n    return (((/*FFI*/ff(((33554433.0)), ((+((Float64ArrayView[((0x0) / (((0x463b45ba))>>>((0x6349a71e)))) >> 3])))), ((Infinity)), ((-9223372036854776000.0)))|0)-((~~(+abs(((Float32ArrayView[4096]))))))))|0;\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [(new Number(-0)), ({toString:function(){return '0';}}), '\\0', (function(){return 0;}), (new Boolean(true)), /0/, '/0/', NaN, (new String('')), [], 0.1, ({valueOf:function(){return '0';}}), null, undefined, 0, objectEmulatingUndefined(), -0, false, [0], '0', (new Number(0)), ({valueOf:function(){return 0;}}), 1, (new Boolean(false)), '', true]); ");
/*fuzzSeed-71289653*/count=269; tryItOut("testMathyFunction(mathy1, /*MARR*/[NaN, {}, NaN, {}, NaN, NaN, NaN, NaN, NaN, NaN, {}, NaN, {}, NaN, NaN, NaN, NaN, NaN, NaN, {}, NaN, NaN, {}, {}, {}, {}, {}, {}, {}, {}, {}, NaN, {}, {}, {}, {}, {}, {}, NaN, {}, {}, NaN, {}, {}, {}, NaN, NaN, NaN, {}, NaN, {}, {}, {}, NaN, NaN, NaN, NaN, NaN, NaN, {}, NaN, {}, NaN, NaN, NaN, {}, {}, {}, {}, NaN, {}, {}, {}, NaN, {}, NaN, {}, NaN, {}, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, {}, {}, NaN, {}, NaN, NaN, NaN, NaN, NaN, {}, NaN]); ");
/*fuzzSeed-71289653*/count=270; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( + Math.log10(Math.cosh(( + (( + Math.atan2(x, 1.7976931348623157e308)) & ( + x)))))) * ( + ((( + Math.log1p((Math.clz32((0x100000000 | 0)) | 0))) + ( + (Math.clz32(y) >>> 0))) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=271; tryItOut("(x !== c);");
/*fuzzSeed-71289653*/count=272; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +(((((((((i0)))+(null)) << (-((0x4ca57f95) <= ((((0x3cc2ab02)))>>>((i1)))))) == (((((!(i0))+((0xf47686d8))-(i0))>>>(((((0xffffffff))>>>((0x1650f690))) < (0xffffffff)))) / ((((((-0x8000000)-(0xff6db76b)+(0xf9855096))|0))+(i1))>>>((!(i0))))))))));\n    {\n      {\n        {\n          i1 = (!(i1));\n        }\n      }\n    }\n    i0 = (i1);\n    (Float64ArrayView[((i0)+(i1)) >> 3]) = ((+(1.0/0.0)));\n    i1 = (i0);\n    return +((w));\n  }\n  return f; })(this, {ff: ((yield -16 | [1,,]))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000001, Number.MIN_VALUE, 42, -(2**53), 0/0, -(2**53+2), Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 0x100000001, 2**53-2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, 1, 0x0ffffffff, 0x080000000, -(2**53-2), -Number.MAX_VALUE, 0x100000000, 0, -0, 2**53, -1/0, 2**53+2, -Number.MIN_VALUE, -0x080000000]); ");
/*fuzzSeed-71289653*/count=273; tryItOut("a2 = Array.prototype.filter.call(this.a0, DFGTrue.bind(m1));");
/*fuzzSeed-71289653*/count=274; tryItOut("i0.send(s0);");
/*fuzzSeed-71289653*/count=275; tryItOut("mathy1 = (function(x, y) { return mathy0(( - ((( + Math.clz32(0)) % ( + Math.abs(x))) >>> 0)), ( + ( + (((x ** (x | 0)) >>> 0) !== (Math.exp((Math.atan((( + ( ! ( + (( + 1/0) & ( + ( ~ y)))))) >>> 0)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [({valueOf:function(){return 0;}}), '\\0', (function(){return 0;}), [], false, objectEmulatingUndefined(), '', 1, '0', null, (new String('')), /0/, 0.1, undefined, -0, (new Boolean(false)), true, (new Number(0)), (new Boolean(true)), ({valueOf:function(){return '0';}}), NaN, [0], '/0/', (new Number(-0)), 0, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-71289653*/count=276; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.acos(( + ((( + ( - ( + ( + mathy1(y, (y != Math.fround(( + Math.pow(( + y), y))))))))) >>> 0) , ( + mathy3((((( + ( + y)) >>> 0) == x) >>> 0), x))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, 2**53, 0x080000000, -0x100000001, -0x07fffffff, -1/0, Math.PI, 2**53+2, -0x100000000, 1.7976931348623157e308, 1/0, 0x07fffffff, -(2**53), -0, -0x0ffffffff, -Number.MIN_VALUE, 0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, 0, -Number.MIN_SAFE_INTEGER, 42, -(2**53-2), 1, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 0/0, Number.MAX_VALUE, 0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-71289653*/count=277; tryItOut("mathy2 = (function(x, y) { return Math.fround((Math.max(Math.fround((Math.fround(Number.MIN_VALUE) < Math.fround((x ^ x)))), ( + Math.acosh(( + (Math.imul((( + (( + y) ? ( + y) : ( + x))) | 0), y) | 0))))) && ((((((((y >>> 0) >> Math.fround(y)) ? y : Math.fround(Math.log10(Math.fround(-Number.MIN_VALUE)))) << (( ~ x) >>> 0)) >>> ( + -0x080000000)) < (Math.trunc((Math.min(( + x), x) | 0)) | 0)) | 0) | 0))); }); ");
/*fuzzSeed-71289653*/count=278; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=279; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1025.0;\n    d1 = (d1);\n    return (((0x99bf1d98)))|0;\n    return ((((((0x7a0629a7))>>>((((0x7c9b1b83)-(0xe4a8cf99))>>>(0xfffff*(0xf00c1dbf))) / (((0x275b936)-(0x23f085b1))>>>((0xffffffff)*-0x28cd2)))) < (0x9702fbc0))-((((Uint32ArrayView[1])) | ((((0x0) <= (0x0)) ? ((((0x9c9d391d))>>>((-0x59e6fdb)))) : (0xb10e0c0a)))) == ((-0xfffff*(Math.max({}, (w = w)))) | (((((16777217.0) == (-512.0))) & ((Uint32ArrayView[1]))) % (abs(((Math.hypot((4277), 15))))|0))))))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); ");
/*fuzzSeed-71289653*/count=280; tryItOut("mathy2 = (function(x, y) { return ( ~ Math.min(( + (( + ( ~ ((Math.log((y >>> 0)) >>> 0) >>> 0))) ** ( + mathy0((( + ( ~ ( + x))) >>> 0), Math.fround(( - ( - y))))))), (Math.round((Math.atan2(Math.hypot(-Number.MAX_SAFE_INTEGER, (y >>> 0)), y) | 0)) | 0))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0x100000001, -0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 42, -(2**53), Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, -0x080000001, 0/0, 0x07fffffff, 0x080000001, -(2**53+2), -1/0, 1/0, Number.MIN_VALUE, -0x100000000, -0x100000001, -(2**53-2), 0x0ffffffff, 0x100000000, 0, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -0, 0x080000000, 2**53, Math.PI]); ");
/*fuzzSeed-71289653*/count=281; tryItOut("{ void 0; setGCCallback({ action: \"majorGC\", depth: 15, phases: \"end\" }); }");
/*fuzzSeed-71289653*/count=282; tryItOut("/*tLoop*/for (let y of /*MARR*/[2**53-2, function(){}, function(){}, function(){}, 2**53-2, function(){}, function(){}, function(){}, function(){}, function(){}, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, 2**53-2, function(){}, new Boolean(false), function(){}, function(){}, function(){}, 2**53-2, function(){}, function(){}, function(){}, new Boolean(false), ({x:3}), function(){}, function(){}, function(){}, ({x:3}), new Boolean(false), ({x:3}), 2**53-2, 2**53-2, function(){}, function(){}, function(){}, ({x:3}), new Boolean(false), ({x:3}), function(){}, 2**53-2, function(){}, 2**53-2, 2**53-2, function(){}, function(){}, function(){}, function(){}, ({x:3}), ({x:3}), 2**53-2, new Boolean(false), function(){}, new Boolean(false), function(){}, ({x:3}), 2**53-2, function(){}, new Boolean(false), ({x:3}), function(){}, function(){}, ({x:3}), 2**53-2, ({x:3})]) { print(\"\\uA1F1\"); }");
/*fuzzSeed-71289653*/count=283; tryItOut("g1.offThreadCompileScript(\"t0.set(a1, 8);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: Object.defineProperty(x, \"keys\", ({})), noScriptRval: true, sourceIsLazy: false, catchTermination: true, elementAttributeName: s1, sourceMapURL: o2.s0 }));");
/*fuzzSeed-71289653*/count=284; tryItOut("print(x);print(x);");
/*fuzzSeed-71289653*/count=285; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.sort.apply(g0.g0.a1, [(function(j) { if (j) { Array.prototype.splice.call(a2, NaN, 11, h0); } else { try { s0.toSource = (function() { try { g0.offThreadCompileScript(\"/* no regression tests found */\"); } catch(e0) { } try { h0.enumerate = f1; } catch(e1) { } r2 = /((?:((?!$)))(?=(?:$[\u0003-\\cT\\uB3FE-\u00f6])|\\x73|[^]|\\S)|\\3\\r+?\\D*?)/gim; throw m1; }); } catch(e0) { } try { s1 = new String; } catch(e1) { } try { a1 + o1; } catch(e2) { } g0.h2.getOwnPropertyDescriptor = (function() { for (var j=0;j<29;++j) { f0(j%3==1); } }); } }), o2]);");
/*fuzzSeed-71289653*/count=286; tryItOut("\"use strict\"; return x;");
/*fuzzSeed-71289653*/count=287; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+abs(((+(0x37c96730)))));\n    return (((-0x8000000)*0xfffff))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0.1, '0', ({toString:function(){return '0';}}), 1, [], undefined, [0], (new Boolean(false)), null, '', ({valueOf:function(){return '0';}}), false, true, (new String('')), (new Boolean(true)), ({valueOf:function(){return 0;}}), (new Number(0)), (new Number(-0)), -0, objectEmulatingUndefined(), /0/, 0, NaN, '/0/', '\\0', (function(){return 0;})]); ");
/*fuzzSeed-71289653*/count=288; tryItOut("for(let d in []);for(let a in []);");
/*fuzzSeed-71289653*/count=289; tryItOut("/*RXUB*/var r = r2; var s = this.s0; print(uneval(s.match(r))); ");
/*fuzzSeed-71289653*/count=290; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(mathy0(Math.fround(( ! ((mathy2((( + (1/0 >>> 0)) >>> 0), ((( + (-0x100000000 | 0)) | 0) >>> 0)) >>> 0) >= Math.fround(2**53-2)))), Math.fround(Math.fround((Math.fround(Math.tanh(( ! ((( + (y >>> 0)) >>> 0) >>> 0)))) ? Math.fround(Math.fround((Math.fround(2**53) > Math.fround((( + ( ! ( + mathy0((Math.ceil((x | 0)) | 0), y)))) ? Math.exp((x | 0)) : (((Math.atan2(y, x) | 0) + ( + y)) >>> 0)))))) : mathy0((((y >>> 0) , y) & (((Math.fround(y) , (0 | 0)) | 0) >>> 0)), mathy1(1, Math.fround(Math.acosh(Math.fround(Math.atan(( ! ( + -0x0ffffffff))))))))))))); }); ");
/*fuzzSeed-71289653*/count=291; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    i0 = ((0xd50d278f) != (((0xffffffff)+(i0))>>>(((((((0xfeedcae2)) >> ((0x5dda8411))) / (((0xfb0c0557)) ^ ((0xb91088e3))))>>>(((0xffffffff) ? (0xfb8afdd1) : (-0x8000000))))))));\n    return +((Float64ArrayView[1]));\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [(new String('')), (new Number(0)), false, null, '\\0', 1, 0.1, /0/, 0, (new Boolean(true)), [], objectEmulatingUndefined(), -0, (new Boolean(false)), [0], (new Number(-0)), true, '0', '', ({toString:function(){return '0';}}), (function(){return 0;}), NaN, ({valueOf:function(){return 0;}}), '/0/', undefined, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-71289653*/count=292; tryItOut("Array.prototype.pop.apply(a0, [s0]);");
/*fuzzSeed-71289653*/count=293; tryItOut("\"use strict\"; Array.prototype.splice.call(a2, m1, a0, h2);");
/*fuzzSeed-71289653*/count=294; tryItOut("/*RXUB*/var r = \"\\u731B\"; var s = \"00000000000000000000\"; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-71289653*/count=295; tryItOut("\"use strict\"; m1.__iterator__ = (function() { v1 = (o2.v0 instanceof e0); return this.v2; });");
/*fuzzSeed-71289653*/count=296; tryItOut("e2.toSource = Array.prototype.every.bind(o1);");
/*fuzzSeed-71289653*/count=297; tryItOut("mathy4 = (function(x, y) { return ((((Math.atanh((( + Math.imul(( + Math.sin(( + (x >= x)))), ( + Math.max(Math.expm1(x), Math.fround(Math.log2(( + Math.cbrt((y | 0))))))))) | 0)) | 0) | 0) ? (( ! Math.fround(( + (-(2**53) | 0)))) | 0) : Math.imul(Math.trunc(( + (( ! (( + Math.atan2(( + x), ( + x))) | 0)) | 0))), Math.fround(Math.hypot(Math.fround((Math.fround(x) | Math.fround(mathy3(y, Math.imul(y, (( - x) | 0)))))), Math.fround(( ! y)))))) | 0); }); ");
/*fuzzSeed-71289653*/count=298; tryItOut("/*hhh*/function ecmmhb(){;}ecmmhb();");
/*fuzzSeed-71289653*/count=299; tryItOut("testMathyFunction(mathy1, [-Number.MAX_VALUE, -0x100000000, -(2**53), 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -0x07fffffff, 2**53, 0, 0.000000000000001, 2**53-2, 42, 0x100000000, -0x100000001, -(2**53+2), 0/0, 0x080000000, Number.MAX_VALUE, -1/0, 0x080000001, -0, -Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 1, Number.MIN_VALUE, 1/0, 0x100000001]); ");
/*fuzzSeed-71289653*/count=300; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=301; tryItOut("testMathyFunction(mathy4, [-0x080000000, -0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, Math.PI, Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, 0x100000001, 2**53+2, -(2**53-2), 1.7976931348623157e308, 0.000000000000001, 0x080000001, -1/0, 0/0, 0x100000000, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, 2**53-2, 1/0, 0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, 0, -0, 0x07fffffff, -(2**53+2), 1, -0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=302; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.max(((Math.max(Math.max(x, (Math.fround(Math.fround(Math.cbrt(Math.fround(x)))) % (x | 0))), (((-(2**53+2) | 0) ? (y | 0) : (0 | 0)) | 0)) - ( + x)) >>> 0), ( ! Math.fround(((( + Math.clz32(( + -(2**53-2)))) == Math.fround(y)) ? Math.fround((Math.pow(((( - (x >>> 0)) >>> 0) | 0), (y | 0)) | 0)) : Math.fround(x))))) ? ( + ((( ! (((y | 0) , (( ~ ((((x >>> 0) >= (y | 0)) >>> 0) | 0)) | 0)) >>> 0)) | 0) ? (((((Math.hypot((2**53+2 >>> 0), (( ~ x) | 0)) | 0) >>> 0) >>> Math.fround(Math.fround(Math.fround(y)))) >>> 0) | 0) : ((Math.hypot(((Math.hypot(x, (Math.asin(Math.fround(-(2**53-2))) >>> 0)) << ( + (x ? y : Math.fround(( ! (y >>> 0)))))) >>> 0), (Math.min((( + x) | 0), (y >>> 0)) | 0)) >>> 0) | 0))) : ((((( ~ y) >>> 0) | 0) ? (y | 0) : Math.fround(Math.abs(Math.fround(((Math.atan(y) >>> 0) !== Math.fround((( + x) << (0x07fffffff >>> 0)))))))) / Math.fround(Math.fround(Math.abs(Math.fround(( ! (Math.log10((y | 0)) | 0)))))))); }); testMathyFunction(mathy0, [1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 0x080000000, 0x07fffffff, 2**53+2, -0x100000001, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, 0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, 42, 0, -0x080000000, 0.000000000000001, Math.PI, -0x080000001, -Number.MIN_VALUE, 2**53-2, -(2**53), -0, 0x0ffffffff, 1, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=303; tryItOut("/*hhh*/function ezbhxp(window, eval, x, {x: {}, \u3056: {\"-29\": {}, x: {x: x, eval: {}}, x: x}, window, x}, z, d, x, x = x, x = x, e, x, e, x){e1.add(i0);}ezbhxp();");
/*fuzzSeed-71289653*/count=304; tryItOut("e1.add(h0);");
/*fuzzSeed-71289653*/count=305; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i0, p1);");
/*fuzzSeed-71289653*/count=306; tryItOut("a2.sort((function() { for (var j=0;j<3;++j) { f1(j%5==1); } }), m2);this.s2 + '';");
/*fuzzSeed-71289653*/count=307; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(s.replace(r, Math.acosh(0x080000001) ==  /x/ )); ");
/*fuzzSeed-71289653*/count=308; tryItOut("a1 + '';\n\"\\u0428\";\n");
/*fuzzSeed-71289653*/count=309; tryItOut("throw x;");
/*fuzzSeed-71289653*/count=310; tryItOut("var kypcvp = new ArrayBuffer(16); var kypcvp_0 = new Uint8ClampedArray(kypcvp); kypcvp_0[0] = 20; var kypcvp_1 = new Int8Array(kypcvp); yield;throw  '' ;");
/*fuzzSeed-71289653*/count=311; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.imul(( + (( + ( + y)) ^ ( + Math.fround(( ~ y))))), ( ~ ((Math.max((y | 0), ((y >>> Math.fround(Math.pow((y >>> 0), Math.pow(( + Math.atan2(y, (x >>> 0))), -0)))) | 0)) | 0) | 0))) | 0); }); testMathyFunction(mathy1, /*MARR*/[false, (uneval(x)), (uneval(x)), function(){}, -0x100000000, timeout(1800), function(){}, (uneval(x)), (uneval(x)), (uneval(x)), timeout(1800), (uneval(x)), timeout(1800), timeout(1800), (uneval(x)), false, timeout(1800), function(){}, -0x100000000, timeout(1800), -0x100000000, timeout(1800), -0x100000000, timeout(1800), function(){}, false, -0x100000000, false, timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), false, timeout(1800), timeout(1800), false, (uneval(x)), function(){}, timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), timeout(1800), false, (uneval(x)), false, (uneval(x)), (uneval(x)), false, timeout(1800), false, false, -0x100000000, (uneval(x)), -0x100000000, function(){}, (uneval(x)), function(){}, (uneval(x)), false, false, (uneval(x)), false, function(){}, -0x100000000, false, false, timeout(1800), (uneval(x)), function(){}, -0x100000000, (uneval(x)), -0x100000000, timeout(1800), (uneval(x)), false, false, function(){}, false, (uneval(x)), false, function(){}, -0x100000000, -0x100000000, (uneval(x)), function(){}, timeout(1800), -0x100000000, -0x100000000, (uneval(x)), function(){}, (uneval(x)), -0x100000000, function(){}, -0x100000000, (uneval(x)), timeout(1800), (uneval(x)), false, false]); ");
/*fuzzSeed-71289653*/count=312; tryItOut("\"use strict\"; var jnaycm = new SharedArrayBuffer(32); var jnaycm_0 = new Uint8ClampedArray(jnaycm); jnaycm_0[0] = [1]; g1.t0[17] = jnaycm_0;");
/*fuzzSeed-71289653*/count=313; tryItOut("{(undefined); }");
/*fuzzSeed-71289653*/count=314; tryItOut("if((x % 27 == 18)) t2.set(t1, ({valueOf: function() { print(x);return 11; }})); else  if (x) v0 = a0.length;");
/*fuzzSeed-71289653*/count=315; tryItOut("\"use strict\"; for (var p in g0) { try { for (var p in p2) { try { Array.prototype.pop.call(a2); } catch(e0) { } try { t2.set(t0, 14); } catch(e1) { } try { v1 = (o2 instanceof i1); } catch(e2) { } this.o2 + this.b0; } } catch(e0) { } h0.has = Number.isFinite.bind(a2); }");
/*fuzzSeed-71289653*/count=316; tryItOut("yield \n(this.__defineGetter__(\"x\", (Math.log1p).bind))\n;");
/*fuzzSeed-71289653*/count=317; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + Math.tanh(( ! Math.log2((y + y))))); }); testMathyFunction(mathy4, [-0x100000000, 1, -0x07fffffff, -0x0ffffffff, 0x080000001, 1/0, -0, 2**53+2, 0, Number.MAX_VALUE, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, 2**53-2, -Number.MAX_VALUE, 0/0, -(2**53+2), -0x080000000, -0x100000001, Math.PI, -(2**53), -(2**53-2), 0x100000000, 42, -Number.MIN_VALUE, 0x080000000, 0x07fffffff, 0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=318; tryItOut("mathy4 = (function(x, y) { return Math.pow(mathy3(( + -Number.MAX_VALUE), ( - x)), mathy2(( + Math.imul(( + Math.abs(y)), ( + Math.tan((Math.log((x | 0)) | 0))))), ( ! ( + ((y === (2**53 >>> 0)) , ( + ( + (( + 2**53-2) << ( + Math.fround(Math.sqrt(Math.fround(-0x100000000)))))))))))); }); ");
/*fuzzSeed-71289653*/count=319; tryItOut("mathy2 = (function(x, y) { return (( ! ((( + Math.hypot(y, Math.acos(x))) , ( + ( ~ ( ! ( - ((y ? x : y) >>> 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, Math.PI, 42, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000001, -0x100000000, 0x07fffffff, 2**53+2, 0x100000000, 0/0, Number.MIN_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, 0x080000001, -Number.MIN_VALUE, -(2**53), -0x07fffffff, -0x080000001, 0x0ffffffff, 2**53-2, 1.7976931348623157e308, 0, Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 1, 1/0, -1/0, -0]); ");
/*fuzzSeed-71289653*/count=320; tryItOut("\"use strict\"; a1 + e2;");
/*fuzzSeed-71289653*/count=321; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((( ! x) ^ (( + ((((-(2**53+2) >>> 0) ^ (y >>> 0)) >>> 0) ** ( + ( + x)))) | 0)) | 0) % ( + ( + Math.fround((Math.cbrt(Math.pow(Math.sign(y), (y ** y))) ? Math.fround((Math.sinh((( - Math.fround(Math.ceil(Math.fround(x)))) >>> 0)) >>> 0)) : ( + (x < ( + y)))))))); }); testMathyFunction(mathy0, [(new Boolean(false)), (new Number(-0)), ({valueOf:function(){return 0;}}), (new String('')), 1, '/0/', -0, (function(){return 0;}), [], true, [0], ({valueOf:function(){return '0';}}), 0.1, null, '\\0', '', (new Boolean(true)), objectEmulatingUndefined(), NaN, /0/, 0, ({toString:function(){return '0';}}), false, (new Number(0)), undefined, '0']); ");
/*fuzzSeed-71289653*/count=322; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=323; tryItOut("\"use strict\"; Array.prototype.unshift.call(a0, a0, t1);");
/*fuzzSeed-71289653*/count=324; tryItOut("");
/*fuzzSeed-71289653*/count=325; tryItOut("\"use strict\"; m0 + '';");
/*fuzzSeed-71289653*/count=326; tryItOut("\"use strict\"; if((x % 4 != 2)) g2.offThreadCompileScript(\"/*RXUB*/var r = r1; var s = \\\"a\\\"; print(s.replace(r, s)); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (window = new RegExp(\"(?!\\\\b\\\\T)+|\\ub914{1,5}*[^]?|(?!([^\\\\xe7\\\\r-\\\\u00D0\\\\d\\\\w]))+\\\\ua1ED|(?!\\\\b)|\\\\3\", \"y\")), noScriptRval: true, sourceIsLazy: true, catchTermination: (x % 39 != 30) }));");
/*fuzzSeed-71289653*/count=327; tryItOut("\"use strict\"; Array.prototype.splice.call(a2, NaN, 6);");
/*fuzzSeed-71289653*/count=328; tryItOut("e2 + '';");
/*fuzzSeed-71289653*/count=329; tryItOut("\"use asm\"; var v1 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-71289653*/count=330; tryItOut("\"use strict\"; \"use asm\"; switch(x) { case ({0: /*RXUE*/new RegExp(\"((?:\\\\d{4,7}.[\\u858c-\\\\uE48B\\\\u0074-\\ua5cf\\\\s\\u00ff-\\u548f]|[^]^[^]?))+?\", \"gi\").exec(\"\"), BYTES_PER_ELEMENT: this.__defineSetter__(\"window\", function  x (y)\"use asm\";   var abs = stdlib.Math.abs;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 3.022314549036573e+23;\n    (Uint16ArrayView[2]) = ((0x8b57cf1a)-(0x968a6e62));\n    d1 = (d0);\n    return (((~(((0x4b48322f) <= (abs((((0x0) / (0xd5d665cf)) ^ (((-576460752303423500.0) == (-17179869184.0)))))|0)))) % (((0xeb02d2b1)*-0xe5e64) & (((0x0))-(!(-0x34157a1))+(1)))))|0;\n  }\n  return f;) }): break; case 2: default: break; break; case (4277): Array.prototype.forEach.apply(a2, [(4277).trim, m2, this.g1.o1, this.g0]);break; case (4277): yield;break; case 7: /*bLoop*/for (var bprtvs = 0; bprtvs < 96; ++bprtvs) { if (bprtvs % 99 == 97) { g1.m1.has(a0); } else { Array.prototype.splice.apply(a2, [NaN, 6]); }  } case delete w.x: break; case 9:  }");
/*fuzzSeed-71289653*/count=331; tryItOut("\"use strict\"; for(e in x != d) {M:if(false) { if ('fafafa'.replace(/a\u000d/g, ((/*wrap2*/(function(){ \"use strict\"; var fbmdez = ({a2:z2}); var vommzg = runOffThreadScript; return vommzg;})()).bind()).bind( '' ))) false\n; else g0.h2.delete = f2;}v1 = Object.prototype.isPrototypeOf.call(f1, g2); }");
/*fuzzSeed-71289653*/count=332; tryItOut("\"use strict\"; /*oLoop*/for (cmywap = 0, {} = x; cmywap < 48; ++cmywap) { m1 = new Map; } ");
/*fuzzSeed-71289653*/count=333; tryItOut("/*hhh*/function tzgfro(...x){a2 + i0;}/*iii*/e2.delete(f2);");
/*fuzzSeed-71289653*/count=334; tryItOut("\"use strict\"; for (var p in h0) { try { o1.v0 = NaN; } catch(e0) { } try { o1 = new Object; } catch(e1) { } try { i2.send(g0); } catch(e2) { } print( \"\" );function x(c, d, x, \u3056, x, a, x, window, eval, e, b, x, c, x, w, x, x, w, y, c, x, d =  /x/g , x, window, x, window, e =  '' , eval, w, a, x, x =  \"\" , \u3056, a, a, NaN, d, a, x = -11, delete) /x/g a0 = Array.prototype.slice.call(a0, -10, -15); }let a = (yield (x) =  /x/ ), e = (makeFinalizeObserver('nursery'))\n, eval, x = (yield  /x/g ), x = true, ookyzu, ldrojy, olkfnt;print(x);");
/*fuzzSeed-71289653*/count=335; tryItOut("var v2 = undefined;");
/*fuzzSeed-71289653*/count=336; tryItOut("L: for (let a of (4277)) {/*RXUB*/var r = /\\s/gym; var s = \"a\"; print(s.match(r));  }");
/*fuzzSeed-71289653*/count=337; tryItOut("o2.toString = (function() { try { /*MXX3*/g0.Int8Array.prototype.BYTES_PER_ELEMENT = g0.Int8Array.prototype.BYTES_PER_ELEMENT; } catch(e0) { } try { Array.prototype.unshift.apply(a0, [i2, t1, p1, v1, e2]); } catch(e1) { } v2 = g2.eval(\"{x: \\u000d[, []], x: {}} = b = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function(y) { return \\\"\\\\uD098\\\" }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })( '' ), function(q) { return q; }, function () { yield  /* Comment */this } )\"); return i0; });");
/*fuzzSeed-71289653*/count=338; tryItOut("\"use asm\"; testMathyFunction(mathy1, [0x07fffffff, 0x080000001, 1, Number.MIN_VALUE, Math.PI, -0x100000001, -(2**53-2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, 0, 0x100000000, 2**53, 2**53-2, -(2**53+2), 0.000000000000001, -0, -1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 0x100000001, 0/0, -Number.MAX_VALUE, 1/0, -0x080000000, -Number.MIN_VALUE, -0x100000000, -0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 42, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=339; tryItOut("t1 = e2;");
/*fuzzSeed-71289653*/count=340; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(a1, t1);");
/*fuzzSeed-71289653*/count=341; tryItOut("e0.has(f1);");
/*fuzzSeed-71289653*/count=342; tryItOut("mathy0 = (function(x, y) { return ( ~ ((Math.max((((x >>> 0) == (window.valueOf(\"number\") >>> 0)) >>> 0), ( + (-0x100000000 , Math.fround(x)))) >> ( ! (((Math.expm1((y | 0)) >>> 0) == (( + (Math.fround(x) ^ (Math.fround(y) >>> 0))) >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy0, [2**53-2, -0, -0x07fffffff, 0x100000001, -(2**53-2), -Number.MIN_VALUE, Math.PI, 0x100000000, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, 1.7976931348623157e308, -0x100000000, 0x0ffffffff, 0.000000000000001, -(2**53+2), -1/0, 0x080000000, -0x080000001, 2**53, 0, 0x080000001, 0/0, -Number.MAX_VALUE, -0x0ffffffff, -0x080000000, 2**53+2, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=343; tryItOut("mathy0 = (function(x, y) { return (Math.atan2(( + ( + (Math.sign((Math.cosh((( ! (-(2**53) >>> 0)) | 0)) | 0)) ** ( + Math.max((Math.imul((x | 0), x) / (y + (( + ( - (-0x0ffffffff | 0))) >>> 0))), (((( + Math.min(( + Math.fround(( + Math.fround(y)))), ( + y))) | 0) + Math.fround((Math.sinh((x | 0)) | 0))) | 0)))))), ( + Math.fround(Math.cbrt(Math.fround((((Math.tanh(( + ((( + Math.fround(2**53+2)) | 0) && ((Math.abs((Number.MAX_VALUE >>> 0)) >>> 0) >>> 0)))) >>> 0) & (y >>> 0)) >>> 0)))))) | 0); }); ");
/*fuzzSeed-71289653*/count=344; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (((( + ( ~ ( + Math.imul(( ! Math.fround(y)), Math.fround(Math.min((( - (y | 0)) | 0), Math.fround(( + Math.hypot(( + x), ( + Math.pow(x, (y >>> 0)))))))))))) >>> 0) < ( + ( - ( + (Math.fround(( - (-Number.MIN_VALUE >>> 0))) <= Math.imul(y, (0/0 | 0))))))) > ( + Math.cosh(( + (Math.max(( + Math.trunc(( + -0x07fffffff))), (x ? (x | 0) : ( - x))) > ( + Math.fround(( + y))))))))); }); ");
/*fuzzSeed-71289653*/count=345; tryItOut("mathy2 = (function(x, y) { return (Math.fround(( + Math.fround(Math.fround(( ~ (mathy1(( + x), Math.imul(x, y)) | 0)))))) + Math.imul(((( + (Math.min(Math.sinh((Math.min((-1/0 | 0), Math.pow(Math.fround(x), y)) | 0)), ( - (((y >>> 0) ^ (-0x100000001 >>> 0)) >>> 0))) | 0)) && Math.fround(( + Math.min(Math.fround(Math.fround((Math.fround(y) > Math.fround(Number.MIN_VALUE)))), Math.fround(Math.cosh(Math.ceil(x))))))) >>> 0), Math.fround(( ! Math.fround((Math.imul((mathy0((x | 0), (2**53+2 | 0)) | 0), ((x ? -Number.MIN_VALUE : (mathy0(x, y) >>> 0)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy2, [-0x0ffffffff, 1/0, Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, -0x080000000, 0x080000001, -0x080000001, Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, 1, -(2**53+2), 0x07fffffff, -0, -0x07fffffff, 0x100000001, -0x100000000, 0x0ffffffff, -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, 42, -1/0, 2**53+2, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), 2**53, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=346; tryItOut("mathy1 = (function(x, y) { return (((( ! Math.atan2(( - ( - y)), (((Math.tanh((( + Math.cosh(-1/0)) | 0)) | 0) << x) | 0))) >>> 0) >>> (Math.fround((Math.asinh((( + (((Math.fround(x) * (y | 0)) | 0) | 0)) | 0)) && ( + ( - (-0x0ffffffff & ( + ( + mathy0(( + x), ( + y))))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, Number.MAX_VALUE, 2**53, 0x0ffffffff, 2**53-2, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000001, 1, -1/0, -Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, -0x080000001, 0x07fffffff, Math.PI, 0x080000000, 0x100000000, 1/0, 2**53+2, -(2**53+2), -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, -0, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, 0/0, Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308, -0x0ffffffff, 0x080000001, -0x080000000]); ");
/*fuzzSeed-71289653*/count=347; tryItOut("a2[3] =  /x/g ;return;");
/*fuzzSeed-71289653*/count=348; tryItOut("print(f2);");
/*fuzzSeed-71289653*/count=349; tryItOut("\"use strict\"; a2 = r0.exec(s1);");
/*fuzzSeed-71289653*/count=350; tryItOut("\"use strict\"; t2 + '';");
/*fuzzSeed-71289653*/count=351; tryItOut("\"use strict\"; var x = ((4277) /= (yield x));v1 = new Number(4.2);");
/*fuzzSeed-71289653*/count=352; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy2(Math.max((Math.pow(((( - (-1/0 >>> 0)) >>> 0) | 0), (Math.hypot(Math.max(( + ( ~ x)), ( + Math.hypot(Math.PI, y))), Math.fround(Math.abs((1 >>> 0)))) | 0)) | 0), ( + Math.imul(( + ( + (( + ( + (( + 1.7976931348623157e308) == ( + (Math.cosh((x | 0)) | 0))))) + (Math.min(( + x), ( + Math.min(( + (((x | 0) !== (-Number.MAX_SAFE_INTEGER | 0)) | 0)), ( + x)))) | 0)))), x))), ((Math.hypot(Math.fround((Math.acos(Math.fround(Math.sinh(Math.fround(y)))) >>> 0)), Math.fround(( + (x >>> 0)))) | 0) <= mathy2(mathy3(x, (x | x)), ( ! y)))); }); testMathyFunction(mathy5, [2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, 0x100000001, 1, -0, 0x0ffffffff, 2**53, Number.MAX_VALUE, 1/0, -(2**53+2), -0x100000001, -0x080000001, Math.PI, -1/0, 42, -0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, 0x080000000, -0x100000000, 2**53-2, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=353; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(((( - ((Math.tan(Math.fround((Math.fround(y) ? Math.fround(( + ( - ( + Number.MAX_SAFE_INTEGER)))) : y))) | 0) | 0)) | 0) , Math.fround((Math.exp((( - (Math.max(Math.fround(Math.max((( ~ ( + Math.fround(Math.min(Math.fround(x), (y | 0))))) | 0), (( - y) , y))), mathy2((Math.fround(Math.pow(x, x)) >>> 0), (y >>> 0))) >>> 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-71289653*/count=354; tryItOut("this.v1 = this.o2.g1.runOffThreadScript();");
/*fuzzSeed-71289653*/count=355; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround(Math.min((mathy1(Math.fround((Math.hypot((y | 0), (Math.trunc(Math.fround(mathy1(x, x))) >>> 0)) | 0)), (y | 0)) | 0), (((x ? x : (0x07fffffff >>> 0)) >>> 0) + ((Math.hypot(y, x) | 0) + ((((Math.fround(y) ? x : Math.fround(( + mathy1(( + -0x0ffffffff), ( + y))))) | 0) !== Math.min(y, y)) | 0))))) * (Math.atan2(Math.fround((Math.pow(( + ( + (( + (y > (y | 0))) ? ( + 0) : ( + (Math.PI ? y : ( + y)))))), y) === ( + (Math.fround((Math.fround(Math.tan(x)) == Math.fround(Math.fround(( ! ( + 0x100000001)))))) >>> 0)))), ((( + mathy1(( ! Math.max(0x0ffffffff, -0x07fffffff)), ((Math.acosh(( + y)) >>> 0) >= Math.pow(( + Number.MIN_VALUE), ( + ( + Math.imul(( + 0/0), y))))))) , 0x0ffffffff) >>> 0)) | 0)); }); testMathyFunction(mathy2, [0/0, 2**53-2, -(2**53+2), Math.PI, 2**53+2, 0, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, 0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, -(2**53), 1/0, -(2**53-2), -0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000000, 1, 0.000000000000001, -0x080000000, -Number.MAX_VALUE, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-71289653*/count=356; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((i2)+((((-0xfffff*((0x2c942abc) != (0x1cf1d395))) | ((0x4b2b7db3)))) ? (i0) : (i2))-((-9.44473296573929e+21) >= (+(1.0/0.0)))))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { throw 3; }, keys: function() { throw 3; }, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [42, 0x080000001, 0, 0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0/0, 1/0, -(2**53-2), 1, Math.PI, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, -0x080000000, 0x07fffffff, -0, 0.000000000000001, 2**53+2, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -(2**53+2), -1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x07fffffff, -0x080000001, 0x100000001]); ");
/*fuzzSeed-71289653*/count=357; tryItOut("m1.get((new (4277)()));");
/*fuzzSeed-71289653*/count=358; tryItOut("\"use strict\"; let (y = x, \u3056 = \"\\uE498\") { /*infloop*/for({} = (/*MARR*/[].map(Function, x.valueOf(\"number\"))); this.__defineGetter__(\"\\u3056\", offThreadCompileScript); Math.hypot(1415678099, -18)) e0.add(g1); }");
/*fuzzSeed-71289653*/count=359; tryItOut("o0.i0.send(o1.e1);");
/*fuzzSeed-71289653*/count=360; tryItOut("v1 = t1.length;");
/*fuzzSeed-71289653*/count=361; tryItOut("v1 = Array.prototype.reduce, reduceRight.call(a1, (function(j) { f1(j); }), t1);function NaN(x = new RegExp(\".*?\", \"gim\"))(4277)Object.defineProperty(this, \"v0\", { configurable: false, enumerable: true,  get: function() {  return t2.BYTES_PER_ELEMENT; } });");
/*fuzzSeed-71289653*/count=362; tryItOut("for (var v of p1) { try { s1 + ''; } catch(e0) { } try { /*MXX2*/g0.Uint32Array = b0; } catch(e1) { } /*MXX2*/g0.JSON.parse = g1; }");
/*fuzzSeed-71289653*/count=363; tryItOut("Array.prototype.unshift.apply(a2, [\"\\uB671\", i0]);");
/*fuzzSeed-71289653*/count=364; tryItOut("Array.prototype.shift.apply(a2, [o1, m1,  /x/g  > \"\\u7C0F\", t2, s0, o1]);");
/*fuzzSeed-71289653*/count=365; tryItOut("/*infloop*/ for (x of this.__defineSetter__(\"NaN\", [1].asin)) {/*vLoop*/for (let lgxpqt = 0, c; lgxpqt < 2; ++lgxpqt) { var w = lgxpqt; this.v0 = new Number(-Infinity); } \n/*RXUB*/var r = /\\3|([^])+(?!(?=[^]{137438953473,137438953473})*?)*+/; var s = \"\"; print(s.match(r)); \ni0 = o0.a2[9]; }");
/*fuzzSeed-71289653*/count=366; tryItOut("mathy2 = (function(x, y) { return ((( + Math.imul(Math.fround(( - (( + y) | 0))), ( + (mathy0(-(2**53), -(2**53+2)) <= x)))) >>> 0) | Math.fround(Math.fround(Math.hypot(((Math.hypot(Math.fround(Math.imul(2**53, x)), Math.fround(Math.fround(Math.hypot(Math.fround(y), Math.fround(( + y)))))) | 0) >>> 0), (mathy0(Math.fround(Math.pow(( + ( + (y / y))), Math.pow(( + ( - ( + (Math.atan2((y | 0), (x | 0)) >>> 0)))), x))), Math.fround(x)) >>> 0))))); }); testMathyFunction(mathy2, [0/0, -Number.MIN_VALUE, 0.000000000000001, 1, 2**53-2, Math.PI, 0x0ffffffff, 0, -0x100000001, -(2**53-2), 1/0, Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, 0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 2**53+2, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000001, -0x080000000, 42, -1/0, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, -(2**53+2), 2**53, -0]); ");
/*fuzzSeed-71289653*/count=367; tryItOut("\"use strict\"; this.a1.sort((function(j) { f0(j); }), h1, o1);");
/*fuzzSeed-71289653*/count=368; tryItOut("\"use strict\"; o1 = h2.__proto__;");
/*fuzzSeed-71289653*/count=369; tryItOut("\"use strict\"; a0.unshift(h0);");
/*fuzzSeed-71289653*/count=370; tryItOut("m0 = a2[6];");
/*fuzzSeed-71289653*/count=371; tryItOut("mathy4 = (function(x, y) { return (Math.acosh((( + (x | (((Math.fround(Math.min((Math.min(-(2**53-2), y) >>> x), Math.trunc(x))) >>> 0) ^ Math.fround((Math.cbrt((x | 0)) | 0))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, -0x0ffffffff, -0x080000000, 1/0, 1, 0x080000000, Math.PI, 0x07fffffff, Number.MIN_VALUE, 0/0, 0, -0x100000001, 0x100000001, -0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 0x100000000, 2**53, -(2**53), 2**53-2, -0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, -(2**53-2), 0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-71289653*/count=372; tryItOut("\"use strict\"; o0.o0.toSource = (function mcc_() { var nqrxxl = 0; return function() { ++nqrxxl; f0(/*ICCD*/nqrxxl % 4 != 2);};})();print(uneval(e2));");
/*fuzzSeed-71289653*/count=373; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.9342813113834067e+25;\n    var d3 = 4.835703278458517e+24;\n    var d4 = -0.015625;\n    var i5 = 0;\n    var d6 = -134217729.0;\n    return ((-(0xffb5381e)))|0;\n  }\n  return f; })(this, {ff: (new Function(\"x\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0x100000000, 1/0, 42, -(2**53), 0, 0/0, 0x07fffffff, 2**53+2, Number.MIN_VALUE, 1.7976931348623157e308, 1, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, Math.PI, -0x07fffffff, -0x0ffffffff, -1/0, -0x100000001, -0x080000001, -Number.MIN_VALUE, 0x100000001, 0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, -0, -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=374; tryItOut("\"use strict\"; Array.prototype.splice.apply(this.a1, [NaN, x]);");
/*fuzzSeed-71289653*/count=375; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.sqrt(( + Math.fround(( - (Math.sign(((Math.min(( + x), x) >>> 0) | 0)) | 0)))))); }); testMathyFunction(mathy1, [-(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, 0x07fffffff, 0x080000000, 0x080000001, 2**53+2, 1, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 42, -0x100000000, -(2**53+2), 0, 0x0ffffffff, -0x080000001, 0x100000000, 0/0, -0, 1/0, Number.MAX_VALUE, -1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, Number.MIN_VALUE, 2**53, Math.PI]); ");
/*fuzzSeed-71289653*/count=376; tryItOut("\"use strict\"; /*bLoop*/for (ufclpt = 0; ufclpt < 122; ++ufclpt) { if (ufclpt % 3 == 0) { v0 = evalcx(\"4\", g2);Array.prototype.shift.apply(a2, [e1, s0, o0.m1, o1]); } else { /*oLoop*/for (jjbsqm = 0, (allocationMarker()); jjbsqm < 119; ++jjbsqm) { a0.splice(-8,  /* Comment */window); }  }  } ");
/*fuzzSeed-71289653*/count=377; tryItOut("/*infloop*/\u0009do /*RXUB*/var r = new RegExp(\"[^]\\\\2{1,}\", \"y\"); var s = \"\\n\\n\\n\"; print(r.exec(s));  while((function(y) { return \"\\u9213\" })());");
/*fuzzSeed-71289653*/count=378; tryItOut("t1[({ set search callee (d) { \"use strict\"; yield (4277) } , NaN: eval(\"/* no regression tests found */\") })] = g1;");
/*fuzzSeed-71289653*/count=379; tryItOut("mathy5 = (function(x, y) { return (( + Math.min(Math.fround(Math.atan(( + (( + ( - x)) ? y : ( + (Math.fround((Math.fround(x) !== Math.fround(x))) >>> Math.fround(mathy3(-Number.MIN_SAFE_INTEGER, x)))))))), Math.fround(( + Math.fround(Math.imul(Math.fround(((Math.fround(x) && Math.fround((( ~ (y >>> 0)) * ( - x)))) >>> 0)), Math.atan2(y, (( ~ Math.fround(0x100000001)) >>> 0)))))))) != Math.fround((mathy0((Math.fround(( - Math.fround((2**53 !== (((Math.hypot(1/0, x) >>> 0) + (y >>> 0)) >>> 0))))) >>> 0), (Math.atan2(y, (mathy0(Math.fround(Math.sqrt((Math.pow(y, x) | 0))), ((Math.sqrt((mathy4(( + ( ~ ( + y))), x) | 0)) | 0) | 0)) | 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x0ffffffff, 0.000000000000001, 0, 0/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -(2**53+2), 2**53-2, -0x080000000, 0x100000001, 0x100000000, Number.MIN_VALUE, Math.PI, -0x100000000, -(2**53-2), -Number.MAX_VALUE, 42, Number.MAX_VALUE, 1/0, -0x100000001, -(2**53), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0x080000001, -0, -0x080000001, -1/0, 2**53, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=380; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 9.44473296573929e+21;\n    {\n      i1 = (0xf8dd54c4);\n    }\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: (x = Proxy.createFunction(({/*TOODEEP*/})(this), 20, mathy2)).apply}, new ArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[x]); ");
/*fuzzSeed-71289653*/count=381; tryItOut("\"use strict\"; testMathyFunction(mathy5, [2**53-2, 0x100000000, -0x100000001, 1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -1/0, -0x080000001, -0x07fffffff, 42, -0x100000000, -0x080000000, -(2**53), 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, 1, 0x0ffffffff, 2**53+2, 0, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), 2**53]); ");
/*fuzzSeed-71289653*/count=382; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.fround((( ! (mathy1(( - 42), Math.fround(( + y))) | 0)) >>> (mathy0(((( ~ (x != (Math.imul((x && y), Math.imul(x, x)) | 0))) | 0) | 0), (( + x) || Math.fround(x))) | 0))) ? (Math.max(((mathy0((Math.min(x, (Math.sign((y >>> 0)) >>> 0)) | 0), Math.acos((y | 0))) || ( + Math.trunc(( + ( + ( - ( + ( - y)))))))) | 0), (( ~ Math.fround(( - (( + (Math.abs(x) != ( + 42))) | 0)))) | 0)) | 0) : ((( + mathy1(Math.fround(Math.asin(x)), /*RXUE*/new RegExp(\".*\", \"im\").exec(\"\"))) ** Math.fround(( - Math.pow(0, (-Number.MAX_SAFE_INTEGER ? y : (((-Number.MAX_SAFE_INTEGER | 0) && (y | 0)) | 0)))))) >>> 0)); }); testMathyFunction(mathy3, [2**53, 1/0, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 42, -(2**53), -0x080000001, 2**53-2, Number.MAX_VALUE, 0x100000000, -0x0ffffffff, -0x080000000, 2**53+2, -0, -0x100000000, Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, 1, -0x100000001, -(2**53+2), Math.PI, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=383; tryItOut("v2 = o2.g2.runOffThreadScript();");
/*fuzzSeed-71289653*/count=384; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=385; tryItOut("if((x % 6 != 0)) { if ((Math.asinh(-15))) for (var p in g0) { try { let a2 = a2.slice(NaN, NaN, v2); } catch(e0) { } f1.toSource = (function() { i2.next(); return e2; }); }} else for (var v of o0.t2) { try { this.v2 = this.o0.a0.reduce, reduceRight((function() { a0.toString = (function mcc_() { var llotrz = 0; return function() { ++llotrz; if (/*ICCD*/llotrz % 5 == 0) { dumpln('hit!'); a0.unshift(g0.h1); } else { dumpln('miss!'); try { m0.has(e0); } catch(e0) { } for (var v of b1) { try { this.v0 = (m0 instanceof v1); } catch(e0) { } try { s2 = o1.s1.charAt(9); } catch(e1) { } try { f2 + ''; } catch(e2) { } neuter(b0, \"same-data\"); } } };})(); throw g2.t1; }), g0.m1, b2); } catch(e0) { } a1.__proto__ = v2; }");
/*fuzzSeed-71289653*/count=386; tryItOut("mathy0 = (function(x, y) { return ( ~ ((((((( + (( + -0) * ( + Math.hypot(y, x)))) >>> 0) || (( ~ ((Math.max(y, 42) < (( + y) >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0) < (Math.pow(( ~ x), ( + ( - x))) | 0)) | 0)); }); ");
/*fuzzSeed-71289653*/count=387; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"^\", \"g\"); var s = \"\\u47d7\\udd0b\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-71289653*/count=388; tryItOut(";");
/*fuzzSeed-71289653*/count=389; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.cbrt((Math.min((mathy0((x >>> 0), (mathy0(Math.fround(( + x)), 1/0) >>> 0)) >>> 0), Math.atan(y)) ? ((Math.atan2(y, x) - -Number.MAX_SAFE_INTEGER) ? y : x) : Math.log2(y))) < Math.fround(Math.sqrt(Math.fround(Math.abs(( + Math.atan(x))))))); }); ");
/*fuzzSeed-71289653*/count=390; tryItOut("\"use strict\"; print(h1);");
/*fuzzSeed-71289653*/count=391; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-71289653*/count=392; tryItOut("/*oLoop*/for (kgkdey = 0; kgkdey < 67; ++kgkdey) { v0 = (f0 instanceof g1); } ");
/*fuzzSeed-71289653*/count=393; tryItOut("\"use strict\"; f1.toSource = f2;");
/*fuzzSeed-71289653*/count=394; tryItOut("a0.length = 11;");
/*fuzzSeed-71289653*/count=395; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=396; tryItOut("/*infloop*/L: for  each(w in (4277)) { if (!isAsmJSCompilationAvailable()) { void 0; void schedulegc(1); } void 0; }a1.pop();");
/*fuzzSeed-71289653*/count=397; tryItOut("/*vLoop*/for (let zfeogi = 0,  /x/ ; zfeogi < 36; ++zfeogi) { const d = zfeogi; v1 = a0[({valueOf: function() { Object.preventExtensions(this.v1);return 6; }})]; } ");
/*fuzzSeed-71289653*/count=398; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\cH\", \"gyim\"); var s = \"\\uffe8\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=399; tryItOut("mathy1 = (function(x, y) { return (Math.tanh((Math.fround(((mathy0((x > (( + Math.hypot(x, -0x100000001)) | 0)), (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) == Math.fround(Math.hypot(0, ((( - (Math.hypot(y, (y | 0)) >>> 0)) >>> 0) !== ((Math.max((Math.atan2(x, x) | 0), Math.PI) | 0) ? y : y)))))) >>> 0)) | 0); }); ");
/*fuzzSeed-71289653*/count=400; tryItOut("print(g1.o1);");
/*fuzzSeed-71289653*/count=401; tryItOut("\"use strict\"; let (x = Math.atan2(-18, 20), y = (4277), x, w, x = (a = Proxy.create(({/*TOODEEP*/})( '' ),  \"\" )), x =  /x/ , otirvk, x, fubyzt) {  \"\" ;\nthis.m1 = new WeakMap;\ne0.delete(g1); }");
/*fuzzSeed-71289653*/count=402; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s2; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=403; tryItOut("f0 = a2[7];");
/*fuzzSeed-71289653*/count=404; tryItOut("mathy0 = (function(x, y) { return Math.sin((Math.tan((Math.min((Math.pow(Math.fround(Math.hypot(x, y)), (Math.imul((x | 0), (Math.atan2(x, y) | 0)) | 0)) >>> 0), ( + Math.fround(Math.atan2(Math.fround(x), Math.fround(x))))) | 0)) | 0)); }); testMathyFunction(mathy0, [0x080000001, 2**53+2, -0x07fffffff, -0x080000000, -0x080000001, 1, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, 0x100000000, -0x100000000, 0x100000001, 0x0ffffffff, Math.PI, 42, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, -1/0, -(2**53-2), 0, -0, 0/0, -(2**53), 0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=405; tryItOut("f0 + '';");
/*fuzzSeed-71289653*/count=406; tryItOut("o1.b2 = g0.objectEmulatingUndefined();");
/*fuzzSeed-71289653*/count=407; tryItOut("print(uneval(this.v2));");
/*fuzzSeed-71289653*/count=408; tryItOut("o0.valueOf = (String.prototype.substring).call;");
/*fuzzSeed-71289653*/count=409; tryItOut("with({b: (this.__defineGetter__(\"x\", Array.prototype.reverse))}){print(x); }");
/*fuzzSeed-71289653*/count=410; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?:[^]|[^\\v-\u0010\u00bd\u1b5c]+))/gi; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=411; tryItOut("if(false) {i2.send(h2);i2.send(p2); }");
/*fuzzSeed-71289653*/count=412; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-71289653*/count=413; tryItOut("mathy1 = (function(x, y) { return Math.atan2((Math.expm1(Math.imul(( + Math.fround(Math.expm1(Math.fround(Math.log2(x))))), ( + x))) >>> 0), Math.clz32(( + Math.pow((( - Math.pow(((Math.acosh((y >>> 0)) >>> 0) | 0), (y | 0))) | 0), (((y >>> 0) >>> ((( - Math.fround(y)) | 0) >>> 0)) | 0))))); }); testMathyFunction(mathy1, [[0], '0', 1, (new Boolean(true)), (new Boolean(false)), [], objectEmulatingUndefined(), /0/, 0.1, false, ({toString:function(){return '0';}}), undefined, -0, '', 0, (new Number(0)), (new Number(-0)), true, ({valueOf:function(){return 0;}}), (function(){return 0;}), NaN, ({valueOf:function(){return '0';}}), '/0/', '\\0', null, (new String(''))]); ");
/*fuzzSeed-71289653*/count=414; tryItOut("/*tLoop*/for (let z of /*MARR*/[y = a, ({}), ({}), ({}), y = a, y = a, ({}), ({}), ({}), ({}), y = a]) { t2 = new Int16Array(b2); }");
/*fuzzSeed-71289653*/count=415; tryItOut("/*bLoop*/for (let ifhsaj = 0; ifhsaj < 38; ++ifhsaj) { if (ifhsaj % 54 == 35) { /*vLoop*/for (let vkmssg = 0, {} = x; (/(?=[^])?(?=\\2){1,1048577}/gm) && vkmssg < 66; ++vkmssg) { c = vkmssg; m2.delete(b2); }  } else { return false;function c(eval = (eval =  \"\" ), x) { \"use strict\"; return /\\1/yim; } /*ODP-2*/Object.defineProperty(o0.g1.s2, 7, { configurable: false, enumerable: (x % 23 != 13), get: Boolean.bind(o0.s1), set: (function() { m2.get(f1); return o0; }) }); }  } ");
/*fuzzSeed-71289653*/count=416; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[\\u00a7-\\ue987\\\\cV-\\\\&\\\\W]\", \"gym\"); var s = \"0\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=417; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-71289653*/count=418; tryItOut("\"use strict\"; v1 = evalcx(\"a0.push(o2, g0.o1.a1, g2, g1);\", g2);");
/*fuzzSeed-71289653*/count=419; tryItOut("v2 = a2.length;");
/*fuzzSeed-71289653*/count=420; tryItOut("\"use strict\"; v0 = (t0 instanceof o2.p2);");
/*fuzzSeed-71289653*/count=421; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2|([^]|(?=^)\\\\b*|^|[^]\\\\W+?([^])|\\\\u24c8\\\\1|(?:(?=\\\\1))|^\\uc4d6)\", \"gm\"); var s = \"\\n\\n\\uc4d6\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=422; tryItOut("o1.v2 = t2[\"1\"];");
/*fuzzSeed-71289653*/count=423; tryItOut("with({}) { for(let x in []); } ");
/*fuzzSeed-71289653*/count=424; tryItOut("throw StopIteration;");
/*fuzzSeed-71289653*/count=425; tryItOut("\"use strict\"; v1 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-71289653*/count=426; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return ((-0x12ddf*(!(i0))))|0;\n  }\n  return f; })(this, {ff: function(q) { return q; }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000001, -0x080000001, 0, 2**53-2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53, -Number.MAX_VALUE, 1.7976931348623157e308, 1/0, 1, -0x07fffffff, -(2**53-2), Number.MAX_VALUE, -0x080000000, Math.PI, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -(2**53+2), -0x100000000, Number.MIN_VALUE, -0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x100000001, 0.000000000000001, 0/0, -1/0, 2**53+2, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=427; tryItOut("/* no regression tests found */\n/*infloop*/M:for(let c =  \"\" ; (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -4398046511103.0;\n    var i4 = 0;\n    return +((d0));\n  }\n  return f; }); /\\2/gyi) {(new RegExp(\"((\\\\\\u458d))(?:\\\\b){1,}\", \"gm\"));t2.set(t1, 0); }\n");
/*fuzzSeed-71289653*/count=428; tryItOut("/*oLoop*/for (let yugykr = 0; yugykr < 46; ++yugykr) { do /*ADP-3*/Object.defineProperty(a1, 16, { configurable: (x % 4 != 0), enumerable: true, writable: false, value: i0 }); while((x / z) && 0); } ");
/*fuzzSeed-71289653*/count=429; tryItOut("s0 + '';");
/*fuzzSeed-71289653*/count=430; tryItOut("testMathyFunction(mathy3, [2**53, 1, 0x080000000, 2**53+2, -(2**53+2), -0x100000001, 0.000000000000001, -0x100000000, 0x100000001, 0, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, 0x100000000, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, 42, 0x080000001, -(2**53-2), 1/0, 0/0, -0x080000001, -(2**53), 0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-71289653*/count=431; tryItOut("o2 = Object.create(a1);");
/*fuzzSeed-71289653*/count=432; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((( ! 0x100000001) >>> 0) < (Math.atanh((Math.asin(mathy0(Math.fround(-Number.MIN_VALUE), Math.fround(Number.MIN_VALUE))) | 0)) >>> 0)) ^ Math.atan(mathy0(( ! Math.fround(-Number.MAX_VALUE)), Math.fround((x & Math.fround((( + 0x100000000) >>> 0))))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000000, 2**53-2, 0x0ffffffff, 1/0, 1.7976931348623157e308, -0x07fffffff, 0.000000000000001, 2**53, Number.MIN_VALUE, 0x100000001, -0x080000000, Math.PI, -0, -(2**53+2), -Number.MAX_VALUE, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, -1/0, -Number.MIN_VALUE, -0x100000001, 0x080000001, 42, -(2**53), -0x100000000, 1]); ");
/*fuzzSeed-71289653*/count=433; tryItOut("let c = \"\u03a0\";e2.delete(v1);");
/*fuzzSeed-71289653*/count=434; tryItOut("t1[13] = Array.prototype.find--;");
/*fuzzSeed-71289653*/count=435; tryItOut("const x, d, x, urqeej, x, x, b, xiuzvf, eusnnl;this.t0[11];");
/*fuzzSeed-71289653*/count=436; tryItOut("/*RXUB*/var r = o1.r1; var s = s0; print(r.exec(s)); ");
/*fuzzSeed-71289653*/count=437; tryItOut("mathy0 = (function(x, y) { return Math.exp(Math.fround((((( + (Math.cbrt(( + ( ~ 1))) >> y)) >>> 0) % ((-Number.MIN_SAFE_INTEGER === y) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[2**53+2, [undefined], [undefined], new String(''), new String('')]); ");
/*fuzzSeed-71289653*/count=438; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var atan = stdlib.Math.atan;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = (i0);\n    i2 = (i2);\n    i2 = (i0);\n    (Float64ArrayView[((i0)) >> 3]) = ((4294967295.0));\n    {\n      switch ((((0xfceeb00e)-(0xf9af8c81)-(0xffffffff)) << ((i0)))) {\n        case 0:\n          (Int32ArrayView[(((i0) ? (0x75dfdbcb) : (i2))+(i2)-((((0x742f3d29)*-0x2f24a)>>>((0xfabce738)-(0x49fd650f))))) >> 2]) = ((/*FFI*/ff(((-1.1805916207174113e+21)), ((d1)))|0)+(i2)+(!(!(i0))));\n          break;\n        case 0:\n          d1 = (d1);\n      }\n    }\n    {\n      {\n        i0 = (0xffffffff);\n      }\n    }\n    return +(({}));\n    {\n      switch ((0x6a5e6b4b)) {\n        case 1:\n          (Uint32ArrayView[2]) = ((0x2bfff5b6));\n          break;\n        case -1:\n          i0 = (i0);\n          break;\n        case -1:\n          return +((+atan(((+((d1)))))));\n        case -3:\n          (Uint32ArrayView[(0x3b03f*((((Int8ArrayView[1])) ^ ((0x649b6cd1) / (0x2c6844ff))) < (((0xc13e884e)+(0xd999f08c)-(0xfc7eb8a4)) ^ ((w = undefined <<= true))))) >> 2]) = ((i0));\n        default:\n          return +((67108865.0));\n      }\n    }\n    return +((+atan2(((+(-1.0/0.0))), ((-576460752303423500.0)))));\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0/0, -0x100000001, 0x100000001, -0, 1.7976931348623157e308, -Number.MAX_VALUE, -1/0, 0x080000000, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, 0x07fffffff, -(2**53+2), -(2**53-2), 2**53+2, 1/0, 0.000000000000001, 2**53-2, 0x100000000, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53, -0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, 42, Number.MAX_VALUE, 0, 1]); ");
/*fuzzSeed-71289653*/count=439; tryItOut("\"use strict\"; v2 = r1.global;");
/*fuzzSeed-71289653*/count=440; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.acosh(( + Math.pow(( + Math.ceil(Math.expm1(Math.fround((Math.fround(y) ** Math.fround((y << (((y >>> 0) < (y | 0)) >>> 0)))))))), ( + ( ! ( + y)))))); }); ");
/*fuzzSeed-71289653*/count=441; tryItOut("\"use strict\"; Array.prototype.forEach.call(a2, f2, t1);");
/*fuzzSeed-71289653*/count=442; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    i0 = (i1);\n    return ((((0xffffffff) >= ((((0xffffffff)))>>>((!(/*FFI*/ff(((abs((((0xffffffff)) | ((0x907e6558))))|0)))|0)))))+((Float64ArrayView[((i0)) >> 3]))))|0;\n  }\n  return f; })(this, {ff: ((delete x.a).throw((4277)))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000001, 2**53, Math.PI, -1/0, -0, 1, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 0x080000001, 0x100000000, 0x0ffffffff, -(2**53), -Number.MIN_VALUE, 42, 0x080000000, -Number.MAX_VALUE, 0x100000001, 0/0, Number.MIN_VALUE, -0x07fffffff, -0x100000000, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, -0x0ffffffff, -(2**53+2), 0, -0x080000000]); ");
/*fuzzSeed-71289653*/count=443; tryItOut("return;");
/*fuzzSeed-71289653*/count=444; tryItOut("this.o2.valueOf = (function() { try { for (var v of p2) { v2 = Object.prototype.isPrototypeOf.call(t1, e0); } } catch(e0) { } try { o0.e1.add(m0); } catch(e1) { } this.o1.e0.has(/*UUV1*/(x.toString = (function(x, y) { return (((Math.fround(-0) | 0) % (x | 0)) | 0); }))); throw f2; });");
/*fuzzSeed-71289653*/count=445; tryItOut("\"use strict\"; print(uneval(o1.s0));");
/*fuzzSeed-71289653*/count=446; tryItOut("/*ODP-2*/Object.defineProperty(f1, \"push\", { configurable: ({x: {c}, x, x: [], NaN: [, , , , ], eval: [], x} = b), enumerable: (4277), get: TypeError.prototype.toString.bind(e1), set: (function() { try { v2 + v1; } catch(e0) { } try { h1 = {}; } catch(e1) { } for (var v of h2) { try { Array.prototype.reverse.apply(a0, []); } catch(e0) { } try { a1.shift(); } catch(e1) { } try { v2 = (g2.v0 instanceof this.o2.v2); } catch(e2) { } t1 = t0.subarray(({valueOf: function() { /* no regression tests found */return 11; }}), 11); } return s0; }) });");
/*fuzzSeed-71289653*/count=447; tryItOut("i1.send(o0);");
/*fuzzSeed-71289653*/count=448; tryItOut("");
/*fuzzSeed-71289653*/count=449; tryItOut("testMathyFunction(mathy5, /*MARR*/[x, x, x, false, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, NaN, (void 0), (void 0)]); ");
/*fuzzSeed-71289653*/count=450; tryItOut("let (x) { e1.__proto__ = o0.g0; }");
/*fuzzSeed-71289653*/count=451; tryItOut("\"use strict\"; for (var v of o2.s1) { try { Object.freeze(m1); } catch(e0) { } try { for (var v of a2) { h0 = {}; } } catch(e1) { } p0 = m1.get(f1); }function NaN()\"\\u910D\"e1 = new Set(b2);");
/*fuzzSeed-71289653*/count=452; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + Math.atanh((mathy1(Math.fround(( ! Math.sign(x))), ( ~ Math.fround(Math.max(y, (y | 0))))) >>> 0))); }); testMathyFunction(mathy2, [1, -(2**53+2), -0x080000001, -0x07fffffff, 0x100000001, -(2**53-2), 1/0, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, 42, 0.000000000000001, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 0x080000000, 0/0, 2**53, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, -0x100000000, 1.7976931348623157e308, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 0, 0x07fffffff, Math.PI, -1/0, -0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=453; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((( ! Math.log1p(mathy1(y, 1))) | 0) & Math.pow((( + (x >= y)) ^ x), ( + y))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, 0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, -0x080000000, 0x080000001, 0/0, -0, 1/0, 0x07fffffff, -(2**53-2), -Number.MIN_VALUE, 42, 1.7976931348623157e308, -0x100000000, Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 1, 2**53, -(2**53+2), -0x100000001, -Number.MAX_VALUE, -0x0ffffffff, -0x080000001, -1/0, -(2**53), 0]); ");
/*fuzzSeed-71289653*/count=454; tryItOut("t2[7] = a1;/*vLoop*/for (hzgukq = 0; hzgukq < 27; ++hzgukq) { const y = hzgukq; ( /x/g ); } ");
/*fuzzSeed-71289653*/count=455; tryItOut("\"use strict\"; o2.m1.get(b2);");
/*fuzzSeed-71289653*/count=456; tryItOut("\"use strict\"; /*infloop*/ for  each(var \"\\uEF3A\".__proto__ in  '' ) selectforgc(o0.o2);");
/*fuzzSeed-71289653*/count=457; tryItOut("\"use strict\"; yield;");
/*fuzzSeed-71289653*/count=458; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.atanh((mathy0((Math.fround((Math.fround(y) != Math.fround(y))) | 0), Math.expm1(Math.round(( + ((((-0x0ffffffff >>> 0) / (y >>> 0)) >>> 0) | x))))) | 0)) * Math.log1p(Math.fround(Math.atan2(Math.fround((( ! (-Number.MAX_SAFE_INTEGER >>> 0)) | 0)), -1/0)))); }); ");
/*fuzzSeed-71289653*/count=459; tryItOut("var euldif = new ArrayBuffer(8); var euldif_0 = new Int32Array(euldif); euldif_0[0] = -29; var euldif_1 = new Int8Array(euldif); var euldif_2 = new Uint8Array(euldif); print(euldif_2[0]); euldif_2[0] =  /x/ ; print(/*oLoop*/for (let wlxyfz = 0; wlxyfz < 38; ++wlxyfz) { x; } );print((4277));/*RXUB*/var r = new RegExp(\"(?=(?=(?:\\\\u0033))*?|(?=(?![\\u00fa-\\\\\\ua572\\u00c2-\\\\A])?(?!\\\\1)*){1})([\\\\\\n\\\\d\\\\x88][^]{2}){1,}|\\\\W*?|\\\\2\", \"\"); var s = \"\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=460; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = ((i0) ? (0x914d602) : (i0));\n    }\n    i0 = (i0);\n    (Int32ArrayView[1]) = ((-0x8000000)*0xf1bdd);\n    d1 = (((0.125)) * ((+(-1.0/0.0))));\n    i0 = (!((Uint8ArrayView[1])));\n    {\n      return +((+(1.0/0.0)));\n    }\n    {\n      {\n        {\n          d1 = (17179869183.0);\n        }\n      }\n    }\n    (Float32ArrayView[(((0xffffffff))-(i0)+(i0)) >> 2]) = ((-65537.0));\n    (Uint16ArrayView[(-0xfe59c*(i0)) >> 1]) = ((imul((!(/*FFI*/ff()|0)), (((0x6ed3*((0xfee2e908)))>>>((0x10d76aa6) % (0x209508ee))) != (((0xdb7b544f)-(0xfd0a57fc))>>>(((0x18cea4a2) != (0x5cee0762))-(timeout(1800))))))|0) % (((!((0x9f27bd0) >= (~~(2.0))))+((((0x83781d3c))>>>((0x9ba35b44))) != (((-0x8000000))>>>((0x279b810c))))-(i0)) << (0xfffff*((abs(((((0xe822ded5) ? (0xfd38832a) : (0xffffffff))) ^ ((0xd530577d)+(0xffffffff))))|0)))));\n    {\n      return +((-8796093022209.0));\n    }\n    switch (((-0x4af92*(0xe0609e76)) ^ ((-0x8000000)-(0x4a88277e)-(0x94b2ad5d)))) {\n      case -2:\n        (Uint32ArrayView[4096]) = (((((0xf0599f88))>>>(x)))*0x27861);\n        break;\n      case 0:\n        i0 = (0xffffffff);\n        break;\n      case -2:\n        d1 = (Infinity);\n      default:\n        {\n          i0 = (/*FFI*/ff(((((((((0x6fb39553) ? (0x226b9a27) : (-0x8000000)))>>>((0xef746037) / (((0x4e249f08))>>>((0xc6116eeb))))))+((+(-1.0/0.0)) != (-257.0))) | ((i0)-((0x57ae84b))))), ((~((0xfafe52eb)))), ((1.25)))|0);\n        }\n    }\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: Math.floor}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308, -(2**53+2), 2**53, -Number.MAX_VALUE, -1/0, -(2**53), 2**53+2, Math.PI, 42, 0x07fffffff, 0/0, -0x100000000, 0x0ffffffff, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, 0.000000000000001, 0, 0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, -0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, Number.MAX_SAFE_INTEGER, -0, 1, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=461; tryItOut(";");
/*fuzzSeed-71289653*/count=462; tryItOut("mathy0 = (function(x, y) { return Math.min((Math.atan2((Math.log2(Math.log(y)) >>> 0), ((Math.abs(((Math.fround(Math.expm1((Math.imul(y, y) >>> 0))) >> ((Math.hypot(x, ( + 2**53-2)) >>> 0) === Math.fround(Math.fround(( + x))))) >>> 0)) >>> 0) | 0)) | 0), (Math.pow(( ~ (Math.acos(((Math.pow(y, (( + (( + Math.asinh(x)) ? ( + ( + Math.cos(( + x)))) : Math.asinh((0x080000001 | 0)))) | 0)) | 0) | 0)) >>> 0)), (Math.max(( + ( ! ( + Math.fround(Math.pow(Math.fround(y), 2**53-2))))), Math.fround(Math.sin(x))) | 0)) | 0)); }); testMathyFunction(mathy0, [0x100000001, Math.PI, -0, 1/0, -0x080000000, 2**53+2, -0x080000001, 1.7976931348623157e308, -(2**53+2), -(2**53-2), Number.MAX_SAFE_INTEGER, 0, 0x100000000, 2**53, -0x0ffffffff, 0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, 0/0, 2**53-2, 0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, 1, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, Number.MIN_VALUE, -1/0, 42, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53)]); ");
/*fuzzSeed-71289653*/count=463; tryItOut("a2 = new Array;");
/*fuzzSeed-71289653*/count=464; tryItOut("var b = (4277), \u3056, mfkwmm, eval = \"\\u6AAF\", fjxork, NaN, x, ebdttz;v0 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 58 != 31), noScriptRval: false, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-71289653*/count=465; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.log2(mathy0((Math.abs(y) | 0), ( ~ (mathy0((( ~ x) | 0), (y | 0)) | 0))))); }); testMathyFunction(mathy1, [0/0, -0x100000000, -0, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, 2**53, 0x0ffffffff, 1/0, -(2**53-2), -(2**53), -0x080000000, -(2**53+2), 0x080000001, 0.000000000000001, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, 0x100000000, 2**53+2, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, Math.PI, 1, 0x100000001, 1.7976931348623157e308, 2**53-2, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-71289653*/count=466; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround((Math.fround(Math.fround(Math.hypot((( + Math.imul(((x ^ ( + Math.tan(x))) >>> 0), Math.clz32(x))) | 0), ((( + ( - ( + y))) === mathy0((0x100000000 | 0), ( ! Math.hypot(y, Math.hypot((-(2**53+2) >>> 0), Math.fround(y)))))) | 0)))) <= Math.fround(Math.fround(( + mathy0((-0x080000001 - x), 0x100000001)))))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, 0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53), 1/0, -0x100000001, 0/0, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 2**53+2, -0x100000000, 0x100000001, 42, 1, 0x080000001, 0x080000000, 0.000000000000001, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, 0, -(2**53-2), -0x080000001, 2**53, Number.MAX_VALUE, Math.PI, 0x0ffffffff, -0x07fffffff, -0]); ");
/*fuzzSeed-71289653*/count=467; tryItOut("g2 + '';");
/*fuzzSeed-71289653*/count=468; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=469; tryItOut("/*hhh*/function gdrqzd(){var z = ('fafafa'.replace(/a/g, x))(delete x.x & \"\\uBCE7\", window(window));/*oLoop*/for (let evmndu = 0; evmndu < 90; ++evmndu) { print((timeout(1800))); } }gdrqzd();");
/*fuzzSeed-71289653*/count=470; tryItOut("mathy4 = (function(x, y) { return (( ! (mathy2(Math.min((Math.log(Math.tan(y)) | 0), (Math.hypot(Math.fround((Math.hypot(Number.MIN_VALUE, x) >= y)), y) >>> 0)), (Math.min(mathy3((( ~ Math.hypot(x, x)) | 0), (( + y) + Math.fround(( + Math.min(Math.tan(-(2**53-2)), ( + x)))))), 2**53+2) | 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-71289653*/count=471; tryItOut("\"use strict\"; \"use asm\"; g0.s0 += s2;");
/*fuzzSeed-71289653*/count=472; tryItOut("\"use strict\"; for(let c of /*FARR*/[.../*FARR*/[(((x | 0) ? (0/0 | 0) : ( + x)) | 0), ...(function() { yield (makeFinalizeObserver('tenured')); } })()], new (x)((c) = e), x, ...new Array(-0),  /x/ ]) e = c;Uint8Array");
/*fuzzSeed-71289653*/count=473; tryItOut("o2.o2.e0.delete(t1);");
/*fuzzSeed-71289653*/count=474; tryItOut("mathy3 = (function(x, y) { return (((Math.hypot((mathy1((Math.fround(((mathy2((x >>> 0), ((2**53 ^ y) >>> 0)) >>> 0) >> Math.hypot(y, Math.fround(Math.min(0/0, -0x07fffffff))))) >>> 0), (mathy0(Math.fround(( ! x)), (( + ( - ( + Math.min(Math.fround(( ~ (y | 0))), 0/0)))) | 0)) >>> 0)) | 0), ( + (( ! (Math.acosh(x) | 0)) | 0))) >>> 0) % ((((Math.atan2((((x | 0) ? (x | 0) : (y | 0)) | 0), y) | 0) >> (( - ( - Math.fround(y))) | 0)) | 0) | 0)) >>> 0); }); testMathyFunction(mathy3, [1, 0x07fffffff, -0x07fffffff, -0, -(2**53-2), Number.MIN_VALUE, Math.PI, 2**53+2, 0x100000001, 0.000000000000001, -(2**53), Number.MAX_VALUE, 42, 1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, -0x080000001, 0x080000001, 0, 1.7976931348623157e308, 0x080000000, -1/0, -0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, -0x0ffffffff, -0x100000000, 0x100000000, 2**53, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=475; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-71289653*/count=476; tryItOut("mathy3 = (function(x, y) { return (mathy2((( - ( ~ Math.tanh(y))) >>> 0), ((( ~ (mathy2(42, Math.fround(Math.max(1, Math.sin(( + mathy2(( + Math.sinh(y)), ( + Math.expm1((0x100000001 | 0))))))))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[ /x/g ,  /x/g , false,  /x/g , (void 0), (void 0),  /x/g , (void 0), (void 0)]); ");
/*fuzzSeed-71289653*/count=477; tryItOut("var durtly, y = (4277), w =  /* Comment *//*FARR*/[].sort, {} = /[^\u491c-\u009e\u0002-\u4faa\\s]/gyi.__defineSetter__(\"c\", String.prototype.lastIndexOf), x = (4277), eval = x;var liivtf = new SharedArrayBuffer(4); var liivtf_0 = new Float64Array(liivtf); liivtf_0[0] = 0; var liivtf_1 = new Int8Array(liivtf); liivtf_1[0] = 0; var liivtf_2 = new Uint8Array(liivtf); print(liivtf_2[0]); liivtf_2[0] = -19; e2.add(b2);print(y);i0.next();print(liivtf_2);");
/*fuzzSeed-71289653*/count=478; tryItOut("\"use strict\"; for (var p in o2.g0.f1) { try { a2.shift(o2.b1, f2); } catch(e0) { } try { Array.prototype.pop.call(a1); } catch(e1) { } try { o1 = v0.__proto__; } catch(e2) { } e2 = new Set(b1); }");
/*fuzzSeed-71289653*/count=479; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?!^){3,}((\\\\2|(\\\\2)|\\\\1)(\\\\b)+))\", \"y\"); var s = \"\"; print(s.replace(r, r , (/*FARR*/[s, x].filter((new Function(\"g0.h2 + h2;\")), let (x = this)  '' )))); ");
/*fuzzSeed-71289653*/count=480; tryItOut("\"use strict\"; Array.prototype.push.apply(a0, [i0, h2, g0.o1, v2, a2, h2, g1]);");
/*fuzzSeed-71289653*/count=481; tryItOut("(x);");
/*fuzzSeed-71289653*/count=482; tryItOut("\"use strict\"; v0 = (b2 instanceof t1);");
/*fuzzSeed-71289653*/count=483; tryItOut("if(false) { if ((makeFinalizeObserver('tenured'))) {s1 += s0;print(uneval(h1)); }} else {a1[1];/*infloop*/while([])print(x); }");
/*fuzzSeed-71289653*/count=484; tryItOut("\"use strict\"; o0.m0.set(t0, s2);");
/*fuzzSeed-71289653*/count=485; tryItOut("/*infloop*/for(let d =  /x/ ; (4277); x--) {true; }");
/*fuzzSeed-71289653*/count=486; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (((Math.max((( + ( + Math.fround(((x >>> 0) << 0x100000000)))) > y), ((( + x) >> ( + (x ? y : x))) <= -0x080000001)) | 0) ? (Math.fround(((Math.clz32(Math.clz32(( + Math.pow(Math.fround(Math.trunc(x)), ( + ( + ( ! ( + x)))))))) | 0) | (Math.fround(mathy1(Math.log1p((-0x080000000 != y)), (Math.log(y) == Math.pow(x, x)))) | 0))) | 0) : (Math.atan2((( + ( + mathy0((Math.cos((y | 0)) | 0), 0x07fffffff))) | 0), (Math.log10((Math.tan(Math.log1p(( + y))) | 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy2, [-0, Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), -0x080000000, 0x100000001, 0/0, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 0, 1.7976931348623157e308, 42, -0x080000001, -(2**53), 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, 1/0, -Number.MAX_VALUE, -0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -1/0, 0x100000000, -(2**53+2), 0x07fffffff, -0x100000001, 0x080000000, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=487; tryItOut("g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: x(28), catchTermination: (x = [,]) }));");
/*fuzzSeed-71289653*/count=488; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=489; tryItOut("mathy0 = (function(x, y) { return Math.fround((( + (((((0x100000000 | 0) !== (y | 0)) | 0) > ( + (((Math.fround(Math.pow(Math.fround(y), Math.fround(y))) >>> 0) !== (x >>> 0)) >>> 0))) | 0)) ? Math.fround(Math.atan(Math.pow(( + Math.asinh(( + (Math.pow(Math.sqrt(1.7976931348623157e308), (y >>> 0)) >>> 0)))), ( + Math.log10(( + (( ! Math.abs(x)) ? ( - y) : 0x100000000))))))) : Math.fround(( + Math.cbrt(( + 1.7976931348623157e308)))))); }); ");
/*fuzzSeed-71289653*/count=490; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(( ~ Math.ceil((Math.tan((Math.imul((mathy0((y | 0), (x | 0)) | 0), x) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [true, ({toString:function(){return '0';}}), false, /0/, (function(){return 0;}), (new Boolean(false)), (new Number(0)), [0], ({valueOf:function(){return '0';}}), 0.1, '/0/', objectEmulatingUndefined(), [], ({valueOf:function(){return 0;}}), -0, (new String('')), 1, NaN, undefined, (new Boolean(true)), null, '', '\\0', (new Number(-0)), '0', 0]); ");
/*fuzzSeed-71289653*/count=491; tryItOut("e1.delete(e1);");
/*fuzzSeed-71289653*/count=492; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(((Math.asin(-0x080000001) >>> 0) || ( + ((((Math.tanh(y) | 0) === (-0x100000001 | 0)) | 0) >= Math.fround((y ? x : Math.fround(((Math.sqrt(2**53) >>> 0) === ( + (( + x) && ( + -Number.MAX_SAFE_INTEGER))))))))))) != ( ! ( - Math.sin((( ~ y) | 0))))); }); testMathyFunction(mathy2, [-0x07fffffff, 0x100000000, 1/0, 0, -(2**53), -0x080000000, -0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, 1.7976931348623157e308, 0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, -Number.MIN_VALUE, -0x0ffffffff, Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53-2), 1, -0x080000001, 0x07fffffff, -0x100000001, -(2**53+2), -Number.MAX_VALUE, -1/0, 0x080000000, Number.MIN_VALUE, 2**53+2, 2**53, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=493; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0/0, Math.PI, 1.7976931348623157e308, 1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -0x080000000, 0x100000001, 0x080000001, 2**53-2, -(2**53+2), -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), 0x080000000, -1/0, 42, 0x100000000, 2**53+2, 0x07fffffff, -0x080000001, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000001, 1, 2**53, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=494; tryItOut("\"use strict\"; /*infloop*/for(var b = null; null; \"\\uE645\") (\"\\uF6AE\");");
/*fuzzSeed-71289653*/count=495; tryItOut("\"use strict\"; t0 = a1[10];");
/*fuzzSeed-71289653*/count=496; tryItOut("\"use strict\"; print(b1);");
/*fuzzSeed-71289653*/count=497; tryItOut("/*RXUB*/var r = /(?!(([^]{1,2})+?(?=.{1,})*?|\\B)+?)/; var s = \"\"; print(s.replace(r, new Function, \"y\")); ");
/*fuzzSeed-71289653*/count=498; tryItOut("\"use strict\"; var c = x;this.g2.offThreadCompileScript(\" \\\"\\\" \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (c % 6 == 4), noScriptRval: new RegExp(\"$+\\\\D(?=^\\\\3){4}\", \"g\"), sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-71289653*/count=499; tryItOut("\"use strict\"; /*RXUB*/var r = /([^])/y; var s = this; print(uneval(s.match(r))); ");
/*fuzzSeed-71289653*/count=500; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy0((( + ((0x0ffffffff ** mathy4(( + x), ( + (( - (x | 0)) >>> 0)))) <= Math.fround(y))) != ( + Math.fround(( + Math.hypot(y, ( ! (Math.pow((1/0 | 0), (0x100000000 | 0)) | 0))))))), ( + Math.fround(( ! (Math.tan((Math.min(( ! y), (x | 0)) | 0)) >>> 0))))); }); ");
/*fuzzSeed-71289653*/count=501; tryItOut("\"use strict\"; t1.set(t1, 8);");
/*fuzzSeed-71289653*/count=502; tryItOut("o1.g1.__proto__ = g2.m0;");
/*fuzzSeed-71289653*/count=503; tryItOut("\"use strict\"; ;");
/*fuzzSeed-71289653*/count=504; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-1/0, 0x0ffffffff, -0x100000000, Math.PI, 0, -Number.MIN_VALUE, -0x080000000, -0x080000001, 1, -0x100000001, 0/0, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -0, 1.7976931348623157e308, -Number.MAX_VALUE, 1/0, -(2**53), 0x080000001, 0x100000000, 0x07fffffff, -0x07fffffff, 0.000000000000001, -(2**53+2), 42, Number.MAX_VALUE, 2**53-2, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 2**53+2]); ");
/*fuzzSeed-71289653*/count=505; tryItOut("\"use strict\"; print(window);function x(x, w, a, x) { print( /x/g ); } s0 += s2;");
/*fuzzSeed-71289653*/count=506; tryItOut("/*infloop*/while((void options('strict')))w, c = length, x, zkczxp, NaN,  , pmxloo;o2.v1 = evalcx(\"/* no regression tests found */\", this.g1);");
/*fuzzSeed-71289653*/count=507; tryItOut("var axinod = new ArrayBuffer(0); var axinod_0 = new Int16Array(axinod); print(axinod_0[0]); a0.reverse(g2);");
/*fuzzSeed-71289653*/count=508; tryItOut("\"use asm\"; \u0009o1 = new Object;let w = Math.hypot(4, -4);");
/*fuzzSeed-71289653*/count=509; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return (mathy0((( ! ( + (( + ( + Math.hypot(( + 0x080000001), ( + x)))) >= ( ~ (mathy0(y, (x | 0)) + ( + mathy3(( + Math.sign(x)), ( + y)))))))) | 0), ((Math.log1p(( + ( + Math.imul(( + ((x >> (Math.PI | 0)) | 0)), ( + Math.max(x, (Math.imul(0x07fffffff, y) == Math.fround(y)))))))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy5, [-(2**53), -0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, 0x07fffffff, 0.000000000000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, 0x100000000, -1/0, Number.MAX_VALUE, 1/0, Math.PI, -0x07fffffff, -0, Number.MIN_VALUE, 0x080000001, 42, -(2**53+2), 0x100000001, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, -(2**53-2), 1, -Number.MIN_VALUE, 2**53-2, 0, 1.7976931348623157e308, 0x080000000]); ");
/*fuzzSeed-71289653*/count=510; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-71289653*/count=511; tryItOut("\"use strict\"; L: print(x);");
/*fuzzSeed-71289653*/count=512; tryItOut("\"use asm\"; a1 = arguments.callee.arguments;");
/*fuzzSeed-71289653*/count=513; tryItOut("g2.g0.offThreadCompileScript(\"/*ADP-3*/Object.defineProperty(a0, ({valueOf: function() { p1.valueOf = /*wrap2*/(function(){ var egmrye = y *= x; var lpxdzp = ((new window()))(); return lpxdzp;})();a = /([^]|[^\\u0088-\\\\u69E8\\\\W])+?|\\\\b|(?:.)\\\\u0035/ym;return 7; }}), { configurable: false, enumerable: true, writable: (x % 25 == 6), value: o2.h2 });\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 5 != 1), noScriptRval: false, sourceIsLazy: (x % 9 == 6), catchTermination: false }));");
/*fuzzSeed-71289653*/count=514; tryItOut("\"use strict\"; Array.prototype.forEach.call(a1, (function() { try { v2 = Object.prototype.isPrototypeOf.call(v1, h2); } catch(e0) { } try { m2.delete(t1); } catch(e1) { } try { g1.v2 = false; } catch(e2) { } Array.prototype.pop.apply(a2, []); return i2; }), f1);");
/*fuzzSeed-71289653*/count=515; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - Math.fround(( ~ (Math.abs(mathy3(Math.fround(y), (x ? 1/0 : x))) | 0)))); }); testMathyFunction(mathy5, ['\\0', [], (function(){return 0;}), ({valueOf:function(){return 0;}}), (new String('')), (new Number(0)), ({valueOf:function(){return '0';}}), NaN, undefined, false, 0, /0/, 0.1, '', null, ({toString:function(){return '0';}}), 1, -0, [0], '0', '/0/', (new Boolean(true)), (new Boolean(false)), objectEmulatingUndefined(), true, (new Number(-0))]); ");
/*fuzzSeed-71289653*/count=516; tryItOut("\"use strict\"; g0.v1 = (s0 instanceof h1);");
/*fuzzSeed-71289653*/count=517; tryItOut("s1.__proto__ = p1;");
/*fuzzSeed-71289653*/count=518; tryItOut("print((window = Object.defineProperty(eval, [[]], ({}))));\n/*MXX3*/g0.DataView.prototype.byteLength = g2.DataView.prototype.byteLength;\n");
/*fuzzSeed-71289653*/count=519; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ( + Math.cos(( + Math.asinh(Math.log(( + (-0x080000001 , Math.imul((Math.imul((y | 0), (1/0 >>> 0)) >>> 0), Math.asin(Math.fround(x)))))))))); }); testMathyFunction(mathy0, [0x07fffffff, 1/0, 2**53, -Number.MIN_VALUE, -0x100000000, 0.000000000000001, -0x0ffffffff, 0/0, 0x100000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, 0, -0x080000001, 0x080000001, 0x100000001, -(2**53), -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, -0x080000000, 2**53+2, 42, 1, -Number.MAX_VALUE, -0, -(2**53-2), 1.7976931348623157e308, Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=520; tryItOut("\"use asm\"; v2 = (a0 instanceof f1);");
/*fuzzSeed-71289653*/count=521; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=522; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + ( + Math.atan2(y, (( + (y | 0)) | 0)))) , Math.fround(Math.fround(((Math.trunc((y | 0)) | 0) <= Math.asin(Math.fround(Math.pow(Math.fround((((-Number.MAX_SAFE_INTEGER >>> 0) == (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)), (0/0 >>> 0)))))))); }); testMathyFunction(mathy0, /*MARR*/[ /x/ , (void 0), (void 0), (void 0), (void 0), x, x,  /x/ , -Infinity, x, x, (void 0), (void 0), x, x,  /x/ ,  /x/ ,  /x/ , x,  /x/ , x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, (void 0), -Infinity, -Infinity, -Infinity, (void 0),  /x/ , (void 0), x,  /x/ , -Infinity, (void 0), (void 0), x, x, x,  /x/ , x,  /x/ , (void 0), (void 0), x,  /x/ ,  /x/ ,  /x/ , (void 0), x, (void 0), (void 0), (void 0), (void 0), -Infinity, (void 0), (void 0), (void 0), (void 0), (void 0), x, x, (void 0), (void 0), (void 0), x, -Infinity, -Infinity, (void 0), (void 0), (void 0), (void 0), x,  /x/ , x,  /x/ ,  /x/ , (void 0), (void 0), -Infinity,  /x/ , (void 0), x, (void 0), x,  /x/ , (void 0),  /x/ , (void 0), (void 0), (void 0),  /x/ ,  /x/ ]); ");
/*fuzzSeed-71289653*/count=523; tryItOut("\"use strict\"; o1 + '';");
/*fuzzSeed-71289653*/count=524; tryItOut("/*bLoop*/for (xovgje = 0; xovgje < 20; ++xovgje) { if (xovgje % 3 == 0) { v2 = (g2 instanceof v2); } else { /*MXX3*/g1.Symbol.unscopables = o2.g1.Symbol.unscopables; }  } ");
/*fuzzSeed-71289653*/count=525; tryItOut("\"use strict\"; Object.freeze(this.t0);");
/*fuzzSeed-71289653*/count=526; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.acosh(( + ( + mathy0(Math.pow(Math.fround(Math.exp(y)), 0x100000001), ( + ( - Math.hypot(-(2**53+2), ( ~ y))))))))); }); testMathyFunction(mathy4, [-0, -(2**53+2), Math.PI, 2**53, 0x080000001, 2**53-2, -(2**53), 0, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, 0/0, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x080000001, Number.MAX_VALUE, 0x07fffffff, -0x100000000, -Number.MIN_VALUE, -0x080000000, 0x080000000, -0x07fffffff, 1/0, -0x100000001, 42, 1, -1/0, -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=527; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return mathy2(( - mathy0(Math.imul((Math.min(0x0ffffffff, Math.fround((Math.fround((x != x)) ? Math.fround((y / x)) : Math.fround(mathy1(y, x))))) | 0), (y | 0)), ( + mathy3(Math.fround(x), y)))), ( - (Math.max((-Number.MAX_SAFE_INTEGER !== ( - Number.MIN_VALUE)), Number.MAX_SAFE_INTEGER) ? (y < ((Math.fround((x , Number.MAX_SAFE_INTEGER)) % (( ! y) | 0)) >>> 0)) : ( - ( ! Math.cos(Math.fround(Math.max(Math.fround(1/0), Math.fround(x))))))))); }); testMathyFunction(mathy5, [1/0, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, -Number.MAX_VALUE, 0.000000000000001, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, -(2**53), 42, 2**53+2, 0, -0, 1, 0x100000001, 2**53, -0x0ffffffff, 1.7976931348623157e308, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0x080000000, -1/0, 0x07fffffff, Number.MIN_VALUE, 0x080000001, -0x080000000, Number.MAX_VALUE, 2**53-2, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=528; tryItOut("print(x); var r0 = x * x; var r1 = 2 - 3; var r2 = 6 - r0; var r3 = 1 - 0; var r4 = 4 - r3; var r5 = r0 % 6; var r6 = x + 7; var r7 = r6 * r4; var r8 = r4 & r7; var r9 = r7 & r6; r6 = 0 ^ r1; var r10 = 9 & r6; var r11 = r6 | 8; var r12 = r5 + 7; var r13 = r9 ^ 6; r1 = r13 ^ 0; var r14 = r3 ^ r10; var r15 = r4 ^ r6; var r16 = r4 ^ r3; var r17 = r11 ^ r0; var r18 = 5 * r0; var r19 = 5 | r16; var r20 = r19 & r4; var r21 = r7 % 8; var r22 = 2 / 1; print(r13); var r23 = r5 * r8; var r24 = r1 & 2; var r25 = r2 & 3; var r26 = r6 % r2; r6 = r17 + r8; var r27 = 8 * x; var r28 = r24 / 0; var r29 = r10 * r16; var r30 = r14 ^ r21; r20 = r23 | r30; var r31 = r15 & 6; var r32 = 2 / 4; var r33 = r6 | 2; r22 = r6 / 7; var r34 = 9 + r20; r16 = r33 / 0; var r35 = r24 ^ r8; var r36 = r28 % r11; var r37 = 7 / 6; var r38 = 6 * r7; var r39 = r17 - r13; var r40 = r10 | 4; r24 = r16 * 6; ");
/*fuzzSeed-71289653*/count=529; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + Math.fround(Math.log(Math.fround((Math.max((y === y), ((Math.cbrt((x >>> 0)) >>> 0) >>> 0)) | 0))))) != (mathy2(( + (Math.cbrt(((Math.max((( ! (x % y)) >>> 0), (((x | 0) >> (x || 0)) >>> 0)) >>> 0) | 0)) | 0)), Math.atan(Math.trunc(x))) | 0)); }); testMathyFunction(mathy5, [-0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000001, 0x100000000, 42, 0x07fffffff, -1/0, 2**53, -(2**53-2), -(2**53+2), Number.MAX_VALUE, -0x100000000, -0x080000001, 0x080000000, 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000, 1/0, Math.PI, 0x100000001, 1, -0, 0, 0.000000000000001, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, 2**53+2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=530; tryItOut("\"use strict\"; /*bLoop*/for (var kqiitf = 0; kqiitf < 161; ++kqiitf) { if (kqiitf % 59 == 19) { g2.f0 = Proxy.createFunction(this.h1, f0, this.f0); } else { let c = arguments, x = yield [z1], window = (this.__defineGetter__(\"this.x\", function(y) { yield y; o0.s0 = this.g0.s1.charAt(10);; yield y; })), rmysaf, y = (--x), x = 3318769262, eval =  \"\" , uftjpx, ojbgdf, z;cxflwk(w+=window\n);/*hhh*/function cxflwk(x, [], x, c, d, window, y, x, x, x, \u3056, x, this.eval, x = x, z, w, w, x, x, x = -26, this = false, NaN =  /x/ , y =  /x/ , e, c, y = new RegExp(\"\\\\uF383{2,3}[\\\\d\\uc4e3]|\\\\b|\\\\2?\\\\1\", \"gym\"), x, x, b, x, y, \u3056, d = window, window, x, NaN, c, this, x, x, x, eval, e, y, window = /[m-\\ubC7d\\u00ed-\\u75B2-:\\cN].|\\b+?|(?=\\1?|\\1){0,}/im, a, x, x, x, w, d, z, c, get, ...c){selectforgc(this.g1.o1);} }  } ");
/*fuzzSeed-71289653*/count=531; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"\\\"use strict\\\"; Array.prototype.forEach.call(a0, (function() { try { for (var v of o2) { try { Array.prototype.pop.apply(a0, []); } catch(e0) { } i1 = a1[15]; } } catch(e0) { } try { a1.valueOf = (function(j) { if (j) { try { var o1.e2 = new Set(s2); } catch(e0) { } try { Array.prototype.sort.call(a1); } catch(e1) { } try { v0.valueOf =  /x/g ; } catch(e2) { } Array.prototype.pop.call(a0); } else { this.t2[5] =  '' ; } }); } catch(e1) { } v0 = (e2 instanceof p0); throw o0.i0; }), b2);\");const a =  '' ;");
/*fuzzSeed-71289653*/count=532; tryItOut("mathy0 = (function(x, y) { return ((Math.pow((Math.max(y, ( ~ (Math.imul((y >>> 0), (y >>> 0)) >>> 0))) >>> 0), (((((Math.log10(((( ! (x >>> 0)) >>> 0) | 0)) | 0) >>> 0) | (y >>> 0)) >>> 0) >>> 0)) >>> 0) !== Math.sign(Math.log10((Math.fround(Math.trunc(Math.max(y, ( + x)))) >>> (y | 0))))); }); testMathyFunction(mathy0, [(new Number(-0)), NaN, (new Number(0)), '\\0', [], '', /0/, objectEmulatingUndefined(), undefined, ({valueOf:function(){return 0;}}), true, 0, (new String('')), '/0/', (function(){return 0;}), ({valueOf:function(){return '0';}}), 0.1, 1, (new Boolean(true)), [0], -0, '0', false, null, (new Boolean(false)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-71289653*/count=533; tryItOut("\"use strict\"; for(let d of [new Array(2192696843)]) let(case 3: ) {  /x/g ;}for(let x in []);");
/*fuzzSeed-71289653*/count=534; tryItOut("v0 = a1.length;");
/*fuzzSeed-71289653*/count=535; tryItOut("/*MXX1*/g2.g0.o0 = this.g1.TypeError.prototype;");
/*fuzzSeed-71289653*/count=536; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.max(((((mathy4((x | 0), (-Number.MIN_SAFE_INTEGER | 0)) | 0) >>> 0) << ( + Math.clz32(Math.fround(Math.log((( + Math.log10(( + y))) | 0)))))) >>> 0), Math.log(((x ? ( + mathy0(( + x), ( + ((y && ( - x)) >>> 0)))) : (Math.min((Math.fround(mathy2(Math.fround(x), Math.fround((0x100000001 ? Math.fround(x) : y)))) | 0), (Math.acosh(y) | 0)) | 0)) >>> 0))); }); ");
/*fuzzSeed-71289653*/count=537; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return Math.tan(((( ! (Math.imul(({a1:1}), Math.fround(( ! Math.cbrt(Math.fround(y))))) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy4, [true, /0/, ({toString:function(){return '0';}}), null, '\\0', 1, '/0/', objectEmulatingUndefined(), undefined, false, NaN, (new Boolean(true)), [0], (new Number(-0)), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), (new String('')), -0, (new Boolean(false)), (function(){return 0;}), 0, '0', [], '', (new Number(0)), 0.1]); ");
/*fuzzSeed-71289653*/count=538; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - mathy0(((y | 0) != Math.imul(y, Math.fround(-Number.MAX_SAFE_INTEGER))), ((( + Math.atan2(Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround(x))), (Math.imul(y, -0x0ffffffff) / 0x07fffffff))) < ( + ( ~ ( + Math.fround(Math.max(Math.fround(y), Math.fround(Math.sign(1)))))))) >>> 0))); }); ");
/*fuzzSeed-71289653*/count=539; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=540; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=541; tryItOut("mathy5 = (function(x, y) { return ( + ( + ( + ( ! ( + (( + Math.fround(( - Math.fround(2**53-2)))) & ( + 0x100000001))))))); }); testMathyFunction(mathy5, [-0, 1, Number.MAX_VALUE, 0, 0x080000001, -(2**53+2), 0/0, 0.000000000000001, Math.PI, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 2**53, -0x080000001, -0x0ffffffff, -0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -0x100000001, 2**53-2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 0x07fffffff, 0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001, 42, 0x080000000, 1/0, -0x100000000]); ");
/*fuzzSeed-71289653*/count=542; tryItOut("mathy5 = (function(x, y) { return mathy3((Math.fround(mathy2(Math.fround((Math.fround(mathy0((( ~ ( + x)) | 0), mathy1((( - (Number.MIN_SAFE_INTEGER | 0)) | 0), ( + x)))) * Math.fround(x))), Math.atan2(Math.ceil(x), Math.cbrt((x >>> 0))))) | 0), Math.max(((( + Math.tan(( + Math.imul(x, -0x080000001)))) ? Math.max(Math.atan2(x, Math.log2(x)), x) : x) | 0), (Math.pow(x, Math.log((( - y) | 0))) | 0))); }); testMathyFunction(mathy5, [0x080000000, -0x0ffffffff, 1, -Number.MAX_VALUE, -(2**53+2), 2**53, 0/0, 0.000000000000001, 0x100000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, 0x080000001, 42, -(2**53), 1.7976931348623157e308, 2**53+2, 0, -0x100000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0, 0x100000001, -1/0, 0x07fffffff, -0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=543; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=544; tryItOut("\"use strict\"; e0.delete(b2);");
/*fuzzSeed-71289653*/count=545; tryItOut("s0 += s2;");
/*fuzzSeed-71289653*/count=546; tryItOut("i0.send(e1);");
/*fuzzSeed-71289653*/count=547; tryItOut("\"use strict\"; a0 = arguments;");
/*fuzzSeed-71289653*/count=548; tryItOut("a1 = /*MARR*/[new Number(1), function(){}, function(){}, new Number(1), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), -(2**53+2), -(2**53+2), -(2**53+2), (-1/0)];");
/*fuzzSeed-71289653*/count=549; tryItOut("\"use strict\"; testMathyFunction(mathy1, [false, [0], -0, /0/, ({toString:function(){return '0';}}), 0, (new String('')), '0', '', NaN, (new Boolean(false)), objectEmulatingUndefined(), (new Boolean(true)), [], true, (new Number(0)), '/0/', ({valueOf:function(){return 0;}}), (function(){return 0;}), 0.1, (new Number(-0)), ({valueOf:function(){return '0';}}), 1, undefined, '\\0', null]); ");
/*fuzzSeed-71289653*/count=550; tryItOut("mathy0 = (function(x, y) { return Math.tanh((Math.log((( ! (( + ( ~ ( + 1))) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [2**53+2, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0, -0x080000000, -0x100000000, -Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, 1, -1/0, -(2**53+2), -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, -(2**53-2), 1/0, -0x080000001, 0x080000000, 0x100000000, -0x0ffffffff, 42, Number.MIN_VALUE, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, 0/0]); ");
/*fuzzSeed-71289653*/count=551; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=552; tryItOut("\"use strict\"; \"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return ( + Math.cbrt(Math.fround(( ! ( + (Math.asinh(Math.imul(Math.acos(Math.fround(( - y))), x)) && ( + ( ! ( + Math.log10((Math.sin(y) >>> 0))))))))))); }); testMathyFunction(mathy4, [1/0, 0x100000001, -0x07fffffff, 2**53-2, 1.7976931348623157e308, -0x0ffffffff, -0x080000000, -0x100000001, 0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0, 42, -Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, -(2**53), 0x100000000, 0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, 1, -0x100000000, -1/0, 0/0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0, 2**53, Math.PI]); ");
/*fuzzSeed-71289653*/count=553; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-71289653*/count=554; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.cbrt(((Math.abs((( ! y) | 0)) != ((Math.min(y, -0x07fffffff) > Math.fround(Math.imul((0x07fffffff >>> 0), (Math.exp(((((y | 0) + (x | 0)) | 0) | 0)) >>> 0)))) % Math.fround(( ~ (Math.max(y, ( - y)) | x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, -0x100000000, 0x100000000, 0/0, 1, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53+2), 0x100000001, -(2**53), 2**53+2, -0x080000000, -0x100000001, 1/0, 0x07fffffff, -1/0, 0, 42, 0x0ffffffff, 0x080000001, Number.MIN_VALUE, 2**53, -0, -0x0ffffffff, Math.PI, 0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=555; tryItOut("p2 + '';");
/*fuzzSeed-71289653*/count=556; tryItOut("\"use strict\"; with()(void schedulegc(o2.g0));");
/*fuzzSeed-71289653*/count=557; tryItOut("t0[[(makeFinalizeObserver('tenured'))]];");
/*fuzzSeed-71289653*/count=558; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0((((( + Math.atan2(( + (y - ((Math.clz32(y) | 0) | x))), ( + x))) | 0) > (( + Math.pow(( + Math.max(Math.hypot(Math.max(y, 0x100000000), y), y)), ( + Math.hypot((0x080000001 > x), 1)))) | 0)) >>> 0), ( + Math.max(( + ( + Math.atanh(y))), ( + Math.atan2((x | 0), ( + mathy0(y, x))))))); }); testMathyFunction(mathy1, [-0x080000000, -0x07fffffff, 0x100000000, 0.000000000000001, 0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -0x100000001, -0x080000001, 42, 0x080000000, -(2**53-2), -0, 0x0ffffffff, 0/0, -0x100000000, Number.MAX_VALUE, -1/0, 1, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001, Math.PI, 1/0, 0x07fffffff, 0x100000001, 2**53+2, 2**53, -(2**53)]); ");
/*fuzzSeed-71289653*/count=559; tryItOut("\"use strict\"; /*bLoop*/for (var itzrhm = 0; ((uneval(\"\\u140D\"))) && ((makeFinalizeObserver('tenured'))) && itzrhm < 38; ++itzrhm) { if (itzrhm % 6 == 0) { /* no regression tests found */ } else { x; }  } ");
/*fuzzSeed-71289653*/count=560; tryItOut("testMathyFunction(mathy1, /*MARR*/[function(){}, function(){}, (0x50505050 >> 1), function(){}, (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), function(){}, (0x50505050 >> 1), (0x50505050 >> 1), function(){}, function(){}, function(){}, (0x50505050 >> 1), function(){}, function(){}, function(){}, (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), function(){}, (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), function(){}, function(){}, function(){}, function(){}, function(){}, (0x50505050 >> 1), function(){}, function(){}, function(){}, function(){}, function(){}, (0x50505050 >> 1), (0x50505050 >> 1), function(){}, (0x50505050 >> 1), (0x50505050 >> 1), function(){}, (0x50505050 >> 1), function(){}, (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), (0x50505050 >> 1), function(){}, (0x50505050 >> 1), (0x50505050 >> 1), function(){}, function(){}, (0x50505050 >> 1), function(){}, function(){}, function(){}, function(){}, function(){}, (0x50505050 >> 1), function(){}, function(){}, function(){}, (0x50505050 >> 1), function(){}, (0x50505050 >> 1), function(){}, function(){}, (0x50505050 >> 1)]); ");
/*fuzzSeed-71289653*/count=561; tryItOut("selectforgc(o2);");
/*fuzzSeed-71289653*/count=562; tryItOut("mathy0 = (function(x, y) { return ((Math.max(Math.max((( + (( + x) * Math.fround(( ! Math.fround(y))))) >>> 0), Math.fround(( + ( + ( + y))))), (((( + (y >>> 0)) | 0) < 42) > (Math.log2(-Number.MIN_SAFE_INTEGER) % Math.cbrt(Math.sin((y , -0x0ffffffff)))))) + (( ! ( + ( - Math.fround((( - ( + (y - x))) >>> 0))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-71289653*/count=563; tryItOut("a0[11] = yield window;");
/*fuzzSeed-71289653*/count=564; tryItOut("{ void 0; void relazifyFunctions('compartment'); }");
/*fuzzSeed-71289653*/count=565; tryItOut("var wxrwjm = new SharedArrayBuffer(0); var wxrwjm_0 = new Uint16Array(wxrwjm); wxrwjm_0[0] = 1e81; var wxrwjm_1 = new Uint8Array(wxrwjm); wxrwjm_1[0] = 17; var wxrwjm_2 = new Int16Array(wxrwjm); wxrwjm_2[0] = 16; var wxrwjm_3 = new Uint8ClampedArray(wxrwjm); var wxrwjm_4 = new Uint32Array(wxrwjm); wxrwjm_4[0] = -8; var wxrwjm_5 = new Uint16Array(wxrwjm); wxrwjm_5[0] = 25; var wxrwjm_6 = new Uint16Array(wxrwjm); var wxrwjm_5[0] = Object.defineProperty(w, \"-5\", ({writable: false, configurable: window, enumerable: false})), z, ldoywb, eval;o2.v1 = g1.runOffThreadScript();Array.prototype.reverse.call(a0);");
/*fuzzSeed-71289653*/count=566; tryItOut("mathy5 = (function(x, y) { return mathy1(Math.log2(mathy2(( - x), (-0 | 0))), ((x | 2**53-2) ? ( ~ Math.trunc((x != y))) : Math.fround(( ! Math.fround(Math.max(Math.fround(Math.fround(Math.hypot((x >>> 0), (( + Math.max(x, ( + (((Number.MIN_SAFE_INTEGER | 0) % (y | 0)) | 0)))) >>> 0)))), Math.fround(y))))))); }); testMathyFunction(mathy5, /*MARR*/[(1/0)]); ");
/*fuzzSeed-71289653*/count=567; tryItOut("for(let d in \nObject.defineProperty(\u3056, \"setHours\", ({value: new Root( /* Comment */window,  \"\" ), writable: true, configurable: false}))) yield x;");
/*fuzzSeed-71289653*/count=568; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=569; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return ( + ( ! ( + Math.log2((( + (( + (y ? -0x100000000 : ( + Math.hypot(( + Math.max(Math.fround(((x >>> 0) / Math.fround(y))), x)), ( + y))))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [-0x080000001, -0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 0/0, 1, -0x0ffffffff, 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000001, 42, -Number.MIN_VALUE, 0, 0x0ffffffff, -0, -0x080000000, Number.MAX_SAFE_INTEGER, -1/0, Math.PI, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), Number.MIN_VALUE, -(2**53), 0.000000000000001, Number.MAX_VALUE, 0x100000001, 0x080000001, 1.7976931348623157e308, 0x07fffffff, -(2**53-2), -0x100000000, 2**53]); ");
/*fuzzSeed-71289653*/count=570; tryItOut("\"use strict\"; i0.send(v2);");
/*fuzzSeed-71289653*/count=571; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.asinh(( + Math.abs(((((x | 0) < ( + Math.hypot(Math.fround(x), ( ! (y ** y))))) | 0) | 0)))); }); testMathyFunction(mathy5, [-0x0ffffffff, 0.000000000000001, 2**53-2, 42, -0, 2**53, 1.7976931348623157e308, -Number.MIN_VALUE, 0/0, 0, 2**53+2, Number.MIN_VALUE, 1/0, -0x100000000, 0x100000000, -0x100000001, -Number.MAX_VALUE, Math.PI, -0x080000000, 0x080000000, Number.MAX_VALUE, 0x0ffffffff, -(2**53), 0x080000001, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2), 0x07fffffff, -(2**53+2), -0x080000001, 1, -Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-71289653*/count=572; tryItOut("mathy5 = (function(x, y) { return ( + (Math.asinh(( + Math.imul((((Math.pow(x, y) >>> 0) ** x) >>> 0), ( ! (Math.log10((2**53 | 0)) | 0))))) + ( + ( + (Math.pow((((Math.max(y, Math.fround(( + ( + x)))) >>> 0) ** ( + y)) | 0), (Math.tan((Math.fround(Math.max(( + ( + ( + ( + x)))), Math.fround(y))) | 0)) | 0)) | 0))))); }); testMathyFunction(mathy5, [0x100000001, -(2**53), -(2**53-2), 42, 0x0ffffffff, 2**53+2, -0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -0x080000001, 0, 1/0, -(2**53+2), 0x080000000, 0x080000001, -Number.MIN_VALUE, 0x100000000, 2**53, Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -0, 0.000000000000001, 1, Number.MAX_VALUE, -1/0, -0x100000001, -Number.MAX_VALUE, 0x07fffffff, 2**53-2, -0x07fffffff, Math.PI]); ");
/*fuzzSeed-71289653*/count=573; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=574; tryItOut("\"use asm\"; for (var p in s1) { a1[14] = this.f2; }");
/*fuzzSeed-71289653*/count=575; tryItOut("\"use strict\"; \"use asm\"; v1 = new Number(4.2);\nt2[o2.v2];Array.prototype.forEach.call(o0.a2, Date.prototype.getMinutes.bind(e0));\n");
/*fuzzSeed-71289653*/count=576; tryItOut("\"use strict\"; /*RXUB*/var r = g0.r2; var s = s2; print(s.replace(r, 'x')); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=577; tryItOut("\"use strict\"; ;");
/*fuzzSeed-71289653*/count=578; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(?=(?:(?=[^\u00e5-\u00ef\\r-\u8348]|[^\\W\\cP].*+?)|(?!.)|[^][\\uB0Be\\x14-\u6e3b\u00d7][^]|$|(?:.))))/i; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=579; tryItOut("/*ODP-2*/Object.defineProperty(t1, \"toLocaleString\", { configurable: (x % 4 == 3), enumerable: (x % 5 != 2), get: (function() { for (var j=0;j<52;++j) { f0(j%5==0); } }), set: (function() { try { g2.a0.shift(); } catch(e0) { } try { a0.shift(); } catch(e1) { } /*RXUB*/var r = new RegExp(\"\\\\3\", \"ym\"); var s = \"a\"; print(r.exec(s));  return b2; }) });");
/*fuzzSeed-71289653*/count=580; tryItOut("a0.forEach((function() { try { print(m1); } catch(e0) { } /*MXX1*/o2 = g1.Array.of; return h2; }));");
/*fuzzSeed-71289653*/count=581; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ( - (( + mathy1(( ! (Math.fround(mathy1(y, Math.fround(y))) ? ((((mathy0(y, (-0x100000000 >>> 0)) | 0) ^ x) | 0) | 0) : mathy1(0, Math.fround(x)))), (((Math.hypot((x | 0), (x | 0)) | 0) + y) | 0))) | 0)); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 0x100000000, -0x0ffffffff, 42, 1/0, -1/0, -0, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, -(2**53+2), -Number.MAX_VALUE, 0.000000000000001, 1, 2**53-2, -0x100000000, 0x0ffffffff, -0x080000000, 0x080000000, 0x080000001, 0, Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, 1.7976931348623157e308, 2**53, -0x100000001, -(2**53), Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001]); ");
/*fuzzSeed-71289653*/count=582; tryItOut("mathy2 = (function(x, y) { return mathy0((Math.cos((( + x) | 0)) >>> 0), ((Math.max(Math.acosh(( ~ Math.fround((((2**53 | 0) ? (x | 0) : (x | 0)) | 0)))), Number.MAX_VALUE) < Math.round(( + Math.fround(Math.sin((( - x) | 0)))))) | 0)); }); testMathyFunction(mathy2, [-(2**53), 1, 0/0, 1/0, 0x0ffffffff, -0x0ffffffff, -1/0, -0x100000001, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, Math.PI, 0x080000000, 0x07fffffff, -(2**53-2), -Number.MAX_VALUE, 0x100000000, -(2**53+2), 0x100000001, 0, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, 42, 0x080000001, -0x07fffffff, 0.000000000000001, 2**53, -0, 2**53+2]); ");
/*fuzzSeed-71289653*/count=583; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-71289653*/count=584; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (d1);\n    }\n    i0 = ((((i0)-((+(-1.0/0.0)) < (NaN))+(0x2d7f5aab)) & (-(((((0xffffffff))) | (((0x30277a0a))+(0xfff6d79b))) > (abs((((0x0) % (0x714663e9))|0))|0)))));\n    d1 = (+(0x33c1cc03));\n    return ((((d1) <= (+(-1.0/0.0)))))|0;\n  }\n  return f; })(this, {ff: (new Function).bind}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 0.000000000000001, -(2**53+2), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, 1/0, -1/0, 2**53, 0, 0x100000000, 0x080000000, -0, -(2**53), Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, 0x100000001, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, 1.7976931348623157e308, 0x080000001, 42, -Number.MIN_VALUE, -0x100000001, Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=585; tryItOut("mathy5 = (function(x, y) { return Math.hypot(( + ( - (Math.asinh(( + ( ~ (Math.log10((y | 0)) | 0)))) >>> 0))), ( - (( - -Number.MIN_SAFE_INTEGER) | 0))); }); testMathyFunction(mathy5, [-(2**53), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -0x080000001, 2**53-2, 1/0, 2**53+2, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -0x0ffffffff, 0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x080000001, -(2**53+2), -0x07fffffff, -0x100000000, 1, -(2**53-2), 2**53, 0x0ffffffff, -1/0, 0/0, Math.PI, -Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, 0x100000000, Number.MIN_VALUE, 0]); ");
/*fuzzSeed-71289653*/count=586; tryItOut("for (var p in p1) { a1.reverse(b2); }");
/*fuzzSeed-71289653*/count=587; tryItOut("mathy2 = (function(x, y) { return Math.min((mathy1(mathy1((x >= (x !== -(2**53+2))), (Math.min((( ~ (-Number.MAX_VALUE | 0)) | 0), y) >>> 0)), (Math.fround(mathy1(( - (y | 0)), Math.fround((0.000000000000001 ? (( ! x) | 0) : Math.max(x, -Number.MAX_SAFE_INTEGER))))) * ((( + (mathy0((x >>> 0), -0x100000001) >>> 0)) / (x >>> 0)) >>> 0))) >>> 0), Math.hypot((((x < (y || ( + mathy1(( + (( - (y | 0)) | 0)), ( + Math.imul(x, x)))))) | 0) ? (mathy1((( + (x | 0)) | 0), (0x100000001 | 0)) | 0) : Math.sinh((( + y) && ( + (x >> (-0x07fffffff >>> 0)))))), Math.atan2(x, mathy1(((y - (x ? (-0x100000001 | 0) : (x | 0))) + ( - 1)), mathy0((2**53-2 >>> 0), y))))); }); testMathyFunction(mathy2, [2**53+2, 0x100000000, 42, 0, 0x100000001, -(2**53), 0x07fffffff, 1, -Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, Math.PI, -0x100000001, 0x080000001, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 0/0, 0.000000000000001, -1/0, 0x080000000, -0x080000000, 2**53-2, 1/0, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, 2**53, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2)]); ");
/*fuzzSeed-71289653*/count=588; tryItOut("v0 = evaluate(\"function f0(e0) \\\"use asm\\\";   var imul = stdlib.Math.imul;\\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    (Uint8ArrayView[((!(0x8015e119))*-0xf0cdd) >> 0]) = (0xa1ef6*((((-0x8000000)+((+(imul((0x2c2af79), (0x89439cd7))|0)) < (+((window--)))))) ? ((((0xfeb2dba2)-(0xfe2f18b6))>>>((0xffffffff))) == (0xe3be6d5e)) : ((-4194305.0) > (d1))));\\n    return (((0x8c3dfd0)-(((-0x67f05*(0x4c36e7e3))>>>(-(!(0xf8701b72)))))))|0;\\n  }\\n  return f;\", ({ global: o2.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: eval(\"21\"), sourceIsLazy: (Date.prototype.setUTCSeconds)(), catchTermination: true }));");
/*fuzzSeed-71289653*/count=589; tryItOut("\"use strict\"; h0 = {};");
/*fuzzSeed-71289653*/count=590; tryItOut("var ecepfc, x = c, x, obzure, x, nwxlms, uonqzi, x = NaN =  '' , x = 0, xrjvjr;var y = x;Math.hypot(6, 1);let udkelm, pghyvw, luxfte, x, e, window, a = [z1], NaN, qbqkln;const e = x;print(e >>> c);");
/*fuzzSeed-71289653*/count=591; tryItOut("udqiwy();/*hhh*/function udqiwy(){const g0.i0 = new Iterator(a0, true);}");
/*fuzzSeed-71289653*/count=592; tryItOut("this.a0.pop();");
/*fuzzSeed-71289653*/count=593; tryItOut("/*RXUB*/var r = /\\3\\3|(?!\\1)|\\b(\\d)\\1/y; var s = \"_a\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=594; tryItOut("mathy4 = (function(x, y) { return Math.hypot(( + Math.log2(Math.clz32(( + Math.atan((Math.sin((Number.MAX_SAFE_INTEGER | 0)) >>> 0)))))), (((Math.max(Math.fround(( + x)), Math.log(y)) | 0) != (Math.fround(( - (Math.log10(Math.imul((Math.ceil((y >>> 0)) >>> 0), Math.fround(Math.pow(Math.fround(y), Math.fround(x))))) >>> 0))) | 0)) | 0)); }); testMathyFunction(mathy4, /*MARR*/[ \"\" ,  \"\" , x,  \"\" , x,  \"\" , x,  \"\" , new Boolean(true), x, x, x, x, new Boolean(true),  \"\" , x, x,  \"\" ,  \"\" ,  \"\" , x, new Boolean(true), x, new Boolean(true),  \"\" ,  \"\" , x, x,  \"\" , x, new Boolean(true), x, new Boolean(true),  \"\" ,  \"\" ,  \"\" ,  \"\" , x, x, x, new Boolean(true), new Boolean(true), x, new Boolean(true),  \"\" ,  \"\" , x,  \"\" , x, new Boolean(true),  \"\" ,  \"\" , x, new Boolean(true),  \"\" , x, x,  \"\" , new Boolean(true), new Boolean(true), new Boolean(true), x,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , x,  \"\" , new Boolean(true), new Boolean(true),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new Boolean(true), new Boolean(true), new Boolean(true),  \"\" , x,  \"\" ,  \"\" ,  \"\" , x, new Boolean(true),  \"\" , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  \"\" , x,  \"\" , new Boolean(true), new Boolean(true),  \"\" , new Boolean(true), new Boolean(true),  \"\" ,  \"\" , x,  \"\" ,  \"\" , x, x,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , new Boolean(true), x,  \"\" ,  \"\" , new Boolean(true), new Boolean(true),  \"\" , new Boolean(true),  \"\" , x, new Boolean(true), x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x,  \"\" ,  \"\" ,  \"\" , x, x, x, x,  \"\" , x, x,  \"\" , new Boolean(true),  \"\" , x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  \"\" , x,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , x, new Boolean(true), new Boolean(true), new Boolean(true),  \"\" , new Boolean(true),  \"\" , new Boolean(true),  \"\" , x, x, new Boolean(true), x,  \"\" , x, new Boolean(true), new Boolean(true), x, new Boolean(true), new Boolean(true),  \"\" ]); ");
/*fuzzSeed-71289653*/count=595; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-71289653*/count=596; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.imul(Math.fround(((y === ((2**53-2 >>> 0) >>> (Math.cos(Math.round(x)) >>> 0))) | Math.fround(((Math.hypot((( + Math.min(( + x), Number.MIN_SAFE_INTEGER)) >>> 0), y) != { disableLazyParsing: false }) | 0)))), ( + (( + (Math.max((( + Math.clz32(( + Math.atan2(y, (x >> Math.asinh(y)))))) | 0), ((-0x100000001 || ((Math.max((x >>> 0), (0x100000001 >>> 0)) >>> 0) && x)) | 0)) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=597; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=598; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n;    i1 = ((((i1) ? (Infinity) : (-268435457.0))));\n    return +((+sqrt(((Float32ArrayView[((i1)+(i1)+(i1)) >> 2])))));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy5, ['0', (function(){return 0;}), objectEmulatingUndefined(), 0, (new Number(-0)), -0, ({valueOf:function(){return '0';}}), (new Boolean(true)), true, [0], '/0/', (new Boolean(false)), '\\0', 1, [], NaN, ({toString:function(){return '0';}}), null, ({valueOf:function(){return 0;}}), (new String('')), 0.1, (new Number(0)), undefined, false, /0/, '']); ");
/*fuzzSeed-71289653*/count=599; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -3.094850098213451e+26;\n    var i3 = 0;\n    var i4 = 0;\n    var i5 = 0;\n    var d6 = -144115188075855870.0;\n    switch (((((-2251799813685248.0) != (-9.671406556917033e+24))+(0x99a4473c)) >> (-0x28fb*(i5)))) {\n      case 1:\n        i4 = ((-1048577.0) != (-1.0078125));\n        break;\n    }\n    d0 = (+/*FFI*/ff(((0x200139db)), ((+(-1.0/0.0))), ((((0x9b766df2)-(-0x8000000)-(i3)) ^ ((/*FFI*/ff(((~~(-1099511627777.0))), ((((0xa870c90b)) << ((0x89ba1059)))), ((0x378afb22)), ((-7.737125245533627e+25)), ((8796093022209.0)), ((-549755813889.0)))|0)+((((0x177271e9)-(0x7eb9da3b)-(0xcce0e875))|0))))), ((NaN)), (((((~~(-2199023255553.0)))*-0x1c6c0) | (((3.022314549036573e+23) != (65.0))*0xfffff))), ((imul((i4), ((0x2102bfe) < (0x3cfb5a0c)))|0)), ((~~(+(-1.0/0.0)))), ((((0x98e6b1a4)) | ((0xfefec2d5)))), ((d6)), ((-3.094850098213451e+26)), ((288230376151711740.0)), ((288230376151711740.0))));\n    {\n      (Float64ArrayView[((i1)) >> 3]) = ((36893488147419103000.0));\n    }\n    d0 = (d0);\n    {\n      switch (((((0x9279ee9a) >= (0x0))) | ((-0x8000000)-(0xaaa335e)))) {\n        case 1:\n          i4 = ((0x695596b7));\n          break;\n        case 0:\n          i5 = (i1);\n          break;\n        case 0:\n          d0 = (+((+(~~(d0)))));\n          break;\n        case -2:\n          d2 = (-4.722366482869645e+21);\n          break;\n        case 0:\n          {\n            i5 = (0x2724ad2b);\n          }\n          break;\n        case 0:\n          (Float64ArrayView[((((((0xd4974e21) == (0xffffffff)))>>>((Float64ArrayView[1]))) != (0xd832b31a))) >> 3]) = ((Float64ArrayView[((0x0) / ((-(0xc63a7b8a))>>>((1.9342813113834067e+25)))) >> 3]));\n        case 1:\nthrow x;          break;\n        default:\n          d0 = (d2);\n      }\n    }\n    i1 = (((x)>>>(((d6) != (+atan2((((void version(170)))), ((-513.0))))))));\n    (Int32ArrayView[4096]) = (((((i3))|0))-(0x3db92c10));\n    (Float32ArrayView[0]) = (x);\n    d2 = (-281474976710657.0);\n    return ((((d) = (x ? (window ? ({a2:z2}) :  /x/ ) : /(?=(?:([\u445c-\u00f0M-\u00ba\\x01-\\x53]*?))|\\uf236|(?:^|\\s))+\\2+?/y === true))+(i4)))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [1, 1/0, 2**53, 0x07fffffff, -0x100000001, -0x07fffffff, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, 0x080000000, Number.MAX_VALUE, 0, 2**53+2, 0x100000001, -Number.MIN_SAFE_INTEGER, 0/0, -1/0, Number.MIN_VALUE, -(2**53-2), 2**53-2, 1.7976931348623157e308, -(2**53), -0x080000001, -Number.MAX_SAFE_INTEGER, -0, -0x080000000, -(2**53+2), 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-71289653*/count=600; tryItOut("neuter(b0, \"same-data\");");
/*fuzzSeed-71289653*/count=601; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min(( + ( ! ( + Math.atanh(Math.max(x, Math.min(( + 0/0), (( + ( + ( + y))) > y))))))), (( - (Math.fround((Math.fround(y) / x)) , (((Math.cosh((( + Math.fround(y)) >>> 0)) >>> 0) >= (y > (Math.imul((x | 0), (y | 0)) >>> 0))) | 0))) , Math.fround(Math.asinh(Math.fround(((2**53+2 + (( - x) | 0)) >>> 0)))))); }); testMathyFunction(mathy0, [0/0, 1, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, 2**53+2, -Number.MIN_VALUE, -0x0ffffffff, 0x080000000, -0x07fffffff, -(2**53+2), 1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, -(2**53-2), Number.MIN_VALUE, -0x100000001, 0x100000000, 2**53-2, -0, 0.000000000000001, 42, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, -0x080000001, -(2**53), 0, 2**53]); ");
/*fuzzSeed-71289653*/count=602; tryItOut("");
/*fuzzSeed-71289653*/count=603; tryItOut("g0.offThreadCompileScript(\"function f0(p1) \\\"use asm\\\";   var atan2 = stdlib.Math.atan2;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    {\\n      d1 = (d1);\\n    }\\n    {\\n      d1 = (+atan2((((((Float64ArrayView[1])) - ((d1))) + (d1))), ((Uint16ArrayView[4096]))));\\n    }\\n    return (((((((0x2804ecb0))) >> ((Uint16ArrayView[(c) >> 1]))))-(i0)-(0xe028483e)))|0;\\n  }\\n  return f;\");");
/*fuzzSeed-71289653*/count=604; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((( ~ (((( ~ (Math.atan((0x080000000 | 0)) >>> 0)) >>> 0) >>> 0) % Math.fround((Math.fround(Math.log2(Math.fround(x))) >>> y)))) | 0) - ( + (Math.cosh((Math.acos(Math.atan(x)) | 0)) | 0))); }); testMathyFunction(mathy4, [0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), -0x080000001, 1/0, 0x100000000, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -0x100000001, 42, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -0, -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, 2**53, 2**53+2, 2**53-2, -(2**53), 1, 0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, 0, 0/0, -1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=605; tryItOut("\"use strict\"; llkawl();/*hhh*/function llkawl(x, eval){print(12);}");
/*fuzzSeed-71289653*/count=606; tryItOut("t0 = t0.subarray(15, 2);");
/*fuzzSeed-71289653*/count=607; tryItOut("this.h1.getOwnPropertyNames = f0;");
/*fuzzSeed-71289653*/count=608; tryItOut("\"use strict\"; h1.getOwnPropertyDescriptor = (function(j) { if (j) { try { for (var p in f1) { try { t0.toSource = (function(j) { if (j) { try { for (var p in o1.t1) { try { v2 = r1.toString; } catch(e0) { } try { this.t2[ /x/ ] = o0.m2; } catch(e1) { } try { Array.prototype.unshift.call(a2, m2, p0); } catch(e2) { } a2.reverse(s0, f1, p0); } } catch(e0) { } try { v2 = this.g2.eval(\"function o2.f1(s0)  { /*MXX3*/g0.Number.isInteger = g2.Number.isInteger; } \"); } catch(e1) { } m0.set(x, e2); } else { try { Object.prototype.unwatch.call(t1, \"a\"); } catch(e0) { } try { print(uneval(m0)); } catch(e1) { } try { Array.prototype.forEach.apply(a1, [(function() { for (var j=0;j<0;++j) { f0(j%3==0); } })]); } catch(e2) { } e2.add(e1); } }); } catch(e0) { } try { Object.defineProperty(this, \"o0.v2\", { configurable: true, enumerable: new OSRExit((this.__defineSetter__(\"(yield d)\", Array.prototype.toLocaleString))),  get: function() {  return true; } }); } catch(e1) { } o2.valueOf = f1; } } catch(e0) { } v2 = evaluate(\"new RegExp(\\\"(?!(?!\\\\\\\\u00C7)?)\\\", \\\"yi\\\")\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 5 == 2), noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 46 == 12) })); } else { try { a1.toString = (function() { for (var j=0;j<124;++j) { g2.f1(j%3==0); } }); } catch(e0) { } try { o1.a1.reverse(); } catch(e1) { } g1.valueOf = (function() { for (var j=0;j<134;++j) { f0(j%4==0); } }); } });");
/*fuzzSeed-71289653*/count=609; tryItOut("Object.defineProperty(o2, \"v1\", { configurable: (x % 10 == 5), enumerable: window,  get: function() { s0 += s0; return t1.length; } });");
/*fuzzSeed-71289653*/count=610; tryItOut("/*MXX3*/g0.Error.prototype = g2.Error.prototype;( \"\" );");
/*fuzzSeed-71289653*/count=611; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.log10(( + Math.fround(Math.abs(y)))) << Math.min(( ! x), mathy2(y, Math.sin(Number.MAX_SAFE_INTEGER)))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 0x100000001, -0x100000000, 1.7976931348623157e308, 0/0, Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 0x080000001, 2**53+2, -(2**53), 0.000000000000001, -0, 42, 0, 1, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, -0x080000000, 0x0ffffffff, 2**53-2, 0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, 0x100000000, 0x07fffffff, 1/0, Number.MAX_VALUE, -1/0, Math.PI, -(2**53+2)]); ");
/*fuzzSeed-71289653*/count=612; tryItOut("mathy2 = (function(x, y) { return Math.imul(Math.atan2((Math.pow(( + (( - x) | 0)), ((Math.acosh((-1/0 | 0)) | 0) >>> 0)) >>> 0), ( + (( ! ((((( ~ Math.fround(x)) >>> 0) ? (( + Number.MAX_VALUE) >> (x >>> 0)) : Math.acos(y)) | 0) >>> 0)) >>> 0))), ( ! ( + (( + y) << ( + ( + (y >= (y ** (x | 0))))))))); }); testMathyFunction(mathy2, [0, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 2**53+2, -(2**53-2), -Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0x100000001, -0x07fffffff, 0x07fffffff, 0x080000000, 2**53, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000000, -0x0ffffffff, -0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, -0x080000000, -0x100000000, 0.000000000000001, 1/0, 2**53-2, 42, -(2**53), 1]); ");
/*fuzzSeed-71289653*/count=613; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-1/0, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, 0, -0x080000001, 2**53, 0x080000001, 0.000000000000001, 42, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -Number.MAX_VALUE, -(2**53), Math.PI, -0x080000000, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000, -0x100000000, -(2**53-2), 0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, -0x0ffffffff, Number.MIN_VALUE, 2**53-2, 1, 0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-71289653*/count=614; tryItOut("testMathyFunction(mathy5, [2**53, -(2**53+2), 2**53-2, -(2**53-2), -Number.MIN_VALUE, 0x100000001, -0x080000000, 0/0, 1.7976931348623157e308, 2**53+2, 0.000000000000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, 0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -0x100000001, -0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 0, 1, -Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, -Number.MAX_VALUE, -0x100000000, 42, Number.MIN_VALUE, -0x0ffffffff, -(2**53), -0x07fffffff, 0x100000000]); ");
/*fuzzSeed-71289653*/count=615; tryItOut("/* no regression tests found */\nif(false) ; else  if (null) {[,];([]); } else {s1 += s2; }\n");
/*fuzzSeed-71289653*/count=616; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.atan2(( + (( ! (( - ((( + Math.cos(y)) === x) >>> 0)) >>> 0)) >>> 0)), (Math.min((x >>> 0), ((y >>> 0) ** Math.fround(Math.cosh(0.000000000000001)))) >>> 0)) !== ( + ( ! (Math.max(Math.trunc(y), 1/0) | 0))))); }); testMathyFunction(mathy2, [0, -Number.MAX_VALUE, 42, -0x100000001, 1, Math.PI, -0x080000001, Number.MAX_VALUE, 0x0ffffffff, 0/0, 0x100000001, Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, -1/0, 1/0, -0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000001, -(2**53+2), 2**53+2, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, 0x080000000, 0.000000000000001, -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=617; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[x, function(){}, this, x, x, x, this, this, x, x, x, x, function(){}, function(){}, x, function(){}, function(){}, function(){}, function(){}, this, function(){}, x, function(){}, x, x, x, function(){}, function(){}, this, this, function(){}, this, x, function(){}, this, x, this, x, this, x, this, this, function(){}, function(){}, function(){}, function(){}, function(){}, x, function(){}, function(){}, this, this, x, function(){}, function(){}, this, this, this, function(){}, this, function(){}, function(){}, function(){}, this, this, this, this, function(){}, function(){}, this, function(){}, this, function(){}, this, this]) { g0.m0.has(v0); }");
/*fuzzSeed-71289653*/count=618; tryItOut("\"use asm\"; v2 = Object.prototype.isPrototypeOf.call(f2, v2);");
/*fuzzSeed-71289653*/count=619; tryItOut("\"use strict\"; const yjucrg, NaN = \u3056 = {}, \u3056 = (void version(170)), [(window), , ], z =  \"\" , snemav;/*vLoop*/for (var llfqmd = 0; llfqmd < 93; ++llfqmd) { const a = llfqmd; a0.forEach((function() { v0 = t2[\"italics\"]; return e2; }), s1); } ");
/*fuzzSeed-71289653*/count=620; tryItOut("\"use strict\"; /*RXUB*/var r = /((\\3\\B^?|\\b)|(?:\\B*?)++?){4,}/gym; var s = \"     \\n\\n\\n    \"; print(uneval(r.exec(s))); let c = x;");
/*fuzzSeed-71289653*/count=621; tryItOut("testMathyFunction(mathy5, [0x080000001, Number.MAX_VALUE, 2**53+2, -0x080000000, -(2**53), 0/0, -1/0, 0x100000001, 2**53, 0x080000000, -(2**53+2), 42, -0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -0x080000001, 0, -Number.MAX_VALUE, 0.000000000000001, -(2**53-2), 2**53-2, 1.7976931348623157e308, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, 1, 0x100000000, -0x07fffffff, -0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-71289653*/count=622; tryItOut("t2[7];");
/*fuzzSeed-71289653*/count=623; tryItOut("\"use strict\"; a2.valueOf = (function() { for (var j=0;j<4;++j) { f0(j%5==0); } });");
/*fuzzSeed-71289653*/count=624; tryItOut("f1(g1.s0);");
/*fuzzSeed-71289653*/count=625; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    /*FFI*/ff();\n    switch ((((Uint8ArrayView[((0xfe03ccc7)) >> 0])) >> ((!((0x5db669d4) < (0x2a7deacd)))))) {\n    }\n    {\n      i1 = (0xf99890a8);\n    }\n    d0 = (-7.555786372591432e+22);\n    {\n      {\n        i1 = (i1);\n      }\n    }\n    (Float64ArrayView[((i1)-(0xfced2200)) >> 3]) = ();\n;    return (((((0xcb667c43))|0) / ((11) ^ (((0xffffffff))))))|0;\n    d0 = (+/*FFI*/ff((((((((((-0x8000000))>>>((0xfb015861))) / (((0x36a476f1))>>>((0xf9d83975)))) | ((((0x786c5f20)) | ((0xfc5a42f1))) % (((0xfa23c641)) >> ((0xb10efe2c))))))) ^ ((i1)-(i1)+(!(i1))))), ((~~(+/*FFI*/ff(((-((+/*FFI*/ff(((\u3056 = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { throw 3; }, has:  /x/ , hasOwn: function() { return false; }, get: encodeURI, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: (let (e=eval) e), keys: function() { return []; }, }; })(null), e =>  { yield e } ))), ((abs((((0x9cac3cc6)) >> ((0x53696289))))|0)), ((34359738369.0)), ((((0x914651de)) ^ ((0x355a15c)))), ((-0.001953125)), ((4294967297.0)), ((-147573952589676410000.0)), ((-0.00390625)), ((1099511627777.0)), ((-524289.0)), ((-1.03125)), ((7.737125245533627e+25)), ((2.4178516392292583e+24)), ((257.0)), ((18446744073709552000.0)), ((-2305843009213694000.0)), ((-1.00390625)), ((0.25)), ((-32769.0)), ((-131073.0)), ((-1152921504606847000.0)), ((16384.0)), ((-32769.0))))))), ((-1.888946593147858e+22)), ((((/*FFI*/ff((((+(0.0/0.0)))), ((-65536.0)), ((-536870913.0)), ((2.3611832414348226e+21)), ((-7.555786372591432e+22)), ((-147573952589676410000.0)))|0)) << (((makeFinalizeObserver('nursery')))+(i1)))), ((-((Float32ArrayView[((0xfaac5020)) >> 2])))), ((~~(+atan2(((-4611686018427388000.0)), ((36028797018963970.0)))))), ((((0xcc13407e)) << ((0xfd2ef0db)))), ((-4398046511105.0)), ((-140737488355329.0)), ((4398046511105.0)), ((-4294967295.0)))))), ((abs((((!(i1))) | ((0xc818e95e))))|0)), (((((9223372036854776000.0) <= (-3.777893186295716e+22))-(0x71e6074d))|0))));\n    {\n      d0 = (Infinity);\n    }\n    i1 = (new ReferenceError(x));\n    switch ((imul((0xfce88429), ((0x277dee23) ? (0xff20f9c4) : (0xad2c0846)))|0)) {\n      case 1:\n        {\n          (Float32ArrayView[2]) = ((+(abs((((/*FFI*/ff()|0)+(/*FFI*/ff(((((0xfcb46f73)+(0xe432a6eb)-(0xfdc17c84)) << ((0xfa455aef)-(0xffffffff)))), ((((0x80eff15)) ^ ((0xfb3416ae)))), (((0xffffffff) ? (-1.5) : (-72057594037927940.0))), ((-33554433.0)), ((274877906943.0)), ((1125899906842623.0)), ((-3.777893186295716e+22)), ((17592186044417.0)))|0)-(/*FFI*/ff((((((0xae3ebc20))*0xb3954)|0)), ((+(0.0/0.0))), ((imul((0xfac5506b), (0xfd12ebcf))|0)))|0)) | ((0x91f2dad3))))|0)));\n        }\n        break;\n      case -3:\n        /*FFI*/ff((((0x9600c698) ? (((134217729.0)) % ((d0))) : (-((+((Float64ArrayView[((0xdee479c)) >> 3]))))))), ((((((0x328a127e)-(0xfc37460a))|0) % ((((x) = (4277))( /x/g ))|0)) >> ((((i1))|0) % (((0xff3262f0)) | ((0xffafc6a0)))))), ((imul((i1), (/*FFI*/ff(((((!(0x4b504194)))|0)), ((-17592186044417.0)), ((1.5474250491067253e+26)), ((-1.5474250491067253e+26)))|0))|0)));\n        break;\n      case -1:\n        return ((((0xfedd07aa) ? ((d0) == (590295810358705700000.0)) : (0xfe7133f1))+(i1)))|0;\n      case 1:\n        d0 = (+(( \"\" )));\n        break;\n    }\n    i1 = (0xfaca5555);\n    return (((0x30833d5b)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; return 2**53+2; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[true, true, true, eval, true, eval, true, eval, true, true, true, true, eval, true, true, true]); ");
/*fuzzSeed-71289653*/count=626; tryItOut("print(x);print((timeout(1800)));e = (4277);");
/*fuzzSeed-71289653*/count=627; tryItOut("m1.get(h0);");
/*fuzzSeed-71289653*/count=628; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.atan2(Math.fround(( ! Math.cos((x >>> x)))), (Math.imul(Math.fround((Math.log((( + x) | 0)) | 0)), Math.fround(((((x >>> 0) >>> Math.acosh((1 | 0))) >>> 0) === (Math.log10(Math.fround(x)) >>> 0)))) >>> 0)) | 0); }); ");
/*fuzzSeed-71289653*/count=629; tryItOut("\"use strict\"; (NaN|=new RegExp(\"(?:[^]+?[^\\\\W])\", \"yi\"));\nv0 = Object.prototype.isPrototypeOf.call(o2, g2);\n");
/*fuzzSeed-71289653*/count=630; tryItOut("\"use asm\"; testMathyFunction(mathy4, [0x07fffffff, 42, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53, 0, 2**53+2, -0x080000000, -0, -0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, Number.MAX_VALUE, -0x07fffffff, 1, -(2**53-2), 0x080000001, 0x080000000, 1/0, Math.PI, 0x100000001, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -(2**53), 0x100000000, 0.000000000000001, 2**53-2]); ");
/*fuzzSeed-71289653*/count=631; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.atan2((( + Math.fround((Math.fround(( + Math.fround(y))) <= Math.fround((x << Math.log1p(( + x))))))) | 0), Math.hypot(mathy0(((( + mathy0(x, x)) / ( ! -0x100000000)) | 0), Math.atan2((Math.tan((y >>> 0)) >>> 0), (x || Math.fround(0x100000001)))), (( + ((Math.min(( + (x & ( + ( + -Number.MIN_VALUE)))), 1/0) >>> 0) ? ( + x) : Math.cos((Math.abs((y >>> 0)) >>> 0)))) | 0))) | 0); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 2**53-2, 0x100000001, 0x100000000, -0x100000000, -0x0ffffffff, -(2**53+2), 0x080000000, Math.PI, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, 0x080000001, 2**53+2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -1/0, 0/0, 0, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), -0x080000000, 1/0, -(2**53-2), 0x07fffffff, Number.MAX_SAFE_INTEGER, -0, -0x100000001, -0x080000001]); ");
/*fuzzSeed-71289653*/count=632; tryItOut("\"use strict\"; /*infloop*/for(\nx >> -12; (4277); \"\u03a0\") {for (var p in f2) { g0.toSource = (function mcc_() { var wfhzcc = 0; return function() { ++wfhzcc; if (/*ICCD*/wfhzcc % 5 == 1) { dumpln('hit!'); g2.offThreadCompileScript(\"\\\"use strict\\\"; delete h1.fix;\"); } else { dumpln('miss!'); try { i1.next(); } catch(e0) { } try { for (var v of g0.p0) { try { o0.v1 = g1.runOffThreadScript(); } catch(e0) { } try { m2.has(o2); } catch(e1) { } try { a0.forEach(); } catch(e2) { } v1 = (g2 instanceof a0); } } catch(e1) { } try { s1 += 'x'; } catch(e2) { } o0 = Object.create(o1); } };})(); } }");
/*fuzzSeed-71289653*/count=633; tryItOut("mathy3 = (function(x, y) { return Math.fround((((Math.hypot((( + mathy2(( + ( ! x)), ( + (Math.asin(x) | 0)))) | 0), (Math.hypot(x, (x >>> 0)) | 0)) | 0) | 0) ? (((Math.cbrt(Math.hypot(0/0, (((x | 0) != (x >>> 0)) >>> 0))) | 0) << (Math.imul(Math.log(( ! x)), Math.min(x, (( ! -0x0ffffffff) >>> 0))) | 0)) | 0) : Math.fround((( ~ (Math.atan2((Math.log1p(Math.imul(-Number.MIN_SAFE_INTEGER, y)) | 0), (Math.acosh(y) >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy3, [1/0, 0x080000000, -(2**53+2), -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53), -1/0, 0, -0x0ffffffff, 0.000000000000001, -0x080000001, -0x07fffffff, 0/0, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, Number.MAX_VALUE, 0x080000001, -(2**53-2), -Number.MIN_VALUE, 1, 0x07fffffff, -0, 0x100000000, 2**53+2, Math.PI, 42, 0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-71289653*/count=634; tryItOut("\"use strict\"; s0 = '';");
/*fuzzSeed-71289653*/count=635; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (Math.pow(Math.fround(Math.atan2(Math.fround(Math.fround(Math.sqrt(Math.fround(Math.atanh((y >>> 0)))))), Math.fround(Math.fround((Math.fround(Math.min(x, (( + x) | 0))) > Math.fround(( + ((x | 0) + ((Math.fround(Math.atan(Math.fround(( + 1)))) * Math.sqrt(y)) | 0))))))))), (( - Math.pow(Math.fround(((Math.atan2(-0x0ffffffff, ( + Math.tan(( + (( + -0x07fffffff) !== x))))) >>> 0) ** ((Math.atan2(((Math.fround(((x >>> 0) != y)) ? ( + ( + y)) : 0x100000001) | 0), (Math.max(Math.fround(x), ((y ? y : 0/0) >>> 0)) >>> 0)) | 0) >>> 0))), Math.fround(y))) | 0)) | 0); }); testMathyFunction(mathy0, [-0x07fffffff, -0x100000000, -Number.MAX_VALUE, 0x100000001, 1/0, -0x080000000, -0x100000001, 2**53-2, 0.000000000000001, 0/0, 0x080000000, 1.7976931348623157e308, 0x100000000, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53+2, 42, 1, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), -0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, -1/0, 2**53, 0, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=636; tryItOut("\"\\u255F\";");
/*fuzzSeed-71289653*/count=637; tryItOut("this.v0 = a0.some((function(a0, a1, a2) { var r0 = a0 | a2; var r1 = 9 | a0; a0 = 7 + 7; r0 = 2 & r0; a2 = x - a0; var r2 = r0 & 5; var r3 = 6 ^ 3; r2 = a1 | a1; var r4 = r1 ^ r1; r3 = r1 / r4; var r5 = 9 * r1; var r6 = x / a1; var r7 = a0 & 5; var r8 = a0 / a0; var r9 = 0 | r7; var r10 = r7 ^ x; var r11 = r6 * x; var r12 = a0 ^ 7; var r13 = r11 - r4; var r14 = 7 ^ r8; var r15 = r6 - r14; r11 = r0 ^ 7; var r16 = r9 ^ r12; r11 = 3 * 9; var r17 = x | r11; var r18 = 7 + r5; print(r12); var r19 = 5 | a2; var r20 = 4 ^ r5; var r21 = 4 | 0; print(r16); var r22 = 6 - r9; var r23 = 9 % r6; var r24 = 0 | r12; var r25 = r5 ^ r22; var r26 = 9 % r17; print(r1); var r27 = 5 | a1; var r28 = r8 & r17; r1 = 9 * 9; var r29 = r8 - r17; var r30 = r10 + 1; var r31 = r6 | r4; var r32 = 5 % r0; var r33 = r0 & r27; var r34 = r2 ^ 5; var r35 = r30 - r3; var r36 = r21 * r22; var r37 = a0 ^ r33; r34 = r23 / r6; var r38 = r19 % r12; r14 = r27 - r16; var r39 = r20 / r12; r34 = r36 / 5; var r40 = r31 ^ r18; var r41 = r22 - 7; r25 = r8 / r9; var r42 = 0 % r27; r26 = r12 | r21; r9 = r28 / r18; r6 = 7 & r39; r29 = r14 & r24; var r43 = r42 * 6; var r44 = r12 | r10; var r45 = r5 / r7; var r46 = r32 & r23; print(r35); var r47 = r42 % 3; var r48 = r20 / 1; r28 = r17 - 8; var r49 = r8 * 7; r33 = r5 + 8; var r50 = r25 ^ r31; var r51 = r19 - r40; r32 = r7 % r46; var r52 = 0 & r6; var r53 = r24 & r26; r21 = 3 & r30; var r54 = 7 % 0; var r55 = 6 * 8; r20 = 4 - 1; var r56 = 0 - r12; var r57 = r50 | 8; var r58 = 1 & r36; r41 = 3 ^ r51; var r59 = r5 % 2; var r60 = r49 * r29; r9 = 9 | r43; print(r17); var r61 = 5 / 2; var r62 = r17 - r5; print(r51); var r63 = r6 / 8; var r64 = 1 * r52; return a0; }), g1);");
/*fuzzSeed-71289653*/count=638; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.expm1(Math.fround(Math.atan2((Math.round(( + ( ~ Math.fround(Math.asinh(2**53))))) >>> 0), Math.ceil(( + ( ! x))))))); }); testMathyFunction(mathy0, [0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 2**53+2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -0x100000000, -0x07fffffff, 0x0ffffffff, 2**53-2, -(2**53-2), 0, -1/0, -0, 0x080000000, Number.MIN_VALUE, 1/0, 0x100000000, 0x080000001, -(2**53), 0/0, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 42, -(2**53+2), -0x100000001, -0x080000000, 1.7976931348623157e308, -0x080000001, 1, 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=639; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ! (Math.log((( ! x) | 0)) ? Math.log1p(( ! (x | 0))) : ( ! (x , (x << x))))); }); testMathyFunction(mathy1, [-0x080000000, 0/0, 0x080000001, 0x100000001, 0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, -Number.MAX_SAFE_INTEGER, 1, 0x100000000, -0x0ffffffff, -(2**53-2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 2**53, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, 0, -1/0, -Number.MIN_VALUE, 1/0, -0x100000001, 1.7976931348623157e308, -0x100000000, 42, Number.MIN_VALUE, 2**53+2, -0, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=640; tryItOut("for (var v of this.b0) { try { Array.prototype.splice.call(g0.a1, NaN, 0, f1, e2); } catch(e0) { } try { m0 = new Map(t2); } catch(e1) { } try { a0 + s1; } catch(e2) { } o2.h0.get = (function() { Array.prototype.push.call(a0, this, v0, o1, f1); return p1; }); }");
/*fuzzSeed-71289653*/count=641; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((Math.atan2((((((x >>> 0) | y) >>> 0) ^ Math.max(x, (( + Math.cosh(x)) | 0))) >>> 0), (((x === ( + Math.clz32(((x | 0) ** y)))) | 0) >>> 0)) >>> 0) && ((Math.expm1((y >>> 0)) >>> 0) == (Math.hypot(Math.fround(Math.fround((-(2**53+2) ? Math.fround(Math.tanh(Math.fround(( ! y)))) : Math.fround((Math.cosh(2**53) >>> 0))))), Math.fround((x ? ( ! (( + (x | 0)) | 0)) : ( + (Math.clz32(( ! y)) , ( + Number.MIN_VALUE)))))) | 0))) >>> 0); }); testMathyFunction(mathy2, [0x100000001, -0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, Number.MIN_VALUE, -1/0, -(2**53+2), Number.MAX_VALUE, -0x100000001, -(2**53), -Number.MIN_VALUE, -(2**53-2), 0x080000001, 0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 2**53, Math.PI, -0, 0, 1, -0x0ffffffff, 0.000000000000001, 0x0ffffffff, 1/0, 0x100000000, -0x100000000]); ");
/*fuzzSeed-71289653*/count=642; tryItOut("mathy0 = var ljhdqz = new ArrayBuffer(0); var ljhdqz_0 = new Int8Array(ljhdqz); ljhdqz_0[0] = 24; ;v0 = evalcx(\"x = f0;\", g0);const g0.v2 = t0.length;; testMathyFunction(mathy0, [2**53-2, -1/0, Math.PI, 1/0, 0x100000001, Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, -(2**53), Number.MAX_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 2**53+2, -(2**53+2), 1.7976931348623157e308, -(2**53-2), 1, 42, -0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -0, 0x0ffffffff, 0, -Number.MIN_VALUE, 0x100000000, 0x07fffffff]); ");
/*fuzzSeed-71289653*/count=643; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy0((((Math.atan(Math.max((((x >>> 0) !== (x >>> 0)) >>> 0), ( + x))) ? Math.fround(y) : Math.ceil(( ! -(2**53-2)))) >>> 0) >>> (((((Math.sin(Number.MAX_VALUE) | 0) !== -0x07fffffff) | 0) >> (mathy2(( + (( + Math.atan2((y | 0), y)) >>> -1/0)), ( + (y ? Math.fround(( - Math.fround(x))) : ( + Math.expm1(0x100000001))))) | 0)) | 0)), ( + ((((Math.hypot(testMathyFunction(mathy1, [0, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, -0, 0.000000000000001, -(2**53+2), -(2**53), 0x07fffffff, 0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -1/0, -Number.MIN_VALUE, 1, -0x100000001, Number.MAX_VALUE, 0x080000001, 0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, 1/0, 1.7976931348623157e308, -0x07fffffff, 2**53+2, -0x100000000]); , ( + (Math.min((-Number.MIN_VALUE >>> 0), y) >>> 0))) >>> 0) === (Number.MIN_VALUE >>> 0)) >>> 0) ? ((Math.min((( + Math.imul(( + -Number.MIN_VALUE), ( + y))) | 0), (Math.max(Math.fround(-Number.MIN_VALUE), (42 >>> 0)) >>> 0)) | 0) >>> 0) : ( + Math.fround(( ~ Math.fround(mathy2(y, ( + x))))))))); }); testMathyFunction(mathy3, [[0], '', /0/, (new Number(0)), 0, 0.1, objectEmulatingUndefined(), NaN, undefined, null, [], (new Number(-0)), -0, '\\0', false, (new Boolean(false)), (function(){return 0;}), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '/0/', true, 1, (new String('')), (new Boolean(true)), '0', ({toString:function(){return '0';}})]); ");
/*fuzzSeed-71289653*/count=644; tryItOut("for(let x in ((Object.getOwnPropertySymbols)(new ((/*MARR*/[{}, -0x07fffffff, {}, -0x07fffffff,  /x/ , undefined, undefined, -0x07fffffff, undefined, -0x07fffffff, undefined, -0x07fffffff,  /x/ , undefined, undefined,  /x/ , undefined, {}, -0x07fffffff, {}, undefined, undefined,  /x/ , -0x07fffffff,  /x/ , {}, {}, {}, -0x07fffffff, {},  /x/ , {}, -0x07fffffff, {}, -0x07fffffff, {},  /x/ , undefined, {}, {},  /x/ , {}, {}].filter(function (NaN) { yield (p={}, (p.z =  /x/g )()) } , this.__defineGetter__(\"x\", mathy1))))()))){/* no regression tests found */ }");
/*fuzzSeed-71289653*/count=645; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.hypot((Math.atan2((Math.round((( + ( - ( + (Math.log2((y >>> 0)) >>> 0)))) | 0)) | 0), ( ! x)) | 0), ( ! (Math.min(0x07fffffff, ((Math.atan((( + ( ~ ( + (( - ( + y)) | 0)))) >>> 0)) >>> 0) || (( - x) | 0))) | 0))); }); testMathyFunction(mathy4, [0x07fffffff, 0x080000000, 0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, -Number.MIN_VALUE, -(2**53), -0x100000001, 0x080000001, Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 2**53+2, -(2**53-2), 2**53, -1/0, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000001, -Number.MAX_VALUE, 1, 42, -0x080000000, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53+2), -0x100000000, 0, -0x07fffffff, -0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=646; tryItOut("\"use strict\"; /*MXX2*/g0.Object.prototype.__proto__ = this.e2;");
/*fuzzSeed-71289653*/count=647; tryItOut("testMathyFunction(mathy1, [0, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, -(2**53+2), -0x100000000, 1/0, -(2**53), 0x100000000, 2**53-2, Number.MAX_VALUE, -0x100000001, 0x080000001, 2**53, -0x0ffffffff, 0.000000000000001, Math.PI, 0/0, -Number.MIN_VALUE, 0x07fffffff, -1/0, 2**53+2, 1, 42, -0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=648; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=649; tryItOut("mathy4 = (function(x, y) { return mathy2(( ~ Math.fround(( ~ -Number.MAX_VALUE))), (mathy0((Math.max(Math.atan(x), ( + mathy0(( + y), ( + (Math.sign(( + 0x100000001)) > mathy0((( ! y) | 0), Number.MIN_VALUE)))))) >>> 0), Math.fround(Math.fround(Math.atan2(Math.fround(x), (y === ( - -Number.MIN_VALUE)))))) >>> 0)); }); testMathyFunction(mathy4, [NaN, [], objectEmulatingUndefined(), 1, null, 0, -0, ({toString:function(){return '0';}}), (new String('')), ({valueOf:function(){return '0';}}), '\\0', 0.1, '0', [0], (new Boolean(true)), (new Number(0)), (new Boolean(false)), undefined, (new Number(-0)), false, (function(){return 0;}), '/0/', '', /0/, ({valueOf:function(){return 0;}}), true]); ");
/*fuzzSeed-71289653*/count=650; tryItOut("mathy4 = (function(x, y) { return (((Math.hypot((mathy3(x, ( + Math.fround(mathy2(y, Math.fround(y))))) | 0), Math.fround(Math.fround((Math.fround(( + Math.sqrt(( + Number.MAX_SAFE_INTEGER)))) !== Math.fround((( + (x >>> 0)) >>> 0)))))) | 0) && mathy0(Math.tan((Math.sign(( ~ y)) & ( - Math.fround(-Number.MAX_SAFE_INTEGER)))), ( + Math.pow(( ! (Math.imul(y, -0x100000001) >>> 0)), (Math.log1p(y) | 0))))) | 0); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 0x07fffffff, -1/0, -(2**53+2), 0x0ffffffff, 0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Math.PI, 42, 1, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, -0x0ffffffff, 2**53-2, -0x080000001, 2**53+2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, -0x100000001, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x07fffffff, 2**53, -0, 1/0, 0x080000000, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=651; tryItOut("o2.e2 = new Set(a1);");
/*fuzzSeed-71289653*/count=652; tryItOut("mathy1 = (function(x, y) { return ( ~ ( + ( + ((((Math.hypot(y, Math.round(y)) && x) | 0) !== (Math.min((y ? (x | 0) : (x ^ -Number.MIN_VALUE)), 0x080000000) | 0)) | 0)))); }); testMathyFunction(mathy1, [0x080000000, -1/0, 0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53), Math.PI, 1, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0x100000000, -0x0ffffffff, -(2**53-2), -0x080000001, 1/0, -0x100000001, 0.000000000000001, -0, 0x0ffffffff, 2**53, 42, -(2**53+2), 2**53-2, 0/0, -Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000000, 0x07fffffff, 0]); ");
/*fuzzSeed-71289653*/count=653; tryItOut("mathy3 = (function(x, y) { return (Math.cbrt((Math.min((Math.fround(Math.imul(Math.fround((Math.fround((Math.imul(Math.cosh(0x100000000), Math.fround(Math.fround(-0))) | 0)) !== ( - Math.fround(y)))), Math.fround(( ~ y)))) >>> 0), (( + ( ! ( + (((x >>> 0) % (Math.hypot(Math.fround(Math.imul(Math.fround(-Number.MIN_VALUE), Math.fround(x))), ( + (Math.abs(-0x100000000) | 0))) >>> 0)) >>> 0)))) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy3, [-0x100000000, -(2**53), 42, 0x07fffffff, 0x080000000, -0x0ffffffff, 2**53-2, -0, -0x100000001, 0x100000000, 0.000000000000001, 1/0, Math.PI, -0x07fffffff, 1, -Number.MAX_VALUE, 0x100000001, -(2**53+2), 2**53+2, -Number.MIN_VALUE, -0x080000001, Number.MIN_VALUE, -(2**53-2), 2**53, 1.7976931348623157e308, 0, -Number.MIN_SAFE_INTEGER, 0/0, -1/0, Number.MIN_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=654; tryItOut("s1 += 'x';");
/*fuzzSeed-71289653*/count=655; tryItOut("\"use strict\"; f1 = Proxy.create(h1, b1);");
/*fuzzSeed-71289653*/count=656; tryItOut("mathy2 = (function(x, y) { return ( ! Math.asinh((( ~ ( + mathy1(( + Math.pow(x, y)), ( + (( + Math.pow(y, y)) + ( + ((x >>> 0) ? y : x))))))) >>> 0))); }); testMathyFunction(mathy2, [0x07fffffff, 42, Math.PI, 2**53+2, -1/0, 1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, -(2**53+2), 2**53-2, 0x100000001, 0x080000001, 0/0, Number.MAX_VALUE, 0x0ffffffff, -(2**53), 0x100000000, Number.MIN_VALUE, -0x100000000, -0x080000001, 0.000000000000001, 1, 2**53, -(2**53-2), -Number.MAX_VALUE, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-71289653*/count=657; tryItOut("return;for(let b of [e = x for each (x in []) if (null)])  /x/g ;");
/*fuzzSeed-71289653*/count=658; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MAX_VALUE, 0x100000001, -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 42, 2**53-2, 2**53, -0x100000000, -0x080000000, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, -Number.MIN_VALUE, 2**53+2, 0, 0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 1, 1/0, -(2**53), -0x07fffffff, -0x0ffffffff, Math.PI, 0.000000000000001, 1.7976931348623157e308, -(2**53+2), 0x07fffffff, 0/0]); ");
/*fuzzSeed-71289653*/count=659; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + ((Math.fround((((mathy0(Math.fround(( ! Math.fround(( ! -(2**53))))), (x | 0)) | 0) >>> 0) ? ((0x080000000 , Math.trunc(-0x07fffffff)) >>> 0) : Math.fround(y))) / ( + Math.min((y >>> 0), ( + (Math.atan2((y >>> 0), (Math.log2(x) | 0)) | 0))))) | 0)) | 0); }); testMathyFunction(mathy4, [-1/0, -0x07fffffff, 2**53, -Number.MIN_VALUE, 0/0, 1, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, -(2**53-2), 42, -0x080000001, -0x100000000, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, Number.MAX_VALUE, 0.000000000000001, 1.7976931348623157e308, Number.MIN_VALUE, Math.PI, 1/0, -(2**53+2), 0x080000000, 2**53+2, 0x100000000, 2**53-2, 0x07fffffff]); ");
/*fuzzSeed-71289653*/count=660; tryItOut("v2 = this.r2.global;");
/*fuzzSeed-71289653*/count=661; tryItOut("selectforgc(o0);");
/*fuzzSeed-71289653*/count=662; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.imul(Math.fround(((( ~ ((( - (x | 0)) | 0) >>> 0)) >>> 0) > Math.atan2(( ! (( ! Math.fround(((( + y) & (y | 0)) | 0))) | 0)), x))), Math.fround(Math.max(( + Math.sinh((( ~ Math.max(y, ( + Math.pow(Math.fround(x), ( + x))))) | 0))), (Math.imul(( + 0x07fffffff), Math.pow((y | 0), ((((((-0x080000001 >>> 0) % (y >>> 0)) >>> 0) / y) | 0) >>> 0))) >>> 0))))); }); ");
/*fuzzSeed-71289653*/count=663; tryItOut("testMathyFunction(mathy5, [0x080000000, -(2**53+2), 0x07fffffff, 1.7976931348623157e308, 2**53+2, Number.MIN_SAFE_INTEGER, 1/0, 0, -0, -(2**53-2), -0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, Math.PI, -Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, -0x100000000, -0x100000001, 0x080000001, -0x080000000, 2**53, -0x07fffffff, 0/0, -(2**53), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, 0x0ffffffff, 1, 0.000000000000001, 42]); ");
/*fuzzSeed-71289653*/count=664; tryItOut("mathy0 = (function(x, y) { return ( + Math.pow(( + ((( + (Math.abs(-0x080000000) | 0)) | 0) << (( - ( + (Math.hypot(y, Math.fround((( + ( - ( + x))) >> Math.fround((Math.atan2(((( ~ (x >>> 0)) | 0) | 0), y) | 0))))) >>> 0))) >>> 0))), ( + (Math.sinh(((( + 2**53) !== ((( + ((Math.fround(Math.sinh(( + y))) >= x) >>> 0)) >>> 0) > ( + x))) | 0)) | 0)))); }); testMathyFunction(mathy0, [-0x100000001, 1/0, 0x080000001, 0x07fffffff, -0x07fffffff, -(2**53), -Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, 2**53-2, 0/0, 1, -0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, -(2**53-2), 0x080000000, 42, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, 2**53+2, -0x100000000, -0x080000000, -0x080000001, Math.PI, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, 2**53]); ");
/*fuzzSeed-71289653*/count=665; tryItOut("testMathyFunction(mathy4, [Number.MIN_VALUE, 0x0ffffffff, 1/0, Number.MAX_VALUE, 0.000000000000001, 0x080000000, 0, -0x100000001, -0x07fffffff, -1/0, -0x100000000, 1, 0x100000000, 2**53, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 2**53+2, -0, 0x080000001, 42, 0x07fffffff, Math.PI, -0x080000000, -Number.MAX_VALUE, -(2**53), 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53-2, -0x0ffffffff, -(2**53+2), -0x080000001]); ");
/*fuzzSeed-71289653*/count=666; tryItOut("testMathyFunction(mathy3, [2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0, 1/0, 0/0, -0x07fffffff, 0x080000001, 2**53, -(2**53+2), 0x100000001, Number.MAX_VALUE, 2**53-2, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, -0, -0x080000001, Math.PI, -(2**53), -(2**53-2), 42, -0x100000001, 0x100000000, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, 0x07fffffff]); ");
/*fuzzSeed-71289653*/count=667; tryItOut("print(x);return [,,];");
/*fuzzSeed-71289653*/count=668; tryItOut("v2 = evaluate(\";\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 5), noScriptRval: Math.pow(8, new RegExp(\"\\\\2\", \"gyi\")), sourceIsLazy: (x % 5 == 1), catchTermination: (c = \"\\u1532\") *= x &= y }));");
/*fuzzSeed-71289653*/count=669; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, Number.MAX_VALUE, 1, -0x080000000, 0.000000000000001, -(2**53), 2**53+2, 0x080000000, 2**53-2, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, 42, -(2**53+2), 1/0, 0/0, -0x100000000, 0x100000001, -0x100000001, 0, -0x080000001, 2**53]); ");
/*fuzzSeed-71289653*/count=670; tryItOut("mathy4 = (function(x, y) { return mathy1(( + ( + (( + Math.cos(y)) >= y))), ( + (( + ( + (((Math.asinh((mathy2(x, (Math.fround(mathy1(Number.MAX_SAFE_INTEGER, ( + x))) ^ x)) | 0)) | 0) >>> 0) >> ((mathy2(x, (( ! -Number.MIN_VALUE) >>> 0)) !== x) >>> 0)))) % (Math.fround(( + ((( + (-0x0ffffffff | 0)) | 0) >>> ( + Math.imul(( + y), ( + ( ! x))))))) % (Math.pow(( + ( + y)), (y >>> 0)) >>> 0))))); }); testMathyFunction(mathy4, [42, -1/0, Number.MIN_SAFE_INTEGER, 0, 1.7976931348623157e308, 0x100000000, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0/0, 2**53+2, -Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -(2**53-2), 0x080000001, -0x07fffffff, 0.000000000000001, -0x080000000, -(2**53), -Number.MAX_VALUE, -0, Math.PI, -0x100000000, Number.MIN_VALUE, -0x0ffffffff, 1, 0x0ffffffff, 0x100000001, -(2**53+2), 0x080000000, -0x080000001]); ");
/*fuzzSeed-71289653*/count=671; tryItOut("s2 = Array.prototype.join.apply(a0, [o2.m0, e1, m0]);\nv2 = o0.a2.length;\n");
/*fuzzSeed-71289653*/count=672; tryItOut("t0[x] = g0;\nthrow undefined;const e = ({});\n");
/*fuzzSeed-71289653*/count=673; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=674; tryItOut("/*ADP-1*/Object.defineProperty(a0, b%=15, ({configurable: true}));");
/*fuzzSeed-71289653*/count=675; tryItOut("mathy5 = (function(x, y) { return ( + Math.exp(Math.fround(( + (( + (Math.imul(mathy2(Math.pow(1, Math.fround(x)), (x >>> 0)), ( ! Math.fround(( ~ y)))) ? Math.hypot((Math.imul((( ~ Math.fround(x)) >>> 0), x) >>> 0), Math.fround(x)) : (Math.atan2(Math.atan(y), 0x080000001) + x))) ? ( + (Math.atanh(mathy4) >>> 0)) : Math.fround(Math.hypot(Math.fround((mathy2((Math.imul(Math.fround((Math.fround(x) < Math.fround(x))), x) | 0), (Math.fround(mathy2((Math.tanh(Math.min(y, (x >>> 0))) | 0), Math.fround(( + (Math.atan2(x, y) | 0))))) | 0)) | 0)), (Math.tanh(((x && x) | 0)) | 0)))))))); }); testMathyFunction(mathy5, ['\\0', [], objectEmulatingUndefined(), (new Number(-0)), false, ({toString:function(){return '0';}}), null, (function(){return 0;}), ({valueOf:function(){return '0';}}), '', true, ({valueOf:function(){return 0;}}), -0, [0], 1, '0', (new String('')), (new Number(0)), 0, (new Boolean(true)), /0/, undefined, 0.1, '/0/', (new Boolean(false)), NaN]); ");
/*fuzzSeed-71289653*/count=676; tryItOut("/*oLoop*/for (ibocud = 0; ibocud < 12; ++ibocud) { Object.prototype.valueOf } /*iii*/a1[({valueOf: function() { g1.a1 = a2;return 6; }})] = g0;/*hhh*/function iyerys([], y){a2.unshift(g0, b1, b2);}");
/*fuzzSeed-71289653*/count=677; tryItOut("\"use strict\"; if((x % 4 == 2)) print( /x/g ); else  if (((function fibonacci(jjzpmb) { v2 = Object.prototype.isPrototypeOf.call(a2, e1);; if (jjzpmb <= 1) { print(x);; return 1; } ; return fibonacci(jjzpmb - 1) + fibonacci(jjzpmb - 2);  })(2))) throw window;");
/*fuzzSeed-71289653*/count=678; tryItOut("print(x.watch(/*MARR*/[(-1/0), new String(''), (-1/0), 1e+81, [[]], [[]], (-1/0), [[]], [[]], [[]], (-1/0), (-1/0), [[]], (-1/0), (-1/0), 1e+81, (-1/0), [[]], (-1/0), new String(''), [[]], new String('')].map(function(y) { return true }, true), function  [] (w)\"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (-((d0)));\n    d0 = (d0);\n    d1 = (d0);\n    d0 = (NaN);\n    d1 = (+abs(((Float32ArrayView[4096]))));\n    d0 = (Infinity);\n    {\n      d0 = (65.0);\n    }\n    d1 = (d0);\n    d1 = (d1);\n    d1 = ((d0) + (+((((((0x449c92fc))) ^ ((eval(\"\\\"use strict\\\"; mathy4 = (function(x, y) { return (mathy0(( + Math.sinh(mathy1((2**53 , y), y))), mathy0(( + Math.trunc(( + x))), ( + ( - ( + (Math.atan2(y, Math.fround(0x0ffffffff)) > Math.fround((Math.fround((Math.fround((y + (-0x0ffffffff >>> 0))) - Math.fround(-Number.MIN_SAFE_INTEGER))) == y)))))))) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), \\\"\\\\u75F6\\\", \\\"\\\\u75F6\\\",  /x/g , objectEmulatingUndefined(), \\\"\\\\u75F6\\\", objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), x, \\\"\\\\u75F6\\\", objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , \\\"\\\\u75F6\\\", objectEmulatingUndefined(), x, x, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), x, objectEmulatingUndefined(),  /x/g , x,  /x/g ,  /x/g , \\\"\\\\u75F6\\\", \\\"\\\\u75F6\\\", objectEmulatingUndefined(),  /x/g , x,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), x, x,  /x/g , x, x, x,  /x/g , x, objectEmulatingUndefined(),  /x/g ,  /x/g , x,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , \\\"\\\\u75F6\\\"]); \") = (uneval({} =  '' ))))) % (((0xfbcd99b3)-(0x2e99a3d0)-(0x541d6aa7)) >> ((0xfc9df5cd)-(0xe1a69588))))>>>((abs((((0xfcfe2b3f)) | ((0x3b5b05fa))))|0) / ((-0xfffff*(0x41f5148c))|0)))));\n    {\n      d0 = (d0);\n    }\n    d1 = (+((+(((1)+((imul((!(1)), ((~~(-1.5)) == (((0xc9f6e816)) >> ((0x5bf53268)))))|0)))|0))));\n    return +(((((+(1.0/0.0)) + (d0))) / ((d0))));\n    return +((d1));\n  }\n  return f;));");
/*fuzzSeed-71289653*/count=679; tryItOut("o2.p1 = x;");
/*fuzzSeed-71289653*/count=680; tryItOut("\"use strict\"; /*vLoop*/for (var fqmzhv = 0; fqmzhv < 3; ++fqmzhv) { d = fqmzhv; t1 = new Uint8ClampedArray(t1); } ");
/*fuzzSeed-71289653*/count=681; tryItOut("mathy1 = (function(x, y) { return Math.exp((( ~ Math.max(Math.atan2((Math.fround(( + (Math.tan(y) >>> 0))) >>> 0), (x >>> 0)), mathy0(Math.min(Math.max(-Number.MIN_SAFE_INTEGER, (Math.cbrt((y >>> 0)) >>> 0)), ( - x)), ((Math.fround(Math.log2(( + x))) ^ x) >>> 0)))) | 0)); }); testMathyFunction(mathy1, [false, -0, '', ({toString:function(){return '0';}}), (new Boolean(true)), /0/, undefined, ({valueOf:function(){return '0';}}), 0.1, (new String('')), null, (new Number(0)), NaN, objectEmulatingUndefined(), '\\0', 0, [0], (new Number(-0)), '/0/', (function(){return 0;}), '0', [], true, ({valueOf:function(){return 0;}}), 1, (new Boolean(false))]); ");
/*fuzzSeed-71289653*/count=682; tryItOut("v2 = Object.prototype.isPrototypeOf.call(s0, g2);");
/*fuzzSeed-71289653*/count=683; tryItOut("/*tLoop*/for (let y of /*MARR*/[ 'A' ,  'A' , (1/0), eval,  '' ,  'A' ,  '' ,  'A' , eval,  'A' , (1/0),  'A' , (1/0),  '' , (1/0),  'A' ,  '' , eval,  '' , eval,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , eval,  'A' ,  'A' ,  'A' , eval, eval, eval]) { return; }");
/*fuzzSeed-71289653*/count=684; tryItOut("o2.toString = (function() { for (var j=0;j<1;++j) { f1(j%4==0); } });Array.prototype.reverse.apply(o1.a1, []);");
/*fuzzSeed-71289653*/count=685; tryItOut("{ void 0; void schedulegc(6); }");
/*fuzzSeed-71289653*/count=686; tryItOut("\"use strict\"; a0.sort((function() { this.e1.has(x); return m1; }), e0, g1, i2);");
/*fuzzSeed-71289653*/count=687; tryItOut("\"use strict\"; function shapeyConstructor(epoysz){\"use strict\"; this[\"getInt8\"] = [1,,];if (epoysz) delete this[\"x\"];for (var ytqkduiiv in this) { }Object.defineProperty(this, \"x\", ({get: (void options('strict_mode')), set: epoysz, configurable: (epoysz % 41 != 26)}));delete this[\"lastIndexOf\"];delete this[\"x\"];for (var ytqhmucir in this) { }if (epoysz) delete this[1];this[\"2\"] = let (b =  \"\" , e, epoysz, x, \u3056, zwyysu, eojosn, d, x) ({epoysz: this});return this; }/*tLoopC*/for (let a of new Array(-23)) { try{let ldjwxb = shapeyConstructor(a); print('EETT'); return;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-71289653*/count=688; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[(0/0), (0/0), (0/0), [1], [1], [1], (0/0), (0/0), (0/0), (0/0), [1], (0/0), (0/0), (0/0), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], (0/0), [1], (0/0), [1], [1], (0/0), (0/0), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], (0/0), (0/0), [1], (0/0), (0/0), (0/0), (0/0), [1], (0/0), (0/0), (0/0), [1], (0/0), [1], (0/0), [1], [1], [1], [1], (0/0), [1], (0/0), (0/0), [1], [1], (0/0), (0/0), (0/0), [1], (0/0), [1], (0/0), [1], (0/0), (0/0), (0/0), [1], [1], [1], (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), [1], [1], (0/0), [1], [1], [1], (0/0), [1], (0/0), [1]]) { for (var p in a0) { try { e1.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ceil = stdlib.Math.ceil;\n  var atan = stdlib.Math.atan;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      switch ((((0xfaea1807)+((0x4de125c5) == (0x5d5f2cb0))) >> ((0x8ccbcb1c)))) {\n        case -2:\n          d0 = (((d1)) % ((d1)));\n          break;\n        case -1:\n          d0 = (+(-1.0/0.0));\n        case -3:\n          d0 = ((0xffffffff));\n          break;\n        case -3:\nprint((eval * eval));          break;\n        case -3:\n          d1 = (+/*FFI*/ff(((+pow(((d0)), ((16777217.0))))), ((d1)), (((((+(0.0/0.0)) == (+(-1.0/0.0)))) << ((((0xf87d6a29)+(-0x8000000)) ^ ((0xfb2e30b9))) / (((0xb55ac986)+(0xfed7be8c)) << ((-0x8000000)))))), ((~~(+(1.0/0.0)))), ((((((0xffffffff)) ^ ((0x39f85f1f))) % (((0x957d351b)) & ((0x4068f334)))) << (false))), ((d0)), ((abs((((0xfdd99159)) ^ ((0x31622f87))))|0)), ((((0x4d33e55)) << ((0xffffffff)))), ((-((1.9342813113834067e+25))))));\n          break;\n        default:\n          d0 = (+ceil(((x))));\n      }\n    }\n    d1 = (((+atan(((+atan2(((((+/*FFI*/ff(((((0x86af4623)) >> ((0x61d762e8)))), ((d1)), ((-4194303.0)), ((-2.0))))) * ((+atan2(((x)), ((144115188075855870.0))))))), ((+((-0x65e6e*((Int16ArrayView[2]))) >> ((0xfe731a6d)-(0xde7df80))))))))))) / ((+atan2(((d0)), ((+/*FFI*/ff(((((-((d1)))) * ((d1)))), ((d0)))))))));\n    return ((0x132d0*((d0) >= (((+(((0xf9a5c341))>>>((0xfc853dcc)+(0xb3065632))))) % ((((Float64ArrayView[((0xc4d825aa)-(0x176570d8)) >> 3]))))))))|0;\n  }\n  return f; })(this, {ff:  '' }, new SharedArrayBuffer(4096)); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(o2.b1, i1); } catch(e1) { } try { this.o0.v1 = g1.eval(\"\\\"\\\\u8CB9\\\"\"); } catch(e2) { } this.m0.valueOf = f1; } }");
/*fuzzSeed-71289653*/count=689; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=690; tryItOut("\"use strict\"; print(uneval(p0));");
/*fuzzSeed-71289653*/count=691; tryItOut("h2 + a0;");
/*fuzzSeed-71289653*/count=692; tryItOut("\"use strict\"; print(uneval(a0));");
/*fuzzSeed-71289653*/count=693; tryItOut("var y;/*RXUB*/var r = /(?![\u2802-\u62a5\\W\u008c-\\u00Be]{1073741823,}|p+)/gym; var s = \"__________\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=694; tryItOut("\"use strict\"; s0.valueOf = (function(j) { if (j) { try { e0.has(a0); } catch(e0) { } try { e0.has(/*UUV2*/(x.setUint8 = x.freeze)\u0009); } catch(e1) { } h1.has = o1.o1.o0.f0; } else { try { g1.m1.delete(b0); } catch(e0) { } try { v0 = this.t1.length; } catch(e1) { } try { g0.__proto__ = p1; } catch(e2) { } m1 = m2.get(e1); } });");
/*fuzzSeed-71289653*/count=695; tryItOut("mathy0 = (function(x, y) { return Math.min(Math.fround(( ! Math.fround((Math.fround(Math.pow(Math.fround(x), ( + Math.fround(( + -0x080000000))))) <= ((Number.MIN_SAFE_INTEGER === y) | 0))))), ( + (( + ( + ( + ( + (( + Math.tanh(-(2**53))) / y))))) ? ( + ( + Math.ceil(Math.acosh(x)))) : ((Math.fround(-(2**53+2)) > Math.fround(Math.max(x, (Math.exp(( + (Math.expm1((y >>> 0)) >>> 0))) >>> 0)))) >>> 0)))); }); testMathyFunction(mathy0, [0x080000000, Math.PI, Number.MIN_VALUE, 2**53, 0, -0x100000001, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, 0x07fffffff, 2**53-2, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, 0/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, 1, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000001, 2**53+2, 0x100000000, -(2**53), 1/0, 0x0ffffffff, -0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=696; tryItOut("\"use strict\"; window = yield 20 ? new RegExp(\"(?:(?=.*.))\", \"gm\") : x, x = \"\\uD058\";f2 = Proxy.createFunction(h0, f0, f2);");
/*fuzzSeed-71289653*/count=697; tryItOut("for (var v of o1) { try { v2 = (this.f0 instanceof e1); } catch(e0) { } try { selectforgc(g2.o0); } catch(e1) { } t1 = new Int16Array(a1); }");
/*fuzzSeed-71289653*/count=698; tryItOut("h1.delete = (function mcc_() { var aqsqdi = 0; return function() { ++aqsqdi; if (false) { dumpln('hit!'); g1.v2 = g0.runOffThreadScript(); } else { dumpln('miss!'); try { s0 += o1.s1; } catch(e0) { } g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: new OSRExit(arguments, timeout(1800) ? x : 25), noScriptRval: x, sourceIsLazy: ((let (e=eval) e)).call(new /[\\u008e\\cQ-\\\u43c2\\t-\ue45b\\\u0001]{3,3}(?=(?=\\3))*?/yim(), allocationMarker()) != \"\\uA74E\", catchTermination: false })); } };})();");
/*fuzzSeed-71289653*/count=699; tryItOut("selectforgc(o0.o0);");
/*fuzzSeed-71289653*/count=700; tryItOut("print(p0);");
/*fuzzSeed-71289653*/count=701; tryItOut("Array.prototype.splice.call(o1.a2, -1, v1);");
/*fuzzSeed-71289653*/count=702; tryItOut("g1.v2.__proto__ = this.p2;");
/*fuzzSeed-71289653*/count=703; tryItOut("h0.delete = Uint8ClampedArray;");
/*fuzzSeed-71289653*/count=704; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000000, Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, -(2**53-2), 0/0, -0, 0x07fffffff, 0x080000001, 0x080000000, -0x0ffffffff, 1, -(2**53+2), -0x07fffffff, -0x100000001, 2**53, -Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, 1/0, 2**53-2, -0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, 0.000000000000001, -1/0, -Number.MAX_SAFE_INTEGER, 0, -(2**53), 0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-71289653*/count=705; tryItOut("\"use strict\"; with({y: (b =  /x/g )})a1.shift(b0, m1);");
/*fuzzSeed-71289653*/count=706; tryItOut("\"use asm\"; (/*MARR*/[ /x/ , new Boolean(true),  \"use strict\" ,  '\\0' , 0x0ffffffff,  '\\0' ,  /x/ ,  \"use strict\" ,  /x/ , 0x0ffffffff, new Boolean(true), 0x0ffffffff,  /x/ , new Boolean(true)].sort(/*wrap3*/(function(){ \"use strict\"; var zjmdwz = (void options('strict')); ((4277))(); }), x));");
/*fuzzSeed-71289653*/count=707; tryItOut("Array.prototype.forEach.call(a2, (new Function).apply, (c) = [, , ] = [{b: c, y: {this.d: [y], \u3056: {b}, \u3056}}, , a, , ]);");
/*fuzzSeed-71289653*/count=708; tryItOut("\"use strict\"; v1 = this.g1.eval(\"function f2(p1)  { \\u0009return (intern(1)) } \");");
/*fuzzSeed-71289653*/count=709; tryItOut("\"use strict\"; /*MXX1*/this.o2 = g0.Uint8ClampedArray.prototype.BYTES_PER_ELEMENT;");
/*fuzzSeed-71289653*/count=710; tryItOut("\"use strict\"; /*RXUB*/var r = /\\3*?/gyi; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=711; tryItOut("\"use strict\"; print(v1);/*hhh*/function eogmml(){{}}/*iii*/v1 = t0.length;");
/*fuzzSeed-71289653*/count=712; tryItOut("f2.__proto__ = o2.e1;");
/*fuzzSeed-71289653*/count=713; tryItOut("v1 = (h2 instanceof h2);");
/*fuzzSeed-71289653*/count=714; tryItOut("t1.__iterator__ = (function mcc_() { var hhwwsu = 0; return function() { ++hhwwsu; this.o1.f2(/*ICCD*/hhwwsu % 8 == 1);};})();");
/*fuzzSeed-71289653*/count=715; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + (Math.imul(((Math.hypot((-(2**53+2) | 0), ((Math.hypot((x >>> 0), (x >>> 0)) >>> 0) | 0)) | 0) != ( ~ x)), Math.pow((Math.atan2(y, ( + Math.pow((x >>> 0), Math.clz32(Math.max(0x07fffffff, y))))) | 0), -(2**53+2))) ^ ( + (Math.max(Math.fround(Math.min(Math.fround((Math.min((mathy2((x - ( - ( + y))), x) | 0), (x | 0)) | 0)), ( + ( - x)))), ((Math.min((Math.fround((((( + Math.cosh(( + x))) >>> 0) > (x >>> 0)) >>> 0)) === x), y) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -Number.MAX_VALUE, 0x100000000, -0x0ffffffff, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 2**53, 0x0ffffffff, -0x080000000, 2**53+2, 1, -1/0, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), 42, 0.000000000000001, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, -(2**53-2), -0x100000000, -0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 0x080000001, 1/0, 0, 0x100000001, -0x080000001]); ");
/*fuzzSeed-71289653*/count=716; tryItOut("null;print(x);");
/*fuzzSeed-71289653*/count=717; tryItOut("g0.s0 = new String;");
/*fuzzSeed-71289653*/count=718; tryItOut("\"use strict\"; v0 = g1.eval(\"/* no regression tests found */\");function c() { print(x); } this.v1 = Array.prototype.every.call(a1, (function() { for (var j=0;j<72;++j) { g0.f1(j%5==0); } }), i1);");
/*fuzzSeed-71289653*/count=719; tryItOut("if(true) {; } else  if ((4277)) {Object.preventExtensions(v1);/*infloop*/while((arguments[\"c\"]--)){for(let x in []); }\u0009 } else {this.a0.unshift((void options('strict_mode')), b0, this.a0, \"\\u48F5\"); }");
/*fuzzSeed-71289653*/count=720; tryItOut("a2.push(x, a0);");
/*fuzzSeed-71289653*/count=721; tryItOut("v1 = evaluate(\"/* no regression tests found */\", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: Math.min(x + x, 12), noScriptRval: false, sourceIsLazy: (x % 56 == 46), catchTermination: (x % 53 != 28) }));");
/*fuzzSeed-71289653*/count=722; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.atan(Math.pow(( - 1/0), Math.atanh(y))) >> ( + Math.max(( + ((Math.fround(x) , Math.fround(Math.fround(Math.asinh(Math.fround(( ~ ( + Math.cos(( + x))))))))) >>> 0)), ( + Math.log(Math.hypot(( + (x == -0)), x)))))); }); testMathyFunction(mathy2, [0.000000000000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, 1.7976931348623157e308, -0x080000000, 1, 1/0, 0x100000001, 0x080000001, -Number.MAX_VALUE, -1/0, Number.MIN_VALUE, -0x080000001, -0x07fffffff, 0/0, -0x0ffffffff, 42, -(2**53-2), -(2**53+2), 0x100000000, Math.PI, -0x100000000, 2**53+2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -0, 0x0ffffffff, 0x080000000, 0]); ");
/*fuzzSeed-71289653*/count=723; tryItOut("\"use strict\"; ");
/*fuzzSeed-71289653*/count=724; tryItOut("o1.toString = (function(j) { g1.g0.f2(j); });");
/*fuzzSeed-71289653*/count=725; tryItOut("\"use strict\"; with({w: (this.__defineGetter__(\"d\", (Function).apply))}){;print(\"\\u767B\"); }");
/*fuzzSeed-71289653*/count=726; tryItOut("/*tLoop*/for (let e of /*MARR*/[/(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, (1/0), (void 0), /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, (1/0), /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, (1/0), (void 0), /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i, (void 0), (void 0), (1/0), /(?:(?=\\2){0,3})(\\u786b\\1(\\D))/i]) { (new RegExp(\"(?!(?:(?=$)))\", \"im\")); }");
/*fuzzSeed-71289653*/count=727; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\1\", \"g\"); var s = \"0\"; print(s.replace(r, false)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=728; tryItOut("\"use strict\"; t1 + '';");
/*fuzzSeed-71289653*/count=729; tryItOut("/*RXUB*/var r = /$?\\cA?\\s|\\u2d5f/yi; var s = \"0\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=730; tryItOut("\"use strict\"; g1.__proto__ = m2;");
/*fuzzSeed-71289653*/count=731; tryItOut("mathy2 = (function(x, y) { return Math.hypot(Math.fround(mathy1(Math.fround(Math.atan((Math.pow(y, Number.MAX_VALUE) | 0))), (Math.max(( ! (Math.atan2(y, 2**53+2) ? (Math.max(x, Math.pow((x >>> 0), -Number.MIN_VALUE)) | 0) : (( ! (y >>> 0)) >>> 0))), Math.min(-1/0, y)) | 0))), (Math.tan(( + ( + Math.cbrt(( + (-(2**53+2) < Math.fround((Math.fround(y) ? (y >>> 0) : Math.fround(( + (( + x) , ( + -0)))))))))))) | 0)); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -1/0, 0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, 0/0, -Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, 1/0, -(2**53+2), 0x0ffffffff, 0x100000000, 42, -(2**53-2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53), -0, 0, 1, -0x080000001, Math.PI, -0x080000000, -0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -0x100000001]); ");
/*fuzzSeed-71289653*/count=732; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?:(?=\\\\D){1}){2,33554435})|(?:((?!.\\\\S{3})?))?|.{1,3}\\\\3?\", \"gy\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); function x(x, z = new RegExp(\"\\\\2|\\\\s\", \"ym\"))(void shapeOf(x))m0.set(f2, this.v0);");
/*fuzzSeed-71289653*/count=733; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ Math.min(( + mathy1(( + ( + Math.min(( + (( - Math.max(x, x)) >>> 0)), ( + mathy2(x, ( + ( + 0x07fffffff))))))), ( + Math.sinh((0x07fffffff <= (mathy3(-(2**53), (x >>> 0)) >>> 0)))))), ((( - (Math.fround(( + (y * ( + Math.atan2(x, x))))) | 0)) | 0) ? (( + (( + Math.fround(Math.log2(Math.fround(( ~ 0x100000001))))) <= ( + -(2**53)))) | 0) : x))); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), NaN, NaN, x, (void 0)]); ");
/*fuzzSeed-71289653*/count=734; tryItOut("/*RXUB*/var r = /\\1+?/i; var s = \"\"; print(s.replace(r, runOffThreadScript, \"ym\")); ");
/*fuzzSeed-71289653*/count=735; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[ '\\0' ,  '\\0' ]) { a2[y =  /x/g  > Math.pow(-17,  /x/ )] = WebAssemblyMemoryMode(\"\\u0686\"--\u000c); }print(\"\\u9A5E\");\np2 = this.a0[o0.v0];\n");
/*fuzzSeed-71289653*/count=736; tryItOut("/*infloop*/for( /* Comment */eval; window; let (b = 0) -13) h0.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-71289653*/count=737; tryItOut("\"use strict\"; let z = /*MARR*/[true, true, true, true, true, true, function(){}, function(){}, true, true, function(){}, true, true, true, function(){}, function(){}, function(){}, true, true, true, function(){}, true, function(){}, true, function(){}, function(){}, true, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, true, function(){}, function(){}, true, true, true, true, function(){}, true, function(){}, true, function(){}, function(){}, function(){}, function(){}, true, function(){}, function(){}, true, true, true, function(){}, true, true, true, function(){}, true, function(){}, true, function(){}, function(){}, true, function(){}, function(){}, function(){}, true, true, function(){}, function(){}, function(){}, true, function(){}, true, true, function(){}, function(){}, true, true, function(){}, true, true, true, function(){}, true, true, true, true];var zgkkis = new ArrayBuffer(2); var zgkkis_0 = new Float32Array(zgkkis); var zgkkis_1 = new Uint8ClampedArray(zgkkis); zgkkis_1[0] = 1433612099; print(zgkkis_1[0]);print(e);");
/*fuzzSeed-71289653*/count=738; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(((mathy0(Math.tanh(( + Math.pow(y, ((mathy0(y, (0x100000001 | 0)) | 0) & y)))), Math.min(( + y), ( + y))) != ((Math.fround(((x & x) - (mathy0((Math.cos((( + (y <= y)) | 0)) >>> 0), (Math.log2(y) ^ x)) | 0))) >>> 0) >>> Math.atan2(x, 0))) , Math.fround(((Math.cbrt(Math.atan2((Math.fround(Math.min(( ~ 0x080000001), y)) >>> 0), (( + mathy0(x, ( + -(2**53+2)))) >>> 0))) | 0) | Math.exp((Math.log1p((Math.fround(( - Math.fround(y))) | 0)) | 0)))))); }); ");
/*fuzzSeed-71289653*/count=739; tryItOut("testMathyFunction(mathy1, [[], NaN, undefined, ({toString:function(){return '0';}}), 1, (new Boolean(false)), false, null, [0], 0, -0, (new String('')), (new Number(0)), ({valueOf:function(){return 0;}}), (function(){return 0;}), '0', objectEmulatingUndefined(), '/0/', 0.1, ({valueOf:function(){return '0';}}), '\\0', (new Boolean(true)), '', true, /0/, (new Number(-0))]); ");
/*fuzzSeed-71289653*/count=740; tryItOut("mathy2 = (function(x, y) { return (Math.atanh(Math.min(Math.tanh((( + (x != ((y >>> 0) === y))) >> x)), Math.sign(( + Math.ceil(Math.pow((y | 0), (Number.MAX_SAFE_INTEGER | 0))))))) >>> 0); }); testMathyFunction(mathy2, [2**53, 0x07fffffff, 0, 1/0, 42, 2**53+2, -0x07fffffff, Number.MAX_VALUE, -0x100000000, 0x080000001, -(2**53), -0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, 2**53-2, 1, -0x080000001, 1.7976931348623157e308, 0/0, -(2**53+2), 0x0ffffffff, Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, 0.000000000000001, -(2**53-2), Number.MIN_SAFE_INTEGER, -0]); ");
/*fuzzSeed-71289653*/count=741; tryItOut("/*iii*/for (var v of h1) { try { e1.add(f1); } catch(e0) { } try { v1 = evaluate(\"o0.o1.m1.has(s2);\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: (String.prototype.localeCompare).call(window, [[]],  /x/g ), noScriptRval: window, sourceIsLazy: true, catchTermination: vrhzyu })); } catch(e1) { } m1.get(g2); }/*hhh*/function vrhzyu(...c){print(x);\nprint( /x/ );\n}");
/*fuzzSeed-71289653*/count=742; tryItOut("new \"\u03a0\"((4277));yield a = Proxy.create(({/*TOODEEP*/})(w),  /x/ );");
/*fuzzSeed-71289653*/count=743; tryItOut("\"use strict\"; /*oLoop*/for (var cvjbkq = 0; cvjbkq < 1; ++cvjbkq) { /*RXUB*/var r = /\\u00e4/gy; var s = \"\\u00e4\"; print(r.exec(s));  } ");
/*fuzzSeed-71289653*/count=744; tryItOut("mathy2 = (function(x, y) { return (Math.trunc(((Math.max(x, (( ! (y >>> 0)) >>> 0)) , ( + ( ~ y))) | 0)) | 0); }); testMathyFunction(mathy2, [(function(){return 0;}), (new Boolean(false)), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), null, (new Number(-0)), (new Number(0)), true, false, '\\0', '/0/', (new String('')), '', -0, '0', (new Boolean(true)), 1, 0, ({valueOf:function(){return '0';}}), /0/, objectEmulatingUndefined(), undefined, [], [0], 0.1, NaN]); ");
/*fuzzSeed-71289653*/count=745; tryItOut("let (w) { yield; }print(x);");
/*fuzzSeed-71289653*/count=746; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      i2 = (i0);\n    }\n    d1 = (((+(0xab451b1d))) - ((+(0x4d963493))));\n    i0 = (!(-0x8000000));\n    {\n      (Uint16ArrayView[1]) = (((d1) <= (295147905179352830000.0))-((-295147905179352830000.0) == (+(-1.0/0.0)))-(0x604f9cc4));\n    }\n    return +((-16385.0));\n  }\n  return f; })(this, {ff:  /x/  ? [[1]] : z.sub}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [(new Number(0)), [0], (new Boolean(false)), [], 1, 0, objectEmulatingUndefined(), 0.1, null, (new Boolean(true)), undefined, '0', '', (new String('')), /0/, ({valueOf:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return 0;}}), -0, NaN, false, ({toString:function(){return '0';}}), '\\0', '/0/', true, (new Number(-0))]); ");
/*fuzzSeed-71289653*/count=747; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1.1805916207174113e+21;\n    var i3 = 0;\n    (Float32ArrayView[2]) = ((4095.0));\n;    i3 = ((0x7f24df5e));\n    d2 = (d2);\n    return +((-129.0));\n  }\n  return f; })(this, {ff: z =>  { yield Math.max(6, 21) } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53-2), -Number.MAX_VALUE, 0x07fffffff, -(2**53), 0x0ffffffff, -(2**53+2), 0, 1.7976931348623157e308, Number.MIN_VALUE, 0.000000000000001, 2**53+2, 2**53, 0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, 1, 42, 0x080000000, Math.PI, -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, -0x100000001, 2**53-2, 1/0, -1/0, 0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=748; tryItOut("\"use strict\"; let (x = ((b ^ x).setHours(x, ((makeFinalizeObserver('tenured')))))) { Array.prototype.unshift.apply(a1, [g0.f2]); }");
/*fuzzSeed-71289653*/count=749; tryItOut("L: {continue L; }");
/*fuzzSeed-71289653*/count=750; tryItOut("Array.prototype.shift.apply(a2, [m1, g2.b2, x, t2]);");
/*fuzzSeed-71289653*/count=751; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ~ (Math.fround(( - Math.fround(Math.cos(( - x))))) >>> 0)); }); testMathyFunction(mathy0, [0/0, 2**53+2, -0, 0x080000001, 0x100000000, -1/0, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, -0x080000000, Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 2**53, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, -(2**53), -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 1/0, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, 42, 2**53-2, Math.PI, 0]); ");
/*fuzzSeed-71289653*/count=752; tryItOut("print(x);e1 = new Set(g2);");
/*fuzzSeed-71289653*/count=753; tryItOut("\"use strict\"; \"use asm\"; v1 = t0[13];");
/*fuzzSeed-71289653*/count=754; tryItOut("\"use strict\"; print(/*RXUE*/new RegExp(\"[^]*?\\\\B\", \"im\").exec(\"\\n\\n\\n \\u008c\\uf17aa\"));w = 17;");
/*fuzzSeed-71289653*/count=755; tryItOut("mathy0 = (function(x, y) { return Math.atan(( - (Math.atan((Math.log2((y | 0)) | 0)) >>> 0))); }); testMathyFunction(mathy0, [-0x0ffffffff, -0, -Number.MIN_VALUE, 0x100000001, -0x100000000, 1/0, 0x100000000, 0x0ffffffff, -1/0, -0x080000001, -0x080000000, -Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, 0.000000000000001, 42, Number.MIN_VALUE, 0x080000001, -(2**53), Math.PI, -0x100000001, 0x07fffffff, 1.7976931348623157e308, -(2**53-2), 2**53-2, 0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-71289653*/count=756; tryItOut("v2 = g1.eval(\"L:if(timeout(1800)) v2 = t0.length; else  if (SyntaxError(x, new window( /x/g ))) {o2 = Object.create(this.e1);Object.prototype.unwatch.call(p1, \\\"toString\\\"); }\\nv2 = a1.length;\\n\");");
/*fuzzSeed-71289653*/count=757; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max((( ~ (( + ( - y)) << (x > x))) >>> 0), (((Math.max((y | 0), Math.atan2((Math.ceil(Math.fround(0/0)) | 0), x)) & Math.fround((x || y))) <= Math.min(Math.hypot(Math.fround(( + (Math.imul((x | 0), (Math.fround((Math.fround(y) ? ( + -0x07fffffff) : Math.fround(0x100000000))) | 0)) | 0))), y), ( + (( + Math.exp((Math.asinh(Math.fround((Math.fround(x) < Math.fround(x)))) >>> 0))) << ( + (Math.fround((-0x100000001 ? (x | 0) : (x >>> 0))) ? ( + ( + (( + (-Number.MAX_SAFE_INTEGER & y)) <= Math.fround(( + (y ^ 0/0)))))) : ( + Math.PI))))))) | 0)); }); ");
/*fuzzSeed-71289653*/count=758; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return (Math.hypot(Math.fround(Math.atanh((mathy1(y, (Math.min((( + (Math.sin((y >>> 0)) | 0)) >>> 0), (y >>> 0)) >>> 0)) >>> 0))), Math.fround(Math.atan2((mathy4(Math.asin(((y != (Math.log(x) >>> 0)) >>> 0)), ( + (( + ( - ( + ((y >>> 0) , y)))) || Math.imul(x, 2**53-2)))) >>> 0), Math.hypot(Math.fround((Math.round((Math.hypot(Math.fround(y), (x | 0)) | 0)) | 0)), ( + ( - ( + x))))))) | 0); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, -1/0, -0, 0x080000000, -Number.MIN_VALUE, 0x07fffffff, 1, -0x080000000, Number.MAX_VALUE, -0x100000000, 42, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, 0, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), 0.000000000000001, 0x080000001, Math.PI, 1.7976931348623157e308, -(2**53-2), 2**53, Number.MIN_VALUE, 0x100000000, 0/0, 2**53-2]); ");
/*fuzzSeed-71289653*/count=759; tryItOut("\"use strict\"; v1 = Infinity;\ne2.has(t2);\n");
/*fuzzSeed-71289653*/count=760; tryItOut("m2.__proto__ = f1;");
/*fuzzSeed-71289653*/count=761; tryItOut("/*hhh*/function pcjwrd(x, x){print(x);}pcjwrd((window), c = \u000ceval);");
/*fuzzSeed-71289653*/count=762; tryItOut("t2[19];");
/*fuzzSeed-71289653*/count=763; tryItOut("var byxrvs = new SharedArrayBuffer(8); var byxrvs_0 = new Uint32Array(byxrvs); var byxrvs_1 = new Uint8Array(byxrvs); byxrvs_1[0] = 20; var byxrvs_2 = new Int32Array(byxrvs); print(byxrvs_2[0]); byxrvs_2[0] = 26; var byxrvs_3 = new Uint32Array(byxrvs); var byxrvs_4 = new Int16Array(byxrvs); var byxrvs_5 = new Int8Array(byxrvs); var byxrvs_6 = new Int16Array(byxrvs); print(byxrvs_6[0]); byxrvs_6[0] = 0; var byxrvs_7 = new Int32Array(byxrvs); print(byxrvs_7[0]); var byxrvs_8 = new Int16Array(byxrvs); print(byxrvs_8[0]); var byxrvs_9 = new Float64Array(byxrvs); var byxrvs_10 = new Uint8Array(byxrvs); byxrvs_10[0] = 8192; /*vLoop*/for (var yuofvy = 0; yuofvy < 34; ++yuofvy) { var c = yuofvy; /*RXUB*/var r = new RegExp(\"\\\\2\", \"g\"); var s = \"\"; print(s.split(r));  } ");
/*fuzzSeed-71289653*/count=764; tryItOut("\"use strict\"; /*vLoop*/for (let pidhkz = 0; pidhkz < 19; ++pidhkz) { w = pidhkz; ( \"\" ); } ");
/*fuzzSeed-71289653*/count=765; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + mathy0(( + (( + (((x | 0) !== (( + (( + x) ? ( + -0x100000000) : ( + y))) | 0)) | 0)) <= mathy0(-0, ( + y)))), (( ~ (mathy0((( ! x) >>> 0), x) >>> 0)) >>> 0))) < ( + ( + Math.fround(Math.min(Math.fround(Math.fround((Math.fround(Math.cos((Math.fround(y) ^ Math.fround(1)))) ^ (Math.imul(( + Math.asinh(0.000000000000001)), (y >>> 0)) >>> 0)))), Math.fround(Math.fround(Math.atan2(((((y ? (( + ((x >>> 0) % ( + y))) | 0) : -0x100000000) & x) | 0) >>> 0), Math.fround(y))))))))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, Number.MAX_VALUE, 42, -(2**53+2), -0x100000001, 1/0, 0x100000000, 2**53+2, -1/0, -(2**53), 2**53-2, 0.000000000000001, 1.7976931348623157e308, -0x0ffffffff, -0x080000000, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0, 0x080000001, -0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, 1, 0/0, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, 0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, 0, 2**53]); ");
/*fuzzSeed-71289653*/count=766; tryItOut("\"use strict\"; do {print(x); } while(((((p={}, (p.z = e)()))((\u3056 = [,,])))) && 0);");
/*fuzzSeed-71289653*/count=767; tryItOut("{/*RXUB*/var r = new RegExp(\"\\\\b\", \"gyim\"); var s = \" \\n\\ufce5 \\ufc90\"; print(s.match(r)); print(r.lastIndex);  }");
/*fuzzSeed-71289653*/count=768; tryItOut("mathy1 = (function(x, y) { return (( - ((((((((Math.sign((((-Number.MAX_SAFE_INTEGER >>> 0) ** x) >>> 0)) | 0) >= Math.asinh(x)) != Math.imul(y, y)) / ((y >> x) | 0)) >>> 0) !== (Math.acos(( ! Math.atanh(x))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy1, [-0x07fffffff, 0x080000001, 0x0ffffffff, 0/0, Number.MAX_VALUE, 0, 0x07fffffff, -0x080000001, 2**53, -0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, Math.PI, -Number.MAX_VALUE, 42, 0x100000000, -0x080000000, 0x100000001, 1/0, Number.MIN_VALUE, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), -(2**53+2), -Number.MIN_VALUE, 2**53+2, -(2**53-2), 1, 2**53-2, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-71289653*/count=769; tryItOut("testMathyFunction(mathy3, [2**53-2, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), 0, 0x080000001, Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 2**53, -0x100000001, -0, 1.7976931348623157e308, -0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, -(2**53-2), Number.MAX_VALUE, 0x100000000, -0x07fffffff, 0.000000000000001, 2**53+2, Math.PI, -(2**53), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1/0, 42, -Number.MIN_VALUE, -0x100000000, -Number.MAX_VALUE, -0x0ffffffff, -0x080000000, 0x080000000]); ");
/*fuzzSeed-71289653*/count=770; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.abs(((( - x) % Math.exp(Math.fround(0x100000000))) >> (Math.atan2((( ! Math.imul(((x * (y >>> 0)) >>> 0), y)) | 0), Math.fround(y)) | 0))); }); ");
/*fuzzSeed-71289653*/count=771; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( ! Math.exp(x))) + Math.fround(mathy3(((Math.log1p(Math.pow(y, y)) <= x) >>> 0), Math.imul(y, Math.min((Math.log10(( + x)) | 0), Math.sin(( + (((y | 0) > (y | 0)) | 0))))))))); }); testMathyFunction(mathy4, [0/0, Math.PI, 0x100000001, Number.MAX_VALUE, -0, 1, Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 0.000000000000001, -0x080000000, 0x100000000, 0x0ffffffff, -0x100000001, 0x080000000, -1/0, 1/0, -0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0, -(2**53+2), Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53-2), -(2**53), -0x080000001, -0x07fffffff, 1.7976931348623157e308, 2**53-2, 0x080000001, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-71289653*/count=772; tryItOut("f1 = f2;false;");
/*fuzzSeed-71289653*/count=773; tryItOut("{ void 0; try { gcparam('markStackLimit', 4294967295); } catch(e) { } } Object.seal(m1);");
/*fuzzSeed-71289653*/count=774; tryItOut("mathy2 = (function(x, y) { return (( + ( ! (Math.tanh((Math.hypot(x, ( /x/  ? Math.fround(x) : y)) >>> 0)) >>> 0))) ** Math.imul((Math.fround(Math.max(Math.fround(Math.atanh((y >>> 0))), Math.fround(x))) / (Math.min(y, Math.fround(( ! (y | 0)))) >>> 0)), Math.fround((( - ((Math.max((Math.atan2(y, x) >>> 0), (((Math.max((x | 0), (x | 0)) | 0) === y) >>> 0)) >>> 0) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=775; tryItOut("\"use strict\"; v1 = g2.eval(\"function f1(this.v2)  { return b } \");function eval()\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -33.0;\n    var i3 = 0;\n    return (((0xfe0fb65f)-(0x4043ac0c)))|0;\n    {\n      (Float32ArrayView[2]) = ((d2));\n    }\n    {\n      {\n        d2 = (d1);\n      }\n    }\n    i3 = (0x413fd583);\n    i0 = (!(!((-0x8000000) < (~~(+(((b) = eval(\"for (var p in g0) { try { v0 = a0.reduce, reduceRight((function() { try { x = i0; } catch(e0) { } try { v1 = a0.reduce, reduceRight((function(j) { o1.f2(j); }), g2); } catch(e1) { } try { Object.defineProperty(this, \\\"v1\\\", { configurable: false, enumerable: x,  get: function() {  return Array.prototype.reduce, reduceRight.call(a1, (function() { try { t0 + m2; } catch(e0) { } try { e1.has(e1); } catch(e1) { } s2 += 'x'; return i2; })); } }); } catch(e2) { } /*MXX2*/g0.Float64Array.length = f0; return s1; })); } catch(e0) { } try { v1 = (s2 instanceof v1); } catch(e1) { } g2.offThreadCompileScript(\\\" \\\\\\\"\\\\\\\" \\\"); }\", function ([y]) { })) %= x))))));\n    (Float64ArrayView[((Float32ArrayView[1])) >> 3]) = ((65535.0));\n    {\n      d2 = (((d1)) / ((1.0)));\n    }\n    return (((0xffffffff)))|0;\n  }\n  return f;s2 += s0;");
/*fuzzSeed-71289653*/count=776; tryItOut("mathy5 = (function(x, y) { return (Math.sin(((Math.fround(Math.tanh(( + (mathy4((y | 0), ((( ~ (Number.MIN_VALUE >>> 0)) >>> 0) | 0)) >>> 0)))) - ( + ( + ( + (x != (Math.cosh(y) | 0)))))) | 0)) | 0); }); ");
/*fuzzSeed-71289653*/count=777; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 590295810358705700000.0;\n    var i3 = 0;\n    var d4 = 33554431.0;\n    (Uint16ArrayView[0]) = (((((4277))+((((0xde1e2547)) << ((0xff5e5c04))) <= (0xfd89a2d))+(!((0x31ef007) ? (0xff22c265) : (0xd669169e))))>>>((0xffffffff)+((0x8cfaeb6a) < (((0x9e6ee1ce))>>>((0xc47a5963))))+(((-(0xd0c40484))>>>(-0xfffff*(0xffffffff)))))) % (0xffffffff));\n    d4 = (+(((0xffffffff) / (0x0))|0));\n    return +((-17.0));\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-71289653*/count=778; tryItOut("g2.s0 += this.s1;");
/*fuzzSeed-71289653*/count=779; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.sin((Math.sign((mathy0(((Math.atan2((y | 0), (y | 0)) | 0) | 0), mathy1(Math.log(-Number.MAX_SAFE_INTEGER), y)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy2, [-(2**53+2), 0, 2**53-2, -(2**53-2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, -0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, -1/0, 2**53+2, 0x07fffffff, 2**53, -0x080000000, -0x07fffffff, 42, -Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, 0x0ffffffff, 0/0, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 1, 0x100000001, 0x080000000, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=780; tryItOut("(p={}, (p.z = x)());");
/*fuzzSeed-71289653*/count=781; tryItOut("\"use strict\"; if(true) {v0 = t0.length;function x(eval, d, x, window, x, x, x, x, y, x, w, x, x, x, y = x, x, x, x, x, x, window, x, x = /(?!(?!(\\w)(\u00f3))|(\\0|.{2,6}|\\\u5dad\\3))/im, w, b, \u3056) { return  ''  } h2 + m2; } else  if (x) /*RXUB*/var r = /(?!([^]?))\\1/gyi; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=782; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ~ Math.fround((( ! Math.fround((Math.fround(Math.sqrt((Math.fround(Math.pow(Math.fround(y), Math.fround((Math.pow((1.7976931348623157e308 >>> 0), y) >>> 0)))) | 0))) == Math.fround((Math.round(y) ? (( + y) !== ( + Math.min((((-0x0ffffffff | 0) >> y) >>> 0), ( + -Number.MAX_SAFE_INTEGER)))) : (Math.min(( + (y % y)), (2**53-2 | 0)) >>> 0)))))) >>> 0))); }); testMathyFunction(mathy1, [-0x100000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, 1/0, -(2**53+2), 0x0ffffffff, 0, 0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1, -0, 0x080000001, 1.7976931348623157e308, -0x0ffffffff, 0/0, 0x080000000, -0x100000001, 2**53-2, -0x07fffffff, -Number.MIN_VALUE, -0x080000000, 42, 2**53+2, 2**53, 0x100000001]); ");
/*fuzzSeed-71289653*/count=783; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+floor(((+((Int16ArrayView[0])))))));\n  }\n  return f; })(this, {ff: String.prototype.bold}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [Math.PI, 1.7976931348623157e308, -Number.MIN_VALUE, -0x07fffffff, 0x080000001, 0x100000000, -1/0, 1/0, 42, -0x100000001, -(2**53), -0x080000000, 0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, 0x07fffffff, -0x080000001, -0x100000000, -0, 0.000000000000001, -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 2**53, Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, 2**53+2, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=784; tryItOut("\"use strict\"; v1 = (p2 instanceof o0);");
/*fuzzSeed-71289653*/count=785; tryItOut("Array.prototype.pop.apply(a2, [eval(\"(null);\", x) ^ null ? [1] : this, t0]);");
/*fuzzSeed-71289653*/count=786; tryItOut("/*MXX3*/g0.Function.prototype.constructor = g0.Function.prototype.constructor;");
/*fuzzSeed-71289653*/count=787; tryItOut("\"use strict\"; v2 = (e0 instanceof p1);");
/*fuzzSeed-71289653*/count=788; tryItOut("\"use strict\"; ");
/*fuzzSeed-71289653*/count=789; tryItOut("((let (x = Math.hypot( /x/ , 18), jhqjyz, riqnfp, usrlcu, tjkmyl, a, e, \u3056) e = c));");
/*fuzzSeed-71289653*/count=790; tryItOut("testMathyFunction(mathy2, /*MARR*/[2**53+2, 2**53+2, 2**53+2, 0x080000001, 0x080000001, ['z'], 0x080000001, ['z'], 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 2**53+2, 0x080000001, 0x080000001, 0x080000001, ['z'], 0x080000001, 0x080000001, 0x080000001, 2**53+2, 2**53+2, 0x080000001, ['z'], ['z'], 2**53+2, 2**53+2, 0x080000001, 0x080000001, ['z'], 0x080000001, ['z'], ['z'], ['z'], 2**53+2]); ");
/*fuzzSeed-71289653*/count=791; tryItOut("mathy2 = (function(x, y) { return Math.acosh(Math.max((Math.imul((Math.fround(Math.pow(mathy0(y, ( - Math.fround(0.000000000000001))), y)) | 0), (mathy1(/*RXUB*/var r = new RegExp(\"\\\\2+([\\\\\\u90c6\\\\ue99C-,\\\\b-\\u000e])(?=[^])*?{4,}\\\\b**\", \"m\"); var s = \"0000000\\n\\n\\n\"; print(s.match(r)); , ( ! y)) | 0)) | 0), (x , ( ~ -(2**53-2))))); }); testMathyFunction(mathy2, [-0x0ffffffff, 42, -0x100000000, 1.7976931348623157e308, 0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), 0x100000000, 2**53+2, 0x100000001, Number.MAX_VALUE, 0x0ffffffff, -0x080000000, 0/0, -0x080000001, 2**53, 0x07fffffff, 1, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000001, Math.PI, 0x080000000, 2**53-2, -(2**53), Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, 0, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=792; tryItOut("testMathyFunction(mathy2, [0x100000000, 2**53-2, -0x100000001, 0.000000000000001, -0x100000000, -(2**53-2), -0x080000001, 1/0, 0/0, 0, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), -Number.MIN_VALUE, -0, -0x080000000, 2**53+2, Math.PI, Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000001, 42, 0x0ffffffff, 1, -0x0ffffffff, -1/0, 0x080000000, Number.MAX_VALUE, 2**53, 1.7976931348623157e308]); ");
/*fuzzSeed-71289653*/count=793; tryItOut("\"use strict\"; t1 = new Uint32Array(b1);");
/*fuzzSeed-71289653*/count=794; tryItOut("\"use strict\"; for(let b in []);;");
/*fuzzSeed-71289653*/count=795; tryItOut("\"use strict\"; p0 + p2;");
/*fuzzSeed-71289653*/count=796; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-71289653*/count=797; tryItOut("o0.o1.o0 + '';");
/*fuzzSeed-71289653*/count=798; tryItOut("/*tLoop*/for (let w of /*MARR*/[x, x, (void 0), 2**53, 2**53, x, x, x, x, x, x, x, x, x, x, x, x, x, x, 2**53, x, x, 2**53, x, 2**53, 2**53, 2**53, (void 0), (void 0), 2**53, x, 2**53, x, x, 2**53, x, 2**53, 2**53, (void 0), x, x, (void 0), 2**53, x, x, (void 0), x, (void 0), 2**53, x, x, 2**53, (void 0), (void 0), x, 2**53, (void 0), (void 0), 2**53, 2**53, x, 2**53, (void 0)]) { /*RXUB*/var r = new RegExp(\"(?=^(?=\\u3bd9|\\u00d3))|(?=\\\\d)|(?!\\\\cX)|(?=$)|(?!\\\\W)*?|\\\\2+?.{2}[\\\\D\\u0009]+?+?(?!(?=\\\\b?)+)+?|(?:.[^]+(?!\\ued9a)*)^{2,}*?\", \"m\"); var s = \"\\u3bd9\\u3bd9\\u3bd9\"; print(uneval(s.match(r)));  }");
/*fuzzSeed-71289653*/count=799; tryItOut("v0 = (e2 instanceof i0);print(uneval(e0));");
/*fuzzSeed-71289653*/count=800; tryItOut("\"use strict\"; o2 = b1.__proto__;");
/*fuzzSeed-71289653*/count=801; tryItOut("testMathyFunction(mathy0, [2**53, -1/0, 0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 42, 1/0, -Number.MIN_VALUE, 0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), -(2**53+2), 0/0, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, 1, Math.PI, -0x100000001, -0, Number.MIN_VALUE, -(2**53), 0x100000001, -0x07fffffff, 0, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=802; tryItOut("\"use strict\"; o0.e1.has((({x: /*FARR*/[].some(arguments.callee.caller)})));");
/*fuzzSeed-71289653*/count=803; tryItOut("/*ADP-2*/Object.defineProperty(g1.a0, (void options('strict_mode')), { configurable: true, enumerable: (x , x), get: (function() { try { /*ODP-1*/Object.defineProperty(b0, \"getUTCHours\", ({enumerable: true})); } catch(e0) { } try { g1.g0.e2 = new Set; } catch(e1) { } try { i2.send(this.v0); } catch(e2) { } Array.prototype.forEach.apply(a1, [(function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((0xf594e3a5)))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096))]); return g0.i2; }), set: (function() { g0.h2.getOwnPropertyNames = (function() { for (var j=0;j<34;++j) { f2(j%5==1); } }); return s2; }) });");
/*fuzzSeed-71289653*/count=804; tryItOut("e2 = new Set;");
/*fuzzSeed-71289653*/count=805; tryItOut("(let (e=eval) e)function x()xi1.send(s1);ftswmx();/*hhh*/function ftswmx(){Object.prototype.watch.call(h1, \"prototype\", (function() { for (var j=0;j<34;++j) { f0(j%4==0); } }));}");
/*fuzzSeed-71289653*/count=806; tryItOut("x;");
/*fuzzSeed-71289653*/count=807; tryItOut("/*tLoop*/for (let b of /*MARR*/[typeof Math.max( /x/g , undefined), [], typeof Math.max( /x/g , undefined), function(){}, function(){}, [], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, [], function(){}]) { o2 + ''; }");
/*fuzzSeed-71289653*/count=808; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=809; tryItOut("\"use strict\"; /*infloop*/for(var a = (\u000cx = (Math.acos(21))) -= Math.cosh(/*UUV2*/(e.toUTCString = e.fontsize)) === w; (p={}, (p.z = URIError(x, false))()); x) i0.send(h0);");
/*fuzzSeed-71289653*/count=810; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.tan(Math.fround(( + Math.fround(1/0)))) | 0), ((Math.atanh(Math.log2(y)) << ( - Math.sin((Math.pow(( + Math.atan2(( + ( ~ Number.MAX_VALUE)), ( + -Number.MAX_VALUE))), Math.sinh(Math.fround((y << y)))) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy0, [-0x080000000, -0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, 0.000000000000001, -(2**53-2), -(2**53), -Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, 42, 2**53, 0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 0, -1/0, 0x0ffffffff, Math.PI, Number.MAX_VALUE, -0x100000001, 1, -Number.MAX_VALUE, 0x080000001, 0/0]); ");
/*fuzzSeed-71289653*/count=811; tryItOut("f2 = (function() { try { p0 = x; } catch(e0) { } try { ; } catch(e1) { } try { this.p0.toString = (function() { for (var j=0;j<60;++j) { f2(j%5==0); } }); } catch(e2) { } print(uneval(e2)); return s1; });");
/*fuzzSeed-71289653*/count=812; tryItOut("\"use strict\"; (( \"\"  + -3));");
/*fuzzSeed-71289653*/count=813; tryItOut("\"use asm\"; i0 = e0.values;");
/*fuzzSeed-71289653*/count=814; tryItOut("v1 = evalcx(\"function f2(m0)  { yield String.prototype.substring([z1], x) } \", g2);");
/*fuzzSeed-71289653*/count=815; tryItOut("\"use strict\"; m2.get(a0);");
/*fuzzSeed-71289653*/count=816; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ((Math.fround((Math.min(((Math.acos(( + (Math.pow((Math.min(Math.hypot(0x080000000, x), x) >>> 0), Math.fround((0x080000000 != (Math.fround((42 ? Number.MAX_SAFE_INTEGER : y)) | 0)))) >>> 0))) >>> 0) | 0), (((y >> Math.abs(( + x))) ? x : Math.pow(x, x)) | 0)) | 0)) ? ((Math.fround((Math.fround(Math.min(y, Math.fround(Math.imul(Math.fround((Math.imul((y >>> 0), (x >>> 0)) >>> 0)), Math.fround(y))))) ? Math.fround(Math.fround(Math.log(Math.atanh(x)))) : Math.fround(-0x100000001))) , ( + Math.pow(((( + x) * x) ? Math.acos(( + x)) : 0x100000000), Math.fround(Math.atan2(Math.fround(y), Math.fround((x >>> (x >>> 0)))))))) >>> 0) : (( + (( + (Math.acosh(y) | 0)) <= ( + Math.asin((( ~ (( + Math.min((((Math.round(y) >>> 0) % x) >>> 0), y)) >>> 0)) >>> 0))))) | 0)) >>> 0); }); testMathyFunction(mathy0, [42, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, -0x080000000, -0, 2**53+2, 0, -Number.MAX_VALUE, 0x100000001, -0x080000001, 0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53-2), Math.PI, -0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, 1, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 2**53, Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, -(2**53+2), 0x0ffffffff, -0x100000000, 0x080000000, -(2**53), 0.000000000000001, Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-71289653*/count=817; tryItOut("\"use strict\"; (\"\\u8EC3\" >> Math.pow(this, 8));");
/*fuzzSeed-71289653*/count=818; tryItOut("mathy0 = (function(x, y) { return (( + (( + Math.log1p(Math.fround(Math.atan2(((x , y) >= Math.fround((((x | 0) == (y | 0)) | 0))), ( ! (x >= x)))))) | 0)) | 0); }); testMathyFunction(mathy0, [0x100000000, -0x100000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 0x080000000, 0x080000001, -0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, 0x07fffffff, 1, -(2**53-2), -(2**53+2), 2**53, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, 0x100000001, -0, Math.PI, -(2**53), 0, 1.7976931348623157e308, 0/0, 2**53+2]); ");
/*fuzzSeed-71289653*/count=819; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.cosh(Math.fround(( + Math.fround(mathy1(x, Math.fround(Math.log1p(Math.fround(y)))))))); }); testMathyFunction(mathy5, [0, 0x100000000, -(2**53), -0x080000001, 42, 0x080000000, -0, -(2**53+2), -1/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, 0x0ffffffff, -Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, 0/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, Math.PI, 0.000000000000001, -0x080000000, Number.MIN_VALUE, 1, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000]); ");
/*fuzzSeed-71289653*/count=820; tryItOut("var r0 = x + x; var r1 = 6 + r0; var r2 = x ^ 6; print(r1); var r3 = r1 * 6; var r4 = r1 - r2; var r5 = r4 + x; r0 = x + r4; var r6 = r2 ^ r4; var r7 = r3 & r2; r5 = r6 + 8; var r8 = r5 - 0; print(r2); r5 = x - r2; var r9 = x * r3; var r10 = 1 + r8; r5 = r0 & 4; var r11 = r9 | r6; var r12 = 5 ^ 7; var r13 = r2 % 0; var r14 = r12 | r4; var r15 = r13 / 3; ");
/*fuzzSeed-71289653*/count=821; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.atan2(Math.atan2((Math.atanh(Math.fround((y & Math.acosh(y)))) >>> 0), Math.fround(( ! Math.fround((Math.imul(( + x), (Math.fround(Math.pow(y, x)) >>> 0)) >>> 0))))), (Math.acos(( + (( + Math.pow((Math.cbrt(Math.fround(x)) | 0), ( + ( + Math.fround((((y | 0) ? 1.7976931348623157e308 : (0x0ffffffff | 0)) | 0)))))) & Math.fround(y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x080000000, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, 1, -1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, -(2**53-2), -0x100000000, 0x0ffffffff, 2**53, -0, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), 0x07fffffff, -0x080000001, 1/0, 0x080000001, Math.PI, -Number.MAX_VALUE, 0x100000000, 0x100000001, -0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, -(2**53), -0x080000000, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=822; tryItOut("a1.splice(NaN, 0);");
/*fuzzSeed-71289653*/count=823; tryItOut("/*tLoop*/for (let z of /*MARR*/[new String(''), new String(''), {}, new String(''), {}, {}, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new Boolean(false), {}, new Boolean(false), new Boolean(false), new String(''), {}, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new Boolean(false), {}, {}, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new String(''), {}, new String(''), new Boolean(false), new String(''), new Boolean(false), new Boolean(false), new String(''), new String(''), {}, new String(''), new Boolean(false), new String(''), new Boolean(false), new Boolean(false), new String(''), new String(''), {}, new String(''), new String(''), {}, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), {}, new Boolean(false), new String(''), new Boolean(false), new Boolean(false), {}, {}, new String(''), {}, new String(''), {}, new Boolean(false), new String(''), new Boolean(false), {}, new String(''), new String(''), {}, {}, {}, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new Boolean(false), {}, {}, new String(''), new Boolean(false), {}, new String(''), {}, {}, new String(''), {}, new String(''), {}, new Boolean(false), new Boolean(false), new String(''), {}, new String(''), new String(''), new String('')]) { /* no regression tests found */ }\nlet bkxckq, x, ggxbcs, x = let (dxamcu) -23 == [z1,,], eval = Math.atan2( '' , 18), lcqhne, avtjgr, hlimdp, sqdnhc, bztpqh;print((/*MARR*/[new Number(1.5), new Number(1.5), .2, .2, new Number(1.5), .2, new Number(1.5), .2, \"\\uBACC\", .2, .2, \"\\uBACC\"].filter((1 for (x in [])), x)));\ndo {this.v1 = h2[\"anchor\"]; } while((x.__defineSetter__(\"x\", Symbol.keyFor)) && 0);\n\n");
/*fuzzSeed-71289653*/count=824; tryItOut("g0 = this;");
/*fuzzSeed-71289653*/count=825; tryItOut("\"use strict\"; throw StopIteration;for(let a of /*PTHR*/(function() { for (var i of  /x/g ) { yield i; } })()) try { return; } catch(w if ( '' ).call(a, (4277))) { w.name; } finally { try { \"\\u092A\"; } catch(z) { (z\u0009); } finally { (let (e=eval) e) }  } ");
/*fuzzSeed-71289653*/count=826; tryItOut("mathy5 = (function(x, y) { return Math.pow(Math.max(Math.hypot((( ! (( + (((((x >>> 0) ? (y >>> 0) : (x >>> 0)) >>> 0) >>> 0) !== (y >>> 0))) >>> 0)) >>> 0), (Math.fround(Math.cos(Math.fround(Number.MIN_VALUE))) >>> 0)), Math.fround(Math.atan2(Math.fround(Math.pow(( ! y), 0.000000000000001)), Math.fround(Math.pow(Math.round(x), ( + ( ~ (Math.hypot(0/0, ( + x)) >>> 0)))))))), (( ! ( + mathy4(( + mathy3(x, 0x100000001)), ( + y)))) ? mathy0(Math.fround(Math.atan2(Math.fround((((x >>> 0) !== (y >>> 0)) >>> 0)), Math.fround(( ~ Math.fround((Math.max(0x080000001, (y >>> 0)) | 0)))))), Math.fround((Math.max((Math.cosh(x) | 0), ((mathy2(-(2**53-2), ( + Math.pow(( + x), ( + (mathy4((y >>> 0), (y >>> 0)) >>> 0))))) >>> 0) | 0)) | 0))) : Math.fround(Math.min(Math.asin((x >= ( + (x + y)))), ( + ( + 0)))))); }); testMathyFunction(mathy5, [-(2**53+2), Number.MAX_VALUE, 2**53+2, 2**53-2, 1/0, 0x100000000, 0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, -(2**53), -0x100000001, 0x080000001, 2**53, 1.7976931348623157e308, 0/0, -1/0, -0x07fffffff, 42, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), -0x100000000, 0x100000001, Math.PI, -0x080000000, -0x080000001, -Number.MIN_VALUE, -0x0ffffffff, 0x07fffffff, -0]); ");
/*fuzzSeed-71289653*/count=827; tryItOut("g1.t2[2] = m0;\nt2.set(g1.t2, 6);\n");
/*fuzzSeed-71289653*/count=828; tryItOut("a1.reverse();\n/*bLoop*/for (upsbtz = 0; upsbtz < 9; ++upsbtz) { if (upsbtz % 6 == 3) { (this); } else { o2.f2 + ''; }  } \n");
/*fuzzSeed-71289653*/count=829; tryItOut("this.m2 = new WeakMap;");
/*fuzzSeed-71289653*/count=830; tryItOut("\"use strict\"; v2 = a2.length;\n{} = ((yield \ne)), y, w = d, jjvkak, x, window, rayvzx, onfexo;v2 = evaluate(\"Array.prototype.splice.call(a0, NaN, ({valueOf: function() { print(x);return 17; }}));\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: [[]], noScriptRval: (x % 7 == 0), sourceIsLazy: (x % 55 == 15), catchTermination: false }));\n");
/*fuzzSeed-71289653*/count=831; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(mathy1(((Math.max(Math.min(( ! x), (((x >>> 0) >>> (\"\\uADBA\" >>> 0)) >>> 0)), (Math.pow(Math.fround(Math.fround(Math.min(x, y))), (-0x100000000 | 0)) >>> 0)) >>> 0) >>> (Math.sin(y) | 0)), Math.fround(Math.min((((Math.sinh((Math.ceil((y - x)) | 0)) >>> 0) ? (( + (( + ( + ( ~ (Math.asin(x) | 0)))) & Math.fround(mathy0(-Number.MAX_SAFE_INTEGER, ( ! y))))) >>> 0) : (mathy0((x % (Math.hypot(((( + -0x07fffffff) , x) >>> 0), (0 >>> 0)) >>> 0)), Math.fround(( - Math.min(x, x)))) >>> 0)) >>> 0), (( + Math.cos(x)) ? y : x))))); }); testMathyFunction(mathy2, [1.7976931348623157e308, -0x080000000, -Number.MAX_VALUE, 0x100000000, -1/0, 0x080000000, 2**53+2, -Number.MIN_VALUE, -(2**53-2), 42, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -0x100000001, -(2**53), -0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0, Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, 2**53-2, -0x080000001, -0x100000000, 0, 1/0, Math.PI, 1, 0x100000001, Number.MAX_VALUE, 0.000000000000001, 2**53]); ");
/*fuzzSeed-71289653*/count=832; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround((Math.atan((( ~ (((Math.atan2((( + Math.imul(y, y)) | 0), (((y >>> 0) === (-0x07fffffff >>> 0)) >>> 0)) | 0) ? (x >>> 0) : (y >>> 0)) >>> 0)) >>> 0)) != ((( - mathy0(( ! x), Math.ceil((( - (x | 0)) >>> 0)))) != (Math.hypot(((( + (( + x) > (((y >>> 0) || y) >>> 0))) >>> 0) != x), (( ! (x >>> 0)) >>> 0)) | 0)) | 0))); }); testMathyFunction(mathy2, ['\\0', (function(){return 0;}), ({valueOf:function(){return 0;}}), /0/, 0, true, ({toString:function(){return '0';}}), null, '/0/', false, undefined, NaN, (new Boolean(false)), 1, (new Number(-0)), (new Number(0)), '0', 0.1, objectEmulatingUndefined(), (new Boolean(true)), [0], (new String('')), [], ({valueOf:function(){return '0';}}), -0, '']); ");
/*fuzzSeed-71289653*/count=833; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-(2**53+2), -0x100000001, 0x080000000, -Number.MAX_VALUE, 0/0, -0x080000000, 2**53-2, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, 0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000001, -0x07fffffff, -1/0, 0.000000000000001, 1/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0, -(2**53), 42, -0x0ffffffff, -Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, 2**53+2, 1, 0x080000001, -0x100000000, 2**53]); ");
/*fuzzSeed-71289653*/count=834; tryItOut("/*tLoop*/for (let a of /*MARR*/[-(2**53-2), 0.000000000000001, function(){}, -0x080000000, function(){}, -0x080000000, -(2**53-2), function(){}, -(2**53-2), 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, x.toLocaleUpperCase(), -(2**53-2), -0x080000000, -0x080000000, -0x080000000, x.toLocaleUpperCase(), 0.000000000000001, 0.000000000000001, x.toLocaleUpperCase(), function(){}, -0x080000000, x.toLocaleUpperCase(), 0.000000000000001, 0.000000000000001, -0x080000000, function(){}, function(){}, -(2**53-2), 0.000000000000001, x.toLocaleUpperCase(), 0.000000000000001, function(){}, 0.000000000000001, -0x080000000, -0x080000000, 0.000000000000001, -(2**53-2), 0.000000000000001, function(){}, -0x080000000, 0.000000000000001, function(){}, -0x080000000, function(){}, function(){}, 0.000000000000001, x.toLocaleUpperCase(), -(2**53-2), -0x080000000, x.toLocaleUpperCase(), -0x080000000, x.toLocaleUpperCase(), -0x080000000, function(){}, -(2**53-2), -(2**53-2), -(2**53-2), x.toLocaleUpperCase(), -0x080000000, -0x080000000, -(2**53-2), -(2**53-2), -(2**53-2), 0.000000000000001, -0x080000000, x.toLocaleUpperCase(), x.toLocaleUpperCase()]) { print(e);let e = x; }");
/*fuzzSeed-71289653*/count=835; tryItOut("this.v0 + b0;");
/*fuzzSeed-71289653*/count=836; tryItOut("\"use strict\"; Object.defineProperty(this, \"g1.v1\", { configurable: true, enumerable: (/*FARR*/[].some(WeakSet, x)).throw(/*MARR*/[x, x, false, objectEmulatingUndefined(), objectEmulatingUndefined(), false, x, false, false, objectEmulatingUndefined(), false, false, x, x, false, objectEmulatingUndefined(), x, false, objectEmulatingUndefined(), false, x, objectEmulatingUndefined(), x, false, false, false, false, false, objectEmulatingUndefined(), false, false, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), false, x, x, false, objectEmulatingUndefined(), objectEmulatingUndefined(), false, false, false, false, false, false, objectEmulatingUndefined(), false]),  get: function() {  return g0.eval(\"/* no regression tests found */\"); } });");
/*fuzzSeed-71289653*/count=837; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    d1 = (+(0.0/0.0));\n    d1 = (-((+(1.0/0.0))));\n    (Float64ArrayView[((0x4aed480d)-(/*FFI*/ff(((d1)), ((((1.0)) / ((67108865.0)))), ((~((0xfcc68769)))))|0)+(0xf49834b4)) >> 3]) = ((-255.0));\n    {\n      i0 = (i0);\n    }\n    i0 = (i0);\n    i0 = ((~~(Infinity)));\n    i0 = (!(/*FFI*/ff(((((i0)-(i0)-(-0x3365b9)) ^ ((0xdaf7ab98)-((/*FFI*/ff(((-0.0625)), ((1152921504606847000.0)), ((-16385.0)), ((-1099511627775.0)), ((-137438953473.0)), ((-4503599627370497.0)), ((1.888946593147858e+22)), ((-9007199254740992.0)), ((1099511627777.0)), ((-70368744177664.0)), ((1.00390625)), ((34359738367.0)), ((-63.0)), ((-6.044629098073146e+23)), ((0.001953125)), ((274877906944.0)), ((562949953421313.0)), ((6.044629098073146e+23)), ((-2251799813685248.0)), ((-8191.0)), ((9.0)), ((36028797018963970.0)), ((549755813888.0)), ((6.189700196426902e+26)), ((-9.44473296573929e+21)))|0) ? (-0x8000000) : (i0))))), ((+(1.0/0.0))), ((-536870913.0)), ((-1.015625)), ((+pow(((-8589934591.0)), ((Infinity))))), ((d1)), ((+abs(((-1152921504606847000.0))))), ((((-1.0078125)) / ((590295810358705700000.0)))), ((3.8685626227668134e+25)))|0));\n    d1 = (-7.555786372591432e+22);\n    d1 = (2.3611832414348226e+21);\n    {\n      d1 = (+(-1.0/0.0));\n    }\n    return +((+((d1))));\n    d1 = (d1);\n    d1 = (+(~~(d1)));\n    return +((+((Infinity))));\n  }\n  return f; })(this, {ff: (function() { yield NaN; } })()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 1, -0, 0, 0x07fffffff, -(2**53-2), Number.MIN_VALUE, 1/0, 0.000000000000001, Math.PI, 0x0ffffffff, 2**53-2, 0x100000000, -0x100000000, -Number.MAX_VALUE, 0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, 2**53, -0x100000001, 2**53+2, -1/0, -Number.MIN_VALUE, -0x080000001, Number.MAX_VALUE, 0/0, 0x080000000, -0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-71289653*/count=838; tryItOut("for (var v of g2.t1) { try { v1 = g1.eval(\"\\\"use strict\\\"; /* no regression tests found */\"); } catch(e0) { } try { this.m1.delete(a2); } catch(e1) { } e1 + ''; }");
/*fuzzSeed-71289653*/count=839; tryItOut("mathy2 = (function(x, y) { return (( - ((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) { var r0 = 7 % a1; var r1 = a13 + a16; var r2 = a13 * a14; var r3 = a16 & 0; var r4 = 4 & 7; print(a9); var r5 = a2 - 5; var r6 = 2 | 6; a6 = r5 + a6; a1 = a2 | r4; var r7 = y % x; a11 = 5 + 3; a0 = 6 / r3; a1 = 6 & 7; var r8 = r7 / a2; a5 = r0 % r1; var r9 = 3 | a5; var r10 = 7 & a2; r6 = r4 % a7; var r11 = 4 | a1; var r12 = a6 % r6; var r13 = 8 % y; a13 = a10 + 3; var r14 = a16 / 6; r2 = 3 % 3; var r15 = a14 / a0; var r16 = y * 1; var r17 = a6 & r4; var r18 = r2 / r13; a16 = r7 ^ a13; print(r11); var r19 = r3 % 0; var r20 = 2 * r3; r11 = r15 - 9; var r21 = r19 | r15; var r22 = 3 % 6; var r23 = 1 * r0; var r24 = 3 ^ r18; var r25 = a12 & a1; var r26 = r24 - 5; var r27 = r26 % 2; var r28 = 5 ^ 7; a13 = 6 / r0; var r29 = 4 ^ a7; a16 = r1 | 8; var r30 = r13 + r18; a3 = 8 * 6; r5 = 1 - 3; var r31 = r25 - r12; var r32 = r23 ^ r11; var r33 = a4 & r28; var r34 = a10 * 0; var r35 = a1 & r25; var r36 = a1 ^ r30; var r37 = r35 * a0; a2 = 0 * r17; x = r16 - r8; r9 = r33 % r5; var r38 = 7 % 9; var r39 = r9 % y; var r40 = 7 ^ 8; var r41 = r25 / r13; return a7; }) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x07fffffff, -0x0ffffffff, 0x080000000, -(2**53+2), 1/0, 1.7976931348623157e308, -Number.MAX_VALUE, 0x080000001, 0/0, 2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -0x080000001, Number.MAX_VALUE, -(2**53-2), 1, 0x100000000, 42, -Number.MIN_VALUE, Math.PI, 0x07fffffff, -0x100000000, -0x100000001, 0.000000000000001, 0x0ffffffff, -0, 2**53, Number.MAX_SAFE_INTEGER, -0x080000000, 0, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53)]); ");
/*fuzzSeed-71289653*/count=840; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.hypot(((((Math.imul(y, y) | 0) <= Math.fround(( - (y | 0)))) / ( + Math.pow(x, ( + y)))) | 0), (( + (( + Math.fround(mathy0((Math.atan2((Math.imul(((x ? ( + 42) : -0x080000000) | 0), (x >>> 0)) >>> 0), (mathy2(-0x0ffffffff, 1/0) >>> 0)) >>> 0), y))) ** ( + y))) | 0)) | 0) != (Math.cosh(( ~ ( + Math.atan(( + (((0x080000000 >>> 0) < (y >>> 0)) >>> 0)))))) * ( ~ Math.fround((((((Math.tan(( + y)) >>> 0) >> (x | 0)) >>> 0) <= ( + ( + mathy0(x, y)))) >>> 0))))); }); testMathyFunction(mathy3, [false, null, (function(){return 0;}), 0.1, /0/, ({valueOf:function(){return 0;}}), true, (new Boolean(false)), [0], [], (new String('')), '/0/', (new Boolean(true)), '\\0', '0', '', ({toString:function(){return '0';}}), (new Number(-0)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), undefined, 0, -0, NaN, (new Number(0)), 1]); ");
/*fuzzSeed-71289653*/count=841; tryItOut("a2.pop([] = (new \n((makeFinalizeObserver('nursery')))(e >= NaN\n)));");
/*fuzzSeed-71289653*/count=842; tryItOut("(x);");
/*fuzzSeed-71289653*/count=843; tryItOut("Array.prototype.splice.apply(a0, [this.h1, o2]);");
/*fuzzSeed-71289653*/count=844; tryItOut("try { 1 - NaN[\"1\"] = x; } catch(z) { with({}) with({}) return (let (w = /\\w/g) 7); } let(e) { e.constructor;}");
/*fuzzSeed-71289653*/count=845; tryItOut("\"use strict\";  for  each(let d in x) e0.has(i1);");
/*fuzzSeed-71289653*/count=846; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-71289653*/count=847; tryItOut("this.t0 = new Uint8ClampedArray(13);");
/*fuzzSeed-71289653*/count=848; tryItOut("\"use strict\"; /*iii*/print(lhusqv);/*hhh*/function lhusqv(d){let (c) { null; }}");
/*fuzzSeed-71289653*/count=849; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.atan2((( ! (((y >>> 0) === -(2**53+2)) | 0)) | 0), ( + ( + (((Math.log1p((y | 0)) | 0) | 0) > ((Math.expm1(mathy0(y, -0x080000001)) ** Math.pow(Math.PI, ( + Math.fround(Math.fround(( + Math.fround(y))))))) >>> 0))))); }); testMathyFunction(mathy1, [0x080000000, -(2**53-2), Number.MIN_VALUE, 2**53-2, -Number.MAX_VALUE, -0x100000000, -0, 0, Math.PI, 1/0, 0.000000000000001, 0x0ffffffff, -0x100000001, -0x080000001, -Number.MIN_VALUE, 1, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, 0x100000000, -0x07fffffff, -1/0, 2**53, 0x080000001, 42, -(2**53+2), Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-71289653*/count=850; tryItOut("for(let e of (function() { yield ( \"\" [\"0\"] = ()); } })()) {s1 = new String(v1);s2 = s0.charAt(12); }with({}) { x.message; } ");
/*fuzzSeed-71289653*/count=851; tryItOut("for (var p in p1) { try { g0.v0 = (g0.v1 instanceof e1); } catch(e0) { } try { /*MXX2*/g1.Float32Array = p2; } catch(e1) { } for (var v of h1) { try { Array.prototype.shift.apply(a0, [this.e2, o1, o2, f0]); } catch(e0) { } try { g2.v0 = Object.prototype.isPrototypeOf.call(a2, s1); } catch(e1) { } h1 + p1; } }");
/*fuzzSeed-71289653*/count=852; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.log2(mathy2(( + ( ~ ( + ((x | 0) & Math.round(-Number.MAX_SAFE_INTEGER))))), ( ! ( - -(2**53+2))))); }); testMathyFunction(mathy3, [0/0, Math.PI, 0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, -1/0, 0x080000001, 0.000000000000001, -0x07fffffff, 2**53+2, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, 0x0ffffffff, -0, 0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 42, 1/0, -0x080000000, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000000, 2**53-2, -0x100000000, -0x080000001, 1, 1.7976931348623157e308, -0x100000001]); ");
/*fuzzSeed-71289653*/count=853; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?![\\\\s\\\\u0076])\", \"im\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=854; tryItOut("mathy0 = (function(x, y) { return (((Math.min(((((Math.log1p(Math.imul(x, y)) != y) >>> 0) & ((( - (( - ( + x)) | 0)) | 0) >>> 0)) >>> 0), Math.fround(( - ( + Math.fround(( + 2**53-2)))))) >>> 0) | 0) === ( + (( + (( ~ (( + Math.atan2(( + (Math.ceil((((y === x) | 0) | 0)) >>> 0)), ((( ! (y >>> 0)) >>> 0) >>> 0))) >>> 0)) >>> 0)) < ( + Math.atan2(Math.sin(-1/0), ((x + Math.atan(( + (( ! (y >>> 0)) >>> 0)))) | 0)))))); }); testMathyFunction(mathy0, /*MARR*/[ /x/g , {x:3},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/ , false,  /x/ , false, false,  /x/ ,  /x/g ,  /x/ ,  /x/ ,  /x/ , false, {x:3}, {x:3}, {x:3},  /x/ , false, false,  /x/ , {x:3}, false, {x:3}, false, false,  /x/ ,  /x/ , {x:3}, false, {x:3},  /x/g ,  /x/ ,  /x/ ,  /x/ ,  /x/ , {x:3}, false, false, {x:3}, false,  /x/ ,  /x/ ,  /x/g ,  /x/g ,  /x/g , {x:3}, {x:3}, false,  /x/g , {x:3},  /x/g , {x:3}, {x:3},  /x/ , {x:3},  /x/ , {x:3},  /x/ ,  /x/g , false, false, {x:3}, false, {x:3},  /x/ , {x:3}, false, false,  /x/ ,  /x/g ,  /x/g ,  /x/ , {x:3},  /x/g , {x:3},  /x/g , {x:3}, false, {x:3}, {x:3},  /x/ , {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, false,  /x/ ,  /x/ , false,  /x/g , {x:3},  /x/ ,  /x/g ,  /x/ ,  /x/g ,  /x/g , {x:3},  /x/ ,  /x/g ,  /x/ , false, false,  /x/g ]); ");
/*fuzzSeed-71289653*/count=855; tryItOut("testMathyFunction(mathy4, [0x080000001, -1/0, 0x100000001, -0x080000000, -(2**53), 0.000000000000001, Number.MAX_VALUE, 2**53+2, 0x100000000, -0x100000000, 42, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, 0x07fffffff, 0, -0x07fffffff, 2**53, 1/0, 1, 1.7976931348623157e308, Math.PI, -0x100000001, -0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=856; tryItOut("mathy1 = (function(x, y) { return (( + (Math.sqrt(( + Math.log10(Math.max(Math.fround((y - x)), x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [2**53-2, -0x100000001, -(2**53), -0, 2**53, 0/0, Number.MIN_SAFE_INTEGER, 1/0, 0x080000000, -0x080000000, 0x0ffffffff, 0, 0x07fffffff, 1, 0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, -(2**53-2), Math.PI, 42, Number.MAX_VALUE, -0x080000001, 2**53+2, -(2**53+2), -0x100000000, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 0x100000001, 0x080000001, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=857; tryItOut("\"use strict\"; \"use asm\"; \u000ca0.push(o0.h1, t0, m0, f2, this.o0.b1, m0, p1);(let (eval, cvtcdv, x) false);");
/*fuzzSeed-71289653*/count=858; tryItOut("print(x)\nthrow -1;");
/*fuzzSeed-71289653*/count=859; tryItOut("");
/*fuzzSeed-71289653*/count=860; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=\u0e82|(?!\\v)|(?=\u00ea))(?:(\\b)+)|.|(.)(?:(?:(?=\\B?))(?:\\W)|.?|([^\\W]))*{2,4}/m; var s = \"\\n\\n\\u00e5\\u00e5\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-71289653*/count=861; tryItOut("with({}) let(c) ((function(){this.zzz.zzz;})());");
/*fuzzSeed-71289653*/count=862; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=863; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.asinh(( + ( ! (((( ~ ( + (Math.fround(( + ( ! ( + x)))) | x))) >>> 0) || ((Math.max((mathy2(((y >> x) | 0), y) | 0), (Math.min((y >> Math.tan(x)), (( ~ y) >>> 0)) | 0)) | 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [1.7976931348623157e308, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, Math.PI, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, 0x07fffffff, 0x100000001, 0x100000000, -0x0ffffffff, 2**53, Number.MIN_VALUE, 42, 1/0, -0x07fffffff, -0x080000000, -Number.MIN_VALUE, -0x100000001, 0x080000001, 2**53+2, 2**53-2, 0x080000000, -(2**53), 0x0ffffffff, -(2**53+2), 0/0, 0, 1]); ");
/*fuzzSeed-71289653*/count=864; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( - Math.fround(( - (((Math.max(mathy0(Math.max(-0x080000000, 2**53+2), ( - y)), Math.max(((x < x) >>> 0), x)) >>> 0) | Math.tanh((y >>> 0))) | 0)))); }); testMathyFunction(mathy5, [0x080000001, 0x0ffffffff, -0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -0, 0/0, -0x100000000, -(2**53-2), -(2**53), -0x080000001, 1, -(2**53+2), 2**53, 0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, -0x080000000, 1/0, 2**53-2, 42, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, Number.MIN_VALUE, 0.000000000000001, 2**53+2, 0x100000000, 0, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=865; tryItOut("v1 = t2.length;");
/*fuzzSeed-71289653*/count=866; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ (( ~ (Math.fround(((( ! y) | 0) + (Math.hypot((Math.fround(Math.hypot(Math.fround((Math.pow((0.000000000000001 >>> 0), (y >>> 0)) >>> 0)), -0x100000001)) | 0), (( + (Math.max(( + y), ( + x)) | 0)) >>> 0)) | 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, /*MARR*/[{},  /x/g , [], [], -Infinity, -Infinity,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , -Infinity, -Infinity,  /x/g , [], {},  /x/g , false, {},  /x/g ,  /x/g , {}, false, {},  /x/g , {},  /x/g ,  /x/g , -Infinity, [], false, [], false, {}, [], {}, false, [], [], [], false,  /x/g , false,  /x/g , false, {}, -Infinity, [], -Infinity,  /x/g ,  /x/g ,  /x/g ]); ");
/*fuzzSeed-71289653*/count=867; tryItOut("\"use strict\"; for (var v of this.o2.f2) { for (var p in o2) { try { for (var p in p1) { try { this.e0.toSource = (function(j) { if (j) { this.a0 = new Array; } else { try { s2 += 'x'; } catch(e0) { } try { t0 = new Float32Array(14); } catch(e1) { } h1[\"setUint32\"] = v2; } }); } catch(e0) { } try { v0 = evalcx(\"/* no regression tests found */\", g1); } catch(e1) { } try { a0[({valueOf: function() { (!Math);return 8; }})] = (y && x) ^ x; } catch(e2) { } h2.valueOf = (function() { try { for (var v of v1) { try { h1 + o2.a2; } catch(e0) { } try { m0 + m1; } catch(e1) { } v0 = this.g1.runOffThreadScript(); } } catch(e0) { } m0.delete(e2); return h0; }); } } catch(e0) { } try { h1.keys = f0; } catch(e1) { } g2.g0.offThreadCompileScript(\"var ffbxcp = new ArrayBuffer(6); var ffbxcp_0 = new Int32Array(ffbxcp); v2 + this.p1;s0 = new String(b1);\"); } }");
/*fuzzSeed-71289653*/count=868; tryItOut("\"use strict\"; { void 0; minorgc(false); }");
/*fuzzSeed-71289653*/count=869; tryItOut("\"use strict\"; a1 = a2.slice(NaN, NaN, a1);");
/*fuzzSeed-71289653*/count=870; tryItOut("mathy3 = (function(x, y) { return Math.cosh(Math.imul(( - Math.atanh(((mathy2((x >>> 0), x) >>> 0) | 0))), Math.atan2(1/0, ((y ? y : ( + (1 >> y))) >>> 0)))); }); testMathyFunction(mathy3, [0, 2**53+2, -0, Number.MAX_VALUE, -(2**53-2), 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), 2**53, -Number.MIN_VALUE, 0x07fffffff, 0/0, -(2**53), 2**53-2, Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, -0x100000001, 0x0ffffffff, 0x080000000, 0x080000001, 0x100000000, -0x080000000, 1.7976931348623157e308, -1/0, Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, Math.PI, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-71289653*/count=871; tryItOut("\"use strict\"; ");
/*fuzzSeed-71289653*/count=872; tryItOut("mathy2 = (function(x, y) { return ( - Math.sqrt(( - Math.asinh((y | 0))))); }); testMathyFunction(mathy2, [-0x100000001, -0x080000000, -(2**53-2), 0x080000001, -(2**53+2), 2**53-2, 0x100000000, -0x080000001, -Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, 0x080000000, Number.MIN_VALUE, 1/0, 2**53, -0x100000000, 1, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 42, 0x0ffffffff, -1/0, 0.000000000000001, Math.PI, 0, 0x100000001]); ");
/*fuzzSeed-71289653*/count=873; tryItOut("this.v1 = b0.byteLength;");
/*fuzzSeed-71289653*/count=874; tryItOut("\"use strict\"; (\"\\u8807\");new RegExp(\"(?:\\\\w)\", \"g\");");
/*fuzzSeed-71289653*/count=875; tryItOut("/*MXX1*/o1 = g1.OSRExit.name;");
/*fuzzSeed-71289653*/count=876; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=877; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?=\\\\b))\", \"ym\"); var s = \"\\u0008\"; print(s.split(r)); ");
/*fuzzSeed-71289653*/count=878; tryItOut("{ sameZoneAs: (4277), cloneSingletons: false }");
/*fuzzSeed-71289653*/count=879; tryItOut("/*tLoop*/for (let z of /*MARR*/[new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), (void 0), (void 0), (void 0), new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), new Boolean(false), (void 0), (void 0), (void 0), (void 0), new Boolean(false)]) { var b = \neval(\"testMathyFunction(mathy3, [Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 0, -(2**53), 1, -Number.MIN_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, -(2**53-2), Math.PI, -0x100000000, 2**53, -1/0, 0x080000001, -Number.MAX_VALUE, -(2**53+2), -0x080000000, 0/0, 1/0, 0x0ffffffff, 0x080000000, 2**53-2, -0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, -0x080000001, -0x0ffffffff]); \", (/*FARR*/[z, x, this,  \"\" ].some |= x));a0 = a0.concat(o2.t2); }");
/*fuzzSeed-71289653*/count=880; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + mathy0((( - (Math.log10((-(2**53) >>> 0)) >>> 0)) | Math.atanh(mathy0(Math.fround((x >= y)), Math.fround(( + Math.fround((Math.round((Math.max(x, y) >>> 0)) >>> 0))))))), Math.cos(((Math.fround((y << Math.fround(Math.max(((-0x080000000 === ( + y)) | 0), x)))) ^ -0x100000000) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=881; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?:(?:\\\\2)(?=^|^)?)+|[^]|(?![^].|(?:^)){4,4}{3,})\", \"gy\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=882; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\\u0018\\u0018\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=883; tryItOut("this.g1.v2 = a2.length;");
/*fuzzSeed-71289653*/count=884; tryItOut("\"use strict\"; \"use asm\"; while((x) && 0){a1 + b1; }");
/*fuzzSeed-71289653*/count=885; tryItOut("\"use strict\"; var oqcpag = new ArrayBuffer(2); var oqcpag_0 = new Float32Array(oqcpag); print(oqcpag_0[0]); var oqcpag_1 = new Uint8ClampedArray(oqcpag); oqcpag_1[0] = -0.992; var oqcpag_2 = new Float32Array(oqcpag); print(oqcpag_2[0]); var oqcpag_3 = new Int16Array(oqcpag); print(oqcpag_3[0]); oqcpag_3[0] = -1; var oqcpag_4 = new Uint16Array(oqcpag); print(oqcpag_4[0]); oqcpag_4[0] = 1990472127; var oqcpag_5 = new Uint32Array(oqcpag); oqcpag_5[0] = -0; print(oqcpag_1[4]);var xvjban = new SharedArrayBuffer(12); var xvjban_0 = new Uint32Array(xvjban); var xvjban_1 = new Float32Array(xvjban); xvjban_1[0] = -23; var xvjban_2 = new Float32Array(xvjban); xvjban_2[0] = 18; with(((uneval(\"\\u1938\"))))7;");
/*fuzzSeed-71289653*/count=886; tryItOut("/*bLoop*/for (var zrijxd = 0; zrijxd < 63; window, ++zrijxd) { if (zrijxd % 6 == 2) { for (var p in s2) { m0.set(v2, {}.yoyo( /x/g )); } } else { i0 = m0.keys; }  } ");
/*fuzzSeed-71289653*/count=887; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-71289653*/count=888; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-71289653*/count=889; tryItOut("mathy4 = (function(x, y) { return ( ! (( ! Math.imul((mathy2(Math.fround(( ! x)), Math.fround((Math.pow(((( - (y >>> 0)) >>> 0) >>> 0), ((mathy3(x, (x | 0)) | 0) | 0)) >>> 0))) >>> 0), 2**53+2)) | 0)); }); testMathyFunction(mathy4, [-(2**53), 0x100000000, 0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, -0, -0x07fffffff, 0x07fffffff, 0.000000000000001, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0x100000000, 0x080000001, 0/0, -1/0, -(2**53-2), -Number.MAX_VALUE, 42, -(2**53+2), Math.PI, -Number.MIN_VALUE, 2**53-2, -0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -0x080000001, 0x080000000, 1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=890; tryItOut("testMathyFunction(mathy4, [0/0, -0x100000000, 1/0, 0x0ffffffff, -1/0, -(2**53), 0.000000000000001, -(2**53-2), -0x0ffffffff, Number.MAX_VALUE, -(2**53+2), -0x080000000, -0x080000001, Number.MIN_VALUE, 1, Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, 42, -0, -0x07fffffff, 2**53, Math.PI, 0x080000000, -Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 0]); ");
/*fuzzSeed-71289653*/count=891; tryItOut("v2 = t1.length;");
/*fuzzSeed-71289653*/count=892; tryItOut("print(a2);");
/*fuzzSeed-71289653*/count=893; tryItOut("Array.prototype.splice.call(a2, NaN, 8, m2);");
/*fuzzSeed-71289653*/count=894; tryItOut("\"use strict\"; for (var v of p1) { try { a1 = o0.o0.a0.map(this.f1, o0.g1, s1); } catch(e0) { } try { var asrxxn = new ArrayBuffer(16); var asrxxn_0 = new Uint16Array(asrxxn); print(asrxxn_0[0]); asrxxn_0[0] = ; var asrxxn_1 = new Uint8ClampedArray(asrxxn); for (var v of a2) { try { (\"\\u8BA7\"); } catch(e0) { } h2.toString = (function() { for (var v of e1) { try { m2.get(g0); } catch(e0) { } try { /*ADP-2*/Object.defineProperty(a0, 17, { configurable: true, enumerable: (asrxxn_0[10] % 4 == 3), get: (function() { try { v0 = null; } catch(e0) { } try { print(uneval(o2.o0)); } catch(e1) { } m1.has(v2); return v0; }), set: (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 4398046511105.0;\n    (Float64ArrayView[((((-0x86105*(0xfd2d2740))>>>(x)) < (((0x2918af94)+(0x3f7a0390))>>>((-0x8000000)-(0xffffffff)-(0xf8b26578))))-(((((4.722366482869645e+21) > (-129.0)))>>>(((32.0)))) <= (((0x4fb36231)+(0xf9ed08cc))>>>((0xfc01a3d9)+(0xfb07106f))))) >> 3]) = ((-0.03125));\n    return (((abs((((i2)) >> (((abs(((((0xfeaa19d6)) ^ ((0xff18b930)))))|0))-((((0xfd0c737a)*0x9d5fe)>>>(0x2b94f*(0x953d9a73)))))))|0) % (~((!(/*FFI*/ff((((-0x78308*(0xff0f81fe)) & ((0xfd4fd55e)))), ((~((i1)-(-0x8000000)))))|0))))))|0;\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; print(asrxxn_1[7]); }}, new SharedArrayBuffer(4096)) }); } catch(e1) { } try { e2 + ''; } catch(e2) { } /*RXUB*/var r = r2; var s = s2; print(uneval(r.exec(s))); print(r.lastIndex);  } return g2; }); }Array.prototype.forEach.call(a2, (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((!((((0x46372479)+(i1)-(i1)) | ((((0xf16828e3))>>>((0xb4e8e262))) / (0x0)))))+(!(0xfd815c61))+(i1)))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)), v1, g2.g1.o2.m1);\nv2 = evaluate(\"v0 = evalcx(\\\"/* no regression tests found */\\\", g1.g1);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: 'fafafa'.replace(/a/g, (1 for (x in []))) <<= (Object.defineProperty(x, \"toString\", ({writable: true, enumerable: (x % 25 != 7)}))), catchTermination: (x % 6 != 1), element: o1 }));\n } catch(e1) { } this.v2 = (m1 instanceof b2); }");
/*fuzzSeed-71289653*/count=895; tryItOut("");
/*fuzzSeed-71289653*/count=896; tryItOut("o0.m1.set(s2, this.__defineGetter__(\"x\", Function));");
/*fuzzSeed-71289653*/count=897; tryItOut("this.e0 = new Set(i2);");
/*fuzzSeed-71289653*/count=898; tryItOut("\"use strict\"; v2 = o2.a0.length;");
/*fuzzSeed-71289653*/count=899; tryItOut("\"use strict\"; {{ void 0; verifyprebarriers(); } return undefined;print(x); }");
/*fuzzSeed-71289653*/count=900; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return ( + ( + Math.fround(((((( ~ (mathy1(Math.fround(x), (x >>> 0)) >>> 0)) || x) >>> 0) % ((( - (((y == 1.7976931348623157e308) > y) | 0)) | 0) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=901; tryItOut("\"use strict\"; a1.pop();");
/*fuzzSeed-71289653*/count=902; tryItOut("\"use strict\"; var a = x, bwqabh, idxsmr, rlullf, x, wsghdt, wopxfc, x, x, d;t1 = new Float64Array(t0);");
/*fuzzSeed-71289653*/count=903; tryItOut("mathy0 = (function(x, y) { return (((Math.fround((( ! Math.hypot((( + x) >>> (Math.trunc((-0x080000001 | 0)) | 0)), x)) && ( - y))) ? Math.fround(Math.hypot(Math.fround((-0x0ffffffff ^ Math.fround((((y | 0) >> ((((-0x080000001 >>> 0) <= (x >>> 0)) >>> 0) | 0)) | 0)))), x)) : ((Math.exp((y | 0)) | 0) - Math.pow(Math.min(( ~ Math.fround(Math.sqrt(Math.fround(y)))), y), ( + Math.pow(2**53, ((Math.PI >>> 0) < (y >>> 0))))))) | 0) > (Math.min((Math.max(Math.fround(Math.max(Number.MIN_VALUE, ( + x))), Math.fround(Math.atan(Math.fround(Math.pow(Math.fround(( + ( - y))), Math.cos(x)))))) | 0), Math.max((Math.acos(( + Math.hypot(0, Math.fround((Math.fround(x) < Math.fround(x)))))) >>> 0), ( + (( + Math.log10((Math.fround((( ! x) >>> 0)) ** Math.fround(x)))) / ( ! x))))) | 0)); }); testMathyFunction(mathy0, [0x080000001, 1.7976931348623157e308, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, 1, -Number.MIN_SAFE_INTEGER, -1/0, -0x100000001, 0x100000000, -0, 2**53, 0, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), Math.PI, 1/0, 0x100000001, -(2**53), -(2**53-2), 0x07fffffff, 0/0, -0x100000000, -0x080000000, 0.000000000000001, 2**53-2, Number.MIN_VALUE, 0x080000000, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=904; tryItOut("Array.prototype.reverse.apply(a2, []);");
/*fuzzSeed-71289653*/count=905; tryItOut("testMathyFunction(mathy5, [-0x07fffffff, -(2**53), 0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -1/0, 1, Number.MAX_VALUE, 0x100000001, -Number.MAX_VALUE, -0, -(2**53+2), -0x100000001, 42, -(2**53-2), 0x080000000, 0, 0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, 2**53-2, Number.MIN_VALUE, 0/0, -0x080000000, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=906; tryItOut("\u3056 = new RegExp(\"\\\\3\", \"gim\"), d, NaN = -4( /x/ .values(), \"\\uB571\"), NaN, z = (let (x) new RegExp(\"(?=(^\\\\cS\\\\B{1,1}+)*?)\", \"yi\")), d, b = x, buziky, glycvh;g2.t1[({valueOf: function() { let (d) { o2 = Object.create((4277)); }return 4; }})] = p2;");
/*fuzzSeed-71289653*/count=907; tryItOut("for(let b of (((function ([y]) { })()).call(Math.min((({} = (window( \"\" , this))) | (({window:  /x/g }))), -12), ))) with({}) { let(z) { arguments = z;} } throw StopIteration;");
/*fuzzSeed-71289653*/count=908; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.log10(((Math.imul(( + Math.fround((( + ( + (x | 0))) ? y : Math.fround(2**53+2)))), ( + Math.hypot((Math.cos((((Math.fround(x) ? Math.acos(x) : x) | 0) >>> 0)) >>> 0), ( + Math.tanh(( + x)))))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy0, [(new Number(-0)), ({valueOf:function(){return '0';}}), '\\0', (new Boolean(true)), 1, [], true, null, ({toString:function(){return '0';}}), undefined, (new Number(0)), NaN, (new Boolean(false)), '0', -0, objectEmulatingUndefined(), '', 0.1, 0, /0/, [0], (new String('')), ({valueOf:function(){return 0;}}), (function(){return 0;}), '/0/', false]); ");
/*fuzzSeed-71289653*/count=909; tryItOut("e2.__proto__ = v2;");
/*fuzzSeed-71289653*/count=910; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=911; tryItOut("mathy4 = (function(x, y) { return (Math.atan2(Math.fround(((Math.max(( ~ Math.fround(( ! Math.fround(x)))), Math.fround(y)) >>> 0) ** (Math.fround((y == Math.fround(( + (x | ( + y)))))) >>> 0))), Math.asinh(Math.log(Math.atanh(y)))) >>> 0); }); ");
/*fuzzSeed-71289653*/count=912; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-71289653*/count=913; tryItOut("/*ADP-3*/Object.defineProperty(a2, 7, { configurable: (x % 3 == 0), enumerable: false, writable: true, value: i1 });");
/*fuzzSeed-71289653*/count=914; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ! (Math.fround(Math.sin(Math.fround(1.7976931348623157e308))) * Math.hypot(Math.cosh(Math.trunc((Math.max(y, 2**53) >>> 0))), x))); }); testMathyFunction(mathy2, [0x100000001, 0, 0x080000001, 0/0, -0x100000001, 0x100000000, 42, -0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), -1/0, 1, 1/0, 2**53-2, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -0x07fffffff, 2**53+2, -0x080000000, -0x080000001, -(2**53-2), -Number.MIN_VALUE, Number.MAX_VALUE, 2**53, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, Math.PI, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=915; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( ! Math.fround(Math.exp((mathy0((( ! (y >>> 0)) | 0), Math.min(x, Math.round(-Number.MIN_SAFE_INTEGER))) | 0))))); }); testMathyFunction(mathy2, [1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53), -(2**53-2), Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, -0x100000000, -(2**53+2), 0x080000001, -0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, -0, -0x080000000, 42, 0x100000001, 0x100000000, 0.000000000000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 1, -1/0, 0x07fffffff, 0x0ffffffff, 2**53, 2**53+2, -0x100000001]); ");
/*fuzzSeed-71289653*/count=916; tryItOut("var o2.v2 = Array.prototype.every.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float64ArrayView[4096]) = ((-4611686018427388000.0));\n    (Float64ArrayView[1]) = ((d1));\n    i0 = (0xf20e8d17);\n    return +((-1.0009765625));\n    d1 = (+ceil(((((-295147905179352830000.0)) / ((147573952589676410000.0))))));\n    return +((((-63.0)) - ((d1))));\n  }\n  return f; })(this, {ff: Boolean.prototype.valueOf}, new ArrayBuffer(4096))]);");
/*fuzzSeed-71289653*/count=917; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ceil = stdlib.Math.ceil;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+ceil(((((-((d1)))) - ((+abs(((+(0.0/0.0))))))))));\n    d1 = (d0);\n    (Int8ArrayView[4096]) = ((~((0x75a5b9a))) / (let (a = \"\\uAC4A\") this));\n    return +((d1));\n  }\n  return f; })(this, {ff: x => (new (Date.prototype.getHours)((x) = function(id) { return id }))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [/0/, (new Boolean(false)), undefined, (new Number(0)), null, (new Number(-0)), objectEmulatingUndefined(), '0', true, (new String('')), (new Boolean(true)), 0.1, -0, (function(){return 0;}), '', [], '\\0', NaN, ({toString:function(){return '0';}}), [0], ({valueOf:function(){return 0;}}), '/0/', ({valueOf:function(){return '0';}}), false, 1, 0]); ");
/*fuzzSeed-71289653*/count=918; tryItOut("\"use strict\"; var b, inmgiy, nrthyn;this.zzz.zzz;");
/*fuzzSeed-71289653*/count=919; tryItOut("with(window)v1 = p0[-15];\n/*RXUB*/var r = new RegExp(\"(?:\\\\2|(?:(?:[^]|\\\\W?+)*?))\", \"g\"); var s = \"\\n\\n\\n\"; print(s.search(r)); \n");
/*fuzzSeed-71289653*/count=920; tryItOut("\"use strict\"; a2.push(m1, m1);");
/*fuzzSeed-71289653*/count=921; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return mathy0(( + Math.asin(( + Math.log(Math.fround(Math.fround((Math.fround((mathy0(( + y), ( + x)) | 0)) % Math.fround(-Number.MAX_VALUE)))))))), Math.fround(Math.max((mathy0(Number.MAX_SAFE_INTEGER, y) | 0), ( + (Math.sign((y | 0)) | 0))))); }); testMathyFunction(mathy1, [42, 0x100000000, 0x100000001, 0x080000001, Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53, 0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -(2**53+2), 1/0, 0/0, 0, 2**53-2, -0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, -Number.MIN_VALUE, -0x080000000, -(2**53), -0x07fffffff, -Number.MAX_VALUE, -0x100000001, -0, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=922; tryItOut("a1.__proto__ = b2;");
/*fuzzSeed-71289653*/count=923; tryItOut("mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return (Math.asinh((((y || (x >>> 0)) >>> 0) >>> 0)) < ( - ( - Math.min(x, y)))); }); testMathyFunction(mathy2, [-0, Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 0x080000001, -0x080000000, 0.000000000000001, 2**53-2, -0x07fffffff, 0x07fffffff, 0/0, -1/0, 42, -Number.MIN_VALUE, Number.MIN_VALUE, 0, Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -(2**53+2), -(2**53-2), 1.7976931348623157e308, Math.PI, -Number.MAX_VALUE, -0x0ffffffff, -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), 1/0]); ");
/*fuzzSeed-71289653*/count=924; tryItOut("mathy3 = (function(x, y) { return ( + Math.log2(( + Math.min(( + ( ! x)), (Math.cos(( ! Math.atanh(y))) >>> 0))))); }); testMathyFunction(mathy3, [-0x080000000, -(2**53), -0x100000001, 0x0ffffffff, 2**53, 0x07fffffff, -0x07fffffff, 0x100000000, 2**53-2, -0x0ffffffff, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -0x100000000, Math.PI, 0x100000001, 1, 0, 0/0, -(2**53+2), 0.000000000000001, 0x080000000, 42, 1/0, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0x080000001, -0, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=925; tryItOut("\"use asm\"; e2.has(p0);");
/*fuzzSeed-71289653*/count=926; tryItOut("Array.prototype.shift.call(a1, x);");
/*fuzzSeed-71289653*/count=927; tryItOut("e2.delete(b2);");
/*fuzzSeed-71289653*/count=928; tryItOut("\"use strict\"; /*infloop*/for(let a = undefined; (/*RXUE*/new RegExp(\"\\\\xc0|(?:\\\\b|.(?=[^\\u1723-\\\\u720d\\\\W\\\\s\\\\ue2Ed-\\\\cV])){4}|(?=\\\\D|[^])\\\\bt{3,}\\\\1(?:.)*?|(?=[^\\\\d\\\\\\ua42e-\\u0097]|.)|\\\\B+|.|[^\\u0088-\\\\\\u2deb\\u00f6k-\\\\u00dB]*?*|\\\\D{2}\", \"ym\").exec(\"\")); (x = eval)) {v0 = ({a2:z2}); }");
/*fuzzSeed-71289653*/count=929; tryItOut("\"use strict\"; s0 = a2.join(s2, h0);");
/*fuzzSeed-71289653*/count=930; tryItOut("for (var p in e0) { try { g0.g0.toString = (function() { try { a0.shift(); } catch(e0) { } try { /*ODP-3*/Object.defineProperty(this.b0, \"__count__\", { configurable: -2916321980, enumerable: x, writable: false, value: s2 }); } catch(e1) { } i0.next(); return h2; }); } catch(e0) { } try { v2 = evaluate(\"function f1(b2)  { yield  /x/  } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: -0, noScriptRval: (x % 5 == 1), sourceIsLazy: true, catchTermination:  /x/g  })); } catch(e1) { } Object.seal(e2); }m0.has((x|=new (window)(-25,  /x/ )));");
/*fuzzSeed-71289653*/count=931; tryItOut("\"use strict\"; v1 = this.g1.eval(\"/* no regression tests found */\");function x(a, NaN = (4277)) { return (4277) } i1.__proto__ = h1;/*bLoop*/for (ockblf = 0; ockblf < 6; ++ockblf) { if (ockblf % 35 == 13) { var o2.m0 = new Map(o1.o1); } else { yield; }  } ");
/*fuzzSeed-71289653*/count=932; tryItOut("\"use strict\"; \"use asm\"; m2.set(s1, i0);");
/*fuzzSeed-71289653*/count=933; tryItOut("with(~(function ([y]) { })())true;");
/*fuzzSeed-71289653*/count=934; tryItOut("\"use strict\"; /*bLoop*/for (yekafu = 0; yekafu < 61; ++yekafu) { if (yekafu % 6 == 0) { with(x)v2 = g2.runOffThreadScript(); } else { /*tLoop*/for (let a of /*MARR*/[{}, x, x, [(void 0)], {}, x, [(void 0)], {}, x, [(void 0)], [(void 0)], x, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], x, x, [(void 0)], [(void 0)], x, [(void 0)], {}, {}, [(void 0)], {}, x, [(void 0)], x, x, x, x, [(void 0)]]) { v1 = (this.h2 instanceof a1);this.v0 = g0.g0.runOffThreadScript(); } }  } ");
/*fuzzSeed-71289653*/count=935; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.pow((( + (Math.log10(Math.fround((Math.asin((Math.exp(x) >>> 0)) >>> 0))) | 0)) >>> 0), (Math.fround(( ~ Math.fround(( + ( - ( + ((Math.atanh(((y || x) >>> 0)) >>> 0) / (((( + x) < ( + -Number.MIN_SAFE_INTEGER)) >>> 0) >> x)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x080000001, -0x0ffffffff, -0x100000000, 1/0, -0x080000000, -0x07fffffff, 0.000000000000001, 42, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, -1/0, 0, -(2**53-2), 0x080000000, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, 0x07fffffff, Math.PI, 2**53-2, 2**53, 0x080000001, 0x0ffffffff, 0/0, -0, -0x100000001, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, -Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-71289653*/count=936; tryItOut("yield;");
/*fuzzSeed-71289653*/count=937; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (( + (mathy0(Math.imul((y < ( ~ Math.sign(-(2**53-2)))), Math.imul((mathy0(Math.max(( + Math.asin(y)), (-(2**53) | y)), (( + (42 !== (Math.trunc(x) >>> 0))) | 0)) | 0), -Number.MIN_VALUE)), (Math.atan2((mathy2(0x080000001, (y >>> 0)) / -1/0), (Number.MAX_VALUE >>> 0)) | 0)) >>> 0)) >>> Math.atan2(( ! ( + (-(2**53-2) / 1))), (( ! x) >>> 0)))); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 0x100000000, 0/0, -Number.MIN_VALUE, 2**53-2, 2**53, -(2**53-2), Number.MAX_SAFE_INTEGER, 1, 0x080000001, Number.MAX_VALUE, 0x07fffffff, -0x080000001, -1/0, -0x07fffffff, -0, 0, -0x0ffffffff, 0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 0.000000000000001, -(2**53+2), 42, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, Math.PI, -0x100000001, 0x080000000, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53)]); ");
/*fuzzSeed-71289653*/count=938; tryItOut("g0.toString = (function(j) { f1(j); });");
/*fuzzSeed-71289653*/count=939; tryItOut("v2 = r2.compile;");
/*fuzzSeed-71289653*/count=940; tryItOut("mathy4 = (function(x, y) { return (Math.log(( + (Math.sinh((Math.sqrt(((((y | 0) <= (y | 0)) | 0) >>> 0)) >>> 0)) >>> 0))) | 0); }); ");
/*fuzzSeed-71289653*/count=941; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.acos(Math.abs(y)) >>> 0) <= (( ! mathy3(Math.fround(( + Math.imul(( + x), (( + y) > (Math.sin((y >>> 0)) >>> 0))))), Math.fround(Math.fround(( + Math.fround((( ! (Math.round((y | 0)) | 0)) >>> 0))))))) >>> 0)); }); testMathyFunction(mathy5, [-0x100000001, -0x07fffffff, -(2**53+2), 42, 0x080000000, -1/0, 2**53, -0, 0x07fffffff, -(2**53), 0.000000000000001, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, -0x080000001, 0x0ffffffff, 0/0, -(2**53-2), 0x100000000, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000001, 0, Number.MAX_VALUE, 2**53-2, 1/0, -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000]); ");
/*fuzzSeed-71289653*/count=942; tryItOut("f0.__proto__ = m1;");
/*fuzzSeed-71289653*/count=943; tryItOut("testMathyFunction(mathy4, [-0x080000000, -(2**53-2), -0x080000001, Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, Math.PI, 0/0, -0x0ffffffff, 0.000000000000001, -0, 0x080000001, -(2**53), 0x07fffffff, Number.MAX_VALUE, -(2**53+2), 2**53, -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, Number.MIN_VALUE, 0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000000, -Number.MAX_VALUE, 0x100000001, -0x100000001, -1/0, 42, 1/0]); ");
/*fuzzSeed-71289653*/count=944; tryItOut("\"use strict\"; m1.has(p2);");
/*fuzzSeed-71289653*/count=945; tryItOut("this.v0 = o0.g1.g0.runOffThreadScript();");
/*fuzzSeed-71289653*/count=946; tryItOut("testMathyFunction(mathy1, [-Number.MIN_VALUE, -0x080000001, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, -0, 0x100000001, 2**53, -0x07fffffff, 1, 42, 2**53-2, 0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, -(2**53+2), 0/0, -1/0, 1/0, 0x07fffffff, 0.000000000000001, 0x100000000, 0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI]); ");
/*fuzzSeed-71289653*/count=947; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((!((0xd374db4) != (((yield allocationMarker())()))))))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-0x100000001, -0x100000000, 42, 1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000000, 0x080000001, Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 0/0, -0, 2**53-2, Math.PI, Number.MIN_VALUE, 1.7976931348623157e308, -0x080000000, 0, 2**53+2, -(2**53), -0x080000001, 0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, 1, -Number.MAX_VALUE, 0x0ffffffff, -(2**53+2), 0.000000000000001, -Number.MIN_VALUE, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=948; tryItOut("\"use strict\"; a0.push(s1);");
/*fuzzSeed-71289653*/count=949; tryItOut("const v0 = a0.reduce, reduceRight((function(j) { if (j) { try { /*MXX1*/o2 = g1.RegExp.prototype.ignoreCase; } catch(e0) { } try { for (var v of g2.f1) { try { print(f2); } catch(e0) { } i2 + o0.o0.e0; } } catch(e1) { } o2.s2 += s2; } else { try { v2 = Object.prototype.isPrototypeOf.call(i2, e1); } catch(e0) { } try { s0 += 'x'; } catch(e1) { } /*ADP-3*/Object.defineProperty(a1, 2, { configurable: (4277), enumerable:  /x/g , writable: 20 in false <<= (w = (4277)), value: h0 }); } }), g2);");
/*fuzzSeed-71289653*/count=950; tryItOut("mathy2 = (function(x, y) { return ( + ( + (( + mathy0((Math.asinh(( + y)) >>> Math.atan2(y, Math.min(x, -0x07fffffff))), (Math.asinh((Math.imul(Math.fround(Math.imul(0x07fffffff, ( + Math.cbrt(( + x))))), Math.fround(( + ( + ( + y))))) >>> 0)) >>> 0))) >> ( - mathy0((( + (mathy1(x, (x | 0)) | 0)) | 0), y))))); }); testMathyFunction(mathy2, [-1/0, -Number.MIN_VALUE, -0x100000000, 42, 0, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, 0x0ffffffff, 2**53-2, 2**53, 0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, 0/0, -0, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000001, -(2**53), Math.PI, -0x100000001, -0x07fffffff, -(2**53+2), 0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1, 2**53+2, 0x100000000]); ");
/*fuzzSeed-71289653*/count=951; tryItOut("Object.defineProperty(this, \"i0\", { configurable: true, enumerable: /*UUV1*/(window.setUTCDate = let (x = this.__defineSetter__(\"eval\", Object.prototype.toLocaleString), aoajvp, x = true, x, mfylfc, \u3056, wkzwug, cpzuzq, x, imdhff) /*RXUE*/new RegExp(\"(?:[^])\", \"gyim\").exec( /x/g )),  get: function() {  return new Iterator(s0, true); } });");
/*fuzzSeed-71289653*/count=952; tryItOut("/*RXUB*/var r = /(?:(?!(\\u0b24)))([\\xC1][\\fB\\s\u0406-\u6475]([^\\d]){2}{2}|[^]?)|((\\B{255})?)/g; var s = \"\"; print(s.replace(r, window, \"gyim\")); ");
/*fuzzSeed-71289653*/count=953; tryItOut("/*tLoop*/for (let w of /*MARR*/[function(){}, new Boolean(false), new Boolean(false), new Boolean(false), function(){}, function(){}, new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(false), function(){}, 0xB504F332, new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(false), new Boolean(false), 0xB504F332, function(){}, 0xB504F332, function(){}, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, function(){}, 0xB504F332, function(){}, new Boolean(false), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(false), function(){}, function(){}, new Boolean(false), 0xB504F332, new Boolean(false), 0xB504F332, new Boolean(false), new Boolean(false), new Boolean(false), 0xB504F332, 0xB504F332, new Boolean(false), 0xB504F332, new Boolean(false), 0xB504F332, function(){}, function(){}, 0xB504F332, function(){}, 0xB504F332, 0xB504F332, function(){}, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, function(){}, new Boolean(false), 0xB504F332, function(){}, function(){}, new Boolean(false), new Boolean(false), function(){}, function(){}, new Boolean(false), 0xB504F332, function(){}, function(){}, function(){}, function(){}, 0xB504F332, function(){}, function(){}, function(){}, function(){}, 0xB504F332, new Boolean(false), function(){}, function(){}, function(){}]) { v1 = g1.eval(\"mathy5 = (function(x, y) { return ( + ( + ( + ((Math.fround(x) != (mathy4(((Math.hypot(-Number.MIN_VALUE, x) >>> 0) | 0), Math.trunc((Math.atan((x | 2**53)) >>> 0))) | 0)) >>> 0)))); }); testMathyFunction(mathy5, /*MARR*/[ /x/g ,  \\\"\\\" , null,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  \\\"\\\" ,  /x/g , null, null, null]); \");print( /x/g );function e(x, []) { return eval(\"/* no regression tests found */\", ((1 for (x in [])))) } switch(/(?:\\r)/) { default: g0.offThreadCompileScript(\"t0.set(this.t2, 7);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  /x/ , noScriptRval: -15, sourceIsLazy: false, catchTermination: false }));break; case \"\\u1DF3\": o1 = new Object;break;  } }");
/*fuzzSeed-71289653*/count=954; tryItOut("const qxbltu, d =  /x/g ;/*hhh*/function fxdayo(c, NaN){\"\\uDCCA\";}/*iii*/throw -4;");
/*fuzzSeed-71289653*/count=955; tryItOut("e2.delete(g0.o1.m2);");
/*fuzzSeed-71289653*/count=956; tryItOut("m1.has(f0);");
/*fuzzSeed-71289653*/count=957; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!\\b)|\\w|\\b\\S\\d*(?![])+?/yi; var s =  /x/g ; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=958; tryItOut("Object.prototype.unwatch.call(i0, \"constructor\");");
/*fuzzSeed-71289653*/count=959; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.imul(26, -27); }); ");
/*fuzzSeed-71289653*/count=960; tryItOut("t1.set(a0, ({valueOf: function() { (window);return 11; }}));print(x);");
/*fuzzSeed-71289653*/count=961; tryItOut("for (var v of h0) { Array.prototype.shift.apply(a1, []); }");
/*fuzzSeed-71289653*/count=962; tryItOut("e2[\"valueOf\"] = o2.b0;");
/*fuzzSeed-71289653*/count=963; tryItOut("f2(f1);");
/*fuzzSeed-71289653*/count=964; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, 0x100000001, Math.PI, 0/0, 2**53, -0, 1/0, -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -0x0ffffffff, 2**53+2, 0.000000000000001, -(2**53+2), 2**53-2, -1/0, -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, 0x100000000, 0x080000001, -0x080000000, 42, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=965; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((( + (Math.min(((( ~ (( ~ x) | 0)) / (( + (y >>> 0)) >>> 0)) | 0), Math.fround(Math.ceil((( + y) >>> 0)))) | 0)) > Math.fround(Math.min((mathy0(Math.fround((y ? Math.fround(Math.fround(Math.pow(Math.fround(( + (( + ((y >> -(2**53+2)) | 0)) === ( + (Math.tanh(x) >>> 0))))), Math.fround((Math.acos((0/0 | 0)) | 0))))) : ( + x))), (( - ((Math.cbrt((x | 0)) != y) | 0)) | 0)) >>> 0), (Math.fround(Math.cos(Math.fround((y === (Math.imul((( ~ x) >>> 0), x) | 0))))) >>> 0)))) >>> 0); }); testMathyFunction(mathy3, [0, -0x0ffffffff, -(2**53+2), -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, 2**53+2, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, 1, 0x100000001, 0x080000000, 2**53-2, 0x0ffffffff, -1/0, 0x080000001, -(2**53), 0/0, 2**53, -0x080000000, -(2**53-2), -0, -0x07fffffff, Math.PI, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000000, 1/0]); ");
/*fuzzSeed-71289653*/count=966; tryItOut("\"use strict\"; undefined;function z(z)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      {\n        i0 = (i0);\n      }\n    }\n    d1 = (18446744073709552000.0);\n    d1 = (+(0.0/0.0));\n    return (((0xf1d1f4d7)))|0;\n  }\n  return f;Array.prototype.splice.call(o2.a1, NaN, 0);");
/*fuzzSeed-71289653*/count=967; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + ( ~ (Math.trunc((Math.sqrt(Math.pow((Math.min((0x100000000 >>> 0), (y >>> 0)) >>> 0), Math.fround(( - ( ~ ( - x)))))) >>> 0)) | 0))); }); testMathyFunction(mathy0, [0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, 0, -(2**53), -0x07fffffff, 0x080000000, Number.MAX_VALUE, -0x080000000, -0x100000000, 1/0, 2**53, 0x100000000, -(2**53+2), 2**53+2, -0x100000001, 1, -1/0, -0, 0.000000000000001, 42, Number.MAX_SAFE_INTEGER, Math.PI, 0x0ffffffff, -(2**53-2), Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-71289653*/count=968; tryItOut("let \u3056, x = /*MARR*/[new Boolean(false), {}, this, (-1/0), this, (-1/0), (-1/0), this, (-1/0), (-1/0), {}, arguments, this, new Boolean(false), this, arguments, (-1/0), new Boolean(false), new Boolean(false), {}, new Boolean(false), this, this, new Boolean(false), arguments, this, new Boolean(false), this, arguments, {}, arguments, (-1/0), this, (-1/0), new Boolean(false), (-1/0), (-1/0), this, {}, {}, arguments, {}, new Boolean(false), (-1/0), new Boolean(false), this, (-1/0), {}, arguments, {}, (-1/0), arguments, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, new Boolean(false), (-1/0), new Boolean(false), new Boolean(false), arguments, this, this, this, this, this, this, this, this, this, this, this, this, this, this, (-1/0), this, this, this, this, arguments, new Boolean(false), new Boolean(false), this, arguments, {}, (-1/0), new Boolean(false), (-1/0), arguments, this, (-1/0), new Boolean(false), this, this, (-1/0), arguments, this, new Boolean(false), arguments, new Boolean(false), this, {}, {}, this, this, new Boolean(false), {}, (-1/0), {}, (-1/0), this, arguments, new Boolean(false), (-1/0), this].some(Math.ceil, (Math.pow(11, (NaN = eval)))), eval = Math.atan2(-5, this), z = -17, eval, e =  /x/g  == 17;/*RXUB*/var r = /(?:(?!(?!\\3)))/g; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=969; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\W\", \"g\"); var s = \"a\"; print(s.replace(r, '')); \nfor (var v of v2) { s1 += s0; }\n");
/*fuzzSeed-71289653*/count=970; tryItOut("x = (4277);/*RXUB*/var r = /(?![]|((?:\\B[4\\D\\d\u00ad]+?))?(\\s){4,}(?!^)*{3}(?:\\D|(?!\\b^)){4}|(?=\\3))/gyi; var s = \"______\"; print(s.split(r)); ");
/*fuzzSeed-71289653*/count=971; tryItOut("this.v0 = this.a1.length;");
/*fuzzSeed-71289653*/count=972; tryItOut("/*tLoop*/for (let d of /*MARR*/[false, false, false, undefined, false, false]) { print(d); }");
/*fuzzSeed-71289653*/count=973; tryItOut("m1.delete(g2.i0);");
/*fuzzSeed-71289653*/count=974; tryItOut("(window);b =  '' ;");
/*fuzzSeed-71289653*/count=975; tryItOut("\"use strict\"; b1 + '';");
/*fuzzSeed-71289653*/count=976; tryItOut("/*bLoop*/for (let pfnotq = 0; pfnotq < 53; ++pfnotq) { if (pfnotq % 113 == 52) { t0 = t2.subarray(null); } else { yield window; }  } ");
/*fuzzSeed-71289653*/count=977; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=978; tryItOut("\"use strict\"; switch(Map(false)) { default:  /x/ ;let b = (x === x);m1.set(x, s0); for (b of \"\\u8974\") let e2 = new Set;for (var p in v1) { Object.prototype.unwatch.call(e1, \"d\"); }break; /*vLoop*/for (var uzyhdq = 0; uzyhdq < 47; ++uzyhdq) { const e = uzyhdq; {} } break; break;  }");
/*fuzzSeed-71289653*/count=979; tryItOut("/*MXX1*/o0 = o0.g0.String.prototype.substr;");
/*fuzzSeed-71289653*/count=980; tryItOut("\"use strict\"; var svtlrt, \u3056 = function ([y]) { }, z, y, x;{}");
/*fuzzSeed-71289653*/count=981; tryItOut("var dmkkws = new SharedArrayBuffer(4); var dmkkws_0 = new Uint8Array(dmkkws); print(dmkkws_0[0]); var dmkkws_1 = new Uint32Array(dmkkws); print(dmkkws_1[0]); dmkkws_1[0] = 3; var dmkkws_2 = new Uint16Array(dmkkws); print(dmkkws_2[0]); dmkkws_2[0] = -8; var dmkkws_3 = new Uint16Array(dmkkws); dmkkws_3[0] = -29; f2.__iterator__ = (function() { for (var j=0;j<2;++j) { g2.f2(j%5==1); } });");
/*fuzzSeed-71289653*/count=982; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - (Math.imul(Math.fround((Math.imul(Math.max(y, ( + -0)), (( ! (x | 0)) | 0)) != Math.atan((((-Number.MIN_VALUE | 0) ? (y | 0) : (x | 0)) | 0)))), (((mathy0((Math.asin((y ** y)) >>> 0), (y >>> 0)) >>> 0) > ( + Math.fround(Math.hypot(( - -Number.MIN_SAFE_INTEGER), Math.fround(x))))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x100000001, Math.PI, 0/0, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, 42, 1.7976931348623157e308, 2**53-2, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), 1/0, 1, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, 0.000000000000001, -0, 2**53+2, -0x0ffffffff, 2**53, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, 0x080000001, -0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), -(2**53)]); ");
/*fuzzSeed-71289653*/count=983; tryItOut("var sihhwb = new ArrayBuffer(32); var sihhwb_0 = new Uint16Array(sihhwb); print(sihhwb_0[0]); var sihhwb_1 = new Float32Array(sihhwb); var sihhwb_2 = new Int32Array(sihhwb); sihhwb_2[0] = -9; var sihhwb_3 = new Float64Array(sihhwb); sihhwb_3[0] = -28; var sihhwb_4 = new Float32Array(sihhwb); var sihhwb_5 = new Int16Array(sihhwb); print(sihhwb_5[0]); sihhwb_5[0] = 22; var sihhwb_6 = new Uint8ClampedArray(sihhwb); print(sihhwb_6[0]); sihhwb_6[0] = -25; var sihhwb_7 = new Int16Array(sihhwb); print(sihhwb_7[0]); var sihhwb_8 = new Int16Array(sihhwb); print(sihhwb_8[0]); sihhwb_8[0] = 24; var sihhwb_9 = new Int16Array(sihhwb); print(sihhwb_9[0]); sihhwb_9[0] = -7; var sihhwb_10 = new Uint8ClampedArray(sihhwb); sihhwb_10[0] = 12; var sihhwb_11 = new Float32Array(sihhwb); sihhwb_11[0] = -5; var sihhwb_12 = new Uint8ClampedArray(sihhwb); sihhwb_12[0] = -24; o0 = this.g0.s0.__proto__;s2 += 'x';/*infloop*/for(let this.__proto__ in ((Math.min(-19, 24))(\"\\u9F2F\")))print();print(sihhwb_8[0]);m2.set(v1, g0.h0);/* no regression tests found */");
/*fuzzSeed-71289653*/count=984; tryItOut("mathy0 = (function(x, y) { return (Math.atan2(( + Math.cbrt((( + ( + ( ~ ( + Math.min(x, 42))))) | 0))), ( + (((( + Math.min(( - ( + Math.max(( + y), Math.cosh(Math.fround(y))))), (Math.fround(( ! 1.7976931348623157e308)) ? ( + (( + y) % ( + Math.fround(( - Math.fround(y)))))) : y))) >>> 0) != Math.max(Math.imul(-0x0ffffffff, Math.exp(y)), ( + (( + (((y >>> y) | 0) - (y | 0))) && Math.ceil((x ** y)))))) >>> 0))) | 0); }); ");
/*fuzzSeed-71289653*/count=985; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var cos = stdlib.Math.cos;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -8191.0;\n    var d5 = 18014398509481984.0;\n    var d6 = -4611686018427388000.0;\n    i2 = (i3);\n    return +((d6));\n    i2 = (i2);\n    return +(((0xfb00e08b) ? (+cos(((d4)))) : (((+(-1.0/0.0))) * ((Float32ArrayView[4096])))));\n  }\n  return f; })(this, {ff: Number.prototype.toLocaleString}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, -0, -0x100000000, -Number.MAX_VALUE, -0x07fffffff, 2**53+2, -1/0, 1/0, 0x080000001, -0x080000001, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 0x100000001, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53), 0x100000000, 2**53-2, Number.MAX_VALUE, 2**53, -0x100000001, 0x07fffffff, 0x080000000, 0/0, 0]); ");
/*fuzzSeed-71289653*/count=986; tryItOut("if(z) { if (timeout(1800)) {/*ODP-3*/Object.defineProperty(s1, \"0\", { configurable: true, enumerable: (x % 45 == 16), writable: (x % 2 != 1), value: g1 }); } else {yield; }}");
/*fuzzSeed-71289653*/count=987; tryItOut("s1 = Array.prototype.join.apply(o1.g2.g0.a1, [s2, x, o2.o0]);");
/*fuzzSeed-71289653*/count=988; tryItOut("/*ADP-1*/Object.defineProperty(a0, x, ({}));");
/*fuzzSeed-71289653*/count=989; tryItOut("\"use strict\"; with((Object.defineProperty(d, /((?!\u008f)|(\\u7F41?|[^]{1}|\\W|[^]|\\b{3,4}))/gi, ({value: /*MARR*/[/(?=.\\2)|^|.|\\2\\B*{4}/gm, 0x100000000,  \"use strict\" , /(?=.\\2)|^|.|\\2\\B*{4}/gm, 0x100000000, {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm, {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm, /(?=.\\2)|^|.|\\2\\B*{4}/gm, {x:3}, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, {x:3}, 0x100000000, 0x100000000, /(?=.\\2)|^|.|\\2\\B*{4}/gm, /(?=.\\2)|^|.|\\2\\B*{4}/gm, {x:3}, {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm,  \"use strict\" , 0x100000000, {x:3}, {x:3},  \"use strict\" ,  \"use strict\" , 0x100000000, {x:3}, {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm, {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm, 0x100000000,  \"use strict\" , /(?=.\\2)|^|.|\\2\\B*{4}/gm, 0x100000000,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , {x:3}, 0x100000000, /(?=.\\2)|^|.|\\2\\B*{4}/gm,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , {x:3}, {x:3}, {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm, /(?=.\\2)|^|.|\\2\\B*{4}/gm, {x:3},  \"use strict\" ,  \"use strict\" , {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm, /(?=.\\2)|^|.|\\2\\B*{4}/gm, 0x100000000, {x:3}, 0x100000000,  \"use strict\" ,  \"use strict\" , {x:3},  \"use strict\" , /(?=.\\2)|^|.|\\2\\B*{4}/gm, 0x100000000, 0x100000000, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, 0x100000000, {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm, {x:3},  \"use strict\" , {x:3}, 0x100000000, {x:3},  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , 0x100000000,  \"use strict\" , /(?=.\\2)|^|.|\\2\\B*{4}/gm, 0x100000000, 0x100000000, {x:3}, {x:3}, /(?=.\\2)|^|.|\\2\\B*{4}/gm,  \"use strict\" , 0x100000000,  \"use strict\" , /(?=.\\2)|^|.|\\2\\B*{4}/gm, 0x100000000, {x:3},  \"use strict\" ,  \"use strict\" ].filter, writable: 8, configurable: true, enumerable: (x % 14 == 6)}))))/*vLoop*/for (likyna = 0; likyna < 66; ++likyna) { c = likyna; print([]); } ");
/*fuzzSeed-71289653*/count=990; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ~ Math.fround(Math.ceil(( + 2**53)))) >>> 0); }); testMathyFunction(mathy3, [(new Number(-0)), null, (new Number(0)), (new Boolean(false)), ({toString:function(){return '0';}}), '', (new String('')), ({valueOf:function(){return 0;}}), 0.1, -0, 1, true, undefined, [0], '0', [], '\\0', (new Boolean(true)), ({valueOf:function(){return '0';}}), /0/, NaN, objectEmulatingUndefined(), 0, false, (function(){return 0;}), '/0/']); ");
/*fuzzSeed-71289653*/count=991; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[new RegExp(\"(?:(?=\\\\1)+?)*|.*\", \"y\"), new String(''), new String(''), new String(''), new RegExp(\"(?:(?=\\\\1)+?)*|.*\", \"y\"), function(){}, new RegExp(\"(?:(?=\\\\1)+?)*|.*\", \"y\"), new String(''), new RegExp(\"(?:(?=\\\\1)+?)*|.*\", \"y\"), function(){}, (-1/0), function(){}, function(){}, (-1/0)]) { /*RXUB*/var r = new RegExp(\"\\\\r\", \"gym\"); var s = \"-\"; print(r.exec(s));  }");
/*fuzzSeed-71289653*/count=992; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[new Boolean(true), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), new Boolean(true), new Boolean(true), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Boolean(true), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(true), new Number(1.5), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Boolean(true), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), new Number(1.5), new Boolean(true), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), new Number(1.5), new Number(1.5), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Number(1.5)]) { Array.prototype.sort.call(a2, (function(j) { if (j) { try { Object.defineProperty(this, \"a0\", { configurable: x = x * x; var r0 = e & 1; x = x / x; var r1 = 2 % e; var r2 = 9 | r1; var r3 = e ^ 5; var r4 = 1 ^ r2; var r5 = r2 + r3; var r6 = 8 + r2; var r7 = 3 % r4; var r8 = 9 | e; var r9 = r8 ^ r5; var r10 = 0 + r9; r4 = r9 * 4; r4 = 7 | r7; var r11 = r6 - r1; var r12 = r3 | 9; e = r6 | 2; var r13 = r3 ^ 1; var r14 = 4 * 7; var r15 = r12 % r13; var r16 = r3 * 0; var r17 = r8 % 3; var r18 = r7 / r5; var r19 = r14 - r3; var r20 = r13 * 2; var r21 = 0 + r6; r17 = r4 / r8; var r22 = r10 ^ 7; var r23 = 4 / 4; r17 = r16 & r0; var r24 = 4 * r23; var r25 = r24 - r15; var r26 = 9 | 9; var r27 = 2 / r17; var r28 = r3 % r13; var r29 = r28 | 2; r14 = r28 * 6; var r30 = r18 / 2; var r31 = r4 * r16; var r32 = r13 * 2; var r33 = 9 * r24; r22 = r32 % r27; var r34 = r7 / r27; var r35 = r17 - 5; r14 = 4 * 4; var r36 = r16 | r30; var r37 = r4 - r28; var r38 = r4 / r5; var r39 = r26 * r28; var r40 = r4 ^ 5; r1 = r32 & r4; var r41 = r7 * r31; var r42 = 8 ^ r2; r30 = 7 | r14; var r43 = r16 / r38; var r44 = r7 * r9; r4 = 2 & r17; var r45 = r27 * r10; r44 = r1 ^ r35; r5 = r6 | r26; r20 = r17 / r45; var r46 = r28 % r18; var r47 = r25 + 4; var r48 = x * r42; var r49 = r47 / 1; var r50 = 9 * r44; x = r22 / r50; var r51 = r39 - r19; print(r33); var r52 = r17 & r16; var r53 = r0 ^ r43; var r54 = r28 * r31; r28 = r28 ^ r10; r17 = 3 + r40; var r55 = r14 / r31; var r56 = r28 ^ r26; var r57 = r6 * r20; var r58 = 9 & r25; e = r32 % r45; var r59 = r32 * r14; var r60 = r57 * r32; var r61 = r31 - r56; print(r27); var r62 = r38 % r60; var r63 = 0 * 7; var r64 = r28 & r9; var r65 = r36 % r44; var r66 = r59 ^ r47; var r67 = r35 | r27; var r68 = r63 % r13; r33 = 3 % r53; var r69 = r23 + r6; var r70 = r12 - x; var r71 = r0 | r68; r33 = r56 | 8; var r72 = 1 / 8; r7 = r46 | 2; var r73 = r31 % e; var r74 = r39 ^ 0; r17 = r67 * 8; r19 = r52 + r51; r70 = r54 / 5; var r75 = r25 / r0; var r76 = r63 - r14; var r77 = r13 ^ r43; r53 = 5 | 8; print(r18); var r78 = r69 / r72; var r79 = r26 | r71; var r80 = r34 - 9; print(r69); var r81 = 1 - 6; var r82 = r13 + 7; var r83 = 8 | r27; var r84 = r3 & 7; var r85 = r45 ^ 9; print(r46); r4 = r37 * r22; var r86 = r24 % r9; print(r14); var r87 = r28 & r48; var r88 = 2 ^ 8; var r89 = r29 + r72; r22 = r83 % r67; var r90 = 4 % r16; var r91 = r33 - r32; var r92 = r60 * r28; var r93 = 5 - r31; var r94 = r14 + r37; var r95 = 8 & r94; var r96 = r29 | r84; var r97 = r59 - 8; var r98 = r68 | 0; var r99 = r8 | 8; var r100 = r98 / 8; var r101 = r43 & r21; var r102 = 8 / 0; var r103 = r54 - r89; var r104 = 4 & r16; var r105 = r20 | r97; var r106 = 6 ^ r99; var r107 = r19 ^ 4; var r108 = 1 | r22; var r109 = 1 % r6; var r110 = 2 % 4; var r111 = r43 + r90; print(r89); var r112 = r79 / r19; print(x); r99 = r43 + 1; print(r55); var r113 = r94 / r108; r91 = 7 ^ r44; var r114 = 0 - 4; var r115 = r80 - r76; var r116 = r13 / r65; var r117 = r107 & r66; r67 = r94 & r18; var r118 = r114 + r113; r111 = 6 - r38; var r119 = r67 ^ 0; var r120 = 0 | r82; var r121 = r93 / 2; var r122 = r13 ^ r36; var r123 = r29 - 0; r59 = 5 % 9; var r124 = r19 - r61; var r125 = r8 + 4; var r126 = r78 / 9; var r127 = r71 % r54; , enumerable: true,  get: function() { v0 = null; return o1.a0.filter(o0); } }); } catch(e0) { } Array.prototype.splice.call(a2, NaN, 12, o0, g0.g1, new RegExp(\"\\\\1\", \"gi\"), i1); } else { try { (void schedulegc(g2.g0)); } catch(e0) { } t1[12] = t1; } })); }");
/*fuzzSeed-71289653*/count=993; tryItOut("\"use asm\"; a2 = a2.slice(5, 4);");
/*fuzzSeed-71289653*/count=994; tryItOut("\"use strict\"; h2.enumerate = f1;/*tLoop*/for (let x of /*MARR*/[let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), 0, 0, (void 0), (void 0), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), 0, 0, (void 0), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), 0, let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), (void 0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), (void 0), let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), (void 0), 0, 0, (void 0), 0, 0, 0, 0, let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh)), 0, (void 0), (void 0), (void 0), 0, let (y = (4277)) (4277)(y.__defineGetter__(\"y\", Math.sinh))]) { if((void options('strict_mode'))) { if (x) {o2.i1 + '';for (var p in i2) { try { h2 = x; } catch(e0) { } try { print(b0); } catch(e1) { } try { a1 + f0; } catch(e2) { } Object.preventExtensions(h2); } } else {v1 = undefined; }} }");
/*fuzzSeed-71289653*/count=995; tryItOut("print(w -=  '' );");
/*fuzzSeed-71289653*/count=996; tryItOut("let (window = allocationMarker(), w = (4277), jwybob, jffmco, c = (4277), zihuof, bzqisk, x = (let (b =  /x/ ) null)) { v0 = a2.length; }");
/*fuzzSeed-71289653*/count=997; tryItOut("\"use strict\"; (-16);Array.prototype.forEach.apply(a1, [(function(a0, a1, a2, a3, a4, a5, a6, a7) { return a6; })]);t2 = new Uint16Array(13);");
/*fuzzSeed-71289653*/count=998; tryItOut("\"use strict\"; \"use asm\"; this.a2.sort(t0);");
/*fuzzSeed-71289653*/count=999; tryItOut("testMathyFunction(mathy1, [[0], '\\0', (new Number(0)), ({valueOf:function(){return '0';}}), '', (new Boolean(false)), ({toString:function(){return '0';}}), null, '/0/', false, 0.1, objectEmulatingUndefined(), 0, (function(){return 0;}), undefined, ({valueOf:function(){return 0;}}), true, /0/, (new String('')), 1, [], (new Boolean(true)), NaN, (new Number(-0)), '0', -0]); ");
/*fuzzSeed-71289653*/count=1000; tryItOut("\"use strict\"; /*infloop*/M:do {v0 = evaluate(\"m0 + '';\", ({ global: g1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 26 == 2), noScriptRval: (x % 5 == 4), sourceIsLazy: false, catchTermination: false }));print(x); } while((( /x/ )()));");
/*fuzzSeed-71289653*/count=1001; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + mathy3(( + (((( ! mathy0(x, (x | 0))) | 0) * ((Math.min((( + (y >>> 0)) | 0), (( - (( ~ (Math.fround(y) >> x)) | 0)) >>> 0)) >>> 0) | 0)) | 0)), ( + Math.pow((mathy3((Math.imul(Math.fround(Math.fround((( + (((x >>> 0) & (y >>> 0)) >>> 0)) * ( + (( + (Math.atan2(y, y) | 0)) | 0))))), ( + Math.fround((-(2**53-2) - ( + (( - (y | 0)) | 0)))))) | 0), Math.fround(Math.fround(Math.atanh(Math.fround((Math.min(2**53, (y - x)) | 0)))))) | 0), (mathy3((Math.tan((1.7976931348623157e308 | 0)) | 0), (((y >> ( + Math.max(x, y))) ? ( + (Math.max(y, x) , ( + x))) : y) >>> 0)) >>> 0))))); }); testMathyFunction(mathy4, [false, (new Boolean(true)), 1, ({toString:function(){return '0';}}), '', undefined, (function(){return 0;}), '\\0', 0.1, -0, objectEmulatingUndefined(), (new Number(0)), true, (new Number(-0)), /0/, (new Boolean(false)), null, 0, '0', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), NaN, (new String('')), [], [0], '/0/']); ");
/*fuzzSeed-71289653*/count=1002; tryItOut("s0 += s1;");
/*fuzzSeed-71289653*/count=1003; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.exp((Math.log1p(Math.fround(( - (Math.atan2(x, ( + y)) - x)))) >>> 0)); }); testMathyFunction(mathy4, [1, objectEmulatingUndefined(), 0, (new Boolean(false)), true, null, (new Boolean(true)), [], '', (function(){return 0;}), ({valueOf:function(){return 0;}}), -0, '0', (new Number(-0)), 0.1, ({toString:function(){return '0';}}), (new Number(0)), /0/, ({valueOf:function(){return '0';}}), undefined, [0], '/0/', (new String('')), false, '\\0', NaN]); ");
/*fuzzSeed-71289653*/count=1004; tryItOut("mathy2 = (function(x, y) { return ( + Math.fround(( + (((Math.atanh((((( + Math.expm1(2**53+2)) << (Number.MAX_VALUE >>> 0)) >>> 0) >>> 0)) >>> 0) << (new Number(1.5) ** ((Math.fround(((Math.fround(Math.expm1(Math.fround(x))) >>> 0) , (y >>> 0))) ** ( ~ Math.acosh(y))) >>> 0))) | 0)))); }); testMathyFunction(mathy2, [(function(){return 0;}), null, NaN, '\\0', ({valueOf:function(){return '0';}}), (new Number(-0)), true, (new Number(0)), objectEmulatingUndefined(), undefined, 1, '/0/', /0/, (new Boolean(false)), ({toString:function(){return '0';}}), false, '', [0], (new Boolean(true)), -0, [], (new String('')), '0', 0, 0.1, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-71289653*/count=1005; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+/*FFI*/ff(((+pow(((((36028797018963970.0)) % ((+(1.0/0.0))))), ((-36893488147419103000.0))))), ((d1)), ((abs((((!((0xffffffff) <= (0x5ed645f2)))+(0xe11f6794)+(0xad8a2e7)) << (((Uint8ArrayView[((i0)) >> 0])))))|0)), ((abs((((0xf8609656)-(-0x8000000)) ^ (((-4398046511105.0) > (35184372088833.0))*-0xfffff)))|0))));\n    d1 = (+(1.0/0.0));\n    return (((i0)*-0xfffff))|0;\n  }\n  return f; })(this, {ff: String.prototype.italics}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000000, -(2**53-2), Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), 0x080000001, 0/0, 2**53, 1, -Number.MIN_SAFE_INTEGER, -0x080000000, -0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, Math.PI, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, 0x100000000, 0x0ffffffff, -0x080000001, 0.000000000000001, Number.MIN_VALUE, 2**53+2, -0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, -1/0, 1/0, 0, 42, -(2**53), Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-71289653*/count=1006; tryItOut("/*infloop*/for((\u3056) in (((neuter).call)(x)))t2[10] = s2;");
/*fuzzSeed-71289653*/count=1007; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1008; tryItOut("a2 + g2;");
/*fuzzSeed-71289653*/count=1009; tryItOut("t1 = t1.subarray(17);");
/*fuzzSeed-71289653*/count=1010; tryItOut("this.o1 = g2.__proto__;");
/*fuzzSeed-71289653*/count=1011; tryItOut("\"use strict\"; /*oLoop*/for (var ltovni = 0; ltovni < 45; ++ltovni) { g0.offThreadCompileScript(\"/* no regression tests found */\")\nprint(x); } ");
/*fuzzSeed-71289653*/count=1012; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return (( ! (Math.imul(Math.hypot(mathy0(( + ( + ( ~ ( + y)))), ( + y)), 2**53+2), ((((Math.fround(( ! ( + x))) / (Math.imul(y, Math.imul(y, x)) | 0)) | 0) && ((Math.pow(Math.min(Math.fround(y), Math.fround(y)), -0x100000001) === ( + (( - x) >>> 0))) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000000, 1, 0/0, -0x0ffffffff, -0x07fffffff, 2**53, 0, -Number.MIN_VALUE, -0x080000001, -0, 1.7976931348623157e308, 0x0ffffffff, -(2**53-2), -1/0, 0x080000001, 1/0, -Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), -0x100000000, -0x100000001, -(2**53+2), 0x100000000, Number.MIN_VALUE, 0x100000001, 42, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-71289653*/count=1013; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.acos(( ! (((y * y) >>> 0) + Math.hypot(( + Math.min(y, -Number.MAX_VALUE)), ( + 0/0))))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 1/0, 42, 0x080000000, -0x07fffffff, 2**53+2, 0x080000001, -0x100000000, -0x080000000, -Number.MAX_VALUE, -0x0ffffffff, 0, 0x100000000, -(2**53-2), 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, -0, 0/0, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), -0x080000001, 2**53-2, -0x100000001, 0.000000000000001, -(2**53), Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=1014; tryItOut("/*hhh*/function gvuemw(x, x, ...b){let v1 = evalcx(\"this.g1.g1.i1.toString = (function(j) { if (j) { g1.t0 = v1; } else { try { v0 = (e2 instanceof p0); } catch(e0) { } o0.m1.has(this.m2); } });\", g0);}/*iii*/print(gvuemw);");
/*fuzzSeed-71289653*/count=1015; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=1016; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d1));\n  }\n  return f; })(this, {ff: 17}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [2**53+2, 0/0, Number.MIN_SAFE_INTEGER, -0, -0x080000000, -1/0, -(2**53+2), 0x100000001, 1.7976931348623157e308, -0x100000000, 2**53-2, Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, 1/0, 0, 0x080000001, -0x080000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x0ffffffff, -0x07fffffff, -0x100000001, -(2**53), -(2**53-2), 0x07fffffff, 0x100000000, 1, 0x0ffffffff, 2**53, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1017; tryItOut("testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, 1/0, 0x100000001, -Number.MAX_VALUE, 0x080000000, -0x100000000, -0x07fffffff, -0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, 0x080000001, 0x07fffffff, 0x100000000, Number.MAX_VALUE, 1, -(2**53), -(2**53+2), 2**53, 42, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 2**53-2, 0, 0x0ffffffff, 0/0, -0x100000001, -0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1018; tryItOut("\"use asm\"; /*RXUB*/var r = new RegExp(\"([^]{536870911,536870911}(?:(?=(?=[\\\\s\\\\u00db-\\ubdfa]).))(?:^|[^\\\\W\\\\D\\\\S]|[^])+?)*?\\\\1\", \"g\"); var s = \"rrrrrrrrrr00\\n a\\u00fca_ \\u00c5\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1019; tryItOut("\"use strict\"; for(d in ((Math.expm1)((Date(\"\\u9A58\", \"\\u04A2\")))))this.m0.delete(g2);");
/*fuzzSeed-71289653*/count=1020; tryItOut("\"use strict\"; for (var p in g2.s1) { try { s1 += s2; } catch(e0) { } try { o2.v1 = g1.runOffThreadScript(); } catch(e1) { } t1.__proto__ = t2; }");
/*fuzzSeed-71289653*/count=1021; tryItOut("mathy5 = (function(x, y) { return (((Math.fround(mathy0(Math.fround(Math.atan2((Math.atanh((mathy3((Math.log2(mathy2(x, 0x07fffffff)) | 0), (((((-0x080000001 < -Number.MIN_SAFE_INTEGER) >>> 0) == ((mathy4((x >>> 0), (-0 >>> 0)) >>> 0) >>> 0)) >>> 0) | 0)) | 0)) >>> 0), Math.cosh((( + Math.round(( + x))) | 0)))), (Math.asinh(( - ( ~ y))) >>> 0))) >>> 0) & (Math.cos(Math.fround(((((((-0x0ffffffff ? Math.sqrt(( + Math.sin(( + y)))) : Math.min((y | 0), (0x100000001 | 0))) | 0) | (y >>> 0)) >>> 0) | 0) >>> (Math.trunc(x) | 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [Math.PI, 0, 0.000000000000001, -0x080000000, 2**53+2, -0x100000001, -0x080000001, 2**53-2, 2**53, 42, 0x080000000, Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), 0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, -Number.MAX_VALUE, -(2**53), 1, -1/0, 0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 1/0, -0, 0/0]); ");
/*fuzzSeed-71289653*/count=1022; tryItOut("mathy5 = (function(x, y) { return ((( ! ((( + (-0x080000000 == x)) % y) >>> 0)) | 0) / ( - (((( + ( ~ ( + Math.fround(Math.pow(Math.fround(x), (x >>> 0)))))) | 0) === mathy2(y, (( + (-0x080000001 >>> 0)) | 0))) ? (((Math.clz32(0x07fffffff) | 0) ? (( ! (y >>> 0)) | 0) : Math.fround((Math.fround(y) >> ( + 42)))) | 0) : (Math.imul(Math.fround(mathy4(( + Math.max(y, y)), Math.fround(Math.pow(42, y)))), 0x07fffffff) | 0)))); }); testMathyFunction(mathy5, [1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, 42, 0x0ffffffff, -1/0, 1, Number.MAX_VALUE, -0, 0/0, 2**53+2, -0x100000001, -(2**53+2), -0x080000001, 0.000000000000001, Number.MIN_VALUE, 2**53, -0x100000000, 0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -0x0ffffffff, -(2**53), 0x080000000, -0x07fffffff, -(2**53-2), 0x100000000, 0x07fffffff, Math.PI]); ");
/*fuzzSeed-71289653*/count=1023; tryItOut("\"use strict\"; if(\"\\uE0B5\") {e2 + '';a2.shift(); } else {Object.freeze(h0); }");
/*fuzzSeed-71289653*/count=1024; tryItOut("v0 = (s2 instanceof p0);");
/*fuzzSeed-71289653*/count=1025; tryItOut("for (var v of g0.t0) { try { f0 = Proxy.createFunction(h1, o1.f2, f1); } catch(e0) { } h1 = a1[({valueOf: function() { a2.toSource = (function(j) { f1(j); });return 7; }})]; }");
/*fuzzSeed-71289653*/count=1026; tryItOut("mathy2 = (function(x, y) { return Math.atan2((Math.acosh((mathy1(( ! ( + Math.exp(x))), Math.fround((((y >>> 0) === (x >>> 0)) >>> 0))) >>> 0)) >>> 0), ( + (((Math.fround(Math.fround(mathy0(Math.fround(1.7976931348623157e308), Math.fround(Math.atanh(y))))) | 0) !== (Math.exp(mathy1(x, ( + -0x07fffffff))) | 0)) | 0))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 2**53, 0x100000000, -0x0ffffffff, 2**53-2, 0.000000000000001, -0, -0x100000001, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, -Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), -(2**53+2), 0x080000000, Math.PI, -0x080000001, 1, 1/0, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, 0x07fffffff, 42, -0x100000000, 0/0, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-71289653*/count=1027; tryItOut("v1 = r1.multiline;");
/*fuzzSeed-71289653*/count=1028; tryItOut("");
/*fuzzSeed-71289653*/count=1029; tryItOut("/*MXX2*/g0.ArrayBuffer.isView = i2;const d = /*UUV1*/(x.getOwnPropertyNames = /*wrap2*/(function(){ var quteqv =  \"\" ; var buvlmt = (function(x, y) { return ( ~ y); }); return buvlmt;})());");
/*fuzzSeed-71289653*/count=1030; tryItOut("\"use strict\"; this.\u3056.fileName;");
/*fuzzSeed-71289653*/count=1031; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1032; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! ( - Math.fround(((Math.exp(-0x080000001) >>> 0) || Math.fround((Math.exp((x & Math.sinh(y))) >>> 0)))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, -(2**53-2), 0x080000001, -0x100000001, 2**53, -0x080000001, Number.MIN_VALUE, 0.000000000000001, 42, Number.MAX_VALUE, -0, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 2**53+2, 0/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -Number.MAX_VALUE, 0x080000000, -(2**53+2), 0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, 0x100000001, 2**53-2, 0x100000000, 1, -0x100000000, -1/0, 0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1033; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ((Math.log(Math.fround((((mathy0(((x >>> 0) < mathy0(x, y)), y) >>> 0) ? (Number.MIN_VALUE >>> 0) : (Math.fround(Math.cos(Math.fround(y))) >>> 0)) >>> 0))) >>> 0) - ( + Math.abs(( + ( ! (Math.exp(( + Math.clz32(y))) >>> 0))))))); }); testMathyFunction(mathy1, [2**53+2, -(2**53), Math.PI, Number.MIN_VALUE, 42, -0x100000000, -0x080000000, 1.7976931348623157e308, 0x0ffffffff, -0x07fffffff, -(2**53+2), 2**53, -1/0, 2**53-2, 0/0, -0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001, -0, -Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -0x080000001, Number.MAX_VALUE, 1, 0x080000000, 0x100000000, 0x07fffffff, -(2**53-2), 0, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=1034; tryItOut("o0.v0 = r1.sticky;");
/*fuzzSeed-71289653*/count=1035; tryItOut("i0 = t2[8];");
/*fuzzSeed-71289653*/count=1036; tryItOut("{ void 0; validategc(false); }");
/*fuzzSeed-71289653*/count=1037; tryItOut("/*infloop*/for((void options('strict')); this.__defineSetter__(\"window\", /*wrap2*/(function(){ \"use asm\"; var dyrmxy = (4277); var rnyzkw = decodeURIComponent; return rnyzkw;})()); \u0009(yield)) v1 = 4.2;");
/*fuzzSeed-71289653*/count=1038; tryItOut("\"use strict\"; testMathyFunction(mathy0, ['\\0', '0', (new Number(0)), [], /0/, 0.1, '', 0, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), (new Number(-0)), (new String('')), ({toString:function(){return '0';}}), 1, true, -0, (function(){return 0;}), undefined, null, [0], (new Boolean(true)), false, '/0/', NaN, (new Boolean(false)), objectEmulatingUndefined()]); ");
/*fuzzSeed-71289653*/count=1039; tryItOut("\"use strict\"; /*infloop*/L:for(let URIError in let (c)  \"\" ) {g1.v1 = new Number(NaN);print(x); }");
/*fuzzSeed-71289653*/count=1040; tryItOut("\"use asm\"; do g1.s0 += s2; while(((4277)) && 0);");
/*fuzzSeed-71289653*/count=1041; tryItOut("const v0 = Array.prototype.reduce, reduceRight.call(a1, (function() { try { a1 + ''; } catch(e0) { } for (var p in i1) { try { v0 = t2.byteLength; } catch(e0) { } a2[/*FARR*/[x].some]; } throw m0; }), a1);");
/*fuzzSeed-71289653*/count=1042; tryItOut("\"use strict\"; /*infloop*/L: for  each((x) in ([] = /*UUV1*/(b.entries = a.values))) {f0(o1.o2);e2.has(o2); }");
/*fuzzSeed-71289653*/count=1043; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0x100000001, 0/0, -1/0, 0, 0x0ffffffff, 0x07fffffff, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), -(2**53+2), -0x080000001, -0, 0x100000000, 1/0, -0x0ffffffff, -(2**53-2), -0x100000001, -0x080000000, -Number.MIN_VALUE, 2**53, -0x07fffffff, -0x100000000, Number.MAX_VALUE, 1, 42, 0x080000001, -Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1044; tryItOut("f0.valueOf = (function() { for (var j=0;j<16;++j) { f1(j%2==1); } });");
/*fuzzSeed-71289653*/count=1045; tryItOut("try { let(e) { throw StopIteration;} } finally { return; } x = d;");
/*fuzzSeed-71289653*/count=1046; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-71289653*/count=1047; tryItOut("\"use strict\"; /*MXX2*/g1.Object.prototype.valueOf = o0.e1;\nlet a1 = arguments.callee.arguments;\n");
/*fuzzSeed-71289653*/count=1048; tryItOut("\"use strict\"; v0 = g0.eval(\"var mvauwd = new ArrayBuffer(12); var mvauwd_0 = new Int16Array(mvauwd); var mvauwd_1 = new Uint8ClampedArray(mvauwd); mvauwd_1[0] = -13; var mvauwd_2 = new Uint8ClampedArray(mvauwd); mvauwd_2[0] = 94568045; var mvauwd_3 = new Int16Array(mvauwd); print(mvauwd_3[0]); mvauwd_3[0] = 16; var mvauwd_4 = new Int16Array(mvauwd); mvauwd_4[0] = 2; Object.prototype.watch.call(b1, \\\"__count__\\\", (function mcc_() { var bflvkk = 0; return function() { ++bflvkk; if (/*ICCD*/bflvkk % 4 == 1) { dumpln('hit!'); try { v0 = evaluate(\\\"\\\\\\\"use strict\\\\\\\"; \\\\\\\"use asm\\\\\\\"; function f1(s2) [[1]]\\\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: \\\"\\\\u45C3\\\", sourceIsLazy: true, catchTermination: false })); } catch(e0) { } try { Object.prototype.unwatch.call(s0, \\\"0\\\"); } catch(e1) { } v1.toString = f2; } else { dumpln('miss!'); try { print(v1); } catch(e0) { } try { a2.toSource = f1; } catch(e1) { } try { o1.o0.v0 = Array.prototype.some.apply(a2, [(function(stdlib, foreign, heap){ \\\"use asm\\\";   function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    d1 = (-3.777893186295716e+22);\\n    return +((d1));\\n    return +((8796093022207.0));\\n  }\\n  return f; })]); } catch(e2) { } a0 = []; } };})());s1 += s1;v1 = g1.runOffThreadScript();\");");
/*fuzzSeed-71289653*/count=1049; tryItOut("mathy1 = (function(x, y) { return ( + mathy0(( + ( + mathy0(( + (( - Math.fround(((Math.log10(Math.cosh((x | 0))) >>> 0) + (x >>> 0)))) | 0)), ( + Math.tanh(( + y)))))), ( + Math.asin((Math.fround(( ~ Math.atan2((1/0 >>> 0), ((Math.fround(Math.fround(-(2**53-2))) | 0) >>> 0)))) | 0))))); }); testMathyFunction(mathy1, [-0x07fffffff, 0.000000000000001, 0x100000001, 0x0ffffffff, 0x080000001, -0x100000000, 2**53, -0x0ffffffff, -0x100000001, -1/0, -(2**53+2), -0, 42, -0x080000000, -0x080000001, 0, 1.7976931348623157e308, 0/0, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, Number.MAX_VALUE, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, Math.PI, Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000]); ");
/*fuzzSeed-71289653*/count=1050; tryItOut("i0.next();");
/*fuzzSeed-71289653*/count=1051; tryItOut("M:if( /x/ ) this.s1 += 'x'; else 19;");
/*fuzzSeed-71289653*/count=1052; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.imul(( + mathy0((Math.fround(Math.trunc(( + y))) ** ( + ( ~ Math.fround(y)))), ( ! ((( + Math.cosh((((x >>> 0) & x) >>> 0))) >>> 0) >>> 0)))), ( - (( + ( + Math.min((Math.pow(Math.fround(y), y) / (y >>> Math.fround(x))), Math.imul((Math.cosh((y && y)) >>> 0), -(2**53+2))))) | 0))); }); ");
/*fuzzSeed-71289653*/count=1053; tryItOut("mathy0 = (function(x, y) { return Math.ceil(Math.fround((Math.tanh((Math.fround(( ~ (Math.atanh(( + -Number.MIN_SAFE_INTEGER)) >>> 0))) >>> 0)) | 0))); }); testMathyFunction(mathy0, [-(2**53+2), 2**53-2, 0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, -(2**53-2), 1/0, 1.7976931348623157e308, -0x080000000, 42, -0x100000000, -(2**53), -Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, 0/0, 0x100000001, -1/0, -0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 1, 2**53, 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53+2, -0, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=1054; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ ( + ( + Math.fround(Math.min((mathy4((y >>> 0), (( + (( + Math.hypot(( + 0/0), ( + -0x080000001))) && ( + -Number.MAX_SAFE_INTEGER))) >>> 0)) >>> 0), ( - 0x07fffffff)))))); }); testMathyFunction(mathy5, /*MARR*/[(void 0), false, new Boolean(true), (void 0), (void 0), false, new Boolean(true), (void 0), new Boolean(true), (void 0), new Boolean(true), false, new Boolean(true), new Boolean(true), (void 0), new Boolean(true), new Boolean(true), (void 0), (void 0), new Boolean(true), (void 0), new Boolean(true), (void 0), (void 0), false, (void 0), false, false, false, new Boolean(true), false, new Boolean(true), new Boolean(true), false, (void 0), false, (void 0), (void 0), new Boolean(true), (void 0), false, new Boolean(true), false, false, new Boolean(true), false, (void 0), (void 0), new Boolean(true)]); ");
/*fuzzSeed-71289653*/count=1055; tryItOut("testMathyFunction(mathy4, [0x07fffffff, 2**53, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 42, Number.MIN_SAFE_INTEGER, -0, -0x100000000, Math.PI, -(2**53-2), -0x07fffffff, 0x100000000, Number.MAX_VALUE, 0/0, 0, 2**53+2, -Number.MIN_VALUE, -0x080000001, -0x0ffffffff, -(2**53+2), 0x100000001, 1, 2**53-2, 0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, -1/0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, -(2**53)]); ");
/*fuzzSeed-71289653*/count=1056; tryItOut("/*RXUB*/var r = new RegExp(\"(.(?:\\\\b+?[^\\\\S\\\\d\\\\B-\\u0087\\\\W]|[\\\\cE\\\\S]+)|\\\\d|[^]|.{0,0}|[^]**(?!(?=\\\\1)+|.))\", \"gym\"); var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=1057; tryItOut("\"use strict\"; /*MXX1*/Object.defineProperty(this, \"o1\", { configurable: (x % 6 != 1), enumerable: true,  get: function() { this.m0.get(b2); return g2.Proxy.length; } });");
/*fuzzSeed-71289653*/count=1058; tryItOut("mathy5 = (function(x, y) { return mathy4(Math.fround(Math.min(Math.fround(((((( + mathy0(0x0ffffffff, 2**53)) | 0) >> ( + y)) % Math.fround(((Math.pow(Math.fround(x), y) >>> 0) << x))) | 0)), Math.fround(Math.max((Math.fround(mathy1(Math.fround((((y >>> 0) ? (x >>> 0) : ((y - (-0x080000000 | 0)) | 0)) >>> 0)), Math.fround(( - x)))) | 0), (Math.pow(( + x), Math.fround(( + Math.fround(y)))) | 0))))), ( ~ Math.exp(((((2**53+2 ^ (Math.log((y | 0)) | 0)) < (Math.PI >>> 0)) >>> 0) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=1059; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    d0 = (d0);\n    {\n      {\n        d0 = (d1);\n      }\n    }\n    d0 = (d1);\n    {\n      {\n        d0 = (d1);\n      }\n    }\n    {\n      d0 = (d0);\n    }\n    d0 = (d0);\n    (Uint16ArrayView[1]) = ((0x22b66c9e));\n    d1 = (d0);\n    d1 = (d0);\n    return +((d1));\n  }\n  return f; })(this, {ff: Root}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-71289653*/count=1060; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.asinh(( + ( ! Math.fround(( - (Math.atan2((((y ^ x) >>> Math.log2(x)) | 0), ((Math.min(y, Math.fround(y)) < -1/0) | 0)) | 0)))))); }); testMathyFunction(mathy0, [0.000000000000001, 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 0x080000000, -0, -0x100000001, 0x07fffffff, -(2**53), 0x100000000, 1, -Number.MAX_VALUE, Math.PI, -1/0, -0x080000001, 0x080000001, 0x0ffffffff, 1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, -0x0ffffffff, 0x100000001, 1/0, 2**53, -(2**53+2), Number.MAX_VALUE, 42, -0x07fffffff, 0, -0x080000000]); ");
/*fuzzSeed-71289653*/count=1061; tryItOut("\"use strict\"; testMathyFunction(mathy0, [2**53+2, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, 1/0, 2**53, 0x080000000, -Number.MAX_VALUE, 0, 1, Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, 0x080000001, -1/0, 2**53-2, -0x080000001, -0x080000000, -(2**53-2), 0/0, 0x07fffffff, -0x100000000, -(2**53), 42, -0, -(2**53+2), 0x100000000]); ");
/*fuzzSeed-71289653*/count=1062; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.ceil(Math.asin(((-Number.MIN_SAFE_INTEGER >>> 0) , Math.tan(Math.sign(y))))); }); testMathyFunction(mathy5, [-0x080000001, 0, 0x100000001, -0, 1.7976931348623157e308, -0x0ffffffff, -(2**53-2), -(2**53+2), -(2**53), -0x07fffffff, 0x100000000, -0x100000001, 0/0, -0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0.000000000000001, -Number.MAX_VALUE, 1/0, 2**53, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1, 0x07fffffff, -1/0, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-71289653*/count=1063; tryItOut("print( /* Comment */new RegExp(\"[^]\", \"gi\"));v2 = evalcx(\"\\\"use strict\\\"; yield  /x/ ;\", g1);");
/*fuzzSeed-71289653*/count=1064; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max(Math.hypot(Math.fround(((y || x) | Math.fround((Math.fround((Math.fround(( ~ (1 | 0))) ? x : Math.fround(Number.MAX_VALUE))) >> ( + (( + (Math.fround(y) == Math.fround((x <= x)))) === ( + Math.min(-1/0, x)))))))), Math.fround(Math.log10((Math.hypot(x, (y >>> 0)) ^ (( + Math.pow(0x0ffffffff, 1/0)) ? ( + x) : Math.atanh(( ~ 0x100000001))))))), Math.atan(((Math.fround((( + y) <= ( + ( + ( ~ x))))) + x) | 0))); }); testMathyFunction(mathy0, [2**53-2, 0, 0x0ffffffff, -0x080000000, -0x100000001, -(2**53-2), 1, -(2**53+2), 42, Math.PI, 1.7976931348623157e308, Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, -Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 1/0, -(2**53), 2**53, 2**53+2, -0x080000001, 0/0, 0x080000000, Number.MAX_VALUE, -0]); ");
/*fuzzSeed-71289653*/count=1065; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=(?=^|[^])|\u008b|\\d*?^[\\s\\0-\\n]{1,1})|[^]|(?:\\B|\\b{1,3}(?=[^])*?){0,0}/; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-71289653*/count=1066; tryItOut("print(uneval(o2.i1));");
/*fuzzSeed-71289653*/count=1067; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=1068; tryItOut("\"use strict\"; v2 = g2.runOffThreadScript();");
/*fuzzSeed-71289653*/count=1069; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[-Number.MIN_VALUE,  /x/ , eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval,  /x/ ,  /x/ , eval,  /x/ ,  /x/ , -Number.MIN_VALUE]) { null; }");
/*fuzzSeed-71289653*/count=1070; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2(( ! (Math.fround(Math.hypot((y | 0), ( + ( + y)))) ? (( + Math.max(Math.round(((Math.imul((y >>> 0), Math.fround(x)) >>> 0) | 0)), (Math.trunc(( ~ x)) >>> 0))) | 0) : ((Number.MAX_SAFE_INTEGER * (mathy2(Math.fround(y), (-(2**53+2) | 0)) | 0)) >>> 0))), (( + ( ~ ( + mathy1((( - Math.log2(y)) >>> 0), ( ~ ( ! 1/0)))))) | 0)); }); testMathyFunction(mathy3, [1/0, 2**53, Number.MAX_VALUE, -(2**53-2), -(2**53+2), 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0/0, Math.PI, 0x080000001, -0x100000001, 0x0ffffffff, -0, 0x100000001, -0x080000001, 2**53+2, 42, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1, 2**53-2, 0x080000000, -0x100000000, -1/0, 0, -Number.MAX_VALUE, -0x080000000, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1071; tryItOut("-1;function a(x, NaN = window, ...x) { v2 = -Infinity; } v2 = b2.byteLength;");
/*fuzzSeed-71289653*/count=1072; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return (( ! ((( + ((y ? Math.fround(x) : ((Math.expm1((y >>> 0)) >>> 0) >>> 0)) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [1, 0x080000001, 0x07fffffff, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -1/0, 1.7976931348623157e308, 0, -Number.MIN_SAFE_INTEGER, 42, -0x080000000, -Number.MIN_VALUE, -(2**53), 0x080000000, 1/0, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, 2**53+2, -0x07fffffff, 0x0ffffffff, -0x100000001, 0/0, -Number.MAX_VALUE, -(2**53-2), Math.PI, Number.MIN_SAFE_INTEGER, -(2**53+2), -0, 2**53-2, -0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=1073; tryItOut("mathy2 = (function(x, y) { return ( ~ Math.ceil((( + ( ~ ( + x))) | 0))); }); testMathyFunction(mathy2, [(function(){return 0;}), (new String('')), objectEmulatingUndefined(), ({toString:function(){return '0';}}), '0', '/0/', [], /0/, undefined, 0.1, null, '\\0', NaN, (new Number(0)), '', true, false, -0, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), [0], (new Boolean(true)), 1, (new Number(-0)), 0, (new Boolean(false))]); ");
/*fuzzSeed-71289653*/count=1074; tryItOut("\"use strict\"; let x = function(){}, x = \u3056, NaN =  /x/g ;s2 += o1.s2;\n");
/*fuzzSeed-71289653*/count=1075; tryItOut("\"use strict\"; x;\ni0 + '';\n");
/*fuzzSeed-71289653*/count=1076; tryItOut("t1 = new Float64Array(9);");
/*fuzzSeed-71289653*/count=1077; tryItOut("\"use asm\"; for (var v of h1) { try { this.s0 = s0.charAt(18); } catch(e0) { } try { Array.prototype.sort.apply(a2, [(function() { for (var j=0;j<100;++j) { f1(j%5==0); } }), v2]); } catch(e1) { } try { h1.set = g0.f1; } catch(e2) { } i2 = new Iterator(p1); }");
/*fuzzSeed-71289653*/count=1078; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.sqrt(mathy1(Math.fround(mathy2(mathy1(Math.atan2(( ! x), ( ~ y)), ((Math.log1p(x) | 0) === y)), ((x == x) & ( + y)))), (( ~ ( + x)) / (((Math.hypot((y | 0), (((Math.pow(x, x) | 0) + (x | 0)) | 0)) >>> 0) - (x >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [2**53-2, 42, -1/0, -0x100000000, 0x100000001, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -(2**53+2), 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, Number.MAX_SAFE_INTEGER, 1/0, 0/0, -0x07fffffff, 0, 0x07fffffff, 1, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 2**53, -0x100000001, 0x100000000, -(2**53-2), -(2**53), -0x080000000, -0]); ");
/*fuzzSeed-71289653*/count=1079; tryItOut("\"use strict\"; a1 = Array.prototype.slice.call(a0, NaN, 13, e1);");
/*fuzzSeed-71289653*/count=1080; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i0);\n    return (( '' ))|0;\n  }\n  return f; })(this, {ff: Date.prototype.toGMTString}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1/0, 1.7976931348623157e308, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53-2), 2**53-2, Number.MAX_SAFE_INTEGER, 42, 2**53, 0, 1, -0x07fffffff, -0x0ffffffff, -(2**53), Number.MIN_VALUE, Math.PI, 0x100000001, 0x0ffffffff, 0x100000000, 0x080000001, -0, -0x100000001, 0.000000000000001, 0/0, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1081; tryItOut("/*RXUB*/var r = /\\ub6AB/yi; var s = \"\\ub68b\"; print(s.split(r)); ");
/*fuzzSeed-71289653*/count=1082; tryItOut(";");
/*fuzzSeed-71289653*/count=1083; tryItOut("\"use asm\"; x;");
/*fuzzSeed-71289653*/count=1084; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.ceil(( - (( ~ ((x >>> 0) ? Math.fround(( - y)) : (( ! (Math.hypot(0x07fffffff, ( + Number.MAX_SAFE_INTEGER)) | 0)) & 0x080000000))) >>> 0))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0x080000000, -0x080000001, 1.7976931348623157e308, 2**53, 0.000000000000001, 0x07fffffff, -0x100000001, 0, -0x0ffffffff, -(2**53+2), Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 0x080000000, 1/0, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, -1/0, -Number.MAX_VALUE, -0x100000000, 42, -0, 1, 0x0ffffffff, 0x100000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1085; tryItOut("Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-71289653*/count=1086; tryItOut("mathy0 = (function(x, y) { return Math.atanh(((((( + (Math.fround(Math.atan2(x, x)) | 0)) | 0) | 0) == (( - ( ~ 0.000000000000001)) | 0)) | 0)); }); ");
/*fuzzSeed-71289653*/count=1087; tryItOut("mathy0 = (function(x, y) { return Math.acosh(((((( + (( + Math.pow(Math.log(x), (y >>> 0))) % Math.cbrt(Math.atan2((Math.asinh(1/0) >>> 0), (x >>> 0))))) >>> 0) >= (( ! Math.cos(x)) >>> 0)) >>> 0) > (( + Math.ceil(-0x0ffffffff)) >>> 0))); }); testMathyFunction(mathy0, [0, 2**53-2, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, -(2**53-2), -Number.MAX_VALUE, 2**53+2, -0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 1/0, 42, Math.PI, 0x080000000, Number.MAX_SAFE_INTEGER, 1, -0, -0x0ffffffff, -0x100000001, 0/0, 0x100000001, -(2**53), -1/0, 0x100000000, -0x080000000, 0x07fffffff, 2**53, -(2**53+2), -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1088; tryItOut("v2 = t2.length;");
/*fuzzSeed-71289653*/count=1089; tryItOut("r1 = /(?=\\3){0,}/gi;");
/*fuzzSeed-71289653*/count=1090; tryItOut("\"use strict\"; v1 = this.r1.compile;");
/*fuzzSeed-71289653*/count=1091; tryItOut("testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), -0x100000000, -0, 0x0ffffffff, 2**53+2, 0x07fffffff, 0x100000000, Math.PI, -0x100000001, Number.MIN_VALUE, 1, 0x100000001, 0.000000000000001, 42, -1/0, -0x07fffffff, -0x080000001, 1.7976931348623157e308, -(2**53), 0/0, 0x080000001, 2**53, 0, 0x080000000, -(2**53+2), -0x080000000]); ");
/*fuzzSeed-71289653*/count=1092; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( ~ (Math.atan((( ! Math.fround(( + y))) !== 2**53-2)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-(2**53-2), -0x100000001, -(2**53+2), -0x080000001, 0x100000001, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, 1, -0x0ffffffff, 2**53, Number.MIN_VALUE, 1/0, 0x07fffffff, 0/0, 42, -Number.MAX_VALUE, -0x100000000, 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), 2**53+2, -0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-71289653*/count=1093; tryItOut("mathy1 = (function(x, y) { return Math.fround(( - ( + mathy0(( + mathy0(Math.imul(x, ( + Math.imul(( + Math.imul(y, Math.fround(x))), x))), ((Math.imul(( + Math.atanh((x >>> 0))), (Math.sign(( + x)) | 0)) | 0) | 0))), ( + ((( + x) | 0) ? Math.fround((( + mathy0(-0x100000001, ( + x))) << Math.fround(y))) : mathy0(( + y), ( + ((mathy0(y, (x | 0)) | 0) >> Math.fround(x)))))))))); }); testMathyFunction(mathy1, /*MARR*/[[], [], null, [], null, [], null, null, [], null, [], [], [], null, [], null, [], null, null, [], [], null, null, [], null, [], null, null, null, [], [], [], [], [], [], null, null, [], null, [], [], null, [], null, null, [], null, null, null, [], [], [], null, null]); ");
/*fuzzSeed-71289653*/count=1094; tryItOut("v1.valueOf = Number.isFinite;");
/*fuzzSeed-71289653*/count=1095; tryItOut("/*iii*/t0.valueOf = (function() { try { for (var p in h1) { try { h2.fix = f2; } catch(e0) { } try { h0.has = f0; } catch(e1) { } i2.next(); } } catch(e0) { } try { Array.prototype.pop.apply(a0, []); } catch(e1) { } try { g1.s2.__iterator__ = (function mcc_() { var gvgyhf = 0; return function() { ++gvgyhf; if (/*ICCD*/gvgyhf % 10 != 7) { dumpln('hit!'); ; } else { dumpln('miss!'); e2 = new Set(p0); } };})(); } catch(e2) { } this.v1 = (f1 instanceof m2); return e1; });/*hhh*/function dzvdph(Math.pow(-24, -22)){Object.preventExtensions(s2);}");
/*fuzzSeed-71289653*/count=1096; tryItOut("o0.v1 = this.g2.eval(\"x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: String.prototype.small, delete: this, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: Object.getPrototypeOf, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: (this).call, }; })(window), Date.prototype.getTime) - ((c = NaN))\");");
/*fuzzSeed-71289653*/count=1097; tryItOut("const aufksb;\u0009/*tLoop*/for (let a of /*MARR*/[objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, (-1/0), null, (-1/0), (-1/0), objectEmulatingUndefined(), (-1/0), (-1/0), false, null, null, (-1/0), false, objectEmulatingUndefined(), objectEmulatingUndefined(), null, (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), null, false, (-1/0), (-1/0), null, null, false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, (-1/0), (-1/0), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), false, (-1/0), (-1/0), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, (-1/0), (-1/0), null, (-1/0), objectEmulatingUndefined(), false, false, (-1/0), false, null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), null, (-1/0), objectEmulatingUndefined(), null, (-1/0), null, (-1/0), objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined(), false, (-1/0), null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), (-1/0), (-1/0), false, false, objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, false, (-1/0), (-1/0), (-1/0), null, null, (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, false, null, null, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), (-1/0)]) { print(a); }");
/*fuzzSeed-71289653*/count=1098; tryItOut("/*oLoop*/for (quqfzr = 0; quqfzr < 22; ++quqfzr) { /* no regression tests found */\nv2 = r2.source;\n } ");
/*fuzzSeed-71289653*/count=1099; tryItOut("s2 += s1;\nf2.__proto__ = f0;\n");
/*fuzzSeed-71289653*/count=1100; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - (Math.cosh ? (( + Math.hypot((Math.atan2((Math.pow(y, ((Math.sqrt(Math.log2(y)) >>> 0) >>> 0)) | 0), (x | 0)) | 0), (Math.min(((((x >>> 0) >= (x >>> 0)) >>> 0) >>> 0), ((y * x) >>> 0)) | 0))) | 0) : ( + mathy0(( + y), ( + ( + ((0/0 | 0) >= 0x080000001))))))); }); ");
/*fuzzSeed-71289653*/count=1101; tryItOut("mathy2 = (function(x, y) { return ( + ( + ( + (Math.tan(mathy1((Math.log((mathy0(Math.fround(x), Math.fround(y)) >>> 0)) < ( + 2**53+2)), ( + ( ! (Math.fround((( + Math.abs(Math.fround(-(2**53+2)))) && (( - x) | 0))) | 0))))) | 0)))); }); testMathyFunction(mathy2, [0x100000001, 0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -1/0, 1.7976931348623157e308, -(2**53), 0x080000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, -0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, 42, Math.PI, 0x0ffffffff, 2**53-2, 0.000000000000001, 0x080000000, -(2**53+2), 0/0, -Number.MAX_VALUE, 1, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -0x100000001, 1/0]); ");
/*fuzzSeed-71289653*/count=1102; tryItOut("o1.v2 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-71289653*/count=1103; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=1104; tryItOut("\"use strict\"; /*RXUB*/var r = g2.r2; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-71289653*/count=1105; tryItOut("/*ADP-3*/Object.defineProperty(a1, v1, { configurable: (x % 4 != 3), enumerable: true, writable: (x % 2 == 0), value: t1 });");
/*fuzzSeed-71289653*/count=1106; tryItOut("a1 + this.h0;");
/*fuzzSeed-71289653*/count=1107; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return ( + mathy3(Math.fround(Math.max(Math.fround(Math.fround(( ! ((Math.log(Math.fround(y)) >>> 0) | 0)))), Math.fround(( + ( ! (((x | 0) <= ((((( - x) | 0) >>> 0) || (-0x07fffffff >>> 0)) | 0)) | 0)))))), (( + (Math.fround(mathy1((Math.cos(x) | 0), (Math.min((x >>> 0), (y >>> 0)) >>> 0))) | 0)) | 0))); }); ");
/*fuzzSeed-71289653*/count=1108; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( ~ ( ~ Math.fround(mathy1((( ! (x | 0)) | 0), Math.fround((Math.imul(((Math.imul((Math.max(x, Math.fround(((x >>> 0) ? (x >>> 0) : (y >>> 0)))) | 0), (x >>> 0)) >>> 0) | 0), (Math.min(( + (( + x) + ( + ( + Math.atan(y))))), ((x | 0) === ((x ? x : x) | 0))) | 0)) >>> 0)))))); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), (makeFinalizeObserver('nursery')), objectEmulatingUndefined(), (makeFinalizeObserver('nursery')), Number.MAX_SAFE_INTEGER, new Number(1.5), Number.MAX_SAFE_INTEGER, (makeFinalizeObserver('nursery')), Number.MAX_SAFE_INTEGER, Infinity, Number.MAX_SAFE_INTEGER, (makeFinalizeObserver('nursery')), Infinity, new Number(1.5), (makeFinalizeObserver('nursery')), Infinity, Infinity, Number.MAX_SAFE_INTEGER, Infinity, (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), (makeFinalizeObserver('nursery')), objectEmulatingUndefined(), new Number(1.5), Infinity, (makeFinalizeObserver('nursery')), new Number(1.5), Number.MAX_SAFE_INTEGER, (makeFinalizeObserver('nursery')), Infinity, objectEmulatingUndefined(), Infinity, (makeFinalizeObserver('nursery')), Number.MAX_SAFE_INTEGER, new Number(1.5), objectEmulatingUndefined(), (makeFinalizeObserver('nursery')), new Number(1.5), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Infinity, Number.MAX_SAFE_INTEGER, new Number(1.5), new Number(1.5), (makeFinalizeObserver('nursery')), Number.MAX_SAFE_INTEGER, new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (makeFinalizeObserver('nursery')), new Number(1.5), Infinity, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, (makeFinalizeObserver('nursery')), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), new Number(1.5), Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, (makeFinalizeObserver('nursery')), objectEmulatingUndefined(), Infinity, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Number.MAX_SAFE_INTEGER, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), Infinity, objectEmulatingUndefined(), Number.MAX_SAFE_INTEGER, Infinity, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined()]); ");
/*fuzzSeed-71289653*/count=1109; tryItOut("mathy0 = (function(x, y) { return ((Math.fround(Math.exp((x ? Math.asin(y) : (( ! (Math.imul(y, Math.atan2(x, x)) | 0)) | 0)))) === Math.fround(( - (Math.log1p((Math.asinh(( + Math.tanh(( + x)))) >>> 0)) >>> 0)))) | 0); }); ");
/*fuzzSeed-71289653*/count=1110; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (((( + mathy2(( + Math.log(( + Math.atan2(( + (( + y) > ( + y))), ( + x))))), ( + Math.clz32((-0x0ffffffff >>> 0))))) ? Math.atan2(( + ( + Math.fround(Math.sign(Math.fround(y))))), ( + ( + Math.asin((Math.fround((y ? Math.fround(-(2**53-2)) : Math.fround(y))) | 0))))) : (( ! (((( + ( + (y ? y : x))) | 0) != (1 & y)) | 0)) | 0)) >>> 0) === (Math.fround((Math.atan2(((( + (( - x) | 0)) ? (mathy1((Math.fround(x) >>> 0), x) >>> 0) : Math.pow(y, Math.asin(x))) >>> 0), ( + (Math.hypot((Math.max(x, y) >>> 0), ((((x | 0) ? (0x0ffffffff | 0) : (x | 0)) | 0) >>> 0)) >>> 0))) >>> 0)) <= Math.cbrt(( + Math.atan2(y, ( + 1)))))); }); ");
/*fuzzSeed-71289653*/count=1111; tryItOut("mathy3 = (function(x, y) { return (Math.tan(((Math.sin((Math.min((Math.pow((-(2**53+2) | 0), (y > ( + y))) | 0), y) >>> 0)) >>> 0) ? ( + Math.sinh(x)) : ( + Math.sign(-Number.MAX_SAFE_INTEGER)))) / ( + Math.pow(( + (((Math.atan2(( + (x == (x | 0))), ( ~ x)) >>> 0) == (Math.cbrt(( + (-Number.MIN_VALUE > (y % y)))) >>> 0)) >>> 0)), ( + Math.pow(Number.MIN_SAFE_INTEGER, Math.acosh(x)))))); }); testMathyFunction(mathy3, [0x07fffffff, -(2**53+2), -0x080000000, 1, Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 1/0, -0x100000000, Number.MAX_VALUE, 2**53, -0x100000001, -0x0ffffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, -Number.MIN_VALUE, -0, -0x07fffffff, 0x100000001, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0, 0x100000000, 0.000000000000001, 42, -(2**53-2), -(2**53), 0x0ffffffff, Math.PI, 2**53-2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=1112; tryItOut("selectforgc(o1);");
/*fuzzSeed-71289653*/count=1113; tryItOut("v0 = a0.length;");
/*fuzzSeed-71289653*/count=1114; tryItOut("\"use strict\"; /*hhh*/function drtggn(){/*oLoop*/for (var tsxbmr = 0; tsxbmr < 91; ++tsxbmr) { print(x); } }drtggn([/*UUV2*/(-12.getFullYear = -12.splice)]);");
/*fuzzSeed-71289653*/count=1115; tryItOut("Array.prototype.splice.call(this.a0, -3, 14, s2, b1, g0.s2, m0, (timeout(1800)), false, e0, x >>= ((((( - ( + Math.hypot((( ~ ( + x)) >>> Math.fround(2**53+2)), Math.sign(-Number.MIN_SAFE_INTEGER)))) | 0) >>> (( + ( ~ ((Math.fround((Math.fround(x) >>> Math.fround(x))) / (Math.fround(Math.expm1(x)) >>> 0)) >>> 0))) >>> 0)) | 0)));");
/*fuzzSeed-71289653*/count=1116; tryItOut("const x, ozemgl, jtmrer;o0.a0.splice(4, ({valueOf: function() { /*RXUB*/var r = new RegExp(\"\\\\b|.{4}|\\\\1\", \"gi\"); var s = \" \\u00c5a\"; print(r.test(s)); return 9; }}));");
/*fuzzSeed-71289653*/count=1117; tryItOut("\"use asm\"; {}\ne2.delete(o1);\n");
/*fuzzSeed-71289653*/count=1118; tryItOut("function shapeyConstructor(eetwfw){if (eetwfw) Object.preventExtensions(this);this[\"isNaN\"] = WeakMap.prototype.get;Object.seal(this);if ((eval(\"x.__defineSetter__(\\\"d\\\", q => q)\"))) Object.defineProperty(this, \"setMilliseconds\", ({writable: (eetwfw % 4 != 2), enumerable: (x % 6 != 3)}));Object.freeze(this);{ a1 = Array.prototype.map.call(a0, (function mcc_() { var jkglif = 0; return function() { ++jkglif; f1(/*ICCD*/jkglif % 4 == 1);};})(), t0); } return this; }/*tLoopC*/for (let z of (this.__defineGetter__(\"z\", ((p={}, (p.z =  \"\" )()).prototype)))) { try{let inshaw = new shapeyConstructor(z); print('EETT'); f0 = a2[v2];}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-71289653*/count=1119; tryItOut("\"use strict\"; /*infloop*/ for  each(var x in (this >  '' )) {/*vLoop*/for (gmbwwd = 0; gmbwwd < 34; ++gmbwwd) { let a = gmbwwd; t1 + ''; } ; }");
/*fuzzSeed-71289653*/count=1120; tryItOut("mathy2 = (function(x, y) { return (Math.sin(( + Math.atanh((((x | 0) ? ((Math.asinh(y) >>> 0) | 0) : Math.fround(x)) | 0)))) | 0); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 2**53, 42, 0x080000001, 1/0, -0x080000000, 2**53+2, -(2**53+2), 0x100000000, 0/0, 1.7976931348623157e308, -0x080000001, 0x100000001, -0, 2**53-2, 0, -Number.MIN_VALUE, 0.000000000000001, 1, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -Number.MAX_VALUE, -(2**53), 0x080000000, -(2**53-2), -0x0ffffffff, -0x100000000, Math.PI, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1121; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.log2(( ~ Math.max((Number.MIN_SAFE_INTEGER >>> 0), (-0x100000001 && (Math.fround(Math.atan2(y, x)) >>> 0))))); }); testMathyFunction(mathy2, [0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, -0x100000001, 2**53-2, 1, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, -0, 1/0, -(2**53-2), Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, -0x080000000, 0x100000000, 0, 42, Number.MIN_VALUE, -(2**53+2), -1/0, 0x07fffffff, 0x100000001, 0/0, 0x080000000, -0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-71289653*/count=1122; tryItOut("print((((function fibonacci(wfvivl) { ; if (wfvivl <= 1) { ; return 1; } ; return fibonacci(wfvivl - 1) + fibonacci(wfvivl - 2);  })(6)).prototype));");
/*fuzzSeed-71289653*/count=1123; tryItOut("/*RXUB*/var r = /(?!((?=[^])*\\w|\\2\\1?)){2,}\\1(?!(?:(?!\\D)|[^]*)*?(?:(?![\u00d5]|.|[^])))*?/y; var s = \"0\\n\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=1124; tryItOut("v2 = Array.prototype.some.call(a2, (function(j) { if (j) { try { i2.send(g2.v1); } catch(e0) { } v2 = (h2 instanceof v2); } else { try { a0.forEach(f1); } catch(e0) { } try { for (var v of e1) { t1[this.e0.toSource = (function(j) { if (j) { v1 = Object.prototype.isPrototypeOf.call(a0, m1); } else { try { g0.e1.has(v0); } catch(e0) { } try { v1 = b1.byteLength; } catch(e1) { } try { for (var p in t0) { try { h2 = {}; } catch(e0) { } for (var v of o1) { try { i1.next(); } catch(e0) { } try { a2[3] =  /x/g ; } catch(e1) { } try { i1.next(); } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(f1, m2); } } } catch(e2) { } /*RXUB*/var r = r0; var s = \"a \\u001ea \\u001ea \\u001ea \\u001ea \\u001e\\u00d9\\u00d9\\u00d9\"; print(r.test(s));  } })] = f2; } } catch(e1) { } p2 + a2; } }));");
/*fuzzSeed-71289653*/count=1125; tryItOut("\"use strict\"; v1 = (i1 instanceof g0);");
/*fuzzSeed-71289653*/count=1126; tryItOut("\"use strict\"; /*oLoop*/for (var poezee = 0; poezee < 13 && (-27); ++poezee) { v2 = (this.a2 instanceof e2); } ");
/*fuzzSeed-71289653*/count=1127; tryItOut("h0.toSource = String.prototype.toLocaleLowerCase.bind(f1);");
/*fuzzSeed-71289653*/count=1128; tryItOut("/*RXUB*/var r = /[^]*/gy; var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1129; tryItOut(";");
/*fuzzSeed-71289653*/count=1130; tryItOut("mathy0 = (function(x, y) { return ((( - y) ? Math.sin((0x100000001 >>> 0)) : (( + Math.atan2(( + 0.000000000000001), ( + Math.max((( ~ (x >>> 0)) | 0), ( ~ ( - y)))))) < y)) <= Math.fround(Math.tan(Math.fround(Math.sign(Math.fround(Math.imul(( + x), Math.asinh(y)))))))); }); testMathyFunction(mathy0, [(new Number(0)), -0, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), 1, [], '', 0, true, /0/, ({toString:function(){return '0';}}), '\\0', [0], false, (new Boolean(true)), 0.1, (new Boolean(false)), NaN, (function(){return 0;}), (new Number(-0)), null, objectEmulatingUndefined(), undefined, (new String('')), '/0/', '0']); ");
/*fuzzSeed-71289653*/count=1131; tryItOut("v2 = evaluate(\"mathy4 = (function(x, y) { \\\"use strict\\\"; return (mathy3(( + Math.fround(( - y))), (Math.min((Math.imul(Math.fround(Math.hypot(x, Math.fround(-Number.MAX_SAFE_INTEGER))), Math.asin(( + x))) >>> 0), ( + ((( + (x | 0)) | 0) / ( - y)))) >>> 0)) != ( - Math.sign((( + -0x100000001) || (x == (((1.7976931348623157e308 >>> 0) & (0x100000000 | 0)) >>> 0)))))); }); testMathyFunction(mathy4, /*MARR*/[new Number(1), NaN, new Number(1), new Number(1), NaN, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1), NaN, new Number(1.5), new Number(1.5), new Number(1), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), NaN, new Number(1)]); \", ({ global: this.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 != 2), noScriptRval: (x % 103 == 73), sourceIsLazy: false, catchTermination: false, element: o2, sourceMapURL: g0.s2 }));");
/*fuzzSeed-71289653*/count=1132; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((((((i1) ? ((((0x696cee5d))>>>((0xfee942c6)))) : (!(!(/*FFI*/ff(((-36893488147419103000.0)), ((-72057594037927940.0)), ((3.777893186295716e+22)), ((-274877906945.0)), ((2.3611832414348226e+21)), ((35184372088832.0)), ((134217729.0)), ((-67108865.0)), ((-1073741825.0)), ((4503599627370497.0)), ((-562949953421313.0)))|0))))) & (((Int16ArrayView[((-0x8000000)) >> 1])))) / (0x1d843edc)))|0;\n  }\n  return f; })(this, {ff: Int32Array}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [/0/, '\\0', ({valueOf:function(){return 0;}}), null, (new Number(0)), (new Number(-0)), ({toString:function(){return '0';}}), (function(){return 0;}), [0], -0, ({valueOf:function(){return '0';}}), 0, false, undefined, (new Boolean(true)), 1, '', (new String('')), true, '/0/', [], NaN, '0', 0.1, objectEmulatingUndefined(), (new Boolean(false))]); ");
/*fuzzSeed-71289653*/count=1133; tryItOut("\"use strict\"; var v2 = o2.o1.t2.length;");
/*fuzzSeed-71289653*/count=1134; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.fround(Math.fround(Math.exp(Math.fround((Math.fround(( ~ (y >>> 0))) < Math.fround(Math.asin(Math.hypot(y, y))))))))); }); ");
/*fuzzSeed-71289653*/count=1135; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0/0, -0x100000000, 0x0ffffffff, -(2**53), -(2**53-2), -0x080000000, 0x080000001, 0, -(2**53+2), 0x080000000, -1/0, -0x080000001, -Number.MAX_VALUE, 2**53-2, -0, -0x100000001, 0x07fffffff, -0x07fffffff, 2**53, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 1, 2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, -0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 42, Math.PI]); ");
/*fuzzSeed-71289653*/count=1136; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a2, 5, { configurable: (x % 4 == 3), enumerable: (x % 9 != 8), writable: x = \"\\u339D\", value: (null.yoyo((Math.tan(-3)))) });");
/*fuzzSeed-71289653*/count=1137; tryItOut("((yield z) >= (void shapeOf(x)));");
/*fuzzSeed-71289653*/count=1138; tryItOut("\"use strict\"; testMathyFunction(mathy0, [NaN, '/0/', (new Number(0)), -0, '0', 0.1, 0, (function(){return 0;}), /0/, ({valueOf:function(){return '0';}}), false, ({valueOf:function(){return 0;}}), (new Boolean(true)), 1, (new Number(-0)), null, objectEmulatingUndefined(), [], (new Boolean(false)), ({toString:function(){return '0';}}), (new String('')), '', undefined, [0], true, '\\0']); ");
/*fuzzSeed-71289653*/count=1139; tryItOut("mathy3 = (function(x, y) { return Math.round((((( + (x >> Math.min(Number.MIN_SAFE_INTEGER, Math.imul(y, 1/0)))) ? Math.tan(Math.atan2(( + Math.imul(x, 0x07fffffff)), Math.max(y, y))) : ( ! 0/0)) >>> 0) >>> Math.fround(Math.pow(( + ( - (-0x080000000 >>> 0))), Math.fround(Math.acosh(y)))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, 2**53-2, 0, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, 42, -Number.MIN_VALUE, -0x100000001, 0x080000001, 0x07fffffff, -(2**53+2), 0.000000000000001, Math.PI, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -0, -1/0, 0x0ffffffff, 0x100000001, 0x100000000, -0x07fffffff, -0x080000001, Number.MIN_VALUE, 2**53, 1.7976931348623157e308, -(2**53-2), -Number.MAX_VALUE, 0/0, -(2**53)]); ");
/*fuzzSeed-71289653*/count=1140; tryItOut("h1.set = f2;");
/*fuzzSeed-71289653*/count=1141; tryItOut("v0 = Array.prototype.reduce, reduceRight.call(a2, (function() { try { ; } catch(e0) { } try { i0.next(); } catch(e1) { } try { this.g0.offThreadCompileScript(\"function f0(e2) x\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce:  /x/g  &= undefined === \"\\uB01D\" < (([]) = window), noScriptRval: true, sourceIsLazy: x, catchTermination: (x % 5 != 3) })); } catch(e2) { } t1[6] = NaN = ((void version(170))).eval(\"print(x);\"); return o0; }), a1, s1, o1.p1);");
/*fuzzSeed-71289653*/count=1142; tryItOut("v2 = evalcx(\"\\\"use strict\\\"; \", g2);");
/*fuzzSeed-71289653*/count=1143; tryItOut("s1 += 'x';");
/*fuzzSeed-71289653*/count=1144; tryItOut("\"use strict\"; Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-71289653*/count=1145; tryItOut("NaN = Proxy.create(({/*TOODEEP*/})(this), null);");
/*fuzzSeed-71289653*/count=1146; tryItOut("/*bLoop*/for (var fbguot = 0; fbguot < 2; ++fbguot) { if (fbguot % 31 == 15) { e2 = new Set; } else { o0.m1.delete(new RegExp(\"^\", \"gy\")); }  } ");
/*fuzzSeed-71289653*/count=1147; tryItOut("\"use strict\"; print(((void options('strict_mode')) , (Math.imul(x, 1e-81))));function z(x, ...a)\"use asm\";   var sqrt = stdlib.Math.sqrt;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return +(((+sqrt(((+(-1.0/0.0))))) + (+(0x0))));\n  }\n  return f;print(this.b1);");
/*fuzzSeed-71289653*/count=1148; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(b1, -2, ({value: ((new (function shapeyConstructor(vljesc){return vljesc; })(true, 5))).call(new offThreadCompileScript(), (this.window &= x), (4277)), writable: true, configurable: true}));");
/*fuzzSeed-71289653*/count=1149; tryItOut("print(x);\ni1.valueOf = (function() { try { a0.unshift(window); } catch(e0) { } try { v1 = (m0 instanceof o2.s0); } catch(e1) { } try { h2.keys = (function() { try { /*MXX3*/g0.RegExp.$7 = o2.g0.RegExp.$7; } catch(e0) { } /*ODP-2*/Object.defineProperty(a0, \"wrappedJSObject\", { configurable: true, enumerable: false, get: f2, set: (function() { function f1(g1)  { print(x); }  return m2; }) }); return this.p2; }); } catch(e2) { } e0.delete(v2); return a1; });\n\nObject.preventExtensions(m1);\n");
/*fuzzSeed-71289653*/count=1150; tryItOut("v1 = (b1 instanceof a2);");
/*fuzzSeed-71289653*/count=1151; tryItOut("v1 = (a0 instanceof i0);");
/*fuzzSeed-71289653*/count=1152; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2\", \"i\"); var s = \"0\\n\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-71289653*/count=1153; tryItOut("\"use strict\"; \"use asm\"; let(b) ((function(){let(w) ((function(){let(grdvwj) ((function(){decodeURIComponent})());})());})());");
/*fuzzSeed-71289653*/count=1154; tryItOut("\"use strict\"; /*infloop*/for(d; null; window) {h0.toSource = (function(j) { f1(j); }); }");
/*fuzzSeed-71289653*/count=1155; tryItOut("/*RXUB*/var r = /(\\s($?)\\s)($)\\3/g; var s = window; print(s.replace(r, encodeURI)); ");
/*fuzzSeed-71289653*/count=1156; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(g1, this.g1.e1);");
/*fuzzSeed-71289653*/count=1157; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!$|(?:\\\\B)+*)[^\\u6110-\\uc47a\\\\W\\\\d]^\\\\S|(?:[^\\\\u0058]+?[\\u009d-\\\\u3658\\u00ec-\\\\u00Ce]\\\\D?){8589934591,8589934591}|[\\ud92c-\\\\ue190\\\\W]{2,4}\", \"gym\"); var s = \"\\uFAA9\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1158; tryItOut("i0.__iterator__ = DataView.prototype.setFloat32.bind(i2);");
/*fuzzSeed-71289653*/count=1159; tryItOut("/*infloop*/for(let [{NaN, y}, {w, e, w: x, x: {\u3056: {\u3056: window, a: {x: {y: d}, b: {eval: [e, x, {x: [], x}, {eval\u000c, z: {}, z: Uint16Array.prototype.BYTES_PER_ELEMENT}], x: window, x: {y: [], b}, \u3056: []}, x, window: window, e: eval}, x: {d: {x: {eval: {y}, window: [, {eval: x, w}, ], b}}, e: [[x], , NaN, {c: [, {}, []], window: [, {}]}, z], NaN, z: [, , []], x}, x: eval, c: x, Object.prototype.propertyIsEnumerable}, x, x, NaN: x, z: [{x, this.x: this.x}, {x: [{x: x, window}], x: [x, , , , {x: [], x, x}], eval, x}, d, , , ]}, x: [, , , , eval, /*\n*/, , {a: [[, {\u3056, eval: x, e: {a, x: [{}], x: x}\u0009}, , b, []], , , , , []], e, e, b: [[, , [, {x: (x = eval)}, ]], , {NaN: x, x: x, c: this.NaN}], window: {}}], undefined\u000c: y}, , , arguments, , , ] =  /x/ ; x; (4277) = (makeFinalizeObserver('nursery'))) if(true) { if (x) {v2 = t1.length; } else {/* no regression tests found */v1 = a2.length; }}");
/*fuzzSeed-71289653*/count=1160; tryItOut("print(x);");
/*fuzzSeed-71289653*/count=1161; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy0(Math.fround((mathy0(( + ( ! (((Math.pow((Math.fround(x) >> Math.fround(y)), y) >>> 0) >= Math.tan(y)) >>> 0))), (((((0x080000000 ? Math.acosh(x) : ((Math.atan(x) >>> 0) , (y >>> 0))) >>> 0) ** (x >>> 0)) >>> 0) >>> 0)) >>> 0)), (Math.pow((Math.log2((Math.min((x >>> 0), ((( + ( + (x | 0))) - ((Math.fround(y) > (-0x100000001 >>> 0)) >>> 0)) >>> 0)) >>> 0)) | 0), (mathy1(( ! (Math.hypot((0x0ffffffff | 0), y) | 0)), (Math.min((( + Math.imul((Math.tan((x >>> 0)) >>> 0), 0x100000000)) >>> 0), ((-Number.MAX_VALUE >>> ( ! 42)) >>> 0)) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy3, [false, '', (new Boolean(true)), 1, -0, (new Boolean(false)), (new String('')), '/0/', '\\0', objectEmulatingUndefined(), (new Number(-0)), ({valueOf:function(){return '0';}}), /0/, NaN, (function(){return 0;}), [], ({toString:function(){return '0';}}), true, undefined, (new Number(0)), 0.1, '0', 0, [0], null, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-71289653*/count=1162; tryItOut("s2.__proto__ = a2;");
/*fuzzSeed-71289653*/count=1163; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.asin(mathy1(Math.fround(( - (( ! 1) === ((( + y) <= (0 <= ( + y))) >>> 0)))), ( ! y)))); }); testMathyFunction(mathy2, [[], ({valueOf:function(){return '0';}}), (new String('')), '0', (new Boolean(false)), true, (new Boolean(true)), (new Number(-0)), NaN, ({toString:function(){return '0';}}), [0], (new Number(0)), undefined, 0.1, '/0/', '', '\\0', (function(){return 0;}), objectEmulatingUndefined(), false, 1, -0, /0/, 0, null, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-71289653*/count=1164; tryItOut("\"use asm\"; s2.valueOf = (function mcc_() { var avrkdr = 0; return function() { ++avrkdr; if (/*ICCD*/avrkdr % 4 != 2) { dumpln('hit!'); try { m0.get(f2); } catch(e0) { } v1 = evaluate(\"o1.o1 = g1;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (void shapeOf(Math.atan2(28, x))), sourceIsLazy: false, catchTermination: (x % 4 != 1) })); } else { dumpln('miss!'); try { for (var v of i2) { try { i0 = m1.keys; } catch(e0) { } try { v1 = (i0 instanceof i1); } catch(e1) { } v2 = g0.runOffThreadScript(); } } catch(e0) { } print(uneval(g1)); } };})();");
/*fuzzSeed-71289653*/count=1165; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.sinh(( + Math.log1p(Math.fround(( + Math.fround((Math.sinh((x >>> 0)) >>> 0))))))); }); testMathyFunction(mathy0, [-0x080000001, 1/0, -0x100000000, -Number.MIN_VALUE, 42, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0/0, 0, 1, -Number.MAX_VALUE, 2**53-2, 2**53+2, 0x100000001, -0x0ffffffff, -(2**53-2), -(2**53+2), Math.PI, 0x100000000, -0x080000000, -(2**53), 1.7976931348623157e308, 2**53, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001]); ");
/*fuzzSeed-71289653*/count=1166; tryItOut("mathy1 = (function(x, y) { return ( + ((((( ~ Math.hypot(0x080000001, -Number.MIN_VALUE)) - ( + y)) >>> (y >= Math.expm1(y))) + Math.hypot(Math.fround((Math.fround(Math.hypot(( + y), Math.log10(y))) >> Math.fround((( + (( ! Math.cosh(( + -0x07fffffff))) >>> 0)) >>> 0)))), ((1.7976931348623157e308 == (-0x0ffffffff < x)) | 0))) + ( + ( ~ Math.trunc(Math.fround(((Math.log1p(Math.fround(Math.abs(( + x)))) >>> 0) << y))))))); }); testMathyFunction(mathy1, [0x100000000, 0x100000001, -1/0, 2**53, 2**53+2, -0x07fffffff, 2**53-2, 1, 0x080000000, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53), -0x100000001, -0x0ffffffff, -0, 0, 1/0, -0x080000000, 0x080000001, 0x0ffffffff, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, -(2**53-2), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -0x080000001, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=1167; tryItOut("\"use strict\"; while((this.__defineGetter__(\"b\", (delete x.x))) && 0){this.a1 = r1.exec(s0); }");
/*fuzzSeed-71289653*/count=1168; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var log = stdlib.Math.log;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float64ArrayView[((/*FFI*/ff(((33554433.0)), ((((0xff3d4164)) | ((0xffffffff)))), ((((0x12f06062)) << ((0xeba98b94)))), ((1.5474250491067253e+26)), ((2251799813685249.0)), ((-134217729.0)), ((-1.25)), ((-16777217.0)), ((-1.0625)))|0)+(0x5d75a2bc)-((0xc2ccb74c))) >> 3]) = (((4277)));\n    i0 = (((((!((0xab22141) ? (0xffffffff) : (0x8cb32a6d)))-(!(0xfbc86fc7)))) > (((i0)+((0x892f97f8) >= (0x8f158c2b)))>>>((i0)+(i0)))) ? (!((-9.44473296573929e+21) < (+((9.0))))) : (0xc913ae34));\n    return +((d1));\n    return +((3.022314549036573e+23));\n    {\n      i0 = ((((((x)+((0x0))+(0xfd8716bb))|0) / ((-(i0)) >> ((/*FFI*/ff(((-1.0)))|0)+((0xd01cc2a0) > (0x14873c3e)))))>>>(((0xffffffff) ? ((((0xfe6c74c9)) & ((0x5f89800b)))) : ((((0xffe3e00e))>>>((0x284bab2e)))))*-0x8ef43)) < (0x3b725fff));\n    }\n    (Int32ArrayView[(((imul(((0xec6c6454) > (0x1e069c83)), (/*FARR*/[null,  /x/ ].sort %= x))|0) == (x))*-0xec130) >> 2]) = ((0x9d463d36)+(0x9e391185));\n    (Float64ArrayView[((0x492c8b7c)) >> 3]) = ((((d1)) / ((+log(((d1)))))));\n    d1 = ((d1) + ((4277)));\n    d1 = (NaN);\n    d1 = (d1);\n    d1 = (d1);\n    d1 = ((Uint32ArrayView[((i0)-(i0)-(i0)) >> 2]));\n    return +((+/*FFI*/ff(((18014398509481984.0)), ((2251799813685247.0)), ((524289.0)), ((-1.1805916207174113e+21)), ((~((((x) = -11 <=  /x/g  ** let (c = true) [z1]) < (abs((-0xcc4465))|0))+((((0xffffffff))>>>((0xfbb2eff4))))))), ((imul(((536870911.0) == (1.125)), (0xfb985c75))|0)), ((Int32ArrayView[1])), ((((-0x8000000)) | ((0x69faee00)))), ((+/*FFI*/ff(((576460752303423500.0)), ((-4.835703278458517e+24)), ((281474976710655.0)), ((511.0))))), ((131073.0)))));\n  }\n  return f; })(this, {ff: function(y) { print(x); }}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000000, 0x080000001, -0, 2**53+2, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 2**53-2, -1/0, 0/0, -0x0ffffffff, -0x100000001, -(2**53), -0x080000000, -(2**53-2), -(2**53+2), -0x100000000, 0x07fffffff, 0x100000001, 1, Number.MAX_SAFE_INTEGER, 0, 1/0, -Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 0.000000000000001, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=1169; tryItOut("testMathyFunction(mathy2, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, 1/0, 1, -0x100000000, 42, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -0, -0x080000000, 0x0ffffffff, 0/0, 2**53, Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, -1/0, -(2**53-2), 0x080000001, 0x100000000, 2**53-2, 2**53+2, -Number.MAX_VALUE, Math.PI, -0x07fffffff, -0x100000001, 0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-71289653*/count=1170; tryItOut("for(let x of Promise) ( \"\" );");
/*fuzzSeed-71289653*/count=1171; tryItOut("((yield d || undefined.e));");
/*fuzzSeed-71289653*/count=1172; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return Math.cbrt((( + (Math.max(y, ( + y)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-71289653*/count=1173; tryItOut("{/*infloop*/for(e = (void options('strict_mode')) <<= (\u3056(\"\\u9CCA\"))\n; undefined;  /x/g ) {/*bLoop*/for (var gxmcsc = 0; gxmcsc < 25; ++gxmcsc) { if (gxmcsc % 6 == 1) { v0 = (m2 instanceof a0); } else { t0 + h0; }  }  }/*infloop*/ for (var (eval(\"v1 = o2.t2.byteOffset;\", /*RXUE*/new RegExp(\"\\\\1\", \"m\").exec(\"\\n\"))).__proto__ of x | b) {Object.defineProperty(this, \"v2\", { configurable: false, enumerable: \"\\uBF4D\",  get: function() {  return f0[\"__proto__\"]; } }); } }");
/*fuzzSeed-71289653*/count=1174; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.sin(((Math.min(((Math.sinh((x >>> 0)) >>> 0) >>> 0), (( + Math.tan(( + (Math.pow(Math.sin(Math.asin(x)), ((Math.cos((Math.sign((Math.atan2((x | 0), (2**53 >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0)) | 0)))) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy2, [0x080000000, 0x0ffffffff, 2**53, 1/0, -(2**53), 2**53+2, Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, Number.MAX_VALUE, 0/0, 0x100000000, -(2**53-2), -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, Math.PI, 0.000000000000001, -Number.MIN_VALUE, -0x07fffffff, -0x080000001, 0x080000001, 1.7976931348623157e308, -0x100000001, -0, -0x0ffffffff, 1, 42, -0x080000000, 0x07fffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1175; tryItOut(" for  each(var z in x) {h0 + f1; }");
/*fuzzSeed-71289653*/count=1176; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((-2147483649.0));\n  }\n  return f; })(this, {ff: (EvalError).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [1/0, -0, -0x0ffffffff, 0x100000000, 1.7976931348623157e308, 0x100000001, 2**53+2, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 42, 1, -(2**53+2), -(2**53), -0x100000001, 0, 2**53, Math.PI, 0x080000001, -0x100000000, 0.000000000000001, 2**53-2, Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000000, -0x080000001]); ");
/*fuzzSeed-71289653*/count=1177; tryItOut("\"use strict\"; v2.toString = (function() { for (var j=0;j<154;++j) { f1(j%3==1); } });");
/*fuzzSeed-71289653*/count=1178; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.sinh((( + mathy0(( + ( ~ (y | 0))), Math.hypot(x, (( ! (y | 0)) | 0)))) >>> 0)); }); testMathyFunction(mathy2, [-0x0ffffffff, -0x100000001, -0x080000001, -0x080000000, Math.PI, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, 2**53-2, 1/0, 0x080000000, 0x07fffffff, Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 42, -0, 2**53+2, 1, -(2**53+2), -0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0/0, -0x100000000, -1/0, 1.7976931348623157e308, 0x100000000, 0x080000001, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=1179; tryItOut("print(h0);");
/*fuzzSeed-71289653*/count=1180; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; }");
/*fuzzSeed-71289653*/count=1181; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atan2(mathy0(Math.max(Number.MIN_SAFE_INTEGER, mathy0(y, x)), Math.abs((Math.expm1(Math.atanh(Math.pow(0x07fffffff, x))) >>> 0))), Math.log10((Math.hypot(Math.log10(x), ( + (x >> Math.fround(Math.asin(x))))) !== Math.fround((Math.fround(Math.atanh(Math.fround(( + x)))) ? Math.max(((Math.imul((y >>> 0), (y >>> 0)) >>> 0) ? Math.PI : x), y) : (Math.fround(Math.imul(x, x)) << Math.fround((Math.hypot(x, ( + ( + mathy0(x, ( + y))))) | 0)))))))); }); testMathyFunction(mathy1, [2**53+2, 0x080000001, 0x0ffffffff, 0x100000001, -0x0ffffffff, 1, 2**53-2, 1/0, 0x100000000, -0x080000001, 0, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, Math.PI, Number.MAX_VALUE, 0/0, -(2**53+2), -0, -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), Number.MIN_VALUE, -0x07fffffff, 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-71289653*/count=1182; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.pow((((Math.fround(Math.expm1((Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround(y))) | 0))) ? (y | 0) : ((mathy0((( ~ y) | 0), (-(2**53+2) | 0)) >>> 0) | 0)) | 0) ^ Math.exp(y)), Math.pow(((x | 0) === (Math.acosh((( ! (( ~ ( + Math.log2(( + y)))) >>> 0)) >>> 0)) >>> 0)), ( + ((( ~ 0x100000001) | 0) == ( + (((2**53 ? (( ~ (x >>> 0)) >>> 0) : -0) | 0) ^ x)))))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, 2**53, -(2**53+2), Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 1, Number.MAX_SAFE_INTEGER, -0x100000000, 0/0, -0x0ffffffff, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -0x080000001, 1/0, 0.000000000000001, 0, 1.7976931348623157e308, Math.PI, 0x100000001, -(2**53-2), 0x07fffffff, -0, -1/0, 0x100000000, -(2**53), 2**53-2, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001]); ");
/*fuzzSeed-71289653*/count=1183; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (Math.log((y >> ( + mathy0(y, ( + y))))) >>> 0)); }); testMathyFunction(mathy3, [(function(){return 0;}), NaN, (new Number(0)), 0, [], 1, (new Number(-0)), '', ({toString:function(){return '0';}}), [0], (new Boolean(true)), '0', -0, (new Boolean(false)), undefined, ({valueOf:function(){return '0';}}), '/0/', /0/, null, '\\0', true, ({valueOf:function(){return 0;}}), 0.1, (new String('')), objectEmulatingUndefined(), false]); ");
/*fuzzSeed-71289653*/count=1184; tryItOut("for (var v of b1) { try { print(uneval(g0.v1)); } catch(e0) { } try { v2 = (v1 instanceof p0); } catch(e1) { } try { h0.keys = this.f1; } catch(e2) { } v2 = evaluate(\"a0.pop();\", ({ global: o1.g2, fileName: null, lineNumber: 42, isRunOnce: x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(q) { return q; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function  x (eval, eval) { \"use strict\"; yield  \"\" ; } , hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { throw 3; }, iterate: (/*wrap2*/(function(){ var wndovg = true; var nijwrg = Array.isArray; return nijwrg;})()).bind, enumerate: function() { throw 3; }, keys: undefined, }; })(/\\S/gym), function (b) { \"use strict\"; yield b } ).valueOf(\"number\"), noScriptRval: (x % 57 == 31), sourceIsLazy: (x % 2 != 1), catchTermination: false })); }");
/*fuzzSeed-71289653*/count=1185; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x100000001, -0x100000001, 2**53, 0x100000000, Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, -0x100000000, -(2**53-2), -0x080000000, -0x080000001, 1/0, 0/0, 1.7976931348623157e308, 0.000000000000001, 0x080000000, 42, -0x0ffffffff, 0x0ffffffff, 2**53-2, 0x07fffffff, -(2**53+2), -0, -(2**53), Math.PI, 1, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 0]); ");
/*fuzzSeed-71289653*/count=1186; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ! ( + (Math.imul((( ! x) | 0), ( + (Math.tanh((Math.asinh((Math.fround(Math.atanh(y)) === Math.fround(y))) | 0)) | 0))) | 0))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, 0x080000001, -1/0, -Number.MAX_VALUE, -0x080000000, 0x100000001, 0, -0x100000001, 0x0ffffffff, -(2**53-2), 0.000000000000001, -(2**53+2), 42, Number.MAX_VALUE, Math.PI, 1, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, 1/0, 2**53+2, -0x100000000, -0x0ffffffff, 0/0, -(2**53), -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, 2**53]); ");
/*fuzzSeed-71289653*/count=1187; tryItOut("v0 = evaluate(\"function f0(h0)  { return /*UUV2*/(\\u3056.__lookupSetter__ = \\u3056.toString) } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 4 != 1), sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-71289653*/count=1188; tryItOut("{m0 + o2;Array.prototype.pop.apply(a1, [e2, let (c, hqavcf, x) /(?!.)/gi]); }");
/*fuzzSeed-71289653*/count=1189; tryItOut("Array.prototype.sort.apply(a1, [p0, a0]);");
/*fuzzSeed-71289653*/count=1190; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.acos(Math.fround(Math.fround((((Math.sin(((Math.imul((x | 0), (x >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0) == ( + ( ! ( + ((((Math.hypot((y >>> 0), x) >>> 0) >>> 0) - ( + Math.asin(Math.fround(0)))) >>> 0))))))))); }); ");
/*fuzzSeed-71289653*/count=1191; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1192; tryItOut("a0.pop(o0.g2.g0.b1);");
/*fuzzSeed-71289653*/count=1193; tryItOut("\"use strict\"; g2.a0.toString = (function mcc_() { var zzsltn = 0; return function() { ++zzsltn; if (zzsltn > 2) { dumpln('hit!'); /*MXX1*/const this.o1 = g1.String.prototype.strike; } else { dumpln('miss!'); s1 = ''; } };})();");
/*fuzzSeed-71289653*/count=1194; tryItOut("/*tLoop*/for (let d of /*MARR*/[1, function(){}, function(){}, function(){}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, 1, function(){}, 0xB504F332, x]) { a0 = /*FARR*/[.../*FARR*/[/*oLoop*/for (gcaews = 0; gcaews < 60; ++gcaews) { Object.prototype.watch.call(a1, -16, (function mcc_() { var einegq = 0; return function() { ++einegq; if (/*ICCD*/einegq % 7 != 0) { dumpln('hit!'); try { m2.get(g2); } catch(e0) { } try { /*RXUB*/var r = g2.r1; var s = \"+_+_+_+_+_+_\"; print(s.search(r));  } catch(e1) { } o2.g1.f0(v2); } else { dumpln('miss!'); try { /*MXX1*/o1 = g1.Date.prototype.setUTCDate; } catch(e0) { } try { o2.__proto__ = t0; } catch(e1) { } try { v2 = true; } catch(e2) { } Array.prototype.reverse.call(a2); } };})()); } , , (({\"9\": /*UUV1*/(a.log1p = Math.imul) })),  \"\" ], x, , null instanceof null]; }");
/*fuzzSeed-71289653*/count=1195; tryItOut("b0.toSource = f0;");
/*fuzzSeed-71289653*/count=1196; tryItOut("o1.v1 = (m1 instanceof a0);");
/*fuzzSeed-71289653*/count=1197; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + mathy2((Math.atan2(( + mathy3(((Math.expm1(( + -0x100000001)) >= Math.fround((Math.fround((Math.atanh((x >>> 0)) >>> 0)) ^ Math.acosh(-0x100000000)))) | 0), Math.fround(( + Math.asinh(Math.fround(( - (((( ~ x) <= (-(2**53-2) >>> 0)) >>> 0) | 0)))))))), (((Math.fround(( - Math.fround(Math.fround(Math.imul(x, /*tLoop*/for (let x of /*MARR*/[new Boolean(true), objectEmulatingUndefined(), x, new Boolean(true), x, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), x, new Boolean(true), objectEmulatingUndefined(), x, new Boolean(true), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Boolean(true), x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), x]) { ({a1:1}); }))))) >>> 0) + (Math.fround((y & 1)) | 0)) | 0)) | 0), ( + Math.tanh(( + ( ! ((y | 0) << x))))))); }); ");
/*fuzzSeed-71289653*/count=1198; tryItOut("\"use asm\"; testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 2**53, 0x07fffffff, 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53-2), 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0.000000000000001, -0x080000001, -0x080000000, 0, 42, -0x0ffffffff, -0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, Number.MAX_VALUE, -1/0, -0, -(2**53), Math.PI, 0/0, -Number.MAX_VALUE, 0x080000000, 2**53+2, -0x100000000, 0x080000001, 0x100000001, 2**53-2, Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1199; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return (( + Math.atan2(( + Math.log10((Math.log10(((( + Number.MAX_SAFE_INTEGER) >>> 0) | 0)) >>> 0))), ( + Math.fround(((( + ( ~ Math.fround(-Number.MAX_SAFE_INTEGER))) || y) & ( - ( - y))))))) ? ( ! Math.max(Math.atan2((y & ( + (Math.imul((y | 0), (y | 0)) | 0))), Math.hypot(Math.fround(2**53), ( + x))), Math.imul(Math.fround((y !== x)), ( + mathy0(( + mathy0(x, x)), ( + 2**53-2)))))) : ( + (Math.pow(Math.fround((y ? -Number.MAX_SAFE_INTEGER : y)), Math.max(((( + (y * Math.max(Math.fround(x), Math.fround(y)))) ^ Math.hypot(Math.atan(y), x)) >>> 0), x)) >>> 0))); }); testMathyFunction(mathy1, [[0], ({valueOf:function(){return 0;}}), '/0/', -0, (new String('')), null, ({toString:function(){return '0';}}), (new Number(-0)), (new Boolean(true)), 0.1, /0/, 1, '0', objectEmulatingUndefined(), (new Number(0)), 0, (new Boolean(false)), NaN, '\\0', '', ({valueOf:function(){return '0';}}), [], false, undefined, true, (function(){return 0;})]); ");
/*fuzzSeed-71289653*/count=1200; tryItOut("\"use strict\"; L:if(true\u000c) {v1 = a1.length;for (var p in o1.t0) { try { for (var v of a1) { try { v1 = (i1 instanceof f2); } catch(e0) { } for (var v of i0) { try { h1.hasOwn = g1.o0.f0; } catch(e0) { } try { t2 = new Int8Array(t2); } catch(e1) { } a2.sort((function() { Array.prototype.splice.call(a0,  \"\" ); return h2; }), this.g2); } } } catch(e0) { } g0.a1 = arguments; } } else {print(null);e2.has(p0); }");
/*fuzzSeed-71289653*/count=1201; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1025.0;\n    return +((+abs(((+(-1.0/0.0))))));\n  }\n  return f; })(this, {ff: Date.parse}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x07fffffff, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, -0x100000000, -0x100000001, 1.7976931348623157e308, 0x0ffffffff, 1/0, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, 1, Math.PI, 0x080000001, -0x0ffffffff, -(2**53-2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000, 0x080000000, 42, Number.MAX_VALUE, 2**53, -(2**53+2), -0, 0, -Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, 0x100000000, 0x100000001]); ");
/*fuzzSeed-71289653*/count=1202; tryItOut("mathy3 = (function(x, y) { return ( + (( + (((((((Math.pow((Math.fround(( - x)) | 0), (Math.fround((-(2**53-2) ? ( + y) : Math.imul((y >>> 0), -Number.MAX_SAFE_INTEGER))) | 0)) | 0) ? (((Math.fround(Math.min(0x07fffffff, x)) >>> 0) !== (y >>> 0)) >>> 0) : Math.acos(Math.fround(Math.atan2(((Math.atan2((x | 0), (x | 0)) | 0) >>> 0), Math.fround(x))))) | 0) - (Math.fround(Math.tan(Math.fround(y))) | 0)) | 0) && Math.fround(Math.fround(( + (( - (x | 0)) | 0))))) | 0)) >= ( + Math.fround(Math.min(Math.fround(( + Math.imul(( + Math.pow((Math.fround(y) | 0), x)), x))), Math.fround((y ^ (x | 0)))))))); }); testMathyFunction(mathy3, /*MARR*/[ '' ,  '' ,  '' , (0/0), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  '' , x, x, (0/0), x,  '' , (0/0), (0/0), x, x, x, x,  '' , x, x,  '' , x, x,  '' , x,  '' , (0/0), (0/0), x,  '' , (0/0),  '' , x,  '' , x, (0/0), x, (0/0), x,  '' , x, (0/0), (0/0), (0/0),  '' , x,  '' , x, (0/0),  '' , (0/0), (0/0),  '' , (0/0),  '' , x,  '' , x, x,  '' , (0/0), x, x, x]); ");
/*fuzzSeed-71289653*/count=1203; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.fround(( ~ ( + (Math.pow(mathy0(Math.fround((Math.atan(x) || x)), ( + Math.fround((( - (x >>> 0)) >>> 0)))), Math.min(y, y)) >>> ( + y))))), Math.fround(( + ( + Math.expm1(Math.max((Math.max(Math.fround(Math.tan((function(x, y) { return x; }))), y) | 0), ( - (Math.PI && Math.imul((y >>> 0), (x >>> 0))))))))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 1/0, -1/0, 0x07fffffff, 0, 1, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, 0/0, 0x0ffffffff, 42, -0x07fffffff, 1.7976931348623157e308, 2**53-2, -(2**53+2), Number.MAX_VALUE, 0x100000001, 0x080000000, -(2**53), -(2**53-2), -0x100000000, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -0x080000001, -0x100000001, 0x100000000]); ");
/*fuzzSeed-71289653*/count=1204; tryItOut("print(uneval(v0));");
/*fuzzSeed-71289653*/count=1205; tryItOut("f0 = m2.get(m2);print(x);");
/*fuzzSeed-71289653*/count=1206; tryItOut("g0.a2.unshift(o2.i2);");
/*fuzzSeed-71289653*/count=1207; tryItOut("\"use strict\"; { void 0; bailout(); } b2.__iterator__ = (function() { try { for (var v of h2) { try { this.v0 = this.t2.length; } catch(e0) { } try { b2 + ''; } catch(e1) { } try { v1 = g2.runOffThreadScript(); } catch(e2) { } ; } } catch(e0) { } try { o1.v0 = evaluate(\"print(x);\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 != 1), noScriptRval: true, sourceIsLazy: x, catchTermination: (x % 5 != 0) })); } catch(e1) { } try { o0.g2.v1 = Object.prototype.isPrototypeOf.call(a2, o2); } catch(e2) { } e0.add(m2); return m0; });");
/*fuzzSeed-71289653*/count=1208; tryItOut("with({}) { let(b) { this.zzz.zzz;} } ");
/*fuzzSeed-71289653*/count=1209; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.cosh(( + Math.min(( + ((( ~ y) ? (mathy0(( + x), -0x100000001) | 0) : ((Math.fround(mathy4(2**53-2, Math.fround(y))) >= Math.fround(Math.hypot(y, (Math.tanh((x | 0)) | 0)))) | 0)) | 0)), Math.fround(Math.abs(( + y))))))); }); testMathyFunction(mathy5, [-0x100000001, -0x080000000, -0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, -0x080000001, 2**53+2, -(2**53-2), -1/0, Number.MAX_VALUE, 0x080000000, -0x07fffffff, 0, 2**53, Number.MIN_VALUE, 1, 0.000000000000001, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, -0, -Number.MIN_VALUE, 0x07fffffff, 0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, 1/0]); ");
/*fuzzSeed-71289653*/count=1210; tryItOut("mathy3 = (function(x, y) { return (((Math.atan2(Math.fround(( + ((( + encodeURIComponent) | 0) ? (Math.max((Math.imul(-Number.MIN_SAFE_INTEGER, Math.fround(mathy2(Math.fround(( ! y)), Math.fround(x)))) >>> 0), (x | 0)) >>> 0) : ( + Math.atan2(Math.fround(Math.fround(((Math.sqrt(Math.fround(-0)) | 0) << Math.fround((( + y) && (y | 0)))))), Math.fround((( ! ( + Math.fround(mathy1((-0 | 0), (y == y))))) >>> 0))))))), Math.cos(x)) | 0) !== (( - (( - (((Math.atan2(x, x) | 0) >>> Math.atan(x)) >>> 0)) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-71289653*/count=1211; tryItOut("mathy0 = (function(x, y) { return (Math.imul((( - (0.000000000000001 >>> 0)) >>> 0), (Math.expm1(Math.min(Math.imul(-0x100000001, x), -0)) || Math.exp((0x0ffffffff | 0)))) & (( + (((( ! Number.MIN_VALUE) | 0) || Math.fround(x)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [2**53, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), 1/0, Math.PI, -Number.MAX_VALUE, Number.MIN_VALUE, 1, 0.000000000000001, 0x07fffffff, 0, 42, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53+2), 0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -0x07fffffff, 0/0, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, 0x100000001, -0x100000000, 1.7976931348623157e308, -(2**53), -0x0ffffffff, -1/0, 0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=1212; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.imul(Math.atan2(( - (y | 0)), (Math.min(Math.fround(Math.min(Math.round(-(2**53-2)), ( + (y * ( + ((x % x) | 0)))))), x) | 0)), Math.fround(Math.atanh(( + Math.hypot(( + ( + (( + ( + (( + x) << ( + x)))) ? ( + 1/0) : ( + -Number.MAX_SAFE_INTEGER)))), ( + ((Math.sinh(x) < (Math.clz32(-(2**53+2)) | 0)) | 0))))))) ** (( + ( + ( + (( ~ 0) < (( ~ Math.trunc(Math.pow(y, x))) >>> 0))))) ? ( + ((( ~ (Math.pow(0, (Math.pow(y, (y | 0)) | 0)) | 0)) | 0) | 0)) : Math.imul(((((y >>> 0) === (( + (Math.fround(Math.ceil(y)) === (2**53+2 | 0))) >>> 0)) >>> 0) >>> 0), (Math.imul(x, ((Math.log1p((x >>> 0)) | 0) ? y : -0x100000000)) | 0)))); }); testMathyFunction(mathy0, [-0x080000000, 42, Number.MIN_VALUE, -0x07fffffff, -(2**53-2), 2**53+2, -(2**53), 0x0ffffffff, 0/0, Number.MAX_VALUE, 0x100000000, -0, 0x100000001, -(2**53+2), 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 0, -0x100000000, 2**53, 1, 1/0, -1/0, -Number.MIN_VALUE, -0x080000001, -0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1213; tryItOut("\"use strict\"; this.v2 = new Number(t2);");
/*fuzzSeed-71289653*/count=1214; tryItOut("mathy0 = (function(x, y) { return Math.log2((Math.max(Math.fround(Math.fround((Math.fround((Math.atan2(x, (( + y) >>> 0)) >>> 0)) ? Math.imul((( - -(2**53-2)) >>> 0), Math.pow(Math.fround((Math.fround(x) === Math.fround(x))), Math.fround(y))) : ((y >>> 0) / (((y >>> 0) ? (y >>> 0) : (Math.clz32(0) >>> 0)) >>> 0))))), (Math.imul(Math.atan2((y | 0), Math.log(Math.exp((0x080000000 | 0)))), ((x << ( + (((x >>> 0) && ((0/0 || x) >>> 0)) >>> 0))) | 0)) | 0)) | 0)); }); testMathyFunction(mathy0, [Math.PI, -0x080000000, -Number.MIN_VALUE, -(2**53), Number.MAX_VALUE, -0x100000001, 1/0, 0/0, 0, 0.000000000000001, 2**53-2, Number.MIN_VALUE, -1/0, -0x0ffffffff, 1, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, 2**53, 2**53+2, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, -0, 0x07fffffff, -(2**53-2), 0x100000001, -0x080000001, 0x100000000, 0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-71289653*/count=1215; tryItOut("mathy5 = (function(x, y) { return Math.hypot(Math.max(( + ((((Math.fround((Math.trunc((Math.fround(y) | (-1/0 >>> 0))) ^ Math.fround((Math.max((x >>> 0), (y >>> 0)) >>> 0)))) | 0) >= (y | 0)) | 0) + (Math.tanh(Math.ceil(Math.fround(x))) | 0))), Math.fround(Math.expm1(( ~ ((( + (((x >>> 0) === (y >>> 0)) >>> 0)) ? (x >>> 0) : (x >>> 0)) | 0))))), (Math.fround(Math.min(Math.fround((Math.pow(y, (mathy2((-1/0 | 0), ((Math.atan2(-0x080000000, Math.fround(-0x07fffffff)) | 0) ^ ( + y))) | 0)) >>> 0)), (mathy4(y, 0.000000000000001) | 0))) & mathy2(( - Math.min(y, x)), ( + (( ! x) , x))))); }); testMathyFunction(mathy5, [42, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, 0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, -0x080000001, 0x0ffffffff, -0x0ffffffff, 2**53+2, 1/0, Number.MAX_VALUE, 1.7976931348623157e308, 0/0, 0x080000001, 2**53-2, -0x07fffffff, -(2**53+2), -Number.MAX_VALUE, 1, -0, 0x080000000, 2**53, -Number.MIN_VALUE, -0x100000000, 0.000000000000001, -0x080000000, Math.PI, 0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000]); ");
/*fuzzSeed-71289653*/count=1216; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-71289653*/count=1217; tryItOut("/*oLoop*/for (let wilezc = 0, mkbkll; wilezc < 25; ++wilezc) { a2.push(a1, a0, a0); } ");
/*fuzzSeed-71289653*/count=1218; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.fround((( ~ (( + Math.min(( + (Math.max(y, ( ~ y)) || y)), ( + ((y ? y : Math.fround(( + x))) <= (x >>> 0))))) | 0)) >>> 0)), ((( + ( + Math.max(( + (((mathy0((Math.cos((y | 0)) >>> 0), 0x100000001) | 0) << (x | 0)) | 0)), (Math.trunc((( ! -Number.MIN_VALUE) >> (Math.pow(y, y) | 0))) >>> 0)))) | (Math.cos(Math.round(x)) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-0, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), 2**53+2, 0x0ffffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, 0, -(2**53), 2**53-2, -0x080000001, -0x080000000, 1.7976931348623157e308, -(2**53+2), 0x080000001, -Number.MAX_VALUE, 0x100000000, 0x07fffffff, -0x0ffffffff, -0x100000000, 0/0, -1/0, 0x080000000, 0x100000001, -Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, -0x100000001, 1]); ");
/*fuzzSeed-71289653*/count=1219; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a2, [v0]);");
/*fuzzSeed-71289653*/count=1220; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (Math.max(x, Math.fround(Math.asin(Math.fround(2**53-2)))) >= (((( + y) != y) >>> 0) <= (( + ( - ((((x >>> 0) && (x >>> 0)) >>> 0) | 0))) === mathy1(y, ( ! Math.asin(y))))))); }); ");
/*fuzzSeed-71289653*/count=1221; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + mathy0(Math.fround(( ! Math.pow((y | 0), (Math.asinh(x) | 0)))), Math.fround((Math.fround(((mathy0(y, (x * 2**53)) ? ( + Math.asin(-Number.MAX_SAFE_INTEGER)) : ( + (( + x) && y))) | (Math.atan2((( ~ Math.fround(-0)) | 0), Math.fround(x)) >>> 0))) || ( ~ (((Math.clz32(( ! x)) | 0) ** x) >>> 0)))))); }); testMathyFunction(mathy1, [0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, 2**53+2, Number.MIN_VALUE, 0x100000000, -Number.MIN_VALUE, 1, -0x080000000, -0x0ffffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, Math.PI, Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 0, -(2**53+2), 0x080000001, 0x07fffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, -0x100000000, 42, 1/0, -1/0, -(2**53-2), -Number.MAX_VALUE, -(2**53), 0x080000000]); ");
/*fuzzSeed-71289653*/count=1222; tryItOut("a1.unshift(f1, this.b0);\n/*RXUB*/var r = r0; var s = \"_\\n\"; print(r.exec(s)); \n");
/*fuzzSeed-71289653*/count=1223; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(((((Math.pow(-0, ( + ( ~ ( + Number.MIN_SAFE_INTEGER)))) >>> 0) / ((( + Math.pow(( + (y < y)), ( + Math.fround(Math.min(x, Math.fround(((-Number.MIN_VALUE >>> 0) >= (y >>> 0)))))))) - x) >>> 0)) >>> 0) ? ((((( ! x) ? x : Math.fround((Math.fround(y) ? Math.fround(((Math.fround(((Math.cos((y >>> 0)) >>> 0) >>> 0)) >>> 0) - (y >>> 0))) : Math.fround(-0x080000001)))) | 0) <= (Math.max(x, (Math.tanh(( + (( + y) / Math.fround(-Number.MIN_VALUE)))) | 0)) | 0)) | 0) : ( + Math.trunc((( + Math.sign((Math.fround(( + Math.fround(x))) | 0))) | 0))))); }); testMathyFunction(mathy4, [0x07fffffff, 0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x100000000, 2**53, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, 1, 0x0ffffffff, -Number.MIN_VALUE, -0x080000001, 2**53-2, 0x100000000, 1/0, 42, Math.PI, 0, -(2**53), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, -1/0, 0/0, 1.7976931348623157e308, -0x080000000, -(2**53+2), -(2**53-2), 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-71289653*/count=1224; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.fround((( - (Math.min(Math.atan2(y, mathy1(y, 0.000000000000001)), ( + Math.fround(mathy2(-(2**53-2), y)))) >>> 0)) | 0))); }); ");
/*fuzzSeed-71289653*/count=1225; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( + ( + ( + Math.min((( ~ -1/0) >>> 0), ((y ^ (((Math.sin(( + (y ^ (x | 0)))) >>> 0) * (Math.min(-0x0ffffffff, x) >>> 0)) | 0)) >>> 0))))) ** ( + (((( - Math.expm1(Math.fround((Math.fround(x) * Math.fround(y))))) | (Math.trunc(((y ? y : Math.max(y, (y | 0))) | 0)) | 0)) | 0) && ( + Math.pow(((Math.expm1(((Math.min((0x100000000 >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0) | 0), y))))); }); testMathyFunction(mathy1, [0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -0x07fffffff, 1/0, Number.MIN_VALUE, 0x100000000, 42, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53-2, -0x080000001, -(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, -1/0, 2**53+2, 1, -0x100000001, 0/0, Math.PI, -(2**53), -0x0ffffffff, -0x080000000, 0, Number.MAX_VALUE, 0x0ffffffff, -(2**53+2), -0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=1226; tryItOut("let d, NaN = [( \"\" .watch(\"getFullYear\", (1 for (x in []))))], x = new function  b (y)allocationMarker()(x), eval, x = x, kshrgy, y = (makeFinalizeObserver('nursery')), w, window = (x.watch(\"7\", Uint8ClampedArray) >= (4277));v2 = a1.length;");
/*fuzzSeed-71289653*/count=1227; tryItOut("\"use asm\"; this.m0.delete(p1);");
/*fuzzSeed-71289653*/count=1228; tryItOut("/*MARR*/[new Boolean(true), \"\\u3099\", \"\\u3099\", function(){}, \"\\u3099\", function(){}, function(){}, \"\\u3099\", \"\\u3099\", function(){}, \"\\u3099\", new Boolean(true), \"\\u3099\", function(){}, new Boolean(true), function(){}, \"\\u3099\", \"\\u3099\", function(){}, function(){}, new Boolean(true), new Boolean(true), \"\\u3099\", function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, \"\\u3099\", function(){}, \"\\u3099\", function(){}, \"\\u3099\", \"\\u3099\", function(){}, new Boolean(true), function(){}, function(){}, new Boolean(true), \"\\u3099\", \"\\u3099\", function(){}, function(){}, \"\\u3099\", \"\\u3099\", function(){}, \"\\u3099\", new Boolean(true), function(){}, new Boolean(true), function(){}, \"\\u3099\", function(){}, new Boolean(true), \"\\u3099\", function(){}, \"\\u3099\", function(){}, function(){}, function(){}, new Boolean(true), \"\\u3099\", \"\\u3099\", \"\\u3099\", function(){}].filter(Object.is, \"\\uD4B7\");");
/*fuzzSeed-71289653*/count=1229; tryItOut("t0[14];");
/*fuzzSeed-71289653*/count=1230; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1231; tryItOut("mathy0 = (function(x, y) { return ( - ( + Math.log2(( + Math.asinh(( + y)))))); }); ");
/*fuzzSeed-71289653*/count=1232; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot((Math.fround(( - Math.atanh(( + Math.imul(Math.fround((Math.min(((x ? (x | 0) : Math.fround(-0)) >>> 0), (x >>> 0)) >>> 0)), Math.fround(y)))))) ? Math.fround(Math.expm1(( + (Math.clz32((Math.hypot(Math.hypot(x, y), x) >>> 0)) >>> 0)))) : Math.fround((Math.cos(Math.hypot(x, ( ~ mathy1(x, -(2**53))))) | 0))), (Math.acosh(((( + (((x | 0) >>> ( ! ( + (( + x) >>> (x | 0))))) | 0)) >= ( + Math.imul(1/0, y))) | 0)) | 0)); }); testMathyFunction(mathy3, [2**53-2, 1.7976931348623157e308, 0.000000000000001, 0x100000000, -0x080000001, 0/0, 42, 0x0ffffffff, -0x080000000, Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, -1/0, -(2**53), 1, -0, 0, Number.MAX_VALUE, 2**53, Math.PI, -0x100000000, -(2**53+2), -0x100000001, -Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, 2**53+2, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=1233; tryItOut("/*iii*//*wrap2*/(function(){ var mzhjzo =  /x/ ; var gafqvo = Array.prototype.concat; return gafqvo;})()('fafafa'.replace(/a/g, function(y) { (function ([y]) { }); }), \"\\u6747\");/*hhh*/function kquehw(a, e = (a = x)){;}");
/*fuzzSeed-71289653*/count=1234; tryItOut("v0 = evalcx(\"/* no regression tests found */\", g1);");
/*fuzzSeed-71289653*/count=1235; tryItOut("\"use asm\"; m0.has(v0);");
/*fuzzSeed-71289653*/count=1236; tryItOut("/*MXX1*/o1 = g2.Array.prototype.includes;");
/*fuzzSeed-71289653*/count=1237; tryItOut("var e = ((makeFinalizeObserver('tenured')));v0 = (i0 instanceof o1.g2);");
/*fuzzSeed-71289653*/count=1238; tryItOut("let x = (let (x = -4)  '' );/*vLoop*/for (nbrexc = 0; ((void version(170))) && nbrexc < 32; ++nbrexc) { var y = nbrexc; ((void options('strict_mode')));o1 = this.g0.t0[4]; } ");
/*fuzzSeed-71289653*/count=1239; tryItOut("e0.add(o1.f1);");
/*fuzzSeed-71289653*/count=1240; tryItOut("testMathyFunction(mathy0, [2**53-2, 0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, -1/0, -(2**53), -0x100000000, 0x0ffffffff, 0, 0x100000001, -Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, 0x080000000, 1/0, -0x080000001, 1, -0x100000001, 0/0, -0x080000000, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 0.000000000000001, -0, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53+2, 2**53, Number.MAX_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1241; tryItOut("\"use strict\"; a2.unshift(a2, s2, p2, e1);print(allocationMarker());");
/*fuzzSeed-71289653*/count=1242; tryItOut("\"use strict\"; g0.v0 = g2.r2.compile;");
/*fuzzSeed-71289653*/count=1243; tryItOut(";");
/*fuzzSeed-71289653*/count=1244; tryItOut("v2 = (a0 instanceof g2);");
/*fuzzSeed-71289653*/count=1245; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy0(( + Math.atan2(0, x)), ( + (( ! (y >>> 0)) >>> 0))) ? Math.ceil(( + ( ! Math.log(( + Math.max((1.7976931348623157e308 >>> 0), x)))))) : (mathy0((Math.acos((Math.min(y, x) >>> 0)) >>> 0), Math.fround(( ~ Math.sign(x)))) >>> 0)); }); testMathyFunction(mathy2, ['/0/', (new Number(-0)), '', /0/, (function(){return 0;}), false, ({toString:function(){return '0';}}), '\\0', ({valueOf:function(){return 0;}}), (new String('')), [0], NaN, true, null, '0', [], 0.1, ({valueOf:function(){return '0';}}), (new Boolean(true)), (new Number(0)), 0, -0, (new Boolean(false)), 1, undefined, objectEmulatingUndefined()]); ");
/*fuzzSeed-71289653*/count=1246; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ! Math.pow((Math.fround(y) >> (Math.tan((Math.asin(-Number.MAX_VALUE) >>> 0)) >>> 0)), Math.min(Number.MAX_SAFE_INTEGER, Math.fround(mathy0(y, -Number.MAX_SAFE_INTEGER))))) | 0); }); testMathyFunction(mathy3, [null, 0, ({valueOf:function(){return 0;}}), '/0/', ({toString:function(){return '0';}}), (new Boolean(true)), (function(){return 0;}), NaN, objectEmulatingUndefined(), false, (new String('')), 0.1, (new Boolean(false)), (new Number(0)), '', -0, '0', [], '\\0', [0], ({valueOf:function(){return '0';}}), /0/, undefined, (new Number(-0)), true, 1]); ");
/*fuzzSeed-71289653*/count=1247; tryItOut("\"use strict\"; this.a1.splice(NaN, 0, i2);");
/*fuzzSeed-71289653*/count=1248; tryItOut("\"use strict\"; i0 + p1;");
/*fuzzSeed-71289653*/count=1249; tryItOut("mathy3 = (function(x, y) { return Math.fround((Math.fround(Math.cos(Math.tan(Math.fround(( + Math.log1p(( + ((Math.log((y >>> 0)) >>> 0) !== y)))))))) !== (Math.asinh(Math.log10((( + (( + (y >>> 0)) ? ((( ! x) | 0) >>> 0) : ( + mathy1(y, (y | 0))))) < (Math.imul(((y % (y << x)) >>> 0), (x >>> 0)) >>> 0)))) >>> 0))); }); ");
/*fuzzSeed-71289653*/count=1250; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.round((( ! Math.tan(( + Math.atan2(Math.hypot((Math.min(((x ? x : x) >>> 0), ( + y)) >>> 0), y), Math.fround(y))))) | 0)); }); testMathyFunction(mathy5, [0x080000000, -(2**53-2), -0, -Number.MAX_SAFE_INTEGER, -(2**53), -1/0, Math.PI, 0/0, 0, 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 0x100000000, 2**53, 0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, -0x080000000, 0x07fffffff, -0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, 1/0, 42, -Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, -0x0ffffffff, -0x080000001, 0x080000001, -0x100000000, 2**53-2]); ");
/*fuzzSeed-71289653*/count=1251; tryItOut(";\n\"\\uB8EE\";\n");
/*fuzzSeed-71289653*/count=1252; tryItOut("for(var \u000db = Math.fround(eval(\"x\", ((function fibonacci(umvjxx) { ; if (umvjxx <= 1) { print(x);; return 1; } ; return fibonacci(umvjxx - 1) + fibonacci(umvjxx - 2);  })(0)) >>> this).throw( /x/ )) in Math.expm1(-3)) m0.delete(this.g2);");
/*fuzzSeed-71289653*/count=1253; tryItOut("v1 = Object.prototype.isPrototypeOf.call(s2, p2);");
/*fuzzSeed-71289653*/count=1254; tryItOut("e2.delete(b0);");
/*fuzzSeed-71289653*/count=1255; tryItOut("mathy3 = (function(x, y) { return ( ! Math.acosh(Math.trunc(Math.fround(( ! Math.fround(Math.fround(( - 0x100000000)))))))); }); testMathyFunction(mathy3, ['', ({valueOf:function(){return '0';}}), [0], 1, (new Boolean(false)), false, ({toString:function(){return '0';}}), '\\0', (new Number(0)), NaN, /0/, [], 0.1, undefined, null, objectEmulatingUndefined(), (new Boolean(true)), '/0/', 0, (new String('')), '0', ({valueOf:function(){return 0;}}), -0, (new Number(-0)), true, (function(){return 0;})]); ");
/*fuzzSeed-71289653*/count=1256; tryItOut("mathy5 = (function(x, y) { return Math.imul((Math.clz32((Math.exp(Math.fround(( + (Math.cosh(( + x)) | 0)))) >>> 0)) >>> 0), (( + (((x >= x) / x) | 0)) | 0)); }); testMathyFunction(mathy5, [42, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, 0.000000000000001, -0, 2**53, 1.7976931348623157e308, -0x07fffffff, 0/0, -(2**53+2), 0x080000000, -Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -0x100000000, -(2**53), -0x0ffffffff, 0x0ffffffff, 2**53+2, -0x080000001, -Number.MIN_VALUE, 0x080000001, 1, 0x100000000, 0, 0x07fffffff, -0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1257; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((Math.fround(( + ( + ( + Math.cbrt(y))))) >= ( + (Math.max(((( ~ (y | 0)) | 0) | 0), ((-Number.MAX_VALUE != -1/0) | 0)) | 0))) ** Math.fround(( + (Math.hypot((y | 0), (x | 0)) | 0)))) | 0); }); testMathyFunction(mathy1, [0.000000000000001, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 42, 2**53-2, Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, Math.PI, 1/0, 2**53, Number.MIN_SAFE_INTEGER, 0x100000001, 0x07fffffff, 1, Number.MAX_VALUE, -(2**53-2), 0x080000000, -0x100000001, -0x07fffffff, 0/0, -(2**53), -0, -1/0, 0x0ffffffff, -0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), 0x100000000, 0, -0x080000000]); ");
/*fuzzSeed-71289653*/count=1258; tryItOut("\"use strict\"; testMathyFunction(mathy3, [42, Math.PI, 1/0, -Number.MAX_VALUE, -0x080000001, 0x07fffffff, 2**53-2, -(2**53+2), 2**53+2, -0, -(2**53), Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, -0x080000000, 1, 0x100000001, 0x0ffffffff, 0.000000000000001, -0x07fffffff, 0/0, 0x100000000, -0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, Number.MIN_SAFE_INTEGER, -1/0, 2**53, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1259; tryItOut("\"use strict\"; selectforgc(g0.o1);");
/*fuzzSeed-71289653*/count=1260; tryItOut("/*RXUB*/var r = r0; var s = s2; print(r.test(s)); function valueOf() { \"use strict\"; return NaN in x } s2 = s2.charAt(v0);");
/*fuzzSeed-71289653*/count=1261; tryItOut("for (var p in f0) { try { h1.delete = g0.f0; } catch(e0) { } try { e2.has(h0); } catch(e1) { } s1 += 'x'; }");
/*fuzzSeed-71289653*/count=1262; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1263; tryItOut("a2.splice(12, 5, m1, i1);\ns0 = m0.get(v2);\n");
/*fuzzSeed-71289653*/count=1264; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.min(Math.pow(Math.hypot((( + 0/0) | ( + ( + Math.hypot((x >>> 0), y)))), x), (Math.asin(((Math.imul(( + Math.log10(( + x))), Math.acosh(Math.fround((Math.cos(( + x)) | 0)))) | 0) | 0)) | 0)), Math.fround((((( + Math.pow((Math.asin((Math.log((Math.fround(Math.acos(Math.fround(x))) | 0)) | 0)) | 0), (( + ( + ( - y))) | 0))) | 0) >> (Math.sqrt(((Math.atanh((Math.sqrt(x) >>> 0)) | 0) >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy1, [-1/0, Math.PI, -0x080000001, -0x07fffffff, 2**53+2, 0/0, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, 2**53, 2**53-2, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 0x0ffffffff, -0, -Number.MIN_VALUE, -(2**53+2), -0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, 1/0, 0x080000000, 0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53), -0x080000000, 0x07fffffff, 0x100000001, 42]); ");
/*fuzzSeed-71289653*/count=1265; tryItOut("\"use strict\"; ");
/*fuzzSeed-71289653*/count=1266; tryItOut("w = x;print( /x/g );");
/*fuzzSeed-71289653*/count=1267; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ( + Math.atanh(( + ((Math.fround(Math.imul(((( ! ((x ^ x) >>> 0)) >>> 0) >>> 0), ( + Math.round(((mathy1((((x ? ( + y) : ( + x)) >>> 0) | 0), 0) | 0) | 0))))) | 0) != (mathy0(Math.trunc(x), 13) >> Math.log10(Math.hypot(x, ((Math.cbrt(x) >>> 0) >>> 0)))))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), 0x100000000, -0x100000001, -0x080000000, 2**53+2, -0, 0, -0x0ffffffff, -1/0, -0x100000000, 0x0ffffffff, 1, -Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, -(2**53+2), 0x100000001, 0/0, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, 2**53-2, Math.PI]); ");
/*fuzzSeed-71289653*/count=1268; tryItOut("\"use strict\"; print(t0);");
/*fuzzSeed-71289653*/count=1269; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x0ffffffff, 0x080000000, -0x100000001, -0x07fffffff, 0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, -1/0, -0x080000001, -0x080000000, -0, 0x100000000, 1, 1/0, 0x100000001, -(2**53+2), Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, 0x07fffffff, 2**53-2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, 0x080000001, 1.7976931348623157e308, -(2**53), -(2**53-2), -0x0ffffffff, Math.PI]); ");
/*fuzzSeed-71289653*/count=1270; tryItOut("e1.delete(m0);");
/*fuzzSeed-71289653*/count=1271; tryItOut("for (var v of v1) { try { g1.offThreadCompileScript(\"{ void 0; void relazifyFunctions(); }\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 65 != 47), sourceIsLazy: true, catchTermination: let (z = /*UUV1*/(\u3056.imul = neuter)) (p={}, (p.z =  \"\" )()) *= Math.cbrt(false) })); } catch(e0) { } try { this.v1 = g0.runOffThreadScript(); } catch(e1) { } try { Object.defineProperty(this, \"a0\", { configurable: true, enumerable: false,  get: function() {  return a2.concat(a2, t0, a2); } }); } catch(e2) { } ; }");
/*fuzzSeed-71289653*/count=1272; tryItOut("\"use strict\"; /*hhh*/function elxjtp(){/*infloop*/for(var {} = ( /x/ .abs(null, \"\\uBC4E\")); eval(\"({a2:z2})\", [z1]); Object.prototype.__defineGetter__([])) x;}elxjtp(((function too_much_recursion(mgexyp) { ; if (mgexyp > 0) { print(g1);; too_much_recursion(mgexyp - 1);  } else {  }  })(15385)));");
/*fuzzSeed-71289653*/count=1273; tryItOut("v0 = t2.byteOffset;");
/*fuzzSeed-71289653*/count=1274; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\u00b2*\", \"gim\"); var s = \"\\uad77\\uad77\\uad77\\uad77\\u00b2\\uad77\\u00b2\\uad77\\uad77\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1275; tryItOut("a1.pop();");
/*fuzzSeed-71289653*/count=1276; tryItOut("\"use strict\"; m1.set(a1, i2);");
/*fuzzSeed-71289653*/count=1277; tryItOut("L:with({b: (/*UUV2*/(x.slice = x.//h\nconcat))}){/*RXUB*/var r = this.r1; var s = \"\"; print(s.search(r)); print(r.lastIndex); i1.next(); }");
/*fuzzSeed-71289653*/count=1278; tryItOut("\"use asm\"; this.g1.g2.o1.g1.m2.has((x = null));");
/*fuzzSeed-71289653*/count=1279; tryItOut("/*RXUB*/var r = /./gyi; var s = \"\\u919c\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=1280; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! ((Math.pow((( - (( + x) | 0)) | 0), ((mathy2((x >>> 0), (Math.fround(( + Math.fround(y))) >>> 0)) >>> 0) | 0)) | 0) | 0)); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, -0x0ffffffff, 2**53-2, -0x100000001, 0x07fffffff, -Number.MAX_VALUE, -(2**53), Math.PI, Number.MIN_VALUE, -0x07fffffff, -0x100000000, 0x100000000, 0.000000000000001, 2**53+2, 0x080000000, 0x100000001, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0/0, -(2**53+2), 2**53, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -0x080000001, 42, 1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1, -0x080000000]); ");
/*fuzzSeed-71289653*/count=1281; tryItOut("m2.set(t0, o1.i1);");
/*fuzzSeed-71289653*/count=1282; tryItOut("\"use strict\"; for (var p in i0) { try { Object.defineProperty(this, \"v2\", { configurable: true, enumerable: false,  get: function() {  return t0.byteOffset; } }); } catch(e0) { } try { e1.delete(g1.g0); } catch(e1) { } /*MXX1*/o1 = g1.Date.prototype.toDateString; }");
/*fuzzSeed-71289653*/count=1283; tryItOut("m0.set(b2, this.h1);");
/*fuzzSeed-71289653*/count=1284; tryItOut("\"use strict\"; ;");
/*fuzzSeed-71289653*/count=1285; tryItOut("\"use strict\"; /*hhh*/function dfuwas(){s1 = '';}dfuwas(let (b) /*RXUE*//[^]/gym.exec(\"\\n\"), (void version(185)));");
/*fuzzSeed-71289653*/count=1286; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?=((?!\\\\3|[]|[^\\\\s\\\\xB5]?)*?)))\", \"gyi\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=1287; tryItOut("with(x != a){v0 = g2.eval(\"\\\"use strict\\\"; /*hhh*/function uaztuj([x]){if(true) print( /x/g ); else {print(x); }}uaztuj((new function(y) { return x }(x.includes((4277), x), (4277))), (new function (d) { return new RegExp(\\\"[\\\\\\\\f\\\\\\\\d\\\\\\\\w\\\\\\\\cO]\\\", \\\"y\\\") } (\\\"\\\\uDEBA\\\")) !== x);\");/*tLoop*/for (let e of /*MARR*/[]) { window; } }");
/*fuzzSeed-71289653*/count=1288; tryItOut("o1.o1.a2 + '';");
/*fuzzSeed-71289653*/count=1289; tryItOut("for (var p in t0) { try { Array.prototype.unshift.apply(a1, [x, g1.g1, f1]); } catch(e0) { } ; }");
/*fuzzSeed-71289653*/count=1290; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d1 = (d1);\n    i2 = ((~~(d1)) >= ((((0xffffffff))) & ((0xffffffff)+((0xd07bf598) != (0xffffffff))-((/*FFI*/ff()|0) ? ((0x4fbbe3f9) != (0x49c6c8e)) : (/*FFI*/ff()|0)))));\n    {\n      d1 = (7.737125245533627e+25);\n    }\n    return (((/*FFI*/ff(((abs(((((/*FFI*/ff(((+(1.0/0.0))), ((-288230376151711740.0)), ((65535.0)), ((2.0)))|0) ? (0xf386813) : (i2)))|0))|0)), ((0x6f7ae102)), ((((0xffffffff)-(0x6002c3ee)) | ((i2)*0x8b1ab))), ((((Uint32ArrayView[((0xec3b39b9)) >> 2])) & ((0x10b707a)-(i2)))), ((+((((1025.0)) % ((-8388609.0)))))), ((d0)), ((((0xffffffff)) << ((0xffe103c0)))), ((-4097.0)), ((4.0)), ((65537.0)), ((8796093022209.0)), ((281474976710657.0)), ((-2305843009213694000.0)), ((-67108865.0)))|0)+(i2)-((i2) ? ((window = Proxy.createFunction(({/*TOODEEP*/})( /x/g ), eval, Date.prototype.toUTCString))(new String('q'))) : (((+(0x1e736077)) + (d1)) <= (d0)))))|0;\n    {\n      return (((i2)+((((0x50272765))>>>((0x27446422) / (0xf87fda))) != (0x2b61f987))))|0;\n    }\n    i2 = ((((~~(+(0.0/0.0))) % (~~(-((d0)))))|0));\n    d0 = (d0);\n    return (((i2)))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[new Boolean(true), new Number(1),  '' ,  '' , new Boolean(true),  '' , false, new Boolean(true), false]); ");
/*fuzzSeed-71289653*/count=1291; tryItOut("let(NaN = ((uneval(('fafafa'.replace(/a/g, (objectEmulatingUndefined).bind))))), x, eval = \u3056 *= x, y = /*FARR*/[ /x/g , 11, ...[], ].map(({/*TOODEEP*/})), x = NaN = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: \"\\uEE25\", has: function() { throw 3; }, hasOwn: function() { return false; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { return true; }, iterate: encodeURI, enumerate: function() { return []; }, keys: function() { return []; }, }; })( /x/g ), RegExp.prototype.compile), y, y = null, c = \"\\u46B8\") { yield [, this.__proto__] = Math.log10(this ^= null).eval(\"(4277)\");}(\nx);");
/*fuzzSeed-71289653*/count=1292; tryItOut("testMathyFunction(mathy0, [2**53, -(2**53-2), 1, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, 2**53-2, 0/0, 1.7976931348623157e308, 0, -1/0, 42, 0.000000000000001, -0, 0x07fffffff, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 0x0ffffffff, -0x0ffffffff, -0x100000000, 0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, -0x080000000, -Number.MIN_VALUE, 0x080000001, 2**53+2, Number.MIN_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=1293; tryItOut("\"use strict\"; p2 + '';");
/*fuzzSeed-71289653*/count=1294; tryItOut("Array.prototype.splice.apply(a2, [NaN, yield \"\\u05A7\" ? Math.hypot(x, -20) : 4 ? \"\\uD387\" : this.watch(\"toString\", neuter), g0.f2]);");
/*fuzzSeed-71289653*/count=1295; tryItOut("t1[({valueOf: function() { for (var v of p1) { try { v0 = evalcx(\"function f1(f0)  { t2 = new Float64Array(o0.t1); } \", g2); } catch(e0) { } v2 = -Infinity; }return 0; }})] = o0.e1;");
/*fuzzSeed-71289653*/count=1296; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[true,  \"\" , true, function(){}, true,  \"\" ]); ");
/*fuzzSeed-71289653*/count=1297; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    (Float32ArrayView[((0xa70ba7e4) % (0xa5ecd094)) >> 2]) = ((((d1)) % ((-((d1))))));\n    return ((((0xca2d352f) < (0x69d269ff))))|0;\n  }\n  return f; })(this, {ff: Object.prototype.hasOwnProperty}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-71289653*/count=1298; tryItOut("mathy2 = (function(x, y) { return ( + (((Math.ceil((x >>> 0)) >>> 0) > ((( ! Math.acosh(((mathy1(( + y), ( + x)) | 0) | (y >>> 0)))) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [undefined, (new Number(0)), [0], '0', 1, (new Boolean(true)), 0.1, objectEmulatingUndefined(), (function(){return 0;}), /0/, ({valueOf:function(){return 0;}}), 0, '/0/', (new String('')), NaN, false, '\\0', -0, true, [], (new Boolean(false)), null, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), '', (new Number(-0))]); ");
/*fuzzSeed-71289653*/count=1299; tryItOut("testMathyFunction(mathy3, /*MARR*/[Infinity, Infinity, (1/0), Infinity, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), Infinity, (1/0), Infinity, (1/0), (1/0), (1/0)]); ");
/*fuzzSeed-71289653*/count=1300; tryItOut("with({x: x})v2 = (a2 instanceof h1);");
/*fuzzSeed-71289653*/count=1301; tryItOut("a0.unshift(t2, o1.h1);");
/*fuzzSeed-71289653*/count=1302; tryItOut("\"use strict\"; /*infloop*/while(delete e.x)(this);");
/*fuzzSeed-71289653*/count=1303; tryItOut("g0.a0[13] = x;");
/*fuzzSeed-71289653*/count=1304; tryItOut("");
/*fuzzSeed-71289653*/count=1305; tryItOut("/*bLoop*/for (let wnnzeg = 0; wnnzeg < 20; ++wnnzeg) { if (wnnzeg % 30 == 18) { o2 = g2.h1.__proto__; } else { g1.f1 = Proxy.createFunction(h0, f2, f1); }  } ");
/*fuzzSeed-71289653*/count=1306; tryItOut("h2 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.unshift.call(g0.a2, i1, m2, v1);; var desc = Object.getOwnPropertyDescriptor(g0.g0.a2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { s1 += 'x';; var desc = Object.getPropertyDescriptor(g0.g0.a2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { /*ODP-3*/Object.defineProperty(g2.g1, (eval(\"x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: window, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { throw 3; }, set: function() { return false; }, iterate: undefined, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(a), (4277))\")), { configurable: (x % 2 != 1), enumerable: true, writable: /*UUV2*/(c.slice = c.assign), value: m0 });; Object.defineProperty(g0.g0.a2, name, desc); }, getOwnPropertyNames: function() { m0 = a2[4];; return Object.getOwnPropertyNames(g0.g0.a2); }, delete: function(name) { g2.m2.set(o1.s1, b1);; return delete g0.g0.a2[name]; }, fix: function() { this.a0.splice(15, v2, o2, m2, g0.b1);; if (Object.isFrozen(g0.g0.a2)) { return Object.getOwnProperties(g0.g0.a2); } }, has: function(name) { v2 = v1[\"__proto__\"];; return name in g0.g0.a2; }, hasOwn: function(name) { throw v1; return Object.prototype.hasOwnProperty.call(g0.g0.a2, name); }, get: function(receiver, name) { return p2; return g0.g0.a2[name]; }, set: function(receiver, name, val) { v1 = false;; g0.g0.a2[name] = val; return true; }, iterate: function() { throw v2; return (function() { for (var name in g0.g0.a2) { yield name; } })(); }, enumerate: function() { b2 + '';; var result = []; for (var name in g0.g0.a2) { result.push(name); }; return result; }, keys: function() { Array.prototype.shift.call(a1, s2, /*UUV2*/(c.italics = c.toString).__defineSetter__(\"d\", (4277).join));; return Object.keys(g0.g0.a2); } });");
/*fuzzSeed-71289653*/count=1307; tryItOut("Array.prototype.splice.call(this.a0, NaN, 10, a2, s2);");
/*fuzzSeed-71289653*/count=1308; tryItOut("\"use strict\"; a0.shift();");
/*fuzzSeed-71289653*/count=1309; tryItOut("(z = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: \"\\u944B\", has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: undefined, iterate: function() { throw 3; }, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })(/(?=[^\u0f59])|\\2+/gyi), Math.pow));");
/*fuzzSeed-71289653*/count=1310; tryItOut("mathy4 = (function(x, y) { return (( ! (Math.fround(Math.sinh((( + x) ? ( + y) : (Math.atan(y) || Math.tan(Math.hypot(x, ( + y))))))) | 0)) | 0); }); testMathyFunction(mathy4, [2**53-2, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_VALUE, 42, -0x080000000, 0x080000000, 2**53+2, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, -0x080000001, -(2**53+2), Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, 0, 0x07fffffff, 0x080000001, 0x100000001, 1/0, -0x100000000, -(2**53-2), -0, 1, 0/0, -0x0ffffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, -1/0, -(2**53)]); ");
/*fuzzSeed-71289653*/count=1311; tryItOut("\"use strict\"; let (\u3056, [] = this ? false : null, y = -0.112, window, window, a, x, a) { var ijplhf = new SharedArrayBuffer(0); var ijplhf_0 = new Int16Array(ijplhf); ijplhf_0[0] = 4; print(ijplhf_0[0]); }");
/*fuzzSeed-71289653*/count=1312; tryItOut("mathy2 = (function(x, y) { return Math.atan2(Math.cosh(Math.fround(Math.log2(Math.fround(( + Math.sinh(Math.fround(mathy0(( + ( ~ Math.fround(2**53+2))), x)))))))), Math.max(( - mathy0(Math.fround(Math.hypot(Math.fround(y), ( + (( + x) && Math.fround(y))))), 1/0)), mathy0((((Math.fround(Math.ceil(Math.fround((Math.fround(mathy0(x, x)) % Math.fround(y))))) | 0) * (( - (Number.MIN_SAFE_INTEGER >>> 0)) | 0)) | 0), (( ~ (Math.max(y, -0x080000001) && Number.MIN_VALUE)) > x)))); }); ");
/*fuzzSeed-71289653*/count=1313; tryItOut("\"use strict\"; /*oLoop*/for (let yhpnid = 0, window.__defineSetter__(\"x\", (let (e=eval) e)) ? this.__defineSetter__(\"eval\", function (a) { \"use strict\"; v1 = evalcx(\"function f0(a1)  { return  /x/g  } \", g1); } ) : [[1]].__defineSetter__(\"x\", String.prototype.sup) + Math.pow(true, -19); yhpnid < 18; ++yhpnid) { t1.set(t1, 18); } ");
/*fuzzSeed-71289653*/count=1314; tryItOut("/*bLoop*/for (var dvzrfl = 0; dvzrfl < 0; ++dvzrfl) { if (dvzrfl % 13 == 5) { return; } else { a0.push(m0, t1, h0); }  } v0 = evaluate(\"Object.defineProperty(this, \\\"v2\\\", { configurable: (x % 10 != 9), enumerable: (x % 3 == 0),  get: function() {  return g0.runOffThreadScript(); } });\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 33 != 15), catchTermination: true }));\n(-171399059);\n");
/*fuzzSeed-71289653*/count=1315; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ Math.round(( ! x))); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -0x0ffffffff, Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 1/0, 42, 0.000000000000001, -(2**53+2), 0x100000000, -0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, 0x07fffffff, -0x080000001, 1.7976931348623157e308, -0x07fffffff, 0, 0/0, -(2**53), 0x100000001, -(2**53-2), -0, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, -0x080000000, 0x080000001, -0x100000000]); ");
/*fuzzSeed-71289653*/count=1316; tryItOut("\"use strict\"; /*bLoop*/for (var yumukl = 0; yumukl < 12; ++yumukl, this) { if (yumukl % 6 == 3) { print(x); } else { a1.unshift(o2, m2, f1, null); }  } ");
/*fuzzSeed-71289653*/count=1317; tryItOut("for([a, d] = delete /*FARR*/[Object.defineProperty(x, \"toLocaleString\", ({value: \nthis}))].sort(Date.prototype.getHours) in window -= e.getTime(x, window)) {L: {print(uneval(this.m1));m1 + t1; }switch(15.eval(\"{}\")) { default: break; t1[18] = i0;case 0: break;  }(4277); }");
/*fuzzSeed-71289653*/count=1318; tryItOut("this.v1.__proto__ = a0;");
/*fuzzSeed-71289653*/count=1319; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( - (( + (Math.fround(Math.asinh(( - (y >>> 0)))) % ( + Math.hypot((Math.hypot((y >>> 0), y) >>> 0), (Math.sin(( ~ 1)) | 0))))) << ((Math.min((x | 0), (( ! ( ! y)) | 0)) | 0) - Math.atanh(Math.fround(Math.min(Math.fround(-(2**53-2)), Math.fround(Math.pow(1.7976931348623157e308, -0x100000000)))))))); }); testMathyFunction(mathy0, [2**53, -0x100000001, -(2**53+2), -0x0ffffffff, -0, Number.MIN_VALUE, 42, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 1, -(2**53), Math.PI, 2**53+2, Number.MAX_VALUE, -1/0, -0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_VALUE, -0x100000000, 0x100000000, -Number.MAX_VALUE, 0x100000001, -0x080000000, 1/0, 0, 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=1320; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return (( + ((Math.atan2(0x100000001, (( - Math.imul((y >>> 0), x)) | 0)) | 0) > ( + (y | Math.fround(y))))) == ( + Math.atanh((Math.hypot(( + Math.acos((y | 0))), (( + Math.pow(( + ( + (0x0ffffffff / ( + 0x080000001)))), (x >>> 0))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, 0.000000000000001, -(2**53+2), 42, 1.7976931348623157e308, Number.MIN_VALUE, 1/0, 0, Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 1, 0x080000000, -(2**53), 2**53, Math.PI, -0x080000001, 0x07fffffff, 0x0ffffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, 2**53-2, 0x100000001, -0x07fffffff, -1/0, Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -0, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=1321; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + (( + ( ~ ( + ( + (( + Math.fround((Math.fround(( + x)) ? Number.MAX_VALUE : Math.fround(mathy3((x | 0), Math.imul(y, ( + -Number.MIN_VALUE))))))) ^ ( + Math.log2(Math.fround(x)))))))) >>> ((( - ( + ((( + (y >>> 0)) === x) === ( + Math.hypot((x && x), Math.fround(y)))))) >>> 0) | 0))); }); testMathyFunction(mathy5, [-(2**53-2), 2**53-2, 2**53+2, Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, -(2**53), 1/0, Number.MIN_VALUE, 0x080000000, -0x080000000, 0x07fffffff, 0x0ffffffff, 0.000000000000001, -0x07fffffff, 42, -Number.MIN_VALUE, 1, -1/0, -(2**53+2), 0x100000000, -0x080000001, 0x100000001, 1.7976931348623157e308, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, 0/0]); ");
/*fuzzSeed-71289653*/count=1322; tryItOut("/*RXUB*/var r = /((?:.)|(?![^\\D\\W\\w\\b])\\B)|\\1/; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=1323; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(f0, g2);");
/*fuzzSeed-71289653*/count=1324; tryItOut("v2 = (4277);");
/*fuzzSeed-71289653*/count=1325; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1, -0x080000001, -0x080000000, 0x0ffffffff, 0x100000000, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 2**53-2, Math.PI, 2**53, 42, 0x100000001, 0x080000000, -(2**53+2), 1.7976931348623157e308, -0x100000000, Number.MAX_VALUE, -(2**53), -0, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53-2), 1/0, 0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1326; tryItOut("i1 = new Iterator(t0, true);");
/*fuzzSeed-71289653*/count=1327; tryItOut(" for (let y of (/*UUV2*/(d.toLocaleString = d.acos))) /*MXX1*/g2.o2 = g1.g0.ReferenceError;");
/*fuzzSeed-71289653*/count=1328; tryItOut("h1.set = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (((d0)) / ((-((-2147483649.0)))));\n    return +((((+((d0)))) * ((+abs(((((((NaN)) / ((d0)))) - ((+sqrt(((d0))))))))))));\n  }\n  return f; })(this, {ff: (4277)}, new ArrayBuffer(4096));");
/*fuzzSeed-71289653*/count=1329; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=1330; tryItOut("/*hhh*/function xbvtec(c){var y, ogdrsu, ugisxi, z, jhdhpz, c, z, pipkpo, eval, window;print(x);}/*iii*/{ void 0; bailAfter(183); } h0.fix = (function(j) { if (j) { m1.set(g1, f2); } else { try { a1 = []; } catch(e0) { } try { v0 = g1.runOffThreadScript(); } catch(e1) { } o0.i2.next(); } });");
/*fuzzSeed-71289653*/count=1331; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.expm1((((((Math.atan2(((( - y) >>> 0) ? -Number.MAX_SAFE_INTEGER : (42 | 0)), Number.MAX_VALUE) >>> 0) ? ( + ( + (mathy3(y, (( ~ y) >>> 0)) | 0))) : Math.max(Math.asin(Math.max(y, ( + x))), Math.sin(x))) | 0) ** (Math.fround(Math.atan2(Math.fround(( + (( - mathy0(y, y)) ? x : Math.sinh(Math.exp((Math.abs(y) >>> 0)))))), Math.fround(( + Math.cbrt(( + (Math.acos((y | 0)) | 0))))))) | 0)) | 0)); }); testMathyFunction(mathy5, [Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 42, -(2**53+2), 0x080000000, Math.PI, -0x100000001, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 1/0, 0.000000000000001, -0x07fffffff, -(2**53), -0, Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, 0/0, 0x100000001, -Number.MAX_VALUE, -(2**53-2), 2**53+2, 0x0ffffffff, 2**53, 0x100000000, 0, 1]); ");
/*fuzzSeed-71289653*/count=1332; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1333; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.log10(Math.fround(Math.sin(Math.fround(Math.log1p(y))))); }); testMathyFunction(mathy5, /*MARR*/[1e-81,  /x/g ,  /x/g ,  /x/g ,  /x/g , [(void 0)],  /x/g , [(void 0)], [(void 0)],  /x/g , 1e-81, 1e-81, [(void 0)], 1e-81, [(void 0)], [(void 0)],  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , 1e-81, 1e-81,  /x/g , 1e-81, 1e-81,  /x/g , [(void 0)],  /x/g ,  /x/g ,  /x/g , [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], 1e-81,  /x/g , 1e-81, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81, 1e-81,  /x/g , [(void 0)],  /x/g ,  /x/g ,  /x/g ,  /x/g , [(void 0)], 1e-81, 1e-81, [(void 0)], [(void 0)], 1e-81, 1e-81,  /x/g ,  /x/g , 1e-81, 1e-81,  /x/g , [(void 0)],  /x/g , [(void 0)], [(void 0)], [(void 0)], 1e-81,  /x/g , [(void 0)],  /x/g , 1e-81,  /x/g , [(void 0)], [(void 0)], 1e-81, 1e-81, 1e-81, [(void 0)], [(void 0)], [(void 0)], [(void 0)],  /x/g , 1e-81, 1e-81, [(void 0)],  /x/g , [(void 0)], [(void 0)], 1e-81, [(void 0)], 1e-81, 1e-81, [(void 0)], 1e-81, [(void 0)], 1e-81, [(void 0)], [(void 0)], [(void 0)],  /x/g , [(void 0)], [(void 0)], [(void 0)], [(void 0)]]); ");
/*fuzzSeed-71289653*/count=1334; tryItOut("while((new function () { \"use strict\"; return  ''  &= true } (({w:  /x/g  }), /*UUV2*/(d.entries = d.entries))) && 0){/*RXUB*/var r = new RegExp(\"\\\\b\\\\1{2,}{4}\", \"m\"); var s = \"\\n a\\u17bf\\n a\\u17bf\\n a\\u17bf\\n a\\u17bf\"; print(s.match(r)); v0 = a0.reduce, reduceRight(b1, i2); }");
/*fuzzSeed-71289653*/count=1335; tryItOut("/*RXUB*/var r = /(?:\\3)/gi; var s = \"\\n\\u00d9\\u00b5\\u00d9\\u00b5\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1336; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (mathy0(( + Math.round(( + Math.pow(x, mathy1(x, y))))), (Math.atanh(Math.imul((( ~ x) >>> 0), ( - (y >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0x100000000, 0/0, 1, 0.000000000000001, 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0, -0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, 1/0, Math.PI, -0x100000000, -0x0ffffffff, 2**53-2, 0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, -0, -0x07fffffff, 0x100000001, -(2**53-2), 0x080000000, 0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, 2**53+2, -0x080000000, -0x100000001]); ");
/*fuzzSeed-71289653*/count=1337; tryItOut("\"use strict\"; if(false) { if ((eval\n)) {s1 += this.s1print(x); }} else {v0 = g2.a2.length; }");
/*fuzzSeed-71289653*/count=1338; tryItOut("t2 = new Uint16Array(t0);");
/*fuzzSeed-71289653*/count=1339; tryItOut("testMathyFunction(mathy4, [-Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, 1/0, 42, 0x080000000, -0x100000001, 2**53, 0x0ffffffff, -(2**53+2), 2**53+2, 0x080000001, -(2**53), -0x100000000, -(2**53-2), -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0, 0/0, Number.MIN_VALUE, 2**53-2, 0.000000000000001, 0, 0x100000001, -0x080000001, -0x0ffffffff, 1, 0x100000000, 0x07fffffff, Math.PI, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=1340; tryItOut("\"use strict\"; let (b) { a2.splice(NaN, 19); }");
/*fuzzSeed-71289653*/count=1341; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.expm1(Math.cos(Math.sign(( + ( ! ( + y)))))); }); testMathyFunction(mathy3, [-0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -(2**53+2), -1/0, 0x100000001, -(2**53-2), 2**53+2, 2**53, -0x080000001, 42, 0x080000000, -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, -(2**53), -0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, Number.MAX_VALUE, 0/0, Math.PI, 1/0, 0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2, -0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=1342; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.ceil(((Math.log10((( ~ Math.atan2(x, (Math.atan((Math.min((y | 0), (y | 0)) >>> 0)) >>> 0))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy3, [0x07fffffff, 2**53, 1/0, -0x080000000, -0x100000001, Math.PI, -(2**53-2), Number.MAX_VALUE, -0x080000001, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, Number.MAX_SAFE_INTEGER, 0, 1, -0, -0x100000000, -0x0ffffffff, -(2**53+2), -(2**53), 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, Number.MIN_VALUE, -0x07fffffff, 1.7976931348623157e308, 0/0, 0x100000000, 42, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=1343; tryItOut("testMathyFunction(mathy5, [Math.PI, 42, 0x0ffffffff, 2**53, -0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000001, 1/0, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000001, 1, -Number.MIN_VALUE, -(2**53), 0x080000001, -Number.MAX_VALUE, Number.MIN_VALUE, 0, -0, -0x080000001, 0.000000000000001, -(2**53+2), -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, -0x07fffffff, -(2**53-2), 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, 0x100000000]); ");
/*fuzzSeed-71289653*/count=1344; tryItOut("o1.v0 = (t0 instanceof h0)\n");
/*fuzzSeed-71289653*/count=1345; tryItOut("v0 = (i0 instanceof o0);");
/*fuzzSeed-71289653*/count=1346; tryItOut("\"use strict\"; Array.prototype.unshift.call(a2, i1, this.i0);");
/*fuzzSeed-71289653*/count=1347; tryItOut("/*tLoop*/for (let d of /*MARR*/[z--, undefined,  /x/ , {},  /x/ , {}, new Number(1.5),  /x/ , new Number(1.5), undefined, new Number(1.5), new Number(1.5),  /x/ , new Number(1.5), z--, z--, undefined, z--, {}, new Number(1.5), new Number(1.5),  /x/ , {},  /x/ ,  /x/ , z--,  /x/ , z--, {},  /x/ ,  /x/ , {}, z--, z--,  /x/ , {},  /x/ , z--, {}, z--, undefined, new Number(1.5), undefined, {}, undefined,  /x/ , new Number(1.5), undefined,  /x/ , z--, z--, z--, new Number(1.5), undefined, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), {}, {}, {},  /x/ , {},  /x/ ,  /x/ , new Number(1.5), new Number(1.5), z--, z--, z--, {}]) { /* no regression tests found */ }");
/*fuzzSeed-71289653*/count=1348; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.max(( + (Math.exp(((( ~ (x | 0)) | 0) >>> 0)) >>> 0)), ( + Math.tan(( + (Math.atan2((( + ( ~ ( + Math.max((((x >>> 0) <= Math.fround(0x0ffffffff)) >>> 0), ((x - y) && x))))) >>> 0), ((( ! -0x080000000) > y) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-71289653*/count=1349; tryItOut("mathy4 = (function(x, y) { return Math.pow(( + Math.round((((x >>> 0) - y) >>> 0))), (mathy0((( ! Math.imul((Math.acosh(( ! y)) | 0), ( + x))) >>> 0), ((Math.asin(( + ( + ((Math.atan2(mathy0(y, 1), ( + y)) | 0) >>> 0)))) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [0x080000001, 2**53-2, -0x07fffffff, 0x100000001, -(2**53), -0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1, 0, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, 0/0, 2**53, 0x07fffffff, -0x100000000, 1/0, 2**53+2, -Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, -0x0ffffffff, Math.PI, -(2**53+2), Number.MIN_SAFE_INTEGER, 42, -0, Number.MIN_VALUE, 0x0ffffffff, -0x100000001, Number.MAX_VALUE, -(2**53-2), 0x100000000]); ");
/*fuzzSeed-71289653*/count=1350; tryItOut("\"use strict\"; v2 = g1.runOffThreadScript();");
/*fuzzSeed-71289653*/count=1351; tryItOut("{ void 0; gcslice(436); } v2 = g1.runOffThreadScript();");
/*fuzzSeed-71289653*/count=1352; tryItOut("this.e0.has(b0);");
/*fuzzSeed-71289653*/count=1353; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i1, e1);");
/*fuzzSeed-71289653*/count=1354; tryItOut("mathy4 = (function(x, y) { return (Math.pow((Math.imul(Math.fround((Math.fround(( + (( + ( - y)) && Math.fround(( - Math.fround(Math.sinh(Math.fround(x)))))))) ? Math.fround(((Math.fround(Math.pow(( + (( + y) * ( + (Math.max((-(2**53-2) | 0), (x | 0)) | 0)))), ( + 0x0ffffffff))) ? 1 : (Math.sqrt(( ~ y)) % 2**53+2)) | 0)) : Math.fround(( ! x)))), (( + Math.log10(( + ( + (( + Math.log1p(( + y))) > ( + ( + x))))))) | 0)) | 0), Math.asin(( - (Math.asin((Math.imul(-(2**53+2), x) >>> 0)) >>> 0)))) | 0); }); testMathyFunction(mathy4, /*MARR*/[typeof new Function([[]]), yield let (e = \"\\uE20D\") \"\\uA3AA\", x, typeof new Function([[]]), typeof new Function([[]]), x, typeof new Function([[]]), typeof new Function([[]]), yield let (e = \"\\uE20D\") \"\\uA3AA\", yield let (e = \"\\uE20D\") \"\\uA3AA\", yield let (e = \"\\uE20D\") \"\\uA3AA\", [1], {x:3}, typeof new Function([[]]), [1], x, x, [1], [1], [1], x, yield let (e = \"\\uE20D\") \"\\uA3AA\", [1], [1], typeof new Function([[]]), {x:3}, yield let (e = \"\\uE20D\") \"\\uA3AA\", x, [1], x, yield let (e = \"\\uE20D\") \"\\uA3AA\", {x:3}, x, typeof new Function([[]]), {x:3}, yield let (e = \"\\uE20D\") \"\\uA3AA\", yield let (e = \"\\uE20D\") \"\\uA3AA\", yield let (e = \"\\uE20D\") \"\\uA3AA\", typeof new Function([[]]), typeof new Function([[]]), x, {x:3}, [1], {x:3}, x, typeof new Function([[]]), x, [1], {x:3}, yield let (e = \"\\uE20D\") \"\\uA3AA\", {x:3}, {x:3}, yield let (e = \"\\uE20D\") \"\\uA3AA\", [1], typeof new Function([[]]), {x:3}, typeof new Function([[]]), [1], [1], [1], {x:3}, typeof new Function([[]]), x, [1], typeof new Function([[]]), {x:3}, [1], yield let (e = \"\\uE20D\") \"\\uA3AA\", x, yield let (e = \"\\uE20D\") \"\\uA3AA\", {x:3}, x, x, typeof new Function([[]]), [1], typeof new Function([[]]), yield let (e = \"\\uE20D\") \"\\uA3AA\", x, typeof new Function([[]]), x, typeof new Function([[]]), yield let (e = \"\\uE20D\") \"\\uA3AA\", yield let (e = \"\\uE20D\") \"\\uA3AA\"]); ");
/*fuzzSeed-71289653*/count=1355; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(( ! Math.imul((( + (Math.pow(-0x07fffffff, y) >>> 0)) >>> 0), x)))); }); testMathyFunction(mathy3, [0.000000000000001, -1/0, 0x100000000, 0x080000000, 0/0, 1.7976931348623157e308, 0x0ffffffff, -(2**53+2), 0x080000001, Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, 2**53-2, 0x100000001, -0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, -0x100000000, 0, -0, 2**53, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -0x080000001, 1, 0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-71289653*/count=1356; tryItOut("\"use asm\"; /*bLoop*/for (let xwgazg = 0, this.zzz.zzz = (x.__defineSetter__(\"\\u3056\", DataView.prototype.setInt32)); xwgazg < 94; ++xwgazg) { if (xwgazg % 2 == 0) { a1.splice(); } else { for (var p in s1) { try { e2.add(b1); } catch(e0) { } try { /*MXX3*/this.g0.Set.prototype.forEach = g1.Set.prototype.forEach; } catch(e1) { } try { Array.prototype.sort.apply(a1, [(function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.03125;\n    var i3 = 0;\n    return ((((Math.min(19,  '' )))))|0;\n  }\n  return f; }), f1]); } catch(e2) { } var v2 = g2.eval(\"/* no regression tests found */\"); } }  } ");
/*fuzzSeed-71289653*/count=1357; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return (mathy0((Math.acos((( + Math.max(((( - x) | 0) | 0), (Number.MIN_VALUE | 0))) , (0x080000001 | 0))) >>> 0), ( + Math.cosh(Math.fround(Math.asinh(( + (( + (( ! Math.fround(x)) | 0)) >>> 0))))))) >>> 0); }); ");
/*fuzzSeed-71289653*/count=1358; tryItOut("switch(({w: x})) { case x: v0 = g2.objectEmulatingUndefined();default: print((timeout(1800)));break; case 7: break;  }");
/*fuzzSeed-71289653*/count=1359; tryItOut("v2 = a0[\"resolve\"];");
/*fuzzSeed-71289653*/count=1360; tryItOut("\"use strict\"; timeout(1800) = t2[15];");
/*fuzzSeed-71289653*/count=1361; tryItOut("print(-6);");
/*fuzzSeed-71289653*/count=1362; tryItOut("print(x);");
/*fuzzSeed-71289653*/count=1363; tryItOut("mathy3 = (function(x, y) { return (Math.imul(Math.fround(( + Math.fround(Math.fround(y)))), Math.min(( + Math.trunc(( + (( - ((y || y) >>> 0)) >>> 0)))), (Math.pow(Math.fround(( ! Math.fround(( + (y >> Math.fround(y)))))), Math.tan(Math.hypot((((y | 0) >>> ((-0x07fffffff ^ ( + y)) | 0)) | 0), Math.fround(-0x100000001)))) >>> 0))) | 0); }); testMathyFunction(mathy3, [2**53+2, 0, -Number.MAX_VALUE, 0x100000000, -0x100000000, -(2**53), 2**53, 1/0, -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1, -0x100000001, -Number.MIN_VALUE, 0x080000001, -0x07fffffff, Math.PI, -0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53-2, 1.7976931348623157e308, -1/0, 0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, -0, 0x100000001, 0/0, -0x080000000, 42, Number.MAX_VALUE, -(2**53-2), 0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1364; tryItOut("h2.delete = f0;");
/*fuzzSeed-71289653*/count=1365; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ~ ( - Math.fround((( ! y) % ( + Math.atan2(Math.fround((x ? x : -0)), Math.fround(x))))))); }); ");
/*fuzzSeed-71289653*/count=1366; tryItOut("for (var v of m0) { e2.delete(o0); }\nprint(x);\n");
/*fuzzSeed-71289653*/count=1367; tryItOut("mathy4 = (function(x, y) { return ( + Math.atan(( + Math.expm1(((1 * ( + Math.abs(( + (( - (y | 0)) | 0))))) >>> 0))))); }); testMathyFunction(mathy4, [(function(){return 0;}), objectEmulatingUndefined(), true, 1, (new Number(-0)), false, -0, null, '/0/', ({toString:function(){return '0';}}), (new Boolean(true)), (new String('')), [0], '0', NaN, ({valueOf:function(){return '0';}}), 0, /0/, 0.1, (new Number(0)), ({valueOf:function(){return 0;}}), [], '', undefined, '\\0', (new Boolean(false))]); ");
/*fuzzSeed-71289653*/count=1368; tryItOut("/*vLoop*/for (var ydgrsl = 0; ydgrsl < 58; ++ydgrsl) { const d = ydgrsl; h0 + ''; } ");
/*fuzzSeed-71289653*/count=1369; tryItOut("mathy1 = (function(x, y) { return Math.atan2(Math.fround(Math.asinh((((( + y) | 0) - Math.fround(Math.asin(Math.fround(Math.asin(0x100000000))))) | 0))), ( ! (Math.fround((Math.hypot(Math.abs(x), (Math.pow(Math.fround(( + (y | 0))), Number.MAX_SAFE_INTEGER) | 0)) | 0)) & ( - (( + Math.pow(( + Math.pow((y == y), y)), Math.pow(( - -0x0ffffffff), Math.round(x)))) | 0))))); }); ");
/*fuzzSeed-71289653*/count=1370; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=1371; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?:\\\\D))|\\\\B|(?!.{0}(\\\\S|${1073741825})([^]){1}(?!(\\\\B)))+\", \"g\"); var s = null >> Math.hypot(this.__defineGetter__(\"z\", (1 for (x in []))), 0x0ffffffff); print(s.match(r)); ");
/*fuzzSeed-71289653*/count=1372; tryItOut("\"use strict\"; for (var v of b2) { try { e1.delete(s2); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(a2, s0); } catch(e1) { } try { a0.splice(h1); } catch(e2) { } const a0 = Proxy.create(h1, i2); }");
/*fuzzSeed-71289653*/count=1373; tryItOut("/*MXX1*/o0 = o0.g2.Math.abs;");
/*fuzzSeed-71289653*/count=1374; tryItOut("v0 = (a2 instanceof f1);");
/*fuzzSeed-71289653*/count=1375; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-71289653*/count=1376; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.sin((( ! Math.atan2((Math.max(((Math.hypot((0.000000000000001 >>> 0), (Math.pow(Math.fround(-Number.MIN_VALUE), y) >>> 0)) >>> 0) | 0), y) | 0), ( + Math.log2(Math.fround(2**53-2))))) | 0)); }); testMathyFunction(mathy5, /*MARR*/[(void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), [1], (void 0), (void 0), [1], (void 0), (void 0), (void 0), [1]]); ");
/*fuzzSeed-71289653*/count=1377; tryItOut("o0.s2 += 'x';");
/*fuzzSeed-71289653*/count=1378; tryItOut("mathy2 = (function(x, y) { return Math.imul((Math.log10((mathy1(((mathy0(( ! y), y) >> ( - x)) < y), (( + Math.fround(Math.imul(Math.fround(Math.fround(((y >>> 0) ? Math.fround(y) : Math.fround(y)))), (Math.PI & 0x080000000)))) || y)) | 0)) | 0), Math.fround(Math.pow((x & ( ~ x)), Math.fround(( ! 0x0ffffffff))))); }); testMathyFunction(mathy2, [2**53-2, -0x080000001, 0x080000001, -0x100000001, 1/0, 2**53, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, -0x07fffffff, Number.MIN_VALUE, -0x080000000, 0x0ffffffff, 42, 0x080000000, -1/0, 0, 0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 0x100000000, Math.PI, -0, Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-71289653*/count=1379; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1380; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?:(?:\\\\B|\\\\b+$){1,}(?:[\\\\x54\\\\w\\\\v-\\\\\\u3be2\\\\0-\\\\f]?|\\\\x88\\\\d|^?)))\\\\b\\u0019\\\\1[\\\\d]\", \"i\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-71289653*/count=1381; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ( ~ Math.fround((Math.fround((( + Math.min(y, (Math.fround(Math.imul(Math.fround(Math.abs(Math.fround(Math.fround(Math.max(x, Math.fround(0.000000000000001)))))), 0x100000001)) >>> 0))) | 0)) ^ (Math.acosh((Math.pow(( + ( + x)), ( + Math.fround((Math.fround(x) + Math.fround(x))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [-0x080000000, 0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000001, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, 2**53, -0x080000001, -0, Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, 1/0, Number.MIN_VALUE, 0.000000000000001, 0, -0x100000000, 0/0, 1, 0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 0x07fffffff, -Number.MIN_VALUE, -0x100000001, -(2**53+2), -0x0ffffffff, 42, -(2**53), -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1382; tryItOut("v2 = evaluate(\"mathy2 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var ff = foreign.ff;\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    return +((-4503599627370497.0));\\n  }\\n  return f; })(this, {ff: decodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53), 0x100000000, 0.000000000000001, 1.7976931348623157e308, -0, 0, Math.PI, 2**53-2, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 2**53, -0x07fffffff, -0x100000001, 0/0, -1/0, 0x100000001, 1, -Number.MIN_VALUE, 0x080000001, -0x080000000, -0x100000000, 42, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x0ffffffff, 1/0, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); \", ({ global: g2.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 == 1), noScriptRval: , sourceIsLazy: Map((this.zzz.zzz = (/((?:\\b|[\u00d3\\uB0F7])(?!([^])\u8f46{3,5}))|\\u0093?/yim).apply()), x), catchTermination: (x % 21 != 20), element: this.o1, elementAttributeName: s2 }));");
/*fuzzSeed-71289653*/count=1383; tryItOut("/*RXUB*/var r = /\\3/im; var s = \"\\uf1bb\\na\\u2629\\u8f46\\u8f46\\u8f46\\u8f46\\u8f46\\u8f46\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=1384; tryItOut("\"use strict\"; /*bLoop*/for (hjxnhq = 0; hjxnhq < 56; ++hjxnhq, (4277)) { if (hjxnhq % 3 == 0) { let (y) { v1 = evalcx(\"/* no regression tests found */\", g2); } } else { h1 = g1.objectEmulatingUndefined(); }  } ");
/*fuzzSeed-71289653*/count=1385; tryItOut("i2 = a1[-26(({})) >>>= (window ? arguments : x)];");
/*fuzzSeed-71289653*/count=1386; tryItOut("a1[2];");
/*fuzzSeed-71289653*/count=1387; tryItOut("/*vLoop*/for (var zalpoi = 0; zalpoi < 158; ++zalpoi) { const w = zalpoi; this.a2.unshift(e1); } ");
/*fuzzSeed-71289653*/count=1388; tryItOut("mathy4 = (function(x, y) { return Math.pow(( + Math.sin((( - Math.fround(( - ( + Math.min(( + (y ** Math.cosh(x))), ( + y)))))) | 0))), (( + ( ~ ((Math.imul(Math.fround(Math.hypot((Math.imul((Math.asinh(y) >>> 0), 1) >>> 0), y)), Math.fround(Math.fround((Math.fround(-(2**53-2)) || Math.fround(y))))) >>> 0) | 0))) >>> 0)); }); ");
/*fuzzSeed-71289653*/count=1389; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=1390; tryItOut("\"use strict\"; Array.prototype.shift.call(a0);");
/*fuzzSeed-71289653*/count=1391; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: function shapeyConstructor(dileda){\"use strict\"; Object.preventExtensions(dileda);return dileda; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000001, -1/0, 0.000000000000001, -(2**53+2), -0x100000000, 42, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -0x080000001, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 1/0, 2**53+2, -Number.MAX_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53), -0, Number.MIN_VALUE, -Number.MIN_VALUE, 0x0ffffffff, 2**53, 0, 1.7976931348623157e308, -0x080000000, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, 1, 0x080000001]); ");
/*fuzzSeed-71289653*/count=1392; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0);");
/*fuzzSeed-71289653*/count=1393; tryItOut("Object.seal(i2);");
/*fuzzSeed-71289653*/count=1394; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.fround(mathy2(Math.fround((((Math.fround(y) != (x >>> 0)) >>> 0) >= Math.hypot(y, (Math.pow(x, x) ? x : y)))), Math.fround(mathy4(y, ( ! ( + ((y >>> 0) === (( + (( + x) ? ( + mathy0(y, Number.MIN_SAFE_INTEGER)) : ( + x))) >>> 0)))))))) + (Math.hypot(Math.fround(Math.cosh(Math.fround((x ? y : x)))), Math.ceil(x)) , (Math.min(((((y >>> 0) < (Math.sqrt(( + (Math.fround(0) & Math.fround((x ? y : -0x080000001))))) | 0)) | 0) | 0), mathy3(Math.asin(x), ( + Math.cos((Math.imul(42, y) ? y : (y >>> 0)))))) | 0))); }); testMathyFunction(mathy5, ['', true, '0', ({toString:function(){return '0';}}), (new String('')), 0, (new Number(0)), [0], ({valueOf:function(){return 0;}}), 0.1, (new Boolean(true)), /0/, NaN, false, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), undefined, (new Boolean(false)), '\\0', (new Number(-0)), [], (function(){return 0;}), '/0/', 1, null, -0]); ");
/*fuzzSeed-71289653*/count=1395; tryItOut("mathy2 = (function(x, y) { return mathy1(((( ! Math.fround((((Math.imul(((x ? y : y) | 0), (( + mathy1(( + Math.log(0/0)), ( + x))) >>> 0)) | 0) - ((mathy0((2**53+2 >>> 0), (( + ( ! x)) >>> 0)) >>> 0) | 0)) | 0))) | 0) | 0), (((((Math.fround(( - Math.fround(Math.pow(y, Math.max((-1/0 >>> 0), (y >>> 0)))))) | ( + (( + y) + ( + (mathy1((( + (( + y) * x)) >>> 0), (x >>> 0)) | 0))))) >>> 0) < (Math.atan(( + y)) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-71289653*/count=1396; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1397; tryItOut("h0.keys = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d0 = ((0x21285ec6) ? (x) : (d1));\n    {\n      d1 = (4097.0);\n    }\n    d1 = (d0);\n    d1 = (d1);\n    d1 = (d1);\n    i2 = ((abs(((-(((((0xffffffff) ? (0xcb598e76) : (0xffffffff)))>>>((0x702c45ec)-(0x10c2a19e))) < (((b))>>>((0x72c2ff85)+(0xf9857150))))) | (-0xaacc8*((+atan2(((d0)), ((d1)))) > (-536870912.0)))))|0));\n    return (((1)-(0xfaf058d0)+(((d1)) < (((0xfa9f1100)+(1))>>>(((33.0) == (d1))+((0x38cb5d6a) != (~~(2097152.0))))))))|0;\n    switch ((((0x39a5f527))|0)) {\n      case 1:\n        d1 = (((Infinity)) - ((((1.0)) / ((2147483649.0)))));\n        break;\n      case 0:\n        return ((((((0xff38f3bc)*0xa6b4)|0))-(-0x8000000)))|0;\n        break;\n      case -3:\n        (Int32ArrayView[(((x)|0) % (((0x44ab13d0) / (0x55241064)) >> ((0xcf0eacc3)))) >> 2]) = ((Uint8ArrayView[(((+abs(((7.737125245533627e+25)))) == (d0))+((-0x8000000) ? (i2) : (0xfe4e894c))) >> 0]));\n        break;\n      case 0:\n        {\n          d0 = (-8796093022209.0);\n        }\n      default:\n        d1 = (+(0x4c9a1668));\n    }\n    {\n      return (((i2)))|0;\n    }\n    d1 = (d1);\n    return ((((0xcf9530d) < (0xd21848a4))-(1)-((i2) ? (0xfde5a223) : (1))))|0;\n  }\n  return f; });");
/*fuzzSeed-71289653*/count=1398; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + (( + Math.pow(( ! Math.fround(Math.atan(( + ( ~ ( + Math.expm1(Math.fround(mathy1((x | 0), 2**53))))))))), Math.atan2(( + (Math.fround(( - Math.fround(y))) - Math.fround((Math.tan((Math.atan2(x, Math.min(y, x)) >>> 0)) >>> 0)))), y))) == ( + mathy0(((((Math.cosh(Math.fround(((x == (Math.trunc(x) >>> 0)) >>> 0))) | 0) * (Math.max(Math.fround(( - Math.fround(x))), y) | 0)) | 0) >>> 0), Math.fround(Math.asin((( + ((Math.pow(x, ( + ( + Math.log(y)))) >>> 0) | 0)) | 0))))))); }); testMathyFunction(mathy3, [-(2**53-2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, -0x100000000, 0x0ffffffff, 42, 0x080000000, 1.7976931348623157e308, -0, 0x100000000, 0.000000000000001, -(2**53), 0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_VALUE, 0x07fffffff, 2**53+2, 1, -0x080000001, 0x100000001, 2**53-2, 2**53, Number.MAX_VALUE, -0x07fffffff, -0x100000001, 1/0, 0/0, -Number.MAX_SAFE_INTEGER, -1/0, -(2**53+2), -Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-71289653*/count=1399; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return (( ~ ( + mathy2(Math.fround((( ! (Math.hypot((y | 0), x) | 0)) ? Math.fround(( ~ Math.asin(Math.fround(y)))) : Math.fround(Math.round(( - y))))), ( - Math.hypot((y | 0), ( - 0x07fffffff)))))) | 0); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000000, 0x0ffffffff, Number.MAX_VALUE, -(2**53-2), 2**53+2, -(2**53+2), -1/0, Math.PI, -0, 0x100000001, 1/0, 1.7976931348623157e308, 0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, 0, 2**53, -0x07fffffff, 42, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, 0.000000000000001, 0x080000000, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=1400; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.cbrt(Math.fround(Math.max(Math.fround((0x100000000 % (((((y != (Number.MAX_VALUE >>> 0)) <= x) | 0) >>> 0) >>> Math.max(Math.PI, (0x100000001 | 0))))), (y | 0)))) | 0) % (mathy0(Math.atan2((Math.fround(Math.atan2(x, Math.fround(Math.fround(Math.log2(Math.fround(x)))))) | 0), x), (( - (( + y) ^ y)) | 0)) | 0)); }); testMathyFunction(mathy1, [-1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0x100000000, Math.PI, 0, 0x080000001, 0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, 1.7976931348623157e308, Number.MAX_VALUE, 1, -Number.MIN_VALUE, 0x100000001, -(2**53-2), -0x100000000, 42, -0x100000001, 2**53, -Number.MAX_VALUE, -0, 2**53+2, 0.000000000000001, 0x0ffffffff, -(2**53), 1/0, -0x080000001, -0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1401; tryItOut("a1.splice(-13, ({valueOf: function() { v2 = (g1.p2 instanceof f2);function x(eval, \u3056) { return ({message: this, eval: c }) } v2.valueOf = f0;return 7; }}), m2, o0);");
/*fuzzSeed-71289653*/count=1402; tryItOut("m0.has(f1);");
/*fuzzSeed-71289653*/count=1403; tryItOut("/*RXUB*/var r = new RegExp(\"[\\u00ab-\\u00c9\\\\S\\\\cK-\\u74f3\\\\s]\", \"gm\"); var s = \"0\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=1404; tryItOut("\"use strict\"; print(uneval(v1));");
/*fuzzSeed-71289653*/count=1405; tryItOut("this.v0 = Object.prototype.isPrototypeOf.call(a1, p0);");
/*fuzzSeed-71289653*/count=1406; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=1407; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(Math.ceil(Math.fround(Math.hypot((x - Math.fround((Math.fround(y) ? Math.fround(( ~ (x >>> 0))) : Math.fround(x)))), (mathy0((y >>> 0), ( + Math.atan2(( + Math.sign(y)), ((0x07fffffff * x) >>> 0)))) >>> 0))))) + (( + (( + Math.acos((x / y))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0.000000000000001, 1.7976931348623157e308, 0, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, 1, -0x100000001, 0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 2**53, 1/0, -0x0ffffffff, 0x080000000, -1/0, 2**53+2, 0x080000001, Math.PI, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 0/0, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 0x100000000, -(2**53-2), 42, -0x07fffffff, Number.MAX_VALUE, -0x080000001]); ");
/*fuzzSeed-71289653*/count=1408; tryItOut("Array.prototype.push.apply(a1, [f1]);");
/*fuzzSeed-71289653*/count=1409; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ((Math.min((Math.fround(Math.imul((1.7976931348623157e308 | 0), Math.fround(Math.atan2((Math.PI >>> 0), (y & (y && x)))))) >>> 0), (Math.atan2(Math.fround((Math.fround(Math.log10(x)) + Math.fround(x))), (Math.min((( + (Math.hypot((x >>> 0), ( + y)) >>> 0)) | 0), ((((y ? Math.cbrt(( + y)) : y) | 0) || (x | 0)) | 0)) | 0)) >>> 0)) | 0) ? (((((Math.sinh(x) << y) >>> 0) >>> 0) - (Math.imul(Math.fround(( - (Math.trunc((y >>> 0)) >>> 0))), Math.imul(((( + Math.min(0x080000000, ( + -0x07fffffff))) ? ((( - (42 | 0)) | 0) >>> 0) : (y | 0)) >>> 0), y)) >>> 0)) >>> 0) : ( ~ Math.fround((y & Math.sin(Math.pow(Math.asinh(y), Math.fround(( + Math.fround(x))))))))); }); ");
/*fuzzSeed-71289653*/count=1410; tryItOut("t1.toSource = f0;");
/*fuzzSeed-71289653*/count=1411; tryItOut("mathy1 = (function(x, y) { return (((Math.ceil(Math.fround((Math.fround(( + (Math.fround((Number.MIN_VALUE & Math.fround(0x0ffffffff))) << Math.acosh(Math.trunc(y))))) | Math.fround(Math.fround(( ~ Math.fround(Math.imul(( + (x + ( + Math.log(y)))), x)))))))) | 0) <= ( + (( - ((Math.max(mathy0(Math.clz32(Number.MIN_SAFE_INTEGER), ( + x)), Math.atan2(y, ( ~ Math.hypot(Math.atan2(x, y), x)))) | 0) >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy1, [Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, 1.7976931348623157e308, 0, 42, 0x100000000, 1, 0x080000001, -0x100000000, Math.PI, 2**53+2, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 0x100000001, 1/0, 2**53-2, 0/0, -0, 0x080000000, -1/0, 2**53, 0.000000000000001, -0x080000001, -(2**53), -0x07fffffff, 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=1412; tryItOut("g2 = this;");
/*fuzzSeed-71289653*/count=1413; tryItOut("/*bLoop*/for (vzmgjm = 0; vzmgjm < 9; ++vzmgjm) { if (vzmgjm % 4 == 3) { (\"\\uA4F2\"); } else { f2 + v0; }  } ");
/*fuzzSeed-71289653*/count=1414; tryItOut("arguments = b;");
/*fuzzSeed-71289653*/count=1415; tryItOut("/*MXX2*/g0.Float64Array.BYTES_PER_ELEMENT = g0.o0;");
/*fuzzSeed-71289653*/count=1416; tryItOut("if((x % 4 != 1)) {/*MXX1*/o1 = g0.Int8Array.prototype.constructor; } else {p1 = Proxy.create(h0, a1); }");
/*fuzzSeed-71289653*/count=1417; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.log2(( ! (((-1/0 | 0) ? (( ! x) | 0) : (y | 0)) | 0))); }); testMathyFunction(mathy0, [0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, -0x07fffffff, -Number.MAX_VALUE, 0/0, -1/0, -0x080000000, 0x100000001, Number.MIN_VALUE, 1, 2**53-2, Number.MIN_SAFE_INTEGER, 0, 2**53, 1/0, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, -0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, -(2**53), -(2**53-2), Math.PI, 2**53+2, -0x100000001, 42, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1418; tryItOut("mathy3 = (function(x, y) { return Math.tanh(Math.hypot(Math.fround(Math.imul(Math.fround(x), Math.fround((y ^ ( + x))))), (Math.cosh(Math.imul(Math.fround(y), ( + (( + (((x << Math.fround(y)) , x) >>> 0)) >>> 0)))) | 0))); }); testMathyFunction(mathy3, /*MARR*/[ /x/g , new Boolean(false), false, x, x, x, x, x, x, x, x, x, x, x, x,  /x/g , false, false, x, ({}), new Boolean(false), new Boolean(false), ({}), ({}), false, new Boolean(false), ({}), false]); ");
/*fuzzSeed-71289653*/count=1419; tryItOut("mathy1 = (function(x, y) { return Math.imul(mathy0((x << (( - (x >>> 0)) >>> 0)), ( + Math.hypot(Math.fround(( + Math.clz32(( + Math.fround(Math.cbrt(Math.fround(( ~ ( + -Number.MIN_VALUE))))))))), ( + mathy0(y, Math.fround(mathy0(42, (((y >>> 0) || (x >>> 0)) >>> 0)))))))), ( + Math.log1p((y | 0)))); }); testMathyFunction(mathy1, [Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -0x080000000, 0x100000001, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, 2**53-2, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001, 0/0, 42, 0x080000000, -0x080000001, 0x07fffffff, -0x100000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 1, 2**53, 1/0, 1.7976931348623157e308, 0, -0, -1/0]); ");
/*fuzzSeed-71289653*/count=1420; tryItOut("let b = x;this.g0.m1.has(e2);");
/*fuzzSeed-71289653*/count=1421; tryItOut("print(x);");
/*fuzzSeed-71289653*/count=1422; tryItOut("Array.prototype.sort.call(a2, (function mcc_() { var iabigd = 0; return function() { ++iabigd; this.f0(/*ICCD*/iabigd % 2 == 1);};})());");
/*fuzzSeed-71289653*/count=1423; tryItOut("if(false) {a1.pop();v0 = (o0 instanceof p2); } else  if (x = /\\3+|[^\\cB-_\\u0003\\u9610-\\u0048]\\B+?*?/) selectforgc(o1); else with({c: /\\2/m})print( /x/g );");
/*fuzzSeed-71289653*/count=1424; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -2199023255553.0;\n    var i3 = 0;\n    i1 = (!(i0));\n    i1 = (/*FFI*/ff()|0);\n    {\n      i3 = ((abs((abs((((/*FFI*/ff(((d2)), ((+abs(((33554433.0))))), ((((0x72eff06a)) & ((0xffffffff)))))|0)*-0x7468f) ^ ((i0)+(0xff7f68b0))))|0))|0));\n    }\n    (Int16ArrayView[2]) = ((((i0)) ^ (((~~(((-1.5111572745182865e+23)) % ((268435455.0)))) != (~~(-18446744073709552000.0)))-(i3)+((0xf86623a1) ? ((0x1d28eb2e)) : (0xf99e1d4f)))) % ((((536870913.0) > ((0xfcd244eb) ? (34359738367.0) : (1.0009765625)))-((0xffffffff) ? ((((0xa5d192f3))>>>((0xbcafddf5)))) : (i0))+(i0))|0));\n    {\n      (Uint32ArrayView[((i0)+(((((0x7cfc3eb0) <= (0x3d85d293))+(0x90f564a6))>>>((0xea748bef)+(0xa226cd6b)-(-0x8000000))))) >> 2]) = ((Int32ArrayView[4096]));\n    }\n    {\n      d2 = (+(0.0/0.0));\n    }\n    return +((-4.835703278458517e+24));\n    i0 = (/*FFI*/ff()|0);\n    i0 = (/*FFI*/ff(((1.00390625)), ((257.0)), ((73786976294838210000.0)))|0);\n    d2 = (+/*FFI*/ff(((((0x2bfe8a00) % (((((eval(\"this.a2 = a0.concat(this.t1);\")()))+(i3)))>>>((0xfdcdabc7)-((0x59abad41) <= (0x24c4f427))))) & ((0xf9b87197)+(i0)+(0xd850a2b0)))), ((0x6207886c))));\n    return +((-3.0));\n  }\n  return f; })(this, {ff: (Uint8Array).call}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[new Number(1.5), new String(''), new Number(1.5), new String(''), new String(''), x, x, new Number(1.5), new String(''), new String(''), new String(''), new String(''), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-71289653*/count=1425; tryItOut("\"use strict\"; print((4277));");
/*fuzzSeed-71289653*/count=1426; tryItOut("\"use strict\"; const eval =  /x/g , eval, c;/*RXUB*/var r = /(\\3)(?!((?=\\w)*?))|(\\S)/gi; var s = \"\\na\"; print(uneval(s.match(r))); ");
/*fuzzSeed-71289653*/count=1427; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.cbrt(( + ( ! Math.fround(Math.exp(( + Math.log10(Math.fround(( + 1))))))))); }); testMathyFunction(mathy0, [(new Number(0)), true, undefined, NaN, '0', ({valueOf:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return 0;}}), 0.1, [], null, (new String('')), (new Boolean(true)), [0], '/0/', '', '\\0', ({toString:function(){return '0';}}), 1, false, objectEmulatingUndefined(), /0/, 0, (new Boolean(false)), (new Number(-0)), -0]); ");
/*fuzzSeed-71289653*/count=1428; tryItOut("a2 = a0.slice(-6, -4);");
/*fuzzSeed-71289653*/count=1429; tryItOut("\"use strict\"; testMathyFunction(mathy1, [(function(){return 0;}), (new Number(0)), (new Boolean(false)), NaN, '/0/', undefined, true, ({valueOf:function(){return 0;}}), /0/, '\\0', false, -0, [], (new String('')), objectEmulatingUndefined(), 0.1, '0', [0], ({toString:function(){return '0';}}), (new Boolean(true)), (new Number(-0)), 1, ({valueOf:function(){return '0';}}), null, 0, '']); ");
/*fuzzSeed-71289653*/count=1430; tryItOut("(\"\\u9E17\");v1 = (t0 instanceof p0);");
/*fuzzSeed-71289653*/count=1431; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan2(Math.fround(Math.asin(((Math.fround(( ! Math.fround(x))) ? (( ! (x | 0)) % Math.fround((Math.fround(y) , Math.fround(y)))) : ( + (Math.fround(Math.acosh(y)) + Math.fround(x)))) ? ( + -0x07fffffff) : Math.imul(Math.max((mathy0((y | 0), x) >>> 0), x), Math.sin(x))))), ( + ( - mathy2(((((((( + Math.min(x, ( + (Math.fround(x) >= (x | 0))))) >>> 0) === (x >>> 0)) >>> 0) >>> 0) == mathy1(Math.fround(y), y)) >>> 0), ( - Math.atanh(( + Math.pow(( + -Number.MAX_SAFE_INTEGER), ( + Number.MAX_SAFE_INTEGER))))))))); }); testMathyFunction(mathy4, [(new Boolean(false)), undefined, (new Number(0)), '', NaN, ({valueOf:function(){return '0';}}), true, objectEmulatingUndefined(), /0/, 0.1, ({valueOf:function(){return 0;}}), (function(){return 0;}), -0, 0, '\\0', ({toString:function(){return '0';}}), null, false, '0', (new Number(-0)), (new Boolean(true)), [], '/0/', 1, [0], (new String(''))]); ");
/*fuzzSeed-71289653*/count=1432; tryItOut("/*RXUB*/var r = new RegExp(\"(?=.)|((^.)*)?|(?![\\\\\\u00d5\\\\D\\\\0-\\\\t])*?|\\\\s+?|(?!(?!.)\\\\B|(\\\\b)\\\\d[^]\\\\1*?(?!\\\\b|\\\\B)..{3,})*\", \"i\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1433; tryItOut("\"use strict\"; a0 = arguments;");
/*fuzzSeed-71289653*/count=1434; tryItOut("\"use strict\"; \"use asm\"; s1 = new String;\nArray.prototype.sort.call(a0, (function(j) { if (j) { try { v2 = (o0.h2 instanceof g0.b1); } catch(e0) { } try { let v0 = t0.BYTES_PER_ELEMENT; } catch(e1) { } selectforgc(o0); } else { try { v2 = Object.prototype.isPrototypeOf.call(p0, m2); } catch(e0) { } try { i1.next(); } catch(e1) { } try { a0[4] = o0; } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(o2.m2, p2); } }), s2, o0.i1, (((let (c = x) [[]])(-13)) = -27), e1);\n");
/*fuzzSeed-71289653*/count=1435; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3.|.[^\\\\\\u8e52\\\\s\\\\w](N)|[^][^]|\\\\D|[^\\ub6f7\\\\\\ue8de]\\\\b|`{4}(?!.{3}|\\\\B\\\\b|.|^|\\\\2?)(?!\\\\B+?)*|(\\\\B\\\\B)|\\\\B(?!.)(?=.)|\\u4ce3?*?\", \"gi\"); var s = \"\\n\\na\\u00b0\\n\\u2ff9\\n\\na\\u00b0\\n\\u2ff9\\n\\na\\u00b0\\n\\u2ff9\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=1436; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.atan(Math.ceil(((x ? x : Math.fround(0x100000000)) >>> 0))); }); ");
/*fuzzSeed-71289653*/count=1437; tryItOut("\"use strict\"; this.t1 = new Int32Array(b1, 36, 13);");
/*fuzzSeed-71289653*/count=1438; tryItOut("v1 = evaluate(\"e0.has(p0);\", ({ global: g1.g0, fileName: null, lineNumber: 42, isRunOnce: (x % 39 != 20), noScriptRval: true, sourceIsLazy: false, catchTermination: this.__defineSetter__(\"b\", /*wrap1*/(function(){ v2 = m2[\"1\"];return (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.fround(( ! ( + Math.pow(( ~ Math.cbrt((( - Math.fround(Math.hypot(Math.fround(Math.pow(Math.fround(( + (y != ( + -0x0ffffffff)))), x)), Math.fround((Math.fround((y | 0)) | 0))))) >>> 0))), (( + Math.fround(( ~ Math.fround(Math.fround(( - (y | 0))))))) | 0))))), Math.fround((Math.fround((Math.fround(Math.min(Math.fround((( ! (Math.fround(( + Math.fround((Math.fround(Math.fround(Math.atan2(-0x07fffffff, Math.hypot(Math.fround(Math.imul(Math.fround(2**53-2), -0)), y)))) >>> 0)))) >>> 0)) >>> 0)), ( + Math.sinh(( + (Math.round((Math.fround((Math.fround(y) - (( + x) | 0))) | 0)) | 0)))))) | 0)) | 0)))); })})()), element: o1 }));");
/*fuzzSeed-71289653*/count=1439; tryItOut("\"use strict\"; /*RXUB*/var r = (void options('strict')); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=1440; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return ((((((/*FFI*/ff(((~((0xffffffff)-(0x858d930f)+(0xfc93d0f5)))), ((((0xfe8343e3)) ^ ((0xb3cd5dae)))), ((abs((0x6df9c052))|0)), ((-288230376151711740.0)), ((-513.0)), ((-4.835703278458517e+24)), ((4294967297.0)), ((-34359738369.0)), ((4611686018427388000.0)), ((-549755813889.0)), ((-3.8685626227668134e+25)), ((288230376151711740.0)), ((-1.0625)), ((8193.0)))|0)+(((0x4144d9ec) > (0x21409cee)) ? (i0) : (0xe2667a7))) << (((~((0x1086f62)-((0x19101f08) >= (0x752cd75f)))) > (~~(+(((0xf891c30d))>>>((0xd2760a78)))))))) == (~((0xfd59ec38))))+(0xb51d0b3f)))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[x, new Number(1.5), new String(''), null, new String('')]); ");
/*fuzzSeed-71289653*/count=1441; tryItOut("mathy2 = (function(x, y) { return ( ! ( + (Math.max(Math.clz32((Math.hypot(( + (0x100000000 > Math.fround(((Math.fround(y) ? Math.fround(y) : Math.fround(x)) >>> 0)))), x) >>> 0)), ( + ( + Math.atan2(((( + x) == ( + x)) >>> 0), y)))) == ((Math.fround(( - (x >>> 0))) ^ ((x % x) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=1442; tryItOut("mathy5 = (function(x, y) { return Math.min((mathy1(((Math.log2(y) | 0) >>> 0), (Math.max(Math.fround(( + (( + Math.expm1(mathy2(y, x))) || ( + Math.pow(( + x), ( + y)))))), Math.fround(( ! (Math.imul(x, ( + x)) | 0)))) >>> 0)) >>> 0), (mathy2(( + ( + ( + mathy3(((0 < x) | 0), (x | 0))))), ((((x >>> 0) >= (y | 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy5, [0x080000001, Number.MAX_VALUE, 2**53, 0x100000000, -0x080000000, 42, -0, -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -0x0ffffffff, -(2**53-2), 0/0, 1, -(2**53), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, -0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, -0x100000000, -Number.MIN_VALUE, 0, -1/0, -0x080000001, 1/0, -0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=1443; tryItOut("\"use strict\"; for (var p in g1) { try { v1.toSource = (function() { try { m0.__proto__ = o2.s2; } catch(e0) { } try { v1 = g1.runOffThreadScript(); } catch(e1) { } m2.set(h0, o0); return h1; }); } catch(e0) { } try { delete m0[\"call\"]; } catch(e1) { } try { let this.v2 = a2.length; } catch(e2) { } t1 = new Uint8Array(b1, 120, 5); }");
/*fuzzSeed-71289653*/count=1444; tryItOut("\"use strict\"; a0.reverse(e0);");
/*fuzzSeed-71289653*/count=1445; tryItOut("g2 = this;");
/*fuzzSeed-71289653*/count=1446; tryItOut("\"use strict\"; ;");
/*fuzzSeed-71289653*/count=1447; tryItOut("h0.delete = (function() { a1 = (allocationMarker() if (Object.defineProperty(z, \"constructor\", ({configurable: false, enumerable: false})))); return p2; });");
/*fuzzSeed-71289653*/count=1448; tryItOut("v0 = g0.runOffThreadScript();");
/*fuzzSeed-71289653*/count=1449; tryItOut("mathy0 = (function(x, y) { return Math.expm1(((Math.pow(( - x), ( ~ ((x && y) % Math.sinh(x)))) >>> 0) == Math.fround(( ! Math.fround(y))))); }); ");
/*fuzzSeed-71289653*/count=1450; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.round(( ! (Math.tanh(((( ! ((y , Math.fround((y ^ y))) | 0)) | 0) | 0)) | 0))); }); testMathyFunction(mathy0, [1.7976931348623157e308, 1, 0x07fffffff, -(2**53+2), -0, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -Number.MIN_VALUE, -0x100000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0, 1/0, -1/0, -0x080000001, -(2**53-2), 0x100000000, 2**53+2, Number.MAX_VALUE, -Number.MAX_VALUE, 0.000000000000001, 0x080000000, Number.MIN_VALUE, Math.PI, -0x100000001, 42, 0x100000001, -0x07fffffff, -(2**53), -0x080000000]); ");
/*fuzzSeed-71289653*/count=1451; tryItOut("s0 = new String(g0.o2.o2.t1);");
/*fuzzSeed-71289653*/count=1452; tryItOut("e1 + a0;");
/*fuzzSeed-71289653*/count=1453; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var cos = stdlib.Math.cos;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = ((+(1.0/0.0)) + (+(((0x8d61e944)+(0x7675ae9a)-(-0x8000000))>>>(((NaN) == (d0))))));\n    {\n      return (((0xdd018036)-(/*FFI*/ff(((~((-0x8000000)))), ((((0xa4ab32c1)) >> (-(/*FFI*/ff(((+abs(((((1.001953125)) * ((-4611686018427388000.0))))))), ((((0x306e7147)) | ((0xa86bc3db)))))|0)))), (((((d0) == (+(0.0/0.0)))-(0x7e810c64)) | ((void options('strict'))))), ((((d1)) - ((+cos(((d0))))))), ((((((2305843009213694000.0)) / ((-8589934593.0)))) - ((+/*FFI*/ff())))), ((((0xa8110e67)+(-0x8000000)) << ((0xed47af3e)+(0xfa55fadd)))), ((((0x9285d8cb)) ^ ((0x685923aa)))))|0)))|0;\n    }\n    (Float32ArrayView[1]) = ((((d1)) % ((+(1.0/0.0)))));\n    return (((0xaf656b21)+(0x41e0bb33)))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-0, -0x100000000, -1/0, -0x080000000, Number.MAX_VALUE, 0.000000000000001, 0/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0x080000001, 0x07fffffff, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), Math.PI, 0x100000000, -(2**53-2), 0x080000001, -0x100000001, 1, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0, 1.7976931348623157e308, 2**53+2, 0x080000000, -0x07fffffff, 2**53-2]); ");
/*fuzzSeed-71289653*/count=1454; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\\u00a0\"; print(r.exec(s)); ");
/*fuzzSeed-71289653*/count=1455; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.hypot((mathy0((mathy1(0, ((((mathy0(((((x >>> 0) === (y >>> 0)) >>> 0) | 0), (mathy2(( ~ 2**53+2), x) | 0)) | 0) == ( - Math.fround(((0.000000000000001 | 0) >>> Math.fround(x))))) | 0) >>> 0)) | 0), ( ~ Math.fround(Math.abs(Math.fround((mathy1(Number.MIN_SAFE_INTEGER, (y >>> 0)) >>> 0)))))) | 0), ( + Math.fround(Math.pow((y < ((((Math.atan(y) >>> 0) % (1 >>> 0)) >>> 0) >>> 0)), Math.round(( + Math.fround(Math.sqrt((mathy0(((y <= (-(2**53) >>> 0)) | 0), Math.fround(Math.fround((Math.fround(x) / ( + 1))))) | 0))))))))); }); testMathyFunction(mathy3, [(new Number(0)), (new Number(-0)), ({valueOf:function(){return '0';}}), -0, '/0/', [], '0', undefined, objectEmulatingUndefined(), (new Boolean(true)), '', 0.1, 0, true, false, null, (new Boolean(false)), [0], '\\0', 1, (function(){return 0;}), (new String('')), ({toString:function(){return '0';}}), /0/, ({valueOf:function(){return 0;}}), NaN]); ");
/*fuzzSeed-71289653*/count=1456; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.fround(Math.fround(Math.exp(Math.fround(Math.hypot(-(2**53+2), (Math.expm1(( + ( ~ ( + 0x07fffffff)))) >>> 0)))))) ? Math.fround(Math.fround(Math.min(Math.fround((Math.max(( + ( ~ Math.fround((x >>> x)))), ((( + Math.sqrt(( + Math.fround(Math.fround(0x0ffffffff))))) && y) >>> 0)) >>> 0)), (Math.atan2(( + Math.pow(y, (Math.fround(0/0) >>> 0))), (((Math.min((((Math.fround(( - Math.fround(x))) | 0) >> (0x0ffffffff | 0)) >>> 0), \"use strict\"; this.v2 = (b2 instanceof o0);) | 0) , (y >>> 0)) >>> 0)) >>> 0)))) : Math.fround(Math.max(((( + y) / ( + ( ~ (( - (y | 0)) | 0)))) == (Math.min(((((x >>> 0) & ((Math.PI % x) >>> 0)) >>> 0) >>> 0), (((y >>> 0) | y) >>> 0)) >>> 0)), Math.atanh(Math.hypot(x, 42))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, 0x0ffffffff, 1, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, 1/0, -0, -0x080000001, Number.MIN_VALUE, 0x100000001, 0/0, -0x100000000, 2**53, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53-2), -Number.MAX_VALUE, -0x100000001, 0x080000000, 0, 0x07fffffff, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000000, 42, -1/0, 0x080000001, -(2**53), 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=1457; tryItOut("i0 + o1.i2;");
/*fuzzSeed-71289653*/count=1458; tryItOut("testMathyFunction(mathy2, [Math.PI, 0x100000000, -1/0, 2**53, -(2**53), 1.7976931348623157e308, -0x080000001, 42, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 0x100000001, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_VALUE, -0x07fffffff, 0x080000001, -0, 0/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2, 0x080000000, 0, 0.000000000000001, -0x0ffffffff, -(2**53+2), -0x080000000, -0x100000001, 1, 1/0]); ");
/*fuzzSeed-71289653*/count=1459; tryItOut("\"use strict\"; m0 = new Map;");
/*fuzzSeed-71289653*/count=1460; tryItOut("\"use strict\"; v1 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 32 == 14), noScriptRval: false, sourceIsLazy: (function ([y]) { })(), catchTermination: (x % 4 == 0) }));function w(e, x, [], a, y, z, x, eval, z, x, NaN, window = this, a, x =  '' , this, c, window, NaN, x = function ([y]) { }, eval, a, x, e, x, x, x, NaN =  /x/g , x, x, \u3056, window, x, x, b, window, y, window, w =  /x/g , \u3056, eval = \"\\uC9C7\", x, w, window, c = new RegExp(\"(?:\\\\1)\", \"y\"), c = -22, x = 11, x, x, -5 = -3, x, \u3056, d, w = this, x, x, \u3056, NaN, y, y, d, c, x, x, window, b, w, x, x, z, x =  \"\" , eval = this, c = x, e, x, x, x, c, x, z, y, x = \"\\u9950\", x, a, e, \u3056, x, c, x, window, NaN, y, x, c, x, x, \"25\",  , \u3056, d, ...x) { v0 = (v1 instanceof o1); } { void 0; disableSPSProfiling(); } Object.prototype.watch.call(o2.b2, \"get\", f2);");
/*fuzzSeed-71289653*/count=1461; tryItOut("print(x);");
/*fuzzSeed-71289653*/count=1462; tryItOut("e1.add(s2);");
/*fuzzSeed-71289653*/count=1463; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1464; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var asin = stdlib.Math.asin;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+(((i0)) | (((~~(d1)))-((~~(+asin(((d1)))))))));\n    {\n      d1 = (16777217.0);\n    }\n    return (((/*FFI*/ff((((+(1.0/0.0)) + (d1))), (((((-0x82ee5*(0xfc1bb943)) >> ((-0x8000000)-(0xb599d32e)+(0xfa0fe59e))) % (((i0))|0)) & (((((0x407e81f2) % (0x7f4c520))|0) < (~~(1.888946593147858e+22)))))), (((d1))), ((NaN)), ((((0xb37c5106) % (0x7f125a24)) & ((i0)-(!(0xffffffff))))), ((8796093022208.0)))|0)+(0xfa30c612)))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-71289653*/count=1465; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(mathy0(Math.fround(Math.sign(x)), ((((x | 0) << (y | 0)) | 0) >>> 0))) % (Math.fround((Math.fround(((Math.log2(( ~ x)) >>> 0) , mathy0(y, 0x07fffffff))) < Math.fround(Math.hypot((( + Math.tan(( + x))) | 0), 0x07fffffff)))) >= Math.tanh(Math.cos(Math.max(mathy0((x >>> 0), x), -0x07fffffff))))) << (( + mathy0(Math.asin(x), Number.MIN_VALUE)) / (((y | x) ** Math.fround(Math.min(Math.sin(Math.log(y)), (( - x) | 0)))) >>> 0))); }); testMathyFunction(mathy1, [-0x080000000, 1, 42, -0x100000000, 0x100000001, -0x0ffffffff, -0x07fffffff, -0x100000001, 2**53+2, 0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, Number.MIN_VALUE, Math.PI, 0, 0x100000000, 0.000000000000001, 2**53-2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -Number.MAX_VALUE, -1/0, 1/0, -0x080000001, Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0/0, -0, 0x080000000]); ");
/*fuzzSeed-71289653*/count=1466; tryItOut("this.o0 = {};");
/*fuzzSeed-71289653*/count=1467; tryItOut("p0 + '';");
/*fuzzSeed-71289653*/count=1468; tryItOut("\"use strict\"; e2.delete(this.h1);");
/*fuzzSeed-71289653*/count=1469; tryItOut("\"use strict\"; let (pgcvvm, e, NaN, a = x -=  \"\" ) { v2 = Array.prototype.reduce, reduceRight.call(this.a0, s2); }");
/*fuzzSeed-71289653*/count=1470; tryItOut("mathy4 = (function(x, y) { return (Math.atan2(( ! (( + ( ~ ( + Math.fround(( ~ ( + mathy1(x, ( + x)))))))) ^ (Math.atanh(x) >>> 0))), Math.asin(((Math.min(Math.clz32(x), y) | 0) ? (((0x080000000 | 0) ? ((( + Math.fround((Math.fround(Math.fround(( ! Math.fround(y)))) >>> Math.fround(Math.PI)))) ? y : y) | 0) : (((y | 0) === ( + ( + x))) | 0)) | 0) : ( ! Math.hypot((y >> ( + Math.log2(x))), x))))) >>> 0); }); testMathyFunction(mathy4, [-0x080000000, -0x100000000, 1, 2**53, -0x0ffffffff, -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, 42, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1/0, -0x100000001, 2**53+2, Math.PI, 0x080000000, 2**53-2, -(2**53+2), -0x080000001, -Number.MIN_VALUE, 0/0, 0x100000001, -0, 1.7976931348623157e308, -1/0, -(2**53), 0.000000000000001, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=1471; tryItOut("mathy5 = (function(x, y) { return (mathy3(((Math.max(Math.fround(( - Math.fround(( + -0x080000000)))), Math.fround((Math.min((Math.imul(Math.max(y, y), Math.log(( + Math.fround(x)))) >>> 0), ((Math.clz32((( ! 2**53-2) | 0)) | 0) >>> 0)) >>> 0))) | 0) >>> 0), ((Math.pow((Math.imul(x, ( + Math.asinh(( + Math.imul(((x >> (x >>> 0)) >>> 0), ( - (Math.pow((0x0ffffffff >>> 0), (-Number.MIN_VALUE >>> 0)) >>> 0))))))) | 0), (((Number.MIN_SAFE_INTEGER ** (0x100000000 | 0)) / Math.cbrt(Math.max(Number.MIN_SAFE_INTEGER, (x >>> 0)))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, /*MARR*/[(1/0), (1/0), [1], [1], [1], [1], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], (1/0), [(void 0)], /*UUV2*/(getter.sinh = getter.has), [1], /*UUV2*/(getter.sinh = getter.has), (1/0), [(void 0)], /*UUV2*/(getter.sinh = getter.has), [(void 0)], /*UUV2*/(getter.sinh = getter.has), function(){}, (1/0), [(void 0)], /*UUV2*/(getter.sinh = getter.has), (1/0), /*UUV2*/(getter.sinh = getter.has), (1/0), function(){}, [(void 0)], [1], /*UUV2*/(getter.sinh = getter.has), function(){}, function(){}, [1], [(void 0)], [1], [1], [1], (1/0), [1], [1], [1], (1/0), function(){}, [1], function(){}, function(){}, function(){}, [(void 0)], [(void 0)], (1/0), /*UUV2*/(getter.sinh = getter.has), [1], function(){}, function(){}, [1]]); ");
/*fuzzSeed-71289653*/count=1472; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53+2), Number.MIN_SAFE_INTEGER, 1/0, 0, 0.000000000000001, -0x100000001, -0x07fffffff, -0x080000000, 2**53+2, -1/0, 0x0ffffffff, 2**53-2, 0x080000001, 0/0, Math.PI, 42, -0x080000001, -Number.MIN_VALUE, 0x07fffffff, -0x100000000, 0x080000000, -0x0ffffffff, -0, 1.7976931348623157e308, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), -Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1473; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + (( + ( + (Math.asin(( + Math.fround(( + (( + Math.fround(Math.min(Math.fround(( + mathy3((0x080000001 >>> 0), (-(2**53) >>> 0)))), (Math.atan2((x | 0), (x | 0)) | 0)))) ? ( + x) : ( + 2**53-2)))))) | 0))) | 0)) | 0); }); testMathyFunction(mathy5, [({toString:function(){return '0';}}), '\\0', ({valueOf:function(){return 0;}}), (new Boolean(false)), -0, (new String('')), '', /0/, false, ({valueOf:function(){return '0';}}), 0.1, true, 1, (function(){return 0;}), (new Number(0)), '/0/', NaN, null, '0', [0], [], undefined, objectEmulatingUndefined(), (new Boolean(true)), 0, (new Number(-0))]); ");
/*fuzzSeed-71289653*/count=1474; tryItOut("\"use strict\"; i2.next();");
/*fuzzSeed-71289653*/count=1475; tryItOut("if([]) e1.add(g0.a2); else  if ((void version(180))) /*bLoop*/for (var pztzqk = 0, fylmpf; pztzqk < 32; ++pztzqk) { if (pztzqk % 27 == 10) { for (var p in p2) { /*RXUB*/var r = r0; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex);  } } else { g2.e1.add(t1); }  } \n/*infloop*/ for (([[]]) of \"\\uCFCF\".valueOf(\"number\").yoyo(this)) {for (var p in p1) { try { Array.prototype.pop.call(a1); } catch(e0) { } try { i1 + ''; } catch(e1) { } g2.offThreadCompileScript(\"h0 = ({getOwnPropertyDescriptor: function(name) { t0 + b2;; var desc = Object.getOwnPropertyDescriptor(b1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v2 = false;; var desc = Object.getPropertyDescriptor(b1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { v0 = t1.length;; Object.defineProperty(b1, name, desc); }, getOwnPropertyNames: function() { p0 = x;; return Object.getOwnPropertyNames(b1); }, delete: function(name) { v0 = (m0 instanceof this.v1);; return delete b1[name]; }, fix: function() { v2 = Object.prototype.isPrototypeOf.call(e1, p0);; if (Object.isFrozen(b1)) { return Object.getOwnProperties(b1); } }, has: function(name) { for (var p in e1) { m2.delete(i1); }; return name in b1; }, hasOwn: function(name) { Array.prototype.shift.apply(a2, [i0]);; return Object.prototype.hasOwnProperty.call(b1, name); }, get: function(receiver, name) { s1.valueOf = f0;; return b1[name]; }, set: function(receiver, name, val) { return h1; b1[name] = val; return true; }, iterate: function() { s0 = a0[v1];; return (function() { for (var name in b1) { yield name; } })(); }, enumerate: function() { v1 = Object.prototype.isPrototypeOf.call(g1.g2.o0.f2, v2);; var result = []; for (var name in b1) { result.push(name); }; return result; }, keys: function() { g0.v1 = a1.length;; return Object.keys(b1); } });\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 4 != 3), sourceIsLazy: this, catchTermination: [,,z1] })); } }\n");
/*fuzzSeed-71289653*/count=1476; tryItOut("mathy1 = (function(x, y) { return mathy0(( + ( - (( ~ (Math.abs((Math.imul(y, 0x080000001) >>> 0)) >>> 0)) >>> 0))), ((((( ! (( + (y === x)) | 0)) & ((( + x) >= ( + ( + ( + (x >>> 0))))) === Math.sqrt(Math.imul(x, x)))) | 0) == ((Math.sqrt(( - y)) >>> 0) >>> 0)) | 0)); }); testMathyFunction(mathy1, [Math.PI, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, 1/0, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, 0, -0x080000001, -0x07fffffff, -(2**53-2), -0x100000001, -0x100000000, 0x100000000, 42, -(2**53+2), -0x080000000, 0x080000001, 0.000000000000001, -Number.MIN_VALUE, -1/0, -(2**53), 0/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, -0x0ffffffff, 0x07fffffff, 0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-71289653*/count=1477; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-(2**53), -1/0, -0x07fffffff, 2**53, 1, 0x07fffffff, 2**53-2, 0x080000000, 42, 0x100000001, 0/0, Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, Math.PI, 0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 2**53+2, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x080000000, 0x100000000, 1/0, -(2**53+2), -0, 0, -(2**53-2), 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-71289653*/count=1478; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.fround((Math.fround(mathy0(( + (Math.fround((x << x)) * Math.clz32(( + ((((x | 0) ^ (y >>> 0)) >>> 0) / x))))), ( + 0.000000000000001))) * Math.fround((Math.log1p(Math.round(( + x))) | Math.fround((Math.fround(((x >>> 0) < Math.sign(x))) ? (x << (y >>> 0)) : Math.fround((((-Number.MIN_VALUE >>> 0) << x) >>> 0)))))))), ( ! Math.min(Math.fround(Math.fround(Math.sqrt(Math.fround(( ! ( - x)))))), (Math.hypot(( + Math.fround(mathy0(0x100000000, Math.fround(-(2**53))))), -(2**53-2)) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=1479; tryItOut("v2 = (o0 instanceof this.g2.i1);");
/*fuzzSeed-71289653*/count=1480; tryItOut("mathy1 = (function(x, y) { return Math.expm1((Math.imul(((( ~ ( - y)) == Math.cosh(y)) | 0), ((((Math.abs(y) | 0) + (y | 0)) | 0) | 0)) | 0)); }); testMathyFunction(mathy1, [0x0ffffffff, -Number.MIN_VALUE, -0x100000000, 2**53, Number.MIN_SAFE_INTEGER, 2**53-2, 1, Number.MIN_VALUE, 1.7976931348623157e308, -1/0, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), 0x080000001, -Number.MAX_VALUE, 1/0, 0, -(2**53), 2**53+2, 0x080000000, 42, -0x07fffffff, -0x080000001, 0.000000000000001, -0x0ffffffff, Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -0, -(2**53+2), -0x100000001, 0x100000001, 0/0]); ");
/*fuzzSeed-71289653*/count=1481; tryItOut("mathy4 = (function(x, y) { return ( + Math.min((Math.imul(Math.fround(( ~ 0x100000001)), (Math.pow(x, x) | 0)) | 0), ( - ( ! y)))); }); testMathyFunction(mathy4, [-(2**53+2), -Number.MAX_VALUE, -(2**53-2), 0x07fffffff, 2**53-2, 2**53+2, 0/0, -0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -0x100000001, Number.MAX_VALUE, 0x100000000, 0x080000000, 0.000000000000001, 42, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, Math.PI, -0x080000001, -0x07fffffff, 0x080000001, 2**53, Number.MIN_SAFE_INTEGER, 1/0, 1, -1/0, -0x080000000, Number.MIN_VALUE, 0]); ");
/*fuzzSeed-71289653*/count=1482; tryItOut("\"use strict\"; const x;for (var p in h2) { try { e0.delete(h0); } catch(e0) { } try { this.v1 = evaluate(\"function f0(g1.p0)  { \\\"use strict\\\"; return arguments } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 32 != 6) })); } catch(e1) { } const a1 = Array.prototype.slice.call(a1, NaN, NaN, b1, a0, o1.i0); }");
/*fuzzSeed-71289653*/count=1483; tryItOut("\"use strict\"; /*RXUB*/var r =  ''  > x; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1484; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.ceil((Math.log10(((Math.tan(-0) | x) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [(new Number(-0)), objectEmulatingUndefined(), (function(){return 0;}), (new Boolean(true)), [0], 1, NaN, null, false, [], '', 0.1, (new Boolean(false)), /0/, -0, ({valueOf:function(){return '0';}}), (new Number(0)), '/0/', ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new String('')), true, '\\0', undefined, '0', 0]); ");
/*fuzzSeed-71289653*/count=1485; tryItOut("mathy3 = (function(x, y) { return Math.sqrt(( + Math.max(Math.hypot(Math.fround(( + Math.atan2(( + ( + ( + -(2**53)))), Math.fround(mathy2(x, x))))), ( + x)), ( - y)))); }); testMathyFunction(mathy3, [1.7976931348623157e308, -0x0ffffffff, -(2**53), 42, Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, 2**53-2, 0x07fffffff, -0x080000001, -(2**53+2), -1/0, Math.PI, 0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, 0x080000000, 0.000000000000001, -0, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, -(2**53-2), 0x100000000, Number.MIN_VALUE, -0x07fffffff, 0x100000001, 0/0]); ");
/*fuzzSeed-71289653*/count=1486; tryItOut("\"use strict\"; (w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: encodeURIComponent, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })((void options('strict_mode'))), function shapeyConstructor(bhxjfb){\"use asm\"; bhxjfb[\"getPrototypeOf\"] = x;{ (15);\nthis;\n } for (var ytqnwddtz in bhxjfb) { }delete bhxjfb[\"constructor\"];bhxjfb[\"min\"] = (bhxjfb = arguments);{ with({a:  \"\" }){([,,z1]);selectforgc(o0); } } { o2 + e2;yield; } Object.freeze(bhxjfb);Object.preventExtensions(bhxjfb);if (bhxjfb) Object.preventExtensions(bhxjfb);return bhxjfb; }, Math.cosh));");
/*fuzzSeed-71289653*/count=1487; tryItOut("e1 + p1;");
/*fuzzSeed-71289653*/count=1488; tryItOut("testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, 0, 0x100000000, -Number.MAX_VALUE, -0, -0x100000001, 42, Number.MIN_VALUE, 0x0ffffffff, -0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, 0/0, 1, 2**53, 1/0, 2**53-2, -0x080000000, -(2**53+2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 2**53+2, -(2**53), -0x07fffffff, 0x07fffffff, 0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=1489; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.fround(( - (((( + y) + (Math.log10((mathy0(( + Math.fround((Math.atan2(y, x) + 0x0ffffffff))), x) >>> 0)) | 0)) >>> 0) >>> 0))) ? ( + Math.hypot(( + ( - ( + Math.atan2(( + (Math.max(y, 0x07fffffff) & Math.fround(y))), y)))), (y !== Math.fround(x)))) : Math.fround(( + (( + Math.expm1(( + mathy0(Math.fround((x ? y : Math.fround(( + ( ! ( + x)))))), ((((y && y) >>> 0) >>> 0) === (y >>> 0)))))) == ( + Math.fround(mathy0(-(2**53+2), Math.fround(x)))))))); }); testMathyFunction(mathy1, [1.7976931348623157e308, -0x07fffffff, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 0.000000000000001, -0x080000001, -0x100000000, 2**53+2, 0, 0/0, Number.MAX_VALUE, 1, 0x100000000, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 1/0, -Number.MIN_VALUE, -(2**53-2), -(2**53), -0x080000000, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -(2**53+2), 0x080000001, 0x0ffffffff, 0x080000000, 0x100000001, -0, 42]); ");
/*fuzzSeed-71289653*/count=1490; tryItOut("m1.has(e2);");
/*fuzzSeed-71289653*/count=1491; tryItOut("v2 = evaluate(\"function f0(h0) x , window\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-71289653*/count=1492; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0x07fffffff, -1/0, 2**53, -0x0ffffffff, -0x07fffffff, -0x100000001, Number.MAX_VALUE, 0.000000000000001, Math.PI, 0/0, 42, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, 0x080000001, Number.MIN_VALUE, 0, -(2**53), 1, 2**53+2, 2**53-2, -(2**53-2), 1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, -0x080000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -0x080000001, 0x080000000]); ");
/*fuzzSeed-71289653*/count=1493; tryItOut("testMathyFunction(mathy0, [0, 0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, -1/0, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, 0x080000001, -(2**53), -(2**53-2), 2**53+2, -0x100000000, 2**53-2, -0x07fffffff, 1.7976931348623157e308, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, -(2**53+2), 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, 42, -Number.MAX_VALUE, -0x100000001, -0, Math.PI, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1, 2**53, -0x080000001]); ");
/*fuzzSeed-71289653*/count=1494; tryItOut("\"use strict\"; a0.shift();");
/*fuzzSeed-71289653*/count=1495; tryItOut("e0.add(f2);");
/*fuzzSeed-71289653*/count=1496; tryItOut("\"use strict\"; let (iiqnov) { var klisqw = new ArrayBuffer(2); var klisqw_0 = new Float32Array(klisqw); print(klisqw_0[0]); klisqw_0[0] = 16; var klisqw_1 = new Uint8ClampedArray(klisqw); klisqw_1[0] = 15; o0.m1 = new WeakMap; }");
/*fuzzSeed-71289653*/count=1497; tryItOut("\"use strict\"; t1[v1] = \"\\uFADB\".valueOf(\"number\");");
/*fuzzSeed-71289653*/count=1498; tryItOut("/*tLoop*/for (let y of /*MARR*/[({x:3}), Infinity, Infinity, 1e81, 1e81, Infinity, 1e81, new Number(1.5), ({x:3}), 1e81, 1e81, 1e81, new Number(1.5), new Number(1.5), new Number(1.5), Infinity, Infinity, 1e81, x, 1e81, Infinity, ({x:3}), Infinity, x, x, x, x, x, x, x, x, x, x]) { m1 + t0; }");
/*fuzzSeed-71289653*/count=1499; tryItOut("\"use strict\"; a0.push(o2.p2, b0, (( '' .yoyo(true)))(new Set(), (DataView(undefined))));");
/*fuzzSeed-71289653*/count=1500; tryItOut("Array.prototype.push.call(a0, this.p0, f2, h2);\n;\n");
/*fuzzSeed-71289653*/count=1501; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow((((Math.pow((x ? ( + x) : /(?=.|[^]|\\B|\ud687)[]{2,}/gyim), (y * x)) === Math.fround((Math.acosh(((y ? y : (y | 0)) | 0)) | 0))) | 0) ? ( ~ (Math.imul(x, Math.trunc(Number.MAX_SAFE_INTEGER)) >>> 0)) : (Math.hypot(((x , Math.fround(( ! Math.fround(y)))) | 0), (Math.imul(-0x07fffffff, ( + -0)) | 0)) | 0)), (Math.imul(( + Math.log1p((( + y) / ( + y)))), (x ? ( - (x | 0)) : y)) >>> 0)); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, Number.MAX_VALUE, -0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, -0x080000000, -0x0ffffffff, 2**53+2, 0/0, -(2**53-2), 1/0, -0, 0.000000000000001, 42, 0x100000000, 0x0ffffffff, -1/0, 0x07fffffff, 0, 0x080000000, -(2**53), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000000, 2**53, -0x100000001, 1, 2**53-2, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1502; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(( - Math.atan2(( ! (x & y)), ((y | 0) > y))), (( ! (Math.min((x | 0), ((((Math.imul(x, y) >>> 0) >>> 0) != (Number.MIN_SAFE_INTEGER | 0)) >>> 0)) | 0)) ? ( + Math.fround((Math.max(( + y), -1/0) & Math.fround(( + Math.trunc(( + Math.cosh(y)))))))) : (mathy0((Math.max(Math.pow((x | 0), (((42 >>> 0) >> x) | 0)), y) | 0), (Math.fround(( ! 0x080000001)) | 0)) | 0))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x100000001, -(2**53), 42, 2**53-2, 0x080000000, -0x0ffffffff, -0x080000001, -0x080000000, 0.000000000000001, -0, 0, 0/0, -1/0, 1.7976931348623157e308, -0x07fffffff, -(2**53+2), 2**53+2, Number.MIN_VALUE, 2**53, 0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, 1, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=1503; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?!(^*|\\\\W))\\\\S*?(?:\\\\b)\\\\B+)\", \"y\"); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1504; tryItOut("\"use strict\"; ;");
/*fuzzSeed-71289653*/count=1505; tryItOut("\"use strict\"; L:switch(Math.cosh(Int32Array()) ^= (new (let (iclztc) -11)).watch(\"apply\", (1 for (x in [])))) { default: h2 = {};break;  }");
/*fuzzSeed-71289653*/count=1506; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use asm\"; return Math.pow((Math.max(((Math.round((((((Math.max((y | 0), (x | 0)) | 0) >>> 0) | (x >>> 0)) >>> 0) >>> 0)) >>> 0) >>> ( + Math.cosh(Math.pow((Math.pow(y, x) | 0), x)))), ((y ? Number.MIN_VALUE : x) ? (( ~ (y >>> 0)) >>> 0) : y)) | 0), Math.hypot(( + Math.log1p(( + (Math.sin((0x0ffffffff >>> 0)) >>> 0)))), Math.imul(Math.sin(x), (( ! Math.fround(y)) >>> 0)))); }); ");
/*fuzzSeed-71289653*/count=1507; tryItOut("var kokphi = new ArrayBuffer(16); var kokphi_0 = new Uint8ClampedArray(kokphi); var kokphi_1 = new Uint8ClampedArray(kokphi); kokphi_1[0] = -864094851; var kokphi_2 = new Int8Array(kokphi); kokphi_2[0] = -4; var kokphi_3 = new Uint8ClampedArray(kokphi); kokphi_3[0] = 0; var kokphi_4 = new Uint32Array(kokphi); print(kokphi_4[0]); var kokphi_5 = new Float64Array(kokphi); print(kokphi_5[0]); kokphi_5[0] = -27; var kokphi_6 = new Int32Array(kokphi); kokphi_6[0] = -28; t1[7];/*tLoop*/for (let e of /*MARR*/[new String(''), function(){}, {x:3}, function(){}, new String(''), new String(''),  /x/ ,  /x/ , {x:3},  /x/ ,  /x/ , {x:3},  /x/ , new String(''), function(){}, {x:3}, function(){}, new String(''),  /x/ , function(){},  /x/ , function(){}, {x:3},  /x/ , {x:3},  /x/ ,  /x/ , {x:3}, new String(''),  /x/ ,  /x/ , {x:3}, function(){},  /x/ ,  /x/ ,  /x/ , {x:3}, function(){},  /x/ , {x:3},  /x/ , {x:3},  /x/ , function(){},  /x/ , function(){}, function(){}]) { g0.s1 += this.s1; }{ void 0; try { startgc(8253); } catch(e) { } } print(kokphi_1[0]);yield (Math.imul(-28, 18)).__defineSetter__(\"kokphi_6[0]\", (new Function(\"a2.sort((function() { v0.toSource = (function(stdlib, foreign, heap){ \\\"use asm\\\";   function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    i0 = (i0);\\n    return ((((~~(((d1)) - ((-268435456.0)))))+(i0)))|0;\\n    return ((0x5cb70*(i0)))|0;\\n  }\\n  return f; }); return o2; }), undefined);\")));g1.s0 += 'x';");
/*fuzzSeed-71289653*/count=1508; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1509; tryItOut("for(let d in []);");
/*fuzzSeed-71289653*/count=1510; tryItOut("a2.unshift(this.o0.b2);");
/*fuzzSeed-71289653*/count=1511; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(((((Math.fround(Math.imul(x, (y >>> 0))) | 0) == (((x | 0) >>> 0) ? ((Math.sin(y) | 0) >>> 0) : 0/0)) ? Math.log10(Math.fround(( + (Math.tanh((Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))) : (Math.pow((Math.asin(y) | 0), x) | 0)) ? Math.fround(Math.ceil((Math.sinh(( + ( - ( + ( - 2**53))))) | 0))) : ( + Math.imul(y, Math.fround(( ! (( - x) >>> 0))))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -(2**53), 1, -Number.MIN_SAFE_INTEGER, 42, 0, -0x100000001, -(2**53+2), 0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -0x080000001, 2**53, -(2**53-2), 0x07fffffff, 0x0ffffffff, -0, Math.PI, 2**53-2, 0x080000001, 0x100000001, 0/0, 0x080000000, -0x080000000]); ");
/*fuzzSeed-71289653*/count=1512; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.pow(( ! Math.log10(( + (( - (x !== ( + Number.MIN_SAFE_INTEGER))) ^ Math.pow((Math.atan2(( + (Math.sinh((y | 0)) | 0)), ( + x)) | 0), ( + ( + (( ! (0x080000001 >>> 0)) >>> 0)))))))), (Math.atan2((Math.fround(( + Math.sin(x))) + Math.fround((( ! (( + (( + x) ** Math.fround(y))) >>> 0)) | 0))), ((( ! x) & Math.fround(-(2**53))) | 0)) | 0)); }); testMathyFunction(mathy0, [-1/0, 0x0ffffffff, 0x080000000, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, 0/0, 0x080000001, 1, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), 2**53+2, -(2**53+2), Math.PI, 0x100000000, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -0x100000001, 2**53, -0x0ffffffff, 2**53-2, 0, -(2**53), 0.000000000000001, -0x100000000, Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1513; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.imul(( + (Math.atan2((x ? (( ~ y) >>> 0) : ( + y)), Math.pow((0x100000000 | 0), ( ! ( - 0)))) >> ( + ( + (( + 0x080000000) >>> ( + Math.sinh(y))))))), (Math.sin((Math.max(Math.fround(Math.hypot(-Number.MAX_VALUE, ((( ~ x) >>> 0) >>> 0))), Math.cbrt(( ! Math.fround(Math.atan2(Math.fround(y), ( - (y >>> 0))))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, /*MARR*/[new Number(1), (uneval(({\"68719476737\":  /x/g  }))), (uneval(({\"68719476737\":  /x/g  }))), (uneval(({\"68719476737\":  /x/g  }))), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-71289653*/count=1514; tryItOut("for(b in (((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; }))(/*UUV1*/(c.forEach = DataView.prototype.getInt32) ? (4277) : (/*FARR*/[null, , ({a2:z2}), true, , NaN, 20, , /((?!\\b?\\b){65,})/gym, null, ...[]])))){/*UUV1*/(x.setUint32 = (new Function(\"switch(a) { case undefined: return;break;  }\")));a2.reverse(); }");
/*fuzzSeed-71289653*/count=1515; tryItOut("mathy1 = (function(x, y) { return ( ! Math.fround(mathy0(Math.fround((( + Math.fround(( ~ Math.fround(x)))) & y)), Math.fround((((Math.tan((( + ( ! ( + y))) >>> 0)) >>> 0) === (Math.pow(y, Math.sinh((Number.MIN_VALUE + y))) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-71289653*/count=1516; tryItOut("\"use strict\"; v0 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (e++), catchTermination: false }));");
/*fuzzSeed-71289653*/count=1517; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.cos((( ! (((Math.log2(2**53+2) | 0) / Math.min(Math.atan2(( + y), y), Math.fround(mathy3(x, (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Int16ArrayView[2]) = ((-0x8000000));\n    {\n      d0 = (d0);\n    }\n    (Int32ArrayView[((i1)+((0x7d26498))-((-2097153.0) == (8589934593.0))) >> 2]) = (((4277))-(0xfe53d845)-(-0x8000000));\n    return (((0xffffffff)*0xfffff))|0;\n  }\n  return f; })(this, {ff: Uint32Array}, new ArrayBuffer(4096)))))) | 0)) >>> 0))); }); ");
/*fuzzSeed-71289653*/count=1518; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(( ! Math.fround(( + Math.atan2((Math.max(y, (Math.asinh(Math.fround(x)) | 0)) | 0), (((( + ( + ( ~ 0x080000000))) === (Math.fround(x) | 0)) | 0) | 0)))))); }); testMathyFunction(mathy0, [2**53-2, Number.MAX_SAFE_INTEGER, 0x080000000, 1, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0, 0x100000001, -0x080000001, 0.000000000000001, Number.MIN_VALUE, 0x100000000, 0x0ffffffff, 2**53, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, 0/0, 1.7976931348623157e308, 0x080000001, Math.PI, -0x100000000, -Number.MIN_VALUE, 42, -0, -Number.MAX_VALUE, -(2**53+2), -1/0, -(2**53), 0x07fffffff, -0x07fffffff, 1/0]); ");
/*fuzzSeed-71289653*/count=1519; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(s.replace(r, 'x', \"gy\")); \ne0.has(p2);\n");
/*fuzzSeed-71289653*/count=1520; tryItOut("\"use strict\"; with({}) let(x, x, eval = x, dtbbzl, x =  /x/g , eval, x, gnyvhn, wdtije, rdwyip) ((function(){x = x;})());");
/*fuzzSeed-71289653*/count=1521; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1522; tryItOut("");
/*fuzzSeed-71289653*/count=1523; tryItOut("let (d, e = Math.max(29, (4277)), c = x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: \"\\u29BF\", getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: undefined, }; })( /x/ ), ({})), w, x = Math, c = (mathy4), x =  /x/ ) { v1 = t0.byteLength; }");
/*fuzzSeed-71289653*/count=1524; tryItOut("\"use strict\"; /*MXX1*/o1 = g2.String.prototype.strike;v2 = g1.runOffThreadScript();");
/*fuzzSeed-71289653*/count=1525; tryItOut("\"use strict\"; i1 = new Iterator(v2);");
/*fuzzSeed-71289653*/count=1526; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return ( ! Math.exp(Math.fround(Math.min((y >>> 0), y)))); }); testMathyFunction(mathy4, [-(2**53), 1, -(2**53-2), -0x100000000, -0x07fffffff, 42, 0, 0.000000000000001, 0x07fffffff, -1/0, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, 0x100000001, Math.PI, 2**53, -0x080000000, -0x0ffffffff, 0x080000000, 2**53-2, -0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, 0/0, -0x080000001]); ");
/*fuzzSeed-71289653*/count=1527; tryItOut("m0.set(f2, o1.g0.f2);");
/*fuzzSeed-71289653*/count=1528; tryItOut("Array.prototype.splice.call(a2, NaN, 15);\n/(?:\\2{2,2}(?:([^]|.*){4}))/gyi = a1[v0];function b(e) { yield; } (function ([y]) { });\n");
/*fuzzSeed-71289653*/count=1529; tryItOut("mathy4 = (function(x, y) { return (Math.atan(Math.fround(( + ( ! Math.fround(mathy0((x >>> 0), ((((x + y) | 0) ? mathy3(y, y) : (y | 0)) | 0))))))) || (Math.acosh(Math.fround((( ! ((x != Math.sinh((-(2**53+2) ** (Math.acosh((y >>> 0)) >>> 0)))) >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy4, [null, (new String('')), 0.1, ({valueOf:function(){return '0';}}), 1, undefined, -0, (new Boolean(true)), objectEmulatingUndefined(), false, (new Number(-0)), NaN, true, '\\0', ({valueOf:function(){return 0;}}), [0], ({toString:function(){return '0';}}), '', (new Number(0)), (new Boolean(false)), '0', [], '/0/', (function(){return 0;}), /0/, 0]); ");
/*fuzzSeed-71289653*/count=1530; tryItOut("t1.toSource = (function() { try { g1.offThreadCompileScript(\"t1 = new Float32Array(b0, 28, 9);\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 6 != 1), sourceIsLazy: false, catchTermination: true })); } catch(e0) { } t1[({valueOf: function() { return /(?:\\u00F1\\w{2,})/gm;d = x;\n/*RXUB*/var r = /(?=[\uef68-\\cM\\S]{0,1}(?=(?!^+))+|\\1?(?=[^](\\w)|$|(?![\\xdb\\s\\u002D-\\u00C6\\w])^)*?)/gy; var s = (4277); print(r.exec(s)); \nreturn 19; }})] = ({x: true}); return i2; });");
/*fuzzSeed-71289653*/count=1531; tryItOut("testMathyFunction(mathy2, /*MARR*/[new Number(1.5), new Number(1), true, new Number(1.5), new Number(1.5), true, new Number(1), new Number(1.5), new Number(1), true, new Number(1), new Number(1), new Number(1), true, new Number(1), true, new Number(1), new Number(1), new Number(1), new Number(1)]); ");
/*fuzzSeed-71289653*/count=1532; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((((i1)+(i0)) & (((((0xcef89dce)-(0xfc62e17e)) ^ ((i1))) > (((0x4731649a)+(0xadb6889)) & (delete b.x)))+((0xc942320c)))) % (0x7e529294)))|0;\n  }\n  return f; })(this, {ff: (Int8Array).bind(w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(){}, getOwnPropertyNames: mathy3, delete: function(name) { return delete x[name]; }, fix: function() { return []; }, has: function (x, b, x, x, a, b = /\\b/y, d, \u3056, window, c, x, x, set, -2771748619, c =  /x/ , x, x, \u3056, case  '' : s2 += s0;break; , eval, eval = true, eval, window = null, \u3056, c, b, b, eval, eval, c, this.x, x, x, x =  /x/ , x, x, eval)\"use asm\";   var Infinity = stdlib.Infinity;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 4503599627370497.0;\n    return +((Infinity));\n    {\n      i0 = (0xf34c9f7d);\n    }\n    i1 = (i1);\n    return +((d2));\n  }\n  return f;, hasOwn: objectEmulatingUndefined, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: /*wrap2*/(function(){ \"use strict\"; var krbjkr =  '' ; var jfggjq = String.prototype.startsWith; return jfggjq;})(), enumerate: (new Function(\"print( '' );\")), keys: function() { return Object.keys(x); }, }; })(\"\\u3425\"), (mathy4).call, neuter))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53+2), -0x07fffffff, 1.7976931348623157e308, 1, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, Number.MAX_VALUE, 1/0, 42, -(2**53-2), 0, 0x080000001, -0x080000001, -0, 2**53+2, 0x0ffffffff, -0x100000000, -1/0, -Number.MAX_VALUE, -0x100000001, 0x080000000, -0x080000000, 0x100000001, 0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, 0.000000000000001, Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1533; tryItOut("mathy1 = (function(x, y) { return Math.pow(((Math.imul((y ? Number.MAX_VALUE : Math.fround(Math.hypot(Math.fround(x), Math.fround(( + Math.log1p((Math.sqrt(1.7976931348623157e308) >>> 0))))))), (Math.min((Math.clz32((Math.log2(-0x07fffffff) >>> 0)) >>> 0), (x === ( + ( + (Math.fround(y) << Math.log2(x)))))) >>> 0)) >>> 0) >>> 0), (( + ((x !== Math.fround(( - Math.fround(y)))) | ( ~ Math.fround(Math.min(Math.fround(x), Math.fround(y)))))) << (Math.clz32((( + (Math.ceil((( - (( - x) | 0)) | 0)) & ( + Math.sqrt(0.000000000000001)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [0x0ffffffff, 0, -1/0, -0x080000001, 1.7976931348623157e308, 2**53, -Number.MIN_VALUE, 0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, -Number.MAX_VALUE, 1/0, 0x07fffffff, 0.000000000000001, 0x080000001, 2**53-2, -(2**53+2), -0x100000001, Number.MIN_VALUE, 1, 42, 2**53+2, -0, -(2**53-2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53), Math.PI]); ");
/*fuzzSeed-71289653*/count=1534; tryItOut("\"use strict\"; var sxohlf = new ArrayBuffer(6); var sxohlf_0 = new Uint16Array(sxohlf); sxohlf_0[0] = -24; var sxohlf_1 = new Int32Array(sxohlf); print(sxohlf_1[0]); var sxohlf_2 = new Uint16Array(sxohlf); print(sxohlf_2[0]); var sxohlf_3 = new Uint8Array(sxohlf); var sxohlf_4 = new Int32Array(sxohlf); sxohlf_4[0] = -0; var sxohlf_5 = new Float32Array(sxohlf); var sxohlf_6 = new Float32Array(sxohlf); a1.push(g2, [/*UUV2*/(eval.isSealed = eval.trunc).yoyo(function  sxohlf_6[5] (window, sxohlf_3[10], sxohlf_5, sxohlf_0[3], window, sxohlf_0, sxohlf_4[1], \u3056 = -0, a, sxohlf_2, sxohlf_3, window, window, z, sxohlf_1[7], w, w, x, /.|(?=.){536870913,}{2}|(?:(?=(.{4}))(?:\\b))/gm, w, sxohlf_1[0], z, a, eval, sxohlf_5[0], sxohlf_0[0] =  /x/g , window, e, e, sxohlf_1, sxohlf_4, e, b = window, x, b, sxohlf_6[5], sxohlf, sxohlf_5[7], delete, d = 16, z, yield, eval, b, y, eval = ({a1:1}), d, sxohlf_2, e, sxohlf_3[10], d, x, x, c, window, sxohlf_0 = true, b, \u3056, window, x, \u3056 = new RegExp(\"(?:.|\\\\3|\\\\2+?)|\\\\G+\", \"gi\"), sxohlf_6[5] =  '' , w, a = /\\2(?=\\3)|(?=(?=\\1)(?!(?:[^]){3,6})(?=.*))/i, sxohlf_2[4], \u3056, w, NaN, eval, y, sxohlf_1[0], sxohlf_4[0], sxohlf_0, sxohlf_4[1], sxohlf, window)//h\n { i2 = new Iterator(a2); } )]);");
/*fuzzSeed-71289653*/count=1535; tryItOut("a0.push(t1);");
/*fuzzSeed-71289653*/count=1536; tryItOut("mathy2 = (function(x, y) { return (((Math.asinh((mathy1(mathy1(x, Math.fround(( ~ -Number.MAX_SAFE_INTEGER))), -1/0) | 0)) | 0) & (Math.atanh(Math.pow(0x100000001, y)) | 0)) | 0); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, -Number.MIN_VALUE, 1, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, -0x080000001, Math.PI, 0x07fffffff, 1.7976931348623157e308, -(2**53-2), -0x100000001, -0x080000000, 1/0, -0x0ffffffff, 0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -0, Number.MIN_VALUE, -0x100000000, 0x080000000, 2**53, 42, 2**53-2, 0/0, -(2**53+2), -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1537; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.atan2((Math.log10((mathy0(((Math.ceil(Math.fround((Math.atan2(y, (y | 0)) | 0))) | 0) >>> 0), Math.fround((Math.tan(y) * (Math.max(Math.fround(x), Math.fround(((Number.MIN_VALUE >>> 0) % x))) >>> 0)))) >>> 0)) >>> 0), Math.sqrt((Math.trunc((Math.max(Math.sin(y), ( + Math.max(y, ( + y)))) | 0)) | 0))); }); ");
/*fuzzSeed-71289653*/count=1538; tryItOut("{h2.__proto__ = b0; }");
/*fuzzSeed-71289653*/count=1539; tryItOut("\"use strict\"; o1.m1.get(t1);");
/*fuzzSeed-71289653*/count=1540; tryItOut("\"use asm\"; yield;\n\n");
/*fuzzSeed-71289653*/count=1541; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.hypot((Math.abs(((Math.cosh(y) + (Math.asin(Math.fround(Math.log2(( + Math.PI)))) | 0)) >>> 0)) >>> 0), ((( ~ ((( + ( + (( + y) || ( + Math.imul(x, x))))) && Math.expm1(x)) >>> 0)) | 0) | 0)) >>> 0); }); ");
/*fuzzSeed-71289653*/count=1542; tryItOut("/*vLoop*/for (var xjxynx = 0; xjxynx < 74; ++xjxynx) { let b = xjxynx; v2.toSource = SharedArrayBuffer.prototype.slice; } ");
/*fuzzSeed-71289653*/count=1543; tryItOut("/*MXX2*/g1.EvalError = g0;");
/*fuzzSeed-71289653*/count=1544; tryItOut("/*infloop*/ for  each(c in 0) print(x);");
/*fuzzSeed-71289653*/count=1545; tryItOut("mathy4 = (function(x, y) { return ( - ( + ( ! Math.fround((Math.log1p(Math.fround(x)) >>> 0))))); }); testMathyFunction(mathy4, [-0x07fffffff, -0x0ffffffff, -1/0, 2**53-2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 1, 0x080000001, -0, -Number.MIN_SAFE_INTEGER, -0x080000001, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, 1/0, -0x080000000, 2**53, -(2**53-2), 0x07fffffff, -Number.MAX_VALUE, -0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, 0.000000000000001, 0x080000000, 0/0, 0x100000001, 2**53+2, -0x100000001, -Number.MIN_VALUE, 0x100000000, -(2**53+2), Math.PI]); ");
/*fuzzSeed-71289653*/count=1546; tryItOut("\"use strict\"; g1.m2.delete(this.t2);");
/*fuzzSeed-71289653*/count=1547; tryItOut("testMathyFunction(mathy5, [-0x0ffffffff, 0/0, 0x080000001, 0x0ffffffff, -0x080000001, Number.MIN_VALUE, 42, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -(2**53-2), 1, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), 2**53+2, 0x100000000, -0, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000000, -0x07fffffff, -Number.MAX_VALUE, 0x07fffffff, -1/0, 0, -0x100000000, 0x080000000, 0.000000000000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1548; tryItOut("(4277);");
/*fuzzSeed-71289653*/count=1549; tryItOut("o2.s1 += 'x';\nL:if(new RegExp(\"\\u4046|(?=.)\", \"gy\")) selectforgc(o0.o2);\n");
/*fuzzSeed-71289653*/count=1550; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-71289653*/count=1551; tryItOut("/*MXX2*/g0.String.prototype.startsWith = b1;");
/*fuzzSeed-71289653*/count=1552; tryItOut("\"use strict\"; \"use asm\"; m0.get(m0);");
/*fuzzSeed-71289653*/count=1553; tryItOut("\"use strict\"; o2.m0.set(o1.h0, a0);");
/*fuzzSeed-71289653*/count=1554; tryItOut("g2.t2 = new Int8Array(t2);");
/*fuzzSeed-71289653*/count=1555; tryItOut("\"use strict\"; a1.shift();");
/*fuzzSeed-71289653*/count=1556; tryItOut("\"use strict\"; o0 = Object.create((encodeURIComponent).bind((b))() || (new RegExp((arguments[\"from\"]) = (void options('strict')))));");
/*fuzzSeed-71289653*/count=1557; tryItOut("for (var v of g0.f2) { Array.prototype.sort.apply(a0, [(function(j) { if (j) { h1.defineProperty = new eval = Proxy.create(({/*TOODEEP*/})( /x/g ), -17)(); } else { try { M: for (d of (y)) {/*infloop*/M:for(b;  \"\" ; [,,]) {e1.has(b0); }g2.g0.e0.add(p2); } } catch(e0) { } try { v1 = g1.eval(\"print(x);\"); } catch(e1) { } try { a0.toSource = (function() { try { g2 = this.b2; } catch(e0) { } a1[1] = b0; return s0; }); } catch(e2) { } /*MXX2*/g2.Set.prototype = b2; } }), o2, v2, o0, s0, h2, m2]); }");
/*fuzzSeed-71289653*/count=1558; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x080000001, 2**53+2, -0x07fffffff, -0x080000000, 0, 0x0ffffffff, 0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, -(2**53-2), -Number.MAX_VALUE, 0.000000000000001, 42, Number.MIN_VALUE, 0x100000001, 0x100000000, 0/0, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, 1/0, -1/0, 0x080000001, Number.MAX_VALUE, -0x100000000, -(2**53), 1, 1.7976931348623157e308]); ");
/*fuzzSeed-71289653*/count=1559; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ! (Math.fround((( ~ ( ! x)) ^ (Math.ceil(Number.MAX_SAFE_INTEGER) | (((Math.acos(y) | 0) ^ Math.fround((Math.fround((x >>> x)) && (Math.PI >>> 0)))) >>> 0)))) >>> 0))); }); testMathyFunction(mathy4, [-0x080000001, Math.PI, 0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000000, 1/0, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, -1/0, -(2**53), -(2**53-2), 2**53+2, -0x0ffffffff, -0, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -0x100000001, -0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1, 1.7976931348623157e308, 42, 0x080000001, 0x080000000, Number.MIN_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, 0x100000001, -0x100000000]); ");
/*fuzzSeed-71289653*/count=1560; tryItOut("\"use strict\"; ((let (kymafi, natzrd, uhvhao, jnakwj, uyvhyy, x = let (a) window, kjwagi) (/*RXUE*//[]/y.exec(\"\\u0016\"))));");
/*fuzzSeed-71289653*/count=1561; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.atan(((Math.sin((mathy3(Math.fround((Math.pow((( + Math.tanh((x | 0))) >>> 0), (x >>> 0)) >>> 0)), Math.acos(( + (Math.min(y, Math.fround((Math.fround(x) ? Math.fround(y) : Math.fround(y)))) >>> 0)))) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy5, [0x080000000, 1, -(2**53-2), 2**53-2, -Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, -0, -Number.MAX_SAFE_INTEGER, 2**53, -1/0, -(2**53+2), Number.MAX_VALUE, 0, -0x100000000, 1/0, 2**53+2, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, 0x100000000, Number.MIN_VALUE, Math.PI, 42, -0x080000000, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, 0/0, 0x07fffffff, -(2**53)]); ");
/*fuzzSeed-71289653*/count=1562; tryItOut("s0 = '';");
/*fuzzSeed-71289653*/count=1563; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (i0);\n    }\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff:  \"\" }, new ArrayBuffer(4096)); ");
/*fuzzSeed-71289653*/count=1564; tryItOut("o0.v1 = (a0 instanceof v1);");
/*fuzzSeed-71289653*/count=1565; tryItOut("m1.has(o2);");
/*fuzzSeed-71289653*/count=1566; tryItOut("mathy2 = (function(x, y) { return ((Math.imul((( + ( + ( ! (((-0x07fffffff ? (Math.sqrt((x >>> 0)) | 0) : (-Number.MAX_SAFE_INTEGER | 0)) | 0) >>> 0)))) ^ ( + Math.acos(((Math.fround(y) && Math.fround(( + ( + ( + y))))) | 0)))), ( + ( ! y))) >>> 0) !== (Math.trunc(( ! (((Math.fround(Math.log10((( + ( ~ 0x0ffffffff)) >>> 0))) >>> 0) || (y >>> 0)) >>> 0))) >>> 0)); }); ");
/*fuzzSeed-71289653*/count=1567; tryItOut("/*RXUB*/var r = /(?!(?=\ua4a8*|\\3{2,})(?=\\cB{4,8}(?:\\3))(?!(?:^)(?=\\b)+?)|.*|.)+|\\xfD/gy; var s = \"\\u0019\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"_\\u0019\\u0019a_a\\n\\u2ff9\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\n\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1568; tryItOut("function f2(e0)  { return ((void version(185))).__defineGetter__(\"w\", /*UUV1*/(d.codePointAt = ((\u3056) = ((function factorial_tail(znlluz, zalhed) { ; if (znlluz == 0) { ; return zalhed; } ; return factorial_tail(znlluz - 1, zalhed * znlluz);  })(1, 1))))) } ");
/*fuzzSeed-71289653*/count=1569; tryItOut("\"use strict\"; Array.prototype.pop.call(a0);");
/*fuzzSeed-71289653*/count=1570; tryItOut("mathy1 = (function(x, y) { return ( - Math.max(( ! (Math.min(Math.atan2(((( + ((y >>> 0) << ( + -0))) >= (2**53 | 0)) | 0), (0.000000000000001 + (y | 0))), x) >>> 0)), Math.atan(x))); }); testMathyFunction(mathy1, [1, 0x100000000, 0.000000000000001, -Number.MIN_VALUE, -(2**53-2), 0x080000000, 0x080000001, -Number.MAX_VALUE, 2**53+2, 0x0ffffffff, -0x07fffffff, -0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, Math.PI, 2**53, 0x07fffffff, -0, 1.7976931348623157e308, -(2**53), Number.MIN_VALUE, -0x080000001, 0, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000001, -(2**53+2), Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, 1/0, 0/0]); ");
/*fuzzSeed-71289653*/count=1571; tryItOut("o1.o0.toString = g1.o1.f2;");
/*fuzzSeed-71289653*/count=1572; tryItOut("function f1(g0.s0)  { \"use strict\"; yield g0.s0 } ");
/*fuzzSeed-71289653*/count=1573; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-71289653*/count=1574; tryItOut("print(x);");
/*fuzzSeed-71289653*/count=1575; tryItOut("/*tLoop*/for (let x of /*MARR*/[ /x/g , null,  /x/g ,  /x/g , null, null,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , null, null, null, null, null, null, null, null, null, null, null, null,  /x/g ,  /x/g ,  /x/g , null,  /x/g ,  /x/g , null,  /x/g , null, null,  /x/g , null, null, null, null, null,  /x/g , null,  /x/g , null,  /x/g ,  /x/g , null,  /x/g , null, null,  /x/g ,  /x/g ,  /x/g ,  /x/g , null,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , null,  /x/g ,  /x/g ,  /x/g ,  /x/g , null, null, null, null, null, null, null,  /x/g , null, null, null, null,  /x/g ,  /x/g ,  /x/g , null, null,  /x/g ,  /x/g , null, null, null,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , null, null, null, null, null, null, null, null,  /x/g , null, null,  /x/g , null, null,  /x/g ,  /x/g , null,  /x/g ]) { g0.v0 = g1.g2.eval(\"/* no regression tests found */\"); }");
/*fuzzSeed-71289653*/count=1576; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(Math.max(Math.fround(Math.fround((Math.pow(Math.fround(( + Math.fround(x))), (Math.atan2(x, Math.trunc(x)) | 0)) , Math.fround((mathy2((Math.imul(( ~ x), x) | 0), (( + Math.max((Math.imul(x, y) >>> 0), ( + Math.fround((Math.fround((Math.cos(y) | 0)) % y))))) | 0)) | 0))))), Math.fround(Math.fround((( + Math.fround(( ! y))) === Math.fround(( + (Math.fround(( + Math.fround((( + x) & ( + y))))) ? Math.fround(Math.tanh((x >>> 0))) : Math.fround(( ~ y)))))))))); }); testMathyFunction(mathy4, [-0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, 0, Math.PI, Number.MAX_SAFE_INTEGER, -0, 0x080000000, Number.MAX_VALUE, 1, -(2**53+2), -0x100000001, 0/0, -0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 42, 2**53, -Number.MIN_VALUE, 2**53-2, 0x080000001, 0.000000000000001, 0x100000000, -(2**53-2), -1/0, -Number.MAX_VALUE, 1/0, 0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-71289653*/count=1577; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((mathy2(Math.asinh((x <= ( ~ ( ! y)))), ( + (( + ( ! ( + ( + y)))) / Math.fround(Math.cbrt(Math.fround(Math.abs(x))))))) | 0) ? mathy1((Math.cos(((x / x) >>> 0)) >>> 0), ( ! Math.fround(Math.acos((x | 0))))) : mathy2(( + (( + x) - ( + Math.pow((mathy2(Math.fround(mathy0(x, (( ~ y) | 0))), (( + (( + x) != ( + (x >= y)))) | 0)) | 0), (y | 0))))), ( ! (( ~ x) >>> 0)))); }); testMathyFunction(mathy3, [-0x07fffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53, -1/0, -(2**53), -0x080000000, 0x0ffffffff, -0x100000000, 0/0, Number.MAX_VALUE, 2**53+2, -0x0ffffffff, -0x100000001, Number.MIN_VALUE, -(2**53-2), -(2**53+2), 1, 42, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 0x100000000, 2**53-2, 0, -0x080000001, 0.000000000000001, 1/0, 0x080000000, 0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, 0x100000001]); ");
/*fuzzSeed-71289653*/count=1578; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((Float32ArrayView[2])))|0;\n    {\n      {\n        (Float64ArrayView[0]) = ((Float64ArrayView[2]));\n      }\n    }\n    d1 = (d1);\n    d0 = (((+((((d0)) % (((!((0x347a1113) < (0x72e9c69f))) ? (((-137438953472.0)) / ((3.8685626227668134e+25))) : (d1))))))) - ((Float64ArrayView[(0x78825*((d1) <= (d1))) >> 3])));\n    (Uint16ArrayView[0]) = ((((0xfc033e92)+(0xfbedb386))>>>((((+(0.0/0.0)) + (d1)) <= (((d0)) / ((d0))))-(-0x8000000))) / (((-0x8000000)-(0x2261293f))>>>((0xc0443add)+((-0x8000000))-(0xcaaf74f8))));\n    d0 = (NaN);\n    return ((((((0x50b9b242))+((0xd89166d3))) ^ ((0xf7e2bdc6))) / (((d1)))))|0;\n  }\n  return f; })(this, {ff: DataView.prototype.setUint8}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [2**53-2, -1/0, -0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, Math.PI, -(2**53+2), 0.000000000000001, 1.7976931348623157e308, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, -(2**53-2), 0x100000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, 1, 0x07fffffff, -0, -Number.MIN_VALUE, 0, Number.MIN_VALUE, -(2**53), 2**53, 0x100000001, -0x080000001, 42, 0/0]); ");
/*fuzzSeed-71289653*/count=1579; tryItOut("\"use strict\"; /*RXUB*/var r = ( \"\" \n); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-71289653*/count=1580; tryItOut("print(eval(\"/* no regression tests found */\"));");
/*fuzzSeed-71289653*/count=1581; tryItOut("\"use strict\"; o1 = new Object;print(x);");
/*fuzzSeed-71289653*/count=1582; tryItOut("\"use asm\"; (new RegExp(\"(?:.+?|\\ufa37|[^]|\\\\2)*?((\\u01c6|)|[\\\\u50E0\\\\L\\\\u006A-\\u00a9\\\\w]))*\", \"yim\"));");
/*fuzzSeed-71289653*/count=1583; tryItOut("L: /* no regression tests found */");
/*fuzzSeed-71289653*/count=1584; tryItOut("\"use strict\"; o1.toString = (function mcc_() { var mlzkyq = 0; return function() { ++mlzkyq; f1(/*ICCD*/mlzkyq % 3 == 2);};})();");
/*fuzzSeed-71289653*/count=1585; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy3(Math.fround(Math.log1p(Math.fround((( + y) + Math.imul(Math.PI, (Math.imul(x, x) | 0)))))), (Math.asinh((((y ? Math.hypot(Math.fround(x), ( + y)) : ( + Math.min(( + -0), ( + Number.MAX_VALUE)))) < ((Math.atan2((0x100000001 >>> 0), ((((0 >>> 0) ? ( + Math.acos(Math.fround(1))) : (y >>> 0)) >>> 0) >>> 0)) | 0) ? Math.fround((Math.asinh(Number.MIN_SAFE_INTEGER) , y)) : Math.fround(Math.fround(( ! (Math.fround(Math.fround(Math.min(y, x))) >>> y)))))) | 0)) | 0)); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, -(2**53), 0x080000000, -0x100000000, 0x080000001, 42, -0x080000001, 0x100000000, -1/0, -Number.MAX_VALUE, 0.000000000000001, 2**53+2, 1, 1/0, -(2**53+2), 0x0ffffffff, Math.PI, -(2**53-2), -0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 0x100000001, -0x080000000, -0x0ffffffff, -0, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1586; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[new Number(1.5), (0/0), (0/0), Number.MIN_VALUE, new Number(1), new Number(1), Number.MIN_VALUE, new Number(1.5), new Number(1.5), new Number(1), new Number(1), new Number(1), new Number(1), Number.MIN_VALUE, new Number(1.5), (0/0), new Number(1), (0/0), new Number(1.5), (0/0), new Number(1.5), (0/0), Number.MIN_VALUE, Number.MIN_VALUE, (0/0), new Number(1), new Number(1.5), new Number(1), (0/0), Number.MIN_VALUE, new Number(1), new Number(1.5), (0/0), Number.MIN_VALUE, new Number(1), new Number(1), new Number(1.5), (0/0), (0/0)]); ");
/*fuzzSeed-71289653*/count=1587; tryItOut("var eval, NaN = x, window = (window === x + (Number((((Int16Array).bind( '' , -23)).call(x, x, (x > c))), new RegExp(\"(?:(?!\\\\u0049|\\\\b)*?)(?:.{2})[\\\\t\\\\u00d2-\\u5f6b\\\\&](?:[^\\\\v])|(?:(?=\\\\b|\\\\0*|[\\\\w\\u4131\\\\d]*))\", \"g\")))), e = eval(\"/* no regression tests found */\", []) >>= (({ get x()undefined }));/*ADP-1*/Object.defineProperty(o0.a2, ({valueOf: function() { /* no regression tests found */return 0; }}), ({set: Date.prototype.setUTCMonth, enumerable: false}));");
/*fuzzSeed-71289653*/count=1588; tryItOut("mathy4 = (function(x, y) { return ((Math.log(( + Math.atanh(y))) >>> 0) >> (Math.pow(Math.fround(( + Math.log2(((( - (y | 0)) | 0) ? Math.atan2(x, (y >>> 0)) : ( + ( + (( + y) ** ( + ( ! y))))))))), Math.acos(y)) >>> 0)); }); ");
/*fuzzSeed-71289653*/count=1589; tryItOut("mathy0 = (function(x, y) { return ( + Math.sinh(( + ( + (( + ( + ( - (Math.fround((Math.sqrt(y) >= ( + mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.fround(( + ( ~ ( + (( - (y | 0)) , x))))), ( + (( ~ (((Math.fround((( + x) ** ( + x))) >>> 0) ** (Math.tan(Math.fround(Math.cos(Math.fround(x)))) >>> 0)) >>> 0)) % ( + ( + ((((0/0 >>> 0) != (x | 0)) >>> 0) ? 0x100000001 : x)))))); }); testMathyFunction(mathy1, /*MARR*/[(1/0), new Boolean(true), new Boolean(true)]); ))) | 0)))) ? ( + (x < Math.fround(mathy2 = (function(x, y) { return Math.round((( + Math.min(y, Math.min(x, ( - ( + (y / (y >>> 0))))))) <= (((Math.sinh((x | 0)) | 0) , (( + Math.hypot(( + (Math.log(x) * ((Math.atanh((2**53+2 | 0)) >>> 0) == Math.ceil(y)))), (-0x100000000 >>> 0))) | 0)) >>> 0))); }); testMathyFunction(mathy2, [(function(){return 0;}), (new String('')), undefined, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), 0, [], true, (new Boolean(false)), objectEmulatingUndefined(), (new Number(-0)), false, [0], 0.1, '', -0, (new Boolean(true)), '\\0', NaN, '0', ({toString:function(){return '0';}}), (new Number(0)), /0/, '/0/', null, 1]); ))) : ( + Math.log2(Math.min(Math.fround((y * x)), y)))))))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, 2**53-2, -0x100000001, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 1/0, 1, -Number.MIN_VALUE, -0, 0x080000000, 0x080000001, 2**53+2, -0x080000001, 1.7976931348623157e308, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, 0x100000001, 0x100000000, -0x100000000, -0x080000000, 2**53, -(2**53), -(2**53-2), Number.MIN_VALUE, 0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, 0.000000000000001, 0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1590; tryItOut("M:if(true) e2.has(g1.o2.i2); else  if (( \"\"  ^= {}\u0009)) {v0 = a0.length; } else g1.e0.delete( \"\" );");
/*fuzzSeed-71289653*/count=1591; tryItOut("p2 + e2;");
/*fuzzSeed-71289653*/count=1592; tryItOut("v2 = g0.runOffThreadScript();\nL: for (var b of x) print(h0);\n");
/*fuzzSeed-71289653*/count=1593; tryItOut("\"use strict\"; /*infloop*/M:while((({\"-16\": this,  get NaN eval (w, d = -35184372088831, x, x, eval, x, window, d, c, z, c, x, x, w =  /x/ , c, x, \u3056, x, e, x, x, w, x =  /x/ , c, of, x, x =  /x/g , c = undefined, w, x = window, w = [[1]], b, NaN, d, b, x, z, d = this, e, \u3056, z, x = undefined, a, x = null, x, this.d, e, a = [1,,], x, x, y = \"\\u0A91\", a, w, w = /(?:(?:(\\2))\\W[^]\\\u5702{4}|(?=\\1?){4})/yim, z, x, w, x, x, x, y, a, x, NaN = 23, d, x =  /x/ , x, b, ...d) { \"use strict\"; (/(?:[^])?/ym); } \u000c })))yield function ([y]) { };");
/*fuzzSeed-71289653*/count=1594; tryItOut("Array.prototype.push.call(o2.a0, p1);");
/*fuzzSeed-71289653*/count=1595; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - (((( + Math.atan2(( + (( + Math.atan2(y, y)) >= ( + x))), Math.fround(Math.sign(Math.fround(x))))) > (x >>> 0)) >>> 0) ? ( - (( + (( + ((0 ? (-1/0 | 0) : (y | 0)) | 0)) >>> 0)) >>> 0)) : ((y === Math.imul(y, x)) >>> 0))) >>> 0); }); testMathyFunction(mathy5, [-1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, 42, -0, -(2**53+2), -0x07fffffff, 0x07fffffff, 0x080000000, Number.MAX_VALUE, -0x080000001, -Number.MAX_VALUE, -(2**53), 0/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 0x100000001, Math.PI, 0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0, -0x100000000, 0.000000000000001, -0x080000000, -(2**53-2), 1, 0x080000001, Number.MIN_VALUE, 2**53+2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, 2**53]); ");
/*fuzzSeed-71289653*/count=1596; tryItOut("/*RXUB*/var r = new RegExp(\"(?!^|\\\\1){3,3}\", \"\"); var s = \")))\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=1597; tryItOut("mathy3 = (function(x, y) { return Math.ceil(( + (Math.exp(Math.atan2(y, ( + mathy0(y, y)))) >= ( ~ (mathy0(y, ( ~ ( + (y ^ x)))) >>> 0))))); }); testMathyFunction(mathy3, /*MARR*/[]); ");
/*fuzzSeed-71289653*/count=1598; tryItOut("\"use strict\"; /*oLoop*/for (vdawcl = 0; vdawcl < 39; ( /* Comment */x), ++vdawcl) { Array.prototype.shift.apply(a0, []); } ");
/*fuzzSeed-71289653*/count=1599; tryItOut("var gzwlhc = new SharedArrayBuffer(4); var gzwlhc_0 = new Int8Array(gzwlhc); gzwlhc_0[0] =  /x/ ; var gzwlhc_1 = new Int32Array(gzwlhc); gzwlhc_1[0] = -7; var d = \"\\uD535\";a1.pop();print(gzwlhc_0);(\"\u03a0\");");
/*fuzzSeed-71289653*/count=1600; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (i1);\n    switch ((((0xfdeb7ff2)+(0xf9bc592f)-(0x3cdf6d52)) | ((i1)))) {\n      case 1:\n        (Float64ArrayView[4096]) = ((/*UUV1*/(a.toString = Boolean)));\n        break;\n      case 0:\n        {\n          d0 = (((-16385.0)) * ((+abs(((((274877906944.0)) - ((-17.0))))))));\n        }\n        break;\n      case -2:\n        return (((0x5f927c16)-(i1)))|0;\n      case -1:\n        i1 = (0xf9986476);\n        break;\n    }\n    return (((((/*UUV2*/(NaN.toJSON = NaN.keys))>>>((0xf8d4f2f7)-((((0xc3f0eae))>>>(((0x5b3cb1dc))))))) > ((((~((0x9132607a)+(0x3b82096c)+(0xf8ee858b))))+((d0) < (d0)))>>>((0xff2867dc))))+((((0xf11e5770)+(/*FFI*/ff(((2097153.0)), ((abs((0x6d4d5153))|0)), ((-549755813889.0)))|0)+(0xee3f3da2)) >> ((i1)+((~((i1)+(0xa0e3f690)))))) > (((((0x1cd4507a) ? (0x14dd9b96) : (0xfeb2e6b3)) ? (0xffffffff) : (0x3c71f94f))+(-0x8000000)) | ((0x1dc2f675)+(!(!((0xffffffff) >= (0x0)))))))))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [undefined, (new Boolean(false)), '0', 0.1, [], '', ({valueOf:function(){return 0;}}), /0/, false, (new Number(0)), (new String('')), 0, [0], '\\0', ({valueOf:function(){return '0';}}), (new Boolean(true)), '/0/', null, objectEmulatingUndefined(), 1, ({toString:function(){return '0';}}), NaN, (function(){return 0;}), (new Number(-0)), -0, true]); ");
/*fuzzSeed-71289653*/count=1601; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, Math.PI, 0x0ffffffff, 2**53, 1, 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, 0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, -0, 0x080000000, -(2**53), -0x0ffffffff, Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, 1.7976931348623157e308, -1/0, 2**53-2, 0, -Number.MAX_VALUE, 0x100000001, -(2**53+2), 0/0, 0x080000001, -0x07fffffff]); ");
/*fuzzSeed-71289653*/count=1602; tryItOut("/*infloop*/M:for(let b =  /x/ ; null; \"\\uE51D\") {this.g2.offThreadCompileScript(\" '' \", ({ global: this.g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 23 == 0), sourceIsLazy: true, catchTermination: (x % 9 == 2), elementAttributeName: s1 }));t1 = m0.get(\"\\u1FBA\"); }");
/*fuzzSeed-71289653*/count=1603; tryItOut("h0.valueOf = (function(j) { if (j) { try { o2.o0.s2 = new String; } catch(e0) { } try { this.a2.forEach((function() { try { Array.prototype.sort.call(a1, v0); } catch(e0) { } try { m0.set(t2, b0); } catch(e1) { } delete h0.defineProperty; throw s1; }), t0, m0, t2); } catch(e1) { } o2.a0 = /*MARR*/[e =  /x/ , e =  /x/ , true, false, true, new String(''), false, new String(''), new String(''), arguments, new String(''), new String(''), arguments, false, new String(''), false, new String(''), false, e =  /x/ , arguments, e =  /x/ , true, true, arguments, new String(''), true, new String(''), new String(''), true, true, arguments, arguments, true, new String(''), true, new String('')]; } else { try { Object.prototype.unwatch.call(o0.g2, \"wrappedJSObject\"); } catch(e0) { } try { e2 = g0.t2[new  /x/g ().throw(/*UUV1*/(z.raw = Number.isSafeInteger))]; } catch(e1) { } /*RXUB*/var r = r2; var s = \"\"; print(r.exec(s));  } });");
/*fuzzSeed-71289653*/count=1604; tryItOut("\"use strict\"; v2 = evaluate(\"\\\"use strict\\\"; testMathyFunction(mathy3, [0x07fffffff, -Number.MAX_VALUE, 0, 1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), Number.MIN_VALUE, -0x0ffffffff, 0/0, -0x100000000, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -0x080000001, -1/0, 0x080000001, -(2**53-2), 0x080000000, 0.000000000000001, 0x100000000, 0x100000001, 42, 2**53+2, 2**53-2, -0x080000000, 2**53, 1.7976931348623157e308, 1, Number.MAX_VALUE, -Number.MIN_VALUE]); \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: window++, noScriptRval: ([14]).eval(\"this\"), sourceIsLazy: /*MARR*/[(1/0), (1/0), (1/0)].sort(Math.sin, -12), catchTermination: (x % 7 != 6) }));");
/*fuzzSeed-71289653*/count=1605; tryItOut("this.t1 = new Int8Array(Object.defineProperty(x, \"getMonth\", ({configurable: false, enumerable: a = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: Date.prototype.setUTCHours, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: /*wrap3*/(function(){ var askscd = []; (function(y) { yield \"\\uAA5C\"; })(); }), }; })(x), function shapeyConstructor(sauzqm){\"use strict\"; return this; }, Array.prototype.slice)})));");
/*fuzzSeed-71289653*/count=1606; tryItOut("mathy3 = (function(x, y) { return (( - (( + ((Math.fround(Math.cbrt(Math.fround(Math.max(y, y)))) >>> 0) & ( + Math.imul((Math.log(( ! ( - (-1/0 >>> 0)))) >>> 0), Math.abs((mathy2((y | 0), -0x100000000) | 0)))))) | 0)) | 0); }); testMathyFunction(mathy3, [0x080000000, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, -0, 2**53+2, -(2**53+2), -0x100000001, Math.PI, -1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 42, 2**53, -Number.MIN_VALUE, -0x07fffffff, 2**53-2, 0x100000000, -0x0ffffffff, -(2**53), 1.7976931348623157e308, 0x100000001, -Number.MAX_VALUE, -0x080000000, 0, 0x080000001, 0/0, 1/0, 0x0ffffffff, -0x080000001, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=1607; tryItOut("a0[g2.v0] = v1;");
/*fuzzSeed-71289653*/count=1608; tryItOut("23;");
/*fuzzSeed-71289653*/count=1609; tryItOut("\"use strict\"; e2.add(m1);");
/*fuzzSeed-71289653*/count=1610; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-71289653*/count=1611; tryItOut("print(o1);");
/*fuzzSeed-71289653*/count=1612; tryItOut("/*infloop*/ for (var c of new RegExp(\"(?!(?=[]){4,}(?=[^\\\\f][^]{4}(?:\\\\W)){2})\", \"m\")) {print(/(?=\u7541)/yi); }");
/*fuzzSeed-71289653*/count=1613; tryItOut("m0.set(o1.b0, g0.g2);");
/*fuzzSeed-71289653*/count=1614; tryItOut("\"use strict\"; { void 0; verifyprebarriers(); } v2 = evalcx(\"function f1(this.b2)  { return [] } \", g2);");
/*fuzzSeed-71289653*/count=1615; tryItOut("t0[7] = o2.t1;function eval(z = window, y) { yield \"\\u7C92\" } (this);(\"\\uAFFD\");");
/*fuzzSeed-71289653*/count=1616; tryItOut("a2[({valueOf: function() { a0.unshift(g1.m1);return 9; }})] = m0;");
/*fuzzSeed-71289653*/count=1617; tryItOut("mathy4 = (function(x, y) { return ( ! Math.atan2(Math.imul((Math.cbrt((( + (( + mathy2(( + y), ((1.7976931348623157e308 * (-Number.MAX_VALUE >>> 0)) >>> 0))) && (Math.trunc(( ~ y)) | 0))) | 0)) | 0), (0.000000000000001 == (Math.atanh((x | 0)) | 0))), ( ~ ((Math.fround(Math.asin(Math.fround(Math.atan2((y >>> 0), (y | 0))))) >>> Number.MAX_VALUE) >>> 0)))); }); testMathyFunction(mathy4, [-0x100000000, -0x0ffffffff, 2**53, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, -0x080000000, 1, 0.000000000000001, 0x080000001, -(2**53+2), -1/0, 1/0, -(2**53), Number.MAX_VALUE, -0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, 0, Number.MIN_VALUE, 2**53+2, 0x080000000, -Number.MIN_VALUE, 0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, 2**53-2, 0x100000000, -0x07fffffff, 42]); ");
/*fuzzSeed-71289653*/count=1618; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-Number.MIN_VALUE, 1/0, -(2**53+2), -0x080000001, -0x100000001, -(2**53), 0.000000000000001, -0, -0x080000000, 42, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 2**53+2, 0/0, 0, 0x080000000, 2**53-2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, 0x07fffffff, -0x07fffffff, 0x100000001, 0x080000001, Math.PI, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, -(2**53-2)]); ");
/*fuzzSeed-71289653*/count=1619; tryItOut("this.i2.send(f0);");
/*fuzzSeed-71289653*/count=1620; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x080000000, 0.000000000000001, -(2**53-2), Math.PI, 0x07fffffff, 1.7976931348623157e308, 2**53, 0x0ffffffff, 2**53+2, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, 1/0, Number.MAX_VALUE, -(2**53), 0x100000000, -0x0ffffffff, -0, 0x100000001, -0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 42, 0x080000000, -Number.MAX_VALUE, 1, -(2**53+2), 0, -0x100000001, 0x080000001, Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1621; tryItOut("do {this.a0[13];e1.add(o2.o0.e1); } while((x) && 0);");
/*fuzzSeed-71289653*/count=1622; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.atanh((( ~ ((Math.tan(Math.fround(( ! ( + 42)))) >>> 0) >>> 0)) === ((y >>> 0) >> (( + Math.pow(( + ( + -Number.MIN_SAFE_INTEGER)), ( + -0))) >>> 0)))); }); testMathyFunction(mathy1, [1/0, 0x100000000, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 0.000000000000001, 0x100000001, -0x07fffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, 2**53+2, 1, -0, Number.MIN_VALUE, -0x100000000, 0, Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 2**53-2, Math.PI, 0/0, -0x080000000, 42, 0x0ffffffff, 1.7976931348623157e308, -0x0ffffffff, -1/0, -0x100000001, -(2**53+2)]); ");
/*fuzzSeed-71289653*/count=1623; tryItOut("\"use strict\"; /*vLoop*/for (var xrozlz = 0, (x = (\u3056 = let (e = new RegExp(\"([^]((?!\\\\B|$){1,4})){0,}\", \"i\")) window)); xrozlz < 66; ++xrozlz) { let d = xrozlz; /*tLoop*/for (let x of /*MARR*/[d, new Number(1), new String('q'), d, d, new Number(1), new String('q'), new Number(1), d, new String('q'), new Number(1), x, x, new Number(1), new String('q'), d, new Number(1), new String('q'), new String('q'), d, new Number(1), new Number(1), new String('q'), new String('q'), new Number(1), d, new Number(1), x, new String('q'), x, d, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Number(1), new String('q'), x, x, new String('q'), d, d, x, d, x, new String('q'), x, x, d, d, d, new Number(1), new String('q'), new String('q'), new Number(1), x, new String('q'), new String('q'), d, new Number(1), new Number(1), new Number(1), new Number(1), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, d, new String('q'), new String('q'), new String('q'), new Number(1)]) { v1 = Object.prototype.isPrototypeOf.call(f0, a1); } } ");
/*fuzzSeed-71289653*/count=1624; tryItOut(";");
/*fuzzSeed-71289653*/count=1625; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((Math.round(mathy0(( + Math.pow(Number.MAX_VALUE, Math.fround((x << Math.fround(-0x100000001))))), (( + Math.asinh(( + ( + Math.max((Math.imul(x, ((0x07fffffff > y) >>> 0)) | 0), (-Number.MAX_SAFE_INTEGER | 0)))))) >>> 0))) | 0), ((( ~ Math.max(Math.fround(( ! Math.fround(Math.cos(y)))), ( + mathy0(Math.fround(y), Math.fround(-0x100000000))))) | 0) ? ( ! (Math.fround(Math.trunc(y)) && Math.clz32(( + x)))) : Math.min((Math.max((Math.atan2(-0x07fffffff, (x >>> 0)) >>> 0), (Math.fround(Math.cosh(x)) >>> 0)) >>> 0), Math.fround((Math.fround(y) != Math.fround(y)))))); }); testMathyFunction(mathy1, [0x100000001, 2**53+2, -1/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53), 1/0, 2**53-2, 0/0, 42, 0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x080000001, -(2**53-2), 0x0ffffffff, -0, -Number.MAX_VALUE, 0x080000001, 0x100000000, 2**53, Number.MAX_VALUE, 1, -(2**53+2), 0.000000000000001, 0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-71289653*/count=1626; tryItOut("mathy0 = (function(x, y) { return Math.atan2(( - (( - Math.min(y, ((Math.fround(x) || -Number.MIN_VALUE) | 0))) | 0)), Math.hypot((Math.fround(Math.imul(Math.fround(Math.abs(( + ( - Number.MIN_VALUE)))), Math.fround(x))) >>> 0), Math.cos((( ! (y ? Math.cos(Number.MIN_SAFE_INTEGER) : (y || -0x0ffffffff))) >>> 0)))); }); testMathyFunction(mathy0, [false, [], (function(){return 0;}), (new Number(0)), true, (new String('')), '0', ({valueOf:function(){return '0';}}), -0, 1, ({toString:function(){return '0';}}), null, undefined, 0.1, '\\0', /0/, 0, [0], (new Number(-0)), '', '/0/', NaN, (new Boolean(false)), ({valueOf:function(){return 0;}}), (new Boolean(true)), objectEmulatingUndefined()]); ");
/*fuzzSeed-71289653*/count=1627; tryItOut("Array.prototype.forEach.call(a1, (function(j) { if (j) { /*RXUB*/var r = r2; var s = s0; print(s.split(r));  } else { try { v2 = (b1 instanceof p0); } catch(e0) { } i1.send(m1); } }));");
/*fuzzSeed-71289653*/count=1628; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.acosh(( + ( ~ (((mathy2(((Math.log10((0x100000001 | 0)) | 0) >>> 0), (Math.cosh(0/0) >>> 0)) | 0) & (( + -1/0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [1.7976931348623157e308, -Number.MIN_VALUE, 0x0ffffffff, -0x100000000, 42, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 0/0, -0x080000000, -1/0, -(2**53), -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 0x07fffffff, 0x080000000, -0x07fffffff, 1/0, 2**53-2, 0x080000001, 2**53, 0, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 2**53+2, -0, 1]); ");
/*fuzzSeed-71289653*/count=1629; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(( ! (( + Math.log1p(y)) <= ( + y))))); }); testMathyFunction(mathy0, [Math.PI, Number.MIN_VALUE, 2**53+2, -0x080000001, -(2**53), -0x100000001, -0x0ffffffff, 0x100000001, -Number.MIN_VALUE, 42, -(2**53+2), 2**53, 0x080000000, 0, 0x100000000, Number.MAX_VALUE, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -0x080000000, -(2**53-2), 0x0ffffffff, 2**53-2, 0/0, 0x080000001, -0x100000000, 0.000000000000001, -1/0, 1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE]); ");
/*fuzzSeed-71289653*/count=1630; tryItOut("eval = linkedList(eval, 0);");
/*fuzzSeed-71289653*/count=1631; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - ( + ( - (((Math.min((( + y) | 0), Math.min(y, (Math.abs(( + x)) | 0))) >>> 0) <= ( ! Math.fround(x))) | 0)))); }); ");
/*fuzzSeed-71289653*/count=1632; tryItOut("(x);let(NaN, x, iuemgu) ((function(){this.zzz.zzz;})());");
/*fuzzSeed-71289653*/count=1633; tryItOut("/*tLoop*/for (let b of /*MARR*/[new String('q'), x, (-1), x, x,  'A' ,  'A' , (-1), (-1), x, new String('q'), (-1), (-1), x, new String('q'),  'A' , new String('q'), x, new String('q'), x,  'A' , (-1),  'A' ,  'A' , new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (-1), new String('q'), (-1),  'A' ,  'A' , new String('q'),  'A' , new String('q'), (-1), new String('q'),  'A' , (-1),  'A' , x, x, x, (-1), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'),  'A' , new String('q'),  'A' , (-1), new String('q'), new String('q'), (-1), new String('q'), new String('q'), (-1), x, new String('q'), new String('q'), x, (-1),  'A' , (-1), new String('q'),  'A' , new String('q'),  'A' , new String('q'),  'A' , (-1),  'A' , new String('q'), new String('q'), new String('q'), new String('q'),  'A' , (-1), new String('q'), (-1), new String('q'), (-1),  'A' ,  'A' ,  'A' ,  'A' ,  'A' , (-1), x,  'A' , (-1), new String('q'),  'A' ,  'A' , (-1), (-1),  'A' ,  'A' , new String('q'), x, x,  'A' ,  'A' ,  'A' , (-1),  'A' , x,  'A' , (-1),  'A' ,  'A' , x, x, new String('q'), x, x, new String('q'), (-1), new String('q'), new String('q'), x,  'A' ]) { ((timeout(1800))); }function x()xM:switch(z <<= new RegExp(\"\\\\1\", \"im\").yoyo(/(?=\\2)*/yi.throw(\"\\u67AA\"))) { default: break; break; -28;break;  }");
/*fuzzSeed-71289653*/count=1634; tryItOut("\"use strict\"; v0 = new Number(o1.h0);\n/*ODP-3*/Object.defineProperty(h0, \"__count__\", { configurable: (x % 2 != 0), enumerable: z, writable: true, value: t0 });\nfunction window() { print(yield x);\nArray.prototype.pop.apply(this.a0, []);\n } g2.h0 = Proxy.create(h0, o2.a2);");
/*fuzzSeed-71289653*/count=1635; tryItOut("s0 += 'x';");
/*fuzzSeed-71289653*/count=1636; tryItOut("\"use strict\"; v0 = a0.every((function mcc_() { var xoymub = 0; return function() { ++xoymub; if (/*ICCD*/xoymub % 8 == 6) { dumpln('hit!'); v0 = Object.prototype.isPrototypeOf.call(s0, b1); } else { dumpln('miss!'); try { v0 = g0.runOffThreadScript(); } catch(e0) { } try { m2.get(this.i1); } catch(e1) { } try { Object.defineProperty(this, \"this.v1\", { configurable: (x % 4 == 0), enumerable: false,  get: function() {  return g1.eval(\"/* no regression tests found */\"); } }); } catch(e2) { } m0.has(--x); } };})());");
/*fuzzSeed-71289653*/count=1637; tryItOut("/*RXUB*/var r = /(?=[^])+\\3+/gim; var s = \"\\uc941\\n\\n\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-71289653*/count=1638; tryItOut("a0.unshift(i1, f2);");
/*fuzzSeed-71289653*/count=1639; tryItOut("/*vLoop*/for (var hscleb = 0; hscleb < 19; ++hscleb) { var x = hscleb; print(uneval(o0)); } ");
/*fuzzSeed-71289653*/count=1640; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Number.MIN_VALUE, 42, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 0x080000000, -0, 2**53+2, -(2**53-2), 0.000000000000001, 2**53, -Number.MIN_VALUE, -0x080000000, 0x100000000, 0x080000001, 1, -1/0, 0, Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -0x100000000, -0x080000001, Math.PI, 0x0ffffffff, -Number.MAX_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-71289653*/count=1641; tryItOut("v2 = (f0 instanceof o0.h2);");
/*fuzzSeed-71289653*/count=1642; tryItOut("\"use strict\"; x.fileName;");
/*fuzzSeed-71289653*/count=1643; tryItOut("(x);");
/*fuzzSeed-71289653*/count=1644; tryItOut("v0 = Array.prototype.some.apply(this.a1, [(function() { for (var j=0;j<146;++j) { f2(j%5==0); } }), f0, g0.t1]);");
/*fuzzSeed-71289653*/count=1645; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -524289.0;\n    return (((0xba121d26)-(i0)))|0;\n  }\n  return f; })(this, {ff: ((uneval(\"\\u64A5\"))) **= /*UUV2*/(z.apply = z.isSealed)}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x100000001, 0.000000000000001, 0x080000001, 1.7976931348623157e308, 2**53-2, -0x080000001, -1/0, -0x07fffffff, 1/0, Math.PI, 1, -(2**53-2), 0x080000000, 0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, -0, -(2**53), Number.MIN_VALUE, 2**53+2, 2**53, 0/0, 0x07fffffff, 0, -Number.MAX_VALUE, -0x080000000, -0x100000001]); ");
/*fuzzSeed-71289653*/count=1646; tryItOut("testMathyFunction(mathy1, [-1/0, 0x100000000, 1.7976931348623157e308, 2**53-2, 42, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53), -0x080000001, 0, 0.000000000000001, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, 1, 0x07fffffff, -(2**53+2), 0/0, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -0x080000000, -0, 0x080000000, -0x100000000, 1/0, -0x100000001]); ");
/*fuzzSeed-71289653*/count=1647; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.pow(((Math.cbrt(( + (( + (Math.sqrt((y >>> 0)) >>> 0)) ? ( + Math.fround(((Math.log10(( + 0x100000001)) >>> 0) || Math.fround((Math.pow((x | 0), ((x >= Math.fround(y)) | 0)) | 0))))) : ( + Math.sqrt(0/0))))) << (Math.max((Math.fround(Math.max(Math.fround(Math.exp(x)), (y | 0))) >>> 0), (Math.fround(Math.atan2(Math.fround(x), Math.fround(Math.fround((Math.fround(-Number.MIN_VALUE) ? (x | 0) : Math.acosh(x)))))) >>> 0)) >>> 0)) >>> 0), ( + ( ~ (Math.min((( - (Math.atanh((Math.fround(Math.pow(Math.fround(x), Math.fround(-1/0))) >>> 0)) | 0)) >>> 0), (( ~ (Math.round(x) | 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy5, [Math.PI, 0, -(2**53+2), 2**53+2, 1.7976931348623157e308, 1/0, 0x080000000, -0x080000001, 0/0, 0x100000000, -0x100000001, -0x07fffffff, 0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, 42, 2**53, -0x080000000, -(2**53-2), -Number.MAX_VALUE, -(2**53), Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 2**53-2, -0, 0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-71289653*/count=1648; tryItOut("var esmxml = new SharedArrayBuffer(4); var esmxml_0 = new Uint8Array(esmxml); print(esmxml_0[1]);return;");
/*fuzzSeed-71289653*/count=1649; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + ( ! (Math.sin(Math.trunc(Math.fround(Math.max(Math.hypot(y, x), Math.fround(x))))) >>> 0))) <= (( + Math.pow(((Math.pow((( ~ (((0/0 >>> 0) | (Math.atan2(y, x) >>> 0)) >>> 0)) >>> 0), ( + Math.max((Math.round((Math.fround((Math.fround(0x07fffffff) << Math.fround(0x080000000))) >>> 0)) >>> 0), ( + Math.fround((((x >>> 0) << (-1/0 >>> 0)) >>> 0)))))) | 0) | 0), ( + (x ? Math.fround(( ! ( - Number.MIN_VALUE))) : Math.fround(Math.atan2((x | 0), ((Math.log10(y) | y) | 0))))))) >>> 0)); }); testMathyFunction(mathy0, [-0, 2**53, 0/0, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, 0x0ffffffff, 0x100000000, 1/0, -(2**53+2), 1, -0x080000001, -(2**53-2), 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000001, -(2**53), 42, 0x100000001, -0x07fffffff, -0x080000000, 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, 0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-71289653*/count=1650; tryItOut("\"use strict\"; {Object.defineProperty(this, \"v0\", { configurable: (x % 4 != 1), enumerable: (b % 4 != 3),  get: function() {  return evalcx(\"/* no regression tests found */\", this.g2); } });const b = (typeof 'fafafa'.replace(/a/g, String.prototype.indexOf)());c = ((Object.create).call(false | atan, ));\ni1.next();\n }");
/*fuzzSeed-71289653*/count=1651; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\B)\", \"gm\"); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-71289653*/count=1652; tryItOut("o1.f0 + a0;");
/*fuzzSeed-71289653*/count=1653; tryItOut("(false);\nthis.v0 = Object.prototype.isPrototypeOf.call(t1, this.s1);\n");
/*fuzzSeed-71289653*/count=1654; tryItOut("/*infloop*/for(var c = new ([z1,,])(); (this.__defineSetter__(\"window\", objectEmulatingUndefined)); null.getInt16(d, window))  /x/g ;");
/*fuzzSeed-71289653*/count=1655; tryItOut("mathy5 = (function(x, y) { return ( ~ ( + Math.atan2(( - (mathy0((Math.asinh(( + Math.hypot((y >>> 0), (y >>> 0)))) >>> 0), (( ! (((y >>> 0) << ( + ( + x))) >>> 0)) >>> 0)) >>> 0)), (mathy1(((( ! (-(2**53+2) | 0)) | 0) >>> 0), x) | 0)))); }); testMathyFunction(mathy5, [-(2**53+2), Number.MIN_VALUE, -0x080000000, -0x0ffffffff, 2**53-2, 0x080000001, -Number.MAX_VALUE, 42, -0, 0x100000000, 0.000000000000001, 2**53+2, -1/0, 0x100000001, 0/0, Math.PI, -0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -(2**53), 0, 0x07fffffff, 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -(2**53-2), -0x080000001, 0x080000000, Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001]); ");
/*fuzzSeed-71289653*/count=1656; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 5.0;\n    var i3 = 0;\n    var i4 = 0;\n    var i5 = 0;\n    var i6 = 0;\n    (Uint8ArrayView[0]) = ((0x952b48f3));\n    (Float32ArrayView[((0xff8c4341)-(i1)) >> 2]) = ((1.5474250491067253e+26));\n    i6 = (i4);\n    (Int8ArrayView[((0xe9d8b2b4)) >> 0]) = ((i6)-(((-17.0))));\n    {\n      i4 = (((0xdc9dda0f) > (0x41c9ed04)) ? ((((0xec28597) % (((0xfc0f1c99))>>>((0x1b374bf5))))>>>(((((0x7171b7a))>>>((0xff2a370f))) < (((0xff2750a0))>>>((0x5a674471)))))) >= (((i3))>>>(-0xe3d00*((-0x33c5f3b) ? (0x3dcd05a8) : (0xffaabc42))))) : ((((i4)) >> ((i4)-(0xfa1b19a1))) < (~((i5)))));\n    }\n    i6 = (i4);\n    i3 = (0x41a16c03);\n    return (((window++)+(i6)-(0x37316b2a)))|0;\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; yield y; m1 = g2.objectEmulatingUndefined();; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0x100000001, 0x080000001, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, 1/0, -1/0, 0/0, 0x080000000, 2**53, 0.000000000000001, -(2**53-2), -(2**53), 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, -0x080000001, -0x080000000, -0x100000000, Math.PI, 2**53-2, 2**53+2, 1, 42, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, -0, 0]); ");
/*fuzzSeed-71289653*/count=1657; tryItOut("/* no regression tests found */");
/*fuzzSeed-71289653*/count=1658; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((( ! mathy2(( ! x), 1)) >>> 0) ? ( - Math.cbrt((mathy1(Math.sign(y), (( - (((42 >>> 0) ? (-0x080000001 >>> 0) : (y >>> 0)) >>> 0)) | 0)) | 0))) : ( + Math.sqrt((((Math.fround(x) >> Math.fround(((( ! x) | 0) ? (y ? (-Number.MAX_SAFE_INTEGER >>> 0) : ( + ( + ( + -Number.MAX_SAFE_INTEGER)))) : Math.acosh((y == (0/0 >>> 0)))))) | 0) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[(4277), false, false, function(){}, false]); ");
/*fuzzSeed-71289653*/count=1659; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var atan = stdlib.Math.atan;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (-0x76a3ccc);\n    }\n    d1 = (x);\n    (Float64ArrayView[0]) = ((+(~~(-((Float64ArrayView[4096]))))));\n    ((4277)) = (((((Float32ArrayView[(((((0xa2a72312) ? (0xff7e01f1) : (-0x8000000)))>>>(((0xbd8d787d))+(0xffffffff))) / (0xc9b29c74)) >> 2]))) + (((d1)) % ((-((Infinity)))))));\n    i0 = (0x13a6f4ec);\n    {\n      d1 = (+atan(((d1))));\n    }\n    i0 = ((((Float32ArrayView[((imul((0x4dc2ac39), (0xffbd1ab1))|0) / (((0xc25fdb4a)) ^ ((0xfb455b4e)))) >> 2]))) ? ((-281474976710657.0) != (d1)) : (0xfa004f8b));\n    return (((Int32ArrayView[(0xc8311*((((0xfdcdbef1)-((0xffffffff)))>>>((0x291e4d00) / (((0xfe99dfff))>>>((0x99f0224))))))) >> 2])))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0/0, -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, 1, 0x100000000, 0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -1/0, -0x080000000, -0, 42, 1/0, Math.PI, -0x100000000, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), -(2**53), 0x080000001, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, 0x080000000, 2**53+2, 0.000000000000001, -0x0ffffffff, 0x100000001, -0x100000001]); ");
/*fuzzSeed-71289653*/count=1660; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s1; print(s.match(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
