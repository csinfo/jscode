

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
/*fuzzSeed-133180449*/count=1; tryItOut("i1 = e0.iterator;");
/*fuzzSeed-133180449*/count=2; tryItOut("t0 + o1;");
/*fuzzSeed-133180449*/count=3; tryItOut("/*infloop*/for({} = (uneval( /x/ )); new (Math.atan2(9, 2))(); x) {print( /* Comment */x);x; }");
/*fuzzSeed-133180449*/count=4; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.acosh(Math.fround((Math.pow(((( + (( - (( ~ Math.fround(2**53+2)) | 0)) | 0)) | 0) >>> 0), (Math.fround((Math.fround((( - (x >>> 0)) >>> 0)) > Math.fround((Math.exp(( ! (y ? x : Number.MAX_SAFE_INTEGER))) | 0)))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-133180449*/count=5; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ Math.fround((((( ~ (Math.min(mathy1(y, y), x) >>> 0)) >>> 0) << (y ? (Math.round((x >>> 0)) >>> 0) : x)) >>> Math.fround(Math.tanh(Math.pow(y, (Math.hypot(( ~ x), ((x >>> 0) + (x >>> 0))) >>> 0))))))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 0, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, -(2**53+2), -0x080000001, -(2**53-2), -0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, -0, 0/0, 0x080000000, -1/0, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000001, 0.000000000000001, -0x080000000, 1, 0x080000001, -Number.MAX_VALUE, 42, Math.PI, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=6; tryItOut("for (var v of e1) { try { v0 = Object.prototype.isPrototypeOf.call(o2, o0); } catch(e0) { } Array.prototype.forEach.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var cos = stdlib.Math.cos;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      (Int32ArrayView[0]) = ((!(0xf9544905))+(/*FFI*/ff((((-140737488355327.0) + (+pow(((32767.0)), ((Float32ArrayView[1])))))), ((((Infinity)))), ((~~(-0.0078125))), ((+/*FFI*/ff(((((0xf8fd072f)+(0x7b3f8fa7)+(-0x8000000)) ^ ((/*FFI*/ff(((-134217729.0)))|0)-(i0))))))))|0));\n    }\n    {\n      i0 = ((0x19d179fc));\n    }\n    (Float32ArrayView[2]) = ((1.0009765625));\n    return +((+cos(((Float32ArrayView[((i0)) >> 2])))));\n    d1 = (+(((i0)+((d1) <= (+/*FFI*/ff((((Float64ArrayView[1]))), ((((0x5a690445)) << ((0xffffffff)))), ((imul((0xfe1d8087), (0x211bd07b))|0)), ((-2.3611832414348226e+21)), ((2305843009213694000.0)), ((-3.8685626227668134e+25)), ((68719476736.0)), ((-3.094850098213451e+26)), ((4194305.0)), ((513.0)), ((-2.3611832414348226e+21)), ((-295147905179352830000.0)), ((-4.722366482869645e+21)), ((2305843009213694000.0)), ((590295810358705700000.0)), ((65.0)), ((-288230376151711740.0)))))) >> ((/*FFI*/ff()|0)+((0xa2905850) != (0x0)))));\n    (Int16ArrayView[((((0x4df9bd78)+(i0))>>>((i0))) % (0xe6793d8c)) >> 1]) = ((((((0x7a02*(0xf8c9702f)) << (0xa471b*(0x4528880d))) < (~((0xb50dc945) / (0xec6a1f95))))*-0xfffff)>>>(((((0xfaeb1d49)) | ((0xfe5f18e8)-(0x914abab3)+(0xfad1a898))))+(-0x8000000))) % (((((0xd2aa33a5)-(0x8ee9e3d8)-(0xde777576)) | ((i0)-(0xb60dee4b))) % (~((-0x8000000) % (((0x7cb832da))|0))))>>>((((!(/*FFI*/ff()|0))+(0xff11d02a))|0) % (((i0)-((0xf8cfeae8) ? (-0x8000000) : (0xfa7d8ff4)))|0))));\n    return +((590295810358705700000.0));\n  }\n  return f; })(this, {ff: () =>  { Array.prototype.splice.call(this.g0.a0, 2, true, o1); } }, new ArrayBuffer(4096)), s0, this.g2.p2]); }");
/*fuzzSeed-133180449*/count=7; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=8; tryItOut("a0.push(b1);\nprint(x);\n");
/*fuzzSeed-133180449*/count=9; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.imul(Math.log1p(Math.asin(Math.max(y, (Math.fround((x | 0)) >>> 0)))), (mathy1(( + ( + Math.cbrt(Math.fround(Math.imul(x, Math.fround((x != ( + ((-Number.MIN_SAFE_INTEGER >>> 0) ? (x >>> 0) : (x >>> 0)))))))))), Math.abs((y | 0))) | 0)); }); testMathyFunction(mathy4, /*MARR*/[ \"\" , (void 0), (void 0),  \"\" ]); ");
/*fuzzSeed-133180449*/count=10; tryItOut("for (var v of o2.g0.v0) { try { print(i0); } catch(e0) { } try { v2 = t0.BYTES_PER_ELEMENT; } catch(e1) { } try { h1.getOwnPropertyDescriptor = (function(j) { if (j) { try { o2.o2 + ''; } catch(e0) { } v2 = o0.b2.byteLength; } else { this.v1 = (t0 instanceof h1); } }); } catch(e2) { } o1.b2 + ''; }");
/*fuzzSeed-133180449*/count=11; tryItOut("f0 = m1.get(f0);");
/*fuzzSeed-133180449*/count=12; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ! Math.fround(mathy0((Math.atanh((x >>> 0)) >>> 0), Math.hypot(Math.hypot(Math.pow(( + (0x0ffffffff ? x : ((((x >>> 0) < -0x0ffffffff) >>> 0) | 0))), x), ((mathy0(x, y) != x) | 0)), (Math.imul(x, -0x07fffffff) != 42))))); }); testMathyFunction(mathy1, [2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, 0x0ffffffff, 0/0, Math.PI, -(2**53-2), -Number.MIN_VALUE, 2**53+2, 42, Number.MIN_VALUE, 0x07fffffff, -0x080000000, 1.7976931348623157e308, 0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000000, 0, Number.MAX_VALUE, -(2**53), -1/0, -0x07fffffff, 0x100000001, 2**53, -0x100000001, -0, Number.MAX_SAFE_INTEGER, 1, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0]); ");
/*fuzzSeed-133180449*/count=13; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((((Math.round(( + (( ! (2**53-2 >>> 0)) >>> 0))) >>> 0) ? ((Math.hypot(( + y), ((Math.hypot(Math.fround(Math.atan2(Math.cos(-Number.MAX_SAFE_INTEGER), Math.sqrt(y))), Math.fround(y)) >>> 0) | 0)) | 0) >>> 0) : (Math.pow((y >>> 0), Math.fround((Math.fround((((y | 0) && (x | 0)) | 0)) <= Math.fround(Math.pow((mathy1((y >>> 0), (x >>> 0)) >>> 0), -Number.MIN_SAFE_INTEGER))))) | 0)) | 0) & ( + Math.max(x, (Math.max((y | 0), ( + -0x07fffffff)) >>> 0)))); }); testMathyFunction(mathy2, [Math.PI, Number.MAX_VALUE, 0x080000000, 0x100000000, -0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1/0, -0x080000001, 2**53-2, -Number.MIN_VALUE, -0, 0x100000001, 2**53+2, -(2**53), 0, 0.000000000000001, 0x07fffffff, -(2**53-2), 42, 1, -0x100000000, 0x080000001, -0x0ffffffff, -1/0, 0/0, 2**53, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -0x080000000]); ");
/*fuzzSeed-133180449*/count=14; tryItOut("v0 = (g1 instanceof o2);");
/*fuzzSeed-133180449*/count=15; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0(Math.cbrt(( + Math.imul(( + y), ( + (Math.sin(( ~ (Math.min(Math.fround((y != y)), y) | 0))) >>> 0))))), Math.fround(Math.imul(mathy1(y, Math.fround(Math.abs(( + x)))), (((((( + Math.abs(-Number.MIN_SAFE_INTEGER)) >>> 0) != Number.MIN_VALUE) | 0) ? ( ! ( + (Math.max((( - x) | 0), (Math.sign(y) | 0)) | 0))) : (mathy0(( + (( + -1/0) / ( + x))), y) | 0)) | 0)))); }); testMathyFunction(mathy2, [0x080000000, 1/0, -(2**53+2), -(2**53), Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, 0x100000000, -(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, -0x07fffffff, 2**53, -0x080000000, -1/0, Number.MAX_VALUE, 0x07fffffff, 0, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, -0x0ffffffff, 0x0ffffffff, 0x100000001, 42, -0, -0x100000000]); ");
/*fuzzSeed-133180449*/count=16; tryItOut("var sndhbz = new SharedArrayBuffer(0); var sndhbz_0 = new Uint8Array(sndhbz); sndhbz_0[0] = 15; x;Array.prototype.pop.call(a2);v1 = (o0.o2 instanceof m1);/*MXX2*/g0.WeakMap.prototype = t2;v1 = evalcx(\"function f1(s2) \\\"use asm\\\";   function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var d2 = 33.0;\\n    var d3 = -4194303.0;\\n    d2 = (d3);\\n    return +((d1));\\n  }\\n  return f;\", g0);print(sndhbz_0[0]);");
/*fuzzSeed-133180449*/count=17; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( + (Math.exp(( + ( - Math.atan2((((x | 0) ? (y | 0) : (y | 0)) | 0), y)))) ? ((Math.fround((Math.clz32(y) | ( + Math.abs(( + (( + (y | 0)) | 0)))))) ^ (Math.fround(Math.atan2(((((( ! (x >>> 0)) >>> 0) | y) | 0) | 0), ((Math.log10(x) | 0) ? (y && y) : Math.hypot(y, y)))) >>> 0)) >>> 0) : ( + mathy1(( + (Math.fround(( + (( ~ (( ~ (y | 0)) | 0)) | 0))) | 0)), Math.fround(Math.max(( ! (( - (((x | 0) != (Number.MIN_VALUE | 0)) | 0)) | 0)), ((Math.round(y) | 0) || ( + Math.pow((0 | 0), (x | 0)))))))))) - ( + ( ~ (Math.fround(((Math.log1p(y) | (y >>> 0)) + (Math.atan2(( + ((-0x100000000 | 0) ^ Math.fround(-0x080000000))), ( + y)) | 0))) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[new String(''), timeout(1800) % (x), 2**53, 2**53, 2**53, new String(''), 2**53, timeout(1800) % (x), timeout(1800) % (x)]); ");
/*fuzzSeed-133180449*/count=18; tryItOut("\"use asm\"; /*hhh*/function ssakmo(x, window){if( \"\" ) {o0 = a2[7]; } else  if (Date.prototype.getUTCFullYear) e2 + ''; else {t2 = new Uint8ClampedArray(b2, 56, 0);yield Math; }}ssakmo((NaN = x).__defineGetter__(\"y\", (null|=29)), (eval(\"/* no regression tests found */\", ! '' )));");
/*fuzzSeed-133180449*/count=19; tryItOut("(x++);");
/*fuzzSeed-133180449*/count=20; tryItOut("\"use strict\"; e2.add(b1);");
/*fuzzSeed-133180449*/count=21; tryItOut("/*tLoop*/for (let x of /*MARR*/[new Boolean(true), (1/0), (1/0), new String('q'), new Boolean(true), new String('q'), new String('q'), new String('q'), new String('q'), (1/0), new String('q'), new String('q'), new String('q'), new Boolean(true), new Boolean(true), (1/0), (1/0), (1/0), new Boolean(true)]) { /* no regression tests found */\na2.reverse();\n }");
/*fuzzSeed-133180449*/count=22; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.max(Math.fround(Math.min(( ~ Math.pow(x, x)), ((((( + ( ~ (x | 0))) || (Math.exp(Math.fround(( - Math.fround(x)))) >>> 0)) >>> 0) <= (Math.exp(( ~ y)) >>> 0)) >>> 0))), Math.fround(( + (( + ((Math.atan2(Math.fround(Math.atan((( ~ x) < Math.fround((-0x07fffffff < Math.fround(x)))))), ( + y)) >>> 0) & (x >>> 0))) || Math.fround((Math.fround(Math.max(( ~ y), (x >>> 0))) ? ((( ~ x) >>> 0) | 0) : Math.fround(Math.fround(Math.atan2(Math.fround(y), Math.fround(-0x080000001)))))))))); }); testMathyFunction(mathy0, [-0x100000000, 2**53+2, -Number.MAX_VALUE, 0x080000001, 0x080000000, 0.000000000000001, -0x080000001, 1/0, -(2**53), 0x0ffffffff, 2**53, Number.MAX_VALUE, 0x07fffffff, -(2**53+2), 0x100000001, Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 0x100000000, 0, -0, 0/0, -0x080000000, -0x100000001, 2**53-2, 1, 1.7976931348623157e308, -Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=23; tryItOut("print(x);");
/*fuzzSeed-133180449*/count=24; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return (( + Math.sign((((( ! x) >>> 0) >= ((((( + y) >>> 0) | 0) | ( ! x)) >>> 0)) >>> 0))) - ((( + (y / (Math.max((mathy1((y >>> 0), (x >>> 0)) >>> 0), y) <= Math.atan2(y, (y >>> 0))))) ? (((( + (( + ( + x)) / ( + x))) + ( + (( + y) >>> (y >>> 0)))) | ((( + y) + (y >>> 0)) >>> 0)) | 0) : (Math.fround(Math.cos(Math.fround(( + Math.fround(( ~ -(2**53+2))))))) | 0)) | 0)); }); testMathyFunction(mathy4, [true, (new String('')), false, 1, objectEmulatingUndefined(), undefined, null, (new Boolean(true)), [], ({valueOf:function(){return '0';}}), '0', (function(){return 0;}), '/0/', -0, [0], ({toString:function(){return '0';}}), NaN, 0.1, 0, ({valueOf:function(){return 0;}}), /0/, (new Number(0)), (new Boolean(false)), (new Number(-0)), '', '\\0']); ");
/*fuzzSeed-133180449*/count=25; tryItOut("e1.add(((function() { \"use strict\"; yield  '' ; } })()));");
/*fuzzSeed-133180449*/count=26; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=27; tryItOut("/*RXUB*/var r = /\\1/gy; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=28; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=29; tryItOut("\"use strict\"; \"use asm\"; e2.has(this.o1.b2);");
/*fuzzSeed-133180449*/count=30; tryItOut("/*RXUB*/var r = r2; var s = s2; print(s.replace(r, eval)); ");
/*fuzzSeed-133180449*/count=31; tryItOut("t1 = new Float64Array(t0);");
/*fuzzSeed-133180449*/count=32; tryItOut("\"use asm\"; a2.splice(0, 2);/* no regression tests found */");
/*fuzzSeed-133180449*/count=33; tryItOut("mathy4 = (function(x, y) { return Math.log1p(Math.fround(Math.max((Math.min((y >>> 0), (y >>> 0)) >>> 0), ( + ( + ( + Math.fround(mathy3(Math.fround((( + ( + (Math.min((1 | 0), (Number.MIN_SAFE_INTEGER | 0)) | 0))) != Math.fround(-0x080000001))), Math.fround(-0x07fffffff))))))))); }); testMathyFunction(mathy4, [-0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000000, 1.7976931348623157e308, 0.000000000000001, -0x080000001, 0/0, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, 0x0ffffffff, 0x080000000, 0x100000001, Number.MIN_VALUE, -1/0, 0, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 2**53+2, -Number.MAX_VALUE, 1, -0, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 42, Math.PI, -(2**53+2), -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=34; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((Math.log1p(( + mathy0(( + mathy0(Math.atan2(y, ( + ( + ( ~ y)))), Math.fround(( + (y | Math.hypot(0x080000000, y)))))), ( + 0x0ffffffff)))) >>> 0) ? (( + ( + (Math.min(0/0, y) >>> 0))) >>> 0) : (( + (Math.fround(mathy0(Math.fround(( - x)), Math.fround(( + mathy0(( + Math.fround(( ! Math.fround(-0x080000000)))), ( + Math.fround(Math.min(Math.fround(Math.min(-0x100000000, (Math.max((y >>> 0), (x >>> 0)) >>> 0))), Math.fround(( ! x)))))))))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [2**53-2, 0x100000000, 0x080000001, -Number.MAX_VALUE, -0x080000000, 0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -Number.MIN_VALUE, 2**53+2, 0.000000000000001, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), Math.PI, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, 0/0, -(2**53), -0x080000001, 1.7976931348623157e308, 1/0, -0x100000001, 42, -0, -0x07fffffff, 0, 0x07fffffff, -(2**53+2), -1/0]); ");
/*fuzzSeed-133180449*/count=35; tryItOut("/*RXUB*/var r = /\\B/y; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-133180449*/count=36; tryItOut("Array.prototype.forEach.apply(a2, [(function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d1));\n    return +((((+(~~(d1)))) - ((d0))));\n  }\n  return f; })(this, {ff: (\"\\uA231\").call}, new ArrayBuffer(4096)), o0]);\n(null);\n");
/*fuzzSeed-133180449*/count=37; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=38; tryItOut("\"use strict\"; testMathyFunction(mathy2, [1/0, 2**53-2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, 0.000000000000001, -0x100000001, -0x080000000, 0x0ffffffff, 42, -1/0, -(2**53+2), -0x080000001, Math.PI, -(2**53), -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, 2**53, -(2**53-2), 0, 1.7976931348623157e308, -0, 0x07fffffff, Number.MIN_VALUE, 0x100000001, 1, 0/0]); ");
/*fuzzSeed-133180449*/count=39; tryItOut("b1[\"getUint16\"] = v1;");
/*fuzzSeed-133180449*/count=40; tryItOut("\"use strict\"; i0 + '';");
/*fuzzSeed-133180449*/count=41; tryItOut("mathy0 = (function(x, y) { return ( - ( + ( - Math.ceil(( ! x))))); }); ");
/*fuzzSeed-133180449*/count=42; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 536870911.0;\n    var i3 = 0;\n    (Uint32ArrayView[((((-0x8000000) ? (0xfb68ab68) : (0xf870bdf7)) ? (0x86551a4d) : ((((0x92c01cb4))>>>((0xfe0562f8))) <= (0x327993fb)))) >> 2]) = ((-0x8000000)-(/*FFI*/ff(((((0xb1f8fd01)+((~~(+(1.0/0.0))) > (abs((((Uint32ArrayView[1]))|0))|0))) | ((0x2d043ee4)))), ((imul(((((0xf97cb88d)+(-0x8000000)+(0xffffffff))>>>((0xe8c328be)+(0xea2632c8)))), (0xfa6ec2ce))|0)), ((0x1a1924f7)), ((d0)), ((((1048576.0)) - ((d0)))))|0));\n    d2 = (((true)) % ((4194305.0)));\n    d1 = (x);\n    d0 = (-9.44473296573929e+21);\n    return +((d2));\n  }\n  return f; })(this, {ff: ((let (e=eval) e)).call}, new ArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=43; tryItOut("testMathyFunction(mathy1, [0, -(2**53+2), 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, 2**53-2, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, -1/0, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, 1, Number.MIN_VALUE, 42, -(2**53), 1.7976931348623157e308, -0x07fffffff, 0x100000001, -0x080000000, 0.000000000000001, -Number.MIN_VALUE, Math.PI, -(2**53-2), 2**53+2, -0, -0x080000001, 0x080000001]); ");
/*fuzzSeed-133180449*/count=44; tryItOut("\"use strict\"; selectforgc(this.o2);");
/*fuzzSeed-133180449*/count=45; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ! (((( ! y) >>> 0) ? ((( + (mathy1(Math.atan2((y >>> 0), -(2**53-2)), (( ! (x >>> 0)) >>> 0)) | 0)) | 0) >>> 0) : ( + ( + mathy1(( + y), ( + y))))) === x)); }); testMathyFunction(mathy2, [0x0ffffffff, 1/0, -0x0ffffffff, -0x100000001, Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53+2), 0x080000000, -0, Math.PI, Number.MAX_VALUE, -(2**53), -0x080000001, 2**53-2, 42, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, 0/0, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, -1/0, 1, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, 0.000000000000001, -0x080000000, 1.7976931348623157e308, 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-133180449*/count=46; tryItOut("\"use strict\"; b0 = new SharedArrayBuffer(18);");
/*fuzzSeed-133180449*/count=47; tryItOut("this.h0.set = (function() { for (var j=0;j<60;++j) { f2(j%5==1); } });");
/*fuzzSeed-133180449*/count=48; tryItOut("print(Math.min( /x/ , /*UUV2*/(d.is = d.tan)));");
/*fuzzSeed-133180449*/count=49; tryItOut("mathy3 = (function(x, y) { return ((Math.pow((Math.tanh((Math.trunc(y) >>> 0)) | 0), (( + Math.fround(Math.sinh((y | 0)))) | 0)) | 0) ? (( - (Math.fround((Math.fround(Math.sign((y | 0))) >= Math.cosh(y))) | 0)) | 0) : (( + (Math.fround(Math.round(( + mathy1(Math.log1p(y), (Math.max((Math.atan2(x, y) | 0), ( +  '' )) >>> 0))))) | 0)) | 0)); }); testMathyFunction(mathy3, [/0/, undefined, '/0/', (new Number(0)), -0, (new Number(-0)), '0', 0, (new Boolean(true)), NaN, ({valueOf:function(){return '0';}}), '', (new Boolean(false)), 0.1, (new String('')), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), ({toString:function(){return '0';}}), '\\0', [0], (function(){return 0;}), false, true, null, 1, []]); ");
/*fuzzSeed-133180449*/count=50; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    i2 = ((0x1139520a));\n    i2 = ((i3) ? (i2) : (0xffffffff));\n    d0 = (-((((Float64ArrayView[(-(i1)) >> 3])) / ((+(0.0/0.0))))));\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: function  x (y)this <= \u3056}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0, -0x080000000, 1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53-2), 0x080000000, 1, 2**53+2, -0x100000001, 0x080000001, -0, 0/0, Math.PI, -Number.MAX_SAFE_INTEGER, 42, -0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, 0.000000000000001, -1/0, -0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), 2**53, -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-133180449*/count=51; tryItOut("\"use strict\"; e0.add(this.m2);");
/*fuzzSeed-133180449*/count=52; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.min(( + mathy0(Math.fround((Math.max(Math.sinh(mathy0(0/0, x)), ( + (Math.asinh(y) >= Math.atanh(x)))) ? ( + (Math.hypot(( + ((((( ~ (1.7976931348623157e308 | 0)) >>> 0) | 0) != ((x , (mathy0(x, (x | 0)) >>> 0)) | 0)) | 0)), ( + (x & x))) >>> 0)) : ( + Math.atanh((y <= -(2**53)))))), Math.fround((Math.atan(Math.fround((Math.fround(Math.pow((0 >>> 0), (Math.fround(((y >>> 0) ? (x >>> 0) : (x >>> 0))) >>> 0))) ? Math.fround(x) : (( + mathy0(( + ( ! x)), ( + (x ? ( + y) : ( + 1/0))))) | 0)))) | 0)))), ( + (( - (Math.round(y) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-133180449*/count=53; tryItOut("testMathyFunction(mathy3, [Number.MAX_VALUE, 0, -0x0ffffffff, -1/0, 2**53+2, 0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, -0, 0x100000001, -0x080000001, 0x100000000, 0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, 1/0, -Number.MAX_VALUE, -0x100000001, 0x080000000, -(2**53), 1, -Number.MIN_VALUE, -(2**53+2), 2**53-2, 0x07fffffff, -0x07fffffff, -(2**53-2), 0/0, -0x100000000, 1.7976931348623157e308, -0x080000000]); ");
/*fuzzSeed-133180449*/count=54; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.max(Math.fround((( - (( + Math.hypot((Math.fround(( - Math.fround(Math.log10(Math.fround(y))))) >>> 0), Math.hypot((mathy0((( + (y | 0)) | 0), x) >>> 0), ( - ((x % x) | 0))))) | 0)) | 0)), Math.fround(mathy0(( + (Math.acos((Math.fround(Math.min(Math.fround(y), Math.fround(0x100000000))) >>> 0)) >>> 0)), Math.imul(( ! -0x080000000), ( ! x)))))); }); testMathyFunction(mathy1, [1/0, Math.PI, -0x080000001, -0x07fffffff, 0x0ffffffff, -(2**53-2), 0, 2**53, -0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, 0x080000000, -0x100000001, 2**53+2, 0/0, -Number.MAX_VALUE, 42, Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 2**53-2, -(2**53), -0, -(2**53+2), 0x080000001, 1, -0x0ffffffff, Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-133180449*/count=55; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4((((Math.fround((Math.fround(( ~ Math.tan(y))) - Math.fround(((((mathy3(( + Math.abs(( + y))), -(2**53-2)) | 0) | 0) && (Math.hypot(x, ( + (( + y) ? ( + 42) : x))) | 0)) | 0)))) | 0) ? (Math.fround(Math.hypot(( + Math.fround(( - Math.fround(mathy2(( + y), (Math.hypot(y, y) >>> 0)))))), ( + Math.pow(( ! x), Math.fround(Math.expm1(y)))))) | 0) : ( + Math.expm1(Math.fround(y)))) | 0), ((Math.imul((Math.max(y, Math.atan2(0x0ffffffff, Math.fround(Math.hypot(Math.fround(y), y)))) / Math.fround(Math.asin(Math.exp(x)))), Math.max(( ~ ( + ( ! Math.max(y, y)))), y)) > (Math.fround(Math.sign(Math.tanh(( ! x)))) | 0)) >>> 0)); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, -0, Number.MAX_VALUE, 42, 0.000000000000001, Number.MIN_VALUE, -(2**53), -0x100000000, -0x100000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53-2), 0x100000000, 0x07fffffff, 0x0ffffffff, -0x080000001, 0/0, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -0x080000000, 0x100000001, 2**53, 2**53+2, -(2**53+2), 1/0, 0, -0x07fffffff, Math.PI, 1.7976931348623157e308, 1, -1/0]); ");
/*fuzzSeed-133180449*/count=56; tryItOut("testMathyFunction(mathy0, [0x100000001, 0x080000000, 0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, 2**53-2, -Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 1, 0x07fffffff, -0x080000000, 2**53, -0x0ffffffff, -1/0, 0x100000000, -0x07fffffff, -0x080000001, 0, 1/0, -(2**53), -0x100000000, -(2**53+2), -0, Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=57; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ((( ~ (( + Math.sin(y)) | 0)) > ( + ( ! (x & Math.fround(Math.sin(Math.asinh(y))))))) + (Math.log2(Math.cos(Math.tanh(( - (y | 0))))) >>> 0)); }); ");
/*fuzzSeed-133180449*/count=58; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=59; tryItOut("mathy1 = (function(x, y) { return Math.fround(((mathy0((Math.fround(( + Math.atan2(( + (Math.max(( ~ Math.fround(y)), (0x0ffffffff >>> 0)) >>> 0)), ( + y)))) || -Number.MIN_SAFE_INTEGER), (( + (y >>> 0)) >>> y)) ^ mathy0(Math.tan(( + ((x | 0) != ( + (0x07fffffff !== -0x100000001))))), (Math.fround(( + (y >>> 0))) ? ( + Math.hypot(( + Math.fround(( ~ (y >>> 0)))), ( + y))) : ( + (-(2**53+2) - -Number.MAX_SAFE_INTEGER))))) && Math.fround(Math.tanh(( + Math.sign(( + ((( + 0.000000000000001) & x) >>> 0)))))))); }); testMathyFunction(mathy1, [-(2**53+2), -0x100000001, 0, -0x100000000, -0x080000001, -(2**53-2), Math.PI, Number.MIN_VALUE, -1/0, -(2**53), -0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 42, 0x100000000, 0.000000000000001, 2**53, 1.7976931348623157e308, 0x07fffffff, -0x080000000, 1, 1/0, 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, 2**53+2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, -0, -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=60; tryItOut("v1 = g2.eval(\"/* no regression tests found */\");");
/*fuzzSeed-133180449*/count=61; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return mathy0(Math.fround(( - Math.fround((Math.min((mathy1(y, (Math.max(x, 0/0) | 0)) >>> 0), ((Math.acos(( ~ (1.7976931348623157e308 == ( + y)))) >>> 0) >>> 0)) >>> 0)))), (Math.acosh(( ~ ( + Math.ceil(( + ( + (( + x) == ( + -Number.MIN_SAFE_INTEGER)))))))) == Math.min(-1/0, ( + (( + ( ~ -0x100000000)) ? ( + -Number.MAX_VALUE) : (Math.expm1(y) | 0)))))); }); testMathyFunction(mathy2, [-0x080000001, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 2**53-2, 0x100000001, 0, 0x07fffffff, 0x080000001, -Number.MIN_VALUE, -1/0, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, -(2**53), -0x0ffffffff, 1.7976931348623157e308, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0.000000000000001, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, Math.PI, -0, 2**53, Number.MIN_VALUE, -0x100000000, 1/0, 42, -Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=62; tryItOut("for (var p in f0) { try { for (var p in o0.e1) { try { v2 = Object.prototype.isPrototypeOf.call(o0.b0, p0); } catch(e0) { } try { this.m0 = new Map(t0); } catch(e1) { } try { o2.m2.has(f0); } catch(e2) { } /*MXX3*/g2.g2.Array.prototype.copyWithin = g0.Array.prototype.copyWithin; } } catch(e0) { } try { v2 = g1.eval(\"v0 = Object.prototype.isPrototypeOf.call(o1.a1, o2)\\nM:for([x, c] =  /x/  in x) {m1.get(t0); }\"); } catch(e1) { } try { e2.add(p1); } catch(e2) { } function f2(s1)  { yield x }  }");
/*fuzzSeed-133180449*/count=63; tryItOut("L:if(x) /*ODP-3*/Object.defineProperty(e1, \"NaN\", { configurable: true, enumerable: 25, writable: true, value: o1.b0 }); else print(x);");
/*fuzzSeed-133180449*/count=64; tryItOut("mathy3 = (function(x, y) { return (Math.hypot((( + Math.fround(y)) | 0), (( + (( + (( + ((x && ( + Math.ceil(2**53+2))) >>> 0)) / ( + x))) <= (Math.fround((Math.fround((Math.acosh(Math.fround(0x100000001)) | 0)) != Math.fround(Math.sqrt(x)))) >>> 0))) >>> 0)) ? Math.max(Math.ceil((Math.min(1, ( + Math.imul((x >>> 0), ( + y)))) | 0)), ( + (mathy1(((Math.fround(x) ? 1/0 : Number.MAX_SAFE_INTEGER) | 0), ( + Math.min((( ! ( + mathy2(y, y))) | 0), (Number.MIN_VALUE | 0)))) >>> 0))) : Math.atan2(( ~ ( + Math.min(( + (x - x)), ( + ( - y))))), ((Math.sin((( + (( + mathy2(y, y)) >>> 0)) >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy3, [(new Boolean(true)), 0.1, null, 0, '\\0', '', [0], false, ({valueOf:function(){return '0';}}), (new Boolean(false)), (new String('')), ({toString:function(){return '0';}}), objectEmulatingUndefined(), undefined, '0', '/0/', 1, (new Number(-0)), true, (new Number(0)), /0/, (function(){return 0;}), -0, [], NaN, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-133180449*/count=65; tryItOut("switch((new (Array.prototype.reduce)(x, new RegExp(\"\\\\3\", \"im\"))(((runOffThreadScript)())))) { default: g0.m2.delete(this.t0);break; ( /x/ );case x: s2.valueOf = (function(j) { if (j) { try { s2 += 'x'; } catch(e0) { } try { v0.__proto__ = t1; } catch(e1) { } try { h1.get = eval; } catch(e2) { } for (var v of m1) { try { a1 = new Array; } catch(e0) { } try { i0.next(); } catch(e1) { } h0 = t2[14]; } } else { try { t0.__proto__ = g0; } catch(e0) { } try { m2.set(g2.f2, o0); } catch(e1) { } try { {} } catch(e2) { } s2 + f1; } });break; case intern(/\u99e5?/gm): s0 += s0; }");
/*fuzzSeed-133180449*/count=66; tryItOut("m1.set(x = z, t2);");
/*fuzzSeed-133180449*/count=67; tryItOut("e0 = new Set(this.h1);");
/*fuzzSeed-133180449*/count=68; tryItOut("/*RXUB*/var r = /(?!^)/yi; var s = x; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=69; tryItOut("\"use strict\"; v0 = g0.g0.g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-133180449*/count=70; tryItOut("o1.v0 = g1.eval(\"(void schedulegc(g2));\")\n");
/*fuzzSeed-133180449*/count=71; tryItOut("i0.__proto__ = m1;");
/*fuzzSeed-133180449*/count=72; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ~ (Math.log1p((mathy2(mathy1(Math.fround(( + Math.fround(Math.hypot(Math.fround(x), Math.fround(y))))), (x >>> 0)), ( + Math.fround(Math.sign(Math.fround(Math.min(( + Math.pow((( + -1/0) != y), Math.fround((( + y) & Math.fround(42))))), Math.fround(( + mathy2(y, 0x100000001))))))))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-133180449*/count=73; tryItOut("Object.defineProperty(this, \"t0\", { configurable: new (eval)([] ? window : -25), enumerable: (x % 4 == 0),  get: function() {  return t0.subarray(v2, 5); } });");
/*fuzzSeed-133180449*/count=74; tryItOut("L:switch(yield x) { case 4: ((uneval(x--))); }");
/*fuzzSeed-133180449*/count=75; tryItOut("\"use strict\"; (void schedulegc(g0));");
/*fuzzSeed-133180449*/count=76; tryItOut("(function(id) { return id });print(x);");
/*fuzzSeed-133180449*/count=77; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-133180449*/count=78; tryItOut("mathy1 = (function(x, y) { return Math.log10(Math.hypot(Math.atanh(Math.cosh((y != y))), (mathy0(((( - ( - Math.fround(( + Math.fround(y))))) >>> 0) >>> 0), (x | 0)) | 0))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 0, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000001, 1, 42, -(2**53-2), Math.PI, 1.7976931348623157e308, 0x080000000, 1/0, 2**53-2, 2**53+2, -0x100000001, 0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -0x080000000, -1/0, Number.MIN_VALUE, -0, 0/0, -Number.MAX_VALUE, -0x0ffffffff, Number.MAX_VALUE, 0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=79; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return Math.hypot(Math.fround(Math.log(( + Math.sqrt(( + y))))), Math.min(( ~ x), (( ! 0) + Math.pow(0x080000001, y)))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, -0, -0x080000001, 42, 1/0, 0x100000000, 0x100000001, 1, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001, 0.000000000000001, -0x07fffffff, 0x0ffffffff, 2**53-2, Number.MAX_VALUE, Math.PI, -(2**53-2), -0x100000001, -Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, 0, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 2**53, -0x0ffffffff, -1/0, 1.7976931348623157e308]); ");
/*fuzzSeed-133180449*/count=80; tryItOut("/*hhh*/function ppnaif(...z){s1 = '';}/*iii*/print(ppnaif);");
/*fuzzSeed-133180449*/count=81; tryItOut("mathy0 = (function(x, y) { return ((((Math.log(y) - Math.pow(((y < ( + (( + y) !== ( + x)))) >>> 0), (( + ( ~ y)) != (-0 / -0x080000000)))) >>> 0) >> Math.expm1(( ! Math.hypot(Number.MAX_SAFE_INTEGER, x)))) >>> ( ! ( + Math.tanh((Math.pow((Math.max(x, (Math.atan((x >>> 0)) >>> 0)) >>> 0), (y >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [null, (new Number(0)), (new Boolean(false)), (function(){return 0;}), [], -0, (new Number(-0)), [0], NaN, (new String('')), undefined, ({valueOf:function(){return '0';}}), true, '\\0', '', 1, 0, 0.1, '/0/', false, ({toString:function(){return '0';}}), '0', (new Boolean(true)), ({valueOf:function(){return 0;}}), /0/, objectEmulatingUndefined()]); ");
/*fuzzSeed-133180449*/count=82; tryItOut("v1 = t0.length;");
/*fuzzSeed-133180449*/count=83; tryItOut("(([] =  /x/ ));");
/*fuzzSeed-133180449*/count=84; tryItOut("/*oLoop*/for (let vylcpb = 0; vylcpb < 43; ++vylcpb) { print(x); } \nArray.prototype.splice.call(o1.a1, NaN, (({-1: (/[\u00e7\\W]/yim)(\"\\u9542\"),  set toString()x })));\n");
/*fuzzSeed-133180449*/count=85; tryItOut("function(id) { return id };");
/*fuzzSeed-133180449*/count=86; tryItOut("mathy5 = (function(x, y) { return ( + Math.min(Math.atan2(Math.fround(mathy3(Math.fround((x << Math.cbrt((Math.log2(0x080000001) >>> 0)))), mathy2(Math.sqrt(( + mathy0(( + y), ( + ( - 0x080000000))))), x))), (Math.fround(mathy4(Math.fround(-(2**53)), Math.fround(Math.asin(Math.fround(( + Math.min(( + (Math.acosh((x >>> 0)) >>> 0)), ( + x)))))))) >>> 0)), Math.fround(Math.fround(Math.imul(Math.fround(Math.min((x != x), (1 === (Math.acosh(x) - (Math.abs((x | 0)) | 0))))), Math.fround(Math.imul((Math.fround(Math.hypot(Math.fround(0x07fffffff), Math.fround(0/0))) !== ( + Math.hypot((2**53+2 >>> 0), (x >>> 0)))), (mathy4(2**53, (((x | 0) == y) >>> 0)) ? 0/0 : (( + x) === (( + (-Number.MAX_VALUE > y)) >> ((x & x) | 0))))))))))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 2**53-2, -(2**53-2), 0x07fffffff, -(2**53+2), 1/0, 0x0ffffffff, 42, 0x080000000, 0x100000000, 0/0, -0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1, 0.000000000000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, -0x100000000, 2**53+2, -Number.MAX_VALUE, -(2**53), -1/0, -0x100000001, -0x080000001, Math.PI, -0x080000000, 2**53, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff]); ");
/*fuzzSeed-133180449*/count=87; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x080000001, -Number.MAX_VALUE, 1, 0x100000001, 2**53+2, 42, -0x080000000, Number.MIN_VALUE, 0x0ffffffff, 1/0, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 0/0, Math.PI, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53, 0x07fffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), Number.MAX_VALUE, -(2**53-2), -0, -1/0, 0x080000000, 0, 2**53-2, -(2**53+2), 0x080000001, -0x100000001]); ");
/*fuzzSeed-133180449*/count=88; tryItOut("print(v2);var w = ([window &= x]);");
/*fuzzSeed-133180449*/count=89; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( - (Math.fround(( ~ Math.fround(Math.hypot(x, x)))) | 0)) | 0); }); testMathyFunction(mathy2, [-(2**53+2), -1/0, -(2**53-2), 1.7976931348623157e308, Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 42, -Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, -0x080000000, 0x07fffffff, Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, -0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, -0x100000001, 0, 1/0, -(2**53), 0x080000000, 0x0ffffffff, 2**53, -0, 1, Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-133180449*/count=90; tryItOut("mathy2 = (function(x, y) { return (((Math.min(Math.asin(( - y)), Math.fround(Math.hypot(Math.fround((Math.sin((( + Math.hypot(( + ( + (( + ((x >>> 0) | (x >>> 0))) ? ( + (x * y)) : ( + 0x07fffffff)))), ( + ( + mathy1(( + y), ( + x)))))) >>> 0)) >>> 0)), (Math.imul((x | 0), ((Math.sign(y) >>> 0) >>> 0)) | 0)))) >>> 0) < ((Math.hypot(((( - Math.hypot(Math.fround(( ! Number.MAX_VALUE)), Math.fround(Math.asin(Number.MIN_VALUE)))) | 0) >>> 0), (Math.max((0x100000001 >>> Math.fround(( ! -(2**53+2)))), x) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [Math.PI, 0/0, -0x100000001, 42, 1.7976931348623157e308, -0x100000000, -(2**53-2), -1/0, 0, -Number.MAX_VALUE, 0x080000001, -(2**53), -0, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, 0.000000000000001, 1/0, -0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, 0x0ffffffff, -(2**53+2), 0x100000000, 0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, Number.MAX_VALUE, 1, -Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=91; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return ( - ((( + (( - (( + ((Math.fround(( ~ -0x0ffffffff)) >> (x >>> 0)) >>> 0)) | 0)) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy3, [-0, 0x080000000, 0x100000000, 1, -Number.MAX_VALUE, 42, -0x07fffffff, -Number.MIN_VALUE, -0x100000000, -(2**53+2), -0x080000000, 2**53-2, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 0.000000000000001, 0x100000001, 0x080000001, 0x07fffffff, -(2**53), Math.PI, Number.MAX_VALUE, 0, -0x100000001, 1.7976931348623157e308, 2**53+2, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-133180449*/count=92; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=.{4,6}[^]*+?)?/g; var s = \"\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=93; tryItOut("mathy5 = (function(x, y) { return Math.clz32((Math.fround((y >>> 0)) - (Math.hypot(Math.acosh(y), (( + Math.sign(x)) | 0)) >>> 0))); }); testMathyFunction(mathy5, [0/0, 0.000000000000001, 0x100000000, 1/0, -0x080000000, Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53+2), -0x100000000, 2**53+2, -Number.MAX_VALUE, -0x07fffffff, 1, 42, 2**53-2, 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 2**53, -(2**53-2), 0x100000001, -Number.MIN_VALUE, 0]); ");
/*fuzzSeed-133180449*/count=94; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:\\\\b{1,}|(?=(?!(?![^\\\\u2cA9\\u4e2f\\\\x77\\u6969]))\\\\cZ?|(?!\\\\d))?)\", \"gyi\"); var s = \"00\"; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=95; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.atan(( + Math.imul(Math.fround(( ! Math.fround(( + Math.abs(y))))), ( - y))))); }); testMathyFunction(mathy5, /*MARR*/[(-1/0), false,  \"use strict\" , ({x:3}),  \"use strict\" , (-1/0), false, ({x:3}),  \"use strict\" ,  \"use strict\" , (-1/0), {}, {}, ({x:3}), false, ({x:3}),  \"use strict\" , (-1/0), (-1/0), false, ({x:3}), (-1/0), false,  \"use strict\" , ({x:3}), false, {}, {}, {}, ({x:3}), {}, {}, false,  \"use strict\" ,  \"use strict\" , false, ({x:3}), ({x:3}), {}, ({x:3}), false, ({x:3}), (-1/0)]); ");
/*fuzzSeed-133180449*/count=96; tryItOut("\"use strict\"; e1.has(i2);");
/*fuzzSeed-133180449*/count=97; tryItOut("mathy4 = (function(x, y) { return Math.sinh((Math.atan((mathy2((mathy3(y, Math.fround(( - Math.fround(1/0)))) | 0), (x | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy4, [Math.PI, -1/0, 0x080000000, -(2**53+2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 42, 0.000000000000001, -0x080000000, 1/0, 0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, 0x0ffffffff, -(2**53), -0x080000001, -0x0ffffffff, 2**53, 2**53+2, -Number.MAX_VALUE, 1, 2**53-2, Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-133180449*/count=98; tryItOut("/*oLoop*/for (var sgmrbj = 0, ucxkzl; sgmrbj < 53; ++sgmrbj) { g1.h2 = ({getOwnPropertyDescriptor: function(name) { m1 = new Map(m0);; var desc = Object.getOwnPropertyDescriptor(p0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g2.s0 += 'x';; var desc = Object.getPropertyDescriptor(p0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { m1.valueOf = f0;; Object.defineProperty(p0, name, desc); }, getOwnPropertyNames: function() { m0.__proto__ = e2;; return Object.getOwnPropertyNames(p0); }, delete: function(name) { print(t0);; return delete p0[name]; }, fix: function() { h2.enumerate = (function mcc_() { var brorcm = 0; return function() { ++brorcm; if (/*ICCD*/brorcm % 4 == 1) { dumpln('hit!'); try { for (var v of t1) { i0 = new Iterator(f0, true); } } catch(e0) { } try { v0 = g2.eval(\"-19\"); } catch(e1) { } try { for (var v of e2) { try { m0.get(f1); } catch(e0) { } try { v0 = Array.prototype.every.apply(a2, []); } catch(e1) { } for (var v of a1) { print(p0); } } } catch(e2) { } m0.has(a0); } else { dumpln('miss!'); for (var p in g2.b2) { try { v2 = (b1 instanceof b1); } catch(e0) { } try { print(uneval(f2)); } catch(e1) { } try { e1.has(v2); } catch(e2) { } Array.prototype.sort.call(a1, (function mcc_() { var gzmlqk = 0; return function() { ++gzmlqk; if (/*ICCD*/gzmlqk % 4 == 1) { dumpln('hit!'); try { a0.splice(NaN, 14); } catch(e0) { } try { t1.valueOf = (function() { for (var v of a1) { try { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  } catch(e0) { } a0.forEach((function(j) { if (j) { try { o0 = Object.create(e0); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(f2, e0); } catch(e1) { } try { o0.m2.has(s1); } catch(e2) { } let v1 = g0.runOffThreadScript(); } else { try { /*MXX1*/g0.o0 = g0.String.prototype.slice; } catch(e0) { } m1.set(i1, h0); } }), h0, h1, f2); } throw i2; }); } catch(e1) { } (void schedulegc(g1)); } else { dumpln('miss!'); try { print(o2.o0.g1.e2); } catch(e0) { } try { v0 = (s0 instanceof a0); } catch(e1) { } try { v0 = b1; } catch(e2) { } /*MXX3*/o0.g0.Int8Array.BYTES_PER_ELEMENT = g1.Int8Array.BYTES_PER_ELEMENT; } };})()); } } };})();; if (Object.isFrozen(p0)) { return Object.getOwnProperties(p0); } }, has: function(name) { Array.prototype.forEach.call(a0, (function() { for (var j=0;j<42;++j) { g2.f2(j%4==1); } }), f1, s1);; return name in p0; }, hasOwn: function(name) { v2 + '';; return Object.prototype.hasOwnProperty.call(p0, name); }, get: function(receiver, name) { g1.__proto__ = f2;; return p0[name]; }, set: function(receiver, name, val) { for (var v of f1) { v2 = g1.runOffThreadScript(); }; p0[name] = val; return true; }, iterate: function() { ;; return (function() { for (var name in p0) { yield name; } })(); }, enumerate: function() { s0.toString = (let (e=eval) e);; var result = []; for (var name in p0) { result.push(name); }; return result; }, keys: function() { return e0; return Object.keys(p0); } }); } ");
/*fuzzSeed-133180449*/count=99; tryItOut("\"use strict\"; e1 = g1.g0.objectEmulatingUndefined();/*MARR*/[[1], [(void 0)], x, [(void 0)], [1], [1], x, x, x, [1], x, [(void 0)], [1], [(void 0)], [1], x, [(void 0)], [(void 0)], x, [(void 0)], x, [1], [(void 0)], x, [(void 0)], x, [1], x, [(void 0)], [(void 0)], [(void 0)], [1], [1], [(void 0)], [1], [1], [(void 0)], x, x, [1], [(void 0)], [(void 0)], [(void 0)], x, [1]].filter(Object.prototype.__lookupSetter__) & new Function();");
/*fuzzSeed-133180449*/count=100; tryItOut("mathy1 = (function(x, y) { return ( + Math.atan2(Math.acosh((Math.atanh(( ! Math.atan2(x, ( + ( + (( + Math.hypot(Math.fround(x), x)) | 0)))))) | 0)), ( + (Math.pow(((( - (mathy0((( + Math.tanh(x)) | 0), ((2**53-2 + (((y | 0) & (mathy0(0/0, -0x080000000) | 0)) | 0)) | 0)) | 0)) | 0) | 0), (( - (Math.asinh((Math.atan((-(2**53+2) | 0)) | 0)) | 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-133180449*/count=101; tryItOut("a0[5] = s2;");
/*fuzzSeed-133180449*/count=102; tryItOut("m0.toSource = Date.prototype.getUTCHours;print(({}) = this >> -16);");
/*fuzzSeed-133180449*/count=103; tryItOut("mathy2 = (function(x, y) { return Math.atan2(( ! Math.sin(Math.fround(( + Math.exp((y >>> 0)))))), (Math.min((Math.abs((mathy1((Math.fround(((( - y) | 0) >>> 0)) >>> 0), ((-0x080000001 ? (Math.abs(x) | 0) : (Number.MAX_SAFE_INTEGER << y)) >>> 0)) >>> 0)) >>> 0), Math.imul(Math.min((((( + Math.tan(( + 2**53))) | 0) ^ ( ~ x)) | 0), (y | 0)), (x ? mathy1(y, Math.fround(Math.imul(Math.fround(Math.pow(x, y)), Math.fround(Math.fround((Math.fround(y) ? Math.fround(y) : Math.fround(x))))))) : -0x100000001))) | 0)); }); testMathyFunction(mathy2, [Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x0ffffffff, 2**53-2, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, 0.000000000000001, -0, -Number.MIN_VALUE, 42, -0x100000000, 2**53, Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, -0x100000001, -1/0, 1, Math.PI, 0x080000000, 0, -0x0ffffffff, 0x080000001, 0x100000001, -(2**53), -0x07fffffff]); ");
/*fuzzSeed-133180449*/count=104; tryItOut("\"use strict\"; print( /x/g );");
/*fuzzSeed-133180449*/count=105; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\2)+\", \"yi\"); var s = /([]\\1)/gym; print(s.replace(r, decodeURI, \"yim\")); ");
/*fuzzSeed-133180449*/count=106; tryItOut("g2.v2 = undefined;\n/*oLoop*/for (let dvcvre = 0, x = let (c)  /x/ , [, ] = \"\\uBB5C\"; (x) && dvcvre < 76; ++dvcvre) { a1.length = 1; } \nselectforgc(o0);");
/*fuzzSeed-133180449*/count=107; tryItOut("\"use strict\"; o2.i0.toSource = (function mcc_() { var vddbhn = 0; return function() { ++vddbhn; if (/*ICCD*/vddbhn % 10 == 2) { dumpln('hit!'); try { v2 = Object.prototype.isPrototypeOf.call(a2, b2); } catch(e0) { } try { s0.valueOf = (function() { try { g1.e2.has(o1); } catch(e0) { } try { v0 = t0.length; } catch(e1) { } try { a0[6] = x; } catch(e2) { } h1.toSource = this.f1; return g1; }); } catch(e1) { } try { /*MXX2*/g1.Error.stackTraceLimit = i2; } catch(e2) { } print(h2); } else { dumpln('miss!'); try { h1.fix = f0; } catch(e0) { } v2 = a2.some((function mcc_() { var dcntxr = 0; return function() { ++dcntxr; if (/*ICCD*/dcntxr % 4 == 0) { dumpln('hit!'); try { e2.add(e2); } catch(e0) { } t1[v1]; } else { dumpln('miss!'); v0 = Object.prototype.isPrototypeOf.call(m2, g0.h1); } };})()); } };})();");
/*fuzzSeed-133180449*/count=108; tryItOut("m1.get(i1);");
/*fuzzSeed-133180449*/count=109; tryItOut("s1 += s2;");
/*fuzzSeed-133180449*/count=110; tryItOut("m1.has(v2);\n(void schedulegc(g0));\n");
/*fuzzSeed-133180449*/count=111; tryItOut("\"use strict\"; v1 = evaluate(\"mathy5 = (function(x, y) { \\\"use strict\\\"; \\\"use asm\\\"; return ( + (( + ( - Math.pow(Math.atan2((( + y) ? ( + x) : y), ( - Math.tanh(y))), (Math.tanh((y | 0)) | 0)))) <= ( + ( - ( + ( ~ ( + ( + (( + (Math.expm1(((-0x07fffffff ? y : -0x080000001) | 0)) | 0)) != ( + Math.imul(( ! (2**53+2 >>> 0)), 1))))))))))); }); testMathyFunction(mathy5, [0.000000000000001, 1.7976931348623157e308, -(2**53-2), -(2**53), -(2**53+2), 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, 0, 0x100000001, 0/0, 1, -0x080000000, 0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, 1/0, 2**53+2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, 0x080000001, -0x100000000, -0x07fffffff, Number.MIN_VALUE, 42, 0x0ffffffff, Math.PI, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0]); \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 4 != 1), noScriptRval: new RegExp(\"\\\\3\", \"\") instanceof \"\\u22BA\", sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-133180449*/count=112; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(e0, \"__count__\", { configurable: (x % 6 == 5), enumerable: true, writable: true, value: o2 });");
/*fuzzSeed-133180449*/count=113; tryItOut("f1.toSource = (function() { try { v2 = evalcx(\"\\n/*RXUE*//(?:(?:\\\\1))/m.exec(\\\"\\\")\\u000c.__defineSetter__(\\\"z\\\", decodeURIComponent)\", this.g1); } catch(e0) { } try { v1 = a1.length; } catch(e1) { } try { this.f1 = f0; } catch(e2) { } for (var p in g1) { try { Object.defineProperty(this, \"this.v1\", { configurable: (x % 4 == 2), enumerable: true,  get: function() {  return g0.runOffThreadScript(); } }); } catch(e0) { } try { v1 = a1.every((function() { for (var j=0;j<36;++j) { f2(j%4==0); } })); } catch(e1) { } i2.next(); } return m2; });");
/*fuzzSeed-133180449*/count=114; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return ((-(0xfe032d30)))|0;\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy1, ['0', ({valueOf:function(){return 0;}}), (function(){return 0;}), '/0/', false, (new Number(-0)), 0.1, [], ({toString:function(){return '0';}}), undefined, NaN, 1, objectEmulatingUndefined(), '', /0/, 0, (new Number(0)), -0, [0], null, (new String('')), ({valueOf:function(){return '0';}}), (new Boolean(false)), true, (new Boolean(true)), '\\0']); ");
/*fuzzSeed-133180449*/count=115; tryItOut("\"use strict\"; e1.delete(this.t1);");
/*fuzzSeed-133180449*/count=116; tryItOut("/*hhh*/function lssrtu(e = ((4277).watch(\"call\"\u0009, Function)), c, ...x){for(var x = true in Math.max(-25, null)) {s0 = ''; }}lssrtu(/*FARR*/[x, ((window)) = x, Math.cbrt(2**53), (yield ({}) = new (window)(({a1:1}), new RegExp(\"(?!\\\\1)*?|\\\\b|(?!$*){131071}\", \"yi\")))(x, x), /(?:[\ufef1]|.*?\u8b5f{2,4})|(?=(([^])))*/y.throw\u000c(((void shapeOf((void options('strict')))))), this %= /\\u00Db|(?!(?!$)\\D{3,})+?|(?:[^]|(?:[\\r-\u00c2])+)/, .../*MARR*/[objectEmulatingUndefined(), -0x100000001, -0x100000001, -0x100000001, objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000001, -0x100000001, -0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000001], .../*FARR*/[...new Array(-25), .../*MARR*/[(x && e)], x, (4277), x = (4277), ({ get __lookupGetter__ e (d, x, x, \u3056 = this, e, x, z, x = e, eval, x = \"\\u98C4\", x, x, window, eval, c, x, y, /\\1/ym = \"\\u6428\", x = new RegExp(\"\\\\1\\\\2*?\\\\2{0,}\", \"y\"), x, e, e, x, x =  \"\" , d, eval, x, c, \u3056 = x, x, NaN, x, x, z, e =  /x/g , x =  /x/g , x, b, y, NaN, x, MAX_VALUE, this.x, c = 27, x, \u3056, x, x, w, x, z, x, c, x, d, e, x, d, x, c, this.x, b, w, x, y, get, eval, a = null, d, b, c, eval, a = \"\\u8908\", x, y, x, \u3056 = this, c =  /x/g , a = [[1]], \u3056, NaN =  /x/g , y, NaN, x, x, window, y, x, x, d, x, \u3056, x, this.y, e, c, b, x, x) { return (4277) }  }), .../*MARR*/[Infinity, false, Infinity, Infinity, this, false, this, this, Infinity, false, this, false, Infinity, this, false, this, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, this, Infinity, this, this, false, Infinity, false, Infinity, this, this, false, false, Infinity, this, this, this, false, false, this, false, this, Infinity, false, this, false, this, this, this, false, false, false, false, this, this, false, this, false, Infinity, false]], , .../*FARR*/[], , ].filter(/*wrap2*/(function(){ var hfnjmm = x; var oizcvy = function  hfnjmm (c)\"use asm\";   var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+abs(((Float64ArrayView[1]))));\n    i1 = (1);\n    i1 = (0xf90b3a85);\n    {\n      {\n        i1 = (1);\n      }\n    }\n    return +((-536870913.0));\n  }\n  return f;; return oizcvy;})(), function(id) { return id }));");
/*fuzzSeed-133180449*/count=117; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(s.replace(r, (x = -((p={}, (p.z = (p={}, (p.z = delete \u3056.c)()))()))) => \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.888946593147858e+22;\n    return +((d1));\n  }\n  return f;)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=118; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((((Math.pow((( ~ ( ! ( ! -0x100000000))) >>> 0), Math.fround(Math.atan2(Math.fround(mathy2(x, Math.sign(-0x0ffffffff))), Math.fround(x)))) ? Math.atan2(mathy2((y | 0), ((x && x) >>> 0)), (x & x)) : Math.fround(( - Math.fround(( + (( + y) ** ( + 1.7976931348623157e308))))))) | 0) ? (Math.fround(( - Math.fround(( ! Math.sqrt(Math.fround(Math.trunc(( + Math.max(( + x), ( + y)))))))))) | 0) : (Math.cos(( + ( + Math.fround(mathy4(Math.fround(x), Math.fround(y)))))) | 0)) | 0); }); testMathyFunction(mathy5, [0/0, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, -(2**53), -0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 2**53, 1/0, 0x080000000, 0, 42, Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, -1/0, -(2**53+2), -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, 2**53-2, 1.7976931348623157e308, -0x080000000, 0x080000001, -0x100000001, 0x100000001, -Number.MAX_VALUE, 1, 0x07fffffff, 0x0ffffffff, 2**53+2]); ");
/*fuzzSeed-133180449*/count=119; tryItOut("g1.v1 = evaluate(\"v0 = g1.eval(\\\"/* no regression tests found */\\\");\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 46 != 41), noScriptRval: (x % 23 != 22), sourceIsLazy: true, catchTermination: Math.fround(Math.cbrt(x)) }));");
/*fuzzSeed-133180449*/count=120; tryItOut("\"use strict\"; i0.__proto__ = o2;");
/*fuzzSeed-133180449*/count=121; tryItOut("this.s0 += g2.s1;");
/*fuzzSeed-133180449*/count=122; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[-Number.MAX_VALUE, [], [], [], -Number.MAX_VALUE, .2, [], [], -Number.MAX_VALUE, [], .2, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, [], [], .2, .2, .2, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, [], [], -Number.MAX_VALUE, [], -Number.MAX_VALUE, .2, -Number.MAX_VALUE, .2, -Number.MAX_VALUE, [], -Number.MAX_VALUE, -Number.MAX_VALUE, .2, [], .2, []]) { print(uneval(b2)); }");
/*fuzzSeed-133180449*/count=123; tryItOut("a1 + o0.p2;");
/*fuzzSeed-133180449*/count=124; tryItOut("\"use strict\"; v0 = (h1 instanceof m2);");
/*fuzzSeed-133180449*/count=125; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.round(( + (( - ( + Math.pow(y, x))) && ((( + (y > Math.fround((Math.fround((0x100000001 ** x)) === Math.fround(-0x100000001))))) - (mathy1(( + (( + Math.fround((-Number.MAX_VALUE , Math.fround(Number.MIN_SAFE_INTEGER)))) , ( + ( - Math.fround(x))))), ( ! ( + Math.sign(y)))) >>> 0)) | 0))))); }); testMathyFunction(mathy2, [0/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -1/0, Math.PI, -0x07fffffff, 0, 2**53-2, 0x080000001, Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), -0x100000001, 42, 2**53+2, 0x080000000, 0.000000000000001, -0x080000000, -Number.MAX_VALUE, 0x0ffffffff, 0x100000001, -0, -Number.MIN_VALUE, Number.MAX_VALUE, 1/0, 0x07fffffff, -(2**53), -0x100000000, 1, 2**53]); ");
/*fuzzSeed-133180449*/count=126; tryItOut("mathy1 = (function(x, y) { return ((Math.acos((Math.atan2((x >>> 0), ( + 2**53)) | 0)) | 0) - (Math.exp((( - y) | 0)) >>> 0)); }); testMathyFunction(mathy1, [-0, -Number.MAX_VALUE, 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, 1, -(2**53-2), -(2**53+2), -0x100000001, -1/0, 1.7976931348623157e308, -0x07fffffff, 2**53, 1/0, -0x080000000, 0x100000000, 2**53-2, 0, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, 0x080000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_VALUE, 42, 0x080000000, -0x0ffffffff, -(2**53), 0.000000000000001, Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=127; tryItOut("/*infloop*/while(encodeURIComponent){print(b2);v1 = t0.length; }");
/*fuzzSeed-133180449*/count=128; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=129; tryItOut("/*MXX1*/o1 = g0.g1.RegExp.lastMatch;");
/*fuzzSeed-133180449*/count=130; tryItOut("/*infloop*/for(var x = \"\u03a0\"; (4277); x) {print((-1775631814.5\n));print(x); }");
/*fuzzSeed-133180449*/count=131; tryItOut("f1.__proto__ = p2;");
/*fuzzSeed-133180449*/count=132; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\n|[^\\\\w\\\\cA-\\\\xa1\\\\cH-\\u00f2]*\\\\w{4,7}|(.*)(?!\\\\B|.)?\", \"gy\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-133180449*/count=133; tryItOut("a1.unshift(i1, o2.b0);");
/*fuzzSeed-133180449*/count=134; tryItOut(" for (let w of window) /*RXUB*/var r = new RegExp(\"(?!.)\", \"\"); var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=135; tryItOut("i1.send(g0);print(uneval(v1));");
/*fuzzSeed-133180449*/count=136; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.pow(Math.fround((Math.fround(Math.hypot(Math.fround(y), Math.fround(( ! Math.imul(( + y), ( + x)))))) + ( + ( ! 0x0ffffffff)))), ( + ( - ( + x)))) << Math.fround(( - Math.fround(Math.fround(mathy0(Math.fround(((Math.atan2(y, x) | 0) % 0.000000000000001)), Math.fround(Math.hypot(x, ( + (((Math.max(y, y) | 0) | 0) ? ((Math.max((x | 0), Math.fround(x)) | 0) | 0) : (((y <= (Math.fround(Math.atan2(y, (y >>> 0))) | 0)) | 0) | 0))))))))))); }); testMathyFunction(mathy1, [42, -Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, 2**53+2, -0x100000001, 2**53, 1, -(2**53+2), 1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 0, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, 0x080000000, -0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, -0x07fffffff, 0x07fffffff, -(2**53), 0x100000001, -(2**53-2), 0/0, 0.000000000000001]); ");
/*fuzzSeed-133180449*/count=137; tryItOut("\"use strict\"; for(let x in []);");
/*fuzzSeed-133180449*/count=138; tryItOut("\"use strict\"; xkjmpp();/*hhh*/function xkjmpp(x = ((makeFinalizeObserver('nursery'))), x){p2 + '';}");
/*fuzzSeed-133180449*/count=139; tryItOut("print(o1.m2);");
/*fuzzSeed-133180449*/count=140; tryItOut("let (window = (4277)) { print(x); }");
/*fuzzSeed-133180449*/count=141; tryItOut("\"use strict\"; /*hhh*/function yrnufn(){print('fafafa'.replace(/a/g, mathy3));/*bLoop*/for (owufwj = 0, /[^]{0}/; owufwj < 3; ++owufwj) { if (owufwj % 2 == 1) { print(eval); } else { (\"\\uF960\"); }  } }yrnufn\u000c((/*UUV1*/(a.has = (void options('strict_mode')))), x.__defineSetter__(\"x\", mathy2));");
/*fuzzSeed-133180449*/count=142; tryItOut("\"use strict\"; a2.reverse();");
/*fuzzSeed-133180449*/count=143; tryItOut("t0 + '';");
/*fuzzSeed-133180449*/count=144; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var sqrt = stdlib.Math.sqrt;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 4503599627370496.0;\n    var d4 = -8796093022209.0;\n    return ((((0xff79b291) ? (i2) : ((d3) == (1.5474250491067253e+26)))))|0;\n    d4 = (+/*FFI*/ff(((-1.125)), ((imul((i2), (0xffffffff))|0)), ((d4))));\n    return ((-0xdc749*(0x580e3283)))|0;\n    d0 = (d4);\n    i1 = (i2);\n    return ((((((!(/*FFI*/ff(((((/*FFI*/ff(((((0xc094cf93)) >> ((0xfbb9750b)))), ((-2199023255553.0)), ((1.5474250491067253e+26)), ((268435457.0)), ((-137438953473.0)), ((8193.0)))|0)) | (((0xf9854200) ? (0xb231c7a3) : (0xfe658a2a))))))|0)))>>>(((0x0)))))-(-0x8000000)))|0;\n    ((x ? ((x * ( + x)) >>> 0) : (x || -0x100000000))) = ((d4));\n    {\n      {\n        d0 = (+sqrt((((i1)))));\n      }\n    }\n    i1 = ((a =  \"\" ) < (((0xa5982424)) | ((!(0xe7d1264f))-(i2))));\n    i2 = (!(!(0x399be083)));\n    {\n      d0 = (3.777893186295716e+22);\n    }\n    switch ((imul((0x235eccce), (/*FFI*/ff(((+((1.5)))))|0))|0)) {\n      case -3:\n        {\n          (/*UUV1*/(e.trim = ArrayBuffer.prototype.slice)) = ((-((((d3)) * (((/*FFI*/ff(((d4)))|0) ? (-2.4178516392292583e+24) : (+(-1.0/0.0))))))));\n        }\n      default:\n        {\n          {\n            {\n              return (((((((4277))+((0x4be985fa) < (abs((x\n))|0)))>>>(((((0xffffffff))>>>((0xfd6f54c9))) > (0x0))+(!((0xffffffff) > (((0x3b9fff48))>>>((0xfd3ba07c)))))+(i1))))-(((((imul((0xfe6be5c2), (0xd2a22bc2))|0) % (((0xf926513c)) & ((0x29d7765)))) & ((0xffffffff)-(/*FFI*/ff()|0)+((0xa21107f6) < (0x9ba17542))))) ? (-0x8000000) : (i1))))|0;\n            }\n          }\n        }\n    }\n    return (((0xffffffff)))|0;\n  }\n  return f; })(this, {ff: function shapeyConstructor(nuflfb){delete this[\"prototype\"];{ (4277); } { this.v0 = r1.exec; } return this; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0/0, 1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, -0, 1, -0x080000001, 0x07fffffff, 0.000000000000001, -(2**53-2), -0x080000000, -(2**53+2), -0x100000001, 0x080000001, 0x100000001, -0x0ffffffff, 0x100000000, Math.PI, -(2**53), 0, -1/0, 1.7976931348623157e308, 2**53-2, 0x0ffffffff, -0x07fffffff, 2**53+2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42]); ");
/*fuzzSeed-133180449*/count=145; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=146; tryItOut("g1.v1 = this.g2.runOffThreadScript();");
/*fuzzSeed-133180449*/count=147; tryItOut("e1.add(s1);");
/*fuzzSeed-133180449*/count=148; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=149; tryItOut("g2.h1.get = f2;");
/*fuzzSeed-133180449*/count=150; tryItOut("mathy1 = (function(x, y) { return (( + ( + (( + Math.atanh(Math.min(mathy0(Number.MIN_VALUE, Math.pow(Number.MIN_SAFE_INTEGER, y)), (Math.fround(Math.sqrt(0x100000001)) + y)))) ^ (Math.exp((x >>> 0)) | 0)))) | 0); }); testMathyFunction(mathy1, /*MARR*/[false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, false, objectEmulatingUndefined(), new String('q'), false, false, false, new String('q'), false, false, false]); ");
/*fuzzSeed-133180449*/count=151; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.min(Math.round(y), (Math.pow(Math.fround(x), ( + ( - y))) ? ((y >>> 0) << ((( ~ ((( ! (mathy0((y >>> 0), -Number.MAX_VALUE) >>> 0)) >>> 0) | 0)) | 0) | 0)) : ( + Math.min(( + -0x080000000), ( + Math.max(( + Math.fround((Math.fround(0x080000000) && Math.fround(Math.imul((-0x080000000 | 0), Number.MAX_VALUE))))), x))))))) >>> 0) || Math.log1p(( + Math.atanh(( + y))))) >>> 0); }); testMathyFunction(mathy4, [42, -(2**53-2), -1/0, -(2**53), -Number.MIN_SAFE_INTEGER, -0, 1, 0x080000001, -0x0ffffffff, -0x100000000, Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, 0/0, 0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, -0x07fffffff, 0x080000000, Math.PI, 0.000000000000001, -0x080000000, 1.7976931348623157e308, 2**53-2, -(2**53+2), 2**53+2, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 0, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0]); ");
/*fuzzSeed-133180449*/count=152; tryItOut("testMathyFunction(mathy0, [undefined, (new Boolean(true)), ({valueOf:function(){return 0;}}), null, (new Boolean(false)), (new Number(0)), '', (new String('')), NaN, -0, 1, objectEmulatingUndefined(), ({toString:function(){return '0';}}), [0], true, '\\0', 0, /0/, false, [], (new Number(-0)), 0.1, '0', (function(){return 0;}), '/0/', ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-133180449*/count=153; tryItOut("mathy0 = (function(x, y) { return ((Math.hypot(Math.fround(Math.tanh(Math.fround(y))), (Math.acosh((Math.hypot(-0, ( ~ Math.atan2(( + x), ( + Math.min(y, x))))) | 0)) >>> 0)) === (( + (Math.fround(Math.fround(( - Math.fround((Math.acosh((( - ( + 0x07fffffff)) | 0)) | 0))))) ? Math.fround(Math.atan2(Math.log2((x | 0)), ((Math.atan2(y, Math.min((y ? Math.cosh((x >>> 0)) : x), x)) >>> 0) | 0))) : Math.fround(((((Math.fround(Math.abs(Math.fround(Math.log(x)))) >>> 0) & (Math.imul((-(2**53-2) | 0), (((x >>> 0) ? 0x100000000 : (y >>> 0)) >>> 0)) >>> 0)) >>> 0) || ( + Math.imul((x | 0), (Math.imul(x, (((0x07fffffff >>> 0) / x) >>> 0)) | 0))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-1/0, 42, 2**53-2, 0x100000001, 0x100000000, 0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, 1.7976931348623157e308, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, -0x080000001, 2**53, Number.MAX_VALUE, -(2**53), 2**53+2, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 1, Math.PI, -0x0ffffffff, Number.MIN_VALUE, 1/0, 0/0, -0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=154; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=155; tryItOut("a1.forEach(f1);");
/*fuzzSeed-133180449*/count=156; tryItOut("mathy5 = (function(x, y) { return mathy1((mathy0(Math.fround(Math.min(((( + (Math.fround(Math.imul(Math.fround(y), Math.fround(Math.min((x | 0), y)))) ^ ( + x))) ? (Math.hypot((-(2**53) >>> 0), (x >>> 0)) >>> 0) : Number.MAX_SAFE_INTEGER) >>> 0), mathy1(Math.trunc(y), (Math.fround(Math.tan(0x07fffffff)) < x)))), ( + Math.log10(( + Math.abs(( + y)))))) >>> 0), ((Math.max((( + ( ~ ( + -0x07fffffff))) >>> 0), ((( + Math.max((y | 0), Math.fround(Math.hypot(Math.cos(y), x)))) << x) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0x080000000, Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000001, -0x100000000, 2**53+2, -0x0ffffffff, 0.000000000000001, 1/0, Number.MAX_VALUE, -0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000001, 42, 0x07fffffff, 0/0, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, -(2**53+2), 2**53-2, -Number.MIN_VALUE, 1, -0, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53, 0, -Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=157; tryItOut("h2 = ({getOwnPropertyDescriptor: function(name) { this.t2.set(a2, let (x = \u3056, eval = (4277), NaN, x, z, x, NaN, window) false().toString((w) = undefined, this));; var desc = Object.getOwnPropertyDescriptor(g0.a2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { throw g0; var desc = Object.getPropertyDescriptor(g0.a2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { p2 = g2.objectEmulatingUndefined();; Object.defineProperty(g0.a2, name, desc); }, getOwnPropertyNames: function() { return e1; return Object.getOwnPropertyNames(g0.a2); }, delete: function(name) { o1.t2[1] = this.s1;; return delete g0.a2[name]; }, fix: function() { v0 = (e1 instanceof o2.o0);; if (Object.isFrozen(g0.a2)) { return Object.getOwnProperties(g0.a2); } }, has: function(name) { e2.add(v2);; return name in g0.a2; }, hasOwn: function(name) { m2 = new Map(f2);; return Object.prototype.hasOwnProperty.call(g0.a2, name); }, get: function(receiver, name) { v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: this.__defineGetter__(\"b\", Math.acosh), sourceIsLazy: false, catchTermination: true }));; return g0.a2[name]; }, set: function(receiver, name, val) { o1 = Object.create(p0);; g0.a2[name] = val; return true; }, iterate: function() { s0 += s0;; return (function() { for (var name in g0.a2) { yield name; } })(); }, enumerate: function() { /*ADP-3*/Object.defineProperty(a0, window, { configurable: (x % 16 != 4), enumerable: (x % 3 != 1), writable: true, value: g0 });; var result = []; for (var name in g0.a2) { result.push(name); }; return result; }, keys: function() { v2 = a1.length;; return Object.keys(g0.a2); } });");
/*fuzzSeed-133180449*/count=158; tryItOut("\"use strict\"; ;");
/*fuzzSeed-133180449*/count=159; tryItOut("\"use strict\"; let v1 = g0.runOffThreadScript();");
/*fuzzSeed-133180449*/count=160; tryItOut("i0 = e2.values;");
/*fuzzSeed-133180449*/count=161; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-1/0, -0x100000001, -Number.MAX_VALUE, 2**53, -0x100000000, -(2**53-2), 2**53-2, 0x07fffffff, 0x080000001, -0x080000000, -0, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), 0x0ffffffff, -(2**53+2), -0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0, Number.MIN_VALUE, 0x100000001, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 2**53+2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 1, 0, 1/0]); ");
/*fuzzSeed-133180449*/count=162; tryItOut("print(x);");
/*fuzzSeed-133180449*/count=163; tryItOut("v1.__proto__ = b2;");
/*fuzzSeed-133180449*/count=164; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.asin(Math.fround((((Math.fround(Math.exp(Math.fround(( + (( + y) + x))))) , -0x100000001) | 0) | mathy0(((( ! (Math.atan2(y, x) >>> 0)) >>> 0) + Math.log((Math.pow(( + x), ( + x)) >>> 0))), ( - (mathy4(0x100000000, (((Number.MIN_VALUE | 0) ? Math.fround(x) : (y | 0)) | 0)) < (Math.ceil(x) >>> 0))))))) | 0); }); ");
/*fuzzSeed-133180449*/count=165; tryItOut("mathy1 = (function(x, y) { return ( + Math.log(( + (Math.cbrt((Math.tan(Math.fround(( + ( + ( + (y , x)))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -(2**53), 1/0, 2**53-2, 0, 0x100000000, 0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0x07fffffff, 42, -0x100000001, Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, 1, -(2**53+2), 2**53, 2**53+2, -0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, -0x100000000, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, 0x0ffffffff, -0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-133180449*/count=166; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.min(mathy0((Math.cos(y) >= y), ( - Math.abs((Math.fround(mathy0(x, x)) - Math.fround(x))))), ( + mathy0(Math.fround(y), Math.fround(Math.imul(x, y))))) ? ( + (Math.sign(((Math.atan2(x, (Math.imul((Math.clz32(y) | 0), (y | 0)) | 0)) >>> 0) | 0)) | 0)) : ((Math.fround(Math.sin(( + Math.pow(Math.fround(Math.imul((Number.MIN_VALUE | 0), y)), Math.fround(Math.fround(( ~ Math.fround(x)))))))) ? (( + ( ~ ( + y))) >>> 0) : Math.fround(Math.atan(((((( ~ (x | 0)) | 0) | 0) != (((y || x) >>> 0) | 0)) | 0)))) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[ 'A' , x, x, x, x, x, x, x, x,  'A' , x, function(){}, function(){}, new Number(1), new Number(1), new String('q'), new Number(1), new Number(1)]); ");
/*fuzzSeed-133180449*/count=167; tryItOut("\"use strict\"; v1 = evalcx(\"function f0(p0)  { \\\"use strict\\\"; { if (isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; } } \", g1);");
/*fuzzSeed-133180449*/count=168; tryItOut("\"use strict\"; i0.send(i0);");
/*fuzzSeed-133180449*/count=169; tryItOut("v0 = t1[v0];");
/*fuzzSeed-133180449*/count=170; tryItOut("{ void 0; selectforgc(this); }");
/*fuzzSeed-133180449*/count=171; tryItOut("var r0 = x % x; var r1 = x * r0; var r2 = r1 & r0; ");
/*fuzzSeed-133180449*/count=172; tryItOut(";");
/*fuzzSeed-133180449*/count=173; tryItOut("\"use asm\"; selectforgc(o1);");
/*fuzzSeed-133180449*/count=174; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=175; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(b1, \"__count__\", ({enumerable: true}));");
/*fuzzSeed-133180449*/count=176; tryItOut("var [] = (4277) *= (RegExp = (window |= /((?!M(?:[\u0014]|\\B)[^]+?)){2}/ym)), z = new Int16Array()\u000c.cbrt((4277)), wcimgs, x, x = \"\\u734A\", x, x, dcunwn;m2.has(p2);");
/*fuzzSeed-133180449*/count=177; tryItOut("/*vLoop*/for (let lskssa = 0; ((4277)) && lskssa < 52; ++lskssa) { x = lskssa; m2.has(t2); } ");
/*fuzzSeed-133180449*/count=178; tryItOut("\"use strict\"; /*hhh*/function uspjzh(eval){print(x);}/*iii*/o0.m2.get(g1);");
/*fuzzSeed-133180449*/count=179; tryItOut("if((new (b => \"use asm\";   var imul = stdlib.Math.imul;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 17592186044417.0;\n    d1 = (+(-1.0/0.0));\n    return ((((4277))-(-0x8000000)-((imul((1), (((((-9007199254740992.0) <= (9007199254740991.0)))>>>(eval % -14))))|0) > (imul((0xb1ce7b2), ((((0xfbb23afc)-(0xf3ff001)) & ((0xa49bbc7e)+(0xa172ca13)-(0x4b3c7f83)))))|0))))|0;\n  }\n  return f;)())) {(x);Array.prototype.push.apply(a1, [p2]); } else const c;1e-81;");
/*fuzzSeed-133180449*/count=180; tryItOut("e0.valueOf = (function(j) { if (j) { try { m2.set(o1, e0); } catch(e0) { } try { /*RXUB*/var r = g2.r0; var s = s0; print(s.search(r));  } catch(e1) { } try { let v0 = evaluate(\"a1[6] = t1;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 != 5), noScriptRval: true, sourceIsLazy: (x % 4 == 2), catchTermination: true, elementAttributeName: s0, sourceMapURL: s0 })); } catch(e2) { } this.a2[o2.o0.v0] = (4277); } else { try { m0.delete(i0); } catch(e0) { } try { this.h0.has = f1; } catch(e1) { } this.o0.m2.get(v1); } });");
/*fuzzSeed-133180449*/count=181; tryItOut("e2 + o0.b1;");
/*fuzzSeed-133180449*/count=182; tryItOut("/*RXUB*/var r = /(?!$)/gy; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-133180449*/count=183; tryItOut("v2 = evalcx(\"(4277)\", g0);");
/*fuzzSeed-133180449*/count=184; tryItOut("\"use strict\"; var a0 = [];");
/*fuzzSeed-133180449*/count=185; tryItOut("");
/*fuzzSeed-133180449*/count=186; tryItOut("a0[v0];");
/*fuzzSeed-133180449*/count=187; tryItOut("L: -x;");
/*fuzzSeed-133180449*/count=188; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+((d1)));\n    d1 = (d1);\n    return (((0x3de7e627)))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; true;; yield y; }}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=189; tryItOut("\"use strict\"; /*RXUB*/var r = /\\2/im; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-133180449*/count=190; tryItOut("\"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (i0);\n    {\n      (Int8ArrayView[2]) = (-(/*FFI*/ff(((((i0)) >> (((abs((((0x83282ad6)+(0xffdc4b5f)) << ((4277))))|0) >= (((i0)+((0x9cfb1110) == (0xffffffff))) << ((0xcb0ed817)-(0xffffffff)-(-0x8000000))))))), ((((-274877906945.0)) * ((Float32ArrayView[4096])))))|0));\n    }\n    return +((-16777215.0));\n  }\n  return f; })(this, {ff: -22.__defineGetter__(\"x\", q => q)}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x100000000, -0, -0x080000001, Number.MIN_VALUE, 0, -(2**53+2), 0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, 1/0, 0/0, 0x07fffffff, -0x07fffffff, 0.000000000000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 42, -(2**53), -(2**53-2), 2**53+2, -Number.MAX_VALUE, -0x080000000, 1, -0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, Number.MAX_VALUE, 1.7976931348623157e308, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 2**53]); ");
/*fuzzSeed-133180449*/count=191; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.expm1(( + Math.hypot((Math.hypot((Math.log1p(x) >>> 0), ((( - Math.fround((Math.fround(Math.ceil(Math.fround(-0x080000000))) & Math.fround(Math.log2(-(2**53+2)))))) | 0) >>> 0)) >>> 0), ((( + ( ! ( + 0x0ffffffff))) / Math.fround(((( + ( - ( + (( ~ (x | 0)) | 0)))) % Math.fround(Math.log10(x))) ? x : (( + y) >>> 0)))) >>> 0)))) | 0); }); testMathyFunction(mathy4, [0, 0x080000000, 0x100000001, -0, Math.PI, Number.MAX_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, -Number.MIN_VALUE, -1/0, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), -0x100000000, 1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), -0x0ffffffff, 42, 2**53+2, 1.7976931348623157e308, 0/0, 0.000000000000001, -Number.MAX_VALUE, 2**53, -0x100000001, 1, -0x080000000, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=192; tryItOut("a2.forEach(p1);");
/*fuzzSeed-133180449*/count=193; tryItOut("testMathyFunction(mathy4, [-0x100000000, -0x080000000, 42, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, 1.7976931348623157e308, -0, 2**53, -(2**53), 0x080000000, -1/0, 0x100000001, -(2**53-2), -Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, 1, 0x080000001, 0/0, 0, -0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 1/0, -0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=194; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=195; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    switch ((0x2a11862d)) {\n      case -1:\n        i1 = ((((0xfc4bbd14))>>>(-(0xe6c51427))) > (0x292512ed));\n      case 1:\n        (Int8ArrayView[((abs((((!(0x2b18b4ff))) ^ ((0x2a416daa) / (0x0))))|0) / (~~(+(0.0/0.0)))) >> 0]) = ((i1)+(0x4e3e86d3));\n        break;\n      case -2:\n        (Uint8ArrayView[(((i1))-(0xf6a51d71)) >> 0]) = ((((((0x91db0844) % (0xffffffff))|0) % (((0x2d092aa1) % (0x467547c2)) >> ((/*FFI*/ff(((1048577.0)), ((73786976294838210000.0)))|0)+(i1)))) ^ ((Int8ArrayView[((Float32ArrayView[1])) >> 0]))) % (imul(((((0x6b605461) / (0x624891d5)) | ((0xfbd98b01)+((0x5e027d4b)))) == ((((1.5) == (-576460752303423500.0))-(i1)) | ((0x220c52d0) / (0x464ce49)))), (0xa8c6d11c))|0));\n        break;\n      case 0:\n        d0 = ((i1) ? (+/*FFI*/ff(((0x5940e0b9)), ((-3.8685626227668134e+25)), ((144115188075855870.0)))) : (d0));\n        break;\n      case 0:\n        {\n          return +((d0));\n        }\n        break;\n      case -1:\n        return +((-((+atan2((((d0) + (3.777893186295716e+22))), ((+((2147483649.0)))))))));\n        break;\n      case 0:\n        d0 = (-7.737125245533627e+25);\n        break;\n      case -3:\n        {\n          d0 = (((-4097.0)) / ((-8388609.0)));\n        }\n        break;\n      case -1:\n        d0 = (/*FARR*/[ \"\" , ...[], x].some(false));\n        break;\n      case -3:\n        (Float64ArrayView[0]) = ((Float64ArrayView[((i1)) >> 3]));\n      case -3:\n        (Uint32ArrayView[((0x82e466b7)*-0x26091) >> 2]) = ((i1)+(/*FFI*/ff(((-65.0)))|0)-(i1));\n      default:\n        (Float64ArrayView[(((0xf8dbbf29) ? (i1) : ((i1)))) >> 3]) = ((d0));\n    }\n    i1 = (-0x8000000);\n    {\n      d0 = (d0);\n    }\n    i1 = ((~~(-7.737125245533627e+25)) < (0x7fffffff));\n    return +((+sqrt(((+(0.0/0.0))))));\n  }\n  return f; })(this, {ff: Function}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000001, Math.PI, 0x100000001, -(2**53), 0.000000000000001, 2**53-2, 1.7976931348623157e308, 0x07fffffff, -0x0ffffffff, -0x080000001, 0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 1, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, -0x07fffffff, 42, 2**53+2, -0x100000000, Number.MIN_VALUE, -(2**53+2), 0, 1/0, -0x080000000, 0/0, 0x0ffffffff, -0, 2**53, -1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=196; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +(new ((mathy3).call)(x));\n  }\n  return f; })(this, {ff: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function shapeyConstructor(lcemoj){\"use strict\"; Object.seal(this);Object.defineProperty(this, \"round\", ({configurable: this}));for (var ytqctvubr in this) { }for (var ytqaoasdd in this) { }return this; }, has: undefined, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: String.prototype.charCodeAt, keys: function() { return []; }, }; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-0, '/0/', 1, 0, (new Boolean(true)), true, (new Number(0)), /0/, ({toString:function(){return '0';}}), undefined, ({valueOf:function(){return 0;}}), [], NaN, '0', (new Number(-0)), '\\0', (new Boolean(false)), (new String('')), (function(){return 0;}), '', ({valueOf:function(){return '0';}}), false, null, 0.1, objectEmulatingUndefined(), [0]]); ");
/*fuzzSeed-133180449*/count=197; tryItOut("print(x);");
/*fuzzSeed-133180449*/count=198; tryItOut("L:switch(this.__defineGetter__(\"w\", decodeURIComponent)) { case 8:  }");
/*fuzzSeed-133180449*/count=199; tryItOut("\"use strict\"; Array.prototype.push.call(a1, f1, v1, this.s0);");
/*fuzzSeed-133180449*/count=200; tryItOut("this.e1.has(g1);");
/*fuzzSeed-133180449*/count=201; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return ( ! (((((mathy1(( + Number.MAX_SAFE_INTEGER), var r0 = 3 - x; x = x * y; var r1 = r0 & r0; var r2 = r0 / 3; r0 = 1 * r0; x = x & y; ) >>> 0) >>> ( - Math.pow(( + 2**53), (x | 0)))) | 0) || ((Math.fround(0) == y) | 0)) | 0)); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, 0x100000000, 1/0, 1.7976931348623157e308, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, -(2**53-2), 2**53, Math.PI, 0x080000001, -0x100000000, -(2**53), 0.000000000000001, -Number.MAX_VALUE, -0, 0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 0/0, 0, -0x07fffffff, 1, 0x0ffffffff, 2**53+2, 2**53-2, 42]); ");
/*fuzzSeed-133180449*/count=202; tryItOut("\"use strict\"; x = a0;");
/*fuzzSeed-133180449*/count=203; tryItOut("m1.delete(t2);");
/*fuzzSeed-133180449*/count=204; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ! Math.min((y === ( + Math.fround(Math.min(mathy0(x, -0), ( ~ Math.fround(Math.log1p(Number.MIN_VALUE))))))), (y ? (( + Math.log2((Math.atan((x >>> 0)) >>> 0))) >>> 0) : ( + Math.fround(Math.tan((Math.log((x >>> 0)) >>> 0))))))) << Math.min(Math.pow(Math.imul(y, (x | 0)), ( ! (Math.cosh(( + 0x080000001)) >>> 0))), Math.imul((Math.acos(Math.abs((x | 0))) | 0), (x | 0)))); }); testMathyFunction(mathy3, [-0x100000001, -0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, 0, Math.PI, -0x080000001, 0x080000001, 2**53, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, -0x0ffffffff, 42, -(2**53-2), -Number.MIN_VALUE, 2**53-2, 0x07fffffff, 0/0, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 1/0, -0, 1.7976931348623157e308, 1, 0.000000000000001, -(2**53), 0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=205; tryItOut("v2 = (a0 instanceof s2);");
/*fuzzSeed-133180449*/count=206; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( + (Math.cbrt(Math.hypot(Math.pow((mathy2((x | 0), (Math.log10(( + x)) | 0)) | 0), Math.atanh(( ! x))), mathy1(y, x))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -0x100000001, 0x100000001, Number.MAX_SAFE_INTEGER, 42, -0x100000000, -1/0, -0x07fffffff, -(2**53), -Number.MAX_VALUE, -0x080000000, 2**53+2, -Number.MIN_VALUE, 2**53-2, 0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), 0, 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, -0, -(2**53+2), 2**53, 0/0, 0x100000000, 1, -0x0ffffffff, Math.PI]); ");
/*fuzzSeed-133180449*/count=207; tryItOut("\"use strict\"; v0 = this.o1.g0.runOffThreadScript();");
/*fuzzSeed-133180449*/count=208; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + mathy0(( + Math.fround(mathy0(Math.fround(Math.cosh(((( + (((y >>> 0) < ((x << (Math.acos((y | 0)) | 0)) >>> 0)) >>> 0)) | 0) | 0))), Math.fround(( - (x | 0)))))), (Math.sign((Math.log2(Math.fround(Math.atan2(( + ((Math.hypot(y, 0) | 0) || x)), Math.fround(( + Math.expm1((y | 0))))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 0x080000001, 0.000000000000001, 42, -0x100000001, -(2**53), -0x080000000, Number.MIN_VALUE, 2**53+2, 0x07fffffff, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, -(2**53+2), -0x080000001, 1.7976931348623157e308, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 0, 0x080000000, -1/0, -0x07fffffff, 1, 2**53]); ");
/*fuzzSeed-133180449*/count=209; tryItOut("let z, NaN = (new Function).call((arguments.callee.prototype), (Array).call(window,  /x/g , \"\u03a0\") <= \"\\u9ED9\", /*wrap2*/(function(){ \"use strict\"; var vcirmq = w; var myswov = /*wrap1*/(function(){ \"use strict\"; g2.a0 = arguments.callee.caller.arguments;return encodeURI})(); return myswov;})()), e = false, x = ( /* Comment */(24++)), z;if(false) {(-0); }");
/*fuzzSeed-133180449*/count=210; tryItOut("eyoycj(x);/*hhh*/function eyoycj(){s0 += this.s1;}");
/*fuzzSeed-133180449*/count=211; tryItOut("\"use strict\"; testMathyFunction(mathy3, [2**53+2, Math.PI, 0x100000001, 0, 0.000000000000001, -0x080000000, 0x080000001, 42, 0x0ffffffff, Number.MIN_VALUE, 1/0, 1, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53, -(2**53-2), Number.MAX_VALUE, 0x080000000, -1/0, -0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 0/0, -0, -Number.MAX_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-133180449*/count=212; tryItOut("i0 = m0.entries;");
/*fuzzSeed-133180449*/count=213; tryItOut("/*bLoop*/for (let qcruhv = 0; qcruhv < 62; ++qcruhv) { if (qcruhv % 5 == 3) { p0 + o1; } else { /*hhh*/function qipgrt\u0009(w){(4277);}qipgrt(); }  } \nx = linkedList(x, 55);\n");
/*fuzzSeed-133180449*/count=214; tryItOut("/*tLoop*/for (let z of /*MARR*/[function(){}, 1.2e3, 1.2e3, function(){}, function(){}, function(){}, 1.2e3, function(){}, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 1.2e3, 1.2e3, 1.2e3, 1.2e3, function(){}, function(){}, 1.2e3, function(){}, 1.2e3, 1.2e3, function(){}, 1.2e3, function(){}, 1.2e3, function(){}, 1.2e3, 1.2e3, function(){}, function(){}, function(){}, 1.2e3, function(){}, function(){}, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, 1.2e3, function(){}, 1.2e3, function(){}, 1.2e3, function(){}, 1.2e3, function(){}, 1.2e3, function(){}, 1.2e3, function(){}, 1.2e3, function(){}, 1.2e3, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, 1.2e3, function(){}]) { print(x); }");
/*fuzzSeed-133180449*/count=215; tryItOut("\"use strict\"; for (var v of o0.g0) { try { this.a2.unshift(f2, o0, o1.g2.a1); } catch(e0) { } try { v1 = (i0 instanceof o2); } catch(e1) { } try { m2 = new Map(m0); } catch(e2) { } this.m2.set(o1.m2, a0); }");
/*fuzzSeed-133180449*/count=216; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( - ((Math.tan((( + mathy0(Math.fround(Math.fround(( - y))), (Math.tan(x) >>> 0))) >>> 0)) >>> 0) * ((Math.abs(( + Math.atan2(Number.MAX_SAFE_INTEGER, (( + (y >>> 0)) >>> 0)))) >>> 0) >>> mathy0(( + mathy0(0x100000000, (Math.min((-Number.MIN_VALUE >>> 0), (Number.MIN_VALUE >>> 0)) >>> 0))), (Math.pow((((0x080000000 | 0) % (0x080000000 | 0)) | 0), (Math.PI | 0)) | 0))))) | 0); }); testMathyFunction(mathy1, [(new Number(0)), (function(){return 0;}), (new Boolean(true)), ({valueOf:function(){return 0;}}), /0/, -0, false, (new String('')), 1, 0, '\\0', ({valueOf:function(){return '0';}}), (new Number(-0)), objectEmulatingUndefined(), undefined, '/0/', '', null, true, NaN, 0.1, '0', [], [0], (new Boolean(false)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-133180449*/count=217; tryItOut("\"use strict\"; this.a1.forEach((function(j) { this.f0(j); }));");
/*fuzzSeed-133180449*/count=218; tryItOut("a2.pop();");
/*fuzzSeed-133180449*/count=219; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.tan(Math.fround(Math.atan2(Math.fround((Math.cbrt((((Math.atan(x) !== x) >>> 0) >>> 0)) >>> 0)), ((y <= ( + ( + ( + ( + x))))) | 0))))); }); ");
/*fuzzSeed-133180449*/count=220; tryItOut("\"use strict\"; L:  /x/ ;");
/*fuzzSeed-133180449*/count=221; tryItOut("/*tLoop*/for (let w of /*MARR*/[new Boolean(true), arguments.caller, arguments.caller, arguments.caller, arguments.caller, new Boolean(true), new String(''), new String(''), new Boolean(true), arguments.caller, new Boolean(true), new String(''), arguments.caller, arguments.caller, new String(''), new Boolean(true), new String(''), new Boolean(true), new Boolean(true), arguments.caller, new Boolean(true), new Boolean(true), new Boolean(true), arguments.caller, arguments.caller, new Boolean(true), arguments.caller, arguments.caller, new Boolean(true), new Boolean(true), new Boolean(true), arguments.caller, new Boolean(true), new String(''), arguments.caller, new String(''), arguments.caller, arguments.caller, arguments.caller, new String(''), new Boolean(true), new Boolean(true), new String(''), new String('')]) { ; }");
/*fuzzSeed-133180449*/count=222; tryItOut("i1.send(i2);");
/*fuzzSeed-133180449*/count=223; tryItOut("mathy0 = (function(x, y) { return ( + ( - ((( + (y == ( + ((Math.log1p(y) > y) | 0)))) >>> ( - ( + ( - Math.fround(Math.cosh(x)))))) ^ Math.fround((Math.fround(Math.hypot(Math.log(Math.atanh(x)), (Math.max((y | 0), (Math.atan2(( + x), (Math.fround(Math.pow(( + y), x)) | 0)) | 0)) | 0))) >= Math.fround(0x07fffffff)))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 0/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 2**53-2, 0x100000001, -1/0, 2**53+2, -0x0ffffffff, -(2**53+2), 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -0x080000000, 42, 1, 1/0, Math.PI, 0, -0x07fffffff, 0x0ffffffff, 2**53, 0x080000001, -Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0, 0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-133180449*/count=224; tryItOut("x;\u0009\nv2 = this.r0.compile;\n");
/*fuzzSeed-133180449*/count=225; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(.{2,2})(?=.|[])\\u4173|\\B*?+)*?/gym; var s = \"R\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\nR\\n\"; print(r.exec(s)); ");
/*fuzzSeed-133180449*/count=226; tryItOut("L:with(x){;v1 = evaluate(\"function f2(o2) new Symbol()\", ({ global: this.g1, fileName: null, lineNumber: 42, isRunOnce: (yield  /x/ ), noScriptRval: /*MARR*/[function(){}, 0.1, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()].some(/(?:(\\1)|([\u0007-\\cY]{3}){2})/i, this.__defineSetter__(\"x\", Array)), sourceIsLazy: new Boolean(false), catchTermination: true })); }");
/*fuzzSeed-133180449*/count=227; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=228; tryItOut("s2 += 'x';");
/*fuzzSeed-133180449*/count=229; tryItOut("\"use strict\"; o1.h2.set = f1;");
/*fuzzSeed-133180449*/count=230; tryItOut("testMathyFunction(mathy0, /*MARR*/[(4277), Math.imul(-12, 0), (4277), (x =  \"\"  | \"\\u0827\".yoyo(x)), (4277), (x =  \"\"  | \"\\u0827\".yoyo(x)), (4277), Math.imul(-12, 0), Math.imul(-12, 0), (x =  \"\"  | \"\\u0827\".yoyo(x)), (4277), Math.imul(-12, 0), Math.imul(-12, 0), Math.imul(-12, 0), Math.imul(-12, 0), Math.imul(-12, 0), (x =  \"\"  | \"\\u0827\".yoyo(x)), Math.imul(-12, 0), Math.imul(-12, 0), (x =  \"\"  | \"\\u0827\".yoyo(x)), Math.imul(-12, 0), (x =  \"\"  | \"\\u0827\".yoyo(x)), (4277), (x =  \"\"  | \"\\u0827\".yoyo(x)), (4277), Math.imul(-12, 0), (x =  \"\"  | \"\\u0827\".yoyo(x)), (4277), (4277), (4277), (x =  \"\"  | \"\\u0827\".yoyo(x)), (4277), Math.imul(-12, 0), Math.imul(-12, 0), (x =  \"\"  | \"\\u0827\".yoyo(x)), Math.imul(-12, 0), (4277), Math.imul(-12, 0), (4277)]); ");
/*fuzzSeed-133180449*/count=231; tryItOut("i2.send(f0);");
/*fuzzSeed-133180449*/count=232; tryItOut("(({a2:z2}));DataView.prototype.setUint8");
/*fuzzSeed-133180449*/count=233; tryItOut("\"use strict\"; e0.has(t2);");
/*fuzzSeed-133180449*/count=234; tryItOut("testMathyFunction(mathy3, [objectEmulatingUndefined(), 0.1, 0, [], null, '/0/', '\\0', (new Boolean(true)), ({toString:function(){return '0';}}), (new Number(-0)), /0/, '', NaN, (new Number(0)), -0, (new Boolean(false)), (function(){return 0;}), ({valueOf:function(){return 0;}}), [0], (new String('')), 1, ({valueOf:function(){return '0';}}), undefined, true, '0', false]); ");
/*fuzzSeed-133180449*/count=235; tryItOut("g1.p2 + '';");
/*fuzzSeed-133180449*/count=236; tryItOut("mathy2 = (function(x, y) { return Math.atan2(( + Math.min(Math.atanh((( ! (Math.imul((x >>> 0), (x >>> 0)) | 0)) | 0)), ( + ( + mathy0(( + y), ( + x)))))), ((Math.imul((Math.atan2(( + (Math.pow((Math.PI >>> 0), (((y ** (Math.sqrt(x) | 0)) >>> 0) >>> 0)) >>> 0)), y) >>> 0), (Math.PI >>> 0)) < (Math.min(((Math.sin(x) < (( - (Math.imul((((y >>> 0) / y) >>> 0), (((y >>> 0) || Math.fround(x)) >>> 0)) >>> 0)) | 0)) | 0), Math.atan2(mathy1(1.7976931348623157e308, x), Math.sqrt(Math.max(y, (x >>> 0))))) | 0)) | 0)); }); testMathyFunction(mathy2, [0x07fffffff, 0x080000001, -0x0ffffffff, -0, 0x080000000, 2**53-2, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), 0x100000000, 42, -Number.MAX_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, 2**53, Math.PI, 1/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 0x100000001, 0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, -(2**53), 1, -0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, -0x07fffffff]); ");
/*fuzzSeed-133180449*/count=237; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=238; tryItOut("for (var v of i0) { try { for (var v of g1.t1) { try { t0[19] = (4277); } catch(e0) { } try { o2.t2 + ''; } catch(e1) { } try { i0.toString = (function() { m1.get(s0); return h2; }); } catch(e2) { } f1 = (function() { try { a0.unshift((4277), m2, -26, m0); } catch(e0) { } try { o1.t0 = t1.subarray(7, ({valueOf: function() { s2 = Array.prototype.join.call(a0, s0, v0);return 17; }})); } catch(e1) { } /*MXX1*/g0.o0 = g1.Object.keys; return s2; }); } } catch(e0) { } try { Array.prototype.splice.call(a0, 7, 14, p2, f2); } catch(e1) { } try { for (var p in g1.g1) { p1 + g2.s1; } } catch(e2) { } s2 += s1; }");
/*fuzzSeed-133180449*/count=239; tryItOut("\"use strict\"; { void 0; void schedulegc(66); } L:if(true) { if (x) new window(arguments);} else v1 = Object.prototype.isPrototypeOf.call(v2, a1);");
/*fuzzSeed-133180449*/count=240; tryItOut("v2 = (delete y.\u3056);let x = x &= new Uint8ClampedArray();");
/*fuzzSeed-133180449*/count=241; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=242; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( - ( + ( + ( + Math.acosh(Math.hypot(y, Math.fround(1.7976931348623157e308))))))); }); ");
/*fuzzSeed-133180449*/count=243; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(( ~ Math.fround((( + Math.hypot((((Math.fround((Math.acos(x) !== x)) | 0) ? Math.fround(Math.atan2(x, 0.000000000000001)) : (y | 0)) | 0), y)) ? ( + (Math.imul((( ! y) >>> 0), (Math.fround(mathy0(Math.fround(-Number.MAX_SAFE_INTEGER), Math.fround((Math.imul(( + -1/0), (0/0 >>> 0)) >>> 0)))) >>> 0)) >>> 0)) : ( + Math.fround((Math.sin((-Number.MIN_VALUE < (( ~ (y | 0)) | 0))) ? Math.fround(x) : y))))))); }); ");
/*fuzzSeed-133180449*/count=244; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + (( + (((Math.sinh((x >>> 0)) >>> 0) ? (Math.hypot(( + Math.hypot(-0x07fffffff, x)), (-0x080000000 >>> 0)) >>> 0) : y) | 0)) & Math.fround(Math.asin((( - (( + ( + 1/0)) != Math.fround(( ~ Math.atanh(mathy3(x, x)))))) >>> 0))))); }); testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), -0x080000001, function(){}, true,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , true, -0x080000001, objectEmulatingUndefined(), -0x080000001,  /x/g , -0x080000001, -0x080000001,  /x/g , -0x080000001, -0x080000001, -0x080000001, true, function(){}, true, function(){},  /x/g , true, objectEmulatingUndefined(), true, function(){}, -0x080000001, true, -0x080000001,  /x/g , -0x080000001, function(){}, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, function(){}, objectEmulatingUndefined(), -0x080000001, objectEmulatingUndefined(), -0x080000001, -0x080000001, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, function(){}]); ");
/*fuzzSeed-133180449*/count=245; tryItOut("testMathyFunction(mathy3, [-(2**53-2), 0x100000001, -(2**53+2), -0x100000001, 1, -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, Math.PI, 0.000000000000001, -0x0ffffffff, 1.7976931348623157e308, 0x080000000, 2**53-2, 0/0, 0x100000000, 0x080000001, 1/0, -0x100000000, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 0, Number.MAX_SAFE_INTEGER, 2**53, -1/0, -0x080000000, -0, -0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=246; tryItOut("mathy5 = (function(x, y) { return mathy4(( + Math.min(( + ( ~ ( + Math.fround((((y == Number.MAX_VALUE) | 0) ** ( + (y & -Number.MIN_SAFE_INTEGER))))))), (( ~ y) | 0))), (Math.atan2(( + x), x) !== (((Math.fround(Math.pow(Math.fround(Math.fround(Math.max(y, y))), (((-(2**53-2) | 0) - x) ? x : (y >>> 0)))) >>> 0) ? (( - x) | 0) : (mathy3(( ! Math.pow(x, -(2**53-2))), -1/0) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-133180449*/count=247; tryItOut("/*tLoop*/for (let e of /*MARR*/[ '' ,  '' ,  '' , ,  '' , ,  '' ,  '' ,  '' ,  '' ,  '' , ,  '' , , , , , , , , , , , , , , , , , , , , , , , , ,  '' , ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , ,  '' , , ,  '' ,  '' ,  '' , ,  '' ,  '' ,  '' , , ,  '' , , , , , ,  '' , ,  '' ,  '' , ,  '' ,  '' , , ,  '' ,  '' ,  '' ,  '' ,  '' , , , , , ,  '' , ,  '' ,  '' ,  '' , , ,  '' ,  '' ]) { for (var p in h0) { try { Array.prototype.splice.apply(a0, [-4, 7, a2, g1]); } catch(e0) { } delete h1.iterate; } }");
/*fuzzSeed-133180449*/count=248; tryItOut("\"use strict\"; a1.splice(NaN, 17);");
/*fuzzSeed-133180449*/count=249; tryItOut("\"use strict\"; L:for(a = (new String('')) ? Math.log(-25) : (4277) in x.__defineSetter__(\"x\", a)) v0 = t1.BYTES_PER_ELEMENT;");
/*fuzzSeed-133180449*/count=250; tryItOut("f2(i0);");
/*fuzzSeed-133180449*/count=251; tryItOut("with({x: ((function factorial(nfcflx) { ; if (nfcflx == 0) { ; return 1; } f2 + '';; return nfcflx * factorial(nfcflx - 1);  })(91166))}){v0 = (s0 instanceof g1); }");
/*fuzzSeed-133180449*/count=252; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?!(?=(?=.){4,8}){2,})*?)\", \"im\"); var s = ({/*toXFun*/toSource: f0 }); print(r.exec(s)); ");
/*fuzzSeed-133180449*/count=253; tryItOut("Array.prototype.sort.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      (Int32ArrayView[(((0xeec029f) >= (((1))>>>(((0x55a85d9a) <= (0x6096652d)))))) >> 2]) = (((-0x8000000) ? (0x56089afa) : (-0x8000000))-((~((0x0) / (0x3a936d1f))) <= ((-0x22692*(i1)) & (0xc43a7*(0xfcaaeebe)))));\n    }\n    return +((Float32ArrayView[0]));\n  }\n  return f; })]);");
/*fuzzSeed-133180449*/count=254; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=255; tryItOut("v0 = g0.eval(\"Array.prototype.forEach.apply(a0, [i2, /*FARR*/[({a1:1}), null].sort(/*wrap2*/(function(){ var ucnlhu =  /x/ ; var yrrhfl = (w = 10, e = \\\"\\\\u382D\\\") => \\\"use asm\\\";   var imul = stdlib.Math.imul;\\n  var Int8ArrayView = new stdlib.Int8Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    var d2 = -1.5;\\n    var i3 = 0;\\n    var d4 = 35184372088833.0;\\n    {\\n      return ((((((Int8ArrayView[(((0x7b4cd27a) ? (0x6ee80bb5) : (0xf97c2d30))+((((0x6f3b51fd))>>>((-0x8000000))))) >> 0])) & ((i3)+(( /x/ ) < (d1))+(-0x8000000))) == (imul((-0x8000000), ((i3) ? (!(-0x8000000)) : (1)))|0))-(-0x8000000)))|0;\\n    }\\n    return ((0xfffff*(!(0xa856fd51))))|0;\\n    i0 = (((-(i3))>>>((i3))));\\n    (Int8ArrayView[4096]) = ((0x50c9ef87) / (((0xfa040e06)+(!(-0x8000000))+(0xfb4e0c2a))>>>(((0x7fccd151) <= (0xdb82a8))+(i0)-(!( /* Comment */SharedArrayBuffer(window))))));\\n    return ((-0x7493a*(0xfde0721e)))|0;\\n  }\\n  return f;; return yrrhfl;})(), this.__defineSetter__(\\\"x\\\", false)), g1.t0]);\");\n(void schedulegc(o0.g1));\n");
/*fuzzSeed-133180449*/count=256; tryItOut("Array.prototype.forEach.apply(a0, [(function mcc_() { var uwqzfb = 0; return function() { ++uwqzfb; if (/*ICCD*/uwqzfb % 2 == 0) { dumpln('hit!'); Array.prototype.push.apply(a0, [this.g0, b1, this.zzz.zzz--.padStart((p={}, (p.z = ((makeFinalizeObserver('nursery'))))()))]); } else { dumpln('miss!'); try { v2 = 0; } catch(e0) { } g0.a2.__proto__ = h0; } };})()]);");
/*fuzzSeed-133180449*/count=257; tryItOut("mathy2 = (function(x, y) { return (Math.log10((( + Math.min(( + (( - (Math.fround(mathy0(Math.fround(( + (y ? ( + y) : ( + x)))), x)) << ( - (Math.atan2((Math.max(Math.fround(y), Math.fround(x)) | 0), ( ! y)) | 0)))) >>> 0)), ( + ( + ( - ( + ( + y))))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-133180449*/count=258; tryItOut("\"use strict\"; h2.iterate = (function(j) { if (j) { try { m1.set(g0, h1); } catch(e0) { } try { a1[7] = (4277); } catch(e1) { } try { s1 += 'x'; } catch(e2) { } i2.next(); } else { try { a0 = Array.prototype.map.apply(a1, [(function(j) { if (j) { try { /*RXUB*/var r = r1; var s = ((p={}, (p.z = x)())); print(uneval(r.exec(s))); print(r.lastIndex);  } catch(e0) { } try { a1.sort((function() { for (var j=0;j<22;++j) { f1(j%2==1); } })); } catch(e1) { } g1.e0.add(b1); } else { try { for (var v of m0) { try { m2.get((4277)); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(f0, g2.i1); } catch(e1) { } try { v1 = true; } catch(e2) { } s0 += 'x'; } } catch(e0) { } try { t0[v2] = b1; } catch(e1) { } print(t1); } })]); } catch(e0) { } try { for (var p in g2.t0) { try { o0.e0.add(v0); } catch(e0) { } try { s2 = Array.prototype.join.call(a0, s2); } catch(e1) { } try { o2.o0.o2.m2.delete(i0); } catch(e2) { } v1 = t0.BYTES_PER_ELEMENT; } } catch(e1) { } try { a1[13]; } catch(e2) { } v0 = new Number(g1.v1); } });");
/*fuzzSeed-133180449*/count=259; tryItOut("\"use strict\"; v2 = a0.every((function mcc_() { var fsmptn = 0; return function() { ++fsmptn; f0(/*ICCD*/fsmptn % 6 == 2);};})());");
/*fuzzSeed-133180449*/count=260; tryItOut("if((x % 16 == 14)) o0 = {}; else  if (x !=   ? /(?=.?)/y : ({a2:z2})) {t0 = m0.get(o2);/*MXX3*/g2.Symbol.name = g2.Symbol.name; } else {(( '' ));print(x); }");
/*fuzzSeed-133180449*/count=261; tryItOut("Array.prototype.pop.call(a2, g1);");
/*fuzzSeed-133180449*/count=262; tryItOut("\"use strict\"; Object.freeze(v0);g0.a2.pop();");
/*fuzzSeed-133180449*/count=263; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n;    return +((Float64ArrayView[0]));\n    d0 = (d0);\n    d0 = (9007199254740992.0);\n    return +((Uint32ArrayView[(((0xffffffff) >= (0xd48931b7))-((((i1)+(i1)) | ((/*FFI*/ff()|0)+(0xc46b3114))) > (((i1)-(i1)) >> ((0xfd145a4b)-(0x910f188f)+(0xf8c8ed97))))-((((0x2fc1e456)) >> (((0x232a2700) < (0x1e5a36e4)))) != (imul(((0x75d45376) > (0x10dcbf1)), (((73786976294838210000.0))))|0))) >> 2]));\n  }\n  return f; })(this, {ff: eval += c}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, 0, Number.MAX_VALUE, 0x0ffffffff, -(2**53+2), 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, Math.PI, 0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, -0, 1/0, -0x080000000, 1, 2**53-2, 2**53+2, 2**53, 0x080000000, -(2**53), -0x100000001, -0x100000000]); ");
/*fuzzSeed-133180449*/count=264; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - ( + ( + ( + mathy2(( + ( + (( + ( ! Math.fround(y))) % ( + (Math.min((x >>> 0), (y >>> 0)) >>> 0))))), ( + Math.atan2(Math.trunc(Math.fround(x)), Math.imul(x, y)))))))); }); testMathyFunction(mathy4, [({toString:function(){return '0';}}), '\\0', '/0/', (new Number(-0)), ({valueOf:function(){return 0;}}), undefined, NaN, (new Boolean(false)), ({valueOf:function(){return '0';}}), 0.1, /0/, [], null, '', -0, false, [0], 0, true, (new Number(0)), (new Boolean(true)), 1, '0', (new String('')), objectEmulatingUndefined(), (function(){return 0;})]); ");
/*fuzzSeed-133180449*/count=265; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-133180449*/count=266; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + ((Math.sign((( + mathy1(( + y), ( + x))) | 0)) >>> 0) + Math.max(0, x))) ? ( + ( ~ Math.fround(Math.atan2(x, Math.tan((( + (y >>> 0)) >>> 0)))))) : ( + mathy0(Math.hypot(( + ( ~ ( + ( + x)))), (((x | 0) ? ((((y | 0) ? Math.fround(( ! Math.fround(y))) : x) | 0) | 0) : ((( - (x >>> 0)) >>> 0) | 0)) | 0)), mathy1((y | 0), (( ! ((Math.sign(Math.fround(y)) | 0) === ( + y))) | 0)))))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, Math.PI, -0x080000000, 1, 2**53+2, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, -(2**53-2), -0x07fffffff, -(2**53+2), -Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, 2**53, -0x080000001, 1.7976931348623157e308, -(2**53), -0, 0/0, -1/0, 1/0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, -0x0ffffffff, 0x100000001, 0x080000000, -Number.MAX_VALUE, 0x100000000, -0x100000000]); ");
/*fuzzSeed-133180449*/count=267; tryItOut("testMathyFunction(mathy3, [Math.PI, -(2**53), 0/0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 2**53+2, 0x080000000, 1, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, -0, 0x07fffffff, 0x100000000, 0.000000000000001, -(2**53+2), -0x07fffffff, 0, -0x080000000, 0x080000001, 0x0ffffffff, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -0x080000001, 2**53, 1.7976931348623157e308, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=268; tryItOut("\"use strict\"; const \u3056, b = this.__defineSetter__(\"\\u3056\", Math.cosh), [] = x, x = x;this.m1.get({x: x, \u3056: ((4277)), z} = {} = \u0009(4277));");
/*fuzzSeed-133180449*/count=269; tryItOut("\"use asm\"; let (d) { s1 = new String(f2); }");
/*fuzzSeed-133180449*/count=270; tryItOut("Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-133180449*/count=271; tryItOut("o0.o2.o0.toString = (function(j) { if (j) { try { m2.has(new Function.prototype.bind(((undefined)))); } catch(e0) { } try { this.m2.get(s1); } catch(e1) { } try { print(uneval(h2)); } catch(e2) { } Object.defineProperty(this, \"o2.e2\", { configurable: (x % 57 != 16), enumerable: false,  get: function() {  return new Set; } }); } else { try { this.e1.add(m0); } catch(e0) { } try { a2.splice(1, v1, m2, b1); } catch(e1) { } g1 = fillShellSandbox(evalcx('')); } });");
/*fuzzSeed-133180449*/count=272; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.hypot(( + (((Math.log2((y | x)) >>> 0) === ((( + ( + Math.asin(( + ( ~ ( + ( ! x))))))) ? Math.tan(( + -Number.MAX_VALUE)) : x) >>> 0)) !== ((((0.000000000000001 ^ Math.max(-0x100000000, (0x100000001 | 0))) | 0) ** (mathy0(Math.imul(x, y), y) | 0)) | 0))), ( + (((Math.min((( + Math.fround(( ! y))) | 0), Math.fround(Math.fround(Math.atan2(( + y), y)))) | 0) !== (((Math.pow(Math.cbrt((Math.hypot(x, (y | 0)) | 0)), 1.7976931348623157e308) | 0) ? (((y ^ (Math.PI >>> 0)) <= -Number.MIN_SAFE_INTEGER) | 0) : ((Math.acosh((x | 0)) | 0) | 0)) | 0)) + Math.fround(mathy0(Math.fround((mathy0(((Math.max((x >>> 0), (Math.fround((y | y)) >= y)) >>> 0) | 0), (Math.abs((Math.asinh((y >>> 0)) >>> 0)) | 0)) | 0)), Math.fround((mathy0((x | 0), (y | 0)) | 0))))))); }); ");
/*fuzzSeed-133180449*/count=273; tryItOut("\"use strict\"; g2.t1[9] = new Date(Math.min(x = /(?=(?!\\W|[^]))|(.+)\\b*|(?=[^]*)|^|\\2?/ym, -4), []);");
/*fuzzSeed-133180449*/count=274; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MAX_VALUE, -(2**53-2), -(2**53+2), -0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, -0x080000000, 2**53-2, 0/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, 2**53+2, -0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, 0x080000000, 0x100000001, 0x0ffffffff, -1/0, 42, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, 1/0, 0x080000001, -0, -0x080000001]); ");
/*fuzzSeed-133180449*/count=275; tryItOut("\"use strict\"; Object.seal(this.a2);");
/*fuzzSeed-133180449*/count=276; tryItOut("/*infloop*/L:for(var [] in ({e: (4277)})) v2 = r1.constructor;/*hhh*/function rcoete/*\n*/(b, z){print(false);}/*iii*/[,];");
/*fuzzSeed-133180449*/count=277; tryItOut("\"use strict\"; m1.__proto__ = b2;");
/*fuzzSeed-133180449*/count=278; tryItOut("e1.valueOf = (function() { try { t2.set(t1, [] = [{x: [, {x: {}, eval}], x: []}, [arguments.callee.caller.arguments]]); } catch(e0) { } try { /*MXX3*/g2.WeakMap.length = g2.WeakMap.length; } catch(e1) { } try { h2.set = (function() { for (var j=0;j<137;++j) { f0(j%5==0); } }); } catch(e2) { } b2.valueOf = (function() { for (var j=0;j<10;++j) { f1(j%3==1); } }); throw this.o2; });");
/*fuzzSeed-133180449*/count=279; tryItOut("\"use strict\"; /*RXUB*/var r = /\u0086/im; var s = \"\\u00a6\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=280; tryItOut("h2.get = (function() { try { e1.add(f2); } catch(e0) { } try { (void schedulegc(g0)); } catch(e1) { } try { v2 = Object.prototype.isPrototypeOf.call(a1, o1.g2); } catch(e2) { } for (var v of t0) { Array.prototype.push.apply(a0, [g0.v2]); } return s0; });");
/*fuzzSeed-133180449*/count=281; tryItOut("x = NaN;");
/*fuzzSeed-133180449*/count=282; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.expm1(((Math.imul(Math.tanh(-0x07fffffff), (Math.imul((y | 0), ( ~ x)) | 0)) >>> 0) >= Math.cosh(( + (( + Math.sinh(2**53+2)) >> ( + (-Number.MAX_SAFE_INTEGER % (( ~ y) >>> 0)))))))); }); testMathyFunction(mathy1, [2**53, -0, 0x100000001, 0x100000000, -Number.MIN_VALUE, 0.000000000000001, 0, -(2**53), -0x100000000, -0x100000001, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1, 0/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, 0x07fffffff, 2**53+2, -0x080000001, 2**53-2, 1.7976931348623157e308, 0x080000001, 42, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -(2**53+2), 1/0, -0x080000000]); ");
/*fuzzSeed-133180449*/count=283; tryItOut("/*tLoop*/for (let a of /*MARR*/[(void version(170)), null, (void version(170)), x, new Number(1), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), (void version(170)), null, new Number(1), (1/0), x, new Number(1), x, (1/0), (void version(170)), x, new Number(1), (1/0), (void version(170)), new Number(1), (1/0), x, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (void version(170)), x, (void version(170)), new Number(1), null, new Number(1), null, (1/0), new Number(1), null, (1/0), null, null, x, (1/0), (1/0), null, new Number(1), (void version(170)), (void version(170)), x, x, (1/0), new Number(1), x, null, new Number(1), (void version(170)), null, (1/0), x, null, x, new Number(1), x, null, (void version(170)), null, (1/0), x, null, (1/0), new Number(1), (void version(170)), null, x, (void version(170)), (1/0), (void version(170)), (1/0), x, x, new Number(1), null, null, (void version(170)), x, (void version(170)), (void version(170)), x, (void version(170)), new Number(1), x, x, (void version(170)), null, new Number(1), (void version(170)), (1/0), (void version(170)), (void version(170)), null, x, x, (1/0), (void version(170)), x, x, x, x, x, x, x, x, new Number(1), null]) { o0.a1.valueOf = f2; }");
/*fuzzSeed-133180449*/count=284; tryItOut("print(uneval(v1));");
/*fuzzSeed-133180449*/count=285; tryItOut("\"use asm\"; (x = \u000c[]);");
/*fuzzSeed-133180449*/count=286; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.min(Math.round(Math.imul(((Math.fround(Math.atan(Math.fround(y))) <= Math.sign(((Math.trunc((-0x100000001 >>> 0)) >>> 0) | y))) | 0), Math.max(x, ( ~ ((( ~ (x | 0)) | 0) | 0))))), ((Math.max((( ~ -(2**53)) | 0), (y | 0)) >>> 0) > ((x ? (Math.exp(Math.atan2((x | 0), (y | 0))) >>> 0) : ((Math.acosh((x >>> 0)) >>> 0) | 0)) ? ((Math.imul(( + y), 0x07fffffff) < 2**53-2) > (Math.fround(Math.log1p(Math.fround(Math.fround(( ! x))))) >>> 0)) : (((x >>> 0) * (y >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 42, 0, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, 1, 1/0, Math.PI, Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, -(2**53), 0x0ffffffff, Number.MIN_VALUE, -0x080000000, 0x080000001, -0x07fffffff, -0x100000000, 0.000000000000001, 0x100000000, 2**53+2, -1/0, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-133180449*/count=287; tryItOut("h1 + '';");
/*fuzzSeed-133180449*/count=288; tryItOut("/*vLoop*/for (lgvgje = 0; lgvgje < 13; ++lgvgje) { let a = lgvgje; /*tLoop*/for (let z of /*MARR*/[(1/0), x = Proxy.create(({/*TOODEEP*/})(23), [1,,]), (1/0), new Boolean(true), new Boolean(true), new Boolean(true), (1/0), (1/0), new Boolean(true), x = Proxy.create(({/*TOODEEP*/})(23), [1,,]), (1/0), new Boolean(true), (1/0), x = Proxy.create(({/*TOODEEP*/})(23), [1,,]), x = Proxy.create(({/*TOODEEP*/})(23), [1,,]), new Boolean(true), (1/0), (1/0), x = Proxy.create(({/*TOODEEP*/})(23), [1,,]), x = Proxy.create(({/*TOODEEP*/})(23), [1,,]), (1/0), (1/0), x = Proxy.create(({/*TOODEEP*/})(23), [1,,]), (1/0), (1/0), x = Proxy.create(({/*TOODEEP*/})(23), [1,,]), (1/0), (1/0), (1/0), new Boolean(true), (1/0), new Boolean(true), new Boolean(true)]) { Array.prototype.unshift.apply(a0, [p0]); } } ");
/*fuzzSeed-133180449*/count=289; tryItOut("for(let x of /*FARR*/[x,  /x/ .__defineSetter__(\"window\", decodeURI)]) let(z = new RegExp(\"(?:$+|^{2}$[^]|[^]{4}+?)\", \"gim\"), x = (delete x.w), NaN, vaovzv, kloqak, mfcgvr, fuyngf, movzbf, plkzjy, x) ((function(){throw y;})());let(z) { throw StopIteration;}");
/*fuzzSeed-133180449*/count=290; tryItOut("((function ([y]) { })() in  /x/ );");
/*fuzzSeed-133180449*/count=291; tryItOut("\"use strict\"; o2.t1 = t1.subarray(18, this.unwatch(length));");
/*fuzzSeed-133180449*/count=292; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use asm\"; return ((((mathy4((Math.pow((x >>> 0), (Math.tan(x) | 0)) | 0), mathy1((Math.pow((Math.tan(x) >>> 0), ( + ( ! Math.fround(y)))) >>> 0), x)) - Math.acosh(y)) >>> 0) >> (Math.fround(Math.hypot(Math.hypot((Math.asin((Math.pow(((Math.asin(y) >>> 0) > (y >>> 0)), x) >>> 0)) >>> 0), ((Math.imul(((( ! (-1/0 | 0)) | 0) >>> 0), (Math.log((( + y) | 0)) | 0)) >>> 0) === ( + ((y - y) ^ (x >>> 0))))), ( + ( ~ Math.fround(Math.imul(Math.fround(x), mathy1(( + (y >>> 0)), x))))))) | 0)) | 0); }); ");
/*fuzzSeed-133180449*/count=293; tryItOut("b = /*RXUE*//(?![\\s])+?|(?!\\1)?/i.exec(\"\"), x, x = (x) = ++eval, vwcavy, x = (4277) % /*RXUE*/new RegExp(\"(?:^)\", \"yim\").exec(\"\"), ghobty, window = [z1,,], x;for (var p in e0) { try { e2.toSource = (function(j) { if (j) { try { v2 = (g2.g1.m0 instanceof g1); } catch(e0) { } try { (void schedulegc(g2)); } catch(e1) { } try { o1.valueOf = (function() { try { for (var v of g1.i1) { try { Object.preventExtensions(o0.a1); } catch(e0) { } i2.next(); } } catch(e0) { } try { Array.prototype.forEach.apply(a1, [eval]); } catch(e1) { } t1 = new Float64Array(b2, 72, ({valueOf: function() { f0 = (function() { g0.t1 = new Int8Array(a1); return m2; });return 10; }})); return g0; }); } catch(e2) { } for (var p in h2) { g2.o1 = new Object; } } else { try { m2.delete(o0.t2); } catch(e0) { } try { v2 = Array.prototype.reduce, reduceRight.call(a1, (function() { t1.set(a2, 7); return o1.h2; }), e, s1, b0, o2.v2, e2); } catch(e1) { } o1.v0 = Object.prototype.isPrototypeOf.call(this.g0, f0); } }); } catch(e0) { } try { Array.prototype.sort.call(a0, (function() { try { a1.splice(NaN, 7); } catch(e0) { } v0 = g2.runOffThreadScript(); return m2; })); } catch(e1) { } try { v2 = o2.g2.runOffThreadScript(); } catch(e2) { } o1.h1.enumerate = f1; }");
/*fuzzSeed-133180449*/count=294; tryItOut("/*bLoop*/for (uybhtt = 0, window; uybhtt < 62; ++uybhtt) { if (uybhtt % 45 == 5) { var x;v0 = (i2 instanceof m1); } else { /* no regression tests found */ }  } ");
/*fuzzSeed-133180449*/count=295; tryItOut("\"use strict\"; var c = q => q(), z, hazdnw, pfqayw, e, y = w === b\n;( /x/g );");
/*fuzzSeed-133180449*/count=296; tryItOut("x = 7 / x; var r0 = x ^ 1; var r1 = r0 - 4; print(r1); var r2 = r0 % r1; r2 = r1 - 5; var r3 = 0 & 6; var r4 = x ^ r0; var r5 = r4 - r1; var r6 = r2 % 6; var r7 = r2 % r6; var r8 = r5 ^ 5; var r9 = 5 & x; var r10 = r9 * r0; x = r4 % r7; var r11 = 8 / r5; print(r9); var r12 = x & r11; var r13 = x * r0; var r14 = 5 + r0; var r15 = 4 % 8; r8 = r12 | r5; var r16 = r6 % 7; var r17 = 1 - 8; var r18 = 4 ^ r14; var r19 = r5 | r13; var r20 = r13 + r2; r2 = r7 + r11; var r21 = r19 + r9; var r22 = 8 - 4; var r23 = r16 * 7; r23 = 8 ^ r2; var r24 = r20 - 2; var r25 = r11 / r6; var r26 = 2 & r22; r3 = r17 ^ r25; r15 = r11 - r12; var r27 = r1 + r11; var r28 = r25 - r22; var r29 = 5 / 5; var r30 = 2 * r15; var r31 = 9 + 5; var r32 = r27 / 9; r31 = 1 + r2; r16 = 5 | r7; r2 = r1 & r15; r0 = r20 / 2; ");
/*fuzzSeed-133180449*/count=297; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-133180449*/count=298; tryItOut("/*infloop*/L:for(e;  '' ; (4277)) (-33554431)\u0009;");
/*fuzzSeed-133180449*/count=299; tryItOut("v2 = t0.length;");
/*fuzzSeed-133180449*/count=300; tryItOut("\"use strict\"; (void schedulegc(g0));");
/*fuzzSeed-133180449*/count=301; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.max((((( ~ ( + Math.cosh(Math.fround((1 ? 42 : y))))) | 0) >= (Math.imul(Math.fround(Math.clz32(Math.fround(x))), Math.atan2((y == y), ( + Math.asinh((Math.atan2(x, ( ! y)) >>> 0))))) >>> 0)) >>> 0), ( + ((mathy0(y, y) >>> 0) & (( + x) >> ( + ( - ( + Math.cosh((1.7976931348623157e308 ? Math.fround(x) : Math.fround(-Number.MAX_VALUE)))))))))); }); ");
/*fuzzSeed-133180449*/count=302; tryItOut("mathy3 = (function(x, y) { return ((Math.fround(( + ((x / x) >= ( + (Math.max((x | 0), (Math.asinh(x) | 0)) | 0))))) - Math.fround(( + ( + ( + Math.atan2((-0x100000000 | 0), (-Number.MAX_VALUE >>> mathy2(y, Math.fround(y))))))))) / Math.abs((( ~ Math.fround(Math.atanh(Math.fround(x)))) | 0))); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), /0/, ({toString:function(){return '0';}}), (new Boolean(false)), (function(){return 0;}), 0, null, [0], [], true, objectEmulatingUndefined(), (new Boolean(true)), 0.1, undefined, '\\0', (new Number(0)), -0, NaN, (new Number(-0)), '/0/', false, (new String('')), '', '0', 1]); ");
/*fuzzSeed-133180449*/count=303; tryItOut("mathy5 = (function(x, y) { return ( + Math.fround(Math.pow(Math.fround(Math.pow((( ~ x) >>> 0), (y | 0))), ( + Math.ceil(Math.atan(x)))))); }); testMathyFunction(mathy5, [-1/0, 0/0, -0x080000000, -0x100000000, 0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0, 42, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001, 2**53, -Number.MIN_VALUE, 0, -0x080000001, 1/0, 0x0ffffffff, Math.PI, 2**53-2, -0x07fffffff, -(2**53), 0x080000001, 1, 0x100000000, -Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 0x080000000]); ");
/*fuzzSeed-133180449*/count=304; tryItOut("s1 += 'x';");
/*fuzzSeed-133180449*/count=305; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=306; tryItOut("Object.preventExtensions(t2);");
/*fuzzSeed-133180449*/count=307; tryItOut("for (var v of v0) { try { a1[9]; } catch(e0) { } m0.has(s2); }");
/*fuzzSeed-133180449*/count=308; tryItOut("\"use strict\"; Array.prototype.shift.call(a0);");
/*fuzzSeed-133180449*/count=309; tryItOut("v0 = r0.exec;");
/*fuzzSeed-133180449*/count=310; tryItOut("/*MXX3*/g1.Promise.prototype.catch = g1.Promise.prototype.catch;");
/*fuzzSeed-133180449*/count=311; tryItOut("\"use strict\"; a2 = arguments;");
/*fuzzSeed-133180449*/count=312; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-133180449*/count=313; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((( + Math.fround(mathy1((((mathy1((x >>> 0), y) >>> 0) ? (Math.hypot(( + y), (mathy0(x, y) | 0)) | 0) : Math.cos(1.7976931348623157e308)) | 0), Math.fround(( + ( ! ( + 2**53+2))))))) << Math.fround(( + y))) | 0) < Math.tan((Math.atan2((Math.min(Math.PI, x) | 0), (mathy0(( ~ 0x080000000), y) | 0)) | 0))); }); testMathyFunction(mathy2, [-1/0, -0x080000001, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, 0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53, 42, -(2**53), 1/0, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, 1, -0x07fffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53-2, -0x0ffffffff, -(2**53-2), 0/0, -0, 0x100000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000001, 0, -Number.MAX_VALUE, 0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-133180449*/count=314; tryItOut("a0 = g0.t2[18];");
/*fuzzSeed-133180449*/count=315; tryItOut("\"use asm\"; throw c;let([] = new ((Date.prototype.setMilliseconds()))(), d = x, z,  /x/  = x, d = (4277), w = delete  '' ) ((function(){for(let c in ((x) =  ''  > x)) let(e) ((function(){print(x);})());})());");
/*fuzzSeed-133180449*/count=316; tryItOut("testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, -1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_VALUE, 0x0ffffffff, -0x100000001, -0x100000000, 0x07fffffff, 1/0, 2**53, 1, -0x080000000, -0x080000001, 0/0, 2**53+2, -0x0ffffffff, -Number.MIN_VALUE, 0x080000000, -(2**53-2), 2**53-2, -0, Math.PI, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-133180449*/count=317; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + ((Math.atan2((( ! mathy1(mathy1(( + x), -0x100000001), x)) , ( ! Math.fround(Math.asinh(( + y))))), ( ! x)) | 0) >> Math.tanh(( ! ( + (Math.fround((((Math.min(y, (y >>> 0)) >>> 0) / ((Math.log10((( + ( + x)) >>> 0)) >>> 0) >>> 0)) >>> 0)) & (( ! Math.fround((Math.fround(y) ** Math.fround((( - (2**53 >>> 0)) >>> 0))))) | 0))))))); }); testMathyFunction(mathy2, [2**53, Number.MIN_SAFE_INTEGER, 42, -0x080000001, 0.000000000000001, 0x07fffffff, 2**53-2, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0, -(2**53-2), -(2**53+2), -Number.MIN_VALUE, -(2**53), -1/0, 0x080000001, 2**53+2, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0/0, 0, 0x100000000, 0x080000000, -0x100000001, Number.MIN_VALUE, 1/0, 1, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=318; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.pow(Math.pow(Math.tanh(( + ( ! (y >= 1/0)))), (((Math.imul(((((-0x100000001 >>> 0) % (Math.atan2(x, (Math.fround(x) ** 0.000000000000001)) >>> 0)) >>> 0) >>> 0), (Math.cos(Math.pow(x, x)) >>> 0)) >>> 0) | 0) << (Math.atan2((y >>> x), ( + Math.imul(( + Math.atanh(Math.fround(x))), x))) | 0))), (( + Math.max(( + mathy4(( + ( + (( + Math.PI) * ( + y)))), ( + ( ~ x)))), Math.fround(Math.imul((mathy3((x | 0), y) >>> 0), (Math.max(Math.pow(y, ((Math.expm1((0.000000000000001 | 0)) >>> 0) | 0)), Math.fround((y ? x : (y >>> 0)))) >>> 0))))) >>> 0))); }); ");
/*fuzzSeed-133180449*/count=319; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( + Math.fround(Math.max(Math.fround((Math.pow(( ~ (y >>> 0)), Math.imul((y != -0x100000001), Math.fround((x >= ( + y))))) <= Math.fround(Math.sin((((1.7976931348623157e308 | 0) <= -0) | 0))))), Math.fround(Math.atan(((1/0 | 0) & (( + Math.log2(-Number.MAX_SAFE_INTEGER)) | 0)))))))); }); testMathyFunction(mathy3, /*MARR*/[ /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ]); ");
/*fuzzSeed-133180449*/count=320; tryItOut("\"use strict\"; \"use asm\"; let(x =  '' .throw(function ([y]) { }), x =  \"\" ) ((function(){for(let e in []);})());");
/*fuzzSeed-133180449*/count=321; tryItOut("mathy4 = (function(x, y) { return Math.sqrt(Math.hypot((( + ( ! ( + (Math.imul((x | (mathy0(x, x) >>> 0)), Math.min(y, x)) | 0)))) + (( + (Math.fround(( ~ (-0x080000001 | 0))) ? x : ( + ( + mathy0(x, y))))) & ( + (((y | 0) / (Math.sqrt(x) | 0)) | 0)))), (((( ~ (Math.hypot(Number.MAX_SAFE_INTEGER, Math.fround(( ~ y))) | 0)) >>> 0) * ((((x | 0) >>> ((Math.atan2(-0x100000000, (x ? Math.fround(Math.ceil(Math.fround(0x100000001))) : y)) >>> 0) >>> 0)) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [-(2**53-2), 0/0, 0x0ffffffff, 0x100000000, 0.000000000000001, -(2**53), 1.7976931348623157e308, 2**53, 2**53-2, -0x080000000, -0, -0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 42, -0x0ffffffff, 1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x100000000, 0x100000001, 0x080000000, 1, -0x080000001, Number.MAX_SAFE_INTEGER, Math.PI, 0x07fffffff, -1/0, 0x080000001, 0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=322; tryItOut("/*infloop*/ for  each(var Int32Array in ('fafafa'.replace(/a/g, (x.valueOf(\"number\"))))) /* no regression tests found */");
/*fuzzSeed-133180449*/count=323; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.acosh((( ~ Math.fround(Math.imul(Math.fround(x), Math.fround(Math.pow(1, x))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-133180449*/count=324; tryItOut("o0 = g0.__proto__;");
/*fuzzSeed-133180449*/count=325; tryItOut("x;");
/*fuzzSeed-133180449*/count=326; tryItOut("");
/*fuzzSeed-133180449*/count=327; tryItOut("mathy3 = (function(x, y) { return mathy0((Math.atan2(Math.atan2(mathy0(( + (Math.cbrt((x >>> 0)) >>> 0)), 1/0), (y ? ((mathy2(Math.fround(y), (Math.imul(x, x) | 0)) | 0) | 0) : (x | 0))), (( + Math.expm1((Math.log1p(-Number.MAX_SAFE_INTEGER) | 0))) | 0)) >>> 0), Math.fround(Math.atan2(( + Math.expm1(Math.fround(( - y)))), Math.hypot((Math.hypot(Math.fround(Math.min(Math.fround(x), Math.fround((-(2**53) ** 1)))), Math.fround(Number.MAX_VALUE)) <= (Math.log(y) | 0)), mathy1(mathy2(Math.atan(x), y), ( ! x)))))); }); ");
/*fuzzSeed-133180449*/count=328; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=329; tryItOut("\"use strict\"; switch((void shapeOf((let (z)  /x/g )))) { case 3: default: break; v1 = Proxy.create(this.h2, b1);a2.pop(Math.imul((w = arguments), 0));break; case this: break; case 0: case 0: this.v1 = evalcx(\" \\\"\\\" \", g2);(true);break;  }");
/*fuzzSeed-133180449*/count=330; tryItOut("\"use strict\"; h2.get = (function(j) { if (j) { try { v2 = (this.s0 instanceof h1); } catch(e0) { } try { for (var v of i0) { try { v1 = Object.prototype.isPrototypeOf.call(this.e0, m1); } catch(e0) { } try { a0.splice(NaN, 4, f1, e2); } catch(e1) { } g0.i0.send(this.g2.e2); } } catch(e1) { } try { for (var v of f1) { try { o2.m2.has(h0); } catch(e0) { } m2 + ''; } } catch(e2) { } s1 = new String(v1); } else { try { a1.sort((function(j) { if (j) { try { g1.i1 = new Iterator(s2, true); } catch(e0) { } m0 + s1; } else { a1 = a0.slice(NaN, NaN); } })); } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(o1, a1); } catch(e1) { } try { print(uneval(f0)); } catch(e2) { } v2 = a2.every((function() { for (var j=0;j<41;++j) { f1(j%4==0); } }), s2); } });");
/*fuzzSeed-133180449*/count=331; tryItOut("\"use strict\"; this.a1.forEach((function(j) { if (j) { try { v2 = Object.prototype.isPrototypeOf.call(s2, h0); } catch(e0) { } t2[1]; } else { try { g0.o2 = m1.get(t1); } catch(e0) { } i2 = e2.entries; } }), this.g2, f2);");
/*fuzzSeed-133180449*/count=332; tryItOut("g0.v1.toString = f1;");
/*fuzzSeed-133180449*/count=333; tryItOut("/*hhh*/function qxxvdj(x){{ void 0; void gc(this, 'shrinking'); }}/*iii*/m0 = a1[8];");
/*fuzzSeed-133180449*/count=334; tryItOut("");
/*fuzzSeed-133180449*/count=335; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=336; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.imul(Math.fround(((((Math.abs(Math.fround(Math.acosh(Math.fround(y)))) | 0) ? ( + ( + x)) : ( + ( + ( + Math.acosh(y))))) | 0) != Math.atan2(Math.imul(Math.fround(Math.cos(y)), Math.fround(y)), Math.atanh(Math.round((y | 0)))))), Math.fround((( ! (( ! (mathy1((Math.min(Math.sinh(Math.atanh(x)), (2**53-2 >>> 0)) | 0), (mathy1(x, x) | 0)) | 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-133180449*/count=337; tryItOut("\"use strict\"; m0.__iterator__ = (function mcc_() { var ozlenu = 0; return function() { ++ozlenu; if (/*ICCD*/ozlenu % 7 == 4) { dumpln('hit!'); try { h2 = t1[9]; } catch(e0) { } try { m1.has(b2); } catch(e1) { } try { g1.offThreadCompileScript(\"function f2(s2) \\\"use asm\\\";   var Infinity = stdlib.Infinity;\\n  var abs = stdlib.Math.abs;\\n  var imul = stdlib.Math.imul;\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var d2 = -16385.0;\\n    i1 = (0xf8fffd41);\\n    switch ((~~(+(((-0x8000000)+(0xfac70a1b))|0)))) {\\n    }\\n    {\\n      i0 = (-0x8000000);\\n    }\\n    (Int32ArrayView[((~~(-288230376151711740.0)) / ((Infinity))) >> 2]) = ((~~(-((+abs(((d2))))))) / (~~(1125899906842625.0)));\\n    return +((d2));\\n    {\\n      (Int16ArrayView[0]) = ((imul((((({}) > (Object.defineProperty(c, \\\"hypot\\\", ({set: function  x (e)\\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var NaN = stdlib.NaN;\\n  var Infinity = stdlib.Infinity;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    d0 = (+abs(((NaN))));\\n    return ((((((d0)) / ((0x16b0035f))))))|0;\\n    d0 = (Infinity);\\n    (Float64ArrayView[2]) = ((-1152921504606847000.0));\\n    d0 = (d0);\\n    {\\n      (Int16ArrayView[(((0xe2d6b2a9))-(0x2e0384d9)-(i1)) >> 1]) = (((-511.0) > (((-33.0)) % ((1.0)))));\\n    }\\n    {\\n      d0 = (536870913.0);\\n    }\\n    return (((((((((-0x8000000))>>>((0xfb46f8e5))) > (0x0))+(i1))>>>((i1)+((((0x8339b948))>>>((0x6a244b57))) > (((0xfaa7bfc4))>>>((0xfbcf8670)))))))+(0xfb6393b3)-(i1)))|0;\\n  }\\n  return f;, enumerable: this})))))), (0xf86b9845))|0) / ((yield ( /x/  === this))));\\n    }\\n    {\\n      i1 = (i0);\\n    }\\n    {\\n      return +((1.0009765625));\\n    }\\n    return +((7.555786372591432e+22));\\n  }\\n  return f;\"); } catch(e2) { } this.v2 = 4.2; } else { dumpln('miss!'); try { Object.defineProperty(this, \"i1\", { configurable: ((d = arguments).hypot), enumerable: (x % 11 != 4),  get: function() {  return new Iterator(t0, true); } }); } catch(e0) { } try { a0.splice(NaN, 2); } catch(e1) { } try { /*tLoop*/for (let x of /*MARR*/[new Number(1.5),  /x/ ,  /x/ , NaN,  /x/ , new Number(1.5),  /x/ , null, NaN, new Number(1.5), new Number(1.5),  /x/ , new Number(1.5), null, NaN, null, null, new Number(1.5), NaN, null, null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  /x/ , new Number(1.5), NaN, new Number(1.5),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Number(1.5), null,  /x/ ,  /x/ , null, new Number(1.5), NaN, NaN]) { ({/*TOODEEP*/})\nv0 = v0[ /x/ ]; } } catch(e2) { } f0 = o0.a1[(4277)]; } };})();");
/*fuzzSeed-133180449*/count=338; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.min(Math.fround(( + ( ~ ( + (( ~ (Math.atan2(Math.min(y, ( + ((y >>> 0) != (y >>> 0)))), Math.fround(Math.ceil(y))) >>> 0)) >>> 0))))), Math.log(Math.hypot(Math.fround(Math.fround(Math.clz32(Math.fround(Math.hypot(y, x))))), (Math.hypot(( + Math.imul(( + x), ( + x))), ((( + mathy3(y, 2**53)) >>> 0) ^ Math.pow(y, y))) >>> 0))))); }); testMathyFunction(mathy4, [-0x080000000, -0x0ffffffff, 1, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, 0x07fffffff, -(2**53), 2**53+2, 42, Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), 0x080000000, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000000, Number.MIN_VALUE, -1/0, 0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, 2**53, -0x100000001, 1/0, -0x100000000, 0/0, 0x100000001, 0x080000001, -0x080000001]); ");
/*fuzzSeed-133180449*/count=339; tryItOut("v2 = a0.every(f2, this.o1);");
/*fuzzSeed-133180449*/count=340; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=341; tryItOut("print(x);");
/*fuzzSeed-133180449*/count=342; tryItOut("\"use strict\"; (4277);");
/*fuzzSeed-133180449*/count=343; tryItOut("/*MXX2*/g2.RegExp.prototype.source = a2;");
/*fuzzSeed-133180449*/count=344; tryItOut("print(g0);");
/*fuzzSeed-133180449*/count=345; tryItOut("Array.prototype.sort.apply(a1, [(function() { v2 = b1.byteLength; return g2; }), o0.s1]);");
/*fuzzSeed-133180449*/count=346; tryItOut("let e = (({y: Element = x}));if(new (Root(false))(eval, 28)\u0009 >>> (--testMathyFunction(mathy0, [-0x100000001, -0x080000000, 0x080000001, 0x100000001, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, Math.PI, 1, -0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 42, -(2**53-2), -1/0, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 1/0, 2**53-2, -0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, -(2**53), 0x100000000, 0x07fffffff, -0, 2**53+2, -Number.MIN_VALUE, -0x07fffffff]); )) { if (x) {print(x);v1 = evalcx(\"o2.s2 = new String;\", this.g1); }} else e0 + '';function e(z, ...w)\"use asm\";   var acos = stdlib.Math.acos;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((+acos(((d0)))));\n    (Int32ArrayView[((0xdcbbe179)+(-0x8000000)) >> 2]) = ((0xfbbbb225)+(0xfe1a31f8));\n    return +((([]) = (x+=/\\2{3,}|(?!(?:[\\d\u00cc\\cL-\\x10])|^\\w|(?:\\B)(?![^])|.^)*?/)));\n  }\n  return f;delete h0.set;a0.push();");
/*fuzzSeed-133180449*/count=347; tryItOut("\"use strict\"; s0 += s1;");
/*fuzzSeed-133180449*/count=348; tryItOut("for(let y in ((x)(([,])()))){/*infloop*/for(let z in (intern( '' ))) print((void options('strict'))); }");
/*fuzzSeed-133180449*/count=349; tryItOut("\"use strict\"; Array.prototype.reverse.call(a2);Object.prototype.unwatch.call(p2, \"set\");");
/*fuzzSeed-133180449*/count=350; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=351; tryItOut("");
/*fuzzSeed-133180449*/count=352; tryItOut("/*MXX1*/o2 = g0.Date.name;\ng2.e2.add(o2);\n");
/*fuzzSeed-133180449*/count=353; tryItOut("testMathyFunction(mathy5, [(new Boolean(false)), 0.1, (new String('')), null, true, -0, ({toString:function(){return '0';}}), NaN, 1, ({valueOf:function(){return 0;}}), '/0/', (new Number(0)), (new Number(-0)), undefined, '\\0', [0], ({valueOf:function(){return '0';}}), /0/, '0', '', (new Boolean(true)), (function(){return 0;}), objectEmulatingUndefined(), false, [], 0]); ");
/*fuzzSeed-133180449*/count=354; tryItOut("\"use strict\"; s1 += 'x';");
/*fuzzSeed-133180449*/count=355; tryItOut("if(false) for (var v of g1.g2.t1) { try { h2 = ({getOwnPropertyDescriptor: function(name) { a1.pop(w, t1, this.e0);; var desc = Object.getOwnPropertyDescriptor(o1.s1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { b0 = new ArrayBuffer(22);; var desc = Object.getPropertyDescriptor(o1.s1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { i2.send(g2.o2);; Object.defineProperty(o1.s1, name, desc); }, getOwnPropertyNames: function() { t0 + '';; return Object.getOwnPropertyNames(o1.s1); }, delete: function(name) { m0.has([,,z1]);; return delete o1.s1[name]; }, fix: function() { v2 = null;; if (Object.isFrozen(o1.s1)) { return Object.getOwnProperties(o1.s1); } }, has: function(name) { v0 = Object.prototype.isPrototypeOf.call(b2, m2);; return name in o1.s1; }, hasOwn: function(name) { t0 = new Uint8Array(a1);; return Object.prototype.hasOwnProperty.call(o1.s1, name); }, get: function(receiver, name) { (void schedulegc(g0));; return o1.s1[name]; }, set: function(receiver, name, val) { s0 += 'x';; o1.s1[name] = val; return true; }, iterate: function() { const v1 = evalcx(\"function f2(a1)  { yield window } \", g0);; return (function() { for (var name in o1.s1) { yield name; } })(); }, enumerate: function() { for (var p in g0) { v1 = Object.prototype.isPrototypeOf.call(g0.m1, t2); }; var result = []; for (var name in o1.s1) { result.push(name); }; return result; }, keys: function() { a1 = r1.exec(s2);; return Object.keys(o1.s1); } }); } catch(e0) { } try { e2.has(m1); } catch(e1) { } try { t0 = t0.subarray(7); } catch(e2) { } v0 = this.a1.reduce, reduceRight((function() { try { a0.forEach((function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 2251799813685249.0;\n    var d3 = 6.189700196426902e+26;\n    var i4 = 0;\n    var d5 = 2147483648.0;\n    var d6 = -32.0;\n    return ((((Float32ArrayView[2]))-((+(0x2dda03d6)) <= (-4398046511105.0))))|0;\n  }\n  return f; }), f0, m0, this); } catch(e0) { } try { v0 = (o0 instanceof i1); } catch(e1) { } try { v2 = (t2 instanceof v2); } catch(e2) { } g0.a2 + ''; throw s2; }), b0); } else  if (/*MARR*/[0x3FFFFFFE, 0x3FFFFFFE,  /x/ , this,  /x/ , 0x3FFFFFFE, 0x3FFFFFFE,  /x/ , 0x3FFFFFFE, this].sort(new Function)) {for (var v of b1) { f2(t2); }a2.sort((function() { try { print(uneval(this.p2)); } catch(e0) { } try { a2 = []; } catch(e1) { } try { neuter(this.b0, \"same-data\"); } catch(e2) { } /*RXUB*/var r = r1; var s = s1; print(s.match(r)); print(r.lastIndex);  return a2; })); } else {print(x); }");
/*fuzzSeed-133180449*/count=356; tryItOut("o2 = {};");
/*fuzzSeed-133180449*/count=357; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=358; tryItOut("mathy3 = (function(x, y) { return ( + ((Math.asinh((Math.hypot(((((x + x) ** x) ** (x | 0)) >>> 0), 1) >>> 0)) | 0) + (Math.asin(Math.fround(Math.max((Math.max((( + y) >>> 0), (x >>> 0)) >>> 0), Math.cosh(y)))) >>> 0))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, 1, Math.PI, -(2**53-2), 0/0, -(2**53), Number.MIN_VALUE, -1/0, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, 0x100000000, 0x100000001, 42, -0x100000000, 0, -0x0ffffffff, 2**53-2, -0x080000000, 0.000000000000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53, -0, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 1/0, 2**53+2]); ");
/*fuzzSeed-133180449*/count=359; tryItOut("i1.valueOf = (function() { try { for (var v of s0) { v1 = g0.eval(\"/* no regression tests found */\"); } } catch(e0) { } try { (void schedulegc(g1)); } catch(e1) { } /*ADP-1*/Object.defineProperty(a1, this.v1, ({value: allocationMarker(), configurable: (x % 34 != 29)})); return s0; });");
/*fuzzSeed-133180449*/count=360; tryItOut("/*RXUB*/var r = /(?:(?!\\B*)|.(?=(\\D)))\\3{4}/gyim; var s = \"_\\n\\n\\u0014\\n\\u009c\\n\\n\\n\\n _\\nD\"; print(s.replace(r, (Math.acos(-5)), \"ym\")); ");
/*fuzzSeed-133180449*/count=361; tryItOut("this.a2.forEach((function() { try { v2 = Object.prototype.isPrototypeOf.call(o2, this.i0); } catch(e0) { } try { s2 += 'x'; } catch(e1) { } e0.delete([[Math]]); return e0; }), m2, i0);");
/*fuzzSeed-133180449*/count=362; tryItOut("\"use strict\"; Array.prototype.unshift.call(a2, a1);");
/*fuzzSeed-133180449*/count=363; tryItOut("/*infloop*/for(z; ({a2:z2}); this) {(\u3056); }");
/*fuzzSeed-133180449*/count=364; tryItOut("\"use strict\"; (4277);");
/*fuzzSeed-133180449*/count=365; tryItOut("i2 + t0;p1 + '';");
/*fuzzSeed-133180449*/count=366; tryItOut("Object.defineProperty(this, \"o2\", { configurable: x, enumerable: true,  get: function() {  return Object.create(i0); } });");
/*fuzzSeed-133180449*/count=367; tryItOut("let e = x;/* no regression tests found */");
/*fuzzSeed-133180449*/count=368; tryItOut("\"use strict\"; /*bLoop*/for (aytwlf = 0; aytwlf < 57; ++aytwlf) { if (aytwlf % 6 == 5) { x = e2; } else { print( \"\" ); }  } ");
/*fuzzSeed-133180449*/count=369; tryItOut("let (x = let (w) x.throw((4277)), mnkhbp) { h2 = ({getOwnPropertyDescriptor: function(name) { Array.prototype.sort.apply(a2, [f1, a2, b0, e2]);; var desc = Object.getOwnPropertyDescriptor(e0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { (void schedulegc(g2));; var desc = Object.getPropertyDescriptor(e0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { print(uneval(v2));; Object.defineProperty(e0, name, desc); }, getOwnPropertyNames: function() { return o1.p2; return Object.getOwnPropertyNames(e0); }, delete: function(name) { return h2; return delete e0[name]; }, fix: function() { /*MXX2*/g1.Array.prototype.values = i2;; if (Object.isFrozen(e0)) { return Object.getOwnProperties(e0); } }, has: function(name) { let s1 = new String;; return name in e0; }, hasOwn: function(name) { o1.a1.unshift(t1);; return Object.prototype.hasOwnProperty.call(e0, name); }, get: function(receiver, name) { a2 = new Array;; return e0[name]; }, set: function(receiver, name, val) { throw h0; e0[name] = val; return true; }, iterate: function() { v2 = r0.sticky;; return (function() { for (var name in e0) { yield name; } })(); }, enumerate: function() { var e0 = new Set(g1.g1.t0);; var result = []; for (var name in e0) { result.push(name); }; return result; }, keys: function() { delete h1[\"expm1\"];; return Object.keys(e0); } }); }");
/*fuzzSeed-133180449*/count=370; tryItOut("with(Math.max(timeout(1800), -1099511627776)){var a, bjrgfo, hueppb, y, w, x, glbbcd, x;v1 = a2.reduce, reduceRight((function(j) { if (j) { Array.prototype.reverse.apply(a0, [o0.v0]); } else { try { for (var v of h0) { try { print(uneval(this.i2)); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(g2, t0); } catch(e1) { } g0.toString = this.f1; } } catch(e0) { } try { Array.prototype.splice.apply(a2, [NaN, 1, g2, m1]); } catch(e1) { } i2.next(); } }), window); }");
/*fuzzSeed-133180449*/count=371; tryItOut("i0.send(i0);");
/*fuzzSeed-133180449*/count=372; tryItOut("mathy3 = (function(x, y) { return Math.trunc(Math.max((( + Math.atan2((Math.imul(( + mathy2(( + 0x080000001), ( + Math.pow(x, Number.MIN_VALUE)))), (Math.pow((Math.fround(mathy1(( + ( + x)), Math.fround(((y ? -0x100000001 : (x >>> 0)) >>> 0)))) | 0), (x | 0)) | 0)) >>> 0), ((( + (-(2**53) | 0)) | 0) && ((mathy1(Math.pow(y, x), y) ? ( + (( + Number.MAX_VALUE) ? ( + -0) : ( + y))) : mathy2(y, x)) | 0)))) | 0), ((Math.clz32(((Math.tanh(Number.MAX_SAFE_INTEGER) / ( + Math.asinh(( + (x * 1.7976931348623157e308))))) >>> 0)) >>> 0) | 0))); }); testMathyFunction(mathy3, [Math.PI, -0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, 0x100000001, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, -0x080000001, -0x100000001, 0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, 42, 0x080000001, 2**53, 0x100000000, -Number.MIN_VALUE, 1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, Number.MIN_VALUE, 0.000000000000001, 2**53-2, -0x100000000, -0x07fffffff, -0x0ffffffff, -(2**53), -1/0, 1, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=373; tryItOut("L: for  each(var e in  '' ) (\u0009[,,]);function e(x, NaN, ...z)\u000c { //h\nyield x } this.g2.m1.has(b1);");
/*fuzzSeed-133180449*/count=374; tryItOut("o1.m0.set(g2.t2, p1);");
/*fuzzSeed-133180449*/count=375; tryItOut("\"use strict\"; o0.g0.v0 + '';");
/*fuzzSeed-133180449*/count=376; tryItOut("a2.shift();");
/*fuzzSeed-133180449*/count=377; tryItOut("\"use strict\"; wwspye(10);/*hhh*/function wwspye(e){for (var v of b1) { f2 = g2.objectEmulatingUndefined(); }}");
/*fuzzSeed-133180449*/count=378; tryItOut("\"use strict\"; v0 = (p1 instanceof s2);");
/*fuzzSeed-133180449*/count=379; tryItOut("\"use strict\"; o1.a1 = [];");
/*fuzzSeed-133180449*/count=380; tryItOut("Array.prototype.unshift.apply(g0.a0, [b2, (/*MARR*/[(1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), Infinity, Infinity, Infinity, Infinity, -22, Infinity, Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), -22, Infinity, objectEmulatingUndefined()].map), x]);");
/*fuzzSeed-133180449*/count=381; tryItOut("g2.offThreadCompileScript(\"function f0(o2) \\\"use asm\\\";   function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var d2 = -8388609.0;\\n    return (((0x33ab3b93)-(1)+((((+(1.0/0.0)))>>>((0xfaa2bba5)-(i1))))))|0;\\n    return ((((1) ? (((((d0) != (d2))-(i1))|0)) : (1))+(0xffffffff)))|0;\\n  }\\n  return f;\", ({ global: g2.g1, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (function (x, ...\u3056) { \"use strict\"; yield -26 } ).call((4277) ? (y =  /x/ ) : x, (\"\\uCE0E\")(), 29), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-133180449*/count=382; tryItOut("/*RXUB*/var r = r0; var s = \"\\n\\n\\n_\\u9f28_\\u9f28_\\u9f28_\\u9f28_\\u9f28_\\u9f28_\\u9f28\"; print(s.split(r)); ");
/*fuzzSeed-133180449*/count=383; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.min((( + ( ~ ( + (((y >>> 0) == (Math.fround(Math.cosh(Math.fround(Math.fround((x <= y))))) >>> 0)) >>> 0)))) >>> 0), (( ! (Math.imul(x, (0x080000000 > y)) || (Math.hypot(x, (y + x)) << (Math.hypot((x >>> 0), ((( ~ -1/0) | 0) >>> 0)) >>> 0)))) >>> 0)); }); ");
/*fuzzSeed-133180449*/count=384; tryItOut("testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, -1/0, 0x100000000, -0x07fffffff, 0, 0x0ffffffff, -0x100000001, 0.000000000000001, 42, 0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, -0x0ffffffff, -0x080000001, -(2**53), 0/0, -0x080000000, -Number.MIN_VALUE, 1, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -(2**53-2), 2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, 2**53, 1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=385; tryItOut("a2.push(((function fibonacci(bbptar) { ( \"\" );\nbreak L;\n; if (bbptar <= 1) { ; return 1; } s2 += s0;; return fibonacci(bbptar - 1) + fibonacci(bbptar - 2); print(uneval(g1.i1)); })(3)), s2, e1);");
/*fuzzSeed-133180449*/count=386; tryItOut("testMathyFunction(mathy2, [Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 2**53, Math.PI, 0x0ffffffff, -0, -0x100000000, -0x080000000, -(2**53), 0x100000001, -Number.MAX_VALUE, 1/0, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, 2**53-2, -(2**53-2), -(2**53+2), -1/0, 0x100000000, 0.000000000000001, 0/0, 1, Number.MIN_SAFE_INTEGER, -0x080000001, 0]); ");
/*fuzzSeed-133180449*/count=387; tryItOut("s2 = a2.join();");
/*fuzzSeed-133180449*/count=388; tryItOut("/*RXUB*/var r = ({a1:1}); var s = \"a\"; print(s.match(r)); ");
/*fuzzSeed-133180449*/count=389; tryItOut("o1.a2[18] = this.p2;");
/*fuzzSeed-133180449*/count=390; tryItOut("Array.prototype.push.apply(a2, [a2, f2, e2, m1]);");
/*fuzzSeed-133180449*/count=391; tryItOut("var lqpgbd = new ArrayBuffer(4); var lqpgbd_0 = new Float64Array(lqpgbd); lqpgbd_0[0] = 22; var lqpgbd_1 = new Float64Array(lqpgbd); lqpgbd_1[0] = 26; var lqpgbd_2 = new Uint8Array(lqpgbd); lqpgbd_2[0] = 27; var lqpgbd_3 = new Float64Array(lqpgbd); lqpgbd_3[0] = -16; var lqpgbd_4 = new Uint32Array(lqpgbd); var lqpgbd_5 = new Float32Array(lqpgbd); lqpgbd_5[0] = -4; print(lqpgbd);print(new  '' );/*MXX1*/const g0.o0 = g0.Date.prototype.getMilliseconds;v0 = g2.runOffThreadScript();t1[v1] = i0;");
/*fuzzSeed-133180449*/count=392; tryItOut("/*RXUB*/var r = /\\2/m; var s = \"\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-133180449*/count=393; tryItOut("\"use strict\"; a2.sort((function() { for (var j=0;j<20;++j) { o0.f0(j%5==1); } }));");
/*fuzzSeed-133180449*/count=394; tryItOut("\"use strict\"; e1.has(g0);");
/*fuzzSeed-133180449*/count=395; tryItOut("v2 = g2.g1.eval(\"a1.__proto__ = m1;\");");
/*fuzzSeed-133180449*/count=396; tryItOut("with({x: x}){print(x);print(window); }");
/*fuzzSeed-133180449*/count=397; tryItOut("p0 + b0;");
/*fuzzSeed-133180449*/count=398; tryItOut("/*hhh*/function fbrqbj(w){/*RXUB*/var r = /(?=(?:\\2*))*/; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); }/*iii*/i2.toString = (function mcc_() { var wvaxeq = 0; return function() { ++wvaxeq; if (/*ICCD*/wvaxeq % 5 == 3) { dumpln('hit!'); try { g0.toString = (function mcc_() { var hnwdab = 0; return function() { ++hnwdab; if (/*ICCD*/hnwdab % 5 == 0) { dumpln('hit!'); try { ; } catch(e0) { } h2.__iterator__ = f1; } else { dumpln('miss!'); try { v1 = Object.prototype.isPrototypeOf.call(t0, b2); } catch(e0) { } /*ADP-3*/Object.defineProperty(a0, ({valueOf: function() { /*ADP-1*/Object.defineProperty(a1, 8, ({configurable: \"\\u0C8A\"}));return 17; }}), { configurable: (x % 34 != 9), enumerable: true, writable: true, value: i0 }); } };})(); } catch(e0) { } try { /*RXUB*/var r = r0; var s = s1; print(r.exec(s));  } catch(e1) { } i1.valueOf = function(q) { return q; }; } else { dumpln('miss!'); g0.v2 = Object.prototype.isPrototypeOf.call(this.a0, i1); } };})();");
/*fuzzSeed-133180449*/count=399; tryItOut("\"use strict\"; s1 = '';");
/*fuzzSeed-133180449*/count=400; tryItOut("s1 += 'x';");
/*fuzzSeed-133180449*/count=401; tryItOut("t2[2] = b1;");
/*fuzzSeed-133180449*/count=402; tryItOut("mathy3 = (function(x, y) { return mathy0(Math.fround(Math.fround(mathy1(Math.fround(( + (Math.fround(Math.log2(((Math.fround(y) ^ -0x080000000) * (Math.log1p((-0x100000001 | 0)) | 0)))) - (y >>> 0)))), Math.fround(( + Math.max(Math.hypot(y, Math.fround(Math.min(x, Number.MAX_VALUE))), ( ! ((x >>> 0) | (( + y) ** y))))))))), (Math.log(( - Math.atanh(( + ( + ( + y)))))) >>> 0)); }); ");
/*fuzzSeed-133180449*/count=403; tryItOut("mathy2 = (function(x, y) { return mathy0(((Math.fround(Math.cos(Math.fround(x))) % (-Number.MIN_VALUE * Math.hypot(-0x07fffffff, ( + ( + ((Math.atan2((x >>> 0), y) >>> 0) % ( + (Math.atanh(Math.fround(Math.pow(x, Math.fround(-0x100000000)))) >>> 0)))))))) | 0), (Math.hypot(((( ! Math.fround((Math.fround(Math.tan(Math.fround(( + Math.imul(( + -0x100000000), ( + x)))))) , (mathy0((Math.atan2((( ~ Number.MAX_SAFE_INTEGER) | 0), (Math.pow(Math.fround(x), (x >>> 0)) >>> 0)) | 0), ((4277) | 0)) | 0)))) | 0) | 0), ((Math.clz32(Math.fround(((Math.ceil(x) * ((Math.log2(Math.hypot(x, Math.fround(Math.min(Math.fround(x), x)))) | 0) | 0)) | 0))) | 0) | 0)) | 0)); }); testMathyFunction(mathy2, [-0x07fffffff, 0x080000001, 0x0ffffffff, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, -0x100000001, -0x080000000, 1.7976931348623157e308, -(2**53), 0, -Number.MIN_VALUE, 2**53, 0x100000000, 2**53-2, 0x100000001, -Number.MAX_VALUE, -0, -(2**53+2), -0x100000000, 2**53+2, Number.MAX_VALUE, 1/0, 1, 0.000000000000001, 42, -1/0]); ");
/*fuzzSeed-133180449*/count=404; tryItOut("-0;function window(...eval)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    i0 = (i0);\n    return ((((-0x7a288cb) ? (((0xf9150252) ? (0xe4f79269) : (0xf8d0075c)) ? (i0) : ((2.3611832414348226e+21) == (-3.094850098213451e+26))) : (-0x8000000))-(i0)+(i0)))|0;\n  }\n  return f;h2.keys = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\ne1.has(g0);    i1 = (i1);\n    {\n      i1 = (i0);\n    }\n    i1 = (i0);\n    return +((function(id) { return id }()));\n    i0 = ((i0) ? (i0) : (i1));\n    {\n      i0 = (1);\n    }\n    return +((-1.1805916207174113e+21));\n  }\n  return f; });function x() { yield var qcuusm = new SharedArrayBuffer(4); var qcuusm_0 = new Uint8Array(qcuusm); qcuusm_0[0] = 22; var qcuusm_1 = new Float32Array(qcuusm); var qcuusm_2 = new Uint32Array(qcuusm); var qcuusm_3 = new Float64Array(qcuusm); qcuusm_3[0] = 8; var qcuusm_4 = new Uint8Array(qcuusm); var qcuusm_5 = new Int16Array(qcuusm); qcuusm_5[0] = 15; var qcuusm_6 = new Uint16Array(qcuusm); var qcuusm_7 = new Int32Array(qcuusm); b2 + ''; '' ;/(?=(?=.{1})\\S|\u4710)|\\b+.|.|[^]{549755813889,}|\\3*{4,8}/gy; } /*RXUB*/var r = /(?:(?:(?!\\3|[\\w\\\u6243-\u2130\\S])|\\2\\w\\w\\b[^]+?)(?=\\W)(?:(?!.))*)/; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-133180449*/count=405; tryItOut("a1.shift(v0, h1, x--, b2);");
/*fuzzSeed-133180449*/count=406; tryItOut("print( '' );a0.sort(f0);");
/*fuzzSeed-133180449*/count=407; tryItOut("mathy0 = (function(x, y) { return (( + (( + Math.min(( + Math.hypot(Math.fround((Math.fround(Math.asinh((x | 0))) ** ( + (Math.atan2((x | 0), x) | 0)))), (( + y) >>> 0))), ( + Math.pow(( + Math.ceil(( + Math.round(( + Math.min((x | 0), (( + x) ? y : x))))))), ( ! y))))) | 0)) | 0); }); testMathyFunction(mathy0, /*MARR*/[ \"\" , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 2**53+2, new Number(1.5), 2**53+2, new Number(1.5), new Number(1.5), new Number(1.5),  \"\" , new Number(1.5),  \"\" ,  \"\" , new Number(1.5),  \"\" , new Number(1.5), new Number(1.5),  \"\" , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 2**53+2, 2**53+2,  \"\" ]); ");
/*fuzzSeed-133180449*/count=408; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.cbrt((Math.min(( + Math.imul(( + ( ~ Math.fround(( ! ( + ( + (( + y) << ( + x)))))))), 2**53)), ((Math.sign(Math.acos(( + x))) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-0x07fffffff, 1, -0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), 0x100000000, -Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, 1.7976931348623157e308, 42, Number.MIN_VALUE, 0, 0x080000001, -0x100000001, Number.MAX_VALUE, -0, 0.000000000000001, -(2**53-2), 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0x0ffffffff, 0x100000001, 2**53, 0x080000000, 0/0, 1/0, Number.MIN_SAFE_INTEGER, -1/0, -0x080000000]); ");
/*fuzzSeed-133180449*/count=409; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[ \"use strict\" ,  '\\0' , new Boolean(false), new Boolean(false),  '\\0' ,  '\\0' ,  '\\0' ,  \"use strict\" , Infinity,  \"use strict\" , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  \"use strict\" ,  \"use strict\" , new Boolean(false),  \"use strict\" , Infinity, new Boolean(false), new Boolean(false), new Boolean(false),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  '\\0' , Infinity, new Boolean(false), Infinity,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Boolean(false),  '\\0' ,  '\\0' , Infinity, Infinity, new Boolean(false),  \"use strict\" ,  '\\0' ,  '\\0' , Infinity, Infinity,  \"use strict\" ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new Boolean(false),  \"use strict\" , Infinity, Infinity, new Boolean(false),  \"use strict\" , new Boolean(false), Infinity,  \"use strict\" ,  \"use strict\" , new Boolean(false), Infinity,  \"use strict\" , new Boolean(false),  \"use strict\" ,  \"use strict\" , Infinity,  '\\0' ,  \"use strict\" ,  \"use strict\" , new Boolean(false),  \"use strict\" , new Boolean(false),  \"use strict\" ,  '\\0' , Infinity, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  '\\0' , Infinity,  \"use strict\" , new Boolean(false), Infinity, Infinity, new Boolean(false),  \"use strict\" ,  \"use strict\" , Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity,  '\\0' , new Boolean(false),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new Boolean(false),  \"use strict\" ,  \"use strict\" , Infinity, new Boolean(false), Infinity, Infinity, new Boolean(false), Infinity, new Boolean(false), Infinity, new Boolean(false),  \"use strict\" , new Boolean(false), new Boolean(false),  \"use strict\" ,  \"use strict\" , Infinity, new Boolean(false), Infinity,  \"use strict\" , new Boolean(false),  '\\0' , Infinity,  '\\0' , new Boolean(false),  '\\0' ,  \"use strict\" ,  '\\0' , Infinity,  '\\0' , Infinity,  '\\0' ,  \"use strict\" , Infinity, Infinity, new Boolean(false),  '\\0' ,  '\\0' , new Boolean(false), Infinity,  '\\0' , Infinity, new Boolean(false), Infinity,  \"use strict\" ,  \"use strict\" ,  '\\0' ,  \"use strict\" ,  '\\0' ,  \"use strict\" , new Boolean(false),  '\\0' ,  '\\0' , new Boolean(false), Infinity, new Boolean(false), Infinity, Infinity]) { ((eval) = [,]); }");
/*fuzzSeed-133180449*/count=410; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.acosh(Math.fround(( ! ( ! (( + x) >>> 0)))))); }); testMathyFunction(mathy3, [true, /0/, 0, '\\0', objectEmulatingUndefined(), 0.1, [0], false, null, (new String('')), (new Boolean(true)), (new Number(0)), NaN, -0, ({valueOf:function(){return 0;}}), [], undefined, '', ({toString:function(){return '0';}}), (function(){return 0;}), '0', 1, (new Number(-0)), '/0/', ({valueOf:function(){return '0';}}), (new Boolean(false))]); ");
/*fuzzSeed-133180449*/count=411; tryItOut("print(x);\nString.prototype.charAt\n");
/*fuzzSeed-133180449*/count=412; tryItOut("b1.toSource = (function() { try { v2 = a2.length; } catch(e0) { } try { v2 = (g2.t1 instanceof g1); } catch(e1) { } try { Object.defineProperty(this, \"h0\", { configurable: ({NaN: x}), enumerable: false,  get: function() {  return {}; } }); } catch(e2) { } e2.has(b1); return this.m1; });");
/*fuzzSeed-133180449*/count=413; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?=(([^\\\\v-\\ueff5\\\\b-\\\\\\u008b])){4,6})|\\\\B[^]\\u00e7)|((?!\\uc5fd)\\\\2)\", \"g\"); var s = \"sssssss\\ue9ee\"; print(r.test(s)); ");
/*fuzzSeed-133180449*/count=414; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        {\n          {\n            {\n              d0 = (d0);\n            }\n          }\n        }\n      }\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: (function(x, y) { return Math.fround(Math.sqrt(y)); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0/0, Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, -0, -0x080000000, -(2**53-2), 1, Number.MIN_VALUE, -1/0, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), 42, -0x080000001, 0, 2**53-2, 0x100000001, 0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 0.000000000000001, Math.PI, 0x080000000, -0x0ffffffff, 0x100000000, 0x0ffffffff, 1/0, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=415; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-133180449*/count=416; tryItOut("\"use strict\"; (1);v0.__proto__ = a0;");
/*fuzzSeed-133180449*/count=417; tryItOut("var v2 = g1.eval(\"g2.__proto__ = o1.o0.f0;\");");
/*fuzzSeed-133180449*/count=418; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"f2.toSource = f2;\");");
/*fuzzSeed-133180449*/count=419; tryItOut("a1.shift();function d() { yield x } v1 = Object.prototype.isPrototypeOf.call(this.p1, e0);\nprint(x);\n");
/*fuzzSeed-133180449*/count=420; tryItOut("v1 = Object.prototype.isPrototypeOf.call(m0, g2);");
/*fuzzSeed-133180449*/count=421; tryItOut("\"use strict\"; print((void options('strict')));");
/*fuzzSeed-133180449*/count=422; tryItOut("/*ODP-1*/Object.defineProperty(s2, \"caller\", ({get: function(y) { yield y; allocationMarker();; yield y; }, set: DFGTrue, configurable: false}));");
/*fuzzSeed-133180449*/count=423; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ! Math.fround(( ~ (( + Math.atan2(( ! (( + (Number.MIN_VALUE / ( + y))) | 0)), Math.acos((( + Math.fround(Math.ceil(Math.fround(Math.fround(( ~ Math.fround(-Number.MIN_VALUE))))))) | 0)))) >>> 0)))); }); testMathyFunction(mathy4, [(new Number(-0)), (new String('')), '', NaN, null, 0.1, false, (new Boolean(true)), '\\0', true, (new Boolean(false)), -0, [], 1, ({valueOf:function(){return '0';}}), undefined, 0, objectEmulatingUndefined(), /0/, (new Number(0)), '0', ({toString:function(){return '0';}}), [0], (function(){return 0;}), ({valueOf:function(){return 0;}}), '/0/']); ");
/*fuzzSeed-133180449*/count=424; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.cosh(Math.fround((( + ((Math.expm1(0x100000000) >>> 0) >= ((((( + (0/0 !== (Math.imul((y >>> 0), (( ~ x) >>> 0)) >>> 0))) | 0) > (Math.round(y) | 0)) | 0) >>> 0))) === Math.hypot(((((x | 0) , (( + x) | 0)) | 0) ? -1/0 : -0x080000000), 2**53))))); }); testMathyFunction(mathy0, [-0x080000000, 0x07fffffff, 1.7976931348623157e308, 2**53-2, Number.MAX_VALUE, 0/0, Math.PI, 2**53, 2**53+2, 0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, -0x0ffffffff, -0, 0x0ffffffff, 0.000000000000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, -(2**53), 42, -(2**53-2), 1, 0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000001, 1/0, -0x07fffffff, 0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=425; tryItOut("eval = z, fdpcer, wjlqja, opngza;print(-23);");
/*fuzzSeed-133180449*/count=426; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((mathy1((( + (( + ( + ( + Math.cbrt(Math.fround(( ! ( + Math.max((y >>> 0), (y | 0))))))))) ? Math.fround(Math.imul(Math.fround(2**53), Math.fround(x))) : ( ! ( + Math.max(Math.fround(Math.cosh(x)), ( - x)))))) | 0), ( + (( ! x) == Math.fround(Math.max(x, Math.hypot((( - (( ! 1) | 0)) | 0), y)))))) >>> 0) ? ( + (( + (((( + Math.imul(( + y), ( + ( ~ y)))) >>> 0) < (x >>> 0)) >>> 0)) - ( + (((((( + Math.log1p(( + Math.atanh(((x >>> 0) != (Number.MAX_SAFE_INTEGER >>> 0)))))) | 0) ? Math.fround(Math.cos(Math.fround(1/0))) : ( + (( + x) && ( + y)))) | 0) + (( ~ (((x | 0) * y) | 0)) | 0)) | 0)))) : Math.asinh((Math.fround((Math.fround((( ! (Math.fround(( ! x)) | 0)) | 0)) + Math.fround(( + Math.pow(( + x), ( + (x >> x))))))) | 0))); }); testMathyFunction(mathy2, [0.000000000000001, 0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -0, 1.7976931348623157e308, 2**53-2, 2**53, Math.PI, 2**53+2, -(2**53), 0x100000001, 0x080000000, 1/0, 0/0, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 42, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, -(2**53+2), -0x100000000, 1, -0x100000001, 0]); ");
/*fuzzSeed-133180449*/count=427; tryItOut("{a1.reverse(m0, this.s1); }\nFloat64Array;/*infloop*/M:do {t0 = new Float32Array(g1.a0);g1.a0.shift(g2); } while(x);\n");
/*fuzzSeed-133180449*/count=428; tryItOut("for (var p in g2) { Object.prototype.watch.call(p2, \"constructor\", (function(j) { if (j) { try { var v1 = g2.eval(\"/* no regression tests found */\"); } catch(e0) { } e1.delete(b1); } else { try { a0[13] = \"\\u52DC\"; } catch(e0) { } try { t1[5]; } catch(e1) { } try { for (var p in g0.o1) { try { g0 = m0.get(i2); } catch(e0) { } i0 + ''; } } catch(e2) { } (void schedulegc(g2)); } })); }");
/*fuzzSeed-133180449*/count=429; tryItOut("b0 = t0[([ /* Comment */('fafafa'.replace(/a/g, Function))])];");
/*fuzzSeed-133180449*/count=430; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (!(((0x313c9caf) > ((((-0x8000000))-(i2))>>>((Int16ArrayView[((0xfdd91474)) >> 1])))) ? (i2) : (0x3c44708c)));\n    i1 = (((((0xd66b2984) > (0x43380ae5))-((0xa724428e))+((((i1)-(i2))|0))) | ((0x4372a0ef)+((((i2)) | ((i1)+(/*FFI*/ff(((-3.0)), ((65.0)), ((-2.4178516392292583e+24)))|0)-(i2))))+((0x3fd74f33)))));\n    i2 = (0xfb2b9381);\n    {\n      (Int32ArrayView[((0xe17e78c8)) >> 2]) = (((Float32ArrayView[2])) / (((uneval('fafafa'.replace(/a/g, eval))))));\n    }\n    return (((/*FFI*/ff(((d0)))|0)*0xfffff))|0;\n  }\n  return f; })(this, {ff: DataView}, new ArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=431; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(( ! Math.sin(y))) < Math.fround((Math.min(( ! x), Math.fround(0.000000000000001)) != (((( + y) | 0) - (Math.fround((y ^ x)) | 0)) | 0))))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000, -0x100000001, 2**53, 0x100000001, -0x07fffffff, -0x080000001, 0x07fffffff, 1, 1.7976931348623157e308, -0x100000000, -0, -1/0, 0, Number.MAX_VALUE, -0x0ffffffff, 0/0, Number.MIN_VALUE, 0x080000000, 0x080000001, 0x0ffffffff, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, -(2**53-2), -(2**53+2), 1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2]); ");
/*fuzzSeed-133180449*/count=432; tryItOut("L: for (var a of x) o0 = new Object;");
/*fuzzSeed-133180449*/count=433; tryItOut("v0 = a0.length;");
/*fuzzSeed-133180449*/count=434; tryItOut("\"use strict\"; /*hhh*/function tedvct(){for (var p in v0) { try { g1.offThreadCompileScript(\"v0.valueOf = (function mcc_() { var ifahuq = 0; return function() { ++ifahuq; if (/*ICCD*/ifahuq % 3 != 0) { dumpln('hit!'); s1 += 'x'; } else { dumpln('miss!'); h1 + ''; } };})();\"); } catch(e0) { } try { for (var p in p1) { a1 = []; } } catch(e1) { } e2.add(h0); }}tedvct([var r0 = x | x; print(r0); x = 9 % x; var r1 = 3 / x; var r2 = r0 * r1; var r3 = r1 + r2; var r4 = r1 % 5; var r5 = r3 - r2; r3 = 5 & r1; var r6 = r3 / x; var r7 = r2 & 7; var r8 = x & r0; var r9 = r2 % r4; var r10 = 5 / 2; var r11 = 5 % r2; var r12 = 3 | r3; var r13 = r1 % 3; var r14 = r13 + r3; var r15 = r9 | 8; var r16 = r2 ^ 6; var r17 = 1 | 4; var r18 = r0 * 4; var r19 = r14 % r15; var r20 = 7 & r8; r12 = 3 & 3; r7 = r4 - r7; r3 = r17 * 2; var r21 = r9 | r15; var r22 = r21 - r10; var r23 = 9 * r4; r11 = r22 - r12; var r24 = r21 / 2; var r25 = r4 / r13; var r26 = r9 | 1; var r27 = r25 / r23; var r28 = r18 + 2; var r29 = r10 * r3; var r30 = r24 + r4; r21 = r25 % r30; var r31 = 7 % 3; ], x);");
/*fuzzSeed-133180449*/count=435; tryItOut("mathy5 = (function(x, y) { return ((Math.min(((Math.imul((( ! ((( ~ ( + y)) >>> 0) >>> 0)) >>> 0), (Number.MIN_VALUE ? y : -0)) | 0) * (Math.sin(((x >> (0x080000000 >>> 0)) >>> 0)) | 0)), (((Math.max(x, (x >>> 0)) >>> 0) * Math.atan(((-(2**53) != (Math.min(( + x), ( + (((y >>> 0) && (-(2**53) >>> 0)) >>> 0))) >>> 0)) | 0))) >>> 0)) >>> 0) % Math.atan(Math.tanh(( ~ 0x080000001)))); }); testMathyFunction(mathy5, [-0x100000001, 2**53+2, Math.PI, 0x07fffffff, -0x080000001, -(2**53-2), Number.MAX_VALUE, -1/0, 2**53-2, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000001, 2**53, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 0x080000001, -0, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 1, 0x100000000, 42, 0x080000000, 1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0x080000000, -(2**53), -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-133180449*/count=436; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=437; tryItOut("\"use strict\"; x = x - x; var r0 = x & 0; var r1 = 8 * x; var r2 = 1 + r1; var r3 = r2 / 7; var r4 = r1 * 8; var r5 = 9 & 8; var r6 = 1 * r5; var r7 = r6 | 8; print(r0); var r8 = 2 + r3; print(r8); ");
/*fuzzSeed-133180449*/count=438; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (( ~ ( + Math.hypot(( + Math.atan2(( + Math.atan2(( + y), ( + y))), Math.fround(( + Math.fround(y))))), ( + 42)))) ^ (Math.trunc(((x ? y : x) >>> 0)) * mathy1((Math.log1p((y | 0)) | 0), y))); }); testMathyFunction(mathy2, /*MARR*/[0x080000001, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, new Number(1.5), 0x080000001, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x3FFFFFFE, 0x080000001, new Number(1.5), new Number(1.5), 0x080000001, 0x080000001, 0x3FFFFFFE, 0x080000001, new Number(1.5), 0x3FFFFFFE, new Number(1.5), 0x3FFFFFFE, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x3FFFFFFE, 0x080000001, new Number(1.5), new Number(1.5), 0x080000001, 0x080000001, new Number(1.5), 0x080000001, new Number(1.5), new Number(1.5), 0x080000001, 0x080000001, 0x3FFFFFFE, 0x080000001, 0x080000001, 0x3FFFFFFE, 0x080000001, 0x3FFFFFFE, 0x3FFFFFFE, new Number(1.5), 0x3FFFFFFE, new Number(1.5), 0x3FFFFFFE, 0x080000001, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, new Number(1.5), 0x3FFFFFFE, new Number(1.5), new Number(1.5), 0x080000001, 0x080000001, 0x080000001, 0x3FFFFFFE, 0x3FFFFFFE, 0x080000001, new Number(1.5), 0x080000001, 0x3FFFFFFE, 0x3FFFFFFE, 0x080000001, new Number(1.5), 0x3FFFFFFE]); ");
/*fuzzSeed-133180449*/count=439; tryItOut("/*tLoop*/for (let a of /*MARR*/[(void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined()]) { print(a); }");
/*fuzzSeed-133180449*/count=440; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + ( ~ Math.fround((Math.tanh((Math.log1p(Math.trunc(( + ((x != (-0x080000000 >>> 0)) >>> 0)))) / Math.imul(( + ((x > (Math.atanh((x >>> 0)) >>> 0)) >>> 0)), (( ~ (Number.MAX_VALUE | 0)) | 0)))) | 0)))); }); testMathyFunction(mathy5, [-0x0ffffffff, 2**53+2, 2**53-2, -0, 1, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x07fffffff, Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, -(2**53-2), 0x080000000, 0x07fffffff, 42, 0x0ffffffff, 0/0, -0x080000000, 1.7976931348623157e308, -(2**53), -0x080000001, 2**53, Number.MAX_VALUE, 1/0, Number.MIN_VALUE, -(2**53+2), 0, -1/0, 0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=441; tryItOut("/*RXUB*/var r = /(?:(((?![\\cM-S])){0,2}.{3,}\\b*|\\D(?:.){0,3}*)?)/gym; var s = \"RRRRRRRRRRRRRR\"; print(r.exec(s)); ");
/*fuzzSeed-133180449*/count=442; tryItOut("Array.prototype.pop.call(o0.g2.a2);");
/*fuzzSeed-133180449*/count=443; tryItOut("/*MXX2*/this.g0.Function.prototype.constructor = h0;");
/*fuzzSeed-133180449*/count=444; tryItOut("testMathyFunction(mathy3, [2**53, -0x07fffffff, Math.PI, -(2**53+2), -1/0, Number.MIN_SAFE_INTEGER, 42, 0x100000000, -0x080000001, 1, Number.MAX_VALUE, -(2**53-2), 0x080000000, -(2**53), 1/0, -0x0ffffffff, -0x080000000, 0x080000001, 0, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, -0x100000001, 1.7976931348623157e308, 0x0ffffffff, 2**53+2, 0/0, 0x100000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-133180449*/count=445; tryItOut("\"use strict\"; s1 += s0;");
/*fuzzSeed-133180449*/count=446; tryItOut("b0 + '';");
/*fuzzSeed-133180449*/count=447; tryItOut("\"use asm\"; var [x, ] = x.__proto__, \u3056 = ((Math.max(-11, undefined)) && x(x, x)), d, iymywm, olfwgm, x = ((makeFinalizeObserver('nursery'))), x, NaN;print(uneval(this.i2));");
/*fuzzSeed-133180449*/count=448; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -0, Number.MAX_VALUE, -Number.MIN_VALUE, 1, -1/0, -(2**53-2), 0, 1.7976931348623157e308, -(2**53+2), 2**53-2, -(2**53), 42, Math.PI, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, -0x080000000, Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, 1/0, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, -0x07fffffff, 0x100000000, -0x100000001, 0x080000001, -0x0ffffffff, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=449; tryItOut("if(x) var b, z, w = this.__defineSetter__(\"x\", new RegExp(\"\\u009a[\\\\x15-\\u00ef\\u3688]\", \"yim\")), x, rwypzz, ygqdtm, b, this.NaN;Array.prototype.unshift.apply(a1, [g2.s0, h0]); else  if ((p={}, (p.z = (yield Math.sign(3922218155)))())) /*infloop*/for(var this.NaN in (Set.prototype.delete).call(x <= (x = y), this.\u0009__defineGetter__(\"d\",  \"\" ), new RegExp(\"\\\\d{1}\", \"gyim\") && this)) for (var v of m1) { /*RXUB*/var r = r2; var s = \"\"; print(s.replace(r, c => \"use asm\";   var ceil = stdlib.Math.ceil;\n  var Infinity = stdlib.Infinity;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[((i0)) >> 2]) = ((this.__defineGetter__(\"x\", runOffThreadScript)));\n    return +((+ceil(((Infinity)))));\n  }\n  return f;, \"\")); print(r.lastIndex);  } else a0.valueOf = (function() { try { /*MXX3*/g0.DataView.prototype.getFloat32 = this.g2.DataView.prototype.getFloat32; } catch(e0) { } /*ADP-1*/Object.defineProperty(a0, 9, ({configurable: true})); return b1; });");
/*fuzzSeed-133180449*/count=450; tryItOut("t1 = t2.subarray(v0);");
/*fuzzSeed-133180449*/count=451; tryItOut("testMathyFunction(mathy3, [2**53, 0x080000000, 1, -0x080000000, -Number.MAX_VALUE, -0, 1.7976931348623157e308, 0x080000001, -(2**53), -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001, 0x0ffffffff, 2**53+2, -Number.MIN_VALUE, 0, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, 0x100000001, 1/0, Math.PI, 2**53-2, 0x100000000, -0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, -(2**53-2), -(2**53+2), 42, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=452; tryItOut("\"use strict\"; f1.valueOf = Object.getOwnPropertyDescriptors.bind(o1);");
/*fuzzSeed-133180449*/count=453; tryItOut("\"use strict\"; y.fileName;x = eval;");
/*fuzzSeed-133180449*/count=454; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=455; tryItOut("a2 = this.a1.concat(this.a1, o1.s2);");
/*fuzzSeed-133180449*/count=456; tryItOut("o0 = v2.__proto__;");
/*fuzzSeed-133180449*/count=457; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1.5474250491067253e+26;\n    i1 = (0x7ad7f041);\n    {\n      d2 = (d2);\n    }\n    return (((!(i1))+(0xb27cd5bd)))|0;\n  }\n  return f; })(this, {ff: (objectEmulatingUndefined).bind()}, new ArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=458; tryItOut("m0.set(v0, t1);");
/*fuzzSeed-133180449*/count=459; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[function(){}, function(){}, false, false, new String('q'), function(){}, (-1/0), new String('q'), false, function(){}, false, function(){}, new String('q'), false, function(){}, (-1/0), function(){}, false, new String('q'), false, false, (-1/0), function(){}, new String('q'), false, new String('q'), false, false, (-1/0), false, function(){}, function(){}, false, (-1/0), false, function(){}]); ");
/*fuzzSeed-133180449*/count=460; tryItOut("testMathyFunction(mathy0, [0x100000001, 42, -Number.MAX_VALUE, 0/0, 0.000000000000001, -0x100000000, -1/0, 1, Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 0, -(2**53), -(2**53-2), 1.7976931348623157e308, -0, -0x100000001, 0x080000001, 0x100000000, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53+2), -Number.MIN_VALUE, 0x07fffffff, -0x080000001, -0x07fffffff, -0x080000000, Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-133180449*/count=461; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[NaN, function(){}, this, NaN, new String('q'), function(){}, NaN, NaN, NaN, NaN, NaN, new String('q'), NaN, function(){}, NaN, new String('q'), NaN, new String('q'),  /x/g ]); ");
/*fuzzSeed-133180449*/count=462; tryItOut("this.g1.offThreadCompileScript(\"for (var v of m1) { try { for (var p in g1) { try { o1 = t1; } catch(e0) { } try { g2.h1.set = f1; } catch(e1) { } try { ; } catch(e2) { } a1.push(g2.v2, this.g0.p1, m2, o0.f0, t0, t1, s0, b0, arguments.callee.caller.caller.caller.arguments >>= Math.sqrt( \\\"\\\" ), -15,  '' ); } } catch(e0) { } g1 = o1.a1[v2]; }\");");
/*fuzzSeed-133180449*/count=463; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=464; tryItOut("/*infloop*/for(var a in ((function(q) { \"use strict\"; return q; })(length))){t0 + ''; }");
/*fuzzSeed-133180449*/count=465; tryItOut("\"use strict\"; m2.get(p2);");
/*fuzzSeed-133180449*/count=466; tryItOut("this.v1 = t2.length;");
/*fuzzSeed-133180449*/count=467; tryItOut("m1.set(this.h2, (uneval((++x))));");
/*fuzzSeed-133180449*/count=468; tryItOut("for (var p in f1) { try { a0.forEach(g1.o2, a1, this.o1.p0); } catch(e0) { } try { /*RXUB*/var r = r1; var s = s2; print(uneval(r.exec(s)));  } catch(e1) { } f2 = Proxy.createFunction(h2, f2, o1.f0); }");
/*fuzzSeed-133180449*/count=469; tryItOut("v1 = new Number(Infinity);");
/*fuzzSeed-133180449*/count=470; tryItOut("print(uneval(f2));");
/*fuzzSeed-133180449*/count=471; tryItOut("\"use strict\"; /*vLoop*/for (iwjxte = 0; iwjxte < 1; ++iwjxte) { let z = iwjxte; print(z); } ");
/*fuzzSeed-133180449*/count=472; tryItOut("\"use strict\"; for(let c in x) {a1.__proto__ = o1.t2; }");
/*fuzzSeed-133180449*/count=473; tryItOut("v0.toString = (function() { f0 + ''; return h0; });\no1.v2 = evaluate(\"function f2(this.o1) y\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  '' , noScriptRval: new RegExp(\"\\\\B\", \"im\"), sourceIsLazy: undefined, catchTermination: false, elementAttributeName: s2 }));x;\u0009\n");
/*fuzzSeed-133180449*/count=474; tryItOut("for (var p in i1) { try { h2.getPropertyDescriptor = (function() { Array.prototype.reverse.apply(a0, []); return b1; }); } catch(e0) { } try { a0.reverse(h0, g1); } catch(e1) { } try { print(g0); } catch(e2) { } v2 = (a0 instanceof p1); }");
/*fuzzSeed-133180449*/count=475; tryItOut("var dkuihr = new ArrayBuffer(4); var dkuihr_0 = new Float64Array(dkuihr); print(dkuihr_0[0]); var dkuihr_1 = new Uint16Array(dkuihr); dkuihr_1[0] = 26; var dkuihr_2 = new Float32Array(dkuihr); dkuihr_2[0] = -19; Object.defineProperty(this, \"v2\", { configurable: false, enumerable: false,  get: function() {  return false; } });\n/*oLoop*/for (var oszosw = 0; oszosw < 9; ++oszosw) { /* no regression tests found */ } \n");
/*fuzzSeed-133180449*/count=476; tryItOut("");
/*fuzzSeed-133180449*/count=477; tryItOut("o0.p1.__iterator__ = (function() { for (var j=0;j<56;++j) { f0(j%5==0); } });");
/*fuzzSeed-133180449*/count=478; tryItOut("throw  \"\" ;-0;");
/*fuzzSeed-133180449*/count=479; tryItOut("m1.toString = (function mcc_() { var otadwx = 0; return function() { ++otadwx; f1(/*ICCD*/otadwx % 10 == 1);};})();");
/*fuzzSeed-133180449*/count=480; tryItOut("/*oLoop*/for (let ezsmfk = 0; ezsmfk < 106; ++ezsmfk) { v0 = (g1.i1 instanceof v0); } ");
/*fuzzSeed-133180449*/count=481; tryItOut("m0 + h1;");
/*fuzzSeed-133180449*/count=482; tryItOut("for (var p in this.g0) { try { e2.toSource = (function() { try { v2 = (b1 instanceof p2); } catch(e0) { } try { /*MXX1*/o1 = g1.Math.expm1; } catch(e1) { } try { v1 = evaluate(\"(4277)\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 95 != 69), sourceIsLazy: true, catchTermination: true, elementAttributeName: s1, sourceMapURL: s2 })); } catch(e2) { } a2.reverse(i1, t2, f0); return a1; }); } catch(e0) { } t0[/*UUV1*/(e.assign = (function handlerFactory(x) {return {getOwnPropertyDescriptor: Float64Array, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: undefined, has: Date.prototype.getFullYear, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: /*wrap1*/(function(){ \"use strict\"; print(x);return true})(), enumerate: (function(x, y) { return Number.MAX_VALUE; }), keys: function() { return Object.keys(x); }, }; }))] = p1; }");
/*fuzzSeed-133180449*/count=483; tryItOut("((void shapeOf(x)));");
/*fuzzSeed-133180449*/count=484; tryItOut("o2.m0 = b0;");
/*fuzzSeed-133180449*/count=485; tryItOut("/*vLoop*/for (let uowqvb = 0; uowqvb < 83; ++uowqvb) { var a = uowqvb; m2.get(b2); } ");
/*fuzzSeed-133180449*/count=486; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.exp(((Math.fround((( + Math.fround(Math.asinh((Math.min((x | 0), (x | 0)) | 0)))) << ( + -0x080000000))) & (((((x >>> 0) <= (x >>> 0)) >>> 0) ^ mathy2(x, x)) | 0)) >= (x - x))); }); ");
/*fuzzSeed-133180449*/count=487; tryItOut("let x = (((function too_much_recursion(zdsuwu) { v1.toSource = (function mcc_() { var pxhalz = 0; return function() { ++pxhalz; f1(/*ICCD*/pxhalz % 6 != 3);};})();; if (zdsuwu > 0) { ; too_much_recursion(zdsuwu - 1);  } else {  }  })(42798))).yoyo(((function a_indexing(ffxpvs, frryel) { ; if (ffxpvs.length == frryel) { ; return (Math.floor).call( /x/ , \"\\uA0EF\"); } var ikwwyr = ffxpvs[frryel]; var hqfahe = a_indexing(ffxpvs, frryel + 1); print(x); var r0 = hqfahe | x; ikwwyr = 8 - r0; print(x); var r1 = hqfahe | 0; var r2 = 4 | 0; var r3 = 8 - r2; var r4 = r3 - x; var r5 = 0 & r2; var r6 = r1 ^ r2; print(r5); var r7 = r6 / 8; print(r4); var r8 = ikwwyr + hqfahe; var r9 = r5 & 6; r5 = hqfahe * r6; var r10 = r1 + r4; var r11 = r1 * 8; var r12 = ikwwyr ^ 5; var r13 = r6 & r0; var r14 = 9 ^ r0; r0 = 5 + r4; var r15 = r8 / x; var r16 = r8 + r11; var r17 = 9 & 4; var r18 = 4 ^ 4; var r19 = r7 * 9; var r20 = 5 ^ r5; var r21 = r14 / r8; var r22 = r4 + r17; ikwwyr = r0 * r1; print(r5); print(x); var r23 = 3 / 1; r16 = r18 + 1; var r24 = x & 8; var r25 = 6 * r15; var r26 = 2 | hqfahe; var r27 = hqfahe * r16; var r28 = r11 - 0; var r29 = x ^ r15; r22 = 1 & r28; r27 = r23 % r14; var r30 = r14 - 2; var r31 = r8 & r15; var r32 = r16 / r2; var r33 = r15 - 7; hqfahe = 4 % r21; var r34 = r22 + r22; var r35 = r13 - r6; r25 = r19 / 3; r10 = r5 | r29; var r36 = r24 & 1; var r37 = 8 | r8; var r38 = 8 | 3; var r39 = r14 * 7; r7 = 9 / 5; r27 = r39 | 4; var r40 = r35 * 2; print(r8); var r41 = r0 / 0; var r42 = r29 | ikwwyr; r34 = r7 | r42; var r43 = r14 + r37; var r44 = 3 & 9; r43 = r33 * r29; var r45 = 4 | r1; var r46 = r31 & 5; r40 = 3 * 7; var r47 = 4 | 0; var r48 = r17 | 4; var r49 = x - 6; var r50 = 2 % r21; var r51 = 7 ^ 2; var r52 = r35 ^ 7; var r53 = r37 ^ 8; r0 = r33 * r34; var r54 = r5 ^ r31; var r55 = r53 - r3; var r56 = r0 | r14; var r57 = r2 & r25; r0 = r55 - r30; r51 = r24 * 9; var r58 = 6 / r37; var r59 = r30 & 8; r51 = r12 * r49; var r60 = 0 + r17; var r61 = r54 / r29; var r62 = r36 | r43; var r63 = r27 - r26; r59 = 9 & r42; x = 7 % r29; var r64 = r32 - hqfahe;  })(/*MARR*/[new Number(1), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), function(){}, new Number(1), function(){}, function(){}, new Number(1), objectEmulatingUndefined(), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), new Number(1), function(){}, new Number(1), function(){}, objectEmulatingUndefined(), new Number(1), function(){}, function(){}, new Number(1), function(){}, new Number(1), function(){}, function(){}, objectEmulatingUndefined(), new Number(1), function(){}, function(){}, function(){}, function(){}, function(){}, objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), function(){}, function(){}, function(){}, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, function(){}], 0)));{ void 0; selectforgc(this); } {}");
/*fuzzSeed-133180449*/count=488; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 65.0;\n    var d3 = 1.001953125;\n    var i4 = 0;\n    var d5 = -0.0009765625;\n    var i6 = 0;\n    var i7 = 0;\n    (Float64ArrayView[4096]) = ((+(1.0/0.0)));\n    d0 = ((i6) ? (((-281474976710657.0)) / ((d3))) : (Infinity));\n    return ((((((0x753339ee)-((1.0009765625) < (+/*FFI*/ff()))) ^ ((0xc921d48c)-(0xd347e957))) < (~~(d2)))+((((0x7bf16485))>>>((0xaf5523ab))))))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; L:switch(x) { default: break;  }; yield y; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0, -0x080000000, 42, 0x100000001, 2**53, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, -1/0, -(2**53-2), Number.MIN_VALUE, 1, 0x080000001, 0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 2**53+2, 0x0ffffffff, -0x07fffffff, -Number.MAX_VALUE, 2**53-2, 0, -0x080000001, -0x0ffffffff, -(2**53+2), 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-133180449*/count=489; tryItOut("\"use strict\"; h0 + '';");
/*fuzzSeed-133180449*/count=490; tryItOut("\"use strict\"; /*infloop*/do {m2.__iterator__ = (function(a0, a1, a2, a3, a4) { var r0 = a1 + x; a1 = 9 * a2; var r1 = a4 * 5; var r2 = a3 ^ 5; var r3 = x ^ 4; var r4 = 0 | r0; var r5 = a3 - 0; print(r0); r0 = r5 & 9; var r6 = 2 % 0; var r7 = a1 * r2; var r8 = r7 ^ 6; var r9 = 3 / 4; var r10 = r2 | a4; print(a1); var r11 = r4 ^ r3; var r12 = a2 | r11; var r13 = 5 * a0; a1 = 9 / r3; var r14 = 4 / r13; var r15 = r8 | r10; var r16 = r13 ^ r12; var r17 = a0 | r11; var r18 = 5 / a0; var r19 = a2 / a2; r7 = a0 & r15; print(r17); var r20 = 4 | 5; var r21 = r6 - r11; var r22 = r11 ^ 0; var r23 = r8 - a1; var r24 = r16 | r1; var r25 = r5 - 2; var r26 = x ^ r23; var r27 = r4 * 7; var r28 = a0 & x; var r29 = 3 & 4; var r30 = r0 - r10; var r31 = 1 + r28; r16 = r6 % r28; print(r18); var r32 = a0 ^ r22; var r33 = r7 + r28; var r34 = 7 % a4; var r35 = r16 | r4; var r36 = a1 | r5; var r37 = r1 + 1; var r38 = r5 ^ 3; var r39 = r28 | r33; var r40 = 3 & r15; var r41 = 1 | r22; var r42 = r4 | r19; var r43 = r34 - a4; var r44 = r23 * 5; print(r36); var r45 = r23 | r39; var r46 = r26 * 6; var r47 = 7 & 6; var r48 = r9 + r36; r10 = r47 | r44; var r49 = 9 & 6; var r50 = 4 + r47; var r51 = 3 + r29; var r52 = r41 + r31; var r53 = x * r14; r40 = r32 / a2; var r54 = r27 - r4; var r55 = 0 * r9; var r56 = 5 * r32; var r57 = 7 | r54; var r58 = r47 - 8; r32 = r58 - r38; var r59 = a3 % r13; var r60 = 3 - r43; r55 = r22 / r53; r22 = 9 % r41; var r61 = r46 % r36; r2 = r25 | r19; var r62 = 4 & 5; var r63 = 3 - 9; var r64 = r36 * 3; var r65 = r64 * r50; var r66 = 7 | 1; var r67 = 5 * r62; var r68 = r36 ^ r59; print(r58); var r69 = 2 * 8; var r70 = 6 % r23; var r71 = 7 * 2; var r72 = r62 / 4; var r73 = 4 % a4; r30 = 9 / 7; var r74 = r18 | 0; r61 = 7 ^ 0; var r75 = 8 & r6; var r76 = r34 * r8; print(r52); var r77 = r1 % r1; r72 = r61 & r25; var r78 = r30 + 5; r34 = r61 ^ 0; var r79 = r20 | r53; var r80 = r36 & 4; var r81 = r48 - r52; var r82 = r16 | r15; var r83 = r44 % r80; var r84 = r83 | 0; var r85 = r12 / 8; var r86 = 4 / r51; var r87 = r23 * r65; r43 = 0 / r85; r46 = 5 % 3; var r88 = r19 + r79; var r89 = r59 ^ r71; r41 = r58 ^ r3; var r90 = r3 % 0; var r91 = r90 % r90; var r92 = r68 * 4; print(r85); var r93 = 8 ^ r85; var r94 = 2 - r18; var r95 = 8 % r38; r95 = r78 & r31; var r96 = r13 / 6; r29 = 0 & 5; var r97 = r54 & 9; var r98 = r32 * r6; var r99 = r27 + r22; var r100 = x / r92; r5 = r96 / 1; var r101 = r7 + r24; var r102 = r96 | a2; var r103 = r50 + 8; var r104 = 8 % r53; r33 = r71 % r95; r78 = r40 % 4; r0 = r75 / r86; r45 = r74 ^ r91; var r105 = 3 - r71; var r106 = 8 / 7; var r107 = r60 | 3; var r108 = r99 % r56; var r109 = r27 - 0; r37 = r17 | r17; print(r35); var r110 = 7 | 4; var r111 = 9 + r40; var r112 = r110 + 9; var r113 = r59 % r43; var r114 = r85 + r19; var r115 = r48 - r81; r51 = r99 ^ 4; r48 = r83 - r3; r67 = r111 & 5; var r116 = r25 % r59; var r117 = 4 & r6; var r118 = r13 / 6; var r119 = 1 % 2; var r120 = r9 % r38; var r121 = 8 % 0; var r122 = 0 / r112; var r123 = r41 | r50; var r124 = r95 + r116; r4 = 6 - 7; var r125 = r64 + r98; var r126 = 2 * r64; var r127 = r22 | r21; var r128 = r89 ^ r3; print(r30); print(r13); var r129 = r28 ^ r52; var r130 = r65 * r68; var r131 = r114 ^ 6; return a4; });{} } while(let (c =  /x/g ) [[]]);");
/*fuzzSeed-133180449*/count=491; tryItOut("v1 = g1.eval(\"function f2(a2)  { return --a } \");");
/*fuzzSeed-133180449*/count=492; tryItOut("b0[\"values\"] = o0.b0;");
/*fuzzSeed-133180449*/count=493; tryItOut("\"use strict\"; this;( \"\" );");
/*fuzzSeed-133180449*/count=494; tryItOut("\"use strict\"; a0.splice(NaN, 6);");
/*fuzzSeed-133180449*/count=495; tryItOut("m0.toString = (function(j) { f2(j); });");
/*fuzzSeed-133180449*/count=496; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + mathy0((( + ( + ( + (Math.fround(((0x100000000 >>> 0) !== mathy0(( + y), (mathy0((y | 0), (x | 0)) | 0)))) / Math.fround(Math.atan2(((((Number.MAX_VALUE >>> 0) & (Math.fround(Math.pow(Math.fround(-0x0ffffffff), y)) >>> 0)) >>> 0) | 0), (((( + ( ~ ( + 1))) | 0) - (y | 0)) >>> 0))))))) | 0), ( + (((( + Math.tan(y)) <= (( ~ (( ~ y) | 0)) | 0)) | 0) >>> Math.max((( ! x) ** Math.fround(Math.min(Math.fround(y), Math.fround(2**53-2)))), Math.hypot((x >>> 0), (y >>> 0))))))); }); testMathyFunction(mathy1, /*MARR*/[{x:3}, {x:3}, -0x0ffffffff, {x:3}, -0x0ffffffff, -0x0ffffffff, {x:3}, {x:3}, {x:3}, -0x0ffffffff, -0x0ffffffff, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, -0x0ffffffff, {x:3}, {x:3}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {x:3}, {x:3}, -0x0ffffffff, {x:3}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {x:3}, -0x0ffffffff, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, -0x0ffffffff, {x:3}, -0x0ffffffff, {x:3}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {x:3}, -0x0ffffffff, {x:3}, {x:3}, {x:3}, -0x0ffffffff, -0x0ffffffff, {x:3}, -0x0ffffffff, {x:3}, {x:3}, {x:3}, -0x0ffffffff, {x:3}, {x:3}, -0x0ffffffff, {x:3}, -0x0ffffffff, -0x0ffffffff, {x:3}, {x:3}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {x:3}, {x:3}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {x:3}, {x:3}, {x:3}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {x:3}, {x:3}, {x:3}, -0x0ffffffff, {x:3}, -0x0ffffffff, -0x0ffffffff, {x:3}, -0x0ffffffff, -0x0ffffffff, {x:3}, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, -0x0ffffffff, {x:3}, -0x0ffffffff, {x:3}, -0x0ffffffff, {x:3}, {x:3}, {x:3}, {x:3}, -0x0ffffffff, -0x0ffffffff, {x:3}, -0x0ffffffff, {x:3}, {x:3}]); ");
/*fuzzSeed-133180449*/count=497; tryItOut("\"use strict\"; /*vLoop*/for (var cskcmz = 0; cskcmz < 38; this.__defineSetter__(\"NaN\", ([({})])), ++cskcmz) { const a = cskcmz; e1.add(this.p2);function x(d, b, c, z, eval, x, e = \"\\u1B56\", \u3056, a, y, y, a, NaN, \u3056, window, x, w, w, x, a, c, eval = false, x, x, z, x =  \"\" , \u3056, a, a, a, e, ...x) { Array.prototype.splice.apply(a1, [NaN, v2]); } print(x); } ");
/*fuzzSeed-133180449*/count=498; tryItOut("\"use strict\"; m0.get(this.s0);\nObject.seal(m1);\n");
/*fuzzSeed-133180449*/count=499; tryItOut("\"use strict\"; function shapeyConstructor(yscppv){\"use strict\"; { for(a in ((Date.prototype.toLocaleString)(eval(\"\\\"use strict\\\"; mathy5 = (function(x, y) { \\\"use strict\\\"; \\\"use asm\\\"; return Math.imul(Math.fround((( - Math.log2(x)) >>> 0)), Math.fround((( ! Math.pow((Math.fround(Math.pow(x, Math.fround(Math.max(Math.fround(x), 0x080000000)))) | 0), (y | 0))) ? Math.log(Math.round(Math.atan(( - ( + y))))) : Math.fround(((Math.min(Math.atan2(x, y), -0x100000000) >>> 0) ? (Math.exp(Math.fround(Math.fround(Math.pow(Math.fround((( + Math.pow(y, y)) && ( + x))), ( + Math.log1p(y)))))) >>> 0) : ((x / Math.fround(x)) >>> 0)))))); }); \").valueOf(\"number\"))))i2 + '';d = yscppv; } this[\"replace\"] = (eval).call( /x/ , );return this; }/*tLoopC*/for (let y of /*MARR*/[true, x, new String('q'), new String('q'), true, true, new String('q'), true, true, x, new String('q'), new String('q'), true, true, x, new String('q'), true, new String('q'), true, x, true, x, x, x, true, x, x, x, new String('q'), true, true, true, true, x, x, x, new String('q'), true, new String('q'), true, x, x, x]) { try{let kyodch = shapeyConstructor(y); print('EETT'); /*tLoop*/for (let z of /*MARR*/[[], null, null, [], -0x100000000, false, {}, -0x100000000, null, [], [], null, -0x100000000, false, false]) { /*ODP-1*/Object.defineProperty(b0, \"callee\", ({get: Date.prototype.getMilliseconds, set: String.fromCharCode, configurable: true})); }}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-133180449*/count=500; tryItOut("\"use strict\"; const krtxvz, x = (/*FARR*/[(((4277))(x, eval))].some(Map.prototype.keys, x)), e;e0.add(e2);");
/*fuzzSeed-133180449*/count=501; tryItOut("h2.getPropertyDescriptor = f1;");
/*fuzzSeed-133180449*/count=502; tryItOut("b1.__proto__ = i1;");
/*fuzzSeed-133180449*/count=503; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.log1p(Math.fround(Math.ceil(((mathy3((( ! Math.pow(Math.PI, x)) | 0), (Math.fround(Math.min(Math.fround(Math.fround(mathy1(Math.fround(x), Math.fround(1/0)))), (0x080000001 | 0))) | 0)) | 0) >= Math.clz32((y << ( + -(2**53))))))))); }); testMathyFunction(mathy5, [1/0, 0x080000000, 0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -0, 0x080000001, 2**53-2, -Number.MIN_VALUE, -(2**53+2), 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -1/0, -0x100000001, -0x080000000, 2**53+2, 42, 0/0, 2**53, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, -(2**53), 0x100000000, Number.MIN_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=504; tryItOut("\"use strict\"; var vyguyq = new ArrayBuffer(4); var vyguyq_0 = new Float64Array(vyguyq); print(vyguyq_0[0]); vyguyq_0[0] = 3; new RegExp(\".\", \"yim\")\u000c;");
/*fuzzSeed-133180449*/count=505; tryItOut("this.v1 = evalcx(\"function g0.f1(i1) \\\"use asm\\\";   function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    d0 = (-140737488355327.0);\\n    return +((d0));\\n  }\\n  return f;\", o2.g2);");
/*fuzzSeed-133180449*/count=506; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=507; tryItOut("g1.t1 = new Uint32Array(b0, 24, 0);");
/*fuzzSeed-133180449*/count=508; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-133180449*/count=509; tryItOut("\"use asm\"; { void 0; selectforgc(this); }");
/*fuzzSeed-133180449*/count=510; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround((Math.fround(Math.max(( - Math.tan(((y === (Math.fround(((-(2**53+2) >>> 0) < (( ! y) >>> 0))) | 0)) >>> 0))), (Math.fround(Math.log2(( + (( + x) >= ( + (( ~ ( + Math.max(Math.fround(Math.hypot(( + y), x)), y))) >>> 0)))))) | 0))) < Math.fround(( + (Math.trunc(((((((Math.hypot(x, x) >>> 0) >> (Math.acosh(x) | 0)) >>> 0) | 0) * (y | 0)) | 0)) >>> 0))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, 0x080000000, Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 42, 0x100000001, -(2**53-2), -0x080000000, 0x100000000, 2**53+2, 0, Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 2**53-2, -0x100000000, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, 0x07fffffff, -(2**53), 1/0, 0/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, -Number.MIN_SAFE_INTEGER, 1, -1/0, -0x080000001, -Number.MAX_VALUE, -0]); ");
/*fuzzSeed-133180449*/count=511; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((( ~ (mathy2(Math.atan2(Math.atan2(x, y), Math.fround((Math.atan2((y | 0), (0/0 | 0)) | 0))), Math.ceil(((mathy0(( + x), ( + (( + -0) ? ( + y) : ( + x)))) >>> 0) >>> 0))) >>> 0)) >>> 0) != (( ! ( ~ (Math.fround((Math.fround((y | 0)) | 0)) == (( ~ (x | 0)) | 0)))) >>> 0)); }); testMathyFunction(mathy3, [1/0, 0x080000001, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, -(2**53-2), Number.MIN_VALUE, 42, -0x100000001, -Number.MAX_VALUE, 0x080000000, 0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), 0.000000000000001, 2**53, 0x100000001, 1, -0x0ffffffff, -0x080000001, 2**53+2, Math.PI, -0x07fffffff, 0x100000000, 2**53-2, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=512; tryItOut("\"use asm\"; v1 = evalcx(\"print(true);\", o0.g2);function [, {NaN}, , , window, {x}](x = x, window, ...x)\"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 68719476737.0;\n    var i3 = 0;\n    {\n      d2 = (-70368744177664.0);\n    }\n    return +((d2));\n  }\n  return f;{(new RegExp(\"\\\\xAD{1}\\\\2(?:(?:(?:\\\\\\u0089)))(?=[\\\\S\\\\u006a](\\\\uED40\\\\s)\\\\2|[^\\\\cI-y\\\\u0033-\\\\xFb#\\\\xf2])\", \"ym\"));function x(z, x, x, b, x = null, x, w, x = new RegExp(\"(?!(?:[^](?!(?:\\\\1)){3,7}))\", \"y\"), x = 16, x, window, w =  /x/ , x, eval, c, b, NaN, w, z, eval = \"\\uF43D\", \u3056, NaN, z = [z1], x, b, d, e, \u3056, x, x, \u3056, x = window, window, x, w = 26, window, a = /(?![^]).{2}*/gyim, x, w = new RegExp(\"\\\\ufD81*?\", \"g\"), x, z, x = window, z, eval, NaN, d, z =  \"\" , x, eval, eval, window, e, x = \"\\uD0CD\", x, d, x, x, x, NaN, c, this.x, x, x)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((-2147483648.0));\n  }\n  return f;neuter }");
/*fuzzSeed-133180449*/count=513; tryItOut("mathy2 = (function(x, y) { return (Math.fround(( ~ Math.fround(Math.imul(( ! ( + (( ~ ((Math.atan2((y | 0), (x | 0)) | 0) | 0)) | 0))), Math.fround(x))))) === Math.log1p((Math.hypot(y, mathy1(y, ( + x))) >>> 0))); }); testMathyFunction(mathy2, [-1/0, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), -0x080000001, Math.PI, 1, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, -Number.MAX_VALUE, -0x080000000, 2**53, -0x0ffffffff, 0.000000000000001, -0, -0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, 42, -(2**53-2), 0x080000000, 0/0, 1.7976931348623157e308, 0x100000000, 1/0, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, 0, 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=514; tryItOut("this.v0 = r0.compile;");
/*fuzzSeed-133180449*/count=515; tryItOut("/*RXUB*/var r = /^/m; var s = (4277); print(r.exec(s)); v2 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: Math.cos( /x/ ).x, element: o1 }));");
/*fuzzSeed-133180449*/count=516; tryItOut("o0.s0.valueOf = f1;");
/*fuzzSeed-133180449*/count=517; tryItOut("testMathyFunction(mathy5, /*MARR*/[mathy0(), new Boolean(false), 0x20000000, 0x20000000, 0x20000000, 0x20000000, objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), 0x20000000, mathy0(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, new Boolean(false), mathy0(), mathy0(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), mathy0(), 0x20000000, 0x20000000, objectEmulatingUndefined(), 0x20000000, NaN, new Boolean(false), new Boolean(false), 0x20000000, mathy0(), new Boolean(false), mathy0(), mathy0(), 0x20000000, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, 0x20000000, objectEmulatingUndefined(), NaN, 0x20000000, NaN, 0x20000000, mathy0(), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), mathy0(), 0x20000000, new Boolean(false), 0x20000000, NaN, 0x20000000, mathy0(), NaN, NaN, 0x20000000, new Boolean(false), objectEmulatingUndefined()]); ");
/*fuzzSeed-133180449*/count=518; tryItOut("x.lineNumber;");
/*fuzzSeed-133180449*/count=519; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.max(Math.fround(Math.max(Math.cbrt(y), ( + (( + ( + (mathy0(x, ( + ( + ( ~ y)))) | ( ~ x)))) != (0x080000000 | 0))))), (( ~ ((( + ( + 0x080000000)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0, 0x100000001, -0x080000001, -0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, Math.PI, 2**53, -0x100000001, 1, -(2**53-2), 0.000000000000001, 42, 1/0, -1/0, -0, 0x080000001, -0x07fffffff, 2**53+2, -(2**53), -(2**53+2), 0x100000000, -Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-133180449*/count=520; tryItOut("e0.add(g2.p2);");
/*fuzzSeed-133180449*/count=521; tryItOut("a2.unshift(t2, (4277));");
/*fuzzSeed-133180449*/count=522; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (( + Math.pow(( + mathy0(x, ( ~ (Math.trunc((Math.atan2(1/0, Number.MIN_VALUE) >>> 0)) >>> 0)))), ( + Math.fround(mathy0(( + ((Math.fround(y) % (Math.fround(mathy0(Math.fround(Math.exp(y)), Math.fround((Math.min(((Math.atan2((-1/0 >>> 0), x) >>> 0) >>> 0), (( + -0) >>> 0)) >>> 0)))) >>> 0)) >>> 0)), (Math.max(((-0x100000001 <= y) >>> 0), (x >>> 0)) >>> 0)))))) ? ( + ( - ( ~ Math.fround(((Math.fround(Math.trunc(Math.fround(( + mathy0(( + y), ( + y)))))) > y) - y))))) : ( + Math.fround(((( - y) || ( ~ -0x080000000)) + (mathy0((((Math.fround(( + x)) === (Math.fround(Math.atanh(Math.fround(x))) >>> 0)) >>> 0) | 0), Object.defineProperty(NaN, \"toSource\", ({enumerable: true}))) | 0)))))); }); testMathyFunction(mathy1, [0x080000001, 1.7976931348623157e308, 2**53, 1, -Number.MAX_VALUE, -(2**53-2), -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, -0x080000000, Number.MIN_VALUE, 0x080000000, -0x080000001, 2**53-2, Number.MAX_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53+2, -(2**53), -Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, Math.PI, 0/0, 1/0]); ");
/*fuzzSeed-133180449*/count=523; tryItOut("print(uneval(b2));");
/*fuzzSeed-133180449*/count=524; tryItOut("\"use strict\"; this.h1.iterate = f2;");
/*fuzzSeed-133180449*/count=525; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=526; tryItOut("\"use strict\"; ;");
/*fuzzSeed-133180449*/count=527; tryItOut("o1 = Object.create(o1.m2);");
/*fuzzSeed-133180449*/count=528; tryItOut("window = linkedList(window, 960);");
/*fuzzSeed-133180449*/count=529; tryItOut("\"use strict\"; \u3056 = linkedList(\u3056, 2301);");
/*fuzzSeed-133180449*/count=530; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=531; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - Math.fround((((Math.min((( + 42) && Math.fround(((mathy3(Number.MIN_SAFE_INTEGER, x) >>> 0) % y))), Math.min(x, y)) | 0) > ((Math.hypot((Math.fround(( - ( + x))) >= Math.fround(y)), mathy0(x, -(2**53+2))) >>> 0) | 0)) | 0))); }); ");
/*fuzzSeed-133180449*/count=532; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ~ ( + Math.max(( + Math.tanh((y ? ( + ( + (0 | 0))) : Math.pow(((y << y) | 0), (( + x) | 0))))), ( + mathy1(Math.exp((( - ((-1/0 , x) | 0)) | 0)), (( + ( ! ( + ( + x)))) ? ( + mathy1(( + y), (y == y))) : (Math.sign(y) | 0))))))); }); testMathyFunction(mathy3, /*MARR*/[ /x/g , true, true,  /x/g ,  /x/g , new Boolean(false), true,  /x/g , new Boolean(false), true,  /x/g ,  /x/g , new Boolean(false),  /x/g , true, true, true, true,  /x/g , new Boolean(false),  /x/g , true,  /x/g , new Boolean(false), true,  /x/g ,  /x/g , true, new Boolean(false), new Boolean(false),  /x/g ,  /x/g ,  /x/g , true,  /x/g ,  /x/g ,  /x/g , new Boolean(false),  /x/g , new Boolean(false),  /x/g , true,  /x/g ,  /x/g , true, true, new Boolean(false), new Boolean(false), true, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), true,  /x/g ,  /x/g , new Boolean(false), true, new Boolean(false), new Boolean(false), true, true,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Boolean(false), true, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  /x/g , new Boolean(false),  /x/g , true,  /x/g , new Boolean(false), new Boolean(false),  /x/g , true,  /x/g , true, true, new Boolean(false), true, new Boolean(false), true,  /x/g ,  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false),  /x/g , new Boolean(false),  /x/g ,  /x/g ,  /x/g , new Boolean(false), new Boolean(false), new Boolean(false), true,  /x/g , true, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), true, true]); ");
/*fuzzSeed-133180449*/count=533; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i0);\n    (Float64ArrayView[1]) = ((((((0x4ac71dfc) / (((0x6d6908b1))>>>((0xfaf3624c))))>>>((i1)-(/*FFI*/ff(((+/*FFI*/ff())), ((-590295810358705700000.0)), ((-68719476737.0)), ((295147905179352830000.0)), ((-295147905179352830000.0)), ((1.2089258196146292e+24)), ((-281474976710657.0)), ((-1.9342813113834067e+25)), ((-1.0)))|0)+(!(i0))))) ? (-((+(-1.0/0.0)))) : (-36028797018963970.0)));\n    i0 = (i0);\n    {\n      i0 = (i1);\n    }\n    {\n      i0 = (i0);\n    }\n    {\n      i0 = ((0xc6cf25b9) < (((i0)-(i0))>>>((i0)+((((!(0x5cf0074a)))>>>((0x90ba708b)-(0xffffffff))) > (((0x84a78601)+(0xfc926afa)-(0x3772a884))>>>(0xc0514*(0x75535944)))))));\n    }\n    return (((0xe51b5ee1) % (0xf9140312)))|0;\n  }\n  return f; })(this, {ff: WeakMap.prototype.get}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=534; tryItOut("\"use asm\"; a1.forEach((function() { try { h2 + ''; } catch(e0) { } try { f0.valueOf = f0; } catch(e1) { } try { m0.set(b0, p1); } catch(e2) { } for (var p in f2) { try { s1 += o2.s0; } catch(e0) { } try { selectforgc(this.o1); } catch(e1) { } (void schedulegc(o1.o2.o2.g2)); } throw m2; }));");
/*fuzzSeed-133180449*/count=535; tryItOut("/*ADP-1*/Object.defineProperty(a0, o2.o0.v2, ({value:  '' , writable: false, enumerable: x || x}));");
/*fuzzSeed-133180449*/count=536; tryItOut("\"use asm\"; /*MXX3*/g1.URIError = o2.g0.URIError;");
/*fuzzSeed-133180449*/count=537; tryItOut("mathy2 = {\u3056, x: [], x: w, x, x\u000c: {}}; testMathyFunction(mathy2, [0, '\\0', null, '/0/', /0/, (function(){return 0;}), NaN, (new Boolean(true)), 0.1, objectEmulatingUndefined(), -0, [0], 1, ({valueOf:function(){return '0';}}), [], false, ({valueOf:function(){return 0;}}), undefined, '0', true, (new Number(-0)), (new Number(0)), '', (new Boolean(false)), ({toString:function(){return '0';}}), (new String(''))]); ");
/*fuzzSeed-133180449*/count=538; tryItOut("\"use strict\"; e1.delete(g1);");
/*fuzzSeed-133180449*/count=539; tryItOut("mathy4 = (function(x, y) { return Math.abs(Math.exp(Math.atan2(( ! Math.exp(x)), Math.atan2((y >>> 0), ((( ~ (y >>> 0)) >>> 0) >>> 0))))); }); testMathyFunction(mathy4, [false, null, (new Number(-0)), (new Boolean(false)), true, '/0/', 1, '0', [], (new Number(0)), '', NaN, '\\0', -0, [0], (function(){return 0;}), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), undefined, (new Boolean(true)), /0/, (new String('')), 0, 0.1]); ");
/*fuzzSeed-133180449*/count=540; tryItOut("\"use strict\"; this.s1 = t0[v1];");
/*fuzzSeed-133180449*/count=541; tryItOut("/*vLoop*/for (var yqcjka = 0; yqcjka < 10; ++yqcjka) { const d = yqcjka; s2 += s0; } ");
/*fuzzSeed-133180449*/count=542; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=543; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=544; tryItOut("/*RXUB*/var r = new RegExp(\"((\\\\S{2047,}))((?=\\\\3)){3}\", \"ym\"); var s = \"''''''a'''\\ued200aaaaaaaaaa\"; print(s.split(r)); ");
/*fuzzSeed-133180449*/count=545; tryItOut("Object.prototype.unwatch.call(o1, \"caller\");");
/*fuzzSeed-133180449*/count=546; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((((((mathy0(Math.hypot(((x ? y : x) || Math.fround(x)), y), (Math.pow((((((x ** x) >>> 0) ? (y >>> 0) : (1.7976931348623157e308 >>> 0)) >>> 0) >>> 0), (2**53-2 ? 0x080000000 : -0)) | 0)) >>> 0) != (Math.fround((Math.fround(y) ? Math.fround(( + mathy0(( + x), ( + Number.MAX_VALUE)))) : Math.fround(y))) >>> 0)) >>> 0) * (Math.sinh(Math.fround(mathy2(0.000000000000001, 1/0))) * ( - 0x080000000))) | 0) ? (((mathy1(Math.hypot(Math.pow(Math.fround(( - ( - (y >>> 0)))), y), ( - ( - Math.pow(0x100000000, y)))), Math.fround(Math.atan2((((x >>> 0) != (x >>> 0)) >>> 0), Math.fround(mathy1(((Math.fround(x) > Math.PI) >>> 0), x))))) | 0) != Math.fround((Math.fround(Math.cos(Math.max(2**53, x))) >>> Math.fround(( + (( + Math.cosh(Math.pow(Math.fround(((x >>> 0) !== Math.fround(y))), Math.fround(42)))) >>> ( + x))))))) | 0) : ((Math.tan((Math.log1p(( + y)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, /*MARR*/[((b && c) != Math.atan2(null, -16)),  /x/ , function(){},  /x/ , function(){},  /x/ , ((b && c) != Math.atan2(null, -16)), function(){}, ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), false, false, ((b && c) != Math.atan2(null, -16)), function(){}, function(){}, ((b && c) != Math.atan2(null, -16)),  /x/ , ((b && c) != Math.atan2(null, -16)), ((b && c) != Math.atan2(null, -16)), function(){},  /x/ , function(){}, false, ((b && c) != Math.atan2(null, -16)), function(){},  /x/ ,  /x/ , function(){}, false,  /x/ , ((b && c) != Math.atan2(null, -16)),  /x/ , false, false,  /x/ ]); ");
/*fuzzSeed-133180449*/count=547; tryItOut("\"use strict\"; L\u000c:if(false) {this; }");
/*fuzzSeed-133180449*/count=548; tryItOut("mathy2 = (function(x, y) { return Math.imul(( + (Math.fround(Math.pow(Math.hypot(2**53-2, x), ( + x))) + ( + (y > Math.exp(( + ((x ? x : x) & -0))))))), mathy1(Math.fround(( + Math.fround(mathy1(-Number.MIN_SAFE_INTEGER, x)))), ( + (mathy1((((-(2**53-2) - x) % mathy1(x, (Math.max(x, (x >>> 0)) | 0))) | 0), (y | 0)) | 0)))); }); testMathyFunction(mathy2, [0x080000000, -Number.MIN_SAFE_INTEGER, 42, 0/0, 0.000000000000001, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), -1/0, 2**53, -(2**53-2), -(2**53+2), Math.PI, 2**53-2, -0x07fffffff, 0x100000001, 0, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, -0x100000000, -0x0ffffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -0x080000000, -0, 0x080000001, -Number.MIN_VALUE, 1]); ");
/*fuzzSeed-133180449*/count=549; tryItOut("mathy2 = (function(x, y) { return Math.trunc(((( ~ -Number.MAX_VALUE) >>> Math.cos((Math.clz32((( - (( - (0x0ffffffff >>> 0)) >>> 0)) >>> 0)) | 0))) | 0)); }); testMathyFunction(mathy2, [0.000000000000001, -0x080000001, 0x080000000, -Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, 1, Number.MAX_SAFE_INTEGER, -0x080000000, 0, -(2**53), 2**53-2, -(2**53-2), Math.PI, 0x0ffffffff, 0x100000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -0, -0x0ffffffff, 0/0, Number.MAX_VALUE, 1/0, -1/0, 0x080000001, 0x07fffffff, Number.MIN_VALUE, 42, 0x100000001, -0x07fffffff, -0x100000000, 2**53, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=550; tryItOut(" for  each(w in (new Number().unwatch(\"valueOf\"))) {(-4.unwatch(2) === (void shapeOf(/(?:(?:$|(?:(?![^]*?)){1,}))/y)));(w); }");
/*fuzzSeed-133180449*/count=551; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d0 = (d1);\n    }\n    d1 = ((Float64ArrayView[((Int32ArrayView[(-(0x10a42383)) >> 2])) >> 3]));\n    {\n      d1 = (d1);\n    }\n    d0 = (d1);\n    d0 = (d1);\nt0[v2] = 17;\nprint( \"\" );\n    return (((0xfaeed37e)*0xd465e))|0;\n  }\n  return f; })(this, {ff: -undefined}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[arguments.caller, objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, arguments.caller, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), arguments.caller, objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), new Number(1), arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, objectEmulatingUndefined(), arguments.caller, new Number(1), arguments.caller, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), arguments.caller, objectEmulatingUndefined(), new Number(1), arguments.caller, new Number(1), arguments.caller, objectEmulatingUndefined(), new Number(1), new Number(1), arguments.caller, arguments.caller, arguments.caller, new Number(1), new Number(1), arguments.caller, new Number(1), objectEmulatingUndefined(), arguments.caller, arguments.caller, arguments.caller, new Number(1), arguments.caller, arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), arguments.caller, new Number(1), arguments.caller, new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), arguments.caller, new Number(1), arguments.caller, arguments.caller, arguments.caller, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), arguments.caller, arguments.caller, arguments.caller, arguments.caller, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, arguments.caller, objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), arguments.caller, objectEmulatingUndefined(), arguments.caller, arguments.caller, objectEmulatingUndefined(), new Number(1)]); ");
/*fuzzSeed-133180449*/count=552; tryItOut("/*bLoop*/for (var lvahix = 0; lvahix < 94; false, ++lvahix) { if (lvahix % 8 == 5) { b2.toString = (function(j) { f2(j); }); } else { v0 = Object.prototype.isPrototypeOf.call(p0, g0.i1); }  } ");
/*fuzzSeed-133180449*/count=553; tryItOut("/*ODP-2*/Object.defineProperty(o0, \"clz32\", { configurable: false, enumerable: (x % 2 == 0), get: (function mcc_() { var gncsna = 0; return function() { ++gncsna; f1(/*ICCD*/gncsna % 6 == 2);};})(), set: (function() { for (var j=0;j<27;++j) { f2(j%4==0); } }) });");
/*fuzzSeed-133180449*/count=554; tryItOut("/*RXUB*/var r = /(?!\u00fd)/g; var s = \"\\u011d\"; print(s.split(r)); function x([{x, b: {}, x: {\u3056: {\u3056: [{}, ], NaN: x}}, x: {NaN: x, x, x, eval: [[{}, , , w], , [{c: //h\n{eval: [], x: [[]]}, x}, []], ]}}, , , [{x, z: x, x: y, x}], [], ], y, x = x, x, a, x, d = let (y = \"\\u7D01\") x, window, x, x, x =  /x/g , \u3056, b = window, x, x, window, \u3056, window, eval, d,  \"\"  =  '' , w, \u3056, x, x, b, x, x, window, window, z, \u3056, x, w, x, x, y = y, NaN = \"\\uEC88\", d, x, x, x = [,,z1], try {  /x/ ; } catch(eval if (function(){return;})()) { print(null); } catch(z if x) { for (var v of g1.o2) { try { i0 + ''; } catch(e0) { } try { v2 = t0.byteLength; } catch(e1) { } try { v1 = (b0 instanceof f0); } catch(e2) { } s1 += s2; } } catch(x) {  } , c, [z1], x, c, c, y, NaN = \"\\uC300\", d)\"use asm\";   var abs = stdlib.Math.abs;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = ((abs(((((((-0x35097f2)+(0x94c518f5)+(0x612af035)) | ((1))))) & ((0x4300ae28))))|0) >= (((!(i2))+((0xdc66e689) <= (0x9d171a1e))-((((0x55e0b6df) % (0x2596158f)) ^ (((0xee7b1920) >= (0x4d029d66)))) >= (((0x51623c71)-(0xcba4b30e)) | ((0xffffffff)+(0xfb36242a)-(0x26a66363)))))|0));\n    i0 = (0xfc6ce1a9);\n    i0 = (i0);\n    {\n      return (((i0)-(i2)+((0xffffffff) != ((((((0x6549945e))>>>((0x807da37b))) <= (((0xf85ac89b))>>>((0xfe3a9174))))*-0xd6b1f)>>>((!(0xf12eb5c)))))))|0;\n    }\n    d1 = (1.00390625);\n    i0 = ((-2097151.0) == (2097152.0));\n    return (((i0)+(0xff5cc30c)))|0;\n  }\n  return f;([[]]);");
/*fuzzSeed-133180449*/count=555; tryItOut("mathy5 = (function(x, y) { return mathy1(((((Math.log2(Math.fround((-1/0 < mathy1(x, (Math.asin(y) >>> 0))))) >>> 0) | 0) >>> ( + Math.atan2(x, ((Math.max(Math.fround(Math.atan2(y, x)), (((( + (mathy1(x, x) | 0)) ^ (( + 0x080000000) | 0)) | 0) | 0)) | 0) + x)))) | 0), mathy3(( + mathy2(Math.fround(0x080000001), ( + ( ~ Math.fround(y))))), ( + ( ~ ( + Math.ceil(Math.fround(Math.abs(Math.fround((mathy4(-0x080000001, y) | 0)))))))))); }); testMathyFunction(mathy5, [2**53+2, 0x100000000, -(2**53+2), 0x080000000, 0, 0/0, 1.7976931348623157e308, 0x07fffffff, 2**53, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000001, -0x080000000, 0x0ffffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, -0x080000001, Number.MAX_VALUE, 0x100000001, -(2**53), Number.MIN_VALUE, -0, -(2**53-2), -0x100000000, -0x07fffffff, 42, 0.000000000000001, Math.PI, -0x0ffffffff, 1/0]); ");
/*fuzzSeed-133180449*/count=556; tryItOut("mathy1 = (function(x, y) { return (Math.sin((((Math.fround(-1/0) != (((-0x07fffffff ? ( + ( + Math.max(( + x), ( + Math.atan2((x | 0), (((x >>> 0) ? (y >>> 0) : y) >>> 0)))))) : ( + Math.pow(Math.fround(y), Number.MIN_VALUE))) | 0) | 0)) == Math.fround(Math.pow(Math.fround((y ^ ( + ( + ( + x))))), Math.fround(mathy0((-0x100000000 >>> 0), (y | 0)))))) | 0)) | 0); }); testMathyFunction(mathy1, [2**53-2, -0, 0x07fffffff, -0x080000001, 2**53, Math.PI, 0/0, -0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, 0x100000000, -(2**53), -0x080000000, 0x080000000, -(2**53+2), -1/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -0x100000000, -Number.MIN_VALUE, 1, -0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, 0x080000001, 0x100000001, Number.MIN_VALUE, -0x0ffffffff, 1/0, Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 42, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=557; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=558; tryItOut("x\n;");
/*fuzzSeed-133180449*/count=559; tryItOut("\"use strict\"; b1.__proto__ = f1;");
/*fuzzSeed-133180449*/count=560; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.expm1(( + Math.log1p(( + (Math.cbrt(Math.fround(( + Math.imul(( + ( + ( - ( + x)))), ( + Math.asinh((mathy2((x | 0), ( + Math.acosh(y))) >>> 0))))))) >>> 0))))); }); ");
/*fuzzSeed-133180449*/count=561; tryItOut("print(a2);/*MXX3*/this.o1.g0.Math.log1p = g2.Math.log1p;");
/*fuzzSeed-133180449*/count=562; tryItOut("/*oLoop*/for (var sbtzgj = 0,  '' ; sbtzgj < 4; ++sbtzgj) { g1 + ''; } ");
/*fuzzSeed-133180449*/count=563; tryItOut("o2.g2.t2[8] = x;");
/*fuzzSeed-133180449*/count=564; tryItOut("var xkllak = new ArrayBuffer(0); var xkllak_0 = new Int16Array(xkllak); xkllak_0[0] = 3; var xkllak_1 = new Int32Array(xkllak); xkllak_1[0] = -19; var xkllak_2 = new Uint16Array(xkllak); xkllak_2[0] = 4; var xkllak_3 = new Uint16Array(xkllak); xkllak_3[0] = 23; var xkllak_4 = new Uint8Array(xkllak); var xkllak_5 = new Int16Array(xkllak); print(xkllak_5[0]); xkllak_5[0] = -2; Array.prototype.splice.apply(a0, [NaN, v2, e0, h0]);decodeURIprint(Math.hypot(-1, -3) / (/*UUV2*/(y.toLocaleTimeString = y.pow)));a0.pop(o2.p0, this.g2);");
/*fuzzSeed-133180449*/count=565; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=566; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, 0x07fffffff, -0x080000001, 42, -Number.MAX_VALUE, 2**53, -0x100000001, 1, Number.MIN_VALUE, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, -0x080000000, 0x100000000, 0x100000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, -1/0, 0x0ffffffff, Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), -0, 0x080000001, 2**53+2, 2**53-2, 0x080000000, 1/0, -0x100000000, 0.000000000000001]); ");
/*fuzzSeed-133180449*/count=567; tryItOut("\"use strict\"; var e = x;g1.offThreadCompileScript(\"(({}))\\n;\");");
/*fuzzSeed-133180449*/count=568; tryItOut("");
/*fuzzSeed-133180449*/count=569; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=570; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = ((i0) ? (-8796093022208.0) : (+(-1.0/0.0)));\n    i0 = (0xfa37f00c);\n    d1 = (((+(0.0/0.0))) / ((Infinity)));\n    d1 = (6.189700196426902e+26);\n    return (((/*FFI*/ff()|0)+(0x8ba8ed32)))|0;\n    return (((((((4277)) <= (0x277411e1)))>>>(((((0xf974f600)-(0xfd2ee8e5)) & ((0xd4567f99)+(-0x8000000))) <= (((0xffffffff))|0))+(i0))) % (((imul((i0), (false))|0) / (((i0)-(i0)) << (0x76d9c*(0xfe4ad987))))>>>((0xf9eb8e0f)))))|0;\n  }\n  return f; })(this, {ff: ArrayBuffer}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=571; tryItOut("mathy5 = (function(x, y) { return (Math.acosh((Math.fround(( - ( ~ -0x0ffffffff))) % ( + (( + (( + ( + mathy1(( + Math.log10(y)), -Number.MIN_SAFE_INTEGER))) < Math.acosh(0x0ffffffff))) ? ( + ( ~ (( ~ (2**53+2 | 0)) | 0))) : ( + ( ! y)))))) >>> 0); }); ");
/*fuzzSeed-133180449*/count=572; tryItOut("print(uneval(i2));var w = (({} = \u0009x));");
/*fuzzSeed-133180449*/count=573; tryItOut("\"use strict\"; v1 = t1.length;");
/*fuzzSeed-133180449*/count=574; tryItOut("print(x);let z = (4277);");
/*fuzzSeed-133180449*/count=575; tryItOut("Object.defineProperty(o0, \"a0\", { configurable: true, enumerable: true,  get: function() { v2 = Object.prototype.isPrototypeOf.call(s2, g1); return r2.exec(g1.s1); } });");
/*fuzzSeed-133180449*/count=576; tryItOut("g2.g1.g1.offThreadCompileScript(\"\\\"use strict\\\"; if(\\\"\\\\u5F0F\\\" <  /x/ ) /*MXX3*/g1.Date.prototype.getTimezoneOffset = g2.Date.prototype.getTimezoneOffset;\");");
/*fuzzSeed-133180449*/count=577; tryItOut("\"use strict\"; /*MXX3*/g1.URIError.length = g0.URIError.length;\nprint(x);\n");
/*fuzzSeed-133180449*/count=578; tryItOut("\"use strict\"; (NaN |= x);t1[17];");
/*fuzzSeed-133180449*/count=579; tryItOut("mathy2 = (function(x, y) { return Math.clz32(Math.fround(( - Math.fround(( ~ ( - ( ~ y))))))); }); testMathyFunction(mathy2, [-0x100000000, -(2**53-2), 0, -0, 1/0, 0/0, Math.PI, 2**53-2, Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, 2**53, 0x080000000, -0x0ffffffff, 0x080000001, -Number.MAX_VALUE, -1/0, 0x07fffffff, -0x100000001, 1, -(2**53), -0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, -(2**53+2), 0x100000001, Number.MIN_VALUE, 2**53+2, 0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=580; tryItOut("/*infloop*/ for (let window of (new (Math.pow(new RegExp(\"((?!(?!$)\\\\1{4,6}.))\", \"gy\"), 25))()).valueOf(\"number\")) /*RXUB*/var r = r2; var s = \"a\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-133180449*/count=581; tryItOut("\"use strict\"; print( /x/  ||  '' );");
/*fuzzSeed-133180449*/count=582; tryItOut("Array.prototype.sort.call(a1, /*wrap2*/(function(){ var oeejkt = (new d =  '' (timeout(1800))); var jpsjcf = ([]) =>  { yield (yield /*FARR*/[...[], ...[], undefined, \"\\u383F\", undefined, false,  \"\" , ...[], ].sort(DataView.prototype.getFloat64)) } ; return jpsjcf;})(), p0);");
/*fuzzSeed-133180449*/count=583; tryItOut("t2 + '';");
/*fuzzSeed-133180449*/count=584; tryItOut("v1 = o0.g1.eval(\"\\\"use strict\\\"; mathy3 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var ff = foreign.ff;\\n  var Int16ArrayView = new stdlib.Int16Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    (Int16ArrayView[((0x1567d271)-(0x3f6f278d)+(0xfa7176c2)) >> 1]) = (-0x751fc*(0xe5562eeb));\\n    d0 = (d1);\\n    return +((((d0)) / ((d1))));\\n  }\\n  return f; })(this, {ff: (/*MARR*/[0, -(2**53-2), -(2**53-2), true, -(2**53-2), 0, -(2**53-2), 0, 0, true, -(2**53-2), true, 0, true, -(2**53-2), true, 0, true, 0, true, -(2**53-2), true, -(2**53-2), -(2**53-2), true, true, 0, 0, -(2**53-2), -(2**53-2), 0, true, -(2**53-2), true, -(2**53-2), 0, 0, true, true, true, -(2**53-2), true, 0, 0, true, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -(2**53-2), -(2**53-2), true, true, -(2**53-2), 0, true])}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [1, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, Math.PI, -0x0ffffffff, 0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000001, -0x100000001, -(2**53-2), 2**53-2, -0, -Number.MIN_SAFE_INTEGER, 0x080000001, 0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 2**53, 42, 1.7976931348623157e308, -0x07fffffff, 0x07fffffff, -0x080000000, 2**53+2, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, -(2**53), 0/0, -(2**53+2), 0x0ffffffff]); \");");
/*fuzzSeed-133180449*/count=585; tryItOut("with((Date.prototype.getUTCMilliseconds)(x, new RegExp(\"\\\\s\", \"gym\")))print(( /x/  % -24));");
/*fuzzSeed-133180449*/count=586; tryItOut("\"use asm\"; v0 = a2.length;x = 5 / x; var r0 = x / 4; r0 = r0 % r0; x = x % 9; var r1 = r0 ^ x; r0 = r0 | r0; var r2 = 9 + x; var r3 = 0 & 7; r1 = 3 / r2; x = r0 - x; var r4 = r3 + r3; var r5 = r0 / r1; var r6 = x - r2; var r7 = r6 | r1; r1 = r3 % r7; print(r4); var r8 = r0 % 8; var r9 = 8 ^ 9; r2 = r3 ^ r7; var r10 = r2 | 2; var r11 = r10 - 7; r2 = r10 & r10; var r12 = r7 ^ 4; var r13 = r4 & 1; var r14 = 9 & r5; var r15 = 5 ^ r4; var r16 = r6 ^ 3; var r17 = r8 % 9; var r18 = 7 | r7; print(r5); var r19 = r1 - 4; var r20 = 2 - r19; r15 = r3 * 6; var r21 = r11 | r12; var r22 = r8 * r8; r22 = r19 ^ r20; var r23 = r19 - r21; var r24 = 9 % 7; var r25 = r22 & 1; var r26 = r10 * r22; r14 = r10 + 8; var r27 = 4 | r19; var r28 = r23 + 0; var r29 = 1 / r0; var r30 = r5 | 2; var r31 = r9 | r30; ");
/*fuzzSeed-133180449*/count=587; tryItOut("{ void 0; minorgc(false); }");
/*fuzzSeed-133180449*/count=588; tryItOut("mathy4 = (function(x, y) { return (( + ((Math.sin(Math.fround(Math.min(y, y))) | 0) == ((Math.fround(y) >>> Math.fround(( - ( + ( + ( + ( + (( + y) - ( + y))))))))) | 0))) === (( + ( + Math.max((Math.max(y, (y & Math.sin((x | 0)))) | 0), ((Math.min(((Math.max((x | 0), (-0x100000001 | 0)) | 0) | 0), ((x !== x) | 0)) | 0) | 0)))) | 0)); }); ");
/*fuzzSeed-133180449*/count=589; tryItOut("\"use asm\"; /*vLoop*/for (tdjebf = 0; tdjebf < 13; ++tdjebf) { const z = tdjebf; m1.has(o0.a1); } ");
/*fuzzSeed-133180449*/count=590; tryItOut("var jicodz = new ArrayBuffer(1); var jicodz_0 = new Uint32Array(jicodz); print(jicodz_0[0]); x;s0 = new String(g2);");
/*fuzzSeed-133180449*/count=591; tryItOut(";");
/*fuzzSeed-133180449*/count=592; tryItOut("\"use strict\"; new RegExp(\"[^]{1,}\", \"\");\nv0 = 0;\n");
/*fuzzSeed-133180449*/count=593; tryItOut("v1 = r2.exec;");
/*fuzzSeed-133180449*/count=594; tryItOut("mathy2 = (function(x, y) { return ( + ( - ( ! ( + ( ! ( + Math.max((Math.imul(-0x100000000, Math.fround(x)) >>> 0), (Math.imul(-0x080000001, (x >>> 0)) >>> 0)))))))); }); ");
/*fuzzSeed-133180449*/count=595; tryItOut("mathy0 = (function(x, y) { return Math.max((Math.min(Math.fround(((x >>> 0) === (y >>> 0))), Math.imul((x >>> 0), (0x080000000 | 0))) >>> Math.fround(( ~ Math.fround(x)))), Math.acosh(( + 1))); }); testMathyFunction(mathy0, [1/0, Number.MAX_SAFE_INTEGER, -0x080000000, -0, Math.PI, 0x080000000, Number.MAX_VALUE, 0/0, 0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -1/0, -0x07fffffff, -0x080000001, 1, 42, 0.000000000000001, 0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, 0x100000000, 2**53-2, 2**53, 2**53+2, -Number.MAX_VALUE, -(2**53), -0x0ffffffff, -(2**53+2), 0x080000001, -Number.MIN_VALUE, 0x100000001]); ");
/*fuzzSeed-133180449*/count=596; tryItOut("\"use strict\"; e0.add(i0);");
/*fuzzSeed-133180449*/count=597; tryItOut("mathy3 = (function(x, y) { return mathy1((( + ( - (( + Math.atan2(Math.imul(( ! x), Number.MAX_SAFE_INTEGER), ( + Math.asinh(( + y))))) >>> 0))) < ((x != Math.round((y * y))) | x)), (( + Math.acos((( ~ (Math.pow(((Math.clz32(y) | 0) | 0), (x | 0)) >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy3, [2**53+2, Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, 42, 0x100000000, Number.MAX_SAFE_INTEGER, 1, 0.000000000000001, -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, -0, 0/0, 2**53, 2**53-2, -0x100000001, -(2**53-2), -1/0, 0x100000001, 0x080000001, -0x07fffffff, -Number.MAX_VALUE, Math.PI, 0x07fffffff, -0x080000000, 1.7976931348623157e308, -(2**53+2), -Number.MIN_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, 0]); ");
/*fuzzSeed-133180449*/count=598; tryItOut("/*vLoop*/for (let iqpfpg = 0, zjezdk; iqpfpg < 1; ++iqpfpg) { let e = iqpfpg; print(x); } ");
/*fuzzSeed-133180449*/count=599; tryItOut("\"use strict\"; Object.prototype.unwatch.call(h2, 14);");
/*fuzzSeed-133180449*/count=600; tryItOut("\"use strict\"; v2 = x;");
/*fuzzSeed-133180449*/count=601; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.abs((Math.fround(Math.acos((Math.fround(( ~ Math.fround(( + (Math.fround(((Math.fround(2**53) >>> 0) % x)) << y))))) | 0))) | (((x >>> 0) ? (Math.atanh(y) >>> 0) : (Math.acosh(y) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [-(2**53), Number.MAX_VALUE, 0, 0/0, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53, 0x080000001, -(2**53+2), 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, -1/0, 1.7976931348623157e308, 0x100000000, -0, 2**53+2, -0x07fffffff, -(2**53-2), 2**53-2, 0x080000000, 1/0, -Number.MIN_VALUE, 0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, 0x07fffffff, Math.PI, 0.000000000000001, -0x100000001]); ");
/*fuzzSeed-133180449*/count=602; tryItOut("mathy3 = (function(x, y) { return (( + (Math.atan2(Math.fround((Math.fround(-Number.MIN_VALUE) >>> Math.fround(Math.atanh((Math.atan2(y, x) | 0))))), Math.fround(( + x))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0, '', (function(){return 0;}), [], '/0/', (new Boolean(true)), -0, '\\0', '0', (new String('')), ({valueOf:function(){return '0';}}), (new Number(-0)), [0], ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), /0/, objectEmulatingUndefined(), NaN, (new Boolean(false)), 1, false, (new Number(0)), undefined, 0.1, true, null]); ");
/*fuzzSeed-133180449*/count=603; tryItOut("this.e0.add(e2);");
/*fuzzSeed-133180449*/count=604; tryItOut("Array.prototype.pop.call(o1.a0, this.e0, i2);/*hhh*/function rblhln(x = x){return;}rblhln(x = Proxy.createFunction(({/*TOODEEP*/})(new RegExp(\"(?!$|[^]*\\\\cX(?=.{3,}))|[^]*\", \"ym\")), function ([y]) { }));");
/*fuzzSeed-133180449*/count=605; tryItOut("t2.set(t1, 18);");
/*fuzzSeed-133180449*/count=606; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=607; tryItOut("\"use strict\"; /*vLoop*/for (var axcvou = 0, pwhdlt; axcvou < 0; ++axcvou) { let e = axcvou; o2.a0.pop(e0); } ");
/*fuzzSeed-133180449*/count=608; tryItOut("{ void 0; selectforgc(this); } ");
/*fuzzSeed-133180449*/count=609; tryItOut("Array.prototype.push.apply(a2, [this.a0, v0, b2]);");
/*fuzzSeed-133180449*/count=610; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=611; tryItOut("\"use strict\"; let (b) { delete this.h0.get; }");
/*fuzzSeed-133180449*/count=612; tryItOut("v1 = this.t2.length;");
/*fuzzSeed-133180449*/count=613; tryItOut("( '' );");
/*fuzzSeed-133180449*/count=614; tryItOut("i1.next();function x(x = x, x, b, x, x, y, x, x, w, let, x, \u3056, NaN, a)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i2 = (0xfb27fe75);\n    return (((0x1586c84f) / ((0x158b2*(0xf9068528))>>>((0x46561605) / (0xff2cfb7b)))))|0;\n  }\n  return f;/(?=(?!.)+?(?:(?!(?!$)))|\\3)+?/gym.clearprint(x);");
/*fuzzSeed-133180449*/count=615; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround(( + Math.atan2(( + Math.clz32((Math.sqrt(y) >> x))), (y % y)))) || Math.min(( + mathy1((mathy1(x, Math.fround(Math.pow(Math.fround(y), Math.fround(x)))) < x), ( ~ (Math.fround(Math.atan2(mathy1(( + 2**53+2), Math.fround(x)), Number.MAX_SAFE_INTEGER)) | 0)))), Math.atan2(( + y), ( + (y - x))))); }); testMathyFunction(mathy2, [-0x07fffffff, 2**53-2, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, 0, -0x0ffffffff, 0x07fffffff, -0, 0x080000001, 2**53+2, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 42, -(2**53-2), 1, 1.7976931348623157e308, 0/0, Math.PI, -(2**53+2), -0x080000001, 0x0ffffffff, 2**53, -Number.MIN_VALUE, 1/0, Number.MAX_VALUE, -0x100000001, -0x080000000, Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=616; tryItOut("\"use strict\"; m1.set(i0, x.unwatch(\"keys\"));");
/*fuzzSeed-133180449*/count=617; tryItOut("/*MXX1*/o1 = g1.g2.Set.prototype;");
/*fuzzSeed-133180449*/count=618; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=619; tryItOut("/*oLoop*/for (var zglbzn = 0, x; zglbzn < 113 && (({} = x(NaN))); ++zglbzn) { v1 = evalcx(\"\\\"use strict\\\"; print((\\\"\\\\u1C5B\\\".getUTCSeconds()));\", g2); } ");
/*fuzzSeed-133180449*/count=620; tryItOut("h0 = ({getOwnPropertyDescriptor: function(name) { /*RXUB*/var r = this.g2.r0; var s = \"aaaaaa\"; print(s.match(r)); ; var desc = Object.getOwnPropertyDescriptor(s2); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v2 = evaluate(\"\\\"use strict\\\"; var yidqjq = new ArrayBuffer(12); var yidqjq_0 = new Uint32Array(yidqjq); yidqjq_0[0] = -10; Object.prototype.watch.call(v1, \\\"getUint32\\\", f0);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 22 != 12), noScriptRval: true, sourceIsLazy: true, catchTermination: true }));; var desc = Object.getPropertyDescriptor(s2); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { print(uneval(v2));; Object.defineProperty(s2, name, desc); }, getOwnPropertyNames: function() { e1.has(v0);; return Object.getOwnPropertyNames(s2); }, delete: function(name) { return v2; return delete s2[name]; }, fix: function() { o1.o1.e2.add(g1);; if (Object.isFrozen(s2)) { return Object.getOwnProperties(s2); } }, has: function(name) { v2 = Object.prototype.isPrototypeOf.call(v0, t1);; return name in s2; }, hasOwn: function(name) { x = p1;; return Object.prototype.hasOwnProperty.call(s2, name); }, get: function(receiver, name) { t2.set(g2.g0.t2, 7);; return s2[name]; }, set: function(receiver, name, val) { this.s0 += 'x';; s2[name] = val; return true; }, iterate: function() { s0 += s2;; return (function() { for (var name in s2) { yield name; } })(); }, enumerate: function() { Array.prototype.reverse.call(a2);; var result = []; for (var name in s2) { result.push(name); }; return result; }, keys: function() { return g0; return Object.keys(s2); } });");
/*fuzzSeed-133180449*/count=621; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2(( + mathy2(Math.sinh(Math.fround(Math.atan2((((x >>> 0) != Math.fround(( ~ y))) | 0), ( ! y)))), ( + (Math.log10((Math.cbrt((mathy2(Math.fround(y), y) | 0)) | 0)) | 0)))), Math.max((mathy2(Math.fround((Math.expm1(-Number.MIN_SAFE_INTEGER) + ( + Math.asin(x)))), ( - x)) | 0), Math.acosh(Math.fround(Math.pow(( + y), Math.fround(Math.exp(x))))))); }); testMathyFunction(mathy3, [-0x07fffffff, Number.MIN_VALUE, 2**53+2, 2**53-2, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, -0, 0x100000001, 1/0, -(2**53), 1, 0/0, 1.7976931348623157e308, -Number.MIN_VALUE, 0, 0.000000000000001, 0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53, -(2**53-2), 0x100000000, -Number.MAX_VALUE, -(2**53+2), Number.MAX_VALUE, Math.PI, -0x080000000, 42, -1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=622; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.sinh(((((( + Math.ceil(Math.fround(Math.hypot(y, (y & x))))) >>> 0) == (( + Math.asinh((Math.min((Math.fround(Math.max(Math.fround(x), Math.fround(x))) % ( + ((-Number.MAX_VALUE >>> 0) , ( + x)))), y) >>> 0))) >>> 0)) >>> 0) && (((Math.hypot(((((x | 0) >= (y | 0)) | 0) >>> 0), (( + (( + x) << ( + (( ~ (-(2**53-2) | 0)) | 0)))) >>> 0)) >>> 0) ? (Number.MIN_SAFE_INTEGER >>> 0) : (Math.atan(mathy1(Math.min(x, y), (x | 0))) >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy3, [-0x080000000, 0, -(2**53+2), -Number.MIN_VALUE, -0x0ffffffff, 0x080000000, -(2**53), -0x080000001, -0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000, 1, -1/0, Math.PI, Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, 0x100000000, -0x07fffffff, 2**53, 0.000000000000001, 2**53+2, 1.7976931348623157e308, 1/0, Number.MAX_VALUE, 0/0, -Number.MAX_VALUE, 42, 0x080000001, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=623; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-133180449*/count=624; tryItOut("mathy5 = (function(x, y) { return (( + ( + Math.sin(Math.imul((Math.max(((0x07fffffff | ( ! y)) >>> 0), (Math.fround(Math.log((Math.tan(-0) | 0))) >>> 0)) >>> 0), ( + x))))) !== ( + Math.max(( + Math.pow(Math.sqrt(Math.fround(x)), Math.expm1(-0x0ffffffff))), Math.pow(( - y), mathy3(x, x))))); }); testMathyFunction(mathy5, [Math.PI, 0x0ffffffff, 1.7976931348623157e308, -(2**53+2), 0x080000000, 0x100000000, -0, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, Number.MIN_VALUE, -0x07fffffff, -(2**53), -0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, 2**53+2, -(2**53-2), 0x100000001, 0x07fffffff, -0x080000001, 0/0, 42, 2**53, 0x080000001]); ");
/*fuzzSeed-133180449*/count=625; tryItOut("/*infloop*/ for (var window of Math.imul(3, 26) = this.__defineSetter__(\"z\", /\\2{4}[^]*?[\\W]?|.|[^]|(?!\\u3f94)*?*?\ud2fc\\s|[^]\\2|($)*|^{0}/.setMinutes)) s2 + h2;");
/*fuzzSeed-133180449*/count=626; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void schedulegc(12); } void 0; } print(\"\u03a0\");");
/*fuzzSeed-133180449*/count=627; tryItOut("\"use asm\"; (let (e) undefined);");
/*fuzzSeed-133180449*/count=628; tryItOut("\"use strict\"; v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: this, sourceIsLazy: (x % 6 != 5), catchTermination: (eval(\"o0.m0.has(a0);\\nreturn;\\n\", x)) }));");
/*fuzzSeed-133180449*/count=629; tryItOut("mathy2 = (function(x, y) { return ( ~ Math.fround(mathy0(mathy0(Math.imul(Math.max(Math.hypot((0x100000000 >>> 0), (( + (( + y) + ( + x))) >>> 0)), x), x), Math.imul(x, ( + Math.abs(-(2**53-2))))), ( - (( + x) >>> 0))))); }); ");
/*fuzzSeed-133180449*/count=630; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.trunc(Math.fround(( + ( - Math.pow(Math.fround(( - y)), Math.imul((mathy4(y, Math.fround(( ! Math.fround(y)))) | 0), (( + ( ~ Math.fround(y))) >= (( ~ ( ~ y)) | 0))))))))); }); testMathyFunction(mathy5, [42, -0, -0x080000000, -(2**53-2), -(2**53+2), 0/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, Number.MAX_VALUE, 0, 0x0ffffffff, -0x080000001, 0x100000001, 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 0.000000000000001, 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, -0x07fffffff, Math.PI, 1, -0x100000000, 2**53, 0x080000000, -1/0, -0x100000001, 0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=631; tryItOut("\"use strict\"; for (var p in h1) { try { v2 = a1.length; } catch(e0) { } v1 = o0.g0.eval(\"this.s2 = s2.charAt(Math.min((b1 = t0.buffer), x));\"); }");
/*fuzzSeed-133180449*/count=632; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.expm1(Math.fround(Math.fround(((mathy1((Math.fround((Math.fround(Math.fround(x)) ? Math.fround(x) : ( + 0x0ffffffff))) >>> 0), Math.fround(( ! -(2**53-2)))) >>> 0) % Math.fround(Math.pow(Math.fround((mathy0((x | 0), (y | 0)) | 0)), Math.fround(Math.fround((Math.fround(Number.MAX_SAFE_INTEGER) >= Math.fround((Math.pow(( + y), Math.fround(Math.fround(Math.trunc(Math.fround(y))))) | 0)))))))))))); }); testMathyFunction(mathy2, [/0/, (new Boolean(true)), false, (new Boolean(false)), 0, (new Number(0)), 0.1, (new String('')), null, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), '/0/', ({toString:function(){return '0';}}), NaN, '', (function(){return 0;}), [0], 1, undefined, '\\0', [], (new Number(-0)), -0, '0', true, objectEmulatingUndefined()]); ");
/*fuzzSeed-133180449*/count=633; tryItOut("mathy4 = (function(x, y) { return (( + ( ! (Math.log1p(x) / y))) >>> 0); }); testMathyFunction(mathy4, [-0x100000001, 0x07fffffff, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, 1, 0x100000000, 1.7976931348623157e308, 1/0, Math.PI, -1/0, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, -0x080000000, -0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x0ffffffff, 2**53, 0x080000000, 0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, Number.MIN_VALUE, 2**53-2, 2**53+2, 42, 0x100000001]); ");
/*fuzzSeed-133180449*/count=634; tryItOut("{ void 0; void schedulegc(this); } /*RXUB*/var r = new RegExp(\"(\\\\d)?(?:(?!(?=\\\\3|(?:[^])|.)\\\\S+|\\\\w{0,0}|\\\\s|(?!(\\\\b)*)))|(?:\\\\1.{1,})+?[\\\\S\\\\t-\\\\ub608](\\\\w|[^\\\\cQ-\\uf15f]+){0}{8388608}$\\\\2*{134217727,134217727}[^]|(\\\\b)\", \"gym\"); var s = \"\\0\\0\\u2b8c\\0\\n\\0\\0\\u2b8c\\0\\n\\n\\n\\n\\n\\n\\n\\u9542\\u9542\\n\\n\\n\"; print(s.replace(r, Map.prototype.forEach)); ");
/*fuzzSeed-133180449*/count=635; tryItOut("/*tLoop*/for (let b of /*MARR*/[[undefined], [undefined], [undefined], x, x, [undefined], [undefined], [undefined], x, [undefined], [undefined], [undefined], [undefined], x, [undefined], x, x, x, x, [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], x, [undefined], [undefined], x, [undefined], [undefined], x, x, [undefined], x, [undefined], x, [undefined]]) { a2.toSource = (function() { try { a2.sort((function(j) { if (j) { try { g2.toSource = (function() { for (var j=0;j<0;++j) { o0.f2(j%4==0); } }); } catch(e0) { } v1 = this.t1.length; } else { h1 = Proxy.create(h0, this.i2); } }), v1); } catch(e0) { } try { for (var v of s0) { try { print(i2); } catch(e0) { } try { v0 + this.h2; } catch(e1) { } try { v2 = (o1 instanceof i2); } catch(e2) { } o2.o2.a1.splice(-3, 5, m0); } } catch(e1) { } try { o1 + ''; } catch(e2) { } for (var p in i0) { try { break M; } catch(e0) { } try { this.m0 + this.t0; } catch(e1) { } try { Array.prototype.sort.apply(a1, [(function() { try { g0.v2 = null; } catch(e0) { } try { g2.g2.v1 = evaluate(\"function f1(a2)  { \\\"use asm\\\"; return \\\"\\\\u61F4\\\" } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: window, noScriptRval: true, sourceIsLazy:  '' , catchTermination: false })); } catch(e1) { } try { ; } catch(e2) { } o1.v0 = o1.o2.t0.length; return s0; })]); } catch(e2) { } Array.prototype.reverse.apply(o0.a2, [h0, g1]); } return g0; }); }");
/*fuzzSeed-133180449*/count=636; tryItOut("/* no regression tests found */Array.prototype.reverse.call(a1);");
/*fuzzSeed-133180449*/count=637; tryItOut("/*MXX2*/g0.Object.getOwnPropertyDescriptor = this.b0;");
/*fuzzSeed-133180449*/count=638; tryItOut("\"use strict\"; mathy0 = /*RXUB*/var r = eval = (-17); var s = \"\"; print(s.split(r)); ; testMathyFunction(mathy0, [-0x080000001, -(2**53+2), 0x0ffffffff, 42, 0, 2**53+2, 1, Number.MAX_VALUE, 0x080000001, -0x100000001, 0x100000001, 1/0, -1/0, -0x100000000, 0/0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, -0, -0x080000000, 0.000000000000001, -0x07fffffff, 1.7976931348623157e308, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -(2**53), 0x080000000, -Number.MAX_VALUE, 2**53, 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=639; tryItOut("mathy1 = (function(x, y) { return Math.min(Math.fround((Math.fround(( ! x)) >>> (Math.imul(( + (( + -0x100000001) ? ( + y) : ( + x))), (Math.imul(( + Math.sin(y)), ( + ( + Math.min(( + x), Math.pow(y, (( - y) | 0)))))) | 0)) | 0))), (((( ! Math.pow(mathy0(x, x), (Math.imul((y >>> 0), (x >>> 0)) >>> 0))) >>> 0) > ((mathy0(((((Math.fround(Math.tanh(Math.fround(Number.MAX_SAFE_INTEGER))) | 0) >= (Math.pow(1, Math.max(Math.fround((Math.fround(x) << Math.fround(0x100000001))), x)) | 0)) | 0) | 0), 2**53) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -0x100000001, 0.000000000000001, 0x100000001, 2**53+2, Math.PI, -0x07fffffff, -Number.MIN_VALUE, -0x0ffffffff, 0x07fffffff, 0, 0x0ffffffff, 1/0, -(2**53), -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), -0, Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 1, 2**53, 1.7976931348623157e308, 0/0, 42, 0x080000000, 0x100000000, -1/0, -Number.MAX_VALUE, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=640; tryItOut("print(uneval(t2));");
/*fuzzSeed-133180449*/count=641; tryItOut("selectforgc(o1);");
/*fuzzSeed-133180449*/count=642; tryItOut("for (var p in b1) { v0 = Object.prototype.isPrototypeOf.call(s2, o0.a0); }");
/*fuzzSeed-133180449*/count=643; tryItOut("mathy5 = (function(x, y) { return Math.tan(Math.cosh((((( + (( + (Math.atan2((y >>> 0), (-0x080000001 >>> 0)) >>> 0)) <= ( + y))) | 0) << (Math.log10(0x0ffffffff) | 0)) | 0))); }); testMathyFunction(mathy5, [-1/0, 0/0, -0, -0x0ffffffff, 0x07fffffff, 0x100000000, 0x080000000, -Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_VALUE, -0x100000000, -0x07fffffff, -(2**53-2), 0.000000000000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53, Math.PI, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 42, 0x100000001, 0, 1/0, 0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), -0x080000001, Number.MAX_VALUE, -0x100000001, 2**53+2, 2**53-2]); ");
/*fuzzSeed-133180449*/count=644; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-133180449*/count=645; tryItOut("/*infloop*/for(var b = [1]; new ((x = w))(); new (({toString:  /x/  }))()) {print((4277)); }\u0009");
/*fuzzSeed-133180449*/count=646; tryItOut("L: for (var y of w = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(\"\\u36D8\"), Object)) selectforgc(o2);");
/*fuzzSeed-133180449*/count=647; tryItOut("\"use strict\"; o2.g2.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-133180449*/count=648; tryItOut("print(/*wrap3*/(function(){ \"use strict\"; var vgfeui = (--arguments.callee.caller.arguments); ((uneval((vgfeui =  '' ))))(); }));");
/*fuzzSeed-133180449*/count=649; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    switch ((((0x64f41c71))|0)) {\n      case -1:\n        return +((d1));\n      case 0:\n        d1 = (+(0.0/0.0));\n      case -2:\n        i2 = (i0);\n        break;\n      case -1:\n        switch (((-(i0)) << ((-0x7898f12)+(-0xe64bf7)-(0xfcda8969)))) {\n          case 0:\n            {\n              (Float64ArrayView[2]) = ((-0.00390625));\n            }\n            break;\n          default:\n            d1 = (d1);\n        }\n        break;\n      case -3:\n        d1 = (1.1805916207174113e+21);\n        break;\n      case -3:\n        i2 = (/*FFI*/ff(((((((((x.unwatch(\"isNaN\")))+((-1048577.0) == (-16385.0)))>>>((/*FFI*/ff(((-6.044629098073146e+23)), ((0.5)))|0)+(!(0xfaeb61a7))-(0xffffffff))))*0x3896a) >> ((0xf90c318e)-(i0)))), ((2147483649.0)), ((d1)), (((i0) ? ((+(1.0/0.0)) + (+(1.0/0.0))) : (+(((0xf82505cf)) << ((-0x1fd9bc7)))))), ((((i0)-(i2)))), ((((((d1)))+(i0)) >> (((1.2089258196146292e+24) > (-67108865.0))*0xa64a8))), ((-0x8000000)), ((+(-1.0/0.0))), ((34359738368.0)), ((-1.125)), ((-549755813889.0)), ((-4294967297.0)), ((32769.0)), ((274877906944.0)), ((-4.722366482869645e+21)))|0);\n        break;\n      case 0:\n        d1 = (3.0);\n        break;\n      case -3:\n        (Uint8ArrayView[(((+sqrt(((+(0x87832b74))))) <= (-562949953421311.0))) >> 0]) = ((x\n)-(i0));\n        break;\n    }\n    {\n      i2 = (!(-0x8000000));\n    }\n    {\n      i0 = (0xf7f0dbf1);\n    }\n    i0 = (i2);\n    i2 = (/*FFI*/ff(((((0x2f6349a6)-(i0)+(i0)) << (((0xf383aff) ? ((0x59f041fa) ? (0x22e7269a) : (0xaf137189)) : (i0))+(i2)-((0xcf11fc03))))), ((((((0xffffffff)+(i2)) ^ ((((0x53b31bba)+(0x9593ccfd)-(0x86d7d9bc)))-(0xb94dbd34)+(i0))) % (((i0))|0))|0)), ((~((((((1.125) != (-8589934593.0))*0xafa6e)>>>((!(i2)))))))))|0);\n    (Uint16ArrayView[0]) = ((((Int16ArrayView[0])) & (((((0x67823ec)-(0xfc484a43)) << ((i0))) != (imul((i0), (0xfa6e5474))|0))+(/*FARR*/[, ...((uneval(x))) for (NaN of []) for each (window in []) for (x of []), ([] = []), ({x: window.yoyo(\"\\u865E\")})].filter))) % (~~(+abs(((d1))))));\n    d1 = (Infinity);\n    i2 = (/*FFI*/ff(((abs((abs((imul((i2), (/*FFI*/ff(((d1)), ((65.0)), ((((0x5c43e95)) | ((0x46b50a8a)))), ((+(0.0/0.0))), ((-0.0625)), ((-72057594037927940.0)), ((137438953473.0)), ((3.094850098213451e+26)))|0))|0))|0))|0)))|0);\n    (Uint16ArrayView[((i0)) >> 1]) = ((i2)+((~~(d1)))+(i2));\n    {\n      d1 = (-0.001953125);\n    }\n    i0 = (i0);\n    i0 = (i2);\n    {\n      i2 = (0xdd7928d8);\n    }\n    i2 = (/*FFI*/ff()|0);\n    i2 = (0x65f38d99);\n    i0 = (!(i0));\n    i2 = ((i2) ? (i0) : (0x9b20c33a));\n    {\n      {\n        return +((Infinity));\n      }\n    }\n    {\n      i2 = (i2);\n    }\n    i2 = (i2);\n    {\n      d1 = ((-0x8000000) ? (d1) : (((134217729.0)) * ((-1.5474250491067253e+26))));\n    }\n    return +((+floor(((+/*FFI*/ff())))));\n  }\n  return f; })(this, {ff: Math.min(4, window).throw((4277))}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53+2), 0/0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0, 0.000000000000001, -0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -0x100000000, 0x0ffffffff, -1/0, -Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, -(2**53-2), Number.MIN_VALUE, -0x07fffffff, 42, 1.7976931348623157e308, 1, -(2**53), -Number.MAX_VALUE, -0x080000001, 1/0, 0x080000000, 0x07fffffff, 2**53+2, -0x0ffffffff, -0, 2**53]); ");
/*fuzzSeed-133180449*/count=650; tryItOut("\"use strict\"; testMathyFunction(mathy4, [1, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 42, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -Number.MIN_VALUE, 0x080000000, 0x080000001, 2**53-2, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -0x080000000, -0x080000001, 0x100000001, 1/0, -0x100000000, 0x100000000, -0x100000001, -(2**53+2), Math.PI, Number.MIN_VALUE, 2**53+2, -(2**53), 0, 0x0ffffffff, 2**53, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=651; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.expm1(( + ((mathy0(( + Math.log1p((Math.max(y, -(2**53-2)) >>> 0))), (( ~ y) | 0)) >= Math.atan2(( + Math.exp(( + ((Math.PI >>> 0) << (y >>> 0))))), Math.pow(Math.imul(x, (2**53 ? ( ~ x) : x)), ( + Math.asin(x))))) | 0))); }); testMathyFunction(mathy2, [0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -1/0, 0/0, 0x100000001, 0.000000000000001, Math.PI, -0x080000001, Number.MAX_VALUE, 0x080000001, -0x080000000, 2**53-2, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, 0, 2**53+2, 1/0, -(2**53+2), 42, -0x100000001, 2**53, -Number.MIN_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -0, Number.MIN_VALUE, 1, -(2**53)]); ");
/*fuzzSeed-133180449*/count=652; tryItOut("/*ODP-2*/Object.defineProperty(g2, \"x\", { configurable: false, enumerable: true, get: (function() { e1 + e2; return i0; }), set: (function() { try { m0.set(\nx =  /x/g , g1.a2); } catch(e0) { } try { i1 + e1; } catch(e1) { } v1 = a2[19]; return g1; }) });");
/*fuzzSeed-133180449*/count=653; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[(1/0), (1/0), true,  /x/g ,  /x/g , (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new String('q'), (1/0), new String('q'), (1/0), true, new String('q'), new String('q'),  /x/g ,  /x/g , (1/0), true, true, new String('q'),  /x/g , true,  /x/g , (1/0), (1/0),  /x/g ,  /x/g ,  /x/g , (1/0), (1/0), (1/0), new String('q'),  /x/g , true, new String('q'), true, (1/0), true, true, (1/0), true,  /x/g , (1/0), true,  /x/g , (1/0), new String('q'), (1/0), true, (1/0),  /x/g , (1/0)]) { print(x);function w(x)\"use asm\";   var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = ((+(1.0/0.0)) <= (9223372036854776000.0));\n    }\n    i2 = (i1);\n    {\n      i1 = ((((i0))>>>(((-32768.0) == (((+(~((0xf8e68687))))) % ((i0))))-((((i1)+((0x8b7f63a7) ? (-0x8000000) : (0xf94b544b)))>>>(((0xd7caa70c) ? (0xd644c903) : (0x29df22a8))-(i1)-(i2)))))));\n    }\n    {\n      i2 = (\nx);\n    }\n    i0 = (((x !== eval) ^ (-0xe7504*(1))));\n    return +((Infinity));\n    i1 = ((i2) ? (((Infinity) + ((((-16777217.0)) - ((0.03125))) + (((-4.722366482869645e+21)) * ((524289.0))))) == ((0xffffffff) ? (((-70368744177665.0)) % ((147573952589676410000.0))) : (+(((0xc67ea3a1))>>>((0xa52f3fe9)))))) : (i1));\n    {\n      i0 = (i2);\n    }\n    {\n      return +((NaN));\n    }\n    i2 = (i1);\n    i1 = ((((Int32ArrayView[(((0xfa6af8df) ? (0xf9680190) : (-0x8000000))+(i0)+(i2)) >> 2])) ^ ((i2)-(i1)+(i0))) > (~((i2)-(((4277)) ? ((((0xf949abfb)) & ((0x4578182f))) > (abs((0x5e434072))|0)) : (i2)))));\n    return +((-3.0));\n  }\n  return f;print(x); }");
/*fuzzSeed-133180449*/count=654; tryItOut("\"use strict\"; v1 = t2.length;");
/*fuzzSeed-133180449*/count=655; tryItOut("v2 = g0.runOffThreadScript();");
/*fuzzSeed-133180449*/count=656; tryItOut("\"use strict\"; testMathyFunction(mathy0, [1.7976931348623157e308, 2**53, Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, -(2**53), 0x0ffffffff, 0x100000000, 2**53-2, 1/0, Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, -1/0, -Number.MIN_VALUE, -0, 0, 1, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, -0x100000000, 0x07fffffff, 0x080000000, -0x080000000, Number.MAX_VALUE, 0x100000001, Math.PI, 42, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0/0]); ");
/*fuzzSeed-133180449*/count=657; tryItOut("\"use strict\"; with(x)/*bLoop*/for (ndjxxs = 0; ndjxxs < 27; ++ndjxxs) { if (ndjxxs % 4 == 0) { t1[1] = /\\d/gm; } else { return this; }  } ");
/*fuzzSeed-133180449*/count=658; tryItOut("");
/*fuzzSeed-133180449*/count=659; tryItOut("\"use strict\"; v0 = evalcx(\"function f1(e2)  { yield e2 } \", g1);");
/*fuzzSeed-133180449*/count=660; tryItOut("\"use strict\"; let window = null, x, x, a, urvfxi, yadarh, kxnuja, xgsrar, x;\u000c(false);");
/*fuzzSeed-133180449*/count=661; tryItOut("\"use strict\"; s2.toSource = f1;");
/*fuzzSeed-133180449*/count=662; tryItOut("v0[0] = p2;");
/*fuzzSeed-133180449*/count=663; tryItOut("mathy3 = (function(x, y) { return mathy0(((Math.hypot((( + ( + ( + ( + ((1/0 >>> 0) ? ((-1/0 | y) >>> 0) : y))))) | 0), (Math.expm1((( + y) < (Math.fround(x) ? Math.fround(y) : (x >>> 0)))) | 0)) | 0) | 0), (Math.fround(( - ((Math.fround(Math.expm1(Math.fround(( ! ( + x))))) | (Math.sin((y >>> 0)) >>> 0)) | 0))) | 0)); }); ");
/*fuzzSeed-133180449*/count=664; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (((( + mathy0(Math.asinh(( + ( ! ( + 0x080000001)))), (Math.fround(Math.max(Math.fround(( + Math.min(( + ( + Math.clz32(( + y)))), ( + (Math.atan(Math.atan2(y, (x / Math.fround(y)))) | 0))))), ( ! y))) >>> 0))) | 0) - (( - ( + ( + Math.imul(y, (((mathy0(x, -Number.MIN_VALUE) >>> 0) >>> (Math.clz32(Math.atan2(x, x)) | 0)) ? Math.tanh((x | 0)) : (Math.atan2((y | 0), (x | 0)) | 0)))))) | 0)) | 0); }); testMathyFunction(mathy2, [-(2**53), -(2**53-2), 2**53+2, 0x100000001, 2**53-2, 0x080000001, 1, -0x080000001, -0x080000000, -1/0, 42, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_SAFE_INTEGER, 0, 0x07fffffff, -Number.MIN_VALUE, -0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, -0x100000001, 0/0, 1.7976931348623157e308, 0x100000000, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, 2**53, Number.MAX_VALUE, -0x0ffffffff, -0]); ");
/*fuzzSeed-133180449*/count=665; tryItOut("{} = x = [,,z1];");
/*fuzzSeed-133180449*/count=666; tryItOut("Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-133180449*/count=667; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + (Math.pow((y >>> 0), (Math.fround(( ~ (y >>> 0))) >>> 0)) >>> 0)) > Math.fround(mathy0(Math.fround((( ~ mathy0(( + y), 0x100000000)) | 0)), Math.fround(Math.fround((Math.fround((Math.atan2((((y | 0) < (y | 0)) | 0), y) >>> 0)) && (Math.ceil((( + ((-0x100000001 | 0) === (x | 0))) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, 2**53-2, Number.MAX_VALUE, Math.PI, -0x080000000, 2**53+2, -Number.MIN_VALUE, 0x100000001, -1/0, 0.000000000000001, -0x100000001, 0x0ffffffff, 0, 0x080000000, -0x0ffffffff, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), 0x07fffffff, -0, -(2**53+2), -(2**53), -0x080000001, 1.7976931348623157e308, 1, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-133180449*/count=668; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.fround(Math.min(( + Math.pow((Math.sin(mathy4((x | 0), ( + (0x0ffffffff , 2**53)))) >>> 0), ((Math.sign(Math.pow(Math.hypot(y, ((((x >>> 0) ? (x >>> 0) : (-0x07fffffff >>> 0)) >>> 0) >>> 0)), Math.hypot(Math.fround(x), Math.fround(Math.pow((((-(2**53+2) | 0) ** (x | 0)) | 0), Math.fround(Math.pow(Math.fround(x), ( + x)))))))) >>> 0) >>> 0))), Math.sin(( - (Math.expm1((Math.fround((Math.fround(0) || ( + Math.atan2(x, ( + 42))))) | 0)) | 0))))); }); ");
/*fuzzSeed-133180449*/count=669; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.pow(Math.asinh((((( + Math.fround((Math.fround(x) <= ( + Math.fround(Math.abs((y | 0))))))) | 0) === ((Math.pow((y >>> 0), (x >>> 0)) >>> 0) | 0)) | 0)), Math.atan2((((Math.imul(Math.fround(( + mathy0((( + (y >>> 0)) >>> 0), ( + (((mathy1(0x0ffffffff, y) | 0) ? (x | 0) : ( ~ -0x080000000)) | 0))))), x) >>> 0) - ((Math.max((x | 0), (( + ( + x)) | 0)) | 0) >>> 0)) >>> 0), ( ! (( - (( ~ y) | 0)) >>> 0))))); }); testMathyFunction(mathy4, [0, (new Number(-0)), true, '/0/', [], undefined, ({valueOf:function(){return '0';}}), NaN, objectEmulatingUndefined(), null, (function(){return 0;}), (new Number(0)), '', /0/, 1, false, (new String('')), '0', ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), [0], (new Boolean(false)), 0.1, -0, '\\0', (new Boolean(true))]); ");
/*fuzzSeed-133180449*/count=670; tryItOut("mathy4 = (function(x, y) { return ((((Math.fround((Math.fround(((Math.exp(y) >>> 0) / Math.atan2(x, ( + y)))) / Math.fround(Math.pow(x, (((x || ((mathy0((2**53 | 0), (x | 0)) | 0) | 0)) | 0) | 0))))) << ( - (x >>> 0))) | 0) ? ((((( + ((mathy3((y | 0), -Number.MAX_SAFE_INTEGER) | 0) !== y)) | 0) == (Math.pow(Math.fround(Math.acos((( ! y) >>> 0))), x) | 0)) | 0) | 0) : (( + ( ! y)) | 0)) | 0); }); testMathyFunction(mathy4, [-(2**53+2), -0x07fffffff, 0x100000001, -(2**53), 0, -Number.MIN_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 0x080000000, 1/0, 1, -1/0, -0x0ffffffff, 42, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, Number.MIN_VALUE, 0/0, 0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, 0x07fffffff, -0x100000001, -0x100000000, 0.000000000000001, 2**53-2, 2**53, 1.7976931348623157e308, -0x080000001]); ");
/*fuzzSeed-133180449*/count=671; tryItOut("\"use strict\"; /*oLoop*/for (let iaeptm = 0, x; iaeptm < 68; ++iaeptm) { /*RXUB*/var r = r2; var s = \"\\n\"; print(s.split(r)); print(r.lastIndex);  } ");
/*fuzzSeed-133180449*/count=672; tryItOut("o2.t0 = new Int16Array(({valueOf: function() { with((4277))return;return 14; }}));\nthis.h2 = {};\n");
/*fuzzSeed-133180449*/count=673; tryItOut("for (var v of t0) { try { s1 += s2; } catch(e0) { } try { o2.o2 + h1; } catch(e1) { } for (var p in e1) { s2 += 'x'; } }");
/*fuzzSeed-133180449*/count=674; tryItOut("v0 = g2.eval(\"selectforgc(o1.o2);\");");
/*fuzzSeed-133180449*/count=675; tryItOut("e1.delete(h1);");
/*fuzzSeed-133180449*/count=676; tryItOut("mathy5 = (function(x, y) { return (Math.log((Math.hypot((( + Math.fround(Math.fround(Math.fround(Math.fround(( ! Math.fround(( ! (0x080000000 >>> 0))))))))) >>> 0), (((( + ( ! ( + x))) | 0) ? (( - (Math.atan(1) === Math.fround(y))) | 0) : ((( - x) ? 2**53+2 : x) | 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, [-0x080000001, -0x080000000, -0, Math.PI, 0, 42, 0.000000000000001, -Number.MAX_VALUE, 1, -0x07fffffff, 2**53-2, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, 0/0, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -(2**53+2), Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, -1/0, 0x080000000, -(2**53), 2**53, -0x100000001, Number.MIN_SAFE_INTEGER, 1/0, 0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-133180449*/count=677; tryItOut("g1.a0[15] = (({eval: x}));");
/*fuzzSeed-133180449*/count=678; tryItOut("\"use strict\"; var x = (new ((++x))(x,  '' )), tyhhyi, inhccq, eval = /*MARR*/[new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1)].sort, x = (true) = z.__defineGetter__(\"z\", (let (e=eval) e)), [] = x, vyqtcy, c, b, rieeeo;/*RXUB*/var r = /(?=(?:(\\2))+|(?:.)(?:(\\2|\\b{2,4}))[^](.?|([^])*))/gym; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=679; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.max(Math.hypot(Math.fround(Math.imul(Math.fround(((-(2**53+2) | 0) != (x ? y : y))), -Number.MAX_SAFE_INTEGER)), ((Math.atan2((( + Math.hypot(((Math.acos((-0 | 0)) | 0) | 0), (x | 0))) | 0), (( + x) | 0)) | 0) | 0)), (Math.pow(mathy0(( + ( + ( + 0))), Math.log(Math.fround(((-(2**53) >>> 0) > (Math.fround((0x080000001 ? y : 1.7976931348623157e308)) >>> 0))))), ( ! ( + Math.tan((Math.trunc(Math.fround(( ~ Math.fround(-Number.MIN_VALUE)))) | 0))))) | 0)); }); ");
/*fuzzSeed-133180449*/count=680; tryItOut("\"use strict\"; for(var x = undefined in ({}) - Math.ceil( /x/g ) - (yield e)) a2[Math.tan(x)] = ((Uint16Array)( /x/g ));");
/*fuzzSeed-133180449*/count=681; tryItOut("{ void 0; try { startgc(26432); } catch(e) { } }");
/*fuzzSeed-133180449*/count=682; tryItOut("/*RXUB*/var r = /(([^])*+|(?!\\D*?)**\\1)+?[^]{1,}/gim; var s = \"\\n\\n\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-133180449*/count=683; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, 0/0, -(2**53-2), 0x0ffffffff, -0x080000000, -0x07fffffff, -Number.MAX_VALUE, 0x080000001, Math.PI, -0x0ffffffff, 0x080000000, 2**53-2, -0x100000001, 0x100000001, 2**53+2, -1/0, -(2**53), Number.MAX_VALUE, 42, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, 2**53, 0.000000000000001, 1, 0x100000000, 1/0]); ");
/*fuzzSeed-133180449*/count=684; tryItOut("Object.freeze(t1);");
/*fuzzSeed-133180449*/count=685; tryItOut("/*infloop*/M:for(b = ( /x/g .x = x); /*FARR*/[y.watch(10, (1 for (x in []))), x,  '' , ...(Math.sqrt(-22) for (y of new (x)(((void version(180))).unwatch(\"call\"), x & d)) if (\"\\u4DA2\"))].map; new RegExp(\"(?:[^\\u86aa\\\\u458A\\\\s]\\\\1)|(\\\\b).*(?!\\u969f)(?!\\\\d)(?=\\u2675){4194304}+?(?=.|\\\\w*?)(?![^])\", \"im\")) /*bLoop*/for (qpmdrr = 0, w = intern(z), x = (void version(170)); qpmdrr < 19; ++qpmdrr) { if (qpmdrr % 4 == 3) { h0 = g0.objectEmulatingUndefined(); } else { /*infloop*/ for (b of \"\\uFBBE\") {for (var p in t2) { try { v1 = g2.runOffThreadScript(); } catch(e0) { } try { g2.s0 += 'x'; } catch(e1) { } try { e2.delete(s2); } catch(e2) { } m2.set(a2, a0); }a2.splice(-4, v1); } }  } ");
/*fuzzSeed-133180449*/count=686; tryItOut("g1.offThreadCompileScript(\"function f0(g1)  { yield g1 } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 5 != 0), sourceIsLazy: true, catchTermination: x >>=  /x/g  }));");
/*fuzzSeed-133180449*/count=687; tryItOut("x, w = (yield (let (c) [1,,])), blrjqp, e;m1.delete(m1);");
/*fuzzSeed-133180449*/count=688; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x07fffffff, 2**53-2, 0x080000001, -1/0, 0x100000000, -Number.MIN_VALUE, -(2**53-2), -(2**53+2), -0x100000001, -Number.MAX_VALUE, 0x080000000, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, 1/0, 0x100000001, 1, -0x100000000, 2**53+2, 0, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, -0, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, 2**53, 0x07fffffff, 0/0, Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=689; tryItOut("Array.prototype.unshift.call(a2, e0, e2);function x() { a2[19]; } ;");
/*fuzzSeed-133180449*/count=690; tryItOut("/*RXUB*/var r = r1; var s = \"\\u00a7\"; print(s.split(r)); ");
/*fuzzSeed-133180449*/count=691; tryItOut("mathy5 = (function(x, y) { return ( + ( + (Math.max(Math.fround((Math.fround(-0x100000001) % Math.fround(y))), Math.log((y | 0))) ? (x / (x % Number.MIN_VALUE)) : Math.sign(Math.fround(x))))); }); testMathyFunction(mathy5, [/0/, 1, objectEmulatingUndefined(), ({toString:function(){return '0';}}), [0], null, '0', ({valueOf:function(){return 0;}}), 0.1, ({valueOf:function(){return '0';}}), (new String('')), [], (new Boolean(false)), (new Number(-0)), true, 0, NaN, (new Number(0)), '\\0', -0, '', (new Boolean(true)), (function(){return 0;}), false, '/0/', undefined]); ");
/*fuzzSeed-133180449*/count=692; tryItOut("{a2[5] = f1; }");
/*fuzzSeed-133180449*/count=693; tryItOut("const b2 = new SharedArrayBuffer(44);");
/*fuzzSeed-133180449*/count=694; tryItOut("mathy3 = (function(x, y) { return Math.max(Math.max(( ~ ( + ( ~ x))), mathy2(x, ((((Math.tanh(y) | 0) | 0) ** (0x100000001 | 0)) | 0))), Math.max(Math.atan2(( + ( + Math.hypot((Math.cos(-0x100000001) | 0), ( + y)))), y), (( ~ (Math.acosh(Math.sign((y !== y))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[x, ['z'],  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , ['z'], ['z'], ['z'], ['z'], x, x, ['z'], ['z'], x,  /x/ , ['z'], x, ['z'], ['z'], ['z'],  /x/ ,  /x/ , x, ['z'], ['z'],  /x/ ,  /x/ , x,  /x/ , x,  /x/ ,  /x/ , ['z'], ['z'], ['z'], ['z'], ['z'],  /x/ , ['z'],  /x/ , x, ['z'], ['z'], ['z'],  /x/ ]); ");
/*fuzzSeed-133180449*/count=695; tryItOut("\"use strict\"; v1 = Infinity;");
/*fuzzSeed-133180449*/count=696; tryItOut("/*RXUB*/var r = r1; var s = \"\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u00a5\\n\\na0\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u081e\\ud2bc\\n\\n\\n\\u00a5\\n\\na0\\u0091\\na\"; print(s.match(r)); ");
/*fuzzSeed-133180449*/count=697; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.cos((((((( + mathy2(( + Math.asinh(x)), ( + 1.7976931348623157e308))) >>> 0) < (x >>> 0)) >>> 0) != ( + ( - ( + ( ! 0/0))))) | 0))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0x100000001, 1, 2**53+2, -0x100000000, 2**53-2, 0x080000000, -1/0, -0x080000000, 0x07fffffff, Number.MIN_VALUE, -(2**53), -0, Math.PI, 2**53, 0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, 42, 0x100000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2), 1.7976931348623157e308, -0x100000001, 0, Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 1/0, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-133180449*/count=698; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 3.094850098213451e+26;\n    var i4 = 0;\n    var i5 = 0;\n    i0 = ((0xffffffff) < (0xa2d9e31f));\n    {\n      (Uint16ArrayView[4096]) = (((~~(((+(((0x8c1d9fea) / (0xb3be06a8))>>>((i1))))) - ((1.0009765625)))))+(i0)+(i0));\n    }\n    d3 = (-1.9342813113834067e+25);\n    i1 = ((((Uint16ArrayView[(0x1c87f*(((0xfe92c134) ? (-2305843009213694000.0) : (-274877906945.0)) >= (1.0078125))) >> 1]))>>>((/*FFI*/ff(((0x475e798)), ((((i4)) & ((0xaf4cebdd)+(0x27a163f3)))), ((0x779a5dac)))|0)-((0xcd2d1b05)))) > (((i1)+(i1)-(i4))>>>((i1))));\n    {\n      i2 = (i0);\n    }\n    return +((1.0009765625));\n  }\n  return f; })(this, {ff: function(y) { \"use strict\"; {} }}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x080000001, Number.MAX_VALUE, 0x100000001, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, 2**53-2, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 1, -Number.MAX_VALUE, 0x07fffffff, -0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, 0x080000000, -0x0ffffffff, 0, -0x080000000, -(2**53-2), -0x100000001, 2**53+2, 1.7976931348623157e308, 0x080000001, -(2**53), 2**53, -1/0]); ");
/*fuzzSeed-133180449*/count=699; tryItOut("mathy1 = (function(x, y) { return (Math.fround((Math.fround(Math.min((Math.max((y | 0), (( + ( + x)) >>> 0)) | 0), x)) != (((( + Math.log(( ! y))) >>> 0) != (Math.asinh(x) >>> 0)) >>> 0))) + ( - (Math.atan2(Math.fround(Math.imul(Math.min((Math.sqrt((x >>> 0)) >>> 0), y), Math.fround(Math.hypot(y, ( + y))))), mathy0(( - y), ( + Math.cbrt((-0x100000000 | 0))))) - Math.fround(( ! Math.acos(Math.fround(y))))))); }); testMathyFunction(mathy1, [42, -Number.MIN_SAFE_INTEGER, -1/0, 1/0, 0.000000000000001, -(2**53), -0x100000000, -0, 0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, 0/0, -0x07fffffff, -Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 2**53+2, 1, -(2**53-2), 2**53-2, -Number.MIN_VALUE, Math.PI, -0x080000000, 0x100000000, Number.MIN_VALUE, 0x100000001, 2**53, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=700; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=701; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + (( + Math.fround(Math.min(mathy2(( + Math.max(( + x), ( + x))), (( + y) % ( + ( ! 1.7976931348623157e308)))), Math.fround(( + (( + Math.acos(x)) <= (( ! (y >>> 0)) >>> 0))))))) << Math.fround(mathy0(Math.fround((((( ~ y) | 0) ^ (Math.asinh(y) | 0)) | 0)), Math.fround(Math.tanh(( ~ Math.acos((Math.imul(x, -(2**53-2)) ? 0 : y))))))))); }); testMathyFunction(mathy4, [/0/, (new Number(0)), -0, [], '0', 0, NaN, null, 1, '\\0', '/0/', (new Boolean(true)), (function(){return 0;}), (new Boolean(false)), 0.1, (new Number(-0)), ({toString:function(){return '0';}}), undefined, ({valueOf:function(){return '0';}}), (new String('')), true, ({valueOf:function(){return 0;}}), [0], objectEmulatingUndefined(), '', false]); ");
/*fuzzSeed-133180449*/count=702; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + (( + Math.fround(( ~ Math.fround(mathy0(x, (Math.ceil((y >>> 0)) >>> 0)))))) == (Math.fround(Math.fround(Math.atan2(Math.imul(x, Math.pow(y, 0/0)), Math.fround((( + ( + ((( + x) | x) >= ( + 0x100000001)))) ^ ( + ( ! x))))))) - Math.fround(mathy0(( + Math.log2(-Number.MIN_VALUE)), y))))) + Math.max((Math.sinh(( + x)) | 0), mathy0((Math.fround(mathy0(y, ( + -0x080000000))) ? Math.fround(0) : Math.fround(Math.pow(( + Math.atan(( + x))), -0x07fffffff))), (( ! (( + Math.tanh(( + ((x | 0) << ( + -(2**53-2)))))) >>> 0)) | 0)))); }); testMathyFunction(mathy1, [(new Number(0)), objectEmulatingUndefined(), NaN, false, 0, ({toString:function(){return '0';}}), 0.1, 1, (new Boolean(true)), null, '0', '\\0', [0], (new Number(-0)), [], '', /0/, ({valueOf:function(){return '0';}}), undefined, (new String('')), ({valueOf:function(){return 0;}}), (function(){return 0;}), (new Boolean(false)), '/0/', -0, true]); ");
/*fuzzSeed-133180449*/count=703; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.round(((( - (x >>> 0)) >>> 0) ? Math.atan2(Math.fround(mathy0(( + 1), (Math.expm1(Math.fround(Math.ceil(Math.fround(y)))) >>> 0))), Math.pow(( + x), Math.fround(x))) : ( + ( + Math.max(( + ((x >>> 0) + (( ~ x) | 0))), ( + mathy0(Math.fround(( + Math.log(( + y)))), Math.atan(x)))))))) | 0); }); testMathyFunction(mathy3, [2**53-2, 0x0ffffffff, 42, 2**53, 1, -1/0, -0x100000000, 0x100000000, -0x080000000, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, -0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, 1/0, -0x100000001, 0x080000001, 0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), -0, 0x07fffffff, -0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=704; tryItOut("mathy5 = (function(x, y) { return (( ! (Math.sign(( + mathy0(Math.fround(y), Math.fround((-(2**53) >>> y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [[], (new Number(-0)), 0.1, '/0/', NaN, ({valueOf:function(){return 0;}}), [0], '', (new String('')), 0, undefined, false, null, (function(){return 0;}), ({toString:function(){return '0';}}), -0, (new Number(0)), '\\0', (new Boolean(true)), 1, /0/, (new Boolean(false)), '0', ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), true]); ");
/*fuzzSeed-133180449*/count=705; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.atan2(((((x , ( ~ x)) != (y | 0)) < ( + ((Math.sqrt((x >> ( + y))) | 0) ? ( + Math.atan(Math.imul(( + mathy0(( + y), ( + (((x | 0) , (-0x0ffffffff | 0)) | 0)))), y))) : ( + Math.min(Math.expm1(Math.fround(( ! x))), (( ~ ( + x)) >>> 0)))))) | 0), (( + Math.abs(( + Math.clz32((( + mathy0(x, ( + Math.imul(( + y), ( + Math.atan2(Math.fround(y), -0x080000000)))))) === (Math.sin((y >>> 0)) >>> 0)))))) | 0)) | 0); }); testMathyFunction(mathy2, [(new Boolean(false)), [], '0', '/0/', 0.1, ({toString:function(){return '0';}}), -0, undefined, NaN, '\\0', (function(){return 0;}), [0], (new Number(0)), null, false, (new String('')), (new Number(-0)), 0, ({valueOf:function(){return 0;}}), '', true, (new Boolean(true)), objectEmulatingUndefined(), /0/, ({valueOf:function(){return '0';}}), 1]); ");
/*fuzzSeed-133180449*/count=706; tryItOut("i1.send(v1);");
/*fuzzSeed-133180449*/count=707; tryItOut("let (bixcuw, x = -11) { i1.__proto__ = p0;function function shapeyConstructor(cqjkrz){this[\"toLocaleLowerCase\"] = NaN;for (var ytqbmvznp in this) { }this[\"toLocaleLowerCase\"] = (({cqjkrz: window}));return this; }()function(){}((makeFinalizeObserver('nursery'))); }");
/*fuzzSeed-133180449*/count=708; tryItOut("");
/*fuzzSeed-133180449*/count=709; tryItOut("this.a2 = r2.exec(s2);");
/*fuzzSeed-133180449*/count=710; tryItOut("Array.prototype.sort.apply(a1, [(function() { try { /*RXUB*/var r = r1; var s = s0; print(s.split(r));  } catch(e0) { } a2 = g2.o2.r1.exec(s0); return this.b2; }), i2, v2, v2]);");
/*fuzzSeed-133180449*/count=711; tryItOut("\"use strict\"; print(x);\nvar sgfvkb = new ArrayBuffer(24); var sgfvkb_0 = new Uint8Array(sgfvkb); sgfvkb_0[0] = -Number.MIN_SAFE_INTEGER; print((+ /x/ ));print(((makeFinalizeObserver('tenured'))));\n");
/*fuzzSeed-133180449*/count=712; tryItOut("a0 = Array.prototype.map.call(o1.a1, (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d0);\n    {\n      {\n        {\n          (Int8ArrayView[((0xffffffff)) >> 0]) = ((imul((!(-0x8000000)), ((((/*FFI*/ff(((3.8685626227668134e+25)), ((33554431.0)))|0)*0xfffff)>>>((0xc869806b)-(0xffb8bad6)-(0xfbfb5dfe))) == (0x683284f4)))|0) % ((((((0xe7a3e909)-(0x619afa0)-(0x2b0b7ffd))>>>(((72057594037927940.0) < (-4611686018427388000.0))+(0xfd5f414e))))*-0x37210) << (0x5aad4*(-0x8000000))));\n        }\n      }\n    }\n    d1 = ((w = this.__defineSetter__(\"y\", (x) => \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      return (((i1)-(i0)))|0;\n    }\n    return (((((((((0x9adb0a4f)+(0xfe172fd7)) << ((0xffffffff)-(0xeea74d4d)-(-0x8000000))) == ((((67108864.0) < (147573952589676410000.0))) & ((0xfe220117)-(0x377a0634))))+(i1))>>>((i0)*0xfb324)) != ((let (e=eval) e)))))|0;\n  }\n  return f;)) + (d1));\n    d1 = (d0);\n    return +((d1));\n    d0 = (d0);\n    d0 = (+/*FFI*/ff());\n    d1 = (d1);\n    {\n      {\n        {\n          {\n            d0 = (d0);\n          }\n        }\n      }\n    }\n    {\n      {\n        d1 = (+(((!(((((0xe263dcf6) != (0xa01f238d))+(0x9ec95e6f))|0) <= (((0xfa843f18)) >> ((0xffffffff)-(0xfbf43d3a)))))) & ((!((+(0.0/0.0)) <= (d1)))-(((Float64ArrayView[1])) >= (((0xffffffff)+(-0x8000000)-(0xc8fab75b))>>>((x)*-0x6424d))))));\n      }\n    }\n    d1 = (d1);\n    d0 = (d1);\n    d0 = (d0);\nprint((4277));    {\n      {\n        d1 = (d1);\n      }\n    }\n    d1 = (d0);\n    d0 = (d0);\n    d0 = (+(-1.0/0.0));\n    d1 = (d0);\n    d1 = (d0);\n    d1 = (d0);\n    d1 = (d1);\n    return +((d0));\n    (Math.ceil(20).__defineSetter__(\"NaN\", eval)) = ((d1));\n    return +(((d1) + (+abs(((+atan2(((+(((!(0xcbf7ee9a)))>>>(((-65535.0) < (-36893488147419103000.0))*0x5acbb)))), ((Float32ArrayView[2])))))))));\n  }\n  return f; })(this, {ff: ({b: x})}, new SharedArrayBuffer(4096)), i1, p0, f0);");
/*fuzzSeed-133180449*/count=713; tryItOut("\"use strict\"; v1 + '';g1.f1(v1);");
/*fuzzSeed-133180449*/count=714; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.tanh((( ~ (Math.imul(Math.hypot(Number.MAX_SAFE_INTEGER, (-0x100000001 ? y : Math.fround(( - -0x100000000)))), Math.log((( + x) || ( + x)))) | 0)) != ((( - (x >>> 0)) >>> 0) % y))) | 0); }); testMathyFunction(mathy0, [({valueOf:function(){return 0;}}), (new Boolean(false)), 1, (function(){return 0;}), false, '/0/', null, (new Number(0)), '', (new String('')), objectEmulatingUndefined(), -0, true, [0], 0.1, NaN, (new Number(-0)), /0/, [], '\\0', '0', (new Boolean(true)), 0, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), undefined]); ");
/*fuzzSeed-133180449*/count=715; tryItOut("\"use strict\"; L:for([y, w] = ((x) =  /* Comment */window) in (this.__defineSetter__(\"x\", (mathy4).bind)).yoyo((intern(-2)))) {f1(f2);e2.delete(e2); }");
/*fuzzSeed-133180449*/count=716; tryItOut("\"use strict\"; e1.delete(g1.g2);");
/*fuzzSeed-133180449*/count=717; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4(Math.abs(Math.fround(Math.min((x >>> 0), ( + Math.trunc(( + ((Math.PI ^ x) >>> 0))))))), ( ! (mathy3(( + ( ~ ( + Number.MIN_VALUE))), Math.log(Math.log10(-(2**53)))) >> Math.fround(( ! Math.fround(Math.pow(( + Math.abs(( + y))), Math.fround(x)))))))); }); testMathyFunction(mathy5, ['/0/', [0], (new Boolean(true)), [], NaN, (new Number(0)), 1, objectEmulatingUndefined(), '\\0', ({valueOf:function(){return 0;}}), (new Boolean(false)), 0.1, ({toString:function(){return '0';}}), (new Number(-0)), 0, (new String('')), undefined, '0', ({valueOf:function(){return '0';}}), false, null, -0, (function(){return 0;}), true, /0/, '']); ");
/*fuzzSeed-133180449*/count=718; tryItOut("mathy4 = (function(x, y) { return Math.pow(((Math.acos(( - (Math.hypot((( ! y) | 0), ((y , (((x >>> 0) > Math.fround(0/0)) >>> 0)) | 0)) | 0))) >>> 0) >= ((( ~ (( + (Math.fround(Math.atan2(Math.fround(x), Math.expm1((( ~ y) | 0)))) | 0)) | 0)) | 0) >>> 0)), mathy0(Math.asin(( - x)), (( + Math.min(( + x), Math.fround(( + Math.max(Math.fround(( ~ x)), 0x100000001))))) * ( + (y ? x : Math.pow(Math.fround((((0x07fffffff >>> 0) % x) >>> 0)), x)))))); }); testMathyFunction(mathy4, [0x100000001, 1/0, -1/0, -0x07fffffff, -Number.MAX_VALUE, 0x080000001, 0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53+2), 0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, -0x100000000, -0x080000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, -0x100000001, Number.MIN_VALUE, 0.000000000000001, -0, 2**53+2, Number.MIN_SAFE_INTEGER, Math.PI, 2**53, -Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, 0/0, 1]); ");
/*fuzzSeed-133180449*/count=719; tryItOut("\"use strict\"; f1 + '';");
/*fuzzSeed-133180449*/count=720; tryItOut("print(/*MARR*/[(1/0), (1/0), (void 0), ({}), ({}), ({}), (void 0), (1/0), (void 0), (void 0), (1/0), ({}), ({}), (1/0), ({}), (void 0), (1/0), ({}), (1/0), (void 0), (void 0), (1/0), ({}), (1/0), (1/0), ({}), (1/0), (void 0), (void 0), ({}), (void 0), (1/0), ({}), (1/0), ({}), ({}), (1/0), (void 0), ({}), (void 0), (void 0), (1/0), (1/0), ({}), ({}), ({}), (1/0), (1/0), (1/0), ({}), (1/0), (void 0), (1/0), (1/0), (1/0), (void 0)].map);");
/*fuzzSeed-133180449*/count=721; tryItOut("mathy1 = (function(x, y) { return ((( + ((mathy0((x | 0), (y | 0)) | 0) > y)) | 0) ? (Math.abs(((Math.ceil((Math.ceil(-0) >>> 0)) >>> 0) >>> 0)) >>> 0) : mathy0(Math.max(Math.atan(y), Math.hypot(((mathy0(y, 2**53-2) <= Math.atan2(y, y)) >>> 0), ( + Math.asin(( + y))))), (( + x) >>> 0))); }); ");
/*fuzzSeed-133180449*/count=722; tryItOut("/*infloop*/M:do this.h1.__iterator__ = (function() { for (var v of i2) { try { this.a2 = a1.map((function() { try { for (var p in g0.t0) { try { s2 = t0[13]; } catch(e0) { } try { t1 = new Float32Array(({valueOf: function() { h2.toSource = (function() { try { t0 = new Int16Array(o2.t1); } catch(e0) { } try { ; } catch(e1) { } this.a1[function ([y]) { }] = m2; return i1; });return 11; }})); } catch(e1) { } try { selectforgc(o2); } catch(e2) { } for (var p in this.a1) { delete v0[\"__iterator__\"]; } } } catch(e0) { } try { v0 = evaluate(\"function f0(g2)  { yield  ''  } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: this, noScriptRval: new RegExp(\"((?:[^]|[^4-\\u009a\\\\W]\\\\d{2,5}[^]{0,3}){3})\", \"yi\"), sourceIsLazy: true, catchTermination: (x % 16 != 12) })); } catch(e1) { } for (var p in t0) { try { o2.o0.valueOf = (function(j) { if (j) { try { e1.add(\"\\uDAE4\"); } catch(e0) { } try { t2[v1] = 10; } catch(e1) { } a0 = Array.prototype.filter.call(g2.a0, (function() { for (var j=0;j<0;++j) { this.f1(j%5==1); } })); } else { try { t2.set(a1, 17); } catch(e0) { } try { m0 = new WeakMap; } catch(e1) { } try { i1 + ''; } catch(e2) { } e2.add(h1); } }); } catch(e0) { } try { e0.delete(g1); } catch(e1) { } try { f1 = Proxy.createFunction(h0, f0, f1); } catch(e2) { } g1.v1 = Array.prototype.reduce, reduceRight.apply(a0, [(function(j) { f1(j); })]); } return o0.o1; })); } catch(e0) { } try { for (var p in a0) { try { this.a0.push(o2.a2, t1); } catch(e0) { } o0.m0.set(/\\cJ[^]?(\\B)*?|(?=(?=\\B{4}|((\\d))).$)/i, g1.b1); } } catch(e1) { } for (var p in s2) { try { e1 = new Set(this.b0); } catch(e0) { } ; } } return a1; }); while(((makeFinalizeObserver('nursery'))));");
/*fuzzSeed-133180449*/count=723; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 4503599627370497.0;\n    return (((/*FFI*/ff(((+(1.0/0.0))))|0)-(/*FFI*/ff(((((0x17dcf5be)*-0xa87f2)|0)), ((((0xb5d2dcb4)-((0x86d62872)))|0)), ((~~(d0))), ((-1099511627777.0)), ((+((Float64ArrayView[((-0x8000000)-(0x3568f9af)) >> 3])))), ((((0xe520a532)+(i1)))), ((imul((0xdca07483), (0x9234cc83))|0)), ((d2)), ((1073741825.0)), ((-1.0078125)), ((36028797018963970.0)), ((-3.8685626227668134e+25)), ((-4097.0)), ((-1.0625)), ((4398046511105.0)), ((-129.0)), ((1025.0)), ((-1.2089258196146292e+24)), ((3.094850098213451e+26)), ((4.0)), ((-35184372088833.0)), ((1.888946593147858e+22)), ((-1.0625)))|0)))|0;\n  }\n  return f; })(this, {ff: Float64Array}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0x100000001, 0, 1.7976931348623157e308, -0x07fffffff, -(2**53+2), -0, -0x080000001, Number.MAX_VALUE, 1, 0x080000000, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 1/0, -0x0ffffffff, Number.MIN_VALUE, -0x080000000, -0x100000000, Math.PI, 0.000000000000001, 2**53, 0x080000001, -Number.MAX_VALUE, -1/0, 0x0ffffffff, -(2**53-2), 0/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=724; tryItOut(";");
/*fuzzSeed-133180449*/count=725; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var log = stdlib.Math.log;\n  var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = (i0);\n    /*FFI*/ff((x), ((d1)), ((~~(1.25))), ((+log(((-140737488355328.0))))), ((~((0x1e88965c)+(i2)))), ((+/*FFI*/ff(((((0x9cf341b1)) >> ((0xadb50e4f)))), ((65537.0)), ((-9.671406556917033e+24)), ((-3.8685626227668134e+25))))), ((((1.125)) - ((7.555786372591432e+22)))), ((-17.0)), ((-4503599627370497.0)), ((-3.022314549036573e+23)));\n    (Float32ArrayView[((i2)*-0xf6d51) >> 2]) = ((d1));\n    return ((((-68719476737.0) >= (8388609.0))-((+/*FFI*/ff(((1.5474250491067253e+26)), ((d1)))) >= (+/*FFI*/ff()))))|0;\n    {\n      d1 = (d1);\n    }\n    switch ((~~(((((0xa61e0a8f)))|0)))) {\n      case 0:\n        return (((((+pow(((+/*FFI*/ff(((((0xa0c64238)) << ((0xffcc400b)))), ((-1048577.0)), ((-65537.0)), ((-2.0)), ((-131073.0)), ((-8796093022209.0)), ((-1.03125)), ((1.888946593147858e+22)), ((274877906945.0)), ((-9007199254740992.0))))), ((-3.022314549036573e+23)))) < (1.2089258196146292e+24)) ? (!(i0)) : ((0x6ea8bbb3) == (((i0)+((0xca1ed743)))>>>(((0x84c9d834) == (((0xfc98e507))>>>((0x17c1609b))))))))))|0;\n        break;\n      case -1:\n        {\n          d1 = (((-2049.0)) * ((+abs((((5.0) + (+(0.0/0.0))))))));\n        }\n      default:\n        i0 = (i2);\n    }\n    i0 = (/*FFI*/ff(((+(-1.0/0.0))))|0);\n    d1 = (d1);\n    return ((0xd85fe*(i2)))|0;\n  }\n  return f; })(this, {ff: (new Function(\"((yield -23));\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[{},  /x/ ,  \"\" , 1e81,  \"\" ,  /x/ ,  \"\" ,  /x/ ,  \"\" ,  \"\" ,  /x/ , {},  /x/ , 1e81,  /x/ , {}, {}, 1e81,  \"\" , 1e81,  /x/ ,  /x/ ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 1e81,  \"\" , {},  \"\" ,  \"\" ,  \"\" ,  \"\" , 1e81,  \"\" , {},  /x/ ,  /x/ , {}, {}, 1e81, 1e81, 1e81,  \"\" ,  /x/ , {}, {},  \"\" , 1e81, 1e81, {}, 1e81,  /x/ , 1e81,  /x/ , 1e81, {},  /x/ , 1e81,  \"\" , {},  /x/ ,  \"\" , {},  \"\" ,  \"\" ,  \"\" , 1e81,  \"\" , 1e81, 1e81,  \"\" ,  /x/ , {},  \"\" ,  \"\" ,  \"\" , {}, {},  \"\" , {}, 1e81,  /x/ ,  /x/ , {}, 1e81, {},  \"\" ,  /x/ ,  \"\" , 1e81]); ");
/*fuzzSeed-133180449*/count=726; tryItOut("window, [] =  /x/ , x, jdfwsb, x, udnfrv;print((4277));");
/*fuzzSeed-133180449*/count=727; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( - (( + Math.clz32(Math.fround((Math.tan(0x07fffffff) ^ (((-0x100000000 | 0) ? ((Math.atanh(x) < Math.fround(( ! Math.fround(y)))) | 0) : (( - (x | 0)) | 0)) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy2, [-0x080000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -0x07fffffff, -0x080000000, 1/0, -Number.MIN_VALUE, 0x07fffffff, 2**53-2, 0x080000001, 1, -0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -(2**53-2), -(2**53), 0/0, Math.PI, 0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, 42, -0x100000001, -(2**53+2), 0x0ffffffff, 1.7976931348623157e308, -0x100000000, 0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=728; tryItOut("a0 = /(?=\\b\\ud60F*?)/m;");
/*fuzzSeed-133180449*/count=729; tryItOut("m1.has(a1);function w(x, x) { return /(?:((?!\\B)|\\3))/m; } i0.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { var r0 = 3 | a10; var r1 = r0 & a8; var r2 = 3 * a3; a11 = a4 - a3; var r3 = a0 / a5; var r4 = r2 % 9; var r5 = a4 - 1; a7 = a11 % x; var r6 = r0 / a9; var r7 = 8 - a2; r3 = a4 - r7; var r8 = a7 / a10; var r9 = a11 * a11; return x; });");
/*fuzzSeed-133180449*/count=730; tryItOut("while((/*FARR*/[window%=\"\\uD9CC\", ].sort) && 0)Array.prototype.forEach.call(a1, (function() { for (var j=0;j<48;++j) { f2(j%2==1); } }), (new (/*FARR*/[, , ].filter(false, x))(x, new RegExp(\"(?:\\\\x37)\", \"\"))) % delete eval.({}) -= \"\\u5C11\" ^ new RegExp(\"\\\\2\", \"\"));");
/*fuzzSeed-133180449*/count=731; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + ( ! ( + (( ~ ( + Math.sign(( - x)))) ? Math.min(( + Math.atan2(Math.fround(Math.min(Math.fround(1/0), Math.fround(( + Math.cos(( + (y > x))))))), -1/0)), Math.tanh(Math.pow(y, -(2**53+2)))) : ( + ( + (( ! ( + (Math.cos(y) >>> 0))) | 0))))))); }); testMathyFunction(mathy5, [0x0ffffffff, 0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 42, 0/0, -0x0ffffffff, -0x07fffffff, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, 2**53-2, 0x080000000, -0x100000000, -0x080000001, -0x080000000, 0.000000000000001, Math.PI, -(2**53+2), -Number.MAX_VALUE, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 1, 2**53, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -1/0, 1/0, -0x100000001, 2**53+2, -Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=732; tryItOut("mathy2 = (function(x, y) { return (Math.fround(Math.imul(Math.fround(Math.cbrt(0x07fffffff)), Math.fround((-0x100000000 - x)))) ^ ( ! Math.hypot(Math.asinh(Math.fround(-(2**53))), (x ? (( - Math.fround((Math.abs((-0x07fffffff | 0)) | 0))) >>> 0) : (( + Math.atan2((y >>> 0), Math.fround(0x0ffffffff))) >>> 0x080000000))))); }); testMathyFunction(mathy2, [-0, 0.000000000000001, -0x0ffffffff, 0x100000000, 42, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000000, 2**53, 0x0ffffffff, 0x07fffffff, -(2**53), 0x080000000, -0x100000001, 0, Number.MIN_VALUE, -(2**53+2), -0x080000001, -0x07fffffff, Number.MAX_VALUE, 1/0, 0/0, 1, Number.MIN_SAFE_INTEGER, 0x080000001, -1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, 2**53+2, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=733; tryItOut("print(e0);\nlet (d = undefined) true;\n");
/*fuzzSeed-133180449*/count=734; tryItOut("mathy5 = (function(x, y) { return ( + Math.cbrt(Math.tanh(((Math.log2(Math.fround(x)) >> ( + (Math.imul((mathy1(x, Math.fround(y)) | 0), ( - x)) | 0))) >>> 0)))); }); testMathyFunction(mathy5, [Math.PI, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_VALUE, 1, -0x080000000, 1/0, -0x0ffffffff, -(2**53-2), -0x080000001, 2**53, 0.000000000000001, -0, -(2**53), 0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, -0x100000001, -1/0, 42, -Number.MAX_VALUE, 0x100000001, 2**53+2, Number.MAX_VALUE, 0/0, 0, -(2**53+2), 0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-133180449*/count=735; tryItOut("e0.has(this.t2);");
/*fuzzSeed-133180449*/count=736; tryItOut("mathy0 = (function(x, y) { return ( - ( ! Math.atan2(( + Math.abs((y > 0.000000000000001))), ( + Math.max(0x07fffffff, Math.hypot(y, Math.fround(Math.clz32(y)))))))); }); ");
/*fuzzSeed-133180449*/count=737; tryItOut("/*oLoop*/for (var xkgqar = 0; xkgqar < 12; ++xkgqar) { e1.delete(i0); } \nv2 = Object.prototype.isPrototypeOf.call(a1, this.p2);\n");
/*fuzzSeed-133180449*/count=738; tryItOut("\"use strict\"; v1 = evaluate(\"mathy5 = (function(x, y) { \\\"use strict\\\"; return (((Math.fround(((x | 0) ^ ((Math.cos(x) && x) | 0))) ? (((((Math.fround(x) != (Math.fround(( ! (1 | 0))) >>> 0)) | 0) == (((y ? Math.atan2(( + Math.atan(( + ( + (x == ( + y)))))), Math.log10(y)) : y) | 0) >>> 0)) | 0) >>> 0) : (( ~ ((( + Math.sin((-0x07fffffff | 0))) !== Math.log2(Math.sin(x))) | 0)) >>> 0)) >>> 0) > ( ! Math.log10((( + ( + y)) - Math.fround(Math.PI))))); }); testMathyFunction(mathy5, [1/0, 0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2, -0x100000000, 0x080000001, 0, -Number.MIN_VALUE, 0x080000000, -0x100000001, -1/0, -(2**53), -0x080000000, -(2**53-2), 1.7976931348623157e308, Math.PI, -Number.MAX_SAFE_INTEGER, 0x100000001, 42, Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, 2**53, 1, -0x080000001, Number.MIN_VALUE, 0x07fffffff, -(2**53+2), -0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE]); \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 3), noScriptRval: (new RegExp(\"(?=(\\\\b)+)+?\", \"gy\")\n\n.yoyo(/*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x].sort(decodeURIComponent))), sourceIsLazy: x, catchTermination: Math.hypot(new (window)((this.__defineGetter__(\"x\", 576460752303423500)), 0), -16) }));");
/*fuzzSeed-133180449*/count=739; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((Math.pow((1/0 >= y), ( - (((Math.fround(mathy0(Math.fround(Number.MAX_VALUE), Math.fround(y))) | 0) ** -0x0ffffffff) & y))) + ((( ! ((Math.log((Math.fround(((x | 0) ** (y | 0))) | 0)) >>> 0) >>> 0)) >>> 0) | 0)) ^ Math.fround(( ! ( + Math.fround(( + Math.fround((Math.atanh(x) ^ Math.hypot(( + Math.imul(y, x)), y))))))))); }); testMathyFunction(mathy1, [Math.PI, -0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, 1/0, 1.7976931348623157e308, -(2**53+2), -0x0ffffffff, -0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, 0, -0x100000000, 0x080000001, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, 0.000000000000001, 0/0, -0, 0x100000000, 1, Number.MIN_VALUE, -0x080000000, 0x0ffffffff, 0x07fffffff, -(2**53)]); ");
/*fuzzSeed-133180449*/count=740; tryItOut("var a, NaN, of = window, chuybr, this.\u3056 = (let (y =  /x/ )  \"\" );window;\nv1 = g0.runOffThreadScript();\n");
/*fuzzSeed-133180449*/count=741; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(i2, g1.o2);");
/*fuzzSeed-133180449*/count=742; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a2, ({valueOf: function() { break ;return 12; }}), ({configurable: true, enumerable: true}));function NaN(eval, ...x)\"\\u4EF5\";");
/*fuzzSeed-133180449*/count=743; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + ( - ( + Math.fround((Math.fround((( + (( + y) ** ( + (( - Math.max(x, (x | 0))) >= x)))) == Math.atan(( + ( + (( + Math.pow(y, -0x0ffffffff)) >= ( + ( + Math.expm1(x))))))))) >= ((Math.fround(Math.imul(Math.sinh(y), Math.fround(x))) <= Math.fround((Math.acosh((Math.acos(y) | 0)) ? (((y >>> 0) ? 1 : ( ~ y)) >>> 0) : Math.pow(y, y)))) >>> 0)))))); }); testMathyFunction(mathy0, [-0x07fffffff, 1, -(2**53-2), -0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53), -0, -0x080000001, 1/0, -1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, Math.PI, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, 0x0ffffffff, 2**53+2, 0, 0x100000001, -0x100000000, 0/0, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, 42, Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308]); ");
/*fuzzSeed-133180449*/count=744; tryItOut("for (var v of g1) { try { v2.__proto__ = o2.g0; } catch(e0) { } try { /*RXUB*/var r = this.g1.r0; var s = s0; print(s.search(r));  } catch(e1) { } a2 = Array.prototype.concat.apply(a1, [g1.a2, v0]); }");
/*fuzzSeed-133180449*/count=745; tryItOut("\"use strict\"; Object.preventExtensions(g1);");
/*fuzzSeed-133180449*/count=746; tryItOut("neuter(b0, \"change-data\");");
/*fuzzSeed-133180449*/count=747; tryItOut("\"use strict\"; v1.toSource = (function() { try { for (var v of o1.o0) { try { g0.v0 + ''; } catch(e0) { } try { i2.toSource = (function mcc_() { var ucqhad = 0; return function() { ++ucqhad; f2(/*ICCD*/ucqhad % 3 == 0);};})(); } catch(e1) { } g2.s0 = new String; } } catch(e0) { } try { for (var v of this.p2) { try { Array.prototype.forEach.apply(a0, [this.f0]); } catch(e0) { } try { a2[8] = o0; } catch(e1) { } v1 = (m0 instanceof a1); } } catch(e1) { } try { v2 = (g1.o1.e2 instanceof o1.g1.b2); } catch(e2) { } m0.get(t2); return g0; });");
/*fuzzSeed-133180449*/count=748; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.sign(Math.fround((Math.fround(( + (( + (Math.fround(( + ( - Math.fround(y)))) >= 1)) ^ ( + mathy1((0x0ffffffff | 0), Math.hypot(x, -0x0ffffffff)))))) ? Math.fround((Math.hypot(y, Math.fround(Math.pow(Math.fround(x), x))) ? Math.fround(Math.atan2(( + 0), Math.fround(Math.max((0 | 0), y)))) : ( + Math.imul(( + y), ( + x))))) : (((((mathy0(x, y) << Math.fround(x)) >>> 0) >>> 0) < Math.acos(( + Math.log(( + y))))) >>> 0)))); }); testMathyFunction(mathy3, [0, 0x080000000, 0x0ffffffff, 2**53+2, -0x07fffffff, 1.7976931348623157e308, 0/0, 1, -0x080000001, 0.000000000000001, 2**53-2, Number.MIN_VALUE, Number.MAX_VALUE, -(2**53+2), 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 42, -0, 2**53, -1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000001, 0x080000001, Math.PI, 0x07fffffff, -0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=749; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy2(Math.hypot(( ! y), ( + (mathy0((Math.fround((( + (( - (1 >>> 0)) >>> 0)) % (Number.MAX_SAFE_INTEGER | 0))) | 0), x) | 0))), Math.fround(Math.max(Math.fround(((Math.hypot(mathy3(((Math.fround(Math.sqrt(Math.fround(x))) != x) >>> 0), (x | 0)), -0x100000001) | 0) < -Number.MAX_SAFE_INTEGER)), ((( ! (( - x) >>> 0)) >>> 0) | 0)))); }); testMathyFunction(mathy4, [1, 2**53, -(2**53+2), 0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, Math.PI, 0, -(2**53), 42, Number.MIN_SAFE_INTEGER, -0, -0x100000001, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, 0x100000001, 2**53-2, -1/0, -0x080000000, -(2**53-2), 0x07fffffff, -0x080000001, 0x100000000, -Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-133180449*/count=750; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        i1 = (0x6e3d29e9);\n      }\n    }\n    i1 = ((((0xf9c39f14)-((0x0) >= (((0xfc615e23))>>>(this.\u000d__defineSetter__(\"b\", ReferenceError.prototype.toString))))) | (((((0x6f26d5d) % (0x3ddbe9f9)) >> ((Uint8ArrayView[0]))) > (~((i1)-((0x1af7ceef) == (0xb9374b66)))))-(0xffffffff))) > ((((0x240f5a02) ? (/*FFI*/ff(((0xfcb5fa4)), ((1.25)), ((-18446744073709552000.0)), ((16385.0)))|0) : ((0xc616ad72)))-(i1)) & ((i1))));\n    d0 = (+pow(((-72057594037927940.0)), ((((d0)) - ((+(1.0/0.0)))))));\n    return (((((Uint8ArrayView[0])) | (-0x8b109*((35184372088833.0) < ((void shapeOf(((function sum_indexing(zsxlpz, asligp) { ; return zsxlpz.length == asligp ? 0 : zsxlpz[asligp] + sum_indexing(zsxlpz, asligp + 1); })(/*MARR*/[true, true, true, new String(''), new String(''), new String(''), true, new String(''), new String(''), new String(''), true, true, true, new String(''), true, new String(''), new String(''), new String(''), true, new String(''), true, new String(''), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, new String(''), new String(''), new String(''), true, true, new String(''), new String(''), true], 0)))))))) / (((0xf97c397d))|0)))|0;\n  }\n  return f; })(this, {ff: w => \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var log = stdlib.Math.log;\n  var pow = stdlib.Math.pow;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 131073.0;\n    i1 = (i0);\n    switch ((((18)) ^ ((i0)))) {\n      default:\n        i2 = ((((i2)-((i0) ? (i1) : (0xf9971987))-(0x75ef53ec)) << (0xf9d6*(i2))));\n    }\n    {\n      {\n        (Float32ArrayView[4096]) = ((+(0.0/0.0)));\n      }\n    }\n    return (((0xe0bd6a9a)))|0;\n    (Float32ArrayView[1]) = ((Float64ArrayView[((~~(8796093022209.0)) % ((((0xffffffff) ? (0x1a06f66c) : (0xb162af54))-((-7.737125245533627e+25) > (-549755813887.0))) >> ((0xffffffff)-(i1)))) >> 3]));\n    i2 = (i2);\n    i1 = (0x1bd4163f);\n    {\n      i1 = ((+atan2(((-8589934593.0)), ((-9.671406556917033e+24)))) >= (((((i2))>>>((-0x8000000)-(0x8dadd7ec))) > (0x0)) ? (+abs(((+log(((-5.0))))))) : (((((d3)) * ((+pow(((2199023255552.0)), ((0.001953125))))))) - ((-35184372088833.0)))));\n    }\n    d3 = (+abs(((4.722366482869645e+21))));\n    return ((((~(((((i1))>>>((((-0x8000000))>>>((0xfd083803))) % (((-0x8000000))>>>((0x1716cbb6))))))+(\u0009d << /*MARR*/[ '\\0' ,  /x/ , objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  '\\0' ].filter(Set.prototype.clear, function(id) { return id }).valueOf(\"number\")))))-((-0x8000000))))|0;\n  }\n  return f;}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 2**53, -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, Math.PI, -(2**53+2), -0, 0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, 42, 0x100000001, Number.MIN_SAFE_INTEGER, 0, 1/0, 2**53+2, 1, -0x100000000, 0/0, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53-2, 0x0ffffffff, -0x0ffffffff, -(2**53-2), -1/0, -0x080000001, -0x080000000, -0x100000001]); ");
/*fuzzSeed-133180449*/count=751; tryItOut("function z(NaN) { return ({a2:z2}) } b1 + v2;let y = [,,z1];");
/*fuzzSeed-133180449*/count=752; tryItOut("/*bLoop*/for (var lhjkfd = 0; lhjkfd < 7; ++lhjkfd) { if (lhjkfd % 49 == 3) { let(y) ((function(){break ;})()); } else { h0 = Proxy.create(h0, t2); }  } v2 = t2.BYTES_PER_ELEMENT;");
/*fuzzSeed-133180449*/count=753; tryItOut("print(({BYTES_PER_ELEMENT: x, \"19\": false }));");
/*fuzzSeed-133180449*/count=754; tryItOut("\"use strict\"; m1.set(v0, \"\\u330F\");var w = this.__defineSetter__(\"\\u3056\", (neuter).call);");
/*fuzzSeed-133180449*/count=755; tryItOut("g0.v1 = (b1 instanceof o0);\nb2.toSource = (function(j) { if (j) { try { a0.sort(f1); } catch(e0) { } try { a2[/\\1/ym]; } catch(e1) { } p2 + v0; } else { try { let t2 = new Uint32Array(b0); } catch(e0) { } try { i0.next(); } catch(e1) { } Array.prototype.forEach.apply(a1, [(function() { try { Array.prototype.shift.call(a0); } catch(e0) { } try { this.m2.delete(p1); } catch(e1) { } Array.prototype.sort.apply(a2, [(function mcc_() { var hwimbz = 0; return function() { ++hwimbz; g0.f0(/*ICCD*/hwimbz % 11 == 7);};})(), g2, this.o0]); return a2; })]); } });\n\n/*tLoop*/for (let a of /*MARR*/[new Number(1.5), arguments.callee, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), arguments.callee, (1/0), (1/0), (1/0), arguments.callee, objectEmulatingUndefined(), NaN, arguments.callee, (1/0), new Number(1.5), objectEmulatingUndefined(), (1/0), NaN, new Number(1.5), (1/0), NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), arguments.callee, objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), arguments.callee, NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, new Number(1.5), NaN, (1/0), new Number(1.5), NaN, new Number(1.5), NaN, new Number(1.5), NaN, new Number(1.5), (1/0)]) { print(e = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function() { throw 3; }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function shapeyConstructor(ptezsk){ptezsk[new String(\"7\")] = false;Object.freeze(ptezsk);delete ptezsk[new String(\"7\")];if (window) delete ptezsk[\"arguments\"];for (var ytqwpvtzm in ptezsk) { }ptezsk[new String(\"7\")] = false;{ \"\\u6FE5\"; } ptezsk[this] = ({/*TOODEEP*/});return ptezsk; }, keys: function() { return []; }, }; })( \"\" ), (1 for (x in [])), Function)); }\n");
/*fuzzSeed-133180449*/count=756; tryItOut("\"use strict\"; v1 = (t1 instanceof b2);");
/*fuzzSeed-133180449*/count=757; tryItOut("let e = (4277);print(x);");
/*fuzzSeed-133180449*/count=758; tryItOut("for(d in ((decodeURIComponent)(\"\\uF8A9\"))){;Array.prototype.forEach.call(a1, (function() { for (var j=0;j<12;++j) { f1(j%4==0); } })); }");
/*fuzzSeed-133180449*/count=759; tryItOut("h2.toSource = (function() { for (var j=0;j<76;++j) { this.o2.f0(j%5==0); } });");
/*fuzzSeed-133180449*/count=760; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.pow(Math.acos((Math.min(( + mathy2(x, ( + (mathy4(x, Math.trunc(y)) >>> 0)))), ( ! x)) >>> 0)), (Math.min((( ~ (Math.fround((Math.fround(new Array(19)) & ( + Math.sqrt(Math.fround(Number.MIN_SAFE_INTEGER))))) | 0)) | 0), Math.imul(Math.sin((Math.fround(mathy4((x | 0), x)) >>> 0)), (Math.round(0x100000001) > x))) >>> 0)); }); testMathyFunction(mathy5, [1/0, Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x100000000, -0, -1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 42, 0.000000000000001, -(2**53+2), 0x0ffffffff, -(2**53), 0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, 0, -0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, -0x100000001, Math.PI, -0x100000000, 1, -(2**53-2), -0x080000001, -0x0ffffffff, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=761; tryItOut("\"use strict\"; const b = (uneval( ''  &= this /  \"\" ));g2 + '';");
/*fuzzSeed-133180449*/count=762; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (( + (Math.max((Math.min(Math.fround(( ! Math.fround((x === Math.PI)))), ( + (( ! (x >>> 0)) <= ( + Math.sign((x >>> 0)))))) | 0), (Math.hypot((( - ( + x)) | 0), (( + Math.asinh(Math.fround(y))) | 0)) | 0)) | 0)) % (Math.fround((((( + mathy0((x * (-(2**53-2) >>> 0)), mathy0(x, (-0x100000000 | 0)))) ** ( + Math.fround(y))) | 0) % ((Math.max(( + x), ( - 0x07fffffff)) >>> 0) | 0))) | 0))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 2**53, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0, -0x100000001, -(2**53), 42, -Number.MAX_VALUE, -0x100000000, -0, 0x100000001, 2**53-2, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, -0x080000000, 0x0ffffffff, -(2**53+2), 0/0, -0x080000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, Math.PI, -1/0, 0x080000000, 0x080000001, -0x0ffffffff, 0x100000000, 1]); ");
/*fuzzSeed-133180449*/count=763; tryItOut("a1 + '';");
/*fuzzSeed-133180449*/count=764; tryItOut("\"use strict\"; ((d) = Math.max(11, -21));");
/*fuzzSeed-133180449*/count=765; tryItOut("g1.i0 + '';");
/*fuzzSeed-133180449*/count=766; tryItOut("\"use strict\"; /*bLoop*/for (var hbtqxo = 0; hbtqxo < 126; ++hbtqxo) { if (hbtqxo % 55 == 37) { [z1]; } else { ; }  } ");
/*fuzzSeed-133180449*/count=767; tryItOut("{ void 0; selectforgc(this); } e1 = new Set;");
/*fuzzSeed-133180449*/count=768; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.pow(Math.fround(Math.tanh(Math.fround(Math.max(x, Math.fround(Math.sqrt(Math.fround((mathy2((y >>> 0), (( + (x >= y)) >>> 0)) | 0)))))))), ( - ((((Math.fround((( + (((Number.MAX_VALUE >>> 0) >>> y) - ( + y))) >>> 0)) >>> 0) | 0) != Math.fround(Math.expm1(( ~ x)))) | 0))); }); testMathyFunction(mathy4, /*MARR*/[{}, {}, {}, (0/0), {}, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), {}, {}]); ");
/*fuzzSeed-133180449*/count=769; tryItOut("/*RXUB*/var r = r0; var s = \"____000000\"; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=770; tryItOut("Array.prototype.unshift.call(a0, g0.g1.o2.h0, h1, g1.a2, h2);");
/*fuzzSeed-133180449*/count=771; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=772; tryItOut("function o1.f0(h1) \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((x))|0;\n  }\n  return f;");
/*fuzzSeed-133180449*/count=773; tryItOut("/*bLoop*/for (vyerlp = 0, eval = x; vyerlp < 82; ++vyerlp) { if (vyerlp % 3 == 1) {  /x/g ; } else { this.e0 = new Set; }  } ");
/*fuzzSeed-133180449*/count=774; tryItOut("var r0 = x - 1; x = r0 - x; var r1 = r0 - x; var r2 = r1 ^ r0; var r3 = x - r2; var r4 = r3 % r2; var r5 = r3 % r2; var r6 = 2 % r5; var r7 = 8 * r2; var r8 = x % 7; var r9 = r7 % 1; var r10 = 3 + r6; x = 2 - x; r2 = 0 % 5; var r11 = 9 ^ r2; var r12 = 8 * x; var r13 = 0 ^ r11; var r14 = 5 % r8; r14 = 2 % r5; r4 = r1 * r7; r10 = 5 * r2; var r15 = 1 / 7; print(r15); var r16 = r3 % r6; var r17 = r2 & r13; var r18 = r11 / r13; var r19 = x / 4; var r20 = r9 ^ r0; var r21 = x + r11; r5 = 5 / 9; r21 = 3 % r15; r13 = r9 - r18; var r22 = r18 - r7; print(r13); var r23 = r13 ^ 0; print(r8); var r24 = x * r13; r21 = r8 - r15; var r25 = r18 - r18; var r26 = 5 + r21; r9 = r18 ^ r0; var r27 = 0 ^ r23; var r28 = r6 + r17; var r29 = r23 & r10; var r30 = r28 & 6; print(r11); var r31 = r2 & r25; var r32 = r20 / r19; var r33 = 0 - r24; var r34 = r21 + r3; var r35 = 3 & 8; var r36 = r32 / r20; var r37 = r14 ^ r33; var r38 = 3 % r6; var r39 = 5 % 2; var r40 = r24 ^ r18; var r41 = r13 * r33; var r42 = 7 ^ r10; r32 = r13 & 0; r4 = 6 % r18; r35 = r9 / r31; var r43 = r28 / r40; r39 = r14 * r23; var r44 = r15 * r2; var r45 = 5 / 5; var r46 = 8 * r34; var r47 = r45 ^ r29; var r48 = 5 & r32; var r49 = 3 + r43; var r50 = r45 / 4; var r51 = 6 ^ 0; var r52 = r12 / r47; var r53 = r9 % r16; var r54 = 4 % r4; var r55 = r51 * r33; var r56 = r40 ^ 1; var r57 = 4 % r40; r17 = 8 ^ r52; r1 = r55 * r16; ");
/*fuzzSeed-133180449*/count=775; tryItOut("");
/*fuzzSeed-133180449*/count=776; tryItOut("\"use strict\"; testMathyFunction(mathy4, /*MARR*/[true, x, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(), true, x,  '\\0' , x, x, x, true, true, objectEmulatingUndefined(), true, true, x,  '\\0' , true, x, true, objectEmulatingUndefined(),  '\\0' , objectEmulatingUndefined(),  '\\0' , x, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, true,  '\\0' , true]); ");
/*fuzzSeed-133180449*/count=777; tryItOut("b, NaN =  '' , rtlkyo, dlgvnm, window, x;/*RXUB*/var r = r0; var s = s2; print(s.search(r)); ");
/*fuzzSeed-133180449*/count=778; tryItOut("v2 = Object.prototype.isPrototypeOf.call(v0, e2);");
/*fuzzSeed-133180449*/count=779; tryItOut("e1.add(h2);");
/*fuzzSeed-133180449*/count=780; tryItOut("v1 = g2.t1.byteOffset;");
/*fuzzSeed-133180449*/count=781; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( - mathy0(Math.atan2(Math.hypot(x, x), x), x)) >>> (Math.ceil(((( + (Math.hypot((y ? y : y), (Math.acosh(Math.fround(Math.log(Math.fround(y)))) | 0)) | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0/0, 0x100000000, 1/0, -1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, -(2**53-2), 0x080000000, -Number.MIN_VALUE, 1, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53+2, -0, 0x0ffffffff, -0x100000001, 2**53-2, 1.7976931348623157e308, -0x080000001, 0x100000001, 2**53, Number.MIN_VALUE, -0x080000000, -0x100000000, 0, -0x07fffffff, 0.000000000000001, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-133180449*/count=782; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?!\\uaabd{1,4}))*\", \"i\"); var s = (decodeURIComponent)(x, false) / x; print(s.split(r)); ");
/*fuzzSeed-133180449*/count=783; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( ! ( + ( + Math.trunc(((((Math.tan(((x / x) >>> 0)) >>> 0) ^ (Math.pow((x !== (y ^ y)), (((((x ? mathy3(-0x100000000, x) : y) >>> 0) ? Math.fround((( + x) ? (x / y) : x)) : (0/0 >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0) >>> 0))))) | 0); }); testMathyFunction(mathy4, [-(2**53-2), 0/0, 2**53-2, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0, Math.PI, 0x080000000, -0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, 0x080000001, -(2**53), 1/0, -0x100000001, Number.MAX_VALUE, 42, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, 1.7976931348623157e308, -Number.MAX_VALUE, -0x080000000, 2**53, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 0x0ffffffff, -0x0ffffffff, 0x100000000, -0x080000001]); ");
/*fuzzSeed-133180449*/count=784; tryItOut("{/*vLoop*/for (let zlsnrk = 0; zlsnrk < 2; ++zlsnrk) { let x = zlsnrk; print(x); }  }");
/*fuzzSeed-133180449*/count=785; tryItOut("( '' );\n(undefined);\n");
/*fuzzSeed-133180449*/count=786; tryItOut("\"use strict\"; o0.v0 + '';");
/*fuzzSeed-133180449*/count=787; tryItOut("selectforgc(o0);");
/*fuzzSeed-133180449*/count=788; tryItOut("print(x);selectforgc(o2.o2.o1);");
/*fuzzSeed-133180449*/count=789; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.5474250491067253e+26;\n    {\n      d2 = ((+(0.0/0.0)) + (+/*FFI*/ff(((imul((/*FFI*/ff(((+(-1.0/0.0))))|0), ((0xc257400f)))|0)))));\n    }\n    {\n      {\n        (Int16ArrayView[4096]) = (([] = Math.imul(window = function ([y]) { }, [[1]] += /\\3+[^]{0}[^]\\B{1,3}+|\\3$+/gym)));\n      }\n    }\n    return (((0x8ccb05b8)))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 0x100000000, 42, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, 1.7976931348623157e308, 2**53-2, -0x100000001, 0x100000001, -0, -0x100000000, -1/0, -(2**53+2), 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53, Math.PI, Number.MAX_VALUE, -(2**53-2), 1/0, 1, 0x080000000, -0x080000000, -0x07fffffff, 0/0, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, 0, -0x0ffffffff, -(2**53), -Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=790; tryItOut("zamofv((4277) <<= (makeFinalizeObserver('tenured')), (4277));/*hhh*/function zamofv(d =  /x/ , z, ...a){o1 = Object.create(i2);}");
/*fuzzSeed-133180449*/count=791; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ~ ( - ( + ( ~ ( + Math.fround(Math.pow(Math.fround(y), Math.fround(x)))))))); }); testMathyFunction(mathy0, [-0x080000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, -1/0, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000001, 0x080000001, -Number.MIN_VALUE, 0x07fffffff, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 42, -0, -(2**53), 1, 2**53, -0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, Math.PI, Number.MIN_VALUE, 1/0, -(2**53-2), 2**53-2, 2**53+2, 0x100000000, 0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=792; tryItOut("\"use strict\"; /*RXUB*/var r = /\\u6b3a{65536,65539}{3}/ym; var s = \"\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\\u6b3a\"; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=793; tryItOut("testMathyFunction(mathy2, [Math.PI, Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 0x100000000, -Number.MAX_VALUE, 42, 0x100000001, 0, -0x07fffffff, 2**53-2, 0x0ffffffff, -0x080000000, -1/0, 0x080000001, -(2**53-2), -(2**53), -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, 1/0, -(2**53+2), -0x0ffffffff, -0, 2**53, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -0x100000000, -0x080000001, -Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-133180449*/count=794; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ( ~ Math.fround(( ~ Math.fround(Math.acosh(((x === ( + Math.fround(Math.sin(y)))) << y)))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, -0x100000000, 2**53+2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 42, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, 1, 0x080000000, 0.000000000000001, 1.7976931348623157e308, -0x100000001, -0, -0x0ffffffff, 0, -0x080000000, -Number.MIN_VALUE, 0x07fffffff, 1/0, 0x100000000, -0x07fffffff, -(2**53), 2**53, 2**53-2, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, -0x080000001]); ");
/*fuzzSeed-133180449*/count=795; tryItOut("testMathyFunction(mathy3, [-Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0x080000001, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -0x080000000, -(2**53-2), -0x07fffffff, 2**53, Math.PI, -0x080000001, -1/0, 0x100000000, 1, 1.7976931348623157e308, 0x100000001, 0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, 0, -0x100000001, -(2**53+2), -0, -Number.MIN_VALUE, 2**53-2, 42, -0x100000000]); ");
/*fuzzSeed-133180449*/count=796; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-133180449*/count=797; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return (((!(/*FFI*/ff(((d1)), ((d0)), (((((((0xfca63874))>>>((0xf90a4f2c))) >= (0x7a8d7f4e))-(0xffffffff))|0)))|0))+(0xe377f556)))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: encodeURI, delete: function() { throw 3; }, fix: undefined, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { throw 3; }, iterate: undefined, enumerate: function() { return []; }, keys: function() { return []; }, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [true, (new String('')), 0.1, -0, /0/, '0', '/0/', (new Number(-0)), (new Boolean(false)), ({toString:function(){return '0';}}), false, 0, (new Number(0)), (function(){return 0;}), NaN, objectEmulatingUndefined(), [0], (new Boolean(true)), '', 1, ({valueOf:function(){return 0;}}), '\\0', null, undefined, ({valueOf:function(){return '0';}}), []]); ");
/*fuzzSeed-133180449*/count=798; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.log10(( ! (-1/0 && (x >>> 0)))) ? ( ! Math.imul((( + mathy2(mathy0(y, Math.fround((y >>> ( + y)))), y)) >>> 0), (( + Math.pow((((y | 0) === (y | 0)) | 0), x)) | 0))) : ( + (( + ( ! y)) < ( + (Math.atanh(Math.fround((Math.fround(Math.hypot(x, x)) * Math.fround(2**53)))) >>> 0))))); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 0x07fffffff, -0x080000001, 0.000000000000001, Number.MIN_VALUE, -0x100000000, -0x0ffffffff, -1/0, Math.PI, 42, -0x07fffffff, 1, -(2**53), 2**53-2, 2**53+2, 1/0, 0x080000001, 0/0, 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -(2**53+2), 0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=799; tryItOut("\"use strict\"; M:if(true) { if (String.prototype.endsWith.prototype) {a2.unshift(h0, m0, s2); } else this.v1 = evalcx(\"/* no regression tests found */\", g1);}");
/*fuzzSeed-133180449*/count=800; tryItOut("\"use strict\"; g2.m0.set(b0, h0);a0.sort((function(j) { if (j) { f0.valueOf = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { var r0 = a10 + 7; var r1 = a6 % 0; var r2 = a5 - a7; r0 = a9 / 3; var r3 = 0 - 2; var r4 = a3 * a4; var r5 = 3 / 6; var r6 = a1 * r1; var r7 = r0 - 1; var r8 = r2 + a2; var r9 = x % a1; var r10 = 8 & r0; var r11 = r2 % a3; var r12 = a7 - a7; var r13 = 6 + a1; var r14 = a8 | a2; var r15 = 3 ^ a9; var r16 = r10 & r15; r7 = r9 ^ a1; r15 = r8 | r7; var r17 = 8 % a0; var r18 = 9 & r0; r0 = 5 ^ 5; var r19 = a7 + r13; var r20 = 4 - r16; var r21 = 6 / a2; a9 = a6 * a11; a0 = x ^ r10; var r22 = 9 % 7; r21 = r13 % a3; print(a8); var r23 = 4 % 3; var r24 = 3 - r1; r1 = r3 * 7; r16 = r5 - r17; print(r14); var r25 = r2 - r3; var r26 = r14 / 6; var r27 = 2 * 8; var r28 = r7 ^ r26; var r29 = r20 * r9; r8 = 9 - a1; var r30 = r9 - 0; r0 = a4 / r21; var r31 = 2 * 0; var r32 = 1 | a2; var r33 = r22 % r10; print(r2); var r34 = 2 / r11; var r35 = 9 % r34; var r36 = r7 | r14; var r37 = r35 - r28; r6 = r2 / a6; var r38 = r26 * r6; var r39 = 3 | a7; var r40 = r35 / 0; r11 = a3 ^ r6; var r41 = 1 % 9; a3 = r0 ^ 5; var r42 = a1 - 8; var r43 = 2 ^ r15; r6 = 0 / 0; var r44 = r24 & 8; var r45 = r17 - r29; var r46 = 0 & 3; var r47 = a9 / r39; r23 = a1 + r47; var r48 = r8 / 8; var r49 = r43 - r27; var r50 = 5 ^ r16; r0 = r45 | r24; return a0; }); } else { try { t1.set(o1.t0, v2); } catch(e0) { } try { g2.a2.push(this.g1.t1, f1, e2); } catch(e1) { } try { Object.defineProperty(o2, \"v2\", { configurable: false, enumerable: (x % 3 != 0),  get: function() {  return evalcx(\"function f1(i0) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var imul = stdlib.Math.imul;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var d2 = -9223372036854776000.0;\\n    d2 = (((+abs(((((2.4178516392292583e+24)) - ((Float32ArrayView[((0xfeefb940)+(0xffffffff)) >> 2]))))))) * ((((new /\\\\3/yi(null).__defineGetter__(\\\"\\\\u3056\\\", Function))) * (((d2) + (d2))))));\\n    return (((0xffffffff)+(0x9e6ab241)))|0;\\n    {\\n      d2 = (-3.022314549036573e+23);\\n    }\\n    return ((((((i0)) ^ (((0x0) >= (((0xbed438f9))>>>((0xfa114167))))+(i0)-(i1))))+((i0) ? ((imul(((0xf8452f3c) ? (0x78a1ba2) : (0xfa591400)), ((-1.00390625) >= (-2097153.0)))|0) <= (abs((((-0x8000000)-(0xa4b56f69)) & (((((0xfa44d034)) ^ ((0xd7012565)))))))|0)) : (0xf85aeae2))))|0;\\n  }\\n  return f;\", g1); } }); } catch(e2) { } var this.g1 = this; } }), v0, s1);");
/*fuzzSeed-133180449*/count=801; tryItOut("/*tLoop*/for (let b of /*MARR*/[eval,  \"use strict\" ,  /x/ , eval, (0/0),  /x/ , eval, (0/0),  /x/ ,  \"use strict\" , (0/0),  \"use strict\" ,  \"use strict\" , eval,  /x/ , eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval,  /x/ , eval, eval,  \"use strict\" ,  \"use strict\" , eval,  /x/ , eval,  \"use strict\" , (0/0), (0/0),  \"use strict\" ,  \"use strict\" ,  /x/ ,  /x/ , (0/0),  \"use strict\" , (0/0), eval,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval,  \"use strict\" , (0/0), eval, eval, eval, (0/0), eval,  \"use strict\" , eval,  /x/ , (0/0),  \"use strict\" , (0/0), eval, (0/0), eval,  \"use strict\" ,  /x/ ,  \"use strict\" , eval, eval,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (0/0),  \"use strict\" ,  /x/ ,  /x/ ,  \"use strict\" ,  /x/ , eval, (0/0),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/ , (0/0), (0/0),  \"use strict\" ,  \"use strict\" , eval, (0/0), (0/0), eval, (0/0), (0/0)]) { m1 + '';\n/*bLoop*/for (lbqrzz = 0; lbqrzz < 24; ++lbqrzz) { if (lbqrzz % 6 == 2) { ; } else { [1,,]; }  } \n }");
/*fuzzSeed-133180449*/count=802; tryItOut("s0.valueOf = (function() { a1[\"\\uAB4A\"] = (4277); return v2; });");
/*fuzzSeed-133180449*/count=803; tryItOut("\"use strict\"; v2 = evalcx(\"o1.v1 = true;\", g0);");
/*fuzzSeed-133180449*/count=804; tryItOut("print(uneval(v2));");
/*fuzzSeed-133180449*/count=805; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (0xfad19842);\n    return +((d1));\n  }\n  return f; })(this, {ff: Boolean}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=806; tryItOut("\"use strict\"; if(false) { if (x) {Array.prototype.reverse.apply(a2, [p0, b2]); }} else {/* no regression tests found */Array.prototype.sort.call(a1, (function(j) { f0(j); }), s2);function \u3056() { ; } a0.splice(NaN, 7, a0);\nfor (var p in f0) { try { v0 = g0.runOffThreadScript(); } catch(e0) { } try { s1 += s1; } catch(e1) { } Object.defineProperty(this, \"g1.e1\", { configurable: false, enumerable: true,  get: function() {  return new Set(g1.i1); } }); }\n }");
/*fuzzSeed-133180449*/count=807; tryItOut("testMathyFunction(mathy5, [-(2**53+2), 0x080000001, 0/0, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, 0x100000000, 0x100000001, -1/0, Number.MIN_VALUE, -0x100000000, Math.PI, 0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, 2**53-2, -0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, -(2**53), Number.MAX_VALUE, 1, 0, -0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, 0x080000000, -0]); ");
/*fuzzSeed-133180449*/count=808; tryItOut("/*oLoop*/for (nnxgjk = 0; nnxgjk < 153; ++nnxgjk) { yield; } ");
/*fuzzSeed-133180449*/count=809; tryItOut("/*bLoop*/for (var xayqzg = 0; xayqzg < 22; ++xayqzg) { if (xayqzg % 52 == 45) { print(/*RXUE*//((?:\\xdC)+?)*.|\\1[^]|\\0/g.exec(\"\")); } else { print(((void options('strict_mode')))); }  } function b(\u3056, window, x, d, x, b, x, x, x = x =  '' , x, eval, x, y = new RegExp(\"(?!(?=[^]|$|[]{3,}*?){0})\\\\b\", \"\"), c = x, b, x, a, NaN, a, e, x, x, x, w, y, x, x, x, window, NaN, \u3056, w, b, d = false, x, window, eval, eval, x, x, window, NaN, w, window, \u3056, x = -14, x, eval, d, \"-20\" =  /x/g , e, b, x, z, eval, x, e = \"\\u32A1\", eval, x =  \"\" , x, a, window, x = x, \u3056 =  \"\" , this.d, b, this.x, \u3056 = new RegExp(\"([^\\\\\\u00a8-\\\\v\\\\Ws-\\\\u002B\\\\w])\", \"g\"), x, z, x, z, \u3056, x, z, y, \u3056, y, c, z, x, b, window) { yield (4277) } switch(\n(uneval(\"\\u9814\"))) { case Math.pow(14, [,,z1]): v0 = Array.prototype.every.call(a2, f1, i0);case ((function factorial_tail(nxeiik, wthtyc) { ; if (nxeiik == 0) { throw \"\\u1F38\";\n( /x/g );\n; return wthtyc; } ; return factorial_tail(nxeiik - 1, wthtyc * nxeiik);  })(73530, 1)): ;break; case eval = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(undefined), [27]):  }");
/*fuzzSeed-133180449*/count=810; tryItOut("\"use strict\"; Object.defineProperty(e, \"NaN\", ({configurable: function ([y]) { }}));");
/*fuzzSeed-133180449*/count=811; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=812; tryItOut("let z = (function ([y]) { })();for (var p in p1) { /*RXUB*/var r = r2; var s = s1; print(s.replace(r, z));  }");
/*fuzzSeed-133180449*/count=813; tryItOut("v0 = evaluate(\" \\\"\\\" \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: x > apply, noScriptRval: ([x] | (b |= \u3056)), sourceIsLazy: typeof  \"\"  &= x, catchTermination: false }));");
/*fuzzSeed-133180449*/count=814; tryItOut("\"use strict\"; function shapeyConstructor(miadtw){\"use strict\"; Object.defineProperty(this, \"arguments\", ({value: (x = ((p={}, (p.z = (4277))()))), enumerable: /*MARR*/[0x100000000, [1], /(?=(?=(?=\\B|\\s.|\\s*|[\\u002d-\\xF2\\\u36de\\d])))/gyi, 0x100000000, objectEmulatingUndefined(), [1], 0x100000000].sort}));return this; }/*tLoopC*/for (let a of /*MARR*/[]) { try{let brmlfr = new shapeyConstructor(a); print('EETT'); h1.getOwnPropertyNames = (function() { for (var j=0;j<40;++j) { f1(j%4==0); } });}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-133180449*/count=815; tryItOut("y = a;");
/*fuzzSeed-133180449*/count=816; tryItOut("for (var p in o2) { v0 = evalcx(\"/* no regression tests found */\", g2); }");
/*fuzzSeed-133180449*/count=817; tryItOut("\"use strict\"; M:do {print((4277)); } while((([] = (eval) = undefined).throw(x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(new RegExp(\"\\\\cV\", \"gi\")), /*wrap1*/(function(){ 6;return d =>  { return /^|(.{0})*|((?:[^])?.[^]*|\\b*?)/gy } })()))) && 0);");
/*fuzzSeed-133180449*/count=818; tryItOut("\"use strict\"; /*MXX1*/o2 = g1.Uint8Array.name;print(x);");
/*fuzzSeed-133180449*/count=819; tryItOut("\"use strict\"; v0 = evalcx(\"/* no regression tests found */\", g2);");
/*fuzzSeed-133180449*/count=820; tryItOut("/*RXUB*/var r = /(\\d*|(?!\u008f)\\B)?|\u82c4[^]((?:\\W{3}(.))|[^\\cN-\\n]+?)|(?=[^\\\u6bbe-\u00cd])((?:\\2))+/gy; var s = undefined; print(r.test(s)); ");
/*fuzzSeed-133180449*/count=821; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.max(Math.fround(( ~ Math.trunc(Math.max(Math.fround(x), Math.fround(mathy0(y, y)))))), ( + Math.log10((((( ! y) | 0) !== ((y ** (x | Math.fround(Math.cosh(Math.fround(0.000000000000001))))) | 0)) | 0)))); }); testMathyFunction(mathy1, [1, 2**53+2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, -0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, 2**53, -(2**53+2), -Number.MAX_VALUE, 0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, Math.PI, -1/0, 0x080000000, 0.000000000000001, Number.MIN_VALUE, -(2**53), -0, 0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, 0x07fffffff, -0x07fffffff, 0x0ffffffff, -(2**53-2), -0x080000001, 0/0, 1/0]); ");
/*fuzzSeed-133180449*/count=822; tryItOut("m0 = this.t0;");
/*fuzzSeed-133180449*/count=823; tryItOut("let (\u000ce) { Array.prototype.pop.call(a2, b1, p1); }");
/*fuzzSeed-133180449*/count=824; tryItOut("o1 + this.o1;");
/*fuzzSeed-133180449*/count=825; tryItOut("a0 = arguments;");
/*fuzzSeed-133180449*/count=826; tryItOut("\"use strict\"; eval = (function(){}), [{}, \u3056, x] = x, a;this.g1.m1.delete(e0);");
/*fuzzSeed-133180449*/count=827; tryItOut("\"use strict\"; (void schedulegc(g2))\n");
/*fuzzSeed-133180449*/count=828; tryItOut("mathy3 = (function(x, y) { return ( + Math.tan((Math.fround((Math.imul(Math.fround((Math.fround((x || x)) === Math.fround(y))), Math.atan2((y ^ 0x0ffffffff), Math.max(Math.fround((Math.min(x, y) | 0)), (y | 0)))) , Math.fround(((( + Math.hypot(( + y), ( + (y | x)))) !== x) * Math.tan(Math.PI))))) >>> 0))); }); testMathyFunction(mathy3, [0x100000000, 0x080000000, -0x100000000, Number.MIN_VALUE, -(2**53-2), -(2**53+2), 0.000000000000001, Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, 0x080000001, 2**53, -0x07fffffff, 42, 0/0, -(2**53), -0x080000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, 2**53-2, 0, 1/0, -0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, 1, Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-133180449*/count=829; tryItOut("switch(x) { default: /*RXUB*/var r = /(?=(?=([^]+|(?:.)|((?=\\A))*){4,})){3}/gym; var s = \"\"; print(r.exec(s));  }");
/*fuzzSeed-133180449*/count=830; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ((( + (Math.acosh(( + Math.cbrt(( - Math.fround(Math.min(x, -Number.MIN_SAFE_INTEGER)))))) | 0)) + ( + (mathy0((( + (y >>> 0)) >>> 0), (Math.trunc((y >>> 0)) >>> 0)) || ( ~ ((Math.atan2(x, Math.max(y, y)) ? (( ~ Math.fround(1/0)) | 0) : ((Math.asin((x | 0)) | 0) | 0)) | 0))))) >>> 0); }); ");
/*fuzzSeed-133180449*/count=831; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var i5 = 0;\n    {\n      {\n        {\n;        }\n      }\n    }\n    return (((i2)-(i0)-((-1152921504606847000.0) < (d1))))|0;\n  }\n  return f; })(this, {ff: x.charAt}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [[], (function(){return 0;}), (new Number(0)), 0.1, false, null, ({valueOf:function(){return 0;}}), 0, '0', true, objectEmulatingUndefined(), 1, ({toString:function(){return '0';}}), '/0/', /0/, '\\0', (new Number(-0)), (new String('')), NaN, undefined, (new Boolean(false)), ({valueOf:function(){return '0';}}), (new Boolean(true)), [0], '', -0]); ");
/*fuzzSeed-133180449*/count=832; tryItOut("m1.__proto__ = s1;");
/*fuzzSeed-133180449*/count=833; tryItOut("for (var v of f1) { try { a1.splice(NaN, 5, p0, o0.g1.g2); } catch(e0) { } a2 + ''; }");
/*fuzzSeed-133180449*/count=834; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=835; tryItOut("var qpmsrp = new ArrayBuffer(0); var qpmsrp_0 = new Int16Array(qpmsrp); qpmsrp_0[0] = -8; var qpmsrp_1 = new Int16Array(qpmsrp); print(qpmsrp_1[0]); var qpmsrp_2 = new Int32Array(qpmsrp); qpmsrp_2[0] = -3; var qpmsrp_3 = new Uint16Array(qpmsrp); qpmsrp_3[0] = 5; var qpmsrp_4 = new Float32Array(qpmsrp); qpmsrp_4[0] = -28; var qpmsrp_5 = new Float32Array(qpmsrp); qpmsrp_5[0] = -22; var qpmsrp_6 = new Int16Array(qpmsrp); a0.sort(Math.log.bind(this.a0));");
/*fuzzSeed-133180449*/count=836; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[new String(''), new String('q'), new String(''), (intern(true)), (intern(true)), new String(''), undefined, undefined, undefined, undefined, new String('q'), undefined, new String('q'), undefined, new String(''), undefined, new String(''), (intern(true)), new String('q'), new String('q'), new String(''), undefined, new String('q'), undefined, undefined, new String(''), new String('q'), (intern(true)), undefined, new String('q'), undefined, (intern(true)), (intern(true)), (intern(true)), (intern(true)), new String('q'), undefined, new String(''), new String('q'), (intern(true)), new String('q'), (intern(true)), new String('q'), new String('q'), new String('q'), (intern(true)), (intern(true)), (intern(true)), (intern(true))]) { for(var [x, y] = (new Function).call(!(4277), x, x) in let (NaN = (function ([y]) { })(), pxdqmh, a = x, d = null, x, y, qaslph, xmkfaq, c, hjuayh)  ''  /= d.__defineGetter__(\"d\", this)) e0.add(s0); }");
/*fuzzSeed-133180449*/count=837; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.exp(( + (( + (y >>> (Math.tan(Math.fround(Math.max(x, (x >>> 0)))) >>> 0))) < (Math.fround(Math.imul(-1/0, (Math.cbrt(y) >> ( + Math.imul(x, ( + 2**53)))))) >>> 0)))); }); testMathyFunction(mathy2, [Math.PI, -0x0ffffffff, -(2**53-2), -0x100000000, 0x080000000, 0x100000001, 0.000000000000001, Number.MAX_VALUE, 1.7976931348623157e308, 1/0, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, -0x100000001, 2**53+2, Number.MIN_VALUE, 2**53-2, -(2**53), -0x07fffffff, 0x100000000, 0x07fffffff, -0x080000001, -Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 2**53, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, 0, 1, -0, -(2**53+2), 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=838; tryItOut("\"use strict\"; testMathyFunction(mathy0, [0.000000000000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), -Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), -0x100000001, 0x100000001, 0x100000000, -0x100000000, 0x080000001, Math.PI, -0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, 2**53-2, -0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, 0, Number.MIN_VALUE, 0x080000000, 0x07fffffff, 0x0ffffffff, 2**53, Number.MAX_VALUE, 2**53+2, -(2**53), -1/0, -0x07fffffff]); ");
/*fuzzSeed-133180449*/count=839; tryItOut("\"use strict\"; v1 = (a0 instanceof this.h1);");
/*fuzzSeed-133180449*/count=840; tryItOut("\"use strict\"; e1.__proto__ = t0;");
/*fuzzSeed-133180449*/count=841; tryItOut("");
/*fuzzSeed-133180449*/count=842; tryItOut("\"use strict\"; print(uneval(s2));");
/*fuzzSeed-133180449*/count=843; tryItOut("\"use strict\"; L: {/*RXUB*/var r = new RegExp(\"\\\\S|\\\\n{67108864}|.|.{1,4098}(?=\\ub08f*?){4,6}*\", \"gm\"); var s = (yield x); print(s.search(r)); if((x % 4 == 1)) {/*ODP-3*/Object.defineProperty(h1, \"constructor\", { configurable: window, enumerable: (x % 3 != 0), writable: false, value: f1 });print(x); } else { /x/g ; } }");
/*fuzzSeed-133180449*/count=844; tryItOut("mathy2 = (function(x, y) { return ( + ( + ( + ((((Math.hypot((( ~ (x & y)) >>> 0), (((( + (( + (( + x) === y)) ? ( + mathy0(( + (x ? x : y)), (x >>> 0))) : ( + -(2**53+2)))) | 0) + ((((y >>> 0) > (x >>> 0)) >>> 0) | 0)) | 0)) >>> 0) | 0) & ( + Math.fround((Math.fround((Math.max((-0x100000000 >>> 0), (Math.tanh(Math.tanh(x)) >>> 0)) >>> 0)) % Math.fround(x))))) | 0)))); }); testMathyFunction(mathy2, [0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, -(2**53), -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, 2**53, 0/0, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, -(2**53-2), 0x080000001, 1, -0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 0x080000000, 42, -(2**53+2), 0x100000001, -Number.MAX_VALUE, -0x07fffffff, -0x100000001, -0x080000000, -1/0, -0x080000001, Math.PI, 0, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=845; tryItOut("mathy1 = (function(x, y) { return ( + Math.hypot(( + Math.trunc(( + Math.fround((Math.fround(y) << Math.fround(y)))))), ( + ( - ( + (( - Math.max(mathy0(x, y), 42)) | 0)))))); }); testMathyFunction(mathy1, [-0x07fffffff, -Number.MAX_VALUE, -(2**53), 0x080000000, 0x07fffffff, 1/0, 2**53+2, 0x100000001, 42, -1/0, 1, 0x100000000, -0x080000000, -0x0ffffffff, -(2**53-2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, -0x100000000, -(2**53+2), 0/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, 2**53-2, -0x080000001, 2**53, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=846; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (((Math.ceil((Math.cos(((Math.min(x, x) + ( + Math.imul(0x100000000, (-Number.MAX_VALUE >>> 0)))) >>> 0)) >>> 0)) ^ (( - ( + ( + Math.min(( + Math.max(x, ( + (( + (1/0 | 0)) | 0)))), ( + Math.sign(x)))))) | Math.fround(Math.abs(x)))) >>> 0) >= ( ! ( + (( - (y >>> 0)) | 0)))); }); ");
/*fuzzSeed-133180449*/count=847; tryItOut("testMathyFunction(mathy2, [2**53-2, -0, Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000000, 0, -Number.MIN_VALUE, 0x100000001, -(2**53-2), 42, 0x07fffffff, -(2**53), 0.000000000000001, 0x0ffffffff, 2**53+2, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, 2**53, 1, -(2**53+2), 0/0, 1.7976931348623157e308, 1/0, -0x100000001, 0x080000000, -0x080000000]); ");
/*fuzzSeed-133180449*/count=848; tryItOut("s0 += s1;");
/*fuzzSeed-133180449*/count=849; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=850; tryItOut(";");
/*fuzzSeed-133180449*/count=851; tryItOut("L:switch(x) { default: case ((({\u3056:  /* Comment */ /x/ })) ** x): break; case 1: case 8: break; case x: break; /* no regression tests found */break; break; case 3: case (4277): case (eval = x): let g1 = this;break;  }");
/*fuzzSeed-133180449*/count=852; tryItOut("\"use strict\"; v2 = g0.runOffThreadScript();");
/*fuzzSeed-133180449*/count=853; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Math.PI, 0x100000000, 0.000000000000001, 42, Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, 0x080000000, 1/0, 0/0, -0x07fffffff, 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000000, -0, -0x080000000, 2**53, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -1/0, 2**53+2, -Number.MIN_VALUE, 0x080000001, 0x07fffffff, 0x0ffffffff, -0x0ffffffff, -0x100000001, 1, -0x080000001]); ");
/*fuzzSeed-133180449*/count=854; tryItOut("e0.delete(b0);");
/*fuzzSeed-133180449*/count=855; tryItOut("mathy0 = (function(x, y) { return ( ! Math.max(((( + Math.max(( + Math.cos((x | 0))), ( + (Math.max((x >>> 0), 0.000000000000001) >>> 0)))) ^ ( + ( ~ ( + (Math.tanh(( + x)) >>> 0))))) >>> 0), Math.atan2(Math.fround(Math.atan2(x, ((x / ((( - (x >>> 0)) | 0) || Math.fround((Math.trunc((x | 0)) >>> 0)))) >>> 0))), Math.atan2(x, ( + Math.imul((( ! ((Math.sin((x | 0)) | 0) | 0)) | 0), y)))))); }); ");
/*fuzzSeed-133180449*/count=856; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.log1p(( ! Math.fround((Math.PI != 1))))); }); ");
/*fuzzSeed-133180449*/count=857; tryItOut("m1 + '';");
/*fuzzSeed-133180449*/count=858; tryItOut("\"use strict\"; o0.a1.unshift(i2, t2, b2);a1[false] = s0;");
/*fuzzSeed-133180449*/count=859; tryItOut("Object.defineProperty(g0.g2, \"v0\", { configurable: (x % 95 == 3), enumerable: (x % 6 == 4),  get: function() {  return g1.eval(\"/* no regression tests found */\"); } });\no0.m1.get(true);\n");
/*fuzzSeed-133180449*/count=860; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((((Math.acosh(((Math.pow((y | 0), (( ! y) | 0)) | 0) | 0)) | 0) != y) * (( + (( - x) >>> 0)) >>> 0)) !== (Math.log(Math.fround(Math.min(Math.fround((((((0x0ffffffff * y) | 0) | 0) ? (Math.fround((Math.fround(-0x100000001) << Math.fround(x))) | 0) : (y | 0)) | 0)), -0x07fffffff))) ** Math.sin(x))) | 0); }); testMathyFunction(mathy0, [1/0, -(2**53), -1/0, 0x100000000, Math.PI, 42, -0x080000001, 1, -Number.MIN_SAFE_INTEGER, -0x100000001, -0, 2**53-2, 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000000, -(2**53+2), 0/0, Number.MAX_SAFE_INTEGER, 2**53, 0, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, -0x080000000, 0x080000001, 0x080000000, 2**53+2, -(2**53-2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=861; tryItOut("f0.toString = (function() { try { m1.delete(s0); } catch(e0) { } v1 = evaluate(\"/*ODP-2*/Object.defineProperty(g0, \\\"length\\\", { configurable: true, enumerable: true, get: f0, set: (function() { try { v2 = (x % 4 == 3); } catch(e0) { } f2(f2); return f0; }) });\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 4), noScriptRval: true, sourceIsLazy: false, catchTermination: false })); return m1; });");
/*fuzzSeed-133180449*/count=862; tryItOut("e1.delete(t2);");
/*fuzzSeed-133180449*/count=863; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.expm1(( ~ y)), Math.tan(( + ((x % (( + ( + x)) | 0)) & ((mathy0((y | 0), ((((0.000000000000001 >>> 0) >= (Math.sqrt(x) | 0)) | 0) >>> 0)) >>> 0) | 0))))); }); testMathyFunction(mathy1, /*MARR*/[true, new String(''), new String(''), new String(''), true, true, true, (0/0), (0/0), true, (0/0), (0/0), new String(''), true, true, true, true, true, (0/0)]); ");
/*fuzzSeed-133180449*/count=864; tryItOut("\"use strict\"; /*oLoop*/for (let ifbzqc = 0; ifbzqc < 1; ++ifbzqc) { print(x); } ");
/*fuzzSeed-133180449*/count=865; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=866; tryItOut("this.o0.p0 + '';function x(\u3056, y) { yield (4277) } /*vLoop*/for (var aztfun = 0; aztfun < 57; ++aztfun) { let d = aztfun; print(d); } ");
/*fuzzSeed-133180449*/count=867; tryItOut("this.zzz.zzz;");
/*fuzzSeed-133180449*/count=868; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[false, arguments.callee, (0/0), (0/0), (0/0), false, arguments.callee, false, (0/0), arguments.callee, false, arguments.callee, this, (0/0), arguments.callee, arguments.callee, this, false, arguments.callee, (0/0), this, this, arguments.callee, this, (0/0), (0/0), (0/0), this, this, this, this, (0/0), false, arguments.callee, this, false, (0/0), (0/0), false, arguments.callee, this, false, this, false, false, false, this, (0/0), false, false, (0/0), this, false, (0/0), this, (0/0), this, arguments.callee, false, arguments.callee, (0/0), arguments.callee, arguments.callee, false, (0/0), (0/0), (0/0), (0/0), false, this, this, (0/0), arguments.callee, false, this, (0/0), this, false, (0/0), arguments.callee, false, arguments.callee, this, arguments.callee, false, this, this, arguments.callee, (0/0), false, this, false, this, arguments.callee, this, (0/0), this, arguments.callee, arguments.callee, (0/0), this, (0/0), (0/0)]) { o2.o0.s0 += s0; }");
/*fuzzSeed-133180449*/count=869; tryItOut("while((x = x) && 0){/*MXX2*/g0.DataView.prototype.setInt8 = v0; }");
/*fuzzSeed-133180449*/count=870; tryItOut("m2.get(o2);");
/*fuzzSeed-133180449*/count=871; tryItOut("\"use strict\"; Object.seal(s1);");
/*fuzzSeed-133180449*/count=872; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atanh(((Math.min((((( ! (( + x) >= 2**53)) | 0) > (( + Math.tan(( + Number.MAX_VALUE))) | 0)) | 0), (x , ((Math.atan2((y | y), (x >>> 0)) >>> 0) | 0))) | (Math.clz32(Math.asinh(y)) | 0)) | 0)); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 0x07fffffff, Math.PI, -(2**53), 0x080000001, 2**53, -0x080000000, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0/0, 1, 0x100000000, -0x100000000, 0, 0x080000000, 42, 1/0, -Number.MAX_VALUE, 2**53+2, 0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, Number.MAX_VALUE, -1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -0, -0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=873; tryItOut("\"use strict\"; /* no regression tests found */\nm1.has(g2.s0);\n");
/*fuzzSeed-133180449*/count=874; tryItOut("o0.__iterator__ = (function mcc_() { var lhgpcp = 0; return function() { ++lhgpcp; if (/*ICCD*/lhgpcp % 7 == 5) { dumpln('hit!'); try { o0 = new Object; } catch(e0) { } try { a2.forEach((function() { try { /*RXUB*/var r = r2; var s = \"AAAAAAAAAA\"; print(s.replace(r, 'x')); print(r.lastIndex);  } catch(e0) { } try { t0[12] = yield 0; } catch(e1) { } try { Array.prototype.sort.apply(a0, [(function(j) { if (j) { try { o0 = Object.create(a0); } catch(e0) { } for (var v of o0.i0) { try { for (var v of e2) { try { v1 = a2.some((function() { try { t1[12] = p1; } catch(e0) { } g2.v2 = (b1 instanceof o2); return b1; })); } catch(e0) { } try { t0.set(t1,  /x/ ); } catch(e1) { } m1.delete(b1); } } catch(e0) { } g2.v0 = (f0 instanceof t2); } } else { try { g0.e0.has(f0); } catch(e0) { } Object.defineProperty(this, \"v2\", { configurable: true, enumerable: false,  get: function() {  return g1.runOffThreadScript(); } }); } })]); } catch(e2) { } p2 + ''; throw p0; }), v2, b1); } catch(e1) { } o1.g0.o1.a2[14] = x.watch(x, objectEmulatingUndefined); } else { dumpln('miss!'); b0 = a2[(Object.prototype.toString)]; } };})();");
/*fuzzSeed-133180449*/count=875; tryItOut("yield (void options('strict'));throw StopIteration;");
/*fuzzSeed-133180449*/count=876; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.hypot(( + ( - Math.exp(Math.fround(( + Math.tan((mathy4(y, x) >>> 0))))))), ( + mathy1(mathy3(42, ((( + mathy0(y, y)) | 0) + (1 | 0))), x))) | (Math.fround((( ~ (Math.pow(((x << (y >>> 0)) >>> 0), (Math.fround((y >>> 0)) >>> 0)) >>> 0)) >>> 0)) * (( + ((Math.pow((Math.round(Math.imul(x, Number.MIN_VALUE)) >>> 0), (Math.tan((( + ( ! x)) | 0)) | 0)) | 0) <= 0x100000001)) | 0))); }); testMathyFunction(mathy5, [0, -0x080000000, -0x0ffffffff, 42, -(2**53), -Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000001, 0x080000001, 2**53, -0x100000001, -(2**53-2), 1/0, -0, 2**53+2, -(2**53+2), 0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, Math.PI, -Number.MIN_VALUE, 0x080000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, Number.MAX_VALUE, 1, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=877; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (((d1)) % ((+atan2(((d1)), ((d0))))));\n    d0 = (+((delete NaN.x.slice())));\n    {\n      return +((d1));\n    }\n    return +((d1));\n  }\n  return f; })(this, {ff: (decodeURIComponent).bind(x)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0, -(2**53), -0x080000000, -(2**53+2), Number.MIN_VALUE, -0x100000001, 2**53-2, -1/0, 0x100000000, 0/0, -0x07fffffff, 0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, 1/0, Number.MIN_SAFE_INTEGER, 2**53, Math.PI, -0x0ffffffff, 1, -Number.MAX_VALUE, 0, 0.000000000000001, 0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, -(2**53-2), 1.7976931348623157e308, 2**53+2, -0x100000000]); ");
/*fuzzSeed-133180449*/count=878; tryItOut("this.a1.splice(-6, (a0 = Array.prototype.map.call(a0, (function() { v1 = Object.prototype.isPrototypeOf.call(a2, h2); throw this.e1; }))));");
/*fuzzSeed-133180449*/count=879; tryItOut("mathy2 = (function(x, y) { return Math.hypot(Math.abs((Math.fround((( ! (y !== mathy0(y, y))) << mathy0(0.000000000000001, ( + x)))) <= Math.imul(( + Math.max((((x - x) ^ y) | 0), y)), Math.asin(y)))), mathy0(Math.max(Math.fround(Math.max(( + x), ( + y))), (x == ( + Math.hypot(Math.fround(( + (y >>> 0))), ( + y))))), (( + (( + Math.atan2(Math.fround((Math.fround(( + mathy1(y, x))) * Math.fround(y))), (Math.sin(0x080000000) >>> 0))) ? ( + y) : (y | 0))) >> (Math.min((x >>> 0), ((Math.tanh(((-0x080000000 >>> 0) , (y >>> 0))) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [0x07fffffff, -1/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 0, -0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -0x080000001, 0x080000000, -Number.MIN_VALUE, 0x080000001, -(2**53-2), Math.PI, -0x100000000, 0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, 0/0, 1/0, 2**53-2, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1, -0x100000001, 2**53, -0x07fffffff, 2**53+2, 1.7976931348623157e308, 0x100000000, -(2**53)]); ");
/*fuzzSeed-133180449*/count=880; tryItOut("mathy1 = (function(x, y) { return (((Math.sin(Math.imul((( - (y | 0)) >>> 0), ( + Math.atan2(( + Math.ceil(-0)), ( + (y === Math.fround(mathy0(x, x)))))))) >>> 0) ? (mathy0(( + mathy0(( + Math.max(y, Math.trunc(-Number.MIN_VALUE))), ( + Math.cosh(x)))), ((( + y) || mathy0(x, ( + ((x | 0) / ( + (Math.max(( + -0x100000001), Math.pow(y, (y | 0))) | 0)))))) | 0)) >>> 0) : (( ~ Math.acos((( + Math.log1p(( + ( + x)))) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, 0.000000000000001, 0/0, -0x07fffffff, -(2**53-2), -0x080000001, 42, Math.PI, 0, Number.MIN_VALUE, -(2**53+2), 0x080000001, -1/0, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, 1, 0x100000001, 0x080000000, 2**53, -0, -0x100000001, 2**53-2, 0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=881; tryItOut("f0 + '';");
/*fuzzSeed-133180449*/count=882; tryItOut("{print(Float64Array.prototype);print(x); }");
/*fuzzSeed-133180449*/count=883; tryItOut("\"use strict\"; g1.offThreadCompileScript(\"Object.defineProperty(this, \\\"g1.t0\\\", { configurable: true, enumerable: true,  get: function() {  return new Uint16Array(b0); } });\", ({ global: o1.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 != 4), noScriptRval: false, sourceIsLazy: false, catchTermination: true }));");
/*fuzzSeed-133180449*/count=884; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=885; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.acosh(Math.pow(Math.max(-Number.MAX_VALUE, ( + Math.imul(( + Number.MAX_SAFE_INTEGER), ( + ( + Math.pow(( + (( - x) | 0)), x)))))), ( + ( ~ ( + Math.min(( + -(2**53+2)), (x >>> 0))))))); }); testMathyFunction(mathy0, [-0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, 2**53-2, -0x080000001, -0x100000000, 0x080000000, 1, -1/0, -0x07fffffff, 0/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0.000000000000001, 1/0, -0, 42, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -0x100000001, -(2**53+2), -0x080000000, 2**53, 1.7976931348623157e308, 0x080000001, 0x0ffffffff, 2**53+2, Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=886; tryItOut("if(true) s0 += this.s1;function NaN(\u3056 = allocationMarker())\"\\uC20C\"a0.shift(a0);");
/*fuzzSeed-133180449*/count=887; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( + (((( ~ ( ~ 1)) & Math.exp(y)) >>> 0) <= ( + (Math.trunc(Math.fround(Math.hypot(Math.fround((y * Math.fround(Math.atanh(x)))), Math.fround(Math.atan2((Math.fround(( - (Math.PI >>> 0))) | 0), -(2**53-2)))))) | 0))))); }); testMathyFunction(mathy0, [-(2**53+2), 0.000000000000001, 0x100000000, -0x0ffffffff, -Number.MIN_VALUE, Math.PI, -0x080000001, -Number.MAX_VALUE, 0x100000001, 1, -0x100000001, 2**53-2, 0x080000000, 0, -0, 0x080000001, 0/0, Number.MIN_VALUE, -1/0, -0x07fffffff, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, -(2**53), 1/0, 42, -0x080000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=888; tryItOut("\"use strict\"; \"use asm\"; o1.o2.e2.has(s2);");
/*fuzzSeed-133180449*/count=889; tryItOut("testMathyFunction(mathy3, [2**53, 0x100000000, -Number.MAX_VALUE, 42, 0x080000000, -1/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), -0x080000001, 2**53+2, -Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, 1, -0, -(2**53), 0x07fffffff, 0, Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, 0x080000001, 0x100000001, 1/0, 0x0ffffffff, -0x080000000, 0/0, 1.7976931348623157e308, 2**53-2]); ");
/*fuzzSeed-133180449*/count=890; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(t0, \"\\u3056\", { configurable: (x % 19 == 18), enumerable: (x % 5 == 2), writable: (x % 5 == 1), value: o1 });");
/*fuzzSeed-133180449*/count=891; tryItOut("\"use strict\"; h2.getPropertyDescriptor = (function mcc_() { var msxifr = 0; return function() { ++msxifr; if (/*ICCD*/msxifr % 4 == 2) { dumpln('hit!'); try { o0.v0 = null; } catch(e0) { } try { Array.prototype.splice.apply(a2, [NaN, 0, i2]); } catch(e1) { } try { Array.prototype.forEach.apply(a2, [(function mcc_() { var kujnxn = 0; return function() { ++kujnxn; if (/*ICCD*/kujnxn % 9 == 1) { dumpln('hit!'); let g0.i1 = new Iterator(a0); } else { dumpln('miss!'); try { Object.preventExtensions(v1); } catch(e0) { } try { for (var p in h2) { /*MXX3*/g1.Uint8ClampedArray.prototype = g2.Uint8ClampedArray.prototype; } } catch(e1) { } for (var v of p1) { v2 + ''; } } };})(), g2.g2, i0]); } catch(e2) { } Array.prototype.pop.call(a0, m1); } else { dumpln('miss!'); t0 = t0.subarray(({valueOf: function() { v1 = evaluate(\"print(x);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 9 == 1), noScriptRval: x, sourceIsLazy: (x % 28 != 18), catchTermination: false, elementAttributeName: s2 }));return 16; }})); } };})();/*RXUB*/var r = r2; var s = \"00\"; print(s.search(r)); ");
/*fuzzSeed-133180449*/count=892; tryItOut("e1.delete(h0);");
/*fuzzSeed-133180449*/count=893; tryItOut("mathy3 = (function(x, y) { return (( - (mathy1((mathy0((( + Math.clz32(x)) | 0), mathy0(Math.fround(Math.atan2(Math.fround(Math.atanh(x)), ((((x | 0) % (y | 0)) | 0) >>> 0))), (Math.abs((-0x100000001 >>> 0)) >>> 0))) | 0), ((Math.max((Math.fround(( + x)) >>> 0), Math.fround((Math.fround((y || (y >>> 0))) ? Math.fround((((x ? Math.min(2**53+2, y) : (y | 0)) >>> 0) % x)) : Math.fround(Math.fround(Math.clz32(Math.fround(y))))))) >>> 0) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[ /x/g , NaN, NaN,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , NaN, NaN,  /x/g ,  /x/g , NaN, NaN,  /x/g ,  /x/g , NaN, NaN,  /x/g , NaN, NaN,  /x/g ,  /x/g , NaN,  /x/g ,  /x/g , NaN,  /x/g , NaN, NaN, NaN,  /x/g , NaN,  /x/g , NaN, NaN, NaN, NaN, NaN, NaN, NaN,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , NaN,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , NaN, NaN, NaN, NaN, NaN,  /x/g , NaN,  /x/g ,  /x/g , NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , NaN, NaN,  /x/g ,  /x/g ,  /x/g ,  /x/g , NaN, NaN, NaN, NaN,  /x/g , NaN,  /x/g , NaN,  /x/g ,  /x/g ,  /x/g , NaN,  /x/g , NaN, NaN, NaN,  /x/g , NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN,  /x/g ,  /x/g , NaN,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , NaN,  /x/g ]); ");
/*fuzzSeed-133180449*/count=894; tryItOut("for (var p in f0) { try { Object.defineProperty(this, \"o1.s2\", { configurable: timeout(1800), enumerable: \"\\uC64D\",  get: function() { e1.has(i1); return new String; } }); } catch(e0) { } /*MXX1*/o2 = g2.RegExp.lastMatch; }");
/*fuzzSeed-133180449*/count=895; tryItOut("\"use strict\"; t0.set(t1, ({valueOf: function() { g0.g1.v0 = a1.some(f2, o0.s0);return 6; }}));\nthis.v1 = g1.runOffThreadScript();\n");
/*fuzzSeed-133180449*/count=896; tryItOut("m2.delete(h0);");
/*fuzzSeed-133180449*/count=897; tryItOut("t1[[] == x] = x;");
/*fuzzSeed-133180449*/count=898; tryItOut("\"use strict\"; print(uneval(o2));");
/*fuzzSeed-133180449*/count=899; tryItOut("mathy4 = (function(x, y) { return (( + (((mathy0(((x + Math.fround(( + x))) | 0), ( + x)) | 0) ? Math.fround(y) : x) ? Math.fround((y >> y)) : ( ~ ( + mathy1((Math.sign(Math.fround(2**53)) | 0), (x | 0)))))) & (( - (mathy3(mathy2(Math.min(y, -0x100000001), Math.fround(Math.imul(Math.fround(Math.log2(( + x))), Math.fround(2**53)))), Math.asinh(x)) | 0)) | 0)); }); ");
/*fuzzSeed-133180449*/count=900; tryItOut("mathy3 = (function(x, y) { return ((((Math.exp((Math.min((( + ( ! (x << ( + mathy0((x >>> 0), (y >>> 0)))))) | 0), (((( ! Math.fround(( + x))) | 0) === (( ~ Math.sqrt(Math.max(x, -0x0ffffffff))) >>> 0)) | 0)) >>> 0)) >>> 0) >>> 0) === ( + (( - ((Math.atan2(Math.pow(y, Math.atan2((y >>> 0), y)), Math.fround(( ~ (mathy0((y | 0), (Math.sin(( + -(2**53+2))) | 0)) | 0)))) | 0) == (x >>> 0))) | 0))) >>> 0); }); testMathyFunction(mathy3, [2**53+2, 0, 1, -Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 0.000000000000001, -0, -0x07fffffff, 0x07fffffff, 2**53, -0x100000001, -0x080000000, 0/0, 1.7976931348623157e308, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, -0x0ffffffff, 0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, -(2**53+2), -0x080000001, -(2**53), Number.MAX_VALUE, 0x100000001, -(2**53-2), -0x100000000]); ");
/*fuzzSeed-133180449*/count=901; tryItOut("testMathyFunction(mathy4, [0x100000001, 0x07fffffff, Math.PI, -(2**53-2), 1/0, -0x0ffffffff, -0x100000001, -0, Number.MAX_VALUE, 2**53, 42, -(2**53), 1.7976931348623157e308, 0.000000000000001, -(2**53+2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, 0x080000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, 0x080000000, 1, -0x080000001, 2**53+2, -1/0, Number.MIN_VALUE, 0, -0x07fffffff, -0x100000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=902; tryItOut("Object.seal(this.a0);");
/*fuzzSeed-133180449*/count=903; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.tanh(((Math.atan2((Math.sinh(x) == y), Math.pow((x >> x), x)) - Math.fround(Math.max(Math.fround((Math.min((y != y), Math.fround(y)) ? (Math.atan((Math.pow(y, Math.round(Math.fround(x))) | 0)) | 0) : y)), Math.fround(2**53)))) >>> 0))); }); testMathyFunction(mathy4, [/0/, null, (new Boolean(true)), 1, objectEmulatingUndefined(), (new Number(-0)), true, '/0/', [0], '', false, (new Number(0)), ({toString:function(){return '0';}}), -0, ({valueOf:function(){return 0;}}), (new Boolean(false)), '0', ({valueOf:function(){return '0';}}), 0, (new String('')), undefined, (function(){return 0;}), '\\0', 0.1, NaN, []]); ");
/*fuzzSeed-133180449*/count=904; tryItOut(";\n/*ADP-3*/Object.defineProperty(a2, 12, { configurable: ((function  x ()window).call(y, function(id) { return id })), enumerable: (x % 3 == 1), writable: (x % 4 == 3), value: h2 });\n");
/*fuzzSeed-133180449*/count=905; tryItOut("const wwgyuq, fzzqtf, x = yield d, x, gpnzrw, rnewrn, siekje, qdeqww, abmvdl, x;b = (this)(arguments);f2.toString = (function() { try { e0.has(this.m2); } catch(e0) { } try { g1.offThreadCompileScript(\"o0.o2 = new Object;\"); } catch(e1) { } try { t1.__iterator__ = w; } catch(e2) { } o2 = Object.create(eval); throw a0; });");
/*fuzzSeed-133180449*/count=906; tryItOut("{a0.pop();s1 += 'x'; }");
/*fuzzSeed-133180449*/count=907; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000001, Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff, Number.MAX_VALUE, 0/0, 0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, -0x080000000, 1/0, -0x080000001, 0x080000000, Math.PI, -0x100000001, 0x100000000, -Number.MAX_VALUE, -1/0, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, 42, -0, -0x07fffffff, -0x100000000, -(2**53), -(2**53+2), 2**53+2, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=908; tryItOut("mathy1 = (function(x, y) { return ( + (( + ( ~ Math.fround(Math.sin(Math.fround(Math.imul(((x & (mathy0((x - Number.MIN_VALUE), y) >>> 0)) >>> 0), ((((Math.ceil((x >>> 0)) >>> 0) >>> 0) >> (y >>> 0)) >>> 0))))))) ? Math.atan2(Math.min(((Math.fround(Math.fround(Math.pow((y | 0), Math.fround(1/0)))) == Math.fround(Math.cos((( ! (x | 0)) >>> 0)))) | 0), Math.fround(( + Math.fround((( ! (x >>> 0)) >>> 0))))), ( ! Math.exp(y))) : ( + (( + Math.min(Math.hypot(Math.fround(y), Math.fround(Math.imul(Math.fround(mathy0(y, y)), 2**53-2))), ( + mathy0(x, ( + ( + mathy0(x, 2**53+2))))))) , ( + (((2**53-2 | 0) ** (Math.clz32(0x0ffffffff) ? (y <= Number.MIN_SAFE_INTEGER) : (x >>> 0))) | 0)))))); }); testMathyFunction(mathy1, [2**53+2, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 42, 1.7976931348623157e308, 0/0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000001, 1, -(2**53+2), -0, 0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 0.000000000000001, -0x0ffffffff, 2**53, -0x080000000, 0x100000001, 2**53-2, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0, -1/0, 0x080000000, 1/0, 0x100000000, Math.PI]); ");
/*fuzzSeed-133180449*/count=909; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - (Math.atan2(( ~ Math.min(x, Math.fround(Math.expm1((Number.MAX_SAFE_INTEGER | 0))))), x) ? (( + ( + (Math.imul(x, Math.fround(Math.atan2(y, y))) >>> 0))) == (( + ((( + x) + x) | 0)) | 0)) : (y === (( ~ Math.tanh(x)) | 0)))); }); testMathyFunction(mathy0, [0, -(2**53), 1, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, -0x100000000, 0x080000000, -0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53-2, -1/0, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER, 42, -0x100000001, -Number.MIN_VALUE, 0x080000001, 2**53, Number.MAX_VALUE, 2**53+2, -0x080000001, 0/0, 0x0ffffffff, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, Math.PI, 1/0, 0x100000000, -0, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=910; tryItOut("/*bLoop*/for (let jwmqsx = 0; jwmqsx < 40; ++jwmqsx) { if (jwmqsx % 3 == 0) { m0.get(f2); } else { /*RXUB*/var r = r2; var s = s2; print(s.replace(r, '\\u0341', \"gy\")); print(r.lastIndex);  }  } for (var v of b2) { try { s2 += s0; } catch(e0) { } for (var v of v0) { try { o0 = v1.__proto__; } catch(e0) { } t1 = new Int8Array(b0, 15, v0); } }");
/*fuzzSeed-133180449*/count=911; tryItOut("L:if(false) { if ((x--)) h2.get = eval;} else \"\\u1E85\";(false);");
/*fuzzSeed-133180449*/count=912; tryItOut("/*tLoop*/for (let x of /*MARR*/[[undefined], false, new String(''), new String(''), new String(''), false, false, x, x, new String(''), new String(''), 0x07fffffff, x]) { g2 + ''; }");
/*fuzzSeed-133180449*/count=913; tryItOut("/*RXUB*/var r = /(?![^])|\\3{3,7}|\\1*([^]|^){1,2}\\1+?/gyi; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=914; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-133180449*/count=915; tryItOut("this.o1.v2 = b2.byteLength;");
/*fuzzSeed-133180449*/count=916; tryItOut("a1.splice(NaN, 5);");
/*fuzzSeed-133180449*/count=917; tryItOut("testMathyFunction(mathy5, /*MARR*/[new Boolean(true), new new /./gyim(intern( \"\" ))(), new new /./gyim(intern( \"\" ))(), new Boolean(true), new new /./gyim(intern( \"\" ))(),  /x/ ]); ");
/*fuzzSeed-133180449*/count=918; tryItOut("testMathyFunction(mathy3, [Math.PI, 0x080000000, -0, 0/0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, 0x100000001, -1/0, -0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, -0x080000000, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, 0.000000000000001, 2**53-2, Number.MAX_VALUE, -(2**53), 0, -0x100000000, 0x080000001, 0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000001, 0x100000000, -(2**53+2), 1.7976931348623157e308, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=919; tryItOut("\"use strict\"; L:for(var z in ((function(y) { \"use strict\"; yield y; /*MXX1*/o1 = o0.g2.Int32Array;; yield y; })(Math.min(/[^]*\\3{0,}(?=\\w\\1)/gyi, 1)))){if(false) {print(x); } else  if (window) h1.valueOf = (function(j) { if (j) { try { ; } catch(e0) { } try { v2 = null; } catch(e1) { } try { Array.prototype.shift.apply(a2, [g0]); } catch(e2) { } i0 + g2.g2.p1; } else { e2.delete(w); } }); else {for (var v of m1) { try { Array.prototype.shift.call(a1); } catch(e0) { } try { let o2 = new Object; } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(m1, g1); }( \"\" ); } }");
/*fuzzSeed-133180449*/count=920; tryItOut("{ void 0; void schedulegc(this); } delete h2.getOwnPropertyNames;");
/*fuzzSeed-133180449*/count=921; tryItOut("b0 = t0.buffer;");
/*fuzzSeed-133180449*/count=922; tryItOut("/*RXUB*/var r = /(?:(^|[^]{3})|(?=(?!\\3))|^)+\\1|\\W|$|\\D+?|[^\\t-\u86d3\\cE-\u862a\\D]+{3}(?:\\2)/gyi; var s = \"AAAA\\u00a8__AAAA\\u00a8__AAAA\\u00a8__00\\n\\n\\u4f5c\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=923; tryItOut("\"use strict\"; /*vLoop*/for (let wmbfge = 0; (x) && wmbfge < 0; ++wmbfge) { const z = wmbfge; (({a: false})); } ");
/*fuzzSeed-133180449*/count=924; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.atan2((( + Math.atanh((( - Math.fround(Math.max(Math.fround(x), Math.fround(y)))) | 0))) ? mathy2((( ! y) >>> 0), mathy2((( ! Math.fround(y)) >>> 0), y)) : Math.asin(( + (( + Math.max(Math.sign(Math.fround(( - Math.fround(2**53)))), x)) >>> ( + (x >>> (x | 0))))))), Math.fround(( - Math.fround(((((( + ( + ( + Math.max(Math.fround(x), Number.MIN_VALUE)))) >>> 0) , ((Math.abs(Math.tanh(-1/0)) | 0) >>> 0)) >>> 0) / Math.atan2(Math.log10(( + Math.max(( + (x ? y : y)), y))), Math.fround(( + x))))))))); }); testMathyFunction(mathy5, [-(2**53), Number.MIN_VALUE, -1/0, 42, 0x100000000, 0x100000001, -(2**53+2), 0x080000000, -0x100000000, -Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, Math.PI, 1, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -(2**53-2), 2**53+2, 0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, -0x100000001, 1/0, -0x080000000, 2**53, 0/0, -0x080000001]); ");
/*fuzzSeed-133180449*/count=925; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.atan2(( + Math.sqrt(Math.fround((Math.sign((-1/0 | 0)) | 0)))), ( + ((Math.fround(( + Math.imul(((Math.fround(( + ( ! (Math.fround(Math.imul(x, (x != Math.fround(y)))) | 0)))) !== (x >>> 0)) >>> 0), (( ~ (((x >>> 0) << Math.pow(Math.pow(-(2**53-2), y), ( ! x))) >>> 0)) >>> 0)))) || Math.fround(Math.asin(y))) | 0))) >>> 0); }); testMathyFunction(mathy2, [0, -0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -0, 42, 2**53-2, Math.PI, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53+2), -0x0ffffffff, -(2**53-2), 1, Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, -1/0, 0/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, -(2**53), -0x100000001, 0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, -0x080000001, 1/0]); ");
/*fuzzSeed-133180449*/count=926; tryItOut("mathy4 = (function(x, y) { return (Math.tan((mathy1((( + Math.acosh(( + y))) | 0), (Math.sinh((( + (( - (Math.fround((Math.hypot(x, y) == Math.fround(y))) | 0)) | 0)) ? ( + Math.log((((x | 0) == (y | 0)) | 0))) : y)) | 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-133180449*/count=927; tryItOut("\"use strict\"; return (4277);");
/*fuzzSeed-133180449*/count=928; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ~ ((Math.fround(Math.fround(( + ( + ( ! (( ~ Math.fround(y)) >>> 0)))))) !== Math.fround(Math.fround((Math.sin(x) << y)))) >>> 0)) | 0); }); ");
/*fuzzSeed-133180449*/count=929; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.min(Math.fround(mathy2(Math.fround(( - ( + ( - x)))), mathy1(( ~ ((mathy0((y | 0), x) >>> 0) >>> 0)), Math.fround(Math.max(Math.fround(( + ((0/0 >>> 0) | x))), y))))), Math.fround(Math.cosh(( ! ((-0x100000001 && x) << ((Math.log10((y | 0)) >>> 0) >>> Math.max(y, y)))))))); }); testMathyFunction(mathy3, [42, -Number.MAX_VALUE, -0x100000001, -0x07fffffff, 0x07fffffff, -0x100000000, Number.MIN_VALUE, 1/0, 1, 0/0, Math.PI, 2**53-2, -0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -1/0, 2**53, 0, Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -(2**53+2), 2**53+2, -0x080000001, -(2**53), 0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, -0x080000000, 0x100000000, -(2**53-2), 0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=930; tryItOut("/*infloop*/ for  each(var x in delete x.b) /*vLoop*/for (let hmpzss = 0; hmpzss < 8; ++hmpzss) { const w = hmpzss; print((uneval(/*UUV2*/(w.__lookupSetter__ = w.pow)))); } ");
/*fuzzSeed-133180449*/count=931; tryItOut("\"use strict\"; print(uneval(m2));");
/*fuzzSeed-133180449*/count=932; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = ((((((!((0xcfa5cf6b) ? (0xfe433ecc) : (0xffffffff)))-(!(i1))) ^ ((0xbce11c33) % (0x5a2dd698))) / (abs((abs((((0xc9de7ea7)-(0x3fe1f581)-(0xfc2b5426)) | ((0xffffffff)-(0x7e9b3de0))))|0))|0))>>>((i1)-(i0))));\n    {\n      {\n        {\n          i2 = (i0);\n        }\n      }\n    }\n    i1 = ((((i2)+(i1))>>>((i1))) == (0xad6b91e9));\n    return ((0xc4c25*((((0x4d0b7c80) / (((!(0xfaf95148)))>>>(((0x2cd94534) ? (0x2be49ea5) : (0x5d4f3b8b))))) | ((i1)-((0xf58455a0) != (0xb5cf822))+(/*FFI*/ff(((imul((-0x8000000), (0xad8076ca))|0)), ((imul((0x9b1393af), (-0x8000000))|0)), ((-576460752303423500.0)), ((-2048.0)))|0))) > (((i0))|0))))|0;\n  }\n  return f; })(this, {ff: (4277)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=933; tryItOut("Object.defineProperty(this, \"v1\", { configurable: (x % 22 == 20), enumerable: true,  get: function() {  return evalcx(\"t2 = new Uint8ClampedArray(t0);\", g2); } });");
/*fuzzSeed-133180449*/count=934; tryItOut("Object.defineProperty(this, \"g0.t0\", { configurable: e, enumerable: (x % 3 != 0),  get: function() {  return t2.subarray(3); } });");
/*fuzzSeed-133180449*/count=935; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return Math.sqrt((( ! Math.fround(Math.fround(Math.hypot(Math.fround(Math.fround(Math.sin(Math.fround(( ! Math.PI))))), Math.fround(( + ( ! ( + (Math.tanh((((x ? x : ( + 0)) >>> 0) >>> 0)) | 0))))))))) | 0)); }); testMathyFunction(mathy1, /*MARR*/[false, -0x07fffffff, 3, false, -0x07fffffff, -0x07fffffff, 3, false, 3, -0x07fffffff, 3, false, false, 3, false, false, 3, 3, -0x07fffffff]); ");
/*fuzzSeed-133180449*/count=936; tryItOut("m2.delete(o1.o1);/* no regression tests found */");
/*fuzzSeed-133180449*/count=937; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-133180449*/count=938; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Number.MIN_VALUE, 0x100000000, 0x080000000, -0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, 2**53, -0, 0x080000001, Math.PI, -0x100000000, 1, -1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000001, -(2**53-2), 0, 0x0ffffffff, 1/0, 2**53-2, -(2**53), 0x100000001, -Number.MAX_VALUE, -0x080000001, -(2**53+2), -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=939; tryItOut("for (var v of b0) { try { v2 = (v2 instanceof g1.h2); } catch(e0) { } for (var p in e0) { v1 = t2.BYTES_PER_ELEMENT; } }");
/*fuzzSeed-133180449*/count=940; tryItOut("mathy3 = (function(x, y) { return Math.expm1(( ~ ( + mathy0((mathy1(Math.trunc((-0x0ffffffff >>> 0)), y) | 0), ( + 0x080000000))))); }); testMathyFunction(mathy3, [1.7976931348623157e308, Math.PI, Number.MAX_VALUE, -0x100000001, -0x080000000, 0x080000001, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53+2), 0, -0x100000000, -(2**53), 42, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0, 2**53, -Number.MIN_SAFE_INTEGER, 0x100000000, 1, Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 2**53+2, 0/0, -0x07fffffff, -1/0, Number.MIN_VALUE, -0x080000001, 0.000000000000001, 1/0, 0x100000001, 2**53-2, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=941; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.acosh(((( + Math.tan((x | 0))) * ( + ( + (((0.000000000000001 , Math.pow(1, y)) != (Math.acosh(y) >>> 0)) >>> 0)))) >>> 0))) || Math.fround((( + ( - x)) && ( ~ (( - ((y << y) | 0)) | 0)))))); }); testMathyFunction(mathy3, [2**53, 42, 1.7976931348623157e308, 2**53+2, -1/0, Math.PI, -0x080000001, 0x07fffffff, -0x100000000, -0x100000001, Number.MIN_VALUE, 0x0ffffffff, 0/0, -(2**53+2), 1/0, -(2**53-2), 0.000000000000001, 0x100000000, -0x0ffffffff, 0x080000000, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, 0x100000001, Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53-2, 1, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=942; tryItOut("testMathyFunction(mathy1, [0/0, 0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -(2**53+2), -0x07fffffff, 1, 0, -Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, 2**53-2, -1/0, -0, 0x07fffffff, 1.7976931348623157e308, 42, -(2**53-2), 2**53, -0x080000000, Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, 1/0, 0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-133180449*/count=943; tryItOut("this.t0[v0] = g1.a1;");
/*fuzzSeed-133180449*/count=944; tryItOut("if(true) Object.defineProperty(this, \"t2\", { configurable: false, enumerable: true,  get: function() {  return new Uint8ClampedArray(g0.b0, 48, 10); } }); else  if (x) {;b0.__iterator__ = String.prototype.fontcolor.bind(b0); } else {s2 += g2.s0;/*RXUB*/var r = r0; var s = s1; print(s.search(r));  }");
/*fuzzSeed-133180449*/count=945; tryItOut("\"use strict\"; a0.forEach((function mcc_() { var nuwagl = 0; return function() { ++nuwagl; f0(/*ICCD*/nuwagl % 10 == 8);};})(), v0, g0.i1, m2);");
/*fuzzSeed-133180449*/count=946; tryItOut("\no2.m0.delete(t0);");
/*fuzzSeed-133180449*/count=947; tryItOut("testMathyFunction(mathy0, [0, '0', '\\0', (new Number(0)), [], (new Boolean(true)), '/0/', ({toString:function(){return '0';}}), (new Number(-0)), [0], NaN, objectEmulatingUndefined(), '', 1, (new Boolean(false)), true, (function(){return 0;}), (new String('')), ({valueOf:function(){return '0';}}), false, ({valueOf:function(){return 0;}}), /0/, undefined, null, -0, 0.1]); ");
/*fuzzSeed-133180449*/count=948; tryItOut("mathy0 = (function(x, y) { return ( + (( + ((Math.atanh((((x >>> 0) <= ((( + 0x07fffffff) >>> 0) >>> 0)) >>> 0)) ? (Math.log(Math.log10(( + Math.hypot(1.7976931348623157e308, x)))) - 0x0ffffffff) : (( - (Math.max(Math.atan2(-0x080000001, y), x) >>> 0)) >>> 0)) | 0)) & ( + Math.fround(Math.exp(Math.fround((( + Math.fround((Math.fround(Math.fround(Math.imul(Math.fround(( - Number.MAX_SAFE_INTEGER)), 0x07fffffff))) >>> Math.fround((Math.cos((y | 0)) | 0))))) ? Math.fround(Math.hypot(( + Math.cos(( + (Math.atan2(((( ~ (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) | 0), y) | 0)))), (( - (Math.tan(Math.sqrt(y)) | 0)) | 0))) : Math.fround((Math.fround(( ! x)) ? (Math.log((( + Math.atanh(y)) , Math.fround(Math.ceil(-(2**53-2))))) >>> 0) : Math.expm1(Math.imul(x, (2**53+2 >>> y)))))))))))); }); testMathyFunction(mathy0, [42, -(2**53+2), 0/0, Number.MIN_VALUE, 0, 2**53-2, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, -(2**53-2), -1/0, 0.000000000000001, 2**53, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0x07fffffff, 0x0ffffffff, -0x080000000, Number.MAX_VALUE, 0x080000000, 2**53+2, 1.7976931348623157e308, 1, -Number.MAX_VALUE, -0x0ffffffff, -(2**53), 0x080000001, 0x100000001, Math.PI, -0x07fffffff, -0x100000001]); ");
/*fuzzSeed-133180449*/count=949; tryItOut("f0 = t1[5];");
/*fuzzSeed-133180449*/count=950; tryItOut("\"use strict\"; s0 += 'x';\nfor (var p in o1) { try { v0 = t2.length; } catch(e0) { } ; }\n");
/*fuzzSeed-133180449*/count=951; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, 42, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000000, Math.PI, 2**53-2, 0x080000000, -(2**53), -0x080000001, 0x0ffffffff, -Number.MAX_VALUE, -0x080000000, 1/0, -1/0, 0x100000001, Number.MAX_VALUE, -0, 2**53+2, -0x100000001, -(2**53-2), -0x07fffffff, 0x07fffffff, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1]); ");
/*fuzzSeed-133180449*/count=952; tryItOut("var r0 = x % x; var r1 = x & 4; x = x - r0; var r2 = r0 * r1; var r3 = x + x; var r4 = r0 - 4; print(r1); ");
/*fuzzSeed-133180449*/count=953; tryItOut("a0 = arguments;");
/*fuzzSeed-133180449*/count=954; tryItOut("this.o2.v0 = (h1 instanceof b0);");
/*fuzzSeed-133180449*/count=955; tryItOut("Object.prototype.watch.call(g2.m2, \"3\", this.o0.f0);");
/*fuzzSeed-133180449*/count=956; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=957; tryItOut("return;w = void (false.watch(\"call\", encodeURIComponent));b1 = h1;");
/*fuzzSeed-133180449*/count=958; tryItOut("a2[timeout(1800)] = z.join(new (makeFinalizeObserver('tenured'))(), timeout(1800));");
/*fuzzSeed-133180449*/count=959; tryItOut("/*hhh*/function wrdsgk(x, e, x, [], x, x, b, d, NaN, x, e, d, eval, z, x, c = this, z, NaN, window, b, x, x, w, x, eval, eval = [,,], x, \u3056, NaN, x, d, x, \u3056 = undefined, d = \"\\uC1B1\", x = {}, x =  '' , b, x, x, y, x, delete, x, c, x, x, x, x, window, NaN, x, y, c, a, e =  '' , window, NaN, NaN =  '' , d, x, x, y, eval, x, x, b = true, x, x, x, 9, set, -19, x, a, x = this, x, \u3056, eval, c, d = false, x, x, \u3056, x, window, x, b){qpjfqx((/*FARR*/[/(?=\\1)/gi, ...[], ...[], , ...[], undefined].filter(objectEmulatingUndefined, true))(), Math.tan(('fafafa'.replace(/a/g, (Function).bind())).unwatch(\"indexOf\")));/*hhh*/function qpjfqx(x, c){b1[\"1\"] = s2;\nM:switch((window =  \"\" )) { case undefined: ;a1.splice(10, 19);case 8: default: e1 = new Set(a0);break; break;  }\n}}wrdsgk(((void options('strict'))), x = /((?!(?!^){3,3}|.))|[^]+[^]|\\S+?|(\\B?)+??/g);");
/*fuzzSeed-133180449*/count=960; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return mathy1(Math.fround(Math.cosh(mathy0((Math.fround((x + y)) | 0), (x | 0)))), mathy0((( ! (y >>> 0)) >>> 0), (( - Math.atan2((mathy1(((Math.sinh(Math.fround(y)) >>> 0) >>> 0), x) >>> 0), ( + Math.cos(Math.hypot(x, x))))) | 0))); }); testMathyFunction(mathy4, [2**53+2, -0x080000001, Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 1/0, -(2**53), -0x080000000, Math.PI, 0.000000000000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53+2), -0x100000001, -0, 0x07fffffff, 0/0, 2**53, 0x080000000, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, -0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 1, -1/0, 42, -0x100000000, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=961; tryItOut("a1 = x;");
/*fuzzSeed-133180449*/count=962; tryItOut("c = new RegExp(\"[\\\\S\\\\W\\\\W\\u00b4][^\\\\A\\\\S\\\\B-\\ue604][^]*|[^\\u0085\\\\cS]*?|^|[^]{3,}\", \"gym\");throw 23;(/^{4}/m);");
/*fuzzSeed-133180449*/count=963; tryItOut("\"use strict\"; switch((4277)) { case 0: for (var p in o2) { try { Array.prototype.shift.call(a0, window, o1); } catch(e0) { } try { e1.add( '' ); } catch(e1) { } try { this.v1 = g1.eval(\"d;\"); } catch(e2) { } v1 = a1.length; }break;  }");
/*fuzzSeed-133180449*/count=964; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return Math.atan2(( + (( + Math.max(( + x), ( + (Math.imul((x >>> 0), (((y >>> 0) >>> (1 >>> 0)) >>> 0)) >>> 0)))) === ( + (( ~ Math.fround((mathy1(mathy2(x, (x | 0)), (Math.pow((x >>> 0), (y >>> 0)) >>> 0)) & ( - -(2**53+2))))) >>> 0)))), ( + Math.hypot(Math.fround(( ! (((y | 0) && (0x080000000 | 0)) | 0))), ((( ~ (( - (Math.tan(x) >>> 0)) | 0)) | 0) >>> 0)))); }); ");
/*fuzzSeed-133180449*/count=965; tryItOut("\"use strict\"; let(hbwdwz, x = (uneval(\"\\uFFD4\")), pouffc, ynlquq, NaN, bpxuad, umdscc) ((function(){with({}) { for(let e in []); } })());for(let w of ( ''  >>> new RegExp(\".\", \"g\"))) return;");
/*fuzzSeed-133180449*/count=966; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( - (( ~ (Math.expm1((Math.fround((Math.fround(( ! ((((((-Number.MIN_SAFE_INTEGER | 0) << -1/0) >>> 0) >>> 0) ? x : (y >>> 0)) >>> 0))) , Math.fround(( + Math.acosh(( + x)))))) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53-2), 0x100000001, Number.MAX_SAFE_INTEGER, 0, 1, 0/0, 0x07fffffff, -0x080000001, 0x080000000, 1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, -1/0, 2**53-2, 0x080000001, 2**53+2, 42, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, -0x07fffffff, 0x100000000, -0x0ffffffff, 2**53, Number.MAX_VALUE, -(2**53), -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, -0x080000000, Math.PI, -0x100000000]); ");
/*fuzzSeed-133180449*/count=967; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.reverse.apply(o1.o0.a1, [({x: ([] = (void options('strict')))}), v1]);");
/*fuzzSeed-133180449*/count=968; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=969; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy3(( + ( ~ ( + Math.asinh((-0x100000001 * (x | 0)))))), (Math.asinh(( + Math.log10((Math.asin(( + ( + Math.max((Number.MAX_SAFE_INTEGER | 0), (Number.MIN_SAFE_INTEGER | 0))))) | 0)))) >>> 0)); }); testMathyFunction(mathy5, [-(2**53+2), -1/0, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0/0, 0, 42, 1, 0x100000001, 0x080000001, -0x0ffffffff, 2**53, -0x080000000, 1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000001, -0, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53-2, -(2**53-2), Math.PI, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, -(2**53), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, -0x07fffffff]); ");
/*fuzzSeed-133180449*/count=970; tryItOut("/*infloop*/M: for  each(Number.prototype.toLocaleString in \nx) {/*vLoop*/for (let lhhrim = 0; lhhrim < 23; ++lhhrim) { const c = lhhrim; o1.a1 + this.o0; } print(x); }");
/*fuzzSeed-133180449*/count=971; tryItOut("/*tLoop*/for (let e of /*MARR*/[arguments, ({}), arguments, ({}), undefined, undefined, undefined, arguments]) { for (var p in t2) { try { e2 + ''; } catch(e0) { } try { i2.next(); } catch(e1) { } g1.offThreadCompileScript(\"print(e);\"); } }");
/*fuzzSeed-133180449*/count=972; tryItOut("mathy3 = (function(x, y) { return Math.imul((Math.cos(Math.fround(( - ( + mathy1(Number.MIN_SAFE_INTEGER, y))))) >>> 0), ((( + Math.pow(y, x)) == Math.fround(Math.atanh(mathy0((( + (Math.imul((y >>> 0), (y >>> 0)) >>> 0)) < x), Math.atan2(x, Math.log2(Number.MAX_SAFE_INTEGER)))))) >>> 0)); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x080000000, 2**53, 2**53-2, -(2**53+2), 2**53+2, 0/0, 0x100000000, -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 0x100000001, 0, -Number.MIN_VALUE, 42, -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -1/0, 1/0, -(2**53), -0, 0.000000000000001, 1.7976931348623157e308, -(2**53-2), -0x100000000, Number.MIN_VALUE, -0x100000001, 1, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=973; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.atan2(( + Math.acosh(( + Math.max(mathy1((x | 0), (( + Math.log10(( + y))) | 0)), ( ! x))))), (( ! (Math.sign(y) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy2, [0x080000000, 2**53, Math.PI, 0/0, -(2**53), 0, 1/0, -Number.MAX_VALUE, -(2**53-2), 1, -1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0.000000000000001, 0x100000001, -0x080000000, -0x07fffffff, 42, 2**53-2, -(2**53+2), -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, -0x080000001, -0, 0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=974; tryItOut("\"use strict\"; Object.freeze(e1);v0 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-133180449*/count=975; tryItOut("\"use strict\"; v2 = evaluate(\"a0.push(h1, e1, t0, p0, s2, v1, s1, this.i0, o0, a2);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /*UUV2*/(eval.toTimeString = eval.for), noScriptRval: (x % 24 == 8), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-133180449*/count=976; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=977; tryItOut("for (var v of p2) { try { /*MXX3*/g2.Number = g1.Number; } catch(e0) { } try { /*ODP-2*/Object.defineProperty(b1, \"e\", { configurable: x, enumerable: false, get: f0, set: new Function }); } catch(e1) { } a0.splice(NaN, 19); }");
/*fuzzSeed-133180449*/count=978; tryItOut("v0 = Object.prototype.isPrototypeOf.call(m0, h1);");
/*fuzzSeed-133180449*/count=979; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=980; tryItOut("\"use strict\"; var soasrl = new ArrayBuffer(4); var soasrl_0 = new Uint16Array(soasrl); soasrl_0[0] = 18; var soasrl_1 = new Float64Array(soasrl); soasrl_1[0] = -19; var soasrl_2 = new Int16Array(soasrl); soasrl_2[0] = -17; var soasrl_3 = new Uint8Array(soasrl); print(soasrl_3[0]); soasrl_3[0] = -3; var soasrl_4 = new Uint8ClampedArray(soasrl); soasrl_4[0] = 6; var soasrl_5 = new Uint16Array(soasrl); var soasrl_6 = new Uint8Array(soasrl); var soasrl_7 = new Uint32Array(soasrl); e1.delete(g1.m1);new RegExp(\"\\\\3\", \"gm\");h2 + t0;return;print((q => q)());v1 = g1.runOffThreadScript();print(soasrl_5[10]);Array.prototype.shift.call(a1, i0);(new RegExp(\"[^]|(?:(?!(?!\\u00a9|.{2,})))(?!(?!(?!(?!\\\\W)){3}))\", \"\"));const v2 = Array.prototype.reduce, reduceRight.apply(a0, [f2, o0.a2, o2, p0, g1, e0, i2, t1]);undefined;");
/*fuzzSeed-133180449*/count=981; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy1(Math.hypot((Math.fround((mathy3(((( - ( + -Number.MIN_VALUE)) | 0) >>> 0), (( ~ ((x ^ Math.fround(y)) | 0)) >>> 0)) << Math.fround(Math.fround(Math.min(Math.fround(Math.fround(Math.cos(Math.fround((Math.hypot(Math.PI, (y >>> 0)) >>> 0))))), x))))) | 0), (( + mathy4(( + Math.fround(Math.log(((Math.fround(x) << (Math.min(( + 0x080000000), Math.fround(Math.hypot(x, x))) >>> 0)) >>> 0)))), ( + Math.exp(Math.fround(mathy0(Math.fround(x), Math.fround(y))))))) | 0)), Math.log10(( ~ (Math.hypot((x >>> 0), (y >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -(2**53+2), 0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 0x080000000, -Number.MIN_VALUE, -1/0, 1/0, 2**53+2, 0.000000000000001, -Number.MAX_VALUE, 0x07fffffff, -0, 42, 1, 2**53, -0x080000000, 2**53-2, 0/0, -(2**53-2), Number.MIN_VALUE, -(2**53), Math.PI, -0x080000001]); ");
/*fuzzSeed-133180449*/count=982; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 9223372036854776000.0;\n    i1 = (i1);\n    switch ((abs((~((i1)+(i1))))|0)) {\n      case -2:\n        {\n          {\n            d0 = (d0);\n          }\n        }\n        break;\n    }\n    return +((d0));\n  }\n  return f; })(this, {ff: Object.getOwnPropertyNames}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000000, 0/0, -0x080000000, 2**53, -0x100000001, 1, -(2**53), -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, -0, 1/0, Number.MIN_VALUE, 2**53+2, -(2**53-2), -0x0ffffffff, -(2**53+2), 0.000000000000001, 0x07fffffff, 0, 0x0ffffffff, 2**53-2, Number.MAX_VALUE, 0x080000000, Math.PI, -0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, 42, 1.7976931348623157e308]); ");
/*fuzzSeed-133180449*/count=983; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((abs(((0xce812*(0x766efd67)) & (((31.0) == (+pow(((-5.0)), ((-1.0009765625)))))-(0x79189828))))|0) < (((((+abs(((Float32ArrayView[4096]))))))-(-0x8000000)) << ((Uint16ArrayView[((((((0xffffffff)) << ((0xea201715)))))+((((0xfbe1f3a9))>>>((0xa12f108c))) > (0x90dc00cc))) >> 1]))));\n    (x) = ((0xffffffff) / (0xc603dfee));\n    d1 = (-524289.0);\n    return +((d1));\n    return +((+((-1.00390625))));\n  }\n  return f; })(this, {ff: Array.prototype.reduce}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=984; tryItOut("testMathyFunction(mathy5, [-0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -0x100000001, 0x100000000, -0x100000000, -(2**53+2), 1, 2**53-2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, -Number.MAX_VALUE, 1/0, 0x080000001, 2**53+2, Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, -0, -(2**53-2), 0, Math.PI, -(2**53), -0x0ffffffff, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, 0/0]); ");
/*fuzzSeed-133180449*/count=985; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.sinh((( + Math.min(((Math.fround(( + x)) * Math.fround(( + Math.clz32(Math.max(Math.fround(y), Math.fround(x)))))) >>> 0), (Math.fround(( - (x ? ( + Math.fround((x === Math.atan2(y, y)))) : (-(2**53-2) ? 2**53 : x)))) >>> 0))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), \"\\u4068\" += ({}), objectEmulatingUndefined(), \"\\u4068\" += ({}), eval, objectEmulatingUndefined(), objectEmulatingUndefined(), eval, objectEmulatingUndefined(), objectEmulatingUndefined(), \"\\u4068\" += ({}), eval, \"\\u4068\" += ({}), \"\\u4068\" += ({}), \"\\u4068\" += ({}), eval, objectEmulatingUndefined(), objectEmulatingUndefined(), eval, \"\\u4068\" += ({}), \"\\u4068\" += ({}), objectEmulatingUndefined(), eval, eval, eval, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), eval, \"\\u4068\" += ({}), eval, eval, eval, objectEmulatingUndefined(), eval, objectEmulatingUndefined(), eval, eval, objectEmulatingUndefined(), eval, objectEmulatingUndefined(), eval, eval, \"\\u4068\" += ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), eval, eval, objectEmulatingUndefined(), \"\\u4068\" += ({}), eval, \"\\u4068\" += ({}), eval, eval, objectEmulatingUndefined(), \"\\u4068\" += ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), \"\\u4068\" += ({}), \"\\u4068\" += ({}), \"\\u4068\" += ({}), \"\\u4068\" += ({}), \"\\u4068\" += ({}), objectEmulatingUndefined(), objectEmulatingUndefined(), eval, eval, eval, objectEmulatingUndefined(), eval, objectEmulatingUndefined(), \"\\u4068\" += ({}), \"\\u4068\" += ({}), \"\\u4068\" += ({}), \"\\u4068\" += ({}), eval, \"\\u4068\" += ({}), \"\\u4068\" += ({})]); ");
/*fuzzSeed-133180449*/count=986; tryItOut("for (var v of o2) { try { a2.reverse(); } catch(e0) { } try { a0 = g0.a0[18]; } catch(e1) { } g0.offThreadCompileScript(\"e0.valueOf = (function() { for (var j=0;j<79;++j) { f2(j%5==1); } });\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 17 == 2), noScriptRval: false, sourceIsLazy: (x % 6 == 4), catchTermination: (({\"28\"\u000c: (e = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: RangeError, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: undefined, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: (arguments.callee.caller).apply, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function shapeyConstructor(bnhcwc){\"use strict\"; bnhcwc[\"__parent__\"] =  \"\" ;bnhcwc[\"toSource\"] = this;bnhcwc[\"toSource\"] = 1;if (22) delete bnhcwc[\"toFixed\"];bnhcwc[\"toSource\"] = false;bnhcwc[new String(\"13\")] = x;return bnhcwc; }, keys: function() { return Object.keys(x); }, }; })(\"\\u4E43\"), x)) })) })); }");
/*fuzzSeed-133180449*/count=987; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]\", \"yi\"); var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=988; tryItOut("mathy4 = (function(x, y) { return ( ~ (((Math.pow((Math.min(x, (( + Math.cbrt((Number.MAX_VALUE >>> 0))) >>> 0)) >>> 0), (Math.fround(((y | 0) ? ((x / ((((( + x) & (y >>> 0)) >>> 0) ? (( + Math.log10(( + x))) >>> 0) : (( - y) >>> 0)) >>> 0)) | 0) : (y | 0))) >>> 0)) >>> 0) ? Math.cbrt(Math.acos(Math.ceil((mathy1(( - x), x) | 0)))) : mathy3((( + (( + (( + y) >> ( + x))) | 0)) | 0), Math.fround(mathy1(Math.fround(Math.min(Math.cbrt(((0x080000001 ? x : y) >>> 0)), ( + 0x100000000))), Math.fround(1/0))))) | 0)); }); testMathyFunction(mathy4, [1, (new Number(-0)), -0, ({valueOf:function(){return '0';}}), false, objectEmulatingUndefined(), NaN, [], '/0/', (new Boolean(false)), (new String('')), '', null, 0, ({valueOf:function(){return 0;}}), (new Number(0)), (new Boolean(true)), (function(){return 0;}), [0], /0/, ({toString:function(){return '0';}}), 0.1, true, '0', '\\0', undefined]); ");
/*fuzzSeed-133180449*/count=989; tryItOut("Object.defineProperty(o2.o0, \"v0\", { configurable: false, enumerable: true,  get: function() {  return undefined; } });");
/*fuzzSeed-133180449*/count=990; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.cos(Math.fround(Math.sign(( + Math.tanh(x)))))); }); testMathyFunction(mathy1, [0x07fffffff, 0x080000001, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, 1, 1/0, -0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, -0x100000000, -1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, -0x100000001, -(2**53-2), -0, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53-2, 42, 0.000000000000001, 0x100000000, -0x0ffffffff, -Number.MAX_VALUE, Math.PI, -0x07fffffff, 1.7976931348623157e308, 0, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=991; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.sign((Math.clz32(( ~ (Math.atanh((Math.max(((Math.fround(-Number.MAX_VALUE) << (x >>> 0)) >>> 0), (-Number.MAX_SAFE_INTEGER | 0)) >>> 0)) | 0))) | 0)) | 0); }); testMathyFunction(mathy0, [0x0ffffffff, 0x07fffffff, -(2**53+2), Math.PI, 0x100000001, 2**53-2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, 42, Number.MAX_VALUE, 1, 0x080000001, -0x100000001, -0x100000000, 0x080000000, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, 1/0, -0x080000000, -(2**53), Number.MIN_VALUE, -1/0, -0, -0x080000001, 0x100000000, 2**53+2]); ");
/*fuzzSeed-133180449*/count=992; tryItOut("testMathyFunction(mathy3, [2**53+2, -0x100000000, 0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, -0, -1/0, 0x100000001, 0/0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x080000000, -0x0ffffffff, -0x100000001, 0x080000001, 2**53-2, 1/0, -(2**53-2), -(2**53), 0x080000000, 0x100000000, Number.MAX_VALUE, 0.000000000000001, 0, 2**53, Math.PI, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=993; tryItOut("\"use strict\"; /*vLoop*/for (var ukqasw = 0; ukqasw < 131; ++ukqasw) { const e = ukqasw; t2[10] = p0\n } ");
/*fuzzSeed-133180449*/count=994; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 137438953471.0;\n    d1 = (d2);\n    d2 = (NaN);\n    (Float32ArrayView[((0xfd22cf69)) >> 2]) = ((d2));\n    d1 = (+((((((i0)+(!(!(i0)))) ^ ((0x8b88a49))))-(0xf2632387))));\n    i0 = ((Float32ArrayView[1]));\n    d1 = (d2);\n    return ((((imul((0xfeaa275b), (0x9d482b50))|0) >= (((0x977673e7)+(!((~((/*FFI*/ff(((2251799813685249.0)))|0)))))) | ((i0)-(i0))))+((((0xffffffff) / (((Int32ArrayView[4096]))>>>((i0))))>>>((0xffffffff)*-0xfffff)))))|0;\n  }\n  return f; })(this, {ff: encodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53), -0x080000000, 0x07fffffff, Number.MIN_VALUE, -0x080000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000001, Math.PI, 1, -0x100000001, 42, Number.MAX_SAFE_INTEGER, 0, 2**53, -(2**53+2), Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_VALUE, 1/0, 2**53+2, -Number.MAX_VALUE, 0x080000001, -0x100000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, 0x0ffffffff, -1/0, -0, -0x0ffffffff, 2**53-2, 0/0]); ");
/*fuzzSeed-133180449*/count=995; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(( + ( + (( + ((( + ( - (Math.fround(Math.tan(x)) >>> 0))) | 0) ** ( + ( + (Math.fround(( - x)) >>> 0))))) != (( + (x ? Math.cbrt((Math.expm1(mathy1((x >>> 0), 0x0ffffffff)) >>> 0)) : Math.trunc((y < -(2**53))))) | 0))))); }); ");
/*fuzzSeed-133180449*/count=996; tryItOut("\"use strict\"; this.g2.v1 = true;");
/*fuzzSeed-133180449*/count=997; tryItOut("\"use strict\"; s1 += 'x'\nv0 = evalcx(\"/* no regression tests found */\", this.g1);");
/*fuzzSeed-133180449*/count=998; tryItOut("mathy4 = (function(x, y) { return Math.fround((( + mathy3(( + (mathy3((Math.min((Math.hypot((y >>> 0), x) >>> 0), y) | 0), mathy1(y, (Math.expm1(y) | 0))) >>> 0)), (Math.fround(( - (Math.acos(Math.acosh(( - 42))) | 0))) >>> 0))) << Math.fround(Math.min((Math.fround(Math.acosh(Math.fround(y))) >>> 0), mathy0(( + Math.imul(( + 0x100000000), ( + x))), ( + Math.clz32(( + (Math.log10((-1/0 == 0x100000000)) || ((y >>> y) >>> 0)))))))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 1/0, 0x080000001, 0, -0x080000001, Math.PI, -0x07fffffff, -1/0, -0x100000001, 1.7976931348623157e308, -0x100000000, 0x080000000, 0x100000000, 0x100000001, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, 42, 1, 0x0ffffffff, -Number.MAX_VALUE, -0x080000000, 2**53-2, -0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -(2**53), 2**53, -Number.MIN_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=999; tryItOut("/*RXUB*/var r = r0; var s = s1; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=1000; tryItOut("mathy4 = (function(x, y) { return ((Math.fround(Math.pow(((((Math.fround((mathy1(x, (( + mathy3((x | 0), (x | 0))) >>> 0)) ? x : ( + (mathy1((0x0ffffffff | 0), (1 | 0)) >>> 0)))) | 0) - (Math.min(( + (( - mathy1(y, Number.MAX_VALUE)) >>> 0)), (Math.atan2(y, -Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0)) | 0) >>> 0), (Math.atan2(((Math.sin(0x07fffffff) | 0) ? y : ( ! (( ~ (Number.MIN_VALUE >>> 0)) >>> 0))), ((Math.pow((Math.sqrt(mathy2(y, y)) >>> 0), ( ! (Number.MIN_VALUE >>> 0))) ? Math.atan2((x | 0), Math.pow(x, (0x100000001 <= y))) : x) | 0)) | 0))) | (( ! (( ! ( + Math.min(( + (Math.round((( + y) & ( + x))) | 0)), ( + Number.MAX_VALUE)))) >>> 0)) >>> 0)) | 0); }); testMathyFunction(mathy4, [0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, 2**53, -(2**53+2), 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 0x0ffffffff, 42, -0x100000001, 0/0, 0x100000001, 1, -Number.MAX_VALUE, 0x100000000, -0x080000001, -1/0, -0, 1/0, Number.MIN_VALUE, -0x100000000, 0.000000000000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, Math.PI, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=1001; tryItOut("\"use strict\"; x;this;");
/*fuzzSeed-133180449*/count=1002; tryItOut("\"use strict\"; (y =>  { \"use strict\"; yield this } ());");
/*fuzzSeed-133180449*/count=1003; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.hypot(Math.round((Math.fround(( ! ( + Math.imul((Math.fround(Math.atan2(Math.fround(y), Math.fround((((x >>> 0) >= x) | 0)))) | 0), ((x - ( + x)) | 0))))) | 0)), Math.hypot(( + ( + ( + (Math.min((y | 0), (x | 0)) | 0)))), (Math.atanh((( ~ -0x100000001) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [0/0, -(2**53+2), 0.000000000000001, -1/0, Number.MIN_VALUE, 0x100000000, -Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, -(2**53-2), -(2**53), 0x100000001, -Number.MAX_VALUE, 2**53+2, 1/0, -Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, 2**53, 2**53-2, 42, 1, 0x080000001, 1.7976931348623157e308, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -0, 0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1004; tryItOut("switch(/*RXUE*//(?:[^]{4097,})$*?|(?:(?=.{0}))/gy.exec(\"\") << /*FARR*/[ /x/ , (function ([y]) { })(), new RegExp(\"[^]|(?!(?:[^\\uee0a\\\\B-\\\\b]){3,}[^\\\\f\\\\B-\\\\u9100\\\\n]{0})|\\u3c01{1,3}\", \"gi\")].some(function (\u3056) { \"use strict\"; return  ''  } )) { default: this.o0.h0.hasOwn = f2;case (makeFinalizeObserver('tenured')): NaN = x;break; case y+=\"\\u9B58\": const a =  '' ;return /(?:(?!\\B)|(?!\\ubcD9))/gi;break; o1.toString = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var acos = stdlib.Math.acos;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1.125;\n    i1 = (i1);\n    i1 = (i1);\n    (Uint32ArrayView[0]) = ((i1));\n    return +((((+abs((((+((Float64ArrayView[(-0xb3e74*(/*FFI*/ff(((((0xfc360478)) >> ((0xc0c9bccf)))), ((+acos(((1025.0))))))|0)) >> 3]))) + (2147483649.0))))))));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); }");
/*fuzzSeed-133180449*/count=1005; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i1)+(((-17592186044417.0)))+(i0)))|0;\n  }\n  return f; })(this, {ff:  ''  *  /x/g }, new ArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=1006; tryItOut("print(this.s1);");
/*fuzzSeed-133180449*/count=1007; tryItOut("a2.splice(NaN, 6);");
/*fuzzSeed-133180449*/count=1008; tryItOut("\"use strict\"; v2 = g1.runOffThreadScript();");
/*fuzzSeed-133180449*/count=1009; tryItOut("mathy1 = (function(x, y) { return ( ! (( ! ( + Math.ceil((((Math.cos(((x != ( - ( + y))) >>> 0)) >>> 0) <= Math.asin(y)) | 0)))) >>> 0)); }); testMathyFunction(mathy1, [-0x100000000, 0x100000000, 0x0ffffffff, 2**53, 0, 1.7976931348623157e308, 2**53+2, 0.000000000000001, -Number.MIN_VALUE, -0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -1/0, -(2**53+2), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 42, -Number.MIN_SAFE_INTEGER, -0x080000000, 0/0, 0x07fffffff, 0x080000000, 1, 0x100000001, Math.PI, -0x0ffffffff, -(2**53), -0, 0x080000001, 1/0, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=1010; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(((Math.acosh((Math.atan2(Number.MIN_SAFE_INTEGER, (\n10 != (y | 0))) >>> 0)) >>> 0) >> (Math.acos((Math.cbrt(((Math.max(Math.fround(y), (( + ( ~ x)) , (y <= x))) >>> 0) | 0)) | 0)) >>> 0))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000000, 2**53+2, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -0x100000001, 0, -0x07fffffff, -0, -0x0ffffffff, -1/0, 0x100000001, -0x100000000, 0x07fffffff, 0/0, 1/0, 42, -(2**53), Number.MAX_SAFE_INTEGER, 2**53-2, 1, 0x100000000, 2**53, -Number.MIN_VALUE, -0x080000001, -(2**53-2), 0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1011; tryItOut("o1.valueOf = (function mcc_() { var inytqv = 0; return function() { ++inytqv; f2(/*ICCD*/inytqv % 6 == 0);};})();");
/*fuzzSeed-133180449*/count=1012; tryItOut("var r0 = x ^ x; var r1 = x - r0; var r2 = 3 + x; var r3 = 2 + 4; var r4 = r1 | r2; var r5 = r3 & x; var r6 = r5 + r5; var r7 = 4 | 1; x = r2 / r5; var r8 = r6 * 0; var r9 = 3 * 3; var r10 = r5 ^ r7; var r11 = r7 & 0; var r12 = r6 & r3; var r13 = 7 & x; var r14 = r11 + r2; var r15 = 4 % r6; var r16 = r9 | r0; var r17 = r14 + r0; var r18 = 6 * r4; var r19 = r15 % 9; r2 = 4 / 9; var r20 = r10 - r12; var r21 = r9 + r4; var r22 = r11 + r19; var r23 = r8 * 6; var r24 = 1 ^ 4; var r25 = 1 ^ r23; var r26 = r10 - r18; r6 = 4 % r1; print(r7); var r27 = r4 | r7; var r28 = 5 % r0; r21 = r4 | r27; var r29 = r14 ^ 4; var r30 = r1 & 3; var r31 = r13 * r7; var r32 = r14 & 6; print(r17); var r33 = r0 | r8; var r34 = r17 * r15; var r35 = 5 | r7; var r36 = r12 / r13; var r37 = r7 & r31; var r38 = r7 & 6; var r39 = r4 - r3; var r40 = r22 ^ 4; var r41 = r39 | r9; var r42 = r36 & 2; var r43 = r39 + 6; var r44 = r2 & r27; var r45 = 1 & r24; var r46 = r17 * r18; r28 = 5 ^ r0; r45 = 1 ^ r12; var r47 = 9 ^ 9; var r48 = 7 & r44; var r49 = 0 * r41; var r50 = r38 % r25; var r51 = r17 + r43; var r52 = r21 & r0; var r53 = r42 ^ 3; var r54 = 1 | r10; var r55 = r24 * 3; var r56 = r4 & 1; r9 = 7 ^ r4; var r57 = 5 + r26; var r58 = 1 + r35; var r59 = r24 * r41; var r60 = 7 + r11; var r61 = r39 - r29; var r62 = r1 - r5; r45 = r58 ^ r36; var r63 = 0 - 2; var r64 = r39 ^ 2; var r65 = 8 / r55; var r66 = 3 / r55; var r67 = r18 / r59; var r68 = 4 ^ r60; var r69 = r1 & 0; var r70 = r68 | 1; var r71 = 5 / 5; var r72 = r55 + r22; var r73 = r15 * r34; var r74 = r34 | r1; r0 = r53 ^ r43; var r75 = 4 | r35; var r76 = 5 / 5; r27 = 3 * r21; var r77 = 3 / 6; var r78 = r1 % r6; var r79 = r27 + 0; var r80 = 6 ^ 8; var r81 = r62 + r32; r36 = r22 | r34; r56 = r24 + r16; var r82 = r10 & r74; var r83 = r77 + r36; var r84 = r82 ^ r18; var r85 = r63 & 7; var r86 = r73 / r53; r14 = 3 % 1; var r87 = r41 | r45; var r88 = 8 % r87; r21 = r45 - r82; r26 = r66 - r6; var r89 = 2 - r45; r17 = r25 ^ r73; var r90 = r86 | r10; var r91 = 6 & r82; var r92 = r24 * r15; var r93 = r7 * r36; var r94 = r49 & r74; var r95 = 7 / r41; r35 = r30 * r7; r67 = r94 / 2; r15 = 0 | 6; r63 = 7 * 9; var r96 = r91 * 9; var r97 = r46 & r67; var r98 = r81 - 6; var r99 = r12 ^ 1; var r100 = r58 ^ r85; r9 = r9 + r44; r45 = r45 * 4; var r101 = r28 + 2; var r102 = r58 & r100; var r103 = r44 * r28; var r104 = 7 ^ r25; var r105 = r68 * r0; var r106 = 7 | 5; r74 = r86 | r44; r26 = r79 * r0; var r107 = 4 & 8; var r108 = r68 + 1; var r109 = r2 / 4; var r110 = r97 + 5; var r111 = 6 ^ r78; var r112 = r107 & r107; var r113 = r42 + r63; r84 = r49 / r60; var r114 = r47 | 8; var r115 = 2 & 8; var r116 = r29 & 8; var r117 = r32 ^ r68; var r118 = 0 / 1; var r119 = 6 ^ r5; r65 = 4 / r0; var r120 = 0 + r68; var r121 = r62 ^ r49; r107 = 1 & 6; print(r73); var r122 = r101 ^ r23; r37 = r4 & r94; var r123 = r7 & 5; var r124 = r35 | 6; var r125 = r38 & r63; var r126 = 5 + 4; r72 = r103 & r45; var r127 = r15 / r26; r72 = r18 + r14; r77 = r99 ^ r98; var r128 = r74 | 4; var r129 = r107 * r111; var r130 = r119 - r15; r122 = 7 % 9; var r131 = r94 % r28; var r132 = 1 ^ r112; var r133 = r60 | 8; var r134 = r18 | r99; var r135 = r125 & 1; r27 = r52 / r45; var r136 = r35 | r59; print(r113); var r137 = 0 % r116; r114 = r62 / r114; var r138 = 5 ^ 1; r40 = 3 ^ 3; var r139 = r97 - r81; var r140 = 6 ^ r96; print(r105); var r141 = r6 / 0; var r142 = r93 | 6; r8 = r68 - r58; var r143 = 1 | r12; var r144 = 0 * r6; var r145 = r108 % r3; r17 = 8 % 6; var r146 = r8 - r6; r133 = r75 / r42; r65 = r45 / r20; r12 = r102 | 8; r71 = r46 | r124; var r147 = r74 - r109; var r148 = r4 - r135; var r149 = r66 * 6; var r150 = r113 * r28; r44 = 3 % 0; var r151 = r70 + r71; var r152 = r127 | 4; r94 = r149 & r13; var r153 = 6 / r63; var r154 = 9 * r48; var r155 = 0 / r26; var r156 = 5 | 8; var r157 = 9 & 8; var r158 = 2 & r63; var r159 = 0 - r58; var r160 = r14 ^ r50; var r161 = r87 + r80; var r162 = r72 | 6; var r163 = 3 * r59; r107 = 3 ^ r10; var r164 = r82 - 9; var r165 = r47 * r59; var r166 = 7 + 8; var r167 = 6 - r135; r149 = 4 / r78; var r168 = 6 * r146; var r169 = 3 & r98; var r170 = 7 / r136; r116 = r53 | 0; print(r4); var r171 = r68 | r113; var r172 = r66 ^ r88; r167 = r171 % r143; var r173 = 5 & 5; var r174 = r156 / r74; var r175 = r62 + r137; var r176 = 8 / r32; var r177 = r111 * r77; print(r102); var r178 = r50 / 1; print(r61); var r179 = r53 ^ 5; var r180 = r162 & 5; print(r63); var r181 = r148 + r93; var r182 = 9 + r152; var r183 = 4 | r125; print(r83); var r184 = r79 / r156; var r185 = r85 & r119; r184 = 5 | r24; var r186 = r12 + 4; r22 = r48 & 3; var r187 = r78 | 1; r179 = 1 - 3; print(r138); var r188 = 9 % 3; print(r5); var r189 = r88 / r115; var r190 = r143 * 3; var r191 = r150 | r94; var r192 = 1 | 4; var r193 = r50 + 9; var r194 = r78 / r9; var r195 = r39 & r95; var r196 = r73 & r23; var r197 = r149 - r176; var r198 = r114 - 4; var r199 = r182 ^ 7; var r200 = r89 - 8; var r201 = r67 | r161; var r202 = x & 6; r72 = 2 / r52; var r203 = r76 + r127; var r204 = r106 ^ r6; print(r172); var r205 = r159 | 0; var r206 = r102 - r132; r183 = r9 + 3; var r207 = r194 / r138; var r208 = r196 % r175; var r209 = r174 % r51; r143 = r93 * 6; var r210 = r39 - r62; var r211 = 8 + r152; var r212 = r5 + 2; var r213 = r151 + r69; var r214 = 3 % r190; var r215 = 8 ^ r142; var r216 = 6 / 9; var r217 = r12 * r27; var r218 = 8 - r35; var r219 = 7 + r77; print(r17); var r220 = r91 - r65; r53 = r140 | r182; var r221 = r26 - 6; var r222 = 7 - 8; var r223 = r126 + 4; r74 = 6 / r38; r54 = r87 | 2; var r224 = r42 / 7; var r225 = r81 / 0; var r226 = 0 & 5; var r227 = r187 | 2; var r228 = r145 % 8; r175 = r61 / r134; var r229 = r108 % 8; var r230 = 8 + 9; var r231 = 8 - r87; r160 = r151 - r67; var r232 = r171 + r40; var r233 = 1 * 1; r189 = r112 * 1; var r234 = r127 | r164; var r235 = r141 * r219; var r236 = r187 & 5; var r237 = 4 / r214; var r238 = r170 | r116; r105 = 0 ^ r177; var r239 = 7 ^ r57; var r240 = 0 & r214; var r241 = 3 + r51; var r242 = r189 * 5; var r243 = 1 % r51; r121 = 2 * r66; r155 = 6 / r223; r208 = r32 / r206; var r244 = r132 / r69; var r245 = 0 | r232; var r246 = r136 | 3; var r247 = r158 * r215; var r248 = r87 % r123; var r249 = r115 * 4; r169 = r63 - r163; var r250 = r28 ^ r38; var r251 = r79 * r213; var r252 = 5 / r141; var r253 = r66 % r32; var r254 = r208 & r41; var r255 = 4 ^ r43; var r256 = r187 ^ r247; var r257 = r195 & 0; var r258 = r112 * r167; r91 = 2 / r85; var r259 = r204 | 3; print(r165); var r260 = r141 | r133; var r261 = 2 % r7; r74 = 3 + 5; var r262 = r208 * r121; var r263 = 8 & r148; var r264 = 3 * r202; var r265 = r141 / 0; var r266 = r107 / r264; r247 = r107 ^ r18; r49 = r154 | r12; var r267 = r27 & r139; var r268 = r192 | r193; var r269 = 7 % r179; var r270 = r126 | 7; var r271 = r159 - 5; r92 = r217 * r249; var r272 = 5 | 3; var r273 = r137 % r150; r15 = 6 | r190; var r274 = r67 ^ 2; var r275 = r203 * r9; var r276 = r212 % r43; var r277 = r137 * 9; var r278 = 0 + r24; var r279 = 2 | r14; var r280 = r215 & r72; var r281 = r211 | 2; var r282 = r107 - r181; var r283 = r17 - 5; var r284 = 6 + r55; var r285 = r0 | r243; r195 = r52 & 9; r190 = r37 * r275; r274 = 8 * r11; var r286 = r250 + r64; var r287 = r64 | 3; var r288 = 3 / r122; r233 = 8 | 5; var r289 = 1 + 5; var r290 = r151 ^ r34; var r291 = r149 / 8; r203 = 8 - 6; r213 = r242 + r78; var r292 = r228 ^ r6; var r293 = r64 + 2; var r294 = r229 & r65; r26 = r196 & 3; var r295 = 1 / 8; var r296 = 1 - 0; var r297 = r187 ^ 7; var r298 = r285 - r237; var r299 = r161 & 8; var r300 = r63 % r219; var r301 = r261 & 5; var r302 = r166 % 4; var r303 = r206 + 6; var r304 = r173 | r208; var r305 = r274 / 0; r183 = r8 ^ 9; r301 = r290 % r224; r8 = r107 + r228; print(r35); var r306 = r31 / 2; r20 = r218 - r302; var r307 = r13 / r215; var r308 = 8 - 8; var r309 = r255 - 3; var r310 = r214 - r129; var r311 = 4 ^ r146; var r312 = r51 / r76; var r313 = r243 / r243; var r314 = r196 & 5; var r315 = r3 * r212; var r316 = r250 ^ r95; r97 = r210 * 4; r288 = r289 ^ r39; var r317 = 2 % r196; var r318 = r39 + r40; var r319 = r36 ^ r57; var r320 = r310 | 6; r40 = 3 | 7; var r321 = r320 - 0; var r322 = r201 & r30; r258 = r300 - 4; var r323 = r221 * r229; var r324 = 3 ^ r233; var r325 = r166 & r223; var r326 = r75 * r198; r15 = 2 & r22; var r327 = r198 ^ r83; var r328 = r20 - r22; var r329 = r247 | 7; var r330 = 5 * r251; r314 = 7 + r330; print(r5); var r331 = r218 * 7; r47 = r150 * r273; var r332 = r148 / 5; var r333 = 0 + r26; var r334 = r77 ^ r332; r284 = r265 & r289; var r335 = r50 | 2; var r336 = r233 - r316; var r337 = 7 & 8; var r338 = r117 & r52; var r339 = 7 & r218; var r340 = 8 | 2; print(r170); r130 = r210 * r126; var r341 = r140 % r212; r270 = 0 - 1; var r342 = 6 - r122; var r343 = r202 + 9; var r344 = 1 ^ r286; var r345 = 3 | 4; var r346 = r333 - r325; r25 = r226 * r183; var r347 = 0 / r97; var r348 = r279 ^ r125; var r349 = r176 / 6; print(r245); var r350 = r74 % r30; var r351 = r280 % r190; var r352 = r43 / r108; var r353 = r12 - r316; print(r182); var r354 = 6 % r257; var r355 = r270 + 0; var r356 = r0 | r338; var r357 = r55 ^ r23; var r358 = r293 % 5; var r359 = 4 + r51; r149 = 6 & 7; var r360 = r334 + r163; var r361 = r39 ^ r264; var r362 = r29 / r211; r208 = r254 * r315; var r363 = 9 | r302; var r364 = 5 & r75; var r365 = 0 + 8; r33 = r210 | r325; var r366 = r297 ^ 4; var r367 = 8 / 0; var r368 = r229 / r80; var r369 = 3 + r52; r39 = 6 - r65; var r370 = r94 + r201; var r371 = 7 * r13; var r372 = r272 / r76; var r373 = r209 / r147; var r374 = r61 / 6; var r375 = r155 & r363; var r376 = r257 * 0; var r377 = 0 / 6; print(r65); var r378 = 7 ^ r70; var r379 = r360 | r254; var r380 = r180 - r296; var r381 = r109 - r216; var r382 = r126 | r168; var r383 = 3 % 3; var r384 = r247 / r29; r28 = r335 * r65; r26 = r364 + r332; r312 = r273 * r214; print(r384); var r385 = r48 & 7; var r386 = r255 % r237; var r387 = r259 % 3; var r388 = r177 & r93; r193 = r160 + 2; var r389 = r82 * 4; var r390 = r305 % r343; var r391 = 9 / 0; var r392 = 3 | r253; var r393 = r280 & r57; var r394 = r267 & 5; var r395 = r96 ^ r47; var r396 = r178 % r138; var r397 = r10 & r331; var r398 = r86 & r58; var r399 = r67 / r15; var r400 = 6 + 8; var r401 = 8 * r0; var r402 = r360 + r68; var r403 = 6 / r192; var r404 = 2 ^ 4; var r405 = 3 * 5; var r406 = r367 ^ r166; var r407 = r200 * 2; var r408 = 5 - 6; var r409 = 0 * r207; var r410 = r265 % 9; var r411 = 9 | r9; var r412 = r291 % r324; r270 = r188 % r173; r16 = r391 ^ r107; r367 = 5 % r145; print(r339); var r413 = r38 * r166; var r414 = r363 - r277; r181 = r68 * r226; r223 = r228 ^ r73; var r415 = 0 | r129; var r416 = r233 / r23; var r417 = r391 + r226; var r418 = 2 / r221; r195 = r19 % 0; var r419 = r168 + 0; var r420 = r94 & r401; r142 = r185 & 0; var r421 = 2 & 4; var r422 = r92 / 9; var r423 = 1 * r360; r304 = r148 & r149; var r424 = 2 & 5; r349 = r245 | 3; var r425 = r257 - 4; r232 = r138 * r324; var r426 = r412 % 7; var r427 = 1 % r16; var r428 = r424 - r309; var r429 = r193 + r410; var r430 = 6 ^ r373; var r431 = r235 * r184; var r432 = 1 * 7; var r433 = r313 - 0; var r434 = r371 & 6; var r435 = 0 & 3; var r436 = r230 & r134; var r437 = r46 & 1; var r438 = r132 / r15; var r439 = 6 - r134; r136 = r57 % 6; var r440 = r33 & r275; var r441 = 7 / r141; var r442 = 0 / r311; r398 = r378 + r137; var r443 = r420 * r159; var r444 = 7 / r211; var r445 = 2 * 4; var r446 = 7 ^ 9; var r447 = 5 * r9; var r448 = 2 & 5; var r449 = 2 | r277; var r450 = r20 ^ 2; r219 = 4 & r277; var r451 = r299 & r244; var r452 = r94 % r5; var r453 = r222 % r6; var r454 = r452 ^ r373; var r455 = 0 + r336; var r456 = 8 & 4; var r457 = 4 + r17; r418 = r410 ^ 9; var r458 = r158 - r7; var r459 = r132 * r86; var r460 = r146 ^ r435; print(r429); var r461 = r290 ^ r235; var r462 = 9 * r39; var r463 = r206 ^ r404; r186 = 3 ^ r286; r370 = 0 ^ r63; var r464 = r398 * 0; print(r338); var r465 = r103 % 9; var r466 = r410 | r463; r457 = 6 / r146; var r467 = r49 % 3; print(r170); var r468 = 5 - r340; r415 = 6 + r449; var r469 = 6 / r74; r73 = 5 * r223; r190 = r96 % 8; var r470 = 6 % 6; var r471 = 8 & 3; print(r297); var r472 = 9 / r100; var r473 = 6 & r351; r330 = 6 / r113; var r474 = r60 * r281; var r475 = 6 % r357; var r476 = r254 + 8; var r477 = r213 & r234; r99 = r421 | r97; var r478 = 6 | r102; var r479 = r124 / 3; var r480 = r69 - r478; r236 = 6 & 5; r252 = r240 * r303; var r481 = 1 - r149; var r482 = r61 | r298; var r483 = r160 ^ r259; var r484 = 1 | r231; var r485 = 2 % r178; var r486 = r473 ^ r65; r24 = 6 & r267; var r487 = r60 - r360; var r488 = r450 / r485; r61 = r18 % r215; var r489 = 8 * r405; var r490 = r314 * r398; r13 = r299 | 7; var r491 = r104 - r97; var r492 = r118 * 4; var r493 = r60 & 9; var r494 = r409 % 6; var r495 = r372 % r283; var r496 = r217 / 7; r88 = r93 ^ 6; var r497 = r94 + 2; var r498 = 9 % r174; var r499 = r179 % r422; var r500 = 4 * r246; var r501 = 2 & r418; var r502 = 4 ^ 4; print(r78); var r503 = 3 & r381; var r504 = 8 / r418; var r505 = r21 * r437; var r506 = r474 | 1; var r507 = r191 - r290; var r508 = 1 / r201; var r509 = r125 * 8; print(r327); var r510 = 0 / r22; r188 = r271 | r381; var r511 = 0 & r29; var r512 = r507 | r147; var r513 = 9 - 3; r329 = r138 * r107; var r514 = 1 * 4; var r515 = r151 & r416; var r516 = r22 % r199; var r517 = r235 | 5; var r518 = r418 % r419; var r519 = r399 | r317; var r520 = 9 + r372; var r521 = r502 | r511; r505 = r460 + r420; var r522 = r28 | 5; var r523 = r17 | 3; r424 = r243 * r208; r77 = r474 | r306; var r524 = r376 % r233; r475 = r64 & 2; var r525 = r244 + r177; var r526 = r270 / 0; r525 = r465 / 4; var r527 = 9 - 8; var r528 = 9 % r139; r493 = r387 % r40; var r529 = 3 & r175; var r530 = r486 % r26; var r531 = r166 + 4; var r532 = 9 % r517; var r533 = 3 % 4; var r534 = r410 - r267; var r535 = 8 * r245; var r536 = 6 * r373; var r537 = 7 * r374; var r538 = 4 | r84; var r539 = r196 & r172; var r540 = r481 ^ 7; r375 = r320 | 4; var r541 = r111 - r335; var r542 = 4 | r474; var r543 = r489 - 1; var r544 = r386 % r247; var r545 = r170 / r107; var r546 = r406 | 5; var r547 = r197 ^ r243; r374 = r53 | r135; var r548 = r60 - r403; r84 = 6 / r207; var r549 = r27 | r379; print(r481); ");
/*fuzzSeed-133180449*/count=1013; tryItOut("mathy2 = (function(x, y) { return Math.fround(( ~ Math.fround(((Math.log1p(Math.fround((Math.fround(y) ? Math.fround(-Number.MAX_SAFE_INTEGER) : Math.fround(Math.trunc(Math.fround(y)))))) + (( ~ (Math.max(( - (x | 0)), Math.hypot((Math.fround(-0x0ffffffff) || Math.fround(mathy0(x, Math.PI))), (( + x) || y))) >>> 0)) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-133180449*/count=1014; tryItOut("let a1 = [];");
/*fuzzSeed-133180449*/count=1015; tryItOut("mathy2 = (function(x, y) { return Math.atan2(((( - ( ! Math.fround(Math.imul(y, Math.fround(x))))) | 0) | 0), ( + (( + (Math.fround((Math.fround(Math.log(y)) >> Math.fround(Math.tan((1 != -(2**53)))))) === Number.MIN_VALUE)) ^ ( + (((((( ~ (-0x0ffffffff >>> 0)) >>> 0) >> -1/0) >>> 0) ** ( + (y && (Math.fround(mathy0((x >>> 0), Math.fround(y))) >>> 0)))) >>> 0))))); }); testMathyFunction(mathy2, [(new Boolean(false)), /0/, ({valueOf:function(){return 0;}}), (function(){return 0;}), (new Number(0)), ({valueOf:function(){return '0';}}), 0, false, (new String('')), objectEmulatingUndefined(), true, [], 1, '0', NaN, (new Number(-0)), null, (new Boolean(true)), '/0/', [0], ({toString:function(){return '0';}}), '\\0', -0, '', undefined, 0.1]); ");
/*fuzzSeed-133180449*/count=1016; tryItOut("\"use asm\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 1.2089258196146292e+24;\n    return (((0xef8fd85c)-((((i3)) ^ (-0xfffff*(i2))))))|0;\n  }\n  return f; })(this, {ff: mathy0}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-0x100000001, 1, 1/0, -0x080000000, 2**53, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, -0x100000000, Number.MAX_VALUE, -(2**53+2), 0x07fffffff, 42, -0x080000001, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, 0x100000001, 2**53-2, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53+2, 0x080000001, Number.MIN_VALUE, -1/0, 0.000000000000001, 0x100000000, 0/0, 0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-133180449*/count=1017; tryItOut("testMathyFunction(mathy1, [2**53-2, Number.MAX_SAFE_INTEGER, 0, -0x080000000, -0x080000001, 2**53+2, 0x080000001, 1.7976931348623157e308, -0, -Number.MIN_VALUE, 42, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -0x0ffffffff, -Number.MAX_VALUE, 0x100000001, 1/0, Number.MAX_VALUE, 0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), 2**53, 0/0, -(2**53), 0x080000000, Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, Math.PI, -1/0, -0x07fffffff, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=1018; tryItOut("/*infloop*/for(let e = []; Math.tanh( /x/ ); function  b (y) { yield ((makeFinalizeObserver('nursery'))) } ()) {{a1 + ''; } }");
/*fuzzSeed-133180449*/count=1019; tryItOut("\"use strict\"; y = x;m0.has(this.g1.m0);");
/*fuzzSeed-133180449*/count=1020; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((((((0x2906b153) ? ((0xf8655c64) ? (0xffffffff) : (0x6646eb0b)) : ((17592186044417.0) >= (-127.0))))>>>(((d1) > (1099511627777.0)))))+((Float64ArrayView[2]))+(0xf0ffddc7)))|0;\n  }\n  return f; })(this, {ff: window = Proxy.create(({/*TOODEEP*/})( '' ),  /x/g )}, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[ \"use strict\" , new String(''), new String(''),  \"use strict\" , false, new String(''), false, objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new String(''), objectEmulatingUndefined(), new String(''), new String(''),  \"use strict\" ,  'A' , false,  'A' ,  'A' , false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , false,  'A' ,  'A' ,  \"use strict\" ,  'A' , false,  'A' , new String(''), objectEmulatingUndefined(),  'A' , false, new String(''),  \"use strict\" , objectEmulatingUndefined(),  'A' ,  \"use strict\" , objectEmulatingUndefined(), new String(''),  'A' ,  'A' ,  \"use strict\" , objectEmulatingUndefined(),  'A' , false,  \"use strict\" ,  'A' ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , new String(''),  \"use strict\" ,  \"use strict\" , false, false,  \"use strict\" ,  \"use strict\" , new String(''), objectEmulatingUndefined(),  'A' , new String(''), objectEmulatingUndefined(), false, objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''),  \"use strict\" ,  \"use strict\" , false, false,  \"use strict\" , false, new String(''),  'A' ,  'A' ,  \"use strict\" ,  \"use strict\" , new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' ,  'A' , false, false, new String(''), objectEmulatingUndefined(), false,  \"use strict\" , new String(''),  'A' ,  'A' , false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, objectEmulatingUndefined(), false,  'A' , new String(''),  \"use strict\" , false,  'A' ,  \"use strict\" ,  'A' ,  'A' ,  \"use strict\" ,  'A' ,  'A' , false, new String(''), objectEmulatingUndefined(),  \"use strict\" ,  'A' ,  'A' ,  \"use strict\" , objectEmulatingUndefined(),  \"use strict\" , new String(''),  \"use strict\" ]); ");
/*fuzzSeed-133180449*/count=1021; tryItOut("[true];");
/*fuzzSeed-133180449*/count=1022; tryItOut("/*RXUB*/var r = -19; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=1023; tryItOut("mathy5 = (function(x, y) { return (( + ( + (Math.hypot(Math.hypot((( + x) | 0), ( ! y)), (x | 0)) == ( + (Math.acosh(( + Math.expm1(((Math.min(y, -(2**53)) << ( + y)) >>> 0)))) | 0))))) ? mathy4(Math.fround((( ~ Math.fround(( + ( - (((-0x07fffffff > x) ^ y) >>> 0))))) >>> 0)), ( + ( + (Math.tanh(y) | 0)))) : ( + ((y | 0) === ( - ( ! (x >>> 0)))))); }); testMathyFunction(mathy5, [2**53+2, -(2**53-2), -0x080000000, -1/0, 1.7976931348623157e308, -0x0ffffffff, -(2**53), Number.MIN_VALUE, -0x07fffffff, 0, 0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), 1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, 2**53-2, Math.PI, 2**53, -0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -0, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, 1, 0/0, 42]); ");
/*fuzzSeed-133180449*/count=1024; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((((Math.max((((( + y) ? (( + ( - ( + x))) >>> 0) : (x >>> 0)) >>> 0) ? Math.hypot(2**53+2, y) : -0x080000001), Math.fround(Math.sinh(Math.fround(x)))) || ((( + y) < Math.log1p((x >>> 0))) & y)) / (( + x) ? (0x07fffffff << y) : ( ! x))) | 0) >> (((Math.sin(y) <= x) >>> 0) ? ((((y != (Math.fround(Math.sign((x >>> 0))) | 0)) << ( ! Math.fround(Math.cosh(Math.fround(x))))) === ( + -0x080000000)) | 0) : ((( ~ ( + Math.imul((y && -0x100000001), (-(2**53) | 0)))) >>> 0) >>> 0))) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-133180449*/count=1025; tryItOut("mathy3 = (function(x, y) { return (mathy1((((( + x) <= y) % ( ! Math.fround((Math.fround(y) < Math.min((x % x), 2**53))))) >>> 0), (( ~ (mathy2((Math.atan2(y, Math.fround(Math.pow(x, (Math.hypot(2**53+2, ( + (( + x) ? ( + -0) : ( + y)))) | 0)))) | 0), ((Math.pow((y | 0), (((y << y) | 0) | 0)) | 0) | 0)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-0x080000001, 1.7976931348623157e308, 0x100000001, 0/0, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, 0x07fffffff, 42, 0x080000000, -0x100000001, Number.MAX_VALUE, 0, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 2**53-2, -(2**53+2), 1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), Number.MIN_VALUE, 0.000000000000001, 0x080000001, 1, -(2**53), 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-133180449*/count=1026; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return Math.atan2((((-0x080000000 !== x) >>> 0) > ( + (Math.hypot(Math.atan(y), (Math.hypot(Math.imul(x, 0x100000001), (y | 0)) >>> x)) >>> 0))), (((( ! -(2**53-2)) , x) ? Math.log(Math.atan2(( + x), Math.imul(( ! x), y))) : x) > Math.cosh(Math.fround(mathy3(Math.fround(0x100000001), Math.fround(42)))))); }); testMathyFunction(mathy4, [-(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, 0x0ffffffff, -0x0ffffffff, 1, 2**53, -(2**53+2), 0, 2**53-2, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, -0x100000000, 0x100000000, 0/0, -0x080000000, 1/0, 0.000000000000001, 0x100000001, 0x07fffffff, -(2**53-2), -0x100000001, -0x080000001, Number.MIN_VALUE, 0x080000001, 42, Math.PI, -0x07fffffff, -0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1027; tryItOut("if(false) { if (mathy0.prototype) v0 = Object.prototype.isPrototypeOf.call(e0, p1); else i1 = Proxy.create(h2, t1);}");
/*fuzzSeed-133180449*/count=1028; tryItOut("f0 = (function() { try { a2 = /*MARR*/[ /x/g , (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  /x/g , (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), objectEmulatingUndefined(), (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()), x, objectEmulatingUndefined(), x, (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()), x, x, (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), objectEmulatingUndefined(), (p={}, (p.z = /\\w/gyi)()), x, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(),  /x/g , (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , (p={}, (p.z = /\\w/gyi)()), x,  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()),  /x/g ,  /x/g , objectEmulatingUndefined(), (p={}, (p.z = /\\w/gyi)()), x,  /x/g , (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x,  /x/g ,  /x/g , x, x, (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(),  /x/g , (p={}, (p.z = /\\w/gyi)()), x, (p={}, (p.z = /\\w/gyi)()),  /x/g ,  /x/g , x,  /x/g , x, (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()),  /x/g , objectEmulatingUndefined(), (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), x, (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), x,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (p={}, (p.z = /\\w/gyi)()), objectEmulatingUndefined(), x, (p={}, (p.z = /\\w/gyi)()), (p={}, (p.z = /\\w/gyi)())]; } catch(e0) { } try { m1 + m1; } catch(e1) { } try { /*ODP-3*/Object.defineProperty(v1, \"prototype\", { configurable: false, enumerable: true, writable: true, value: g0 }); } catch(e2) { } o1.f0(h0); return t0; });");
/*fuzzSeed-133180449*/count=1029; tryItOut("\"use strict\"; t2.toSource = (function() { try { o1.e1.add(i1); } catch(e0) { } o1.v0 = a2.length; return e1; });");
/*fuzzSeed-133180449*/count=1030; tryItOut("\"use strict\"; o2.t0[7] = v0;");
/*fuzzSeed-133180449*/count=1031; tryItOut("/*infloop*/for(var intern(undefined).__proto__ in 'fafafa'.replace(/a/g, Int32Array)) \u000c{print(this.p2);((SharedArrayBuffer((x)))); }");
/*fuzzSeed-133180449*/count=1032; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1033; tryItOut("v2 = new Number(a0);");
/*fuzzSeed-133180449*/count=1034; tryItOut("\"use strict\"; this.g1.a2.pop();");
/*fuzzSeed-133180449*/count=1035; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( ! Math.atan2(Math.min(Math.cos((-Number.MIN_VALUE - (0x080000001 >>> 0))), (Math.fround(Math.acosh(y)) == Math.cbrt(( + Math.sinh(-1/0))))), ( - Math.atan2((mathy1(y, (( + (Math.fround(x) || Math.atanh((y >>> 0)))) | 0)) | 0), Math.sign(y))))) >>> 0); }); testMathyFunction(mathy2, [-0x07fffffff, 2**53-2, 0, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, 0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, -(2**53), -0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 42, -0, 1/0, 2**53+2, 0/0, 0x100000000, 0x07fffffff, -1/0, -(2**53+2), 0.000000000000001, -(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0x100000001, 2**53]); ");
/*fuzzSeed-133180449*/count=1036; tryItOut("/*RXUB*/var r = /(?=(?:\\2{4,}))/gy; var s = \"\\u000cPPPPPPPPP\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=1037; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1038; tryItOut("\"use strict\"; for(z in typeof [,,]) v2 = (v2 instanceof e2);");
/*fuzzSeed-133180449*/count=1039; tryItOut("\"use strict\"; switch((4277)) { case 7:  }");
/*fuzzSeed-133180449*/count=1040; tryItOut("L:with({e: x.prototype}){g0.v2 + '';o2.g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 4), noScriptRval: true, sourceIsLazy: false, catchTermination: true, elementAttributeName: s1 })); }\u000c");
/*fuzzSeed-133180449*/count=1041; tryItOut("{/* no regression tests found */ }");
/*fuzzSeed-133180449*/count=1042; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1043; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.max(Math.sin((( + Math.acos(Math.round(( + ( ! ( ! x)))))) >>> 0)), ((Math.abs(((-Number.MAX_VALUE ? Math.cosh(-0x080000000) : ((Math.max(((0x0ffffffff ? Math.fround((Math.atanh((y >>> 0)) >>> 0)) : x) | 0), (Math.trunc(( - (-Number.MAX_SAFE_INTEGER | 0))) | 0)) | 0) % (y >>> 0))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy0, [-0x100000000, Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, 0x080000001, -(2**53), Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 0x100000000, 2**53, Math.PI, -0, -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 0x0ffffffff, 0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, -(2**53-2), 1, -1/0, 0.000000000000001, 42, 1/0, -0x100000001, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=1044; tryItOut("testMathyFunction(mathy2, [true, (new String('')), 0.1, undefined, (new Number(-0)), '', (function(){return 0;}), objectEmulatingUndefined(), [0], NaN, '0', 0, null, ({valueOf:function(){return 0;}}), '\\0', '/0/', (new Boolean(true)), (new Number(0)), [], ({toString:function(){return '0';}}), (new Boolean(false)), false, ({valueOf:function(){return '0';}}), -0, 1, /0/]); ");
/*fuzzSeed-133180449*/count=1045; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.log(( + (( - Math.fround((Math.min(( - (Math.cos(((Math.fround(((y | 0) % Number.MAX_SAFE_INTEGER)) & 2**53-2) | 0)) | 0)), x) >>> 0))) | 0)))); }); testMathyFunction(mathy0, [-0x100000001, -0, 2**53+2, 2**53, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, -0x080000000, -0x080000001, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, Math.PI, 0x100000000, 1.7976931348623157e308, 1, Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53), -0x07fffffff, 0/0, 42, 1/0, 0x100000001, 0.000000000000001, -1/0, 0x080000001, 0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1046; tryItOut("\"use strict\"; a2 + a1;");
/*fuzzSeed-133180449*/count=1047; tryItOut("\"use asm\"; var v1 = g2.eval(\"/* no regression tests found */\");");
/*fuzzSeed-133180449*/count=1048; tryItOut("\"use strict\"; /*MXX1*/o2 = g1.Symbol;");
/*fuzzSeed-133180449*/count=1049; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.pow(( + ( - Math.log2(Math.pow(Math.sqrt(Math.fround(y)), ( + (( + (( ! Math.fround(y)) | 0)) + (x >>> 0))))))), ( + Math.fround((Math.min(( + Math.atan2(y, x)), y) === Math.fround(( + Math.min(( + (Math.imul(x, (Math.fround(( + (y >>> 0))) >>> 0)) >>> 0)), ( + (x ? (y >>> 0) : Math.expm1(y))))))))))); }); ");
/*fuzzSeed-133180449*/count=1050; tryItOut("s0 = g1.objectEmulatingUndefined();");
/*fuzzSeed-133180449*/count=1051; tryItOut("\"use asm\"; /*bLoop*/for (uloeqf = 0, gmflrx; uloeqf < 6; ++uloeqf, (z) = [1,,]) { if (uloeqf % 7 == 4) { print(x); } else { i0 + ''; }  } ");
/*fuzzSeed-133180449*/count=1052; tryItOut("/*bLoop*/for (let hanrnt = 0, d = window; hanrnt < 25; ++hanrnt) { if (hanrnt % 30 == 16) { h0.toSource = (function mcc_() { var clhibo = 0; return function() { ++clhibo; if (/*ICCD*/clhibo % 7 == 0) { dumpln('hit!'); m2 + m1; } else { dumpln('miss!'); try { o0.a2 = a2.map((function() { i0 = new Iterator(g0.g1.f2, true); return g2.e1; })); } catch(e0) { } t0 = new Uint8ClampedArray(b0); } };})(); } else { /*ADP-2*/Object.defineProperty(a1, [,,], { configurable: (x % 6 != 0), enumerable: /(?:[^\\B-\u00ff]*|(^)\u0011|\\B[^]+??)/gyim, get: (function() { try { Array.prototype.reverse.apply(g2.a1, []); } catch(e0) { } v2 = g1.eval(\"function f2(s0) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    var i2 = 0;\\n    var i3 = 0;\\n    d1 = (9.0);\\n    return (((0x1b60ef13) % (((1)+(1))>>>((((i3)-((0x5a32293c))) << ((-0x8000000))) / (abs((((0xffe8b2c4)-(0x766c99fc)-(-0x8000000))|0))|0)))))|0;\\n  }\\n  return f;\"); return m0; }), set: (function() { try { v0 = new Number(4.2); } catch(e0) { } v1 = Infinity; return o1.e0; }) }); }  } ");
/*fuzzSeed-133180449*/count=1053; tryItOut("t0[15] = (/*MARR*/[0x10000000, (void 0), 0x10000000,  \"\" ,  \"\" , 0x10000000, 0x10000000, (void 0), (void 0), (void 0), 0x10000000, (void 0), 0x10000000,  \"\" , 0x10000000, 0x10000000, (void 0),  \"\" ,  \"\" , (void 0), (void 0), (void 0), (void 0), 0x10000000,  \"\" , 0x10000000,  \"\" ,  \"\" ,  \"\" , (void 0), 0x10000000, (void 0), 0x10000000,  \"\" , 0x10000000,  \"\" , (void 0), (void 0), 0x10000000, 0x10000000, (void 0), 0x10000000, 0x10000000, 0x10000000,  \"\" ].filter);h0.valueOf = (function() { try { o0.v2 = (g1.g1 instanceof a0); } catch(e0) { } try { o2.h1 + ''; } catch(e1) { } t0.set(a2, 12); return o0.g2; });");
/*fuzzSeed-133180449*/count=1054; tryItOut("\"use strict\"; /*infloop*/ for  each(var e in eval(\"this\", /\\1/yi)) {m2.set(this.v1, a2); }");
/*fuzzSeed-133180449*/count=1055; tryItOut("\"use strict\";  for  each(let y in new (NaN = \"\\u517D\")()) {/*RXUB*/var r =  /x/g  *= [,,] ? -15 : -13; var s = c != a; print(uneval(r.exec(s))); Array.prototype.sort.call(a2, (function() { for (var j=0;j<15;++j) { this.g2.f0(j%4==1); } }), b1, h1, a1); }");
/*fuzzSeed-133180449*/count=1056; tryItOut("i2.__proto__ = e0;");
/*fuzzSeed-133180449*/count=1057; tryItOut("this.f1 = Proxy.createFunction(h1, o0.o2.f2, f2);m0 = new WeakMap;");
/*fuzzSeed-133180449*/count=1058; tryItOut("selectforgc(o0);");
/*fuzzSeed-133180449*/count=1059; tryItOut("\"use strict\"; a0.push(h0, this.s0, m0, g1.o0);function w([]) { \"use strict\"; yield  /x/g  } (new RegExp(\"(?=^|\\\\B*)|(?!(.{4,7})*)+?\", \"g\"));/*ODP-1*/Object.defineProperty(o2.s2, \"reduce\", ({configurable: true, enumerable: (void options('strict_mode')) >> ((1 for (x in [])))( /x/g ,  \"\" )}));");
/*fuzzSeed-133180449*/count=1060; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(mathy0((( - (((( + Math.fround(( ~ (-(2**53-2) << y)))) !== ( + Math.pow(x, (y | 0)))) >>> 0) < Math.fround((( - y) | 0)))) | 0), (( ! (Math.cosh((( ! Math.hypot(y, mathy1(x, ( + 2**53-2)))) | 0)) | 0)) | 0))); }); ");
/*fuzzSeed-133180449*/count=1061; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + mathy4(( + ( ~ Math.fround(Math.max(((Math.imul(( + (( + x) ^ ( + x))), mathy2(y, 2**53+2)) | 0) | 0), Math.fround(Math.max((((mathy2((x | 0), (Math.imul(y, y) | 0)) >>> 0) ? ((( + -0x100000001) ? y : y) >>> 0) : (( + (y | 0)) | 0)) >>> 0), (x >>> 0))))))), Math.fround(Math.tanh((( + Math.log10(y)) >>> 0))))); }); testMathyFunction(mathy5, [0x080000001, 0, -0, 1.7976931348623157e308, -0x100000000, -0x080000001, 42, 1/0, -0x07fffffff, 0x0ffffffff, 0x07fffffff, -0x100000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, Number.MAX_VALUE, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, -Number.MAX_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 1, 2**53, 2**53-2, -(2**53), 0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 0x100000000, 0/0]); ");
/*fuzzSeed-133180449*/count=1062; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot((y >>> Math.tan(y)), Math.max((( + Math.sinh(-(2**53))) | 0), ((Math.fround(( + ( + (Number.MAX_VALUE ? ( + x) : ( + ( + x)))))) ** Math.round((0x07fffffff >>> 0))) | 0))) < ( + Math.fround(Math.cosh(Math.max(Math.pow((Math.max(y, x) >>> 0), (x >>> 0)), ((y ? (Math.sinh(x) | 0) : (y | 0)) | 0)))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000000, -(2**53), 1, 2**53-2, -(2**53+2), -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, -1/0, Math.PI, -0x100000000, 0x100000001, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53+2, 42, Number.MIN_VALUE, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, 0.000000000000001, 0x100000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 0x080000001, -0, -0x0ffffffff, 2**53, -0x080000000]); ");
/*fuzzSeed-133180449*/count=1063; tryItOut("//h\nwhile(( \"\" \n.valueOf(\"number\")) && 0){t1 = t1.subarray(v2, ({valueOf: function() { for (var p in o0) { try { s1 = Array.prototype.join.apply(a1, [s0]); } catch(e0) { } this.o2.p1 = g0.objectEmulatingUndefined(); }return 16; }}));(z); }");
/*fuzzSeed-133180449*/count=1064; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.sinh(Math.fround(( - Math.fround((((( ! x) >>> 0) + (x >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [2**53, 0.000000000000001, -1/0, 2**53+2, 0/0, -0x080000001, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, 0x080000001, Math.PI, -0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -Number.MAX_VALUE, 1, 1/0, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -0x080000000, Number.MIN_VALUE, -(2**53), Number.MAX_VALUE, -(2**53+2), -0x07fffffff, 0x0ffffffff, 0x080000000, 0x100000000, -(2**53-2), -0x100000001, 42]); ");
/*fuzzSeed-133180449*/count=1065; tryItOut("/*infloop*/ for  each(let e in Math) {s0.__proto__ = o1.o2.i1;\"\u03a0\"; }");
/*fuzzSeed-133180449*/count=1066; tryItOut("\"use strict\"; let (x = new yield 0((void shapeOf(function ([y]) { })), allocationMarker()) ? -8.eval(\"for (var v of m0) { try { g1.e2.has(o2.s0); } catch(e0) { } try { a1.unshift(o2); } catch(e1) { } try { var e0 = new Set(h1); } catch(e2) { } i1.next(); }\") : let (x) y, x = (DataView), x, this = x, w, x = \"\\u31F4\", rvgspo, x, x, uksuds) { /*MXX2*/g0.Symbol.iterator = p1; }i1.send(this.h2);");
/*fuzzSeed-133180449*/count=1067; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( + Math.atan2((mathy0(( + Math.imul(Math.fround(-1/0), Math.fround(Math.fround((x ? ( + (Math.pow(((y ? 0x100000001 : x) | 0), -(2**53+2)) | 0)) : y))))), ( + Math.ceil(x))) >>> 0), Math.atan2(( + Math.imul(( + (Math.atan2((( + Math.PI) | 0), (-(2**53-2) | 0)) | 0)), ( + Math.ceil(y)))), Math.fround(Math.fround(Math.max(( + y), ( + y))))))) ? ( + (Math.log1p((Math.fround((Math.pow(( ~ (mathy1((y | 0), (-(2**53+2) | 0)) | 0)), 0.000000000000001) | 0)) >>> 0)) >>> 0)) : ( + Math.fround((Math.fround((Math.max((0x080000001 | 0), Math.atanh(y)) | 0)) << Math.fround((Math.min(mathy1(x, (0x07fffffff ? (x > (x ? -0x100000001 : (y | 0))) : x)), (Math.fround(Math.cbrt(Math.fround(Math.min((( + (y << x)) | 0), (mathy1(x, x) >>> 0))))) | 0)) | 0)))))); }); testMathyFunction(mathy2, [(new Boolean(true)), [], ({valueOf:function(){return '0';}}), 0.1, ({valueOf:function(){return 0;}}), (new Number(-0)), '/0/', (function(){return 0;}), -0, objectEmulatingUndefined(), undefined, (new Number(0)), NaN, ({toString:function(){return '0';}}), false, null, '\\0', '', true, '0', (new String('')), 0, /0/, [0], 1, (new Boolean(false))]); ");
/*fuzzSeed-133180449*/count=1068; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[objectEmulatingUndefined()]) { /* no regression tests found */ }");
/*fuzzSeed-133180449*/count=1069; tryItOut("mathy3 = (function(x, y) { return ( ! (Math.max((Math.acos(Math.hypot(Math.fround(( ! (y & x))), Math.fround(( + ( + ( + 0/0)))))) >>> 0), (Math.asin((Math.min(( ! (((-Number.MIN_VALUE | 0) ^ (-Number.MAX_VALUE | 0)) | 0)), ( + x)) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-(2**53), 1, -Number.MIN_VALUE, -Number.MAX_VALUE, -0, 0x07fffffff, 0.000000000000001, 2**53-2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, -0x100000000, -0x07fffffff, 0x0ffffffff, -0x080000000, 42, -0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0, Math.PI, -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, -0x100000001, 0x100000001, 2**53, -0x0ffffffff, 0x080000001, Number.MIN_VALUE, 2**53+2, 1/0, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=1070; tryItOut("testMathyFunction(mathy2, [0x07fffffff, -0x080000000, 2**53+2, Math.PI, -0x080000001, -0x100000001, -0, 2**53-2, 2**53, -0x100000000, 1.7976931348623157e308, 0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, -0x07fffffff, 42, Number.MAX_SAFE_INTEGER, 0x080000000, 1, Number.MAX_VALUE, 1/0, Number.MIN_VALUE, -(2**53-2), 0, 0x100000000, -1/0, -Number.MAX_VALUE, -(2**53), 0.000000000000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1071; tryItOut("\"use strict\"; g1.a1[10] = /\\1+/.__defineGetter__(\"e\", offThreadCompileScript);");
/*fuzzSeed-133180449*/count=1072; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( - (Math.abs(Math.cos(( ! mathy3(Math.min(y, y), y)))) >>> 0))); }); testMathyFunction(mathy4, [-0x0ffffffff, -(2**53-2), -1/0, -0, 0x0ffffffff, -0x100000001, -(2**53), -Number.MIN_VALUE, 0, 0x100000000, -0x080000000, 0/0, Math.PI, -(2**53+2), 0x080000000, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53+2, 0x07fffffff, 1, -0x080000001, -0x100000000, 1/0, 2**53-2, 42, 2**53, 0x100000001]); ");
/*fuzzSeed-133180449*/count=1073; tryItOut("g0.offThreadCompileScript(\"f0 = Proxy.createFunction(g2.h0, f0, f2);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 17 != 5), noScriptRval: false, sourceIsLazy: this, catchTermination: (/*FARR*/[(/*FARR*/[, ].map(c = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: neuter, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: undefined, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: undefined, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: undefined, keys: function() { throw 3; }, }; })(x), offThreadCompileScript))), ...(function() { yield \n(timeout(1800)); } })(), (makeFinalizeObserver('tenured')), , window].map) }));");
/*fuzzSeed-133180449*/count=1074; tryItOut("/*infloop*/for(x = /*\n*/(makeFinalizeObserver('nursery'))\n; eval-=allocationMarker(); (4277)) {var mqkxis, x, btotqt, y;v1 = (b2 instanceof a2);\nprint((yield NaN));\n }");
/*fuzzSeed-133180449*/count=1075; tryItOut("\"use strict\"; /*MXX2*/g0.String.prototype.substring = f2;");
/*fuzzSeed-133180449*/count=1076; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[0.000000000000001, false, 0.000000000000001, 0.000000000000001, undefined, false, objectEmulatingUndefined(), objectEmulatingUndefined(), 0.000000000000001, 0.000000000000001, objectEmulatingUndefined(), [undefined], 0.000000000000001, 0.000000000000001, objectEmulatingUndefined(), undefined, undefined, 0.000000000000001, undefined, undefined, objectEmulatingUndefined(), false, objectEmulatingUndefined(), [undefined], [undefined], objectEmulatingUndefined(), undefined, 0.000000000000001, 0.000000000000001, false, undefined, 0.000000000000001, 0.000000000000001, [undefined], undefined, undefined, objectEmulatingUndefined(), [undefined], false, objectEmulatingUndefined(), objectEmulatingUndefined(), undefined, 0.000000000000001, false, 0.000000000000001, undefined, false, [undefined], undefined, objectEmulatingUndefined(), [undefined], [undefined], 0.000000000000001, 0.000000000000001, false]) { this.s1 + ''; }v1 = Object.prototype.isPrototypeOf.call(t2, h2);");
/*fuzzSeed-133180449*/count=1077; tryItOut("let (x) { const v2 = g0.runOffThreadScript(); }");
/*fuzzSeed-133180449*/count=1078; tryItOut("this.t1.set(this.t2, ({valueOf: function() { eval = window-=new RegExp(\"((?!.)*|\\\\3{3,5})\", \"g\") < (new (/*MARR*/[[], objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined(), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), objectEmulatingUndefined(), [], -(2**53-2), -(2**53-2), -(2**53-2), objectEmulatingUndefined(), -(2**53-2)].some(WeakMap, new RegExp(\"\\\\S(?:($?))+?\", \"gyim\")))());g2.h1.delete = f1;return 1; }}));");
/*fuzzSeed-133180449*/count=1079; tryItOut("b1 + '';");
/*fuzzSeed-133180449*/count=1080; tryItOut("switch((/*RXUE*/new RegExp(\"(?!\\\\u0031)\", \"ym\").exec(\"Q\").blink())) { case 2:  }");
/*fuzzSeed-133180449*/count=1081; tryItOut("h0.has = this.f0;\no2.o0.a0[({valueOf: function() { t2[14] = o2.b1;return 13; }})];\n");
/*fuzzSeed-133180449*/count=1082; tryItOut("mathy3 = (function(x, y) { return ((( + Math.imul(( + Math.imul((Math.pow((y | 0), (new x() | 0)) | 0), ( + 1/0))), ( + (( ! Math.fround(( ~ x))) >>> 0)))) >>> 0) >> mathy2(Math.atan((Math.min((Math.expm1((Math.fround(Math.exp(Math.fround(y))) >>> 0)) | 0), (( + Math.pow(( + x), ( + x))) | 0)) | 0)), Math.atan2(( + ( + x)), (((x >>> 0) <= y) == Number.MAX_SAFE_INTEGER)))); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, 1, 2**53+2, 2**53, -(2**53-2), -(2**53), Math.PI, 0.000000000000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000000, 0x07fffffff, 42, 2**53-2, -0, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 0x080000000, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0, -0x100000000, 0x0ffffffff, 1/0, -(2**53+2), -0x080000000, -0x07fffffff, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1083; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround((((Math.cos((y >>> 0)) >>> ( + (( + ( - ( + ( ! {})))) == ( + y)))) >>> 0) + (Math.atan2((( + ( ~ ((((( + ( ! (Math.hypot(Math.atan(x), (-Number.MAX_VALUE | 0)) | 0))) >>> 0) + (y >>> 0)) >>> 0) >>> 0))) | 0), Math.sinh((Number.MAX_VALUE ? Math.log1p(Math.fround(Math.PI)) : y))) >>> 0))); }); ");
/*fuzzSeed-133180449*/count=1084; tryItOut("\"use strict\"; this.s1 += this.s0;");
/*fuzzSeed-133180449*/count=1085; tryItOut("/*tLoop*/for (let c of /*MARR*/[(0/0), (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, NaN, (0/0), objectEmulatingUndefined(), NaN, NaN, NaN, NaN, (0/0), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (0/0), (0/0), NaN, NaN, objectEmulatingUndefined(), NaN, NaN, (0/0), objectEmulatingUndefined(), (0/0), (0/0), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, NaN, (0/0), NaN, objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), (0/0), objectEmulatingUndefined(), (0/0), NaN, NaN, NaN]) {  }");
/*fuzzSeed-133180449*/count=1086; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1087; tryItOut("testMathyFunction(mathy4, [-0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 1/0, -0x080000001, 2**53-2, -(2**53+2), 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, 1, -0x07fffffff, -(2**53), -(2**53-2), 0x0ffffffff, Number.MAX_VALUE, Math.PI, 2**53, 42, 0, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, -1/0, 0/0, -0]); ");
/*fuzzSeed-133180449*/count=1088; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 2.4178516392292583e+24;\n    var i4 = 0;\n    var i5 = 0;\n    (Float64ArrayView[(((-140737488355329.0) == ((\u3056 = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function() { throw 3; }, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { return true; }, get: undefined, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: (encodeURI).call, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: DataView, }; })(Math.expm1(x)), 28.__defineGetter__(\"x\", Object)))))+(i4)-(((0x3f55c95b) == (0xb6a43693)) ? (i0) : (i0))) >> 3]) = ((+pow(((+(((/*FFI*/ff()|0)) >> ((i5))))), ((72057594037927940.0)))));\n    switch ((((/*FFI*/ff(((590295810358705700000.0)), ((-32767.0)), ((-513.0)), ((2.4178516392292583e+24)), ((-4.835703278458517e+24)), ((2097152.0)), ((-36893488147419103000.0)), ((-1.125)), ((-1.001953125)), ((16385.0)), ((-1048577.0)), ((65535.0)), ((1.0625)), ((549755813887.0)), ((-73786976294838210000.0)))|0)*0x8e9a2) ^ ((!(0x30825310))+(i0)))) {\n      case -2:\n        d3 = (9007199254740992.0);\n        break;\n      case 1:\n        i5 = ((((!(!(/*FFI*/ff()|0)))+(((((Math.imul(4, 0x080000000))))>>>((/*FFI*/ff(((2147483648.0)), ((7.737125245533627e+25)), ((-35184372088832.0)), ((-1073741824.0)))|0))) > ((((0x7fffffff)))>>>((0xfa723c9c)-(0xfcfd1a53))))) & ((i0)+(i2)+(0xfafb2a78))) == (~((0x1d9b9861) % (0x0))));\n        break;\n      default:\n        i0 = (0xfa577eac);\n    }\n    return +((Float32ArrayView[0]));\n  }\n  return f; })(this, {ff: (4277)}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, 0x080000001, 0x080000000, 2**53+2, -0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, 2**53-2, 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, -0x07fffffff, -(2**53), Number.MAX_VALUE, 0/0, 0x0ffffffff, -Number.MIN_VALUE, 0x100000001, -0x0ffffffff, -(2**53+2), -0x080000000, 0, 42, -1/0, -(2**53-2), 1, -0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -0x100000000]); ");
/*fuzzSeed-133180449*/count=1089; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return (( + ( ! (( + y) || (-Number.MAX_SAFE_INTEGER | 0)))) - Math.fround(Math.exp(((( + Math.atan2((( + (( + 2**53) >> ( + y))) >>> 0), (0.000000000000001 / x))) * (( ~ (y >>> 0)) >>> 0)) | 0)))); }); ");
/*fuzzSeed-133180449*/count=1090; tryItOut("mathy2 = (function(x, y) { return (Math.pow(((((Math.sin(Math.ceil(( + Math.exp((((Math.fround(( ~ (y >>> 0))) | 0) < y) | 0))))) >>> 0) >> (( + (( + ( ! ( - x))) / ( + x))) >>> 0)) >>> 0) >>> 0), ( + ((Math.hypot(((((y >>> 0) ? (Math.expm1(( ~ y)) >>> 0) : (Math.clz32(( + ( + y))) | 0)) >>> 0) | 0), ((Math.atan2(( + -(2**53-2)), x) >>> 0) | 0)) + (Math.cos((Math.fround(mathy1((mathy0(Math.fround(Math.hypot(Math.fround(x), Math.fround(0x07fffffff))), y) | 0), (( - x) ** (( + (x >>> 0)) >>> 0)))) | 0)) | 0)) | 0))) >>> 0); }); testMathyFunction(mathy2, [0/0, 0x0ffffffff, -0x080000000, 1.7976931348623157e308, 0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, 1, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53-2, 2**53+2, -0x07fffffff, 0, -0x080000001, -0x0ffffffff, 0x080000001, 0x07fffffff, Math.PI, -(2**53+2), Number.MAX_VALUE, -0x100000001, 0x100000001, -Number.MAX_VALUE, -0x100000000, 2**53, 42, Number.MIN_SAFE_INTEGER, -0, -(2**53-2), -(2**53), -1/0]); ");
/*fuzzSeed-133180449*/count=1091; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1092; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((( + (( + ( + 42)) * ( + (Math.hypot((x >>> 0), (0x0ffffffff >>> 0)) >>> 0)))) || (0.000000000000001 << x)) | ((( ! ( + (( + x) || x))) | 0) ? (( + Math.trunc(Math.fround(( + mathy0(( + y), ( + y)))))) | 0) : Math.atan2(( + Math.hypot(( + ( ~ y)), ( + ((y ? y : y) ? ( + Math.sign((y | 0))) : (y | 0))))), Math.fround(Math.cbrt((Math.fround(Math.log2(x)) >>> 0)))))); }); testMathyFunction(mathy2, [[0], '0', ({valueOf:function(){return 0;}}), '/0/', (function(){return 0;}), null, (new Number(0)), (new Boolean(true)), undefined, (new Boolean(false)), true, NaN, [], /0/, objectEmulatingUndefined(), 0, (new Number(-0)), ({valueOf:function(){return '0';}}), 1, 0.1, '', false, '\\0', (new String('')), -0, ({toString:function(){return '0';}})]); ");
/*fuzzSeed-133180449*/count=1093; tryItOut("mathy5 = (function(x, y) { return (( + (( + mathy1(Math.fround(Math.tan((((x | 0) ? y : (x | 0)) | 0))), x)) | 0)) | 0); }); testMathyFunction(mathy5, [0, NaN, (new Boolean(true)), [0], objectEmulatingUndefined(), /0/, '/0/', true, undefined, -0, '', (new Boolean(false)), (new String('')), false, (new Number(-0)), null, [], (new Number(0)), ({valueOf:function(){return '0';}}), 1, ({toString:function(){return '0';}}), (function(){return 0;}), ({valueOf:function(){return 0;}}), 0.1, '0', '\\0']); ");
/*fuzzSeed-133180449*/count=1094; tryItOut("mathy1 = (function(x, y) { return (Math.hypot(Math.min((((( ! Math.fround(( ~ -0x100000001))) >>> 0) ** Math.fround(Math.log((y | 0)))) >>> 0), ( ! Math.fround((Math.fround((y && x)) , Math.fround((Math.acos(Number.MIN_SAFE_INTEGER) | 0)))))), Math.fround((Math.fround((( ~ Math.tan(Math.hypot(-0, (mathy0((y | 0), (x | 0)) | 0)))) & ( - (y | 0)))) % Math.fround(Math.ceil((( - (((y | 0) <= y) >>> 0)) >>> 0)))))) >>> 0); }); ");
/*fuzzSeed-133180449*/count=1095; tryItOut("\"use asm\"; Array.prototype.pop.apply(g2.a0, []);");
/*fuzzSeed-133180449*/count=1096; tryItOut("print(\"\u03a0\".throw(-1));");
/*fuzzSeed-133180449*/count=1097; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((mathy1(Math.fround(Math.expm1(( + Math.imul(( ~ x), Math.fround(( - (( + x) >>> 0))))))), (Math.fround((y || x)) !== y)) | 0) || (Math.fround(((((y + (Math.sqrt(Math.fround((Math.fround((((Math.clz32(Math.fround(y)) | 0) || x) >>> 0)) % Math.fround((( ! x) ** ( - y)))))) | 0)) >>> 0) >>> 0) >= (( + ((x >> x) ^ mathy0(Math.fround(Math.exp(Math.fround(y))), (( + -Number.MAX_SAFE_INTEGER) | 0)))) | 0))) | 0)); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, -0x100000000, -0x07fffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x07fffffff, 1/0, -(2**53-2), -0x100000001, Number.MAX_VALUE, 1, 2**53+2, 0x0ffffffff, -0x080000001, -Number.MAX_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000001, 0, -0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, -(2**53), 42, Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, -0, Math.PI, 2**53-2, 2**53]); ");
/*fuzzSeed-133180449*/count=1098; tryItOut("v1 = Object.prototype.isPrototypeOf.call(a1, b2);");
/*fuzzSeed-133180449*/count=1099; tryItOut("\"use strict\"; v0 = evaluate(\"a2 + '';\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 11 != 2), sourceIsLazy: true, catchTermination: (x % 17 != 11) }));");
/*fuzzSeed-133180449*/count=1100; tryItOut("t0 + '';");
/*fuzzSeed-133180449*/count=1101; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.ceil(((((1 >>> 0) ? (-0x100000001 >>> 0) : y) >>> 0) << (Math.imul(y, x) >>> 0))) , Math.sign(( ~ ( + (((( ! ((x >= 1) < y)) | 0) ? (( + Math.hypot(Number.MAX_SAFE_INTEGER, ((x ? 1.7976931348623157e308 : (x >>> 0)) >>> 0))) | 0) : Math.max(x, y)) | 0))))); }); ");
/*fuzzSeed-133180449*/count=1102; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1103; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 5.0000000000000000000000, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 5.0000000000000000000000, 0x0ffffffff, 0x0ffffffff]) { /*vLoop*/for (xsftfe = 0; xsftfe < 2; ++xsftfe) { var e = xsftfe; print((4277)); }  }");
/*fuzzSeed-133180449*/count=1104; tryItOut("mathy1 = (function(x, y) { return ( - ((((((Math.sqrt(x) >>> 0) != (( + Math.ceil(( + ( - x)))) >>> 0)) >>> 0) | 0) ? (((Math.fround(( + Math.fround((Math.tanh(Math.fround(-Number.MAX_SAFE_INTEGER)) >>> 0)))) << (( ~ Math.trunc(-0)) | 0)) | 0) | 0) : (( + Math.expm1(( + y))) | 0)) | 0)); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 0, -0x0ffffffff, -(2**53-2), -0x100000001, -(2**53+2), 0x100000000, -0x100000000, 0x080000000, 0x100000001, -0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, 2**53-2, 2**53+2, 0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, 2**53, 0x080000001, -(2**53), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -1/0, 0/0, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, -0x07fffffff, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=1105; tryItOut("uxlubg, w, x, czkpfz, x, x;(x)");
/*fuzzSeed-133180449*/count=1106; tryItOut("\"use strict\"; o2.t0 = new Uint16Array(a2);g1.v0.toSource = (function() { for (var j=0;j<3;++j) { this.f2(j%5==1); } });");
/*fuzzSeed-133180449*/count=1107; tryItOut("v1 = g0.g0.o2.g1.eval(\"\\\"use strict\\\"; \");v0 = (v2 instanceof this.a1);");
/*fuzzSeed-133180449*/count=1108; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1109; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-133180449*/count=1110; tryItOut("let (y) {  for (var e of \"\\u0B33\") a1 = p1;e = (\u000c{/*toXFun*/toSource: (function mcc_() { var ckhzio = 0; return function() { ++ckhzio; f0(/*ICCD*/ckhzio % 5 == 1);};})() }); }");
/*fuzzSeed-133180449*/count=1111; tryItOut("testMathyFunction(mathy1, ['/0/', -0, 0.1, objectEmulatingUndefined(), 0, [0], (new Number(-0)), null, ({valueOf:function(){return 0;}}), '0', '', '\\0', ({toString:function(){return '0';}}), (new Number(0)), NaN, /0/, (new Boolean(true)), (function(){return 0;}), ({valueOf:function(){return '0';}}), false, 1, [], (new String('')), (new Boolean(false)), true, undefined]); ");
/*fuzzSeed-133180449*/count=1112; tryItOut("mathy5 = (function(x, y) { return mathy1(Math.fround(Math.atan2(( + Math.atan2(( + 0x07fffffff), y)), Math.fround((( ! ((Math.PI ? Number.MAX_SAFE_INTEGER : (x | 0)) >>> 0)) ? Math.min((((x >>> 0) - (y >>> 0)) >>> 0), mathy3((x ? -0x07fffffff : y), y)) : (Math.fround(( - x)) <= Math.fround(Math.hypot(0, Math.imul(x, (( - (y >>> 0)) >>> 0))))))))), ( + Math.max(( + (Math.fround(Math.cbrt(Math.fround(y))) - ( ~ (Math.fround(Math.tanh(x)) > Math.fround(Math.log((-Number.MIN_SAFE_INTEGER && x))))))), ( + Math.min(Math.sin(y), Math.max(x, y)))))); }); ");
/*fuzzSeed-133180449*/count=1113; tryItOut("/*RXUB*/var r = new RegExp(\"(?:^{0,4})+?\", \"gy\"); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-133180449*/count=1114; tryItOut("a0 = arguments;");
/*fuzzSeed-133180449*/count=1115; tryItOut("v1 = o1.r2.sticky;");
/*fuzzSeed-133180449*/count=1116; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\1)\\\\2|[^\\\\D\\\\W\\\\W]?\\\\w\\\\uD828|[^M-\\\\u008B\\\\r-\\u2d8a\\\\d]|[^].*{3}\", \"gm\"); var s = function(q) { \"use strict\"; return q; }.prototype; print(s.replace(r, (4277), \"yim\")); ");
/*fuzzSeed-133180449*/count=1117; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x0ffffffff, -1/0, -0x100000000, -0x100000001, 0, Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, 0x100000000, Number.MIN_VALUE, 0.000000000000001, -(2**53+2), -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), 0x080000000, Number.MAX_SAFE_INTEGER, 42, 2**53, 1, 2**53+2, -0x07fffffff, -0x080000001, -(2**53-2), -Number.MAX_VALUE, -0, 0x100000001, Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, 0x0ffffffff, Math.PI, 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=1118; tryItOut("mathy3 = (function(x, y) { return ( + ( + (Math.ceil(Math.fround((( ~ (( + (( + Math.min((x | 0), x)) ? (((( + ( + y)) | 0) | 0) ? ( + -(2**53)) : (( + (( + x) & ( + mathy1(y, x)))) | 0)) : ( + Math.max(Math.fround(y), y)))) >>> 0)) >>> 0))) >>> 0))); }); testMathyFunction(mathy3, [2**53-2, 1.7976931348623157e308, 0x0ffffffff, 0.000000000000001, 0/0, 0, -0x080000000, -(2**53-2), -0x07fffffff, -(2**53), 42, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, -Number.MAX_VALUE, 1, -0, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53+2), 0x080000001, 0x07fffffff, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, 0x100000001, Number.MAX_VALUE, 2**53+2, -0x100000000, -1/0, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1119; tryItOut("\"use strict\"; o2.s1 = s0.charAt(4);");
/*fuzzSeed-133180449*/count=1120; tryItOut("e1.delete(e1);");
/*fuzzSeed-133180449*/count=1121; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2((( ~ ((((((x + x) >>> 0) | 0) && Math.fround((mathy1(Math.sqrt(x), (0x07fffffff | 0)) | 0))) | 0) | 0)) | 0), Math.fround(Math.acosh(Math.fround((y , (Math.sign(( + Math.fround((Math.fround((((y | 0) || ( + -1/0)) >>> 0)) ? Math.fround(x) : ( + ((x >>> 0) ? ( + x) : Math.fround(y))))))) >>> 0))))))); }); testMathyFunction(mathy4, /*MARR*/[NaN, NaN, function(){}, function(){}, null, null, NaN, null, null, null, null, null, function(){}, function(){}, function(){}, null, null, function(){}, NaN, NaN, null, NaN, null, NaN, null, function(){}, null, null, NaN, null, null, null, NaN, NaN, NaN, NaN, null, function(){}, null, null, null, NaN, NaN, function(){}, function(){}, function(){}, null, function(){}, NaN, NaN, NaN, NaN, function(){}]); ");
/*fuzzSeed-133180449*/count=1122; tryItOut("testMathyFunction(mathy2, [(new Number(-0)), -0, null, ({valueOf:function(){return 0;}}), 0.1, '0', objectEmulatingUndefined(), '\\0', '', (new Number(0)), /0/, '/0/', true, undefined, (new Boolean(true)), 1, false, (function(){return 0;}), (new String('')), NaN, [], ({valueOf:function(){return '0';}}), 0, [0], (new Boolean(false)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-133180449*/count=1123; tryItOut("/*RXUB*/var r = new RegExp(\".[^]|\\\\s|\\\\cN|^*?{1,}|(?![M])+?\\\\3+?\", \"y\"); var s = \"\\n\\n\\n\\n\\uf3df\\uf3df\\uf3df\\n\\n\\n\\n\\uf3df\\uf3df\\uf3df\\n\\n\\n\\n\\uf3df\\uf3df\\uf3df\"; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=1124; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = new RegExp(\"[^\\\\xfb-\\ue8dd\\\\cC-,]|(?=(?!\\\\B+?([^])^\\\\x29))*|(?=\\\\W){4}|(\\\\d)|(?=[^])+??(?:(?=\\\\B|[^])){2,5}\", \"g\"); var s = \"\\u00fcaaaaa\\u00fc\\u00fc\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-133180449*/count=1125; tryItOut("/*vLoop*/for (var firdxk = 0, +c; (13 == x) && firdxk < 162; x, ++firdxk) { var c = firdxk; o1.valueOf = g0.o2.f1; } ");
/*fuzzSeed-133180449*/count=1126; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=1127; tryItOut("\"use strict\"; Object.prototype.unwatch.call(this.v2, new String(\"3\"));print(x);");
/*fuzzSeed-133180449*/count=1128; tryItOut("\"use strict\"; v1 = (m1 instanceof g2);");
/*fuzzSeed-133180449*/count=1129; tryItOut("/* no regression tests found */a = allocationMarker();");
/*fuzzSeed-133180449*/count=1130; tryItOut("g0.g1.h2.get = g1.f0;");
/*fuzzSeed-133180449*/count=1131; tryItOut("Object.defineProperty(this, \"a0\", { configurable: false, enumerable: false,  get: function() { Array.prototype.push.apply(a2, [f1, o2, (/*UUV1*/(w.getUint32 = encodeURIComponent)).unwatch([])]); return a2.concat(t2, t2, g0.a0, t2, t2, g1); } });");
/*fuzzSeed-133180449*/count=1132; tryItOut("\"use strict\"; print(x);\nfor (var p in f0) { try { e1.add(m2); } catch(e0) { } m0 + ''; }\ni1.next();");
/*fuzzSeed-133180449*/count=1133; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    return +((-274877906945.0));\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ print(((function fibonacci(rnsswh) { ; if (rnsswh <= 1) { ; return 1; } ; return fibonacci(rnsswh - 1) + fibonacci(rnsswh - 2); (/(?=((\\B[^]){1,2}))+/gym);function e() { yield window } ( /x/g ); })(5)));return (4277)})()}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=1134; tryItOut("testMathyFunction(mathy1, [1, 2**53+2, 0x100000001, Number.MAX_VALUE, 0x080000000, -Number.MAX_VALUE, -0x100000000, -0x07fffffff, 2**53, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, 0/0, -(2**53-2), -0x080000000, -0, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, Number.MIN_VALUE, Math.PI, 1/0, 0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, -0x0ffffffff, 2**53-2, 42, -(2**53), -Number.MAX_SAFE_INTEGER, -1/0, 0]); ");
/*fuzzSeed-133180449*/count=1135; tryItOut("");
/*fuzzSeed-133180449*/count=1136; tryItOut("Array.prototype.shift.call(a2, g2, s0);");
/*fuzzSeed-133180449*/count=1137; tryItOut("mathy3 = (function(x, y) { return Math.log1p(( ! ( + -0x07fffffff))); }); testMathyFunction(mathy3, [-0x080000001, -Number.MIN_VALUE, 0/0, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, 0, -(2**53+2), -0x100000001, 1.7976931348623157e308, 0x080000000, Math.PI, Number.MIN_VALUE, -1/0, 0x100000001, -0x100000000, 42, -0, -0x080000000, -Number.MAX_VALUE, -(2**53-2), Number.MAX_VALUE, 1, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -0x0ffffffff, 2**53, 0x0ffffffff, -0x07fffffff, 0.000000000000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-133180449*/count=1138; tryItOut("print(new ((new let (y)  '' (x)))((/*RXUE*/new RegExp(\"(?![\\u008a\\\\s\\\\n-\\\\n\\\\W]|\\\\D[^\\\\d\\\\u2bfd]{0,}(?:\\\\B?){2,5}|r{31,}|(?=\\\\2))\", \"y\").exec(\"\")) &= (new RegExp(\"..\", \"gm\").throw(\"\u03a0\")), (void options('strict'))) ? this.x = this.watch(new String(\"15\"), [1,,].getFloat64) : (Map.prototype.values).call(x ^ y, x));");
/*fuzzSeed-133180449*/count=1139; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=1140; tryItOut("Array.prototype.push.apply(a0, [t2, this.o2.v1, this.f0]);");
/*fuzzSeed-133180449*/count=1141; tryItOut("t0[6] = ((void options('strict_mode'))).__defineGetter__(\"z\", neuter);");
/*fuzzSeed-133180449*/count=1142; tryItOut("mathy3 = (function(x, y) { return ((((Math.exp(Math.min(y, (Math.min(Math.acosh(Math.fround(y)), x) >>> 0))) || ( + ( - Math.min(y, y)))) != ((((Math.pow((( + (( + ( ! y)) || ( + y))) >>> 0), (y >>> 0)) >>> 0) | 0) < (Math.trunc((0x080000001 != y)) | 0)) | 0)) | 0) > (( + Math.trunc(Math.imul(-Number.MIN_SAFE_INTEGER, Math.cosh(( + Math.hypot(-(2**53+2), (( + ( - (0x080000001 >>> 0))) >>> 0))))))) >> ( + (Math.hypot((y | 0), (( - 0x080000000) | 0)) | 0)))); }); testMathyFunction(mathy3, /*MARR*/[ /x/ , new Number(1),  /x/ , new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  /x/ , false, new Number(1), new Number(1),  /x/ , new String('q'), new String('q'),  /x/ , new String('q'),  /x/ , new Number(1),  /x/ ]); ");
/*fuzzSeed-133180449*/count=1143; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Math.PI, 1.7976931348623157e308, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, 0x100000001, -0x080000001, 0x0ffffffff, 1, 0/0, Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 42, 0, -(2**53), -(2**53+2), -0x100000000, -Number.MIN_VALUE, 2**53-2, -0x080000000, Number.MAX_VALUE, -1/0, 2**53+2, 0x080000001, 0x080000000, 0x100000000, 0.000000000000001, 2**53, 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=1144; tryItOut("const g2.a2 = this.r0.exec(s0);");
/*fuzzSeed-133180449*/count=1145; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.pow(((Math.imul(( ! x), x) >>> 0) ^ (( + mathy2((( ~ y) >>> 0), ( + y))) / x)), (( ~ (-Number.MIN_VALUE , y)) | 0))); }); testMathyFunction(mathy3, [Math.PI, -0x100000001, 2**53, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, 0x080000001, 0.000000000000001, 0, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, 0x100000001, 0x07fffffff, 42, -(2**53+2), -0x080000000, -0x100000000, -1/0, -Number.MIN_VALUE, -0x07fffffff, Number.MIN_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, 0x100000000, 0/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1146; tryItOut("/*tLoop*/for (let c of /*MARR*/[new Boolean(true), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new Boolean(true), x, Infinity, new Boolean(true), x, new Boolean(true), x, new Boolean(true), new Boolean(true), new Boolean(true), Infinity, x, Infinity, x, x, x, new Boolean(true), x, Infinity, x, new Boolean(true), Infinity, new Boolean(true), x, x, x, Infinity, Infinity, x, x, Infinity, new Boolean(true), Infinity, x, new Boolean(true), x, Infinity, new Boolean(true), x, new Boolean(true), new Boolean(true), new Boolean(true), Infinity, x, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), Infinity, Infinity, Infinity, x, x, new Boolean(true), new Boolean(true), Infinity, x, Infinity, x, Infinity, x, Infinity, x, x, x, Infinity, new Boolean(true), x, x, new Boolean(true), new Boolean(true), new Boolean(true), Infinity, x, new Boolean(true), new Boolean(true), Infinity, x, x, Infinity, Infinity, new Boolean(true), new Boolean(true), new Boolean(true), x, Infinity, x, x, Infinity, new Boolean(true), Infinity, new Boolean(true), new Boolean(true), Infinity, x, Infinity, Infinity, x, new Boolean(true), x, Infinity, x, x, Infinity, Infinity, new Boolean(true), new Boolean(true), new Boolean(true), Infinity, x, Infinity]) { (\"\\uE28A\"); }");
/*fuzzSeed-133180449*/count=1147; tryItOut("{t1 = t0.subarray(19, 4); }");
/*fuzzSeed-133180449*/count=1148; tryItOut("testMathyFunction(mathy0, [Number.MAX_VALUE, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, -0x07fffffff, 0x100000000, 1, -(2**53+2), -1/0, -(2**53-2), -0x100000001, -(2**53), 0.000000000000001, 0x080000001, -0x080000000, 0x080000000, -0x100000000, 2**53-2, 2**53, 1/0, Number.MIN_VALUE, -0x0ffffffff, -0x080000001, 0/0, Math.PI, 0x100000001, 0x0ffffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=1149; tryItOut("\"use strict\"; print(m1);");
/*fuzzSeed-133180449*/count=1150; tryItOut("\"use strict\"; /*vLoop*/for (let znbisi = 0, jcmkwx; znbisi < 0; ++znbisi) { var d = znbisi; g0.offThreadCompileScript(\"d\"); } ");
/*fuzzSeed-133180449*/count=1151; tryItOut("m1.get(m2);\na1.unshift(m1, g0);\n");
/*fuzzSeed-133180449*/count=1152; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = \"\\u00b2\"; print(r.test(s)); ");
/*fuzzSeed-133180449*/count=1153; tryItOut("\"use strict\"; /*bLoop*/for (let wjccpr = 0; wjccpr < 8; ++wjccpr) { if (wjccpr % 14 == 10) { v2 = r0.ignoreCase; } else { print(x);o1 = new Object; }  } ");
/*fuzzSeed-133180449*/count=1154; tryItOut("\"use asm\"; s0 += s2;");
/*fuzzSeed-133180449*/count=1155; tryItOut("t2 + '';");
/*fuzzSeed-133180449*/count=1156; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.min(Math.pow((Math.round(Math.fround(Math.sin(Math.hypot(y, Math.fround(( - Math.fround(y))))))) >>> 0), (( + Math.sign(Math.fround(((((y | 0) ? (y | 0) : x) | 0) % y)))) >>> 0)), ( ~ ( + (Math.fround(Math.min(( - 1.7976931348623157e308), x)) * Math.fround(Math.pow(x, ( + Math.cos(mathy1(y, x)))))))))); }); testMathyFunction(mathy2, [0x080000001, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, -0, -(2**53+2), -0x07fffffff, 1.7976931348623157e308, 0x100000000, -0x080000001, -(2**53), 2**53-2, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -0x0ffffffff, -0x100000001, 0, 2**53+2, Number.MAX_VALUE, -0x080000000, 0/0, -1/0, 0x07fffffff, 42]); ");
/*fuzzSeed-133180449*/count=1157; tryItOut("m0.has(g2);");
/*fuzzSeed-133180449*/count=1158; tryItOut("mathy2 = (function(x, y) { return (( + ( + ( + (Math.sinh(x) % Math.min((( + Math.cos(( + Math.atan2(( + x), ( + x))))) | x), x))))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[new String(''), NaN, NaN, 0.1, new String(''), new String(''), new String(''), new String(''), NaN, 0.1, 0.1, NaN, new String(''), 0.1, 0.1, new String(''), NaN, NaN, new String(''), new String(''), NaN, NaN, 0.1, NaN, 0.1, NaN, new String(''), NaN, 0.1, NaN, NaN, NaN, new String(''), NaN, 0.1, NaN, 0.1, 0.1, new String(''), new String(''), new String(''), NaN, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, NaN, 0.1, NaN, 0.1, 0.1, NaN, 0.1, new String(''), new String(''), NaN, new String(''), new String(''), NaN, new String(''), new String(''), NaN, 0.1, 0.1, NaN, 0.1, 0.1, NaN, new String(''), 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, new String(''), new String(''), NaN, NaN, NaN, new String(''), new String(''), NaN, NaN, new String(''), 0.1, NaN, NaN, new String(''), 0.1, NaN, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), 0.1, 0.1, NaN, new String(''), NaN, new String(''), new String(''), NaN, 0.1, 0.1, 0.1, 0.1, 0.1, new String(''), NaN, 0.1, NaN, new String(''), 0.1, new String(''), 0.1, new String(''), 0.1, NaN, new String(''), NaN, 0.1, NaN, 0.1]); ");
/*fuzzSeed-133180449*/count=1159; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.atan2(Math.fround(( - Math.fround(Math.fround(Math.max(Math.fround(Math.log((x << x))), x))))), (Math.fround(Math.min(Math.fround(Math.tanh((2**53 >>> 0))), (( ~ ((( - (x | 0)) | 0) | 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy5, [Math.PI, -0x080000000, 0x0ffffffff, -1/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, 0, Number.MAX_VALUE, 2**53+2, 1, 42, 1.7976931348623157e308, 2**53, 0x100000001, 1/0, -0x100000000, -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 0/0, -0x080000001, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), 2**53-2, 0.000000000000001]); ");
/*fuzzSeed-133180449*/count=1160; tryItOut("v0 = Object.prototype.isPrototypeOf.call(o2.v0, v2);");
/*fuzzSeed-133180449*/count=1161; tryItOut("\"use strict\"; Array.prototype.unshift.apply(a1, [i2, s0, a1, g2.m2]);");
/*fuzzSeed-133180449*/count=1162; tryItOut("\"use strict\"; let y = -15, y, snrhwh, w;print(-28);");
/*fuzzSeed-133180449*/count=1163; tryItOut("(function(stdlib, foreign, heap){ \"use asm\";   function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1.0625;\n    return +((-4194303.0));\n  }\n  return f; })");
/*fuzzSeed-133180449*/count=1164; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-Number.MAX_VALUE, 0x080000001, -0x07fffffff, -0x080000000, 2**53, 1/0, -1/0, Math.PI, -0x100000001, 0x100000000, 1.7976931348623157e308, 0x080000000, -(2**53-2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53), 1, 42, 2**53+2, 2**53-2, 0, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, 0x07fffffff, -0x080000001, 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-133180449*/count=1165; tryItOut("print(uneval(g0));var b = x;");
/*fuzzSeed-133180449*/count=1166; tryItOut("t2.set(a1, 13);\nt2 + g2;\n");
/*fuzzSeed-133180449*/count=1167; tryItOut("let (z = (-6\n ^= x)) (new \"\u03a0\");");
/*fuzzSeed-133180449*/count=1168; tryItOut("mathy2 = (function(x, y) { return ( + Math.sin(( + Math.atan2((Math.min((( - y) | 0), ((y || Math.fround(( ! (-0x100000000 >>> 0)))) | 0)) | 0), ( ! (x >>> 0)))))); }); testMathyFunction(mathy2, [0/0, 0x100000000, Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 42, -1/0, 0x080000000, 0, -(2**53+2), 1/0, -0, 2**53, -(2**53-2), -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0x100000000, 1.7976931348623157e308, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, 0.000000000000001, -0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53-2, 2**53+2, Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=1169; tryItOut("mathy1 = (function(x, y) { return Math.asinh((mathy0(((( - (Math.expm1(Math.hypot(1/0, (0x080000001 >>> 0))) >>> 0)) >>> 0) >>> 0), (Math.acosh(Math.fround(x)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-133180449*/count=1170; tryItOut("print(g1.b0);");
/*fuzzSeed-133180449*/count=1171; tryItOut("e0.add(b1);");
/*fuzzSeed-133180449*/count=1172; tryItOut("mathy5 = (function(x, y) { return Math.min(Math.atan2(( + x), (Math.abs((y | 0)) | 0)), Math.max(( + ((y & (( + ( ! y)) | 0)) | 0)), ( + ((mathy1(( ! (42 >>> 0)), ( ! (Math.fround(Math.log(Math.fround(y))) | 0))) - ( - x)) | 0)))); }); testMathyFunction(mathy5, [-0x0ffffffff, -0x100000000, -(2**53-2), Number.MIN_VALUE, 42, 0, Number.MAX_VALUE, 0x100000001, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 1/0, -0x07fffffff, -0x100000001, 0x080000000, 2**53, -0, 0/0, 2**53+2, 0x080000001, -Number.MIN_VALUE, -0x080000000, -1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1173; tryItOut("testMathyFunction(mathy0, /*MARR*/[0.000000000000001, new String(''), [],  \"\" , 0.000000000000001, [], 0.000000000000001,  \"\" ,  \"\" , 0.000000000000001,  \"\" , [], 0.000000000000001, new String(''), new String(''), new String(''), 0.000000000000001, 0.000000000000001, 0.000000000000001, 0.000000000000001, [], [],  \"\" ,  \"\" , new String(''), new String(''), [], new String(''),  \"\" , 0.000000000000001, 0.000000000000001,  \"\" ,  \"\" , new String(''), [], new String(''), [], new String(''), [], new String(''), 0.000000000000001, 0.000000000000001, new String(''), []]); ");
/*fuzzSeed-133180449*/count=1174; tryItOut("\"use strict\"; print( /x/g );function x()\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((((-3.8685626227668134e+25)) - ((-1.0078125))));\n    i1 = (1);\n    return +((524289.0));\n  }\n  return f;print(t1);");
/*fuzzSeed-133180449*/count=1175; tryItOut("\"use strict\"; a2.shift(a2);");
/*fuzzSeed-133180449*/count=1176; tryItOut("/*MXX2*/this.g2.String.prototype.trimLeft = m2;");
/*fuzzSeed-133180449*/count=1177; tryItOut("\"use strict\"; m1.__proto__ = h0;");
/*fuzzSeed-133180449*/count=1178; tryItOut("{for (var v of o1) { try { m1 = m2; } catch(e0) { } try { o1 = g1.o2.o1.__proto__; } catch(e1) { } s1 = s1.charAt(v1); } }");
/*fuzzSeed-133180449*/count=1179; tryItOut("\"use strict\"; t2[v2] = this.s2;");
/*fuzzSeed-133180449*/count=1180; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1181; tryItOut("/*oLoop*/for (gbuwpl = 0; gbuwpl < 35; ++gbuwpl) { v1 = t1.byteOffset; } ");
/*fuzzSeed-133180449*/count=1182; tryItOut("v0 + '';");
/*fuzzSeed-133180449*/count=1183; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; void schedulegc(this); } void 0; } Object.prototype.unwatch.call(h2, 17);");
/*fuzzSeed-133180449*/count=1184; tryItOut("mathy2 = (function(x, y) { return (((( ~ ( + (Math.exp(Math.acosh(((y < 0x080000000) >>> 0))) >>> 0))) | 0) || ( + 1/0)) !== mathy0(Math.max(-Number.MAX_SAFE_INTEGER, ( ~ (y | 0))), ((2**53 ? Math.log1p((x ? (-(2**53-2) >>> 0) : y)) : Math.imul((x >>> 0), (Math.atan2((x >>> 0), x) >>> 0))) ** x))); }); testMathyFunction(mathy2, [Math.PI, 2**53+2, -0x080000000, -0x0ffffffff, -1/0, -0x100000000, 1.7976931348623157e308, -(2**53+2), -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, -(2**53-2), 0x100000000, -0x080000001, 0x080000001, -Number.MIN_VALUE, Number.MIN_VALUE, 42, 1/0, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, 0x0ffffffff, -0, 2**53-2, 0, 0/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-133180449*/count=1185; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.clz32(Math.min(( + (Math.imul((Math.abs(( + (( + -Number.MIN_SAFE_INTEGER) % ( + 1/0)))) >>> 0), x) >>> 0)), (Math.fround(mathy4(Math.fround((( - (( - (((y >>> 0) << (x >>> 0)) >>> 0)) | 0)) | 0)), Math.fround((Math.fround(x) ? ( + (( + x) ? ( + ( ! x)) : ( + 2**53-2))) : x)))) >>> 0)))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 0x100000000, 0/0, -(2**53-2), 0x080000000, -(2**53+2), -0x100000001, 0x100000001, -0x0ffffffff, 0x080000001, 0, -0, 0x0ffffffff, 2**53-2, Number.MIN_VALUE, 1/0, 2**53, 0x07fffffff, 42, -0x080000000, -1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, 2**53+2, -0x100000000, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-133180449*/count=1186; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((0x97cc1bbe) > (((/*FFI*/ff(((((0x7e67a05a)-(0xf9c6f0ac)+(-0x8000000)) >> ((0xfde9f2d0)*-0x6865d))), ((2.0)), ((w) = new RegExp(\".|((?!\\\\S\\\\1))+*?\", \"yim\")), ((0.00390625)), ((3.022314549036573e+23)), ((-65.0)), ((7.737125245533627e+25)))|0)+((((i0))>>>((0x491cc517)+(-0x8000000)-(0xfd6d0f16))))-(i1))>>>((/*FFI*/ff(((2147483649.0)), (((-0x8000000) ? (-8.0) : (-137438953471.0))), ((((0xedbf568f)) & ((0x78667c4)))))|0)-(0x3beca1b6)+(i0))));\n    (Uint32ArrayView[((~~(String()))) >> 2]) = ((i1)-(i1)+((x) < (0xb2955402)));\n    i0 = (i0);\n    return (((Uint16ArrayView[1])))|0;\n  }\n  return f; })(this, {ff: c =>  { return (void options('strict')) } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, -0x100000000, Math.PI, -0x07fffffff, -Number.MAX_VALUE, 2**53+2, 0, -(2**53-2), -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000001, 42, -0x080000001, -1/0, 2**53-2, -Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, 0x100000001, -0, 0x07fffffff, Number.MIN_VALUE, -(2**53), -0x0ffffffff, 1/0, 0x080000000, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, 0.000000000000001, 1, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1187; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + (( + Math.min(Math.min(Math.fround(( + y)), Math.hypot((y >>> y), (Math.max(y, (y | 0)) | 0))), (Math.min((1/0 && (y | 0)), Math.tanh(x)) && x))) | 0)) >>> 0); }); testMathyFunction(mathy0, [[], (new Boolean(true)), undefined, '0', -0, 1, false, (function(){return 0;}), ({valueOf:function(){return 0;}}), (new Number(-0)), NaN, '\\0', objectEmulatingUndefined(), [0], (new Number(0)), '', ({valueOf:function(){return '0';}}), (new String('')), ({toString:function(){return '0';}}), 0, (new Boolean(false)), '/0/', null, 0.1, true, /0/]); ");
/*fuzzSeed-133180449*/count=1188; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.max(( ~ ((Math.sinh((Math.max((((Math.tanh(Math.sin(y)) >> (Math.imul(x, (( + (x | 0)) | 0)) >>> 0)) >>> 0) >>> 0), (((((( + 2**53+2) && ( + y)) >>> 0) >>> 0) & (Math.atan((Math.cos(( + y)) >>> 0)) | 0)) >>> 0)) >>> 0)) >>> 0) | 0)), Math.fround(( ! ((( ~ (( + ( ! Math.fround(x))) | 0)) | 0) , ( - y))))); }); ");
/*fuzzSeed-133180449*/count=1189; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.atan(( + (( + x) == ( + Math.fround((Math.fround(( ~ (y >>> 0))) + Math.fround(1))))))) ? ( + ((( + (( ~ (x | 0)) | 0)) % (y >>> 0)) >>> 0)) : ( + (mathy3((y >>> 0), ((Math.imul((-0x080000001 | 0), Number.MIN_SAFE_INTEGER) | 0) >>> 0)) >>> 0))) <= ((mathy3(((Math.log1p((0/0 >>> 0)) >>> 0) | 0), (Math.cos(Math.fround(0x080000001)) | 0)) | 0) ^ (( + Math.clz32((( - (( + ( - (x | 0))) >>> 0)) >>> 0))) >>> 0))); }); ");
/*fuzzSeed-133180449*/count=1190; tryItOut("\"use strict\"; Math;");
/*fuzzSeed-133180449*/count=1191; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((+(0xf5e567f)));\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [Number.MAX_VALUE, 42, 1, -Number.MIN_VALUE, 0x100000000, 0x080000000, -0x080000000, -(2**53+2), 0/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, -0x100000001, -(2**53), 2**53+2, -0, -1/0, Math.PI, -0x100000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 1/0, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 0.000000000000001, 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=1192; tryItOut("s1 += s1;");
/*fuzzSeed-133180449*/count=1193; tryItOut("mathy0 = (function(x, y) { return (Math.trunc(Math.fround((((( - Math.fround(Math.atan((x >>> 0)))) | 0) ? (Math.fround((Math.fround(( ~ -0)) != Math.fround(Math.atan2(-0x07fffffff, Math.fround(-0x100000000))))) | 0) : (( + ( ~ ( + ((-(2**53-2) >>> 0) ? 42 : (Math.fround(Math.min(Math.fround(-0x100000001), ( + y))) >>> 0))))) >>> 0)) | 0))) ^ (Math.fround(Math.atan2(( + (Math.min((( + Math.exp(Math.min(x, Number.MAX_VALUE))) | 0), ((y | ( - -0x080000000)) | 0)) >>> 0)), ( + Math.cbrt((( + ( ~ y)) >>> 0))))) & Math.acos(( + ( - ( + Math.sign((y | 0)))))))); }); testMathyFunction(mathy0, [2**53, 2**53-2, -1/0, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0.000000000000001, -0x080000000, -0, 0/0, 1/0, Math.PI, 42, 0x0ffffffff, -0x080000001, 0x100000000, -0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, 1, 2**53+2, 0, 1.7976931348623157e308, 0x080000001, -(2**53-2), 0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1194; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.cbrt((Math.tan((Math.sinh((( + (x | 0)) | 0)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-133180449*/count=1195; tryItOut("mathy0 = (function(x, y) { return ((((Math.expm1((Math.min(x, (Math.sin(( + 2**53+2)) | 0)) | 0)) >>> 0) < Math.hypot(Math.fround(((( + y) - x) && (Math.min(y, -(2**53-2)) >>> 0))), (( ~ (-0x080000000 >>> 0)) >>> 0))) , (Math.max(Math.min(x, x), ( + (Math.atan2(( + x), x) & ( + ( ! ( + (Math.exp((Math.log((0x080000001 | 0)) | 0)) | 0))))))) | 0)) | 0); }); ");
/*fuzzSeed-133180449*/count=1196; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1197; tryItOut("e0.add(g2.i0);function a(d, x, window, a, NaN, w, x, \u3056, y = \"\u03a0\", x, x = \"\\uF72F\", b, e, c, x, a, e, NaN, window, x = this, x = NaN, z, y, b, \u3056, a, c = x, x, b, x, \u3056 = window, window, y = this, d = ({a1:1}), x, e = window, x, z, x, x, z, w, NaN, e, x, e = true, x, \u3056, \"-7\", x, b, z, eval =  \"\" , x, x, toSource, z =  /x/g , x, x, \u3056, window, y, \u3056, x =  \"\" , x, b, b, d, x =  /x/g , x, b, b, x, c, x = false, x = \"\\uA2D2\", y = window, -15, \u3056, e, c = 1e-81, eval, x = /(?:\\3)\\x0e\\2|\\v|\u84e5*?(?!\\D\\b*)+?/gym, d, d, x, x = 13, eval, \u3056)\u0009\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (0xfaa7ac33);\n    return +((Float32ArrayView[(((i2) ? ((((-0x8000000)) | ((0x804856ea))) >= (~(((0x66ea3ddf) != (0xffffffff))))) : ((4294967297.0) < (((2097153.0)) - ((3.8685626227668134e+25)))))+((d0) < (-5.0))) >> 2]));\n  }\n  return f;print(window);");
/*fuzzSeed-133180449*/count=1198; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1199; tryItOut("v1 + m0;");
/*fuzzSeed-133180449*/count=1200; tryItOut("mathy1 = (function(x, y) { return ((( + ( - (( ~ (Math.tanh((( ~ y) | 0)) >>> 0)) >>> 0))) / (Math.fround(Math.abs(Math.fround((Math.fround(x) ? Math.fround(y) : Math.fround(x))))) == ( + (Math.clz32(( + (((Math.cosh(y) | 0) & Math.hypot((x | 0), Math.fround(y))) , y))) >> ( + Math.fround(Math.pow((Number.MAX_VALUE >>> 0), Math.acosh(Math.fround(( + mathy0(( + x), ( + y)))))))))))) | 0); }); testMathyFunction(mathy1, [-0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, 1/0, 2**53, -0x0ffffffff, Math.PI, 0x100000001, -(2**53+2), 1, 0.000000000000001, 0x080000000, 0x080000001, Number.MAX_VALUE, -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 0x07fffffff, -(2**53), -0x100000000, 0, -0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000000, 42, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-133180449*/count=1201; tryItOut("mathy3 = (function(x, y) { return ( + (( + Math.sinh((( + (Math.atanh((mathy0(( + Math.imul(Math.fround(y), ( + Math.asin((x >>> 0))))), -(2**53+2)) | 0)) | 0)) >>> 0))) * ( + Math.fround(Math.acos(mathy1(y, (Math.acosh((y >>> 0)) >>> 0))))))); }); ");
/*fuzzSeed-133180449*/count=1202; tryItOut("mathy4 = (function(x, y) { return (( ~ (mathy2(( ~ x), Math.fround((Number.MAX_SAFE_INTEGER << x))) | 0)) - (Math.atan2(Math.fround(Math.log1p(Math.fround(y))), Math.fround(Math.clz32(Math.fround(x)))) ** mathy2(( + x), Math.fround(Math.atan2(( + Math.atan2((y >>> 0), y)), Math.atan2(( + x), ( + (Math.cosh((-0x080000001 >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy4, [0x080000001, 0x100000000, -0x080000001, -0, Math.PI, -0x080000000, 0, 0x0ffffffff, 0x07fffffff, -(2**53+2), -0x07fffffff, -(2**53), 2**53, 42, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -0x100000000, -Number.MIN_VALUE, -0x100000001, 0/0, 1, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 1/0, 0x100000001, -1/0, 0x080000000, 2**53-2, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1203; tryItOut("e2.has(g2);");
/*fuzzSeed-133180449*/count=1204; tryItOut("/*iii*/ '' ;/*hhh*/function anqcfv(x, ...y){o0.v2 = evaluate(\"Array.prototype.reverse.call(this.a0);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: \"\u03a0\", noScriptRval: false, sourceIsLazy: (x % 9 != 4), catchTermination: (x % 3 == 2) }));}");
/*fuzzSeed-133180449*/count=1205; tryItOut("this.i0.send(g1.v2);");
/*fuzzSeed-133180449*/count=1206; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((( - mathy1((y | Math.fround(y)), Math.fround(y))) , ( + Math.fround(Math.pow(Math.tanh(x), Math.acos(-0x100000000))))) <= Math.cos((Math.max(mathy1(( ! 0x0ffffffff), y), (x , (Math.atan2(x, (y >>> 0)) >>> 0))) | 0))); }); testMathyFunction(mathy3, [0x100000000, 1.7976931348623157e308, -(2**53-2), -(2**53+2), 0x100000001, 2**53, -0x100000000, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, -(2**53), -0x0ffffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, -Number.MIN_VALUE, 0, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 2**53+2, 42, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, -0, -0x100000001, 0.000000000000001, -0x07fffffff, 1/0, 1]); ");
/*fuzzSeed-133180449*/count=1207; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( ! Math.fround((( + ( ~ (( + mathy0(Number.MAX_SAFE_INTEGER, x)) >>> 0))) ? Math.fround(Math.pow(y, ( ! Math.fround(Math.expm1(y))))) : ( + ( ~ ( + Math.fround(( ~ Math.fround(((y / x) >>> 0))))))))))); }); testMathyFunction(mathy1, /*MARR*/[ \"\" ,  \"\" , 0x080000001, 0x080000001, (void 0), [(void 0)], function(){}, [(void 0)], (void 0), [(void 0)], 0x080000001, 0x080000001, 0x080000001, [(void 0)], function(){},  \"\" , [(void 0)],  \"\" , function(){},  \"\" , [(void 0)], function(){},  \"\" , 0x080000001, 0x080000001, function(){}, function(){}, [(void 0)], [(void 0)], function(){}, [(void 0)], function(){},  \"\" , (void 0), (void 0), (void 0), function(){}, function(){}, 0x080000001, function(){}, [(void 0)], [(void 0)], [(void 0)], 0x080000001,  \"\" , 0x080000001, function(){}, [(void 0)], function(){}, function(){}, [(void 0)], (void 0), function(){}, (void 0),  \"\" , 0x080000001, function(){}, function(){}, function(){},  \"\" ,  \"\" ,  \"\" ,  \"\" , [(void 0)], 0x080000001, function(){},  \"\" , function(){}, 0x080000001, [(void 0)], 0x080000001, (void 0), [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], function(){},  \"\" , 0x080000001, 0x080000001, 0x080000001, 0x080000001, function(){}, function(){}, function(){}, 0x080000001, 0x080000001,  \"\" , 0x080000001, function(){}, (void 0),  \"\" ,  \"\" , function(){}, 0x080000001, 0x080000001, [(void 0)], function(){}, (void 0), (void 0), function(){},  \"\" ,  \"\" , function(){},  \"\" , (void 0), (void 0), [(void 0)], 0x080000001]); ");
/*fuzzSeed-133180449*/count=1208; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, -Number.MIN_VALUE, 2**53, 0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), 2**53-2, -Number.MAX_VALUE, Number.MIN_VALUE, 0, -(2**53-2), 42, 0x080000000, 0/0, 0x100000001, -Number.MIN_SAFE_INTEGER, 1/0, Math.PI, -0x100000000, -1/0, -0x100000001, -0x0ffffffff, 0.000000000000001, -0, 2**53+2, -0x080000001, -0x080000000, 0x080000001]); ");
/*fuzzSeed-133180449*/count=1209; tryItOut("/*oLoop*/for (epumxn = 0,  /* Comment */(4277); epumxn < 58; ++epumxn) { var x = (eval(\"f2 = Proxy.createFunction(h1, f2, f2);\",  /x/g .watch(\"caller\", length))), zfqmsz, x = (({}) <<= x), x =  /x/ ;/*oLoop*/for (hulizt = 0; hulizt < 27; ++hulizt) { x = a1; }  } ");
/*fuzzSeed-133180449*/count=1210; tryItOut("print(x);\nObject.seal(m0);\n");
/*fuzzSeed-133180449*/count=1211; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.log2(Math.acos(((Math.fround(Math.asinh(x)) & (( ! (x | 0)) | 0)) >>> 0)))); }); testMathyFunction(mathy1, /*MARR*/[x, -0x5a827999, x, (-0), -0x5a827999, x, (-0), -0x5a827999, x, x, (-0), new Boolean(true), x, x, x, -0x5a827999, x, -0x5a827999, (-0), -0x5a827999, -0x5a827999, x, -0x5a827999, (-0), -0x5a827999, (-0), x, (-0), new Boolean(true), x, x, -0x5a827999, new Boolean(true), -0x5a827999, x, new Boolean(true), (-0), -0x5a827999, -0x5a827999, (-0), x, (-0), new Boolean(true), x]); ");
/*fuzzSeed-133180449*/count=1212; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + ( + Math.log10(Math.pow(Math.trunc(x), (mathy4((y | 0), ( + -0x080000000)) >>> 0))))); }); testMathyFunction(mathy5, [0x07fffffff, -0x100000000, 1, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, 0, 1/0, 2**53, 0x080000001, -(2**53+2), 0x100000000, 0x0ffffffff, -0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -0x080000001, 2**53-2, 0x100000001, -0x100000001, -0x080000000, -(2**53-2), -1/0, -0x07fffffff, 0x080000000, 1.7976931348623157e308, 0.000000000000001, 42, Math.PI, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-133180449*/count=1213; tryItOut("selectforgc(o0.o2);");
/*fuzzSeed-133180449*/count=1214; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.atan2(Math.fround((Math.fround((((y | 0) == Math.hypot(Math.fround(((( ~ x) | 0) && Math.fround(x))), x)) | 0)) > (Math.pow((mathy0(((((0/0 | 0) % x) ? x : ( + (y | 0))) >>> 0), (( ! (x | 0)) >>> 0)) >>> 0), y) | 0))), Math.atan2(Math.fround(( ! (x | 0))), (Math.sinh((x >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [0x080000000, 42, 1.7976931348623157e308, 2**53, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -0x100000001, -1/0, Math.PI, -0x0ffffffff, -0x07fffffff, -(2**53+2), 0/0, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, -0x080000000, 0x100000000, -Number.MIN_VALUE, 1, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, -0, 0, 0x080000001, Number.MAX_VALUE, 1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-133180449*/count=1215; tryItOut("throw d;");
/*fuzzSeed-133180449*/count=1216; tryItOut("/*bLoop*/for (jxfjsm = 0, NaN; jxfjsm < 17; ++jxfjsm) { if (jxfjsm % 2 == 0) { (let); } else { print(x); }  } function x()d ^ xi1.send(i0);");
/*fuzzSeed-133180449*/count=1217; tryItOut("\"use strict\"; \"use asm\"; Array.prototype.sort.call(a2, (function() { for (var j=0;j<48;++j) { f0(j%2==0); } }));");
/*fuzzSeed-133180449*/count=1218; tryItOut("t2[8] = h0;");
/*fuzzSeed-133180449*/count=1219; tryItOut("/*bLoop*/for (zzmaxw = 0; zzmaxw < 161; ++zzmaxw) { if (zzmaxw % 31 == 14) { Math.pow(-20, 5);\u0009 } else { /*vLoop*/for (let pnvxwo = 0,  /x/g ; pnvxwo < 59; ++pnvxwo) { w = pnvxwo; t0 = o2.t0.subarray(v0, 4); }  }  } ");
/*fuzzSeed-133180449*/count=1220; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.hypot((mathy0(Math.hypot(y, Math.asinh(( - x))), Math.cbrt(2**53)) >>> 0), (( + Math.cosh(( + (Math.log10((((Math.fround(Math.cos(mathy0(y, x))) | 0) ** Math.fround(( + Math.fround(y)))) | 0)) | 0)))) >>> 0))); }); testMathyFunction(mathy1, [-(2**53-2), 1.7976931348623157e308, -Number.MAX_VALUE, 2**53, 0x07fffffff, Math.PI, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), Number.MIN_SAFE_INTEGER, -0, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, 0x080000000, -0x080000000, 0.000000000000001, 0x080000001, 2**53-2, 2**53+2, 0x100000001, -0x100000000, -1/0, 0, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-133180449*/count=1221; tryItOut("/*MXX1*/o2 = g2.Date.prototype.getTime;");
/*fuzzSeed-133180449*/count=1222; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!(Z{1,4}|$.(?:[^])|^\\\\W+?|[^]{0,})){0,0}\", \"gyi\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-133180449*/count=1223; tryItOut("\"use asm\"; a1 = Array.prototype.map.apply(a2, []);\n/*oLoop*/for (oauvkh = 0; oauvkh < 3; ++oauvkh) {  \"\" ; } \n");
/*fuzzSeed-133180449*/count=1224; tryItOut("\"use strict\"; Object.defineProperty(g2, \"o0.v1\", { configurable: true, enumerable: true,  get: function() {  return evalcx(\"this.g2.f1(i2);\", g0); } });");
/*fuzzSeed-133180449*/count=1225; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.exp(( + Math.imul((Math.acosh((( + Math.fround(Math.max(( ~ y), (-(2**53) - y)))) | 0)) | 0), Math.fround((Math.fround(Math.log2(y)) , x)))))); }); testMathyFunction(mathy3, [0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, Math.PI, 0x100000000, -(2**53), -0x07fffffff, 0x080000000, 1.7976931348623157e308, -0x100000000, 1, 0x080000001, -1/0, -0x080000001, 1/0, -0x0ffffffff, 42, 0x0ffffffff, 2**53-2, -0x100000001, 0x07fffffff, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0, 0, -0x080000000, 2**53+2]); ");
/*fuzzSeed-133180449*/count=1226; tryItOut("t2 = new Uint8ClampedArray(a2);");
/*fuzzSeed-133180449*/count=1227; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(h1, p2);");
/*fuzzSeed-133180449*/count=1228; tryItOut("mathy0 = (function(x, y) { return ( ~ ( + Math.atanh(Math.fround(Math.abs(y))))); }); testMathyFunction(mathy0, ['', [0], (new Number(-0)), ({valueOf:function(){return 0;}}), '/0/', (new Boolean(true)), '\\0', 0, ({valueOf:function(){return '0';}}), null, /0/, [], (new Number(0)), false, ({toString:function(){return '0';}}), objectEmulatingUndefined(), -0, undefined, (function(){return 0;}), 0.1, NaN, (new Boolean(false)), true, 1, (new String('')), '0']); ");
/*fuzzSeed-133180449*/count=1229; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.ceil(Math.cos(((( + (y ** Math.hypot(( + -0x080000001), ( + Math.atan(( + y)))))) | ( + (( + ( ~ ( + x))) | 0))) >>> 0)))); }); testMathyFunction(mathy5, [-0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, 0/0, -Number.MAX_SAFE_INTEGER, 2**53+2, -1/0, 0x07fffffff, 0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0, -(2**53+2), -0x100000000, 0x080000000, -Number.MIN_VALUE, 0x0ffffffff, 0x080000001, 0.000000000000001, 42, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, -(2**53-2), 1/0, -0, 2**53, -0x100000001, -Number.MAX_VALUE, 1, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1230; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 1, Math.PI, 0x100000000, 1.7976931348623157e308, -0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 0x100000001, 0x080000000, 0x07fffffff, -0x100000001, 0, 2**53-2, 0x080000001, 42, 0.000000000000001, -1/0, 0/0, -(2**53+2), -0x080000001, -(2**53-2), 2**53+2, -(2**53), -0x100000000, -0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=1231; tryItOut("/*tLoop*/for (let y of /*MARR*/[(1/0),  /x/ , (1/0), -Number.MIN_SAFE_INTEGER,  /x/ ,  /x/ , (1/0),  /x/ , -Number.MIN_SAFE_INTEGER, (1/0), (1/0), (1/0), (1/0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (1/0),  /x/ , (1/0), -Number.MIN_SAFE_INTEGER,  /x/ , -Number.MIN_SAFE_INTEGER, (1/0),  /x/ ,  /x/ , -Number.MIN_SAFE_INTEGER, (1/0), (1/0), (1/0), -Number.MIN_SAFE_INTEGER,  /x/ , (1/0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (1/0),  /x/ ,  /x/ , -Number.MIN_SAFE_INTEGER,  /x/ ,  /x/ , -Number.MIN_SAFE_INTEGER,  /x/ , -Number.MIN_SAFE_INTEGER, (1/0), (1/0),  /x/ , (1/0), (1/0), (1/0), (1/0), (1/0),  /x/ ,  /x/ , -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER,  /x/ ,  /x/ , (1/0), (1/0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER,  /x/ ,  /x/ , (1/0), (1/0), -Number.MIN_SAFE_INTEGER,  /x/ ,  /x/ , (1/0), -Number.MIN_SAFE_INTEGER,  /x/ , (1/0), -Number.MIN_SAFE_INTEGER, (1/0),  /x/ , (1/0),  /x/ , -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (1/0), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, (1/0),  /x/ , (1/0), (1/0),  /x/ , (1/0),  /x/ , -Number.MIN_SAFE_INTEGER, (1/0),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , (1/0), (1/0),  /x/ , (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , (1/0), (1/0), (1/0), -Number.MIN_SAFE_INTEGER, (1/0), (1/0), -Number.MIN_SAFE_INTEGER,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , (1/0), -Number.MIN_SAFE_INTEGER, (1/0),  /x/ ,  /x/ ]) { /*RXUB*/var r = new RegExp(\"(?=(?!\\\\3|(?:[\\\\D\\\\u001C]{0,}){1})){3}\", \"gi\"); var s = \"\"; print(uneval(s.match(r)));  }\n");
/*fuzzSeed-133180449*/count=1232; tryItOut("t1 = new Int32Array(a2);c = Math.pow(let (a = (4277), guyuyq, epptjd, c, NaN, iswcme, window, c, x) this.__defineGetter__(\"x\", Math.abs), (void options('strict')) /= (window ? (t0[9] = t2) : x.valueOf(\"number\")));");
/*fuzzSeed-133180449*/count=1233; tryItOut("/*iii*/for(let [b, w] = ([ \"\" ]) in /[^]?\\2**(?=\\D?)/yi) {let a1 = Array.prototype.concat.apply(a2, [t0, g1.t1, a0]);(\"\\u460E\"); }/*hhh*/function nkiool(...x){e1.delete(h0);}");
/*fuzzSeed-133180449*/count=1234; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1235; tryItOut("m0 + '';");
/*fuzzSeed-133180449*/count=1236; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.pow(Math.fround(( ~ Math.fround((Math.fround(( - Math.fround(y))) ** Math.atan2(( + (( + x) <= ( + ((x * (y >>> 0)) >>> 0)))), ((Math.atan(((((-(2**53+2) | 0) || (y | 0)) | 0) | 0)) | 0) | 0)))))), (( + Math.sin(( ! Math.cbrt(( + (( + x) + -0x080000000)))))) ? ( + (( + (( ! ((( + (( + x) ? ( + y) : ( + -0x100000000))) ? ( + ( + Math.sqrt(( + 1)))) : x) | 0)) | 0)) , ( + (-0x080000001 ? y : ( + Math.min(Math.fround(( ~ Math.PI)), y)))))) : ( + (((Math.atanh((Math.fround(((y | 0) ? ( + (x >>> 0)) : (-0x100000001 | 0))) >>> 0)) >>> 0) | 0) | (Math.min((-1/0 === ( + (( + Math.fround(Math.pow(Math.fround(2**53-2), ( + x)))) < ( + x)))), Math.fround(Math.atan2(( + Math.sqrt(x)), ( + x)))) | 0))))); }); testMathyFunction(mathy0, [-(2**53), -Number.MAX_VALUE, 0x080000000, -0x07fffffff, -(2**53+2), Number.MIN_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, -0x100000001, 0x100000001, -0, 1/0, -0x080000000, -Number.MIN_VALUE, -0x0ffffffff, -0x080000001, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, 2**53, 0x0ffffffff, -0x100000000, Number.MAX_VALUE, 1, -(2**53-2), 1.7976931348623157e308, 42, Math.PI, 0x07fffffff, 0, Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-133180449*/count=1237; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.atan2((((((Math.hypot(((( + (0x080000000 | 0)) ? y : Math.round(x)) | 0), (Math.fround((Math.fround(Math.fround(mathy0(Math.fround(Math.fround((Math.fround(( + Math.sin(( + y)))) || y))), Math.fround(( + ( - ( + x))))))) && Math.fround((y / Math.fround(mathy1(Math.fround(y), Math.fround(y))))))) | 0)) | 0) >>> 0) << ( + ((Math.fround(( ~ ( + ( + Math.fround(-(2**53)))))) >>> 0) ^ (Math.fround((( + (Math.sin((x | 0)) | 0)) & ((x <= y) | 0))) >>> 0)))) >>> 0) >>> 0), ( + Math.log(( + (x === y))))) >>> 0); }); testMathyFunction(mathy3, [-0x100000001, 42, Math.PI, 0/0, -1/0, 0x100000000, 0, 1/0, 2**53-2, 0x080000000, 2**53, -0x0ffffffff, -0, -0x100000000, -0x080000000, -0x080000001, Number.MAX_VALUE, 0x100000001, 0.000000000000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 1, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53), 1.7976931348623157e308, -(2**53-2), 0x080000001]); ");
/*fuzzSeed-133180449*/count=1238; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( - Math.fround(Math.max(Math.atan2(Math.max(0x080000000, x), ( ~ Math.cosh(-(2**53)))), (Math.sqrt((y >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [2**53+2, 0x100000000, -0, 1/0, 1.7976931348623157e308, 0x080000000, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), -0x07fffffff, -0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0, 0x0ffffffff, -1/0, 0x080000001, -0x100000000, Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 42, 0/0, 0x100000001, -(2**53+2), -Number.MIN_VALUE, Number.MIN_VALUE, 2**53-2, -(2**53), -Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, -0x080000001, 0.000000000000001, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1239; tryItOut("print([1] -  /x/g );/* no regression tests found */");
/*fuzzSeed-133180449*/count=1240; tryItOut("/*tLoop*/for (let b of /*MARR*/[x, 0x50505050, x, 0x50505050, x, 0x50505050, x, 0x50505050, x, 0x50505050, x, 0x50505050, x, 0x50505050, x, x, x, 0x50505050, x, x, 0x50505050, x, 0x50505050, x, x, x, 0x50505050, x, x, x, x, 0x50505050, x, x, 0x50505050, 0x50505050, x, x, 0x50505050, x, 0x50505050, 0x50505050, x, x, x, x, x, x, x, x, 0x50505050, x, x, x, x, 0x50505050, 0x50505050, x, x, x, x, 0x50505050, x, x, x, x, x, x, 0x50505050, x, 0x50505050, x, x, x, 0x50505050, 0x50505050, x, x, x, x, x, 0x50505050, x, x, 0x50505050, x, 0x50505050, 0x50505050, 0x50505050, x, 0x50505050, x, x, x, 0x50505050, x, x, x, x, 0x50505050, x, 0x50505050, x, x, x, x, 0x50505050, x, 0x50505050, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, 0x50505050, 0x50505050, x, 0x50505050, x, x, x, x, x, 0x50505050, 0x50505050, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, 0x50505050, x, 0x50505050, x, x, 0x50505050, 0x50505050, x, x, 0x50505050, 0x50505050, x]) { Array.prototype.forEach.call(a0, (function() { try { b2 = t0.buffer; } catch(e0) { } a0 = m1.get(t2); return h1; })); }\nlet (d, vgzjrt, z, aypzgn, oiodzt, hxlhxj, this.b, y, mhfuon, kbwwyo) { this.t0 = x; }\n");
/*fuzzSeed-133180449*/count=1241; tryItOut("mathy5 = (function(x, y) { return Math.hypot((Math.imul((Math.fround(Math.cos(Math.fround(Math.acos(-(2**53))))) ? ( + x) : x), Math.max(mathy3(Math.ceil(0/0), x), (((((y + Math.fround(y)) | 0) - (Number.MIN_VALUE | 0)) >>> 0) >>> 0))) | 0), (( - ( + ( + ( + ( - Math.fround(y)))))) || ( + (y / ( + (mathy0(( + ((((x | 0) || (42 >>> 0)) | 0) + ( + (Math.atan2(Math.fround(( ! x)), x) >>> 0)))), Math.acosh(Math.fround(x))) | 0)))))); }); ");
/*fuzzSeed-133180449*/count=1242; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.asin(Math.expm1((( + mathy1(( + (((y === (x | 0)) ? ((Math.max(Math.PI, y) >>> 0) | 0) : Math.atan2(y, Math.fround(x))) >>> 0)), x)) == ( + ( ~ Math.fround(( + (( + y) * ( + Math.ceil(1.7976931348623157e308)))))))))); }); testMathyFunction(mathy2, [-1/0, -(2**53+2), 2**53, Number.MIN_VALUE, -0x100000001, 42, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, 0x07fffffff, 1, -0x080000000, 1.7976931348623157e308, 0x080000001, -(2**53-2), 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, 0x0ffffffff, -Number.MIN_VALUE, 0x100000001, -0x07fffffff, 2**53+2, 0/0, Math.PI, 1/0, -0x080000001, -0x0ffffffff, 0.000000000000001, -(2**53), -Number.MAX_VALUE, -0, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1243; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1244; tryItOut("\"use strict\"; a1.shift();true;");
/*fuzzSeed-133180449*/count=1245; tryItOut("m2.has(i1);");
/*fuzzSeed-133180449*/count=1246; tryItOut(";");
/*fuzzSeed-133180449*/count=1247; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(( - ( + Math.fround(Math.log10(Math.fround(1))))), Math.fround(Math.tanh(Math.fround((( - ((((-(2**53) & Number.MIN_SAFE_INTEGER) | 0) ? Math.fround(( + x)) : ( + (y * (Math.tanh(x) !== (y >>> 0))))) | 0)) | 0))))); }); testMathyFunction(mathy4, [-(2**53), 2**53-2, -0x080000000, Number.MIN_VALUE, 0x100000001, -0, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, 2**53+2, 0x080000001, -(2**53-2), 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, 42, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, 0, 2**53, 0/0, -0x0ffffffff, 1, 0.000000000000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MAX_VALUE, 0x0ffffffff, 1/0, -1/0]); ");
/*fuzzSeed-133180449*/count=1248; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1249; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + Math.atan2(Math.fround(Math.acos(Math.fround(( + Math.sqrt(( + ( ~ Math.PI))))))), ( + (( ~ ( + ( ! (((Math.fround(( + Math.fround(x))) | 0) ** (y | 0)) | 0)))) ** ((Math.expm1(y) | 0) & (Math.atan2((y | 0), (0x07fffffff | 0)) | 0)))))); }); testMathyFunction(mathy5, [1/0, 0x100000000, 0, 2**53-2, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, -1/0, Number.MAX_VALUE, 0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000, -0x07fffffff, -0, 0x07fffffff, Math.PI, 0x080000001, -0x100000000, 2**53+2, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, 0x100000001, -0x0ffffffff, -(2**53), 1, 0/0, -0x080000001, 42, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1250; tryItOut("mathy3 = (function(x, y) { return (( + Math.atan2((Math.hypot(x, Math.fround((1 >> (( - ( + x)) >>> 0)))) , Math.pow(y, (((x >>> 0) >= (x >>> 0)) | 0))), ( + (Math.exp((Math.fround(Math.cosh(Math.fround(Math.fround(Number.MAX_SAFE_INTEGER)))) | 0)) | 0)))) * ( + (Math.fround(y) ? Math.tan(( - x)) : (Math.fround(Math.sin(Math.fround(Math.expm1(x)))) ? (mathy2((Math.fround(( ! (((x >>> 0) ** (y >>> 0)) >>> 0))) | 0), (mathy2(x, 0x07fffffff) | 0)) | 0) : y)))); }); testMathyFunction(mathy3, [-(2**53), 2**53, -(2**53+2), 0, -Number.MIN_VALUE, -0x07fffffff, 0x080000001, 1.7976931348623157e308, 1/0, -0x080000001, 0/0, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, -0x080000000, -0, 0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, Number.MAX_SAFE_INTEGER, 42, 1, Math.PI, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, -Number.MAX_VALUE, 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1251; tryItOut("\"use strict\"; w.stack;let(z = intern(Array()) *= x, suchaw, y = ([x]) =  /x/g  += x, x, sdhdmk, [] =  '' , x = e) { ;}");
/*fuzzSeed-133180449*/count=1252; tryItOut("mathy4 = (function(x, y) { return Math.max(((Math.atan2(Math.hypot((( + ( ! ( + x))) >>> 0), Math.hypot(Math.trunc(0x07fffffff), Math.fround(Math.round(x)))), Math.sinh((Math.asinh((y >>> x)) == y))) | Math.fround((Math.fround(( ! Math.fround(mathy2((Math.max(( + y), Math.sinh(x)) >>> 0), (y >>> 0))))) === Math.abs(Math.fround(Math.asin(1)))))) >>> 0), Math.fround(( - (( ~ Math.min(((Math.imul(-0, y) ? y : -0x100000000) >>> 0), Math.fround(((y >>> 0) & Math.fround((( ~ ( + y)) | 0)))))) | 0)))); }); testMathyFunction(mathy4, [(new Boolean(false)), null, 0, objectEmulatingUndefined(), '', (function(){return 0;}), 1, undefined, [], '0', '\\0', ({valueOf:function(){return 0;}}), (new Boolean(true)), (new Number(0)), (new Number(-0)), [0], ({toString:function(){return '0';}}), NaN, ({valueOf:function(){return '0';}}), 0.1, true, '/0/', false, (new String('')), -0, /0/]); ");
/*fuzzSeed-133180449*/count=1253; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (mathy1((Math.sign(Math.fround(Math.fround((Math.acosh(y) ** ( - y))))) | 0), (Math.fround((Math.fround(mathy2(( + ( - -(2**53+2))), ( + ( + ( + (y != ( + mathy1(y, x)))))))) !== Math.fround(Math.abs(( + Math.atan(Math.cbrt(( + Math.cbrt(( + x)))))))))) | 0)) | 0); }); ");
/*fuzzSeed-133180449*/count=1254; tryItOut("\"use strict\"; Array.prototype.unshift.apply(o1.a2, [m2,  /x/g ]);");
/*fuzzSeed-133180449*/count=1255; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.min((Math.hypot(Math.fround((((Math.atan2((Math.atan((x | 0)) | 0), ( ~ ( - y))) ** (mathy0(x, (y >>> 0)) >>> 0)) >>> 0) & (Math.expm1((0.000000000000001 >>> 0)) >>> 0))), (( + Math.atan2(y, ( + y))) | 0)) >>> 0), (( - (mathy0(x, (( + ( + ( - ( + y)))) >>> 0)) | 0)) >>> 0))); }); testMathyFunction(mathy2, [-0x080000001, -(2**53-2), 2**53, 0x100000001, Math.PI, 0x080000001, -0x07fffffff, 0/0, 0x080000000, -Number.MIN_VALUE, -0x100000001, -0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -0, -1/0, 0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0, 0.000000000000001, -0x080000000, -0x0ffffffff, 0x100000000, -(2**53+2), 1, Number.MIN_SAFE_INTEGER, 2**53+2, 42, -Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1256; tryItOut("/*MXX2*/g1.g1.Function.prototype.bind = o2.g1.o2;");
/*fuzzSeed-133180449*/count=1257; tryItOut("\"use strict\"; testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), '', 0, true, (new Boolean(true)), [0], '0', undefined, ({toString:function(){return '0';}}), (new Number(0)), '\\0', 0.1, -0, [], objectEmulatingUndefined(), '/0/', 1, null, (new Number(-0)), false, (new Boolean(false)), NaN, (new String('')), (function(){return 0;}), /0/]); ");
/*fuzzSeed-133180449*/count=1258; tryItOut("\"use strict\"; this.h2.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-133180449*/count=1259; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return new /*wrap1*/(function(){ \"use strict\"; print(y);return \"\\uAF6E\"})()(); }); testMathyFunction(mathy3, [-(2**53), 0/0, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53-2, 0, -0x100000000, Math.PI, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, -0x080000000, -0x0ffffffff, 0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 1.7976931348623157e308, -1/0, -0x100000001, 1, 0x080000001, 0x0ffffffff, -0x07fffffff, 42, -0, 1/0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=1260; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2?((?=\\\\B)?)\", \"gim\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-133180449*/count=1261; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.atan2(( - mathy2((( ~ 42) === Math.fround(-Number.MAX_VALUE)), (Math.expm1(( + Math.atan(Math.fround(x)))) | 0))), (Math.fround(Math.acos(Math.fround(Math.fround(( + Math.fround((y && x))))))) * Math.tanh(( + mathy2(( - x), y)))))); }); testMathyFunction(mathy3, [-(2**53-2), Number.MAX_VALUE, -0x100000001, -0x100000000, 2**53+2, -0x07fffffff, 1, 0.000000000000001, 0x100000001, 0x07fffffff, -0x080000000, -0, 2**53-2, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, 42, 0x080000001, 1.7976931348623157e308, -0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, -(2**53+2), 0x080000000, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, 2**53, -Number.MIN_VALUE, Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-133180449*/count=1262; tryItOut("print(Math.min((void shapeOf(((b = window)))), -6));");
/*fuzzSeed-133180449*/count=1263; tryItOut("\"use strict\"; L:for(var e in (/*UUV2*/(y.getInt8 = y.round))) h0.getOwnPropertyNames = (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((0xa3db598f) > (((-0x8000000)*-0x33162)>>>(((((0x34c56d81)) << ((4277))))+(0xfee0bf7c))))*0xa048d))|0;\n  }\n  return f; });{ if (isAsmJSCompilationAvailable()) { void 0; void schedulegc(156); } void 0; }");
/*fuzzSeed-133180449*/count=1264; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-1/0, 1, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x100000001, -(2**53+2), 0/0, 2**53+2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), -0x07fffffff, -0x0ffffffff, 0x080000001, 0x080000000, 0x100000000, -0x100000000, 2**53, -0x080000000, -(2**53), Number.MAX_VALUE, -0x080000001, 42, Number.MIN_VALUE, 0x0ffffffff, Math.PI, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, 2**53-2, -0]); ");
/*fuzzSeed-133180449*/count=1265; tryItOut("var d = [,,z1];a2.push(f2);\nprint(x);\n");
/*fuzzSeed-133180449*/count=1266; tryItOut("\"use strict\"; m2.has(s0);");
/*fuzzSeed-133180449*/count=1267; tryItOut("\"use strict\"; a0[14];\ni2 = new Iterator(e0);\n");
/*fuzzSeed-133180449*/count=1268; tryItOut("mathy0 = (function(x, y) { return ((Math.tan(((( ~ ((( ! (( + ( ~ ( + y))) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0) * Math.imul(( + ( + ( + Math.asinh((x != y))))), Math.log2(( + (( + ( ! ( + ((y >>> 0) ^ -0)))) | 0))))); }); testMathyFunction(mathy0, [2**53+2, -0x0ffffffff, 0x07fffffff, 2**53-2, 0, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53, -(2**53-2), 1/0, 1, -1/0, 0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, Math.PI, -0x080000000, -0x100000000, 42, 0x100000001, -Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 0x0ffffffff, -0, 0x100000000, -(2**53), 0/0]); ");
/*fuzzSeed-133180449*/count=1269; tryItOut("switch(x) { case 6: t1 = new Uint16Array(this.a0);default: v0 = evaluate(\"/$(?![^])*{2,}|(?:\\\\W|^|\\\\1{32769,32773}|.?[\\\\x1e])?/gy;p1 = o2.m0.get(b2);\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: eval(\"print( '' .unwatch(\\\"toSource\\\"));\", undefined), noScriptRval: true, sourceIsLazy: (x % 5 == 1), catchTermination: true }));case Math.max( \"\" , -0.567): /*infloop*/while(x){/*bLoop*/for (let qhylop = 0; qhylop < 0; ++qhylop, (void options('strict'))) { if (qhylop % 6 == 4) { g2 + ''; } else { ;return  /x/g ; }  } this.m2 + ''; }break; case (makeFinalizeObserver('nursery')): for(var a in ((eval)((yield new RegExp(\"(?=.*)(?![^\\\\W\\\\w\\u3037-px])|[^]{3,}.\\\\b|\\\\u007d*|(.?){3,}|(?!\\\\B){2}\", \"gm\")))))e1.delete(f2);a0.toSource = f1;break; m1.set(this.o1.a0, s1);break;  }");
/*fuzzSeed-133180449*/count=1270; tryItOut("mathy1 = (function(x, y) { return Math.atan2((((( + ( - ( + (Math.pow((( + Math.min(( + Math.hypot(( + (y ^ (x >>> 0))), x)), ( + x))) >>> 0), (x | 0)) >>> 0)))) | 0) !== (( + Math.fround(( - ( ! ( + y))))) | 0)) | 0), Math.fround(Math.tan(Math.ceil(((Math.asinh((( + x) >>> 0)) >>> 0) | 0))))); }); testMathyFunction(mathy1, /*MARR*/[{}, (void 0), x, x, (void 0),  /x/ , {}, -0, x,  /x/ , {}, x, x, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, -0, x, -0, -0, x]); ");
/*fuzzSeed-133180449*/count=1271; tryItOut("\"use strict\"; /*bLoop*/for (pckxhj = 0; pckxhj < 9; ++pckxhj) { if (pckxhj % 25 == 10) { ; } else { print(x); }  } ");
/*fuzzSeed-133180449*/count=1272; tryItOut("for (var v of p0) { try { /*RXUB*/var r = this.r2; var s = s2; print(s.replace(r, function ([y]) { }));  } catch(e0) { } try { a1 = arguments; } catch(e1) { } v2 = this.r0.toString; }");
/*fuzzSeed-133180449*/count=1273; tryItOut("with({d: (4277).eval(\"o2 = Object.create(s1);\")}){Array.prototype.forEach.apply(a0, [f0]);this.t2[(window = Proxy.createFunction(({/*TOODEEP*/})(this), new Function, (Function).bind) ? (4277) : ((d) =  '' ))]; }");
/*fuzzSeed-133180449*/count=1274; tryItOut("mathy5 = (function(x, y) { return ( + ( - ( + ( - (Math.imul(Math.atan2(y, x), (mathy1(x, x) >>> y)) | 0))))); }); testMathyFunction(mathy5, [1, ({valueOf:function(){return 0;}}), (function(){return 0;}), objectEmulatingUndefined(), 0.1, (new String('')), [0], [], (new Number(0)), 0, undefined, true, '', -0, '\\0', /0/, ({toString:function(){return '0';}}), (new Boolean(false)), '0', (new Boolean(true)), ({valueOf:function(){return '0';}}), false, '/0/', null, (new Number(-0)), NaN]); ");
/*fuzzSeed-133180449*/count=1275; tryItOut("mathy1 = (function(x, y) { return Math.atan2(Math.atan2(((mathy0((y << 0x080000001), Math.exp(( + Number.MIN_VALUE))) >>> Math.hypot(x, ( + (( + x) === ( + (( ~ (0x100000000 | 0)) | 0)))))) | 0), ( + (( ~ (y | 0)) >> Math.fround(mathy0(Math.atan2(Math.fround((Math.pow((x >>> 0), (0.000000000000001 >>> 0)) >>> 0)), Math.fround(y)), Math.fround(y)))))), ((y >>> ( + ( + Math.hypot((x >>> (y >>> 0)), mathy0((Math.fround((y ^ Math.fround(Math.fround(Math.tan(Number.MIN_VALUE))))) >>> 0), (-Number.MIN_SAFE_INTEGER >>> 0)))))) * Math.pow(( + (( + y) << ( + -0))), ( ~ ( + Math.atan2((y | 0), (Math.PI >>> 0))))))); }); ");
/*fuzzSeed-133180449*/count=1276; tryItOut("\"use strict\"; o0.h1.enumerate = (function(j) { if (j) { try { v1 = evaluate(\"function f0(h1)  { yield e in w } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: Object.defineProperty(\u3056, \"toString\", ({configurable: (x % 12 == 0)})).watch(\"__parent__\", Date.prototype.getMilliseconds), sourceIsLazy: (x % 70 == 62), catchTermination: ({/*toXFun*/toSource: function() { return this; },  set 29 z (b) { print(x); }  }), sourceMapURL: o0.o0.s2 })); } catch(e0) { } for (var p in t0) { try { s1 += 'x'; } catch(e0) { } try { ; } catch(e1) { } t1 = e2; } } else { try { m2.set(t2, this.o1); } catch(e0) { } g0.e1.add(b2); } });");
/*fuzzSeed-133180449*/count=1277; tryItOut("try { return (yield /*FARR*/[ /x/ ].some( /x/g , length)); } catch(x if (function(){let(c) ((function(){return x;})());})()) { x.lineNumber; } catch(y if x) { /(?!\\2)|(\\w)/g } catch(x) { let(b) ((function(){-26 = z;})()); } finally { try { String.prototype.trimLeft } finally { for(let y in (function() { yield x; } })())  /x/ ; }  } /*tLoop*/for (let d of /*MARR*/[new Number(1.5), new Number(1.5), 0x0ffffffff, new Number(1.5), 0x0ffffffff, new Number(1.5), 0x0ffffffff, new Number(1.5), 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, new Number(1.5), 0x0ffffffff, 0x0ffffffff, new Number(1.5), 0x0ffffffff, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x0ffffffff, new Number(1.5)]) { (\"\\u2AE2\"); }");
/*fuzzSeed-133180449*/count=1278; tryItOut("/*infloop*/while(( /x/ .unwatch(\"indexOf\"))){print(x);f2(f2); }");
/*fuzzSeed-133180449*/count=1279; tryItOut("for (var p in p2) { try { /*MXX2*/g2.Array.prototype.join = g1; } catch(e0) { } try { for (var v of e2) { try { m1 = new Map; } catch(e0) { } o1.a2.sort((function(j) { f2(j); }), (4277)); } } catch(e1) { } try { v2 = g1.eval(\"Object.defineProperty(this, \\\"t1\\\", { configurable: (x % 5 != 3), enumerable: (x % 2 == 0),  get: function() { g1.v2 = (g2.i0 instanceof b0); return new Uint8Array(5); } });\"); } catch(e2) { } i1.next(); }");
/*fuzzSeed-133180449*/count=1280; tryItOut("mathy0 = (function(x, y) { return (Math.sign((Math.abs((Math.log1p((( + ( + Math.abs(Math.fround(x)))) | 0)) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-133180449*/count=1281; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x080000001, 0x080000001, -1/0, 42, -0x07fffffff, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53), -0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, -0x100000000, 0/0, -(2**53-2), 1/0, 2**53-2, Number.MIN_SAFE_INTEGER, 2**53+2, 1, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, 0x080000000, -(2**53+2), 0x100000001, -0x080000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=1282; tryItOut("m1.get(t1);");
/*fuzzSeed-133180449*/count=1283; tryItOut("v0 = t2.byteOffset;");
/*fuzzSeed-133180449*/count=1284; tryItOut("this.zzz.zzz;with({}) { throw z; } ");
/*fuzzSeed-133180449*/count=1285; tryItOut("mathy2 = (function(x, y) { return (( ! ((((Math.pow(( + ( + Math.pow(Math.imul((( - (y | 0)) >>> 0), x), Math.imul((x | 0), ( + Math.min(( + x), ( + ( ! y)))))))), ( - (y != x))) >>> 0) ? (Math.fround(( ! Math.fround(x))) >>> 0) : (Math.asin(( + Math.hypot((( + x) >>> 0), (0 | 0)))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0, 0, 0x080000001, 0.000000000000001, -(2**53-2), -0x07fffffff, -0x100000000, 0/0, 1/0, 2**53+2, 1, 2**53-2, 42, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, 0x100000001, 0x080000000, -1/0, -Number.MAX_VALUE, 0x07fffffff, Number.MAX_VALUE, -0x080000001, -0x080000000, Math.PI, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, 0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1286; tryItOut("mathy2 = (function(x, y) { return Math.fround(mathy1(Math.fround(Math.max(Math.sinh((Math.sinh((-0x0ffffffff + y)) / Math.fround(((( ~ -Number.MAX_VALUE) | 0) * x)))), (( + Math.sinh((Math.PI && ( + Math.fround(Math.clz32(Math.fround(y))))))) < ( + (Math.log10((mathy0((x | 0), (-Number.MIN_VALUE >>> 0)) | 0)) >>> 0))))), Math.fround((mathy1((( + Math.asinh(( + ( + mathy0(Math.fround(( ! Math.fround(Math.asinh(((y !== (x | 0)) | 0))))), ( + Math.tan((0x100000001 | 0)))))))) | 0), Math.fround((mathy1(Math.asin(((Math.min(( + y), 0/0) >>> 0) , (-0 >>> 0))), (Math.hypot((y >= y), ( + -Number.MIN_SAFE_INTEGER)) >>> 0)) << ( + x)))) | 0)))); }); testMathyFunction(mathy2, [-0, Math.PI, Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, -0x100000000, 0, -0x080000001, 1/0, 0x0ffffffff, 0x080000001, 42, -(2**53+2), 2**53-2, -0x080000000, 0x07fffffff, -0x07fffffff, -0x100000001, Number.MIN_VALUE, 1, -Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x100000001, -Number.MAX_VALUE, -1/0]); ");
/*fuzzSeed-133180449*/count=1287; tryItOut("testMathyFunction(mathy0, [-0x080000001, -0x100000001, 0x080000001, 1.7976931348623157e308, -1/0, 0, Math.PI, Number.MIN_SAFE_INTEGER, 42, 1/0, -(2**53-2), 0x100000000, 1, -(2**53), 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, 0/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, 0x100000001, 0x080000000, -0x100000000, 2**53, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1288; tryItOut("\"use strict\"; /*vLoop*/for (let fbawuj = 0; fbawuj < 26; ++fbawuj) { c = fbawuj; Object.defineProperty(this, \"v2\", { configurable: c, enumerable: true,  get: function() {  return a2.every((function(j) { if (j) { try { f2 + ''; } catch(e0) { } v1 = t0.length; } else { try { h1.has = o2.f1; } catch(e0) { } try { f2 = (function(j) { if (j) { try { for (var p in o2.m0) { try { Object.defineProperty(this, \"this.v2\", { configurable: false, enumerable: (c % 2 != 1),  get: function() { Object.defineProperty(this, \"v2\", { configurable:  '' , enumerable: /[^](\\W){1,}?\\3/gym,  get: function() {  return Array.prototype.reduce, reduceRight.apply(a1, [new RegExp(\"(?!.)|(?:(?=$){0,3})$|\\\\b|\\\\u00f4\\\\b{2,6}(?!\\\\B{0})\", \"im\")]); } }); return g2.eval(\"\\\"use strict\\\"; for (var v of p0) { i1 = new Iterator(g2, true); }\"); } }); } catch(e0) { } g1.g0.s0 += s1; } } catch(e0) { } try { v0 = evalcx(\"h2.__proto__ = p2;\", o0.g1); } catch(e1) { } this.t2[0]; } else { try { delete s1[\"charCodeAt\"]; } catch(e0) { } try { h1.getOwnPropertyNames = (function mcc_() { var sdgwbq = 0; return function() { ++sdgwbq; f0(/*ICCD*/sdgwbq % 6 == 0);};})(); } catch(e1) { } try { m2.has( '' ); } catch(e2) { } o2 + t2; } }); } catch(e1) { } try { v2 = g2.eval(\"print((this\\n));\"); } catch(e2) { } /*RXUB*/var r = r2; var s = s2; print(uneval(r.exec(s)));  } }), s2); } }); } ");
/*fuzzSeed-133180449*/count=1289; tryItOut("v1 = evaluate(\"t0.toString = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14) { var r0 = a12 ^ x; var r1 = a8 | a5; var r2 = a8 * a14; var r3 = a9 & a0; var r4 = a3 & a13; a0 = a0 / a10; var r5 = 6 + a14; var r6 = r4 ^ 8; r6 = 4 & 2; var r7 = 1 / 3; r2 = a14 - a10; print(a0); var r8 = a3 / 6; var r9 = 6 ^ r7; var r10 = 4 ^ 1; var r11 = 3 ^ r9; var r12 = 8 + a4; a7 = 0 - 1; var r13 = a14 - a8; var r14 = 5 ^ 8; var r15 = r9 - 5; var r16 = 0 - r9; var r17 = a12 / r16; var r18 = r7 & 4; var r19 = r17 - r10; var r20 = r17 & a3; var r21 = r16 - r12; var r22 = 4 | 6; var r23 = a3 & 7; var r24 = a3 % r1; var r25 = a12 & 4; var r26 = 0 ^ r11; var r27 = a7 % a8; var r28 = 6 * x; var r29 = 0 ^ a9; var r30 = 7 + 9; var r31 = r1 * a4; var r32 = r18 % 1; var r33 = r15 ^ r4; var r34 = 4 ^ r3; r19 = r14 * r4; var r35 = r5 | r4; var r36 = 0 ^ 0; var r37 = r6 & a12; a14 = r9 % a11; r1 = 2 / 7; var r38 = 1 ^ 3; r0 = 9 + r33; var r39 = a12 % r16; return a3; });\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: false }));");
/*fuzzSeed-133180449*/count=1290; tryItOut("/*hhh*/function hkzrjg(x){/* no regression tests found *//* no regression tests found */}hkzrjg();");
/*fuzzSeed-133180449*/count=1291; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -2097153.0;\n    {\n      (Int32ArrayView[((-0x8000000)) >> 2]) = ((0xecb3f1dc)+((d0) < (-2049.0)));\n    }\n    i1 = ((-1.0625) == (d2));\n    switch ((((i1)*-0xf0fa8)|0)) {\n      case -1:\n        {\n          d0 = (+(1.0/0.0));\n        }\n        break;\n      case -1:\n        i1 = (0xf874ef6c);\n        break;\n      default:\n        switch (((Float32ArrayView[((0xf8776897)) >> 2]))) {\n          case -3:\n            i1 = (0x5c8ff2b8);\n            break;\n          default:\n            {\n              d2 = (d0);\n            }\n        }\n    }\n    d2 = (2.3611832414348226e+21);\n    d2 = (d0);\n    i1 = (!(0x8cee9cbb));\n    return +((+(0xc66cb4a1)));\n  }\n  return f; })(this, {ff: Math.tanh}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=1292; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.sin(Math.cos((Math.cbrt((1 | 0)) | 0))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0.000000000000001, -(2**53), 0x07fffffff, -0x100000001, 1/0, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, 1, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_VALUE, 0x080000000, 0x100000001, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, -1/0, -0, 0/0, Number.MIN_SAFE_INTEGER, Math.PI, 2**53, -0x07fffffff, Number.MAX_VALUE, 2**53+2, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53-2, Number.MIN_VALUE, 42, -0x080000001, 0x080000001, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=1293; tryItOut("\"use strict\"; Math.hypot(5.0000000000000000000000, x);/*\n*/");
/*fuzzSeed-133180449*/count=1294; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-133180449*/count=1295; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1296; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.sign(Math.sin(( ! ((( ! -Number.MIN_VALUE) ? Math.fround(y) : (y >>> 0)) | 0)))) % (Math.asinh(( + ( ~ ( + (Math.max((2**53-2 | 0), (Math.acos((((x | 0) || (x | 0)) | 0)) | 0)) | 0))))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[this,  /x/ ,  /x/ , this, this,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , this,  /x/ ]); ");
/*fuzzSeed-133180449*/count=1297; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.atan(Math.fround(( + (( ! ((Math.sign((2**53-2 | 0)) || (( ! x) | 0)) >>> 0)) >>> 0))))) >>> 0) & (mathy0(( + ( + mathy0(Math.pow(Math.min(Math.fround(( ~ Math.fround(x))), x), ( + mathy0(-Number.MIN_VALUE, -(2**53+2)))), Math.fround(( ~ (x >>> 0)))))), (( ! Math.fround(Math.pow((0x100000000 >>> 0), (y >>> 0)))) && (( ! (mathy0((mathy0((x >>> 0), (y >>> 0)) >>> 0), y) >>> 0)) >>> 0))) >>> 0)); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000001, 0x080000000, -0x07fffffff, -0x080000000, -0x100000001, -0x100000000, 1, -(2**53+2), 0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0, Number.MAX_VALUE, 0x080000001, 1/0, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, 2**53, -0, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, 0/0, -(2**53), 42, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, -Number.MIN_VALUE, 2**53+2, -(2**53-2), 0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1298; tryItOut("/*RXUB*/var r = new RegExp(\"(?!(?!\\\\u006E))|\\\\u4675+?.\\\\d{0,7}.([^]){1,}(?=\\u3e92|[^]*?([\\\\W\\\\d\\\\b-\\u0088])|[\\\\d]*)+\", \"gi\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=1299; tryItOut("g2.m1.get(g1);");
/*fuzzSeed-133180449*/count=1300; tryItOut(" for  each(b in (new  '' ((4277)))) {let (x = ((makeFinalizeObserver('nursery'))), eval, a = false, w, \u3056, b =  \"\" , fqkxdy, c = (byteLength.unwatch(\"__iterator__\"))) { e0 = new Set; }/*oLoop*/for (let elmrzo = 0; elmrzo < 41; ++elmrzo) { v1 = (g1 instanceof p1); }  }");
/*fuzzSeed-133180449*/count=1301; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.acosh((Math.atan2((Math.log(((Math.atan2((( ! Math.pow(y, -0x080000000)) | 0), (Math.fround(( ! y)) | 0)) | 0) >>> 0)) | 0), Math.fround((Math.fround((mathy1((y | 0), (x | 0)) | 0)) < x))) | 0))); }); testMathyFunction(mathy4, [0.000000000000001, -0, 0x0ffffffff, Number.MAX_VALUE, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, -0x0ffffffff, 42, -1/0, -Number.MIN_VALUE, -0x100000001, -0x07fffffff, 2**53-2, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, 0x080000000, Math.PI, 0, 0x080000001, -0x080000001, 2**53, Number.MIN_SAFE_INTEGER, 1, 0x100000000]); ");
/*fuzzSeed-133180449*/count=1302; tryItOut("print((({d, d: [, ], x: yield, window: c\n} = (void options('strict_mode')))));");
/*fuzzSeed-133180449*/count=1303; tryItOut("\"use strict\"; s2 = new String(p1);");
/*fuzzSeed-133180449*/count=1304; tryItOut("v2 = this.a2.reduce, reduceRight((function() { try { o1 = new Object; } catch(e0) { } try { t2 = new Uint32Array(t0); } catch(e1) { } m1 + ''; return t2; }), g2.b1, f2, f0, t2, o1, this.p0, v1);");
/*fuzzSeed-133180449*/count=1305; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=1306; tryItOut("mathy1 = (function(x, y) { return Math.max((Math.fround((Math.fround(Math.fround(Math.max(Math.fround(( + ( + ( + Math.fround((Math.min(Math.fround(x), (mathy0(y, ( + y)) >>> 0)) >>> 0)))))), Math.fround(Math.hypot(Math.atan2((Math.fround(y) > y), x), (x >>> 0)))))) ^ Math.fround((Math.hypot(2**53+2, ( - -0x100000001)) >> (x | 0))))) >>> 0), (mathy0(( + (((( + Math.imul(-1/0, (( + (-1/0 | 0)) | 0))) != ((Math.cbrt((-Number.MAX_SAFE_INTEGER | 0)) | 0) >>> 0)) | 0) % x)), (Math.imul(((( ~ ( + ( + Math.max(( + 0/0), ( + x))))) >>> 0) | 0), ((( + (((Math.imul(Math.fround(y), ((( ! (-1/0 >>> 0)) >>> 0) | 0)) | 0) != 0.000000000000001) | 0)) | 0) | 0)) | 0)) | 0)); }); testMathyFunction(mathy1, /*MARR*/[arguments, arguments, arguments, 0/0, arguments,  'A' ,  'A' ,  'A' , 0/0,  'A' , 0/0, 0/0, arguments,  'A' , 0/0,  'A' ,  'A' ,  'A' , 0/0, 0/0,  'A' , arguments, 0/0,  'A' , arguments, 0/0, 0/0,  'A' , 0/0,  'A' ,  'A' , 0/0,  'A' , 0/0, arguments, arguments,  'A' , arguments, arguments,  'A' , 0/0, 0/0, arguments, arguments,  'A' , arguments, arguments,  'A' , 0/0, arguments, 0/0,  'A' ,  'A' , 0/0, 0/0, arguments, arguments, arguments]); ");
/*fuzzSeed-133180449*/count=1307; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + Math.min(( + Math.fround(mathy0((Math.atan2((x || 0x100000000), ((y >>> 0) + ( + mathy3(( + x), (y | 0))))) >>> 0), Math.fround(Math.hypot(Math.fround(mathy3(42, ( + -Number.MIN_SAFE_INTEGER))), Math.fround((Math.fround(( + y)) < x))))))), (( - (((((Math.max(-0, mathy2(y, y)) | 0) >= (y | 0)) | 0) ? ((( ! (((y >>> 0) ** (y >>> 0)) >>> 0)) < Math.fround(y)) >>> 0) : (Math.max(x, x) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [0x100000000, -0x080000000, Number.MIN_VALUE, -(2**53), 1, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, 0x100000001, 0/0, -0x07fffffff, 0, 0x0ffffffff, -Number.MIN_VALUE, -0x100000001, 1/0, 2**53, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, 0x07fffffff, 2**53-2, -(2**53+2), 0x080000000, 0x080000001, -0x0ffffffff, -Number.MAX_VALUE, 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, -0, Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-133180449*/count=1308; tryItOut("switch(new Number(x)) { case 8: default: Array.prototype.push.call(a2, p2, v2); }");
/*fuzzSeed-133180449*/count=1309; tryItOut("\"use strict\"; ;v1 = evaluate(\"function f0(s2)  { \\\"use strict\\\"; yield new RegExp(\\\"(?!(?=(?:[^])|\\\\\\\\b*|(?!\\\\\\\\D))\\\\\\\\r){0}\\\", \\\"gm\\\") } \", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-133180449*/count=1310; tryItOut("testMathyFunction(mathy4, [-1/0, 0x07fffffff, -(2**53+2), -0, -0x100000001, 1, 1/0, -0x07fffffff, 0/0, -0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 42, 0x100000001, 2**53, 0x080000000, Math.PI, -0x100000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, 2**53+2, 2**53-2, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE, 0x100000000, -(2**53)]); ");
/*fuzzSeed-133180449*/count=1311; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, 0x40000001, 0x40000001, 0x40000001, 0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, function(){}, function(){}, 0x40000001, function(){}, function(){}, function(){}, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, 0x40000001, function(){}, function(){}, 0x40000001, function(){}, function(){}, function(){}, function(){}, function(){}, 0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, function(){}, function(){}, 0x40000001, function(){}, 0x40000001, function(){}, function(){}, function(){}, 0x40000001, 0x40000001, 0x40000001, 0x40000001, 0x40000001, function(){}, 0x40000001, function(){}, 0x40000001, function(){}, function(){}, function(){}, function(){}, function(){}, 0x40000001, function(){}, 0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, function(){}, 0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, function(){}, 0x40000001, function(){}, function(){}, 0x40000001, 0x40000001, 0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, 0x40000001, 0x40000001, function(){}, 0x40000001, function(){}, function(){}, function(){}]) { g2.m1.set(this.o1.p2, i0); }");
/*fuzzSeed-133180449*/count=1312; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.min(Math.min(( + (Math.sinh(x) | 0)), (Math.ceil((( + y) >>> x)) | 0)), ( + Math.min(( + Math.hypot(( + (x != x)), ( + (Math.fround(Math.hypot((Math.fround(Math.log((0 << (y | 0)))) >>> 0), (y >>> 0))) - ( + Math.fround(( + (y >>> 0)))))))), ((((( - Math.sin(y)) >>> 0) | 0) >= (( - Math.pow(x, (Math.imul((((x | 0) % (y | 0)) | 0), (Math.log(x) | 0)) >>> 0))) >>> 0)) | 0)))); }); testMathyFunction(mathy0, [2**53+2, 0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 2**53-2, Math.PI, Number.MIN_VALUE, 0/0, 0x100000001, 2**53, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -0x080000000, 1/0, 0x0ffffffff, -(2**53), 42, -0x0ffffffff, 0, -0x100000001, -0, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 0x080000001, 1.7976931348623157e308, -0x07fffffff, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=1313; tryItOut("\"use strict\"; o2.a2.shift(p2, a0);");
/*fuzzSeed-133180449*/count=1314; tryItOut("a0.reverse();");
/*fuzzSeed-133180449*/count=1315; tryItOut("t1 = new Uint16Array(b0, 104, v1);");
/*fuzzSeed-133180449*/count=1316; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( - ((( ~ ( + (( ! (Math.cos((Math.cbrt((x >>> 0)) >>> 0)) >>> 0)) >>> 0))) | 0) | 0)); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, -0x0ffffffff, 0x0ffffffff, Number.MIN_VALUE, 0.000000000000001, -0x100000000, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, Number.MAX_SAFE_INTEGER, 0/0, -1/0, 0x100000000, 0x080000001, 0, -(2**53+2), -0x100000001, 0x100000001, -Number.MIN_VALUE, 42, -(2**53-2), -0x07fffffff, 1/0, 2**53, 1.7976931348623157e308, 1, -0x080000000, -(2**53), 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-133180449*/count=1317; tryItOut("a0[10];");
/*fuzzSeed-133180449*/count=1318; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2\", \"gyim\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-133180449*/count=1319; tryItOut("mathy2 = (function(x, y) { return (((( - Math.sin(( + mathy0(( + Number.MAX_VALUE), ( + Math.min(x, 0x100000000)))))) >>> 0) ? (Math.max(((mathy0((( + Math.fround((Math.fround(y) && y))) >>> x), Math.sqrt(( + y))) | 0) | 0), (mathy0((Math.pow(42, -1/0) >>> 0), ( + Math.tan(y))) >>> 0)) >>> 0) : (( ~ Math.fround(Math.exp(x))) >>> 0)) | 0); }); ");
/*fuzzSeed-133180449*/count=1320; tryItOut("o2 = {};");
/*fuzzSeed-133180449*/count=1321; tryItOut("for (var v of b0) { this.v0 = (s2 instanceof h2); }");
/*fuzzSeed-133180449*/count=1322; tryItOut("const apfrng, y, iuernz;t1[10] = m0;");
/*fuzzSeed-133180449*/count=1323; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ~ Math.fround(((Math.cos((Math.cos(Math.max(x, Math.fround(Math.pow(x, x)))) >>> 0)) >>> 0) + Math.log(Math.fround((Math.fround((Math.pow(x, ((1 * -(2**53+2)) >>> 0)) >>> 0)) != Math.fround(x))))))); }); testMathyFunction(mathy0, /*MARR*/[function(){}, function(){}, (1/0), (1/0), 0x0ffffffff, (1/0), (1/0), 0x0ffffffff, function(){}, 0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), 0x0ffffffff, (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), 0x0ffffffff, (1/0), function(){}, 0x0ffffffff, 0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), 0x0ffffffff, 0x0ffffffff, objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, 0x0ffffffff, (1/0), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, function(){}, function(){}, (1/0), 0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), 0x0ffffffff, (1/0), (1/0), objectEmulatingUndefined(), function(){}, function(){}, 0x0ffffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), function(){}, objectEmulatingUndefined(), (1/0), 0x0ffffffff, objectEmulatingUndefined(), (1/0), function(){}, 0x0ffffffff, function(){}, 0x0ffffffff, objectEmulatingUndefined(), function(){}, 0x0ffffffff, 0x0ffffffff, function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-133180449*/count=1324; tryItOut("Object.defineProperty(this, \"a0\", { configurable: , enumerable: x,  get: function() {  return arguments; } });");
/*fuzzSeed-133180449*/count=1325; tryItOut("\"use strict\"; for(let c in ((offThreadCompileScript)(eval *= x)))t1.set(t1, 7);");
/*fuzzSeed-133180449*/count=1326; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.log10(Math.fround(Math.fround(Math.hypot(Math.log10(Math.fround(( - Math.fround(( ! Math.fround(x)))))), mathy0(Math.asin(Math.fround((Math.min((y >>> 0), ((0.000000000000001 === y) >>> 0)) >>> 0))), (Math.hypot(( + Math.imul(( + y), ( + x))), x) - (y === y)))))))); }); testMathyFunction(mathy2, /*MARR*/[x, null, (void 0), x, new Number(1.5), x, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), null, x, new Number(1.5), null, new Number(1.5), x, null, null, x, new Number(1.5), (void 0), (void 0), x, (void 0), (void 0), new Number(1.5)]); ");
/*fuzzSeed-133180449*/count=1327; tryItOut("yield (4277);");
/*fuzzSeed-133180449*/count=1328; tryItOut("\"use strict\"; o1.a1.splice(-7, (4277));");
/*fuzzSeed-133180449*/count=1329; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ! Math.sign(Math.pow(Math.log10(Math.atan2(x, 0x080000000)), x))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 0x100000000, 1.7976931348623157e308, 1, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53, 0x100000001, -0x080000000, -0x100000000, -0x080000001, 0, 42, -0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -1/0, 0.000000000000001, -(2**53), 0x07fffffff, Math.PI, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, -0, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=1330; tryItOut("/*bLoop*/for (let uyihjj = 0; uyihjj < 102; ++uyihjj) { if (uyihjj % 4 == 0) { this.h1.defineProperty = (function(j) { if (j) { try { g0.e1.add(p2); } catch(e0) { } o0.a2 = []; } else { try { e2.has(m2); } catch(e0) { } try { v2 = NaN; } catch(e1) { } e1.delete(e0); } }); } else { var \u3056, eval, eaoafz, prdcnq, z, z;Array.prototype.unshift.call(a2, b0, b1); }  } ");
/*fuzzSeed-133180449*/count=1331; tryItOut("print(x);");
/*fuzzSeed-133180449*/count=1332; tryItOut("\"use strict\"; Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-133180449*/count=1333; tryItOut("t1 = new Uint32Array(b0, 6, 0);");
/*fuzzSeed-133180449*/count=1334; tryItOut("mathy2 = (function(x, y) { return (((Math.log10(Math.fround(Math.acosh(Math.min((Math.atan2(( + Math.PI), (x | 0)) >>> 0), (x >>> 0))))) >>> 0) && ((Math.log2((( + (( + ( - x)) >> (Math.sqrt(x) + Math.fround(( ~ Math.fround((0 , x))))))) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy2, [1.7976931348623157e308, 2**53, -0x080000000, -(2**53), 0, -Number.MIN_VALUE, 1/0, -0x100000001, -0, 0.000000000000001, -1/0, Math.PI, 0x0ffffffff, 0/0, -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, -Number.MAX_VALUE, -0x07fffffff, 0x100000001, 2**53+2, -(2**53-2), 42, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 2**53-2, 0x080000000, Number.MAX_VALUE, 0x100000000, 0x07fffffff]); ");
/*fuzzSeed-133180449*/count=1335; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: (4277), enumerable: (x % 9 != 2),  get: function() {  return o0.t2.length; } });");
/*fuzzSeed-133180449*/count=1336; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.imul(Math.fround(Math.pow((((x | 0) * ((Math.trunc((x >>> 0)) >>> 0) >>> 0)) >>> 0), Math.max(Math.round(((y * (x | 0)) | 0)), (Math.clz32(Math.fround((Math.atan2((Number.MAX_SAFE_INTEGER >>> 0), (-0x080000000 >>> 0)) >>> 0))) >>> 0)))), (Math.fround(Math.sin(Math.expm1((( + (x && x)) | 0)))) & Math.exp(-0x0ffffffff)))); }); ");
/*fuzzSeed-133180449*/count=1337; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1338; tryItOut("for (var p in e2) { try { a1.forEach((function() { try { Array.prototype.splice.call(a0, -2, ({valueOf: function() { a2 = a2.filter((function() { try { e1 = p0; } catch(e0) { } try { g0.offThreadCompileScript(\"function f2(p0)  { yield (let (smhrbu, nqkojp, rrrwst, w)  \\\"\\\" ) } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval:  '' , sourceIsLazy: -25, catchTermination:  /x/ , elementAttributeName: s0 })); } catch(e1) { } try { this.s2 += 'x'; } catch(e2) { } f0(v2); return t1; }));return 9; }})); } catch(e0) { } try { Object.defineProperty(this, \"a2\", { configurable: true, enumerable: false,  get: function() {  return r2.exec(s2); } }); } catch(e1) { } try { i2.next(); } catch(e2) { } this.a0.push(f1, p1, v0, g2, o2.p2, s2); return i2; }), h1); } catch(e0) { } try { for (var p in h2) { try { o1.i1.next(); } catch(e0) { } try { e2 + i2; } catch(e1) { } try { a2.shift(); } catch(e2) { } v0 = evalcx(\"t0.set(a1, g0.v1);\", this.g2); } } catch(e1) { } try { for (var p in g0.a0) { try { this.s1 += 'x'; } catch(e0) { } try { v2 = 4; } catch(e1) { } try { g0 = this; } catch(e2) { } m0.set(g1.o2, m2); } } catch(e2) { } a2.pop(); }");
/*fuzzSeed-133180449*/count=1339; tryItOut("o0 = Object.create((d >>> yield));");
/*fuzzSeed-133180449*/count=1340; tryItOut("a1[0] = i0;\nfor (var p in e1) { try { /*RXUB*/var r = this.r2; var s = o2.s0; print(s.match(r)); print(r.lastIndex);  } catch(e0) { } for (var v of this.e1) { a2 = arguments.callee.caller.caller.caller.caller.arguments; } }\n");
/*fuzzSeed-133180449*/count=1341; tryItOut("(9);");
/*fuzzSeed-133180449*/count=1342; tryItOut(" \"\" ;\no2.__proto__ = v0;\n");
/*fuzzSeed-133180449*/count=1343; tryItOut("g0.a0[7] = t1;");
/*fuzzSeed-133180449*/count=1344; tryItOut("\"use strict\"; /*infloop*/for(var x in (((offThreadCompileScript).apply)(-18)))/*bLoop*/for (var fkczpo = 0; (let (d) /${0}|(?:(\\b|^)+)^|[^]([^\u0012]+)(?=.(?=[^])+?)|(?!(.))|[^ \\w\\b]/gym) && fkczpo < 51; ++fkczpo) { if (fkczpo % 5 == 0) { with({e: \"\\uCAF5\"})print(x); } else { (false); }  } ");
/*fuzzSeed-133180449*/count=1345; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(( ~ Math.fround((mathy3((( + x) <= 1.7976931348623157e308), x) >>> 0))))); }); testMathyFunction(mathy4, [-0x0ffffffff, 1, 2**53, 0x100000001, 0x07fffffff, 0x080000001, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, 1/0, -0x100000001, -0x100000000, Number.MAX_VALUE, 2**53-2, 42, -0x080000001, -Number.MIN_SAFE_INTEGER, -0, 0x0ffffffff, 0, 0x100000000, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, -(2**53+2), 0x080000000, -Number.MAX_VALUE, 0/0, -0x080000000, -0x07fffffff, -(2**53-2), 0.000000000000001, -1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1346; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2(((((mathy1(((x >>> 0) * (Math.max(( + y), y) >>> 0)), (y >= ( + mathy0(( + x), x)))) , ( + Math.atan2(Math.clz32(y), y))) | 0) != ((( + (Math.max(( - Number.MAX_VALUE), 42) >>> 0)) >>> 0) | 0)) | 0), (Math.fround(Math.atan2((Math.fround(x) ? x : Math.fround(Math.fround(Math.fround(Math.max((Math.pow(x, y) >>> 0), (x | 0)))))), x)) | Math.fround(( ! ( + ((Math.min((Math.fround(x) <= ( + ( + ( + y)))), ( + ( ! ( + y)))) >>> 0) <= ( + ( + ( + x))))))))); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -0x080000001, -(2**53-2), Math.PI, 0.000000000000001, -0x100000001, -Number.MIN_VALUE, 1/0, -0, 0/0, 42, -(2**53), Number.MAX_VALUE, -Number.MAX_VALUE, -1/0, 0x080000001, 0x07fffffff, 2**53-2, 0x080000000, -0x080000000, -0x0ffffffff, -0x100000000, 1.7976931348623157e308, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=1347; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -73786976294838210000.0;\n    var i3 = 0;\n    /*FFI*/ff((((((Infinity) == (d2))+(i3)) << ((Uint32ArrayView[1])))), ((((-0x8000000)) << (((0x5d0a29b1) >= (0x314c374a))+(i1)-(i1)))), ((~((i0)))), ((imul(((0xcf7a91a3) <= (0x523a0629)), (i3))|0)), ((+/*FFI*/ff())), ((4294967295.0)), ((abs((-0x8000000))|0)), ((134217728.0)), ((262145.0)));\n    d2 = (-549755813888.0);\n    (Int8ArrayView[((~((i0)-((0x3821dbd0) >= (0x1c6aa4f3))-(0x385b2edd))) % (abs((((-0x8000000)*0xa897d) ^ ((0xfc7be924)-(-0x8000000))))|0)) >> 0]) = ((0x3973e406)-(i3));\n    (Float32ArrayView[2]) = ((+pow(((Infinity)), ((9.44473296573929e+21)))));\n    (Float64ArrayView[(((i3) ? (0xd58d3e5a) : ((0xffc647b7) ? (0xf812a072) : (0xfe1e743c)))-((7.555786372591432e+22) <= (-288230376151711740.0))) >> 3]) = ((549755813887.0));\n    return ((-(((((!(0x32c87330))-(((Infinity)))+((1.5) != (-9223372036854776000.0)))|0)) ? (0xfd5f8ccd) : (i1))))|0;\n  }\n  return f; })(this, {ff: (Set.prototype.has).bind()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [({valueOf:function(){return '0';}}), 0, null, (new Boolean(true)), '/0/', NaN, 0.1, 1, [], (new Number(0)), false, /0/, [0], objectEmulatingUndefined(), '\\0', -0, ({valueOf:function(){return 0;}}), undefined, ({toString:function(){return '0';}}), '0', (new Number(-0)), (new Boolean(false)), '', (new String('')), (function(){return 0;}), true]); ");
/*fuzzSeed-133180449*/count=1348; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x080000000, -Number.MAX_VALUE, 0x080000001, 1/0, -0, -0x100000001, 0/0, 0x0ffffffff, 1.7976931348623157e308, 2**53+2, -Number.MIN_VALUE, -0x080000000, -(2**53-2), -0x080000001, 2**53-2, Math.PI, 0x07fffffff, 0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, -0x07fffffff, 0x100000000, Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, -0x100000000, 42, -1/0, 1]); ");
/*fuzzSeed-133180449*/count=1349; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.sqrt((Math.sin(((Math.fround(( ~ y)) % ((Math.imul(Math.min(0x0ffffffff, y), -0) >>> 0) >>> 0)) < ( + ( ~ ( + y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x07fffffff, 0x07fffffff, -(2**53), 0, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_VALUE, -(2**53+2), 0x100000001, 0.000000000000001, 0x080000001, -0x0ffffffff, Number.MAX_VALUE, 0x100000000, -0, -Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, -1/0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, 1/0, -0x100000001, -0x080000000, -0x100000000, 2**53, Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-133180449*/count=1350; tryItOut("\"use strict\"; let gsodoq, NaN = (\u3056 = \"\\u6E9E\");v2 = r1.constructor;");
/*fuzzSeed-133180449*/count=1351; tryItOut("testMathyFunction(mathy4, [-0, 0.1, '0', false, objectEmulatingUndefined(), 1, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Boolean(true)), (new String('')), '/0/', [], null, (new Number(0)), ({valueOf:function(){return '0';}}), (new Number(-0)), (new Boolean(false)), (function(){return 0;}), undefined, true, /0/, '', 0, [0], NaN, '\\0']); ");
/*fuzzSeed-133180449*/count=1352; tryItOut("o0.toSource = (function() { try { o1 = this.g0.objectEmulatingUndefined(); } catch(e0) { } g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 69 == 57), sourceIsLazy:  /x/ , catchTermination: true })); return this.o2; });neuter");
/*fuzzSeed-133180449*/count=1353; tryItOut("\"use strict\"; /*iii*/v1 = g0.runOffThreadScript();/*hhh*/function rxxxeb(x, \u3056,  \"\"  = this.__defineSetter__(\"x\", b =>  { yield -2 } ), window, x, x, z, x, getter, d, x = 15, x, y, NaN, x, b,  , \u3056, w, a, x =  '' , x = Math, x, z, this.c = \"\\u46F3\", y =  /x/g ){o0 = Object.create(this.g0.g0);}\nx = t0;\n");
/*fuzzSeed-133180449*/count=1354; tryItOut("g0.a2.shift(m1);");
/*fuzzSeed-133180449*/count=1355; tryItOut("\"use strict\"; \"use asm\"; t1[x] = x;");
/*fuzzSeed-133180449*/count=1356; tryItOut("print(uneval(p2));");
/*fuzzSeed-133180449*/count=1357; tryItOut("\"use strict\"; v1 = Array.prototype.some.apply(a0, [(function(j) { if (j) { try { s0 += 'x'; } catch(e0) { } v2 = a0.length; } else { try { m2.has(h0); } catch(e0) { } i1.send(b1); } }), m2, t1]);");
/*fuzzSeed-133180449*/count=1358; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1359; tryItOut("\"use strict\"; s0 + e2;");
/*fuzzSeed-133180449*/count=1360; tryItOut("\"use strict\"; v2 = Array.prototype.some.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = ((d1) + (-72057594037927940.0));\n    d1 = (d0);\n    {\n      d1 = (d0);\n    }\n    {\n      (Int16ArrayView[4096]) = (((((((0xaa9c41a) <= (0x69529860))+(0xe3fc0bec)-((0xe4ff2c48) < (0x0)))>>>((((0x41603506))>>>((0xffffffff))) / (0xc381a37f))) >= ((((Int8ArrayView[2]))-(/*FFI*/ff(((abs((0xcc346e2))|0)), ((8388609.0)), ((4.835703278458517e+24)))|0))>>>((0xfa896450)+((~((0x531476c6))))))) ? (0x78c88118) : (-0x13f3bde)));\n    }\n    d0 = (+((((0xf89fe0b4))+(0x9a1f34fe)) & (-0x219c9*(((-0xe593f*(!(0x641d888d)))>>>((0xffffffff) / (0xd5091d63))) < (((0x8001dff7) / (0xffffffff))>>>(((0x4a1acfcf))+(0xf2dbbad0)))))));\n    d1 = (+(-1.0/0.0));\n    {\n      d1 = (-((Float32ArrayView[1])));\n    }\n    return +(((Uint16ArrayView[1])));\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096))]);");
/*fuzzSeed-133180449*/count=1361; tryItOut("this.a0.reverse(i1);");
/*fuzzSeed-133180449*/count=1362; tryItOut("\"use strict\"; m2.has(e1);");
/*fuzzSeed-133180449*/count=1363; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.pow(( + ( ! Math.fround(Math.min(( + Math.acosh(1/0)), Math.imul((( + x) ? ( + 0x0ffffffff) : 0x100000001), (x << -0x080000001)))))), Math.pow((( + (( - (mathy0(((( - (x | 0)) | 0) >>> 0), (x >>> 0)) >>> 0)) >>> 0)) >>> 0), Math.hypot(( + mathy0(( + (Math.fround(x) >>> ( + x))), Math.fround(Math.trunc(Math.fround(x))))), y)))); }); testMathyFunction(mathy1, [1, 0.000000000000001, -(2**53-2), -0, 0/0, -Number.MIN_VALUE, Number.MAX_VALUE, 42, 2**53, -Number.MAX_SAFE_INTEGER, 2**53+2, 0, -0x07fffffff, -(2**53+2), 0x0ffffffff, -1/0, 2**53-2, -Number.MAX_VALUE, 0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -0x080000001, 0x100000001, -0x080000000, 0x07fffffff, Number.MIN_VALUE, Math.PI, 0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, 1/0]); ");
/*fuzzSeed-133180449*/count=1364; tryItOut("");
/*fuzzSeed-133180449*/count=1365; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1366; tryItOut(";");
/*fuzzSeed-133180449*/count=1367; tryItOut("\"use strict\"; let x = (4277), e, y = new RegExp(\"(((?=\\\\cD(\\\\x94)))|[^]^){0,3}\", \"m\").__defineSetter__(\"window\", encodeURIComponent);for (var p in e1) { try { for (var v of t0) { e1 = new Set(o1); } } catch(e0) { } v1 = evalcx(\"function f2(o2.b0)  { \\\"use strict\\\"; return (\\nlength) } \", g2); }");
/*fuzzSeed-133180449*/count=1368; tryItOut("a1 = this.o0.a1.filter((function(j) { if (j) { /*RXUB*/var r = r0; var s = \"\"; print(r.test(s));  } else { try { i1.next(); } catch(e0) { } e0.delete(o0.h2); } }), a2, g0)\n");
/*fuzzSeed-133180449*/count=1369; tryItOut("testMathyFunction(mathy1, [Math.PI, 0x080000000, 1.7976931348623157e308, -0x100000001, -1/0, -0x07fffffff, 0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 0x07fffffff, Number.MIN_VALUE, -0x100000000, 0x100000000, 42, -0, 0, 0x100000001, 0x080000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, 0/0, -0x080000000, -0x0ffffffff, 2**53, -(2**53+2), 2**53-2, 1/0, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53)]); ");
/*fuzzSeed-133180449*/count=1370; tryItOut(";");
/*fuzzSeed-133180449*/count=1371; tryItOut("mathy2 = (function(x, y) { return ((Math.fround(( ~ Math.fround((Math.asinh(y) << Math.fround((Math.fround(x) ? Math.fround(0x100000001) : Math.fround((Math.log((2**53-2 >>> 0)) >>> 0)))))))) >>> ((( + ( - (Math.hypot(( + mathy0(Math.acosh((-Number.MIN_SAFE_INTEGER >>> 0)), y)), x) >>> 0))) >> ( + mathy0((x | 0), ((x ** x) >>> (Number.MAX_SAFE_INTEGER == Math.fround(( + x))))))) | 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[ /x/ , objectEmulatingUndefined(), new Boolean(true), [], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, [], [], null, null, null, [], new Boolean(true), null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, new Boolean(true),  /x/ , null,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), new Boolean(true), null,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , [], objectEmulatingUndefined(), new Boolean(true), [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], null, objectEmulatingUndefined(), []]); ");
/*fuzzSeed-133180449*/count=1372; tryItOut("/*RXUB*/var r = true; var s = \"\"; print(s.split(r)); h2.set = f0;");
/*fuzzSeed-133180449*/count=1373; tryItOut("x.stack;");
/*fuzzSeed-133180449*/count=1374; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ! (( + Math.max((mathy2(x, (Math.fround(Number.MIN_VALUE) ? Math.fround(x) : Math.fround(y))) ** Math.pow(x, y)), Math.pow((Math.atan2(x, Math.fround(x)) ^ (Math.fround(( ! (y >>> 0))) >>> 0)), ( + -0x100000000)))) > ( + (mathy2((Math.hypot((\"use strict\"; mathy5 = (function(x, y) { return ( + (mathy4(Math.sqrt(Math.fround(Math.imul(x, ( - ( + x))))), mathy1(( + (( + ( + x)) ** 0.000000000000001)), -0x080000001)) ? ( + Math.log2(Math.fround(Math.ceil(( + Math.min(( + x), ( + (Math.max(0x0ffffffff, y) & (Math.log1p((x >>> 0)) >>> 0))))))))) : ( + (Math.cbrt((( + Math.pow(Math.imul(Math.fround(x), Math.fround((((0x100000001 >>> 0) / (( - x) >>> 0)) >>> 0))), mathy2(( ! 0x100000000), -(2**53)))) >>> 0)) >>> 0)))); });  >>> 0), Math.log2((y | 0))) >>> 0), Math.fround(Math.imul(Math.fround((((x >>> 0) / (y >>> 0)) >>> 0)), 0/0))) | 0)))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, -(2**53-2), -1/0, Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, -Number.MIN_VALUE, -0x0ffffffff, 1, 1/0, -0x07fffffff, 1.7976931348623157e308, -0x080000001, -0x100000000, 42, -0x080000000, -Number.MAX_VALUE, 0x100000000, 0/0, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, Number.MAX_VALUE, 0, -0, 2**53+2, 2**53, 0x0ffffffff, 0x100000001, Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-133180449*/count=1375; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.min((((( + Math.tanh(y)) >>> 0) + (((((( + x) >> Math.min(((x ? ( ! y) : x) >>> 0), Math.sign((Math.imul(x, (x | 0)) | 0)))) | 0) / ((Math.asinh(Math.fround(x)) | 0) | 0)) | 0) >>> 0)) | 0), (Math.fround((((( ! Math.cbrt(y)) | 0) & (( + y) | 0)) ? Math.fround(Math.sqrt((0x100000001 >>> 0))) : (Math.imul((y >= 0x080000001), (y % 1/0)) >>> 0))) | 0)); }); ");
/*fuzzSeed-133180449*/count=1376; tryItOut("f2.toString = (function() { try { Array.prototype.pop.apply(a1, []); } catch(e0) { } try { o0 = i2.__proto__; } catch(e1) { } try { /*ODP-2*/Object.defineProperty(i1, \"reduce\", { configurable: false, enumerable: x >>= x, get: (function(j) { if (j) { Object.prototype.unwatch.call(b2, \"for\"); } else { try { s0 = new String(s2); } catch(e0) { } try { ; } catch(e1) { } Array.prototype.splice.apply(a2, [NaN, 17]); } }), set: (function(j) { if (j) { try { f1 = (function mcc_() { var qsuidw = 0; return function() { ++qsuidw; f0(/*ICCD*/qsuidw % 11 == 3);};})(); } catch(e0) { } try { for (var p in o2) { try { a2[4] =  \"\" ; } catch(e0) { } try { p2.toString = (function() { g2 + ''; return g1.o2; }); } catch(e1) { } a1.sort(a0, o0, a1); } } catch(e1) { } /*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { m1.has(f0);return 19; }}), { configurable: true, enumerable: false, get: f0, set: (function() { for (var j=0;j<7;++j) { f0(j%5==1); } }) }); } else { Array.prototype.unshift.apply(a0, [o1, h2]); } }) }); } catch(e2) { } e2.delete(/(?=(?=[\u3de0-\\\u0007\u181a-\u642f\\D]).[^]\\b\\w+{3})|(\\D+?)/m.y); return f1; });");
/*fuzzSeed-133180449*/count=1377; tryItOut("/*infloop*/for(x; (((x = window = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: undefined, delete: undefined, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: undefined, enumerate: neuter, keys: function() { return Object.keys(x); }, }; })(null), /*wrap1*/(function(){ yield x;return (Number.isNaN).bind(x)})()))) |= (void shapeOf(((x = x))))); (void shapeOf(x))) {v0 = (f2 instanceof e0);Object.defineProperty(this, \"v2\", { configurable: false, enumerable: (x % 6 != 4),  get: function() {  return evaluate(\";\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 4 != 1), sourceIsLazy: false, catchTermination: timeout(1800) })); } }); }");
/*fuzzSeed-133180449*/count=1378; tryItOut("\"use strict\"; e2.has((uneval(x)));");
/*fuzzSeed-133180449*/count=1379; tryItOut("g2.valueOf = (function() { for (var j=0;j<34;++j) { f0(j%2==1); } });");
/*fuzzSeed-133180449*/count=1380; tryItOut("Object.prototype.unwatch.call(e0, \"x\");");
/*fuzzSeed-133180449*/count=1381; tryItOut("\"use strict\"; v0 = (b0 instanceof e1);");
/*fuzzSeed-133180449*/count=1382; tryItOut("g1 = this;");
/*fuzzSeed-133180449*/count=1383; tryItOut("s0 += s1;");
/*fuzzSeed-133180449*/count=1384; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return ( ! ((( + (( + (( + y) ** ( + (((1.7976931348623157e308 | 0) > (0x100000001 | 0)) | 0)))) != y)) ** (( - y) | 0)) | 0)); }); testMathyFunction(mathy1, [0x07fffffff, 1, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, 42, -0, 0x0ffffffff, 0x080000000, -0x080000000, 0, -(2**53-2), 0.000000000000001, -(2**53), 2**53+2, -0x080000001, -0x100000001, -0x100000000, 2**53-2, -0x0ffffffff, 0/0, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0x080000001, 0x100000001, -0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1385; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.atan(Math.fround(Math.min(Math.max((mathy0(((mathy0(Math.fround(Math.fround((Math.fround(y) << Math.fround(x)))), ((y % y) >>> 0)) >>> 0) | 0), ((y + 2**53) | 0)) | 0), Math.fround((Math.atanh((Math.fround(mathy0(Math.fround(y), Math.fround(x))) | 0)) | 0))), ( - ( + (((y < Number.MIN_VALUE) | 0) != ( + Math.tanh(y)))))))); }); ");
/*fuzzSeed-133180449*/count=1386; tryItOut("\"use strict\"; f1(v1);");
/*fuzzSeed-133180449*/count=1387; tryItOut("v0 = Array.prototype.reduce, reduceRight.apply(a0, [Set, m1, v1, new (function(y) { yield y; const buggcj, y, x;yield 21;; yield y; })()]);");
/*fuzzSeed-133180449*/count=1388; tryItOut("'fafafa'.replace(/a/g, objectEmulatingUndefined);\nt1 = t0[7];\n");
/*fuzzSeed-133180449*/count=1389; tryItOut("/*MXX1*/g0.o0 = g2.String.fromCharCode;");
/*fuzzSeed-133180449*/count=1390; tryItOut("\"use strict\"; /*MXX3*/g2.SyntaxError.prototype.toString = g2.SyntaxError.prototype.toString;");
/*fuzzSeed-133180449*/count=1391; tryItOut("m2.get(p2);");
/*fuzzSeed-133180449*/count=1392; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1393; tryItOut("mathy5 = (function(x, y) { return mathy4(Math.log1p(( + Math.cbrt(Math.fround(Math.log1p((x % y)))))), ( - Math.atan(( + (mathy2((0x07fffffff | 0), ((( ~ (x >>> 0)) >>> 0) | 0)) | 0))))); }); testMathyFunction(mathy5, [0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 1, 2**53+2, 0.000000000000001, 2**53, -0x07fffffff, 0, 2**53-2, 1.7976931348623157e308, 0x080000001, 42, 0x0ffffffff, -0x080000001, -0x080000000, Math.PI, Number.MAX_VALUE, -0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, -(2**53-2), -(2**53+2), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 1/0, -1/0, -Number.MAX_VALUE, -(2**53), 0x100000000, -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1394; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.clz32((( ~ ((( + ( ~ ( + Math.min((x >>> x), x)))) ? Math.fround(( ~ ( + y))) : Math.min((( + (Math.fround(1/0) <= (-Number.MIN_VALUE >>> 0))) >>> 0), ( + Math.hypot(( + ( + ( + -0x100000001))), ( + x))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [1, [], (new String('')), (new Boolean(false)), 0.1, '/0/', (new Boolean(true)), false, ({valueOf:function(){return '0';}}), 0, undefined, '\\0', ({valueOf:function(){return 0;}}), (new Number(-0)), [0], (function(){return 0;}), (new Number(0)), NaN, null, '0', true, '', -0, objectEmulatingUndefined(), ({toString:function(){return '0';}}), /0/]); ");
/*fuzzSeed-133180449*/count=1395; tryItOut("/*iii*/x;/*hhh*/function cclroo(x, ...x){throw ((/*RXUE*/new RegExp(\"(?!\\\\3)|(?!(?!\\\\W)){1,5}\", \"gym\").exec(\"___\"))).call((x\n), );s0 += s2;}");
/*fuzzSeed-133180449*/count=1396; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ~ Math.fround(Math.hypot(Math.cos(y), ( + Math.atanh(Math.asin(Number.MAX_VALUE)))))); }); ");
/*fuzzSeed-133180449*/count=1397; tryItOut("\"use strict\"; this.m1.get(((function sum_slicing(xjpgfu) { ; return xjpgfu.length == 0 ? 0 : xjpgfu[0] + sum_slicing(xjpgfu.slice(1)); })(/*MARR*/[(uneval(Math.hypot(21,  '' ))).keyFor(), x, new Number(1), objectEmulatingUndefined(), x, objectEmulatingUndefined(), (uneval(Math.hypot(21,  '' ))).keyFor(), x, objectEmulatingUndefined(), new Number(1), (uneval(Math.hypot(21,  '' ))).keyFor(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), (uneval(Math.hypot(21,  '' ))).keyFor(), x, (uneval(Math.hypot(21,  '' ))).keyFor(), (uneval(Math.hypot(21,  '' ))).keyFor(), (uneval(Math.hypot(21,  '' ))).keyFor(), (uneval(Math.hypot(21,  '' ))).keyFor(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), (uneval(Math.hypot(21,  '' ))).keyFor(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), x, objectEmulatingUndefined(), (uneval(Math.hypot(21,  '' ))).keyFor(), x, (uneval(Math.hypot(21,  '' ))).keyFor(), x, x, objectEmulatingUndefined(), (uneval(Math.hypot(21,  '' ))).keyFor(), x, objectEmulatingUndefined(), x, x, x, x, new Number(1), x, new Number(1), (uneval(Math.hypot(21,  '' ))).keyFor(), x, new Number(1), x, x, x, (uneval(Math.hypot(21,  '' ))).keyFor(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), new Number(1), new Number(1), (uneval(Math.hypot(21,  '' ))).keyFor(), (uneval(Math.hypot(21,  '' ))).keyFor(), x, new Number(1), new Number(1), x, x, objectEmulatingUndefined(), new Number(1), (uneval(Math.hypot(21,  '' ))).keyFor(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, objectEmulatingUndefined(), new Number(1), (uneval(Math.hypot(21,  '' ))).keyFor(), x, new Number(1), (uneval(Math.hypot(21,  '' ))).keyFor()])));");
/*fuzzSeed-133180449*/count=1398; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2|(.){2}\\\\b{4}(?:(?=[^\\\\cY-\\\\x4c])*)(?=\\\\r|(?=[^]){4}).[^]+|(?!\\\\B)\\\\3[^]+?|[^]^*?{0,4}\", \"i\"); var s = \"\\n\\n\\n\\n\"; print(s.search(r)); \ne2.add((void shapeOf(eval(\"print( /x/g );\", /*UUV1*/(x.toLocaleUpperCase = function(y) { \"use strict\"; g0.g1.e1 + v2; })))));\n");
/*fuzzSeed-133180449*/count=1399; tryItOut("\"use strict\"; let c = \u000c(({c: x, x}) = (4277));print(x);");
/*fuzzSeed-133180449*/count=1400; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1401; tryItOut("/*ADP-3*/Object.defineProperty(a2, ({valueOf: function() { print(v2);return 13; }}), { configurable: (x % 3 == 2), enumerable: {} = (4277), writable: (x % 2 != 1), value: e1 });");
/*fuzzSeed-133180449*/count=1402; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.cbrt(Math.fround(Math.asin(( + Math.pow(Math.fround(Math.fround(Math.atan(Math.fround(Math.tan(y))))), y))))); }); testMathyFunction(mathy5, [-0, 0x100000000, 0.000000000000001, -Number.MIN_VALUE, 0x080000000, -Number.MAX_VALUE, 0, -0x100000001, Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, 2**53, 0x07fffffff, 0x0ffffffff, -0x080000001, Math.PI, 1, 42, Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, 0x100000001, -(2**53), -(2**53+2), 1.7976931348623157e308, 0x080000001, -0x100000000, 0/0, -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=1403; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=1404; tryItOut("\"use strict\"; Object.defineProperty(this.o0, \"this.g2.o0.v1\", { configurable: false, enumerable: ({x: this}),  get: function() {  return Infinity; } });");
/*fuzzSeed-133180449*/count=1405; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      (Float64ArrayView[1]) = ((+(1.0/0.0)));\n    }\n    i1 = (0xa0c5abf6);\n    return (((i1)))|0;\n    d0 = ((+abs((((+(abs((abs((0x774dfff8))|0))|0)) + (+abs(((-2199023255553.0)))))))) + (-274877906943.0));\n    switch (((((((0xfbe64896))|0))+(0xfb3f8dc7)) | ((i1)-(i1)))) {\n    }\n    {\n      d0 = (((makeFinalizeObserver('nursery'))));\n    }\n    i1 = (i1);\n    return (((0xfc6857dd)-((~~(((-1.9342813113834067e+25)) / ((33554433.0)))))-(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: Math.hypot(0, -3)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-0x0ffffffff, -0x080000000, -0, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, 42, 0.000000000000001, 0x07fffffff, 0x080000000, -Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, -(2**53+2), -0x07fffffff, 2**53+2, -0x080000001, -1/0, 0x0ffffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1, 2**53, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, Math.PI, 1/0, 1.7976931348623157e308, Number.MAX_VALUE, 0]); ");
/*fuzzSeed-133180449*/count=1406; tryItOut("\"use strict\"; print(uneval(p2));");
/*fuzzSeed-133180449*/count=1407; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[Number.MAX_SAFE_INTEGER, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, Number.MAX_SAFE_INTEGER, function(){}, Number.MAX_SAFE_INTEGER, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, false, Number.MAX_SAFE_INTEGER, function(){}, Number.MAX_SAFE_INTEGER, function(){}, Number.MAX_SAFE_INTEGER, false, Number.MAX_SAFE_INTEGER, false, false, function(){}, false, function(){}, false, false, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, Number.MAX_SAFE_INTEGER, false, Number.MAX_SAFE_INTEGER, false, Number.MAX_SAFE_INTEGER, function(){}, Number.MAX_SAFE_INTEGER, false, Number.MAX_SAFE_INTEGER, function(){}, false, Number.MAX_SAFE_INTEGER, false, false, false, Number.MAX_SAFE_INTEGER, false, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, false, Number.MAX_SAFE_INTEGER, function(){}, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, function(){}, false, Number.MAX_SAFE_INTEGER, function(){}, function(){}, false, Number.MAX_SAFE_INTEGER, false, Number.MAX_SAFE_INTEGER, function(){}, function(){}, false, false, function(){}, function(){}, function(){}, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1408; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1409; tryItOut("\"use strict\"; v1 = g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-133180449*/count=1410; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return ( + Math.cosh(( + Math.hypot(( + (-Number.MAX_VALUE >>> ( + (42 / (( + -0) >>> 0))))), ( + (Math.exp(Math.fround(( - ( + y)))) >>> 0)))))); }); testMathyFunction(mathy3, /*MARR*/[ 'A' ,  'A' , undefined,  'A' ,  'A' , undefined,  'A' ,  'A' , undefined, undefined, undefined, undefined,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , undefined,  'A' , undefined,  'A' ,  'A' , undefined,  'A' ,  'A' , undefined,  'A' ,  'A' ]); ");
/*fuzzSeed-133180449*/count=1411; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.imul((Math.hypot((Math.imul(y, (( - (mathy0(( + x), x) | 0)) >>> 0)) | 0), Math.fround(Math.clz32(y))) >>> 0), (mathy0(((x >>> 0) * (( ~ (x | 0)) >>> 0)), (( ~ Math.pow(-0x100000000, 1)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-(2**53+2), -(2**53), Math.PI, -0x100000001, -Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, 2**53+2, 1/0, 0.000000000000001, Number.MIN_VALUE, 2**53-2, 0x07fffffff, 0x080000000, 0x100000000, 42, -(2**53-2), 1.7976931348623157e308, 0/0, 0, -0x080000000, Number.MAX_VALUE, 0x080000001, 0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -1/0, -0x100000000, 1, 2**53, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000001]); ");
/*fuzzSeed-133180449*/count=1412; tryItOut("mathy0 = (function(x, y) { return Math.abs((( + Math.pow(( + (y == x)), ( + (Math.exp(( + Math.ceil(( + x)))) >>> 0)))) <= Math.imul(( + ( + ( + Math.atan2(( + ( ! (y >>> 0))), y)))), y))); }); testMathyFunction(mathy0, [0x100000001, -0x07fffffff, 0x0ffffffff, -Number.MIN_VALUE, 0, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, 2**53, -1/0, -(2**53+2), 0x07fffffff, 0x080000001, 2**53+2, 0.000000000000001, 1, 1.7976931348623157e308, 0x100000000, Number.MIN_VALUE, 2**53-2, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, -0, 42, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, -0x100000000, Math.PI, Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=1413; tryItOut("i1.next();");
/*fuzzSeed-133180449*/count=1414; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-133180449*/count=1415; tryItOut("a2.pop();");
/*fuzzSeed-133180449*/count=1416; tryItOut("testMathyFunction(mathy2, [2**53, -0, 0x100000000, -0x100000000, 0.000000000000001, 0, 2**53-2, -0x100000001, -(2**53-2), -Number.MAX_VALUE, Math.PI, 0x080000000, 0x080000001, -Number.MIN_VALUE, 42, 0x07fffffff, 1/0, 0/0, -1/0, 1, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=1417; tryItOut("/*iii*/g0.v2 = new Number(h2);/*hhh*/function gkqjki(w, x, x, NaN, y, x, y, e, NaN, NaN, x, x, x, \u3056, NaN, w, x, c, y, d, b, d, \u3056, d, y, x,  , x, eval, x, eval, \u3056, window, a, b, x, c, b, x, NaN, e, get =  /x/ , b = ({a1:1}), eval =  '' , x, c, y, x, a, x, y, w, e, x =  \"\" , d =  /x/g , x, z, x = this, x = arguments, b, x, e, let, x, c, d, x, b, \u3056 = ({a2:z2}), x, x, z, NaN, w, b, x, \u3056 =  '' , x, e, x, eval, b, NaN, c, e, x, a, b, x, e, x){print(x);}");
/*fuzzSeed-133180449*/count=1418; tryItOut("let this.v2 = evalcx(\"function f1(g2.e0) (/*MARR*/[g2.e0].filter(/*wrap3*/(function(){ \\\"use strict\\\"; var kwdige = (void shapeOf( '' )); (Function)(); })))\", g0);");
/*fuzzSeed-133180449*/count=1419; tryItOut("for (var v of a1) { try { t2[13] = g1; } catch(e0) { } try { t0 = m1.get(s0); } catch(e1) { } try { b1 = t1.buffer; } catch(e2) { } o0 = p1.__proto__; }");
/*fuzzSeed-133180449*/count=1420; tryItOut("a0.unshift(e1, t2, a1, g0, g0);");
/*fuzzSeed-133180449*/count=1421; tryItOut("print(x);\nprint(x);\n");
/*fuzzSeed-133180449*/count=1422; tryItOut("a2.length = 15;");
/*fuzzSeed-133180449*/count=1423; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(( + ((x , Math.fround(mathy0(Math.fround((( + (( + x) || ( + y))) < (-0 >>> 0))), ( + (( + x) > -0x100000000))))) === (mathy2(mathy1((mathy1(( + Math.fround(y)), x) ? x : mathy1(Math.log(x), (( ~ (2**53 >>> 0)) | 0))), y), (((x | 0) ? (( ~ 2**53) | 0) : ( + 0.000000000000001)) | 0)) | 0)))); }); ");
/*fuzzSeed-133180449*/count=1424; tryItOut("e2.add(o1);");
/*fuzzSeed-133180449*/count=1425; tryItOut("a2.toSource = f2;");
/*fuzzSeed-133180449*/count=1426; tryItOut("\"use strict\"; print(x);function y(x, x, b, x, z, y, w, x, x, a, d, b, x, x, x, w, NaN, NaN, w, NaN, z, x = {}, x, z, x = window, e, d, NaN, x, NaN, w, x, e, x = null, x, a, c, x = \"\\uFD85\", c = new RegExp(\"(?=^){4,}*\", \"gyi\"), b = -2, \"29\", x, x, NaN = 28, x = [], eval = undefined, y, NaN, y, NaN, NaN, x, x = true, x, x, e, w, eval = ({a2:z2}), \u3056 = 22, z, x = new RegExp(\"(?!(.)[^]\\\\3)*?|(?!(?=.)){1,}(?=\\\\S{0,}){4}\", \"i\"), \u3056, eval, x =  '' , b = Math, delete, eval = new RegExp(\"[\\\\d]*\", \"\"), x = /((?=[^\\\ue83f]|(?:\\b)|(?:.)))\\\u00de\\d++|\\2**?/ym, a = y, e = \"\\u4A70\", setter, x, x, z =  /x/ , a, x = /(?:\\2)*?|\\1*|(?!\\d[^]+?)|\\1|(?:\\u00E7)\\3?/ym, x, c = true, \u3056, eval, x =  \"\" , x, \u3056) { yield x } h0.hasOwn = f2;");
/*fuzzSeed-133180449*/count=1427; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    return +((d1));\n  }\n  return f; })(this, {ff: (decodeURIComponent).apply}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x0ffffffff, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, 0x080000001, Math.PI, 0/0, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53, -0x080000001, Number.MIN_VALUE, -0, -1/0, 0, 2**53+2, -(2**53), -Number.MIN_VALUE, 1/0, -Number.MAX_VALUE, -0x100000001, 0x100000000, -(2**53-2), 0x080000000, 0.000000000000001, 2**53-2, -0x07fffffff, -0x100000000]); ");
/*fuzzSeed-133180449*/count=1428; tryItOut("\"use strict\"; { void 0; void gc(this); } -19;");
/*fuzzSeed-133180449*/count=1429; tryItOut("/*vLoop*/for (kpdmyg = 0, ((x = x)), function ([y]) { }; kpdmyg < 146; ++kpdmyg) { y = kpdmyg; print(x); } ");
/*fuzzSeed-133180449*/count=1430; tryItOut("\"use strict\"; ");
/*fuzzSeed-133180449*/count=1431; tryItOut("\"use strict\"; m1.valueOf = (function() { try { ; } catch(e0) { } e0[\"[]\"] = v1; return m0; })\n/*RXUB*/var r = /(?:[^\\w\ub314\u929a\\cC])+?|\ufe44|^|^+?++|\\s(?:\\W|^|[^]+?)([^])^|(?=[]*?){1,2}(?:[^])|(?!(?![^]{3,})){32,33}/ym; var s =  '' ; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-133180449*/count=1432; tryItOut("a1 = arguments;\nv1 = Object.prototype.isPrototypeOf.call(o1, i2);\n");
/*fuzzSeed-133180449*/count=1433; tryItOut("mathy3 = (function(x, y) { return (((Math.fround(((Math.sqrt(Math.fround((Math.fround(x) || Math.fround(y)))) | 0) % Math.fround((Math.min((x / (Math.fround(( + Math.fround((Math.hypot((y >>> 0), (y >>> 0)) >>> 0)))) | 0)), (( + x) < ( + x))) | 0)))) >>> 0) >>> Math.round((mathy1((Math.hypot((Math.atan(({configurable: true})) >= -Number.MAX_VALUE), x) % y), ((Math.imul(( ~ ( + Math.fround(x))), ((2**53+2 ? y : x) | 0)) | 0) >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy3, [2**53-2, -1/0, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, -(2**53+2), 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, -0, 1.7976931348623157e308, -0x080000001, 0x100000000, 2**53+2, 0, 2**53, 42, 0/0, 0x0ffffffff, -0x100000000, -(2**53), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), -0x100000001, 1, 0x100000001, 0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1434; tryItOut("\"use asm\"; testMathyFunction(mathy1, [0.000000000000001, -(2**53), -1/0, -(2**53-2), 0, -0x0ffffffff, 0x080000001, 0x07fffffff, 2**53+2, -(2**53+2), 2**53, Math.PI, -0x07fffffff, 0x100000001, -Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, -0, 2**53-2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, -0x080000000, 1.7976931348623157e308, -Number.MAX_VALUE, 0/0, -0x100000000, 0x100000000, 1/0, 1, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1435; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1436; tryItOut("\"use strict\"; /*oLoop*/for (efmwfa = 0; efmwfa < 10; ++efmwfa) { v2 = (g2 instanceof m0); } ");
/*fuzzSeed-133180449*/count=1437; tryItOut("/*oLoop*/for (var mgqaem = 0; mgqaem < 2; ++mgqaem, y = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { throw 3; }, fix: function() { return []; }, has: \"\\uA54A\", hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: undefined, }; })(-1), Object.assign)) { e2.has((4277)); } ");
/*fuzzSeed-133180449*/count=1438; tryItOut("/*bLoop*/for (var kaiqzc = 0, window; kaiqzc < 51; ++kaiqzc) { if (kaiqzc % 5 == 2) { (\"\\u9A5C\"); } else { s1 += 'x'; }  } ");
/*fuzzSeed-133180449*/count=1439; tryItOut("g1.v2 = (e0 instanceof g1.o0.o2);");
/*fuzzSeed-133180449*/count=1440; tryItOut("Array.prototype.forEach.call(a0, (function(stdlib, foreign, heap){ \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      return +((4194305.0));\n    }\n    {\n      d0 = (-2305843009213694000.0);\n    }\n    d0 = (((d0)) * ((Float32ArrayView[((i1)) >> 2])));\n    i1 = (0x242327ab);\n    (Float32ArrayView[4096]) = ((d0));\n    i1 = (1);\n    (Float64ArrayView[(x) >> 3]) = ((d0));\n    switch (((((((0xffdb0679)) ^ ((0xffffffff))))) | ((-0x8000000)))) {\n      case 0:\n        i1 = (0x12404a18);\n        break;\n      case 1:\n        (Float64ArrayView[((0xded77801)) >> 3]) = ((((1.0)) - ((+(1.0/0.0)))));\n      case -3:\n        {\n          {\n            (Float64ArrayView[1]) = ((-147573952589676410000.0));\n          }\n        }\n        break;\n      default:\n        switch (((((0x2c9a8dfd))) >> (-0xd3231*(i1)))) {\n          case 0:\n            {\n              (Uint32ArrayView[((1)-((((Float64ArrayView[0])) / (/*UUV2*/(y.setUTCMinutes = y.reject))) <= (d0))) >> 2]) = ((((function a_indexing(ffzlxy, jcnntu) { ; if (ffzlxy.length == jcnntu) { ; return jcnntu; } var etbfhr = ffzlxy[jcnntu]; var hdeumd = a_indexing(ffzlxy, jcnntu + 1); s2 += s1; })(/*MARR*/[function(){}, function(){}], 0)))+(i1));\n            }\n            break;\n          default:\n            i1 = (0xaa99954d);\n        }\n    }\n    d0 = (+(1.0/0.0));\n    {\n      d0 = (((Float64ArrayView[((void options('strict_mode'))) >> 3])));\n    }\n    {\n      d0 = (d0);\n    }\no2.v2 = g2.eval(\"print(this.v1);\");    d0 = (d0);\n    d0 = (590295810358705700000.0);\n    {\n      {\n        d0 = (d0);\n      }\n    }\n    (Float32ArrayView[(((-67108863.0) == (-576460752303423500.0))) >> 2]) = ((Float64ArrayView[(-0x7a56e*((0x81058ae7))) >> 3]));\n    return +((-33554432.0));\n    return +((+(-1.0/0.0)));\n  }\n  return f; }), v1, window, this.v1);");
/*fuzzSeed-133180449*/count=1441; tryItOut("\"use strict\"; print(false);");
/*fuzzSeed-133180449*/count=1442; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.min(((Math.round(((Math.hypot((y | 0), ((( ~ (x | 0)) | 0) | 0)) | 0) >>> 0)) >>> 0) >= Math.fround((Math.fround((Math.max(( + x), ( + Math.exp(y))) >>> 0)) !== ( + y)))), (( + ( ! Math.fround((( ! ((Math.sqrt(Math.fround(( ~ ( + x)))) | x) | 0)) | 0)))) ? (Math.atan2((( ~ (((y | 0) ? (y | 0) : y) | 0)) | 0), (( + (( + y) <= ( + -Number.MIN_VALUE))) | 0)) | 0) : (Math.hypot(( + (( + (y <= x)) , (x >>> 0))), Math.atanh(y)) >>> 0)))); }); testMathyFunction(mathy0, [null, /0/, '', (new Boolean(false)), ({valueOf:function(){return 0;}}), false, (function(){return 0;}), (new Number(0)), '0', 0.1, (new Boolean(true)), [], '\\0', undefined, ({toString:function(){return '0';}}), true, 0, 1, NaN, (new String('')), ({valueOf:function(){return '0';}}), '/0/', objectEmulatingUndefined(), -0, (new Number(-0)), [0]]); ");
/*fuzzSeed-133180449*/count=1443; tryItOut("for (var p in f1) { try { for (var v of a1) { try { for (var v of i2) { try { for (var p in v0) { this.v2 = evaluate(\"break M;\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: window, noScriptRval: (x % 26 != 13), sourceIsLazy: (x % 4 != 1), catchTermination: arguments })); } } catch(e0) { } try { a1.push(g0.g1, x); } catch(e1) { } try { o2 = o0.g2.g0.__proto__; } catch(e2) { } p0.toString = f0; } } catch(e0) { } Array.prototype.push.apply(a1, [g1, g0.g1, h2, p0, e || d]); } } catch(e0) { } m1.delete(m1); }");
/*fuzzSeed-133180449*/count=1444; tryItOut("o1.h1.get = (function(j) { if (j) { this.v1 = (t1 instanceof o2.g0); } else { try { t2 = new Int16Array(b2); } catch(e0) { } try { print(m0); } catch(e1) { } e0.add(e2); } });");
/*fuzzSeed-133180449*/count=1445; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.atan2((( + Math.fround(( + Math.log((x >> x))))) | 0), Math.hypot((((((Math.fround(x) ? Math.trunc(Math.fround(y)) : Math.pow((x !== y), y)) >>> 0) % ((x == y) >>> 0)) >>> 0) >>> 0), 42)) ? ((( - (y >>> 0)) >>> 0) ** (( + (Math.acosh((Math.fround(( - Math.pow((y - Math.fround(y)), y))) >>> 0)) | 0)) >>> 0)) : Math.fround(mathy0(Math.sign(Math.log2(-0x07fffffff)), ( + (x , ((Math.fround(Math.atan2(y, y)) === ( + Math.acosh(( + -Number.MAX_VALUE)))) >>> 0)))))); }); testMathyFunction(mathy2, [0.000000000000001, -Number.MIN_SAFE_INTEGER, 1, 0x07fffffff, -Number.MAX_VALUE, 42, 0, -0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0x100000000, -0x0ffffffff, -(2**53+2), 2**53+2, -Number.MIN_VALUE, -(2**53), 0x080000001, 2**53, 0/0, 2**53-2, -0x080000000, 0x080000000, -(2**53-2), -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_VALUE, 1/0, Math.PI, -0x080000001, -1/0, -0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-133180449*/count=1446; tryItOut("\"use strict\"; g1.v1 = a2.reduce, reduceRight();");
/*fuzzSeed-133180449*/count=1447; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.sign(((y % Math.fround(Math.fround(( + x)))) != ( + Math.fround(Math.imul(Math.fround(y), Math.fround(Math.fround((Math.fround(Math.log2((Math.atan(x) >>> 0))) !== Math.fround(x))))))))) >>> 0); }); testMathyFunction(mathy2, [0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000001, -(2**53-2), -Number.MIN_VALUE, 0.000000000000001, 1/0, 0, -(2**53), 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, 2**53, -0x100000000, 0/0, 0x080000001, -Number.MAX_VALUE, 42, -0, 0x0ffffffff, -1/0, 1.7976931348623157e308, 2**53-2, -0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000001, 2**53+2, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-133180449*/count=1448; tryItOut("testMathyFunction(mathy5, [2**53-2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -(2**53+2), -Number.MIN_VALUE, -0x080000000, 0x100000001, 42, -(2**53-2), 2**53+2, 0/0, -0x100000001, 0x080000000, 0x0ffffffff, 0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, 1, 0x080000001, -0x0ffffffff, 2**53, -1/0, -(2**53), 1.7976931348623157e308, 0x07fffffff, 0x100000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=1449; tryItOut("m0.toSource = (function() { for (var j=0;j<33;++j) { f0(j%3==1); } });");
/*fuzzSeed-133180449*/count=1450; tryItOut("");
/*fuzzSeed-133180449*/count=1451; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-133180449*/count=1452; tryItOut("m0.get(g2.o1);");
/*fuzzSeed-133180449*/count=1453; tryItOut("this.t1[7] = x;");
/*fuzzSeed-133180449*/count=1454; tryItOut("\"use asm\";  for (let b of (new RegExp.prototype.exec()).__defineGetter__(\"getter\", function shapeyConstructor(jkjmtp){\"use strict\"; \"use asm\"; if (jkjmtp) this[\"isNaN\"] = (4277);if ((void shapeOf(++c)).valueOf(\"number\") / jkjmtp) this[\"isNaN\"] = new Boolean(true);this[\"isNaN\"] = {};this[\"isNaN\"] = Infinity;if (jkjmtp) this[\"isNaN\"] = ({} = (4277));for (var ytqulhmqt in this) { }this[\"isNaN\"] = arguments.callee.caller.caller;for (var ytqvnwjcz in this) { }return this; })) print(v0);");
/*fuzzSeed-133180449*/count=1455; tryItOut("mathy5 = (function(x, y) { return Math.cbrt(( + mathy1(( + Math.atan(( + ( + ( + ( + (mathy4((y | 0), (0 | 0)) | 0))))))), Math.hypot(((( + (Math.asin((-0 >>> 0)) >>> 0)) >= ( + x)) | 0), (( ! (( - y) >>> 0)) | 0))))); }); testMathyFunction(mathy5, [-(2**53), 2**53-2, -Number.MIN_VALUE, -1/0, 0, -(2**53-2), 42, 0x080000000, 2**53, 1.7976931348623157e308, -0x100000001, 0x100000000, -0, -0x0ffffffff, 1/0, Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, 1, Math.PI, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, 0x07fffffff, -0x07fffffff, 0x100000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 0.000000000000001]); ");
/*fuzzSeed-133180449*/count=1456; tryItOut("i2 = new Iterator(p2);");
/*fuzzSeed-133180449*/count=1457; tryItOut("\"use strict\"; print(s1);");
/*fuzzSeed-133180449*/count=1458; tryItOut("\"use strict\"; testMathyFunction(mathy0, [2**53+2, -(2**53+2), 0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE, 2**53, -(2**53-2), 0.000000000000001, -(2**53), 0, Math.PI, 42, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -1/0, -0x100000001, -0x07fffffff, 0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 0x100000001, 0x0ffffffff, 1, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, -0, 0/0, -0x0ffffffff]); ");
/*fuzzSeed-133180449*/count=1459; tryItOut("h0 = g0.o0.a0[14];");
/*fuzzSeed-133180449*/count=1460; tryItOut("g1.v0 = t2.length;");
/*fuzzSeed-133180449*/count=1461; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((((Math.fround(( - (((( + ( ~ ( + y))) >>> 0) == ( + Number.MIN_SAFE_INTEGER)) >>> 0))) | 0) & Math.log1p((((((y | y) >>> 0) >= y) | 0) ? (x | 0) : ( + (( ! (Math.min((y >>> 0), x) >>> 0)) >>> 0))))) | 0) === (Math.fround(( ~ Math.fround(( ! ( + ((-0x07fffffff ^ (Math.pow((x | 0), Math.log(y)) | 0)) | 0)))))) | 0)) | 0); }); ");
/*fuzzSeed-133180449*/count=1462; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-133180449*/count=1463; tryItOut("a1.sort((function() { v1 = g1.runOffThreadScript(); return p2; }), h1, h0, g1, e0, a1, b0);");
/*fuzzSeed-133180449*/count=1464; tryItOut("o2.a0[15] = g0;yield;function x() { yield new Uint16Array() } Array.prototype.pop.apply(a1, []);");
/*fuzzSeed-133180449*/count=1465; tryItOut("v2 = Object.prototype.isPrototypeOf.call(o2, a1);");
/*fuzzSeed-133180449*/count=1466; tryItOut("g0.t1 = new Uint8Array(a1);");
/*fuzzSeed-133180449*/count=1467; tryItOut("\"use strict\"; Object.defineProperty(this, \"v0\", { configurable: x, enumerable: 'fafafa'.replace(/a/g, (4277)),  get: function() {  return evalcx(\"(void schedulegc(g1));\", g0); } });");
/*fuzzSeed-133180449*/count=1468; tryItOut("\"use strict\"; /*bLoop*/for (var bxgbhz = 0; bxgbhz < 44; ++bxgbhz) { if (bxgbhz % 6 == 4) { print(uneval(p2)); } else { window;/*hhh*/function verosg(){v2 = t0.byteOffset;}verosg(window); }  } ");
/*fuzzSeed-133180449*/count=1469; tryItOut("a1.forEach((function mcc_() { var zqwgok = 0; return function() { ++zqwgok; if (/*ICCD*/zqwgok % 4 == 0) { dumpln('hit!'); try { v0 = a1.length; } catch(e0) { } try { for (var v of i1) { ; } } catch(e1) { } try { t2[({a2:z2})]; } catch(e2) { } f2 + i0; } else { dumpln('miss!'); try { (void schedulegc(g2)); } catch(e0) { } Array.prototype.reverse.apply(a1, [t1, o0]); } };})(), p1,  \"\" , h0);print(x);");
/*fuzzSeed-133180449*/count=1470; tryItOut("s2 += 'x';function e(b)(eval) = NaN = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: ({/*TOODEEP*/}), getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: /*wrap3*/(function(){ \"use strict\"; var yuuqyi = undefined; (decodeURI)(); }), fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: Int16Array, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: undefined, }; })( \"\" ), x)s2 + '';");
/*fuzzSeed-133180449*/count=1471; tryItOut("\"use strict\"; print(o2.b0);");
/*fuzzSeed-133180449*/count=1472; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1473; tryItOut("Object.prototype.unwatch.call(v0, \"arguments\");");
/*fuzzSeed-133180449*/count=1474; tryItOut("\"use strict\"; /*infloop*/ for (Function.prototype of eval(\"/* no regression tests found */\")) a1.push(f2, e1);");
/*fuzzSeed-133180449*/count=1475; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.log(( + (Math.fround(( + (( - x) && ( + ( ~ y))))) ** (( - ( + Math.tan(Math.atan2(y, x)))) >>> 0)))) >>> 0); }); ");
/*fuzzSeed-133180449*/count=1476; tryItOut("mathy2 = (function(x, y) { return mathy0(( + Math.atan2((((x >>> 0) || (x >>> 0)) | 0), mathy1(y, (( + x) == ( + -1/0))))), Math.imul(mathy0((Math.asinh((x >>> 0)) ? Math.cosh(x) : x), (Math.min(x, (( + ( + Math.imul(( + mathy0(1, x)), ( + x)))) * ( + x))) >>> 0)), mathy0(Math.fround(( ~ (mathy0(x, Math.fround(x)) | 0))), ( + mathy1(( + x), ( + ( ~ -Number.MIN_SAFE_INTEGER))))))); }); testMathyFunction(mathy2, [-0, -0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, 0/0, 0, 0x0ffffffff, 2**53-2, Math.PI, -1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, 42, 2**53, 0x080000001, 0x07fffffff, -0x100000001, 0x100000000, -0x080000001, -0x080000000, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x07fffffff, -(2**53-2), -(2**53), 1/0, 0x100000001, 0x080000000, 1, 0.000000000000001, Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=1477; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return (((!(i2))*-0x76558))|0;\n    d1 = ((!(i0)) ? (2199023255553.0) : (-1.1805916207174113e+21));\n    return (((i2)*-0xbb178))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-133180449*/count=1478; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1479; tryItOut("\"use strict\"; v2 = (o0.o1.p1 instanceof o2.e2);");
/*fuzzSeed-133180449*/count=1480; tryItOut("testMathyFunction(mathy2, [1.7976931348623157e308, 1/0, 0x07fffffff, 0/0, -0x07fffffff, 0, 0x0ffffffff, Math.PI, 0.000000000000001, -0x100000001, 0x100000000, -0x0ffffffff, 2**53, 0x080000000, 2**53-2, 0x080000001, 2**53+2, -1/0, 1, -Number.MAX_VALUE, 0x100000001, -(2**53-2), -(2**53+2), -(2**53), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, -0x080000001, -0x080000000, -0, -Number.MIN_VALUE, -0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1481; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((((( + ( + ( - -Number.MAX_SAFE_INTEGER))) ? ( + Math.atan2((Math.atan2((x | 0), (Math.pow(x, ( + (( - (x | 0)) >>> 0))) | 0)) | 0), 1)) : 0x100000001) % (((0x080000001 >> (( ! (y >>> 0)) >>> 0)) >>> 0) || (( - ( + Number.MIN_VALUE)) >>> 0))) >>> 0) >>> Math.cos(( ~ y))); }); ");
/*fuzzSeed-133180449*/count=1482; tryItOut("e1.add(i0);");
/*fuzzSeed-133180449*/count=1483; tryItOut("\"use strict\"; for (var p in this.m1) { try { m1.toSource = f2; } catch(e0) { } try { m0.has(f1); } catch(e1) { } try { v1 = Proxy.create(h0, s1); } catch(e2) { } g0.e0.add(g2.b0); }");
/*fuzzSeed-133180449*/count=1484; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1485; tryItOut("/*RXUB*/var r = /(?:\\B|\\3\\S\\d|(?=.|\\S){4})+?(?:\\2{4,}){1,}|\u00e9\\S\\B|(\\w){1,}/i; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-133180449*/count=1486; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1487; tryItOut("try { x = x; } finally { let(b) { throw b;} } ;");
/*fuzzSeed-133180449*/count=1488; tryItOut("mathy3 = (function(x, y) { return Math.fround((Math.fround((((( + Math.imul(y, x)) < ( + x)) ? (Math.cosh(((( + 0/0) << (x >>> 0)) >>> 0)) | 0) : y) & ( + (( ~ ( + y)) < ((((x % y) & Math.fround((Math.fround(x) === Math.fround(x)))) ? (((y >>> 0) ? ((Math.pow(x, Math.fround(mathy1(Math.fround(-0x080000000), -Number.MAX_VALUE))) | 0) >>> 0) : (Math.fround(( + Math.fround(y))) >>> 0)) >>> 0) : ( ~ -Number.MAX_SAFE_INTEGER)) >>> 0))))) > ( + ( - (( - (mathy0((((( + Number.MIN_VALUE) >>> 0) ? x : (x >>> 0)) >>> 0), Math.pow(x, (y == 0.000000000000001))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [0.000000000000001, 0x080000001, 42, -1/0, -(2**53+2), 0x100000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, Number.MIN_VALUE, -0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1/0, -0x07fffffff, 2**53, 0, 1, -0x100000001, -0x100000000, -0, 2**53+2, -Number.MIN_VALUE, 0x07fffffff, -(2**53-2), -(2**53), 0x100000001, 2**53-2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-133180449*/count=1489; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1490; tryItOut("mathy2 = (function(x, y) { return (((Math.acos(( + (Math.imul((( ! Math.hypot((x & (Math.asinh(x) >>> 0)), ((Math.fround(y) >>> Math.fround(y)) | 0))) >>> 0), (Math.min(Math.fround(1.7976931348623157e308), Math.fround((Math.hypot(Math.imul((-(2**53+2) >>> 0), (0/0 >>> 0)), ((-0x080000000 + Math.fround(x)) | 0)) | 0))) >>> 0)) >>> 0))) | 0) << Math.min(( + (( + ( + ( - ( + Math.fround((((Math.acos((x >>> 0)) >>> 0) != ( + Math.pow(( + y), (y | 0)))) & y)))))) ? ( + ((-0x080000000 >>> -(2**53)) === (-0 != 0/0))) : ( + Math.max(( + x), ((x % ((2**53-2 >>> 0) && y)) | 0))))), (Math.max((Math.tan(Math.fround(y)) >>> 0), (mathy1(( + Math.fround(mathy0(y, Math.fround(mathy1((-Number.MAX_SAFE_INTEGER >>> 0), -Number.MAX_VALUE))))), ((Math.asin((y >>> 0)) >>> 0) | ( + (x === (y >>> 0))))) | 0)) >>> 0))) | 0); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, Math.PI, 1/0, -0x080000001, 2**53+2, -Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 0x07fffffff, 0x100000000, -Number.MAX_VALUE, 2**53, -0x100000001, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 0x080000001, 0x100000001, 0x080000000, -0x07fffffff, 1, 2**53-2, -(2**53), -0x100000000, -(2**53-2), -0x080000000, -0x0ffffffff, -(2**53+2), -1/0, 0x0ffffffff, 0/0, 0]); ");
/*fuzzSeed-133180449*/count=1491; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1492; tryItOut("\"use strict\"; print(uneval(p2));");
/*fuzzSeed-133180449*/count=1493; tryItOut("\"use strict\"; { void 0; verifyprebarriers(); }");
/*fuzzSeed-133180449*/count=1494; tryItOut("\"use strict\"; b0 = new SharedArrayBuffer(136);");
/*fuzzSeed-133180449*/count=1495; tryItOut("var c = x;(null);");
/*fuzzSeed-133180449*/count=1496; tryItOut("testMathyFunction(mathy2, /*MARR*/[0x40000001, 0x40000001, -Infinity, -Infinity, new Number(1), new Number(1), 0x40000001, -Infinity, -Infinity, 0x40000001, new Number(1), 0x40000001, new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), new Number(1), 0x40000001, -Infinity, 0x40000001, new Number(1), -Infinity, new Number(1), new Number(1), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), -Infinity, -Infinity, new Number(1), new Number(1), new Number(1), -Infinity, new Number(1), -Infinity, new Number(1), new Number(1), -Infinity, new Number(1)]); ");
/*fuzzSeed-133180449*/count=1497; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.abs(Math.fround(Math.abs((Math.fround(( + Math.atan2(( + y), Math.fround(Math.expm1(x))))) << ((new ((1 for (x in [])))((makeFinalizeObserver('nursery')), this)) | 0))))); }); testMathyFunction(mathy1, [2**53-2, 0.000000000000001, 0x0ffffffff, -0x07fffffff, 1/0, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, Number.MIN_VALUE, -Number.MAX_VALUE, 42, -(2**53+2), 2**53+2, -0x100000000, 0x07fffffff, -(2**53), -0x0ffffffff, 0x100000000, 0x080000000, -0x080000000, -1/0, -Number.MIN_VALUE, 2**53, Math.PI, 0x080000001, 1.7976931348623157e308, 0, -0x100000001, -0]); ");
/*fuzzSeed-133180449*/count=1498; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + Math.abs(( + ( + ( ~ (( + ( + (( + ( - x)) >>> 0))) >>> 0)))))) , (( ! ( + -Number.MIN_SAFE_INTEGER)) >> Math.expm1((( + (Math.exp(( + y)) | 0)) >>> 0)))); }); testMathyFunction(mathy0, [0.000000000000001, 1, -1/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 1.7976931348623157e308, 0x080000000, -0x080000001, -0x100000001, 0x100000001, 0, -0, 0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 2**53, 2**53+2, 0x080000001, 42, 0x07fffffff, 0x0ffffffff, -(2**53), -0x100000000, 0/0, -(2**53-2), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, -0x0ffffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1499; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Int16ArrayView[0]) = ((0xfb8b3d31)+((p={}, (p.z = ( /x/g  ** /\\1+/ym))())));\n    d1 = (562949953421313.0);\n    d0 = (d0);\n    d0 = (+(((0xfbc1ba24)-(0xfcff3ce4)) << ((0xfcfe28a3)-(0xffffffff)-(0xfe4d67c5))));\n    d1 = (d1);\n    d0 = (d0);\n    return +((+(0.0/0.0)));\n    return +((((Float32ArrayView[(-(0xffffffff)) >> 2])) % ((d0))));\n    return +((d0));\n    return +((+/*FFI*/ff(((~((((-0x8000000)) & ((/*FFI*/ff()|0))) / (imul(((-0x31671d3) <= (((/*FFI*/ff(((-33.0)), ((-8.0)), ((-128.0)), ((-36028797018963970.0)), ((2.0)), ((-8388609.0)), ((140737488355329.0)), ((-17179869185.0)), ((-35184372088833.0)))|0))|0)), (/*FFI*/ff(((d0)), ((+abs(((d0))))), ((((0xffffffff)) & ((0x9e1dabf)))), ((8589934593.0)), ((-1.888946593147858e+22)), ((-549755813889.0)), ((-34359738369.0)), ((1.0078125)), ((9.44473296573929e+21)))|0))|0)))), ((~((-0x4c00bf8)))), ((~(((((0x32220222) == (0x7fffffff))-(0xf97bb964))>>>((0xffffffff)*0x6cef7)) % (0x7a355c36)))), ((((0xaffeb686)*-0x932b2)|0)), ((+((Float64ArrayView[((0x97003ab6) / (0x7e573cb4)) >> 3])))))));\n    return +((+abs(((d1)))));\n  }\n  return f; })(this, {ff: String.prototype.padEnd}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [1, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, -(2**53), -Number.MAX_VALUE, -1/0, -0x0ffffffff, Math.PI, 42, 2**53-2, -0x080000000, 0x100000000, 0x080000000, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0, -0, Number.MAX_VALUE, -(2**53+2), 0/0, 2**53, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x07fffffff, -(2**53-2), 0x080000001, -0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-133180449*/count=1500; tryItOut("\"use strict\"; /(?:$|[^]|\\b{0}+[D-y]{524287}|(?:(?:\\2)))/;/*ADP-2*/Object.defineProperty(a1, this.v1, { configurable: false, enumerable: false, get: (function mcc_() { var ytzmop = 0; return function() { ++ytzmop; f1(/*ICCD*/ytzmop % 3 != 1);};})(), set: f2 });");
/*fuzzSeed-133180449*/count=1501; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( ! ( + Math.fround((( + (x == ( + (( + ((y | 0) % y)) | 0)))) + ( + ((Math.asin(y) >>> 0) >>> Math.exp(Math.atan2((-(2**53-2) | 0), ( + (( + x) != ( + 0x100000001)))))))))))); }); testMathyFunction(mathy1, [-0, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, 0.000000000000001, 2**53+2, Number.MIN_VALUE, 1, Number.MAX_VALUE, 0x100000001, 0x080000000, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -0x0ffffffff, 42, -(2**53+2), 1/0, 0x080000001, -0x080000001, -0x080000000, 1.7976931348623157e308, 0x0ffffffff, Math.PI, -Number.MIN_VALUE, 0x07fffffff, 2**53-2, -0x07fffffff, -(2**53), -(2**53-2)]); ");
/*fuzzSeed-133180449*/count=1502; tryItOut("this.g2.offThreadCompileScript(\"o2.v2 = a0.length;\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 3 == 0), sourceIsLazy: false, catchTermination:  /x/  }));function window(x, eval) { e0.has(b0); } v0 = o1.a2.length;");
/*fuzzSeed-133180449*/count=1503; tryItOut("/*tLoop*/for (let x of /*MARR*/[{}, function(){}, {}, {}, {}, {}, {}, function(){}, {}, function(){}, {}, {}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, {}, function(){}, function(){}, function(){}, function(){}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}]) { i1.send(h0); }");
/*fuzzSeed-133180449*/count=1504; tryItOut("Array.prototype.shift.call(a2, v1);");
/*fuzzSeed-133180449*/count=1505; tryItOut("");
/*fuzzSeed-133180449*/count=1506; tryItOut("\"use asm\"; f0 = o0;\no2.f0 = (function() { try { print(uneval(s1)); } catch(e0) { } try { s1 += 'x'; } catch(e1) { } try { m1.delete(o1.p1); } catch(e2) { } a1 + s1; return e1; });\n");
/*fuzzSeed-133180449*/count=1507; tryItOut("if(\"\u03a0\") a0.sort((function() { try { ; } catch(e0) { } try { o0.g2.h0.hasOwn = /*wrap2*/(function(){ var bhhowx = w; var szlfld = eval; return szlfld;})(); } catch(e1) { } s0 += s0; return o0.e0; })); else  if ((yield /(?:\\2){1}/gyim))  /x/ ;");
/*fuzzSeed-133180449*/count=1508; tryItOut("\"use strict\"; f0.toSource = (function mcc_() { var evvxcg = 0; return function() { ++evvxcg; if (/*ICCD*/evvxcg % 8 == 3) { dumpln('hit!'); v2 = a1.length; } else { dumpln('miss!'); try { s0 += 'x'; } catch(e0) { } try { s1 += 'x'; } catch(e1) { } try { h1.__proto__ = m0; } catch(e2) { } v0 = Object.prototype.isPrototypeOf.call(e1, i2); } };})();");
/*fuzzSeed-133180449*/count=1509; tryItOut("t1 = new Int32Array(t1);");
/*fuzzSeed-133180449*/count=1510; tryItOut("/* no regression tests found */");
/*fuzzSeed-133180449*/count=1511; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0x9e08641a);\n    i1 = (0xfd6dad31);\n    return (((-0x8000000)+((((0x567b8bbf))>>>(((i1) ? (0xde78c23b) : (0xff019f70)))))))|0;\n    return (((0x84562019)-(0xff25d456)))|0;\n  }\n  return f; })(this, {ff: (Math.max(this -  \"\" , -8)).big}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, ['', /0/, true, (new Number(-0)), [0], 1, NaN, (new Boolean(false)), (new Boolean(true)), null, ({toString:function(){return '0';}}), '/0/', (function(){return 0;}), 0, undefined, '\\0', (new String('')), (new Number(0)), [], '0', false, ({valueOf:function(){return 0;}}), -0, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), 0.1]); ");
/*fuzzSeed-133180449*/count=1512; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.max((Math.pow(Math.cos((( ~ Math.fround((x != -0x080000001))) >>> 0)), (((Math.atan2(Math.acosh(2**53-2), x) | 0) / x) ? x : 1/0)) | 0), Math.fround(mathy1(Math.tanh(Math.cosh(Math.fround(Math.max(Math.fround(x), Math.fround((x + x)))))), ((y | 0) ? (y | 0) : Math.fround(mathy0((( + Math.round(( + /*MARR*/[y, y, new String(''), (0/0), new String(''), (0/0), new String(''), y, new String(''), (0/0), (0/0), new Number(1.5), (0/0), y, y, y, y, new Number(1.5), (0/0), y, (0/0), new String(''), y, (0/0), (0/0), y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, y, (0/0), y, y, new Number(1.5), y, y, new Number(1.5), y, new String(''), (0/0), y, new Number(1.5), (0/0), new String(''), new Number(1.5), y, new String(''), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new String(''), new String(''), y, new Number(1.5), new Number(1.5), new Number(1.5), y, new Number(1.5), new String(''), new String(''), y, new String(''), new Number(1.5), y, y, new Number(1.5), (0/0), y, new Number(1.5), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0)]))) >>> 0), (x >>> 0)))))))); }); ");
/*fuzzSeed-133180449*/count=1513; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-133180449*/count=1514; tryItOut("mathy2 = (function(x, y) { return (( ! (mathy1(Math.fround(( ! Math.fround((Math.fround(Math.ceil(y)) >>> ( + Math.hypot(1.7976931348623157e308, x)))))), ( + ( + Math.trunc(( + ( + Math.hypot(Math.max(x, x), x))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, -1/0, 1/0, 0, -0, -(2**53-2), -(2**53+2), -0x100000001, 42, -0x100000000, 1.7976931348623157e308, -(2**53), 0x100000000, 0x080000000, -0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 0x100000001, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, 0x0ffffffff, 1]); ");
/*fuzzSeed-133180449*/count=1515; tryItOut("mathy2 = (function(x, y) { return Math.sinh(Math.fround((Math.fround(( ~ mathy0(y, -0x100000001))) - ( - ( + ( - ( + -Number.MIN_VALUE))))))); }); ");
/*fuzzSeed-133180449*/count=1516; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[e && x, null, e && x, e && x, e && x, e && x,  \"use strict\" , (-1/0), new Number(1.5), e && x, null, (-1/0), new Number(1.5), (-1/0),  \"use strict\" , null, e && x, e && x, null, new Number(1.5),  \"use strict\" , (-1/0), null, null, e && x, new Number(1.5),  \"use strict\" , new Number(1.5), new Number(1.5), null, null, new Number(1.5), null, null,  \"use strict\" , e && x, e && x, null, e && x, null, (-1/0), new Number(1.5), (-1/0),  \"use strict\" , e && x, null, e && x, e && x, (-1/0),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (-1/0), null, null, new Number(1.5), null,  \"use strict\" , null, (-1/0), e && x, new Number(1.5), (-1/0), null,  \"use strict\" , (-1/0), new Number(1.5),  \"use strict\" , (-1/0), null,  \"use strict\" , e && x, (-1/0), (-1/0), (-1/0),  \"use strict\" , (-1/0),  \"use strict\" , null, null,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , e && x, (-1/0), e && x,  \"use strict\" ,  \"use strict\" , e && x, new Number(1.5), e && x, null,  \"use strict\" , null, null,  \"use strict\" , e && x,  \"use strict\" ,  \"use strict\" , new Number(1.5),  \"use strict\" , e && x, new Number(1.5),  \"use strict\" , null, e && x, e && x, null, null, (-1/0), null, null, new Number(1.5), e && x, new Number(1.5),  \"use strict\" ]); ");
/*fuzzSeed-133180449*/count=1517; tryItOut("mathy1 = (function(x, y) { return Math.cos(mathy0(Math.fround((Math.expm1((-0x0ffffffff !== Math.fround(y))) <= ( ~ ( - (((x & (y >>> 0)) >>> 0) | 0))))), (( + (( + ( + -0)) | 0)) | 0))); }); testMathyFunction(mathy1, [2**53+2, -Number.MAX_VALUE, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0, 0x080000001, 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -(2**53-2), 0x100000001, -0x080000000, -1/0, -0, -0x0ffffffff, 1.7976931348623157e308, 42, -(2**53+2), Number.MIN_VALUE, 1, -(2**53), 0x07fffffff, -Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 2**53, 0x100000000, Math.PI, 1/0, -Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-133180449*/count=1518; tryItOut("/*RXUB*/var r = /(?:((?=(.))\\B[^\\S\\x3C\\Wu-\\u00E0]|[]*\\\u9fa6|[^]{0,3}|^|\\cA|\\W?){3,})/g; var s = \"\"; print(s.replace(r, '\\u0341', \"gyim\")); ");
/*fuzzSeed-133180449*/count=1519; tryItOut("z, w, x = (4277), d = 21, bqdluv, lwwtsk, z;f1 = -23;");
/*fuzzSeed-133180449*/count=1520; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.tanh(Math.fround(Math.atan(( + ( + (( + mathy1(-0x0ffffffff, x)) === ( + x))))))); }); testMathyFunction(mathy2, [0x100000000, 0x0ffffffff, 0x080000000, -0x100000000, Number.MAX_VALUE, 0x07fffffff, 1/0, -0x080000001, 1.7976931348623157e308, -0x0ffffffff, Number.MIN_VALUE, 0/0, -(2**53-2), 0x100000001, -1/0, Number.MAX_SAFE_INTEGER, 42, -(2**53), -0, 0.000000000000001, -Number.MIN_VALUE, 0, 2**53, -0x080000000, -0x100000001, Math.PI, 1, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-133180449*/count=1521; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-(2**53), -0x100000001, 2**53, 1.7976931348623157e308, -0x0ffffffff, 0x07fffffff, 2**53-2, 1, -1/0, 0x080000001, -(2**53+2), -0x080000000, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 0.000000000000001, -(2**53-2), 2**53+2, -0x080000001, 0, -0x100000000, 42, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, 1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000]); ");
/*fuzzSeed-133180449*/count=1522; tryItOut("var x = function(id) { return id }(), kxsviv, NaN = (x) = -140737488355329;m0 = new Map;");
/*fuzzSeed-133180449*/count=1523; tryItOut("((new /(?:[^]|\\b)/gi(new RegExp(\"(?=.)\", \"yim\"), window)));\n/*infloop*/for(let c = x; 17; new RegExp(\"\\\\S\", \"m\")) g2.m0.has(a0);\n");
/*fuzzSeed-133180449*/count=1524; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-133180449*/count=1525; tryItOut("selectforgc(o2);");
/*fuzzSeed-133180449*/count=1526; tryItOut("\"use strict\"; a2.unshift(this.g1.v0, g1, o2, i2, g0);t1 = new Int32Array(t0);");
/*fuzzSeed-133180449*/count=1527; tryItOut("for(let b in []);y.constructor;");
/*fuzzSeed-133180449*/count=1528; tryItOut("\"use asm\"; g2.m2 = new Map;");
/*fuzzSeed-133180449*/count=1529; tryItOut("mathy1 = (function(x, y) { return ( ~ mathy0(Math.atan2((Math.acos(x) >>> 0), (( ! Math.clz32((( ~ x) >>> 0))) >>> 0)), ( + Math.max(( + (x + (2**53+2 >>> 0))), (Math.pow(((( ~ (( - 0x080000000) | 0)) | 0) >>> 0), (y >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, [1, 2**53-2, -0x100000000, 1.7976931348623157e308, 2**53, 0x100000000, -(2**53+2), -0x080000001, 0/0, 2**53+2, 0x0ffffffff, -0, Math.PI, -0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), Number.MAX_VALUE, -(2**53), -0x100000001, -Number.MIN_VALUE, 0x080000001, 0x080000000, 42, 0, 0.000000000000001, 0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-133180449*/count=1530; tryItOut("a1.forEach();");
/*fuzzSeed-133180449*/count=1531; tryItOut("o2.v1 = Object.prototype.isPrototypeOf.call(f1, f1);");
/*fuzzSeed-133180449*/count=1532; tryItOut("\"use strict\"; v1 = evaluate(\"for (var p in e2) { try { a0.pop(); } catch(e0) { } try { i2.next(); } catch(e1) { } Object.defineProperty(this, \\\"v0\\\", { configurable: true, enumerable: /(?!(?=\\\\B))/im,  get: function() {  return this.g2.runOffThreadScript(); } }); }\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 2 == 1), catchTermination: true }));");
/*fuzzSeed-133180449*/count=1533; tryItOut("/*RXUB*/var r = /(?:.|\\1{2,2}|(?:(?=.*))?(\\B)*|\\B\\S{0}){16777216}/gi; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
