

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
/*fuzzSeed-66366547*/count=1; tryItOut("let (d) { v1 = this.g2.eval(\"v2 = a1.length;\"); }");
/*fuzzSeed-66366547*/count=2; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2((( ~ ( ! y)) >>> 0), ((Math.fround(( + (Math.max(Math.fround(( - -Number.MIN_SAFE_INTEGER)), ((y ? 1/0 : ( + Math.exp(( + ( + y))))) | 0)) | 0))) | ( ~ ((mathy2((-(2**53+2) >>> 0), y) ? ((( ! 0x080000001) | 0) >>> 0) : y) * y))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-1/0, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, 0x100000000, 2**53, 42, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, -0x07fffffff, 1, -(2**53), -0x100000000, 0x080000001, 0x080000000, 0.000000000000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, 0x100000001, 1.7976931348623157e308, 0/0, Number.MAX_VALUE, 0x07fffffff, 1/0, 2**53-2, -0x080000001, 0x0ffffffff, -(2**53+2), -0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=3; tryItOut("o1.f0 = Proxy.createFunction(h2, o1.f0, f2);");
/*fuzzSeed-66366547*/count=4; tryItOut("\"use strict\"; { void 0; abortgc(); }");
/*fuzzSeed-66366547*/count=5; tryItOut("mathy5 = (function(x, y) { return ( + Math.atan2(( + ( + ( ! (Math.cbrt(Math.pow((mathy4(((y * x) >>> 0), (( + mathy2(42, (((y >>> 0) !== (y >>> 0)) >>> 0))) | 0)) >>> 0), (( + y) >>> 0))) >>> 0)))), ( + ((y ? ( + (( + x) ? x : mathy1(x, ((Math.fround((Math.cosh((-0x07fffffff >>> 0)) >>> 0)) / (0 >>> 0)) >>> 0)))) : x) === Math.pow(( ! (Math.imul(((x >>> 0) < y), x) ? x : y)), (Math.max(y, (x >>> 0)) | 0)))))); }); testMathyFunction(mathy5, [-0x100000000, 1, -(2**53+2), 0.000000000000001, -0x080000001, 1.7976931348623157e308, 1/0, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, Number.MIN_VALUE, -Number.MAX_VALUE, -0, -1/0, Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, -0x100000001, 2**53, 0x07fffffff, -(2**53), 0x0ffffffff, 0x100000001, 0x080000001, -(2**53-2), 0/0, -0x080000000, 0x080000000, 42, 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=6; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((( + (Math.min((( ! ( - Math.fround(Math.max(Math.fround(y), Math.fround(y))))) >>> 0), ((((y >>> 0) ? Math.log1p(-0x100000001) : (mathy2((Math.atan2((Math.hypot((x | 0), x) | 0), ((Math.acosh(y) >>> 0) | 0)) | 0), Math.fround(Math.ceil(( + ( + ((((0x100000001 | 0) !== y) >>> 0) ? ( + x) : ( + x))))))) >>> 0)) >>> 0) >>> 0)) >>> 0)) || (Math.atanh((Math.fround(Math.cosh(( + Math.sin(( + ( - x)))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy3, [-0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), 0x080000001, -0x100000000, 0.000000000000001, Math.PI, 0x07fffffff, 2**53, -0x080000001, 1, -(2**53), 0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, -0x0ffffffff, 0x100000001, 0x080000000, Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53+2), -0, 1.7976931348623157e308, -Number.MIN_VALUE, 42, 0x100000000, Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, -Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-66366547*/count=7; tryItOut("/*ODP-1*/Object.defineProperty(g2.a0, \"valueOf\", ({configurable: true, enumerable: false}));");
/*fuzzSeed-66366547*/count=8; tryItOut("g2.v1 = new Number(0);");
/*fuzzSeed-66366547*/count=9; tryItOut(";");
/*fuzzSeed-66366547*/count=10; tryItOut("b1.__iterator__ = (function(j) { if (j) { try { o0 = p1.__proto__; } catch(e0) { } a2 = arguments.callee.caller.arguments; } else { try { o2.s1 += 'x'; } catch(e0) { } try { this.g1.offThreadCompileScript(\"\\\"use strict\\\"; mathy5 = (function(x, y) { \\\"use strict\\\"; return Math.imul(( - (Math.min(x, x) / Math.fround((Math.fround(y) === Math.fround(((( ~ x) ^ y) >>> 0)))))), ( + mathy3(( + ( + Math.max(Math.fround(Math.fround((-0x0ffffffff << y))), y))), ( + (Math.asin((((( + Math.imul(( + Math.cos(( + 0/0))), Math.log(( + ( - x))))) ? (-(2**53) >>> 0) : (Math.fround(((y ? ( + y) : x) ^ mathy0(y, x))) >>> 0)) >>> 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [1, true, '', objectEmulatingUndefined(), (new Number(-0)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '\\\\0', (new Number(0)), (new Boolean(true)), [], '0', (new String('')), (function(){return 0;}), undefined, [0], 0.1, false, /0/, 0, null, '/0/', ({valueOf:function(){return '0';}}), (new Boolean(false)), NaN, -0]); \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 3), noScriptRval: false, sourceIsLazy: (x % 78 != 39), catchTermination: (x % 63 != 27) })); } catch(e1) { } /*MXX1*/o0 = g1.Object.prototype.__defineGetter__; } });");
/*fuzzSeed-66366547*/count=11; tryItOut("h0.defineProperty = (function() { for (var j=0;j<83;++j) { f2(j%4==0); } });");
/*fuzzSeed-66366547*/count=12; tryItOut("/*tLoop*/for (let z of /*MARR*/[x, x, x, x,  /x/g ,  /x/g , x, x,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x, x,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g , x,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , x,  /x/g , x,  /x/g ,  /x/g , x,  /x/g ,  /x/g , x,  /x/g , x, x, x,  /x/g , x, x, x,  /x/g , x, x,  /x/g , x, x, x,  /x/g , x,  /x/g , x,  /x/g , x, x,  /x/g , x,  /x/g , x,  /x/g , x, x,  /x/g ,  /x/g ,  /x/g , x, x, x,  /x/g ,  /x/g ,  /x/g ,  /x/g ]) { print(z); }");
/*fuzzSeed-66366547*/count=13; tryItOut("\"use strict\"; Array.prototype.shift.apply(a2, []);");
/*fuzzSeed-66366547*/count=14; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.acosh(Math.clz32(Math.tan((Math.pow((y | 0), x) >>> 0)))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, -Number.MAX_VALUE, 1/0, 0x100000001, 0, -0x100000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53+2, 1, -0x080000000, -1/0, -0x07fffffff, 0x080000001, -(2**53), 0x080000000, 2**53-2, 0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, 0/0, -0, -Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 42, 2**53, 0x100000000, -0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-66366547*/count=15; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( ~ Math.fround(mathy1(( + Math.expm1(( + ( + (( + Math.atan2(( + 1), ( + y))) ? Math.fround(y) : Math.fround(y)))))), mathy2(( + (( + 0.000000000000001) !== ( + Math.fround((Math.fround(0/0) > Math.fround(y)))))), Math.max(x, Math.tan(y))))))); }); testMathyFunction(mathy3, /*MARR*/[new String(''), function(){}, new String(''), x, new String(''), function(){}, function(){}, [1], [1], [1], x, function(){}, [1], x, [1], 0x100000000, x, function(){}, [1], [1], function(){}, new String(''), function(){}, new String(''), new String(''), 0x100000000, new String(''), new String(''), [1], new String(''), 0x100000000, [1], [1], x, 0x100000000, new String(''), x, 0x100000000, function(){}, x, function(){}, [1], function(){}, x, x, 0x100000000, [1], new String(''), new String(''), new String(''), function(){}, 0x100000000, function(){}, x, new String(''), function(){}]); ");
/*fuzzSeed-66366547*/count=16; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.abs(( + (Math.fround(mathy0((Math.trunc(Math.imul(( + mathy1(x, -0x07fffffff)), (Math.pow((Math.PI >>> 0), (x >>> 0)) >>> 0))) >>> 0), (Math.fround((y || y)) >>> 0))) ** (( ~ Math.atan2(( + Math.ceil((mathy0((x | 0), y) >>> 0))), ( + (Math.log2(y) | x)))) | 0))))); }); testMathyFunction(mathy2, /*MARR*/[function(){}, (void 0), (void 0), (void 0), function(){}, (void 0), (void 0), function(){}, (void 0), function(){}, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), function(){}, (void 0), (void 0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (void 0), (void 0), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, (void 0), (void 0), (void 0), function(){}]); ");
/*fuzzSeed-66366547*/count=17; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.ceil(Math.fround((((mathy1(( + y), ( ~ (x !== Math.pow(y, y)))) >>> 0) ** (Math.imul(Math.fround(( - Math.fround(x))), (Math.fround((Math.fround(Math.max(Math.fround(( + y)), Math.fround((Math.max(( + -Number.MAX_SAFE_INTEGER), (((x & (Number.MAX_SAFE_INTEGER | 0)) | 0) | 0)) | 0)))) & Math.fround(Math.exp(Math.clz32(y))))) | 0)) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-66366547*/count=18; tryItOut("L: {let (x) { t2.__proto__ = g2.e1; }print(x);function NaN() { yield [] = (w = \"\\u6154\") } /* no regression tests found */ }");
/*fuzzSeed-66366547*/count=19; tryItOut("t1.set(t1, 3);");
/*fuzzSeed-66366547*/count=20; tryItOut("\"use strict\"; o2.a0 = arguments.callee.arguments;");
/*fuzzSeed-66366547*/count=21; tryItOut("\"use strict\"; a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = newGlobal({  }); f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-66366547*/count=22; tryItOut("\"use strict\"; /*hhh*/function isxeva(\u3056, ...a){if((x % 4 == 1)) { if ( ''  ** \"\\uDF8E\") print(x);} else {v0 = g2.runOffThreadScript(); }}isxeva();");
/*fuzzSeed-66366547*/count=23; tryItOut("e0.delete(i2);");
/*fuzzSeed-66366547*/count=24; tryItOut("g2.h0.iterate = g1.o1.f2;");
/*fuzzSeed-66366547*/count=25; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    i0 = (i0);\n    (Int32ArrayView[((/*FFI*/ff(((3.777893186295716e+22)), ((-((+/*FFI*/ff(((((0xf8e0030b)) << ((0xffffffff)))), ((eval(\"mathy4 = (function(x, y) { \\\"use strict\\\"; return Math.exp(((Math.sign(( + ( - (x !== Math.fround((( ! ( + y)) | 0)))))) | 0) | 0)); }); testMathyFunction(mathy4, [Number.MIN_VALUE, -0x100000001, -1/0, Math.PI, -(2**53), 0x100000001, 0x080000001, 2**53+2, 0.000000000000001, 1/0, -0x0ffffffff, 2**53-2, -0x100000000, 2**53, 1, -0x080000000, Number.MAX_VALUE, -(2**53-2), 0/0, -0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, 0x100000000, 0x0ffffffff, 42, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000, -(2**53+2)]); \")))))))), (((((0x563e539e))*0x923cf)|0)), ((~~(((-1.2089258196146292e+24)) - ((-513.0))))), ((((-0x8000000))|0)), ((1.5111572745182865e+23)), ((65537.0)), ((4503599627370497.0)), ((128.0)), ((-1048577.0)), ((33.0)))|0)) >> 2]) = (((i0) ? (i0) : (i0))-(!(i1)));\n    i0 = (((4294967297.0) + (-129.0)) > (-4097.0));\n    return (((i1)+((-4503599627370497.0) != (+(0xdfbf588a)))+((0xc15e932c) >= ((((0x3bf19cd3) < (0x27bdaf61))+(!(i0))+((-1073741823.0) <= (-140737488355329.0)))>>>((i1))))))|0;\n  }\n  return f; })(this, {ff: Math.max}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [0x080000000, 0x100000001, -(2**53-2), 0x0ffffffff, -(2**53+2), 0.000000000000001, 0/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000000, -0, 2**53+2, Number.MIN_VALUE, -(2**53), -0x080000001, Math.PI, Number.MAX_VALUE, 0, -0x100000000, 42, 0x07fffffff, -Number.MAX_VALUE, 1, 0x100000000, 1.7976931348623157e308, -0x0ffffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 2**53-2, 1/0]); ");
/*fuzzSeed-66366547*/count=26; tryItOut("\"use strict\"; { void 0; try { gcparam('sliceTimeBudget', 38); } catch(e) { } } let (x) { v2 = Object.prototype.isPrototypeOf.call(this.f1, o0); }");
/*fuzzSeed-66366547*/count=27; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=28; tryItOut("g1.offThreadCompileScript(\"with({}) { let(((arguments.callee.caller).call((this.__defineSetter__(\\\"x\\\", x)), eval(\\\"e2.add(29);\\\", false))), atqgll, piudym, z = ( /* Comment */[z1,,]), pkdewn) { this.zzz.zzz;} } for(let w of /*wrap1*/(function(){ \\\"use strict\\\"; g0.o2.g0 + '';return function(y) { yield y; for (var v of m2) { try { v1 = (m1 instanceof o1); } catch(e0) { } try { /*MXX2*/g0.Symbol.prototype.constructor = p0; } catch(e1) { } this.f1 = (function() { for (var j=0;j<5;++j) { f2(j%2==1); } }); }; yield y; }})()) throw StopIteration;\");");
/*fuzzSeed-66366547*/count=29; tryItOut("\"use strict\"; const y = ((4277).__proto__);/*MXX1*/o0 = g0.Function.prototype.toString;");
/*fuzzSeed-66366547*/count=30; tryItOut("v2 = t0.BYTES_PER_ELEMENT;\nh1.toString = (function(j) { if (j) { try { print(uneval(p2)); } catch(e0) { } try { a1 = Array.prototype.filter.call(a1, f0); } catch(e1) { } try { p0.__proto__ = a0; } catch(e2) { } s1 = ''; } else { try { ; } catch(e0) { } try { m2.delete(o1); } catch(e1) { } Array.prototype.splice.apply(a0, [NaN, 11]); } });\n");
/*fuzzSeed-66366547*/count=31; tryItOut("o1.toSource = (function(j) { f1(j); });");
/*fuzzSeed-66366547*/count=32; tryItOut("");
/*fuzzSeed-66366547*/count=33; tryItOut("mathy0 = (function(x, y) { return (( ~ (Math.expm1((( + ( - (Math.sinh(Math.log10(x)) >>> 0))) >>> 0)) >>> 0)) >> Math.log2((( + ( ! ( + y))) | -Number.MAX_SAFE_INTEGER))); }); testMathyFunction(mathy0, [-1/0, -0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), 0x07fffffff, -(2**53+2), Math.PI, -0x07fffffff, 2**53-2, -0x080000001, 0x100000001, 2**53+2, 0, 0x100000000, 42, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, 1, 1.7976931348623157e308, -(2**53-2), 2**53, -0, Number.MAX_VALUE, -0x100000000, -0x100000001]); ");
/*fuzzSeed-66366547*/count=34; tryItOut("\"use strict\"; function shapeyConstructor(hpkpvh){\"use strict\"; hpkpvh[\"arguments\"] = Set.prototype.values;{ a1 = arguments.callee.arguments; } hpkpvh[\"setTime\"] = eval;for (var ytqflmkzw in hpkpvh) { }hpkpvh[\"setTime\"] = this;if (hpkpvh) hpkpvh[\"wrappedJSObject\"] = arguments.callee.caller.caller;hpkpvh[\"getPrototypeOf\"] = 1e-81;return hpkpvh; }/*tLoopC*/for (let e of /*PTHR*/(function() { for (var i of []) { yield i; } })()) { try{let rmaxim = new shapeyConstructor(e); print('EETT'); (true);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-66366547*/count=35; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2\", \"gm\"); var s = \"\"; print(uneval(s.match(r))); \nfor (var p in o1.i1) { try { t1[13] =  /x/g .__defineSetter__(\"x\", decodeURIComponent); } catch(e0) { } try { a1.sort((function(j) { if (j) { Array.prototype.forEach.call(a2, (function() { for (var j=0;j<38;++j) { f0(j%4==0); } }), h1, m0, s2); } else { try { v2 = Object.prototype.isPrototypeOf.call(e1, t2); } catch(e0) { } e1.has(a2); } })); } catch(e1) { } try { g2.offThreadCompileScript(\"function f2(a1)  { return this } \"); } catch(e2) { } g0.s1 += s1; }\n");
/*fuzzSeed-66366547*/count=36; tryItOut("\"use strict\"; if((x % 2 != 1)) print(x); else {for (var p in t0) { try { for (var v of f1) { try { o1.a2[false] = /\\3|\\B[^]|[\\W\\n]\\b{127,128}([^\\s\\t\\s])*?/gi; } catch(e0) { } o0 = new Object; } } catch(e0) { } h1 + o0; }/*RXUB*/var r = r1; var s = \"\"; print(r.test(s));  }");
/*fuzzSeed-66366547*/count=37; tryItOut("testMathyFunction(mathy4, [-(2**53), 0x0ffffffff, 0.000000000000001, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, -0x080000001, -Number.MIN_VALUE, 2**53, 0/0, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 2**53+2, 1/0, -(2**53-2), Number.MAX_VALUE, -0x080000000, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, -1/0, 1, 0x100000001, 42, 0x07fffffff, 1.7976931348623157e308, -(2**53+2), 0x080000001, -0x07fffffff, -0]); ");
/*fuzzSeed-66366547*/count=38; tryItOut("L: print(undefined);");
/*fuzzSeed-66366547*/count=39; tryItOut("\"use strict\"; /*vLoop*/for (let dvntaa = 0; dvntaa < 16; ++dvntaa) { let a = dvntaa; s1 += s0; } ");
/*fuzzSeed-66366547*/count=40; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.trunc((( ! ( + Math.pow(( + (((Math.fround(( ~ 0x100000001)) | 0) | ((Math.cbrt(y) >>> 0) | 0)) | 0)), ( + y)))) | 0)); }); testMathyFunction(mathy3, [1.7976931348623157e308, 0x100000000, -(2**53-2), 2**53, -0, Math.PI, Number.MIN_VALUE, 2**53+2, -1/0, 1/0, -Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 1, 42, -(2**53+2), 0x100000001, -0x080000000, 2**53-2, 0x080000000, 0, -0x100000000, -0x100000001, 0/0, 0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, 0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-66366547*/count=41; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.acos((Math.hypot((Math.min(mathy2(y, x), Math.hypot((y <= -0x07fffffff), x)) >>> 0), (((((Math.imul(( + Math.cosh((y >>> 0))), (-0x100000000 >>> 0)) >>> 0) >>> 0) !== ((Math.min(( + y), (((Math.fround(( - x)) ? x : x) >>> 0) | 0)) | 0) >>> 0)) >>> 0) | 0)) >>> 0)); }); ");
/*fuzzSeed-66366547*/count=42; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.ceil(((Math.atan2((Math.max((Math.atan2((0x080000000 | 0), y) | 0), (x >>> 0)) >>> 0), Math.pow((( ~ ( + (x > ( + Math.PI)))) >>> 0), y)) >>> 0) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[new Boolean(true), true, true, new Boolean(true), ({}), new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-66366547*/count=43; tryItOut("this.v1 = new Number(t1);");
/*fuzzSeed-66366547*/count=44; tryItOut("s1 = '';");
/*fuzzSeed-66366547*/count=45; tryItOut("v0 = r2.toString;");
/*fuzzSeed-66366547*/count=46; tryItOut("p0.valueOf = (function() { for (var j=0;j<71;++j) { f1(j%3==1); } });");
/*fuzzSeed-66366547*/count=47; tryItOut("mathy4 = (function(x, y) { return ( + Math.sqrt(Math.fround(Math.atan2(Math.fround((Math.cosh(((( - (( + Math.exp(((( + Math.hypot(x, ( + y))) + y) >>> 0))) >>> 0)) >>> 0) | 0)) | 0)), Math.fround((Math.max((mathy3((Math.log1p(Number.MAX_VALUE) >>> 0), Math.fround(Math.pow((y | 0), (( + Math.cosh(( + x))) | 0)))) >>> 0), ( - ( + Math.fround(Math.acos(Math.fround(0x100000001)))))) | 0)))))); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, 0x100000000, 42, -0x080000000, -(2**53), -0, -0x0ffffffff, -(2**53+2), 0, -0x100000001, 1, 0/0, -0x080000001, 2**53+2, 0x100000001, -0x100000000, 2**53-2, 2**53, -(2**53-2), -Number.MIN_VALUE, 0x0ffffffff, 0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, -1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-66366547*/count=48; tryItOut("\"use strict\"; (let) = linkedList((let), 1235);var x = ((makeFinalizeObserver('tenured')).yoyo(x));");
/*fuzzSeed-66366547*/count=49; tryItOut("delete o2.g2.p0[\"__proto__\"];");
/*fuzzSeed-66366547*/count=50; tryItOut("b0 = new SharedArrayBuffer(52);");
/*fuzzSeed-66366547*/count=51; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return ((((-0x40638*(0xfc260210)) & ((0xfbc1d633)-((~((!(i2))+((((-0x8000000))>>>((0xd7668556))) > (((0xfacb1ad1))>>>((0xf9e25acf)))))) > (~~(d0)))))))|0;\n  }\n  return f; })(this, {ff: eval(\" /x/g \").setDate}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x0ffffffff, 0x0ffffffff, 42, -(2**53), -(2**53-2), 0, Number.MAX_VALUE, -0x080000000, 1.7976931348623157e308, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53+2), -0, -1/0, -0x080000001, -0x07fffffff, 0x080000000, Math.PI, 0x07fffffff, 2**53+2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000001, 0/0, -Number.MIN_VALUE, 1, 0x100000000, 0x100000001]); ");
/*fuzzSeed-66366547*/count=52; tryItOut("x;");
/*fuzzSeed-66366547*/count=53; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( - Math.atan2(Math.fround(( + ( ! (0x100000000 >>> 0)))), (mathy0(Math.fround(Math.abs(-0x07fffffff)), y) >>> 0))); }); testMathyFunction(mathy3, [1.7976931348623157e308, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, -0x080000001, Math.PI, 0x07fffffff, Number.MAX_VALUE, 2**53, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, 42, -(2**53), 0x080000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, 1, -0x100000000, 0, -(2**53+2), -0x100000001, -Number.MAX_VALUE, -0, 2**53+2, 0x100000001, 0/0, Number.MIN_SAFE_INTEGER, -1/0, 0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=54; tryItOut("mathy1 = (function(x, y) { return Math.asinh((( + Math.sqrt(Math.sinh(y))) | 0)); }); testMathyFunction(mathy1, [-(2**53+2), -0x0ffffffff, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, 0.000000000000001, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, 1, -0x100000000, -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, 0/0, Math.PI, 1/0, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0x100000001, -0x080000000, 0x0ffffffff, -(2**53), 42, -0x07fffffff, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, -0, 2**53+2, -1/0]); ");
/*fuzzSeed-66366547*/count=55; tryItOut("\"use strict\"; var dqbmzx = new SharedArrayBuffer(2); var dqbmzx_0 = new Uint32Array(dqbmzx); var dqbmzx_1 = new Float64Array(dqbmzx); dqbmzx_1[0] = -21; var dqbmzx_2 = new Int32Array(dqbmzx); dqbmzx_2[0] = 27; var dqbmzx_3 = new Float32Array(dqbmzx); dqbmzx_3[0] = -17; var dqbmzx_4 = new Float64Array(dqbmzx); dqbmzx_4[0] = 19; (/*RXUE*//(?:(?=[^]+?|\u00cb+)){0,2}/g.exec(\"\\u00cb\\u00cb\\u00cb\"));;Array.prototype.reverse.apply(a0, [g0.v2]);/*MXX1*/o0 = g1.Promise.name;print(uneval(m1));v1 = Object.prototype.isPrototypeOf.call(v2, t0);");
/*fuzzSeed-66366547*/count=56; tryItOut("/*tLoop*/for (let x of /*MARR*/[new String('q'), function(){}, function(){}, function(){}, new String('q'), new String('q'), new String('q'), function(){}, new String('q'), function(){}, function(){}, new String('q'), function(){}, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), function(){}, new String('q'), new String('q'), new String('q'), new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), function(){}, new String('q'), new String('q'), function(){}, function(){}, new String('q'), function(){}, new String('q'), new String('q'), new String('q'), function(){}, function(){}, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), function(){}, new String('q'), function(){}, function(){}, function(){}, new String('q'), new String('q'), function(){}, new String('q'), function(){}, new String('q'), new String('q'), function(){}, function(){}, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new String('q'), function(){}, function(){}, new String('q'), function(){}, new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new String('q'), new String('q'), function(){}, function(){}, new String('q'), function(){}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), function(){}, new String('q'), new String('q'), new String('q'), function(){}, new String('q'), function(){}, new String('q'), new String('q'), new String('q')]) { e2.has(i2); }");
/*fuzzSeed-66366547*/count=57; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a0, (4277).watch(\"10\", Number), { configurable: (x % 3 == 2), enumerable: (x % 98 == 81), writable: (x % 52 != 26), value: (makeFinalizeObserver('tenured')) });");
/*fuzzSeed-66366547*/count=58; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=59; tryItOut("e0.__proto__ = b2;");
/*fuzzSeed-66366547*/count=60; tryItOut("\"use strict\"; ( /* Comment */(void options('strict_mode')) -= (Math.max(8, null)));");
/*fuzzSeed-66366547*/count=61; tryItOut("");
/*fuzzSeed-66366547*/count=62; tryItOut("\"use strict\"; this.o0 = new Object;");
/*fuzzSeed-66366547*/count=63; tryItOut("g2.v0 = new Number(4);");
/*fuzzSeed-66366547*/count=64; tryItOut("Object.defineProperty(this, \"v2\", { configurable: false, enumerable: (x % 66 == 60),  get: function() {  return g0.runOffThreadScript(); } });");
/*fuzzSeed-66366547*/count=65; tryItOut("Array.prototype.forEach.apply(a2, [(function(j) { if (j) { try { h1[\"localeCompare\"] = g0.s1; } catch(e0) { } try { h0.iterate = (function(j) { if (j) { try { this.m0.get(a2); } catch(e0) { } try { r2 = new RegExp(\"[^]\", \"im\"); } catch(e1) { } v1 = (o1.o1.f0 instanceof g0.g2); } else { try { f0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Int32ArrayView[1]) = (((-((Float32ArrayView[2]))) >= (+abs(((1099511627775.0))))));\n    d0 = (1.0);\n    (Float32ArrayView[(((0xbf576bc2) >= (0xb28c036a))) >> 2]) = ((1.0));\n    d0 = (-((d0)));\n    return (((((((((((0xffffffff))>>>((0x49f77440)))))|0) % (((0x24d399a)+(0xfd84deeb)+(0x4f0ed036)) | ((0xa95a86ef)-(0xfa1981f5)-(0xfa5d9baa))))>>>(-((d0) >= (d1)))))-(0x244d08cf)))|0;\n  }\n  return f; }); } catch(e0) { } try { ; } catch(e1) { } o2 = {}; } }); } catch(e1) { } o0.e2.delete(f2); } else { try { /*ODP-2*/Object.defineProperty(t0, \"normalize\", { configurable: x, enumerable: false, get: (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { var r0 = a7 + a7; var r1 = 3 - a4; var r2 = a0 ^ a7; print(a7); print(a5); var r3 = a6 ^ a5; r0 = a0 % a6; var r4 = a3 & x; var r5 = 0 * r4; var r6 = a4 - r4; a11 = a2 ^ a8; print(a10); a0 = 9 + a10; var r7 = a5 % a1; var r8 = r4 / a5; var r9 = a3 / r0; var r10 = a3 ^ 9; var r11 = r2 | a10; a2 = r8 + a8; var r12 = x * r10; var r13 = 7 - 9; var r14 = 8 ^ 4; var r15 = 8 + 1; r8 = a8 - 5; return a4; }), set: o0.o0.f1 }); } catch(e0) { } try { print(uneval(m1)); } catch(e1) { } try { b1.__iterator__ = (function() { for (var j=0;j<32;++j) { f1(j%3==0); } }); } catch(e2) { } Array.prototype.push.apply(a0, [p0, s0, o1.g2, o1]); } })]);");
/*fuzzSeed-66366547*/count=66; tryItOut("t2.__iterator__ = (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((+(1.0/0.0)));\n  }\n  return f; });");
/*fuzzSeed-66366547*/count=67; tryItOut("testMathyFunction(mathy3, [null, true, '\\0', '0', '/0/', '', 0, objectEmulatingUndefined(), ({toString:function(){return '0';}}), NaN, 1, ({valueOf:function(){return 0;}}), (new Boolean(false)), [0], (new String('')), /0/, (function(){return 0;}), -0, ({valueOf:function(){return '0';}}), (new Number(-0)), false, (new Boolean(true)), 0.1, undefined, (new Number(0)), []]); ");
/*fuzzSeed-66366547*/count=68; tryItOut("{ void 0; gcPreserveCode(); } g2.g1.o0.i0 = a2[15];");
/*fuzzSeed-66366547*/count=69; tryItOut("\"use strict\"; i0 = new Iterator(g0);");
/*fuzzSeed-66366547*/count=70; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=71; tryItOut("print(uneval(b0));");
/*fuzzSeed-66366547*/count=72; tryItOut("print(window >= x);");
/*fuzzSeed-66366547*/count=73; tryItOut("this.m0.get(f0);");
/*fuzzSeed-66366547*/count=74; tryItOut("print(/*FARR*/[.../*PTHR*/(function() { for (var i of (function() { yield let (b = /[^]/i) window; } })()) { yield i; } })(), new (function(y) { return /*FARR*/[ /x/g ].sort(decodeURI) })(x, /(?!\\2.|^(?!.)|[^]{8388607,})*/gm.throw(window))].sort);");
/*fuzzSeed-66366547*/count=75; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=\\\\3*)(?=(?:\\\\d\\\\3)${2}){1,}\", \"gyi\"); var s = x; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-66366547*/count=76; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=77; tryItOut("mathy4 = (function(x, y) { return (( - ((( + ( + Math.trunc(Math.fround((( + y) >>> 0))))) << ( + (( + Math.sin(( + Math.cos((0 >>> 0))))) , ((y ** (Math.tan((( + y) | 0)) | 0)) << Math.abs(y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [(function(){return 0;}), '0', 0.1, (new String('')), '', -0, (new Number(-0)), [0], 0, [], NaN, (new Boolean(true)), 1, '\\0', (new Boolean(false)), /0/, ({valueOf:function(){return 0;}}), '/0/', objectEmulatingUndefined(), (new Number(0)), true, ({toString:function(){return '0';}}), undefined, false, null, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-66366547*/count=78; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { return Math.fround(Math.ceil(Math.fround((Math.hypot((( + Math.log10((Math.tanh(((( ! y) >>> 0) >>> 0)) >>> 0))) | 0), (mathy3(Math.cos(Math.max((x | y), Math.fround(y))), (mathy3(((( - (Math.ceil(y) | 0)) | 0) >>> 0), (y >>> (-0x100000001 >>> 0))) >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy5, [0x080000000, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -0x100000001, 0x080000001, -(2**53), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, 2**53+2, -(2**53+2), -0, -0x080000000, -0x0ffffffff, -0x07fffffff, 0x100000001, 0/0, -0x080000001, -0x100000000, Math.PI, 1, 0x07fffffff, Number.MAX_VALUE, -(2**53-2), 0, 1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, 42]); ");
/*fuzzSeed-66366547*/count=79; tryItOut("s0 += 'x';");
/*fuzzSeed-66366547*/count=80; tryItOut("\"use strict\"; print(v2);");
/*fuzzSeed-66366547*/count=81; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(( + ( ~ ( + mathy1((Math.atanh((Math.sign(x) >>> 0)) | 0), (Math.exp((y >>> 0)) % -0x100000001)))))); }); testMathyFunction(mathy2, [-0, (new String('')), 0, ({valueOf:function(){return 0;}}), (new Number(0)), [], /0/, '/0/', undefined, NaN, (new Boolean(false)), (function(){return 0;}), 1, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), '\\0', null, [0], '', ({toString:function(){return '0';}}), true, 0.1, '0', false, (new Number(-0)), (new Boolean(true))]); ");
/*fuzzSeed-66366547*/count=82; tryItOut("\"use strict\"; yield;\nfor (var v of e2) { try { a1.reverse(); } catch(e0) { } try { for (var v of o1) { try { /*ADP-1*/Object.defineProperty(g1.a2, ({valueOf: function() { e2.toString = function(y) { /*RXUB*/var r = r2; var s = \"\"; print(s.split(r));  };return 1; }}), ({get: Number.prototype.toFixed, set: window, enumerable: false})); } catch(e0) { } try { Object.defineProperty(this, \"v0\", { configurable: (x % 4 != 0), enumerable: true,  get: function() {  return new Number(f0); } }); } catch(e1) { } this.m0.has(i1); } } catch(e1) { } try { v0 = r2.ignoreCase; } catch(e2) { } (void schedulegc(g2)); }\n");
/*fuzzSeed-66366547*/count=83; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-66366547*/count=84; tryItOut("((q => q)((uneval(x)) ^ (eval = (function  x (\u3056 = \"\\u5A4A\") { \"use strict\"; yield \"\u03a0\" } .prototype))));");
/*fuzzSeed-66366547*/count=85; tryItOut("mathy1 = (function(x, y) { return ( + (( - (Math.sinh(( + Math.atan2(Math.fround(Math.imul(( + Math.max(x, x)), ( + 1))), y))) >>> 0)) ? mathy0(Math.fround(Math.fround(( ! ( + Math.pow(( + y), ( + y)))))), Math.atan2(Math.min(((y || y) >>> 0), x), ( + Math.ceil(x)))) : ( + Math.imul(( + Math.fround(Math.atanh(( + x)))), ((( + mathy0(( + (Math.acosh((Number.MAX_VALUE >>> 0)) >>> 0)), x)) !== Math.fround(Math.cbrt(Math.fround(Math.fround((Math.fround(-0x07fffffff) >= Math.fround(y))))))) ? (x != y) : mathy0((( ~ Math.abs(Number.MAX_VALUE)) | 0), Math.fround(-0x080000000))))))); }); ");
/*fuzzSeed-66366547*/count=86; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - ( ! Math.atan2((0 & Math.fround(( - (Math.fround(Math.min((x >>> 0), Math.fround(( - x)))) >>> 0)))), Math.pow(( ! y), (( - x) >>> 0))))); }); testMathyFunction(mathy5, [0x07fffffff, -0x080000001, 2**53, Number.MAX_SAFE_INTEGER, -1/0, -(2**53), 0x100000000, -0x100000001, -0, -Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, 2**53+2, 2**53-2, 0x0ffffffff, 0x100000001, -0x100000000, Number.MAX_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1/0, -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000000, -0x080000000, 42, 0.000000000000001, 0, 1.7976931348623157e308, 1, -Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-66366547*/count=87; tryItOut("mathy4 = (function(x, y) { return ( + Math.round(Math.atan2(Math.imul((( + (x | 0)) | 0), x), (Math.sign((Math.min(y, y) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-66366547*/count=88; tryItOut("let (e) { e1.add(e2); }");
/*fuzzSeed-66366547*/count=89; tryItOut("{m1.delete(g2);i1 + i2; }");
/*fuzzSeed-66366547*/count=90; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.fround(Math.min(mathy2(((Math.log10(Math.fround(( + Math.sign(Number.MAX_VALUE)))) >>> 0) >> Math.cbrt(x)), (-0x080000001 | 0)), ( - ( - ( + y))))) ? Math.fround(((Math.pow((x !== (((x | 0) != (( + Math.cosh((( + x) | 0))) | 0)) | 0)), (0 ? ( + (( + Math.fround(Math.atan2(y, Math.acos(-0x100000000)))) & Math.fround(Math.max(x, (( + y) >>> 0))))) : ( + x))) ? Math.fround(Math.hypot(Math.fround(y), Math.fround(mathy1((Math.expm1((y >>> 0)) >>> 0), 42)))) : (Math.max((-0x0ffffffff >>> 0), (Math.fround(Math.sign(Math.fround(-(2**53-2)))) >>> 0)) >>> 0)) | 0)) : Math.fround((( - (mathy2(( + Math.round(x)), Math.fround(( + ( ! x)))) | 0)) | 0))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, 0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000000, 2**53-2, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, 1, -1/0, 0x0ffffffff, -(2**53+2), 2**53, -0x100000001, 0, 0x080000001, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, -(2**53-2), 0x100000001, 2**53+2, 42, -0x100000000]); ");
/*fuzzSeed-66366547*/count=91; tryItOut("g1.m2.has(g2.b2);");
/*fuzzSeed-66366547*/count=92; tryItOut("xqctkw(/\\b/gi);/*hhh*/function xqctkw(setter = x, x, x, a, window, \u3056, d, window, window, x, eval, x, window, window, b, y, x, x, x, z, eval, x, e, \u3056, x, eval = window, x, NaN, w, x, set, c, c = new RegExp(\"(\\\\S\\\\B+?)?\", \"g\"), x, x, c){a0 = a0.concat(t1, a1, t0, t0, a2, t1, a1, a0);}");
/*fuzzSeed-66366547*/count=93; tryItOut("/*RXUB*/var r = /(^){0,}^|(?![^])+?/yi; var s = \"\\n\\u00e6\\n\\n\\n\\n\\n\\n\\u00e6\\n\\n\\n\\n\\n\\n\\u00e6\\n\\n\\n\\n\\n\"; print(s.replace(r, function (...c)y =  for (w of 24) for each (x in  /x/ )\u0009)); ");
/*fuzzSeed-66366547*/count=94; tryItOut("\"use strict\"; \"use asm\"; o1.__proto__ = e2;");
/*fuzzSeed-66366547*/count=95; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.acos(Math.sinh(((Math.pow(-1/0, Math.fround(x)) >>> 0) >>> 0))); }); testMathyFunction(mathy3, [({toString:function(){return '0';}}), /0/, (function(){return 0;}), undefined, '0', (new Number(-0)), NaN, false, objectEmulatingUndefined(), 0.1, '/0/', ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), 0, true, [], (new Boolean(true)), (new Number(0)), '\\0', [0], -0, (new Boolean(false)), '', (new String('')), null, 1]); ");
/*fuzzSeed-66366547*/count=96; tryItOut("\"use strict\"; Array.prototype.pop.call(a2);");
/*fuzzSeed-66366547*/count=97; tryItOut("h1 + '';allocationMarker();");
/*fuzzSeed-66366547*/count=98; tryItOut("\"use strict\"; for (var p in f2) { try { s2 = s1.charAt(({valueOf: function() { this.s0 + g1;return 8; }})); } catch(e0) { } try { m2.delete(o2); } catch(e1) { } try { (void schedulegc(g1)); } catch(e2) { } Array.prototype.unshift.apply(a2, [x]); }");
/*fuzzSeed-66366547*/count=99; tryItOut("/*vLoop*/for (rgwhww = 0; rgwhww < 95; ++rgwhww) { let c = rgwhww; v2 = (i2 instanceof p1); } ");
/*fuzzSeed-66366547*/count=100; tryItOut("(yield  '' );");
/*fuzzSeed-66366547*/count=101; tryItOut("\"use strict\"; /*hhh*/function jpoehb(){this.f1.toString = (function() { try { selectforgc(o2); } catch(e0) { } try { neuter(o2.b0, \"same-data\"); } catch(e1) { } Array.prototype.shift.call(a0, v2, p0, e0, g0, e2, o2, this.s1); return this.t1; });}/*iii*/print(jpoehb);");
/*fuzzSeed-66366547*/count=102; tryItOut("\"use strict\"; i1.__proto__ = a1;");
/*fuzzSeed-66366547*/count=103; tryItOut("mathy2 = (function(x, y) { return ((Math.fround(Math.max(Math.fround(( + Math.min(Math.fround(Math.fround(( ! Math.fround(0.000000000000001)))), Math.fround((Math.atanh((x | 0)) | 0))))), Math.fround(Math.acos(( + Math.cbrt(( + (((mathy1(Math.fround(-(2**53-2)), (2**53-2 >>> 0)) >>> 0) >>> Math.fround(Math.min(( + x), x))) >>> 0)))))))) | 0) , (Math.fround(Math.log1p(( + ( ! (mathy1(((-0x100000001 || (-0 | 0)) || x), x) | 0))))) | 0)); }); testMathyFunction(mathy2, [Math.PI, 0x07fffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, 0/0, 42, -Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, Number.MAX_VALUE, -0, 1, 0x080000001, 0x100000001, 0x100000000, 2**53-2, -(2**53), -1/0, -(2**53+2), -(2**53-2), 2**53, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -0x100000001, -0x080000001, -0x080000000]); ");
/*fuzzSeed-66366547*/count=104; tryItOut("\"use strict\"; print(++(x));");
/*fuzzSeed-66366547*/count=105; tryItOut("/*RXUB*/var r = /[^]/yi; var s = \"\\uefb5\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=106; tryItOut("\"use strict\"; testMathyFunction(mathy5, [Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 1/0, 42, -Number.MAX_VALUE, 0x100000001, 0, Math.PI, -0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 0/0, 1.7976931348623157e308, 0x080000001, -0x080000000, -0x100000001, -0, -(2**53+2), -0x0ffffffff, 2**53, 0x100000000, 2**53-2, -(2**53), -0x080000001, 0.000000000000001, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=107; tryItOut("o0 = e1.__proto__;function z(window, x = this.__defineGetter__(\"x\", () =>  { \"use strict\"; i0.send(m0); } ), ...x)\"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Uint16ArrayView[((!(!((((0x74e38f51)) | ((-0x8000000))))))-(0xffffffff)) >> 1]) = ((0xf903988b));\n    return (((0x50bfd548)-(0xffffffff)+(0xfd778865)))|0;\n  }\n  return f;/*infloop*/for(b = /\\1|$++([^]\\u0003(?:.)\\S\\W{3,6}|\\D\\\u44bd|([^]|$){0,})/yi;  /x/g ;  /x/ ) {yield; }");
/*fuzzSeed-66366547*/count=108; tryItOut("b2 = t2[10];");
/*fuzzSeed-66366547*/count=109; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.tan(Math.hypot(Math.log1p(Math.fround(Math.hypot(y, Math.tanh(2**53+2)))), ( + mathy2(Math.pow(( + Math.fround(Math.imul(y, ((((x | 0) | Math.fround(0x100000000)) | 0) >>> 0)))), (y << (Math.min((y >>> 0), x) >>> 0))), Number.MIN_VALUE))))); }); testMathyFunction(mathy5, [-0x0ffffffff, -(2**53-2), -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, Math.PI, -0x07fffffff, -0x100000000, 0x100000000, -0x080000000, 1/0, 1, -1/0, 0, 0x07fffffff, -0, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, -(2**53), 0.000000000000001, 0x080000001, 2**53+2, 42]); ");
/*fuzzSeed-66366547*/count=110; tryItOut("/*oLoop*/for (var kjwcpi = 0; kjwcpi < 53; ++kjwcpi) { this.v2 = Object.prototype.isPrototypeOf.call(v0, m1); } ");
/*fuzzSeed-66366547*/count=111; tryItOut("mathy4 = (function(x, y) { return (Math.fround(Math.max(Math.fround(Math.min(Math.fround((Math.fround(y) ? Math.fround(y) : Math.fround(y))), ( + ( - -0)))), Math.fround((mathy3((-(2**53+2) | 0), (( - -0x0ffffffff) | 0)) | 0)))) ? (mathy2(( - ( + (( + ((0x07fffffff | 0) !== x)) || ( + mathy3(Math.fround(Math.abs(y)), ( - Math.PI)))))), Math.max((( + ( + (( + x) * (Math.min(((y ** -Number.MIN_VALUE) >>> 0), -1/0) >>> 0)))) | 0), (x | 0))) >>> 0) : Math.fround(( - ((Math.clz32(0x100000000) | 0) | 0)))); }); testMathyFunction(mathy4, [0, 1.7976931348623157e308, 2**53-2, -0x100000001, 2**53+2, -1/0, -0x100000000, 1, -(2**53+2), -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, -Number.MIN_VALUE, -(2**53), 0.000000000000001, -Number.MAX_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, 0x100000000, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, -0x0ffffffff, 42, -(2**53-2), -0x080000001, 0/0]); ");
/*fuzzSeed-66366547*/count=112; tryItOut("Object.prototype.unwatch.call(o2.t2, \"toString\");");
/*fuzzSeed-66366547*/count=113; tryItOut("testMathyFunction(mathy0, [0x100000000, 0, -0x07fffffff, -Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, 0x100000001, -(2**53+2), Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 0/0, -0x080000001, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -0, -0x100000000, -1/0, -0x080000000, Math.PI, 2**53+2, 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 1.7976931348623157e308, 1/0, 0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=114; tryItOut("a = linkedList(a, 637);");
/*fuzzSeed-66366547*/count=115; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.clz32(Math.fround(mathy1(Math.fround((((((2**53 ? (( - mathy2(-(2**53), Number.MAX_VALUE)) | 0) : ((((y >>> 0) ^ (y >>> 0)) | 0) | 0)) | 0) - Math.hypot(2**53, ( + y))) | 0) ? (((Math.fround(Math.hypot(x, x)) - Math.fround(mathy3(Math.fround(y), x))) | (Math.max(y, y) >>> 0)) | 0) : ((Math.log1p(x) == (Math.imul((y >>> 0), (((x >>> 0) | (y | 0)) >>> 0)) >>> 0)) | 0))), Math.fround(mathy2(Math.fround(( ! ( + x))), Math.fround(y)))))); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, -(2**53+2), -Number.MAX_VALUE, -0x080000001, 42, -(2**53-2), -1/0, -(2**53), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -0x080000000, 1.7976931348623157e308, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53, -0x100000001, 2**53-2, Number.MAX_VALUE, -0, 1/0, 0, 0.000000000000001, 0x07fffffff, 0x080000001, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-66366547*/count=116; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + mathy0(( + mathy2((( + ((( + ( + ( + ((y | 0) + 0x07fffffff)))) >>> 0) <= ( + x))) - mathy2((((Number.MAX_SAFE_INTEGER * ( + x)) | 0) <= ( + ( - ( + Math.log10(-0x080000000))))), Math.hypot(x, y))), ( - x))), ( + Math.fround((Math.fround(((Math.fround(( - Math.fround(y))) !== (((y | 0) <= x) | 0)) | Math.fround(((mathy1(Math.fround(Math.sinh(Math.fround(y))), y) >>> 0) >>> Math.fround((mathy0(y, ( + 1)) + -1/0)))))) ** Math.fround(mathy1((Math.min(Math.fround((Math.log((y >>> 0)) >>> 0)), ( + ( ~ Math.hypot(x, ( + 1))))) | 0), (mathy0(mathy0(y, mathy0(y, y)), (((-(2**53) | 0) ? (x | 0) : (y | 0)) | 0)) >>> 0)))))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -Number.MAX_VALUE, 0.000000000000001, 1.7976931348623157e308, 2**53+2, -0, 0/0, 0x080000000, -0x0ffffffff, -0x100000000, -(2**53-2), Math.PI, 1, 42, 0, 2**53-2, -0x080000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 1/0, -0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), 0x07fffffff, 2**53, -0x07fffffff, 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=117; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan2(( + ( - ( + ( + ( ! ((x >= ((Math.fround((mathy1(Math.max(Number.MAX_VALUE, y), ( + 2**53)) | 0)) !== (Math.max(y, y) | 0)) | 0)) | 0)))))), ( + ( + Math.pow(mathy3(( + (x === Math.min(0/0, (((2**53-2 | 0) <= (( + ((y | 0) << (x | 0))) | 0)) | 0)))), ( + (Math.fround(Math.fround(Math.fround(( ! Math.fround(Math.fround(mathy0(Math.fround(y), Math.fround(-0x07fffffff)))))))) | y))), Math.fround(Math.max(( + y), x)))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, -0x0ffffffff, -(2**53-2), 0, -Number.MIN_VALUE, 2**53-2, -0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0, 0/0, 1, -1/0, -(2**53), 2**53, 0.000000000000001, 0x07fffffff, -0x080000000, 0x0ffffffff, 1/0, -(2**53+2), 2**53+2, Math.PI, 42, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-66366547*/count=118; tryItOut("\"use strict\"; switch(-29) { default: m2.get(this.o1);case Math.imul(1, ((makeFinalizeObserver('tenured')))): break; case x: break;  }");
/*fuzzSeed-66366547*/count=119; tryItOut("let (hnbixc) { h1 + ''; }");
/*fuzzSeed-66366547*/count=120; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(i2, o2);");
/*fuzzSeed-66366547*/count=121; tryItOut("for (var v of p0) { try { f1.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (-33554433.0);\n    i1 = (0x8504130a);\n    (Int8ArrayView[0]) = ((i1)-((+((+(-1.0/0.0)))) != (((((-((intern((x & this)))))) % ((-8388608.0)))) - ((d0)))));\n    d0 = (-4.722366482869645e+21);\n    {\n      (Int8ArrayView[((imul((0x5d654f40), (i1))|0) % (abs((~~(d0)))|0)) >> 0]) = ((i1));\n    }\n    (Float32ArrayView[1]) = ((((d0)) - (((((-1.5111572745182865e+23) + (+(((0x529e7296) % (0x7fffffff))>>>((0xffffffff)*0x2133f))))) / ((274877906945.0))))));\n    d0 = (d0);\n    i1 = (0xffffffff);\n    i1 = ((~(((((0xfe3feb89)) | (0xef62f*(0x18c599f8))))-((0x79946eba)))));\n    (Int32ArrayView[2]) = ((i1)+(i1));\n    {\n      switch ((((0x905836d1)*0x56160) | ((i1)+((-0x8000000))))) {\n        case -1:\n          (Int8ArrayView[0]) = ((((((((0xffffffff)-(-0x8000000)+(0xc461d17f))>>>((0x464c7b47) / (0xeea819f))) != (0xfccd8cb5))) | ((0xa6d866b0)-(/*FFI*/ff()|0)+(!((x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: new Function, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: 10, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function shapeyConstructor(qeppnh){this[\"16\"] = 16;Object.seal(this);Object.seal(this);Object.defineProperty(this, this, ({value:  '' }));for (var ytqxhdggs in this) { }if (x) this[\"slice\"] = new Boolean(false);Object.preventExtensions(this);Object.defineProperty(this, \"toString\", ({configurable: (x % 13 != 4)}));this[\"slice\"] =  '\\0' ;delete this[\"slice\"];return this; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: function() { throw 3; }, }; })(29), () =>  { return new RegExp(\"(?=\\\\2)\", \"gyim\") } )))))) < (0x6723ebe)));\n          break;\n        case -2:\n          {\n            {\n              d0 = (+(0xa8342fa7));\n            }\n          }\n          break;\n        case -2:\n;          break;\n        case -1:\n          i1 = (((((((36028797018963970.0) <= (-36893488147419103000.0))-((0x0))-(i1))>>>((0xfa842a38)+(0xffffffff))))) ? (i1) : ((d0) != (((((1.0009765625)) % ((-2251799813685249.0))) + (-1125899906842623.0)) + (d0))));\n          break;\n      }\n    }\n    {\n      i1 = ((((i1))|0));\n    }\n    i1 = (0x85dded2e);\n    {\n      {\n        switch ((((0xffffffff)) & ((0xd7093fd2)-(0xfc38097f)-(0xf993124c)))) {\n          case -2:\n            d0 = (+(0x7f36f88a));\n            break;\n          case 0:\n            {\n              {\n                d0 = (131071.0);\n              }\n            }\n            break;\n        }\n      }\n    }\n    {\n      i1 = (0xfd9b6b67);\n    }\n    i1 = (((+(0.0/0.0)) > (35184372088833.0)) ? (((0xfa48e471)+((imul((i1), (i1))|0)))) : ((0x7c965658)));\n    {\n      return (((0x7a7d4e3c)-(0x55406055)+((4503599627370497.0) <= (+(0x959a3f1f)))))|0;\n    }\n    d0 = (+(((((((((0xf9976249))>>>((0x6dee9f87)+(0xa116ae5f)-(-0x8000000))) < (((0xf806d9ff)-(0xfb095c9a))>>>((0xe6d5c34e) / (0xffffffff)))))|0)))>>>((i1))));\n    {\n      i1 = (((0x3a3c3*(i1)) << ((0xe3644ac5)+(!((Float64ArrayView[2])))-(0xfec9b905))) >= (((((0xf3952a34) ? (0x34820bb2) : (-0x8000000)) ? ((((0x2ce420e0)) ^ ((0x9b7b2770)))) : (i1))-((((0x0) % (0x0)) ^ ((0x71162cd5) / (-0x591deb1))) > ((0x4afbf*((0x5c0e9cb1)))|0))) | ((0x475d0135)-(!((d0) == (d0))))));\n    }\n    return (((0x7f4f41f7)+(i1)-(0xf15476a2)))|0;\n    (Int16ArrayView[((0x50cec39d)) >> 1]) = ((i1)-(0x3e427037));\n    d0 = (+(0xc697a403));\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: Float32Array}, new ArrayBuffer(4096)); } catch(e0) { } try { a0.splice(-13,  /* Comment */x, intern(/*FARR*/[].map(RegExp.prototype.exec)), Math.exp(14)); } catch(e1) { } a1.length = x; }");
/*fuzzSeed-66366547*/count=122; tryItOut("yield ((getter) = new (encodeURI)(window != x,  \"\" ));");
/*fuzzSeed-66366547*/count=123; tryItOut("if((x % 3 == 1)) {m2.set(x, (this.__defineSetter__(\"x\", function (d)((makeFinalizeObserver('nursery')))))); } else  if (--d) {v0 = (b2 instanceof f1); } else {g2.offThreadCompileScript(\"Array.prototype.push.apply(o2.a2, [o2.v1, o1, h0]);\", ({ global: o0.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 49 == 2), noScriptRval: true, sourceIsLazy: (x % 2 != 1), catchTermination: true, element: g2.o1, elementAttributeName: s0, sourceMapURL: s2 }));e0.add(g2.g1); }");
/*fuzzSeed-66366547*/count=124; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.log2((Math.asin((Math.asinh(mathy0(Math.fround((Math.ceil(( ! y)) | 0)), Math.fround(( - Math.min((mathy1((x >>> 0), x) | 0), y))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[this, this,  '' , this,  '' , false,  '' , false, false, this, this, false, this,  '' , false, this,  '' , this, false,  '' ,  '' , false,  '' , false, this, this, this, false,  '' , false, false, this,  '' , this,  '' ,  '' , false, this, false, false,  '' ,  '' , this, false, this,  '' ,  '' , this,  '' ,  '' , false, false, false,  '' , this, false, false, false, false, false, false, false, false, false, false, false, this,  '' , false,  '' , false, false,  '' , false, false, this,  '' , false, this, false, false, this]); ");
/*fuzzSeed-66366547*/count=125; tryItOut("\"use strict\"; this.v0 = t1.length;");
/*fuzzSeed-66366547*/count=126; tryItOut("\"use strict\"; this.s2 = new String;");
/*fuzzSeed-66366547*/count=127; tryItOut("mathy0 = (function(x, y) { return ( ~ (Math.pow((Math.fround(Math.max(Math.fround(((( ~ Math.fround(x)) >>> 0) - Math.fround(Math.imul(Math.fround((((Number.MIN_VALUE | 0) << (y | 0)) | 0)), y)))), (( ~ (x | 0)) | 0))) | 0), ((( ~ (y | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), new String(''), new String(''), new String(''), new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''), x, objectEmulatingUndefined(), objectEmulatingUndefined(), new String('')]); ");
/*fuzzSeed-66366547*/count=128; tryItOut("mathy0 = (function(x, y) { return ( ~ (( + Math.max((Math.log10(y) | 0), ( + Math.atan2(Math.log(x), ((Math.fround(0x0ffffffff) !== (( - 1.7976931348623157e308) >>> 0)) >>> 0))))) >>> 0)); }); testMathyFunction(mathy0, [1/0, 2**53, -0x080000000, -0x07fffffff, 42, 2**53+2, 0x0ffffffff, Number.MIN_VALUE, -(2**53+2), 0, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53), -1/0, -0, -0x100000000, 0/0, -0x080000001, -0x100000001, -Number.MAX_VALUE, 0x100000000, 0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-66366547*/count=129; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.max((((( ~ Math.pow(Math.imul(((Math.imul((x | 0), (-0x100000001 | 0)) | 0) | 0), Math.imul(0x100000001, y)), Math.pow(x, ( + (x && y))))) >>> 0) >>> (Math.hypot(( ~ x), (Math.min(((Math.pow((y | 0), (y | 0)) | 0) | 0), x) | 0)) >>> 0)) >>> 0), (((Math.cosh(( ~ (( - y) - y))) | 0) <= mathy0((((x >>> 0) & (( - (-1/0 >>> 0)) >>> 0)) >>> 0), ( + Math.log10(x)))) != (Math.imul(x, mathy0(Math.fround((Math.fround(x) << Math.fround(x))), (((x >>> 0) < x) >>> 0))) >>> 0))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -1/0, 2**53, 0, -0x100000000, 42, 0x100000001, Number.MIN_VALUE, 2**53-2, -Number.MIN_VALUE, 0/0, 1.7976931348623157e308, Number.MAX_VALUE, 0x080000000, 2**53+2, 1, -(2**53), 0.000000000000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, Math.PI, -(2**53-2), -0x100000001, -0, -0x080000000]); ");
/*fuzzSeed-66366547*/count=130; tryItOut("(-22.valueOf(\"number\"));");
/*fuzzSeed-66366547*/count=131; tryItOut("mathy0 = (function(x, y) { return ( + Math.max(( + (Math.atan2(Math.abs(x), y) >>> Math.fround(Math.max(x, Math.fround((Math.atan2((( + (Math.fround(Math.abs((x | 0))) ? Math.asinh(0x100000000) : y)) >>> 0), (-Number.MIN_VALUE >>> 0)) >>> 0)))))), ( + ( - (((Math.pow(Math.acos(Math.fround(Math.imul(y, y))), ( - ( + Math.atan2(( + (Math.abs((x | 0)) | 0)), Math.max(0x100000000, y))))) | 0) === (Math.fround(Math.exp(Math.fround(x))) | 0)) | 0))))); }); testMathyFunction(mathy0, [({toString:function(){return '0';}}), [0], 0, (new Number(-0)), ({valueOf:function(){return '0';}}), 1, 0.1, /0/, null, '/0/', ({valueOf:function(){return 0;}}), (new Boolean(false)), [], undefined, objectEmulatingUndefined(), true, false, NaN, (function(){return 0;}), '0', '\\0', (new Boolean(true)), (new Number(0)), (new String('')), -0, '']); ");
/*fuzzSeed-66366547*/count=132; tryItOut("\"use asm\"; m0.get(a1);");
/*fuzzSeed-66366547*/count=133; tryItOut("\"use strict\"; {x = x % x; var r0 = x & 9; r0 = 2 | r0; var r1 = x * x; print(r1); x = x ^ x; var r2 = x + x; var r3 = 7 / x; var r4 = 1 & r3; var r5 = 4 - r3; var r6 = 6 | 3; var r7 = 2 / r2; r6 = r4 - r1; var r8 = 5 % r6; var r9 = r4 | 8; var r10 = 4 - r2; r0 = 4 % 9; var r11 = 5 * 1; var r12 = r11 * r2; var r13 = r9 - 8; var r14 = 4 & r3; var r15 = r9 + r13; var r16 = r12 % 7; print(r2); var r17 = r2 % 7; var r18 = 4 + r6; var r19 = 5 + 5; r11 = r18 / r17; var r20 = r8 * x; var r21 = r6 / 7; r0 = 6 - 4; var r22 = r10 | 6; var r23 = r20 / r22; var r24 = x & r19; var r25 = 9 & 0; print(r24); r7 = r13 % 6; var r26 = r21 - 6; r22 = 0 % 9; r2 = 4 + r6; var r27 = r6 * 7; print(r10); var r28 = r2 * 6; r8 = r5 - r5; var r29 = r10 % r5; var r30 = 4 * r22; var r31 = 6 + 1; var r32 = r0 * r16; var r33 = r23 + 0; print(r23); r19 = r17 % r18; var r34 = 0 ^ x; print(r8); var r35 = r32 / r27; r18 = 9 & 4; var r36 = 6 + r4; var r37 = r30 & r30; var r38 = 2 / 3; var r39 = r10 - r32; var r40 = r25 % 9; var r41 = 4 ^ r3; var r42 = r7 + r26; var r43 = 0 * r0; var r44 = r33 * r6; var r45 = r25 % r11; var r46 = r2 ^ 4; r1 = r41 / r6; var r47 = r43 % r46; var r48 = x + r18; var r49 = r9 % 4; r12 = r12 % r30; var r50 = r33 - 4; var r51 = r14 * 4; r48 = 8 - r19; var r52 = r46 * r50; var r53 = r6 % r33; r23 = r20 - 2; var r54 = r2 % r13; print(r22); var r55 = 6 | r40; var r56 = r1 * r23; var r57 = 4 & r19; var r58 = r6 - r3; var r59 = 2 / 8; var r60 = r16 / r30; var r61 = r46 & 5; var r62 = r41 * 5; r9 = r35 | 4; print(r5); print(r38); r58 = r58 & r38; var r63 = r41 ^ 2; var r64 = r21 / r17; r22 = r35 * r42; var r65 = 6 & 2; var r66 = r11 * r7; var r67 = 7 + r44; r64 = r11 % 5; var r68 = 4 / r38; var r69 = r23 | r11; var r70 = 0 + r56; r53 = r4 % r24; var r71 = r50 ^ 7; var r72 = r61 % r24; var r73 = r68 + r16; var r74 = r68 ^ r19; var r75 = 2 / 5; var r76 = r31 & r69; var r77 = r4 + 3; var r78 = r77 * r77; var r79 = r52 - 6; var r80 = r1 * r18; print(r24); var r81 = r56 / r12; var r82 = 5 ^ r19; r5 = r46 % r34; var r83 = 5 ^ r7; var r84 = r12 | 4; var r85 = 4 * r75; var r86 = r47 / r26; print(r15); var r87 = r35 & r34; r67 = r64 + r12; var r88 = 5 / r67; var r89 = r33 ^ 0; var r90 = r35 ^ r67; var r91 = r32 / 8; var r92 = r8 | 1; r50 = 8 % r48; var r93 = r16 / r17; var r94 = r72 & r18; r92 = r73 % 6; var r95 = r59 + r46; r53 = 9 / 8; var r96 = r11 / r53; var r97 = 6 % r12; var r98 = r37 & 5; r28 = r24 | 2; r52 = 4 ^ 4; var r99 = r19 / r56; var r100 = 2 - r34; var r101 = 6 % 7; r76 = 8 ^ r13; var r102 = 5 & 4; var r103 = r87 | 6; var r104 = r8 % 8; var r105 = r1 + 0; r77 = r77 / r23; r87 = 1 % 3; r95 = r98 | 4; var r106 = r47 + 6; var r107 = r23 & r1; var r108 = r47 ^ r13; var r109 = 2 - 5; print(r20); var r110 = 0 & 2; r3 = 6 / 7; var r111 = r77 % 3; r93 = r100 / 2; print(r46); r0 = r78 - r55; var r112 = r86 * r1; var r113 = r88 ^ r58; var r114 = r56 ^ r25; r33 = r13 * r48; r25 = r78 % r49; var r115 = r2 * r85; var r116 = r109 & r97; var r117 = r48 % r9; var r118 = r76 ^ r23; r48 = r108 & r62; var r119 = 1 ^ 6; r8 = 7 / 3; var r120 = 5 / r75; print(r54); var r121 = 1 - r84; r8 = r32 / r100; var r122 = 5 ^ 9; print(r63); r27 = r94 | 9; var r123 = r91 + r7; var r124 = r46 * 5; var r125 = r24 / r18; var r126 = r10 & r17; var r127 = r59 - 2; var r128 = 7 % 9; r121 = r58 ^ r45; var r129 = r102 % r42; r53 = 7 / 1; var r130 = r1 - r92; var r131 = r37 | r36; var r132 = 5 + r94; print(r46); var r133 = 7 + 3; var r134 = r128 / r23; print(r79); var r135 = 1 + r111; var r136 = r113 * r66; var r137 = 3 & r113; r54 = 0 % r114; var r138 = r137 & r31; var r139 = 9 % r49; var r140 = r121 / r116; var r141 = r118 * r44; var r142 = 8 ^ 3; var r143 = r97 % 6; var r144 = r82 - r126; var r145 = 9 % 1; print(r133); var r146 = r62 / r51; r34 = r123 + r132; r134 = r143 | 0; var r147 = r1 + r22; var r148 = 5 - r46; var r149 = r131 & r134; var r150 = r83 + 5; var r151 = 0 * r86; var r152 = r55 & r109; r23 = r78 | r103; r115 = 3 - r5; var r153 = r144 | r128; r127 = 8 | r47; r90 = 8 - r84; var r154 = r26 | r32; var r155 = r58 + r116; r52 = 4 / 3; var r156 = r18 | 8; var r157 = r12 * r132; var r158 = r108 % r43; var r159 = r1 * r65; var r160 = r21 | 0; var r161 = r150 % r122; var r162 = r117 % r10; var r163 = r16 % 6; print(r91); var r164 = r110 + r45; var r165 = r114 % r69; r25 = 5 | r49; var r166 = r81 + 8; r125 = 8 | 2; var r167 = r127 ^ r8; r13 = r16 + r159; var r168 = r48 | r125; var r169 = r48 * r131; var r170 = 9 + r142; var r171 = r143 / 9; var r172 = r68 * r61; var r173 = r108 + 1; var r174 = 6 + r56; var r175 = r49 % r50; var r176 = r145 % r52; var r177 = r121 & r94; r70 = 9 ^ 0; var r178 = r65 - r45; var r179 = r175 / 9; var r180 = r8 ^ 0; var r181 = r25 % r0; var r182 = 3 * r81; var r183 = r174 + 8; var r184 = r43 | r47; var r185 = r86 | 8; var r186 = r1 | r115; r80 = r107 - r176; var r187 = r64 % r167; var r188 = 6 ^ 6; var r189 = r178 | r138; r122 = r59 & r59; r104 = x ^ r108; var r190 = 2 | r112; r0 = 3 | r184; var r191 = r83 + 8; var r192 = r15 + r160; var r193 = r119 - r60; var r194 = r85 | r143; var r195 = 5 | r184; var r196 = r98 + r3; var r197 = r100 + 1; var r198 = r48 & 1; var r199 = r120 % r196; r151 = r72 % 0; var r200 = r102 / r141; var r201 = r144 & r45; r16 = 9 * r120; var r202 = r187 ^ r183;  }");
/*fuzzSeed-66366547*/count=134; tryItOut("s0 += s0;");
/*fuzzSeed-66366547*/count=135; tryItOut("a2 = /*PTHR*/(function() { for (var i of [x in x for each (y in allocationMarker()) for each (x in (4277)) for each (NaN in x) for (x in x) for (x[\"toUTCString\"] in Math.sinh(2)) for each (b in x)\u0009 for (Object.prototype.__lookupSetter__ in x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: ({/*TOODEEP*/}), set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: null, }; })(true), (function(x, y) { return Math.atan2(x, y); }), function (\ne)window)) for each (x in (4277)) for ({e: {}} of /*MARR*/[ '\\0' , 1,  '\\0' , 1,  '\\0' , [,,], [,,],  '\\0' , 1,  '\\0' ,  '\\0' , [,,], [,,],  '\\0' , 1, [,,], [,,],  '\\0' , [,,],  '\\0' , [,,], 1,  '\\0' , 1, 1, [,,], 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, [,,], [,,], [,,], [,,],  '\\0' , 1, [,,],  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , [,,], [,,], [,,], 1,  '\\0' ,  '\\0' , 1,  '\\0' ,  '\\0' , [,,], 1, [,,], [,,], [,,], [,,], 1, [,,], 1, 1, [,,],  '\\0' ,  '\\0' , 1, [,,], [,,], 1,  '\\0' , 1, [,,], 1, [,,],  '\\0' , 1, [,,], 1, 1, 1, 1,  '\\0' , 1, 1,  '\\0' ,  '\\0' ,  '\\0' , 1,  '\\0' , 1,  '\\0' , 1, 1, 1, 1, 1, 1, [,,], 1, [,,],  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , [,,], [,,], [,,],  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , [,,],  '\\0' ,  '\\0' ,  '\\0' , 1, 1,  '\\0' , [,,],  '\\0' ,  '\\0' , 1, [,,], 1])]) { yield i; } })();");
/*fuzzSeed-66366547*/count=136; tryItOut("/*infloop*/M: for  each(x in  /* Comment */((void shapeOf(((function factorial(tntyxx) { ; if (tntyxx == 0) { ; return 1; } ; return tntyxx * factorial(tntyxx - 1);  })(0)))))) {print(uneval(i0));print(s2); }");
/*fuzzSeed-66366547*/count=137; tryItOut("/*infloop*/M: for  each(var x in new (new ((function(x, y) { return 0x080000000; }))())((void shapeOf(/[^\uae40]/m)), (4277))) {L:with({a: \"\\u5D7F\"()(x++, )}){const v2 = g2.eval(\"e0.has(g1);\");g0.t0.set(o1.t1, 11); } }");
/*fuzzSeed-66366547*/count=138; tryItOut("mathy5 = (function(x, y) { return (Math.pow(((((y < y) | 0) , ((( - ((Math.min((((Math.pow(Math.PI, y) >>> 0) % (x | 0)) >>> 0), (x >>> 0)) >>> 0) | 0)) | 0) | 0)) | 0), Math.fround((Math.atan2(mathy4(( + mathy4((y >>> 0), (y >>> 0))), Math.atan2((x | 0), Math.PI)), Math.fround(Math.cosh((Math.log10(-Number.MIN_VALUE) | 0)))) | ( ~ mathy3(((0x100000000 === (((0 | 0) - (( + y) | 0)) | 0)) >>> 0), Math.cos(2**53-2)))))) | 0); }); testMathyFunction(mathy5, [0.000000000000001, -(2**53), 0x07fffffff, -(2**53-2), 2**53, 0x080000001, 2**53-2, 2**53+2, 0x0ffffffff, Math.PI, 0, -0, 1, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, 0x080000000, Number.MIN_SAFE_INTEGER, 1/0, -0x080000000, -(2**53+2), -0x100000001, 1.7976931348623157e308, Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, -0x0ffffffff, 0x100000001, 42, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=139; tryItOut("\"use strict\"; /*MXX2*/g2.DataView.length = g2;");
/*fuzzSeed-66366547*/count=140; tryItOut("/*MXX2*/o0.g1.Math.expm1 = b2;");
/*fuzzSeed-66366547*/count=141; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 295147905179352830000.0;\n    var i3 = 0;\n    i0 = (i3);\n    (Int16ArrayView[2]) = ((((((0x34981c66) > (0xffffffff))+(((0xcbad7*(-0x8000000)) | ((0xfcf08286)+(0xffffffff))) != (abs((((0x8ba6207c)) ^ ((0x6e467f19))))|0))-(/*FFI*/ff(((((/*FFI*/ff(((Infinity)), ((-1.2089258196146292e+24)), ((549755813889.0)), ((1.888946593147858e+22)))|0)) | ((0x3abab004) / (0x3b5ee733)))), ((1152921504606847000.0)), ((abs((0x221380e1))|0)), ((((0xf7a63c5c)) | ((0xfc27fd9b)))), ((1048576.0)), ((-8589934593.0)), ((7.555786372591432e+22)), ((8193.0)), ((8193.0)), ((9.671406556917033e+24)), ((288230376151711740.0)), ((-2199023255553.0)), ((-3.0)), ((36028797018963970.0)), ((8193.0)), ((-36028797018963970.0)), ((288230376151711740.0)))|0)) | (((((0xfc5a6535) ? (0xf82d52af) : (0xf96c4b94))) | ((!((0x7d2e0566) > (0x0)))*0xc64f2)) / (abs((((i0)*-0x890b7)|0))|0)))));\n    i3 = (i0);\n    switch ((~((i3)+(0xb1cbeb61)))) {\n    }\n    d2 = (((d2)));\n    return +((((-129.0)) * ((4097.0))));\n  }\n  return f; })(this, {ff: (new Function(\"print(x);\"))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MIN_VALUE, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, 0x100000000, 0x0ffffffff, -0, -0x080000001, 2**53+2, -0x080000000, -(2**53-2), -0x100000001, 0x100000001, 0.000000000000001, -(2**53+2), 0x080000000, 0x07fffffff, 0/0, -Number.MAX_VALUE, 0, -0x07fffffff, 1/0, 42, -0x100000000, -(2**53), 2**53, Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 1, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=142; tryItOut("\"use strict\"; let (x) { ((Array.prototype.sort).call((\u000cwindow = (Math.acosh(\"\\u3BF1\"))), /*MARR*/[\"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", \"\\u0043\", false, objectEmulatingUndefined(),  /x/ , x,  /x/ , false, \"\\u0043\", false, \"\\u0043\", false, false, \"\\u0043\", x, x, objectEmulatingUndefined(), false, x, \"\\u0043\", x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, false].filter(Array.prototype.find, []), x)); }");
/*fuzzSeed-66366547*/count=143; tryItOut("v2 = Array.prototype.reduce, reduceRight.call(a0, (function() { try { /*MXX3*/g1.g2.Number.MAX_SAFE_INTEGER = g2.Number.MAX_SAFE_INTEGER; } catch(e0) { } (void schedulegc(g2.g1)); return o2; }), g0);");
/*fuzzSeed-66366547*/count=144; tryItOut("let (a) { /*ODP-1*/Object.defineProperty(p2, \"__count__\", ({value: \"\\uC5D7\", writable: (eval = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: false, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: 0, get: function(receiver, name) { return x[name]; }, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(\"\\u05EB\"), function  y (x, b, y = undefined, this.a, \u3056, b = window, a =  /x/g , x, c, a, x, a = this, b, x = /./gyim, a, c, b = this, a, a, x = \"\\u3FDA\", b, NaN, NaN, w, NaN, a = [z1,,], a, a, NaN = function(id) { return id }, window, eval, window, b, x, a, a, y, e, a, eval, y = x, \u3056, b = [[]]) { \"use strict\"; yield new neuter() } )), configurable: false, enumerable: (x % 4 != 2)})); }");
/*fuzzSeed-66366547*/count=145; tryItOut("b0 + i2;");
/*fuzzSeed-66366547*/count=146; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=147; tryItOut("\"use strict\"; t0 = new Float64Array(this.b2, 26, );");
/*fuzzSeed-66366547*/count=148; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o0.e0, i1);");
/*fuzzSeed-66366547*/count=149; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.hypot((Math.fround(Math.min(((-(2**53) | 0) === -Number.MAX_VALUE), ( + ( ~ (Math.atan2(Math.cbrt(y), (x >>> 0)) >>> 0))))) >>> 0), ((( + (( + ( ! ( + Math.pow((( + Math.log10(( + -(2**53+2)))) | 0), x)))) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy5, [-0x080000000, -0x100000001, 0x080000000, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 0/0, 0, Number.MIN_VALUE, 0x07fffffff, -(2**53-2), 0x080000001, 0x100000001, -0x0ffffffff, 2**53, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), 1, 1/0, -Number.MIN_SAFE_INTEGER, -0, -Number.MIN_VALUE, Math.PI, 2**53+2, -0x080000001, Number.MAX_VALUE, -1/0, -0x100000000, -(2**53), Number.MAX_SAFE_INTEGER, 0x0ffffffff, 42, 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=150; tryItOut("/*MXX1*/g2.o2 = o2.g2.Math.imul;function x() { g2.m0 = new WeakMap; } ( /x/g );");
/*fuzzSeed-66366547*/count=151; tryItOut("v2 = (h1 instanceof m0);\n(function(x, y) { return y; })\n");
/*fuzzSeed-66366547*/count=152; tryItOut("mathy1 = (function(x, y) { return Math.cos(( + Math.hypot(Math.fround(Math.fround(( - Math.fround(x)))), (Math.min((-0x07fffffff >>> 0), x) ? x : y)))); }); testMathyFunction(mathy1, [0x080000001, -1/0, -0x080000000, 42, -0x100000001, 0, 0/0, 1/0, -(2**53+2), -0x0ffffffff, 0x07fffffff, -(2**53-2), -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0.000000000000001, Math.PI, 0x100000000, 1.7976931348623157e308, 0x100000001, -0x07fffffff, 0x080000000, 1, Number.MIN_VALUE, 2**53-2, 2**53, Number.MAX_VALUE, -0x080000001, 0x0ffffffff, -0]); ");
/*fuzzSeed-66366547*/count=153; tryItOut("mathy3 = (function(x, y) { return (Math.asin((( ! ((Math.sinh(((Math.fround(Math.PI) && 0.000000000000001) | 0)) | 0) | 0)) | 0)) != ((((x | 0) % 0) | 0) << Math.asin(((((((( + ((( + Math.PI) <= (y | 0)) >>> 0)) >>> 0) >> ( + y)) >>> 0) <= (((y | 0) ? (x >>> 0) : ( + Math.tan(-(2**53)))) | 0)) >>> 0) >>> 0)))); }); testMathyFunction(mathy3, [0/0, -(2**53), 1.7976931348623157e308, -0x0ffffffff, 0x07fffffff, 1/0, 1, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, 0x0ffffffff, 0x100000000, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53+2), 0, 2**53-2, -1/0, Number.MIN_VALUE, -0x100000000, -0x080000001, -0x080000000, 0x080000000, -Number.MAX_VALUE, -0, Math.PI, 42, 2**53, Number.MAX_VALUE, 0.000000000000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=154; tryItOut("\"use strict\"; e0 = new Set;");
/*fuzzSeed-66366547*/count=155; tryItOut("\"use strict\"; o2 = f0.__proto__;");
/*fuzzSeed-66366547*/count=156; tryItOut("\"use strict\"; \"use asm\"; a1.pop();");
/*fuzzSeed-66366547*/count=157; tryItOut("testMathyFunction(mathy4, /*MARR*/[function(){}, -0x100000001, function(){}, function(){}, -0x100000001, (1/0), -0x100000001, -0x100000001, (1/0), function(){}, function(){}, (1/0), (1/0), (1/0), (1/0), -0x100000001, -0x100000001, -0x100000001, (1/0), -0x100000001, (1/0), (1/0), -0x100000001, -0x100000001, function(){}, function(){}, function(){}, function(){}]); ");
/*fuzzSeed-66366547*/count=158; tryItOut("o0.a1 = Array.prototype.concat.call(g0.a2, a0, t1, a2);\ng1.offThreadCompileScript(\"undefined\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 20 == 3), sourceIsLazy: true, catchTermination: true }));\n");
/*fuzzSeed-66366547*/count=159; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (( ~ ( - ( ~ Number.MIN_VALUE))) ^ ( + (Math.imul(((( + (y >>> 0)) >>> 0) | 0), Math.hypot(((( ~ (y >>> 0)) >>> 0) >>> 0), -1/0)) | 0)))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0x080000001, -0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53), 0x080000000, 0x0ffffffff, -Number.MAX_VALUE, Number.MIN_VALUE, 42, -0x07fffffff, 2**53, Math.PI, -0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 0/0, -0x0ffffffff, -Number.MIN_VALUE, -1/0, -(2**53+2), 2**53+2, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, 1, -(2**53-2), 1/0, -0x080000000, 0x07fffffff, 0x100000000]); ");
/*fuzzSeed-66366547*/count=160; tryItOut("mathy5 = (function(x, y) { return Math.tanh(Math.round(Math.cos(Math.fround(Math.hypot(Math.fround(x), (y + ( + y))))))); }); ");
/*fuzzSeed-66366547*/count=161; tryItOut("\"use strict\"; /* no regression tests found */let b = x;");
/*fuzzSeed-66366547*/count=162; tryItOut("\"use strict\"; print(uneval(this.g1.b2));");
/*fuzzSeed-66366547*/count=163; tryItOut("print(x);\no2.o2.a1.sort((function() { try { b1 + ''; } catch(e0) { } try { g0.offThreadCompileScript(\"0.996;\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (function ([y]) { })(), sourceIsLazy: \"\\uD484\", catchTermination: true })); } catch(e1) { } e2 = Proxy.create(h0, g0.e2); return g2; }), f2);\n");
/*fuzzSeed-66366547*/count=164; tryItOut("mathy1 = (function(x, y) { return ((( + Math.min(( + ( - ( + (((( + -0) && (y | 0)) >>> 0) >>> ( ! y))))), (Math.atan2(((-1/0 ? x : x) | 0), (( - (42 < (mathy0(x, Math.PI) >>> x))) | 0)) | 0))) | 0) + Math.sqrt((Math.hypot((Math.fround(Math.acosh(x)) | 0), ((Math.log10(Number.MIN_SAFE_INTEGER) ? Math.clz32(Math.fround(x)) : (((-0x07fffffff | 0) & ( + ( + Math.min((x >>> 0), x)))) | 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [Math.PI, 0x080000001, -0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 0, -Number.MIN_VALUE, -1/0, Number.MIN_VALUE, 0x07fffffff, 1/0, -(2**53-2), 1.7976931348623157e308, 0x100000000, 0x080000000, -0x07fffffff, -(2**53+2), -0x100000001, 0x100000001, 2**53+2, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_VALUE, 42, -0, -0x080000000, -0x100000000, 2**53]); ");
/*fuzzSeed-66366547*/count=165; tryItOut("\"use strict\"; M:for(d in ((function (z) { return (\u0009window(Math.round(z)) =  /x/ ) } )(true))){var okdgpq = new SharedArrayBuffer(12); var okdgpq_0 = new Float64Array(okdgpq); okdgpq_0[0] = 20; /*tLoop*/for (let a of /*MARR*/[arguments.callee, new Number(1.5), new Number(1.5), new Number(1.5), {}, new Number(1.5), arguments.callee, new Number(1.5), 5.0000000000000000000000, {}, {}, new Number(1.5), 5.0000000000000000000000, new Number(1.5), 5.0000000000000000000000]) { e2 + ''; } }");
/*fuzzSeed-66366547*/count=166; tryItOut("this.g0.toSource = o0.o0.f1;");
/*fuzzSeed-66366547*/count=167; tryItOut("/*RXUB*/var r = /(?=(?!\\3(?=.{0}).?[^]{255,}|\\b))/gim; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-66366547*/count=168; tryItOut("(x);");
/*fuzzSeed-66366547*/count=169; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]\\\\2|(?=\\\\d.{1})[^](?=(?=^)|^[])|\\\\2|.(\\\\b)*|(?!\\\\s+\\\\D)|(?![^])++?\", \"gm\"); var s = \"\\n\"; print(r.exec(s)); ");
/*fuzzSeed-66366547*/count=170; tryItOut("mathy0 = (function(x, y) { return ( ~ Math.fround(Math.log(Math.expm1(Math.hypot(0x080000000, (x ** y)))))); }); testMathyFunction(mathy0, [0, 0.000000000000001, 2**53, -0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 0/0, -(2**53-2), 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, -0x080000001, -0x0ffffffff, 2**53+2, 0x100000001, -(2**53+2), 1/0, 0x100000000, 1.7976931348623157e308, 0x080000001, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -0, 42, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -(2**53), 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=171; tryItOut("testMathyFunction(mathy3, /*MARR*/[new String(''), arguments.caller, new String(''), arguments.caller, new Number(1.5), new Number(1.5), new String(''), -0x100000000, new String(''), arguments.caller, -0x100000000, -0x100000000, new String(''), -0x100000000, -0x100000000, arguments.caller]); ");
/*fuzzSeed-66366547*/count=172; tryItOut("e0 = new Set;");
/*fuzzSeed-66366547*/count=173; tryItOut("\"use strict\"; b = a;with({}) for(let e of /*MARR*/[(1/0), NaN, {}, function ([y]) { }(this), {}, NaN, (1/0), function ([y]) { }(this), (1/0), function ([y]) { }(this), {}, function ([y]) { }(this), {}, {}, (1/0), function ([y]) { }(this), NaN, NaN, {}, {}, function ([y]) { }(this), {}, function ([y]) { }(this), function ([y]) { }(this), function ([y]) { }(this), NaN, function ([y]) { }(this), function ([y]) { }(this), (1/0), {}, function ([y]) { }(this), function ([y]) { }(this), function ([y]) { }(this), (1/0), (1/0), (1/0), function ([y]) { }(this), {}, {}, (1/0), (1/0), {}, function ([y]) { }(this), NaN, function ([y]) { }(this), {}, (1/0), (1/0), function ([y]) { }(this), (1/0)]) for(let e of new Array(28)) with({}) { return; } ");
/*fuzzSeed-66366547*/count=174; tryItOut("v1 = this.g2.g1.runOffThreadScript();");
/*fuzzSeed-66366547*/count=175; tryItOut("\"use strict\"; var wazmmg = new SharedArrayBuffer(4); var wazmmg_0 = new Uint8ClampedArray(wazmmg); print(wazmmg_0[0]); wazmmg_0[0] = -12; var wazmmg_1 = new Float32Array(wazmmg); print(wazmmg_1[0]); wazmmg_1[0] = 13; var wazmmg_2 = new Int16Array(wazmmg); wazmmg_2[0] = -0.464; ;print(wazmmg);print(wazmmg_0[5]);(/([^][^]{536870911}|([\u008d-\u4b95\\d]\\B(?!\\b){4}))/im);/*ODP-1*/Object.defineProperty(f0, \"getDate\", ({enumerable: (wazmmg_2[1] % 8 == 0)}));wazmmg_0;s2 += s2;for (var p in i1) { try { v2 = new Number(this.e0); } catch(e0) { } Array.prototype.unshift.apply(a0, [g2.g2.e1, this.v2]); }print(wazmmg_2[0]);print(wazmmg);o2.__iterator__ = (function() { for (var j=0;j<14;++j) { f1(j%5==0); } });function set()\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Float64ArrayView[0]) = (((0xfef44045) ? (3.8685626227668134e+25) : (((\u3056 **= x) ? (i0) : (i1)) ? (+atan2((((-9.44473296573929e+21) + (3.094850098213451e+26))), ((-1152921504606847000.0)))) : (-((((+(-1.0/0.0))) - ((+abs(((255.0)))))))))));\n    return ((((((i0)*-0xd66ef) | ((i0)+(!(0xfa1483d4))+(((Float32ArrayView[((0x6ecca046)) >> 2])) <= (0x5b43064e)))))-(1)))|0;\n  }\n  return f;print(/./i);");
/*fuzzSeed-66366547*/count=176; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(v2, g2);");
/*fuzzSeed-66366547*/count=177; tryItOut("h2.enumerate = (function(j) { if (j) { Array.prototype.push.apply(g0.a1, [g2.o1.g2]); } else { try { selectforgc(o1); } catch(e0) { } try { g0.offThreadCompileScript(\"\\\"use strict\\\"; ;\\nlet t2 = new Uint32Array(t1);\\n\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (eval & x), noScriptRval: false, sourceIsLazy: false, catchTermination: true })); } catch(e1) { } try { delete m2[new String(\"5\")]; } catch(e2) { } t0 = new Int8Array(b1, 2, v1); } });");
/*fuzzSeed-66366547*/count=178; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( ! (Math.pow(Math.imul((( ~ y) | 0), ((( + ( + (y ? 0x0ffffffff : (Math.fround(mathy3(x, x)) * x)))) >>> 0) | 0)), Math.sign(((Math.asinh(Math.fround((Math.asinh(((-Number.MAX_SAFE_INTEGER << x) | 0)) | 0))) | 0) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy5, [(new Number(0)), undefined, (new Number(-0)), '0', NaN, ({toString:function(){return '0';}}), (new Boolean(false)), /0/, true, 0, [0], 1, -0, null, (new Boolean(true)), '', (new String('')), '/0/', objectEmulatingUndefined(), false, 0.1, (function(){return 0;}), '\\0', [], ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-66366547*/count=179; tryItOut("var r0 = 0 ^ 3; var r1 = r0 - r0; var r2 = r1 | 4; var r3 = r0 ^ x; var r4 = r0 ^ r0; var r5 = 1 & r2; var r6 = 3 / r2; var r7 = r2 & r3; var r8 = 2 & x; var r9 = 1 * 9; var r10 = r6 & r9; var r11 = r5 - r2; var r12 = r5 * r5; var r13 = r4 ^ r2; var r14 = r7 ^ r5; var r15 = r12 - x; var r16 = r10 % r10; var r17 = r5 - r15; var r18 = 0 * r17; var r19 = r0 | r5; var r20 = 8 * 9; var r21 = 0 ^ x; r12 = r7 & r12; var r22 = 4 % r16; var r23 = 0 & r3; var r24 = 1 % r16; var r25 = 5 | 2; var r26 = 0 - r11; var r27 = r7 % 3; r14 = r11 | r18; r2 = r24 * 0; print(r11); var r28 = r8 | r13; var r29 = 9 * r26; r6 = 3 & r12; var r30 = 0 + r2; r11 = 6 ^ r16; var r31 = r7 & r30; var r32 = r15 ^ 6; x = r14 - x; var r33 = 3 & r0; var r34 = r25 + r15; r6 = r8 / 3; var r35 = r5 % 5; var r36 = r17 - r4; var r37 = r13 * r31; var r38 = r6 ^ r36; var r39 = r38 | 6; r24 = r8 + x; var r40 = 3 & r1; r27 = r40 * r37; var r41 = r35 / r31; var r42 = 7 | 9; var r43 = 5 % r18; print(r6); var r44 = 2 / r3; r44 = r30 ^ 4; var r45 = r12 / r31; r40 = 9 ^ r29; var r46 = r38 & r13; var r47 = r28 * r28; var r48 = r6 / r40; r10 = r41 % r45; var r49 = r21 & r23; var r50 = r26 ^ 3; print(r7); var r51 = 4 | r15; var r52 = r34 % 0; var r53 = r39 & 0; var r54 = r18 / r19; var r55 = 4 / 2; var r56 = r20 - r40; var r57 = r42 & r12; var r58 = 2 | 5; var r59 = r28 ^ 3; ");
/*fuzzSeed-66366547*/count=180; tryItOut("print(uneval(s2));");
/*fuzzSeed-66366547*/count=181; tryItOut("\u000de = x;throw let (NaN) e;");
/*fuzzSeed-66366547*/count=182; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.log(( + Math.imul((Math.round((Math.hypot(( + y), y) | 0)) <= x), ( + Math.pow(( + 0x07fffffff), ( ! Math.abs(x)))))))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, -0x080000001, 1, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, -0x100000000, 42, Number.MIN_VALUE, 0x080000000, 0x100000001, 0x07fffffff, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 2**53-2, -0, -(2**53), Math.PI, Number.MAX_VALUE, 2**53, -0x0ffffffff, 2**53+2, -0x100000001, 0x080000001, 1.7976931348623157e308, -(2**53+2), -(2**53-2), Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=183; tryItOut("L:if( /x/g ) {m0.delete(a1); } else  if ([1]) print(x);");
/*fuzzSeed-66366547*/count=184; tryItOut("var odjhxt = new ArrayBuffer(16); var odjhxt_0 = new Uint16Array(odjhxt); print(odjhxt_0[0]); var odjhxt_1 = new Uint8Array(odjhxt); odjhxt_1[0] = -16; var odjhxt_2 = new Int8Array(odjhxt); odjhxt_2[0] = new decodeURI(/*FARR*/[ \"\" , ...[], /(?!\\3{512,}(?!\\w))/gi].filter( '' )); var odjhxt_3 = new Int32Array(odjhxt); odjhxt_3[0] = -10; var odjhxt_4 = new Int32Array(odjhxt); print(odjhxt_4[0]); t0.__iterator__ = (function(j) { if (j) { f1(o2.a1); } else { try { this.a2.unshift(g1.t2, h0); } catch(e0) { } try { v2.toSource = (function(j) { if (j) { try { print(b0); } catch(e0) { } try { v2 = new Number(NaN); } catch(e1) { } /*RXUB*/var r = r1; var s = \"\"; print(r.exec(s));  } else { try { Object.freeze(i1); } catch(e0) { } try { s2 += 'x'; } catch(e1) { } b1 = new ArrayBuffer(22); } }); } catch(e1) { } var v2 = true; } });");
/*fuzzSeed-66366547*/count=185; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.cbrt(( + Math.exp(( + mathy0(y, Math.atanh(( + (Math.sin((y >>> 0)) === ( + (( + (-0 | 0)) | 0)))))))))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, 2**53+2, 2**53-2, -(2**53+2), 42, -0, 0x100000001, -0x100000000, 1, 0x07fffffff, -0x07fffffff, 1/0, 0, 0x080000001, 0x100000000, -0x080000001, 0.000000000000001, -0x100000001, -(2**53), 2**53, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, Math.PI, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0, -Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53-2), 0x080000000]); ");
/*fuzzSeed-66366547*/count=186; tryItOut("p0.toString = (function() { for (var j=0;j<26;++j) { f0(j%5==0); } });");
/*fuzzSeed-66366547*/count=187; tryItOut("v2 = o0.g0.runOffThreadScript();");
/*fuzzSeed-66366547*/count=188; tryItOut("/*tLoop*/for (let d of /*MARR*/[ /x/g , arguments.callee, arguments.callee, arguments.callee, arguments.callee, w, arguments.callee, w, w, w,  /x/g ,  /x/g , w, w, arguments.callee, w, arguments.callee, w,  /x/g , w, arguments.callee,  /x/g , w, w, w,  /x/g , arguments.callee, arguments.callee, w, w, w,  /x/g , arguments.callee,  /x/g , w, w, w, arguments.callee, w, w, w, w, w,  /x/g , w,  /x/g , arguments.callee, w, w, w,  /x/g , w, w, w, arguments.callee,  /x/g , w,  /x/g , arguments.callee, w, arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , w,  /x/g , w, w,  /x/g , arguments.callee, w, arguments.callee,  /x/g , w, w, arguments.callee,  /x/g , w, w, w,  /x/g , arguments.callee,  /x/g , w,  /x/g , w, arguments.callee,  /x/g , w]) { s1 += 'x'; }const w = allocationMarker() > (4277);");
/*fuzzSeed-66366547*/count=189; tryItOut("testMathyFunction(mathy3, [-0x080000000, -0x07fffffff, -(2**53-2), 0x0ffffffff, 0/0, -0, 0x080000000, 1.7976931348623157e308, -0x100000001, Math.PI, 2**53+2, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, -1/0, Number.MAX_VALUE, 0x100000001, 2**53, Number.MIN_SAFE_INTEGER, -0x100000000, 1, -(2**53), Number.MAX_SAFE_INTEGER, 1/0, -0x0ffffffff, -0x080000001, 0x07fffffff, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, Number.MIN_VALUE, 0x100000000, 2**53-2, 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=190; tryItOut("/*oLoop*/for (icjmbj = 0, x =  /x/ , $* = (c = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: undefined, hasOwn: function() { throw 3; }, get: function() { return undefined }, set: function() { return true; }, iterate: function(y) { ({}); }, enumerate: function() { return []; }, keys: undefined, }; })( /x/g ), /*UUV1*/(\u3056.setUint32 = DataView.prototype.setUint32))); icjmbj < 58; ++icjmbj) { for (var v of m2) { try { v0 = Object.prototype.isPrototypeOf.call(this.h0, t1); } catch(e0) { } h1.getPropertyDescriptor = f0; } } ");
/*fuzzSeed-66366547*/count=191; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-66366547*/count=192; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ~ (( ! ( + x)) >>> 0)); }); testMathyFunction(mathy5, [Math.PI, -0x080000000, -0x0ffffffff, -0, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0, -0x07fffffff, 0, -Number.MIN_VALUE, 42, -(2**53), Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, 1.7976931348623157e308, 2**53, Number.MAX_SAFE_INTEGER, 0x080000001, 0.000000000000001, 1, -0x080000001, 0x0ffffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 0x100000000, 0/0, 0x100000001, 1/0, -(2**53+2), -(2**53-2), Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=193; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=194; tryItOut("mathy4 = (function(x, y) { return Math.atan2((((mathy2((Math.atanh((Math.min((Math.fround(y) | 0), (x | 0)) | 0)) << Math.fround(Math.sqrt(( + y)))), ( ! (x | 0))) && ( + (Math.sinh(((Math.cos(( + x)) | 0) | 0)) | 0))) >>> 0) | 0), (Math.fround(( ! Math.fround(( + Math.acosh(( + ( ~ (Math.fround(x) >>> Math.fround(y))))))))) | 0)); }); ");
/*fuzzSeed-66366547*/count=195; tryItOut("(true);");
/*fuzzSeed-66366547*/count=196; tryItOut("selectforgc(o1);h0.set = f1;");
/*fuzzSeed-66366547*/count=197; tryItOut("\"use strict\"; t2.set(a1, 17);");
/*fuzzSeed-66366547*/count=198; tryItOut("with({x: x}){Array.prototype.pop.apply(a1, []); }");
/*fuzzSeed-66366547*/count=199; tryItOut("\"use strict\"; if((x % 54 != 43)) /*oLoop*/for (var klthfu = 0; klthfu < 44; ++klthfu) { g2 + i2; }  else {; }");
/*fuzzSeed-66366547*/count=200; tryItOut("\"use strict\"; o0.h1.fix = (function(j) { if (j) { try { v1 = g2.eval(\"function o0.f2(m2) (arguments.callee.caller.arguments) = (4277)\"); } catch(e0) { } try { /*RXUB*/var r = r2; var s = s2; print(s.match(r));  } catch(e1) { } try { m1.toSource = (function mcc_() { var fulsdv = 0; return function() { ++fulsdv; if (/*ICCD*/fulsdv % 6 == 2) { dumpln('hit!'); try { a1 = new Array; } catch(e0) { } for (var p in v1) { try { a0[11] = s0; } catch(e0) { } r0 = /(^)*?\\2|[^?\u58c7-\u383c-\\u0012-\u5621\\D]{4,}|\\d/gim; } } else { dumpln('miss!'); try { a2.reverse(this.s1, f2); } catch(e0) { } try { this.v2 = g0.runOffThreadScript(); } catch(e1) { } e2.add(this.m0); } };})(); } catch(e2) { } s1 + ''; } else { try { t2 = t0[5]; } catch(e0) { } try { for (var p in m2) { v1 = (s0 instanceof b2); } } catch(e1) { } Array.prototype.sort.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -7.737125245533627e+25;\n    d2 = (Infinity);\n    return +((d2));\n  }\n  return f; })(this, {ff: (TypeError.prototype.toString).call}, new SharedArrayBuffer(4096)), p0, g0, s1, this.t1, p0]); } });");
/*fuzzSeed-66366547*/count=201; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ( + (( + ( + (( + ( + ( - ( + Math.cos(( + (( + Math.trunc(Math.fround(2**53+2))) ** ( + x)))))))) , ( + Math.pow(Math.pow(Math.imul((y | 0), (y | 0)), ((( ! (mathy2(( + x), Math.fround((Math.fround(1/0) >> y))) >>> 0)) >>> 0) >>> 0)), y))))) >>> ( + Math.sqrt(Math.trunc((Math.tanh((Math.imul((y >>> 0), ( + 1/0)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [-0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, 0, 0.000000000000001, -Number.MIN_VALUE, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000000, -0, Number.MAX_VALUE, 0x100000001, 42, Math.PI, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, 1.7976931348623157e308, -(2**53-2), 0/0, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, -(2**53), -0x07fffffff, -Number.MAX_VALUE, 0x080000000, -0x100000000, -0x080000001, -1/0, -(2**53+2)]); ");
/*fuzzSeed-66366547*/count=202; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.fround(( ~ (Math.fround(((y >>> 0) ? Math.pow((x + Math.acosh((x >>> 0))), ( + (((-0x080000000 ? y : x) >>> Math.tanh(x)) | x))) : ( + ( + (( + ( + ( ! (y | 0)))) && ( ~ (1 || y))))))) | 0))) && ( ~ ( + Math.atan2(0x100000001, y))))); }); testMathyFunction(mathy2, [0x100000001, 1, 1/0, 0/0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), -0x07fffffff, -1/0, 2**53+2, -0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 0x0ffffffff, -(2**53-2), -0x0ffffffff, 42, 2**53, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, 0, 0.000000000000001, 0x080000001, 1.7976931348623157e308, 0x080000000]); ");
/*fuzzSeed-66366547*/count=203; tryItOut("mathy0 = (function(x, y) { return Math.sign((Math.hypot((( ! ( + (Math.fround(( + (( + y) <= ( + x)))) ** ( + Math.fround(( + x)))))) | 0), (Math.acosh(Math.sin(x)) | 0)) | 0)); }); ");
/*fuzzSeed-66366547*/count=204; tryItOut("p1 + '';");
/*fuzzSeed-66366547*/count=205; tryItOut("a2 = Array.prototype.map.apply(a1, [(function() { try { this.t0.set(o0.a2, v1); } catch(e0) { } try { t2[(4277)] = p0; } catch(e1) { } for (var p in v2) { try { s2 += o0.s1; } catch(e0) { } /*MXX2*/this.g2.SyntaxError.prototype.message = g0; } throw g2; })]);");
/*fuzzSeed-66366547*/count=206; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-66366547*/count=207; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! (( + ((( + Math.fround(Math.min(Math.pow(y, (Math.max((0x0ffffffff | 0), x) | 0)), (( ! ((((x >>> 0) < ((x >= y) >>> 0)) >>> 0) >>> 0)) >>> 0)))) | 0) ^ ( + Math.cosh(( + ((Math.tanh((Math.min(y, x) >>> 0)) >>> 0) - (x | 0))))))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[(void 0), (0/0), (void 0), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), -Infinity, (void 0), (0/0), Math.min((2**53-2 ? x : x), x), (void 0), Math.min((2**53-2 ? x : x), x), Math.min((2**53-2 ? x : x), x), (0/0), (void 0), (0/0), (0/0), -Infinity, -Infinity, (0/0), (0/0), -Infinity, (void 0), (void 0), (void 0), (void 0), Math.min((2**53-2 ? x : x), x), (0/0), -Infinity]); ");
/*fuzzSeed-66366547*/count=208; tryItOut("s2 += 'x';");
/*fuzzSeed-66366547*/count=209; tryItOut("\"use strict\"; var x = eval(\"/* no regression tests found */\");;");
/*fuzzSeed-66366547*/count=210; tryItOut("\"use strict\"; \n/*ODP-1*/Object.defineProperty(m2, \"trimLeft\", ({}));\n");
/*fuzzSeed-66366547*/count=211; tryItOut("\"use strict\"; Array.prototype.push.apply(o2.a0, [g2.i1, f1, a0, h2, this.g1, o1.g1]);");
/*fuzzSeed-66366547*/count=212; tryItOut("testMathyFunction(mathy0, [-0x100000000, -0x07fffffff, -(2**53+2), 1.7976931348623157e308, 2**53+2, -1/0, -Number.MAX_SAFE_INTEGER, 0x080000000, 1, 0x0ffffffff, 42, 1/0, 0x07fffffff, 2**53-2, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53, -0x0ffffffff, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, 0x080000001, -0x100000001, 0x100000001, 0.000000000000001, -(2**53-2), Number.MIN_VALUE, Number.MAX_VALUE, -0, 0, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=213; tryItOut("i2 = t1[x];");
/*fuzzSeed-66366547*/count=214; tryItOut("t1 + '';");
/*fuzzSeed-66366547*/count=215; tryItOut("e2.has(f0);");
/*fuzzSeed-66366547*/count=216; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=217; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x0ffffffff, 0x100000001, 0/0, 0x080000000, 0x080000001, -0x080000000, 1, -0x100000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, -(2**53+2), -(2**53-2), 0, Number.MIN_SAFE_INTEGER, 2**53+2, -0, 0.000000000000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, 0x100000000, -1/0, -0x100000000, Number.MIN_VALUE, 2**53, -(2**53), 0x07fffffff, Math.PI, 0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-66366547*/count=218; tryItOut("s1 + '';");
/*fuzzSeed-66366547*/count=219; tryItOut("testMathyFunction(mathy3, [0/0, 0x080000001, -0x07fffffff, 0x100000000, -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, 0, -0x100000001, Math.PI, -0x080000000, 2**53+2, -0x100000000, 0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53), Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, -Number.MAX_VALUE, 2**53, -(2**53-2), -0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, -0, 1, -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=220; tryItOut("v0 = g0.t0.length;");
/*fuzzSeed-66366547*/count=221; tryItOut("\"use strict\"; v0 = Array.prototype.every.call(a1, (function() { try { s2 = a0[2]; } catch(e0) { } try { m1.get(x); } catch(e1) { } try { for (var p in h1) { f0.toString = (function() { v1 = a0.length; return h2; }); } } catch(e2) { } i2 = e2.iterator; return this.o1.g0; }));");
/*fuzzSeed-66366547*/count=222; tryItOut("testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 0x100000001, 0x080000001, -0x100000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, -1/0, 0/0, -0x07fffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -Number.MIN_VALUE, -0x100000001, -(2**53), 2**53, -(2**53-2), -Number.MIN_SAFE_INTEGER, 42, 1, 1.7976931348623157e308, 0x100000000, -(2**53+2), -0x080000000, 1/0, 0, 0.000000000000001, 0x080000000, -Number.MAX_VALUE, -0, 2**53+2]); ");
/*fuzzSeed-66366547*/count=223; tryItOut("/*tLoop*/for (let d of /*MARR*/[[1], Number.MAX_SAFE_INTEGER, (4277), function(){}, function(){}, function(){}, (4277), [1], Number.MAX_SAFE_INTEGER, function(){}, (4277), Number.MAX_SAFE_INTEGER]) { v1 = Object.prototype.isPrototypeOf.call(this.g1.p0, p1); }");
/*fuzzSeed-66366547*/count=224; tryItOut("\"use strict\"; \"use asm\"; t0 = new Uint8Array(({valueOf: function() { if((encodeURIComponent) ? \u000d(new String('q')) : (/(?!\\b)|\\2{2,1026}|[](?!.)*/gm.__defineSetter__(\"w\", ({})))) {g1.m0.delete(m2); } else  if (eval(\"mathy5 = (function(x, y) { return Math.fround(Math.cosh(Math.fround(( + Math.min(( + mathy2(0x100000001, y)), ( + (((x >>> 0) ? (Math.atanh(x) >>> 0) : (( + (( + 0x07fffffff) ? 2**53-2 : (0x07fffffff | 0))) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy5, /*MARR*/[false, null, null, false, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, false, 1e4, 1e4, function(){}, null, false, function(){}, false, null, 1e4, function(){}, false, function(){}, null, false, function(){}, function(){}, null, null, function(){}, function(){}, function(){}, null, function(){}, false, 1e4, null, null, null, null, null, null, null, null, function(){}, false, 1e4, 1e4, null, null, function(){}, 1e4, false, false, null, function(){}, function(){}, 1e4, 1e4, function(){}, false, 1e4, function(){}]); \")) print((w >>= x)); else this;v0 = (f1 instanceof f0);return 19; }}));");
/*fuzzSeed-66366547*/count=225; tryItOut("function g1.f1(f0) /*FARR*/[ /x/ ].filterprint((p={}, (p.z = x)()));");
/*fuzzSeed-66366547*/count=226; tryItOut("o1.s2 += 'x';");
/*fuzzSeed-66366547*/count=227; tryItOut("\"use strict\"; x = x;");
/*fuzzSeed-66366547*/count=228; tryItOut("var kpqvic, uudals, qoeshx, x, x;/* no regression tests found */");
/*fuzzSeed-66366547*/count=229; tryItOut("{ void 0; try { gcparam('markStackLimit', 4294967295); } catch(e) { } } this.r1 = new RegExp(\"(?=(?:.{2,536870915}\\\\D))+?(?!((\\\\1)){0,})\", \"gm\");");
/*fuzzSeed-66366547*/count=230; tryItOut("print((new RegExp(\"(?!(?:[^])*?[^]{1,2}{2})\", \"gym\"))());");
/*fuzzSeed-66366547*/count=231; tryItOut("m0.set(o1, p2);");
/*fuzzSeed-66366547*/count=232; tryItOut("print(/((?=[^]+)|[^]\\1{3}*?)/g);");
/*fuzzSeed-66366547*/count=233; tryItOut("mathy3 = (function(x, y) { return Math.atan2(Math.atanh((Math.trunc(( + ( ! (Math.hypot(y, y) | 0)))) | 0)), (Math.fround((Math.fround(( ~ x)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [2**53+2, 1.7976931348623157e308, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000000, 1, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, 2**53-2, -0, -0x100000001, 0, -Number.MIN_VALUE, 0x100000000, 42, -1/0, 0.000000000000001, 0x080000001, -0x0ffffffff, -(2**53), Math.PI, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, -(2**53-2), 2**53, 0x0ffffffff, 1/0, -0x080000000, -(2**53+2)]); ");
/*fuzzSeed-66366547*/count=234; tryItOut("delete h0.keys;");
/*fuzzSeed-66366547*/count=235; tryItOut("print(uneval(h0));");
/*fuzzSeed-66366547*/count=236; tryItOut("\"use strict\"; print(x);\n[,,z1];\n");
/*fuzzSeed-66366547*/count=237; tryItOut("e0 + '';");
/*fuzzSeed-66366547*/count=238; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; bailAfter(955); } void 0; }");
/*fuzzSeed-66366547*/count=239; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\".\", \"gi\"); var s = delete d.w; print(uneval(r.exec(s))); ");
/*fuzzSeed-66366547*/count=240; tryItOut("/*infloop*/for(var d = new RegExp(\"\\\\2*\", \"i\"); (1.__defineGetter__(\"\\u3056\", Function)); \"\\u8C54\".unwatch(\"arguments\") ? 20++ : x) akrlur(x, (this.__defineSetter__(\"d\",  /x/g ) %= Math.max(27, 2918624507)));/*hhh*/function akrlur(c = d){(void schedulegc(g1));}");
/*fuzzSeed-66366547*/count=241; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (((mathy0(Math.atan2(( - Math.sign(y)), (Math.log1p((y | 0)) | 0)), ((Math.fround(( + (Math.cosh((x | 0)) >>> 0))) ** (Math.cos((Math.fround(Math.log((Math.pow(y, Math.min(x, y)) | 0))) >>> 0)) >>> 0)) >>> 0)) >>> 0) != (Math.atan2(Math.fround(((( ~ (Math.sign((x >>> 0)) >>> 0)) | 0) >> Math.ceil(( + (( + x) % ( + x)))))), (( - ( ! ( + (((y | 0) == (y | 0)) | 0)))) - x)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x100000001, -(2**53), 0x0ffffffff, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, 42, 0.000000000000001, 0x100000000, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, -0x07fffffff, 0x07fffffff, 0x080000001, -0, -0x080000001, Math.PI, -0x100000001, 1.7976931348623157e308, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, -(2**53-2), 0x080000000, 2**53, 1/0, 0, -0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-66366547*/count=242; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround((Math.fround(Math.atan(Math.fround(mathy4((( ! ((( - (y | 0)) | 0) | 0)) | 0), Math.fround(Math.atan2(x, x)))))) >>> (Math.imul((( + 0) | 0), (Math.log(y) | 0)) | 0))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, 0x100000001, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -0x0ffffffff, 0x080000000, 42, Math.PI, 0x0ffffffff, 2**53+2, -(2**53), -0x100000000, -0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 0, 2**53, -(2**53+2), -0x080000001, -0, -(2**53-2), 0.000000000000001, -1/0]); ");
/*fuzzSeed-66366547*/count=243; tryItOut("\"use strict\"; g2.t0 = g0.objectEmulatingUndefined();");
/*fuzzSeed-66366547*/count=244; tryItOut("var hdtqed = new ArrayBuffer(8); var hdtqed_0 = new Int16Array(hdtqed); print(hdtqed_0[0]); hdtqed_0[0] = 25; var hdtqed_1 = new Uint32Array(hdtqed); hdtqed_1[0] = -13; var hdtqed_2 = new Uint16Array(hdtqed); hdtqed_2[0] = -9007199254740992; m0.delete(this.f1);");
/*fuzzSeed-66366547*/count=245; tryItOut("/*bLoop*/for (let rfittf = 0, cmlhuk, (new (x)(x, x)); rfittf < 26; ++rfittf) { if (rfittf % 3 == 0) { false;m1.has(g1.s0); } else { /*ODP-2*/Object.defineProperty(a0, \"callee\", { configurable: true, enumerable: true, get: (function() { for (var j=0;j<45;++j) { g0.f0(j%5==1); } }), set: this.f2 }); }  } ");
/*fuzzSeed-66366547*/count=246; tryItOut("\"use strict\"; g2.m2.toSource = (function() { for (var j=0;j<26;++j) { f1(j%4==1); } });");
/*fuzzSeed-66366547*/count=247; tryItOut("\"use strict\"; v1 = (e0 instanceof h0);v2 = evalcx(\"h0 + m1;\", g0);");
/*fuzzSeed-66366547*/count=248; tryItOut("/*oLoop*/for (let uqtruv = 0, hhoobz; uqtruv < 45 && ((eval(\"mathy5 = (function(x, y) { \\\"use strict\\\"; return (mathy3((( - ( - Math.fround(( + Math.fround((( + mathy2(( '' );, ((x ? x : (x | 0)) | 0))) >>> 0)))))) >>> 0), ((Math.fround(Math.acosh(Math.fround(Math.sin(x)))) || (Math.fround(( ! (-1/0 >> Math.imul(0, ( + y))))) | 0)) >>> 0)) >>> 0); }); \"))); ++uqtruv) { eval(\"print(x);\", delete c.a); } ");
/*fuzzSeed-66366547*/count=249; tryItOut("\"use strict\"; v0 = evaluate(\"Array.prototype.push.call(a0, b0, o2, e2, t0, v2, this.t1);\", ({ global: o2.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x -= (allocationMarker())), noScriptRval: false, sourceIsLazy: (x % 2 != 0), catchTermination: false }));");
/*fuzzSeed-66366547*/count=250; tryItOut("\"use strict\"; throw StopIteration;");
/*fuzzSeed-66366547*/count=251; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (Math.fround(Math.pow(Math.fround((((x | 0) >>> Math.hypot(y, 0.000000000000001)) | 0)), Math.fround(Math.fround(( ! Math.fround(y)))))) || Math.fround(Math.hypot(y, ( + (( + Math.fround(Math.asinh(Math.sign(Math.round(0x080000001))))) ? ( + x) : (y | 0))))))); }); testMathyFunction(mathy0, [({toString:function(){return '0';}}), [], (new Boolean(false)), '/0/', true, objectEmulatingUndefined(), /0/, false, '', (new String('')), undefined, 0.1, (function(){return 0;}), (new Number(0)), 0, (new Number(-0)), '0', '\\0', ({valueOf:function(){return 0;}}), (new Boolean(true)), 1, ({valueOf:function(){return '0';}}), [0], NaN, -0, null]); ");
/*fuzzSeed-66366547*/count=252; tryItOut("mathy1 = (function(x, y) { return (Math.atan2(Math.imul(((Math.atan2((Math.hypot((x | 0), ((x > x) | 0)) >>> 0), ((x & Math.pow(y, Math.fround((Math.fround((x * ( + 0.000000000000001))) / Math.fround(y))))) >>> 0)) >>> 0) >>> 0), (((y << ( + Math.max(0x100000000, x))) + Math.asin(mathy0(Math.fround(y), Math.fround((( ! Math.fround(x)) >>> y))))) >>> 0)), (((Math.hypot(Math.fround(mathy0(Math.fround(( ! y)), Math.fround(mathy0(Number.MIN_SAFE_INTEGER, y)))), ( + x)) | 0) === (Math.log1p(x) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy1, [-(2**53-2), 0x080000001, Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, 2**53, 2**53+2, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -(2**53+2), 0x100000000, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, 42, 0.000000000000001, 0x0ffffffff, Number.MIN_VALUE, Math.PI, -0x07fffffff, -(2**53), 2**53-2, -0x100000001, -Number.MAX_VALUE, -0x100000000, 0/0, -0, 0x080000000, 0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000]); ");
/*fuzzSeed-66366547*/count=253; tryItOut("m1.has(s2);");
/*fuzzSeed-66366547*/count=254; tryItOut("a0.splice(-5, 4, p2, e1);m1.set(b0, this.o2);");
/*fuzzSeed-66366547*/count=255; tryItOut("\"use asm\"; testMathyFunction(mathy5, [-(2**53), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53+2), 0x100000001, 0/0, 0.000000000000001, -(2**53-2), 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0, Number.MAX_VALUE, 0x080000001, 0x080000000, 2**53-2, Math.PI, -0x07fffffff, 0x07fffffff, -0x0ffffffff, -0x100000001, -0x100000000, -0, 1/0, -1/0, 0x100000000, 42, Number.MAX_SAFE_INTEGER, -0x080000000, 1, 2**53+2, Number.MIN_VALUE, 2**53, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-66366547*/count=256; tryItOut("\"use asm\"; mathy4 = (function(x, y) { return (Math.cbrt(((( ~ (Math.fround(Math.fround(Math.pow(Math.fround(x), Math.fround((( ! y) >>> 0))))) & ( ! y))) ? Math.hypot(Math.fround(Math.cbrt((( ! 2**53+2) | 0))), ( + (( + x) + Math.hypot(x, Math.abs(y))))) : ((( + ((mathy2((x >>> 0), -Number.MIN_SAFE_INTEGER) >>> 0) >>> 0)) | 0) != Math.hypot(x, mathy3(y, -0x07fffffff)))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[true, true, [1], [1], .2, x, .2, true, .2, .2, x, x, .2, [1], [1], [1], [1], .2, x, [1], .2, true, [1], [1], true, [1], [1], x, x, x, .2, [1]]); ");
/*fuzzSeed-66366547*/count=257; tryItOut("i0.next();");
/*fuzzSeed-66366547*/count=258; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-66366547*/count=259; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy4, [-0, 0x080000001, -1/0, 0x080000000, 2**53+2, -0x07fffffff, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, 2**53, Math.PI, -0x080000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 0x0ffffffff, -0x100000001, 1.7976931348623157e308, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, 1, Number.MIN_VALUE, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), -(2**53+2), -(2**53)]); ");
/*fuzzSeed-66366547*/count=260; tryItOut("let (a) { print(a); }");
/*fuzzSeed-66366547*/count=261; tryItOut("s2 = this.s0.charAt(13);");
/*fuzzSeed-66366547*/count=262; tryItOut("m1.set(m2, t2);");
/*fuzzSeed-66366547*/count=263; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, objectEmulatingUndefined(), x, (void 0), objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]) { yield [,,z1]; }");
/*fuzzSeed-66366547*/count=264; tryItOut("/*oLoop*/for (let qaihch = 0; qaihch < 63; ++qaihch, /*UUV1*/(x.reverse = offThreadCompileScript)) { f2(g1.i1); } ");
/*fuzzSeed-66366547*/count=265; tryItOut("/*bLoop*/for (var mexqep = 0; mexqep < 1; ++mexqep) { if (mexqep % 73 == 5) { o0.g1.offThreadCompileScript(\"g0 + '';\"); } else { let (dzowzj, c = this) { v0 = t0.byteOffset; } }  } ");
/*fuzzSeed-66366547*/count=266; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( ! (mathy4(Math.round(y), (((( ~ y) ^ ( + ( ~ x))) >>> 0) - (((Math.min((x | 0), (x | 0)) | 0) >>> 0) | ((( + -0x080000001) ? (y | 0) : (( ~ (x != y)) | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy5, ['', -0, NaN, 0.1, '0', undefined, objectEmulatingUndefined(), true, false, '\\0', (new Number(0)), null, [0], (function(){return 0;}), ({valueOf:function(){return '0';}}), [], /0/, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new String('')), (new Boolean(true)), 0, 1, (new Number(-0)), (new Boolean(false)), '/0/']); ");
/*fuzzSeed-66366547*/count=267; tryItOut("var t0 = new Int16Array(7);");
/*fuzzSeed-66366547*/count=268; tryItOut("var r0 = 2 & x; var r1 = 9 ^ 0; var r2 = r1 - r1; var r3 = r2 % r1; var r4 = r3 % x; print(r4); var r5 = r4 ^ r4; r0 = r1 - 0; var r6 = 0 * r5; r6 = 3 - 8; var r7 = r2 + r1; var r8 = r6 / r4; var r9 = 4 - r4; r7 = r1 - r1; var r10 = r6 + 9; var r11 = r5 / r2; var r12 = r2 / 5; var r13 = x ^ r8; var r14 = r11 & 6; var r15 = 9 % r11; var r16 = r3 / r1; r7 = 5 * r2; print(r11); var r17 = 1 ^ r16; var r18 = r11 % 4; var r19 = r2 * 8; var r20 = r16 + 2; print(r17); var r21 = r13 - 2; var r22 = 8 % r9; var r23 = r13 & r16; var r24 = 3 | r23; var r25 = 5 | r12; var r26 = r12 * r20; var r27 = r4 * r20; var r28 = 5 + r0; var r29 = r6 % r21; var r30 = 3 * 8; r25 = r16 - r11; r17 = r10 | r27; var r31 = r17 ^ r26; var r32 = r9 | r21; var r33 = r23 / 1; var r34 = 3 % r29; var r35 = r29 & 1; var r36 = 2 ^ r16; var r37 = 2 ^ r16; var r38 = 4 - 9; var r39 = r3 + r37; var r40 = r30 * r21; var r41 = r13 / r3; var r42 = r10 - r17; r14 = r19 - 6; print(r26); r22 = r40 + r28; var r43 = x / r11; r10 = r39 * 0; var r44 = r20 & 7; var r45 = r39 / 6; var r46 = r25 ^ r31; var r47 = 1 | r36; var r48 = r21 / x; var r49 = 7 | r4; var r50 = r40 & 8; var r51 = 4 % 8; var r52 = r31 ^ r46; r21 = r40 / r38; var r53 = 2 | 5; var r54 = 1 % r48; r1 = 0 & r53; var r55 = r8 + 2; var r56 = r33 & r17; var r57 = r13 & r9; r14 = r17 - r53; r36 = r28 & 4; r18 = 1 + r53; var r58 = 3 % 8; r18 = 7 ^ 9; r2 = r31 ^ r37; var r59 = 7 - 6; r17 = r38 % r22; var r60 = r27 * 1; print(x); print(r41); r4 = r50 | r31; var r61 = r57 % r50; r47 = 1 - r39; var r62 = r48 - 8; var r63 = r20 & r58; var r64 = 9 & r36; var r65 = 4 + r58; var r66 = r50 * r54; r31 = r50 - r65; var r67 = r15 - 2; var r68 = r63 | r31; var r69 = r43 - r45; var r70 = r8 * r35; var r71 = r40 ^ r52; var r72 = r45 * 3; var r73 = r53 - r15; var r74 = r57 % 4; var r75 = 8 - r3; ");
/*fuzzSeed-66366547*/count=269; tryItOut("/*tLoop*/for (let y of /*MARR*/[ /x/ , new String(''),  /x/ , new String('')]) { m1 = new WeakMap; }");
/*fuzzSeed-66366547*/count=270; tryItOut("m2.delete(o0.g0);");
/*fuzzSeed-66366547*/count=271; tryItOut("a1[ /* Comment */\"\\u8F1C\"] = o2.v1;\njwutkg(/*UUV1*/(eval.entries = (function ([y]) { })()));/*hhh*/function jwutkg(c){throw \"\\u8C7D\";}\n");
/*fuzzSeed-66366547*/count=272; tryItOut("p2.toString = (function(j) { if (j) { try { a2 = a1.slice(12, -3, o0.g1); } catch(e0) { } try { m1.delete(g1); } catch(e1) { } this.o0.valueOf = (function() { try { f1 = Proxy.createFunction(h1, f2, f2); } catch(e0) { } b2 + ''; return i2; }); } else { try { selectforgc(o2); } catch(e0) { } a2.push(i0, o1.v2, s2, b0, t2, m0, g1, h2, this.f1); } });");
/*fuzzSeed-66366547*/count=273; tryItOut("h1.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-66366547*/count=274; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.min((Math.fround(((Math.atan2((((Math.atan2((x >>> 0), x) | 0) <= (y | 0)) | 0), Math.sign(Math.atanh(y))) | 0) , (Math.fround((Math.cos(1.7976931348623157e308) <= x)) | 0))) ** ((( + Math.fround(( + ( ~ y)))) ** (y >>> 0)) >>> 0)), ( + (((( - Math.fround(Math.tanh(Math.atan2(1/0, x)))) >>> 0) === (x >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, 1/0, 0x080000000, -0x100000000, Number.MIN_VALUE, -0x0ffffffff, 2**53, 0/0, -0x080000000, -0x100000001, -(2**53-2), Math.PI, -Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, 0, 2**53+2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x0ffffffff, -0, 2**53-2, -Number.MAX_VALUE, -(2**53+2), Number.MAX_VALUE, -0x080000001, 0x100000000, -1/0, 1]); ");
/*fuzzSeed-66366547*/count=275; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( ~ ( + ((((Math.min((y >>> 0), (Math.fround(( - y)) >>> 0)) >>> 0) | 0) / (Math.pow(y, y) | 0)) | 0))); }); testMathyFunction(mathy0, [-0x100000001, -Number.MAX_SAFE_INTEGER, 1, 0/0, -0x080000000, -1/0, 1.7976931348623157e308, 2**53-2, -0x100000000, -Number.MAX_VALUE, 0x080000000, -(2**53), 0x080000001, 2**53, -0, Number.MIN_VALUE, -(2**53-2), 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, 0.000000000000001, 1/0, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -0x0ffffffff, 42, -(2**53+2), -0x080000001, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=276; tryItOut("mathy2 = (function(x, y) { return ((( - ( - (mathy0(-0, Math.atan2(x, x)) >>> 0))) >> ( + Math.expm1(( + Math.max((Math.fround((Math.asin(( + y)) >>> 0)) >>> 0), ((( - ( + Math.hypot(y, (( - y) >>> 0)))) | 0) | 0)))))) >>> 0); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, 0x100000001, -Number.MIN_VALUE, -1/0, -0, 0/0, Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 2**53, 1.7976931348623157e308, -(2**53+2), 0.000000000000001, -0x07fffffff, 2**53+2, 0x080000001, -0x0ffffffff, -(2**53-2), -0x080000000, 0, -(2**53), -0x080000001, 0x100000000, 42, -0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x07fffffff, 1]); ");
/*fuzzSeed-66366547*/count=277; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.imul((( + Math.imul(Math.atan(x), ( + Math.exp((( - -0x080000001) | 0))))) ^ mathy1(( - x), Math.max(x, Math.fround(( ! Math.fround(x)))))), (Math.log2((Math.asin((x >>> 0)) ? (((( - (Math.fround(( ~ Math.fround(0x100000001))) | 0)) | 0) && Math.max((( + mathy0(Math.fround(2**53+2), Math.fround((Math.fround(y) ? Math.fround(x) : Math.fround(y))))) >>> 0), y)) >>> 0) : (( + Math.cosh(( + (x ? x : Math.fround(-0x0ffffffff))))) , (y >>> 0)))) | 0)); }); testMathyFunction(mathy2, /*MARR*/[function(){}, new String('q'), function(){}, new String('q'), function(){}, function(){}, new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(true), function(){}, function(){}, function(){}, function(){}, new String('q'), function(){}, (0/0), (0/0), (0/0), new String('q'), new String('q'), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new Boolean(true), new String('q'), (0/0), new Boolean(true), (0/0), new String('q'), new Boolean(true), function(){}, (0/0), (0/0), function(){}, new String('q'), function(){}, (0/0), new Boolean(true), (0/0), new String('q')]); ");
/*fuzzSeed-66366547*/count=278; tryItOut("\"use strict\"; \"use strict\"; a0.toString = (function mcc_() { var vvljcb = 0; return function() { ++vvljcb; f0(true);};})();");
/*fuzzSeed-66366547*/count=279; tryItOut("a1.toString = f2;");
/*fuzzSeed-66366547*/count=280; tryItOut("/*infloop*/while(x)var vuvzwx = new ArrayBuffer(8); var vuvzwx_0 = new Uint8ClampedArray(vuvzwx); vuvzwx_0[0] = -13; var vuvzwx_1 = new Uint8Array(vuvzwx); var vuvzwx_2 = new Float64Array(vuvzwx); print(vuvzwx_2[0]); vuvzwx_2[0] = -8; var r0 = vuvzwx_0 - 8; var r1 = vuvzwx / r0; print(r1); var r2 = r0 | 9; var r3 = vuvzwx % 7; var r4 = vuvzwx_1[7] | 9; var r5 = r4 % r3; var r6 = r3 ^ 4; var r7 = 4 / r6; var r8 = 9 * vuvzwx_0; var r9 = 1 % vuvzwx_0; vuvzwx_0[0] = r0 - 3; r1 = vuvzwx_2[8] & 1; var r10 = vuvzwx_1[7] | 3; var r11 = 4 % vuvzwx_1[0]; var r12 = r0 & r7; var r13 = r8 - 7; var r14 = r0 * 9; var r15 = 9 ^ x; var r16 = 9 / vuvzwx; var r17 = 8 + 8; var r18 = r5 % r0; var r19 = r16 & 2; var r20 = r11 / vuvzwx_1[0]; var r21 = 9 | 2; vuvzwx_2 = r2 / vuvzwx_2[0]; var r22 = 5 / r18; var r23 = r1 ^ r19; var r24 = vuvzwx_0[0] & 2; var r25 = r14 ^ vuvzwx_0[0]; var r26 = 3 * vuvzwx_2; var r27 = r12 ^ r1; r4 = r2 * 8; ;Object.defineProperty(this, \"v0\", { configurable: (vuvzwx_0 % 14 == 3), enumerable: false,  get: function() {  return a2.length; } });e2.add(f2);");
/*fuzzSeed-66366547*/count=281; tryItOut("mathy2 = (function(x, y) { return ((((Math.clz32(((Math.hypot((x | 0), (Math.fround(((x >>> 0) ? (y >>> 0) : (-(2**53+2) >>> 0))) | 0)) | 0) >>> 0)) >>> 0) >>> 0) , (mathy0(Math.pow(0, -1/0), x) - ( - Math.PI))) ** Math.imul((((mathy1((y | 0), Math.cbrt(x)) | 0) - Math.pow((x >>> 0), x)) | 0), ((Math.fround(Math.atan2(( + x), y)) ? Math.fround(( + mathy0(Math.fround(-Number.MAX_VALUE), (x | 0)))) : Math.fround(( + ( + ( ! x))))) ** (x >>> 0)))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), 0, ({valueOf:function(){return 0;}}), (new Boolean(false)), (new Number(-0)), /0/, 0.1, '/0/', ({valueOf:function(){return '0';}}), (new Number(0)), (new Boolean(true)), '0', (function(){return 0;}), (new String('')), '', NaN, [0], -0, ({toString:function(){return '0';}}), null, [], false, '\\0', true, 1, undefined]); ");
/*fuzzSeed-66366547*/count=282; tryItOut("{ void 0; abortgc(); }");
/*fuzzSeed-66366547*/count=283; tryItOut("function shapeyConstructor(feiyez){for (var ytqqdnbec in this) { }this[\"__defineGetter__\"] = (function(x, y) { \"use strict\"; return ( + ( + Math.imul(( ~ (( + Math.sinh(( + x))) >>> 0)), Math.sin(Math.hypot(x, 0))))); });this[\"__defineGetter__\"] =  '' ;if (x\n) this[\"__defineGetter__\"] = \"\\u8DEE\";delete this[\"toString\"];this[\"toString\"] = function(y) { yield y; this.o2.a1 = ([a = Proxy.create(({/*TOODEEP*/})(\"\\u05E5\"), this)] for (d of (function() { yield  /x/ ; } })()) if ( '' ));; yield y; };this[(({-19: -4,  set -3(x =  '' , x) { yield this }  }) ? new TypeError() : eval(\"mathy0 = (function(x, y) { return ( + (((Math.sin(( ! Math.fround(( - Math.fround(Math.fround((Math.fround(x) >> Math.fround(y)))))))) >>> 0) !== Math.sign((Math.fround(Math.atan2(Math.fround(y), Math.fround(Math.exp(y)))) ^ Math.expm1(x)))) && (Math.sign((Math.log10((((y | 0) >> (-1/0 | 0)) | 0)) | 0)) | 0))); }); testMathyFunction(mathy0, [0, 0x100000000, Math.PI, -0x100000001, -1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, -0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, -(2**53+2), 0x07fffffff, 2**53, 1/0, -(2**53), -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000000, 1, 0.000000000000001, -0x100000000, 2**53-2, -0x0ffffffff, 42, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, 1.7976931348623157e308, -0x080000001, 2**53+2, 0/0, -Number.MAX_VALUE, Number.MAX_VALUE]); \"))] = (yield [z1]);{ print(function(y) { yield y; continue ;; yield y; }.prototype); } for (var ytqqaogev in this) { }{ /* no regression tests found */ } return this; }/*tLoopC*/for (let d of /*FARR*/[x, b = c , eval, .../*FARR*/[...(/*RXUE*//(?!\\D)/im.exec(\"0\").watch(\"y\", Date.prototype.setUTCSeconds) for each (a in (this for each (d in -0)))), delete c.y, (\"\\uE187\".includes(({a: x}), -1)), x, ]]) { try{let usgmds = new shapeyConstructor(d); print('EETT'); a0.sort(f2);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-66366547*/count=284; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( - ( ~ ( + mathy4(( + Math.hypot(Math.fround((Math.trunc(Math.fround(-(2**53))) >>> 0)), (y | 0))), ( + Math.fround(( ! (( ! y) | 0)))))))) >>> 0); }); ");
/*fuzzSeed-66366547*/count=285; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + (( + (mathy1((Math.max(y, Math.cosh(y)) | 0), (Math.fround((Math.imul(Math.fround(x), Math.fround(y)) & -Number.MAX_SAFE_INTEGER)) | 0)) | 0)) && ( + ( + ( ~ ( ! -Number.MIN_SAFE_INTEGER)))))); }); testMathyFunction(mathy5, /*MARR*/[-Number.MIN_SAFE_INTEGER, eval, (4277), -Infinity, {x:3}, -Number.MIN_SAFE_INTEGER, {x:3}, eval, {x:3}, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, eval, eval, (4277), -Infinity, (4277), -Number.MIN_SAFE_INTEGER, {x:3}, (4277), {x:3}, -Infinity, eval, (4277), (4277), {x:3}, -Infinity, -Number.MIN_SAFE_INTEGER, -Infinity, eval, -Number.MIN_SAFE_INTEGER, (4277), {x:3}]); ");
/*fuzzSeed-66366547*/count=286; tryItOut("g0.o1.m2.get(e2);");
/*fuzzSeed-66366547*/count=287; tryItOut("mathy5 = (function(x, y) { return ( + (Math.fround(((Math.hypot(((Math.asin((1.7976931348623157e308 >>> 0)) | 0) | 0), ((Math.log((y ? (x % y) : x)) | 0) | 0)) | 0) > Math.fround((( + Math.log1p(((1/0 << ((( ! (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0) >>> 0)) >>> 0))) + ( + ( + Math.pow(( + ( + ( ~ ( + (( + 42) | ( + y)))))), ( + (Math.log2((x | 0)) | 0))))))))) != (( - ((Math.atanh(x) >>> 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [-0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, 42, -0x080000001, 0x100000000, -(2**53+2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -1/0, -0x07fffffff, Math.PI, 2**53+2, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53, -0x080000000, 1, 0, 0/0, 2**53-2, -Number.MIN_VALUE, Number.MAX_VALUE, 1/0, -Number.MAX_VALUE, 0.000000000000001, -0, -0x100000000, 1.7976931348623157e308, -(2**53-2), 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=288; tryItOut("\"use strict\"; { void 0; void schedulegc(282); }");
/*fuzzSeed-66366547*/count=289; tryItOut("testMathyFunction(mathy4, [-(2**53), -(2**53-2), 0, -0x100000001, -0x07fffffff, -0x080000001, 1, -0, Number.MAX_SAFE_INTEGER, -1/0, -0x100000000, 1/0, 0x080000001, -Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, 2**53, 0x080000000, -Number.MAX_VALUE, 0x100000001, 0x07fffffff, 0.000000000000001, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53+2, 42, 0x0ffffffff, -(2**53+2), 0/0, Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, 0x100000000, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=290; tryItOut("x.lineNumber;");
/*fuzzSeed-66366547*/count=291; tryItOut("this.a2.splice(NaN, 1);\nvar r0 = 1 % 8; var r1 = 6 - 6; var r2 = r1 & r1; var r3 = r2 + r0; var r4 = r0 & r1; r0 = r3 % 4; var r5 = x / x; var r6 = r1 ^ r2; var r7 = r6 + r5; var r8 = r4 / 3; r7 = 8 | r4; var r9 = 9 + 5; var r10 = r7 | r6; var r11 = x + 4; var r12 = r2 ^ r3; var r13 = 0 - r11; var r14 = r10 & r11; var r15 = 5 & r13; var r16 = 9 % 7; var r17 = 9 + 9; print(r14); r2 = 1 / r2; var r18 = r17 & 5; var r19 = 8 * r9; var r20 = r15 + r12; var r21 = r3 * x; var r22 = r0 / r6; print(r11); var r23 = r4 % 9; var r24 = 4 - r2; var r25 = r17 * r18; var r26 = 2 / r6; r3 = r14 + r9; var r27 = r17 + 0; var r28 = x / r20; r25 = r27 - r25; r15 = x - r0; var r29 = 3 & 1; r15 = r28 % r20; var r30 = r22 ^ r14; var r31 = r17 % 3; var r32 = 6 + r21; var r33 = r26 + r1; var r34 = 2 | r30; r7 = r32 & 8; var r35 = r24 - r19; var r36 = r5 / 6; r33 = r10 ^ r27; var r37 = r33 - r25; var r38 = r15 / r36; x = r22 ^ r8; var r39 = r29 % r25; var r40 = r10 * r19; var r41 = 8 / x; var r42 = 7 & 2; var r43 = r18 - r36; var r44 = 0 % 9; var r45 = 9 & 3; var r46 = r39 ^ 4; var r47 = r17 | r40; var r48 = r39 & r23; var r49 = r9 | r20; var r50 = r28 & 4; var r51 = r11 | r46; r16 = r25 ^ r14; var r52 = r11 / r35; var r53 = 7 | r10; var r54 = r44 ^ r17; var r55 = r50 | r52; var r56 = r24 - r46; var r57 = 5 & 1; var r58 = 5 & r26; r3 = 9 / r36; var r59 = r50 - r0; var r60 = r6 % 5; var r61 = r59 * 3; var r62 = 0 - r23; var r63 = 6 % r21; r57 = r31 * r1; var r64 = r5 - 4; var r65 = r21 - r27; var r66 = 0 ^ r38; var r67 = 6 | r3; var r68 = 0 / r45; var r69 = r51 & 8; var r70 = r60 ^ r39; var r71 = r47 - r14; var r72 = 2 & r7; var r73 = 8 ^ r68; r38 = r73 - 7; var r74 = 3 + r51; var r75 = 7 - r32; var r76 = r65 | 8; r4 = 6 * 9; var r77 = r57 + r72; var r78 = 0 / 6; var r79 = r8 % r63; var r80 = r41 + 6; var r81 = r69 % 4; r57 = r76 ^ r14; var r82 = r40 & 2; r18 = r49 - r40; var r83 = r18 % 1; var r84 = r1 * r26; var r85 = r26 % 6; var r86 = 1 - r49; var r87 = r29 / r66; var r88 = r46 * r58; var r89 = 7 % 6; print(r76); var r90 = r2 | 6; var r91 = r82 ^ r37; var r92 = r55 + 1; var r93 = 4 * r28; var r94 = r14 * r83; var r95 = 0 % 5; var r96 = r80 * r50; var r97 = r42 * 3; print(r62); var r98 = r54 - r35; var r99 = r89 % r94; r28 = r64 * 3; var r100 = 2 * 3; r95 = 6 ^ r70; var r101 = r53 * r3; var r102 = 8 + 8; var r103 = r80 - r91; var r104 = r3 * 7; var r105 = 5 % r69; var r106 = r24 * r55; var r107 = 0 & r59; r21 = r106 - 5; var r108 = 8 | r27; print(r19); var r109 = r101 % r38; var r110 = r65 + r13; var r111 = 5 * r41; r58 = r18 ^ r106; x = r107 + 1; var r112 = r63 - 8; r77 = r89 - 8; var r113 = 3 * r61; var r114 = r84 & r27; var r115 = r30 - 6; r22 = 8 * r84; var r116 = 1 * r1; var r117 = 6 | r102; print(r24); var r118 = 9 / r93; var r119 = r0 % r68; var r120 = r45 | r36; var r121 = 5 % 7; var r122 = r24 & r57; \n");
/*fuzzSeed-66366547*/count=292; tryItOut("mathy3 = (function(x, y) { return (((Math.pow((((((-(2**53-2) , Math.fround(( ! Number.MAX_SAFE_INTEGER))) >>> 0) === (x >>> 0)) >>> 0) >>> 0), (( + (y ^ x)) >>> 0)) >>> 0) != mathy2(Math.fround(mathy1((( + Math.atan(y)) ^ (mathy0(1.7976931348623157e308, mathy2(x, x)) >>> 0)), Math.fround(( ~ (Math.atan2(x, (y / y)) | 0))))), (Math.pow(((( + ( - ( + x))) << ( ~ y)) | 0), (Math.fround(((Math.pow(x, x) >>> 0) ** (x >>> 0))) | 0)) | 0))) | 0); }); testMathyFunction(mathy3, [0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, -0x100000000, -0x0ffffffff, -0, 42, -(2**53-2), -Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, 0x100000000, -(2**53+2), 0.000000000000001, Number.MAX_VALUE, 2**53, 0x07fffffff, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 1, 0x0ffffffff, 0/0, -0x080000001, 1.7976931348623157e308, 0x080000001, Math.PI, -0x080000000, -1/0, -0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=293; tryItOut("\"use strict\"; g2.a1.sort((function() { try { for (var p in g2) { try { i0.next(); } catch(e0) { } try { /*MXX1*/o2 = g2.Function.name; } catch(e1) { } g0.offThreadCompileScript(\"z = let (cpnfsl) 1\"); } } catch(e0) { } try { for (var p in h0) { try { g0.offThreadCompileScript(\"{ void 0; minorgc(false); } Array.prototype.splice.call(g2.a2, NaN, ({valueOf: function() { for (var v of i1) { try { a2 = []; } catch(e0) { } try { i2.__iterator__ = f0; } catch(e1) { } try { this.b1 = t1.buffer; } catch(e2) { } /*ADP-2*/Object.defineProperty(a0, 8, { configurable: true, enumerable: -3777983106, get: f1, set: (function(a0, a1, a2, a3, a4, a5, a6, a7, a8) { var r0 = 2 + 6; a7 = 7 + a4; var r1 = 9 % a1; var r2 = a0 % a1; var r3 = 1 | a2; var r4 = a6 + a4; var r5 = a7 * a3; var r6 = x * 4; r5 = 6 / 8; var r7 = 3 | r6; var r8 = x - 5; var r9 = r7 - a0; var r10 = a8 - 7; x = a1 % 0; var r11 = r2 & a2; var r12 = 3 * r10; var r13 = x | a4; var r14 = r12 - a1; var r15 = x * r2; r13 = 5 % r14; r2 = x / r13; print(a2); var r16 = r10 - a0; a3 = 0 / 4; var r17 = a6 | 5; var r18 = x & r8; r16 = r8 + 9; var r19 = a2 / r9; var r20 = 7 & 2; var r21 = r6 & r7; var r22 = r18 ^ 1; var r23 = a1 - 5; var r24 = r1 * r16; var r25 = 3 + 8; var r26 = r24 & r8; var r27 = 4 & r23; var r28 = x & r0; r25 = r21 | r26; a0 = 0 - 9; var r29 = 4 - r7; print(a5); var r30 = r3 ^ 3; var r31 = r26 & r3; var r32 = 2 - r15; return a0; }) }); }const x =  '' ;return 18; }}));\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 7 != 0), noScriptRval: false, sourceIsLazy: (x % 9 == 6), catchTermination: true })); } catch(e0) { } try { /*MXX2*/g0.Date.prototype.getMonth = t2; } catch(e1) { } Array.prototype.sort.apply(a0, [String.fromCodePoint.bind(m1)]); } } catch(e1) { } try { /*RXUB*/var r = r0; var s = s0; print(s.replace(r, '', \"gi\")); print(r.lastIndex);  } catch(e2) { } Array.prototype.splice.apply(a1, [-17, 5]); throw v0; }));");
/*fuzzSeed-66366547*/count=294; tryItOut("");
/*fuzzSeed-66366547*/count=295; tryItOut("\"use strict\"; Array.prototype.forEach.call(a1, (function(j) { if (j) { try { Array.prototype.splice.apply(a0, [NaN, x, e0, p1]); } catch(e0) { } try { Array.prototype.pop.apply(a0, []); } catch(e1) { } try { h2.hasOwn = this.f1; } catch(e2) { } g0.o1.o1.i2.toSource = (function() { o1.t1[12] = p0; return m0; }); } else { try { v1 = (o2 instanceof p1); } catch(e0) { } try { this.f2 = (function() { v0 = r1.compile; return m0; }); } catch(e1) { } try { this.v0 = t1.byteLength; } catch(e2) { } o0.a2.push(this.i2, o0.f0, a2, g0.g0.i1, s2); } }), s1, g0, s2, this.s1);");
/*fuzzSeed-66366547*/count=296; tryItOut("{x; }");
/*fuzzSeed-66366547*/count=297; tryItOut("testMathyFunction(mathy2, [2**53+2, 0x100000000, 0x100000001, 1, -(2**53-2), -Number.MAX_VALUE, -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 0/0, -(2**53+2), -0x0ffffffff, 2**53, 0, -Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 0x07fffffff, Math.PI, -1/0, -0x100000001, -0x07fffffff, 2**53-2, 0x080000001, -0x080000000, 1.7976931348623157e308, -0x080000001, 0.000000000000001, 1/0]); ");
/*fuzzSeed-66366547*/count=298; tryItOut("\"use strict\"; m0.delete(a2);");
/*fuzzSeed-66366547*/count=299; tryItOut("(timeout(1800));");
/*fuzzSeed-66366547*/count=300; tryItOut("print(p2);");
/*fuzzSeed-66366547*/count=301; tryItOut("o0.h1.__proto__ = p0;");
/*fuzzSeed-66366547*/count=302; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Int8ArrayView[4096]) = ((!(0xfef08663))+(/*FFI*/ff()|0)-((imul(((abs((abs((((0xf8a1492e))|0))|0))|0)), ((i1) ? (/*FFI*/ff(((4194305.0)), ((4294967296.0)), ((2147483647.0)), ((549755813887.0)), ((-4503599627370497.0)), ((-295147905179352830000.0)), ((140737488355329.0)), ((-32767.0)), ((1.0078125)), ((-1.001953125)), ((-1.03125)), ((-9.671406556917033e+24)), ((129.0)), ((4.722366482869645e+21)), ((-35184372088831.0)), ((8388609.0)), ((-1125899906842625.0)))|0) : (i1)))|0) == (abs((abs((abs((((0xfa33afb1)-(0x6836cb2b)-(0xf8519d7e)) & (0xfffff*(0xffb324c2))))|0))|0))|0)));\n    return ((((((((((0x35463253) < (0xcc6d8d6b))-(0xffffffff))>>>(((-32769.0) > (-32.0)))))) | ((0xf960e869))))+(0xffffffff)-(0x96b4f938)))|0;\n  }\n  return f; })(this, {ff: false}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[0x100000000, (), (), 0x100000000, 0x100000000, (), Infinity, Infinity, Infinity, (), function(){}, Infinity, 0x100000000, (), new Boolean(true), new Boolean(true), (), 0x100000000]); ");
/*fuzzSeed-66366547*/count=303; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=304; tryItOut("print(b0)\nv0 = Object.prototype.isPrototypeOf.call(i0, e0);");
/*fuzzSeed-66366547*/count=305; tryItOut("i0.send(this.v0);");
/*fuzzSeed-66366547*/count=306; tryItOut("g0.s2 = a2.join(g2.s2);");
/*fuzzSeed-66366547*/count=307; tryItOut("\"use strict\"; /*oLoop*/for (let wuvgor = 0; wuvgor < 1; ++wuvgor) { Array.prototype.sort.apply(a1, [(function() { try { f1.toString = (function() { try { const g0.v2 = a1.length; } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(g0.v1, this.m0); } catch(e1) { } ; return s2; }); } catch(e0) { } try { o0.a2 = []; } catch(e1) { } g1.v0 = g0.eval(\"/* no regression tests found */\"); return h1; })]); } ");
/*fuzzSeed-66366547*/count=308; tryItOut("/*RXUB*/var r = g1.r0; var s = s2; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=309; tryItOut("/*bLoop*/for (var firjzu = 0; firjzu < 7; ++firjzu) { if (firjzu % 37 == 5) { v1 = o2.g2.eval(\"print(x);\"); } else { yield; }  } ");
/*fuzzSeed-66366547*/count=310; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=311; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(o2.b0, t0);");
/*fuzzSeed-66366547*/count=312; tryItOut("\"use strict\"; x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: function() { throw 3; }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: undefined, enumerate: decodeURI, keys: function() { return Object.keys(x); }, }; })(z), Object.prototype.valueOf);");
/*fuzzSeed-66366547*/count=313; tryItOut("mathy0 = (function(x, y) { return Math.cbrt(Math.exp((Math.fround(Math.pow(Math.fround(( + Math.max(Math.fround((x && Math.fround((y ? (x >>> 0) : (x >>> 0))))), ( + Math.ceil((( + Math.max(( + ( + Math.pow((0/0 >>> 0), Math.fround(x)))), ( + Math.min(Math.PI, Number.MAX_SAFE_INTEGER)))) >>> 0)))))), Math.fround((x != y)))) >>> 0))); }); testMathyFunction(mathy0, [0x080000000, 0x080000001, 1.7976931348623157e308, -(2**53), -0x080000001, Number.MAX_SAFE_INTEGER, 1, 2**53+2, -0x0ffffffff, 2**53, 0, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, Math.PI, 1/0, -Number.MIN_SAFE_INTEGER, 0/0, 42, -0x100000001, -0, 0x100000000, -(2**53+2), 0x0ffffffff, -0x100000000, 2**53-2, -0x080000000, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 0x100000001, -1/0, -0x07fffffff]); ");
/*fuzzSeed-66366547*/count=314; tryItOut("");
/*fuzzSeed-66366547*/count=315; tryItOut("const s0 = o1.a2.join(s1, s0, b0, h2, g1);");
/*fuzzSeed-66366547*/count=316; tryItOut("mathy4 = (function(x, y) { return Math.min(( + (( + ( - Math.fround(((( + x) >>> 0) + x)))) >>> (( ~ ( + Math.imul(( ! y), y))) >>> 0))), ( - (Math.log1p(( + ((( + -0x080000001) | 0) | ( + y)))) | 0))); }); testMathyFunction(mathy4, [1, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, -Number.MAX_VALUE, 1/0, -0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x100000000, Number.MAX_VALUE, 0x07fffffff, 2**53, 0.000000000000001, -0x100000001, -0x080000001, -0x100000000, -0x080000000, -(2**53), -(2**53+2), -0x0ffffffff, -Number.MIN_VALUE, 0, 42, Math.PI, 2**53-2, 0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=317; tryItOut("e1 + '';");
/*fuzzSeed-66366547*/count=318; tryItOut("\"use strict\"; t0 = new Float32Array(b2, 64, 17);");
/*fuzzSeed-66366547*/count=319; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [42, -0x07fffffff, -(2**53-2), Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, -0, 2**53+2, 0.000000000000001, 1, Number.MIN_SAFE_INTEGER, 2**53, -(2**53), -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, Math.PI, -0x100000001, -0x0ffffffff, 0x0ffffffff, -(2**53+2), 0, -0x100000000, 2**53-2, -Number.MAX_VALUE, -1/0, 0x080000001, 0x07fffffff, -0x080000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0]); ");
/*fuzzSeed-66366547*/count=320; tryItOut("/*vLoop*/for (whknjh = 0; whknjh < 29; ++whknjh) { const x = whknjh; t1 = new Uint8ClampedArray(this.o2.b0, 4, 13); } ");
/*fuzzSeed-66366547*/count=321; tryItOut("a0[1] = ({}) = ((p={}, (p.z = \"\\u77FA\")()));");
/*fuzzSeed-66366547*/count=322; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ( ~ Math.sinh((Math.fround(Math.log10(Math.fround(0x0ffffffff))) && ( + Math.sign(( + x)))))); }); testMathyFunction(mathy5, [1.7976931348623157e308, -0x0ffffffff, 42, 2**53, 0, -1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0, -(2**53+2), Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, 1, 0x100000001, 1/0, -0x100000000, Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53-2, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, 0/0, -0x07fffffff, -0x080000001, -(2**53), -Number.MIN_VALUE, Math.PI, 0x080000000, 2**53+2]); ");
/*fuzzSeed-66366547*/count=323; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.hypot((Math.log10(Math.round(y)) >>> 0), Math.pow(Math.tan(( + Number.MAX_SAFE_INTEGER)), y)) <= Math.cosh((( + Math.imul(Math.acosh(x), (x >>> 0))) >>> 0))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, Number.MIN_VALUE, 0x080000000, -0x0ffffffff, -0x080000000, 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, -0, -(2**53), 2**53-2, 0x100000000, -0x07fffffff, 0, -(2**53-2), 0.000000000000001, -0x100000000, 2**53, 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1, -0x100000001, 1/0, -0x080000001, -1/0, 42, 0x100000001, -(2**53+2)]); ");
/*fuzzSeed-66366547*/count=324; tryItOut("\"use strict\"; if((allocationMarker() << null)) { if ((v1 = (v1 instanceof p1))) /*infloop*/for(var [[] = ((p={}, (p.z = [])())), , [, ], []] = (a *= x); ((makeFinalizeObserver('tenured'))); \u0009new ((function ([y]) { })())((4277), new RegExp(\"\\u9860{2,5}|..|(?:.)*{0,4}\", \"y\"))) {/* no regression tests found */ } else {v1 = g0.eval(\"b1 = t1.buffer;\"); }}");
/*fuzzSeed-66366547*/count=325; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=326; tryItOut("mathy5 = (function(x, y) { return (Math.hypot(( + Math.fround(( ! Math.fround(( ! ((Math.exp(( ! x)) | 0) > ((((x >= (Math.imul(y, (-0x080000001 | 0)) | 0)) >>> 0) == (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))))))), ((mathy3(( + ( ~ ( + ((y >>> 0) / (Math.imul(( + y), ( + x)) >>> 0))))), Math.hypot(mathy0(( + x), y), (x ? (x >> (x >>> 0)) : y))) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1.7976931348623157e308, 0/0, 2**53, Number.MIN_VALUE, -0x100000001, -0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -0x080000000, Number.MAX_VALUE, -0x100000000, 42, Number.MAX_SAFE_INTEGER, Math.PI, 1, -0x0ffffffff, 2**53-2, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 1/0, 2**53+2, -(2**53+2), -(2**53), 0x080000000, 0x080000001, -(2**53-2), -0x07fffffff, 0, -1/0, Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=327; tryItOut("for(let c in []);b = x;");
/*fuzzSeed-66366547*/count=328; tryItOut("print(x);");
/*fuzzSeed-66366547*/count=329; tryItOut("m0.delete(((void options('strict_mode'))));");
/*fuzzSeed-66366547*/count=330; tryItOut("mathy0 = (function(x, y) { return Math.atan((Math.min(Math.cos((Math.acos(( + Math.round(Math.fround(y)))) >>> 0)), ( + ((( + (x | 0)) | 0) , (Math.atan2((((-0x0ffffffff | 0) ^ (x | 0)) | 0), (( ~ ( + y)) >>> 0)) >> 0x100000001)))) | 0)); }); ");
/*fuzzSeed-66366547*/count=331; tryItOut("testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, -1/0, -0x0ffffffff, 0.000000000000001, -0x080000000, -Number.MIN_VALUE, 1/0, Math.PI, Number.MAX_VALUE, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0/0, -(2**53-2), 0x07fffffff, -0, 2**53-2, 1.7976931348623157e308, 2**53+2, 1, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, 0x100000000, 0x100000001, 0, 42]); ");
/*fuzzSeed-66366547*/count=332; tryItOut("\"use strict\"; L:with({x: (let (b) (e %= a) ^= x >>> y)}){print(t0); }");
/*fuzzSeed-66366547*/count=333; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.imul((Math.pow((Math.atan2(x, (Math.hypot(Math.fround(Math.min((x >>> 0), x)), (Math.fround(x) >>> 0)) >>> (( + x) - y))) >>> 0), (((x >>> 0) << Math.imul(y, ( - ( + ( ! ( + y)))))) >>> 0)) >>> 0), Math.round(((( ! (1 | 0)) | 0) ? x : Math.exp(mathy2(( + y), mathy1(-Number.MAX_SAFE_INTEGER, x)))))) | 0); }); testMathyFunction(mathy3, [0, 2**53+2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 42, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, 1, 0x100000000, 0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), -0, Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, -0x0ffffffff, 0x080000001, 2**53-2, 1/0, 2**53, Math.PI, -0x100000001, 0x080000000, -(2**53-2), -0x080000001, -(2**53+2), 0/0]); ");
/*fuzzSeed-66366547*/count=334; tryItOut("\"use strict\"; let (a) { m2.has(p2); }");
/*fuzzSeed-66366547*/count=335; tryItOut("testMathyFunction(mathy3, [0/0, -Number.MAX_VALUE, 0x07fffffff, -1/0, 1.7976931348623157e308, -(2**53), -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, 1, -(2**53+2), -0x080000000, 1/0, 2**53-2, Math.PI, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 42, -0x100000000, 0, -0x0ffffffff, 0x100000001, 0x100000000, 0x0ffffffff, 0x080000001, -(2**53-2), -0, -0x07fffffff, 0x080000000]); ");
/*fuzzSeed-66366547*/count=336; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.asin(((((Math.atan2(Math.hypot((x <= y), y), (Math.fround(( + Math.fround((mathy0((y * Math.cosh(y)), Math.PI) | 0)))) | 0)) | 0) >>> 0) && (Math.fround(( ! (y >>> 0))) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, Math.PI, -0x100000000, 1, 2**53, -0x080000000, 1.7976931348623157e308, 0, 0x100000000, 2**53-2, 0.000000000000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, 42, -0, 1/0, -0x07fffffff, Number.MAX_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -1/0, 0/0, -Number.MIN_VALUE, 0x080000001, 0x100000001, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=337; tryItOut("testMathyFunction(mathy0, /*MARR*/[true, function(){}, function(){}, true, x, function(){}, Infinity, function(){}, function(){}, x, function(){}, function(){}, x, true, Infinity, x, true, x, function(){}, x, function(){}, function(){}, function(){}, x, Infinity, Infinity, function(){}, x, function(){}, Infinity, function(){}, x]); ");
/*fuzzSeed-66366547*/count=338; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.round(( + mathy3(( + (Math.trunc((Math.atan2((x <= Math.fround(( + ( ~ x)))), x) | 0)) | 0)), Math.fround(Math.min(0x100000001, y))))) >>> 0)); }); testMathyFunction(mathy4, [0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, 2**53, -Number.MAX_VALUE, -(2**53), -0x100000001, Math.PI, -0x100000000, 0x100000000, 2**53+2, -0x080000001, 0x080000001, 1/0, 0x0ffffffff, Number.MIN_VALUE, 2**53-2, 0x07fffffff, 42, -0, 0.000000000000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 0/0, -0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=339; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2((Math.ceil(( + (( + (Math.min(0x07fffffff, Math.fround(Number.MIN_SAFE_INTEGER)) >>> 0)) ** Math.pow((Math.sign((( ! ( + x)) >>> 0)) | 0), ( + ( ~ ( + y))))))) >>> 0), (( - mathy0(( ~ (( - Math.asinh(x)) >>> 0)), Math.cbrt((mathy1(Math.log1p(( + 1/0)), (Math.max(Math.fround(x), x) >>> 0)) | 0)))) | 0)); }); ");
/*fuzzSeed-66366547*/count=340; tryItOut("\"use strict\"; print(uneval(o2));");
/*fuzzSeed-66366547*/count=341; tryItOut("let ([] = (4277), x = (e ^= y), x, nzakks, x, d, x, ikbeqf, eval) { a1.pop(); }v2 = evalcx(\"this.g1.t0.__iterator__ = (function mcc_() { var aokera = 0; return function() { ++aokera; if (/*ICCD*/aokera % 6 == 1) { dumpln('hit!'); (void schedulegc(o1.g2)); } else { dumpln('miss!'); v1 = Object.prototype.isPrototypeOf.call(a1, h1); } };})();\", g0);");
/*fuzzSeed-66366547*/count=342; tryItOut("let x, erroxv, x = -4, hezqrm, capexj;/*tLoop*/for (let x of /*MARR*/[new Boolean(false), new Boolean(false), objectEmulatingUndefined(), this, objectEmulatingUndefined(), this, objectEmulatingUndefined(), this, this, new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), this, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), this, objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false)]) { o2.g2.offThreadCompileScript(\"4\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 2 == 1) })); }");
/*fuzzSeed-66366547*/count=343; tryItOut("\"use strict\"; yield this;print(x);");
/*fuzzSeed-66366547*/count=344; tryItOut("selectforgc(o2);");
/*fuzzSeed-66366547*/count=345; tryItOut("\"use strict\"; /*infloop*/for(let {} = [].unwatch(\"__proto__\");  '' ; ().__defineGetter__(\"delete\", Function)) {v0 = a1.reduce, reduceRight((function(j) { f0(j); }), s1); }");
/*fuzzSeed-66366547*/count=346; tryItOut("for (var v of o0) { try { g0.m1.set(p1, t2); } catch(e0) { } this.v2 = a1.length; }");
/*fuzzSeed-66366547*/count=347; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + ( - ( + (( - ( + (( + (x >>> 0)) >>> 0))) | 0)))); }); testMathyFunction(mathy0, [-0x0ffffffff, -0, -(2**53-2), -0x100000000, 42, 0x080000000, 2**53, -Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, -Number.MAX_VALUE, -(2**53), 0x100000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, Math.PI, 0x080000001, 0, 2**53+2, 0/0, 0x0ffffffff, 0x07fffffff, 2**53-2, 1/0, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000]); ");
/*fuzzSeed-66366547*/count=348; tryItOut("/*iii*//*vLoop*/for (let uoqhll = 0; uoqhll < 6; ++uoqhll) { let a = uoqhll; for (var p in g2) { try { /*ADP-3*/Object.defineProperty(a1, ({valueOf: function() { print(uneval(v2));return 16; }}), { configurable: (function ([y]) { })(), enumerable: 9, writable: false, value: h2 }); } catch(e0) { } try { s0 += s1; } catch(e1) { } try { print(uneval(e1)); } catch(e2) { } for (var p in b0) { try { for (var p in b1) { try { h2.hasOwn = f1; } catch(e0) { } ; } } catch(e0) { } try { m1.set(i0, v2); } catch(e1) { } t2[18] = /*UUV2*/(a.getFloat32 = a.then); } } } /*hhh*/function ozcwjl( ){v1 = a1.length;\no2.i0.next();\n}");
/*fuzzSeed-66366547*/count=349; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(f1, i1);");
/*fuzzSeed-66366547*/count=350; tryItOut("\"use strict\"; Array.prototype.forEach.call(a1, (function() { try { i1.send(this.g0.o1); } catch(e0) { } a2.reverse(); return this.m1; }));");
/*fuzzSeed-66366547*/count=351; tryItOut("mathy3 = (function(x, y) { return (( - (Math.min((Math.min(Math.fround(mathy1((Math.fround(( - mathy1(x, Math.atan2(Math.fround(x), ( + y))))) | 0), (x >>> 0))), (x | ( + -(2**53)))) | 0), (Math.atan2(( + Math.fround((y & x))), (mathy2(Math.fround(x), Math.fround(Math.fround(( - Math.fround(x))))) | 0)) > ((Math.fround((Math.cosh(x) >>> 0)) < Math.sign((( + -(2**53)) | 0))) >>> 0))) | 0)) | 0); }); ");
/*fuzzSeed-66366547*/count=352; tryItOut("\"use strict\"; v2 = (e2 instanceof o1.g1);");
/*fuzzSeed-66366547*/count=353; tryItOut("\"use strict\"; m2.__iterator__ = (function() { try { const o2.v2 = o0.g1.t2.BYTES_PER_ELEMENT; } catch(e0) { } try { v1 = a2.reduce, reduceRight(); } catch(e1) { } try { v2 = evaluate(\"function f1(t0)  { yield x = ('fafafa'.replace(/a/g, function shapeyConstructor(jraqxh){\\\"use strict\\\"; if (jraqxh) jraqxh[\\\"__proto__\\\"] = w;jraqxh[\\\"forEach\\\"] = \\\"\\\\uC785\\\";jraqxh[\\\"forEach\\\"] = ({a1:1});return jraqxh; })) } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: true, sourceIsLazy: true, catchTermination: false })); } catch(e2) { } ; return h0; });");
/*fuzzSeed-66366547*/count=354; tryItOut("continue M;o2.s1 += s2;\nvar hianba = new ArrayBuffer(12); var hianba_0 = new Uint32Array(hianba); t0 = new Float32Array(b1);\n");
/*fuzzSeed-66366547*/count=355; tryItOut("print(this);\nfor (var p in s1) { try { m2.has(f1); } catch(e0) { } try { g0.t2 = a2[3]; } catch(e1) { } h1.set = this.f2; }\n");
/*fuzzSeed-66366547*/count=356; tryItOut("\"use strict\"; v1 = a2.some((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { a5 = a16 ^ a10; var r0 = x * a5; var r1 = a18 & a16; print(a5); var r2 = a13 + 8; var r3 = r2 / a8; var r4 = a2 / r0; var r5 = r4 % a14; var r6 = a0 | a16; var r7 = 6 + 8; var r8 = 3 | a17; var r9 = a4 ^ r3; a13 = 2 | 0; var r10 = 1 + a18; var r11 = 9 + 6; r3 = 0 - r2; var r12 = a11 * a19; var r13 = a5 + a8; r9 = a1 % 3; var r14 = 7 * a5; var r15 = 9 + a1; a4 = a9 * a2; var r16 = 2 / 9; var r17 = r3 - r1; var r18 = 7 | 5; var r19 = 8 - 0; var r20 = a10 + 0; r4 = 7 & a18; var r21 = r15 - a17; var r22 = a18 / r8; r14 = 3 % 1; var r23 = r21 - 4; var r24 = a13 - a19; r24 = 6 | a19; var r25 = r12 * r4; var r26 = a4 | a19; var r27 = 0 ^ a0; var r28 = 2 | 2; a4 = r10 ^ 7; var r29 = r13 ^ r2; var r30 = r5 % a18; var r31 = r9 - 9; var r32 = 8 + 4; var r33 = r9 * r1; var r34 = r19 ^ a13; var r35 = 9 & 8; a5 = a10 & a4; r32 = 5 + a8; var r36 = r31 ^ a8; var r37 = 4 % r1; var r38 = r21 & r20; var r39 = r4 + a16; var r40 = 4 & a5; a4 = a0 & r7; r5 = a7 ^ 9; var r41 = 5 ^ r8; a12 = r6 * r20; var r42 = x - a10; a18 = r23 ^ 3; var r43 = 3 / 2; var r44 = r1 ^ 6; var r45 = 6 | r42; print(r5); var r46 = 0 / 9; var r47 = 0 / 8; var r48 = a13 | 4; var r49 = a16 | 8; var r50 = r38 % r25; a16 = a17 - r5; r26 = r13 - a19; r35 = r16 & 1; var r51 = r25 + r27; var r52 = r13 - 2; var r53 = r48 | r7; a14 = a3 % r53; var r54 = 5 + 2; var r55 = 9 ^ r33; r3 = 0 ^ 9; var r56 = r31 & 0; var r57 = r37 | 7; var r58 = 4 % a15; r28 = r40 + 9; var r59 = a18 - r34; var r60 = 4 + 4; print(r44); var r61 = 9 | r28; r49 = r24 & r28; var r62 = r61 * 8; var r63 = r54 + 0; r4 = r60 & r31; var r64 = 0 - a17; var r65 = r18 % r19; var r66 = 8 / a10; var r67 = 4 + 4; var r68 = 0 - 1; var r69 = a7 | r20; print(r14); var r70 = r26 / r27; a10 = 3 % r59; r56 = 6 | 5; var r71 = r67 + 1; var r72 = r0 | 8; print(a16); print(r23); var r73 = a18 % r32; var r74 = 3 - 8; var r75 = r35 - r64; var r76 = 1 * r39; print(r56); a1 = r52 | r1; var r77 = 1 - 7; r13 = r39 & r12; var r78 = r22 - a17; var r79 = r22 | r45; var r80 = x - 1; var r81 = 8 % a0; var r82 = r57 ^ a14; var r83 = 6 | r10; var r84 = 1 + a7; var r85 = a5 ^ r3; var r86 = r42 ^ a6; var r87 = r64 & a6; var r88 = a18 ^ r62; var r89 = r5 & r77; var r90 = r37 - a12; var r91 = 6 ^ 8; var r92 = 4 ^ r19; var r93 = 5 % 6; var r94 = 5 / 3; var r95 = r0 * 8; var r96 = r2 / 2; var r97 = 5 | r47; var r98 = 4 / 8; print(r75); var r99 = 5 & r33; var r100 = 7 * r28; var r101 = r46 * r73; var r102 = r98 & r85; var r103 = r68 + r75; var r104 = r89 ^ r30; var r105 = 2 ^ 0; var r106 = r74 & r62; r33 = r96 | 8; return a9; }), a0, g1.o2);");
/*fuzzSeed-66366547*/count=357; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((4277));\n    return ((((((!((0xffffffff))))>>>(((0x3a89d66e))+(0xffffffff)+((0x0)))) < (((0xfaf6ab65)+(0xffffffff))>>>((0xaa8aaf6e)-(0xd3a646ac))))-(i1)))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ a1.sort((function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var acos = stdlib.Math.acos;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n'x'  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = ((((/*MARR*/[[1], function(){}, function(){}, -0x5a827999, -0x5a827999, new Number(1), [1], function(){}, [1], function(){}, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, -0x5a827999, [1], function(){}, new Number(1), -0x5a827999, new Number(1), new Number(1), new Number(1), new Number(1), [1], function(){}, function(){}, function(){}, -0x5a827999, new Number(1), function(){}, function(){}, function(){}, function(){}, new Number(1), -0x5a827999, -0x5a827999, function(){}, -0x5a827999, -0x5a827999, new Number(1), [1], -0x5a827999, -0x5a827999, [1], function(){}, -0x5a827999, [1], new Number(1), [1], new Number(1), function(){}, [1], [1], [1], new Number(1), new Number(1), new Number(1), new Number(1), [1], -0x5a827999, function(){}, -0x5a827999, -0x5a827999, new Number(1), new Number(1), -0x5a827999, new Number(1), new Number(1), new Number(1), function(){}, [1], [1], [1], function(){}, new Number(1), -0x5a827999, -0x5a827999, [1], new Number(1), -0x5a827999, new Number(1), function(){}, new Number(1), function(){}, -0x5a827999, [1], function(){}, new Number(1), -0x5a827999, function(){}, -0x5a827999, new Number(1), -0x5a827999, new Number(1), -0x5a827999, [1], [1], new Number(1), function(){}, [1], [1], [1], new Number(1), function(){}, -0x5a827999, -0x5a827999, -0x5a827999, [1], function(){}, new Number(1), [1], [1], -0x5a827999].some))) - ((Infinity)));\n    d0 = (+acos((((eval(\"/* no regression tests found */\", (e || z)))))));\n    {\n      i1 = ((((0x88399ebf) >= (0x78743dee)) ? (+(((0xba00bb7f)-(i1)) | ((~~(d0)) / (~~(1.2089258196146292e+24))))) : (-35184372088832.0)));\n    }\n    return (((i1)))|0;\n    i1 = (0x1e712810);\n    d0 = (d0);\n    (Float64ArrayView[4096]) = ((((-(((4277))))) - ((-0.001953125))));\n    (Float64ArrayView[2]) = ((-1025.0));\n    d0 = ((i1) ? ((i1)) : (+(1.0/0.0)));\n    return (((0xafcd3539)+(i1)))|0;\n  }\n  return f; })(this, {ff: function (y, x) { return \"\u03a0\" } }, new SharedArrayBuffer(4096)));return (x = Proxy.create(({/*TOODEEP*/})(\"\\uD88E\"), \"\\u495E\"))})()}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, -0x100000000, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, -(2**53+2), Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, 1/0, -0x080000001, 1, 2**53-2, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 0x080000001, 0, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, -0x0ffffffff, -0, Math.PI, -(2**53), 2**53+2, 0x100000000, 2**53]); ");
/*fuzzSeed-66366547*/count=358; tryItOut("/*infloop*/for(var e in (((x, x, ...\u3056) =>  { \"use strict\"; b = linkedList(b, 1386); } )(window))){/* no regression tests found */ }");
/*fuzzSeed-66366547*/count=359; tryItOut("mathy1 = (function(x, y) { return ( + ( - ( + ((( ! mathy0(Math.fround(Math.pow(y, y)), Math.fround(Math.imul(x, Math.fround(y))))) || ( ~ mathy0(-Number.MAX_SAFE_INTEGER, Math.exp((Number.MIN_VALUE | 0))))) ? ((Math.max(( + (Math.round((((y | 0) >> (y | 0)) >>> 0)) >>> 0)), ( + (y >> y))) >>> 0) ? ( + (( + (( - (Math.fround(Math.max(Number.MIN_VALUE, x)) | 0)) | 0)) % ( + mathy0((Math.hypot(( + (2**53+2 | 0)), Math.fround((((x | 0) ? (y | 0) : (x | 0)) | 0))) | 0), (y | 0))))) : ( - ( ! x))) : Math.log2(( + Math.imul((y >>> 0), ( + ( ~ Math.fround(Number.MAX_VALUE)))))))))); }); ");
/*fuzzSeed-66366547*/count=360; tryItOut("\"use strict\";  \"\" ;");
/*fuzzSeed-66366547*/count=361; tryItOut("a1 = /*PTHR*/(function() { for (var i of /*FARR*/[]) { yield i; } })();");
/*fuzzSeed-66366547*/count=362; tryItOut("/*tLoop*/for (let b of /*MARR*/[(x >= (19 == x(x))), undefined, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, (x >= (19 == x(x))), 0x2D413CCC, 0x2D413CCC, (x >= (19 == x(x))), (x >= (19 == x(x))), (x >= (19 == x(x))), (x >= (19 == x(x))), (x >= (19 == x(x))), undefined, 0x2D413CCC, 0x2D413CCC]) { Array.prototype.forEach.call(a0, (function(j) { if (j) { e2.delete(s1); } else { try { v2 = true; } catch(e0) { } this.v0 = Proxy.create(h2, g2); } }), i0, s1, g1); }");
/*fuzzSeed-66366547*/count=363; tryItOut("x.name;this.zzz.zzz;");
/*fuzzSeed-66366547*/count=364; tryItOut("testMathyFunction(mathy5, ['\\0', 0.1, (new String('')), NaN, '/0/', (new Boolean(false)), (function(){return 0;}), false, undefined, /0/, ({toString:function(){return '0';}}), null, 0, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Number(0)), (new Boolean(true)), '', (new Number(-0)), [0], -0, true, objectEmulatingUndefined(), [], '0', 1]); ");
/*fuzzSeed-66366547*/count=365; tryItOut("mathy3 = (function(x, y) { return ( + ( ~ ( + (( + (y >>> 0)) >= (Math.imul(((( ! (Math.fround(( ! x)) >>> 0)) >>> 0) | 0), ((Math.hypot(((Math.acos(( + (y || x))) >>> 0) >>> 0), (x >>> 0)) >>> 0) | 0)) >>> 0))))); }); ");
/*fuzzSeed-66366547*/count=366; tryItOut("v1 = g0.eval(\"/* no regression tests found */\");\ng1.e1 + p1;\n");
/*fuzzSeed-66366547*/count=367; tryItOut("var dtuqyt = new SharedArrayBuffer(6); var dtuqyt_0 = new Int16Array(dtuqyt); dtuqyt_0[0] = -0.424; print([z1,,]);");
/*fuzzSeed-66366547*/count=368; tryItOut("mathy5 = (function(x, y) { return ( + ( ! mathy0((Math.sin((Math.hypot((x >>> 0), ((( - 0x100000001) && Math.cosh(Math.fround(y))) >>> 0)) >>> 0)) >>> 0), Math.expm1((Math.min(((( - x) || Math.asinh((Math.pow(-(2**53+2), -1/0) | 0))) | 0), (mathy1(( + Math.min(x, y)), ( + ( ~ ( + 0)))) | 0)) | 0))))); }); testMathyFunction(mathy5, /*MARR*/[new String(''), new Boolean(false), (-1/0), (-1/0), new Boolean(false), new String(''), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-66366547*/count=369; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy3((( + (mathy0(x, y) | 0)) >>> 0), (Math.hypot(Math.fround(Math.asin(Math.fround(Math.expm1(( + (x == ( + Math.imul(( + -0x07fffffff), ( + -1/0))))))))), ((((( + Math.max(( + (( + (-(2**53) >>> 0)) >>> 0)), ( + Math.sinh(((x | 0) >> ( + y)))))) | 0) != (( + (( + (Math.hypot(Math.hypot(x, y), ( - y)) | 0)) | 0)) | 0)) >>> 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-66366547*/count=370; tryItOut("\"use strict\"; a1[8] = this.zzz.zzz = (4277);");
/*fuzzSeed-66366547*/count=371; tryItOut("mathy2 = (function(x, y) { return ( + (mathy1(mathy1(y, y), Math.fround((Math.fround(( ~ ((( ! y) >>> 0) >>> 0))) ? Math.fround(Math.hypot(Math.fround(-0x080000001), ( + x))) : (( - ( ! x)) >>> 0)))) > (Math.hypot(( + (y | 0)), (Math.min((x >>> 0), y) >>> 0)) | ((( + x) === y) || ( + (( + Math.cos(x)) ? ( + 2**53-2) : ( + ( ! ( + Math.max(( + x), ( + y))))))))))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), undefined, (new String('')), '\\0', -0, NaN, '/0/', ({valueOf:function(){return 0;}}), (new Number(-0)), ({toString:function(){return '0';}}), 0, true, ({valueOf:function(){return '0';}}), (new Number(0)), 0.1, null, (function(){return 0;}), [0], (new Boolean(true)), '0', [], 1, '', (new Boolean(false)), false, /0/]); ");
/*fuzzSeed-66366547*/count=372; tryItOut("{ void 0; setGCCallback({ action: \"minorGC\", phases: \"both\" }); }");
/*fuzzSeed-66366547*/count=373; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( - Math.fround(mathy1((((( ~ (x >>> 0)) >>> 0) <= ( + Math.cos(((( + x) | (y | 0)) | 0)))) | 0), ((((Math.fround(Math.abs(Math.fround((Math.fround(x) ? y : mathy3(-Number.MAX_VALUE, (Math.fround(y) + y)))))) | 0) / (Math.max(( - (Math.sign(1/0) | 0)), ( + ((-0x100000001 >>> 0) !== (x >>> 0)))) >>> 0)) | 0) | 0)))); }); ");
/*fuzzSeed-66366547*/count=374; tryItOut("\"use strict\"; v0 = a2.length;print(x);");
/*fuzzSeed-66366547*/count=375; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=376; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Math.PI, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, 0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 0x100000001, 1/0, 0x0ffffffff, -0x080000000, 2**53-2, -0x100000001, Number.MAX_VALUE, 0.000000000000001, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), 2**53+2, 42, 0x080000001, -0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, -(2**53), 0x100000000, -Number.MAX_SAFE_INTEGER, -1/0, 1, -0, 0, 2**53]); ");
/*fuzzSeed-66366547*/count=377; tryItOut("this.s1 += 'x';");
/*fuzzSeed-66366547*/count=378; tryItOut("mathy2 = (function(x, y) { return ( + Math.abs(( + ( + Math.hypot(( + (mathy0(Math.fround(( + Math.fround(Math.pow(Math.hypot(x, Number.MIN_VALUE), x)))), ((((y | 0) == (Math.asin(x) | 0)) | 0) >>> 0)) >>> 0)), Math.fround(( ! mathy0((Math.hypot(((x && 0x100000000) >>> 0), (y >>> 0)) >>> 0), Math.asin(( + ( ~ y))))))))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, -1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, -0, 0, 0x07fffffff, 42, -(2**53-2), 0x100000000, Math.PI, 1.7976931348623157e308, 1, -0x100000001, 1/0, -0x100000000, 0/0, 0x0ffffffff, 2**53, -0x0ffffffff, -0x07fffffff, 0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53+2, 0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=379; tryItOut("for(c = (w) = x in (4277)) {y * x; }");
/*fuzzSeed-66366547*/count=380; tryItOut("mathy0 = (function(x, y) { return ( + (( ! (( - Math.imul(x, y)) & Math.trunc(x))) >>> 0)); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, Number.MAX_VALUE, 0x080000000, 2**53+2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 0.000000000000001, -(2**53-2), -0x080000001, 2**53, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, 0x100000000, 0x080000001, -(2**53), 0x0ffffffff, 0/0, -(2**53+2), -0x100000001, Math.PI, -1/0, -0, -Number.MIN_VALUE, 42, 1.7976931348623157e308, 0, -0x0ffffffff, -0x100000000]); ");
/*fuzzSeed-66366547*/count=381; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MAX_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, -0, 0x100000000, -0x07fffffff, 0.000000000000001, 0/0, 0x07fffffff, 42, 1.7976931348623157e308, 0x100000001, -Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, 0, Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 0x080000000, 1, -Number.MIN_VALUE, -0x100000001, -(2**53-2), 2**53+2, 2**53-2, Math.PI, 1/0, 0x080000001, -0x080000000, -0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=382; tryItOut("\"use strict\"; v1 = g0.runOffThreadScript();");
/*fuzzSeed-66366547*/count=383; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\3|\\\\W|$+(\\\\b)\\\\S\\\\W([^])|(?=^)+??{1,})\", \"gim\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-66366547*/count=384; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=385; tryItOut("testMathyFunction(mathy4, [0x100000001, 0.000000000000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, -0, 0x07fffffff, -(2**53-2), 1, -0x07fffffff, 1.7976931348623157e308, 2**53, -0x0ffffffff, 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 2**53+2, -(2**53+2), -0x080000000, -0x080000001, 0, -Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, 42, 0x080000000, -1/0, 0/0, Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=386; tryItOut("i0.send(i1);");
/*fuzzSeed-66366547*/count=387; tryItOut("\"use strict\"; s1.toString = (function() { for (var j=0;j<84;++j) { f2(j%5==1); } });");
/*fuzzSeed-66366547*/count=388; tryItOut("o1 = f0.__proto__;function w([, , , {x: {x, x: {NaN, x, NaN: []}, x, x: [x, {z: {x: {x: z}, b: x.x}, c: {this.c: c((( + ( ~ (Math.ceil((Math.pow((x && x), x) | 0)) | 0))))), x: d}}], eval, y: [{y: {}, y, set: {x: {}, x, eval: {d: [], \u3056, x: a}}, y: {x: []}, \u3056: [{}, (4277)[\"constructor\"]]}, , ], x: {x: b, NaN, window: []}}, z, NaN: {x: {e: [[[]], [, {window: [], x: window}, \u3056, d], {\u3056: [, ], x, x}], eval}, z, x: x, c}, eval, x: [, , , w, , , [, , , , [NaN, , , ]]]}, , , , , ], b, x, d, x, x = Math.hypot(224431799,  /x/g ), \u3056, d, b, \u3056 = d = \"\\uD3CF\", a, b, x =  /x/g , x, x, x, eval, \u3056, x, w, b, window =  '' , y, \u3056, x, b = 6, x, NaN, x, e) { yield { void 0; minorgc(false); } } v0 = undefined;");
/*fuzzSeed-66366547*/count=389; tryItOut("\"use strict\"; (/(\\d|\\B\\W+?)?|[^]|\\3*?/im);;");
/*fuzzSeed-66366547*/count=390; tryItOut("\"use strict\"; /*infloop*/L:for(var [NaN, [d], , [, x, {this.x: {x: {z: x}, a: []}, a, x: /* no regression tests found */}, , , , x], ] = allocationMarker(); (4277); (this.__defineSetter__(\"NaN\", (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: /*wrap1*/(function(){ \"use asm\"; print({} = c);return function(q) { return q; }})(), defineProperty: function() { throw 3; }, getOwnPropertyNames: objectEmulatingUndefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })))) {v0 = (o0 instanceof s2);/*hhh*/function aooxel(window, e, eval, x, this.x, \u3056, c, e, e =  '' , x, x, delete, x =  \"\" , x, z = true, window){( '' /*\n*/);}/*iii*/const t1 = new Int16Array(({valueOf: function() { return;return 13; }})); }");
/*fuzzSeed-66366547*/count=391; tryItOut("ztjalo, d, qalukp, cqymgs;\u000c( \"\" );a1.toString = f2;");
/*fuzzSeed-66366547*/count=392; tryItOut("print(g2);");
/*fuzzSeed-66366547*/count=393; tryItOut("\"use strict\"; for(b in ((function(q) { return q; })(x)))v1 = r0.source;");
/*fuzzSeed-66366547*/count=394; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround((Math.max(Math.max(Math.fround(( ! ( + Math.log(( + x))))), ( ~ Math.fround((Math.fround(x) ? Math.fround(x) : Math.fround(-Number.MAX_VALUE))))), Math.min(( + Math.imul(-0x080000000, Math.fround((0.000000000000001 > (y - Number.MIN_SAFE_INTEGER))))), (( ! ( + x)) >>> 0))) ? ( + Math.min(( + ( ! 0x0ffffffff)), mathy1(y, x))) : Math.min(Math.fround((x | (-0 ? (((0x100000000 ? x : Math.fround(Math.pow(Math.fround(x), Math.fround(y)))) ? y : ( ~ x)) >>> 0) : ((x >>> 0) || Math.pow(Math.cos(x), x))))), ((Math.pow(( + Math.max(y, -0x100000001)), (Math.atan2(((mathy0(( + -0x07fffffff), Math.fround(Math.hypot((Math.atan2((-Number.MAX_VALUE >>> 0), (x >>> 0)) >>> 0), (Math.fround(0x100000001) ^ y)))) | 0) | 0), Math.fround(y)) >>> 0)) >>> 0) | 0)))); }); ");
/*fuzzSeed-66366547*/count=395; tryItOut("\"use strict\"; p1.valueOf = (function() { for (var j=0;j<111;++j) { f2(j%2==0); } });");
/*fuzzSeed-66366547*/count=396; tryItOut("");
/*fuzzSeed-66366547*/count=397; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=398; tryItOut("t1.toString = (function(j) { if (j) { o2.h0.__proto__ = p0; } else { try { Object.prototype.watch.call(i2, NaN * x.isExtensible(), (function(j) { if (j) { try { s1 += 'x'; } catch(e0) { } g2 + e0; } else { try { const o0.o2 = {}; } catch(e0) { } Array.prototype.pop.call(a1, this.g1.g1, Object.defineProperty(e, new String(\"-12\"), ({value:  \"\" }))); } })); } catch(e0) { } try { t1 = new Float32Array(b0); } catch(e1) { } v2 = a2.reduce, reduceRight(); } });");
/*fuzzSeed-66366547*/count=399; tryItOut("var himjer, \u3056 = (void version(170)), x, z, fdgclc, ydzpkr, rzzhgk, window;Array.prototype.forEach.apply(a2, [(function() { for (var j=0;j<147;++j) { f0(j%4==0); } })]);");
/*fuzzSeed-66366547*/count=400; tryItOut("/*RXUB*/var r = /((?:\\s|(?=$)(?!$.)(?!^?.)){4,})(\uedb8{0,}\\cI+?|(?![^+-\u00ea\\u590d-\\\ue7ee\\xc4\\x1D-\u4d3d])\\B?)?/y; var s = \"\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\u0009\\u0009 a  \\u4c5a1\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\uedb8\\u0009\\u0009 a  \\u4c5a1\"; print(s.search(r)); ");
/*fuzzSeed-66366547*/count=401; tryItOut("/*oLoop*/for (let reoifu = 0; reoifu < 0; (w.__defineGetter__(\"x\", /*wrap3*/(function(){ \"use strict\"; var axpdfp = undefined; (true)(); }))), ++reoifu) { var sulqbe = new ArrayBuffer(24); var sulqbe_0 = new Uint16Array(sulqbe); sulqbe_0[0] = 8; f0 + b1; } ");
/*fuzzSeed-66366547*/count=402; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - Math.fround(Math.fround(Math.pow(Math.fround((( + ((( + (mathy2(mathy0(y, 0.000000000000001), ((y != ( + 0x0ffffffff)) >>> 0)) >>> 0)) && (Math.expm1(( + ( - (y >>> 0)))) | 0)) | 0)) >>> 0)), Math.fround(((((Math.hypot(((((Math.fround((y / x)) << Math.fround(-(2**53))) , -0x07fffffff) >>> 0) | 0), ((mathy1(x, ((Math.sqrt((y | 0)) | 0) | 0)) | 0) | 0)) | 0) >>> 0) > (Math.fround(( ~ Math.fround(x))) >>> 0)) >>> 0)))))) | 0); }); testMathyFunction(mathy3, [Math.PI, 1.7976931348623157e308, 0x07fffffff, -0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), Number.MIN_VALUE, -0x080000000, Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, 0x100000000, -0x100000000, 0, -Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, 2**53, 42, 0x080000001, -0x07fffffff, 0x080000000, -0x0ffffffff, -0, 1, 0x100000001, 0/0, -1/0, 2**53-2]); ");
/*fuzzSeed-66366547*/count=403; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=404; tryItOut("/*bLoop*/for (let ddewvt = 0; ddewvt < 126; ++ddewvt) { if (ddewvt % 6 == 5) { a0 = new Array; } else { v1 = (v0 instanceof this.g1.b1); }  } ");
/*fuzzSeed-66366547*/count=405; tryItOut("/*oLoop*/for (var hulvmv = 0, d = \"\\uB765\"; hulvmv < 3; ++hulvmv) { /*bLoop*/for (var qqfnye = 0; qqfnye < 127; ++qqfnye) { if (qqfnye % 5 == 0) { Array.prototype.shift.apply(a0, [s2, f1]); } else { /*RXUB*/var r = r0; var s = \"\"; print(s.split(r)); print(r.lastIndex);  }  }  } ");
/*fuzzSeed-66366547*/count=406; tryItOut("\"use strict\"; Array.prototype.sort.apply(a0, [f1]);");
/*fuzzSeed-66366547*/count=407; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + (( + (( + Math.sinh((Math.min((( + x) >>> 0), ((x ? Math.imul((x ? x : x), y) : x) >>> 0)) >>> 0))) == (( - Math.sign(((( + y) ^ (x | 0)) | 0))) - (( + Math.max(x, x)) | 0)))) ? ( + mathy0(( - ( + (( + ((Math.fround(-0x080000000) >> 0.000000000000001) | 0)) * ( + x)))), ((( + (Math.fround((( - (( + Math.atan((( ! -(2**53+2)) | 0))) >>> 0)) >>> 0)) * ( + x))) ? y : Math.fround((Math.fround(( ! x)) !== Math.fround(x)))) | 0))) : ( + (mathy1((Math.fround((Math.fround(Math.fround(Math.acosh(Math.fround(Math.hypot(( + Number.MIN_VALUE), x))))) <= (x >>> 0))) | 0), (( + ( + ((x | 0) ? y : -Number.MAX_VALUE))) | 0)) | 0)))); }); ");
/*fuzzSeed-66366547*/count=408; tryItOut("mathy4 = (function(x, y) { return (Math.fround(Math.acosh(Math.fround(((( - (0x0ffffffff | 0)) | 0) != (Math.round((Math.fround((Math.fround((((x >>> 0) != (y >>> 0)) >>> 0)) ? Math.fround((y ^ Math.fround(1.7976931348623157e308))) : Math.fround(y))) | 0)) | 0))))) ? ( + ( + (Math.min(Math.fround(((Math.atan2(Math.fround(Math.atan2(y, (-(2**53+2) | 0))), y) | 0) && mathy0(-Number.MIN_VALUE, y))), (Math.sqrt(( + ( - x))) | 0)) | 0))) : (Math.cosh(Math.fround(Math.fround(( + Math.fround(-(2**53+2)))))) ? Math.imul(2**53+2, Math.fround(mathy1(Math.fround(((( + Math.fround(Math.pow(y, x))) <= ( + y)) >>> 0)), Math.fround(x)))) : mathy2(x, Math.log10(-0x07fffffff)))); }); testMathyFunction(mathy4, [0, -Number.MAX_VALUE, 0x07fffffff, -1/0, -0x0ffffffff, 2**53, -0, Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0/0, Number.MIN_VALUE, -0x080000000, 0.000000000000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 1, Math.PI, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, -0x080000001, -0x100000000, 42, -0x07fffffff, 0x0ffffffff, -(2**53+2), -0x100000001, 2**53-2, -Number.MIN_VALUE, 0x080000001, 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=409; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(t1, m2);");
/*fuzzSeed-66366547*/count=410; tryItOut("\"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return Math.sqrt((( + Math.fround(( ~ ( + (y + Math.fround(Math.atan((Math.max(( + ( ! ( + -0x080000001))), Math.fround(-Number.MIN_SAFE_INTEGER)) >>> 0)))))))) << Math.fround(((( ~ Math.fround(( + ( - Math.fround(x))))) < -0x080000001) | 0)))); }); ");
/*fuzzSeed-66366547*/count=411; tryItOut("mathy5 = (function(x, y) { return (Math.imul(Math.fround(( - ((Math.pow((( + Math.cbrt((((y >>> 0) != y) >>> 0))) | 0), ((((x | 0) >>> (x | 0)) >>> 0) ? (( + (y ? x : ( + mathy4(y, 0x100000001)))) >>> 0) : (Math.atan2(y, x) >>> 0))) | 0) != x))), ((( ~ x) ** Math.fround(Math.min(-0x080000001, Math.fround(Math.min((Math.fround(Math.hypot(Math.fround(( + mathy3(( + x), x))), (x | 0))) | 0), (y | 0)))))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[]); ");
/*fuzzSeed-66366547*/count=412; tryItOut("print(x);const w = /*FARR*/[/(?=(?=[^].|\\2{0})|(.\\w[^]{2})((?!\u62cf{4})(.{4,})).)/im,  /x/ , /[^\\s\u00a5]{2,3}(?:(?:^|\\b)|.+){3,}/gy, , 4].map;");
/*fuzzSeed-66366547*/count=413; tryItOut("\"use strict\"; g0.g0.a0.forEach((function() { for (var j=0;j<1;++j) { g2.f0(j%4==0); } }));");
/*fuzzSeed-66366547*/count=414; tryItOut("\"use strict\"; Array.prototype.pop.call(a1);\n(void schedulegc(g2));\n");
/*fuzzSeed-66366547*/count=415; tryItOut("let(sewvgf, cbvnmg) { for(let b of /*FARR*/[window,  '' , \u3056, \"\\u4DC2\", -24, \"\\uFCE2\", new RegExp(\"[\\\\cT-\\\\x20]\", \"y\"), d]) print(x);}");
/*fuzzSeed-66366547*/count=416; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.min(Math.fround(Math.acosh(y)), Math.fround(( + (( + Math.pow(( + (Math.fround({}) / Math.fround(-Number.MAX_SAFE_INTEGER))), ( + y))) >>> 0)))) << Math.asinh((Math.acosh((y * 42)) >>> 0))); }); testMathyFunction(mathy5, [Math.PI, 2**53-2, -0x07fffffff, Number.MIN_VALUE, -0x080000000, 0x100000001, -0x100000001, -0x0ffffffff, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, 42, 0x100000000, Number.MAX_VALUE, 0x080000001, -(2**53-2), -(2**53+2), -(2**53), 0, -Number.MAX_VALUE, 2**53+2, 2**53, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, 1, 0.000000000000001, 0x0ffffffff, 1.7976931348623157e308, -1/0, 0x080000000, 0x07fffffff]); ");
/*fuzzSeed-66366547*/count=417; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy2(( + ( ! Math.clz32(( + ( - ( + Math.imul(((y < -(2**53)) | 0), ((y & (0x100000000 | 0)) | 0)))))))), ( + (((( ! ((Math.hypot((Math.fround(Math.cos((y >>> 0))) | 0), (Math.log1p(Math.max(Math.fround(x), ( + Math.fround(-0x07fffffff)))) | 0)) | 0) >>> 0)) >>> 0) , ( ! ( + x))) | 0))); }); testMathyFunction(mathy3, [({toString:function(){return '0';}}), (new Boolean(false)), (new Boolean(true)), NaN, false, 0.1, '/0/', 1, '\\0', true, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), null, (new String('')), (new Number(-0)), -0, 0, objectEmulatingUndefined(), undefined, [], '0', '', /0/, (new Number(0)), [0], (function(){return 0;})]); ");
/*fuzzSeed-66366547*/count=418; tryItOut("mathy5 = (function(x, y) { return Math.fround(mathy0((((( - y) >>> 0) * ( ! Math.fround(mathy1(( + Math.min((y & y), ( + Math.atan2(y, Math.atan2(2**53+2, y))))), Math.fround((Math.fround((Math.acos((y | 0)) | 0)) != Math.fround((Math.ceil(-Number.MIN_SAFE_INTEGER) >>> 0)))))))) | 0), (mathy2(Math.fround(((makeFinalizeObserver('nursery')) ** (( /x/ )(/./g)) ^ mathy1(Math.imul(x, y), Math.fround(Math.clz32((mathy4(( + x), x) >>> 0)))))), Math.fround(Math.expm1(( + ( + ((Math.clz32(Math.fround(Math.clz32(Math.fround(y)))) >>> 0) >> ( + 0x100000000))))))) | 0))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 0x0ffffffff, 2**53+2, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, 0x100000001, -0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, -(2**53), 42, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0, -0x100000001, -0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, -(2**53-2), -(2**53+2), Math.PI, Number.MAX_SAFE_INTEGER, 1, 0x080000000, 0/0, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 0x07fffffff, 2**53]); ");
/*fuzzSeed-66366547*/count=419; tryItOut("\"use strict\"; /*hhh*/function sitqnp(x, x = x = Proxy.create(({/*TOODEEP*/})(z), new RegExp(\"(?!(?!((\\\\B)){0,4095}))(?![^])\", \"gyi\")), x, w, d, x = this, b, x, x, NaN, Math, x, y, c, x, b, z = 26, w = /\\\u6ee7/i, z =  '' , this = -10, x, x, eval, x, z, this.a, d, x, w, x,  , x, x, NaN, y, x, eval =  /x/g , x, c, z = ({a1:1}), NaN, NaN, w, y = new RegExp(\"(?!^)\", \"yi\"), x, w, x = window, x = null, y, eval, x, c, w, c, x, x, x, x, e = window, z =  /x/ , a, c, e, c, a, this = new RegExp(\"\\\\b\\\\3+?\", \"m\"), a, \u3056 = 11, c, x, this.x, c, x, eval, x, window, this.e, x, this.y, x, x, x, a){print(x);}/*iii*/v0 = a1.reduce, reduceRight();");
/*fuzzSeed-66366547*/count=420; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -2049.0;\n    var d3 = -8388609.0;\n    var i4 = 0;\n    d3 = (d2);\n    d2 = (d2);\n    switch (((((0x4b8e1ef3) ? (0xf68241b7) : (0xffffffff))) << ((0xc9ed7992)+(0xb99dc145)))) {\n      case 0:\n        d3 = (d1);\n        break;\n    }\n    {\n      return ((((arguments[\"toString\"] = NaN << z))-(0xcd94381d)+((Infinity) != (d1))))|0;\n    }\n    d3 = (d0);\n    (Uint16ArrayView[((0xf85afd92)-((32769.0) != (d1))) >> 1]) = ((/*FFI*/ff(((abs(((((((-0x8000000))>>>((0x4629c43f))) != (0xc40df231))-(0xff20142d)) & (((decodeURI)(\"\\u86EE\".eval(\"mathy2 = (function(x, y) { \\\"use strict\\\"; return Math.atan2(((Math.sinh(Math.fround((( + Math.pow(Math.max(x, y), (x === 42))) >> mathy0(x, ( + (( + y) != y)))))) != Math.fround(( ~ Math.fround(mathy0(( + Math.min(Math.fround(((-(2**53) >>> 0) & Math.fround(0x080000001))), y)), Math.fround(Math.min(Math.fround(Math.trunc(Math.fround(y))), ( - y)))))))) | 0), (Math.imul((( + x) || ( + x)), (( ~ Math.max(Number.MAX_VALUE, mathy0(y, -1/0))) | 0)) , (Math.round(( - x)) ? (Math.asin(((Math.pow(( + x), ( + Math.max(x, Math.atan2(y, x)))) | 0) | 0)) | 0) : (Math.tanh(( + Math.PI)) | 0)))); }); testMathyFunction(mathy2, [2**53, -0x100000001, 0x080000000, 0x07fffffff, 1/0, 0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0, 1, -Number.MAX_VALUE, -(2**53-2), 2**53+2, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, 0x100000000, -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, -Number.MAX_SAFE_INTEGER, -1/0, 0, Math.PI, -0x080000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, -(2**53), 0/0, -0x100000000, 0x080000001]); \"), ( \"use strict\" ) >> this\n)))))|0)), ((-((-36893488147419103000.0)))), ((abs((((0xffffffff)-(-0xee876b)) ^ (((((-0x8000000)) ^ ((-0x8000000)))))))|0)), ((-1025.0)), ((0x2754b147)))|0)-(0xfb9fd782)+(0x8fb974d3));\n    d1 = (d0);\n    switch ((((0xedd5de7c)*-0x58980) | ((((-0x8000000)) & ((-0x8000000)))))) {\n      case 1:\n        d0 = (d0);\n        break;\n      case -3:\n        d2 = (+(1.0/0.0));\n        break;\n      case -1:\n        {\n          (Float64ArrayView[4096]) = ((d1));\n        }\n        break;\n    }\n    return ((((0x69974bc9) ? (({a2:z2})) : (0xffffffff))-(((((0x7a781a1d) ? (0xfcd5ff0) : ((0xffffffff)))-((((0xffffffff)) ^ ((0xfa586709))) >= (((0xe1387ef6)) ^ ((0xfb63f451))))) | ((true)+((((-0x8000000)) >> ((0x280cf15b))) == (~~(d1))))) <= (~~(+/*FFI*/ff((((0xf9024e47) ? (d1) : (d1))), ((((Uint32ArrayView[0])) << ((0x41f218a6) % (0x7fffffff)))), (((((((0xffffffff))>>>((0xf8eacc94))))-((--NaN))))), ((((0xffffffff)) >> ((0xf94b99a9)))), (((Float32ArrayView[4096]))), ((-3.8685626227668134e+25)), ((-18446744073709552000.0)), ((-1.0078125)), ((1048577.0)), ((1099511627776.0)), ((-4398046511103.0)), ((140737488355329.0)), ((8589934593.0)), ((-6.189700196426902e+26)), ((-576460752303423500.0)), ((-4194304.0))))))))|0;\n    {\n      (Uint8ArrayView[4096]) = (((((!(0xe50916b6)))>>>((0xf88af252))))-(0x91a408f2));\n    }\n    {\n      d3 = (-36028797018963970.0);\n    }\n    d3 = ((((((0xf66739e))) / ((+abs(((+abs(((-524289.0)))))))))) * ((+(((((0x76cd2c6f)-(0xfbc04bc7)) | ((0xb06a8c46)*-0xfffff)) / (((0x556ff429)-(i4))|0)) | ((-0x8000000))))));\n    {\n      d2 = ((((!((0x331cbf6f) > (0xa8b8f916))) ? (2.4178516392292583e+24) : (+((d1))))) * ((((0x36b084c)))));\n    }\n    (Float64ArrayView[((0xd7e5a1ee) / (0x279bd06d)) >> 3]) = ((d0));\n    {\nv1 + t0;    }\n    d3 = ((+(((0xffffffff)) | (-0xfffff*(0x5ac78f1a)))) + (d0));\n    {\n      d1 = (d3);\n    }\n    d1 = (+(1.0/0.0));\n    d2 = (-6.189700196426902e+26);\n    d2 = (d2);\n    d3 = (+pow(((NaN)), ((NaN))));\n    d2 = (d2);\n    return (((0x887ef239)-(false instanceof this)))|0;\n  }\n  return f; })(this, {ff: Math.clz32(\"\\u5046\")}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[new Boolean(true), new Number(1.5), new Number(1.5), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), new Number(1.5), new Number(1.5), (1/0), (1/0), new Number(1.5), 0.000000000000001, new Number(1.5), new Boolean(true), 0.000000000000001, new Boolean(true), function(){}, 0.000000000000001, 0.000000000000001, new Boolean(true), function(){}, function(){}]); ");
/*fuzzSeed-66366547*/count=421; tryItOut("mathy1 = (function(x, y) { return Math.max(Math.fround(( ~ Math.fround(mathy0((((( + -0) | 0) ? Math.min(y, y) : (( + (( + y) << x)) >>> 0)) % y), Math.hypot(Math.min(y, (Math.fround((Math.fround(x) / Math.fround(-0x100000000))) | 0)), ( + Math.fround(( ! (y | 0))))))))), (Math.pow(Math.atan((( + Math.hypot((Math.fround(Math.atan2(( ! y), -0x100000001)) >>> 0), ( + (Math.sign(( + x)) <= (((0x100000001 >>> 0) >= (y >>> 0)) >>> 0))))) >>> 0)), (Math.max((((-1/0 | 0) >>> (Math.atan2(Math.fround((( + (0 | 0)) >>> 0)), -0x0ffffffff) | 0)) | 0), ( - Math.fround(Math.cosh(Math.fround(( - Math.fround(x))))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, ['\\0', '/0/', 1, (new Number(0)), [0], -0, /0/, undefined, 0.1, '', true, objectEmulatingUndefined(), NaN, (new String('')), (function(){return 0;}), 0, (new Number(-0)), false, (new Boolean(false)), ({valueOf:function(){return '0';}}), null, '0', (new Boolean(true)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), []]); ");
/*fuzzSeed-66366547*/count=422; tryItOut("/*RXUB*/var r = /\\2{0,}/gyim; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.match(r)); var w = let (x)  /x/g ;");
/*fuzzSeed-66366547*/count=423; tryItOut("/*RXUB*/var r = /(?:(?!((?=[^])*))|\\3)/gm; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-66366547*/count=424; tryItOut("v2 = r1.flags;");
/*fuzzSeed-66366547*/count=425; tryItOut("/*infloop*/for(e; ((function sum_indexing(ziunro, mozqxh) { ; return ziunro.length == mozqxh ? 0 : ziunro[mozqxh] + sum_indexing(ziunro, mozqxh + 1); })(/*MARR*/[new String(''),  /x/g , objectEmulatingUndefined(), new String(''), Number.MIN_VALUE, 2, Number.MIN_VALUE, objectEmulatingUndefined(),  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), 2, Number.MIN_VALUE,  /x/g ,  /x/g ,  /x/g , 2, Number.MIN_VALUE, new String(''), 2,  /x/g , 2, Number.MIN_VALUE, 2, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g , 2, 2, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g , new String(''), new String(''),  /x/g ,  /x/g ,  /x/g , Number.MIN_VALUE,  /x/g , Number.MIN_VALUE, Number.MIN_VALUE,  /x/g ,  /x/g , 2, Number.MIN_VALUE, 2, objectEmulatingUndefined(), 2, new String(''), objectEmulatingUndefined(), objectEmulatingUndefined(), new String(''),  /x/g ,  /x/g , new String(''),  /x/g , 2,  /x/g ,  /x/g , Number.MIN_VALUE,  /x/g , objectEmulatingUndefined(), 2,  /x/g , objectEmulatingUndefined(), Number.MIN_VALUE,  /x/g , new String(''), Number.MIN_VALUE, new String(''), new String(''),  /x/g , Number.MIN_VALUE, 2, 2, Number.MIN_VALUE, 2, 2, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), 2, new String(''), 2, 2, Number.MIN_VALUE, Number.MIN_VALUE, 2, 2,  /x/g , objectEmulatingUndefined(), 2, new String(''), 2, objectEmulatingUndefined(), 2, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE,  /x/g , objectEmulatingUndefined(), new String(''), new String(''), new String(''), 2, Number.MIN_VALUE,  /x/g , objectEmulatingUndefined(), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new String(''), objectEmulatingUndefined(),  /x/g , new String(''), objectEmulatingUndefined()], 0)); x) v2 = new Number(-0);");
/*fuzzSeed-66366547*/count=426; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=427; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( ~ Math.fround(( + ((Math.fround(Math.abs((y / Math.imul(y, (((0x100000000 | 0) === ( + 2**53+2)) | 0))))) | 0) ^ Math.fround(Math.imul(Math.atan2(-0, x), ((((y >>> 0) ? (x | 0) : (x | 0)) | 0) ** (y < (y | 0)))))))))); }); testMathyFunction(mathy0, [false, 1, (new Number(0)), true, objectEmulatingUndefined(), (new Boolean(true)), [0], (new Boolean(false)), ({valueOf:function(){return 0;}}), undefined, null, -0, /0/, (new Number(-0)), (new String('')), 0.1, 0, [], '', '\\0', (function(){return 0;}), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '/0/', NaN, '0']); ");
/*fuzzSeed-66366547*/count=428; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.cosh((Math.expm1((mathy1(( + Math.max(( + (Math.imul((((x << (((( + x) === 2**53+2) >>> 0) | 0)) | 0) | 0), (Math.pow(2**53+2, y) | 0)) | 0)), ( + (Math.hypot((0.000000000000001 | 0), ((Math.expm1(( + x)) >>> 0) | 0)) | 0)))), (((((( - Math.fround(x)) | 0) > x) >>> 0) ? ((Math.log2((( ! y) >>> 0)) >>> 0) | 0) : (x >>> 0)) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, 0, 2**53-2, -Number.MAX_SAFE_INTEGER, 2**53+2, -0, -0x080000000, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53+2), -0x07fffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, -0x100000000, 0.000000000000001, 0/0, 42, 0x080000001, 0x100000000, -1/0, -(2**53), Math.PI, Number.MIN_VALUE, 1/0, Number.MAX_VALUE, 0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-66366547*/count=429; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(Math.atanh(Math.fround((y ? Math.cos(Math.round(2**53-2)) : y)))), (Math.imul((((Math.tan((x != (y / x))) | 0) != Math.fround(( ~ Math.fround(( ~ x))))) >>> 0), ((( ~ (( + ( - ( + ( - 42)))) >>> 0)) | 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [0x080000000, -0x100000001, 0x0ffffffff, 42, 0, -0x080000001, -0, 0x080000001, -1/0, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, 1, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, -0x07fffffff, -(2**53-2), 1.7976931348623157e308, -0x0ffffffff, 0x100000000, 2**53+2, 1/0, 0x100000001, 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53, -Number.MIN_VALUE, Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=430; tryItOut("this.a2.pop();");
/*fuzzSeed-66366547*/count=431; tryItOut("m2.delete(o0);");
/*fuzzSeed-66366547*/count=432; tryItOut("print(x.yoyo(x));");
/*fuzzSeed-66366547*/count=433; tryItOut("mathy5 = (function(x, y) { return mathy0((Math.sign(( + ( - ( + Math.imul(( + y), (Math.PI | 0)))))) == Math.imul(( + (mathy3((( + Math.pow((y | 0), Math.fround(y))) >>> 0), (( ! Math.fround(y)) >>> 0)) >>> 0)), x)), (Math.imul((mathy0(Math.fround(y), (Math.hypot((Math.expm1(x) >>> 0), (y >>> 0)) >>> 0)) >>> 0), (Math.cbrt((((Math.asinh(y) ? Math.atan2(Math.fround(x), Math.fround(-Number.MIN_VALUE)) : (Math.atanh((( ! y) | 0)) | 0)) >>> 0) | 0)) | 0)) ** ( - Math.min(x, (( + x) , ( + y)))))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 0x100000000, 42, 0x0ffffffff, 2**53, -0x080000001, -0x100000000, 2**53+2, 1, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, 0x080000000, -0, -(2**53), -(2**53+2), -0x080000000, 2**53-2, -0x100000001, -0x0ffffffff, 1/0, -(2**53-2), -Number.MIN_VALUE, Math.PI, 0x100000001, 0/0, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=434; tryItOut("for(let y in ((c => ((c)()))((Float64Array.prototype))))if((void options('strict')) instanceof (yield (x) = /*FARR*/[x].some(Math.sign,  \"\" ))) t1.set(t2, 1);");
/*fuzzSeed-66366547*/count=435; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=436; tryItOut("\"use strict\"; \u000clet x, x = x, x;(++eval);");
/*fuzzSeed-66366547*/count=437; tryItOut("do v0 = Object.prototype.isPrototypeOf.call(p1, m0); while(((ArrayBuffer.prototype.slice).call(\u3056, )) && 0);");
/*fuzzSeed-66366547*/count=438; tryItOut("g0.r2 = /(?:((?!(?![^\u0098\\cV-\\u001B]|\\s))))[\\xa7\\xb2]\\W|[^]\\2|(\\u0e03\\B)/yim;");
/*fuzzSeed-66366547*/count=439; tryItOut("Array.prototype.unshift.call(a0, g2.s2);");
/*fuzzSeed-66366547*/count=440; tryItOut("Array.prototype.push.apply(o0.a0, [intern( /x/ ), m1]);");
/*fuzzSeed-66366547*/count=441; tryItOut("m1.has(s2);");
/*fuzzSeed-66366547*/count=442; tryItOut("mathy0 = (function(x, y) { return (( ~ (((((Math.sqrt(( + (Math.imul((( + Math.imul(( + ( + (( + Math.acos(y)) >>> 0))), ( + -0x080000000))) >>> 0), ( + (y ? (( - (x >>> 0)) >>> 0) : Math.log10(x)))) >>> 0))) | 0) >>> 0) || ((( - x) >= (( + (((((( + (( ~ (y >>> 0)) >>> 0)) | 0) | 0) ? (1 ? Math.imul(x, 0/0) : \"\\u184F\") : (x | 0)) | 0) >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, 2**53+2, 0x07fffffff, -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, -0x07fffffff, Math.PI, 2**53-2, Number.MAX_VALUE, -(2**53-2), 0x080000001, -0x0ffffffff, -1/0, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000001, 1.7976931348623157e308, 0/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, 42, 0, 0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0, 0x0ffffffff, Number.MIN_VALUE, 1, -0x080000000, 1/0]); ");
/*fuzzSeed-66366547*/count=443; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(o1.i0, a1);");
/*fuzzSeed-66366547*/count=444; tryItOut("\"use strict\"; yjfvgb((4277));/*hhh*/function yjfvgb(x, b = eval(\"this\", ({a2:z2}))){x[\"trimRight\"]}");
/*fuzzSeed-66366547*/count=445; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=446; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x07fffffff, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53, 0x07fffffff, 2**53+2, 0x080000001, 1/0, 0x0ffffffff, 0x100000001, 0x080000000, 1, -0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, -0, 42, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, 0, 1.7976931348623157e308, -0x080000000, -0x0ffffffff, Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53-2, Math.PI, 0x100000000, -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=447; tryItOut("v2 = (h1 instanceof m0);");
/*fuzzSeed-66366547*/count=448; tryItOut("/*ADP-3*/Object.defineProperty(o0.a1, ({valueOf: function() { Object.prototype.watch.call(v2, new String(\"11\"), (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Uint32ArrayView[((0xd6383368)) >> 2]) = (((x) = x = Proxy.createFunction(({/*TOODEEP*/})(this), function(y) { yield y; print( /x/ );; yield y; }))-(0xfe116801));\n    return (((0xc67f1b45)+(0xbb0e81df)+((0xf928478))))|0;\n    (Float32ArrayView[((0x936697ec)*-0x7b12a) >> 2]) = ((Float32ArrayView[0]));\n;    d0 = (-268435457.0);\n    return (((i1)+((\u3056 = x))))|0;\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)));return 3; }}), { configurable: (x % 58 == 3), enumerable: false, writable: true, value: f1 });");
/*fuzzSeed-66366547*/count=449; tryItOut("mathy3 = (function(x, y) { return Math.imul(Math.min(( ! Math.hypot(y, (((Math.tanh(y) >>> 0) === (y >>> 0)) >>> 0))), ( ! Math.abs(( + -Number.MAX_VALUE)))), ((( + Math.min(Math.asinh(Math.fround(mathy0(Math.fround(y), Math.fround(( + y))))), Math.pow((Math.hypot(Math.round(1/0), ( ~ Math.fround((((x >>> 0) , (y | 0)) | 0)))) | 0), (( ! (( + Math.hypot(( + y), ( + -0x080000000))) >>> 0)) >>> 0)))) + Math.sqrt(x)) >>> 0)); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, 0x080000000, -0, -0x080000000, -1/0, -0x100000000, -0x080000001, 0x0ffffffff, 0x080000001, -(2**53+2), 0/0, 1.7976931348623157e308, 2**53+2, 42, 0x07fffffff, -0x100000001, -(2**53-2), 1/0, -0x0ffffffff, Number.MAX_VALUE, -(2**53), 0x100000000, 1, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=450; tryItOut("/*RXUB*/var r = /./gm; var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-66366547*/count=451; tryItOut("\"use strict\"; b1 = new SharedArrayBuffer(136);");
/*fuzzSeed-66366547*/count=452; tryItOut("g2.v0 = a2.length;");
/*fuzzSeed-66366547*/count=453; tryItOut("return;try { for(let e of /*FARR*/[x, x, .../*FARR*/[.../*FARR*/[], , , , .../*FARR*/[ '' , ...[], ], this, , (w = x)], ...(function() { \"use asm\"; yield (function ([y]) { })(); } })(), , ...TypeError, false]) let(a) { let(e = e, eval, x) ((function(){{}})());} } finally { for(let b in []); } ");
/*fuzzSeed-66366547*/count=454; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=455; tryItOut("h1 = g2.objectEmulatingUndefined();");
/*fuzzSeed-66366547*/count=456; tryItOut("szhdxy();/*hhh*/function szhdxy(){/*MXX1*/o0 = this.g1.Array.prototype.every;}");
/*fuzzSeed-66366547*/count=457; tryItOut("for (var p in t2) { try { v0 = new Number(NaN); } catch(e0) { } try { a2.push(m1); } catch(e1) { } x = g1; }");
/*fuzzSeed-66366547*/count=458; tryItOut("{f2.__iterator__ = (function() { try { a0 + t0; } catch(e0) { } f0(e0); return o0.e2; }); }");
/*fuzzSeed-66366547*/count=459; tryItOut("/*tLoop*/for (let d of /*MARR*/[[undefined], null, [undefined], [undefined], new String('q'), [undefined], ({x:3}), ({x:3}), ({x:3}), new String('q'), null, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), null, [undefined], new String('q'), null, null, [undefined], new String('q'), [undefined], [undefined], new String('q'), ({x:3}), [undefined], null, new String('q'), ({x:3}), [undefined], new String('q'), [undefined], ({x:3}), ({x:3}), null, null, null, null, null, null, ({x:3}), [undefined], ({x:3}), null, ({x:3}), null, null, ({x:3}), ({x:3}), null, null, ({x:3}), ({x:3}), new String('q'), [undefined], new String('q'), ({x:3}), new String('q'), null, [undefined], [undefined], null, null, [undefined], new String('q'), [undefined], new String('q'), new String('q'), ({x:3}), new String('q'), null, ({x:3}), new String('q'), [undefined], new String('q'), null, null, ({x:3}), null, new String('q'), new String('q'), ({x:3}), null, null, new String('q'), new String('q'), ({x:3}), [undefined], new String('q'), new String('q'), [undefined], ({x:3}), [undefined], new String('q'), new String('q'), ({x:3}), [undefined], ({x:3}), new String('q'), null, null, [undefined], ({x:3}), ({x:3})]) { ( /x/ ); }");
/*fuzzSeed-66366547*/count=460; tryItOut("s0 += s1;function x(z) { return function(y) { yield y; with((2).call(false)){const v0 = t1.BYTES_PER_ELEMENT;v2 = Object.prototype.isPrototypeOf.call(o2, b2); }; yield y; }.prototype } g1.t1 = Proxy.create(h2, g2.o0.o0);function window() { \"use strict\"; yield  /x/g  } print([] = x);");
/*fuzzSeed-66366547*/count=461; tryItOut("v2 = evaluate(\"/*RXUB*/var r = new RegExp(\\\"(?=(?:\\\\\\\\xc0|(?=(?!\\\\\\\\3)))?)*|(?:(?:\\\\\\\\d)|\\\\\\\\u7c5D(?!(?=[\\\\\\\\S\\\\\\\\f])|[\\\\\\\\d\\\\\\\\u0020-\\\\\\\\uD08f-\\\\ufcfa\\\\\\\\w\\\\\\\\D]){1,3}|\\\\\\\\S?[^]*?|[\\\\\\\\0\\\\\\\\s\\\\\\\\t-\\\\\\\\0](?!^)?)\\\", \\\"gyim\\\"); var s = \\\"_\\\"; print(s.replace(r, timeout(1800))); \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 2 != 1), noScriptRval: (x % 2 != 0), sourceIsLazy: (({ get 16 x (x, d)(4277), 0: (makeFinalizeObserver('tenured')) })), catchTermination: false }));");
/*fuzzSeed-66366547*/count=462; tryItOut("delete m1[\"getUTCHours\"];");
/*fuzzSeed-66366547*/count=463; tryItOut("Object.prototype.unwatch.call(o0, \"entries\");");
/*fuzzSeed-66366547*/count=464; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-(2**53+2), 0x100000000, -0, -(2**53-2), 0x080000000, 0.000000000000001, 2**53+2, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, -1/0, 0x080000001, 2**53, 0/0, -Number.MIN_VALUE, -0x080000001, -0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, Math.PI, 0x07fffffff, 0, 0x0ffffffff, 0x100000001, Number.MIN_VALUE, 42, 1, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001]); ");
/*fuzzSeed-66366547*/count=465; tryItOut("mathy5 = (function(x, y) { return ( ! Math.fround(Math.fround(((Math.min(x, x) ? 2**53 : x) === (((x >>> 0) & Math.fround(x)) >>> 0))))); }); ");
/*fuzzSeed-66366547*/count=466; tryItOut("\"use strict\"; {\u0009(\"\\u359E\");var e0 = new Set(m1); }");
/*fuzzSeed-66366547*/count=467; tryItOut("v2 = (h1 instanceof v2);");
/*fuzzSeed-66366547*/count=468; tryItOut("with(x)i0.__iterator__ = f2;");
/*fuzzSeed-66366547*/count=469; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(Math.imul(((Math.exp(-Number.MAX_SAFE_INTEGER) | 0) <= Math.fround((((Math.imul(y, 0x100000000) >>> 0) ? (y >>> 0) : y) >>> 0))), Math.log10((((Math.cbrt(( + Number.MIN_SAFE_INTEGER)) | 0) ^ (y >>> 0)) | 0))), (((( ~ (mathy0(( + Math.fround((Math.fround(Math.acos(x)) % Math.fround(0x100000001)))), (( + y) | 0)) >>> 0)) | 0) , ((( + (( + x) ? ( + x) : ( + ( ! y)))) & Math.fround((Math.fround(Math.log1p((x | 0))) ? Math.fround(( + (x | 0))) : Math.fround(( + (Math.fround(mathy0(Math.PI, y)) | 0)))))) | 0)) | 0)); }); testMathyFunction(mathy1, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 0x0ffffffff, -0x100000000, 2**53-2, -(2**53+2), Number.MIN_VALUE, 2**53, 0/0, 0x080000000, -0x080000001, -0, 2**53+2, 1, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 42, Math.PI, -1/0, 0, 1/0, 0x07fffffff, 1.7976931348623157e308, 0x080000001, 0x100000001, -(2**53-2), -0x080000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=470; tryItOut("\"use strict\"; for (var v of p0) { try { m0.delete(f0); } catch(e0) { } try { v1 = r0.test; } catch(e1) { } try { /*MXX1*/o0 = g2.Object.isSealed; } catch(e2) { } s0 += this.s1; }");
/*fuzzSeed-66366547*/count=471; tryItOut(";");
/*fuzzSeed-66366547*/count=472; tryItOut("\"use strict\"; a1.forEach((function(j) { if (j) { try { o0.g2.o2 = t1[8]; } catch(e0) { } s2.__proto__ = o0; } else { /*ADP-2*/Object.defineProperty(o0.a1, 7, { configurable: (x % 11 == 0), enumerable: true, get: (function() { try { /*ADP-2*/Object.defineProperty(a2, ({valueOf: function() { v0 = a0.length;return 18; }}), { configurable: false, enumerable: false, get: (function() { for (var j=0;j<9;++j) { f0(j%5==0); } }), set: (function mcc_() { var wzblkj = 0; return function() { ++wzblkj; if (/*ICCD*/wzblkj % 7 == 2) { dumpln('hit!'); try { i2 = g0.g2.g0.a1.keys; } catch(e0) { } try { m1.set(m1, s1); } catch(e1) { } try { i1 = new Iterator(b1, true); } catch(e2) { } a0.length = 4; } else { dumpln('miss!'); try { Array.prototype.reverse.apply(g2.a2, []); } catch(e0) { } try { for (var v of this.g2) { Array.prototype.push.apply(a1, [i1, e1, e1]); } } catch(e1) { } print(uneval(s2)); } };})() }); } catch(e0) { } try { Array.prototype.pop.call(a0, o0.i0, p2); } catch(e1) { } v2 = evalcx(\"a2.splice(NaN, 15, m2, x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: \\\"\\\\u00FD\\\".toString, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: (encodeURI).call, }; })(window), \\\"\\\\u10FE\\\" in  '' .unshift, x = Proxy.createFunction(({/*TOODEEP*/})([]), this)), f0, v1, e0, g2, p0);\", g2); return h2; }), set: (function(j) { if (j) { try { g0.offThreadCompileScript(\"this.v1 = evaluate(\\\"s0 += 'x';\\\", ({ global: g2.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 5 == 1), sourceIsLazy: false, catchTermination: (x % 20 != 7), element: g2.o1, elementAttributeName: s0, sourceMapURL: this.s0 }));\"); } catch(e0) { } try { v1 = o2[z]; } catch(e1) { } try { g1.toString = Number.prototype.valueOf.bind(v0); } catch(e2) { } e1 + o1; } else { try { v1 + g2.s2; } catch(e0) { } try { t0.toSource = (function() { try { a2[g1.v1] = new (eval)(/(?!\\2(?!.)+\\b|[\\s](\\cD)+?)(?=\\2[^]+?)|(?:\\s)(?:\\B)|${3}[\\w\\u005f\\x15\\cQ](?!^)++?/ym, window).valueOf(\"number\"); } catch(e0) { } try { this.e1.add(o1.o2.v2); } catch(e1) { } s1 = ''; return o2.e1; }); } catch(e1) { } for (var v of s1) { try { print(this.m2); } catch(e0) { } this.i0.toSource = (function mcc_() { var aepqka = 0; return function() { ++aepqka; if (/*ICCD*/aepqka % 11 == 6) { dumpln('hit!'); try { s2 = new String(a2); } catch(e0) { } e1 = Proxy.create(this.h1, s2); } else { dumpln('miss!'); try { m0.get(g2); } catch(e0) { } try { e1.add(h0); } catch(e1) { } o0.__iterator__ = f1; } };})(); } } }) }); } }), this.b0);");
/*fuzzSeed-66366547*/count=473; tryItOut("var iehxcf = new ArrayBuffer(8); var iehxcf_0 = new Uint16Array(iehxcf); iehxcf_0[0] = -10; print(uneval(h1));");
/*fuzzSeed-66366547*/count=474; tryItOut("\"use strict\"; g1.b2 = t1.buffer;");
/*fuzzSeed-66366547*/count=475; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.atan2((( + ((Math.min(Math.hypot(y, x), (y ? Math.min(Math.fround(y), y) : y)) === (( + mathy2(( + Math.min(-0x080000001, x)), ( + (y ? -0 : x)))) >>> 0)) >>> 0)) | 0), ( + Math.abs(Math.fround(Math.hypot(Math.fround(Math.fround(( ~ Number.MIN_SAFE_INTEGER))), Math.fround(Math.acosh(( + ((y | 0) == ( + (Math.hypot((Math.atan2(y, y) | 0), y) | 0))))))))))); }); testMathyFunction(mathy5, [-(2**53-2), 0x0ffffffff, 0x100000001, -(2**53), 0/0, -0x07fffffff, -1/0, 2**53, 1/0, 0.000000000000001, 0x100000000, -0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -0x080000000, 1, -Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, 42, -0, -Number.MAX_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, 0x07fffffff, Number.MIN_VALUE, 0]); ");
/*fuzzSeed-66366547*/count=476; tryItOut("\"use strict\"; for (var v of s2) { try { o1.h0.hasOwn = g0.g2.f1; } catch(e0) { } b1 = new SharedArrayBuffer(20); }");
/*fuzzSeed-66366547*/count=477; tryItOut("mathy3 = (function(x, y) { return (Math.atan2(Math.hypot(Math.min((mathy2(y, (Math.atan2(Math.hypot(y, 0.000000000000001), x) >>> 0)) | 0), ( + ( + ((mathy1((y >>> 0), ( + -Number.MAX_VALUE)) >>> 0) ? Math.sin(( ~ x)) : (x | 0))))), ((Math.expm1(Math.fround(( ~ y))) % x) | 0)), mathy2(Math.min(Math.fround(((Math.atan2(( + y), y) % (x >>> 0)) >>> 0)), Math.sinh(Math.fround((Math.atan2((y | 0), (y >>> 0)) >>> 0)))), Math.max((Math.trunc((((Math.expm1((x | 0)) - x) / (x | 0)) | 0)) | 0), Math.fround(((-0x07fffffff >>> 0) < (y >>> 0)))))) | 0); }); testMathyFunction(mathy3, [-1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, Math.PI, 0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, 1/0, 0, -(2**53), Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, 2**53, 2**53-2, 0x080000001, -0x100000000, 0.000000000000001, -0x100000001, -0x080000001, 0x07fffffff, 42, 2**53+2, 0x100000001, -(2**53+2), -0, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=478; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.hypot((Math.asinh(((mathy2(mathy0((Math.imul((Math.atan2((x >>> 0), (y >>> 0)) >>> 0), x) >>> 0), 0x100000000), (( - ( ! ( - x))) >>> 0)) != Math.max(((Math.atanh(x) + (x | 0)) | 0), (0 | 0))) | 0)) >>> 0), mathy0(( ! Math.max(y, Math.fround(( ! ((Math.fround(( - Math.fround(y))) >>> 0) + ( + 0x0ffffffff)))))), ( + Math.log(( + y))))) >>> 0); }); testMathyFunction(mathy3, [Math.PI, 0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, 42, 0x0ffffffff, 1.7976931348623157e308, -(2**53-2), 2**53-2, -0x07fffffff, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, 0, -0x080000000, 2**53, -0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -(2**53), Number.MAX_VALUE, 2**53+2, 1, -(2**53+2), -0x100000001, -0, 1/0, -Number.MAX_VALUE, 0x100000000, -1/0, 0/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=479; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); \nreturn;function b(\u3056, d =  '' )+function (x, x, c, \u3056, new RegExp(\"(?=.*?)(?:\\\\1|\\\\b\\\\b+?)+(?:[^])|\\\\uEffF|.{1,3}$|[^\\\\cY-A\\u00c8-]\\\\W\\\\f]\\\\xE3\", \"ym\"), c, window, c, x =  /x/ , d, b, this, \"19\", z, a = y, a = -4, b, x, x, b, x, x, x, w, x, window, x, c, NaN = \"\\uB1D1\", y, x, eval, x, ...x) { yield window } .prototype.throw((a ^= w).watch(\"1\", function  x (c)\"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\nvar oiaces = new SharedArrayBuffer(4); var oiaces_0 = new Float64Array(oiaces); oiaces_0[0] = 28; var oiaces_1 = new Int8Array(oiaces); oiaces_1[0] = 6; var oiaces_2 = new Int8Array(oiaces); print(oiaces_2[0]); oiaces_2[0] = 29; for(let [d, d] = \"\\uB315\" in \"\\uD6BA\") {t1.toSource = (function() { s2 += 'x'; return o1.g2; }); }\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    (Uint32ArrayView[0]) = ((i0)+((~~(-274877906944.0)) == (((i1)-(i2)+(i0)) & ((((-0x4986a*(i1))) >= (0x3db8ad61))))));\n    i2 = (!((((imul((i1), ((((0xa00b359b)) << ((0x74acd830)))))|0) / (abs((((i3)) >> (((1.2089258196146292e+24) > (-3.777893186295716e+22)))))|0))>>>(0x84900*(i0)))));\n    i1 = ((((1))|0) == (imul(((-590295810358705700000.0) == (-1.0009765625)), ((+((-131073.0))) >= (+((((((1125899906842624.0)) - ((-9.44473296573929e+21)))) / ((-3.777893186295716e+22)))))))|0));\n    {\n      i0 = (i1);\n    }\n    i2 = (i0);\n    i0 = (((((((i1)-((0x7f5049f1) >= (0x7fffffff)))>>>(((void shapeOf((4277))))*-0x3ab2e)) > (0xbbbf81e1))+(i0))>>>(((((((0x2889d622))>>>((0xf90ba0e8))) / (0x0))>>>((i0)-((140737488355329.0) > (-1073741825.0))+(i1)))))));\n    (Float32ArrayView[2]) = ((-4.722366482869645e+21));\n    (Float64ArrayView[((i0)) >> 3]) = ((((+abs(((295147905179352830000.0))))) * ((562949953421313.0))));\n    {\n      i2 = (i0);\n    }\n    i2 = ((((!(1))+(i2)) & ((i1)+(i3)+(i0))));\n    return ((((((i1)) << ((-0x8000000)+((abs((((0xff21c764)-(0x2b3d6afd))|0))|0) > ((((0x226f9979))) ^ ((1)))))))+(((((((-1.0625) > (3.022314549036573e+23)))|0) / (~(0xfffff*(i2)))) ^ ((((((-70368744177664.0) >= (-17592186044416.0))-((((0xffffffff)) << ((-0x8000000))) <= (((-0x57d5432)) << ((0xe5d94a45)))))|0)))) == (0x348f2ba3))))|0;\n    i3 = (i2);\n    return (((i1)))|0;\n  }\n  return f;))Array.prototype.shift.apply(a0, []);");
/*fuzzSeed-66366547*/count=480; tryItOut("v1 = x;");
/*fuzzSeed-66366547*/count=481; tryItOut("mathy4 = (function(x, y) { return Math.fround((Math.fround(Math.imul(y, (((( ! (Math.fround(Math.pow(Math.fround(x), Math.fround((y * Math.exp(y))))) | 0)) | 0) ? mathy1(x, x) : Math.fround((x ? Math.atanh(-Number.MIN_SAFE_INTEGER) : Math.fround((Math.clz32(x) | 0))))) >>> 0))) + ( + Math.max(( + Math.cosh((Math.fround(Math.ceil(Math.fround(Math.imul(Math.fround(x), x)))) % 0x100000000))), ( + (Math.imul((0x0ffffffff !== x), ( + (((Math.clz32(y) & ( ! (( + Math.max(( + x), ( + x))) >>> 0))) | 0) - ( + y)))) >>> 0)))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 1.7976931348623157e308, 1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, -(2**53+2), 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -0x0ffffffff, -0x07fffffff, -0x100000001, 0/0, -Number.MAX_VALUE, -0x100000000, -0x080000001, 0x080000001, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 2**53, -0x080000000, 1, Number.MAX_VALUE, 42, 0x07fffffff, -0, 0x100000000, Math.PI]); ");
/*fuzzSeed-66366547*/count=482; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var acos = stdlib.Math.acos;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      /*FFI*/ff(((imul((i0), (0xfe870cc7))|0)), ((Infinity)), ((((0x1b148d0a)*-0x29f3) >> (((((0xfbe1ae4e)) | ((-0x8000000))) <= (((0xaedde28a)) >> ((0xa0582d56))))))));\n    }\n    (Float64ArrayView[(((((Uint32ArrayView[((0x632273cb)) >> 2]))>>>((0x0) / (0xc713488c))))-(0x5dd0be79)) >> 3]) = ((d1));\n    (Int16ArrayView[0]) = (((((i0)-((+acos(((d1)))) != (d1))) >> ((0xc45baa94))) < (abs((((i0)+(i0)+(0xfc58a385)) << ((i0)*0xce41a)))|0))+((((0x31410a27)) & ((i0))) > (abs((((((0xa367d5df))>>>((0x7354d8e1))) / (0x6c58df76)) ^ ((0xb924200c))))|0)));\n    d1 = ((((+(1.0/0.0))) - (x)) + (d1));\n    (Float64ArrayView[2]) = ((+(-1.0/0.0)));\n    return +((-562949953421313.0));\n  }\n  return f; })(this, {ff: SharedArrayBuffer.prototype.slice}, new ArrayBuffer(4096)); ");
/*fuzzSeed-66366547*/count=483; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.asin(Math.fround(( + mathy2(((Math.log10(y) | 0) | 0), Math.pow(( + x), Math.fround(Math.hypot((y % y), y))))))); }); ");
/*fuzzSeed-66366547*/count=484; tryItOut("\"use strict\"; o1.o1 = Proxy.create(h0, o0);");
/*fuzzSeed-66366547*/count=485; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((Math.atan2(((Math.pow(x, 1.7976931348623157e308) - (Math.max((Math.clz32((-0x100000001 | 0)) | 0), x) | 0)) ? ((((Math.sinh((Math.cos(y) >>> 0)) >>> 0) || (x >>> 0)) >>> 0) >>> 0) : Math.abs((mathy2((-(2**53+2) >>> 0), (x >>> 0)) >>> 0))), ((mathy0(Number.MAX_VALUE, Math.round(mathy1(x, y))) == (Math.min(( + ( + ( ! (0.000000000000001 | 0)))), y) >>> 0)) >>> 0)) - (Math.fround(( - Math.fround(( ! Math.fround(Math.imul(x, y)))))) | 0)) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[-3/0, [], (1/0)]); ");
/*fuzzSeed-66366547*/count=486; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[new String(''), x, new String(''), function(){}, function(){}, function(){}, function(){}, function(){}, x, 0x100000001, new String(''), function(){}, x, function(){}, new String(''), 0x100000001, x, new String(''), new String(''), new String(''), 0x100000001, new String(''), function(){}, x, function(){}, x, x, new String(''), 0x100000001, new String(''), new String(''), new String(''), function(){}, 0x100000001, function(){}, function(){}, x, x, x, 0x100000001, x, 0x100000001, function(){}, new String('')]) { ( \"\" ); }");
/*fuzzSeed-66366547*/count=487; tryItOut("with({c: x = null})g2.o0.o2.v0 = (i2 instanceof o0);");
/*fuzzSeed-66366547*/count=488; tryItOut("\"use strict\"; b0 = this.t0[({valueOf: function() { Array.prototype.shift.apply(a0, []);return 14; }})];/*vLoop*/for (vbklch = 0; vbklch < 40; ++vbklch) { e = vbklch; (void schedulegc(g0)); } ");
/*fuzzSeed-66366547*/count=489; tryItOut("c = linkedList(c, 2976);");
/*fuzzSeed-66366547*/count=490; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - ( - Math.sinh((Math.hypot(( + Math.hypot(( + Number.MAX_SAFE_INTEGER), ( + mathy1(Math.fround(y), -0x07fffffff)))), ((( ! x) >>> 0) , x)) | 0)))); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 42, -0x080000001, -(2**53-2), -(2**53), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, 1, 0, -0x100000000, 0.000000000000001, 2**53-2, 0x080000001, -Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x080000000, 1/0, -0x100000001, 0x100000000, Number.MAX_VALUE, 0x0ffffffff, 0x080000000, 2**53, Math.PI, 0x100000001, 1.7976931348623157e308, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=491; tryItOut("mathy3 = (function(x, y) { return (Math.acosh(Math.fround(mathy2(Math.fround(Math.max((Math.min(( ! x), (y | 0)) | 0), Math.fround((Math.imul((y | 0), (x | 0)) === Math.fround(x))))), Math.fround(( ~ x))))) !== ((Math.imul((mathy0(y, x) ? y : -Number.MAX_VALUE), ((Math.fround(mathy1(Number.MAX_VALUE, x)) && (Math.min(x, y) | 0)) >>> 0)) | 0) - ((x <= Math.imul((Math.trunc(x) >>> 0), y)) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[(0/0), function(){}, (0/0), new String(''), new String(''), new String('q'), function(){}, new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new String(''), new String('q'), (0/0), new String(''), (0/0), new String(''), (0/0), function(){}, new String('q'), new String(''), function(){}, function(){}, new String(''), function(){}, new String('q'), new String(''), new String('q'), function(){}, function(){}, new String('q'), (0/0), new String('q'), function(){}, new String('q'), function(){}, new String('q'), new String('q'), new String(''), (0/0), function(){}, (0/0), function(){}, new String(''), (0/0), new String('q'), (0/0), new String('q'), function(){}, function(){}, new String(''), (0/0), function(){}, function(){}, function(){}, function(){}, new String(''), new String('q'), function(){}, function(){}, new String('q'), function(){}, (0/0), function(){}, function(){}, function(){}, new String('q'), (0/0), new String('q'), function(){}, new String(''), new String(''), (0/0), function(){}, function(){}, function(){}, new String('q'), (0/0), (0/0), function(){}, function(){}, function(){}, new String(''), function(){}, (0/0), (0/0), function(){}, new String(''), (0/0), function(){}, (0/0), (0/0), new String('q'), function(){}, function(){}, function(){}, (0/0), (0/0), new String('q'), new String(''), (0/0), new String(''), function(){}, function(){}, new String(''), new String('q'), new String('q'), function(){}, function(){}, (0/0), function(){}, function(){}, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (0/0), function(){}, new String(''), new String(''), new String(''), (0/0), function(){}, function(){}, function(){}, new String('q'), function(){}, function(){}, function(){}, (0/0), new String(''), (0/0), function(){}, new String('q'), (0/0), function(){}, function(){}, (0/0), new String('q'), new String(''), (0/0), new String('q'), function(){}, new String('q'), new String('q'), new String(''), new String(''), (0/0), function(){}, function(){}]); ");
/*fuzzSeed-66366547*/count=492; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + Math.max(( + ((Math.clz32((Math.fround(( ! Math.fround(x))) >>> 0)) >>> 0) ** Math.hypot((Math.fround(y) >>> Math.min(Math.fround(Math.atanh(Math.fround(y))), ( + x))), Math.fround(( ! (((Math.cos(x) | 0) < x) | 0)))))), Math.fround(Math.tan(Math.fround(Math.max(Math.fround(Math.fround((Math.fround(Math.fround(Math.hypot(Math.fround(x), Math.fround(Math.imul(y, ( + x)))))) + Math.fround((Math.cos((y | 0)) | 0))))), Math.fround(( + x)))))))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, 0x080000000, -0x080000001, -(2**53+2), 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 1, 2**53+2, -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, -0x07fffffff, 0.000000000000001, 1/0, -0, Math.PI, 0x080000001, 2**53-2, 0/0, -0x080000000, -0x100000001, 42, 1.7976931348623157e308, -Number.MIN_VALUE, -1/0, 0, 0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=493; tryItOut("this.m0.get(v1);");
/*fuzzSeed-66366547*/count=494; tryItOut("\"use strict\"; this.v0 = t1.BYTES_PER_ELEMENT;");
/*fuzzSeed-66366547*/count=495; tryItOut("a = this;let (x) { a0 = arguments; }function window(x, {c: {}, \u3056, eval: [[{w, x: [, ]}, , {NaN, \"15\": {y: {y: {}}, e, e: d}, x: {b: x}, \u3056: y, \u3056: /(?=[^]|^+$[^\\\u38e8\\f-\\0\u5960]\\v.($)*)/gm.NaN}, ], , , (void options('strict_mode')), , [(z ** function ([y]) { })(2733437692)], ]}, x, setter, x) { return x } v2 = g0.eval(\"function o1.f2(g2)  { \\\"use strict\\\"; yield x.eval(\\\"x = p2;\\\").watch(\\\"callee\\\", offThreadCompileScript) } \");");
/*fuzzSeed-66366547*/count=496; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=497; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((((0xedd79c09) % (((0x7c0e50c2) % (0x462fc723))>>>(((0x190b6c7d) ? (0xa2668211) : (0x86410a0f))+((0xe78dbae0) ? (0x7e5a53f7) : (0x6332cc72)))))>>>((0xffffffff)+(/*FFI*/ff(((+(0.0/0.0))))|0)+((+((+pow(((-7.555786372591432e+22)), ((127.0)))))) >= (-3.022314549036573e+23)))) / ((((0x97ec88b5) >= (0xffffffff))-(x))>>>((i1)))))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[null, null, x, new Boolean(true), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  /x/ , null, x, null, null,  /x/ , x,  /x/ , x, null, x, x, null, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x, x, new Boolean(true), x, x, x, null,  /x/ , x,  /x/ , null,  /x/ , x, x,  /x/ , x, x, new Boolean(true), null,  /x/ , x, new Boolean(true), x,  /x/ , x, x, x, new Boolean(true),  /x/ , x, new Boolean(true), new Boolean(true), x, x, new Boolean(true), new Boolean(true), new Boolean(true),  /x/ , new Boolean(true), x, new Boolean(true), new Boolean(true),  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), null, x, x, x]); ");
/*fuzzSeed-66366547*/count=498; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( ! Math.fround(( + ( + (( + ((Math.fround(Math.atan(x)) | 0) == ( + Math.max(y, (1.7976931348623157e308 === x))))) <= y))))); }); testMathyFunction(mathy0, [Math.PI, Number.MIN_VALUE, -0x0ffffffff, 1, 0, 2**53, 0x080000000, 1.7976931348623157e308, -(2**53+2), -Number.MAX_VALUE, 0x100000001, 0/0, -Number.MIN_VALUE, -0x080000001, -0, Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53-2), 0.000000000000001, 1/0, Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, -0x080000000, 42, 2**53+2, 0x100000000, -0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-66366547*/count=499; tryItOut("print(m0);");
/*fuzzSeed-66366547*/count=500; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.min(Math.imul(Math.atan2(Math.min(Number.MAX_VALUE, x), (Math.atan2(-(2**53), ( + x)) * y)), (Math.ceil((( ! y) >>> 0)) | 0)), Math.max(((Math.fround(Math.max(-0x080000000, y)) ? (mathy0(-0x07fffffff, y) >>> 0) : (x | 0)) >>> 0), Math.fround(Math.sqrt(Math.fround(( + ((y | 0) + (y | 0)))))))) & Math.imul(Math.abs((Math.asinh(( + y)) >>> 0)), ((Math.tanh(((Math.sinh((0x080000001 | 0)) | 0) | 0)) | 0) + Math.max(x, ( + y))))); }); testMathyFunction(mathy1, [0x07fffffff, -(2**53-2), 0x080000000, -Number.MAX_SAFE_INTEGER, -0, 0x100000001, -Number.MIN_VALUE, 2**53, -0x100000001, -Number.MAX_VALUE, 1.7976931348623157e308, -1/0, -(2**53), 2**53+2, 0/0, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, 0.000000000000001, 1, -0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, 42, -(2**53+2), 0, -0x080000000, 0x0ffffffff, -0x080000001, 2**53-2, -0x100000000]); ");
/*fuzzSeed-66366547*/count=501; tryItOut("/*vLoop*/for (let badmrb = 0; badmrb < 5; ++badmrb) { var c = badmrb; v2 = a1.length;function c()windowprint(true); } ");
/*fuzzSeed-66366547*/count=502; tryItOut("\"use strict\"; /*ODP-1*/Object.defineProperty(t1, \"getMinutes\", ({configurable: (x % 47 == 20), enumerable: false}));");
/*fuzzSeed-66366547*/count=503; tryItOut("mathy1 = (function(x, y) { return (( + ( + ( ! (Math.min(( + ( ! ( + 0/0))), y) | 0)))) | (mathy0((( ~ Math.fround(x)) | 0), (Math.max(Number.MAX_SAFE_INTEGER, (( + Math.atan2(( + ( ! ( + Math.atan2(x, 2**53)))), ( + (((y >>> 0) << (y >>> 0)) >>> 0)))) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy1, /*MARR*/[ \"use strict\" , -Infinity, this.__defineSetter__(\"eval\", String.prototype.italics), this.__defineSetter__(\"eval\", String.prototype.italics),  \"use strict\" , this.__defineSetter__(\"eval\", String.prototype.italics), this.__defineSetter__(\"eval\", String.prototype.italics),  /x/g , -Infinity, this.__defineSetter__(\"eval\", String.prototype.italics), -Infinity,  /x/g ,  /x/g , -Infinity,  \"use strict\" , this.__defineSetter__(\"eval\", String.prototype.italics), this.__defineSetter__(\"eval\", String.prototype.italics), function(){}, this.__defineSetter__(\"eval\", String.prototype.italics), -Infinity, -Infinity,  /x/g ,  /x/g , this.__defineSetter__(\"eval\", String.prototype.italics), this.__defineSetter__(\"eval\", String.prototype.italics),  /x/g , -Infinity, function(){}, -Infinity]); ");
/*fuzzSeed-66366547*/count=504; tryItOut("print((void version(180)));");
/*fuzzSeed-66366547*/count=505; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + ( + ( + (Math.exp(Math.min((((Math.fround(Math.min(( + -(2**53-2)), ( + x))) / x) >>> 0) | 0), x)) | 0)))) * ( + (( + Math.atan(Math.atanh(Math.hypot(-Number.MAX_VALUE, (y | 0))))) | 0))); }); ");
/*fuzzSeed-66366547*/count=506; tryItOut("mathy0 = (function(x, y) { return Math.cosh((Math.log(Math.trunc((( + x) >>> 0))) >>> 0)); }); ");
/*fuzzSeed-66366547*/count=507; tryItOut("\"use strict\"; /*MXX1*/o0 = g1.Uint32Array.BYTES_PER_ELEMENT;");
/*fuzzSeed-66366547*/count=508; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((d0));\n  }\n  return f; })(this, {ff: (w, b) =>  { \"use strict\"; v1 = NaN; } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0x07fffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, 0x100000000, 0/0, -0, Math.PI, -0x100000001, -0x100000000, 0.000000000000001, 1.7976931348623157e308, 1/0, -Number.MAX_VALUE, 42, 0x100000001, 0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, 0x080000001, -Number.MIN_VALUE, -(2**53), -0x0ffffffff, -1/0, 2**53+2, -(2**53+2), 1, 2**53, Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=509; tryItOut("v1 = this.g0.runOffThreadScript();");
/*fuzzSeed-66366547*/count=510; tryItOut("\"use strict\"; const NaN = 9, lwpmrg, x, x = null, zqswju, xbjsrz, ixahjc, x, uwqkdl, x;((4277));");
/*fuzzSeed-66366547*/count=511; tryItOut("M:with((function  z (w) { return x } (\u3056)))var jfqzid = new ArrayBuffer(4); var jfqzid_0 = new Int16Array(jfqzid); print(jfqzid_0[0]); var jfqzid_1 = new Float32Array(jfqzid); print(jfqzid_1[0]); e0.add(o0);for (var v of g1.i0) { print(g1.b2); }v2 = false;");
/*fuzzSeed-66366547*/count=512; tryItOut("for (var v of e1) { e1 = new Set(this.f2); }");
/*fuzzSeed-66366547*/count=513; tryItOut("v2 = true;");
/*fuzzSeed-66366547*/count=514; tryItOut("v1 = evaluate(\"function this.f2(f1)  { {(({a1:1})); } } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 == 2), noScriptRval: (x % 47 == 20), sourceIsLazy: x, catchTermination: false, elementAttributeName: o0.g1.s2 }));");
/*fuzzSeed-66366547*/count=515; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((d0));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-1/0, -Number.MAX_SAFE_INTEGER, -0, 1, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000001, 2**53-2, -0x100000000, 0x100000001, -Number.MAX_VALUE, -0x080000001, 0/0, -(2**53-2), 1/0, 42, Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, 2**53, 0x080000001, Number.MAX_VALUE, -0x0ffffffff, Math.PI, 0x080000000, -0x07fffffff, 1.7976931348623157e308, 0x0ffffffff, 0, 2**53+2, -(2**53+2), -Number.MIN_VALUE, -0x080000000]); ");
/*fuzzSeed-66366547*/count=516; tryItOut("e1.add(m1);");
/*fuzzSeed-66366547*/count=517; tryItOut("\"use strict\"; e1.add(a1);");
/*fuzzSeed-66366547*/count=518; tryItOut("with({}) try { for(let x in []); } catch(d) { return ((Math.hypot([,,z1], this)) = z = get); } print(x);\nArray.prototype.forEach.call(a0, /*wrap1*/(function(){ \"use strict\"; return Math.exp})());\n");
/*fuzzSeed-66366547*/count=519; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=520; tryItOut("/*infloop*/for(var w = (Function)(); (/*UUV1*/(y.big = ({a2:z2}))).eval(\"/* no regression tests found */\"); [1]) /*hhh*/function atuziu(x, y){print(/(?:(?=(?=\\2)*?))*/gi);}/*iii*/;\nv0 = evaluate(\"new RegExp(\\\"(?=(?:\\\\\\\\b))|(?!\\\\\\\\1{1,5}[\\\\u00f0]|^^*){0,}\\\", \\\"gym\\\")\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /*RXUE*/new RegExp(\"\\\\2|(?!\\\\B)|\\\\b{0,3}*\", \"gim\").exec(\"\") | function(id) { return id }.valueOf(\"number\"), noScriptRval: true, sourceIsLazy: true, catchTermination: (x % 5 == 4) }));\n");
/*fuzzSeed-66366547*/count=521; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float64ArrayView[0]) = ((+(0.0/0.0)));\n    d1 = (1.125);\n    i0 = ((0xffffffff));\n    d1 = (d1);\n    (Float64ArrayView[((0xffffffff)-(0x7f3b1ff5)) >> 3]) = ((d1));\n    return +(((+(0.0/0.0)) + (+(-1.0/0.0))));\n  }\n  return f; })(this, {ff: mathy0}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MAX_VALUE, -1/0, -0x0ffffffff, 0x100000000, 0.000000000000001, -0x080000000, 2**53, -0, 0x07fffffff, 0x100000001, -0x07fffffff, 2**53+2, 1.7976931348623157e308, -0x100000001, 42, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x0ffffffff, -0x080000001, -(2**53-2), 0, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 2**53-2, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -(2**53), Number.MIN_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=522; tryItOut("const hfvsbn, einbec, w, y, z, lypanm, eval;v2 = Object.prototype.isPrototypeOf.call(m2, g2);");
/*fuzzSeed-66366547*/count=523; tryItOut("/*tLoop*/for (let y of /*MARR*/[['z'], ['z'], 0.1, ({x:3}), 0.1, 0.1, 0.1, ({x:3}), ['z'], ['z'], ({x:3}), ['z'], ['z'], ({x:3}), 0.1, ({x:3}), 0.1, ({x:3}), 0.1, ({x:3}), ['z'], 0.1, ['z'], 0.1, 0.1, ['z'], ({x:3}), ({x:3}), 0.1, ({x:3}), 0.1, 0.1, ({x:3}), ({x:3}), 0.1, ({x:3}), ({x:3}), 0.1]) { ([1,,]); }do /*infloop*/ for (x[\"valueOf\"] of  '' ) \n{g2.offThreadCompileScript(\"mathy0 = (function(x, y) { return ( - (Math.min((((((Math.min(x, (Math.min((Number.MIN_VALUE >>> 0), (2**53 >>> 0)) >>> 0)) > ( ! x)) | 0) == (( ! (y / y)) | 0)) | 0) | 0), (( - ((Math.atan2((( + Math.atan2(1/0, 0x100000001)) >>> 0), (x | 0)) | 0) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [0x07fffffff, 2**53+2, Math.PI, 0/0, 1/0, 0x080000001, 42, -Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 0x0ffffffff, -0, 2**53-2, -0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000001, 1, 0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), 0.000000000000001, 2**53, 0x080000000]); \"); } while((Math.imul( /* Comment */({wrappedJSObject:  '' , window: w }), new (((void version(180))).getUTCSeconds)(x))) && 0);");
/*fuzzSeed-66366547*/count=524; tryItOut("Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-66366547*/count=525; tryItOut("testMathyFunction(mathy4, /*MARR*/[null, function(){}, null, (-1/0), null,  '\\0' ,  '\\0' , function(){}, true, function(){}, (-1/0), null, (-1/0), null, true, function(){}, true, function(){}, null]); ");
/*fuzzSeed-66366547*/count=526; tryItOut("\"use strict\"; (function(id) { return id });t1[12];");
/*fuzzSeed-66366547*/count=527; tryItOut("{/*MXX2*/g0.DataView = this.g0; }");
/*fuzzSeed-66366547*/count=528; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53-2), Number.MAX_VALUE, 1/0, 0x100000001, -Number.MAX_VALUE, Math.PI, -0x0ffffffff, -Number.MIN_VALUE, -0x080000001, 1, -1/0, -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53), 0x100000000, 0x080000001, 2**53+2, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, -0, -0x080000000, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53-2, 0, 2**53, 0x0ffffffff, -0x100000000, 0.000000000000001, 0/0]); ");
/*fuzzSeed-66366547*/count=529; tryItOut("for(let c of [x]) {}return;");
/*fuzzSeed-66366547*/count=530; tryItOut("var voatvq, cgjkid, w;for (var v of g2.i1) { try { Object.defineProperty(o0, \"g1.v2\", { configurable: true, enumerable: true,  get: function() {  return a0.some((function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (!((~((i1)+(i1)+(i0))) < (((i1)+(i1)) >> (((0x0) != (0xf43ec54c))-(i1)))));\n    return (((-0x384b42d) % (imul(((0x0) > (0x0)), ((((((0xfeb81557)) << ((0x44d5f69e))) % (0x5614ad7f))>>>(-0x92955*(i1)))))|0)))|0;\n  }\n  return f; })(this, {ff: Object}, new ArrayBuffer(4096)), (4277)); } }); } catch(e0) { } try { v0 = (a2 instanceof e2); } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(g2, o1.g0); }");
/*fuzzSeed-66366547*/count=531; tryItOut("\"use strict\"; e2.has(this.g2.o0);");
/*fuzzSeed-66366547*/count=532; tryItOut("\"use strict\"; \"use asm\"; testMathyFunction(mathy5, [0.000000000000001, 1, Number.MIN_VALUE, 2**53, 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, 0x080000000, -0x080000001, 42, 1.7976931348623157e308, -0x100000000, -(2**53-2), -1/0, -(2**53), 0x100000000, Math.PI, -0x07fffffff, 2**53+2, -0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0, -(2**53+2), 0/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, -0, -0x0ffffffff, -0x100000001, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=533; tryItOut("mathy3 = (function(x, y) { return (Math.sin((( + Math.acosh(( + mathy0(x, -1/0)))) | 0)) | 0); }); testMathyFunction(mathy3, [-0x100000001, Number.MIN_VALUE, 42, -(2**53), -0x080000001, -(2**53+2), 0x100000001, 2**53, 0x100000000, -Number.MAX_VALUE, -1/0, 0x080000000, 0.000000000000001, -0x080000000, 0x0ffffffff, Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, 0, Number.MIN_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, 1, -0x07fffffff, Math.PI, -(2**53-2), -0x0ffffffff, -0x100000000, 2**53+2, 0x080000001, 1/0, -Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=534; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, -0x080000001, 0, 0x080000000, -0x07fffffff, -(2**53+2), -0x100000000, -0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, 0.000000000000001, 2**53, -(2**53-2), 1.7976931348623157e308, -0, Number.MAX_VALUE, 0x07fffffff, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -0x100000001, 1, -Number.MIN_VALUE, -0x080000000, 0x100000000, -Number.MAX_VALUE, Math.PI, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-66366547*/count=535; tryItOut("\"use strict\"; i1.send(b0);");
/*fuzzSeed-66366547*/count=536; tryItOut("\"use strict\"; e2 + '';");
/*fuzzSeed-66366547*/count=537; tryItOut("t2 = new Uint16Array(t1);for (var p in e1) { o2 = {}; }");
/*fuzzSeed-66366547*/count=538; tryItOut("this.h0.__proto__ = g1.i1;");
/*fuzzSeed-66366547*/count=539; tryItOut("");
/*fuzzSeed-66366547*/count=540; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=541; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(( + Math.max(( + Math.acos(Math.fround(Math.min(Math.fround(( - Math.sign(-Number.MAX_SAFE_INTEGER))), x)))), ( + ( + Math.asinh(( + Number.MIN_VALUE))))))), Math.fround(( ~ mathy0(Math.imul(x, y), (Math.atan2(y, Math.fround(Math.atan(Math.fround(x)))) - Math.round(( ~ y)))))))); }); testMathyFunction(mathy3, /*MARR*/[ /x/ , false,  /x/ , (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined()]); ");
/*fuzzSeed-66366547*/count=542; tryItOut("(false);\nv0 = g1.eval(\"window;\");\n");
/*fuzzSeed-66366547*/count=543; tryItOut("e2.has(\"\\u961D\");");
/*fuzzSeed-66366547*/count=544; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0, Number.MIN_VALUE, -Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, 2**53-2, 0x100000001, 1, 0x100000000, 0x080000000, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53, -(2**53+2), -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, 0x07fffffff, Math.PI, 0x080000001, Number.MAX_VALUE, -0x100000001, -1/0, 2**53+2, -0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, -0x080000000, 0, 0x0ffffffff, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=545; tryItOut("/*infloop*/ for  each(Function in \"\\uDDD8\") v2 = Object.prototype.isPrototypeOf.call(g0.a0, e1);");
/*fuzzSeed-66366547*/count=546; tryItOut("\"use strict\"; v2 = 4;");
/*fuzzSeed-66366547*/count=547; tryItOut("return;");
/*fuzzSeed-66366547*/count=548; tryItOut("\"use strict\"; r0 = new RegExp(\"(?![^](^)+?)\", \"i\");");
/*fuzzSeed-66366547*/count=549; tryItOut("/*vLoop*/for (var utwgxr = 0; utwgxr < 30; ++utwgxr, null) { var b = utwgxr; g2.h1.get = (function() { try { a1.sort((function() { for (var j=0;j<89;++j) { f0(j%2==1); } }), o0, e0); } catch(e0) { } o0 = o0.__proto__; throw s0; }); } ");
/*fuzzSeed-66366547*/count=550; tryItOut("throw StopIteration;");
/*fuzzSeed-66366547*/count=551; tryItOut("print(uneval(g2));\na2.pop();\n( \"\" );");
/*fuzzSeed-66366547*/count=552; tryItOut("mathy5 = (function(x, y) { return Math.fround((Math.fround(mathy4(( + Math.atanh(Math.fround(mathy1(mathy3(x, ( + ((( ! ( + y)) | 0) !== ( + y)))), x)))), (Math.atan2(Math.atan2((-Number.MAX_VALUE , 0/0), Math.pow((x >>> 0), (y | 0))), Math.fround(Number.MIN_VALUE)) | 0))) & Math.fround((( + Math.imul((mathy1(Math.fround(y), 0/0) | 0), (0/0 | 0))) >>> 0)))); }); testMathyFunction(mathy5, [true, (new Number(0)), objectEmulatingUndefined(), undefined, ({toString:function(){return '0';}}), '\\0', '/0/', (new Boolean(false)), [0], (function(){return 0;}), (new Number(-0)), 0, [], /0/, 0.1, NaN, '', ({valueOf:function(){return 0;}}), (new Boolean(true)), '0', ({valueOf:function(){return '0';}}), 1, null, (new String('')), false, -0]); ");
/*fuzzSeed-66366547*/count=553; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.max(Math.fround(( ! (Math.asin(Math.atan2(Math.tanh((Math.fround(x) ? Math.fround(y) : x)), ((mathy0(y, x) | 0) | y))) >>> 0))), Math.tan(Math.fround(( + ( + y))))) | 0); }); testMathyFunction(mathy4, [[0], '0', (new Boolean(true)), ({toString:function(){return '0';}}), (new Number(-0)), true, '', 0, ({valueOf:function(){return '0';}}), '/0/', undefined, objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), [], NaN, -0, (new Number(0)), null, (new Boolean(false)), (new String('')), 1, (function(){return 0;}), false, '\\0', /0/]); ");
/*fuzzSeed-66366547*/count=554; tryItOut("");
/*fuzzSeed-66366547*/count=555; tryItOut("\"use strict\"; Object.seal(h0);function z(...a)\"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    (Int8ArrayView[((0x6a718808)-(-0x8000000)-(!(!((0x1cd4e66) ? (-0x8000000) : (0x179faff7))))) >> 0]) = (((((( /x/ .yoyo(/\\u8071/yim.valueOf(\"number\"))) == (((0xf0f3de77))>>>((0x9ebbfc0e))))-(0x539c8557)) & (((imul(((0x4ae5f9b3)), (0x15d9737))|0) > (imul((i2), (i2))|0)))))-(0xf8c62261)-((Infinity) == (((-2.0)) - ((d1)))));\n    return ((((-((8589934593.0))) > (d1))))|0;\n  }\n  return f;v2 = g2.r2.unicode;");
/*fuzzSeed-66366547*/count=556; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0x100000000, 0, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, -0x07fffffff, 2**53+2, 2**53-2, 0x100000000, 1/0, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 2**53, -0x080000001, -1/0, 0.000000000000001, -0x100000001, 42, 1, 0x100000001, -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=557; tryItOut("g1.toSource = (function(j) { if (j) { i0.next(); } else { try { i1.send(p0); } catch(e0) { } try { a2[11]; } catch(e1) { } try { /*MXX3*/g2.Math.tanh = g2.Math.tanh; } catch(e2) { } m1.toSource = (function mcc_() { var voiagx = 0; return function() { ++voiagx; f2(/*ICCD*/voiagx % 3 == 0);};})(); } });");
/*fuzzSeed-66366547*/count=558; tryItOut("o2.g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 3), noScriptRval: false, sourceIsLazy: (x.__defineSetter__(\"NaN\", Date.prototype.toDateString)), catchTermination: false, element: this.o2, elementAttributeName: s1 }));");
/*fuzzSeed-66366547*/count=559; tryItOut("testMathyFunction(mathy0, [[0], 1, ({valueOf:function(){return '0';}}), 0, -0, ({toString:function(){return '0';}}), '\\0', 0.1, (new Boolean(false)), (function(){return 0;}), '0', (new Boolean(true)), false, (new Number(0)), [], ({valueOf:function(){return 0;}}), '', '/0/', true, objectEmulatingUndefined(), NaN, (new String('')), undefined, null, (new Number(-0)), /0/]); ");
/*fuzzSeed-66366547*/count=560; tryItOut("v1 = evalcx(\"\\\"use strict\\\"; v2 = evaluate(\\\"(4277)\\\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: 16.__defineSetter__(\\\"x\\\", ({/*TOODEEP*/})), noScriptRval: (x % 5 == 4), sourceIsLazy: this.__defineGetter__(\\\"x\\\", window), catchTermination: (x % 5 == 0) }));\", g0);");
/*fuzzSeed-66366547*/count=561; tryItOut("\"use strict\"; t0 = new Uint8Array(v2);");
/*fuzzSeed-66366547*/count=562; tryItOut("\"use strict\"; /*infloop*/do {print(/^\\w|\\3{0}(?!$)?|\\B*.^{3}|\\S{3,}|(?=(?=\\d))/gym);(-15); } while(true);");
/*fuzzSeed-66366547*/count=563; tryItOut("t2 = t2.subarray(5, 15);");
/*fuzzSeed-66366547*/count=564; tryItOut("g1.valueOf = (function(j) { if (j) { Array.prototype.unshift.call(a0, v2, f2, p0); } else { g2.v2 = Object.prototype.isPrototypeOf.call(f1, o1); } });");
/*fuzzSeed-66366547*/count=565; tryItOut("let (e = x ^ (window.prototype), szvuym, kqvprp) { s0 += 'x'; }");
/*fuzzSeed-66366547*/count=566; tryItOut("let (mxront, x, e, d, x, this = new RegExp(\"[^]|(([^\\u30de\\\\uCFe2\\\\ud58e\\\\f-\\u00a3][^])){3,3}+?\", \"\").yoyo(this), NaN, jzzrxp, sgrkau, uwdhpa) { print((4277));function eval(NaN, y, NaN, y, x, x, a =  /x/g , e, x, e, window, \u3056, x, z, x, w, w, b, w, x, x, x, NaN, x, eval, d =  \"\" , NaN, x, y, x, w, d, x) { return /*UUV1*/(w.getOwnPropertySymbols = (1 for (x in []))) }  '' ; }\nlet z = (4277);x = i0;\n");
/*fuzzSeed-66366547*/count=567; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var sqrt = stdlib.Math.sqrt;\n  var Infinity = stdlib.Infinity;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d1 = (+/*FFI*/ff((Math.max(-16, this)), ((d1)), ((d0)), ((~~(+((d0))))), ((d0)), ((67108863.0)), ((-9007199254740992.0)), ((((0x4cfdd05b))|0)), ((((0x3ba66c8d)) & ((0x10523da7)))), ((9223372036854776000.0)), ((8796093022209.0))));\n    }\n    d0 = (((d1)) % ((d1)));\n    {\n      d1 = (d0);\n    }\n    d0 = (d1);\n    d0 = (8388608.0);\n    (Uint8ArrayView[((0xf8c78c0d)) >> 0]) = (((((-0x8000000))>>>((({x: (0 !==  /x/ )}))+(x))))-(((((((0xe2e7acd3)*-0x8000c) & ((0xa8669911) / (0xffffffff))) == (imul(((0xffffffff)), (0x8240121b))|0))+((/*FFI*/ff(((0x40396177)), ((147573952589676410000.0)), ((-32769.0)), ((1152921504606847000.0)))|0) ? ((0x1dad26be) >= (0x3c808f0c)) : ((0xffffffff)))) >> ((((0x2d0add61) % (0x365e7cbd))>>>((Int16ArrayView[((0xf4779052)) >> 1]))) % (0xe9a6c48c)))));\n    d0 = (-0.00390625);\n    d1 = (1099511627777.0);\n    {\n      d1 = (+sqrt(((+((((~(((d1) > (d0)))) != (~~(d0))))>>>((0x1fb421f0)))))));\n    }\n    d0 = (-1.0625);\n    return ((((((/*FFI*/ff(((d1)), (((4277))), ((d0)), ((((!(0xd25b6e2e))) ^ ((0x21e8655b)))), ((((295147905179352830000.0)) - ((1.2089258196146292e+24)))), ((((0xfe7fe8b2)) & ((0x2c6599f2)))), ((268435456.0)))|0)) & ((0x5ad25863)+(!((((Infinity)) / ((d1))) < (((d1)) - (((-6.189700196426902e+26) + (-3.022314549036573e+23)))))))))))|0;\n    {\n      d0 = (-33554433.0);\n    }\n    d0 = (d0);\n    {\n      d0 = (d1);\n    }\n    switch ((((4277)) & (0x3be01*(-0x8000000)))) {\n      default:\n        d1 = (-((d1)));\n    }\n    {\n      d0 = (((NaN)) % ((+(1.0/0.0))));\n    }\n    return (((0xfe6cdfef)-(0xaaee5b05)))|0;\n    return ((((((0x86cfe345)-(0x15b97b36)) & (((((0xffffffff) != (0xbe75f8b5)))>>>(((0xffffffff) ? (0xe9292cca) : (0x8e50828a))+((0x0) < (0xf46376c5)))) / (((0xd5a310c4)+((imul((0x551e0c2e), (0xfc06c457))|0)))>>>(((((0x9b1b5a1f))>>>((0xffffffff))))-((0x7fffffff) <= (0x3dfd2b4b)))))))))|0;\n    d0 = (d0);\n    return ((((+/*FFI*/ff((((((((0x129e3062) ? (-262145.0) : (-274877906945.0)) != (+(0.0/0.0))))) >> ((((-0x8000000))|0) % (~((0xffffffff)))))), ((0x1a6627b0)), ((((0xffffffff)-(0xfa83822b)+(0x20346b34)) | ((0x4d569eba)+(0xfdf0180c)+(0xa152c010)))))) >= (d0))+(/*MARR*/[x, -0x080000001, -0x080000001, (-1/0), objectEmulatingUndefined(), (-1/0), x, -0x080000001].map(neuter))+((0xfbd28c97) ? (0x2792f9ff) : (-0x8000000))))|0;\n  }\n  return f; })(this, {ff: function (\u3056, \u3056) { yield allocationMarker() ? undefined : ((function sum_slicing(fpcpjs) { ; return fpcpjs.length == 0 ? 0 : fpcpjs[0] + sum_slicing(fpcpjs.slice(1)); })(/*MARR*/[function(){}, -0x07fffffff, -0x07fffffff, window, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), window, -0x07fffffff, function(){}, function(){}])).valueOf(\"number\") } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000000, -Number.MAX_SAFE_INTEGER, 0, -(2**53-2), 42, -Number.MIN_VALUE, 0x080000001, -0x080000001, Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 0.000000000000001, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 0x100000001, -0x100000001, 1.7976931348623157e308, -(2**53), -0x080000000, -(2**53+2), -Number.MAX_VALUE, -0x100000000, -0x07fffffff, -0, 2**53, 1, -1/0, -Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, 0x0ffffffff, 1/0, Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-66366547*/count=568; tryItOut("NaN;\na2[v1] = [z1];\n");
/*fuzzSeed-66366547*/count=569; tryItOut("for (var p in g1) { try { o2 = Object.create(s1); } catch(e0) { } ; }");
/*fuzzSeed-66366547*/count=570; tryItOut("\"use asm\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    return +((33554433.0));\n  }\n{ sameZoneAs: x, cloneSingletons: (x % 3 == 0) }  return f; })(this, {ff: e => (SharedArrayBuffer.prototype.slice)(new RegExp(\"(?!\\\\2)+\", \"g\"), 14)}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0.000000000000001, -0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, -0x080000001, -0, 42, -(2**53), 0x0ffffffff, Math.PI, -0x07fffffff, -(2**53-2), 0/0, 2**53-2, -0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, 0x100000000, 0, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, Number.MIN_VALUE, 0x07fffffff, 0x100000001, 1, 2**53+2, 2**53, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=571; tryItOut("m0.get(i2);");
/*fuzzSeed-66366547*/count=572; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-66366547*/count=573; tryItOut("/*tLoop*/for (let y of /*MARR*/[ /x/g , arguments.callee, arguments.callee, arguments.callee,  /x/g , new Number(1), new Number(1),  /x/g ,  /x/g ,  /x/g , new Number(1), arguments.callee,  /x/g ,  /x/g , new Number(1),  /x/g , new Number(1), new Number(1), new Number(1),  /x/g , new Number(1), new Number(1), arguments.callee,  /x/g , arguments.callee,  /x/g ,  /x/g , arguments.callee, arguments.callee, arguments.callee, arguments.callee,  /x/g , new Number(1), new Number(1), arguments.callee,  /x/g , arguments.callee, new Number(1), arguments.callee, arguments.callee, new Number(1),  /x/g , new Number(1), new Number(1), arguments.callee, arguments.callee,  /x/g , arguments.callee,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , arguments.callee,  /x/g , arguments.callee, arguments.callee,  /x/g , new Number(1), arguments.callee, arguments.callee, new Number(1), arguments.callee, new Number(1), arguments.callee, new Number(1), new Number(1),  /x/g , arguments.callee,  /x/g , arguments.callee, new Number(1),  /x/g ,  /x/g , new Number(1), new Number(1), arguments.callee, arguments.callee]) { Array.prototype.splice.apply(a2, [NaN, ({valueOf: function() { v1 = null;return 19; }}), p1, f1, v0, !y, h0]); }");
/*fuzzSeed-66366547*/count=574; tryItOut("t1.set(a1, 15);");
/*fuzzSeed-66366547*/count=575; tryItOut("v1 = (g1 instanceof b1);");
/*fuzzSeed-66366547*/count=576; tryItOut("/*bLoop*/for (sqbcvk = 0; sqbcvk < 38; ++sqbcvk, (let (w) w)) { if (sqbcvk % 6 == 5) { switch(new RegExp(\"(?!(?=\\\\n)|\\\\B+|([\\u00b7-\\\\u46b5\\\\u0080-\\\\x3d\\\\S\\\\B-\\u8492])?\\\\3{4294967296,})\", \"y\").__defineSetter__(\"NaN\", Math.floor)) { default:  }let w = delete b.e; } else { /*RXUB*/var r = new RegExp(\"[^\\\\ueF28-\\\\u542F\\\\cE-\\\\f\\\\0-\\\\u00d4Z](.\\\\B)(\\\\d|(?:\\\\u00B4))|((?:\\\\b))*(?:($|.)?[^][\\\\r-\\u00df\\\\\\u5ce7]*{3,5})*?\", \"i\"); var s = \"\\uef28a\"; print(s.match(r)); print(r.lastIndex);  }  } ");
/*fuzzSeed-66366547*/count=577; tryItOut("print(x);\n/*MXX3*/g2.Date.prototype.toDateString = g2.Date.prototype.toDateString;\n");
/*fuzzSeed-66366547*/count=578; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.sinh(( ~ ((( + (((y === -0x07fffffff) ? ( + 0x100000000) : x) >>> 0)) ? ( ! Math.sinh(y)) : y) | 0))); }); testMathyFunction(mathy1, [-0x080000000, -0, -(2**53), -Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, Math.PI, 1, -Number.MIN_SAFE_INTEGER, 1/0, 0, 2**53+2, 42, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, -0x100000001, 2**53, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, 0.000000000000001, 0x080000001, 0x100000001, -1/0, -0x080000001, 0x080000000, -0x100000000]); ");
/*fuzzSeed-66366547*/count=579; tryItOut("i2 + '';");
/*fuzzSeed-66366547*/count=580; tryItOut("\"use strict\"; /*vLoop*/for (let dhblph = 0; ( /x/ .valueOf(\"number\")) && dhblph < 5; ++dhblph) { const d = dhblph; p1 + v2; } ");
/*fuzzSeed-66366547*/count=581; tryItOut("mathy0 = (function(x, y) { return ( + (((((x - x) >>> 0) != (( + (( - (y ? (x ^ (y & y)) : Math.max(Number.MIN_VALUE, (y >>> 0)))) ? ( - x) : ( + Math.fround(( - y))))) | 0)) >>> 0) ? Math.cbrt((Math.max(Math.fround(( + x)), ( + x)) | 0)) : (Math.hypot(Math.fround(Math.fround(Math.hypot((( - x) >>> 0), y))), (( + ((Math.sign((Math.hypot(Math.PI, Number.MAX_VALUE) >>> 0)) >>> 0) >>> (Math.log1p(Math.fround(Math.acosh((Math.min((x >>> 0), x) >>> 0)))) >>> 0))) | 0)) | 0))); }); testMathyFunction(mathy0, [-(2**53-2), 0x100000001, 1, -0x080000000, 0, Number.MIN_VALUE, Math.PI, -1/0, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53+2), -0x07fffffff, 1/0, 2**53+2, -0, 1.7976931348623157e308, 0.000000000000001, -0x100000001, 0x080000000, 0x07fffffff, -0x0ffffffff, -Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), 2**53, 0x100000000, 42, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=582; tryItOut("h2.toSource = (function() { m2.has(p2); return this.e0; });");
/*fuzzSeed-66366547*/count=583; tryItOut("Array.prototype.shift.apply(a0, [f2, g2, this.s1]);");
/*fuzzSeed-66366547*/count=584; tryItOut("this.t1[({valueOf: function() { a1 = Array.prototype.map.apply(a0, [f2, o0.i0]);return 19; }})] = (x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function() { return true; }, get: undefined, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })(23), x));");
/*fuzzSeed-66366547*/count=585; tryItOut("");
/*fuzzSeed-66366547*/count=586; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -36028797018963970.0;\n    var i3 = 0;\n    var i4 = 0;\n    return (((/*FFI*/ff(((((i3)-(0xffffffff)+(i0)) << ((i0)*-0x26449))), ((((~~((+(1.0/0.0)))) % ((Float32ArrayView[((0x3818cfbf)-(0xfb751519)) >> 2]))) << ((+(1.0/0.0))))), ((~~(36028797018963970.0))), (((i0) ? (+abs(((-33554433.0)))) : (d2))), ((d2)), ((d1)), ((-562949953421313.0)))|0)+(i0)))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: (x.delete).apply, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { var prop = x[name]; return (typeof prop) === 'function' ? prop.bind(x) : prop; }, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: /*wrap3*/(function(){ \"use strict\"; var liwxzw =  \"\" ; ( /x/g )(); }), keys: function() { throw 3; }, }; })}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [NaN, ({valueOf:function(){return 0;}}), 0.1, '\\0', (new Number(0)), -0, ({valueOf:function(){return '0';}}), (function(){return 0;}), [], (new Boolean(true)), (new String('')), undefined, null, objectEmulatingUndefined(), [0], ({toString:function(){return '0';}}), /0/, (new Boolean(false)), '', true, '/0/', 1, 0, (new Number(-0)), false, '0']); ");
/*fuzzSeed-66366547*/count=587; tryItOut("g0.p0 + '';");
/*fuzzSeed-66366547*/count=588; tryItOut("testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, 2**53, -(2**53-2), 0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, 0/0, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 2**53-2, 42, -0x080000000, 1.7976931348623157e308, 0x100000000, -(2**53+2), 1/0, 2**53+2, -0x0ffffffff, 0.000000000000001, -1/0, 0, 1, -0x080000001, 0x100000001, -(2**53)]); ");
/*fuzzSeed-66366547*/count=589; tryItOut("(\"\\u7CE5\");2;");
/*fuzzSeed-66366547*/count=590; tryItOut("Array.prototype.push.apply(a0, [b0, o1, p0, s2]);\ne1.delete(this.t1);\n");
/*fuzzSeed-66366547*/count=591; tryItOut("m0.has(e2);");
/*fuzzSeed-66366547*/count=592; tryItOut("/*tLoop*/for (let d of /*MARR*/[['z'], undefined, undefined, undefined, eval, new Boolean(false), eval, eval, new Boolean(false), ['z'], ['z'], eval, ['z'], ['z'], eval, eval, new Boolean(false), ['z'], ['z'], ['z'], undefined, eval, ['z'], eval, new Boolean(false), new Boolean(false), undefined, eval, ['z']]) { v2 = (p2 instanceof g2.o0.o2.o0); }");
/*fuzzSeed-66366547*/count=593; tryItOut("Object.defineProperty(this, \"o0.v1\", { configurable: x, enumerable: false,  get: function() {  return evaluate(\"/*MXX1*/o1 = g0.g0.Array.prototype.copyWithin;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /*MARR*/[new String(''),  /x/ , new String(''), new String(''), new String('')], noScriptRval: true, sourceIsLazy: (x % 3 != 0), catchTermination: x })); } });");
/*fuzzSeed-66366547*/count=594; tryItOut("\"use strict\"; h0.hasOwn = (4277);\nreturn window;\n");
/*fuzzSeed-66366547*/count=595; tryItOut("g1.i1.next();");
/*fuzzSeed-66366547*/count=596; tryItOut("v2 = Object.prototype.isPrototypeOf.call(s2, t2);");
/*fuzzSeed-66366547*/count=597; tryItOut("\"use asm\"; m0.get(f0);");
/*fuzzSeed-66366547*/count=598; tryItOut("mathy4 = (function(x, y) { return ( ! ( + ((Math.fround(Math.exp(( + x))) << (Math.min(Math.fround(mathy3(Math.fround(( ! Math.fround((Math.fround(x) , Math.fround(y))))), Math.fround(Math.log1p(x)))), ((((x | 0) ? (Math.cbrt(y) | 0) : (x | 0)) | -(2**53)) | 0)) >>> 0)) | 0))); }); ");
/*fuzzSeed-66366547*/count=599; tryItOut("\"use strict\"; testMathyFunction(mathy4, [2**53, -(2**53+2), 2**53-2, 0x080000000, 1/0, 0.000000000000001, 0/0, -Number.MIN_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, -Number.MAX_VALUE, 2**53+2, -0, Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, -0x080000000, -0x0ffffffff, -0x07fffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53-2), 0x07fffffff, -0x100000001, 1, 42, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), 1.7976931348623157e308, 0x100000001]); ");
/*fuzzSeed-66366547*/count=600; tryItOut("const c, vcjdkm, NaN = ((yield ((void options('strict'))))), wxdtuj, x, x = (window = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })((((4277)).call( '' , 22 ? this : NaN, 19))), null));with({w: 21})continue ;");
/*fuzzSeed-66366547*/count=601; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    d0 = (d1);\n    d0 = (((Float64ArrayView[((0x2c7107dc)) >> 3])) * ((d0)));\n    i2 = (0x408ae3ad);\n    return (((!(((x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: decodeURI, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { throw 3; }, fix: function() { return []; }, has: undefined, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: /[^]/im, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })( '' ), {} ,  /x/ ))) >= (0x432fefa8)))))|0;\n  }\n  return f; })(this, {ff: Map}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x100000000, -1/0, -0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, -0, Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53), 1, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, Math.PI, Number.MAX_VALUE, 0, -Number.MIN_VALUE, 42, -0x07fffffff, 0x0ffffffff, 0.000000000000001, 0x100000001, 1/0, 0x07fffffff, 2**53-2, 2**53+2, -(2**53-2), -Number.MAX_VALUE, 2**53, -0x100000001, 0x080000001]); ");
/*fuzzSeed-66366547*/count=602; tryItOut("g2.g2.v2 = 4.2;");
/*fuzzSeed-66366547*/count=603; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -262145.0;\n    d0 = (d2);\n    return (((0xf95545a7)))|0;\n  }\n  return f; })(this, {ff: window ? x : Math.max(arguments, 22)}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x080000000, 0, -0x0ffffffff, Math.PI, -0x080000001, 1, 0/0, 0x080000001, 0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -0x100000001, 0x0ffffffff, -1/0, -0x07fffffff, -(2**53), Number.MAX_VALUE, 42, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, 2**53-2, -(2**53-2), 2**53+2, -Number.MAX_VALUE, 2**53, Number.MIN_VALUE, 1/0, 0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=604; tryItOut("m0.set(/*UUV2*/(x.find = x.repeat), p0);");
/*fuzzSeed-66366547*/count=605; tryItOut("\"use strict\"; a0.unshift(this.h1);");
/*fuzzSeed-66366547*/count=606; tryItOut("for (var v of e1) { try { m2.set(a1, x); } catch(e0) { } try { Array.prototype.unshift.apply(a2, [timeout(1800)]); } catch(e1) { } try { o1.m1.set(o0, t2); } catch(e2) { } s0 + e0; }");
/*fuzzSeed-66366547*/count=607; tryItOut("{s0 += s2; }");
/*fuzzSeed-66366547*/count=608; tryItOut("mathy1 = (function(x, y) { return mathy0((Math.min(Math.min(( + Number.MAX_SAFE_INTEGER), x), (Math.atanh((y | 0)) | 0)) >>> 0), ((Math.log1p((Math.min(y, x) >>> 0)) >>> 0) >>> 0)); }); ");
/*fuzzSeed-66366547*/count=609; tryItOut("if((x % 45 == 0)) {o0.e0.delete(h2);v2 = Object.prototype.isPrototypeOf.call(o0, g1); }");
/*fuzzSeed-66366547*/count=610; tryItOut("(void schedulegc(g0.g2));");
/*fuzzSeed-66366547*/count=611; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ~ (((((mathy1((Math.fround(Math.tanh(( + (( - (x | 0)) | 0)))) >>> 0), (x | 0)) | 0) & ((Math.imul((( + ((( ! (x >>> 0)) >>> 0) ** (mathy0(Math.fround(x), ( + -0x07fffffff)) | 0))) >>> 0), y) && (( + (((mathy3((x | 0), (x | 0)) | 0) >>> 0) ? ( + y) : ( + y))) & (( ~ (y >>> 0)) >>> 0))) | 0)) <= (( + ( ! ( + (mathy1(y, ((Math.min((y >>> 0), (((( + ( - x)) | 0) < 2**53) >>> 0)) >>> 0) >>> 0)) >>> 0)))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [2**53, 2**53-2, -0x100000001, 0.000000000000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 1, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, -0x080000001, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, -0x080000000, 0x100000001, -0x100000000, Math.PI, 1/0, Number.MIN_VALUE, 2**53+2, 0, -0x07fffffff, -(2**53+2), 0/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53)]); ");
/*fuzzSeed-66366547*/count=612; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=613; tryItOut("if((x % 28 == 26)) print(x); else  if (x) var pztnii = new ArrayBuffer(8); var pztnii_0 = new Uint16Array(pztnii); var pztnii_1 = new Uint8ClampedArray(pztnii); pztnii_1[0] = -24; var pztnii_2 = new Uint8Array(pztnii); var pztnii_3 = new Int32Array(pztnii); return [z1,,];undefined;Array.prototype.forEach.apply(a0, [(function(j) { if (j) { try { v2 = (p2 instanceof h0); } catch(e0) { } try { o1.g1.v2 = Object.prototype.isPrototypeOf.call(m0, h1); } catch(e1) { } v1 = g0.eval(\"i0 = new Iterator(h2);\"); } else { try { m1.get(p2); } catch(e0) { } try { ; } catch(e1) { } try { for (var p in v2) { try { v0 = g2.m2.get(g2.m0); } catch(e0) { } try { m1.has(v2); } catch(e1) { } v0 + ''; } } catch(e2) { } e1 + g0; } })]);;");
/*fuzzSeed-66366547*/count=614; tryItOut("v1 = evalcx(\"e0.has(i2);\", this.g1);");
/*fuzzSeed-66366547*/count=615; tryItOut("mathy5 = (function(x, y) { return ( - Math.pow((x < (( + (mathy3((((-Number.MAX_VALUE , x) >>> 0) >>> 0), (x << x)) >>> 0)) ^ (( + Math.min(Math.atan2(x, y), y)) >> x))), ( ~ ( + (y / x))))); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 1, -Number.MIN_VALUE, 0.000000000000001, Math.PI, 0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), 0x080000001, 2**53, -0x080000000, -0x0ffffffff, 1.7976931348623157e308, -0x100000001, -(2**53-2), 42, 0x0ffffffff, -0x07fffffff, 0x100000001, -0, -0x080000001, -1/0, 1/0, 0, -0x100000000, 0/0, -Number.MAX_VALUE, -(2**53), 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000]); ");
/*fuzzSeed-66366547*/count=616; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( - mathy1(Math.cosh(Math.fround(Math.imul(Math.fround(y), Math.fround(Math.fround((mathy2((y > (y | 0)), x) !== (-Number.MIN_VALUE >>> 0))))))), ( + Math.atan2((Math.min((Math.fround(-Number.MAX_SAFE_INTEGER) | x), y) >>> 0), (( + ( ! ( + (Math.max((x >>> 0), ((( ~ (x >>> 0)) >>> 0) >>> 0)) >>> 0)))) >>> 0))))) >>> 0); }); ");
/*fuzzSeed-66366547*/count=617; tryItOut("");
/*fuzzSeed-66366547*/count=618; tryItOut("let y = eval(\"x\", x);/*ODP-3*/Object.defineProperty(m2, \"entries\", { configurable: (y % 17 != 16), enumerable: false, writable: (y % 5 == 3), value: o0.e2 });");
/*fuzzSeed-66366547*/count=619; tryItOut("/*infloop*/L:while(x & (function(y) { \"use strict\"; return this }((Math.hypot(-13, this)), \"\\uF7B1\")))for (var p in t1) { try { print(uneval(g2.s1)); } catch(e0) { } f0 = (function(j) { if (j) { try { Array.prototype.unshift.call(a2, b1); } catch(e0) { } Object.freeze(m2); } else { try { o2 = Object.create(h0); } catch(e0) { } /*RXUB*/var r = r1; var s = \"\\u000c\\u008b\"; print(s.search(r)); print(r.lastIndex);  } }); }");
/*fuzzSeed-66366547*/count=620; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.max(Math.log10(Math.fround(( + Math.fround(y)))), ((Math.cosh(Math.fround(x)) | 0) > Math.atan2((Math.max((x >>> 0), (x >>> 0)) >>> 0), ((x === y) | 0)))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, 2**53+2, 0x100000000, -(2**53-2), 0.000000000000001, -0x100000001, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53), -0x100000000, -0x080000000, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, -Number.MIN_VALUE, 2**53-2, 0x080000000, Math.PI, -(2**53+2), -1/0, 0x080000001, 0x100000001, 0x0ffffffff, 1/0, -0x080000001, 0x07fffffff, -0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, 0, Number.MIN_VALUE, 42]); ");
/*fuzzSeed-66366547*/count=621; tryItOut("v0 = g1.runOffThreadScript();");
/*fuzzSeed-66366547*/count=622; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log((( ! (Math.round((( ~ 0) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[[(void 0)], -0x100000001, -0x100000001, new Boolean(false), new Boolean(false), [(void 0)], -0x100000001, function(){}, [(void 0)], function(){}, {x:3}, [(void 0)], {x:3}, -0x100000001, -0x100000001, -0x100000001, -0x100000001, {x:3}, -0x100000001, [(void 0)], [(void 0)], new Boolean(false), function(){}, function(){}, function(){}, -0x100000001, new Boolean(false), {x:3}, -0x100000001, {x:3}, new Boolean(false)]); ");
/*fuzzSeed-66366547*/count=623; tryItOut("{ void 0; void schedulegc(this); }");
/*fuzzSeed-66366547*/count=624; tryItOut("\"use strict\"; {v1 = g0.runOffThreadScript(); }");
/*fuzzSeed-66366547*/count=625; tryItOut("for([c, z] = this\n in (let (c)  \"\" .throw(x))) {let (e) { /*MXX1*/o1 = g0.Array.prototype.every;new RegExp(\"(?=(\\\\2))|\\\\1\", \"gy\").watch(new String(\"8\"), x); }Array.prototype.sort.call(a1, (function(j) { if (j) { try { /*ODP-2*/Object.defineProperty(o0, new String(\"0\"), { configurable: (4277), enumerable: (x % 39 != 8), get: /*wrap2*/(function(){ var anxqmg = (4277); var nohshl = q => q; return nohshl;})(), set: function(y) { yield y; ;; yield y; } }); } catch(e0) { } try { g2.a2.reverse(); } catch(e1) { } try { for (var v of m1) { a2 = Array.prototype.map.apply(a1, [(function() { try { Object.seal(i1); } catch(e0) { } try { m0 + ''; } catch(e1) { } try { a0.toSource = (function mcc_() { var tbdufd = 0; return function() { ++tbdufd; if (true) { dumpln('hit!'); s2 += 'x'; } else { dumpln('miss!'); try { v2 = (v2 instanceof e2); } catch(e0) { } v0 = Object.prototype.isPrototypeOf.call(h2, p1); } };})(); } catch(e2) { } Array.prototype.shift.apply(this.a2, []); return s1; }), a2]); } } catch(e2) { } print(uneval(g1.a1)); } else { try { a2.pop(h1, s2); } catch(e0) { } try { o2 = g0.__proto__; } catch(e1) { } try { this.v0 = (b0 instanceof s0); } catch(e2) { } t0.toString = (function() { for (var j=0;j<35;++j) { f1(j%2==0); } }); } }), z, t1); }");
/*fuzzSeed-66366547*/count=626; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-66366547*/count=627; tryItOut("let (cymkwx, obpgfv) { print(x);function eval(x)\u000c { h0.enumerate = f1; } m0.set(b2, o2.b1); }");
/*fuzzSeed-66366547*/count=628; tryItOut("\"use strict\"; /*bLoop*/for (rodhmc = 0; rodhmc < 54 && ([,]); ++rodhmc) { if (rodhmc % 6 == 1) { g2.v2 = Object.prototype.isPrototypeOf.call(p0, f2); } else { v1 = Object.prototype.isPrototypeOf.call(o0, p1); }  } ");
/*fuzzSeed-66366547*/count=629; tryItOut("/*RXUB*/var r = /(?:\\1)?|((?:\\3*)){2,6}+/m; var s = \"\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\\n\\n\\n\\n\\n\\n\\u0082\\n\"; print(s.replace(r, '\\u0341', \"gm\")); print(r.lastIndex); v2 = Object.prototype.isPrototypeOf.call(o0.e1, t0);");
/*fuzzSeed-66366547*/count=630; tryItOut("v0 = Object.prototype.isPrototypeOf.call(f2, v0);");
/*fuzzSeed-66366547*/count=631; tryItOut("v0 = Object.prototype.isPrototypeOf.call(t0, m1);");
/*fuzzSeed-66366547*/count=632; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.fround(( + (( + 1/0) >>> 0)))); }); testMathyFunction(mathy3, [0x07fffffff, 2**53, -Number.MAX_VALUE, -(2**53+2), -0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), 1, 2**53+2, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 0/0, -0x0ffffffff, 0x100000001, 0x080000000, -0x07fffffff, 2**53-2, -0x100000000, -0x080000001, 0.000000000000001, 0x0ffffffff, Math.PI, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0, 0x080000001, 42, -0x080000000, Number.MAX_VALUE, -0x100000001, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-66366547*/count=633; tryItOut("o1.g0.v0 = evalcx(\"/*hhh*/function qwhfmc(){v1 = (t1 instanceof a0);}qwhfmc(-16);\\nprint(f2);\\n\", g1);");
/*fuzzSeed-66366547*/count=634; tryItOut("e0.add(v0);");
/*fuzzSeed-66366547*/count=635; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.sign(mathy0((( + Math.max(( + ( + (y | x))), Math.imul(Math.fround((mathy0(x, mathy0(0x0ffffffff, y)) & ((((y >>> 0) >> (( ~ y) >>> 0)) >>> 0) | 0))), x))) >>> 0), Math.fround((x ? ((Math.expm1(y) || x) , ((y > (x | 0)) | 0)) : Math.clz32(y))))); }); testMathyFunction(mathy3, [1/0, 0x07fffffff, Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000000, -Number.MIN_VALUE, 2**53+2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), 1.7976931348623157e308, 2**53, 0x100000001, 0x080000001, 0/0, -0x100000000, Math.PI, 42, -0x080000000, -0x0ffffffff, -Number.MAX_VALUE, -1/0, -0x100000001, -0, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=636; tryItOut("let(c) { with({}) this.zzz.zzz = w;}x.stack;");
/*fuzzSeed-66366547*/count=637; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=638; tryItOut("\"use strict\"; for(let b in []);");
/*fuzzSeed-66366547*/count=639; tryItOut("\"use strict\"; this.s0 += s2;");
/*fuzzSeed-66366547*/count=640; tryItOut("p2 + '';");
/*fuzzSeed-66366547*/count=641; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.cosh((( - ( + ( + ( ~ ( + x))))) | 0)), ((Math.hypot(((Math.fround(x) >>> Math.fround(Math.cosh(Math.hypot(x, y)))) | 0), ( + Math.pow(( + ( + Math.imul(x, ( + y)))), ( + ( + Math.pow(Math.fround(y), ( + 1.7976931348623157e308))))))) | 0) & ( ~ Math.min(-Number.MAX_VALUE, y)))); }); testMathyFunction(mathy1, [0x100000001, -0x080000000, 0x0ffffffff, Math.PI, 2**53, 2**53+2, 0/0, 1.7976931348623157e308, 0x080000000, 0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, 42, 2**53-2, -0x080000001, -(2**53+2), -(2**53), -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, 1, -1/0, 1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001, -0x100000001, -0x07fffffff, 0x100000000]); ");
/*fuzzSeed-66366547*/count=642; tryItOut("v0 = evalcx(\"function this.f1(m2)  { \\\"use strict\\\"; yield let (nupwvb, arguments, iczfyg, window = 27.watch(\\\"toPrecision\\\", arguments.callee.caller), x, sweoad) false } \", g0);");
/*fuzzSeed-66366547*/count=643; tryItOut("mathy5 = (function(x, y) { return ( + Math.pow((mathy4((( + mathy2((( + mathy0((( - Math.fround(x)) | 0), Math.imul(Number.MAX_VALUE, y))) % ( ~ (y >>> 0))), ( + y))) >>> 0), Math.pow(0x0ffffffff, (Math.atan2((Math.fround(Math.ceil(Math.fround(y))) | 0), (Math.log((y >>> 0)) | 0)) | 0))) >>> 0), ( + (Math.log(Math.fround(Math.fround(Math.pow(Math.fround(mathy3(Math.imul(y, Math.fround(mathy3(y, mathy1(Math.PI, y)))), (y | 0))), (Math.max(x, 0x080000000) >>> 0))))) >>> 0)))); }); testMathyFunction(mathy5, [0, -Number.MAX_SAFE_INTEGER, 1, 1/0, Number.MIN_VALUE, 42, -(2**53), 0x0ffffffff, -(2**53-2), -0x100000000, -0x100000001, -(2**53+2), 2**53, 0/0, -0x080000000, -Number.MIN_VALUE, -0, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, 0x100000000, Math.PI, 2**53-2, 0x080000001, 2**53+2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, -0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=644; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.log(Math.fround((( + (y * y)) != ( + ( + ( + ( + -0x080000000))))))); }); testMathyFunction(mathy2, /*MARR*/[null, arguments,  /x/ , null, ((void shapeOf(\n[x]))),  /x/ , null,  /x/ , null,  /x/ , arguments, arguments, null, arguments,  /x/ , arguments, ((void shapeOf(\n[x]))),  /x/ , null, ((void shapeOf(\n[x]))), arguments, null, arguments,  /x/ ,  /x/ , ((void shapeOf(\n[x]))), arguments, arguments, null, ((void shapeOf(\n[x]))), null, ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))),  /x/ , arguments, arguments, arguments, null, ((void shapeOf(\n[x]))), null, ((void shapeOf(\n[x]))),  /x/ , arguments,  /x/ , null,  /x/ , ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), null, ((void shapeOf(\n[x]))), null, null,  /x/ , arguments,  /x/ , null,  /x/ , null, null, null, null, null,  /x/ , null, ((void shapeOf(\n[x]))),  /x/ , null, arguments, ((void shapeOf(\n[x]))), null, arguments, null, ((void shapeOf(\n[x]))), null, ((void shapeOf(\n[x]))),  /x/ , ((void shapeOf(\n[x]))), arguments,  /x/ , null,  /x/ , null, arguments, arguments, arguments,  /x/ , arguments,  /x/ ,  /x/ ,  /x/ , ((void shapeOf(\n[x]))), null, ((void shapeOf(\n[x]))), arguments, null, arguments, arguments, null, ((void shapeOf(\n[x]))),  /x/ , null, arguments, ((void shapeOf(\n[x]))),  /x/ , ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), null, arguments, ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))),  /x/ , null, ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), ((void shapeOf(\n[x]))), arguments,  /x/ ,  /x/ , arguments, null, ((void shapeOf(\n[x])))]); ");
/*fuzzSeed-66366547*/count=645; tryItOut("o1.e0.has(t2);");
/*fuzzSeed-66366547*/count=646; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + ( ! ( + ( + Math.asinh(( + Math.imul((( ! (( - x) >>> 0)) >>> 0), ( + ( + Math.fround((-(2**53-2) ^ Math.imul(( + ( + ( + ( + y)))), ( + -Number.MAX_VALUE))))))))))))); }); testMathyFunction(mathy2, [0, (function(){return 0;}), -0, ({valueOf:function(){return 0;}}), (new Boolean(false)), [0], ({valueOf:function(){return '0';}}), '\\0', true, ({toString:function(){return '0';}}), null, '', '0', 0.1, objectEmulatingUndefined(), /0/, 1, undefined, [], (new Number(-0)), false, (new Boolean(true)), NaN, '/0/', (new Number(0)), (new String(''))]); ");
/*fuzzSeed-66366547*/count=647; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-66366547*/count=648; tryItOut("\"use strict\"; L:if((x % 4 != 1)) m2.get(g0.t1); else  if (\n(eval(\"/* no regression tests found */\", window))) print(x);");
/*fuzzSeed-66366547*/count=649; tryItOut("mathy2 = (function(x, y) { return ( + mathy1(( + ((((Math.log10(y) | 0) == (Math.min(-(2**53), ( + Math.acos(( + 0x07fffffff)))) | 0)) | 0) ? (mathy0(( + Math.cos(Math.log1p(y))), ( + (( + Math.fround(0/0)) | 0))) | 0) : ( + ( ! ( + Math.fround(Math.hypot(Math.fround(x), (x >>> 0)))))))), ( + Math.fround((( ! y) ? Math.fround(( - Math.fround(( + ((Math.trunc(x) | 0) >>> 0))))) : Math.fround((Math.pow((Math.log2(-(2**53)) >>> 0), ( + (Math.tan((( ! (y >>> 0)) | 0)) | 0))) >>> 0))))))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), 0x0ffffffff, -0x080000000, Number.MIN_VALUE, 2**53-2, 0.000000000000001, 42, 1/0, -1/0, Math.PI, 0x080000001, 0/0, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, 0x100000000, -0x07fffffff, -0, Number.MAX_VALUE, 0x07fffffff, 0x100000001, 0, 2**53, -Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, 1, -0x100000001, -(2**53)]); ");
/*fuzzSeed-66366547*/count=650; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot((((( ~ ( + mathy0(0x080000000, ( + (((-(2**53-2) | 0) << (y | 0)) >>> 0))))) >>> 0) , (((((( ~ ((y - y) | 0)) | 0) >>> 0) > (mathy2(( + (((x | 0) ? (x | 0) : (x | 0)) | 0)), y) >>> 0)) >>> 0) >>> 0)) >>> 0), Math.fround(Math.abs(((( - ((( + (( - y) | 0)) | 0) >>> 0)) >>> 0) >> ( + (((y | 0) & (Math.fround((Math.atan2(Number.MAX_VALUE, (x | 0)) | 0)) | 0)) | 0)))))); }); ");
/*fuzzSeed-66366547*/count=651; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\2.|[^]|[^\\\\b-\\\\cK\\\\x41]([^\\\\D\\u00b7\\\\cC-\\\\u00d1]).|\\\\B$[]|\\\\2(?=(?!\\\\f*?)[^]*?|[^]+?|\\\\s[\\\\uDa9A-\\udb3a\\\\S\\u1f3a-\\\\\\u00a3\\\\b-\\uedab]+[^\\\\cI\\u00a2-\\\\v\\\\r-\\\\x5A\\\\cS-\\uc73c]?)|(?!\\\\b)(?=\\\\b)?\\u00cc\\\\S|(?:.)[^][-\\u00e9\\\\w\\\\x1f>-\\u020a\\\\xaC]|[^]|\\\\xA6+|[^\\\\v-[\\\\u5289]|(?!(?!\\\\d))(?!\\\\0)(?=\\\\3+?)(?=\\\\w{549755813888,549755813888})|\\\\B*{536870911,}\", \"gy\"); var s = \"\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048#\\n\\n\\n\\u6495\\n\\n\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048\\u00a1\\nKa\\n1\\nKa\\n1\\u00cca\\ub048\\ub048_0_00000_0\\ub048\\ub048\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=652; tryItOut("v2 = evaluate(\"function f1(s0)  { \\\"use strict\\\"; yield [Math.atan2(5, (4277))] } \", ({ global: o2.g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: x, sourceIsLazy: x > (function ([y]) { })()(\u000c), catchTermination: (1 for (x in [])).prototype }));");
/*fuzzSeed-66366547*/count=653; tryItOut("\"use strict\"; var rbpftz = new ArrayBuffer(6); var rbpftz_0 = new Float64Array(rbpftz); var rbpftz_1 = new Float32Array(rbpftz); var rbpftz_2 = new Uint8Array(rbpftz); print(o2.f2);");
/*fuzzSeed-66366547*/count=654; tryItOut("var noauus = new ArrayBuffer(2); var noauus_0 = new Float32Array(noauus); var noauus_1 = new Uint8Array(noauus); noauus_1[0] = 4; var noauus_2 = new Int16Array(noauus); noauus_2[0] = 0.776; var noauus_3 = new Int32Array(noauus); noauus_3[0] = 18; var noauus_4 = new Uint16Array(noauus); noauus_4[0] = -23; var noauus_5 = new Int32Array(noauus); print(noauus_5[0]); noauus_5[0] = 10; var noauus_6 = new Float64Array(noauus); var noauus_7 = new Uint32Array(noauus); (eval(\"/* no regression tests found */\"));print(noauus_5);m1.has(i0);/*bLoop*/for (uidsii = 0; uidsii < 20; ++uidsii) { if (uidsii % 2 == 1) { v1 = (e1 instanceof v1); } else { ; }  } ");
/*fuzzSeed-66366547*/count=655; tryItOut("\"use strict\"; g0.__proto__ = g2.i0;");
/*fuzzSeed-66366547*/count=656; tryItOut("mathy1 = (function(x, y) { return Math.atan2(Math.acos(( + ( ~ Math.hypot(0x080000001, Math.round(x))))), ( + ((( ~ Math.fround((-0x100000001 ^ ( - Number.MIN_VALUE)))) >>> 0) < Math.fround((((x >>> 0) === ((Math.log10(( + (x , 0x07fffffff))) | 0) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-66366547*/count=657; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + (Math.log1p(Math.pow(Math.fround(((Math.trunc((x >>> 0)) >>> 0) != (x === ( + Math.cbrt(( + y)))))), Math.imul((Math.sign(x) >>> 0), (Math.PI | 0)))) | 0)) | 0); }); testMathyFunction(mathy0, ['', objectEmulatingUndefined(), [], /0/, 0, ({toString:function(){return '0';}}), (new Number(-0)), (function(){return 0;}), ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Boolean(true)), 0.1, -0, 1, true, false, undefined, (new Number(0)), (new Boolean(false)), '\\0', '/0/', null, NaN, '0', [0], (new String(''))]); ");
/*fuzzSeed-66366547*/count=658; tryItOut("\"use strict\"; {\"\\uAD3A\";Array.prototype.shift.apply(a1, [e2, o0, t0]); }");
/*fuzzSeed-66366547*/count=659; tryItOut("x = t2;");
/*fuzzSeed-66366547*/count=660; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + Math.tan((( ! Math.fround(Math.tan(Math.fround(y)))) | 0))) ? Math.hypot(Math.fround(mathy1((( + ( + ( + y))) | 0), ( + (Math.log(( + ((x | 0) > (x | 0)))) ? x : ( + mathy0(( + Math.fround(( ~ x))), ( + ( + (( + y) >= ( + y)))))))))), ((Math.max((Math.imul(Math.atan(Math.fround((( ! x) | x))), Math.sqrt(-Number.MIN_SAFE_INTEGER)) | 0), (( ~ Math.log(-0x100000000)) >>> 0)) >>> 0) >>> 0)) : (Math.log10((x % ( ~ -Number.MAX_VALUE))) != (Math.tanh((mathy0(y, 0x080000001) | 0)) | 0))); }); ");
/*fuzzSeed-66366547*/count=661; tryItOut("mathy5 = (function(x, y) { return ( + (( + Math.atan2(( + ( + (Math.pow((( ~ y) >>> 0), x) - Math.sign(y)))), ( + Math.fround(Math.cosh(( + mathy2(Math.sinh(Math.max(Math.fround(y), y)), ( + Math.log(y))))))))) | 0)); }); testMathyFunction(mathy5, /*MARR*/[new Number(1), new Number(1), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), x, new Number(1), (4277), (4277), yield [1,,], new Number(1), yield [1,,], new Number(1), (4277)]); ");
/*fuzzSeed-66366547*/count=662; tryItOut("o0.v2 = t1.byteOffset;let c = (yield null);");
/*fuzzSeed-66366547*/count=663; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( - Math.fround(mathy2(((Math.acosh(x) >>> 0) | 0), Math.fround(( - Math.log1p(Math.fround(mathy1(0x100000001, -Number.MAX_SAFE_INTEGER)))))))) >>> 0); }); testMathyFunction(mathy5, [-0x080000000, -(2**53+2), 0x0ffffffff, -0, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 1, 1/0, Number.MIN_VALUE, Math.PI, 42, -0x100000001, 0x07fffffff, 0, 2**53+2, -0x080000001, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, -1/0, 2**53, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, 0.000000000000001, -0x07fffffff, 0x100000001, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, -0x100000000]); ");
/*fuzzSeed-66366547*/count=664; tryItOut("let (e) { v1 = Object.prototype.isPrototypeOf.call(h0, v2); }");
/*fuzzSeed-66366547*/count=665; tryItOut("testMathyFunction(mathy3, [2**53-2, 0x100000000, -1/0, -0x100000000, -0x080000000, -0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, 2**53+2, 0x100000001, 0x080000000, 42, -(2**53), -0x080000001, 0x07fffffff, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, 1/0, 1.7976931348623157e308, 0/0, 0.000000000000001, 0x0ffffffff, 0, 0x080000001, Number.MAX_VALUE, -0x07fffffff]); ");
/*fuzzSeed-66366547*/count=666; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ (( + (Math.fround((((( + Math.fround(x)) >>> 0) % ((( - ((( + x) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> ( + Math.tanh(Math.cos(42))))) | 0)); }); testMathyFunction(mathy5, [-0x080000000, 0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, 42, -0x07fffffff, -0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 1, 0/0, 2**53+2, -1/0, -0x100000000, 0, -(2**53+2), -(2**53), 1.7976931348623157e308, Number.MAX_VALUE, 1/0, 0x07fffffff, -(2**53-2), 2**53-2, 0x080000001, -Number.MAX_VALUE, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, 2**53]); ");
/*fuzzSeed-66366547*/count=667; tryItOut("mathy4 = (function(x, y) { return mathy3(((((( + (( + Math.imul((Math.log1p(Math.fround(-Number.MIN_VALUE)) >>> 0), -Number.MAX_SAFE_INTEGER)) == Math.fround(((Math.fround(y) | y) | 0)))) , (Math.fround(-(2**53-2)) % Math.fround(( ~ ( + (x + 0.000000000000001)))))) | 0) ? (((Math.fround((( ! (-1/0 | 0)) / y)) >= Math.fround(mathy3(Math.fround(((x | 0) == x)), Math.fround(y)))) | 0) | 0) : (mathy1((( + Math.atan(Math.atan2(-0, ( + x)))) || y), ( + Math.pow(Math.fround(Math.max((Math.atanh(x) >>> 0), Math.fround(Math.cosh((y >>> 0))))), mathy3(x, (-0x100000001 | 0))))) | 0)) | 0), (new EvalError() != ((void version(180))) >= Math.atan((Math.cos(( ~ (Math.fround(Math.asinh(y)) / x))) | 0)))); }); testMathyFunction(mathy4, [-0x080000001, -Number.MAX_VALUE, 0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), 0/0, -0x100000001, 0x100000001, 1, -0x080000000, -(2**53-2), -0x07fffffff, 1/0, 42, Math.PI, Number.MAX_VALUE, -0, 0x080000001, 0x07fffffff, 2**53+2, 0x0ffffffff, -Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -(2**53+2), 0, 0x100000000, 1.7976931348623157e308, -0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=668; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - Math.fround(Math.sin(Math.fround(( ! (Math.hypot(x, 1.7976931348623157e308) | 0)))))); }); testMathyFunction(mathy3, [Math.PI, -Number.MIN_VALUE, 1, 42, -0, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, 1.7976931348623157e308, 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, 0x080000001, Number.MIN_VALUE, 0, 0/0, -1/0, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, 0x080000000, 1/0, -0x07fffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, -0x100000001, -(2**53+2), 0x100000000, -Number.MAX_VALUE, -(2**53-2), -0x080000001, -0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=669; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=670; tryItOut("m0.has(t0);");
/*fuzzSeed-66366547*/count=671; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atan2(Math.atanh(( - (Math.sin(-0) >>> 0))), Math.fround(Math.max(( - Math.fround(Math.cbrt(Math.fround(y)))), ((Math.atan2((Math.acosh(1.7976931348623157e308) | 0), (( ! (Math.min((x >>> 0), (y >>> 0)) >>> 0)) | 0)) | 0) << Math.sqrt(Math.trunc(Number.MAX_VALUE)))))); }); testMathyFunction(mathy3, /*MARR*/[false, new String(''), {x:3}, new String(''), (Set.prototype.entries), {x:3}, false, {x:3}, false, ({a2:z2}), (Set.prototype.entries), new String(''), ({a2:z2}), false, {x:3}, ({a2:z2}), ({a2:z2}), {x:3}, (Set.prototype.entries), false, (Set.prototype.entries), (Set.prototype.entries), new String(''), ({a2:z2}), ({a2:z2}), (Set.prototype.entries), ({a2:z2}), false, {x:3}, ({a2:z2}), ({a2:z2}), (Set.prototype.entries), {x:3}, false, {x:3}, {x:3}, (Set.prototype.entries), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), ({a2:z2}), {x:3}, false, false, {x:3}, new String(''), ({a2:z2}), (Set.prototype.entries), (Set.prototype.entries), false, (Set.prototype.entries), (Set.prototype.entries), {x:3}, false, false, false, {x:3}, ({a2:z2}), {x:3}, false, (Set.prototype.entries), ({a2:z2}), false, ({a2:z2}), (Set.prototype.entries), false, false, false, (Set.prototype.entries), ({a2:z2}), ({a2:z2}), {x:3}, (Set.prototype.entries), new String(''), (Set.prototype.entries), false]); ");
/*fuzzSeed-66366547*/count=672; tryItOut("selectforgc(o2);");
/*fuzzSeed-66366547*/count=673; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      return +((d0));\n    }\n    d0 = (d1);\n    d1 = (d1);\n    return +((Infinity));\n    return +((d1));\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [({toString:function(){return '0';}}), objectEmulatingUndefined(), '', '\\0', ({valueOf:function(){return 0;}}), /0/, 0.1, undefined, (new Boolean(false)), 0, '/0/', [], ({valueOf:function(){return '0';}}), (function(){return 0;}), false, '0', (new String('')), (new Boolean(true)), -0, true, null, (new Number(0)), 1, (new Number(-0)), NaN, [0]]); ");
/*fuzzSeed-66366547*/count=674; tryItOut("mathy5 = (function(x, y) { return Math.cbrt((( + ((( - 0.000000000000001) + Math.max(( + (( + y) ? ( + x) : Math.log2(y))), x)) >>> 0)) | 0)); }); testMathyFunction(mathy5, [0.1, (function(){return 0;}), objectEmulatingUndefined(), /0/, true, '0', 1, (new String('')), undefined, '/0/', null, NaN, ({valueOf:function(){return 0;}}), '', ({valueOf:function(){return '0';}}), (new Boolean(true)), false, '\\0', (new Number(-0)), 0, -0, ({toString:function(){return '0';}}), [0], (new Number(0)), [], (new Boolean(false))]); ");
/*fuzzSeed-66366547*/count=675; tryItOut("b1.valueOf = (function mcc_() { var mkdixd = 0; return function() { ++mkdixd; f0(/*ICCD*/mkdixd % 8 == 1);};})();");
/*fuzzSeed-66366547*/count=676; tryItOut("o0.s0 += s1;");
/*fuzzSeed-66366547*/count=677; tryItOut("e0 = new Set(i1);\nprint(\"\\u560D\");\n");
/*fuzzSeed-66366547*/count=678; tryItOut("mathy2 = (function(x, y) { return ( + (mathy0((mathy0((-0x080000001 && x), Math.trunc(( ! x))) | 0), ( + mathy0(( + ((Math.cbrt(0x100000001) | 0) ? x : Math.imul(( + ( + Math.fround(-Number.MIN_VALUE))), (-0x080000000 | 0)))), ((((Math.clz32((y >>> 0)) >>> 0) >>> 0) / (x >>> 0)) >>> 0)))) == (( ~ Math.expm1(Math.fround(Math.imul(y, (( - x) ? (-Number.MAX_SAFE_INTEGER | 0) : Math.fround(0)))))) * ((( + ( + 0x080000000)) >> ( + (Math.imul((x | 0), (( + x) ** ( + x))) !== ( + y)))) | 0)))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, Math.PI, -0x0ffffffff, 2**53, 0, -Number.MIN_VALUE, -0x080000001, 0x080000001, 2**53+2, 1, -1/0, -0x080000000, -(2**53+2), 0x100000001, -0, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, -(2**53-2), 42, 0x080000000, -0x100000000, 0x07fffffff, Number.MIN_VALUE, 2**53-2, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, -0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-66366547*/count=679; tryItOut("Array.prototype.push.call(a0, m0);");
/*fuzzSeed-66366547*/count=680; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=681; tryItOut("\"use strict\"; m1.get(s0);let z = (4277);");
/*fuzzSeed-66366547*/count=682; tryItOut("( '' );function x(x) { return x } print(x);");
/*fuzzSeed-66366547*/count=683; tryItOut("\"use strict\"; delete h1.getOwnPropertyDescriptor;");
/*fuzzSeed-66366547*/count=684; tryItOut("undefined;\ne1.add(t0);\n");
/*fuzzSeed-66366547*/count=685; tryItOut("\"use strict\"; i2.send(a1);");
/*fuzzSeed-66366547*/count=686; tryItOut("t0.set(t0, 8);");
/*fuzzSeed-66366547*/count=687; tryItOut("var hqmvvn = new SharedArrayBuffer(4); var hqmvvn_0 = new Int8Array(hqmvvn); print(hqmvvn_0[0]); hqmvvn_0[0] = 12; var hqmvvn_1 = new Int8Array(hqmvvn); hqmvvn_1[0] = 23; var hqmvvn_2 = new Uint8ClampedArray(hqmvvn); hqmvvn_2[0] = 5.0000000000000000000000; var hqmvvn_3 = new Int32Array(hqmvvn); hqmvvn_3[0] = 0; var hqmvvn_4 = new Float32Array(hqmvvn); print(hqmvvn_4[0]); hqmvvn_4[0] = -11; var hqmvvn_5 = new Uint32Array(hqmvvn); hqmvvn_5[0] = -4; var hqmvvn_6 = new Float64Array(hqmvvn); var hqmvvn_7 = new Float32Array(hqmvvn); print(hqmvvn_7[0]); hqmvvn_7[0] = -12; var hqmvvn_8 = new Uint8Array(hqmvvn); print(hqmvvn_8[0]); hqmvvn_8[0] = -18; var hqmvvn_9 = new Uint8Array(hqmvvn); var hqmvvn_10 = new Uint32Array(hqmvvn); /* no regression tests found */");
/*fuzzSeed-66366547*/count=688; tryItOut("NaN = linkedList(NaN, 6106);");
/*fuzzSeed-66366547*/count=689; tryItOut("mathy2 = (function(x, y) { return Math.max(Math.acosh((Math.cos(y) | 0)), Math.fround(((Math.fround(( ! (Math.imul(( + ( ! ( + x))), x) >>> 0))) < y) & ((Math.asin(Math.log1p((Math.hypot((0x0ffffffff >>> 0), (y >>> 0)) >>> 0))) | 0) | 0)))); }); testMathyFunction(mathy2, [-0x080000000, 2**53+2, -0x100000000, Number.MAX_VALUE, 0x07fffffff, -(2**53), -Number.MIN_VALUE, 0x100000001, -0, 0/0, 0x080000000, -0x080000001, 0, -(2**53+2), 1.7976931348623157e308, 42, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -Number.MAX_VALUE, 2**53, 2**53-2, 1/0, -(2**53-2), 0x080000001, Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0, -0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1]); ");
/*fuzzSeed-66366547*/count=690; tryItOut("\"use strict\"; let (x, x, b, x, eval =  \"\" , qnwktu, x, smwdeu, mrlzqh) { v1 = r2.ignoreCase; }");
/*fuzzSeed-66366547*/count=691; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.acos(( ! (Math.imul((Math.atan2(Math.log2(x), x) | 0), ( - Math.fround((mathy0((x >>> 0), (x >>> 0)) >>> 0)))) | 0))); }); testMathyFunction(mathy2, [-0x100000000, 0, -0x100000001, 1, Number.MIN_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, 0x080000000, -0x080000000, 0x0ffffffff, -0x0ffffffff, -0x080000001, -0x07fffffff, -0, Number.MAX_VALUE, 42, -(2**53), 2**53-2, Math.PI, 0x07fffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 0/0, 1/0, -Number.MAX_VALUE, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-66366547*/count=692; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.atanh(( - ( - (Math.clz32(Math.min(x, 0)) >>> 0)))) - ( + Math.pow(Math.atan((((( + mathy0(x, (((x >>> 0) , y) >>> 0))) >>> 0) ^ 0x080000000) | 0)), ( + ( - ( + (( ! (x >>> 0)) >>> 0))))))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -Number.MIN_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 1/0, -(2**53+2), -0x100000000, 0x100000001, -0x100000001, 0x080000001, 2**53-2, 0x100000000, -0, 42, Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, -Number.MAX_VALUE, -1/0, -0x07fffffff, 0x07fffffff, 0, Number.MAX_VALUE, -0x080000000, 0x080000000, 2**53, -(2**53-2), 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=693; tryItOut("\"use strict\"; t2[9] = t0;");
/*fuzzSeed-66366547*/count=694; tryItOut("/*ADP-3*/Object.defineProperty(a1, 4, { configurable: (this.__defineSetter__(\"a\", (arguments.callee).bind( /x/g ))), enumerable: (new mathy2(\"\\u852B\", window--).throw(new (decodeURI)(timeout(1800)))), writable: true, value: e2 });");
/*fuzzSeed-66366547*/count=695; tryItOut("v0 = evalcx(\"i2 + b0;\\nprint( /x/g );\\n\\njmhxqg;v0 = r0.source;\\n\", g0);");
/*fuzzSeed-66366547*/count=696; tryItOut("\"use strict\"; /*vLoop*/for (zdqxql = 0; (window) && zdqxql < 2; ++zdqxql) { const z = zdqxql; o1.s0 + ''; } ");
/*fuzzSeed-66366547*/count=697; tryItOut("\"use strict\"; s0 = s0.charAt(7);var b = (uneval(([null])));");
/*fuzzSeed-66366547*/count=698; tryItOut("testMathyFunction(mathy0, [-Number.MAX_VALUE, 2**53+2, 0.000000000000001, 0/0, Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, 0x100000001, -Number.MIN_VALUE, 1, -0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, 0x100000000, 2**53, 0x0ffffffff, -0, -0x080000001, 0x080000001, 1.7976931348623157e308, -(2**53-2), 0x07fffffff, 42, -0x100000000, 2**53-2, -(2**53+2), -0x080000000, -0x07fffffff]); ");
/*fuzzSeed-66366547*/count=699; tryItOut("/*RXUB*/var r = /(((?:(?!(\uaa12{4,4})))*?))+|\\1|\\d?|((?=(?!t))){3,7}|[^]/gim; var s = \"\"; print(s.replace(r, '\\u0341', \"i\")); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=700; tryItOut("neuter(o2.b0, \"change-data\");");
/*fuzzSeed-66366547*/count=701; tryItOut("\"use strict\"; const a = x, x, d, jyztdf, y, z = null.throw(c), x, e, ukflkq;h0 = t1[18];");
/*fuzzSeed-66366547*/count=702; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return Math.fround(Math.asin(mathy1(Math.fround(( - (( ! ( ~ Math.fround(mathy1(Math.fround(x), Math.fround(x))))) >>> 0))), Math.sqrt(Math.fround((Math.cosh(y) << Math.tan((x - x)))))))); }); testMathyFunction(mathy2, [0x100000000, -1/0, -0x0ffffffff, 2**53, -(2**53), 0/0, 0x07fffffff, -0x100000001, -(2**53-2), 1/0, 1, 1.7976931348623157e308, -Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, -Number.MIN_VALUE, 0x0ffffffff, 2**53+2, 0x080000000, Number.MAX_VALUE, Math.PI, 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), -0x080000000, -0, Number.MIN_SAFE_INTEGER, 0x100000001, 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=703; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=704; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.atan2((( + Math.sinh(x)) | 0), ((Math.imul(( + Math.exp(Math.fround(Math.sin(0x080000001)))), (((mathy1(mathy3(x, y), x) <= (x + Math.fround(y))) | 0) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[(void 0),  '' , function(){}, x, undefined, undefined, function(){}, function(){}, (void 0),  '' , function(){}, function(){}, x, function(){}, x, x, x, x, undefined, x, undefined, function(){}, undefined, (void 0), undefined]); ");
/*fuzzSeed-66366547*/count=705; tryItOut("mathy0 = (function(x, y) { return Math.fround((Math.fround((( ! Math.imul(( ! 0/0), 0x080000001)) & ((( ~ Math.atan(y)) > (y >>> 0)) >>> 0))) || ((x + ( + Math.exp(( + -0x0ffffffff)))) >>> Math.fround(Math.hypot((x >>> 0), (y >>> 0)))))); }); testMathyFunction(mathy0, /*MARR*/[undefined, undefined, undefined,  /x/ , undefined,  /x/ ,  /x/ , undefined,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , undefined,  /x/ ,  /x/ , undefined,  /x/ ,  /x/ , undefined,  /x/ ,  /x/ , undefined,  /x/ ,  /x/ ,  /x/ , undefined,  /x/ , undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,  /x/ ,  /x/ , undefined, undefined, undefined, undefined, undefined, undefined, undefined,  /x/ , undefined, undefined, undefined,  /x/ , undefined,  /x/ ,  /x/ , undefined,  /x/ , undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,  /x/ ,  /x/ , undefined,  /x/ ,  /x/ , undefined, undefined,  /x/ , undefined,  /x/ ,  /x/ , undefined, undefined,  /x/ , undefined,  /x/ ,  /x/ , undefined,  /x/ , undefined, undefined, undefined, undefined,  /x/ ,  /x/ ,  /x/ ,  /x/ , undefined, undefined,  /x/ ,  /x/ , undefined, undefined, undefined,  /x/ ,  /x/ ,  /x/ , undefined, undefined,  /x/ ,  /x/ , undefined, undefined, undefined, undefined, undefined, undefined,  /x/ ,  /x/ , undefined]); ");
/*fuzzSeed-66366547*/count=706; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=707; tryItOut("x.message;");
/*fuzzSeed-66366547*/count=708; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul((Math.hypot((Math.asin(( + x)) >>> 0), x) == Math.tanh(Math.log(((Number.MIN_SAFE_INTEGER >>> y) == Math.fround(y))))), (( + ((( - (x >>> 0)) >>> 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-66366547*/count=709; tryItOut("testMathyFunction(mathy5, [Math.PI, 0, 2**53, -(2**53), -0, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, 0x080000000, -0x100000001, -(2**53-2), -0x07fffffff, 0/0, -Number.MAX_VALUE, 1/0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, 42, -1/0, -0x080000001, 2**53+2, 0x07fffffff, 0x100000001, 1.7976931348623157e308, Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000]); ");
/*fuzzSeed-66366547*/count=710; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((0x0));\n    {\n      i1 = (i0);\n    }\n    {\n      i0 = (i1);\n    }\n    i0 = (/*FFI*/ff(((+((+((b instanceof a) | ((true))))))))|0);\n    i1 = (i1);\n    i1 = (i0);\n    i0 = (i1);\n    (x) = ((1.9342813113834067e+25));\n    i1 = (i0);\n    (Float64ArrayView[( \"\" ) >> 3]) = ((-1.0078125));\n    {\n      {\n        i1 = (i0);\n      }\n    }\n    i0 = (i0);\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: mathy4}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000000, 0/0, -0x07fffffff, -0x100000001, 0.000000000000001, 0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 1, 0x0ffffffff, -(2**53), 0x080000000, Math.PI, 1/0, -(2**53-2), Number.MIN_VALUE, 2**53+2, -Number.MIN_VALUE, -1/0, 0x07fffffff, 42, 2**53-2, -0, 2**53, 0x100000001, 1.7976931348623157e308, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-66366547*/count=711; tryItOut("v2 = g2.eval(\"o1.m1.has(p1);\");");
/*fuzzSeed-66366547*/count=712; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [({toString:function(){return '0';}}), (new String('')), (new Number(-0)), 1, 0, (new Boolean(false)), '', '\\0', /0/, [0], false, '/0/', objectEmulatingUndefined(), [], -0, '0', (new Number(0)), true, (new Boolean(true)), NaN, ({valueOf:function(){return 0;}}), (function(){return 0;}), undefined, null, 0.1, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-66366547*/count=713; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.min(Math.hypot(Math.pow(Math.max(x, ((x , (0x0ffffffff | 0)) | 0)), (Math.fround(y) >>> Math.cbrt(x))), (( + mathy1(Math.abs(Math.hypot(1/0, y)), ( + Math.log2(( + ( ! mathy1(y, y))))))) , x)), (Math.max((mathy0(Math.round(Math.fround((-1/0 ? y : y))), (( + Math.log10(( + x))) >>> 0)) | 0), (Math.fround(( + y)) | 0)) && Math.atan2((( - Math.fround(x)) | 0), Math.min((((2**53 >>> 0) ? (x >>> 0) : y) >>> 0), x)))); }); testMathyFunction(mathy2, [-1/0, 0.000000000000001, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, 0, -0x080000001, -0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, -0x0ffffffff, 2**53, 0x080000001, 1, 0x080000000, -0x080000000, -0x07fffffff, 0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Math.PI, 2**53-2, -0, 0x0ffffffff, 2**53+2, 42, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -(2**53)]); ");
/*fuzzSeed-66366547*/count=714; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( + Math.imul(( + (y !== Math.fround(Math.min(Math.fround(mathy2(y, Math.fround(Math.asinh(x)))), Math.fround(Math.fround((Math.fround(Math.atan(( + y))) & Math.fround(Math.atan2(Math.fround(Math.max(x, y)), -Number.MAX_VALUE))))))))), ( + (( - (((( + (y < ( + y))) !== -0x080000001) | 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy5, [0/0, -0x100000001, 1.7976931348623157e308, 2**53+2, 2**53-2, -(2**53), 0x0ffffffff, 0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, -0, 42, -0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, -0x080000000, 0x07fffffff, 0x100000000, 0, 0x100000001, 1, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), Number.MAX_VALUE, -0x080000001, -Number.MAX_VALUE, 2**53, Math.PI, Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-66366547*/count=715; tryItOut("\"use strict\"; if(false) v0 = Object.prototype.isPrototypeOf.call(i0, this.g2.s2); else  if (eval(\"/* no regression tests found */\", Math.max(-0, 19))) {v1 = r2.sticky;v1 + ''; }");
/*fuzzSeed-66366547*/count=716; tryItOut("v2 = false;");
/*fuzzSeed-66366547*/count=717; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.fround((Math.fround(( + Math.hypot(( + ( + (Math.fround(Math.min(Math.fround(y), Math.fround(Math.cosh(x)))) ? ( + y) : ( + Math.fround(Math.atan2(x, (y >> 2**53-2))))))), ( + (Math.pow((((y >>> 0) >= (y >>> 0)) >>> 0), (y | 0)) | 0))))) >= (Math.asinh(Math.fround((Math.fround(( ~ y)) < (2**53-2 | 0)))) >>> 0)))) / Math.fround((( ! (( + Math.fround(Math.sinh(Math.max(mathy0(y, -0x080000000), y)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [1/0, 0, 0x100000000, -Number.MAX_VALUE, 2**53+2, 0x0ffffffff, 1.7976931348623157e308, -(2**53), Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), Number.MIN_VALUE, -0x100000001, Math.PI, -Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -0x0ffffffff, -0x080000000, -0x080000001, Number.MAX_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 42, -0x100000000, -1/0, 0x080000001, 2**53-2, 0x100000001, 1, -0x07fffffff, 2**53]); ");
/*fuzzSeed-66366547*/count=718; tryItOut("print(\"\\u058D\");function x() { yield  /x/g  } h0.keys = f1;");
/*fuzzSeed-66366547*/count=719; tryItOut("print(x);");
/*fuzzSeed-66366547*/count=720; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; void gc(); } void 0; }");
/*fuzzSeed-66366547*/count=721; tryItOut("/*RXUB*/var r = /(?![\\D\\u87cc\\s\\W]){1,3}(?!(?!\\2)){3}\\W{2,}|\\D/gim; var s = \"_\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=722; tryItOut("mathy5 = (function(x, y) { return (mathy1((Math.sign(Math.cos(( ~ ( ! 0x0ffffffff)))) >>> 0), ((Math.atanh(( ~ ( - Math.log(y)))) | 0) > ((2**53 * Math.fround(Math.atanh(Math.fround(x)))) === Math.max(Math.fround((-0 > Math.sinh(((y <= y) >>> 0)))), ( + y))))) >>> 0); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, 0, Math.PI, -0x080000001, -0x100000001, 2**53-2, 0x100000000, -(2**53-2), -(2**53+2), -1/0, 1, -(2**53), -0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000000, 0.000000000000001, 42, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, 0x080000000, 2**53, 2**53+2, 0x100000001, -0, -0x100000000, -0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-66366547*/count=723; tryItOut("mathy4 = (function(x, y) { return (mathy0((Math.fround(Math.fround((mathy1((((y | 0) !== 2**53-2) | 0), ((Math.max(Math.pow(( + y), y), (Math.fround(Math.min(Math.fround(x), Math.fround(x))) >>> 0)) >>> 0) | 0)) | 0))) >>> 0), (((( + ( + mathy2(Math.imul(Math.imul(0x0ffffffff, ( + (Math.fround(x) < x))), x), ( + y)))) >= ( + Math.fround((( + Math.expm1(( + ( + Math.min(0x080000000, ( + y)))))) !== Math.fround(Math.fround(Math.trunc(Math.fround(( + Math.trunc(( + x))))))))))) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [2**53, -0x0ffffffff, -0x100000001, -0x080000001, 0x100000001, 0x100000000, Number.MAX_VALUE, -0, -(2**53), -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0/0, -(2**53+2), -(2**53-2), 0x07fffffff, 2**53-2, 0x080000001, -Number.MAX_VALUE, 1/0, -Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, -0x100000000, 1, 42, 2**53+2, -1/0, Number.MIN_VALUE, 0x0ffffffff, 0, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=724; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.round(Math.atan2(Math.sinh((Math.asinh(Math.imul(x, x)) | 0)), Math.tanh(y))); }); testMathyFunction(mathy0, ['/0/', ({valueOf:function(){return 0;}}), [0], 0, ({toString:function(){return '0';}}), (new Number(-0)), /0/, null, ({valueOf:function(){return '0';}}), (new Boolean(false)), objectEmulatingUndefined(), NaN, 0.1, undefined, '0', '\\0', 1, (new String('')), [], '', (new Number(0)), (new Boolean(true)), (function(){return 0;}), -0, true, false]); ");
/*fuzzSeed-66366547*/count=725; tryItOut("z;break M;");
/*fuzzSeed-66366547*/count=726; tryItOut("testMathyFunction(mathy3, [1/0, -(2**53-2), 0x0ffffffff, 0x080000001, 2**53+2, -0x080000000, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000000, 42, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0x100000001, -0x100000001, 2**53, 1.7976931348623157e308, -0, Number.MIN_VALUE, 0/0, -(2**53+2), -0x080000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, 2**53-2, -0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, 1, 0.000000000000001, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=727; tryItOut("\"use strict\"; v2 = this.t0.length;f0(s0);");
/*fuzzSeed-66366547*/count=728; tryItOut("a2[v1];");
/*fuzzSeed-66366547*/count=729; tryItOut("/*RXUB*/var r = /(?:(?!(?!\\W)))/yi; var s = \"a\"; print(s.replace(r, (uneval(undefined)))); ");
/*fuzzSeed-66366547*/count=730; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.trunc(Math.fround(((( ! (mathy1((-0x100000001 | 0), (0x0ffffffff | 0)) | 0)) | 0) ? (((x | 0) + (Math.imul(Math.fround(( - y)), (( + (Math.expm1(( + x)) | 0)) | 0)) >>> 0)) | 0) : ( ! Math.atan2(y, -0x080000001)))))); }); ");
/*fuzzSeed-66366547*/count=731; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x0ffffffff, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, -(2**53+2), -0x080000001, 0x080000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000001, -(2**53), 0x100000001, 2**53-2, 0x0ffffffff, 1/0, 0x080000001, 2**53+2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 1, Math.PI, -(2**53-2), 1.7976931348623157e308, -0x100000000, 0x07fffffff, 42, 0x100000000, 2**53, -Number.MIN_VALUE, Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=732; tryItOut("mathy4 = (function(x, y) { return Math.fround(((Math.fround((Math.fround(1) * Math.fround(Math.fround((( + y) === Math.fround((x ? ( - x) : -Number.MAX_SAFE_INTEGER))))))) >> Math.fround(Math.min(Math.fround(( + (Math.fround(( + Math.expm1(y))) == Math.fround(x)))), x))) ? Math.max(y, ( + ((( + Math.max(( + x), ( + -0))) >> -25) === -0x100000000))) : ( ~ Math.trunc(( - 0x100000000))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 2**53, 0/0, 0x100000001, -(2**53+2), -0x100000000, 1/0, 42, -0x07fffffff, 0x100000000, -Number.MAX_VALUE, 1, -1/0, 0, -0, -0x100000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), -Number.MIN_VALUE, Math.PI, -0x080000001, -0x080000000, 2**53-2, 2**53+2, Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, 0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=733; tryItOut("\"use strict\"; a0.sort((function mcc_() { var mrxzva = 0; return function() { ++mrxzva; f2(/*ICCD*/mrxzva % 6 == 4);};})(), o1, g0, p0);");
/*fuzzSeed-66366547*/count=734; tryItOut("");
/*fuzzSeed-66366547*/count=735; tryItOut("{} = x, c = \"\\u1A8F\", c, zhswmn, c;i0.__proto__ = o2;");
/*fuzzSeed-66366547*/count=736; tryItOut("v2 = new Number(-0);");
/*fuzzSeed-66366547*/count=737; tryItOut("testMathyFunction(mathy1, [[0], '', (new Number(0)), '/0/', ({valueOf:function(){return '0';}}), (new Number(-0)), 1, '0', (new Boolean(false)), '\\0', NaN, ({toString:function(){return '0';}}), -0, 0.1, ({valueOf:function(){return 0;}}), true, /0/, false, [], null, (new Boolean(true)), 0, (function(){return 0;}), objectEmulatingUndefined(), (new String('')), undefined]); ");
/*fuzzSeed-66366547*/count=738; tryItOut("\"use asm\"; o1.i1.__proto__ = o0;\nprint(x = \"\\uBFC7\");\nprint((4277));\n\n");
/*fuzzSeed-66366547*/count=739; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\1\", \"gim\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=740; tryItOut("\"use strict\"; /*hhh*/function rnqopr(eval = /[^]/gyi){this.h0 = ({getOwnPropertyDescriptor: function(name) { t0 = new Uint32Array(({valueOf: function() { (({}));return 9; }}));; var desc = Object.getOwnPropertyDescriptor(e1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { g0.a1.sort((function() { for (var p in f0) { try { print(g0); } catch(e0) { } try { a0.shift(b2, v0); } catch(e1) { } try { e0 + this.i1; } catch(e2) { } o2.v2 = evalcx(\"function f1(s0)  { return 11 } \", g0); } return o1; }), o2.b2, o2.f0, b0, this.p0,  /x/g , i1);; var desc = Object.getPropertyDescriptor(e1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { g0.a2.reverse(p0);; Object.defineProperty(e1, name, desc); }, getOwnPropertyNames: function() { o0.m1.delete(this.s0);; return Object.getOwnPropertyNames(e1); }, delete: function(name) { this.e2.add(m1);; return delete e1[name]; }, fix: function() { a1[1] = a2;; if (Object.isFrozen(e1)) { return Object.getOwnProperties(e1); } }, has: function(name) { a0.splice(NaN, ({valueOf: function() { print(x);return 11; }}));; return name in e1; }, hasOwn: function(name) { Object.defineProperty(this, \"t0\", { configurable: undefined, enumerable: false,  get: function() {  return new Uint32Array(b0); } });; return Object.prototype.hasOwnProperty.call(e1, name); }, get: function(receiver, name) { h1 + '';; return e1[name]; }, set: function(receiver, name, val) { v1 = evaluate(\"h1.delete = f1;\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 9 == 6), sourceIsLazy: \"\\uA24F\", catchTermination: true }));; e1[name] = val; return true; }, iterate: function() { v0 = g1.runOffThreadScript();; return (function() { for (var name in e1) { yield name; } })(); }, enumerate: function() { a0.reverse(h1);; var result = []; for (var name in e1) { result.push(name); }; return result; }, keys: function() { g2.offThreadCompileScript(\"v0 = true;\");; return Object.keys(e1); } });}/*iii*/true;");
/*fuzzSeed-66366547*/count=741; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul(((((x == ((((Math.tanh(((Math.min((x >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0) | 0) > (Math.fround(( ! Math.fround(( - x)))) | 0)) | 0)) >>> 0) % (Math.fround((((Math.hypot(((y === (x | 0)) | 0), ( + ((Math.fround((x * x)) | 0) ? ( + x) : Math.fround(Math.abs(Math.fround(y)))))) >>> 0) | 0) ? Math.fround(( - x)) : (y >>> 0))) | 0)) >>> 0), ( + (( + mathy0(( - 0x080000001), (( ! (( + x) >>> 0)) >>> 0))) >>> ((((x >>> 0) ** (( ~ (y | 0)) | 0)) >>> 0) | 0)))); }); testMathyFunction(mathy1, [-0, 2**53+2, 1.7976931348623157e308, 0, -0x080000001, -Number.MIN_VALUE, 0/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x0ffffffff, -(2**53), -0x100000001, 0x100000001, 1/0, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_VALUE, -0x080000000, 0x0ffffffff, -0x100000000, 0x080000001, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 0x07fffffff, 0x100000000, 2**53, Math.PI, 1, 42, -(2**53+2)]); ");
/*fuzzSeed-66366547*/count=742; tryItOut("mathy2 = (function(x, y) { return ( ~ ( + Math.cos(Math.max(Math.asin(( + y)), x)))); }); testMathyFunction(mathy2, [-0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, 2**53+2, 1, 0.000000000000001, 2**53, -0x0ffffffff, 1.7976931348623157e308, -0, -0x07fffffff, 0/0, -0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, -(2**53+2), -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, -1/0, Number.MIN_VALUE, 0x100000001, 1/0, 0x080000001, 42, -(2**53), Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 0x080000000, Math.PI, 0x100000000]); ");
/*fuzzSeed-66366547*/count=743; tryItOut("function shapeyConstructor(mgjglh){this[\"0\"] = DataView.prototype.setInt8;this[\"arguments\"] = (\n-6);Object.seal(this);if (mgjglh) { (new \"\\u3B97\"( '' ));( \"\"  - -29); } Object.freeze(this);if (mgjglh = Math.pow(true, b).throw(encodeURI())) Object.preventExtensions(this);if (mgjglh) this[(delete x.a)] = mgjglh;this[(delete x.a)] = ;return this; }/*tLoopC*/for (let x of (function() { \"use strict\"; yield x; } })()) { try{let sdnlgt = shapeyConstructor(x); print('EETT'); for(var w in ((function(q) { return q; })(Math.ceil(-14))))v2 = (b2 instanceof o2.o1);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-66366547*/count=744; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=745; tryItOut("/*RXUB*/var r = /\\d|(?=(?:])+)|([]\\W{0,3}([^]{1})){2,2}(?!(?=\\uD67b*?)(?=\u82e6$\u0014(?:\\uF5da))*|(?=(?!\\W)|(\\W)(?!.)[^]?*\\3))/gim; var s = \"_\"; print(s.search(r)); ");
/*fuzzSeed-66366547*/count=746; tryItOut("\"use strict\"; delete g2.h2.iterate;");
/*fuzzSeed-66366547*/count=747; tryItOut("v1 = Object.prototype.isPrototypeOf.call(v0, i1);");
/*fuzzSeed-66366547*/count=748; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( ~ ( + ( + ( + ( + ( + y))))))); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, -0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 42, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -Number.MAX_VALUE, -0x100000001, 2**53-2, Math.PI, -(2**53), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, 0x100000001, 0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1/0, 0x080000001, -0x100000000, Number.MAX_VALUE, 0/0, -1/0, 2**53, -(2**53-2), 1, 0x0ffffffff, -0x080000001, 0x100000000, 2**53+2]); ");
/*fuzzSeed-66366547*/count=749; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use asm\"; return Math.pow(( - Math.max(-1/0, ( - ( + ( + x))))), (mathy0((Math.min((Math.min(Math.ceil(( + Math.min(x, y))), (x >>> 0)) >>> 0), (( + (( + y) >= ( + y))) === mathy0(( + -0x100000000), -(2**53-2)))) | 0), ((Math.log10(Math.fround((Math.cos(((mathy0(-Number.MAX_SAFE_INTEGER, (2**53-2 >>> 0)) >>> 0) | 0)) | 0))) && Math.fround(( - Math.pow(((y >= y) !== mathy1(y, x)), Math.hypot(y, x))))) | 0)) | 0)); }); testMathyFunction(mathy2, [({toString:function(){return '0';}}), (new Boolean(true)), (new Boolean(false)), /0/, [0], (new String('')), false, (function(){return 0;}), 0, ({valueOf:function(){return '0';}}), 1, null, objectEmulatingUndefined(), true, undefined, '', (new Number(0)), '0', (new Number(-0)), '\\0', '/0/', NaN, [], -0, ({valueOf:function(){return 0;}}), 0.1]); ");
/*fuzzSeed-66366547*/count=750; tryItOut("\"use strict\"; g1.v1 = g0.eval(\"/*bLoop*/for (vjfbra = 0; vjfbra < 0; ++vjfbra) { if (vjfbra % 5 == 4) { g2 + ''; } else { g1.t0 + s0; }  } \");");
/*fuzzSeed-66366547*/count=751; tryItOut("\"use strict\"; v1 = (p2 instanceof p0);");
/*fuzzSeed-66366547*/count=752; tryItOut("\"use strict\"; \"use asm\"; v0 = (o0 instanceof t2);");
/*fuzzSeed-66366547*/count=753; tryItOut("\"use strict\"; with({d: ({x: (4277), x: (\nreturn null / let (e = this) \"\\uC98F\") })})for (var p in m1) { try { o1.valueOf = (function() { for (var j=0;j<19;++j) { f2(j%2==1); } }); } catch(e0) { } v0 = Object.prototype.isPrototypeOf.call(o0.t2, i2); }Array.prototype.shift.apply(a2, []);");
/*fuzzSeed-66366547*/count=754; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((((((~~(-1.015625)) == (~~(+(((0xe3feb86f))>>>((0xfecb03f2))))))+(i1)) >> (((0x0))-(0xff88ecdb)-(0xfacae0a3))) % (((i1)+((imul((i1), (0xa71478fe))|0))+(-0x8000000)) << ((~((i1)+(0x1236a91f)+(0x17e30d1a))) / (((0x5ed30999))|0)))))|0;\n  }\n  return f; })(this, {ff: function(y) { return x }}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [Math.PI, 0x100000001, 2**53+2, Number.MAX_VALUE, -0x100000000, 42, -Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, 2**53, -0, -0x080000000, -(2**53-2), -0x07fffffff, 1, -(2**53), -0x0ffffffff, 1/0, -0x100000001, 0x080000001, 0/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -0x080000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 2**53-2, -Number.MIN_VALUE, 0x100000000, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=755; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.min((mathy0((((Math.fround((( + Math.trunc(( + x))) > (Math.clz32((x >>> 0)) >>> 0))) != Math.fround((x ? (Math.expm1(( + (Math.max(( + y), ( + y)) | 0))) | 0) : Math.hypot((y | 0), (x | 0))))) | 0) >>> 0), (Math.fround((Math.fround(Math.fround((x || (( - -(2**53+2)) | 0)))) ** Math.fround(y))) >>> 0)) >>> 0), Math.atan2(Math.min((( ! ((Number.MIN_SAFE_INTEGER ? x : Math.fround(( ! y))) | 0)) >>> 0), ( + ( ! ((( + (x | 0)) >>> 0) | 0)))), Math.max(( + y), (Math.min((Math.fround(( - 0.000000000000001)) | 0), (0x0ffffffff | 0)) | 0)))); }); testMathyFunction(mathy1, [-0, -0x080000000, Number.MIN_VALUE, 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, -0x080000001, 0, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -0x100000000, 0x080000000, 0x100000001, 1/0, 1.7976931348623157e308, 0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), 2**53+2, Number.MAX_VALUE, 1, Math.PI, 0x0ffffffff, 42, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, 2**53-2, -0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=756; tryItOut("\"use strict\"; /*infloop*/for(let String.prototype.split in ((neuter)( '' )))print(x);");
/*fuzzSeed-66366547*/count=757; tryItOut("\"use strict\"; x = linkedList(x, 252);");
/*fuzzSeed-66366547*/count=758; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-66366547*/count=759; tryItOut("/*oLoop*/for (let sbetvq = 0; sbetvq < 73; ++sbetvq) { for (var p in s2) { try { t1[2] = this.e1; } catch(e0) { } try { m1.delete(f2); } catch(e1) { } try { for (var v of e0) { try { g0.m2 = new Map; } catch(e0) { } try { a1.push(p0, this.g2.i2, g2, e1, g1, i2, b0, this.i1); } catch(e1) { } try { v2 + ''; } catch(e2) { } print(b0); } } catch(e2) { } v0 = o0.t2.length; } } ");
/*fuzzSeed-66366547*/count=760; tryItOut("mathy5 = (function(x, y) { return ( ~ (Math.asinh((Math.hypot(( + ( + Math.imul(mathy4((x >>> 0), (y | 0)), x))), -0x080000001) | 0)) | 0)); }); testMathyFunction(mathy5, [1/0, 0x07fffffff, -1/0, 42, 0, 0x100000001, -0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x080000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), -Number.MAX_VALUE, Number.MAX_VALUE, -0x080000000, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -(2**53+2), 0x080000001, -0, 0/0, 2**53-2, 2**53, 1, 0x080000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=761; tryItOut("v2 = Object.prototype.isPrototypeOf.call(this.a0, o2.e0);");
/*fuzzSeed-66366547*/count=762; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.round(Math.atan2(( + ( - ( + Math.log(Math.fround(( ! x)))))), Math.fround(( - (Math.sqrt(( + (Math.abs((y >>> 0)) >>> 0))) | 0)))))); }); testMathyFunction(mathy0, [0/0, Math.PI, -0, -Number.MAX_SAFE_INTEGER, 0, -0x07fffffff, 0x100000000, 42, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, 2**53, 0x080000001, -0x080000000, -(2**53), -0x0ffffffff, 1/0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0.000000000000001, 1, -Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, -0x100000001, Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, -Number.MIN_VALUE, -1/0, -(2**53+2), -0x100000000]); ");
/*fuzzSeed-66366547*/count=763; tryItOut("g1.s1 += 'x';");
/*fuzzSeed-66366547*/count=764; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.cos(Math.fround(Math.atan2((((((x | 0) !== (y | 0)) | 0) & ( + Math.pow(( + (Math.cos(y) >>> 0)), ( + y)))) >>> 0), (((x >>> 0) > (( ~ y) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-66366547*/count=765; tryItOut("Object.defineProperty(this, \"i2\", { configurable:  /x/ , enumerable: (x % 3 == 1),  get: function() {  return m2.values; } });");
/*fuzzSeed-66366547*/count=766; tryItOut("a1 + '';");
/*fuzzSeed-66366547*/count=767; tryItOut("\"use strict\"; g1.o1.a1 = new Array;");
/*fuzzSeed-66366547*/count=768; tryItOut("let (d) { a0 = Array.prototype.slice.call(a2, NaN, -5);\n \"\" \ne0.add(g2); }");
/*fuzzSeed-66366547*/count=769; tryItOut("o1.m0.has(g0.t1);");
/*fuzzSeed-66366547*/count=770; tryItOut("this.v1 = evalcx(\"\\\"use strict\\\"; mathy4 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var Infinity = stdlib.Infinity;\\n  var ff = foreign.ff;\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    (Float32ArrayView[4096]) = ((Float64ArrayView[4096]));\\n    d1 = (+(1.0/0.0));\\n    d1 = (+((((((0xbe8d440a)+(0xfd6006d4)+(0xf0c75d7e)) | ((0xffdd835))) != ((((-16383.0) <= (-1.1805916207174113e+21))+((0xfbbeb976) ? (0xbadeb4a6) : (0xfc06fd70))) | ((0x3617cf5) / (0x31898f9b)))) ? (d1) : (d1))));\\n/* no regression tests found */    d0 = (d0);\\n    return ((((((0x788590d6)-(0x5209c5f6)-((-4.722366482869645e+21) > (-((Infinity)))))>>>((0xfc0409c2)+(-0x8000000)-((0xffffffff) ? (0xe640506f) : (/*FFI*/ff(((-9.671406556917033e+24)))|0)))))*-0xfffff))|0;\\n  }\\n  return f; })(this, {ff: (function(x, y) { return (Math.min(Math.fround(Math.log2(Number.MAX_SAFE_INTEGER)), y) * 2**53+2); })}, new ArrayBuffer(4096)); testMathyFunction(mathy4, ['0', (new String('')), [], /0/, (new Number(0)), '', ({valueOf:function(){return 0;}}), 1, (function(){return 0;}), null, undefined, NaN, false, ({toString:function(){return '0';}}), true, (new Boolean(true)), 0, ({valueOf:function(){return '0';}}), (new Number(-0)), 0.1, '\\\\0', [0], objectEmulatingUndefined(), -0, '/0/', (new Boolean(false))]); \", this.g1);");
/*fuzzSeed-66366547*/count=771; tryItOut("M:if(false) { \"\" ;t1.set(a2, 6);v0 = Object.prototype.isPrototypeOf.call(o0, e0); } else {print(x); }");
/*fuzzSeed-66366547*/count=772; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((\\\\cH)?){1,}|(?!(?!\\\\D+?|\\\\cO|(?:\\u0005))+|\\\\n)^\", \"y\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-66366547*/count=773; tryItOut("t0[({valueOf: function() { /*vLoop*/for (bplauf = 0, hunvyj; bplauf < 83; ++bplauf) { z = bplauf; print(-17); } for (var p in t1) { try { a2 = r2.exec(s1); } catch(e0) { } v2 = o0.t1.BYTES_PER_ELEMENT; }return 15; }})] = (4277);");
/*fuzzSeed-66366547*/count=774; tryItOut("m1.toString = (function() { for (var j=0;j<11;++j) { f1(j%5==1); } });");
/*fuzzSeed-66366547*/count=775; tryItOut("\"use strict\"; v0 = t0.length;\nm1.set(f0, p1);\n");
/*fuzzSeed-66366547*/count=776; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o2, p2);");
/*fuzzSeed-66366547*/count=777; tryItOut("o0.valueOf = (function mcc_() { var bwhcqc = 0; return function() { ++bwhcqc; if (false) { dumpln('hit!'); try { Array.prototype.shift.apply(o0.a2, [b2]); } catch(e0) { } try { g2.g2.v1 = o0.a1.reduce, reduceRight(p2, m0); } catch(e1) { } selectforgc(this.o2); } else { dumpln('miss!'); v0 = (a2 instanceof m1); } };})();");
/*fuzzSeed-66366547*/count=778; tryItOut("(Math.ceil(-14))//h\n;");
/*fuzzSeed-66366547*/count=779; tryItOut("\"use strict\"; i2 = e1.entries;function b(eval = ++(a), {z: [, ]}) { \"use strict\"; return (((uneval(x)))\n) } print((/*UUV1*/(y.startsWith = Math.min)));");
/*fuzzSeed-66366547*/count=780; tryItOut("g0.b1 = new ArrayBuffer(12);");
/*fuzzSeed-66366547*/count=781; tryItOut("f2 + '';");
/*fuzzSeed-66366547*/count=782; tryItOut("for (var v of e1) { h2 = ({getOwnPropertyDescriptor: function(name) { i1 + t1;; var desc = Object.getOwnPropertyDescriptor(h0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { throw h0; var desc = Object.getPropertyDescriptor(h0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { throw t0; Object.defineProperty(h0, name, desc); }, getOwnPropertyNames: function() { o2.e1.add(p2);; return Object.getOwnPropertyNames(h0); }, delete: function(name) { i0.next();; return delete h0[name]; }, fix: function() { o1.f1(i0);; if (Object.isFrozen(h0)) { return Object.getOwnProperties(h0); } }, has: function(name) { Object.freeze(p2);; return name in h0; }, hasOwn: function(name) { print(this.i1);; return Object.prototype.hasOwnProperty.call(h0, name); }, get: function(receiver, name) { print(o0);; return h0[name]; }, set: function(receiver, name, val) { /*RXUB*/var r = r0; var s = \"(\\u0085\\u00d1(\\u0085\\u00d1(\\u0085\\u00d1(\\u0085\\u00d1\"; print(s.match(r)); ; h0[name] = val; return true; }, iterate: function() { this.o1.v2 = (i1 instanceof p2);; return (function() { for (var name in h0) { yield name; } })(); }, enumerate: function() { v0 = t1.length;; var result = []; for (var name in h0) { result.push(name); }; return result; }, keys: function() { v1 = t0.length;; return Object.keys(h0); } }); }");
/*fuzzSeed-66366547*/count=783; tryItOut("for(let w = eval(\"/* no regression tests found */\") in window = d) {/*tLoop*/for (let a of /*MARR*/[objectEmulatingUndefined(), true, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, new Boolean(true), Infinity, true, new Boolean(true), true, new Boolean(true), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(true), 2, new Boolean(true), 2, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity, true, new Boolean(true), objectEmulatingUndefined(), 2, new Boolean(true), Infinity, objectEmulatingUndefined(), 2, objectEmulatingUndefined(), true, Infinity, new Boolean(true), Infinity, true, 2, Infinity, 2, new Boolean(true), true, 2, 2, new Boolean(true), objectEmulatingUndefined(), new Boolean(true), 2, objectEmulatingUndefined(), true, new Boolean(true), 2, true, objectEmulatingUndefined(), true, new Boolean(true), Infinity, new Boolean(true), Infinity, Infinity, Infinity, true, true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), 2, Infinity, 2, Infinity, true, Infinity, true, 2, 2, true, Infinity, true, new Boolean(true), objectEmulatingUndefined()]) { (\"\\u70D3\"); }g1.a2 = new Array; }");
/*fuzzSeed-66366547*/count=784; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-66366547*/count=785; tryItOut("mathy1 = (function(x, y) { return (Math.min(((( - ((Math.fround(y) <= ( ! y)) | 0)) | 0) | 0), Math.abs(Math.log1p(Number.MAX_VALUE))) <= mathy0((Math.fround(Math.sign(Math.fround(-0x100000000))) | 0), Math.atan2(y, Math.imul((((0 | 0) == x) >>> 0), (-0x080000000 >>> 0))))); }); testMathyFunction(mathy1, [0x100000001, 1, -0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -0, -0x080000000, -0x07fffffff, 0, Math.PI, 0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), -Number.MIN_VALUE, 0x100000000, -1/0, 1/0, 0/0, 1.7976931348623157e308, 0x080000001, -0x0ffffffff, 0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=786; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=\\\\3((?:\\\\1+)))\", \"yi\"); var s = \"\\u58e1\\u58e1\\u58e1o\\n\\n\\u58e1\\u58e1\\u58e1(\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-66366547*/count=787; tryItOut("print(x);throw window.tanh(false);");
/*fuzzSeed-66366547*/count=788; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - ( + ((((Math.min((mathy0(y, y) | 0), (Math.fround(( ~ Math.fround((y < 0x100000000)))) | 0)) | 0) | 0) ^ (0x080000000 | 0)) % ( + ( + ((y && Math.fround(( + ( + 0x07fffffff)))) >>> 0)))))); }); testMathyFunction(mathy3, [0x100000001, 0x080000000, 42, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, 2**53-2, -(2**53-2), 1/0, 0/0, -0x080000000, -(2**53), 0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53, 1.7976931348623157e308, -0x0ffffffff, -0x100000001, Math.PI, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 1, 0x0ffffffff, -0, 0x07fffffff, -1/0]); ");
/*fuzzSeed-66366547*/count=789; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=790; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.trunc(Math.log10(Math.exp((((-0 >>> 0) > (Math.expm1((y , ( ~ (x >>> 0)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy2, [0.000000000000001, -0x100000001, -0, 1/0, 0x100000000, 1.7976931348623157e308, -Number.MAX_VALUE, 1, -(2**53-2), Number.MAX_VALUE, 0/0, 0x07fffffff, 0x080000000, 0x080000001, -(2**53+2), 0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, Math.PI, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, 2**53+2, -1/0, 2**53-2, 42, -(2**53), -0x080000000, 0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=791; tryItOut("v0 = this.b0.byteLength;");
/*fuzzSeed-66366547*/count=792; tryItOut("for(let [y, b] = y in new RegExp(\"(?!^+?(?=\\\\b*))(?=[^]|(?:[\\\\\\u00fa-\\ucda4\\\\D\\\\D\\\\M-\\\\u0081]|\\\\B){4,}{0,})\", \"m\")) {m2.has(m1); }");
/*fuzzSeed-66366547*/count=793; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\3{0}(?:[^])|.[\\\\uA1d3-\\\\\\u00ec\\\\x7d\\u0091\\\\cR])|$|(?=(?!\\\\x3d))|\\\\~*|$\\\\B\\\\2\\\\w|(?:[^]{1,}|\\\\1){3,4}*(?!\\\\w){524287}^{32,}{2,}|(?:([^]))\\u0007\", \"i\"); var s = \"\\uffe7\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=794; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.max((Math.clz32(Math.log10(( + Math.atan2(( + ( - 0x100000001)), Math.fround((x | Math.fround(x))))))) << Math.fround((( + (( ! (mathy3(Math.log10(x), x) >>> 0)) >>> 0)) | 0))), Math.max((( - (-0x100000000 ? -(2**53-2) : Math.min((Math.hypot((y >>> 0), (y >>> 0)) >>> 0), ( - y)))) >>> 0), ( + Math.ceil(Math.fround((Math.atan(( + mathy1(Math.fround((y & Number.MIN_SAFE_INTEGER)), x))) | 0)))))) >>> 0); }); testMathyFunction(mathy4, [0x100000001, -0x0ffffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, 1/0, -1/0, -0x080000000, 42, 0x07fffffff, 0/0, -(2**53), -Number.MIN_VALUE, -0x07fffffff, -0x080000001, 0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, -0, 1, 2**53, 1.7976931348623157e308, 0x080000001, -(2**53-2), -Number.MAX_VALUE, 0x100000000, -0x100000000, -(2**53+2), 2**53+2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-66366547*/count=795; tryItOut("/*vLoop*/for (ttdrwm = 0, x = x; ttdrwm < 18; ++ttdrwm) { let d = ttdrwm; print(x); } ");
/*fuzzSeed-66366547*/count=796; tryItOut(" for  each(let d in x) x = d % x; var r0 = 3 * 3; var r1 = d ^ 0; var r2 = r1 ^ r0; var r3 = d % r0; x = 8 / 8; var r4 = x | 1; r4 = 6 - r0; var r5 = d / r1; var r6 = 8 / 7; var r7 = 5 - 1; var r8 = 2 / r1; var r9 = r8 % 9; var r10 = r3 & r7; var r11 = 5 | 3; var r12 = 7 - r2; var r13 = r1 * r3; var r14 = r13 / 3; var r15 = r8 ^ r10; r10 = r13 / r1; var r16 = r15 & d; var r17 = 6 * r2; var r18 = d % 7; var r19 = r7 % r12; r5 = 2 + r6; var r20 = r8 ^ x; var r21 = 4 - r14; r21 = r2 & r2; var r22 = 4 & r9; var r23 = r16 | x; var r24 = r7 | 1; var r25 = r22 & r20; r18 = r19 / 0; var r26 = r11 - r13; var r27 = r5 & r0; var r28 = 8 / r21; var r29 = r15 ^ r13; r21 = r23 * r29; var r30 = 1 / r10; var r31 = 5 + r9; var r32 = 4 / r29; var r33 = 5 | 7; r2 = r15 / r7; var r34 = r14 * r0; var r35 = r19 / r16; var r36 = 7 / 6; var r37 = 1 | 9; r3 = 5 / 9; var r38 = 3 ^ r12; var r39 = d - r12; var r40 = r7 | r37; var r41 = 0 | r13; var r42 = 9 * 5; var r43 = 4 | d; var r44 = 7 + r38; ");
/*fuzzSeed-66366547*/count=797; tryItOut("\"use strict\"; e0.add(f0);");
/*fuzzSeed-66366547*/count=798; tryItOut("\"use strict\"; v1 = (o0 instanceof v1);");
/*fuzzSeed-66366547*/count=799; tryItOut("/*RXUB*/var r = /(?=\\s)|\\b+|(?!^(?![^](?:\\\u8081)*?)+?)/gym; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-66366547*/count=800; tryItOut("");
/*fuzzSeed-66366547*/count=801; tryItOut("\"use strict\"; /*bLoop*/for (let nplnzs = 0; nplnzs < 19; ++nplnzs) { if (nplnzs % 73 == 2) { /*RXUB*/var r = new RegExp(\"\\\\1\", \"\"); var s = \"\"; print(s.replace(r, ((let (fukzaj) \"\\u1BD1\")()), \"gy\")); print(r.lastIndex);  } else { /*ADP-3*/Object.defineProperty(g0.a0, x, { configurable: true, enumerable: true, writable: y, value: o2.o2.a0 }); }  } ");
/*fuzzSeed-66366547*/count=802; tryItOut("v0 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 7 == 2), noScriptRval: (x % 45 != 32), sourceIsLazy: x, catchTermination: false }));");
/*fuzzSeed-66366547*/count=803; tryItOut("f2 = (function(j) { if (j) { try { t2 + ''; } catch(e0) { } v0 = a0.length; } else { try { h0 + h2; } catch(e0) { } Array.prototype.pop.apply(a1, [o2.s2]); } });");
/*fuzzSeed-66366547*/count=804; tryItOut("mathy0 = (function(x, y) { return Math.expm1(( - Math.cbrt(((x - Math.trunc(Math.fround(y))) >>> 0)))); }); testMathyFunction(mathy0, [2**53-2, -Number.MIN_VALUE, -0x080000001, 0.000000000000001, 0x100000000, 0/0, -(2**53), -(2**53+2), -0x0ffffffff, -1/0, 0x080000001, -0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, Math.PI, 0x07fffffff, -0x080000000, Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), 1.7976931348623157e308, 42, 0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, -0x100000000, 1, 0x080000000, 2**53, -0x100000001]); ");
/*fuzzSeed-66366547*/count=805; tryItOut("t1 = new Float32Array(a0);");
/*fuzzSeed-66366547*/count=806; tryItOut("{ void 0; verifyprebarriers(); } p1 = a1[6];");
/*fuzzSeed-66366547*/count=807; tryItOut("\"use strict\"; e1.add(b2);");
/*fuzzSeed-66366547*/count=808; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, -0x100000001, 0x080000000, -(2**53+2), -Number.MAX_VALUE, 2**53+2, Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, 1/0, 0x080000001, 1.7976931348623157e308, -0x100000000, 2**53, 0.000000000000001, 1, Number.MAX_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, 0, Math.PI, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, 0x100000001, -(2**53), -1/0, 0x100000000, -0x080000001, 2**53-2, 42, Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-66366547*/count=809; tryItOut("mathy5 = (function(x, y) { return Math.sin(( + (Math.hypot((2**53 ^ Math.fround(42)), ( + mathy2(Math.pow(0x07fffffff, y), mathy3(Number.MIN_SAFE_INTEGER, Math.hypot(Math.hypot(x, Math.fround(y)), x))))) | 0))); }); testMathyFunction(mathy5, [false, '/0/', 0.1, NaN, 1, '\\0', (new Number(-0)), [0], (new Boolean(false)), '0', ({valueOf:function(){return 0;}}), [], -0, ({valueOf:function(){return '0';}}), 0, (new Boolean(true)), ({toString:function(){return '0';}}), true, /0/, objectEmulatingUndefined(), (new Number(0)), undefined, (new String('')), null, (function(){return 0;}), '']); ");
/*fuzzSeed-66366547*/count=810; tryItOut("\"use strict\"; (((d) = null));function x(\u3056)\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1.5111572745182865e+23;\n    var i3 = 0;\n    var i4 = 0;\n    var i5 = 0;\n    return +((Float32ArrayView[0]));\n  }\n  return f;var ufzsae = new ArrayBuffer(6); var ufzsae_0 = new Float32Array(ufzsae); print(ufzsae_0[0]); yield;");
/*fuzzSeed-66366547*/count=811; tryItOut("\"use strict\"; Array.prototype.push.apply(a0, [o0]);");
/*fuzzSeed-66366547*/count=812; tryItOut("m1.delete(b2);");
/*fuzzSeed-66366547*/count=813; tryItOut("testMathyFunction(mathy1, [-Number.MIN_VALUE, 1/0, -0x100000001, 0x100000000, -0x080000001, -0, 0/0, -(2**53+2), -1/0, 0x080000000, -0x0ffffffff, 0x0ffffffff, Number.MAX_VALUE, -0x080000000, Number.MIN_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, 2**53, 0, Math.PI, -(2**53), 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 1, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 0x080000001, -Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, 0x07fffffff, 2**53-2, -Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=814; tryItOut("\"use strict\"; a2.forEach((function() { for (var j=0;j<101;++j) { f2(j%4==1); } }), h0, s2, this.s1, this.i2, v0);let h2 = ({getOwnPropertyDescriptor: function(name) { a0.unshift(i2, o0.i1, v1, g2.o1);; var desc = Object.getOwnPropertyDescriptor(a0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { return o1; var desc = Object.getPropertyDescriptor(a0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { s1 += 'x';; Object.defineProperty(a0, name, desc); }, getOwnPropertyNames: function() { for (var v of v2) { Object.preventExtensions(i1); }; return Object.getOwnPropertyNames(a0); }, delete: function(name) { const v2 = g2.runOffThreadScript();; return delete a0[name]; }, fix: function() { for (var p in h1) { o1.v0 = b0.byteLength; }; if (Object.isFrozen(a0)) { return Object.getOwnProperties(a0); } }, has: function(name) { v0 = Object.prototype.isPrototypeOf.call(s2, p1);; return name in a0; }, hasOwn: function(name) { v1 = this.g1.eval(\"/* no regression tests found */\");; return Object.prototype.hasOwnProperty.call(a0, name); }, get: function(receiver, name) { s2 += s1;; return a0[name]; }, set: function(receiver, name, val) { selectforgc(g0.o1);; a0[name] = val; return true; }, iterate: function() { g2.offThreadCompileScript(\"\\\"use strict\\\"; mathy4 = (function(x, y) { return ( + ( ! (( + (Math.atan2(( + Math.fround(( - y))), ( + (Math.fround(Math.fround(Math.fround(0x100000001))) ? x : Math.fround((0x100000001 <= Math.fround(Math.sqrt(-0x07fffffff))))))) | 0)) | 0))); }); testMathyFunction(mathy4, [-(2**53+2), -0x100000000, 1.7976931348623157e308, 0x0ffffffff, 0x100000001, 42, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0, 1, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, -0x100000001, Math.PI, 2**53, Number.MIN_SAFE_INTEGER, 2**53-2, 0x07fffffff, -(2**53), 0x080000001, 0.000000000000001, -Number.MIN_VALUE, -(2**53-2), -0x080000000, -0x080000001, -1/0, -0x07fffffff, 1/0, 0/0, 2**53+2, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0, 0x080000000]); \", ({ global: this.g1, fileName: null, lineNumber: 42, isRunOnce:  /x/  ? -10 : window, noScriptRval: false, sourceIsLazy: (x % 6 != 2), catchTermination: true }));; return (function() { for (var name in a0) { yield name; } })(); }, enumerate: function() { v0 = g1.runOffThreadScript();; var result = []; for (var name in a0) { result.push(name); }; return result; }, keys: function() { Array.prototype.push.call(a0, f0);; return Object.keys(a0); } });");
/*fuzzSeed-66366547*/count=815; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[new String(''), [], [],  \"\" , 0x100000000, [],  \"\" , 0x100000000, new String(''),  \"\" , [], new String(''), new String(''), [], new String(''),  \"\" ,  \"\" , 0x100000000, new String(''), new String(''), [],  \"\" , 0x100000000, [], new String(''), [], 0x100000000, new String(''), new String(''), 0x100000000, new String(''), [],  \"\" , [], 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, 0x100000000, [], 0x100000000, new String(''), 0x100000000, new String(''), 0x100000000, new String(''), new String(''),  \"\" , new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''),  \"\" , new String(''), [], new String(''),  \"\" ]) { Array.prototype.push.apply(a2, [s1]); }");
/*fuzzSeed-66366547*/count=816; tryItOut("v0 = t1.length;");
/*fuzzSeed-66366547*/count=817; tryItOut("/*tLoop*/for (let d of /*MARR*/[{x:3}, {x:3}, {x:3}, .2, (1/0), {x:3}, {x:3}, (1/0), .2,  '\\0' , (1/0),  '\\0' ,  '\\0' , .2,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , (1/0),  '\\0' ,  '\\0' , (1/0), .2, {x:3},  '\\0' ,  '\\0' , (1/0), {x:3}, {x:3}, .2, (1/0), .2,  '\\0' , (1/0),  '\\0' , .2,  '\\0' ,  '\\0' , (1/0), .2, (1/0),  '\\0' , {x:3}, .2, .2,  '\\0' , (1/0),  '\\0' ,  '\\0' , {x:3}, (1/0),  '\\0' ,  '\\0' , .2, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0)]) { print([,,z1]); }");
/*fuzzSeed-66366547*/count=818; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.pow(Math.asinh(Math.imul(Math.fround(( ~ ( + ( + ( + Math.cosh(Math.fround(y))))))), Math.pow(( + Math.log1p(( + x))), y))), (Math.max(x, (( + Math.ceil(( + ((( ! y) >>> 0) % y)))) | 0)) !== (mathy2((mathy2(Math.fround((Math.fround(x) % Math.fround(x))), (Math.max(((x + (0.000000000000001 >>> 0)) >>> 0), (2**53+2 >>> 0)) >>> 0)) >>> 0), (((Math.atanh(( ! -0x07fffffff)) <= Math.fround(( ! y))) >>> 0) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [0.000000000000001, -0x0ffffffff, Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, -Number.MAX_VALUE, -0x080000001, 0x07fffffff, 42, -Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, -0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53, -0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, -(2**53), 0x080000000, -0x100000001, 0x080000001, Math.PI, -0x07fffffff, -(2**53-2), 1, -1/0, 0x100000001]); ");
/*fuzzSeed-66366547*/count=819; tryItOut("v1 = (t2 instanceof m0);");
/*fuzzSeed-66366547*/count=820; tryItOut(";function x(w = x--, x)\"use asm\";   var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 1.25;\n    i0 = (0xd07cdc8d);\n    i1 = (i1);\n    (Int16ArrayView[(((d2) >= (+(~((i1)))))) >> 1]) = (((-3.0) != (-524289.0)));\n    (Float32ArrayView[((i1)) >> 2]) = ((d2));\n    return +((d2));\n  }\n  return f;for (var v of s2) { v0.toSource = (function() { for (var j=0;j<58;++j) { f0(j%2==0); } }); }");
/*fuzzSeed-66366547*/count=821; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=822; tryItOut("mathy3 = (function(x, y) { return Math.acos(Math.hypot(( + ( + (( - (x >>> 0)) >>> 0))), (( + Math.asin(Math.sign((y ? -0x07fffffff : ( + x))))) >>> 0))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, 42, -0x0ffffffff, 2**53, -(2**53+2), 1/0, -0x080000000, 1, -0x100000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -0x080000001, -0x07fffffff, Math.PI, 0x100000000, 2**53-2, -1/0, 0/0, 0x0ffffffff, -0x100000000, 0, 0x080000001, -(2**53-2), -Number.MAX_VALUE, 0.000000000000001, 0x100000001, -0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=823; tryItOut("if(false) v1 = g1.eval(\"h1 + '';\"); else  if ((b) = NaN) g0.e2 = new Set(o0); else for (var v of o2.a1) { g0.offThreadCompileScript(\"function f2(a2) \\\"use asm\\\";   var abs = stdlib.Math.abs;\\n  var pow = stdlib.Math.pow;\\n  var Int32ArrayView = new stdlib.Int32Array(heap);\\n  var Int8ArrayView = new stdlib.Int8Array(heap);\\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\\n  var Float32ArrayView = new stdlib.Float32Array(heap);\\n  function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    (Int32ArrayView[(((((-0x8000000)-(0xbddfd67c)+(0x63e90c17)) & (-0x4e3a9*(0x3eba4f0b))))*-0x29dc7) >> 2]) = ((((d1) > (+(((0xbcfd55ed)) >> ((0x631e5a4f))))) ? ((((0x3511387f)+(0xb3785bca)-(0xcc99023f)) >> ((0xea9c911b)))) : (((Int8ArrayView[((0xffffffff)-(0x213584b7)) >> 0])) < (+(((( + (((( + (( ~ x) | 0)) | 0) | 0) ? (( + Math.ceil(( + 0x100000000))) | 0) : ( ! Math.max(( + Math.fround(Math.max(( + -0), Math.fround(x)))), Math.hypot(Math.imul(( + (Math.fround(x) | ( + x))), 1.7976931348623157e308), 2**53-2))))) + ( + ( + Math.min(Math.fround(Math.pow(( + Math.imul(Math.fround(((Math.cbrt((-Number.MIN_VALUE | 0)) | 0) <= Math.atan2(x, x))), Math.fround(0x080000001))), (( + (x <= Math.fround(x))) || Math.fround(Math.exp(x))))), ( + Math.min(( + (((Math.asin((-(2**53+2) | 0)) | 0) != Math.fround(Math.hypot(-0x080000000, Math.fround(-Number.MAX_SAFE_INTEGER)))) % 2**53-2)), ((x | 0) >> ( + (x && Number.MAX_SAFE_INTEGER))))))))) >>> 0)))))-(0x26a85614)-(i0));\\n    (Uint16ArrayView[((0x74360ff8) % (0x1d209c7)) >> 1]) = (((!(i0)) ? ((((i0)-(i0))>>>((i0)))) : (!(0x22ee29f)))*0xfffff);\\n    i0 = (((((0xcacb5ee7))-(-0x8000000)-(0x9e6f4ac2)) & (((~~(1.9342813113834067e+25)) == (((0xf284336c)-(i0))|0))+(i0))) > ((((+abs(((+(0.0/0.0))))) != (+pow(((((7.555786372591432e+22)) - ((-36893488147419103000.0)))), ((Float32ArrayView[1])))))) >> (-(0xc17465cb))));\\n    i0 = (i0);\\n    return +((1125899906842625.0));\\n  }\\n  return f;\"); }");
/*fuzzSeed-66366547*/count=824; tryItOut("\"use strict\"; /*infloop*/ for (b of (x /= (window == 2))) {/*RXUB*/var r = new RegExp(\"((\\\\w|$|\\\\b^|^?[]*.{3,5}))\", \"gm\"); var s = \"\"; print(r.exec(s)); print(r.lastIndex);  }");
/*fuzzSeed-66366547*/count=825; tryItOut("\"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return ( + ( ~ Math.fround(Math.fround(Math.clz32(Math.fround(Math.pow((( ~ ( + (Math.clz32((x | 0)) ^ 2**53))) >>> 0), Math.fround((((( + y) > -(2**53+2)) + -(2**53)) !== y))))))))); }); testMathyFunction(mathy5, [-(2**53-2), 1/0, -0, 0x080000001, -0x07fffffff, 0.000000000000001, 1.7976931348623157e308, -(2**53+2), Number.MAX_VALUE, 2**53+2, 0x07fffffff, 0, 0x080000000, 2**53-2, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, 0x100000000, -0x0ffffffff, Math.PI, 1, 0x0ffffffff, -(2**53), 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53]); ");
/*fuzzSeed-66366547*/count=826; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( - ( + ( ~ ( + Math.pow(( + x), ( + ((Math.pow(((Math.fround(( - y)) !== -0x080000000) >>> 0), ((( + y) ^ ( ! y)) >>> 0)) >>> 0) << Math.atan2((mathy1(( + 0.000000000000001), (y >>> 0)) | 0), (Math.imul(y, y) | 0)))))))))); }); testMathyFunction(mathy2, [Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000000, -0x0ffffffff, 1/0, 0x080000001, 0x0ffffffff, 0, -0x100000001, 1.7976931348623157e308, -0x07fffffff, 2**53+2, 2**53-2, Number.MIN_VALUE, -(2**53-2), 0x07fffffff, -Number.MIN_VALUE, -1/0, Number.MAX_SAFE_INTEGER, -0x080000001, 42, 1, -(2**53), -Number.MAX_VALUE, 0/0, 0x100000001, Number.MAX_VALUE, 2**53, 0.000000000000001, 0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=827; tryItOut("print(x);/* no regression tests found */");
/*fuzzSeed-66366547*/count=828; tryItOut("function f1(p1)  { return  \"\"  } ");
/*fuzzSeed-66366547*/count=829; tryItOut("/*RXUB*/var r = /(?!\\1|\\3\\u0085*(?=[^]*?|.|[^]+)?(?=[^]|[]{1073741824,1073741824}){1}|(?=(?=\\D|.?+)|((\\W|\\b)*)*?))/im; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n{\\n\\nEE\\nEE\\nEEEE\"; print(s.replace(r, r((s\n)) = function(q) { return q; })); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=830; tryItOut("v2 = t2.byteOffset;");
/*fuzzSeed-66366547*/count=831; tryItOut("{ void 0; minorgc(true); } this.s1 = Proxy.create(h0, this.s1);");
/*fuzzSeed-66366547*/count=832; tryItOut("\"use strict\"; \n");
/*fuzzSeed-66366547*/count=833; tryItOut("if((new false(/*vLoop*/for (becbgq = 0; becbgq < 36; ++becbgq) { d = becbgq; v0 = a1.length; } ).yoyo(SyntaxError.prototype =  /x/g  * \"\\uFC94\"//h\n)).__defineSetter__(\" \\\"\\\" \", function(y) { return ( \"\"  || \"\\u4841\"\n) })) g1.e1.delete(o0.i2); else  if (x) {a1 = Proxy.create(h0, i2); }");
/*fuzzSeed-66366547*/count=834; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.max(( + (Math.atan2((y | 0), (Math.fround(Math.sinh(Math.fround(0/0))) | 0)) * ( + Math.fround((Math.fround(( ~ Math.log1p((1 >>> 0)))) | ( + (y >= (Math.min(-Number.MIN_VALUE, (x && 1.7976931348623157e308)) >>> 0)))))))), Math.log1p(( + ( ~ Math.hypot((Math.imul(x, ( + y)) >>> 0), Math.sign((x >>> 0))))))); }); ");
/*fuzzSeed-66366547*/count=835; tryItOut("t2 + m2;");
/*fuzzSeed-66366547*/count=836; tryItOut("/*vLoop*/for (let lnsgft = 0, Math.tanh(/\\b\\cN|[^\u334e\\cO]^{1,}^/gyi), yield ((function sum_slicing(cjqued) { v1 = Object.prototype.isPrototypeOf.call(g2, g2);; return cjqued.length == 0 ? 0 : cjqued[0] + sum_slicing(cjqued.slice(1)); })(/*MARR*/[new Number(1), arguments])); (x) && lnsgft < 84; ++lnsgft) { e = lnsgft; ((void options('strict'))); } ");
/*fuzzSeed-66366547*/count=837; tryItOut("L:if(true) { if ((4277)) p2 + '';} else {s0 = ''; }");
/*fuzzSeed-66366547*/count=838; tryItOut("a2.reverse(o0);");
/*fuzzSeed-66366547*/count=839; tryItOut("switch((4277)) { case true.unwatch(new String(\"10\")): x = this.g0.v2; }");
/*fuzzSeed-66366547*/count=840; tryItOut("\"use strict\"; /*bLoop*/for (let ihtncy = 0; ihtncy < 67; ++ihtncy) { if (ihtncy % 42 == 5) { /*infloop*/for(c = x; (let (z) new RegExp(\"(?![^]?.*)*?\\\\b(?=(?!(.+)))\", \"gm\")); x = \u3056) print(216133646); } else { print(x); }  } ");
/*fuzzSeed-66366547*/count=841; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return Math.atan(( + Math.imul(( + mathy2(Math.fround(mathy4(Math.fround(Math.atan((x >>> 0))), Math.fround(( ~ mathy1(( + Math.PI), Math.fround(y)))))), Math.ceil(Math.fround(( + (Math.sin(Math.fround(-1/0)) | 0)))))), (Math.pow(Math.fround(mathy3((Math.atan2((y >>> 0), (y >>> 0)) >>> 0), Math.ceil((x | 0)))), Math.fround(Math.imul(y, 1.7976931348623157e308))) | 0)))); }); ");
/*fuzzSeed-66366547*/count=842; tryItOut("const o1.v0 = a2.length;function yield([], x = this.watch(\"findIndex\", /^/gi), e, d, this.e, x, b, x, c, x, x, c, x, NaN =  /x/ , w, \u3056, y, e, NaN, d, x = null, w, \u3056, x, x, window, \u3056, getMinutes, x, a, x =  /x/g ) { \"use strict\"; yield (4277) } i1 = new Iterator(p1);");
/*fuzzSeed-66366547*/count=843; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( ~ ( + ((((Math.sqrt(Math.fround(x)) >>> 0) + (y >>> 0)) >>> 0) ? ( + x) : 0.000000000000001))) == ((Math.hypot((((x < y) , (((((Math.fround(y) > y) | y) | 0) >> ( ~ 1.7976931348623157e308)) | 0)) >>> 0), (Math.imul(Math.tan(Math.min(x, ( + (((y >>> 0) <= (y >>> 0)) >>> 0)))), (Math.max(x, ( + Math.tanh(x))) | 0)) >>> 0)) >>> 0) , (Math.tanh(Math.fround(Math.pow(Math.fround(( ~ 0x0ffffffff)), Math.fround(y)))) && x))); }); ");
/*fuzzSeed-66366547*/count=844; tryItOut("print(x);this.zzz.zzz;");
/*fuzzSeed-66366547*/count=845; tryItOut("let x, lgqcza, window, plawcv, x, x, x;return 11;");
/*fuzzSeed-66366547*/count=846; tryItOut("s2.toSource = (function(j) { if (j) { try { m2.get(m1); } catch(e0) { } try { e2.add(b1); } catch(e1) { } Array.prototype.push.apply(a2, []); } else { try { Array.prototype.shift.apply(a1, []); } catch(e0) { } try { g2.i0 = t0[6]; } catch(e1) { } a2 = i1; } });");
/*fuzzSeed-66366547*/count=847; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\1|(?:(((?!(?=[\\\\v-\\u0087]))))){4,4}|\\\\2|(($))^)\", \"m\"); var s = \"\\\\\\\\\\\\\\\\\\\\\"; print(s.split(r)); ");
/*fuzzSeed-66366547*/count=848; tryItOut("for (var v of t0) { try { this.e2.add(b2); } catch(e0) { } try { m2 = new Map; } catch(e1) { } try { v2 = Array.prototype.some.call(o0.a1, (function() { for (var j=0;j<8;++j) { f2(j%2==0); } })); } catch(e2) { } Array.prototype.shift.apply(a0, []); }");
/*fuzzSeed-66366547*/count=849; tryItOut("\"use strict\"; \"use asm\"; print(i2);");
/*fuzzSeed-66366547*/count=850; tryItOut("v1 = Object.prototype.isPrototypeOf.call(f1, o0.o0);");
/*fuzzSeed-66366547*/count=851; tryItOut("mathy3 = (function(x, y) { return ( ~ ((( ! Math.imul((( - ((Math.pow((y | 0), ((x + x) | 0)) | 0) >>> 0)) ? (x % Math.fround(( + Math.fround(y)))) : Math.fround(( ~ x))), Math.sin(x))) >>> 0) | 0)); }); ");
/*fuzzSeed-66366547*/count=852; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( + ( + ( + (Math.fround((Math.fround((Number.MAX_VALUE === y)) << (x | 0))) % Math.expm1(y))))) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[ /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , undefined, undefined, false, objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , false,  /x/ ,  /x/ ,  /x/ , false, false, undefined, false, false, false, false, false, false, false, false, false, false, undefined, false, false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, undefined,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , undefined, objectEmulatingUndefined(), false, false, false, objectEmulatingUndefined(),  /x/ , undefined, objectEmulatingUndefined(), false, false, false,  /x/ , false, objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), undefined, objectEmulatingUndefined(), false,  /x/ , objectEmulatingUndefined(), undefined, undefined, objectEmulatingUndefined(), undefined]); ");
/*fuzzSeed-66366547*/count=853; tryItOut("\"use strict\"; print(uneval(f0));");
/*fuzzSeed-66366547*/count=854; tryItOut("Array.prototype.pop.apply(a1, [g0.t1]);");
/*fuzzSeed-66366547*/count=855; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return Math.trunc((Math.fround(Math.fround(( + Math.fround(Math.imul(Math.asinh(Math.abs(x)), (y >= x)))))) | Math.atan2(Math.pow(( + ((y <= -Number.MAX_SAFE_INTEGER) % ( + Math.atan2(( + y), ( + x))))), y), Math.fround(Math.min(Math.fround((((y >>> 0) || Math.fround(x)) >>> 0)), Math.min(x, x)))))); }); testMathyFunction(mathy2, [-0x080000001, 1.7976931348623157e308, -(2**53), -Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, 2**53+2, -1/0, 0x100000000, 2**53, -0x080000000, 0x0ffffffff, Number.MAX_VALUE, 0, -Number.MAX_VALUE, -0, -0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, Number.MIN_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, -Number.MAX_SAFE_INTEGER, 42, 0x07fffffff, -(2**53+2), 1, 0x080000001, -0x100000001, 2**53-2]); ");
/*fuzzSeed-66366547*/count=856; tryItOut("mathy1 = (function(x, y) { return Math.expm1(((((Math.log10(Number.MIN_SAFE_INTEGER) >>> 0) != mathy0((x >>> ( + x)), x)) >>> 0) < (( - ((y ? Math.fround(Math.pow(x, x)) : y) >>> 0)) + Math.tan(( + Math.cosh(Math.acosh(x))))))); }); testMathyFunction(mathy1, [-(2**53), 1, 2**53, 0, 42, -0x080000000, -1/0, 0x100000001, -Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, -0x0ffffffff, -0, 2**53-2, -0x100000001, Math.PI, 0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, -(2**53-2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, 0x080000001, 1.7976931348623157e308, -0x100000000]); ");
/*fuzzSeed-66366547*/count=857; tryItOut("(void schedulegc(g2));");
/*fuzzSeed-66366547*/count=858; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!$){1,}(?=.)^\\B\\B(?=[^\\S\\u0025-\\xEb])\\B|[^]^{65536,65540}{32}+/gm; var s = \"\\n\\n\\n\\n\\n\\n\\n\\nB0\\uab38\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\nB0\\uab38\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\nB0\\uab38\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\nB0\\uab38\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\nB0\\uab38\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\nB0\\uab38\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\nB0\\uab38\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\nB0\\uab38\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\\n\\n\\n\\n\\u8a8c\\u00ff\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-66366547*/count=859; tryItOut("/*hhh*/function ulafdo(){m2.__proto__ = b0;}ulafdo(((makeFinalizeObserver('nursery'))), 0.263);");
/*fuzzSeed-66366547*/count=860; tryItOut("/*RXUB*/var r = new RegExp(\"(?:(?:^)*?|(?:.\\\\B)*(?=\\\\S[^])\\\\W{4}|[^]{4,5}|[]?+?|\\\\1)+\", \"gyim\"); var s = let (a = x) (4277); print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=861; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=862; tryItOut("/*vLoop*/for (rrrngm = 0; rrrngm < 6; ++rrrngm) { var x = rrrngm; /* no regression tests found */ } ");
/*fuzzSeed-66366547*/count=863; tryItOut("mathy4 = (function(x, y) { return (Math.trunc(((( - ( - y)) | 0) ^ (( + Math.imul(( + ( + (-1/0 >>> 0))), y)) | 0))) >>> 0); }); testMathyFunction(mathy4, [(new String('')), ({valueOf:function(){return '0';}}), 0.1, objectEmulatingUndefined(), 0, undefined, '', (new Number(0)), true, (new Number(-0)), '\\0', [], -0, '/0/', ({toString:function(){return '0';}}), (new Boolean(false)), (new Boolean(true)), 1, null, ({valueOf:function(){return 0;}}), [0], (function(){return 0;}), false, NaN, '0', /0/]); ");
/*fuzzSeed-66366547*/count=864; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return Math.fround(( ~ Math.imul((Math.atan2(Math.fround(x), Math.fround((((mathy0(y, x) ? (y | 0) : x) ** (y >>> 0)) >>> 0))) >>> 0), Math.max((( + ( + ((2**53 | 0) , (y | 0)))) | 0), (Math.cosh(Math.tan((0x0ffffffff / 42))) | 0))))); }); testMathyFunction(mathy2, [2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, 2**53, 1, -0, 0.000000000000001, -0x080000000, 0x100000001, 0x100000000, -0x080000001, 0x080000001, -0x100000000, -(2**53-2), 2**53-2, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, -Number.MIN_VALUE, -(2**53+2), 0x07fffffff, -0x100000001, 1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0, 0/0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53), 42, 0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=865; tryItOut("i0 + '';\n/*MXX3*/g1.Array.prototype.sort = g1.Array.prototype.sort;\n");
/*fuzzSeed-66366547*/count=866; tryItOut("e0 = new Set;");
/*fuzzSeed-66366547*/count=867; tryItOut("mathy5 = (function(x, y) { return (Math.log10((Math.cos((( + Math.hypot(( + ( - (0x0ffffffff | 0))), Math.fround((((x << (x >>> 0)) & y) , ( + Math.clz32(( + Math.min((y >>> 0), (x | 0))))))))) >>> 0)) | 0)) | 0); }); ");
/*fuzzSeed-66366547*/count=868; tryItOut("g0.offThreadCompileScript(\"\\\"use strict\\\"; testMathyFunction(mathy4, [Math.PI, 1/0, -Number.MIN_VALUE, 0.000000000000001, -0x080000001, 2**53-2, 0/0, -1/0, -0x100000001, -0x100000000, -(2**53+2), -Number.MAX_VALUE, 0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 42, 0x100000001, 2**53, -0x07fffffff, 0x07fffffff, 0x0ffffffff, 0x080000000, 2**53+2, Number.MIN_VALUE, 1, 0, -0x0ffffffff, -0, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), 1.7976931348623157e308]); \");g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 22 == 4), sourceIsLazy: x, catchTermination: e%=(void options('strict_mode')), element: o0, elementAttributeName: s0, sourceMapURL: g1.s1 }));");
/*fuzzSeed-66366547*/count=869; tryItOut("\"use strict\"; v0 = t2.byteOffset;");
/*fuzzSeed-66366547*/count=870; tryItOut("t1[11] = {};const z = new RegExp(\"(?:^)\", \"gim\") % x;");
/*fuzzSeed-66366547*/count=871; tryItOut("/*RXUB*/var r = new RegExp(\"((?=\\\\u0046)|^)+?\", \"gim\"); var s = \"FF\"; print(r.test(s)); ");
/*fuzzSeed-66366547*/count=872; tryItOut("e2.add(i1);");
/*fuzzSeed-66366547*/count=873; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.min(((( ! (Math.expm1(-0x080000001) >>> 0)) >>> 0) | 0), (((( - Math.sinh(Math.clz32(( + ( - x))))) | 0) ? 42 : Math.fround(mathy1(Math.fround((Math.pow((0.000000000000001 & x), Math.fround((( + Math.log2(( + x))) / ( + x)))) >>> 0)), Math.fround(y)))) | 0))) + Math.fround(mathy1(( + Math.expm1(Math.fround(Math.tanh(Math.fround((( - x) && x)))))), ( + y))))); }); testMathyFunction(mathy4, [-(2**53), -0x0ffffffff, -0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, 42, 1.7976931348623157e308, -Number.MIN_VALUE, -0, -(2**53+2), -0x100000000, 0x100000000, 0, 0x0ffffffff, Math.PI, Number.MIN_VALUE, 0x100000001, 0.000000000000001, 0x07fffffff, -0x07fffffff, 2**53, -0x080000001, 0x080000001, -Number.MAX_VALUE, 1/0, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 2**53+2, -1/0, 0x080000000, -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=874; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 4611686018427388000.0;\n    var i3 = 0;\n    switch ((~~(d2))) {\n      default:\n        d2 = (d0);\n    }\n    /*FFI*/ff(((d0)), ((0x206eefa3)), ((((0x847671d9)) | ((0xb6c2b1e0)))), ((~(((0x6f60873b))))), ((d2)), (((((-134217729.0)) / ((-2.0))))));\n    i3 = (0xfdbedeef);\n    d2 = (Infinity);\n    d2 = (+abs(((d0))));\n    i3 = (i3);\n    d1 = (d2);\n    d0 = ((/*FFI*/ff(((imul((0xffffffff), (i3))|0)), ((d0)), ((~~(-68719476737.0))), ((((0xffffffff)+(0xf9334598)) ^ ((0x71ec8ae9)+(-0x8000000)))), ((549755813889.0)), ((((0xd1589483)) | ((0x867026f)))), ((65535.0)), ((2.3611832414348226e+21)), ((268435457.0)), ((2305843009213694000.0)))|0) ? (-7.555786372591432e+22) : (d2));\n    return (((0x1d88bc81)))|0;\n  }\n  return f; })(this, {ff: function shapeyConstructor(navmsr){navmsr[\"length\"] = ({x:3});for (var ytqoqttft in navmsr) { }Object.defineProperty(navmsr, -10, ({get: mathy3, set: (4277)}));if (navmsr) navmsr[\"callee\"] = -0x5a827999;for (var ytqfwbxoy in navmsr) { }for (var ytqhazldr in navmsr) { }navmsr[\"isView\"] = function (y) { let (d) { i1.next(); } } ;Object.defineProperty(navmsr, \"entries\", ({set: new x(((void options('strict')))).slice, enumerable: navmsr}));return navmsr; }}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-66366547*/count=875; tryItOut("i2 + i0;");
/*fuzzSeed-66366547*/count=876; tryItOut("\"use strict\"; with(\"\\uD956\"){print(x); }");
/*fuzzSeed-66366547*/count=877; tryItOut("mathy2 = (function(x, y) { return (((Math.fround((Math.log10((x << y)) | 0)) | 0) >> ((( + Math.fround(( ! (mathy0(Math.min(( ! x), x), Math.fround(x)) | 0)))) * mathy0(x, ( ! 0x080000001))) | 0)) | 0); }); testMathyFunction(mathy2, [0.000000000000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 2**53+2, 0x100000001, -0x100000001, -(2**53-2), 0x080000000, 1, Number.MAX_VALUE, 0x07fffffff, -(2**53+2), -0x080000000, -0x07fffffff, 0x0ffffffff, 0x100000000, Number.MIN_VALUE, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, -(2**53), -0x0ffffffff, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -1/0, 2**53-2, 1/0, 2**53, -0x080000001, Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-66366547*/count=878; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.atan2(( + (Math.trunc((Math.ceil(Math.acos(Math.fround(( ~ ((-0x0ffffffff * x) >>> 0))))) >>> 0)) >>> 0)), ( + ( + ( - Math.fround((mathy1((Math.trunc(x) >>> 0), (x > ( ! ( + Math.atan2(Math.fround(-(2**53-2)), 0x100000000))))) || ((mathy0((y / x), ( + mathy0((Math.imul(-0x080000000, 1/0) | 0), ( + Math.cbrt(-Number.MIN_VALUE))))) >>> 0) | 0)))))))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, -0x100000000, -0, 0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, 0x080000000, -Number.MIN_VALUE, 0x080000001, -1/0, 2**53, -(2**53+2), -0x07fffffff, 2**53+2, -Number.MAX_VALUE, 0x0ffffffff, -0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53), 42, -(2**53-2), 0x07fffffff, 0x100000000, 0/0, -0x080000000, Number.MAX_VALUE, 2**53-2, 0, -0x080000001, -Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-66366547*/count=879; tryItOut("const ausnil, window, x = ({}) = /.(?!\\1)(\\B)[^\\s]{2}*(?:[^]{0})?/gi.__defineGetter__(\"getter\", Date.prototype.getUTCMinutes), w, window;/* no regression tests found */");
/*fuzzSeed-66366547*/count=880; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -(2**53), 42, -Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, 1, 0/0, 0x100000001, -0x080000000, 2**53+2, -(2**53+2), 0x100000000, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, -(2**53-2), Math.PI, -0x100000001, 0x080000000, -0x0ffffffff, 1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 2**53, -1/0, 2**53-2, -0x100000000, 0x0ffffffff, 0]); ");
/*fuzzSeed-66366547*/count=881; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ( + ( ~ ( + (((( + Math.expm1(( + y))) | 0) !== (Math.pow(( + ( + ( + (x >>> (Math.fround(Math.cos(( + -0x0ffffffff))) | 0))))), ( + x)) | 0)) | 0)))); }); testMathyFunction(mathy0, /*MARR*/[Infinity, function(){}, Infinity, true, Infinity, true, (-1/0), (-1/0), window.__defineSetter__(\"\\u3056\", objectEmulatingUndefined), true, window.__defineSetter__(\"\\u3056\", objectEmulatingUndefined), Infinity, (-1/0), (-1/0), Infinity, (-1/0), function(){}, window.__defineSetter__(\"\\u3056\", objectEmulatingUndefined), function(){}, (-1/0), window.__defineSetter__(\"\\u3056\", objectEmulatingUndefined)]); ");
/*fuzzSeed-66366547*/count=882; tryItOut("Array.prototype.unshift.apply(a1, []);");
/*fuzzSeed-66366547*/count=883; tryItOut("testMathyFunction(mathy4, [Math.PI, -0x100000001, 42, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, 0x100000001, -(2**53-2), -0x080000000, 2**53+2, 1.7976931348623157e308, 2**53-2, -0x07fffffff, 1, 0/0, Number.MAX_VALUE, 0x07fffffff, 0x100000000, 1/0, -0x0ffffffff, 0x080000000, -1/0, -Number.MAX_VALUE, -0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0, 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=884; tryItOut("mathy3 = (function(x, y) { return (( + (((( + ( + mathy2((x | 0), mathy0(( + Math.pow(( + ( - y)), ( + x))), x)))) | 0) , Math.fround(Math.imul(-0x080000000, x))) | 0)) > ( + Math.max(( + (Math.fround(( - Math.min(y, Math.fround(Math.sin(( - y)))))) & Math.fround((x ? Math.fround(0) : Math.fround(-(2**53+2)))))), ( + Math.atan2(Math.fround(Math.hypot((-0x080000001 >>> 0), ( + 42))), Math.atan2(Math.fround((Math.fround(( + (( + 0/0) > ( + Math.min(y, 42))))) / Math.fround(1.7976931348623157e308))), y)))))); }); ");
/*fuzzSeed-66366547*/count=885; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), function(){},  /x/g , function(){},  /x/g , function(){}, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-66366547*/count=886; tryItOut("print(uneval(v2));");
/*fuzzSeed-66366547*/count=887; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.min(Math.fround((((Math.fround((Math.cos((2**53-2 >>> 0)) >>> 0)) <= ((Math.pow(( + -(2**53+2)), ( + mathy1(x, 42))) >>> 0) >>> 0)) >>> 0) * Math.ceil(mathy1(( + Math.hypot(x, x)), Math.fround((x && x)))))), ((Math.max(mathy1(( ~ Math.atanh(x)), (( + ( + Math.hypot((Math.hypot(Math.max(1, (y | 0)), (x | 0)) | 0), Math.pow(y, ( + Math.imul(x, ( + x))))))) | 0)), (Math.fround((Math.fround(Math.min((x | 0), (x | 0))) == Math.fround(x))) >>> 0)) | 0) | 0)); }); testMathyFunction(mathy2, [-0x100000001, -0x100000000, 1, -0, 0x080000000, 2**53, -0x080000001, 0/0, -0x07fffffff, 42, -(2**53+2), 0x080000001, -(2**53), 2**53+2, 2**53-2, Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MAX_VALUE, 1/0, 0, 0x100000001, -1/0, 0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, Math.PI, 0x0ffffffff, -(2**53-2), 0.000000000000001, -0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=888; tryItOut("(this);");
/*fuzzSeed-66366547*/count=889; tryItOut("\"use strict\"; v1 = evalcx(\"Array.prototype.forEach.apply(a0, [(function() { for (var j=0;j<3;++j) { f0(j%5==0); } })]);\", g1);");
/*fuzzSeed-66366547*/count=890; tryItOut("\"use strict\"; /*MXX2*/g1.RegExp.prototype.global = p0;");
/*fuzzSeed-66366547*/count=891; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=892; tryItOut("\"use strict\"; this.a0[2] = m1;");
/*fuzzSeed-66366547*/count=893; tryItOut("mathy2 = (function(x, y) { return Math.sign(( + (((((x ? (Math.min((y | 0), 0x100000000) | 0) : ((x - Math.fround((Math.fround(((y >>> 0) <= x)) >= x))) | 0)) | 0) | 0) !== (y | 0)) | 0))); }); testMathyFunction(mathy2, [0x07fffffff, -0x100000001, 2**53-2, 0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, 1, -0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, -0, 1/0, 0/0, -Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, 0, -0x080000001, -0x080000000, 0x100000001, Number.MIN_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, 42, Math.PI, 0x080000001, 2**53, 1.7976931348623157e308, 2**53+2, Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=894; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(Math.sqrt(Math.fround((( ~ y) , Math.fround(( ! Math.fround(Math.fround((( + x) % (-0x0ffffffff ? Math.PI : -0x080000000)))))))))) && ( ~ (Math.fround(( + Math.fround(y))) > Math.cos((x - x))))); }); testMathyFunction(mathy2, [2**53+2, -0, -(2**53+2), 0, 42, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 0x0ffffffff, -1/0, 0x100000001, 0x080000001, 0/0, -0x080000000, -(2**53), 1, 0x07fffffff, -Number.MAX_VALUE, -0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, -(2**53-2), -0x0ffffffff, 0x080000000, Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, -0x100000001, Math.PI, -0x080000001]); ");
/*fuzzSeed-66366547*/count=895; tryItOut("v2 = new Number(e2);");
/*fuzzSeed-66366547*/count=896; tryItOut("/*RXUB*/var r = new RegExp(\"[^]*?\\\\2{3}|(?=(^)\\\\u0001|[\\\\cZ\\u9865\\\\s]|(?!\\\\b)(?:e+?)*)*\", \"\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-66366547*/count=897; tryItOut("\"use strict\"; /*infloop*/do {/* no regression tests found *//*RXUB*/var r = /\\d+/yi; var s = \"______\"; print(r.exec(s));  } while('fafafa'.replace(/a/g, Array.prototype.shift));");
/*fuzzSeed-66366547*/count=898; tryItOut("testMathyFunction(mathy1, [0x080000000, 1.7976931348623157e308, 0/0, 2**53+2, 0x100000001, 0x080000001, 2**53, 0x0ffffffff, 0, -0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, Math.PI, 2**53-2, -0x100000000, 1, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 42, -(2**53-2), -Number.MIN_VALUE, -0x080000001, -1/0, -0, -0x080000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, 1/0, 0x07fffffff]); ");
/*fuzzSeed-66366547*/count=899; tryItOut("/*infloop*/for(let [, \u000c{x, e: {w: {x: x, x: [[], a, , , e], x, \"23\", z: {e: [{x, x: [false.__proto__, ]}, , \u000c, ], a: e}, x}, d: {NaN, eval: [{}, c, [], d, ], \u3056, x: {d}, x: (27.unwatch(\"slice\")), x: ({z: {}})}}}, , , [, , , , [, {x: {{}: {x: [[], [a, x], \u3056]}, x: {x, x: [], w}}, x: [], eval, e: x}, x, [, [{}, , , x, (void options('strict')).x], ], arguments.callee.arguments\u000c, ], [, , , d], [, {x: window}, , {w: w, y: d, x: [[], {d: {z}, x, x: {x: [, {}], window: {w: {}, x: x}, x}}, , ], a: {x, x: [{NaN: [], this.c: [], x}, , , [, ]], a: c, eval, y: {x: c, \u3056: {}, NaN, x: window}}, \u3056: NaN, y: [, {z: x, x, b: {a: [], x: {eval: a, x: x}, x}}, ]}, \n{NaN, x: {}, eval: {}}, {x, a: [], \u3056: [, ]\u000c, window}, {b: [], c: {}, e: this, \u0009a: {x, x: z}, \u3056, \u3056}], ], x, {}, [, , , , {NaN: [z, ], x, eval: y, \u3056, x, x, y}, e, WeakSet.prototype]] in  /x/ ) {var hthyrw = new ArrayBuffer(3); var hthyrw_0 = new Int32Array(hthyrw); x;for(let a in ((Math.fround(( + Number.MAX_VALUE))).watch(\"valueOf\", Date.prototype.getUTCDate))) {print(({/*toXFun*/toString: Function })); } }");
/*fuzzSeed-66366547*/count=900; tryItOut("");
/*fuzzSeed-66366547*/count=901; tryItOut("const locohw, window, x, c, jjdehw, a;/*MXX3*/this.g1.String.prototype.link = this.g1.String.prototype.link;");
/*fuzzSeed-66366547*/count=902; tryItOut("/*RXUB*/var r = r0; var s = s0; print(r.exec(s)); ");
/*fuzzSeed-66366547*/count=903; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=904; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + ( + ((y + Math.max(-(2**53-2), (( + x) * ( + (((x >>> 0) - (-(2**53-2) >>> 0)) >>> 0))))) ? Math.max(( + (x > (x & -0x100000000))), Math.pow(y, y)) : ( + Math.ceil(( + (Math.tan(( + Math.hypot(x, -0x080000000))) >>> 0))))))) >>> 0); }); ");
/*fuzzSeed-66366547*/count=905; tryItOut("v2 = o1.g2.runOffThreadScript();");
/*fuzzSeed-66366547*/count=906; tryItOut("\"use strict\"; testMathyFunction(mathy0, /*MARR*/[false, x, new Boolean(false), Infinity, allocationMarker(), x, allocationMarker(), new Boolean(false), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, false, Infinity, x, false, Infinity, allocationMarker(), x, Infinity, x, Infinity, x, Infinity, allocationMarker(), new Boolean(false), allocationMarker(), allocationMarker(), allocationMarker(), new Boolean(false), x, x, false, x, allocationMarker(), Infinity, Infinity, Infinity, x, allocationMarker(), allocationMarker(), x, new Boolean(false), Infinity, Infinity, x, false, false, Infinity, Infinity, Infinity, new Boolean(false), x, new Boolean(false), Infinity, allocationMarker(), Infinity, new Boolean(false), allocationMarker(), new Boolean(false), new Boolean(false), false, x, new Boolean(false), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, x, allocationMarker(), false, Infinity, false, x, Infinity, new Boolean(false), new Boolean(false), Infinity, Infinity, Infinity, Infinity, allocationMarker(), false, allocationMarker(), x, x, x, false, allocationMarker(), new Boolean(false), new Boolean(false), new Boolean(false), x, allocationMarker(), x, new Boolean(false), false, new Boolean(false), Infinity, allocationMarker(), new Boolean(false), new Boolean(false), x, Infinity, Infinity, new Boolean(false), x, allocationMarker(), new Boolean(false), false, x, false, Infinity, new Boolean(false), false, false, Infinity, x, false]); ");
/*fuzzSeed-66366547*/count=907; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( ! (( ~ (y & Math.log(y))) >>> 0)), ( + Math.imul(((( + Math.fround(Math.min(Math.fround(y), Math.fround(y)))) * (y | 0)) | 0), Math.hypot(-0x080000001, (Math.sqrt(( - Math.fround(x))) >>> 0)))))); }); testMathyFunction(mathy5, [2**53+2, 0x100000000, 0x100000001, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, -0, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, 0, -Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, 2**53, -0x100000000, -0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, 0/0, -(2**53), 42, -0x100000001, 1, 0x080000000, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=908; tryItOut("\"use strict\"; a0.unshift(v2, h2, s2);");
/*fuzzSeed-66366547*/count=909; tryItOut("o0.v0 = g2.eval(\"\\\"use strict\\\"; {i0.send(a0); }\");");
/*fuzzSeed-66366547*/count=910; tryItOut("h1.keys = (function(j) { if (j) { try { v1 = Array.prototype.reduce, reduceRight.apply(a0, [(function() { for (var j=0;j<93;++j) { f2(j%4==0); } })]); } catch(e0) { } try { v1 = (v1 instanceof t2); } catch(e1) { } try { h0 + m1; } catch(e2) { } this.o1.o2 + v2; } else { for (var v of s2) { try { m0.get(s2); } catch(e0) { } try { this.g0.offThreadCompileScript(\"s0 = '';\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 2 != 0), noScriptRval: (x % 3 == 2), sourceIsLazy: false, catchTermination: false, sourceMapURL: s0 })); } catch(e1) { } v1 = g0.runOffThreadScript(); } } });");
/*fuzzSeed-66366547*/count=911; tryItOut("v1 = (e2 instanceof h2);");
/*fuzzSeed-66366547*/count=912; tryItOut("32232975;");
/*fuzzSeed-66366547*/count=913; tryItOut("mathy1 = (function(x, y) { return Math.min(mathy0(( ! 2**53), ( + Math.fround((Math.fround(Math.hypot(((x | 0) & x), Math.imul(y, y))) + Math.asinh(y))))), ( + ( - ( + (x << (Math.cos(y) | 0)))))); }); testMathyFunction(mathy1, /*MARR*/[null,  /x/g , new Boolean(true), null, null, 1e4, null,  /x/g , Math.PI, 1e4,  /x/g , null, 1e4, Math.PI, Math.PI, new Boolean(true),  /x/g ,  /x/g , new Boolean(true), Math.PI,  /x/g , Math.PI, null,  /x/g ,  /x/g ]); ");
/*fuzzSeed-66366547*/count=914; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.log(Math.tan((y << (( + y) ** (y | x))))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, 42, 2**53, -0, 0x0ffffffff, -1/0, Number.MIN_VALUE, 1/0, 0x100000000, 0x100000001, 2**53+2, 2**53-2, -0x080000000, 0.000000000000001, -(2**53-2), Math.PI, 0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), 1.7976931348623157e308, 0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, 0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, 0x07fffffff]); ");
/*fuzzSeed-66366547*/count=915; tryItOut("g1.v2 = undefined;");
/*fuzzSeed-66366547*/count=916; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.acosh(( + mathy0(((((Math.sign((-Number.MAX_VALUE >>> 0)) != (y >>> 0)) | 0) ** ( ! -0x100000001)) | 0), mathy0(( + x), y)))); }); testMathyFunction(mathy1, [-0x100000001, 1, -0x0ffffffff, 0x080000001, 0x080000000, 2**53, 2**53+2, -0, 0x07fffffff, Number.MIN_VALUE, -0x080000001, -0x100000000, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, 0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, -(2**53+2), -0x07fffffff, -(2**53), -Number.MAX_VALUE, 0x100000000, 0/0, 0.000000000000001, 0, Number.MAX_VALUE, 1.7976931348623157e308, -1/0]); ");
/*fuzzSeed-66366547*/count=917; tryItOut("mathy3 = (function(x, y) { return Math.cos(( + ( + (Math.fround(Math.max(Math.hypot((0.000000000000001 >>> 0), Math.log2(x)), mathy2((Math.sinh((y | 0)) | 0), Math.fround(Math.imul(Math.fround(x), 1.7976931348623157e308))))) > ( + (mathy0((-0 >>> 0), (( + y) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [-0x100000000, 2**53-2, -0x080000000, Number.MIN_VALUE, -(2**53), 1, 2**53+2, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, 0, -0, 0.000000000000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 42, Number.MAX_VALUE, 0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0/0, -0x0ffffffff, 0x080000001, -1/0, 0x0ffffffff, 0x080000000, -0x07fffffff, -0x080000001, 0x100000000, 1.7976931348623157e308, 1/0, 2**53, Math.PI, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=918; tryItOut("/*infloop*/for(let \u3056 in -2) print(x);");
/*fuzzSeed-66366547*/count=919; tryItOut("\"use strict\"; Array.prototype.push.apply(a1, [s1, e0, [1,,] ,  \"\"  ^ (String.prototype.normalize)() -= eval, x, v2, g1.i1]);");
/*fuzzSeed-66366547*/count=920; tryItOut(";");
/*fuzzSeed-66366547*/count=921; tryItOut("mathy2 = (function(x, y) { return ( + Math.min((Math.sinh(((y > ( + (( ~ (( ~ Math.fround(-1/0)) >>> 0)) >>> 0))) * Math.atan2(( + 42),  '' ))) >>> 0), Math.sign(Math.hypot((Math.trunc(Math.fround((y & Math.imul((( + (( + x) ? (y | 0) : ( + x))) >>> 0), (y >>> 0))))) >>> 0), (( ! y) >>> 0))))); }); testMathyFunction(mathy2, [2**53-2, 0x0ffffffff, Number.MIN_VALUE, 0/0, 2**53+2, 2**53, -0x100000000, 0x080000000, -(2**53+2), 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, -0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, 1, 0x100000001, -0x0ffffffff, -Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, -0x07fffffff, Number.MAX_VALUE, -0x080000000, -(2**53-2), -Number.MIN_VALUE, -0, -0x100000001, -1/0, 0x080000001, 1.7976931348623157e308, 42, -(2**53)]); ");
/*fuzzSeed-66366547*/count=922; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=923; tryItOut("\"use strict\"; for(let e in []);");
/*fuzzSeed-66366547*/count=924; tryItOut("mathy2 = (function(x, y) { return Math.asin(Math.expm1(mathy1(x, Math.fround(( ~ ( + (((y >>> 0) , x) | 0))))))); }); ");
/*fuzzSeed-66366547*/count=925; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=926; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log(( + (( ~ Math.min(y, (x | 0))) , ( ~ mathy0(Math.max((Math.min(y, x) | 0), ((Math.imul((mathy0(x, 0x100000000) >>> 0), (2**53-2 >>> 0)) >>> 0) | 0)), ( + mathy0(x, ( + x)))))))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, 2**53, -1/0, -0x0ffffffff, 0x100000001, Number.MIN_VALUE, 0/0, 0x07fffffff, 1.7976931348623157e308, Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 0x080000001, 0, -0x100000001, 2**53+2, -Number.MAX_VALUE, -0x100000000, 0.000000000000001, -(2**53-2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000000, -0, 42, 0x080000000, -(2**53)]); ");
/*fuzzSeed-66366547*/count=927; tryItOut("t2 = new Int16Array(8);");
/*fuzzSeed-66366547*/count=928; tryItOut("\"use strict\"; testMathyFunction(mathy1, [Number.MIN_VALUE, -Number.MAX_VALUE, -0, -0x100000001, 2**53, Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, 0, -(2**53), -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, 0x100000001, Math.PI, 0x080000001, 2**53-2, 0/0, Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, 0x100000000, 42, -0x080000000, 2**53+2, -(2**53-2), 0.000000000000001, 1, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=929; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - ( + Math.expm1(( + (( + (((Math.atanh(y) | 0) % mathy2(((( + x) ? x : (x >>> 0)) >>> 0), y)) | 0)) ** ( + ((((( ~ 2**53+2) >>> 0) ? (y | 0) : y) !== Math.fround(Math.hypot(mathy2(( + y), ( + -0x100000001)), x))) | 0))))))); }); testMathyFunction(mathy4, [[0], null, (new Boolean(false)), 0.1, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), true, /0/, [], '', 0, ({toString:function(){return '0';}}), NaN, ({valueOf:function(){return 0;}}), '\\0', false, (new Boolean(true)), -0, '/0/', (new String('')), (new Number(0)), (new Number(-0)), undefined, '0', (function(){return 0;}), 1]); ");
/*fuzzSeed-66366547*/count=930; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Math.PI, -0, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -0x100000000, Number.MIN_VALUE, 42, -Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, 0, Number.MAX_VALUE, 0x100000001, 1/0, 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, 2**53-2, -0x080000001, -(2**53), 1, -(2**53+2), 1.7976931348623157e308, 2**53, -0x100000001, 2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=931; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-66366547*/count=932; tryItOut("const [[NaN, [, , {}], [[], d, ], {eval}], , x, c, ] = x, x = ({x: (((b % this.window))((4277), e)) }), z, x = ({__proto__: /(?!(((?:[\u795e\udb5c\u0008\\cW]{8388609}(?=^.)))))/m,  get -19 window (NaN, x, ...\u3056) { \"use asm\"; h2.hasOwn = (function(j) { f1(j); }); }  }), x = ({a: (new Function)( \"\" , false) }), x = /*RXUE*/new RegExp(\"(\\ua615[^])(?![^]\\\\B)+*\", \"gy\").exec(\"\"), e, z = \"\\u6CE0\";a2 + s1;");
/*fuzzSeed-66366547*/count=933; tryItOut("g2.offThreadCompileScript(\"(({a1:1}) || Math.max( \\\"\\\" , 6))\", ({ global: g1.o1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 6 == 2), noScriptRval: true, sourceIsLazy: false, catchTermination: false }));");
/*fuzzSeed-66366547*/count=934; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.cosh(( + Math.imul(Math.ceil(y), Math.pow(1/0, Math.fround(mathy1(Math.fround(Math.cbrt((y | 0))), Math.fround(x))))))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -1/0, 2**53+2, -Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 1, 0x0ffffffff, -0x080000001, 0x080000001, -(2**53), 2**53-2, -0x07fffffff, -(2**53+2), 1.7976931348623157e308, 0x100000000, -0x100000000, 2**53, 0, -0, 0x100000001, Math.PI, -0x0ffffffff, 0.000000000000001, 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-66366547*/count=935; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"([^]){0,}\", \"gyi\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=936; tryItOut("with((void shapeOf(undefined)))/*MXX1*/o2 = g1.Int32Array.BYTES_PER_ELEMENT;");
/*fuzzSeed-66366547*/count=937; tryItOut("\"use strict\"; Array.prototype.unshift.apply(a0, []);");
/*fuzzSeed-66366547*/count=938; tryItOut("L:with({a: yield ((4277) ? x : x)}){/*bLoop*/for (let drcxfz = 0; drcxfz < 63; ++drcxfz) { if (drcxfz % 11 == 0) { for (var p in b0) { try { h0.keys = (function() { for (var j=0;j<163;++j) { f0(j%2==0); } }); } catch(e0) { } i2.next(); } } else { axqlkr(this);/*hhh*/function axqlkr(x = \"\\u0E19\", x, a, a, x, NaN, c, e, x, x, eval,  , eval, eval, a, \u3056, d, a, eval, a, w, x, x, a, z =  /x/ , x =  /x/ , x, x, w = -5, x, e, NaN = \"\\uC325\", a = false, x, a, eval, x = \"\\uBCB6\", \u3056, e, x = window, getter, x, x, z, a =  \"\" , x, e, a, x, -19, e, w, b, 26, a = [,], x, window, a,  , a = \"\\uF801\", \u3056 = (function ([y]) { })(), y = new RegExp(\"(?:(?![^]|$?)+|(?=^)|(?:$?)){0,}\", \"gm\"), window, a, x, x, x = window, b =  '' , x, x, c, \"-9\" = undefined, d, NaN, x, \u3056, x, window, a, a, get, a, b, a, d, b, eval, e, 25, a = e, a, window){h2.__proto__ = g2.t0;} }  }  }");
/*fuzzSeed-66366547*/count=939; tryItOut("\"use strict\"; /*hhh*/function twrhfn(z, this.z){m2 = new Map(e0);}/*iii*/p2.__iterator__ = (function() { try { i2.next(); } catch(e0) { } try { v0.__proto__ = this.e1; } catch(e1) { } try { delete h2.getOwnPropertyDescriptor; } catch(e2) { } Array.prototype.pop.call(a0); return a0; });");
/*fuzzSeed-66366547*/count=940; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.hypot((( + ( - Math.round(-Number.MIN_VALUE))) | 0), (( + Math.fround((( + Math.asinh(( + mathy4(x, ( + (( + ( + x)) | 0)))))) & (mathy0(Math.max(x, (Math.fround(1) ? Math.fround(( + ( ! Math.fround(2**53+2)))) : Math.fround(-Number.MAX_SAFE_INTEGER))), x) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy5, [0x07fffffff, -0x080000000, 1, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 2**53, -0x100000001, 2**53+2, -Number.MIN_VALUE, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0, 0x100000001, 0/0, 0x0ffffffff, -(2**53+2), 0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, 42, 1.7976931348623157e308, -0x080000001, 1/0, 0x100000000, -(2**53-2), Math.PI, -Number.MAX_VALUE, -0x0ffffffff, -(2**53), 2**53-2, Number.MAX_VALUE, 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=941; tryItOut("hsiwqw(x);/*hhh*/function hsiwqw(x){let gwlcie, c, x;s1 += 'x';}");
/*fuzzSeed-66366547*/count=942; tryItOut("let x = ((makeFinalizeObserver('tenured'))), sgfpeg, d;print(x);");
/*fuzzSeed-66366547*/count=943; tryItOut("mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return mathy0(Math.min(Math.max(Math.hypot(( ! (y | 0)), (Math.imul((mathy1(y, x) | 0), -(2**53-2)) <= x)), ( - ( + x))), Math.fround(( ! Math.fround(((Math.fround(mathy1(y, x)) >>> (( + (( + x) ? ( + ((x || 2**53+2) >>> 0)) : ( + -Number.MAX_SAFE_INTEGER))) | 0)) >>> 0))))), Math.fround(Math.hypot(( + ( - ( ! (( - (-(2**53+2) >>> 0)) | 0)))), ( + Math.fround((Math.fround(mathy1(y, ( + 1.7976931348623157e308))) << Math.cos(x))))))); }); ");
/*fuzzSeed-66366547*/count=944; tryItOut("mathy3 = (function(x, y) { return Math.clz32(( ! ( + Math.clz32(Math.fround(( - Math.fround(y))))))); }); testMathyFunction(mathy3, [0x080000001, 0x100000001, -1/0, 2**53, 0/0, 0x100000000, 1, -(2**53+2), Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0, -0x07fffffff, -0, -Number.MAX_VALUE, -0x080000001, -(2**53), 2**53+2, -0x100000000, -(2**53-2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, -0x080000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 42, Number.MIN_VALUE, 0x080000000, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0]); ");
/*fuzzSeed-66366547*/count=945; tryItOut("\"use asm\"; Object.preventExtensions(g2);");
/*fuzzSeed-66366547*/count=946; tryItOut("\"use strict\"; const d, jtvbxm, \u3056, uzimvg, nrylei, [] = new (/(?!\\B|\\S|(?=[^])?.+?)/m)( /x/ , x);a1.unshift(g1.o2);");
/*fuzzSeed-66366547*/count=947; tryItOut("\"use strict\"; /*MXX2*/g2.Array.prototype.unshift = a1;");
/*fuzzSeed-66366547*/count=948; tryItOut("\"use strict\"; v0 = g2.runOffThreadScript();/*RXUB*/var r = r0; var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-66366547*/count=949; tryItOut("");
/*fuzzSeed-66366547*/count=950; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((mathy0(( + ( ~ (( ~ y) | 0))), ((( + x) > ( + ( + ( ! ( + x))))) >>> 0)) >>> 0) < Math.log10(( + Math.cbrt(( + Math.min(( + x), Math.fround(x))))))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, -0, 1, -1/0, 2**53+2, -(2**53), 0, -(2**53+2), -0x080000000, -0x080000001, 0/0, -0x100000001, 0x100000001, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 2**53, -0x100000000, 0x080000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 42, -Number.MIN_VALUE, -0x0ffffffff, 0x100000000, Math.PI, 0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=951; tryItOut("testMathyFunction(mathy4, [0, 2**53, Math.PI, 1, 0x080000000, Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 0x100000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -1/0, -0x100000000, 0x0ffffffff, 42, -(2**53), -Number.MIN_VALUE, -0x100000001, Number.MAX_VALUE, -0x080000000, -0x080000001, -(2**53+2), 0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, -0, 2**53-2, Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=952; tryItOut("\"use strict\"; this.s0 += s0;");
/*fuzzSeed-66366547*/count=953; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -511.0;\n    i1 = (i1);\n    (Float32ArrayView[(((~((0x481c8591))) != (((0xe51e49c0)) ^ ((0xb57b6a56))))+(!(i1))+(0xfff67a00)) >> 2]) = ((d0));\n    i1 = (0xffffffff);\n    i1 = (!(0xffffffff));\n    d0 = (d0);\n    return (((i1)*-0xfffff))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -0x100000000, -0x080000000, 0/0, 0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0, 0x080000000, -0x0ffffffff, 0x100000001, 42, -Number.MIN_VALUE, -Number.MAX_VALUE, 1, 1/0, -(2**53-2), Number.MAX_VALUE, 2**53+2, 2**53-2, -0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 0x0ffffffff, -0x080000001, -(2**53), 0x080000001]); ");
/*fuzzSeed-66366547*/count=954; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x080000001, -(2**53-2), -(2**53+2), 1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, -0x0ffffffff, 42, 0.000000000000001, 1.7976931348623157e308, -1/0, 0, -Number.MAX_VALUE, 2**53-2, 0/0, Number.MAX_SAFE_INTEGER, Math.PI, -(2**53), -Number.MIN_VALUE, 0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1, 2**53, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, 0x100000001, -0x080000001, 0x100000000, -0, -0x100000001]); ");
/*fuzzSeed-66366547*/count=955; tryItOut("\"use strict\"; \"use asm\"; for (var v of i1) { try { g2.v2 = r1.source; } catch(e0) { } try { for (var v of p2) { try { g2.v1 = t2.BYTES_PER_ELEMENT; } catch(e0) { } try { print(uneval(e1)); } catch(e1) { } try { a2 = Array.prototype.concat.apply(a0, [t0, o2]); } catch(e2) { } v2 = (e2 instanceof v1); } } catch(e1) { } a2.sort((function() { try { print(uneval(g1)); } catch(e0) { } try { h0 + ''; } catch(e1) { } v0 = (v0 instanceof v2); return e0; })); }");
/*fuzzSeed-66366547*/count=956; tryItOut("o2 = {};function \u3056(a, d) { \"use strict\"; v2 = a0.length; } t2 + '';");
/*fuzzSeed-66366547*/count=957; tryItOut("\"use strict\"; for(var y in (yield (delete d.x))) {v1[\"toString\"] = this.v2;for (var v of g1) { try { print(a2); } catch(e0) { } try { /*MXX3*/g0.WeakSet.prototype.add = this.g1.WeakSet.prototype.add; } catch(e1) { } v0 = false; } }");
/*fuzzSeed-66366547*/count=958; tryItOut("mathy1 = (function(x, y) { return mathy0((Math.sin((Math.max(((y !== (y ^ (( - y) | 0))) | 0), ( + Math.log10(( + (Math.asin((y | 0)) | 0))))) >>> 0)) | 0), ((( ~ (Math.hypot((Math.imul(y, Math.min(x, mathy0(y, y))) >>> 0), ((Math.log10((mathy0((2**53+2 >>> 0), y) | 0)) | 0) >>> 0)) >>> 0)) < ( - ( + ( + (Math.round(y) >>> 0))))) | 0)); }); ");
/*fuzzSeed-66366547*/count=959; tryItOut("mathy0 = (function(x, y) { return ( ! ( + Math.clz32(( ~ ( + y))))); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, 0x080000001, -(2**53-2), 2**53+2, -(2**53+2), -0x100000001, -0, 2**53-2, 0x07fffffff, 0x100000001, 0x0ffffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_VALUE, 1, 1/0, -Number.MIN_VALUE, -1/0, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, -0x100000000, 0x080000000, -0x080000001, 2**53, 42]); ");
/*fuzzSeed-66366547*/count=960; tryItOut("tnjdba();/*hhh*/function tnjdba(x, window){yield a = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), (z) =>  { yield window } , function(y) { \"use strict\"; return  /x/  });t2 = new Float32Array(13);}");
/*fuzzSeed-66366547*/count=961; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=962; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var atan = stdlib.Math.atan;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -5.0;\n    var i3 = 0;\n    var d4 = 1.125;\n    switch ((allocationMarker())) {\n      case 1:\n        {\n          d0 = (((NaN)) % ((d1)));\n        }\n        break;\n      case 0:\n        i3 = (0x58b841c1);\n        break;\n      default:\n        d4 = (+atan(((+((d2))))));\n    }\n    i3 = (0x9537d590);\n    d4 = (d4);\n    d2 = (d4);\n    return +((-3.777893186295716e+22));\n  }\n  return f; })(this, {ff: Date.prototype.setSeconds}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0, Number.MAX_SAFE_INTEGER, 1/0, Math.PI, Number.MAX_VALUE, 42, 0, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000000, 2**53-2, 0x100000000, -0x080000000, -0x07fffffff, 1.7976931348623157e308, -(2**53), 0x0ffffffff, 0/0, 0x080000000, -1/0, Number.MIN_VALUE, -0x080000001, -Number.MAX_VALUE, -(2**53-2), 2**53, 0.000000000000001, 0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 1, 2**53+2, 0x07fffffff]); ");
/*fuzzSeed-66366547*/count=963; tryItOut("var bzbbge = new ArrayBuffer(2); var bzbbge_0 = new Float32Array(bzbbge); bzbbge_0[0] = -0; (this);");
/*fuzzSeed-66366547*/count=964; tryItOut("\"use strict\"; /*MXX2*/g0.Object.setPrototypeOf = g0.g0;");
/*fuzzSeed-66366547*/count=965; tryItOut("print(window);;");
/*fuzzSeed-66366547*/count=966; tryItOut("mathy2 = (function(x, y) { return (Math.log2(Math.fround(Math.min(((Math.atan2(( ! Math.fround(y)), y) << Math.pow(( + -1/0), ( + ( + (Math.sinh((x | 0)) == (-(2**53) | 0)))))) >>> 0), Math.fround(( + ((Math.atan2(Number.MIN_SAFE_INTEGER, Math.pow((x ? Math.hypot((y | 0), y) : y), Math.fround(mathy0((y | 0), x)))) | 0) < ((Math.max(x, x) % ( + Math.min((x >>> 0), ((x ? 1.7976931348623157e308 : x) >>> 0)))) >>> 0))))))) >>> 0); }); testMathyFunction(mathy2, [2**53, 0.000000000000001, 0x100000000, -0x100000000, 0x100000001, 0/0, -Number.MAX_VALUE, -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 2**53+2, 0x0ffffffff, -(2**53), -0x080000000, -1/0, 0x080000001, 1, Number.MAX_SAFE_INTEGER, 1/0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, -0x100000001, -0x080000001, -0x07fffffff, -0, 1.7976931348623157e308, 42, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=967; tryItOut("var x, c, x, x = z | x, e, x = x, NaN = x, x;\"\\u91BC\";\na2.splice(NaN, g2.v0, e1);\no2.m0.get(o1);");
/*fuzzSeed-66366547*/count=968; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[ \"\" , 2**53+2,  \"\" ,  \"\" ,  /x/g ,  \"\" , -Infinity,  /x/g , new String(''), new String(''),  \"\" ,  \"\" ,  \"\" , -Infinity, new String(''), new String(''),  /x/g , -Infinity, -Infinity, -Infinity, -Infinity, new String(''),  \"\" ,  \"\" ,  \"\" , -Infinity, new String(''),  \"\" , 2**53+2, new String(''), new String(''), 2**53+2, -Infinity, -Infinity, 2**53+2, 2**53+2]); ");
/*fuzzSeed-66366547*/count=969; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -70368744177664.0;\n    var i3 = 0;\n    d2 = (((d2)) / ((+atan2(((+((Float32ArrayView[((Uint8ArrayView[(((-0x8000000) ? (0xfe3b5304) : (0x21bbbcc4))) >> 0])) >> 2])))), ((-((d0))))))));\n    (Uint8ArrayView[1]) = (((2251799813685249.0) <= (-4097.0)));\n    i1 = (i1);\n    {\n      i3 = (/*FFI*/ff(((-((-65537.0)))), ((Float64ArrayView[(((i3) ? (i1) : ((0x5ce507dc)))-(i3)) >> 3])), ((((Uint16ArrayView[((-0x8000000)-(0xde53d7)) >> 1]))|0)), ((+atan2(((-((+(1.0/0.0))))), ((+((d0))))))), ((((0x24d1ac75)*-0xfffff) << ((0xef0ec71e)))), ((((0xc24dbccc)*-0x12830) << ((0xb6c1ece2)-(-0x8000000)-(0xd4546c63)))), ((((0xffffffff)+(-0x8000000)) | ((0xf302bfc)+(0x815d9846)+(0xffffc06d)))), ((9223372036854776000.0)), ((((0xffffffff)) ^ ((0xfac19362)))), ((1048577.0)), ((-1.5111572745182865e+23)), ((1024.0)), ((-36893488147419103000.0)), ((-6.189700196426902e+26)), ((18446744073709552000.0)), ((72057594037927940.0)))|0);\n    }\n    i1 = (0x4d29cc92);\n    i1 = (0x135ca316);\n    return +((d2));\n    return +((+(-1.0/0.0)));\n    (Float32ArrayView[((i3)) >> 2]) = ((this));\n    i1 = (((((((i1)+(i3))>>>((i3))) >= (0xf902972)))>>>((0x807d255b))) < (0x7405d60a));\n    return +((((Float32ArrayView[((!(i1))-(0xe43474fe)) >> 2])) % ((Float64ArrayView[((0xff0995bf)+(0xfb957e74)) >> 3]))));\n  }\n  return f; })(this, {ff: Object.isExtensible}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [0, -0x07fffffff, 1, -Number.MIN_VALUE, 2**53-2, Number.MIN_VALUE, -(2**53-2), 0.000000000000001, 2**53+2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 1/0, -(2**53), 42, -0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, -0x080000001, -1/0, -0x100000000, 0x100000000, -0x080000000, 0x080000000, 1.7976931348623157e308, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, 0x0ffffffff, -0, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-66366547*/count=970; tryItOut("this.v2 = t2.length;");
/*fuzzSeed-66366547*/count=971; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; minorgc(true); } void 0; }");
/*fuzzSeed-66366547*/count=972; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=973; tryItOut("Array.prototype.forEach.apply(g0.a0, [(function() { try { o2.e0 = Proxy.create(h1, b2); } catch(e0) { } try { h2.getOwnPropertyNames = f2; } catch(e1) { } try { ; } catch(e2) { } Array.prototype.pop.apply(a1, []); return t2; })]);");
/*fuzzSeed-66366547*/count=974; tryItOut("v2 = this.a2.reduce, reduceRight();");
/*fuzzSeed-66366547*/count=975; tryItOut("f1.valueOf = (function(j) { if (j) { try { for (var v of this.o1.i2) { try { Object.defineProperty(this, \"g1.a1\", { configurable: true, enumerable: false,  get: function() {  return r2.exec(g1.s1); } }); } catch(e0) { } try { g0.__proto__ = m2; } catch(e1) { } /*MXX1*/o1 = g0.SimpleObject.name; } } catch(e0) { } t2 + ''; } else { try { m0.set(f2, h0); } catch(e0) { } g1.v1 = evaluate(\"s1 = '';\", ({ global: o2.g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: false, catchTermination: true, elementAttributeName: s1, sourceMapURL: s2 })); } });");
/*fuzzSeed-66366547*/count=976; tryItOut(";");
/*fuzzSeed-66366547*/count=977; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53), Number.MIN_VALUE, 1/0, -(2**53+2), 1, -0, 2**53-2, 0x100000001, -1/0, 0/0, 0x100000000, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0x0ffffffff, 0.000000000000001, -0x0ffffffff, 0, -(2**53-2), 0x080000001, 2**53, -Number.MAX_VALUE, -0x100000000, -0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53+2]); ");
/*fuzzSeed-66366547*/count=978; tryItOut("mathy2 = (function(x, y) { return (mathy1(Math.sinh(( ! ( + Math.fround((x && Math.fround(x)))))), Math.fround((Math.fround(( + Math.fround(((y >= (Math.PI | 0)) == ((( + x) >= 0x0ffffffff) | 0))))) | Math.fround(Math.pow(0.000000000000001, Math.log2(((y | 0) , 2**53))))))) !== mathy0(Math.asin(-0x100000001), (( + Math.fround(Math.exp((y >>> 0)))) || Math.cos((Math.max(Number.MAX_VALUE, Math.max(0x100000000, x)) >>> 0))))); }); ");
/*fuzzSeed-66366547*/count=979; tryItOut("/*oLoop*/for (ttlbll = 0; ttlbll < 4; ++ttlbll) { Array.prototype.sort.apply(a0, [(function mcc_() { var smqcpe = 0; return function() { ++smqcpe; if (/*ICCD*/smqcpe % 6 == 3) { dumpln('hit!'); try { t1.set(a0, 0); } catch(e0) { } g2.v0 = Object.prototype.isPrototypeOf.call(v0, g1.o0.a1); } else { dumpln('miss!'); try { s1 += s2; } catch(e0) { } try { this.v1 = r0.ignoreCase; } catch(e1) { } g2.offThreadCompileScript(\"v2 = (h0 instanceof p1);\"); } };})()]); } ");
/*fuzzSeed-66366547*/count=980; tryItOut("mathy3 = (function(x, y) { return Math.fround(((new (x)(y, -19)) ? Math.fround(mathy1((( ~ (-Number.MIN_VALUE | (Math.expm1(y) ** y))) | 0), Math.hypot((mathy1(( - Number.MIN_SAFE_INTEGER), -Number.MIN_VALUE) ? x : 1/0), Math.fround(( - (y - (y >>> 0))))))) : (( + Math.round(( + Math.imul((( - ( ! ( + x))) ? 2**53+2 : (2**53-2 >>> 1)), mathy2(Math.fround(Math.min(Math.fround(0), Math.fround((Number.MAX_VALUE ? x : (-Number.MIN_VALUE >>> 0))))), ((1 | 0) == x)))))) | 0))); }); testMathyFunction(mathy3, /*MARR*/[(1/0), x, (1/0), Infinity, Infinity, (1/0), Infinity, Infinity, x, (1/0), Infinity, Infinity, Infinity, (1/0), x, x, Infinity, Infinity, (1/0), x, x, x, Infinity, (1/0), x, x, x, Infinity, Infinity, Infinity, (1/0), x, (1/0)]); ");
/*fuzzSeed-66366547*/count=981; tryItOut("mathy3 = (function(x, y) { return (Math.imul((((Math.cos((x >>> 0)) >>> 0) << Math.trunc(Math.log1p((y && x)))) >>> 0), ( + ( + ( + (((Math.log1p(((x == y) | 0)) | 0) - Math.atan(x)) >>> 0))))) | 0); }); testMathyFunction(mathy3, [0x080000001, 0x100000000, 2**53, Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0, -1/0, -0, -(2**53), 1/0, 42, Math.PI, 2**53-2, 0x080000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 0/0, -(2**53+2), -(2**53-2), 1, Number.MIN_VALUE, -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -0x080000000, 0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=982; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var atan = stdlib.Math.atan;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\no2.a0.splice(7, ({valueOf: function() { /*RXUB*/var r = /[\\cK-\\r\u4b7c]/yi; var s = \"\\u66f4\"; print(s.replace(r, Math.sinh, \"yi\")); return 13; }}), i0);\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      d0 = (-288230376151711740.0);\n    }\n    return (((!(0xf5ae46f4))*-0xdcddb))|0;\n    /*FFI*/ff(((((imul(((0xf6ffb7de)), ((0x66beb435) ? (0x4032f880) : (-0x5388961)))|0)) - ((d0)))), ((((!(!(i1)))) ^ ((i2)+(0xeb0553f6)))), ((0x3effe2e3)), (((i2) ? (-1.125) : (((-7.737125245533627e+25)) * ((-1.001953125))))), ((Infinity)), ((imul((0xf6e3255f), (0xfb7f2b91))|0)));\n    i2 = (/*FFI*/ff(((~((i2)-(i1)))), ((+atan(((new String((this.x = []), x)))))), ((NaN)), ((d0)), ((2.3611832414348226e+21)), ((((i2)*0xfffff) | ((0xd6cd46be) / (0xd6b284a7)))), ((imul((i2), ((0x1fe2a21a) < (0x159b2121)))|0)), ((((0xfd70522c)) << ((0xffffffff)))), ((uneval( '' ))), ((1.2089258196146292e+24)))|0);\n    d0 = (1.5);\n    i2 = (i1);\n    (Int8ArrayView[1]) = ((+((((+/*FFI*/ff((((((((0x8bb9f318))>>>((0x8d6f0420))) == (0x8d944af3))) << ((i2)+((0x9455073a) ? (0xfebd0cde) : (0x6465e614))))), ((+abs(((((+pow(((137438953473.0)), ((-17592186044417.0))))) / ((((1.0)) % ((-262144.0)))))))))))) / ((72057594037927940.0))))));\n    return (((i2)+((((!(-0x8000000))-((0x9bcce1fe) < (((0x5426790))>>>((0x368aff9c))))) >> ((i2))) <= (abs(((((((0xa30cb65a))>>>((0x8176d35))))*0xcc2de) | (-0x72e96*(0xfb53c1db))))|0))))|0;\n  }\n  return f; })(this, {ff: \"\\u4453\" ** new RegExp(\"(\\\\3{64,65}){0}|\\\\1|${4,}\\\\W+|.{2,5}\", \"im\")}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53), 2**53, -0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, -0x080000001, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 0x07fffffff, 0x100000000, 1, -(2**53+2), 42, -0x07fffffff, -0x100000000, -Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, 0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, -Number.MIN_VALUE, 0, 2**53-2, 1/0, 0.000000000000001, Number.MIN_VALUE, -(2**53-2), -0x080000000, Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-66366547*/count=983; tryItOut("mathy5 = (function(x, y) { return ( + (Math.fround(Math.atan2(Math.pow(mathy4((0x100000001 == (y >>> 0)), (((x ? (x >>> 0) : y) >>> 0) | 0)), (( + (y % ( + y))) - ( + Math.fround(Math.acosh(Math.fround(y)))))), (Math.hypot(((y & x) | 0), ((mathy2(((Math.pow((Math.sin(x) >>> 0), (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0) | 0), (( ~ Math.fround(y)) | 0)) | 0) | 0)) | 0))) + ((( ~ y) ^ (((((y * y) | 0) < Number.MAX_VALUE) | 0) / y)) >>> 0))); }); testMathyFunction(mathy5, [-0x080000000, Math.PI, 0.000000000000001, 0x080000001, 0x100000000, 1/0, -0x100000001, -0x07fffffff, 2**53, Number.MAX_VALUE, -1/0, -0, 1, 0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53-2, -0x100000000, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0, -0x080000001, -0x0ffffffff, -(2**53+2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000001, 0/0, 42, -(2**53), -Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=984; tryItOut("v0 + i0;");
/*fuzzSeed-66366547*/count=985; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.asinh(( + Math.cbrt(Math.round(Math.fround(NaN = NaN)))))); }); ");
/*fuzzSeed-66366547*/count=986; tryItOut("v2 = evalcx(\"h2.defineProperty = (function() { try { v1 = a0.length; } catch(e0) { } try { v1 = (f0 instanceof e2); } catch(e1) { } try { s2 += 'x'; } catch(e2) { } a1[17] = a2; return this.e2; });\", g1);");
/*fuzzSeed-66366547*/count=987; tryItOut("a0 = /*PTHR*/(function() { for (var i of /*FARR*/[.../*MARR*/[new String('q'), [] = (window.__defineSetter__(\"x\", Math.atanh)), [] = (window.__defineSetter__(\"x\", Math.atanh)), (0x50505050 >> 1), (0x50505050 >> 1), new String('q'), new String('q'), [] = (window.__defineSetter__(\"x\", Math.atanh)), [] = (window.__defineSetter__(\"x\", Math.atanh)), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), [] = (window.__defineSetter__(\"x\", Math.atanh)), new Boolean(true), new Boolean(true), new String('q'), [] = (window.__defineSetter__(\"x\", Math.atanh)), (0x50505050 >> 1), new Boolean(true), new Boolean(true), [] = (window.__defineSetter__(\"x\", Math.atanh)), new Boolean(true)],  /x/ , , , (arguments.callee)((x = \"\\uFC0B\".__defineGetter__(\"d\", function(q) { return q; }))), (yield \"\\u9F25\"), intern(null), ((let (a) window)), (\n(/*FARR*/[5,  \"\" , new RegExp(\"$|^\\u00d3{3}?\\\\b*?|[^]|[^]+|(?!\\\\b[^\\\\\\u3c69\\\\cQ-\\u12de]+)\\\\D\", \"\"), , ].map)), , .../*MARR*/[function(){}, (void options('strict')), (void options('strict')), function(){}, objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), (void options('strict')), (void options('strict')), function(){}, (void options('strict')), function(){}, (void options('strict')), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), function(){}, (void options('strict')), (void options('strict')), (void options('strict')), (void options('strict')), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}], (throw ((function sum_slicing(clohke) { ; return clohke.length == 0 ? 0 : clohke[0] + sum_slicing(clohke.slice(1)); })(/*MARR*/[[1], new String('q'), new String('q'), [[1]], [1], [1], [[1]], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), [[1]], objectEmulatingUndefined(), objectEmulatingUndefined(), [[1]], [[1]], objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [[1]], objectEmulatingUndefined(), new String('q'), [[1]], [1], [1], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [[1]], [1], objectEmulatingUndefined(), [1], [1], [[1]], objectEmulatingUndefined(), [[1]], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], [1], objectEmulatingUndefined(), [[1]], [1], [1], [1], [1], new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()])) - x), , x.__defineGetter__(\"x\", (1 for (x in [])))(eval % x, (eval(\"Array.prototype.sort.call(o1.a1, (function mcc_() { var jidjhf = 0; return function() { ++jidjhf; if (/*ICCD*/jidjhf % 8 == 5) { dumpln('hit!'); try { Array.prototype.forEach.call(a0, f2, g0.m2); } catch(e0) { } x = g2; } else { dumpln('miss!'); try { h1 + ''; } catch(e0) { } try { e1.add(a1); } catch(e1) { } try { v1 = g1.runOffThreadScript(); } catch(e2) { } Object.preventExtensions(s0); } };})(), o0.i2);\", x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: undefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: function() { return false; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { throw 3; }, hasOwn: function() { throw 3; }, get: undefined, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: undefined, keys: function() { return Object.keys(x); }, }; })(function ([y]) { }), Function)))), timeout(1800), ([new Uint8Array(/(?:[^]|[^][^])+?/gy, Math)])]) { yield i; } })();");
/*fuzzSeed-66366547*/count=988; tryItOut("{ void 0; minorgc(false); } t2 = new Int32Array(t1);");
/*fuzzSeed-66366547*/count=989; tryItOut("e2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (d0);\n    return +((+(0.0/0.0)));\n  }\n  return f; })(this, {ff: function (e) { g1.i2.send(f2); } }, new ArrayBuffer(4096));");
/*fuzzSeed-66366547*/count=990; tryItOut("do {/*RXUB*/var r = /(?=(\u36e7|[\\r-\u8014])\\b\\b${1,1}\\B)[\\u0057-\\u00E8;-\\cB\\uf093]|(\\ub656|^+)|[^]+?/gim; var s = \"W\"; print(s.replace(r, '')); M:with({b:  /x/g }){g1.offThreadCompileScript(\"/* no regression tests found */\"); } } while(((4277) -= (/*RXUE*//(?:\\2|\\\ud2a3{2,})|(?=(?=[^]\\B)){2,}{3,}/g.exec(\"\\na1 \\uf96e a\\n\\u06f7  \\na1 \\uf96e a\\n\\u06f7  \"))) && 0);");
/*fuzzSeed-66366547*/count=991; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.sin((( ! Math.fround(mathy0(Math.fround(Number.MIN_SAFE_INTEGER), Math.fround(mathy0(-(2**53-2), Math.log2(-(2**53+2))))))) ? Math.fround((( + x) | 0)) : ( + Math.atan2(( + ( + ( - ( + ( + x))))), ( + x))))); }); testMathyFunction(mathy4, [[0], true, (new Boolean(false)), ({valueOf:function(){return '0';}}), undefined, (new Number(-0)), '/0/', null, (function(){return 0;}), false, -0, ({valueOf:function(){return 0;}}), '', /0/, ({toString:function(){return '0';}}), '\\0', [], (new String('')), objectEmulatingUndefined(), 1, 0, '0', NaN, 0.1, (new Boolean(true)), (new Number(0))]); ");
/*fuzzSeed-66366547*/count=992; tryItOut("var c = (void options('strict_mode'));print((c != x));");
/*fuzzSeed-66366547*/count=993; tryItOut("/*RXUB*/var r = new RegExp(\"(\\\\1{3,7})(?:(?:^)?)|.*?\", \"yi\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=994; tryItOut("t2 = t1.subarray(5);");
/*fuzzSeed-66366547*/count=995; tryItOut("\"use strict\"; print(\"\\u14EE\");");
/*fuzzSeed-66366547*/count=996; tryItOut("\"1\"");
/*fuzzSeed-66366547*/count=997; tryItOut("\"use strict\"; (undefined);\nf0.valueOf = (function mcc_() { var pdvdck = 0; return function() { ++pdvdck; f1(/*ICCD*/pdvdck % 10 == 3);};})();\n");
/*fuzzSeed-66366547*/count=998; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.min(Math.atan2(Math.atan2(Math.fround(Math.expm1(Math.fround(Math.min(Math.fround(( + Math.log((x | 0)))), Math.fround(x))))), (( + 1/0) ? Math.min((-0x100000000 >>> 0), ((x & x) >>> 0)) : (Math.cosh((y >>> 0)) >>> 0))), (Math.round(((( ~ ((( - (0/0 && 42)) >>> 0) | 0)) | 0) | 0)) | 0)), Math.fround(( + Math.ceil(y)))); }); testMathyFunction(mathy0, [-1/0, -0x0ffffffff, Number.MAX_VALUE, 0x080000000, 0, 2**53, -0x080000000, -(2**53-2), -Number.MAX_VALUE, 1/0, Number.MAX_SAFE_INTEGER, -(2**53), 0x07fffffff, -0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 2**53+2, 0x100000000, 0/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -0, 2**53-2, 0x0ffffffff, -(2**53+2), -0x080000001, 0.000000000000001, 42, -0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, 1]); ");
/*fuzzSeed-66366547*/count=999; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.atan2(( + Math.atan2(( + mathy0((( - Math.fround(Math.sin((0x080000001 >>> 0)))) | 0), Math.fround((Math.log1p((y >>> 0)) >>> 0)))), ( + ( + ( ! ( + (( - Math.cbrt(y)) | 0))))))), Math.fround((( + (( + Math.fround(Math.trunc((x >>> 0)))) || ( + Math.abs(( ~ ( + Math.sin(Math.fround(y)))))))) ** Math.atan2(Math.pow(y, ((y , x) | 0)), ( + ( ~ ( + mathy1(( + x), (-(2**53+2) | 0))))))))); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), false, (new Boolean(true)), (new Number(-0)), null, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (function(){return 0;}), NaN, '0', '/0/', -0, [], ({valueOf:function(){return '0';}}), undefined, '\\0', '', (new String('')), 0, 1, (new Number(0)), [0], /0/, 0.1, true, (new Boolean(false))]); ");
/*fuzzSeed-66366547*/count=1000; tryItOut("\"use asm\"; /*MXX1*/o0 = g0.Date.prototype.toString;");
/*fuzzSeed-66366547*/count=1001; tryItOut("h0 + this.g0.s1;");
/*fuzzSeed-66366547*/count=1002; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 4097.0;\n    var i4 = 0;\n    i0 = (i2);\n    return (((abs((this))|0) / (~(-(i2)))))|0;\n  }\n  return f; })(this, {ff: x = x}, new ArrayBuffer(4096)); ");
/*fuzzSeed-66366547*/count=1003; tryItOut("a = linkedList(a, 3496);");
/*fuzzSeed-66366547*/count=1004; tryItOut("mathy5 = (function(x, y) { return ( ! Math.fround((Math.pow(Math.imul(Math.fround(Math.max(Math.fround(y), ( + x))), ( + (0x07fffffff !== (y >>> 0)))), ((y & Math.fround(Math.round(-0x080000001))) | 0)) | 0))); }); ");
/*fuzzSeed-66366547*/count=1005; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(a2, ({valueOf: function() { w = /*FARR*/[\"\\u7B80\", (z) = this, , (/*FARR*/[\"\\uA108\", \"\\uA7EE\", 4, undefined, , ...[], x, ...[]].some(Uint16Array)), ((void version(180))), new encodeURI(-15), .../*MARR*/[x],  /x/ .yoyo(\"\\uA2CD\"), (4277)];/*infloop*/for(z; (let (x) let (c =  /x/g , x, xfvtdh, a, qscihn, e, x, vzngda) ((void shapeOf(\"\\u8297\"))) ? new (\"\\u9461\")(/\\b*/gy) : c); (let (\u3056, y, b) w)) \"\\u1544\";\nreturn \"\\u89CC\";\nreturn 14; }}), { configurable: new (Uint8Array)(), enumerable: let (a = Int16Array(({a2:z2}), this)) ((4277))().small(let (y = this) new RegExp(\"(?!.\\\\s\\\\b+)\\\\3(\\u954d.(\\\\W)|^)+\", \"\"), (4277)), writable: true, value: x });");
/*fuzzSeed-66366547*/count=1006; tryItOut("((void version(185)) ? /((?=\\B{3,}))|[^]|(?![^])|\\s+?|(?:[\\D\\u002D])|\\2|0+/gyim : timeout(1800));");
/*fuzzSeed-66366547*/count=1007; tryItOut("\"use strict\"; for(let z in /*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, null, null, function(){}, null, function(){}, null, null, null, new String('q'), new String('q'), null, null, null, null, null, null, null, function(){}, new String('q'), function(){}, function(){}, new String('q'), new String('q'), function(){}, function(){}, function(){}, new String('q'), null, null, new String('q'), new String('q'), new String('q'), null, new String('q'), new String('q'), new String('q'), null, function(){}, function(){}, null, null, new String('q'), function(){}, null, new String('q'), function(){}, function(){}, function(){}, new String('q'), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, null, function(){}, null, null, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), null, new String('q'), new String('q'), null, function(){}, new String('q'), function(){}, new String('q'), null, null, function(){}, null, function(){}, function(){}, new String('q'), new String('q'), new String('q'), new String('q'), function(){}, function(){}, null, new String('q'), null, new String('q'), function(){}, function(){}, null, null, function(){}]) return;");
/*fuzzSeed-66366547*/count=1008; tryItOut("for(let [d, a] = (x) =  /x/  in (eval = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: undefined, delete: Int32Array, fix: Array.prototype.copyWithin, has: function(name) { return name in x; }, hasOwn: SharedArrayBuffer, get: undefined, set: function() { throw 3; }, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(x), (4277)))) {/*infloop*/ for  each(y in ((x) = (4277))) {((4277));yield (yield \"\\u5274\"); }Array.prototype.reverse.call(a1);; }");
/*fuzzSeed-66366547*/count=1009; tryItOut("testMathyFunction(mathy0, [-1/0, -0x080000001, 1.7976931348623157e308, 0, 0x100000001, -0, Number.MAX_VALUE, 0x100000000, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0.000000000000001, 0/0, 2**53+2, 1, -Number.MAX_VALUE, -(2**53), 0x0ffffffff, -0x0ffffffff, 0x080000001, -Number.MIN_VALUE, Math.PI, -0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, 2**53, -0x100000000, 0x07fffffff, 42, Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-66366547*/count=1010; tryItOut("mathy0 = (function(x, y) { return (Math.pow(( + Math.imul(((Math.imul((x >>> 0), (( + ( + ( ~ x))) >>> 0)) > ( + (Math.sin((( + y) + x)) | 0))) | 0), Math.log1p((Math.log(y) >>> 0)))), ( - (( ~ Math.max((( ~ ( ~ -Number.MAX_SAFE_INTEGER)) | 0), Math.fround(Math.atanh((y | 0))))) | 0))) | 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, 1/0, 2**53-2, 0x0ffffffff, 0, Number.MIN_VALUE, Number.MAX_VALUE, 42, 0x07fffffff, -0x100000000, 0x100000001, -(2**53-2), 1, -0x07fffffff, -Number.MAX_VALUE, -0x080000001, 0x080000001, -0, -(2**53+2), 2**53, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, Math.PI, 2**53+2, -1/0, 0x100000000, -0x080000000, -0x100000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=1011; tryItOut("s0 + p0;");
/*fuzzSeed-66366547*/count=1012; tryItOut("\"use strict\"; a1.sort();");
/*fuzzSeed-66366547*/count=1013; tryItOut("/*RXUB*/var r = /(\\S)+?/gim; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-66366547*/count=1014; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.acos(((Math.atan((Math.asin(x) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, ['', (new String('')), 1, 0.1, (function(){return 0;}), objectEmulatingUndefined(), [], true, NaN, '/0/', undefined, false, ({valueOf:function(){return 0;}}), (new Number(-0)), '0', '\\0', /0/, (new Number(0)), [0], 0, (new Boolean(false)), null, -0, ({valueOf:function(){return '0';}}), (new Boolean(true)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-66366547*/count=1015; tryItOut("e0.delete(g2.s1);");
/*fuzzSeed-66366547*/count=1016; tryItOut("");
/*fuzzSeed-66366547*/count=1017; tryItOut("t1 = t2.subarray(2, v2);");
/*fuzzSeed-66366547*/count=1018; tryItOut("\"use strict\"; e2.add(s2);");
/*fuzzSeed-66366547*/count=1019; tryItOut("testMathyFunction(mathy2, /*MARR*/[2, new Number(1), NaN, new Number(1), new Number(1), new Number(1),  'A' , function(){},  'A' , NaN, new Number(1), new Number(1)]); ");
/*fuzzSeed-66366547*/count=1020; tryItOut("return x[new String(\"5\")]++;for(let y in (y || d)) x = c;");
/*fuzzSeed-66366547*/count=1021; tryItOut("\"use strict\"; o1.v2 = evalcx(\"s1.valueOf = (function(x, y) { return Math.max(Math.fround(( ~ Math.fround(((Math.hypot(((x > (( ~ ((0x080000001 == 0) | 0)) ? (Math.abs((-(2**53+2) | 0)) | 0) : /*RXUE*/new RegExp(\\\"($$[%-\\\\\\\\ua607]){31}(\\\\\\\\1)|(?:((?:[^]*)))*\\\", \\\"gyi\\\").exec(\\\"\\\"))) | 0), (Math.sign((Math.abs(Math.min(x, y)) ^ (Math.PI < x))) | 0)) | 0) * Math.max(( + ( ! ((Math.fround(Math.min(-0x07fffffff, -Number.MAX_SAFE_INTEGER)) || (y | 0)) || Math.fround((Math.fround(x) === Math.fround(1.7976931348623157e308)))))), ( + (Math.expm1(x) >>> 0))))))), Math.imul((( ~ (Math.tan((x | 0)) | 0)) >>> 0), (Math.max((( + (y | 0)) | 0), (Math.fround(Math.trunc(Math.fround(x))) <= -Number.MIN_SAFE_INTEGER)) + ( - y)))); });\", g0);");
/*fuzzSeed-66366547*/count=1022; tryItOut("mathy5 = (function(x, y) { return Math.ceil((( - ((((mathy0(Math.fround((Math.tan((0 | 0)) | 0)), y) | 0) * (( + ( ~ ( + (( + x) < y)))) | 0)) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, -Number.MAX_VALUE, -0x080000000, 0x100000001, -(2**53), 0, -0x100000001, 2**53+2, -(2**53-2), -1/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, 0x100000000, -0x100000000, -0x0ffffffff, 0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, Math.PI, 1, Number.MAX_SAFE_INTEGER, 42, 0x080000000, -0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, 1.7976931348623157e308, Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-66366547*/count=1023; tryItOut("/*oLoop*/for (let uewgzz = 0; uewgzz < 76; ++uewgzz) { {} } ");
/*fuzzSeed-66366547*/count=1024; tryItOut("\"use strict\"; print(({a1:1}).__defineGetter__(\"x\", false));var x = (Array.prototype.findIndex.prototype);");
/*fuzzSeed-66366547*/count=1025; tryItOut("\"use strict\"; \"use asm\"; o1.v2 = (x % 3 != 0);");
/*fuzzSeed-66366547*/count=1026; tryItOut("a0.splice(-11, ({valueOf: function() { selectforgc(g2.o1);return 14; }}));");
/*fuzzSeed-66366547*/count=1027; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return mathy1(( + (( + (((Math.ceil((( + Math.log2(( + 0x07fffffff))) >>> 0)) | 0) | mathy1(Math.fround((Math.fround(Number.MIN_SAFE_INTEGER) ? ( + Math.min(x, Math.fround(( ~ (x >>> 0))))) : Math.fround(y))), Math.fround((Math.asin((2**53-2 >>> 0)) >>> 0)))) | 0)) ? ( + ( ~ (Math.max((Math.cosh((-0x080000000 | 0)) >>> 0), (Math.fround(Math.round(0)) >>> 0)) >>> 0))) : ( + (((( ! ((Math.max(y, Math.hypot(x, 0/0)) >>> Math.asin(x)) >>> 0)) >>> 0) | 0) ** ((mathy1((Math.expm1(0/0) | 0), (x | 0)) >>> 0) == Math.log(y)))))), (Math.pow((Math.clz32(Math.max(x, ((x | ( + ( + ( ! Math.fround(x))))) | 0))) | 0), (( + (Math.pow((Math.fround(( + (x | 0))) | 0), (x | 0)) | 0)) | 0)) | 0)); }); testMathyFunction(mathy4, [-0x080000001, 1/0, 0.000000000000001, 0x0ffffffff, 0, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0x080000000, 1, -(2**53), Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, -0, -0x07fffffff, 42, 1.7976931348623157e308, 2**53+2, 2**53-2, -0x0ffffffff, 0x080000001, -(2**53-2), -(2**53+2), 2**53, -Number.MIN_VALUE, 0x100000000, -0x100000001, -Number.MAX_VALUE, -0x100000000, 0x07fffffff, Number.MAX_VALUE, 0/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1028; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(Math.hypot((( - Math.pow(( ! y), -1/0)) | 0), ((Math.cosh((( + Math.pow((x ? (((Math.sinh(y) >>> 0) * ((( + x) & y) >>> 0)) >>> 0) : x), ( + y))) | 0)) | 0) | 0))), Math.fround((Math.asinh(((( + (-Number.MAX_SAFE_INTEGER | 0)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 2**53-2, -Number.MIN_VALUE, -0x100000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, -0x100000000, -0x080000000, -(2**53-2), -0x07fffffff, 1/0, 0x100000001, 0x080000000, 0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, Math.PI, 2**53+2, -0x0ffffffff, Number.MAX_VALUE, 0/0, 0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53, -(2**53+2), -1/0, 0x100000000, 1.7976931348623157e308, 0, 1, 42]); ");
/*fuzzSeed-66366547*/count=1029; tryItOut("for(b in \"\\u849B\") {/*MXX3*/g1.String.prototype.repeat = g1.String.prototype.repeat;Array.prototype.forEach.apply(a0, [(function(a0, a1) { var r0 = 9 % b; b = 1 ^ a1; var r1 = b * r0; var r2 = 1 / a1; r1 = r0 ^ a1; r0 = a0 | r2; var r3 = a0 % 9; x = 7 | 4; x = x + r3; var r4 = 9 - 2; var r5 = r2 & r1; b = a1 & a0; var r6 = r4 | 4; var r7 = 9 % a1; r7 = r0 + r7; r3 = r3 / r3; r1 = r3 & 8; print(r1); var r8 = b - 6; var r9 = 1 | 0; var r10 = 6 ^ 8; var r11 = 1 + 7; r11 = r4 * r11; var r12 = b % 1; var r13 = r2 | r9; var r14 = 6 | 0; r0 = 2 & r4; var r15 = r0 | 5; var r16 = 9 ^ 3; var r17 = r0 - r12; var r18 = 0 / r10; print(r10); var r19 = 2 % r3; var r20 = 4 - 0; var r21 = r19 * r12; var r22 = a0 - r10; var r23 = r14 ^ b; var r24 = r14 % x; r11 = 6 ^ a0; r19 = 8 - 4; var r25 = r16 % r17; var r26 = r11 ^ r2; var r27 = a1 | 8; var r28 = r11 * b; var r29 = r8 % r13; var r30 = r29 + a0; var r31 = r0 ^ r17; r23 = r25 | r19; var r32 = r10 - r17; var r33 = 6 | r28; var r34 = r7 ^ 9; print(r0); var r35 = r32 ^ a0; var r36 = 8 ^ 8; a0 = r27 * r19; var r37 = r2 / r0; var r38 = a0 & 1; var r39 = 5 * 0; var r40 = 5 % r7; var r41 = r27 % r20; var r42 = r38 - r18; var r43 = r3 % 2; var r44 = 7 - r17; var r45 = 5 * r18; var r46 = r20 ^ r16; var r47 = r24 | r24; var r48 = r30 + 0; var r49 = r35 | r13; var r50 = 7 / 5; var r51 = r4 | 1; var r52 = r3 * r3; var r53 = r29 / r1; r15 = r2 & b; r5 = r12 - r11; r42 = r8 * r20; var r54 = b / r41; r5 = r44 / r54; var r55 = 8 + r37; r27 = r23 & r30; var r56 = r40 ^ r52; var r57 = r10 ^ 1; var r58 = r14 - r52; r6 = r28 * r41; var r59 = a1 * r53; var r60 = 6 / r52; var r61 = r40 / 3; var r62 = r30 | r4; r29 = 4 & r54; var r63 = 6 & 3; var r64 = r43 | r47; var r65 = r62 ^ 7; var r66 = r58 ^ r60; var r67 = r5 + 4; var r68 = 0 ^ r67; var r69 = r10 + 1; r12 = r13 ^ r68; r32 = 2 ^ r53; var r70 = r69 ^ r65; r36 = r12 ^ r0; var r71 = 4 & r10; var r72 = r23 | 3; r35 = r55 * r8; var r73 = r32 * r23; print(r69); r73 = 7 | r52; var r74 = r32 + 8; var r75 = r54 * r34; var r76 = r59 + 8; var r77 = r38 ^ 8; var r78 = r9 % 0; var r79 = 9 & r18; var r80 = 0 % r69; var r81 = r70 % r57; r57 = 1 | r4; var r82 = 7 | r5; r28 = 1 * r71; var r83 = 7 | r60; var r84 = 7 - 1; var r85 = 7 * r36; var r86 = 7 / r14; r38 = 5 - 6; r79 = r26 - r46; var r87 = r73 & r24; var r88 = r15 % r37; r26 = 4 + r59; var r89 = 3 * r48; r62 = r27 ^ r42; var r90 = 7 ^ r76; var r91 = r89 ^ r32; var r92 = r78 | r26; var r93 = 9 + r33; var r94 = r18 & r25; r80 = r40 + r22; r34 = r85 * r54; var r95 = 2 + 8; var r96 = r15 / r36; x = r48 ^ r36; var r97 = 1 ^ r45; var r98 = 3 % r93; var r99 = r64 ^ 8; var r100 = 5 / r73; var r101 = a0 + r35; var r102 = r92 ^ r57; var r103 = r45 % r59; var r104 = r37 - r43; var r105 = 7 % 5; var r106 = 9 & 2; var r107 = 5 & r11; var r108 = 3 + r37; var r109 = r67 ^ r22; var r110 = 0 * 1; var r111 = r67 * 4; var r112 = 8 & r5; var r113 = 1 * 3; var r114 = r84 / r60; var r115 = r40 - r34; var r116 = 2 / r56; r47 = 3 ^ 2; var r117 = r12 % 7; var r118 = r70 * 2; var r119 = r30 / 1; print(r2); var r120 = r60 | r26; var r121 = 9 - 6; var r122 = r10 & r97; var r123 = 0 & r92; var r124 = r8 | r44; var r125 = r88 % r97; var r126 = 7 * r77; var r127 = r81 - r36; var r128 = r71 & r65; var r129 = 2 * r77; var r130 = a0 - 7; var r131 = 8 + r116; var r132 = r95 * r6; var r133 = r99 ^ 8; var r134 = r39 % r63; var r135 = r19 * 6; r55 = r66 % r97; var r136 = r45 + 4; var r137 = 1 % r76; var r138 = r16 + r134; r61 = r108 / r9; var r139 = r65 & r96; var r140 = r108 ^ 4; var r141 = r115 ^ r97; var r142 = r44 - r98; var r143 = r42 ^ r89; var r144 = r40 / r141; var r145 = r71 / 9; var r146 = 0 / 0; r59 = 0 % r22; var r147 = r121 ^ r109; print(r0); r7 = 2 ^ 8; var r148 = 0 % r60; var r149 = r104 * r144; var r150 = r142 - 0; var r151 = r107 % r93; var r152 = r140 + r54; r59 = r25 & 2; var r153 = 9 | 1; r118 = r99 ^ r80; var r154 = r148 + r112; var r155 = 9 / r31; var r156 = 2 & r77; var r157 = r42 * r127; var r158 = r69 * r128; var r159 = 4 & r83; print(r116); var r160 = 6 / 7; var r161 = 5 - r51; r116 = r11 ^ r91; var r162 = r110 - r13; r98 = r26 | 3; var r163 = a0 & 0; r36 = r26 * 4; var r164 = 6 ^ 5; var r165 = 8 - r51; r112 = 1 + r141; var r166 = 7 * r95; var r167 = r14 ^ r90; r136 = 5 & 6; var r168 = r84 | r131; r56 = 6 % 5; var r169 = 4 | r12; var r170 = r59 & r64; var r171 = r158 ^ a0; var r172 = r136 % r10; var r173 = 6 | 4; var r174 = r91 - r112; var r175 = 3 % 1; var r176 = 3 - r25; var r177 = r24 / r100; var r178 = r7 & r109; r20 = r68 ^ r113; var r179 = r125 / 5; var r180 = r1 * 7; var r181 = r164 / r40; var r182 = r162 * r26; var r183 = 0 & 5; var r184 = 1 | r93; r169 = 3 & 2; var r185 = 3 ^ r45; var r186 = 6 / r5; var r187 = 9 * 9; var r188 = r100 & r129; var r189 = 4 * 1; var r190 = r49 * r28; var r191 = r55 & 9; var r192 = 3 / 9; var r193 = r164 - 2; var r194 = 9 / r0; r131 = r11 / r89; var r195 = 8 & r131; var r196 = r162 % r56; var r197 = 3 / r175; var r198 = r175 / r109; var r199 = r7 & r92; var r200 = r28 & r107; var r201 = r147 ^ r91; var r202 = r3 & r111; var r203 = r89 / r76; var r204 = r87 | r171; var r205 = 7 & 9; var r206 = 0 % 5; r47 = r22 + 1; r137 = r48 * 2; r31 = 3 | 3; r83 = r171 & r80; var r207 = 3 & r169; var r208 = 3 * 1; r37 = 4 % r91; var r209 = r160 | 7; var r210 = r108 % r80; r167 = 6 ^ r176; var r211 = r198 % r189; r84 = r31 - 0; var r212 = r62 | r170; r197 = 8 * 3; var r213 = r176 - r164; var r214 = x | 6; var r215 = 6 * r62; var r216 = 0 + r8; var r217 = r10 ^ r75; var r218 = 5 % r15; var r219 = 0 / r179; var r220 = r54 % 5; r127 = r61 - r186; var r221 = r138 ^ r82; var r222 = 4 + 5; var r223 = r135 + 3; r44 = r172 | r103; var r224 = 7 * r192; var r225 = r147 & 8; r162 = r89 | r138; r170 = 7 % r192; r116 = r133 ^ r186; var r226 = r81 ^ 1; print(r211); var r227 = 7 | 7; var r228 = 6 / r211; var r229 = r175 - r111; r185 = 7 + r136; var r230 = r88 - 3; var r231 = r129 % r5; var r232 = r39 % r156; var r233 = 7 % r69; var r234 = r101 - r70; var r235 = 0 ^ r228; var r236 = r68 % r109; var r237 = r72 | r153; var r238 = 8 ^ 7; var r239 = 3 ^ 7; var r240 = r191 * r29; var r241 = r167 & 6; var r242 = r240 / 5; var r243 = 1 % r166; var r244 = 5 + r179; r146 = 5 / r224; var r245 = r62 * r236; var r246 = r114 / r100; var r247 = r55 / 4; r190 = r126 | r220; var r248 = 6 / r175; var r249 = 2 * r157; print(r78); var r250 = 1 | r77; var r251 = r0 - r44; var r252 = r237 * r224; var r253 = 7 - 3; var r254 = 5 * r93; var r255 = 9 / r204; var r256 = 5 % 0; var r257 = r223 | r62; r223 = r47 * 8; var r258 = r116 / r138; var r259 = 9 % r52; var r260 = r179 * r121; var r261 = r117 * r192; var r262 = r109 / r185; r196 = r140 * r68; var r263 = r136 ^ r42; r86 = r151 * 0; var r264 = r128 / r113; var r265 = r8 * r11; var r266 = 8 & r182; var r267 = r24 & r247; var r268 = r179 + r116; r17 = r95 / r135; var r269 = r30 | r268; var r270 = r106 * r257; var r271 = 6 * 3; var r272 = 6 / 1; var r273 = r102 + 8; r104 = r148 * r258; var r274 = b * r11; r247 = 4 - r140; var r275 = 9 / r238; var r276 = r75 | 7; r13 = r55 - r153; var r277 = r250 - r84; r79 = 4 - r5; var r278 = r166 - r247; var r279 = r271 & 7; var r280 = r228 & r238; var r281 = r77 ^ r189; var r282 = r206 - 8; var r283 = 6 + 1; var r284 = 6 - 5; r256 = r3 % r24; var r285 = r44 ^ 3; r283 = 4 * 7; print(r243); r163 = r69 + 8; r122 = r64 / 5; var r286 = r101 & r254; var r287 = r106 & 7; var r288 = 2 & r11; var r289 = 7 | r35; r97 = r182 & r204; var r290 = r260 | 9; var r291 = 5 ^ r250; var r292 = r227 + r134; var r293 = r228 - r145; var r294 = 9 % 8; print(r38); var r295 = 7 / r112; var r296 = r147 * r294; var r297 = r52 % 5; r142 = r106 * r79; var r298 = 9 / r12; var r299 = r264 * r281; var r300 = 8 ^ a1; r180 = 0 + r23; var r301 = r166 / r0; var r302 = r257 * 4; var r303 = r236 / r140; var r304 = r187 / r252; print(r152); r115 = a1 / 0; var r305 = 3 ^ r205; r38 = r239 * r148; var r306 = 6 | r94; var r307 = r54 - 5; var r308 = r57 + r288; r152 = 1 | r127; var r309 = r126 / r194; var r310 = r17 ^ 6; var r311 = 4 / 9; r72 = r6 & 3; var r312 = 1 - r253; r104 = 7 / r222; r170 = r81 ^ 0; var r313 = 5 - 6; print(r40); var r314 = r153 / 3; var r315 = r23 - r233; var r316 = r38 | 6; r249 = r9 * 1; var r317 = 7 / 4; var r318 = r41 * r44; print(r111); var r319 = 6 ^ r35; r247 = r41 % r40; var r320 = r199 & r140; var r321 = r8 & r41; var r322 = 6 % 4; var r323 = r18 ^ r241; var r324 = r162 + r241; var r325 = r72 % r16; r31 = r323 / r129; var r326 = r166 - r225; var r327 = r256 * r37; var r328 = r110 & 3; var r329 = 1 * 8; var r330 = r213 % r131; var r331 = 6 * r20; var r332 = 4 & r161; r192 = r1 * r74; var r333 = 6 ^ r148; var r334 = 6 / 1; r227 = r166 * r235; var r335 = r324 | 0; var r336 = r184 * 5; var r337 = r76 ^ r242; var r338 = r33 ^ r33; var r339 = r154 ^ r166; r61 = 6 / r267; var r340 = 4 - r269; var r341 = r36 + r30; var r342 = r197 / r307; var r343 = 1 * 1; var r344 = r123 * 1; var r345 = r259 - r322; var r346 = 4 ^ r89; var r347 = r112 | r15; var r348 = r280 + r120; var r349 = r300 / r309; var r350 = r278 % 2; var r351 = r15 | r151; var r352 = r69 * r17; var r353 = r290 % r307; var r354 = r34 / r262; var r355 = r260 - r297; var r356 = 4 + 4; var r357 = r167 - r23; r195 = 0 & r155; var r358 = r299 * r236; var r359 = r302 + r342; var r360 = 1 * r9; var r361 = r33 + r166; r170 = r143 * r217; var r362 = r104 & 5; var r363 = a0 & 7; var r364 = r176 & r221; var r365 = r256 ^ 7; var r366 = r336 * r301; var r367 = r240 - r62; var r368 = r213 & r141; r91 = 8 ^ 9; var r369 = r308 / r128; var r370 = 1 * r258; var r371 = r163 ^ 2; var r372 = 6 ^ r131; var r373 = r22 / r79; var r374 = r120 * 0; var r375 = r240 * r345; var r376 = r286 * r129; var r377 = r46 | 6; var r378 = r202 % 2; var r379 = r48 * 1; r232 = r51 & r49; r6 = r347 & r156; var r380 = 3 & r170; var r381 = r127 % r216; var r382 = r326 % r136; var r383 = 0 / 3; var r384 = 6 | 5; var r385 = r354 % r269; var r386 = r98 + r342; var r387 = 6 * 1; var r388 = 9 - r172; var r389 = r49 * r363; var r390 = r308 * r45; r306 = r109 / r262; r280 = r313 / r158; var r391 = r350 * 4; r329 = r374 + r20; var r392 = 7 / 7; r214 = r124 % b; var r393 = r7 ^ r254; var r394 = 1 / r60; r239 = r174 % r176; r367 = 3 % r340; print(r375); var r395 = 2 - r53; var r396 = 6 ^ r0; var r397 = r10 + 9; var r398 = 5 - r228; var r399 = r51 * r311; var r400 = 2 & r47; var r401 = 9 ^ 8; r325 = r65 % r170; r23 = r105 / 6; var r402 = 8 & r235; var r403 = r72 * r142; var r404 = r223 + r55; r68 = 7 / r93; var r405 = 9 / r125; var r406 = 8 / 1; var r407 = r315 + r210; r34 = r332 & r73; var r408 = r212 % r66; var r409 = r158 / 6; var r410 = r372 % r359; var r411 = r269 % 0; var r412 = 9 | r55; var r413 = 7 / r195; var r414 = r330 - r111; var r415 = 5 ^ r170; var r416 = r4 ^ r298; var r417 = r171 * r118; var r418 = r150 % r402; var r419 = r366 * 8; var r420 = r156 * r82; var r421 = r24 % r277; var r422 = r232 ^ 4; var r423 = r342 - r42; r224 = 9 / 8; var r424 = r192 * r89; var r425 = 5 / r391; var r426 = r45 & r371; var r427 = r197 - r251; r184 = 5 & 6; var r428 = r404 * r223; var r429 = r325 & r207; r47 = r284 * r179; var r430 = r355 * 4; var r431 = r345 % 0; var r432 = r89 & r367; var r433 = r406 - r402; var r434 = r369 ^ a0; var r435 = r68 | r337; r89 = r323 ^ 5; var r436 = r296 ^ 5; var r437 = 8 * r390; var r438 = 2 & r333; var r439 = r351 ^ 9; var r440 = r374 & 1; r417 = r163 ^ r237; var r441 = 9 / 4; var r442 = r69 & 0; var r443 = 6 & r83; var r444 = r362 - r350; var r445 = r180 % r178; var r446 = 3 & r337; var r447 = r346 + 0; var r448 = 7 + r354; r307 = 9 + r16; var r449 = r423 & r186; var r450 = r168 ^ r368; var r451 = r96 ^ 0; var r452 = 3 + r27; var r453 = r123 ^ 3; var r454 = 2 % 3; var r455 = r91 * 4; r202 = r404 * r228; var r456 = r323 / r252; var r457 = r294 + 2; var r458 = r154 - r120; var r459 = 7 - r175; var r460 = r94 - r168; var r461 = 0 ^ r143; r296 = r138 / r146; var r462 = 4 + r141; r146 = r316 ^ 8; var r463 = r72 + r55; var r464 = r397 & r223; r291 = r219 % 1; r255 = r329 / r251; var r465 = 4 - r195; r257 = 5 | r188; var r466 = r116 | 0; var r467 = 7 * 4; r199 = r30 & r318; var r468 = r318 & 7; var r469 = r21 * r269; var r470 = r49 & 9; r24 = r412 & r185; var r471 = r242 ^ r65; r182 = r105 ^ 5; r162 = 3 + 0; var r472 = r23 + 1; r10 = 0 & 0; var r473 = 7 - r376; var r474 = 0 % 0; var r475 = 0 / r47; var r476 = r214 + 3; r434 = r210 & r24; var r477 = r149 / r174; var r478 = 4 | r470; r229 = 5 * r3; var r479 = r439 / 8; r478 = r379 * r26; var r480 = r462 / 0; var r481 = r380 ^ 6; var r482 = r470 - r26; var r483 = 0 & 6; var r484 = r135 ^ r321; var r485 = r451 | r413; var r486 = r465 & r258; var r487 = r146 + 8; var r488 = r141 + r177; var r489 = r99 / r73; r466 = r20 % r108; var r490 = r315 | 3; var r491 = 1 | r317; var r492 = 0 * r127; print(r174); var r493 = r435 + r31; var r494 = r103 | r422; var r495 = r351 & r168; var r496 = 7 / r212; var r497 = r210 * r339; var r498 = r46 % r363; var r499 = r224 & r253; var r500 = r462 | r207; r163 = r78 / r30; var r501 = r342 ^ 2; var r502 = r129 | r160; var r503 = r111 & 6; var r504 = 0 - r330; r192 = 2 ^ 7; r455 = 1 | r254; var r505 = r395 ^ r99; r373 = 6 * 7; var r506 = r97 + 1; print(r463); var r507 = 6 & r304; var r508 = r253 | r195; var r509 = 2 + r293; var r510 = r337 * r384; var r511 = r387 | r111; var r512 = 5 - r425; var r513 = r233 / 4; var r514 = 0 / r382; var r515 = r228 & r46; var r516 = r461 ^ r80; var r517 = 5 + 8; var r518 = 8 % r394; r474 = r78 & r293; var r519 = r468 | r390; var r520 = r142 * r111; var r521 = r257 + r89; print(r149); var r522 = r277 | r4; r9 = r24 % r497; var r523 = r467 + r443; var r524 = r196 + r419; var r525 = r360 ^ 8; var r526 = r386 + r120; var r527 = r25 / r190; r238 = 2 % r181; var r528 = 4 + r158; r404 = r259 / r397; r473 = r343 ^ r381; var r529 = r514 * 0; var r530 = 2 & 8; var r531 = r423 | 5; var r532 = r281 & r299; var r533 = 2 % r429; r420 = r62 + 3; print(r454); var r534 = 0 & r407; var r535 = r57 % 6; r315 = r50 % r345; r275 = r477 / r350; var r536 = r27 / r176; r465 = r399 & r289; r6 = r523 ^ r149; var r537 = 6 - r164; r104 = r332 | 7; var r538 = 8 % r135; r313 = 9 & r307; var r539 = r274 - r343; var r540 = r108 & 5; print(r89); var r541 = r206 * 4; r331 = 5 - r178; var r542 = r105 | r40; r276 = r347 % 1; var r543 = 1 | r27; var r544 = r377 ^ 7; var r545 = r12 + 4; var r546 = r32 & r481; var r547 = 7 / r254; var r548 = r171 / r431; var r549 = r269 % 3; r461 = r394 | 2; var r550 = 9 - r338; var r551 = 8 | r413; var r552 = 0 ^ 8; var r553 = r71 / r277; var r554 = 1 | 1; var r555 = r145 & 2; var r556 = r323 & 8; r508 = r261 / 4; var r557 = r371 | 0; var r558 = r322 / r358; var r559 = r395 | r431; var r560 = 7 / r530; var r561 = r301 ^ r497; var r562 = 3 * r70; var r563 = r382 & 8; var r564 = r141 | r63; var r565 = 0 + r203; var r566 = r34 - r120; var r567 = r122 & r21; print(r104); r61 = r225 / 5; var r568 = r43 - r80; r315 = r55 * 4; var r569 = r244 | r75; var r570 = r134 * r282; print(r250); var r571 = r432 & 2; var r572 = r560 - r381; var r573 = r59 - 7; r338 = r307 + r166; var r574 = r334 & r223; var r575 = 9 - r556; r230 = r133 * 5; var r576 = r180 - r104; var r577 = 7 % r517; var r578 = 6 & 5; var r579 = r279 % r195; var r580 = r269 % r231; print(r341); var r581 = 2 ^ 9; var r582 = 5 - 0; r105 = r336 & 8; print(r463); r134 = r297 + 0; var r583 = r318 - r10; var r584 = r282 | 0; var r585 = a1 ^ r440; var r586 = r95 + r263; var r587 = r116 ^ r578; var r588 = r118 ^ 2; return x; })]); }");
/*fuzzSeed-66366547*/count=1030; tryItOut("\"use strict\"; testMathyFunction(mathy3, [2**53, -0x080000000, 0/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, -0, 0x080000000, -0x0ffffffff, -Number.MAX_VALUE, -0x100000000, Math.PI, 1/0, 42, 2**53-2, -Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, -(2**53), -0x100000001, 0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 1, -0x080000001, 0x07fffffff, 0x100000000, -0x07fffffff, -1/0, 1.7976931348623157e308, 0x100000001, 0x0ffffffff, Number.MIN_VALUE, 2**53+2]); ");
/*fuzzSeed-66366547*/count=1031; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + (( - ((( + (( + ( + Math.hypot(y, ( + y)))) - Math.PI)) + (Math.imul(y, y) - (y | 0))) | 0)) >>> 0)); }); testMathyFunction(mathy2, [2**53+2, -0x080000000, Math.PI, -0x100000000, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, -0, 0.000000000000001, 0x100000001, 2**53-2, 2**53, 0x07fffffff, 0x080000001, -0x080000001, 0/0, 1, 42, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, 0x0ffffffff, 0x100000000, -0x0ffffffff, -(2**53), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff]); ");
/*fuzzSeed-66366547*/count=1032; tryItOut("s0 + '';");
/*fuzzSeed-66366547*/count=1033; tryItOut("Array.prototype.push.call(a0, a2, e2, f1);");
/*fuzzSeed-66366547*/count=1034; tryItOut("mathy4 = (function(x, y) { return mathy0(Math.fround(Math.log1p(( + Math.acos((mathy0(((( + (x + Math.fround(0x0ffffffff))) + Number.MAX_SAFE_INTEGER) - -0x0ffffffff), Math.PI) | 0))))), ((((( + Math.atan2(x, ( + x))) !== ( + ( + (y >= ( + Math.hypot(-0x0ffffffff, y)))))) | 0) / ( + (( - ( + ( + ( + y)))) | 0))) | 0)); }); ");
/*fuzzSeed-66366547*/count=1035; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 4194305.0;\n    var d5 = 2.4178516392292583e+24;\n    var d6 = -9.44473296573929e+21;\n    {\n      d4 = (1.0078125);\n    }\n    d0 = (+(-1.0/0.0));\n    return (((Uint8ArrayView[0])))|0;\n    switch ((((((0xffffffff))>>>((0xfda2d2fd))) / (((0xde81290e))>>>((-0x51a2c67))))|0)) {\n      case -3:\n        (Uint32ArrayView[((0xffffffff)+((0x14ac618d) ? ((0xf8bf7023) ? (0xf8fd1bd3) : (0xfbab288f)) : (i1))) >> 2]) = (((d4) >= (d4)));\n        break;\n      case 1:\n        /*FFI*/ff();\n        break;\n      case -2:\n        return (((/*FFI*/ff()|0)+(-0x8000000)+((Int16ArrayView[0]))))|0;\n        break;\n      default:\n        d4 = (+(1.0/0.0));\n    }\n    {\n      return (((0xee510a25)-(i3)+((~~(+/*FFI*/ff())))))|0;\n    }\n    (Uint16ArrayView[((0x78a6861a)) >> 1]) = (((d4) == (d5)));\n    (Int16ArrayView[0]) = (((((0x2f4a92bf)) | ((i1))) >= (((x)-((i1) ? (-0x8000000) : (-0x8000000)))|0)));\n;    {\n      {\n        i3 = (0xc452cdef);\n      }\n    }\n    d4 = (d5);\n    d4 = (33.0);\n    {\n      (Int32ArrayView[(((Uint32ArrayView[((0xffffffff) / (0x9c6468cc)) >> 2]))+(i1)-(0x5fbda70a)) >> 2]) = (((d4) > (((d5)) - ((+/*FFI*/ff(((((0xe20fb489)-((((0x4321d4e1) <= (0x7c54e5be))*-0xfffff)))|0)), ((-1073741823.0)), ((-4.835703278458517e+24)), ((+(0x1550365a))), ((-8388609.0)))))))-(!(0xffffffff)));\n    }\n    d4 = (+(-1.0/0.0));\n    d4 = (((d0)) - ((7.555786372591432e+22)));\n    {\n      i2 = (i2);\n    }\n    return (((!((d4) > (-134217728.0)))))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [undefined, 0.1, 1, ({valueOf:function(){return 0;}}), '0', (new Number(-0)), -0, true, (function(){return 0;}), (new String('')), NaN, ({valueOf:function(){return '0';}}), [], [0], '/0/', 0, '\\0', (new Boolean(false)), /0/, (new Boolean(true)), ({toString:function(){return '0';}}), objectEmulatingUndefined(), false, null, '', (new Number(0))]); ");
/*fuzzSeed-66366547*/count=1036; tryItOut("v0 = t0.length;");
/*fuzzSeed-66366547*/count=1037; tryItOut("i1.send(h2);");
/*fuzzSeed-66366547*/count=1038; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[false]) { e2.add(o0.o0.b1); }");
/*fuzzSeed-66366547*/count=1039; tryItOut("\"use strict\"; g1.h0.get = f2;");
/*fuzzSeed-66366547*/count=1040; tryItOut("\"use strict\"; g1 + v0;");
/*fuzzSeed-66366547*/count=1041; tryItOut("\"use strict\"; /*infloop*/L:for(arguments[\"7\"] in (((1 for (x in [])))(16)))(-20);");
/*fuzzSeed-66366547*/count=1042; tryItOut("\"use strict\"; M: for  each(let w in null) null;");
/*fuzzSeed-66366547*/count=1043; tryItOut("v2 + '';");
/*fuzzSeed-66366547*/count=1044; tryItOut("o2.v0 = new Number(g0);");
/*fuzzSeed-66366547*/count=1045; tryItOut("\"use strict\"; g0.offThreadCompileScript(\"/*RXUB*/var r = /$(?!(?!\\\\B|\\\\b|\\\\B){1,}\\\\2){0,}{2,8193}/gi; var s = \\\"\\\"; print(s.search(r)); \");");
/*fuzzSeed-66366547*/count=1046; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -3.094850098213451e+26;\n    var i3 = 0;\n    return (((i1)-(/*FFI*/ff(((+(0x9f9f94b))), ((abs((((0x2974d7ce)+(0x797f2441)) | ((!(-0x8000000)))))|0)), ((+((+((Float32ArrayView[0])))))))|0)))|0;\n  }\n  return f; })(this, {ff: q => q}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [42, 0x080000001, 0x07fffffff, 0x100000001, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, -(2**53), 2**53+2, -1/0, 0x0ffffffff, -Number.MAX_VALUE, -0x080000001, -(2**53-2), 0x100000000, Number.MAX_VALUE, -0x100000000, -0x080000000, -0, -Number.MIN_VALUE, 0/0, 0, 1/0, -Number.MAX_SAFE_INTEGER, 1, -(2**53+2), -0x0ffffffff, Number.MIN_VALUE, Math.PI, 2**53, 2**53-2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1047; tryItOut("/*RXUB*/var r = /\\D|(?!\u00cc|.|\u5418|\u00b3?**)*/ym; var s = \"a\"; print(s.replace(r, s)); ");
/*fuzzSeed-66366547*/count=1048; tryItOut("let (w) { for (var p in i2) { try { Array.prototype.shift.apply(a0, [m1]); } catch(e0) { } try { h2 = {}; } catch(e1) { } try { p2 + t2; } catch(e2) { } print(g2); } }");
/*fuzzSeed-66366547*/count=1049; tryItOut("{ void 0; minorgc(false); }");
/*fuzzSeed-66366547*/count=1050; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround(( + Math.max(( + (Math.hypot(( - ( ! x)), ( + Math.log1p(x))) | 0)), ( + ((y & (x | 0)) < 42))))) >>> ( + Math.abs(( + Math.clz32(Math.trunc(y))))))); }); testMathyFunction(mathy1, [-Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, -0x100000001, -0x100000000, -0x080000001, 2**53, 0x080000001, -1/0, 0x100000000, 1, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, 0/0, Math.PI, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 0x080000000, 42, 0x0ffffffff, Number.MIN_VALUE, -(2**53), 0x07fffffff, Number.MAX_VALUE, 1.7976931348623157e308, -0, 2**53+2, 1/0]); ");
/*fuzzSeed-66366547*/count=1051; tryItOut("L: break ;");
/*fuzzSeed-66366547*/count=1052; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( ~ Math.imul((Math.fround(( ! ( + (( + y) === ( + Math.PI))))) === (mathy0(y, y) && (Math.pow((Math.fround(mathy1(Number.MIN_VALUE, 0x0ffffffff)) >>> 0), (( + ( ! (x >>> 0))) >>> 0)) >>> 0))), (Math.max(( + (( + Math.exp(y)) && ( + x))), ( + y)) ? (x >>> 0) : ( + Math.atanh(Math.fround((( ~ x) | 0)))))))); }); testMathyFunction(mathy3, [0x100000000, 0x07fffffff, -0x080000000, -0x080000001, 42, 2**53-2, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, -0x0ffffffff, 2**53+2, 1/0, 0x100000001, -(2**53), Math.PI, 1.7976931348623157e308, -0x07fffffff, 1, 0x080000001, -Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, -0, -0x100000001, -Number.MIN_VALUE, 0x080000000, -(2**53-2), 0/0, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=1053; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\\\u00f9|(?=(?!(\\\\x4A*))+?|(?!\\\\cS(?!\\\\b))+{1})+\", \"gym\"); var s = \"\\u00f9\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=1054; tryItOut("mathy0 = (function(x, y) { return Math.hypot(Math.acos(Math.fround((Math.fround(Math.round(Math.sqrt((((y <= x) >>> 0) << Math.asinh(x))))) ? Math.fround(( ~ y)) : Math.fround((Math.max(y, 0.000000000000001) >>> 0))))), (( - Math.clz32(Math.cosh(Math.asin(x)))) | 0)); }); testMathyFunction(mathy0, /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-66366547*/count=1055; tryItOut("testMathyFunction(mathy3, [0x080000001, Math.PI, -0x080000000, 0, 2**53+2, 0x0ffffffff, 0x100000001, 42, 1.7976931348623157e308, 1/0, 2**53, -(2**53+2), 2**53-2, -0x100000001, -0x080000001, 0x100000000, -(2**53-2), -0x100000000, Number.MIN_VALUE, 0.000000000000001, -0x07fffffff, -0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -1/0, 1, Number.MAX_VALUE, 0x07fffffff, 0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1056; tryItOut("\"use strict\"; {print(m0);i1 = a1.iterator; }");
/*fuzzSeed-66366547*/count=1057; tryItOut("a1.sort((function() { try { g0.offThreadCompileScript(\"this.g2.a1 = ((intern(z = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: /*wrap3*/(function(){ \\\"use strict\\\"; var klsnnm = /((?=(?=n)){3,3}(?:(?=(\\\\B)))|[^]*?|[^\\\\s\\u47cb\\\\d\\\\x93]?)\\\\1/; ((new RegExp(\\\"\\\\\\\\cR\\\", \\\"im\\\")).call)(); }), keys: function() { return []; }, }; })(function(id) { return id }), (4277)))) for each (x in ( /x/g )) for (x in ((yield y -= x))) for (x in (x = b **= x)) for each (x in String.prototype.substr));\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (delete |= y), sourceIsLazy: false, catchTermination: false })); } catch(e0) { } b0 = t1[({valueOf: function() { m0.set(m0, o0);;return 4; }})]; return o0; }), i1);");
/*fuzzSeed-66366547*/count=1058; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((+((-(i2)) >> (((((!((((0xfd64ff5d)) ^ ((0xc300133a))) == (((0xfd05ead9)) << ((0xd93a917f))))))>>>((~((0x28b3c3d2))) / (((0xf82c26c8)) ^ ((0xadf65d82))))))))));\n  }\n  return f; })(this, {ff: ((DataView.prototype.setFloat32)(/*UUV2*/(x.search = x.forEach)))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-66366547*/count=1059; tryItOut("var a = x, x;o2 = a1[12];");
/*fuzzSeed-66366547*/count=1060; tryItOut("/*infloop*/for(w in ((this.__defineGetter__(\u0009\"e\", eval))(-3330765818))){/*hhh*/function tuekvv(this, d){a0 + s0;}tuekvv( '' ); }");
/*fuzzSeed-66366547*/count=1061; tryItOut("mathy3 = (function(x, y) { return (((Math.hypot((0x07fffffff | 0), ( + (mathy1(((Math.hypot((( + Math.acosh(( + Math.acosh(-0x100000001)))) >>> 0), (( + Math.cos(( + 0/0))) >>> 0)) >>> 0) >>> 0), ((y * -Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0))) <= (mathy2(Math.fround(Math.min(y, Math.fround(( ~ Math.min(Math.fround(y), (y | 0)))))), Math.fround(Math.log((Math.asin((x | 0)) | 0)))) >>> 0)) >>> 0) , Math.cbrt(( ! Math.min(( + Math.pow(y, Math.fround((Math.fround(( + (Math.fround(x) === y))) && ( + x))))), ( + ( ~ (0x0ffffffff | 0))))))); }); ");
/*fuzzSeed-66366547*/count=1062; tryItOut("{/*MXX3*/g1.Array.prototype.length = g1.Array.prototype.length;with(((function sum_slicing(efzjht) { ; return efzjht.length == 0 ? 0 : efzjht[0] + sum_slicing(efzjht.slice(1)); })(/*MARR*/[(1/0), ['z'], new String(''), new String(''), ['z'], (void 0), (1/0), (1/0), ['z'], ['z'], new String(''), new String(''), new String(''), ['z'], new String(''), (1/0), new String(''), ['z'], ({}), new String(''), (void 0), ({}), (void 0), ({}), (1/0), (1/0), (1/0), ({}), ({}), new String(''), ({}), new String(''), ({}), (1/0), (void 0), ({}), ({})]))\u000c){e0.has(f0);v2 = evalcx(\"Array.prototype.reverse.apply(a2, [g0]);\", this.g0); } }");
/*fuzzSeed-66366547*/count=1063; tryItOut("\"use strict\"; /*vLoop*/for (opargb = 0, 14; opargb < 148; ++opargb) { var z = opargb; print( '' ); } ");
/*fuzzSeed-66366547*/count=1064; tryItOut("for (var v of e1) { try { const a2 = Array.prototype.slice.apply(a1, [3, NaN, o0.s1, b1]); } catch(e0) { } m0 = Proxy.create(h1, g1); }");
/*fuzzSeed-66366547*/count=1065; tryItOut("\"use asm\"; f1 + o1.h2;");
/*fuzzSeed-66366547*/count=1066; tryItOut("");
/*fuzzSeed-66366547*/count=1067; tryItOut("var w = (makeFinalizeObserver('nursery'));encodeURI(y = (/*UUV1*/(arguments.toString = q => q) ^ intern( /x/ )));");
/*fuzzSeed-66366547*/count=1068; tryItOut("print(x);\nArray.prototype.sort.call(this.a2, (function(j) { if (j) { try { let e0 = new Set; } catch(e0) { } try { m0.has(g0); } catch(e1) { } s2 = new String; } else { try { delete h1.defineProperty; } catch(e0) { } g1.m0.has(f1); } }), b2);\n");
/*fuzzSeed-66366547*/count=1069; tryItOut("mathy4 = (function(x, y) { return ( + ( - (Math.hypot(((Math.acos((1.7976931348623157e308 >>> Math.min(x, mathy1(-0x080000000, ( + x))))) | 0) >>> 0), (( + Math.pow(Math.sinh(x), Math.fround(x))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-66366547*/count=1070; tryItOut("this.t0.__proto__ = h1;");
/*fuzzSeed-66366547*/count=1071; tryItOut("this.a0.push(b1, o1);");
/*fuzzSeed-66366547*/count=1072; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ~ ((((Math.fround(mathy1(( + ( - ( + 0x100000000))), (mathy0(y, 1) | 0))) | 0) != (Math.hypot(x, Math.fround(Math.pow(Math.max(function(id) { return id }, x), (x < 2**53)))) | 0)) | 0) | 0)); }); testMathyFunction(mathy3, [0x080000001, 1, -0x100000000, 0/0, 42, 0x100000001, 0x100000000, Number.MIN_VALUE, 2**53+2, -0, 0x0ffffffff, -0x080000001, 0, 0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), -1/0, -0x080000000, -(2**53-2), Math.PI, 2**53, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=1073; tryItOut("\"use strict\"; var x, a = this, x, fyojul, \u3056, x;o2.g1.offThreadCompileScript(\"this\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-66366547*/count=1074; tryItOut("\"use strict\"; x = x, x = ((4277).__proto__ = (4277)), x = new RegExp(\"^\", \"gy\"), a = ((yield  '' )), x, qacdtx, fuvqzd;for (var v of g2.f2) { try { s2 += 'x'; } catch(e0) { } try { Object.defineProperty(this, \"v0\", { configurable: (x % 29 == 0), enumerable: null,  get: function() {  return r2.exec; } }); } catch(e1) { } ; }");
/*fuzzSeed-66366547*/count=1075; tryItOut("mathy4 = (function(x, y) { return Math.clz32(((Math.log(((Math.acos(( + (Math.cosh(Math.fround(x)) | 0))) >>> 0) | 0)) % ( + ((Math.fround(Math.hypot(Math.fround(x), Math.fround((((( ~ y) * ( + x)) < (Math.fround(Math.min((0x080000001 | 0), y)) >>> 0)) | 0)))) || (Math.fround(x) === Math.fround(-0))) | 0))) | 0)); }); testMathyFunction(mathy4, [-(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0/0, -Number.MIN_VALUE, -0x07fffffff, 2**53, -0x080000001, Math.PI, 2**53-2, 1.7976931348623157e308, 0x0ffffffff, 0, 0x100000000, -Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, -(2**53+2), -0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 1/0, 1, 2**53+2, 42, -(2**53), -1/0, -0x100000000, 0x080000001, 0x100000001, 0x080000000]); ");
/*fuzzSeed-66366547*/count=1076; tryItOut("\"use strict\"; for(var a in ((decodeURI)(Math.hypot(16, \"\\u24B2\")))){v2 = evaluate(\"yield \\\"\\\\uD6E2\\\";\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 63 == 15), noScriptRval: true, sourceIsLazy:  /x/g , catchTermination: false }));v0 = Array.prototype.reduce, reduceRight.call(o0.a0, (function() { try { e0.has(f1); } catch(e0) { } try { Object.defineProperty(this, \"t0\", { configurable: false, enumerable: true,  get: function() {  return new Int8Array(v2); } }); } catch(e1) { } try { i2.next(); } catch(e2) { } m1.set(s0, a0); return p1; }), b1); }");
/*fuzzSeed-66366547*/count=1077; tryItOut("print(new RegExp(\"(?!(?:(?!\\\\W))[^]{3,6})|\\u0083*?(?:(?=[^\\\\u4549-\\\\u007E]))\", \"im\"));\nvar v2 = new Number(4.2);\n");
/*fuzzSeed-66366547*/count=1078; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(Math.acos(Math.atanh(( ! Math.min((Math.hypot(y, (Math.pow(y, (Math.atan2(-0x0ffffffff, (y >>> 0)) >>> 0)) >>> 0)) >>> 0), x))))); }); testMathyFunction(mathy1, [0/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -0, -0x080000001, 0.000000000000001, 0x080000001, 2**53, -0x100000001, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, -0x100000000, 0x080000000, -0x07fffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 1, -(2**53), 0x100000000, -(2**53+2), 0x0ffffffff, -1/0, Number.MAX_VALUE, -0x080000000, 1/0, -Number.MAX_VALUE, 2**53+2, 2**53-2, 42]); ");
/*fuzzSeed-66366547*/count=1079; tryItOut("(false.watch(false, arguments.callee.caller));");
/*fuzzSeed-66366547*/count=1080; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g1, b2);");
/*fuzzSeed-66366547*/count=1081; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-66366547*/count=1082; tryItOut("/*RXUB*/var r = (((({})(z)))()); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=1083; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Math.PI, -0, 1.7976931348623157e308, 2**53+2, 2**53, -Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, -(2**53), 2**53-2, Number.MIN_VALUE, 0x080000000, -1/0, -0x100000000, 0x080000001, -0x07fffffff, 0x07fffffff, -(2**53+2), 0x100000000, -0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, -0x100000001, -(2**53-2), Number.MAX_VALUE, 0x0ffffffff, 42, 1, 0x100000001, 0/0]); ");
/*fuzzSeed-66366547*/count=1084; tryItOut("\"use strict\"; a1.valueOf = (function mcc_() { var fmodkf = 0; return function() { ++fmodkf; o0.o0.f0(/*ICCD*/fmodkf % 9 == 7);};})();");
/*fuzzSeed-66366547*/count=1085; tryItOut("\"use strict\"; const a = x, x\u0009;print(x);e2.has(v2);");
/*fuzzSeed-66366547*/count=1086; tryItOut("v2 = this.a2.some((function() { for (var j=0;j<64;++j) { o0.f2(j%2==0); } }));");
/*fuzzSeed-66366547*/count=1087; tryItOut("\"use strict\"; return x;for(let e of /*PTHR*/(function() { \"use asm\"; for (var i of (--d for each (x in ((4277) if ( /x/ ))) for each (\u3056 in []) for each (e in []) for each (w in \"\\uB928\"))) { yield i; } })()) let(rbfafz, e( \"\" ), e = e) { let(maszid, gsistt, furabx, kxdifo, jykodd) { let(x = \"\\u9822\", x, \u3056) { WeakMap}}}");
/*fuzzSeed-66366547*/count=1088; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return (Math.fround(Math.log(Math.hypot(( + (( + (( ! x) | 0)) | 0)), ( + ( - (Math.exp(Math.fround(((x === x) << ( + y)))) >>> 0)))))) & Math.fround(Math.atan2((( + Math.sinh(( + (Math.imul((x | 0), (Math.atan2(y, y) >>> 0)) | 0)))) | 0), (Math.hypot(Math.fround(Math.acosh(Math.fround(Math.hypot((Math.fround(( + (y >>> 0))) | 0), (x | 0))))), ( - x)) | 0)))); }); testMathyFunction(mathy0, [1/0, 2**53+2, -(2**53-2), -0x080000001, -Number.MIN_VALUE, 0x100000000, -0x100000000, -0x080000000, 42, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), 0x0ffffffff, -0, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0x080000001, 0x07fffffff, -1/0, Math.PI, 2**53, 0x100000001, -0x100000001, 0, -Number.MAX_VALUE, 2**53-2, 0/0, 1]); ");
/*fuzzSeed-66366547*/count=1089; tryItOut("arguments.callee.caller.caller.caller.caller");
/*fuzzSeed-66366547*/count=1090; tryItOut("mathy0 = (function(x, y) { return (Math.imul(Math.pow((Math.exp((-6 ?  /x/g  :  /x/  | 0)) | 0), (0x080000001 ? Math.sign((( - y) | 0)) : x)), (( + ((-(2**53-2) >>> y) >>> 0)) >>> 0)) ? ((Math.imul(Math.sin(x), Math.log1p((-Number.MAX_SAFE_INTEGER | 0))) ? x : (Math.sqrt((x !== Math.atan2((((y >>> 0) ? y : (y >>> 0)) >>> 0), Math.fround(y)))) | 0)) < (Math.log10(Math.pow(y, Number.MAX_VALUE)) || ( - (y ? (Math.exp((x | 0)) >>> 0) : -(2**53))))) : Math.fround(Math.pow(Math.fround(((( + ( - -(2**53))) % (x | 0)) | 0)), Math.fround(( + Math.sin(( + ((( ! ( + 42)) >>> 0) - (y >> y))))))))); }); testMathyFunction(mathy0, [/0/, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), '', (new Number(-0)), -0, (new Boolean(true)), (new String('')), ({valueOf:function(){return '0';}}), '/0/', (new Boolean(false)), 1, null, [0], '0', 0.1, (function(){return 0;}), (new Number(0)), 0, NaN, true, undefined, '\\0', ({toString:function(){return '0';}}), false, []]); ");
/*fuzzSeed-66366547*/count=1091; tryItOut("(new  /x/g );");
/*fuzzSeed-66366547*/count=1092; tryItOut("s0 += s0;");
/*fuzzSeed-66366547*/count=1093; tryItOut("let delete = x, x = c+= /x/g , x = x, z, txkmkv, x, x, uzzpem, uujoqi, x;let this.g0.a0 = arguments.callee.caller.caller.caller.caller.arguments;");
/*fuzzSeed-66366547*/count=1094; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.max(( + ( ~ (Math.imul(( + mathy4(x, ((Math.expm1((x >>> 0)) >>> 0) | 0))), (( - ( + ( + Math.sinh(Math.fround(x))))) >>> 0)) >= y))), (Math.atan2(( ~ ( - Math.fround((( - ((Math.ceil((-0 >>> 0)) >>> 0) | 0)) | 0)))), ( + mathy3(( + Math.fround(( - ( + Math.round(( + (( + mathy1(( + y), ( + x))) << y))))))), ( + Math.fround(Math.min(( + (Math.fround(y) - x)), (((y >>> 0) < ( - (x , 0.000000000000001))) >>> 0))))))) | 0)); }); testMathyFunction(mathy5, [0x080000000, 0.000000000000001, -Number.MAX_VALUE, -1/0, -(2**53), 0/0, 0x100000000, Number.MIN_VALUE, 0, -0x0ffffffff, -(2**53-2), 1.7976931348623157e308, -0x100000001, -0x080000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, -0x080000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, -Number.MIN_VALUE, 42, 1, -0x07fffffff, 0x080000001, 1/0, -0x100000000, 0x07fffffff, Math.PI, 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=1095; tryItOut("/*MXX1*/o0 = g0.Date.prototype.getDate;");
/*fuzzSeed-66366547*/count=1096; tryItOut("(void schedulegc(o2.o1.o1.g1));");
/*fuzzSeed-66366547*/count=1097; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = 590295810358705700000.0;\n;    d0 = (d0);\n    {\n      d0 = (-4.835703278458517e+24);\n    }\n    return (((!(-0x8000000))-(-0x8000000)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); ");
/*fuzzSeed-66366547*/count=1098; tryItOut("\"use strict\"; a0.sort();");
/*fuzzSeed-66366547*/count=1099; tryItOut("Object.defineProperty(this, \"v0\", { configurable: /*RXUE*/new RegExp(\"(?:\\\\D)*?[^]|.\", \"gyi\").exec(\"\\n\"), enumerable: (x % 17 != 1),  get: function() {  return evaluate(\"m0.set(p1,  '' );\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: x.getDay(/*RXUE*/new RegExp(\"(?!\\\\s*?|[^]?.)(?=[^]*?){8589934592,8589934596}\", \"gm\").exec(\"\\u53aa\\u53aa\\u53aa\\u53aa\\u53aa\\u53aa\\u53aa\\u53aa\\u53aa\\u53aa\"), x), sourceIsLazy: (x % 14 == 3), catchTermination: true, element: g0.g0.o0, sourceMapURL: s1 })); } });\nm2.get(b0);\n");
/*fuzzSeed-66366547*/count=1100; tryItOut("-10;");
/*fuzzSeed-66366547*/count=1101; tryItOut("mathy4 = (function(x, y) { return ( - ( + ( + Math.atan(( + (( + y) ? Math.sqrt(Math.sign(Math.imul(Math.fround(x), x))) : ( + y))))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, 42, 2**53+2, 0x080000000, 0/0, 0x100000000, -0x100000000, -0x07fffffff, -0, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, Number.MIN_VALUE, -0x100000001, 0, 1, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, 0x0ffffffff, 0x07fffffff, Math.PI, -0x080000001, -1/0, -Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, 1/0, -0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=1102; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=1103; tryItOut("print(t2);const w =  /x/ ;");
/*fuzzSeed-66366547*/count=1104; tryItOut("\"use strict\"; /*infloop*/for(w = (c = x);  '' ; (4277)) var ncixrn = new ArrayBuffer(8); var ncixrn_0 = new Uint32Array(ncixrn); M:if((x % 115 == 94)) e2.delete((function ([y]) { })()); else for (var p in e1) { try { v0 = evalcx(\"t0 = new Uint8ClampedArray(t2);\", g0.g0); } catch(e0) { } for (var v of s1) { Object.defineProperty(this, \"this.i1\", { configurable: false, enumerable: \"\\u0396\",  get: function() {  return new Iterator(v2); } }); } }");
/*fuzzSeed-66366547*/count=1105; tryItOut("mathy2 = (function(x, y) { return ((Math.sinh(Math.fround(( + Math.max(x, y)))) > ( - (Math.hypot(Math.fround(( + Math.atanh(( + (((42 | 0) ** Math.fround((Math.exp(((1 ? -Number.MAX_VALUE : (y | 0)) >>> 0)) >>> 0))) | 0))))), Math.fround(x)) | 0))) | 0); }); testMathyFunction(mathy2, [-1/0, 1.7976931348623157e308, 0x0ffffffff, -(2**53-2), 0x100000000, -0x080000001, 0/0, -0, Number.MIN_VALUE, 0, -Number.MAX_VALUE, -0x100000001, 0x080000000, 0x080000001, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, Number.MAX_VALUE, 0x100000001, 2**53+2, -0x0ffffffff, -0x080000000, 1, -(2**53), -0x100000000, 42, -(2**53+2), 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1106; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u2596\\n\\n\\ud269\\n\\u2596\\u2596\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u2596\\n\\n\\ud269\\n\\u2596\\u2596\"; print(s.search(r)); a0[6] = t1;");
/*fuzzSeed-66366547*/count=1107; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.abs(( + Math.log10(Math.fround((((( + ((((-Number.MAX_SAFE_INTEGER ? ((( + x) >>> 0) | 0) : (y | 0)) | 0) && x) - (0x100000000 >>> 0))) | 0) / Math.tan(( ~ x))) | 0)))))); }); testMathyFunction(mathy3, [0, 2**53+2, -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000000, -0x080000000, Math.PI, 0x100000001, 0x0ffffffff, 42, 0x07fffffff, -(2**53-2), -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, -(2**53+2), 0x100000000, 1, 2**53, -0x100000001, 0.000000000000001, -0, -0x080000001, 2**53-2, 0/0, 1/0, -1/0, 1.7976931348623157e308, -0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=1108; tryItOut("\"use strict\"; v0 = Array.prototype.reduce, reduceRight.apply(a2, [/*wrap3*/(function(){ var vpudsv = x > z + null |= (4277); (vpudsv)(); }), b0]);");
/*fuzzSeed-66366547*/count=1109; tryItOut("mathy2 = (function(x, y) { return Math.ceil(Math.atan2((y ? (Math.fround(x) , Math.fround((mathy1(x, (y | 0)) | 0))) : (x && (Math.max(x, y) >>> 0))), (((Math.imul(y, x) >>> 0) >= (1/0 | 0)) / ((y ? Math.hypot(y, (Math.atanh(-Number.MIN_SAFE_INTEGER) | 0)) : x) >>> 0)))); }); ");
/*fuzzSeed-66366547*/count=1110; tryItOut("Array.prototype.push.call(a0, + \"\"  < x);");
/*fuzzSeed-66366547*/count=1111; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-66366547*/count=1112; tryItOut("s1 = new String(o0);");
/*fuzzSeed-66366547*/count=1113; tryItOut("\"use strict\"; o2.g2.e1.add(a1);");
/*fuzzSeed-66366547*/count=1114; tryItOut("t2.set(this.t2, v0);");
/*fuzzSeed-66366547*/count=1115; tryItOut("{e1 + t0;v1 = g0.runOffThreadScript();\u3056 = linkedList(\u3056, 6566); }");
/*fuzzSeed-66366547*/count=1116; tryItOut("\"use strict\"; h0 + '';");
/*fuzzSeed-66366547*/count=1117; tryItOut("mathy5 = (function(x, y) { return (Math.fround(((Math.cosh(( - Math.imul(x, x))) >>> 0) ^ ((( + ( + ( ! ( + ((y | 0) - x))))) >>> ((( ! y) | 0) >>> 0)) >>> 0))) < ( + Math.atan2(Math.atan2((((x >>> 0) >= (y >>> 0)) >>> 0), ( + ( ~ x))), (mathy3(x, x) - (42 >>> 0))))); }); testMathyFunction(mathy5, /*MARR*/[true, objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), true, {}, true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), true, {}, true, {}, {}, {}, {}, {}, objectEmulatingUndefined(), true, {}, objectEmulatingUndefined(), true, {}, {}, {}, {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, true, true, true, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), {}, objectEmulatingUndefined(), objectEmulatingUndefined(), true, {}, true, objectEmulatingUndefined(), true, {}, true, objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), true, {}, {}, objectEmulatingUndefined(), true, {}, true, {}, objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), true, true, true, true, true, true, objectEmulatingUndefined()]); ");
/*fuzzSeed-66366547*/count=1118; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=1119; tryItOut("const NaN, x, x & x = x, pnylsz;a1.forEach((function mcc_() { var lmygpa = 0; return function() { ++lmygpa; f1(/*ICCD*/lmygpa % 3 == 0);};})(), (void version(180)));");
/*fuzzSeed-66366547*/count=1120; tryItOut("testMathyFunction(mathy3, [-(2**53-2), 0x100000001, Number.MAX_SAFE_INTEGER, 0, 2**53-2, 0x07fffffff, Math.PI, 0x080000000, Number.MAX_VALUE, 0x100000000, -1/0, Number.MIN_VALUE, -0x0ffffffff, 2**53+2, 0/0, -0x100000001, -0x07fffffff, 0x080000001, -(2**53+2), 2**53, 1/0, 1, 0x0ffffffff, -Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -0x080000000, -Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=1121; tryItOut("\"use strict\"; this.o2.a0.reverse(i1);");
/*fuzzSeed-66366547*/count=1122; tryItOut("\"use asm\"; a2.pop(b0, g1.m1);");
/*fuzzSeed-66366547*/count=1123; tryItOut("this.g0.a1.length = 6;");
/*fuzzSeed-66366547*/count=1124; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=1125; tryItOut("\"use strict\"; e0.has(o2.o1);");
/*fuzzSeed-66366547*/count=1126; tryItOut("\"use strict\"; \"use asm\"; this.t0.set(a2, 8);/./gym;\nprint(x);\n");
/*fuzzSeed-66366547*/count=1127; tryItOut("\"use asm\"; var xbflaw = new ArrayBuffer(16); var xbflaw_0 = new Float64Array(xbflaw); var xbflaw_1 = new Uint8Array(xbflaw); xbflaw_1[0] = 5; var xbflaw_2 = new Uint16Array(xbflaw); xbflaw_2[0] = 3; var xbflaw_3 = new Int8Array(xbflaw); xbflaw_3[0] = 15; var xbflaw_4 = new Uint8ClampedArray(xbflaw); var xbflaw_5 = new Int16Array(xbflaw); var xbflaw_6 = new Int8Array(xbflaw); var xbflaw_7 = new Uint8Array(xbflaw); var xbflaw_8 = new Int16Array(xbflaw); xbflaw_8[0] = -29; var xbflaw_9 = new Int16Array(xbflaw); xbflaw_9[0] = -26; var xbflaw_10 = new Int32Array(xbflaw); xbflaw_10[0] = 2147483648; var xbflaw_11 = new Uint16Array(xbflaw); print(xbflaw_3);print(null);delete h1[\"prototype\"];print(xbflaw_6[0]);print(((a) = \"\\uF981\"));Array.prototype.sort.apply(a1, [(function(a0, a1, a2, a3, a4) { print(xbflaw_3[0]); var r0 = xbflaw_11[0] ^ 8; r0 = xbflaw_6[0] * a4; var r1 = 1 - xbflaw_9[0]; print(a2); var r2 = xbflaw_6 | xbflaw_9[4]; var r3 = xbflaw_9 + xbflaw_8[4]; var r4 = xbflaw_2 + 9; var r5 = xbflaw_6[0] % xbflaw_4[2]; print(xbflaw_5); var r6 = xbflaw_3[9] / 7; var r7 = a3 | xbflaw_0; var r8 = 5 * xbflaw_8[0]; var r9 = 9 - 9; var r10 = xbflaw_9[4] & xbflaw_8[0]; xbflaw_5[0] = 4 | xbflaw_2[0]; var r11 = r6 * 9; var r12 = xbflaw_2[4] / xbflaw_10[10]; var r13 = xbflaw_6[0] / 0; var r14 = r12 ^ a0; var r15 = 2 ^ 8; xbflaw_2[0] = 8 * r6; a1 = 4 ^ 9; var r16 = 0 / r5; var r17 = a1 ^ r16; var r18 = xbflaw_0 | xbflaw_11; var r19 = r3 - xbflaw_7; r15 = xbflaw_6 % 6; var r20 = xbflaw_1[0] | xbflaw_6[0]; var r21 = r5 ^ xbflaw_7; var r22 = xbflaw_3 + a2; var r23 = r5 + r13; var r24 = 9 - xbflaw_8; var r25 = xbflaw_8[0] | 1; return xbflaw_1[0]; }), g2.o2]);;v0 = a1.length;y%=\"\\u4490\";print((this.__defineSetter__(\"NaN\", q => q)));");
/*fuzzSeed-66366547*/count=1128; tryItOut("\"use asm\"; function shapeyConstructor(lqxnnv){if (new (objectEmulatingUndefined)(true, new RegExp(12, false))) lqxnnv[\"-5\"] =  /x/g ;lqxnnv[\"toLocaleString\"] = runOffThreadScript;return lqxnnv; }/*tLoopC*/for (let d of /*MARR*/[true, length, length, true, length, function(){}, length]) { try{let mmbrej = shapeyConstructor(d); print('EETT'); v2 = this.r0.sticky;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-66366547*/count=1129; tryItOut("e0 + '';\nx;\n");
/*fuzzSeed-66366547*/count=1130; tryItOut("\"use strict\"; print(uneval(m2));");
/*fuzzSeed-66366547*/count=1131; tryItOut("mathy1 = (function(x, y) { return ( ~ ((( + ( ! Math.fround(mathy0(Math.fround(( ! Math.fround(x))), (Math.fround(( ~ Math.fround(-Number.MAX_SAFE_INTEGER))) | 0))))) | 0) >>> Math.max(Math.log10(x), Math.asin(( + Math.tanh(( + x))))))); }); testMathyFunction(mathy1, [-0x100000001, 0/0, 1, -1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, 0x080000000, 0x080000001, -0, 0x0ffffffff, 1.7976931348623157e308, Math.PI, -0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 42, -0x080000001, Number.MAX_VALUE, -0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53), 0x100000000, -Number.MIN_VALUE, Number.MIN_VALUE, 0x07fffffff, 2**53, -Number.MAX_VALUE, -(2**53-2), 0.000000000000001, 0x100000001]); ");
/*fuzzSeed-66366547*/count=1132; tryItOut("s1 += 'x';");
/*fuzzSeed-66366547*/count=1133; tryItOut("mathy2 = (function(x, y) { return ((mathy1(( + y), ( + ( ~ Math.sqrt(( + x))))) >>> 0) ? (Math.asinh(( + ((Math.min((Math.log((mathy1(Math.max(x, 1.7976931348623157e308), 0/0) >>> 0)) >>> 0), ( + ( + ( + x)))) >>> 0) << (( + Math.expm1(Math.fround(Math.imul((y >>> 0), Math.fround(y))))) >>> 0)))) >>> 0) : (mathy1((( ~ (x + ( + -0x07fffffff))) | 0), ( + Math.log(-1/0))) | 0)); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, 0, -(2**53+2), 1, 0x080000000, -Number.MAX_VALUE, Number.MAX_VALUE, 42, 2**53-2, -0x080000000, 0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, 0x080000001, 0x100000000, -0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, -(2**53-2), 0x07fffffff, -0x0ffffffff, -0x100000001, -0x100000000, 2**53, 2**53+2, 0.000000000000001, 1.7976931348623157e308, -0x07fffffff, -(2**53), 0/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1134; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(a0, 0, ({set: decodeURI, configurable: (x % 6 == 2)}));");
/*fuzzSeed-66366547*/count=1135; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + Math.max(( + (((Math.atan2(( + Math.fround(y)), y) >>> 0) <= (Math.acos(x) >>> 0)) >>> 0)), ( + Math.fround(Math.pow(Math.fround(mathy2(((Math.sign((1/0 | 0)) | 0) | 0), ( + x))), Math.fround(x)))))) & ( + ( + ( - (x >>> 0))))); }); testMathyFunction(mathy3, [0x100000000, -(2**53+2), -0x100000001, -0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, 0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 0x080000001, 0x100000001, -0x100000000, -1/0, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, 1, Math.PI, 0, -(2**53), 1/0, -0x0ffffffff, -Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, Number.MAX_VALUE, -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, 1.7976931348623157e308, 2**53-2, 42]); ");
/*fuzzSeed-66366547*/count=1136; tryItOut("/*vLoop*/for (var hpjzzl = 0; hpjzzl < 21; ++hpjzzl) { const y = hpjzzl; e0.valueOf = f0; } ");
/*fuzzSeed-66366547*/count=1137; tryItOut("mathy1 = (function(x, y) { return ( + ( + (Math.sign((Math.max(Math.fround(0x07fffffff), y) | 0)) | 0))); }); testMathyFunction(mathy1, [[], -0, (new Number(-0)), 0, 1, ({valueOf:function(){return 0;}}), true, undefined, '/0/', false, '', (function(){return 0;}), 0.1, null, (new Number(0)), ({valueOf:function(){return '0';}}), (new Boolean(false)), '\\0', ({toString:function(){return '0';}}), NaN, (new String('')), /0/, objectEmulatingUndefined(), (new Boolean(true)), '0', [0]]); ");
/*fuzzSeed-66366547*/count=1138; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]|(?=\\\\D)|[^]|(\\u00e0\\uf82c{0,3}){1,}{3}{0,}\", \"i\"); var s = (void options('strict_mode')); print(s.split(r)); ");
/*fuzzSeed-66366547*/count=1139; tryItOut("v2 = Object.prototype.isPrototypeOf.call(b0, i1)");
/*fuzzSeed-66366547*/count=1140; tryItOut("\"use strict\"; g0.s1 += 'x';");
/*fuzzSeed-66366547*/count=1141; tryItOut("mathy4 = (function(x, y) { return ((((( ! (Math.hypot(Math.fround((( + (( + x) | 0)) & ((( - -Number.MAX_SAFE_INTEGER) >>> 0) >>> 0))), x) | 0)) + Math.atan(Math.fround((Math.hypot((((mathy2((( - y) >>> 0), ((mathy0(y, (x | 0)) | 0) >>> 0)) >>> 0) - y) | 0), ((( + y) * ((x && x) | 0)) | 0)) | 0)))) >>> 0) & ((x | x) != ( ! ( - Math.min(( ~ 2**53+2), (Math.imul(0x080000001, -0x100000001) >>> 0)))))) | 0); }); ");
/*fuzzSeed-66366547*/count=1142; tryItOut("switch( \"\" ) { default: break; case 2: case 0: break;  }");
/*fuzzSeed-66366547*/count=1143; tryItOut("var yugczh = new ArrayBuffer(3); var yugczh_0 = new Uint32Array(yugczh); print(yugczh_0[0]); t0[\"17\"] = this;v0 = (g2 instanceof t1);");
/*fuzzSeed-66366547*/count=1144; tryItOut("Array.prototype.reverse.apply(this.a1, []);");
/*fuzzSeed-66366547*/count=1145; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + Math.cbrt((Math.min(Math.min(Math.fround((Math.sqrt((( ~ (y | 0)) | 0)) | 0)), Math.fround(x)), (Math.fround(( + x)) , Math.sign(x))) >>> 0))) < ( + ( - ( - (Math.fround(Math.hypot(Math.fround((Math.min(x, (x | 0)) | 0)), Math.fround(-0))) >>> 0)))))); }); ");
/*fuzzSeed-66366547*/count=1146; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return ((((allocationMarker()).call(x, /(?!(?=(.*?)?)|[^\\v-\\u00dc])/im, (new x())))+(0xfcf0e946)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), null, (function(){return 0;}), (new Boolean(false)), ({toString:function(){return '0';}}), false, (new Number(0)), -0, [0], ({valueOf:function(){return 0;}}), NaN, 1, (new Boolean(true)), undefined, '0', [], true, '\\0', (new Number(-0)), 0, (new String('')), '', '/0/', 0.1, /0/]); ");
/*fuzzSeed-66366547*/count=1147; tryItOut("\"use strict\"; print(g0);");
/*fuzzSeed-66366547*/count=1148; tryItOut("for (var v of o1.a2) { try { Array.prototype.shift.apply(o2.a0, []); } catch(e0) { } try { Object.preventExtensions(h2); } catch(e1) { } try { h2.getPropertyDescriptor = (function(j) { if (j) { v0 = Object.prototype.isPrototypeOf.call(h1, g2); } else { s2 += 'x'; } }); } catch(e2) { } v1 = evalcx(\"/* no regression tests found */\", o1.g2.g0); }true;");
/*fuzzSeed-66366547*/count=1149; tryItOut("o1.i0.__proto__ = e0;");
/*fuzzSeed-66366547*/count=1150; tryItOut("\"use strict\"; Object.defineProperty(o1, \"f0\", { configurable: false, enumerable: (x % 3 != 0),  get: function() {  return Proxy.createFunction(h0, o1.f2, f1); } });");
/*fuzzSeed-66366547*/count=1151; tryItOut("\"use strict\"; \"use asm\"; v2 = a0.length;");
/*fuzzSeed-66366547*/count=1152; tryItOut("mathy5 = (function(x, y) { return Math.hypot((( + ( ~ ( + mathy3(( + ( + Math.cosh(Number.MIN_SAFE_INTEGER))), ( + (( - (y | 0)) | 0)))))) >>> 0), ((( - (Math.max((Math.ceil(((Math.fround(y) ** y) | 0)) | 0), (2**53-2 | 0)) | 0)) && ((( + Math.sqrt(( + (Math.imul(y, 0x0ffffffff) , Math.sinh(( + ( ! ( + y)))))))) != ( + ( + x))) >>> 0)) | 0)); }); testMathyFunction(mathy5, [2**53, -0x080000000, 42, Number.MIN_VALUE, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, 2**53-2, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, Number.MAX_VALUE, -(2**53-2), -1/0, 0x100000000, 0x0ffffffff, -0x100000000, 0x100000001, 1/0, -(2**53+2), 0.000000000000001, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -(2**53), -Number.MAX_VALUE, 0x07fffffff, Math.PI, 0x080000001, -0x080000001, 0, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=1153; tryItOut("a2.sort();");
/*fuzzSeed-66366547*/count=1154; tryItOut("t0[3] = this.i0;");
/*fuzzSeed-66366547*/count=1155; tryItOut("\"use strict\"; g1.a0.reverse();");
/*fuzzSeed-66366547*/count=1156; tryItOut("o0.t0[9] = (false in (new RangeError().watch(\"arguments\", (function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return false; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: String.prototype.slice, hasOwn: undefined, get: function(receiver, name) { return x[name]; }, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: objectEmulatingUndefined, keys: function() { return Object.keys(x); }, }; }))));");
/*fuzzSeed-66366547*/count=1157; tryItOut("g1.o2.s2 += 'x';");
/*fuzzSeed-66366547*/count=1158; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, 2**53, 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), 0, -(2**53-2), -0x07fffffff, -(2**53+2), 42, -0, 1, 0.000000000000001, 1/0, -Number.MIN_VALUE, 0x080000000, -1/0, -0x080000001, 0x07fffffff, Math.PI, -0x100000000, -0x080000000, 0x100000001, -0x0ffffffff, 0x100000000, 2**53-2, -0x100000001]); ");
/*fuzzSeed-66366547*/count=1159; tryItOut("\"use strict\"; v1 = g0.eval(\"mathy5 = (function(x, y) { \\\"use strict\\\"; return (((Math.fround(Math.exp(Math.fround(Math.atan(((Math.fround(x) == Math.fround(x)) | 0))))) | 0) + ((Math.min(( + (0x080000001 * ((-0x0ffffffff !== Math.fround(Math.abs((y | 0)))) >>> 0))), (Math.pow(( ~ ( + Math.atan2(y, ((x + x) | 0)))), x) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy5, [0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 0.000000000000001, 0x080000000, 0x0ffffffff, 1.7976931348623157e308, 42, -0x100000000, -0x080000000, -0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, 0/0, -(2**53+2), -Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -0, 0, 1/0, Number.MIN_VALUE, 0x100000001, 0x100000000, 2**53+2, 1, Number.MIN_SAFE_INTEGER, Math.PI, -1/0, -(2**53), 2**53-2]); \");");
/*fuzzSeed-66366547*/count=1160; tryItOut("a2.length = 5;");
/*fuzzSeed-66366547*/count=1161; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.atan(case  /x/g : ); }); testMathyFunction(mathy3, [({valueOf:function(){return 0;}}), (new Number(-0)), 0, '\\0', null, NaN, undefined, false, '0', objectEmulatingUndefined(), 1, (new Number(0)), (function(){return 0;}), 0.1, '', [0], [], ({toString:function(){return '0';}}), (new Boolean(true)), -0, (new Boolean(false)), /0/, (new String('')), '/0/', ({valueOf:function(){return '0';}}), true]); ");
/*fuzzSeed-66366547*/count=1162; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return ( - (Math.cos((Math.pow((x >>> 0), ( + ( + ( - (y >>> 0))))) | 0)) && (( + ( + Math.fround(Math.min(( + Math.log(Number.MIN_VALUE)), Math.fround(y))))) | 0))); }); testMathyFunction(mathy4, [1, -(2**53+2), Math.PI, -Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, 2**53, -0x100000001, 2**53-2, 2**53+2, Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, -1/0, -(2**53), 0, 0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, -0x080000000, -0x0ffffffff, 0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, 0x080000001, -0x080000001, -0x100000000, 0x080000000, 1.7976931348623157e308, -(2**53-2), 0.000000000000001]); ");
/*fuzzSeed-66366547*/count=1163; tryItOut("\"use asm\"; t1 = new Uint16Array(g0.b1, 0, 6);");
/*fuzzSeed-66366547*/count=1164; tryItOut("v2 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-66366547*/count=1165; tryItOut("\"use strict\"; o1.g2 = g0.objectEmulatingUndefined();");
/*fuzzSeed-66366547*/count=1166; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=1167; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.pow((( + Math.fround(Math.imul(( + Math.sin(x)), ( + ( + Math.cbrt(( + Math.sqrt((Math.sign(x) || ((Math.pow(x, Math.fround(y)) | 0) >>> 0)))))))))) >= (( + Math.acos(Math.log(y))) <= Math.fround(( - Math.fround((y || (x >>> 0))))))), Math.fround(Math.atan2(Math.fround(Math.fround(((Math.pow(y, x) >>> 0) == (( + ( ~ (y | 0))) ^ ( + ( + Math.sin(( + Math.imul(x, 1))))))))), Math.fround((((( + Math.sign(y)) | 0) != (((( + x) >= ( + (( ~ 42) >>> 0))) | 0) | 0)) | 0))))); }); ");
/*fuzzSeed-66366547*/count=1168; tryItOut("\"use strict\"; b1.toString = (function() { for (var j=0;j<9;++j) { g1.f2(j%4==0); } });");
/*fuzzSeed-66366547*/count=1169; tryItOut("m1.toString = f1;function x(eval = new RegExp(\"\\\\2+?\\\\3\", \"g\") & 8)\"use asm\";   var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((-(-0x8000000)))|0;\n    d0 = (+(0.0/0.0));\n    (Uint16ArrayView[(0xff319*(0xfec96f89)) >> 1]) = ((!(0x33c85931)));\n    return (((-0x40b2571)+((!((0xb9124f76) < (((0x121b83c0) / (0x86955d03))>>>((0xff3f7ca0)-(0x4720eaaf))))) ? (0x60f9b276) : (0xd1ffe2b4))))|0;\n  }\n  return f;(d);function x() { \"use strict\"; yield new offThreadCompileScript() } x;");
/*fuzzSeed-66366547*/count=1170; tryItOut("\"use strict\"; let (NaN, ycxret, c = ({a1:1}), x = (d = \"\\u0462\"), a, vquyvn, d = Int8Array(new RegExp(\"(?=(\\ub44f)|[\\\\B\\\\d]*?|^|\\\\uE99d\\\\W|[^\\\\x2f-\\u00d6\\\\D\\u00e1\\u00ad-\\\\u152F]|[^]*?+?\\\\S)\", \"gy\"), null)) { Array.prototype.forEach.call(a1, (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 4194305.0;\n    var i4 = 0;\n    i2 = ((0x2fb10ee4) >= (0x89a40379));\n    i4 = ((0x0));\n    return ((((((!(0x6eed71f9))-(-0x1011586)-(i2))>>>(((((-0x555f25f))>>>((0xfe130a55))))*-0xa19bc)) > (((!((+/*FFI*/ff(((7.737125245533627e+25)), ((-7.555786372591432e+22)), ((65537.0)), ((-8388609.0)), ((-1048577.0)), ((1125899906842624.0)), ((1125899906842625.0)), ((8589934593.0)), ((65.0)))) <= (d3))))>>>((!((0x9aeb8661) < (0x560be96a))))))+(0x4746557d)+(0xb295f1e8)))|0;\n  }\n  return f; })(this, {ff: String.prototype.italics}, new SharedArrayBuffer(4096))); }");
/*fuzzSeed-66366547*/count=1171; tryItOut("let ({window: {/*MARR*/[]: x, x: w}} = delete y.\u3056 == x, [] = (Math.imul(11, /(.?)/i).unwatch(12)), b, x = Math.min(20, 860901743.5), c, uozspl, e, gttcps, xgwuep, txtgji) { v2 = Object.prototype.isPrototypeOf.call(o1, this.o2.v0); }");
/*fuzzSeed-66366547*/count=1172; tryItOut("/*RXUB*/var r = r0; var s = this.g2.s0; print(uneval(s.match(r))); ");
/*fuzzSeed-66366547*/count=1173; tryItOut("print(x);");
/*fuzzSeed-66366547*/count=1174; tryItOut("\"use strict\"; this.v2 = evalcx(\"/*FARR*/[]\", this.g2);");
/*fuzzSeed-66366547*/count=1175; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (Math.tanh(((Math.min((( + (( + ( ~ Math.atan2(( + Math.pow(-0x100000001, ( + x))), Math.cos(x)))) != ( + x))) | 0), (((x > y) && Math.atan2((Number.MIN_VALUE >>> 0), (y >>> 0))) | 0)) | 0) | 0)) | 0); }); ");
/*fuzzSeed-66366547*/count=1176; tryItOut("/*MXX2*/g2.SharedArrayBuffer.name = o0.m1;");
/*fuzzSeed-66366547*/count=1177; tryItOut("/*RXUB*/var r = new RegExp(\"$\", \"gy\"); var s = \"\\u9aa7\"; print(r.exec(s)); ");
/*fuzzSeed-66366547*/count=1178; tryItOut("testMathyFunction(mathy3, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, 0/0, Number.MIN_VALUE, 0x100000001, -0x07fffffff, 1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, 2**53+2, -(2**53), -0x080000000, 0x080000000, 2**53-2, -0x100000000, 1.7976931348623157e308, 0x0ffffffff, 1, -0x0ffffffff, 0.000000000000001, -0x080000001, -Number.MIN_VALUE, -1/0, 2**53, -(2**53+2), -0x100000001, -0, 0x080000001, 0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-66366547*/count=1179; tryItOut("e2.__proto__ = a2;");
/*fuzzSeed-66366547*/count=1180; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.atanh((Math.max(((( + x) < ( - x)) | 0), (Math.min((( + y) <= Math.max(x, Math.PI)), (Math.asin(( ~ 0x100000001)) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [0.000000000000001, -0x07fffffff, -(2**53-2), 1/0, 0x07fffffff, 0x0ffffffff, 2**53, 0x080000000, 2**53+2, 2**53-2, -1/0, -Number.MAX_VALUE, 0x100000000, Math.PI, Number.MIN_VALUE, 0/0, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, -0x100000000, -(2**53+2), 1.7976931348623157e308, -0, Number.MAX_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, 1, 0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53), 0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-66366547*/count=1181; tryItOut("a0 = r0.exec(s2);");
/*fuzzSeed-66366547*/count=1182; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=1183; tryItOut("v0 = Object.prototype.isPrototypeOf.call(s2, o2.p2);");
/*fuzzSeed-66366547*/count=1184; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var acos = stdlib.Math.acos;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -0.03125;\n    var d3 = -65537.0;\n    var d4 = -15.0;\n    {\n      (Float32ArrayView[((0xd07041)+(0x7aafadca)) >> 2]) = ((+(((0x2aa1db77))>>>((-0x8000000)-(0x6110877d)-(-0x8000000)))));\n    }\n    (Uint32ArrayView[0]) = ((/*FFI*/ff()|0));\n    d0 = (+acos((((d2) + (NaN)))));\n    {\n      {\n        return +(((d0) + (-67108865.0)));\n      }\n    }\n    d2 = ((Float32ArrayView[2]));\n    return +((+abs(((d1)))));\n    return +((d1));\n  }\n  return f; })(this, {ff: function  x (\u3056, eval) { \"use strict\"; return x } }, new ArrayBuffer(4096)); testMathyFunction(mathy0, [2**53, 0x100000000, -0x07fffffff, -0, Math.PI, -0x0ffffffff, 42, 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -0x080000000, 0.000000000000001, 1, -0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, -(2**53+2), 0x07fffffff, 1.7976931348623157e308, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53), 1/0, 0, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53+2, -(2**53-2), -0x100000000]); ");
/*fuzzSeed-66366547*/count=1185; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.log2(Math.min((mathy1((Math.fround(Math.max(((( + (y < ( + y))) >>> 0) , (( ! y) >>> 0)), (Math.ceil(((Math.pow(Math.fround(( - y)), x) >>> 0) | 0)) | 0))) | 0), ( + ( + mathy1(( ! 1), (y / x))))) | 0), (( + x) >>> 0))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 42, 2**53, Number.MAX_VALUE, -0x080000001, -0x080000000, 0x080000001, Number.MAX_SAFE_INTEGER, -0, 0x100000001, -0x100000000, 0x07fffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53-2, -(2**53+2), 0x0ffffffff, -(2**53-2), 1/0, 2**53+2, -1/0, 0/0, -(2**53), -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, 0, 1, -0x0ffffffff, 0.000000000000001, Math.PI, 0x080000000]); ");
/*fuzzSeed-66366547*/count=1186; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return ( + (( + Math.tanh(( + Math.log(y)))) ? ( + ( + Math.min(( + ( ~ x)), ( + mathy2((Math.tan((x >>> 0)) | 0), x))))) : ( + mathy2(( + Math.abs(( + (Math.fround(Math.hypot(Math.fround(-0x080000000), y)) === x)))), ( + ( - (Math.log10((Math.round((( + (x | 0)) | 0)) | 0)) | 0))))))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, -0, 2**53-2, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, 0x080000000, -(2**53-2), 2**53+2, Number.MIN_SAFE_INTEGER, 1, -Number.MAX_SAFE_INTEGER, 1/0, 0, -0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 42, 0x100000000, 0x100000001, -1/0, -(2**53+2), 0.000000000000001, 1.7976931348623157e308, 0/0, -0x080000001, -Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, -0x080000000, Math.PI, -(2**53), 0x07fffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=1187; tryItOut(";/*bLoop*/for (zjiuvz = 0; zjiuvz < 0; ++zjiuvz) { if (zjiuvz % 6 == 4) { [[1]];(this); } else { (-604948599); }  } ");
/*fuzzSeed-66366547*/count=1188; tryItOut("/*hhh*/function jslgor(b = this, c = (this.__defineGetter__(\"x\", (Map.prototype.entries).call)).__defineSetter__(\"setter\", x), d, {eval}, x, NaN, [], x, y, x, z, d = window, x, c, z, x = x, x, x, y, b = null, x, e, c, x = true, a = /$/yim, window, x = this, x = \"\\u08DA\", x, d){v2 = evaluate(\"function f1(b0)  { yield NaN-- } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 2), noScriptRval: (x % 5 != 1), sourceIsLazy: true, catchTermination: true, element: o1, sourceMapURL: s2 }));}/*iii*/var xjcbdm = new SharedArrayBuffer(8); var xjcbdm_0 = new Uint32Array(xjcbdm); xjcbdm_0[0] = -6; var xjcbdm_1 = new Uint8ClampedArray(xjcbdm); var xjcbdm_2 = new Uint8ClampedArray(xjcbdm); var xjcbdm_3 = new Uint16Array(xjcbdm); print(xjcbdm_3[0]); xjcbdm_3[0] = 7; var xjcbdm_4 = new Uint8Array(xjcbdm); xjcbdm_4[0] = 27; print([eval(\" \\\"\\\" \", window)]);");
/*fuzzSeed-66366547*/count=1189; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((( + Math.trunc(( + (Math.min(( + Math.trunc(( + x))), Math.fround(y)) ** ( + (( ! ( - ( + x))) >>> 0)))))) >>> 0) - ( + ( - ( + ( + Math.cosh(y)))))); }); ");
/*fuzzSeed-66366547*/count=1190; tryItOut("mathy3 = (function(x, y) { return Math.sin(Math.max((( - ((( ~ (0 | 0)) | 0) | 0)) | 0), (Math.fround(x) | Math.atan2((y | 0), (( ~ (( ~ x) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [0x080000000, -(2**53+2), -0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, 2**53, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000000, 0x080000001, 1, 1.7976931348623157e308, -0x080000001, -1/0, 0x100000000, 0.000000000000001, 2**53+2, -0x0ffffffff, Number.MIN_VALUE, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x100000000, 0, 42, 0/0, 1/0, -(2**53), 2**53-2, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1191; tryItOut("\"use strict\"; o2.h2.valueOf = (function() { for (var j=0;j<19;++j) { f1(j%4==1); } });");
/*fuzzSeed-66366547*/count=1192; tryItOut("\"use strict\"; \"use asm\"; a1.shift(s2);");
/*fuzzSeed-66366547*/count=1193; tryItOut("/*vLoop*/for (let hyawrr = 0; hyawrr < 46; ++hyawrr) { d = hyawrr; /*iii*//*hhh*/function bprkjn(\u3056, eval, e, z, window, d, window, x =  \"\" , let, sqrnjj, hcdamy, lkkpga,  '' , gsdjnj, z, a = new RegExp(\"\\\\S$+?*|$\\\\b*?\\\\S+?*?\", \"gyim\"), NaN = false, y = new RegExp(\".\", \"ym\"), d, x, d, eval, b, this.x, d, z, d, window, x, b){print(x);} } ");
/*fuzzSeed-66366547*/count=1194; tryItOut("e0 + '';");
/*fuzzSeed-66366547*/count=1195; tryItOut("/*oLoop*/for (let hkuegw = 0; hkuegw < 48; ++hkuegw) { a0.splice(NaN, 5, o2, s0, m1); } ");
/*fuzzSeed-66366547*/count=1196; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ((Math.expm1(( + Math.sinh(( + y)))) >>> Math.min(Math.expm1(y), mathy0(y, Math.fround(((( ~ ((Math.min((y | 0), (( + Math.cos(( + y))) >>> 0)) | 0) | 0)) | 0) ? (0x100000001 | 0) : ((y , y) | 0)))))) | 0); }); testMathyFunction(mathy3, [false, (new Number(0)), undefined, [], (new Boolean(true)), '', -0, objectEmulatingUndefined(), NaN, '0', (new String('')), /0/, 0, '/0/', ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), true, (new Boolean(false)), 0.1, (new Number(-0)), ({toString:function(){return '0';}}), '\\0', (function(){return 0;}), 1, null, [0]]); ");
/*fuzzSeed-66366547*/count=1197; tryItOut("o1 = m2.__proto__;");
/*fuzzSeed-66366547*/count=1198; tryItOut("\"use strict\"; for (var p in f0) { try { for (var v of g0.i2) { try { f1(b1); } catch(e0) { } try { print(p2); } catch(e1) { } try { a2[v0] = i0; } catch(e2) { } v0 = new Number(NaN); } } catch(e0) { } try { h1.getOwnPropertyDescriptor = f1; } catch(e1) { } Array.prototype.shift.call(a1, b1, m2); }");
/*fuzzSeed-66366547*/count=1199; tryItOut("");
/*fuzzSeed-66366547*/count=1200; tryItOut("\"use strict\"; i0 + f1;");
/*fuzzSeed-66366547*/count=1201; tryItOut("for(let a in /*MARR*/[new Boolean(false), NaN, new Boolean(false), new Boolean(false), true, NaN, NaN, NaN, new Boolean(false), true, new Boolean(false), true, NaN, new Boolean(false), NaN, new Boolean(false), true, new Boolean(false), true, new Boolean(false), true, NaN, new Boolean(false), true, true, NaN, NaN, NaN, NaN, true, new Boolean(false), new Boolean(false), NaN, NaN, true, true, NaN, NaN, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, NaN, true, NaN, true, NaN, new Boolean(false), true, NaN, NaN, true, NaN, NaN, new Boolean(false), true, true, new Boolean(false), NaN, new Boolean(false), true, true, NaN, NaN, new Boolean(false), NaN, NaN, new Boolean(false), NaN, new Boolean(false)]) return -17;");
/*fuzzSeed-66366547*/count=1202; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.log2(Math.max(((((Math.sinh((y | 0)) | 0) >>> 0) <= (x >>> 0)) >>> 0), Math.log((Math.hypot((x >>> 0), (Math.PI >>> 0)) ? x : -Number.MAX_SAFE_INTEGER))))); }); testMathyFunction(mathy0, /*MARR*/[window >>> x, ({}), new Boolean(true), ({}), ({}), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), ({}), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), ({}), window >>> x, window >>> x, ({}), window >>> x, ({}), window >>> x, new Boolean(true), ({}), window >>> x, window >>> x, window >>> x, ({}), new Boolean(true), ({}), ({}), ({}), ({}), new Boolean(true)]); ");
/*fuzzSeed-66366547*/count=1203; tryItOut("o1 = new Object;");
/*fuzzSeed-66366547*/count=1204; tryItOut("a1.sort(f0);");
/*fuzzSeed-66366547*/count=1205; tryItOut("h2.fix = (function mcc_() { var wsbswm = 0; return function() { ++wsbswm; if (/*ICCD*/wsbswm % 7 == 6) { dumpln('hit!'); print(g1.o0.f2); } else { dumpln('miss!'); try { t0.set(t2, 4); } catch(e0) { } v2 = (this.g2 instanceof t2); } };})();");
/*fuzzSeed-66366547*/count=1206; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.asinh(((( ~ (Math.hypot(( + (mathy3(-0, y) || mathy3((y | 0), (y | 0)))), (x >>> 0)) | 0)) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1/0, 0x0ffffffff, -0x0ffffffff, -0x080000001, 2**53-2, -Number.MIN_VALUE, 0x080000000, 2**53, -(2**53-2), -0x100000001, -0x100000000, Math.PI, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, -1/0, 1, Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, 0x100000001, 2**53+2, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0, 0, -0x080000000, 42, -0, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-66366547*/count=1207; tryItOut("testMathyFunction(mathy3, [-0x07fffffff, 0x07fffffff, 0.000000000000001, 0x080000000, 42, 1.7976931348623157e308, 2**53+2, 0x100000000, -0x100000000, 1/0, -0, 0x0ffffffff, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53-2), Math.PI, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, 0, 0x100000001, -(2**53), 0/0, -(2**53+2), -Number.MIN_VALUE, -0x100000001, 1, 2**53-2, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, 2**53, -0x080000000, -0x080000001]); ");
/*fuzzSeed-66366547*/count=1208; tryItOut("\"use strict\"; g1.a2.splice(NaN,  /x/ );");
/*fuzzSeed-66366547*/count=1209; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul(( + ((Math.sqrt((Math.clz32(Math.fround((x > (y ^ x)))) >>> 0)) >>> 0) === Math.fround(Math.tan(Math.fround((( ~ (Math.acosh(x) | 0)) | 0)))))), (Math.max(( + ((Math.log(x) >>> 0) + ( + ((new (q => q)( '' )) || Math.exp((Math.hypot((y | 0), (42 >>> 0)) | 0)))))), ((( + Math.imul(Math.hypot(Number.MAX_SAFE_INTEGER, y), y)) >>> 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-66366547*/count=1210; tryItOut("print(t2);");
/*fuzzSeed-66366547*/count=1211; tryItOut("print(s0);\n/* no regression tests found */\n");
/*fuzzSeed-66366547*/count=1212; tryItOut("print();");
/*fuzzSeed-66366547*/count=1213; tryItOut("mathy5 = (function(x, y) { return Math.imul(( + Math.fround(Math.min((Math.sin((((0x080000000 | 0) ? (x | 0) : (y + Math.fround((Math.fround(y) % x)))) | 0)) | 0), Math.fround(Math.round((Math.fround(Math.atan2(Math.fround(mathy0(( + -0x080000000), Math.fround(y))), y)) | 0)))))), Math.atan2((Math.hypot(( ~ (((x | 0) ? mathy1(x, x) : 0.000000000000001) >>> 0)), mathy2(1/0, y)) ** mathy3((y <= x), ((( /x/  >>> 0) ? x : (Math.abs(x) >>> 0)) >>> 0))), ( - ((Math.hypot((x | 0), ( - 0x080000000)) & (mathy1(Math.cbrt(((Math.fround(y) != x) >>> 0)), Math.log1p(( + y))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [({valueOf:function(){return 0;}}), '/0/', null, ({valueOf:function(){return '0';}}), 1, (new Boolean(true)), (new Boolean(false)), '\\0', /0/, false, ({toString:function(){return '0';}}), [], (new String('')), (new Number(-0)), objectEmulatingUndefined(), '0', NaN, 0, undefined, (function(){return 0;}), (new Number(0)), -0, 0.1, '', [0], true]); ");
/*fuzzSeed-66366547*/count=1214; tryItOut("/*tLoop*/for (let a of /*MARR*/[new String(''), new Boolean(false), new String(''), false, new Boolean(false), new Boolean(false), false, new String(''), new Boolean(false), false, false, new String(''), new String(''), false, new Boolean(false), new Boolean(false), false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, new Boolean(false), new String(''), new Boolean(false), false, new String(''), false, new Boolean(false), false, new Boolean(false), new Boolean(false), new String(''), new String(''), new String(''), new Boolean(false), new String(''), false, new Boolean(false), new Boolean(false), new Boolean(false), new String(''), false, new String(''), false, false, new Boolean(false), false, false, false, false]) { g0.e1.has(this.h1); }");
/*fuzzSeed-66366547*/count=1215; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(( + Math.sinh((( ~ ( + ( + Math.log2(x)))) | 0)))) >>> 0); }); testMathyFunction(mathy0, [1, (new Boolean(true)), true, (new Boolean(false)), '/0/', '', 0, ({valueOf:function(){return '0';}}), null, (new Number(0)), '0', '\\0', NaN, objectEmulatingUndefined(), [], false, (new String('')), (function(){return 0;}), (new Number(-0)), -0, [0], ({toString:function(){return '0';}}), 0.1, undefined, /0/, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-66366547*/count=1216; tryItOut("\"use asm\"; /*bLoop*/for (var rnbzuy = 0; rnbzuy < 24; ++rnbzuy) { if (rnbzuy % 5 == 0) { y; } else { g2.m1 = new WeakMap; }  } ");
/*fuzzSeed-66366547*/count=1217; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = /\\1/yi; var s = \"\\ua13f1\\u0091 \"; print(r.test(s)); ");
/*fuzzSeed-66366547*/count=1218; tryItOut("function shapeyConstructor(ppxtzr){Object.defineProperty(ppxtzr, \"d\", ({}));for (var ytqawfxzc in ppxtzr) { }Object.freeze(ppxtzr);Object.seal(ppxtzr);Object.preventExtensions(ppxtzr);ppxtzr[10] = undefined;Object.defineProperty(ppxtzr, \"valueOf\", ({}));for (var ytqfpejxe in ppxtzr) { }Object.freeze(ppxtzr);ppxtzr[\"isFinite\"] =  /x/g ;return ppxtzr; }/*tLoopC*/for (let x of /*FARR*/[/*UUV2*/(e.sup = e.sinh), (({call: null })), ...x, .../*MARR*/[false, function(){}, function(){}, function(){}, false, function(){}, false, function(){}, false, function(){}, false, false, false, false, false, function(){}, false, false, function(){}, function(){}, false, function(){}, false, function(){}, function(){}, function(){}, false, false, false, function(){}, false, function(){}, function(){}, function(){}, false, false, false, function(){}, false, function(){}, false, false, false, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, false, function(){}, false, function(){}, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, function(){}, function(){}, function(){}, false, function(){}, function(){}, false, function(){}], , .../*FARR*/[], (yield [this.__defineSetter__(\"b\", (new Function(\"v1.__proto__ = i1;\")))])]) { try{let odzwoc = new shapeyConstructor(x); print('EETT'); this.m2 = new Map;}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-66366547*/count=1219; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.imul(Math.min(((((( ~ y) | 0) ** ((y >>> Math.asin(y)) | 0)) | 0) ? ( + mathy4(( + ( + Math.ceil(((x >> x) | 0)))), y)) : ( ~ Math.sqrt(y))), (Math.fround(mathy1(Math.fround(((1/0 + (x >>> 0)) >>> 0)), Math.fround(( - Math.fround(-(2**53+2)))))) | 0)), ( + ( + ( + (Math.max((y >>> 0), (( + Math.acos(( ! y))) >>> 0)) >>> 0))))) | 0); }); testMathyFunction(mathy5, /*MARR*/[(0/0), (0/0), x, new Number(1.5), -0xB504F332, new Number(1.5), x, x, (0/0), x, (0/0), -0xB504F332, -0xB504F332, 0x100000000, x, 0x100000000, 0x100000000, 0x100000000, -0xB504F332, new Number(1.5), (0/0), 0x100000000, 0x100000000, x, new Number(1.5), new Number(1.5), 0x100000000, new Number(1.5), x, -0xB504F332, (0/0), new Number(1.5), 0x100000000, -0xB504F332, 0x100000000, x, (0/0), -0xB504F332, x, (0/0), -0xB504F332, 0x100000000, -0xB504F332, new Number(1.5), x, x, x, 0x100000000, x, (0/0), (0/0), (0/0), 0x100000000, 0x100000000, (0/0), (0/0), new Number(1.5), 0x100000000, x, -0xB504F332, 0x100000000, -0xB504F332, (0/0), (0/0), 0x100000000, new Number(1.5), (0/0), (0/0), (0/0), -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, -0xB504F332, new Number(1.5), new Number(1.5), 0x100000000, -0xB504F332, new Number(1.5), -0xB504F332]); ");
/*fuzzSeed-66366547*/count=1220; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (-9223372036854776000.0);\n    (Uint32ArrayView[4096]) = ((-0x8000000)-(i0));\n    {\n      d1 = (((+(1.0/0.0))) * ((+/*FFI*/ff(((-((d1)))), ((-17592186044416.0)), ((d1)), ((((((-536870913.0)) * ((1.5474250491067253e+26)))) / ((d1))))))));\n    }\n    d1 = (9.671406556917033e+24);\n    d1 = (1.5111572745182865e+23);\n    i0 = (0x98e833d0);\nm1.set(this.o2.a0, b2);    (Float32ArrayView[2]) = (((0x154e69de) ? (d1) : (((0xffffffff)+(/*FFI*/ff(((((d1)) - ((Float32ArrayView[2])))), ((((0xfcf90638)-(0x3869d916)) >> ((0xa6eb35d4)))), ((((0xffffffff)) | ((0xfd4bde27)))), ((67108865.0)))|0)-(0xffffffff)))));\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; a1.forEach(g1.o0, i1, f0);; yield y; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [objectEmulatingUndefined(), 0.1, /0/, (function(){return 0;}), [0], undefined, '', 1, NaN, 0, -0, '/0/', ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (new Boolean(false)), (new Number(0)), (new Boolean(true)), true, ({valueOf:function(){return '0';}}), (new String('')), (new Number(-0)), '0', null, [], false, '\\0']); ");
/*fuzzSeed-66366547*/count=1221; tryItOut("\"use strict\"; m2.has(a1);");
/*fuzzSeed-66366547*/count=1222; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 137438953473.0;\n    switch ((((i0))|0)) {\n      case -2:\n        {\n          d1 = (((-((Float64ArrayView[((!(i0))-(0x2a75e74)) >> 3])))) / ((-16384.0)));\n        }\n        break;\n      default:\n        i2 = (0x2792dca8);\n    }\n    {\n      (Uint8ArrayView[2]) = ((((0xffffffff)) ? (0xf898b5c3) : (i2)));\n    }\n    d1 = ((void options('strict')));\n    i2 = (i0);\n    i2 = (0xfb33d0ad);\n    {\n      switch ((imul((0x24a5676a), (0x6b4edc1c))|0)) {\n        default:\n          d3 = (+((d3)));\n      }\n    }\n    d1 = (1.5111572745182865e+23);\n    d1 = (-295147905179352830000.0);\n    {\n      i0 = ((((d3))));\n    }\n    (Float64ArrayView[(((d3) >= ((0x26c4b53e) ? (-274877906945.0) : (-4611686018427388000.0)))-(0xbc1aa0f8)) >> 3]) = ((536870911.0));\n    return +((d3));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [0x100000000, 42, -0, -Number.MAX_VALUE, 0x07fffffff, 0.000000000000001, 2**53-2, -(2**53), 0x080000000, Number.MAX_VALUE, -0x080000000, -(2**53+2), 2**53+2, -0x080000001, 1, 0x100000001, -(2**53-2), -0x100000001, 1/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0, 0x080000001, -Number.MIN_VALUE, -1/0, Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=1223; tryItOut("/*tLoop*/for (let w of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, new Number(1.5), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), new Number(1.5), NaN, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), NaN, objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, new Number(1.5), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), NaN, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), NaN, NaN, objectEmulatingUndefined(), NaN, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), NaN, new Number(1.5), NaN, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), NaN, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), NaN, new Number(1.5), objectEmulatingUndefined(), NaN, new Number(1.5), objectEmulatingUndefined()]) { m2.delete(m1); }");
/*fuzzSeed-66366547*/count=1224; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + Math.tan(Math.fround(((-0x0ffffffff < (Math.cosh(( + Math.trunc(y))) >>> 0)) >= Math.log(Math.fround(-Number.MIN_VALUE)))))) >> ( + ((mathy0(((y == y) | 0), (( ! Math.cosh(y)) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy5, [-0x07fffffff, 0, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53+2, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, -0x080000000, 2**53-2, 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000000, -1/0, 0x080000001, Math.PI, 0x0ffffffff, 0/0, -0x080000001, -(2**53+2), 1, -0x100000000, 2**53, 42, Number.MAX_VALUE, -Number.MIN_VALUE, -0, -0x0ffffffff, -(2**53-2), 0x07fffffff, -(2**53), -0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=1225; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=1226; tryItOut("\"use strict\"; let NaN =  '' ;[z1];");
/*fuzzSeed-66366547*/count=1227; tryItOut("\"use strict\"; tgcmmq( ? this : ( + Math.pow(x, x)), Object.defineProperty(x, \"arguments\", ({configurable: false, enumerable: new (new Function)(18)})));/*hhh*/function tgcmmq(x, window, a, x, x, \u3056, x, c, set, a, d, of =  \"\" , x = -0, window = ({}), x, w, x, x, NaN, z, x, this.x, x, x, x, d, x, c, z, let, window, \u3056, x = /\\1/yim, e =  \"\" , d =  /x/ , w = this, d,  , x, x, this.d = 4398046511105, x = true, x, eval, x, e = 7, x, x =  /x/g , x, d, x, b, y, x = this, b, x, z, y, b, e, b = true){e1 = m2;}");
/*fuzzSeed-66366547*/count=1228; tryItOut("/*oLoop*/for (kdxufr = 0; kdxufr < 53; ++kdxufr) { for (var v of g2.e0) { try { v0 = Object.prototype.isPrototypeOf.call(this.g2.b1, p2); } catch(e0) { } try { t1.set(a1, window); } catch(e1) { } t1.__proto__ = o0.g2.g1; } } ");
/*fuzzSeed-66366547*/count=1229; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( ~ ( + Math.max(( + (Math.abs(y) | 0)), ( + ((mathy2((-0 >>> 0), (( ~ mathy0(y, Math.sqrt(x))) | 0)) | 0) ** (Math.pow((mathy1(((Math.atan2((Math.exp(-0x07fffffff) >>> 0), (x | 0)) | 0) | 0), (x >>> 0)) | 0), (y >>> 0)) | 0)))))) | 0); }); testMathyFunction(mathy3, [2**53+2, 2**53-2, 1, 0/0, -0x07fffffff, -0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, 0, 2**53, -0x100000000, -0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, -(2**53-2), 1/0, -(2**53), 0x080000000, -(2**53+2), 1.7976931348623157e308, Math.PI, 0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000001, -0x080000001, -0, 0x100000000, 0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 42, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=1230; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.clz32(Math.fround(Math.atan2((Math.sinh(( + y)) >>> 0), mathy2(((Math.tanh(Math.fround(x)) >>> 0) >>> 0), (Math.tanh((( - x) | 0)) | 0))))); }); testMathyFunction(mathy4, [-0, 0, false, null, (new String('')), undefined, '0', ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), NaN, /0/, [], ({toString:function(){return '0';}}), '', (function(){return 0;}), '/0/', '\\0', (new Boolean(true)), [0], ({valueOf:function(){return '0';}}), 1, (new Number(0)), (new Boolean(false)), 0.1, true, (new Number(-0))]); ");
/*fuzzSeed-66366547*/count=1231; tryItOut("\"use strict\"; this.zzz.zzz;");
/*fuzzSeed-66366547*/count=1232; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = o1.s0; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=1233; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, Math.PI, -(2**53+2), -0, -0x080000000, -Number.MIN_VALUE, 0x080000000, -(2**53), -1/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, -(2**53-2), 1/0, 0/0, 42, 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, 1, 0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, Number.MIN_VALUE, 2**53, -0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 0x100000000, 0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=1234; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((( + (Math.sign((Math.hypot(( + x), ( + 0)) >>> 0)) === (Math.atan2((( ~ (0x0ffffffff ? x : y)) >>> 0), Math.fround(Math.atan2((2**53+2 | 0), ((( ~ (Math.asin((x >>> 0)) >>> 0)) >>> 0) | 0)))) >>> 0))) || Math.atan(Math.cosh(( + x)))) == mathy0(((((Math.max(x, (Math.fround(Math.atan2(Math.fround(x), Math.fround((((x >>> 0) !== ( + y)) >>> 0)))) | 0)) | 0) | 0) != (Math.imul(x, (x ? y : Math.atanh(Number.MAX_VALUE))) == y)) >>> 0), Math.fround(mathy0((0x0ffffffff ? ((Math.sinh((y >>> 0)) >>> 0) | 0) : (Math.fround(Math.max((( ~ -1/0) >>> 0), (( ~ -Number.MAX_SAFE_INTEGER) >>> 0))) >>> 0)), Math.fround(Math.hypot(mathy0((Math.hypot(x, x) | 0), Math.fround(x)), x)))))); }); testMathyFunction(mathy2, [42, 2**53-2, Math.PI, -0x07fffffff, -(2**53-2), 2**53+2, 1/0, 1.7976931348623157e308, -0x080000000, 1, 0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, -0x0ffffffff, 0x07fffffff, -0x100000001, 0x080000001, Number.MIN_VALUE, -(2**53+2), -(2**53), 0x100000000, 0x0ffffffff, Number.MAX_VALUE, 0, -0x080000001, -0x100000000, -0, Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-66366547*/count=1235; tryItOut("with({y: -20}){if((y % 5 != 3)) o1 = new Object; else  if ( '' ) {({}); } else {i1.next();s1 += 'x'; } }");
/*fuzzSeed-66366547*/count=1236; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.fround(Math.fround(( - Math.fround(( + ((( + (Math.pow((Math.expm1(((y >> x) >>> 0)) >>> 0), -Number.MIN_VALUE) >>> 0)) >>> 0) ? y : (y - (((y >>> 0) | Math.tan((y >>> 0))) >>> 0)))))))) , (Math.log(( + Math.pow((((( ~ Math.fround(( ! y))) >>> 0) - ( ! (y >>> 0))) >>> 0), Math.log10(Math.min(Math.fround(Number.MAX_SAFE_INTEGER), ( + Math.tanh((y | 0)))))))) >>> 0)); }); ");
/*fuzzSeed-66366547*/count=1237; tryItOut("var NaN, qakzqa, x = ({d: x} = new RegExp(\"(?!(?:.\\\\b)(?!(?!\\\\B))|$*|^*?(?:.)+)|[^]|$(?:.)[^](?:\\\\D)*?\", \"yi\")), x, [] = (intern( /x/ ) >>= ({}) = offThreadCompileScript())\u000c(intern( /x/ ), (yield  /x/ )), w = (void shapeOf((yield (x = window)))), x, tfobbt, b = (4277);print(uneval(v1));");
/*fuzzSeed-66366547*/count=1238; tryItOut("/*ADP-2*/Object.defineProperty(a1, 4, { configurable: true, enumerable: (x % 12 == 3), get: f2, set: (function(j) { if (j) { try { a0 = new Array; } catch(e0) { } try { v0 = a1.reduce, reduceRight(function  e (x = function ([y]) { }.eval(\"\\\"use strict\\\"; /*MXX2*/g2.Array.prototype.fill = v1;\"), window, x, x, x, window, d, x =  /x/g , w, eval, d, x, x = toLocaleString, c, y,   = e, x, x = x, eval, window, b, eval, z, a = this, b, x, x =  /x/ , d, window, x, this.x, d, x, y, x, x, window, x = \"\\u7B0E\", \u3056, x, c, x, x, x, w, x, x, NaN, y =  /x/ , x = this, a, d = /\\b|(\\1([^\uc628-i\\W\\W]))/gyi, \u3056, c, x, x, d, y =  '' , x, w, d = null, x, e, e, x, e, x = x)(4277).__defineGetter__(\"Error\", DataView.prototype.getUint16), b0, i1); } catch(e1) { } try { i1.next(); } catch(e2) { } v0 = Array.prototype.reduce, reduceRight.apply(a0, [f2, m0]); } else { try { a1.forEach(v0, (4277)); } catch(e0) { } v1 = Array.prototype.some.call(a0, (function(j) { if (j) { try { /*MXX3*/g0.Date.prototype.getUTCSeconds = g2.Date.prototype.getUTCSeconds; } catch(e0) { } try { v2 = g2.eval(\"false\"); } catch(e1) { } try { m1 = new WeakMap; } catch(e2) { } g1.m0 = new WeakMap; } else { try { const s1 = new String(i0); } catch(e0) { } try { e2.add(s0); } catch(e1) { } try { a2 = new Array; } catch(e2) { } b1 = new SharedArrayBuffer(72); } })); } }) });");
/*fuzzSeed-66366547*/count=1239; tryItOut("\"use strict\"; e2 = new Set(i2);");
/*fuzzSeed-66366547*/count=1240; tryItOut("\"use strict\"; a = this, x = Math.min( \"\" ,  '' ), d = /\\B/gym, w;((new (13)()));");
/*fuzzSeed-66366547*/count=1241; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=1242; tryItOut("\"use strict\"; this.m2 + p0;");
/*fuzzSeed-66366547*/count=1243; tryItOut("m0 = new Map;");
/*fuzzSeed-66366547*/count=1244; tryItOut("\"use strict\"; this.p0.__proto__ = i1;");
/*fuzzSeed-66366547*/count=1245; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.hypot(Math.fround(Math.cosh(Math.hypot((y ? ( + x) : Number.MIN_SAFE_INTEGER), Math.min(x, Math.fround(-Number.MAX_SAFE_INTEGER))))), ((( + (( - Math.hypot(x, ( + 1/0))) >>> 0)) >>> 0) % Math.expm1((Math.hypot(x, (( + (x | 0)) | 0)) >>> 0)))) | 0); }); ");
/*fuzzSeed-66366547*/count=1246; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.fround(Math.fround(Math.exp(Math.fround(Math.pow((y | 0), 0x07fffffff))))) >= Math.tanh(Math.fround(Math.tan(Math.fround(y))))); }); testMathyFunction(mathy5, [0, 0x080000000, 1, -0x100000001, 2**53, -0, Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, -0x080000000, 0x080000001, 0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, 1/0, 1.7976931348623157e308, 2**53-2, 0x100000001, 42, -(2**53-2), -0x100000000, 0.000000000000001, -(2**53+2), -0x080000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, -(2**53), 0/0, 0x07fffffff, Number.MIN_VALUE, -1/0]); ");
/*fuzzSeed-66366547*/count=1247; tryItOut("mathy5 = (function(x, y) { \"use asm\"; return Math.fround(((Math.fround(Math.log10(Math.fround(Math.fround(Math.atan(Math.imul(x, x)))))) | 0) % Math.fround(Math.fround(((mathy3(Math.fround(Math.max((((Number.MAX_VALUE >>> 0) != ((( + (Math.fround((Math.fround(y) ? x : Math.fround(y))) | 0)) | 0) >>> 0)) >>> 0), y)), Math.fround(y)) >>> 0) % (Math.max(((( ~ (1/0 >>> 0)) >>> 0) | 0), x) >>> 0)))))); }); testMathyFunction(mathy5, [0x080000001, 0x100000000, 2**53, 0x080000000, Number.MAX_VALUE, -(2**53), -1/0, 1/0, 0, -(2**53+2), -0x0ffffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -(2**53-2), Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, 2**53-2, 42, 0/0, 1, Math.PI, 0.000000000000001, -0x07fffffff, -0x080000000, -0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1248; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return ( + ( + ( + ( + Math.hypot(( + (Math.acosh((Math.log((Math.fround(Math.min(Math.fround(-0x080000001), Math.fround(y))) >>> 0)) >>> 0)) >>> 0)), ( + (( + y) === -0))))))); }); testMathyFunction(mathy2, [0x080000000, 0x080000001, 0.000000000000001, 2**53-2, -Number.MIN_VALUE, Math.PI, -0x100000001, -Number.MAX_VALUE, 2**53, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53), 1/0, 0x0ffffffff, 1, -0x080000001, 0x07fffffff, -0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, -(2**53+2), -0x100000000, -(2**53-2), 0/0, -0x080000000, -1/0, 42, 0, Number.MIN_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-66366547*/count=1249; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-1/0, -Number.MAX_VALUE, -0x080000000, 2**53, 2**53-2, 0x080000000, -(2**53-2), 0x0ffffffff, -0x100000001, 0/0, 42, 0x100000001, Math.PI, -0x07fffffff, -0x0ffffffff, -0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -0x080000001, 2**53+2, -(2**53+2), 1/0, Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 0x100000000, 1, 0x07fffffff]); ");
/*fuzzSeed-66366547*/count=1250; tryItOut("\"use strict\"; f1 + '';");
/*fuzzSeed-66366547*/count=1251; tryItOut("testMathyFunction(mathy1, /*MARR*/[ /x/ ,  /x/ , x, ['z'],  /x/ , ['z'], x, ['z'], ['z'],  /x/ , ['z'], new Number(1),  /x/ , new Number(1), ['z'], new Number(1), ['z'],  /x/ , ['z'], ['z'], ['z'],  /x/ , new Number(1), new Number(1), new Number(1),  /x/ , new Number(1), x, ['z'],  /x/ ,  /x/ , new Number(1), new Number(1), ['z'], x, x,  /x/ , x,  /x/ , new Number(1),  /x/ , ['z'], x, new Number(1),  /x/ , x, new Number(1), new Number(1), x, x,  /x/ , new Number(1), ['z'], ['z'], new Number(1), x, x, new Number(1),  /x/ ,  /x/ ,  /x/ ,  /x/ , x,  /x/ , ['z'],  /x/ , ['z'],  /x/ , new Number(1), new Number(1), new Number(1),  /x/ , ['z'], new Number(1), x, new Number(1),  /x/ ,  /x/ , ['z'], ['z'],  /x/ , new Number(1), new Number(1), x, ['z'],  /x/ , ['z'],  /x/ , x, ['z'], new Number(1), ['z'],  /x/ , new Number(1),  /x/ , new Number(1),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , ['z'], new Number(1), x, ['z'], x,  /x/ , new Number(1), new Number(1), ['z'], ['z'], ['z'],  /x/ , ['z'], new Number(1), x, new Number(1), ['z'], ['z'], x,  /x/ , ['z'], x, x, new Number(1), ['z'], x, x, ['z'], x, ['z'], x, x,  /x/ , new Number(1),  /x/ , x, x, new Number(1),  /x/ ,  /x/ , ['z'],  /x/ , new Number(1), x, x, new Number(1), x, new Number(1), ['z'],  /x/ ,  /x/ , new Number(1), new Number(1), new Number(1), new Number(1), x, ['z'], new Number(1),  /x/ , new Number(1),  /x/ ,  /x/ ]); ");
/*fuzzSeed-66366547*/count=1252; tryItOut("g1.a0.length = 9;");
/*fuzzSeed-66366547*/count=1253; tryItOut("a0[14];");
/*fuzzSeed-66366547*/count=1254; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.log2((Math.round(Math.fround(( ! ( - (x ? x : y))))) | 0)) | 0) << (( + Math.log1p((x >= Math.sin(-0x100000000)))) >> Math.sqrt((y !== Math.clz32(y))))); }); ");
/*fuzzSeed-66366547*/count=1255; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.atan2(( + Math.sinh(Math.abs(Math.asin(( + x))))), Math.fround((( - ( + (x << ( + (Math.fround(Number.MAX_VALUE) | Math.fround(x)))))) | 0))); }); testMathyFunction(mathy0, [0.1, 0, [0], true, (new Number(0)), (function(){return 0;}), (new String('')), [], false, (new Boolean(false)), (new Number(-0)), ({toString:function(){return '0';}}), '\\0', ({valueOf:function(){return '0';}}), (new Boolean(true)), '/0/', objectEmulatingUndefined(), '0', 1, ({valueOf:function(){return 0;}}), undefined, NaN, '', null, /0/, -0]); ");
/*fuzzSeed-66366547*/count=1256; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+abs((({} = null))));\n    d0 = (+(((d0))>>>((((((-274877906945.0) <= (-3.777893186295716e+22))-(0xd9630baa)) ^ ((-0x8000000)+(0xffe9ac8b)+(0xfacfef08))))-(((0x121a8c78) ? (d1) : (d1)) == ((NaN))))));\n    return +((d0));\n  }\n  return f; })(this, {ff: function  \u3056 (c)/*FARR*/[...[], ({a1:1}), ].filter(function(q) { return q; }, -22)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [({valueOf:function(){return '0';}}), (function(){return 0;}), 0.1, NaN, '\\0', objectEmulatingUndefined(), false, 0, -0, '0', [0], /0/, true, (new String('')), null, (new Boolean(true)), (new Boolean(false)), 1, (new Number(0)), '/0/', ({valueOf:function(){return 0;}}), (new Number(-0)), undefined, ({toString:function(){return '0';}}), '', []]); ");
/*fuzzSeed-66366547*/count=1257; tryItOut("t1 = new Uint8ClampedArray(this.b1, 144, 16);");
/*fuzzSeed-66366547*/count=1258; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; gcslice(2347410569); } void 0; } this.v1 = evalcx(\"((uneval(/\\\\S/gi)))\", this.g2);");
/*fuzzSeed-66366547*/count=1259; tryItOut("b0.toString = (function(j) { if (j) { try { a1 = a0.slice(NaN, -4, g0.m1); } catch(e0) { } try { this.v1 = g0.eval(\"/*infloop*/L:for(let  \\\"\\\" .NaN =  /x/  >> undefined; Math.min(undefined <<= -28, a = /^*?(?=.{3,6}+)[\\\\cF-\\ua075-\\ub06a\\u000c-\\\\cN\\\\t-B]|\\u2c81{4}|(?!\\\\b)*?*/gy); [([,](this,  /x/ ))]) {M:do ( /x/g ); while((this) && 0); }\"); } catch(e1) { } Array.prototype.push.apply(a0, [t1, m2]); } else { try { /*RXUB*/var r = this.g2.r1; var s = x; print(s.replace(r, '', \"gi\"));  } catch(e0) { } try { Array.prototype.push.call(this.a0, f1, for(let z of new Array(-6)) switch(\"\\uBECB\"(arguments, true)) { case window ? 4 :  /x/g : g2.__proto__ = a1;case 0: ;break; case Math.pow( /x/ , 27): return NaN;default: m2 = new Map(v0);break;  }); } catch(e1) { } try { for (var v of e2) { try { Object.defineProperty(this, \"o2.o0.t1\", { configurable: (x % 23 == 20), enumerable: (x % 90 != 80),  get: function() {  return new Uint16Array(b0); } }); } catch(e0) { } try { i2 = new Iterator(a1, true); } catch(e1) { } try { o2.v2 = Object.prototype.isPrototypeOf.call(a2, this.g0); } catch(e2) { } s1 += 'x'; } } catch(e2) { } Array.prototype.pop.apply(a1, [h0, a1, f2]); } });");
/*fuzzSeed-66366547*/count=1260; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 16777217.0;\n    (Int8ArrayView[2]) = ((i1));\n    (Uint8ArrayView[((i1)) >> 0]) = ((0xf87f5004)+((-16385.0) != (2305843009213694000.0))+(((((((0x15a1a02d))>>>((0xaaea081a))) == (((0xc3cb5293))>>>((0xffffffff))))*-0xffcfb)>>>(((~~(-8589934593.0)))-(-0x8000000)+(((0x6870aaa7) > (0x66133bf8))))) <= ((((((36028797018963970.0)) % ((513.0))) >= (((7.555786372591432e+22)) / ((6.044629098073146e+23))))-((0xffffffff) ? (0x339b3f9e) : (0xf8b00ad6)))>>>((Int8ArrayView[2])))));\n    d2 = (-((140737488355329.0)));\n    d2 = (9007199254740992.0);\n    return +((-65535.0));\n    return +(x);\n  }\n  return f; })(this, {ff: (e = eval+=d ? (x = this.eval(\"/* no regression tests found */\")) : (Uint16Array()), window) =>  { /*tLoop*/for (let c of /*MARR*/[undefined, undefined, [], [], undefined, undefined, [], undefined, [], [], undefined, undefined, [], undefined, [], undefined]) { for (var v of this.b0) { try { g2.g2.e0.add(s0); } catch(e0) { } try { /*RXUB*/var r = o2.r2; var s = s1; print(s.match(r)); print(r.lastIndex);  } catch(e1) { } for (var v of v0) { try { o0.v2 = new Number(p2); } catch(e0) { } try { for (var p in f0) { i2.next(); } } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(m0, h2); } catch(e2) { } b1 = t0.buffer; } } } } }, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53-2), -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, 2**53-2, 0x07fffffff, -0x100000001, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 2**53+2, -0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_VALUE, -0, -1/0, 0x0ffffffff, Number.MAX_VALUE, 2**53, 0.000000000000001, -0x080000000, 0x100000000, 1/0, -0x0ffffffff, 0, -0x080000001, -(2**53), 42, 1.7976931348623157e308, 0x100000001]); ");
/*fuzzSeed-66366547*/count=1261; tryItOut("mathy0 = (function(x, y) { return Math.fround(( ~ ((Math.fround(( - Math.fround(Math.max(Math.fround((y == y)), (((x | 0) ? ((((y | 0) !== x) | 0) | 0) : (2**53 | 0)) >>> 0))))) == (((( ! -(2**53-2)) >>> 0) >> (Math.abs((( ! (( + Math.trunc(( + 0x080000000))) | 0)) | 0)) | 0)) >>> 0)) | 0))); }); ");
/*fuzzSeed-66366547*/count=1262; tryItOut("M:if(x) \u000d/* no regression tests found */ else {t1[15] = a2; }");
/*fuzzSeed-66366547*/count=1263; tryItOut("\"use strict\"; e2.delete(e1);");
/*fuzzSeed-66366547*/count=1264; tryItOut("/*RXUB*/var r = r0; var s = \"a\"; print(s.replace(r, (4277))); ");
/*fuzzSeed-66366547*/count=1265; tryItOut("\"use strict\"; for (var v of g1) { v2 = Array.prototype.some.apply(a1, [s2, v2, o2]); }");
/*fuzzSeed-66366547*/count=1266; tryItOut("\"use strict\"; Array.prototype.shift.call(a0, g2, m2, this.e2);");
/*fuzzSeed-66366547*/count=1267; tryItOut("v2 = evalcx(\"g0.offThreadCompileScript(\\\"function f0(b2)  { return (4277) } \\\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: /*MARR*/[function(){}, 1.7976931348623157e308, function(){}, 1.7976931348623157e308, function(){}, 1.7976931348623157e308, function(){}, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, function(){}, 1.7976931348623157e308, function(){}, function(){}, 1.7976931348623157e308, function(){}, 1.7976931348623157e308, function(){}, 1.7976931348623157e308, function(){}, 1.7976931348623157e308, function(){}, function(){}, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308].filter(function (e) { \\\"use strict\\\"; return (/*RXUE*//*RXUE*/new RegExp(\\\"[^]\\\", \\\"m\\\").exec(\\\"\\\\u9e39\\\").exec(\\\"\\\")) } ), noScriptRval: false, sourceIsLazy: true, catchTermination: true }));\", this.g0);");
/*fuzzSeed-66366547*/count=1268; tryItOut("Array.prototype.push.call(this.a1, o1.s1, e2, o2.g0);");
/*fuzzSeed-66366547*/count=1269; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround(Math.pow(( ~ Math.pow(Math.fround(Math.cbrt(Math.fround(Math.imul(y, (x ? x : x))))), ( ~ ( ! x)))), (mathy0((Math.imul((( + (x >>> 0)) >>> 0), ( ~ y)) >>> 0), x) < ( + (Math.fround(Math.atanh(Math.max(Math.hypot(x, y), y))) * ( + ( - mathy1(Math.fround(y), Math.fround(x))))))))); }); testMathyFunction(mathy4, /*MARR*/[0x0ffffffff, 0x0ffffffff, (-1/0), 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, (-1/0), 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, (-1/0), 0x0ffffffff, (-1/0), 0x0ffffffff, (-1/0), 0x0ffffffff, (-1/0), (-1/0), 0x0ffffffff, (-1/0), 0x0ffffffff, (-1/0), 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, (-1/0), (-1/0), (-1/0), 0x0ffffffff, 0x0ffffffff, 0x0ffffffff, (-1/0), (-1/0), (-1/0), 0x0ffffffff, (-1/0), 0x0ffffffff, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0)]); ");
/*fuzzSeed-66366547*/count=1270; tryItOut("print(x);");
/*fuzzSeed-66366547*/count=1271; tryItOut("this.m0.has(p2);");
/*fuzzSeed-66366547*/count=1272; tryItOut("a0[v2] = s1;\nprint(x);\n");
/*fuzzSeed-66366547*/count=1273; tryItOut("mathy0 = (function(x, y) { return Math.hypot((( + ( + Math.atan2(( + y), ( + x)))) | 0), ( + ( + (( + x) ? ( + (Math.imul(( + ( - x)), x) | 0)) : ( + Math.fround(Math.imul(Math.fround(0x07fffffff), Math.fround(( + Math.atan2(Math.fround(-0x0ffffffff), Math.fround(x))))))))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 2**53-2, 0x07fffffff, -0x07fffffff, -0x100000001, -1/0, 0/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 0x080000000, -(2**53-2), 1/0, 2**53+2, -0x080000000, 1.7976931348623157e308, Math.PI, 0x100000001, -(2**53+2), 0x100000000, -Number.MAX_VALUE, 0.000000000000001, 0, -0x100000000, Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1, 42, 0x0ffffffff, 0x080000001, -(2**53), -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=1274; tryItOut("g2.m1.get(t0);");
/*fuzzSeed-66366547*/count=1275; tryItOut("\"use strict\"; L: var {} = x, x = x = x, y = this, a = [[1]], dgjlyg, runkva, fvuikl, cqvqyk;print(uneval(m0));");
/*fuzzSeed-66366547*/count=1276; tryItOut("this.i0.send(this.p1);");
/*fuzzSeed-66366547*/count=1277; tryItOut("\"use strict\"; this.zzz.zzz;");
/*fuzzSeed-66366547*/count=1278; tryItOut("v1 = o0.o2.a1.length;");
/*fuzzSeed-66366547*/count=1279; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x100000000, 0, 0x080000001, Math.PI, 0x07fffffff, 1, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 0/0, -0x0ffffffff, -0x07fffffff, 1/0, 2**53, -(2**53), Number.MIN_VALUE, -0x080000000, -0x080000001, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, 1.7976931348623157e308, 0x0ffffffff, -(2**53-2), -0x100000001, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 0x080000000, 42, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1280; tryItOut("mathy5 = (function(x, y) { return Math.fround(( ! (Math.hypot(mathy4((Math.tan(( + Math.abs(( + ( - 1/0))))) >>> 0), (Math.fround(mathy2((y >>> -Number.MIN_SAFE_INTEGER), x)) >>> 0)), Math.fround(Math.sqrt(-0x080000000))) >>> 0))); }); ");
/*fuzzSeed-66366547*/count=1281; tryItOut("/*tLoop*/for (let d of /*MARR*/[(void 0), x, (void 0), (void 0), x, [undefined], [undefined], (void 0), [undefined], (void 0), x, (void 0),  \"use strict\" , [undefined],  \"use strict\" , [undefined], (void 0),  \"use strict\" , [undefined], (void 0), x, x, x, x, x, x, [undefined], x, [undefined], x, x]) { with({d: delete x.x})/*MXX2*/g2.SyntaxError.prototype = f1; }");
/*fuzzSeed-66366547*/count=1282; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.tanh(((Math.imul(y, ( + ((( ! ( + (Math.pow(x, y) >>> y))) >>> 0) >= y))) > Math.fround((Math.fround((( ! (Math.hypot(x, Math.fround(x)) >>> 0)) >>> 0)) ** Math.fround(y)))) | 0)) | 0); }); testMathyFunction(mathy1, [[0], true, '', [], 0.1, (function(){return 0;}), null, '/0/', NaN, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), undefined, -0, '\\0', 1, objectEmulatingUndefined(), (new Number(0)), /0/, (new Boolean(true)), (new String('')), 0, ({toString:function(){return '0';}}), '0', false, (new Boolean(false)), (new Number(-0))]); ");
/*fuzzSeed-66366547*/count=1283; tryItOut("const a2 = Array.prototype.slice.call(a0, NaN, NaN);");
/*fuzzSeed-66366547*/count=1284; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.sqrt(mathy0((y ? ( + Math.min(Number.MAX_VALUE, Math.abs(( ! ( + ( ! ( + y))))))) : (mathy0(x, y) >>> 0)), Math.fround(( + ( + ( + ( + (Math.round((y >>> 0)) >>> 0)))))))); }); ");
/*fuzzSeed-66366547*/count=1285; tryItOut("mathy0 = (function(x, y) { return Math.fround(Math.sinh(Math.fround((Math.max(( + -(2**53+2)), Math.pow(Math.sqrt(x), ((( ~ ((( ! Math.min(x, x)) | 0) | 0)) | 0) >>> 0))) | 0)))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 1/0, Math.PI, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 0x080000001, 0x100000000, -0x080000000, 1.7976931348623157e308, 2**53-2, Number.MAX_VALUE, Number.MIN_VALUE, -0x100000001, 1, 0x100000001, -(2**53-2), -1/0, -(2**53), -0x0ffffffff, -0x100000000, 42, 0x07fffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 0, -0, 2**53, -Number.MAX_VALUE, -0x080000001, -0x07fffffff]); ");
/*fuzzSeed-66366547*/count=1286; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ~ (Math.fround(( ! Math.fround((Math.log2((x >>> 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy5, [-0x100000001, Math.PI, 1, -Number.MIN_VALUE, 0.000000000000001, Number.MAX_VALUE, -0x080000001, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -(2**53-2), 0x100000000, -0x07fffffff, 0/0, -0x080000000, -1/0, 1.7976931348623157e308, 1/0, -(2**53), 0x080000001, 0x100000001, -0x100000000, 2**53-2, 2**53+2, 2**53, -Number.MAX_VALUE, 0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 0x080000000, -0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1287; tryItOut("\"use strict\"; /*RXUB*/var r = o0.r2; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-66366547*/count=1288; tryItOut("h0 + '';");
/*fuzzSeed-66366547*/count=1289; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround(((( + Math.atan((mathy0(( + (Math.fround(y) ? Math.fround(x) : Math.fround((Math.abs(x) | 0)))), y) >>> 0))) + (( + Math.pow((Math.cosh((( ~ ( ~ (x | 0))) ^ (mathy0((-0x0ffffffff | 0), (0x0ffffffff | 0)) | 0))) | 0), (Math.log1p((Math.imul(x, mathy0(y, x)) > 42)) | 0))) >>> 0)) | 0)) !== Math.fround(Math.fround((((y , ( + Math.fround(Math.hypot(Math.fround((((y >>> 0) >>> (0x07fffffff >>> 0)) >>> 0)), Math.fround(x))))) >>> 0) >> Math.atanh(( ~ ((Math.tanh((x | 0)) >>> 0) >> y)))))))); }); testMathyFunction(mathy1, [0, 2**53-2, 0x0ffffffff, 0.000000000000001, 2**53+2, Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), -(2**53+2), -1/0, 0x100000000, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, 42, 0x080000001, -0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, 1, -0x07fffffff, 0x100000001, 0x080000000, 0/0, 2**53, 0x07fffffff, -0x0ffffffff, 1/0, Number.MAX_VALUE, -0x080000001]); ");
/*fuzzSeed-66366547*/count=1290; tryItOut("s2 += s2;");
/*fuzzSeed-66366547*/count=1291; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + (mathy0(mathy2(( + Math.acosh(( + y))), 42), (Math.PI === Math.tanh(x))) ? (Math.atan(mathy1(( + ((x >>> 0) < (x + x))), ( + Math.fround(( ! Math.fround(x)))))) === Math.exp((( ~ x) >>> 0))) : Math.cosh(((Number.MIN_VALUE || ((Math.sign(x) | 0) ? y : ( ~ y))) * ((x >> (x | 0)) | 0))))) ** (mathy2(Math.fround(Math.fround((Math.fround(Math.tan(x)) ** Math.fround(Math.cos(((Math.sqrt(y) | 0) <= (x | 0))))))), Math.pow(Math.atan(Math.fround((mathy1(( + 0), (y | 0)) >>> 0))), ( + ( + (-0x080000001 != y))))) >>> 0)); }); testMathyFunction(mathy3, [0.000000000000001, -0x080000001, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), -(2**53), -0, 1/0, -0x100000001, 0x0ffffffff, Math.PI, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0/0, 2**53, Number.MIN_VALUE, -1/0, 2**53-2, -0x100000000, -Number.MIN_VALUE, -0x0ffffffff, 0, 1, 0x080000001, 0x07fffffff, 42, Number.MAX_VALUE, -(2**53-2), -0x080000000, 0x100000000]); ");
/*fuzzSeed-66366547*/count=1292; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((( + ((Math.round((Math.imul(( ! ( ~ x)), Math.fround((y / x))) >>> 0)) >>> 0) >>> 0)) >>> ((Math.fround((( + ((Math.min(-Number.MAX_SAFE_INTEGER, y) === x) >>> 0)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy1, [0.1, 0, 1, (new Boolean(true)), '0', (function(){return 0;}), (new String('')), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), [], [0], '', false, '\\0', NaN, ({toString:function(){return '0';}}), /0/, undefined, -0, '/0/', (new Number(-0)), null, true, (new Number(0)), ({valueOf:function(){return '0';}}), (new Boolean(false))]); ");
/*fuzzSeed-66366547*/count=1293; tryItOut("for(let c of /*MARR*/[-0x100000001, x, -0x100000001, x, -0xB504F332, -0x100000001, x, -0xB504F332, x, x, -0xB504F332, objectEmulatingUndefined(), -0xB504F332, -0xB504F332, x, -0x100000001, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), -0xB504F332, -0xB504F332, x, -0x100000001, -0xB504F332, -0x100000001, -0x100000001, objectEmulatingUndefined(), x, objectEmulatingUndefined(), -0xB504F332, -0xB504F332, x, x, x, x, x, x, x, x, x, x, x, -0x100000001, -0x100000001, objectEmulatingUndefined(), -0xB504F332, x, -0xB504F332, -0x100000001, -0x100000001, x, x, -0x100000001, objectEmulatingUndefined(), -0x100000001, -0x100000001, x, -0x100000001, -0x100000001, -0x100000001, x, objectEmulatingUndefined(), -0xB504F332, objectEmulatingUndefined(), -0xB504F332, objectEmulatingUndefined(), -0x100000001, x, objectEmulatingUndefined(), objectEmulatingUndefined()]) yield (4277);");
/*fuzzSeed-66366547*/count=1294; tryItOut("var bnqdvt = new SharedArrayBuffer(12); var bnqdvt_0 = new Uint32Array(bnqdvt); var bnqdvt_1 = new Int32Array(bnqdvt); bnqdvt_1[0] = 3; var bnqdvt_2 = new Int16Array(bnqdvt); bnqdvt_2[0] = 27; var bnqdvt_3 = new Int16Array(bnqdvt); print( \"\" );h1.fix = (function() { try { a2 + h2; } catch(e0) { } v2 = 4; return this.t0; });print(new RegExp(\"\\\\b\", \"gi\"));");
/*fuzzSeed-66366547*/count=1295; tryItOut("mathy2 = (function(x, y) { return ((( + (y >> ((y > (Math.atan(Math.pow(Math.fround(x), ( + Math.PI))) >>> 0)) | 0))) == ((Math.atanh(( ~ x)) >>> 0) + (mathy1(( + Math.hypot(((Math.fround((Math.fround(x) !== Math.fround(x))) ? (((2**53-2 >>> 0) * (x >>> 0)) >>> 0) : ( + 1.7976931348623157e308)) | 0), (Math.sin(2**53+2) | 0))), (x | 0)) ? x : Math.imul(( ~ ( + (x & Math.fround(0/0)))), Math.fround(mathy1(Math.hypot((-Number.MIN_VALUE | 0), Math.fround(x)), x)))))) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[ \"use strict\" , objectEmulatingUndefined(), new String('q'),  \"use strict\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), {x:3},  \"use strict\" , {x:3}, objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(),  \"use strict\" , {x:3},  \"use strict\" ,  \"use strict\" ,  \"use strict\" ]); ");
/*fuzzSeed-66366547*/count=1296; tryItOut("o1.a1.unshift(o2.p0);");
/*fuzzSeed-66366547*/count=1297; tryItOut("/*RXUB*/var r = /\\1/gy; var s = \"\\n\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-66366547*/count=1298; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var sqrt = stdlib.Math.sqrt;\n  var floor = stdlib.Math.floor;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -295147905179352830000.0;\n    (Int16ArrayView[0]) = (((+abs(((-((d2)))))) <= (+sqrt(((1152921504606847000.0)))))+((((0xb5a35e8b)) | ((0xf997d6e6) / (0x5f1653bd))) != (~(((-0xf88b6*(i1)))+(((+floor(((-536870913.0))))))))));\n    d0 = (+(1.0/0.0));\n    d0 = (d0);\n    return +((4095.0));\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[Infinity, x, Infinity, new String(''), new String(''), new String(''), null, Infinity, Infinity, new Number(1), x, new Number(1), x, x, Infinity, Infinity, Infinity, Infinity, x, new String(''), new Number(1), new Number(1), Infinity, new String(''), new String(''), new Number(1), x, new String(''), x, new Number(1), null, new String(''), new String(''), Infinity, x, null, x, null, new String(''), new String(''), x, new String(''), Infinity, x, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, Infinity, null, new String(''), new String(''), null, x, new Number(1), new String(''), new Number(1), Infinity, new String(''), null, Infinity, Infinity, null, new Number(1), new Number(1), x, x, new Number(1), new Number(1), Infinity, x, new String(''), new Number(1), new String(''), new Number(1), x, new Number(1), x, x, new String(''), x, new String(''), Infinity, new String(''), Infinity, Infinity, null, Infinity, x, x, new String(''), null, x, Infinity, null, new Number(1), null, null, null, new String(''), new String(''), Infinity, Infinity, x, Infinity, null, Infinity, new Number(1), new String(''), Infinity, null, new String(''), Infinity, null, new String(''), new Number(1), null, new Number(1), new Number(1), new Number(1), null, x, Infinity, Infinity, new String(''), new Number(1), new Number(1), x, new String(''), x]); ");
/*fuzzSeed-66366547*/count=1299; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      {\n        {\n          return ((((Float32ArrayView[(((((i1)) ^ (-0x76d8b*(0x7496e6f0))) <= ( /x/ .unwatch(new String(\"-8\"))))-((((-0x3aaa7*((0x86fc1c6a))) & ((0xb8156b7d)-(0xec5d1a88)-(0x9e23ebc2)))))-(0xf97c0492)) >> 2]))+((((0x4e2c877a)) & ((i1)-(-0x8000000)+(((-0x607736) > (0x36141fd2)) ? (0xf7d2bfaf) : ((0x19e1bc74))))))))|0;\n        }\n      }\n    }\n    switch ((((i1)-((0xb283a7c0) < (0x6ad9383b))) ^ (((0x5674ef80) >= (0x277ecfef))))) {\n      case 1:\n        i1 = ((9.0) >= (+(0.0/0.0)));\n        break;\n      case -2:\n        (Float32ArrayView[(x) >> 2]) = ((+(-1.0/0.0)));\n        break;\n      case 0:\n        d0 = (73786976294838210000.0);\n        break;\n      case -1:\n        i1 = ((((Float64ArrayView[0])) & ((i1)+(i1))));\n      case 0:\n        i1 = (((arguments) = x));\n    }\n    return ((((imul((0xd65b8c04), (i1))|0))))|0;\n  }\n  return f; })(this, {ff: Uint32Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[0x100000001, (void 0), new Number(1.5), 0x100000001, (void 0), (void 0), 1e+81, new Boolean(false), new Boolean(false), 0x100000001, (void 0), new Number(1.5), 1e+81, new Boolean(false), new Number(1.5), 0x100000001, new Boolean(false), (void 0), new Number(1.5), 1e+81, 1e+81, new Number(1.5), 0x100000001]); ");
/*fuzzSeed-66366547*/count=1300; tryItOut("\"use strict\"; let c = x;m1.get(m2);");
/*fuzzSeed-66366547*/count=1301; tryItOut("\"use strict\"; t2[1] = b0;");
/*fuzzSeed-66366547*/count=1302; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=1303; tryItOut("\"use strict\"; g2.v0 + ''\ndelete t1[\"__count__\"];");
/*fuzzSeed-66366547*/count=1304; tryItOut("for (var v of m0) { try { /*infloop*/ for (var y of [,,]) /*bLoop*/for (var ealdyv = 0; ealdyv < 55; ++ealdyv) { if (ealdyv % 24 == 19) { f0(s0); } else { g1 = x; }  }  } catch(e0) { } try { v0 = evalcx(\"x\", g0.g1); } catch(e1) { } (void schedulegc(g0)); }");
/*fuzzSeed-66366547*/count=1305; tryItOut("a2 = Array.prototype.filter.apply(g2.a2, [f2, o2]);");
/*fuzzSeed-66366547*/count=1306; tryItOut("print(RegExp((undefined |= ({a1:1})) === (-3)));");
/*fuzzSeed-66366547*/count=1307; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float32ArrayView[0]) = ((d0));\n    return ((-0x67d39*(0x793043f6)))|0;\n  }\n  return f; })(this, {ff: Root}, new ArrayBuffer(4096)); ");
/*fuzzSeed-66366547*/count=1308; tryItOut("\"use strict\"; { void 0; void readSPSProfilingStack(); }");
/*fuzzSeed-66366547*/count=1309; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(this.s0, g2);");
/*fuzzSeed-66366547*/count=1310; tryItOut("gswqmf([z1], (x--));/*hhh*/function gswqmf(x, x, x, x, c = (new \u000callocationMarker()()), eval, \u3056 = (Math.max(-12, -20)), e,  /x/ , w = window, x, eval, x, b, \u3056, \u3056, b, w = [], NaN, x, eval, x, e, e, NaN, x, x, x = [z1], NaN, x, z, x, x, x, b, x, d = /((?:\\B){4}|(?=^[\\n\\u0F05\\r-\\B]))(?:\\d|[^\\0-\\cE\\cS-T]|[^])|[^]{2,6}{2,3}(?:\u00ad|.)|\\2|($)|${3,}+?/gyi, d = new RegExp(\"(^)\", \"yi\"), z = -27, x, x = 8, NaN = eval, x = -9, w =  /x/g , w, eval = -4, NaN, x = function ([y]) { }, x, x = new RegExp(\"(?!(?![]|.*?))?\", \"im\"), x, c = Math, b = function ([y]) { }, NaN, c, x = [1,,], x, x = x, window, \u3056, a = x, x, c, w, w, x, \u3056, x = false, e, x =  /x/ , x, this.e, x){if((x % 49 == 24)) {o2.f2 = x; } else  if ( '' ) {print([]);print(2); } else throw /(?=\\B\\r)$+{67108865}/ym;}");
/*fuzzSeed-66366547*/count=1311; tryItOut("h2.toString = function(y) { delete h0.defineProperty; };");
/*fuzzSeed-66366547*/count=1312; tryItOut("mathy1 = (function(x, y) { return Math.sinh((((Math.min((((( - Math.imul(y, y)) | 0) * (2**53+2 | 0)) | 0), Math.fround(( - Math.fround(y)))) >>> 0) ? (Math.fround(( + ( - 0x100000001))) >>> 0) : (( + ( + ( + (( + Math.hypot((( ~ Number.MAX_SAFE_INTEGER) >>> 0), 2**53)) | 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0/0, 1.7976931348623157e308, 0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 0x07fffffff, 2**53+2, -0x07fffffff, -1/0, 0x100000001, 0x080000000, 1/0, -0x100000000, -(2**53+2), 2**53-2, 0x100000000, Number.MIN_VALUE, -(2**53), -0x080000001, 0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, -0, -Number.MAX_VALUE, 2**53, -0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001]); ");
/*fuzzSeed-66366547*/count=1313; tryItOut("a2 = new Array;");
/*fuzzSeed-66366547*/count=1314; tryItOut("\"use strict\"; s2 += s0;\nvar xvjnso = new SharedArrayBuffer(8); var xvjnso_0 = new Int32Array(xvjnso); xvjnso_0[0] = -24; v0 = null;\n");
/*fuzzSeed-66366547*/count=1315; tryItOut("\"use strict\"; t1[3] = f1;");
/*fuzzSeed-66366547*/count=1316; tryItOut("");
/*fuzzSeed-66366547*/count=1317; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -262145.0;\n    {\n;    }\n    d3 = (-1.03125);\n    i2 = (0x1f6c0bc7);\n    {\n      d0 = (+(-1.0/0.0));\n    }\n    (Uint32ArrayView[((/*FFI*/ff(((+abs(((1073741824.0))))), ((((0xfcd84f8d)) | ((0xf3c2e481)))), ((~~(257.0))), ((-2097152.0)), ((-1.5474250491067253e+26)), ((-9223372036854776000.0)))|0)+((((0xfc16954c))>>>((0xffffffff)+(0xb53f5a8f))))+((((0xffffffff))>>>((0xffffffff))) < (((0x105d45ab))>>>((-0x580a08c))))) >> 2]) = (((0xfffff*(0x1e21758))>>>((i2))) / (0x646f0c5f));\n    switch ((((-0x3094759)+((0x7080dc6a))) & ((0xe9716a17)-(0x39eebc21)+(0xfa951237)))) {\n      case 0:\n        i2 = (/*FFI*/ff((x), (((+((-2.3611832414348226e+21))))))|0);\n        break;\n      case 1:\n        d3 = (+(1.0/0.0));\n        break;\n    }\n    i2 = (!((0x2c7637db) ? (i2) : (0xd5d18ada)));\n    return (((this)+(((({ get 18(x)\"\\u1A0A\" }))) >= ((590295810358705700000.0) + (d0)))))|0;\n  }\n  return f; })(this, {ff: String.prototype.padStart}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, Math.PI, 2**53, 2**53-2, 2**53+2, -(2**53-2), -Number.MAX_VALUE, -0x0ffffffff, 0x100000001, -0x080000001, 42, 1, -0x100000000, 0.000000000000001, 0x080000001, -0x100000001, -(2**53+2), -1/0, 0/0, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 0x0ffffffff, 0]); ");
/*fuzzSeed-66366547*/count=1318; tryItOut("var ridslp = new ArrayBuffer(8); var ridslp_0 = new Int16Array(ridslp); ridslp_0[0] = 3; s0 += 'x';");
/*fuzzSeed-66366547*/count=1319; tryItOut("Array.prototype.reverse.apply(o0.a0, []);");
/*fuzzSeed-66366547*/count=1320; tryItOut("\"use strict\"; var rcgukc = new SharedArrayBuffer(4); var rcgukc_0 = new Uint8Array(rcgukc); rcgukc_0[0] = 1; var rcgukc_1 = new Uint32Array(rcgukc); rcgukc_1[0] = 562949953421311; var rcgukc_2 = new Uint8Array(rcgukc); print(rcgukc_2[0]); var rcgukc_3 = new Int32Array(rcgukc); rcgukc_3[0] = -22; var rcgukc_4 = new Uint16Array(rcgukc); var rcgukc_5 = new Float32Array(rcgukc); var rcgukc_6 = new Int32Array(rcgukc); rcgukc_6[0] = 20; v2 = NaN;a0.pop();g2.offThreadCompileScript(\"/* no regression tests found */\");( /x/g );print((this.__defineGetter__(\"window\", function(y) { return new RegExp(\"\\u76b2{0,}$|(?=.)*\\\\1+?|\\\\3{4,}\", \"gim\") })));s1 += 'x';g2.offThreadCompileScript(\"OSRExit\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: window, catchTermination: true }));");
/*fuzzSeed-66366547*/count=1321; tryItOut("\"use strict\"; v0 = (t0 instanceof v1);");
/*fuzzSeed-66366547*/count=1322; tryItOut("testMathyFunction(mathy2, [-1/0, 0, 2**53, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, 2**53+2, -0x080000000, -(2**53), Number.MIN_VALUE, -0x080000001, 0x080000001, 0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -0x100000001, -Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, -(2**53+2), 0x07fffffff, Number.MAX_VALUE, -0x07fffffff, -0, 1/0, 0.000000000000001, 42, 0x100000001, 0x0ffffffff, Math.PI, 0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-66366547*/count=1323; tryItOut("\"use strict\"; v1.toString = (function(j) { if (j) { try { this.a0[yield (4277)] = arguments; } catch(e0) { } try { t1[10] = -32769; } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(s2, g0); } catch(e2) { } /*RXUB*/var r = r2; var s = \"\"; print(r.exec(s));  } else { s2 += s2; } });");
/*fuzzSeed-66366547*/count=1324; tryItOut("mathy4 = (function(x, y) { return mathy3(( - Math.min((( - (y, window | 0)) >>> (y | 0)), (( + y) / (( - ( + ((Math.imul((1.7976931348623157e308 >>> 0), (x >>> 0)) >>> 0) & Math.expm1(x)))) | 0)))), ((((-0 | 0) === Math.fround(mathy3(Math.fround(y), Math.fround(mathy0(Math.hypot(( + x), y), Math.acosh(y)))))) | 0) !== (( + Math.fround((( - (Math.imul((Math.pow((2**53 | 0), (y >>> 0)) >>> 0), Math.fround(y)) | 0)) | 0))) | 0))); }); testMathyFunction(mathy4, /*MARR*/[new Boolean(true)]); ");
/*fuzzSeed-66366547*/count=1325; tryItOut("a1 = Array.prototype.slice.call(a0, -2, NaN, o2, e1, g2, g2.f0, a0);print(x);");
/*fuzzSeed-66366547*/count=1326; tryItOut("/*tLoop*/for (let d of /*MARR*/[x, x,  /x/ , x, x, x, function(){}, x, x, x, x, x, function(){}, x, x, function(){},  /x/ ,  /x/ , x, x, x,  /x/ , x, x, x, function(){}, x,  /x/ ,  /x/ , function(){}, x,  /x/ , function(){}, x,  /x/ , x, x, x, x, function(){}, x,  /x/ , x, x,  /x/ ,  /x/ , x,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , x,  /x/ ,  /x/ , x, x, x, x, function(){}, x, function(){},  /x/ , function(){}, x, x, x, x, function(){}, x, x, function(){}, function(){}, x, function(){}, x, x, function(){}, function(){}, function(){},  /x/ , function(){},  /x/ ,  /x/ , x, x, x, x, function(){}, x, x, x, function(){}, x, x,  /x/ , function(){}, x, function(){}, function(){},  /x/ ]) { v2 = undefined; }");
/*fuzzSeed-66366547*/count=1327; tryItOut("v1 = (h0 instanceof s2);");
/*fuzzSeed-66366547*/count=1328; tryItOut("var wpyyjd = new ArrayBuffer(12); var wpyyjd_0 = new Uint16Array(wpyyjd); var wpyyjd_1 = new Int16Array(wpyyjd); var wpyyjd_2 = new Uint8Array(wpyyjd); wpyyjd_2[0] = 3; print(wpyyjd_0[6]);print(wpyyjd_1[3]);");
/*fuzzSeed-66366547*/count=1329; tryItOut("\"use strict\"; for (var v of o2.i0) { g0.v0 = new Number(e0); }");
/*fuzzSeed-66366547*/count=1330; tryItOut("L:with({y: x})(\"\\uF2BF\");print(y);");
/*fuzzSeed-66366547*/count=1331; tryItOut("testMathyFunction(mathy3, [0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), -0x100000001, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53-2, 0.000000000000001, 0x080000000, 42, 0/0, -0x0ffffffff, 2**53, 0x080000001, -0x080000000, 1.7976931348623157e308, 0x100000000, 2**53+2, -Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, 1/0, 1, Number.MAX_VALUE, -1/0, 0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-66366547*/count=1332; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1.7976931348623157e308, -(2**53+2), -(2**53-2), -0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001, -0x080000001, -0x100000000, -0x100000001, -0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, 0x100000000, 0x080000001, 2**53, 1, 0x0ffffffff, 1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, Math.PI, -0, 2**53+2, -1/0, 0, -(2**53), 2**53-2]); ");
/*fuzzSeed-66366547*/count=1333; tryItOut("(d =  \"\" );");
/*fuzzSeed-66366547*/count=1334; tryItOut("\"use strict\"; const d = DataView(x, ((arguments.callee.arguments)) = ((function factorial(azfjvs) { ; if (azfjvs == 0) { ; return 1; } e1.delete(i0);; return azfjvs * factorial(azfjvs - 1);  })(1663)));/*hhh*/function clsbkp(eval, e){a0.shift();}/*iii*/print(this);");
/*fuzzSeed-66366547*/count=1335; tryItOut("mathy5 = (function(x, y) { return (Math.fround((((x || ( + ( ! ( - Number.MAX_VALUE)))) | 0) <= ((Math.sinh((y | 0)) >>> 0) ? ( + Math.hypot(Math.fround(( + Number.MIN_VALUE)), (((y >>> 0) & (y | 0)) >>> 0))) : (Math.fround(Math.max(y, x)) << mathy4(y, -1/0))))) ? (Math.min(((Math.clz32((( + Math.pow(((y >>> 0) & y), y)) / ((( + x) << (2**53 > x)) >>> 0))) | 0) >>> 0), (( ! ( + x)) >>> 0)) >>> 0) : Math.atan2((Math.abs(x) | 0), Math.cosh(( + mathy3(( + (mathy3((x >>> 0), Math.fround(y)) >>> 0)), ( + ( + (( + (y % ( + y))) & ( + x))))))))); }); testMathyFunction(mathy5, [0x100000001, -0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -(2**53), 0x07fffffff, 2**53, -0x100000000, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -0x080000001, -(2**53-2), Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), 2**53-2, 1, -0, -1/0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, 0x080000001, 0, 0x100000000, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-66366547*/count=1336; tryItOut("\"use strict\"; ((yield /(?:\\cA\\1^*?)/));");
/*fuzzSeed-66366547*/count=1337; tryItOut("print(Math.ceil(/(?:(\\u00Af)\\s{1,})*|(?:.)(?=[^])\\B+?(?=(?=$)?[^\\r-\\0-\u00f8\\s]|\\B*){4,}/g +  '' ));\nthis.m0 = new Map(e1);\n");
/*fuzzSeed-66366547*/count=1338; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=1339; tryItOut("testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, -(2**53+2), 2**53, 1, 1.7976931348623157e308, -0x080000000, 0/0, -(2**53-2), 42, Math.PI, 0.000000000000001, 0x100000000, -1/0, -0x100000000, 0x080000001, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, 2**53+2, Number.MAX_VALUE, 0x100000001, 1/0, -0, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, 0, -0x080000001]); ");
/*fuzzSeed-66366547*/count=1340; tryItOut("var lbbnyj = new ArrayBuffer(0); var lbbnyj_0 = new Uint8ClampedArray(lbbnyj); lbbnyj_0[0] = 1; this.v1 = (m1 instanceof h0);;print(intern(28));return;");
/*fuzzSeed-66366547*/count=1341; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ ((Math.sign(((Math.fround(y) != Math.fround(-0)) | 0)) | 0) / ( ! ( ~ ( + mathy0(Number.MIN_SAFE_INTEGER, ( + x))))))); }); testMathyFunction(mathy2, [-0x07fffffff, -0x080000000, -0, -0x080000001, 0x100000001, -0x100000000, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, 0x100000000, 1.7976931348623157e308, -(2**53), 2**53, 2**53+2, 0x0ffffffff, 0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, 0/0, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, -1/0, 2**53-2, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-66366547*/count=1342; tryItOut("const g1.v2 = evalcx(\"/* no regression tests found */\", g2);");
/*fuzzSeed-66366547*/count=1343; tryItOut("mathy1 = (function(x, y) { return Math.max(Math.cbrt(Math.fround(( + Math.fround((mathy0((x | 0), x) - ((y - y) | 0)))))), (( + Math.max(Math.log1p((y >>> 0)), ( + Math.max(Math.sign((y * -(2**53-2))), ( + ( + ((-(2**53) >>> 0) << Math.acos(Math.fround((((x , x) >>> 0) == x)))))))))) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), -0x080000001, -0x080000001, -0x080000001, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x080000001, objectEmulatingUndefined(), -0x080000001, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x080000001, -0x080000001, -0x080000001, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x080000001, -0x080000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x080000001, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-66366547*/count=1344; tryItOut("\"use strict\"; /*RXUB*/var r = /\\B/gi; var s = \" \"; print(s.match(r)); ");
/*fuzzSeed-66366547*/count=1345; tryItOut("\"use strict\"; ");
/*fuzzSeed-66366547*/count=1346; tryItOut("\"use asm\"; /*RXUB*/var r = /\\2{2}(?!(?=(?:.)){0}(?!..?)(?!^{3,}|.)+.|(?![^]))|(?:(\\D){3,7}|[^]{4194305}|(?:\\S){0,1})/gym; var s = \"\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6aaaaaa\\n\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\u00e6\\n\\u00e6\\u00e6\\u00e6\"; print(r.test(s)); \nconst v0 = new Number(0);\n\nx = i1;\n");
/*fuzzSeed-66366547*/count=1347; tryItOut("/* no regression tests found */");
/*fuzzSeed-66366547*/count=1348; tryItOut("/*bLoop*/for (hwsssb = 0; hwsssb < 45; ++hwsssb) { if (hwsssb % 18 == 3) { t2.valueOf = o1.f2; } else { /*MXX1*/o1 = this.g1.Date.prototype.setDate; }  } ");
/*fuzzSeed-66366547*/count=1349; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=1350; tryItOut("mathy5 = (function(x, y) { return ( + (( + ((Math.sin(y) == ( + Math.acos(Math.cosh(((Math.acosh((y | 0)) | 0) == Number.MAX_SAFE_INTEGER))))) >>> 0)) === (( ! Math.pow(Math.fround(( ~ Math.fround(( ~ (x | 0))))), ( + Math.atanh(( ~ (Math.atan2(2**53+2, (y >>> 0)) >>> 0)))))) ** ( + ( + Math.min(( + (( ~ (( + Math.exp((x >>> 0))) >>> 0)) >>> 0)), ( + ( ~ Math.fround(Math.asinh(x)))))))))); }); testMathyFunction(mathy5, /*MARR*/[ /x/g , new Boolean(true)]); ");
/*fuzzSeed-66366547*/count=1351; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?!((?=\\3){3,5}))?)/gy; var s = Math.pow(this.__defineGetter__(\"c\", Object.prototype.__defineGetter__), -127188184); print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-66366547*/count=1352; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=1353; tryItOut("testMathyFunction(mathy5, [0, -0x100000000, -0x080000000, 2**53, 0/0, -0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 1, 0x100000000, Number.MAX_VALUE, 2**53-2, -(2**53-2), Number.MIN_VALUE, -1/0, -0x100000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, -Number.MAX_VALUE, 0x080000001, 0x07fffffff, -0x07fffffff, 0x0ffffffff, Math.PI, 0x100000001, 2**53+2, 1/0, -0x0ffffffff, -0x080000001, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-66366547*/count=1354; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(( ! Math.fround((((Math.fround(Math.hypot(Math.max(Math.atan2(Math.imul((x >>> 0), y), (Math.max(y, ((y >>> 0) === ( + x))) >>> 0)), x), ( + Math.min(Math.max(( + Math.exp((x >>> 0))), Math.imul(x, y)), x)))) | 0) % ((Math.pow((Math.fround(Math.imul(y, x)) >>> 0), (x >>> 0)) >>> 0) | 0)) | 0)))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0x100000001, Math.PI, 2**53-2, 0/0, 2**53+2, 42, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 0.000000000000001, 1, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, -(2**53-2), 0x100000001, -(2**53), 0, Number.MIN_SAFE_INTEGER, 2**53, -Number.MAX_VALUE, -0x080000001, -0x0ffffffff, 0x080000000, -1/0, Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, -0x100000000, 0x100000000, 1/0, -Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, -0x07fffffff]); ");
/*fuzzSeed-66366547*/count=1355; tryItOut("a1 = [];");
/*fuzzSeed-66366547*/count=1356; tryItOut("t2[15] = x+=(yield ((function factorial_tail(snsaik, czgtut) { ; if (snsaik == 0) { ; return czgtut; } ; return factorial_tail(snsaik - 1, czgtut * snsaik); yield; })(19877, 1))(, (4277).toUpperCase()));");
/*fuzzSeed-66366547*/count=1357; tryItOut("mathy3 = (function(x, y) { return mathy1((( ! Math.pow((((Math.tan(( + x)) | 0) % Math.fround(x)) >>> 0), (Math.imul(Math.fround((Math.fround(-0x100000001) >> x)), -(2**53)) >>> 0))) >>> 0), ( + (Math.hypot(x, (Math.imul(Math.imul(Math.fround(mathy2(Math.fround(y), Math.fround(0x100000000))), 0), (Math.abs(1.7976931348623157e308) >>> 0)) >>> 0)) >= Math.sqrt(-(2**53+2))))); }); testMathyFunction(mathy3, [0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53-2, -(2**53+2), 0, Number.MIN_VALUE, -(2**53-2), 0.000000000000001, -1/0, 0x080000000, 0x07fffffff, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, -(2**53), 1/0, -0, -0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x100000001, 2**53, -0x0ffffffff, Number.MAX_VALUE, 42, -0x100000000, 1, 2**53+2]); ");
/*fuzzSeed-66366547*/count=1358; tryItOut("print(x);");
/*fuzzSeed-66366547*/count=1359; tryItOut("\"use strict\"; Object.defineProperty(this, \"t1\", { configurable: eval(\"/^+/gyi\"), enumerable: false,  get: function() {  return new Uint8ClampedArray(new RegExp(\"(?=[^]{3,})\", \"gi\")); } });");
/*fuzzSeed-66366547*/count=1360; tryItOut("Object.defineProperty(this, \"v0\", { configurable: false, enumerable: x += new Object.prototype.__defineSetter__( \"\" ).unwatch(\"toSource\"),  get: function() {  return g2.runOffThreadScript(); } });");
/*fuzzSeed-66366547*/count=1361; tryItOut("Array.prototype.unshift.apply(a1, [e2, h1, a1, o2.a0, i0, m2, p2, i1]);");
/*fuzzSeed-66366547*/count=1362; tryItOut("(new TypeError());");
/*fuzzSeed-66366547*/count=1363; tryItOut("throw [[1]];t1.set(a0, ({valueOf: function() { m1.has(a1);return 10; }}));");
/*fuzzSeed-66366547*/count=1364; tryItOut("\"use asm\"; let(z) { with({}) let(iwjupn, y, fboqmg, x, e) { selectforgc(o2);}}");
/*fuzzSeed-66366547*/count=1365; tryItOut("/*ADP-3*/Object.defineProperty(a0, v2, { configurable: false, enumerable: true, writable: true, value: o0.g2 });");
/*fuzzSeed-66366547*/count=1366; tryItOut("/*oLoop*/for (var rofjbk = 0; rofjbk < 107; ++rofjbk) { /* no regression tests found */ } ");
/*fuzzSeed-66366547*/count=1367; tryItOut("\"use strict\"; for (var p in i0) { try { s2 = s1.charAt(((void options('strict')))); } catch(e0) { } try { e1.add(m0); } catch(e1) { } s2 += s2; }");
/*fuzzSeed-66366547*/count=1368; tryItOut("mathy0 = (function(x, y) { return ( - Math.round((( ! -0x100000001) || ((Math.cbrt(( + 2**53+2)) >>> 0) | 0)))); }); testMathyFunction(mathy0, [0, 0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, -0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, 0x080000000, -0x07fffffff, -(2**53-2), Number.MAX_VALUE, -0x080000000, -1/0, 0x0ffffffff, 0/0, -Number.MIN_VALUE, 2**53+2, 1, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), -0x100000000, Math.PI, -(2**53), -0x080000001, 2**53, 1.7976931348623157e308, 42, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=1369; tryItOut("h2.toString = (function() { try { this.t1[15] = s1; } catch(e0) { } try { this.b2.toString = (function() { try { p2.valueOf = (function() { for (var j=0;j<3;++j) { f1(j%2==0); } }); } catch(e0) { } ; return g1; }); } catch(e1) { } this.h1.set = f0; return t1; });");
/*fuzzSeed-66366547*/count=1370; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (((( + ((Math.atanh(( + (Math.log1p(((((((x | 0) >>> y) | 0) % (Math.atanh(Math.acosh(( + y))) | 0)) | 0) >>> 0)) >>> 0))) | 0) >> ( ~ Math.max(x, y)))) >>> 0) | (Math.ceil(Math.imul(( ! Math.cos(x)), y)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), Math.PI, -0x080000001, 0/0, 0.000000000000001, 0, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53), -0x0ffffffff, -0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, 0x100000000, -0x100000000, 2**53+2, Number.MIN_VALUE, 42, -Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, 1/0, 1, -1/0, 2**53, -0, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000000]); ");
/*fuzzSeed-66366547*/count=1371; tryItOut("{a1 = m1.get(g1.f1); }");
/*fuzzSeed-66366547*/count=1372; tryItOut("mathy3 = (function(x, y) { return Math.fround((( - (((( ~ y) / (Math.sinh(0x080000000) >>> 0)) , y) >>> 0)) ? Math.fround(Math.max(Math.fround(Math.imul(( + mathy2(( + ( + (((x >>> 0) % (y >>> 0)) >>> 0))), ( + (Math.pow(((Math.PI & Math.fround(-(2**53+2))) | 0), (2**53 | 0)) | 0)))), (( + (( + -0x07fffffff) <= Math.fround(0x080000001))) >>> 0))), Math.acos(Math.fround(Math.exp(Math.pow(0x080000001, x)))))) : Math.asin(Math.atan2(( + y), Math.fround(( ~ Math.fround((-0x0ffffffff !== Math.max(y, y))))))))); }); testMathyFunction(mathy3, [2**53-2, 0x080000001, 0/0, 42, -0, 0x100000000, -Number.MAX_VALUE, -0x100000001, -0x080000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, -(2**53), -(2**53+2), Math.PI, -1/0, 0x07fffffff, -0x100000000, Number.MAX_VALUE, 0, 0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1/0, 1, 2**53+2, -0x080000001, 1.7976931348623157e308, -(2**53-2), 2**53, 0.000000000000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=1373; tryItOut("\"use strict\"; \"use asm\"; v1 + this.h0;");
/*fuzzSeed-66366547*/count=1374; tryItOut("print(x);");
/*fuzzSeed-66366547*/count=1375; tryItOut("for (var p in o1) { try { e2.add(o1); } catch(e0) { } try { Array.prototype.push.call(a2, o1, ((runOffThreadScript).call('fafafa'.replace(/a/g, /(?=[\\u00f4]|((?!(?!\\B))))/),  \"\" ))); } catch(e1) { } s1.__iterator__ = (function() { try { v0 = evalcx(\"\\\"use strict\\\"; (void shapeOf(this));\", g2); } catch(e0) { } try { e1.has(o0); } catch(e1) { } try { Array.prototype.push.call(a0, o0); } catch(e2) { } print(uneval(f2)); return t0; }); }");
/*fuzzSeed-66366547*/count=1376; tryItOut("\"use strict\"; print(-22);( \"\" );");
/*fuzzSeed-66366547*/count=1377; tryItOut("L:while((undefined <<= x) && 0)selectforgc(o0);");
/*fuzzSeed-66366547*/count=1378; tryItOut("(this);");
/*fuzzSeed-66366547*/count=1379; tryItOut("print(o0);\nprint(x);\n");
/*fuzzSeed-66366547*/count=1380; tryItOut(";");
/*fuzzSeed-66366547*/count=1381; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.trunc((Math.atan2((mathy0(((Math.pow(x, (mathy3((y < ( + x)), y) | 0)) | 0) >>> 0), ( ! ( + -0))) | 0), ( + mathy2(( + Math.fround((( + mathy2(Math.max(x, (Math.atan(y) >>> 0)), ( + Math.log10(( + x))))) >> Math.fround(( ! ((mathy4(y, (-0x100000000 >>> 0)) >>> 0) | 0)))))), (((( ~ (Math.fround((-0x0ffffffff < (x >>> 0))) >>> 0)) >>> 0) > (( ~ x) | 0)) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000000, -1/0, -0x080000001, 1, 0/0, 2**53-2, -(2**53), 0x100000000, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, 0x100000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x080000000, -0, Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 1/0, 0, 0x07fffffff, 1.7976931348623157e308, 0.000000000000001, 42, 0x0ffffffff, 2**53, -(2**53-2), -Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_VALUE, 0x080000001, -0x07fffffff]); ");
/*fuzzSeed-66366547*/count=1382; tryItOut("\"use strict\"; function f2(s2)  { yield  ''  } ");
/*fuzzSeed-66366547*/count=1383; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -1099511627776.0;\n    {\n      {\n        d2 = (1073741825.0);\n      }\n    }\n    d2 = (+(-1.0/0.0));\n    {\n;    }\n    {\n      {\n        (Int32ArrayView[((((((0xfad070fd) ? (0xd0405852) : (0x812d884c))) ^ (((((-0x8000000)) | ((0x357d0213)))))))) >> 2]) = ((i1)+(0xfc2301ce));\n      }\n    }\n    return +((67108865.0));\n  }\n  return f; })(this, {ff: String.prototype.toLocaleLowerCase}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[-Infinity, -Infinity, -Infinity, -Infinity, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), -Infinity, (0/0), -Infinity, -Infinity, -Infinity, (0/0), -Infinity, -Infinity, (0/0), (0/0), -Infinity, (0/0), -Infinity, (0/0), -Infinity, -Infinity, (0/0), -Infinity, -Infinity, (0/0), -Infinity, -Infinity, -Infinity, (0/0), -Infinity, -Infinity, (0/0), (0/0), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, (0/0), (0/0), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, (0/0), (0/0), (0/0), -Infinity, -Infinity, -Infinity, (0/0), (0/0), -Infinity, -Infinity, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), -Infinity, (0/0), (0/0), (0/0), -Infinity, -Infinity, (0/0), (0/0), -Infinity, -Infinity, (0/0), (0/0), -Infinity, -Infinity, (0/0), (0/0), (0/0), -Infinity, -Infinity, -Infinity, -Infinity, (0/0), -Infinity, -Infinity, (0/0)]); ");
/*fuzzSeed-66366547*/count=1384; tryItOut("\"use strict\"; s0 += 'x';print(/*MARR*/[new Number(1), new Number(1), (-1/0), new Number(1), (-1/0), new Number(1), (-1/0), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (-1/0), new Number(1), (-1/0), (-1/0), new Number(1), new Number(1), new Number(1), (-1/0), (-1/0), new Number(1), (-1/0), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (-1/0), new Number(1), (-1/0), new Number(1), (-1/0), new Number(1), new Number(1), (-1/0), new Number(1), new Number(1), new Number(1), new Number(1), (-1/0), new Number(1), (-1/0), new Number(1), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Number(1), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new Number(1), (-1/0), (-1/0), (-1/0), new Number(1), new Number(1), (-1/0), (-1/0)].map.__defineGetter__(\"x\", RegExp.prototype.test));this.a2.push(o1.h1);");
/*fuzzSeed-66366547*/count=1385; tryItOut("i1.next();function z(\u3056 = (/*UUV2*/(d.UTC = d.then)), ...\u3056)\"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    d1 = (1.125);\n    return (((i3)*0x213d))|0;\n  }\n  return f;h0.fix = f2;b0 = new SharedArrayBuffer(104);");
/*fuzzSeed-66366547*/count=1386; tryItOut("\"use strict\"; /*infloop*/for(let arguments in \"\\u1061\") a2 = a2.slice(-5, NaN);");
/*fuzzSeed-66366547*/count=1387; tryItOut("\"use strict\"; /*FARR*/[x, ...[], null, ...[], , , -18, ...[], new RegExp(\"((?:\\\\b|^\\\\uECdD+)|[^]|[^]{1,1})\\\\B\", \"\"), , ...[], \"\\uFFFA\", , this,  \"\" , , -2, 18].sort((function(x, y) { \"use strict\"; return x; }));");
/*fuzzSeed-66366547*/count=1388; tryItOut("\"use strict\"; /*vLoop*/for (lzbegy = 0; lzbegy < 52; ++lzbegy) { d = lzbegy; this.g2 = this; } ");
/*fuzzSeed-66366547*/count=1389; tryItOut("/*infloop*/for(((function factorial(aahgzo) { ; if (aahgzo == 0) { ; return 1; } ; return aahgzo * factorial(aahgzo - 1);  })(61297)); (\"\\uFE01\".__defineSetter__(\"c\", (({/*TOODEEP*/})).bind)); (a = Math.hypot(-29, Float64Array())) |= x) /* no regression tests found */");
/*fuzzSeed-66366547*/count=1390; tryItOut("/*vLoop*/for (zziyxa = 0; zziyxa < 122; ++zziyxa) { let c = zziyxa; L:for(var b in allocationMarker()) {v0 + ''; } } ");
/*fuzzSeed-66366547*/count=1391; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + mathy1(((Math.min(0x080000000, ( + ((y >>> 0) === y))) | 0) ? ( ~ ( ! ( + Math.atan2(y, mathy3(y, y))))) : (( ! mathy1(( - ( + 0x0ffffffff)), ( + Math.min((x >>> 0), ( + -0x07fffffff))))) | 0)), Math.fround(Math.imul((( - (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0), ( + (( + 2**53+2) | ( + ( ! Math.ceil(( + y)))))))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), -0x0ffffffff, 0/0, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, -(2**53+2), Math.PI, 2**53, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 42, -0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, -(2**53), -0, -0x080000001, 0x080000000, 0x080000001, 1/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 0.000000000000001, 1, 0x100000000, -1/0, -0x100000001, -0x100000000, 2**53+2, -Number.MIN_VALUE]); ");
/*fuzzSeed-66366547*/count=1392; tryItOut("Array.prototype.reverse.call(g2.g0.a2, t0);");
/*fuzzSeed-66366547*/count=1393; tryItOut("\"use strict\"; Array.prototype.sort.call(a0, (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) { var r0 = a0 * a1; var r1 = a12 * 4; var r2 = 9 + 5; var r3 = r2 / a6; a7 = a4 ^ a2; var r4 = a11 % a8; var r5 = a4 | r2; var r6 = x * a11; a7 = 2 / 1; var r7 = r1 * 6; var r8 = a0 / a12; var r9 = a10 | a7; var r10 = a1 % 8; var r11 = 1 & 2; var r12 = x % 3; print(r6); var r13 = r8 & 5; var r14 = a11 % r12; a7 = r6 / a7; var r15 = 9 + a3; var r16 = r5 + 9; var r17 = r15 % a11; var r18 = a6 % r2; r6 = r0 - 8; var r19 = 1 % a3; var r20 = r11 - 6; var r21 = 1 | a12; a7 = a7 - r11; var r22 = 7 ^ a0; r1 = a0 % 4; var r23 = 7 & a9; var r24 = 2 & a5; var r25 = 9 - 7; var r26 = r24 - 3; var r27 = 0 + r9; var r28 = 0 & a3; var r29 = 6 - r27; r20 = 4 ^ r18; r6 = 5 & 5; var r30 = a11 | a9; var r31 = r13 ^ 5; var r32 = r1 % 3; var r33 = r2 - 5; var r34 = r9 * r13; r1 = r1 * a7; var r35 = r4 ^ 9; r5 = r31 * 4; var r36 = r10 - 2; var r37 = a4 + 4; a10 = 0 / 9; var r38 = r13 | 6; var r39 = r23 + r8; a10 = r15 & r25; r13 = 9 - r8; return a7; }));");
/*fuzzSeed-66366547*/count=1394; tryItOut("");
/*fuzzSeed-66366547*/count=1395; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (-7.737125245533627e+25);\n    }\n    return +((+pow(((-(((x) ? (-140737488355329.0) : (576460752303423500.0))))), ((Float64ArrayView[(((-((0xfdc406ac))) >> ((new /*FARR*/[].filter(decodeURI)()))) % ((0x3810*(i1)) ^ (((-4503599627370497.0) >= (1025.0))-((0x2d4c2e57) < (0x3d3d58d9))))) >> 3])))));\n    /*FFI*/ff(((d0)), ((d0)), ((-0x8000000)), ((((0xf8786988)) >> ((0xffffffff)-(0x1d5d0666)-(0xd88da9e7)))), ((((!(-0x69a822c))) << ((0xfe29117e)+(0xffffffff)))), ((0x5b085742)), ((d0)), ((-1099511627777.0)), ((-549755813889.0)));\n    i1 = (((((-1.0))-(/*FFI*/ff(((2199023255551.0)), ((((33554431.0)) / ((4.835703278458517e+24)))), ((1.5474250491067253e+26)), ((-549755813888.0)), ((-576460752303423500.0)), ((3.8685626227668134e+25)))|0)+(!((~((0xffbfc109))) != (((0x2feaee14)) | ((0xffffffff)))))) & ((i1))) >= ((((((0xfeff892c)+(0x6c23b349)) | ((-0x8000000)-(0xfecb806c))))-(i1)-(i1)) << ((Int16ArrayView[0]))));\n    return +((1.0));\n  }\n  return f; })(this, {ff: Array.prototype.splice}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [(new Boolean(true)), '\\0', '0', [0], (new Number(0)), 0.1, true, (function(){return 0;}), undefined, '/0/', null, ({valueOf:function(){return '0';}}), 1, (new String('')), '', -0, NaN, ({toString:function(){return '0';}}), false, 0, (new Boolean(false)), [], (new Number(-0)), /0/, ({valueOf:function(){return 0;}}), objectEmulatingUndefined()]); ");
/*fuzzSeed-66366547*/count=1396; tryItOut("mathy0 = (function(x, y) { return ( + Math.hypot((Math.log10(Math.fround(( ~ ( ! (Math.fround(( - Math.pow(( + x), x))) >>> 0))))) >>> 0), ( + ( ~ (((((( + Math.acos(( + ( + (x >>> 0))))) | 0) == ((-(2**53-2) + Math.fround((((x | 0) < y) >>> 0))) | 0)) | 0) | 0) - -Number.MIN_SAFE_INTEGER))))); }); testMathyFunction(mathy0, [-1/0, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -0x0ffffffff, -0x080000000, 0x100000000, Number.MIN_VALUE, -0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0/0, -0, -(2**53), 0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, 0, 0x100000001, 2**53+2, 0x080000001, 0x07fffffff, 0.000000000000001, -0x100000000, 0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53-2), 2**53-2, -Number.MIN_VALUE, 2**53, 1/0, 1]); ");
/*fuzzSeed-66366547*/count=1397; tryItOut("/*RXUB*/var r = r2; var s = s0; print(s.match(r)); ");
/*fuzzSeed-66366547*/count=1398; tryItOut("g0.offThreadCompileScript(\"testMathyFunction(mathy5, [[0], -0, '', [], (new Number(0)), (function(){return 0;}), 0, 1, ({toString:function(){return '0';}}), (new Boolean(true)), '0', (new String('')), 0.1, (new Number(-0)), (new Boolean(false)), '/0/', true, false, NaN, '\\\\0', objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), /0/, undefined, null, ({valueOf:function(){return '0';}})]); \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 != 1), noScriptRval: new RegExp(\"\\\\3\", \"gy\"), sourceIsLazy: true, catchTermination: true, elementAttributeName: this.o2.s0 }));\nprint(x);\nconst a = 15;");
/*fuzzSeed-66366547*/count=1399; tryItOut("mathy0 = (function(x, y) { return ((Math.hypot(Math.acosh(((Math.imul(( ! Math.fround((-0 ? Math.fround(-0) : Math.fround(0x100000001)))), y) , -0x080000001) >>> 0)), Math.hypot(( + (Math.fround(Math.pow(y, Math.fround(Math.fround(( - 0x080000001))))) >= y)), ( + ( + ( + ( ~ 0x080000000)))))) >>> 0) % (Math.tan(((Math.abs((Math.abs((Math.fround((Math.fround(y) === ( + x))) >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-0, -(2**53+2), 2**53-2, 0x080000001, 1, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, -0x0ffffffff, -(2**53-2), Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, Math.PI, -(2**53), 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, 1.7976931348623157e308, 0, -0x080000001, 0/0, Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, 0x100000001, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, 42, 0x07fffffff, -0x07fffffff, 2**53]); ");
/*fuzzSeed-66366547*/count=1400; tryItOut("\"use strict\"; g0.v0 = g0.eval(\"(makeFinalizeObserver('nursery'))\");");
/*fuzzSeed-66366547*/count=1401; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=1402; tryItOut("v1 = -Infinity;");
/*fuzzSeed-66366547*/count=1403; tryItOut("print(('fafafa'.replace(/a/g, Map.prototype.entries)));/*MXX1*/o2 = g2.WeakMap.prototype;\na2[6] = \"\\u0EC5\";\n");
/*fuzzSeed-66366547*/count=1404; tryItOut("\"use strict\"; \"use asm\"; this.h2.__proto__ = a2;");
/*fuzzSeed-66366547*/count=1405; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((Float64ArrayView[(((0x0) < (0xf793c385))*0xfffff) >> 3]));\n  }\n  return f; })(this, {ff: Element}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x100000001, 0, -0, -Number.MIN_VALUE, 1/0, 1.7976931348623157e308, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 2**53, 42, -(2**53), -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, 2**53+2, 0x080000000, -1/0, 0.000000000000001, -0x0ffffffff, -0x07fffffff, 2**53-2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, 0/0, -0x080000001, Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-66366547*/count=1406; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.log1p(Math.min(( + Math.sinh(( + x))), y)) << Math.fround(mathy1(Math.fround(( ~ Math.fround(x))), (Math.tan((x | 0)) | 0)))); }); testMathyFunction(mathy4, [Math.PI, 1/0, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 2**53, Number.MAX_VALUE, -0x0ffffffff, 0x07fffffff, -0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, 0.000000000000001, -0x07fffffff, 2**53-2, 0/0, 42, -0x100000001, -0x080000000, -(2**53+2), 0x080000000, -0x100000000, 0x0ffffffff, 0x100000000, 0, -(2**53), 2**53+2, Number.MIN_VALUE, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1407; tryItOut("g2 = g2.t1[5];");
/*fuzzSeed-66366547*/count=1408; tryItOut("/* no regression tests found */\n/*MXX3*/g0.Proxy.name = g2.g1.Proxy.name;\n");
/*fuzzSeed-66366547*/count=1409; tryItOut("v1 = Object.prototype.isPrototypeOf.call(g2.i2, f0);");
/*fuzzSeed-66366547*/count=1410; tryItOut("mathy1 = (function(x, y) { return Math.hypot((Math.fround(Math.atan2(Math.fround(Number.MIN_SAFE_INTEGER), Math.fround(( - x)))) || (( ~ (Math.atan2(( ! Math.atan2(2**53, ( + x))), x) >>> 0)) >>> 0)), ( ~ (Math.max(Math.expm1(y), (Math.sqrt(y) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-66366547*/count=1411; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.hypot(Math.fround(( - ( + ((( + Math.atan2(( ~ y), y)) >>> 0) && Math.fround((( - x) < Math.fround((mathy0(x, x) | 0)))))))), (((Math.acos(Math.fround(mathy0(Math.fround(( + (( + x) ? ( + x) : (x | 0)))), Math.fround((Math.min(Math.fround(x), ( + (Math.imul((x >>> 0), (( + Math.ceil(( + x))) | 0)) >>> 0))) | 0))))) * Math.sinh(((1.7976931348623157e308 >>> 0) % y))) >>> 0) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[x, x, (-1/0), (-1/0), (-1/0), x, x, x, (-1/0), (-1/0), (-1/0), (-1/0), x, (-1/0), x, x, (-1/0), (-1/0), x, x, (-1/0), (-1/0), (-1/0), x, x, x, x, x, (-1/0), x, x, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), x, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), x, x, x, x, (-1/0), x, x, (-1/0), x, x, x, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), x, x, x, x, x, x, x, x, x, x, (-1/0), (-1/0), x, x, x, (-1/0), (-1/0), (-1/0), x, (-1/0), x, (-1/0), (-1/0), x, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), x, x, x, (-1/0), (-1/0), (-1/0), x, x, (-1/0), x, x, (-1/0), (-1/0), x]); ");
/*fuzzSeed-66366547*/count=1412; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((i1)*-0x60dbe))|0;\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [2**53-2, -0, -0x080000001, 0, 0x080000000, -(2**53), -0x07fffffff, -0x080000000, 1/0, 1, -(2**53-2), 0x080000001, 1.7976931348623157e308, 2**53, 42, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, -0x0ffffffff, 0x100000001, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0x100000000, 0/0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, 0x0ffffffff, -(2**53+2), 0.000000000000001, 2**53+2, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-66366547*/count=1413; tryItOut("\"use strict\"; t2 + this.o2;");
/*fuzzSeed-66366547*/count=1414; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ( - Math.fround(mathy1(Math.fround((( ~ (mathy0(Math.log1p(-Number.MAX_VALUE), Math.fround(((-Number.MAX_VALUE != y) | y))) >>> 0)) >>> 0)), Math.fround(( + ( + y))))))); }); testMathyFunction(mathy3, [1, -(2**53-2), -0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53, -0x080000001, -0x080000000, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, 1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, -Number.MIN_VALUE, Math.PI, 2**53+2, -0x100000000, 2**53-2, 0/0, 0x100000000, -0, 0x100000001, 42, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -1/0, 0x080000000, 0, 0.000000000000001, -(2**53+2), 1.7976931348623157e308, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1415; tryItOut("/*tLoop*/for (let y of /*MARR*/[function(){}, function(){}, function(){}, length, length, function(){}, length, function(){}, function(){}, length, length, function(){}, length, function(){}, length, function(){}, length, function(){}]) { (-4); }");
/*fuzzSeed-66366547*/count=1416; tryItOut("print(arguments);function eval(e = (4277).__defineSetter__(\"\\u3056\", null))\"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 16777217.0;\n    var i4 = 0;\n    var d5 = -33554433.0;\n    i4 = (((((((0xf5befe50)+((0xc9202260) < (0x12eef21b)))>>>((i4)-((0x7394b97c)))) != (0x355e081b))+((((0xffa74612)*0x12dbf)>>>((0x42eb5be8)-(0xd867dba5)+(-0x30e2da4)))))|0) == (imul(((abs((((Int32ArrayView[(((0x6532509a))+((0x5857b336))) >> 2]))))|0)), (!((3.777893186295716e+22) >= (1.888946593147858e+22))))|0));\n    return +((1.5474250491067253e+26));\n  }\n  return f;(x);");
/*fuzzSeed-66366547*/count=1417; tryItOut("v1 = (b1 instanceof s1);");
/*fuzzSeed-66366547*/count=1418; tryItOut("\"use strict\"; var nhdgix = new SharedArrayBuffer(1); var nhdgix_0 = new Uint8Array(nhdgix); s2 + '';");
/*fuzzSeed-66366547*/count=1419; tryItOut("mathy3 = (function(x, y) { return (Math.hypot(Math.fround(Math.atan2(( + y), Math.fround(Math.asin(Math.fround(y))))), Math.fround(Math.atan2(Math.fround((((Math.sqrt(y) >>> 0) !== (x >>> 0)) >>> 0)), ( - x)))) == (Math.fround(( - Math.fround((Math.clz32(( + x)) | 0)))) / mathy2(( + Math.atan2(0/0, ( + Math.hypot(Math.max(y, y), y)))), 2**53+2))); }); testMathyFunction(mathy3, [0x07fffffff, -0x100000000, 1/0, -(2**53), 0x100000000, 0x0ffffffff, 42, -0, 2**53, -1/0, -(2**53+2), 0x080000000, -Number.MAX_VALUE, 0, Number.MIN_VALUE, 1.7976931348623157e308, 0/0, 0x100000001, 2**53+2, -Number.MIN_VALUE, -0x080000000, -0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), 2**53-2, Number.MIN_SAFE_INTEGER, -0x100000001, 0.000000000000001, 0x080000001]); ");
/*fuzzSeed-66366547*/count=1420; tryItOut("/*RXUB*/var r = (makeFinalizeObserver('tenured')); var s = /*UUV1*/(x.trunc = Object.prototype.toString); print(r.test(s)); ");
/*fuzzSeed-66366547*/count=1421; tryItOut("this.a2[12] = g0;");
/*fuzzSeed-66366547*/count=1422; tryItOut("\"use strict\"; print(f1);");
/*fuzzSeed-66366547*/count=1423; tryItOut("this.s2 = m0.get(this.h0);");
/*fuzzSeed-66366547*/count=1424; tryItOut("\"use strict\"; this.m1.set(e2, p2);");
/*fuzzSeed-66366547*/count=1425; tryItOut("o1 = {};");
/*fuzzSeed-66366547*/count=1426; tryItOut("(/\\1/gym);");
/*fuzzSeed-66366547*/count=1427; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ((((Math.imul(Math.log1p(Number.MIN_VALUE), (Math.fround(mathy0(y, y)) - y)) != (Math.hypot(( + (( + x) !== (x >>> 0))), (x | 0)) | 0)) <= ( ! (Math.pow(( + y), (( + (( + (Math.cbrt(42) >>> 0)) === ( + y))) >>> 0)) >>> 0))) == (Math.tan(( ~ x)) >>> Math.fround(((Math.cbrt((( + (( + (Math.imul((y | 0), (x >>> 0)) | 0)) / Math.max(-0x100000000, 2**53))) | 0)) | 0) === Math.fround(( + ( + ( + 1.7976931348623157e308)))))))) >>> 0); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 1/0, 0x080000000, -0x080000000, 2**53-2, -(2**53-2), 0, -1/0, -0x080000001, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 0x100000001, 2**53+2, -0x07fffffff, -0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -(2**53), -(2**53+2), 0.000000000000001, Math.PI, 0/0, -Number.MIN_VALUE, 0x07fffffff, 2**53, 42, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, 0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-66366547*/count=1428; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy2((( + Math.imul(( + ( + Math.asin(( + y)))), ( + ( + Math.imul(x, x))))) - ((Math.hypot((Math.fround(( - ( + Math.cos(Math.fround(0x100000001))))) >>> 0), ((mathy3(Math.min((2**53-2 & (x | 0)), mathy3((y >>> 0), ( + x))), (Math.fround(((( + y) >>> 0) === y)) | 0)) | 0) >>> 0)) >>> 0) >>> 0)), Math.pow(( + Math.sign(( ! y))), (y ? ((Math.atan2(x, x) <= -0x080000001) - Math.fround(x)) : ( + Math.expm1(( + mathy0(Math.fround((Math.max(x, (x | 0)) == y)), x))))))); }); testMathyFunction(mathy5, /*MARR*/[-Infinity,  /x/g , false, [undefined], function(){}, -Infinity,  /x/g , function(){}, [undefined], [undefined], -Infinity, [undefined], [undefined], false,  /x/g ,  /x/g , [undefined], -Infinity, function(){}, -Infinity, false, false, false, -Infinity, [undefined], [undefined], function(){}, false, -Infinity, false, [undefined], [undefined], [undefined], -Infinity, -Infinity, false, [undefined], -Infinity, -Infinity,  /x/g , function(){}, [undefined],  /x/g , [undefined], function(){},  /x/g ,  /x/g , [undefined], function(){}, [undefined],  /x/g , [undefined], function(){}, function(){}, [undefined]]); ");
/*fuzzSeed-66366547*/count=1429; tryItOut("mathy2 = (function(x, y) { return (Math.acosh(Math.fround(Math.atanh(Math.pow(((x ? 0.000000000000001 : (y % (x >>> 0))) >>> 0), Math.fround(( ! Math.log1p((mathy1(42, x) >>> 0)))))))) ? ( + Math.exp(( + ( + 1/0)))) : Math.fround((( ~ (Math.tanh((mathy1(-0x0ffffffff, ( + ( + x))) >>> 0)) >>> 0)) ^ ( + (( + x) & ( + x)))))); }); testMathyFunction(mathy2, [0/0, Number.MAX_VALUE, 1/0, 2**53-2, 0x100000001, 0.000000000000001, 0x100000000, Math.PI, 0x080000001, 2**53, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, 1, 2**53+2, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 0x07fffffff, Number.MIN_VALUE, 0, -0x080000000, -(2**53+2), -1/0, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000000, -0x100000000, -Number.MAX_VALUE, -(2**53-2), -(2**53), 0x0ffffffff, -0x100000001]); ");
/*fuzzSeed-66366547*/count=1430; tryItOut("v0 = new Number(-Infinity);");
/*fuzzSeed-66366547*/count=1431; tryItOut("/*infloop*/while(undefined.hasOwnProperty(11)){print(/*UUV2*/(x.toLocaleTimeString = x.anchor));m1.has(s0); }");
/*fuzzSeed-66366547*/count=1432; tryItOut("mathy1 = (function(x, y) { return Math.atanh(( + ( ~ (Math.sin((Math.log((( - Math.fround(Math.imul(Math.fround(y), Math.fround(x)))) >>> 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-66366547*/count=1433; tryItOut("h1.fix = (function(j) { if (j) { for (var v of h1) { try { v1 = Array.prototype.some.call(a0); } catch(e0) { } g2.o2.__iterator__ = (function() { try { a0 + ''; } catch(e0) { } try { m0.set( '' , this.i0); } catch(e1) { } try { a0 = new Array; } catch(e2) { } /*MXX2*/g2.Uint16Array.prototype = e2; return this.g0; }); } } else { try { s0.toString = f0; } catch(e0) { } try { p1 + i2; } catch(e1) { } try { f1.toString = f2; } catch(e2) { } o0.m2 = new Map(this.o1.p2); } });print(x);");
/*fuzzSeed-66366547*/count=1434; tryItOut("mathy1 = (function(x, y) { return Math.max((mathy0((Math.fround(Math.abs(Math.fround(42))) >>> 0), (Math.log10(( - y)) | 0)) | 0), Math.sinh(Math.fround(Math.pow((Math.fround(Math.asin(Math.fround((( + (-(2**53) >>> 0)) >>> 0)))) | 0), Math.fround(Math.cos((( + y) !== ( + y)))))))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53), -1/0, 2**53+2, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, 0x080000001, 1/0, Number.MIN_SAFE_INTEGER, 0, -0x100000001, -Number.MIN_VALUE, -0x0ffffffff, Math.PI, 0x100000001, -0x100000000, 2**53, -Number.MAX_VALUE, 42, -0x07fffffff, 0.000000000000001, 0/0, 0x100000000, -(2**53+2), -0, -0x080000001, -(2**53-2), 0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-66366547*/count=1435; tryItOut("/*vLoop*/for (let rtuiim = 0; rtuiim < 17; ++rtuiim) { z = rtuiim; print(x); } ");
/*fuzzSeed-66366547*/count=1436; tryItOut("mathy2 = (function(x, y) { return Math.pow(Math.exp(mathy1((Math.fround(Math.imul((Number.MAX_SAFE_INTEGER | 0), ( + (( + y) >> y)))) - y), ( + x))), Math.abs(( + Math.imul(( + Math.min(x, ((Math.imul((y >>> 0), (Number.MAX_VALUE >>> 0)) >>> 0) ^ y))), ( + (( ~ 0/0) >>> 0)))))); }); testMathyFunction(mathy2, [Math.PI, 0x080000000, Number.MAX_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -1/0, 2**53, -0x100000000, -0x0ffffffff, -(2**53), -(2**53+2), 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, Number.MIN_VALUE, 2**53-2, 1, 2**53+2, -0x080000001, 0, 1/0, -0x07fffffff, 1.7976931348623157e308, 0.000000000000001, -(2**53-2), -0x100000001, 42, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001]); ");
/*fuzzSeed-66366547*/count=1437; tryItOut("\"use asm\"; mathy1 = (function(x, y) { return Math.max(Math.cos(Math.expm1(((( - (-0x07fffffff >>> 0)) >>> 0) - (Math.acosh((-Number.MIN_VALUE >>> 0)) >>> 0)))), (( + (( ~ Math.hypot(Math.max((Math.min(y, y) | 0), Number.MIN_VALUE), x)) * (Math.fround(Math.hypot(Math.fround(-0x080000000), Math.fround(Math.log(Math.hypot(( ! ( + Math.pow(y, x))), Math.tanh(Math.tanh(x))))))) | 0))) >>> 0)); }); testMathyFunction(mathy1, [Number.MIN_VALUE, 2**53-2, -0x07fffffff, Math.PI, 0x0ffffffff, 0x100000001, -(2**53+2), 1/0, -(2**53-2), 0x080000001, -0x100000000, -(2**53), 0.000000000000001, -0x080000000, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -0, -1/0, 0, Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, 2**53, -Number.MAX_VALUE, -0x100000001, 2**53+2, 1.7976931348623157e308, -0x0ffffffff, 0x07fffffff, 42]); ");
/*fuzzSeed-66366547*/count=1438; tryItOut("\"use strict\"; let(znjhjb, {c: [, [{w: []}, ]], b, \u3056: {x: {y: {}}, x: x}} = /*RXUE*//[^\\w\\u002b-\u0093\\B][^]|(?:\\1)|./gyim.exec(\"\\ud44a\"), x = (undefined), x =  /x/  +=  /x/g , x = Math.pow(-3, -10), a, e, kizpiq, oplzdb, vufhvs) ((function(){for(let d in /*FARR*/[x, new (4277)()]) let(d = /*MARR*/[ /x/ ,  /x/g , new Boolean(false),  /x/ ,  /x/ ,  '\\0' , new Number(1.5), new Number(1.5), new Boolean(false),  '\\0' ,  /x/g , new Number(1.5), new Number(1.5), new Number(1.5),  /x/g ,  /x/g , new Boolean(false),  '\\0' ,  '\\0' , new Number(1.5),  '\\0' , new Number(1.5), new Boolean(false),  /x/g , new Number(1.5), new Boolean(false), new Boolean(false),  /x/g ,  /x/ ,  /x/g ,  /x/g ,  /x/g ,  /x/ ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  /x/ ,  /x/g ,  /x/ ,  /x/g ,  '\\0' ,  /x/g ].filter(e =>  /x/g ).revocable(((function factorial(thbtab) { ; if (thbtab == 0) { Array.prototype.shift.call(a0, e0, o1);; return 1; } ; return thbtab * factorial(thbtab - 1);  })(75305)), new (mathy4)(-2)), NaN = new RegExp(((makeFinalizeObserver('nursery')))), fziucr, d = z++, e, d = /(?:(?:[^\u00e6\\W\\s].*?)|.*?)|(?!(?:\\1))[^]+?[\u00ba\\W\\uE8F9\\w]?/gm, jigflh, d) { let(eval =  ''  -= window, auqaga, tqvhlo, tkwnam, \u3056, panreg, \u3056, kzyrdr, eval, scjlig) { throw StopIteration;}}})());let(x = e = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: undefined, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: undefined, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })('fafafa'.replace(/a/g, function(y) { yield y; e0.add(o2);; yield y; })), Array.from, (neuter).apply), c = ('fafafa'.replace(/a/g, Math.sin)), eval = new (b =>  { \"use strict\"; return x } )(x), d = let (z =  /x/g ) \"\\u419C\", y) ((function(){for(let d of offThreadCompileScript) x = x;})());");
/*fuzzSeed-66366547*/count=1439; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-66366547*/count=1440; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[{}, []]) { print(x); }");
/*fuzzSeed-66366547*/count=1441; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -262143.0;\n    i2 = (0x53be5c6d);\n    return (((((-7.737125245533627e+25) == (((0xf29cd5ce)) ? (65536.0) : (d1))) ? (0xfae5b8f2) : (/*FFI*/ff(((~((0xa0c088d0)))), ((-8193.0)), ((((0xffffffff)+(0x1978d092)+(0xfd50f950)) & ((i0)))), ((((0x505a58b9))|0)), ((d1)), ((((0xffffffff)) >> ((0xf11b6c7a)))), ((3.022314549036573e+23)), ((35184372088833.0)), ((262144.0)), ((-0.001953125)), ((-1.5111572745182865e+23)), ((2199023255553.0)), ((-7.555786372591432e+22)), ((9007199254740992.0)))|0))))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [undefined, NaN, false, ({valueOf:function(){return 0;}}), -0, '', 0, /0/, (function(){return 0;}), (new Boolean(true)), (new Boolean(false)), null, (new String('')), [0], '0', '/0/', (new Number(0)), true, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), (new Number(-0)), objectEmulatingUndefined(), 0.1, 1, [], '\\0']); ");
/*fuzzSeed-66366547*/count=1442; tryItOut("/*iii*/b0.__iterator__ = f1;/*hhh*/function jcutby(){p1 = t2[12];}");
/*fuzzSeed-66366547*/count=1443; tryItOut("v2 = Object.prototype.isPrototypeOf.call(o1, p1);function b(this.x, b)yield (Math.atan2( \"\" , -6))print(timeout(1800));");
/*fuzzSeed-66366547*/count=1444; tryItOut("o1.g1.p1 = m1.get(b0);\nyield;\n");
/*fuzzSeed-66366547*/count=1445; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (i0);\n    }\n    (Int16ArrayView[4096]) = ((i0)*-0x9bbd4);\n    d1 = (d1);\n    return (((0x43439c66)+(0xf99267e8)))|0;\n  }\n  return f; })(this, {ff: (new RegExp(\"\\\\3\", \"g\") ? \"\\u4F9B\" : null)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x080000001, -0x07fffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000000, 0, Number.MIN_VALUE, -(2**53), 0/0, 0x0ffffffff, -0x100000000, 42, 2**53, 1.7976931348623157e308, 1, 1/0, 0x100000001, Number.MIN_SAFE_INTEGER, -0, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, 0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, -Number.MIN_VALUE, -0x100000001, -Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), 2**53-2, -1/0, -0x080000000]); ");
/*fuzzSeed-66366547*/count=1446; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = ((0xd5b5624f) <= (0x964deee0));\n    i1 = (i1);\n    i1 = (i0);\n    return +((-549755813889.0));\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-66366547*/count=1447; tryItOut("g1.offThreadCompileScript(\"eval\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: (x % 5 != 0), sourceIsLazy: true, catchTermination: (x % 58 == 41), element: o1 }));");
/*fuzzSeed-66366547*/count=1448; tryItOut("s2 = t2[ '' ];print(x);");
/*fuzzSeed-66366547*/count=1449; tryItOut("mathy2 = (function(x, y) { return ( ! (((Math.atan2(Math.atan2((x >>> 0), x), Math.fround(y)) >>> Math.fround(y)) >>> 0) << ((( + (Math.atanh(((y || ( ~ ( + ( ~ x)))) >>> 0)) >>> 0)) < Math.log2(Math.fround(Math.fround(Math.abs(Math.fround(y)))))) | 0))); }); testMathyFunction(mathy2, /*MARR*/[0x40000001, (void 0), 0x40000001, (void 0), 0x40000001, (-1/0), -0x2D413CCC, (-1/0), 0x40000001, (void 0), -0x2D413CCC, (void 0), (void 0), -0x2D413CCC, (-1/0), 0x40000001, -0x2D413CCC, 0x40000001, (-1/0), 0x40000001, -0x2D413CCC, -0x2D413CCC, 0x40000001, (-1/0), -0x2D413CCC, (-1/0), (void 0), (void 0), -0x2D413CCC, -0x2D413CCC, 0x40000001, 0x40000001, (-1/0), -0x2D413CCC, (void 0), (-1/0), (-1/0), (-1/0), 0x40000001, 0x40000001, (void 0), -0x2D413CCC, -0x2D413CCC, -0x2D413CCC, 0x40000001, -0x2D413CCC, -0x2D413CCC, (-1/0), (void 0), -0x2D413CCC, 0x40000001, (-1/0), 0x40000001, -0x2D413CCC, 0x40000001, -0x2D413CCC, (-1/0), -0x2D413CCC, -0x2D413CCC, (void 0), (-1/0), 0x40000001, (void 0), -0x2D413CCC, (void 0), (void 0), 0x40000001, (void 0), -0x2D413CCC, 0x40000001, -0x2D413CCC, (void 0), 0x40000001, 0x40000001, (-1/0), -0x2D413CCC, 0x40000001, (void 0), (-1/0), (-1/0), -0x2D413CCC, 0x40000001, (void 0), -0x2D413CCC, (void 0), (-1/0), 0x40000001, (void 0), (-1/0), (void 0), 0x40000001, (-1/0), (void 0), (-1/0)]); ");
/*fuzzSeed-66366547*/count=1450; tryItOut("\"use strict\"; ((let (b) /^/im).yoyo( /x/ ));o1.t1.__proto__ = o1;");
/*fuzzSeed-66366547*/count=1451; tryItOut("mathy4 = (function(x, y) { return (( - (Math.fround(((Math.fround(mathy2(Math.fround(y), ( + mathy3(( + Math.fround((Math.fround((Math.imul(y, y) >>> 0)) / Math.fround(( + x))))), ( + ( ~ ( + x))))))) | 0) || Math.fround(Math.imul((Math.max((Math.log((Math.pow(Math.sin(x), 2**53+2) >>> 0)) >>> 0), ( + y)) >>> 0), Math.fround(( + Math.fround(( ! ( + (((x >>> 0) && ((Math.max(-Number.MIN_SAFE_INTEGER, (Number.MAX_SAFE_INTEGER | 0)) | 0) | 0)) | 0)))))))))) | 0)) | 0); }); ");
/*fuzzSeed-66366547*/count=1452; tryItOut("var vtrfdz = new SharedArrayBuffer(8); var vtrfdz_0 = new Int8Array(vtrfdz); vtrfdz_0[0] = -4; var vtrfdz_1 = new Int16Array(vtrfdz); print(vtrfdz_1[0]); vtrfdz_1[0] = 4; var vtrfdz_2 = new Int16Array(vtrfdz); print(vtrfdz_2[0]); vtrfdz_2[0] = -17; var vtrfdz_3 = new Int8Array(vtrfdz); var vtrfdz_4 = new Uint8Array(vtrfdz); vtrfdz_4[0] = -0x07fffffff; var vtrfdz_5 = new Float32Array(vtrfdz); var vtrfdz_6 = new Float64Array(vtrfdz); vtrfdz_6[0] = -27; var vtrfdz_7 = new Int32Array(vtrfdz); print(vtrfdz_7[0]); var vtrfdz_8 = new Int32Array(vtrfdz); print(vtrfdz_8[0]); var vtrfdz_9 = new Float32Array(vtrfdz); vtrfdz_9[0] = -28; var vtrfdz_10 = new Uint8Array(vtrfdz); print(vtrfdz_10[0]); vtrfdz_10[0] = 134217729; var vtrfdz_11 = new Uint16Array(vtrfdz); var vtrfdz_12 = new Uint16Array(vtrfdz); Array.prototype.push.call(a0, f1);this.v0 = evalcx(\"i0.next();\", g2);this.v0 = g0.runOffThreadScript();a2.push(h0, f1, v1);/* no regression tests found */Array.prototype.push.apply(a1, [((uneval( '' ))), p0, p0, m1]);this.a1.sort(f0);/*RXUB*/var r = new RegExp(\"${0,3}\", \"yim\"); var s = \"\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-66366547*/count=1453; tryItOut("mathy2 = (function(x, y) { return ( ~ (( - ( + Math.hypot(( + Math.fround(Math.ceil(Math.fround(y)))), ( + Math.ceil(( + Math.atan(( + y)))))))) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[-Infinity, [1], [1], [1], -Infinity, [1], -Infinity, new Number(1.5), new Number(1.5), new Number(1.5), -Infinity, new Number(1.5), -Infinity, -Infinity, [1], -Infinity, [1], -Infinity, [1], [1], [1], [1], [1], [1], -Infinity, -Infinity, -Infinity, [1], new Number(1.5), -Infinity, [1], new Number(1.5), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], -Infinity, [1], -Infinity, new Number(1.5), new Number(1.5), -Infinity, new Number(1.5), new Number(1.5), new Number(1.5), -Infinity, [1], new Number(1.5), [1], -Infinity, new Number(1.5), new Number(1.5), [1], new Number(1.5), -Infinity, -Infinity, new Number(1.5), [1], -Infinity, [1], new Number(1.5), new Number(1.5), -Infinity, -Infinity, new Number(1.5), new Number(1.5), [1], -Infinity, new Number(1.5), -Infinity, [1], -Infinity, new Number(1.5), new Number(1.5), -Infinity, new Number(1.5), [1], [1], [1], [1], [1], [1], [1], [1], new Number(1.5), new Number(1.5), new Number(1.5), -Infinity, -Infinity, [1], [1], -Infinity, [1], new Number(1.5), -Infinity, -Infinity, new Number(1.5), [1], -Infinity, [1], [1], new Number(1.5), [1], new Number(1.5), new Number(1.5), -Infinity, -Infinity, -Infinity, [1], new Number(1.5), -Infinity, new Number(1.5), -Infinity, [1], -Infinity, [1], new Number(1.5), new Number(1.5), -Infinity, -Infinity, new Number(1.5), [1], [1], new Number(1.5), [1], -Infinity, -Infinity, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [1], new Number(1.5), [1], -Infinity, [1], [1], new Number(1.5)]); ");
/*fuzzSeed-66366547*/count=1454; tryItOut("mathy4 = (function(x, y) { return (Math.atan((( + ( - ((x | 0) !== 0x07fffffff))) != ( + ( - 0)))) , ( + ((((( + Math.pow(Math.fround(( ! 2**53-2)), ( + Math.hypot((Math.cbrt(Math.fround(( ! y))) >>> 0), y)))) | 0) | ((( ~ y) >>> 0) | 0)) | 0) === ( + mathy1(( + ( + Math.trunc(( + y)))), ( + (Math.pow((y | 0), (Math.fround(( - Math.fround(Math.sin((( + (x | 0)) | 0))))) | 0)) >>> 0))))))); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, Math.PI, -1/0, 2**53-2, -0x07fffffff, 0x07fffffff, 0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_SAFE_INTEGER, 0, -0, Number.MIN_VALUE, -(2**53-2), 0x100000000, 2**53+2, 1, -0x080000001, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, 1/0, -0x100000000, 42, 2**53, 0x080000000, -(2**53+2), -0x080000000, 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-66366547*/count=1455; tryItOut("\"use strict\"; \"use asm\"; e2.has(b1);");
/*fuzzSeed-66366547*/count=1456; tryItOut("\u3056, x = ((function sum_slicing(khdgcp) { ; return khdgcp.length == 0 ? 0 : khdgcp[0] + sum_slicing(khdgcp.slice(1)); })(/*MARR*/[ /x/g , undefined, arguments, undefined, undefined])), x = (4277), x = /(\\1)+\\2[]/gm, x, x;let c, x, x;( /x/g );");
/*fuzzSeed-66366547*/count=1457; tryItOut("testMathyFunction(mathy4, [2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, 0x07fffffff, 0x080000001, -0x080000001, 0.000000000000001, 42, Number.MIN_VALUE, -0x080000000, -Number.MAX_VALUE, 1/0, 0x100000001, 0, 1.7976931348623157e308, 2**53, -0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000, -1/0, -0, -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53+2), -0x100000000, -(2**53), Math.PI, -(2**53-2), -0x0ffffffff, 1, 0x080000000]); ");
/*fuzzSeed-66366547*/count=1458; tryItOut("/*RXUB*/var r = r2; var s = s2; print(uneval(r.exec(s))); ");
/*fuzzSeed-66366547*/count=1459; tryItOut("\"use strict\"; g0.o1 = h1.__proto__;");
/*fuzzSeed-66366547*/count=1460; tryItOut("o1 + this.f2;");
/*fuzzSeed-66366547*/count=1461; tryItOut("Array.prototype.reverse.call(a2);");
/*fuzzSeed-66366547*/count=1462; tryItOut("{f2.valueOf = f1; }");
/*fuzzSeed-66366547*/count=1463; tryItOut("/*infloop*/for(yield  /x/g ; (\n-0); (intern([1] % [,,]).getSeconds(eval(\"print(x);\", window), (4277)))) {t2 = t2.subarray(12);\nnew RegExp(\".[^]+?|(?=(\\\\cB{1}))+?+\", \"i\");\n }");
/*fuzzSeed-66366547*/count=1464; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?!(?=(?:[^\\u5064\\\\w\\\\D]))\\\\B([^]|\\\\B){3,5}(?!(?!$){2})(\\\\w)?))\", \"g\"); var s = \"1\\naa0\"; print(s.search(r)); ");
/*fuzzSeed-66366547*/count=1465; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.atan2((Math.imul(Math.fround(( ! ( + mathy3((1 | 0), (Math.fround((y ? Math.fround(y) : Math.fround(y))) ? x : y))))), (Math.hypot(((( ~ Math.fround(y)) | 0) >>> 0), y) >>> 0)) | 0), (( ! Math.hypot(Math.fround(mathy1(Math.fround(( + Math.exp(( + (y >>> (-0 >>> 0)))))), Math.fround(Math.imul(2**53-2, Math.sign(( + -0x0ffffffff)))))), ( ~ y))) | 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000001, -Number.MAX_VALUE, 0/0, 0x100000001, -Number.MIN_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x07fffffff, -0x0ffffffff, -(2**53+2), 0x080000001, 0x0ffffffff, 0x080000000, -0x07fffffff, 2**53, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, -1/0, -(2**53-2), Number.MAX_VALUE, -0x080000001, Math.PI, 1, 1/0, 0.000000000000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, 1.7976931348623157e308, 2**53-2, 0, -(2**53)]); ");
/*fuzzSeed-66366547*/count=1466; tryItOut("/*ODP-1*/Object.defineProperty(b1, \"NaN\", ({configurable: (x % 8 != 7)}));");
/*fuzzSeed-66366547*/count=1467; tryItOut("m1.set(i1, b2)");
/*fuzzSeed-66366547*/count=1468; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((-((((+sqrt(((d1))))) / ((+(((0x13e9d17f) ? (1025.0) : (-((NaN)))))))))));\n  }\n  return f; })(this, {ff: function(y) { yield y; a2 = new Array;; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[]); ");
/*fuzzSeed-66366547*/count=1469; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.atan2((( - (Math.max((mathy3((x >>> 0), y) | 0), y) >>> 0)) >>> 0), (( - (( + (( + (( + mathy2(( + -(2**53-2)), ( + ( ! 0x080000000)))) == Math.fround(((x | 0) && Math.fround(x))))) || ( + ( + mathy1(( + mathy2(-(2**53+2), -(2**53+2))), (mathy3((y | 0), ((Math.pow((Math.hypot(x, Math.PI) | 0), (0 | 0)) | 0) | 0)) | 0)))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, 2**53-2, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000001, Number.MAX_VALUE, -0, Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, 42, -Number.MAX_VALUE, 0x0ffffffff, Number.MIN_VALUE, 1/0, -Number.MIN_VALUE, -(2**53+2), -1/0, 1.7976931348623157e308, -0x07fffffff, 0, 2**53, -0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, 1, -0x100000000, -(2**53-2), -(2**53), -0x0ffffffff, -0x100000001, 0x07fffffff]); ");
/*fuzzSeed-66366547*/count=1470; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.min(Math.imul(Math.acos(x), ( ! Math.fround((x === y)))), ( + Math.cbrt((( ~ ( ~ Math.fround(Math.max(Math.PI, x)))) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[(0/0), function(){}, function(){}, (0/0),  /x/g , function(){}, (0/0),  /x/g , (0/0), (0/0), function(){}, (0/0), (0/0), (0/0),  /x/g ,  /x/g , function(){}, function(){}, (0/0), function(){}, function(){}, function(){},  /x/g ,  /x/g ,  /x/g ]); ");
/*fuzzSeed-66366547*/count=1471; tryItOut("mathy5 = (function(x, y) { return ( ~ ( ~ (Math.min(((Math.tanh(Math.fround((Math.pow(y, y) & (Math.tan(1) | 0)))) >>> 0) | 0), (Math.atan2(Math.min(x, y), Math.fround((x & y))) | 0)) | 0))); }); testMathyFunction(mathy5, [objectEmulatingUndefined(), (new String('')), '0', (new Number(-0)), /0/, ({valueOf:function(){return '0';}}), [], (function(){return 0;}), 0.1, '\\0', 0, '/0/', ({valueOf:function(){return 0;}}), (new Number(0)), undefined, [0], ({toString:function(){return '0';}}), true, '', (new Boolean(false)), NaN, 1, null, (new Boolean(true)), -0, false]); ");
/*fuzzSeed-66366547*/count=1472; tryItOut("\"use strict\"; for (var p in e2) { try { p1 = a2[o2.v2]; } catch(e0) { } try { g0.v1 = g2.t1.length; } catch(e1) { } v2 = evalcx(\"s1 += 'x';\", g1.g1); }");
/*fuzzSeed-66366547*/count=1473; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return Math.hypot((Math.atan2(((((x | 0) - ( + -1/0)) - (Math.sinh(y) >>> 0)) | 0), (Math.cos((Math.log2((0x080000000 >>> 0)) >>> 0)) | 0)) | 0), ( ! (x ? Math.cbrt(Math.fround(Math.tanh(Math.asinh(y)))) : ( + (( + y) > ( + Math.fround(( + (x | 0))))))))); }); testMathyFunction(mathy0, [1.7976931348623157e308, 2**53+2, 1, Math.PI, 2**53-2, -(2**53), -(2**53+2), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, -(2**53-2), 2**53, 0x080000001, -0x0ffffffff, 0x0ffffffff, 0x100000000, -0, 0x080000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x100000001, -1/0, 0x07fffffff, -0x080000001, -0x080000000, 0, 1/0, 42, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-66366547*/count=1474; tryItOut("{for(var [x, y] =  /x/  in null) [];let y = (z) = \"\\uB354\".throw(undefined);let (w) { v2 = new Number(0); } }");
/*fuzzSeed-66366547*/count=1475; tryItOut("\"use strict\"; o1.h2.has = f2;");
/*fuzzSeed-66366547*/count=1476; tryItOut("/*RXUB*/var r = new RegExp(\"(?:$){67108864}((?=}[\\\\d\\u009d]?){2,}\\\\3{4})|\\\\2^[^]|\\\\3|\\\\s{2}\", \"ym\"); var s = \"\\n\\n\\u2a9b\\n\\n\\n\\n\\n\\n\\u2a9b\\n\\n\\n\\n\\n\\n000000\"; print(r.test(s)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
