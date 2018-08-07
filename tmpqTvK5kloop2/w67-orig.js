

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
/*fuzzSeed-116111302*/count=1; tryItOut("/*MXX1*/this.o0 = g0.Object.getOwnPropertySymbols;");
/*fuzzSeed-116111302*/count=2; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((((0xfa3c4bb5))>>>((Uint32ArrayView[2]))) / ((((imul(((eval(\"/* no regression tests found */\", \"\\u9E10\"))), ((0xfb3e6035) ? (0xffffffff) : (0xfa5b0fd2)))|0) < (((0xeaebe57d)) >> ( ''  ? (new OSRExit((makeFinalizeObserver('tenured')), Math.hypot(-17, [1]))) : (uneval(\u3056)))))*-0x5b74d)>>>((0xfc02c591)+(/*FFI*/ff(((+((-2199023255553.0)))), (((i1))))|0)))))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; return (((y >>> 0) ^ (x >>> 0)) >>> 0); })}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x080000001, 2**53-2, -0, -Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 1, 2**53+2, 1.7976931348623157e308, -0x100000000, 0x080000000, Number.MIN_VALUE, 1/0, -(2**53+2), -0x080000001, 0x100000001, 0, Math.PI, -Number.MIN_VALUE, 0.000000000000001, 0/0, -1/0, -Number.MAX_VALUE, 0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 42, -(2**53), -0x07fffffff, -0x080000000]); ");
/*fuzzSeed-116111302*/count=3; tryItOut("testMathyFunction(mathy1, [0x0ffffffff, -Number.MIN_VALUE, 1, -0, Number.MIN_VALUE, 0x100000000, -(2**53-2), 42, 2**53, 0x080000000, -1/0, 0x07fffffff, Math.PI, 1.7976931348623157e308, 0.000000000000001, 1/0, -0x07fffffff, 0/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, -0x080000001, 2**53+2, -0x100000001, 0x080000001, 0, 0x100000001, -0x100000000, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -0x080000000]); ");
/*fuzzSeed-116111302*/count=4; tryItOut("\"use strict\"; Math;-4;");
/*fuzzSeed-116111302*/count=5; tryItOut("/*ODP-1*/Object.defineProperty(b1, \"toString\", ({configurable: false}));");
/*fuzzSeed-116111302*/count=6; tryItOut("\"use strict\"; e1.delete(h0);function b() { yield /*MARR*/[ /x/ , function(){}, ['z'], (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), function(){}, (-1/0), (-1/0), ['z'],  /x/ , function(){}, (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), ['z'], function(){}, function(){},  /x/ , (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], ['z'], (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), (-1/0), (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), ['z'], (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), function(){}, function(){}, ['z'], ['z'], (-1/0), (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), (-1/0),  /x/ , function(){},  /x/ , (-1/0), function(){},  /x/ , (/*RXUE*/new RegExp(\"\\\\3\", \"gyim\").exec(\"\")), function(){}, (-1/0), ['z'], function(){},  /x/ , (-1/0)] } i0 + b2;function y(x) { m2.has(e1); } e0 = new Set;function x(x, d)\"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var Infinity = stdlib.Infinity;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (((1) ? (0x6e03c0b3) : (i1)) ? (i1) : (i1));\n    i1 = (((abs((((Int32ArrayView[4096])) << ((0x32370af3)-(0xf8815eae)-(-0x28c3ae0))))|0) < (~((((x.eval(\"/* no regression tests found */\")))|0)))) ? (i1) : ((imul(( /x/g ), (0xfd5c23ad))|0)));\n    {\n      d0 = (d0);\n    }\n;    i1 = ((((0xe6a26d65)-((0xf9e71678) ? (0xdfffd12e) : ((262145.0) < (-590295810358705700000.0))))>>>((i1)+(0x7a5177c6)+(-0x8000000))) <= (0xffffffff));\n    d0 = (d0);\n    {\n      i1 = (0xf9398188);\n    }\n    (Float64ArrayView[((0xfd74eda8)-(i1)-((abs((~~(d0)))|0))) >> 3]) = ((-((d0))));\n    i1 = (i1);\n    {\n      d0 = (4294967297.0);\n    }\n    switch ((((i1)+(i1)) & ((Int8ArrayView[((0xa294c98c)) >> 0])))) {\n      default:\n        switch ((~(((0x5a306080))-((0xd96cbb3c) ? (0xfba4999b) : (0xfb02c11d))+(1)))) {\n          case -3:\n            d0 = (+atan2(((d0)), ((+((4.722366482869645e+21))))));\n            break;\n          case -3:\n            (Float32ArrayView[((((((0xfcce12c1))>>>((0xf9ca26d2)+(0x55001526)-(0x131c9c1e))) < (((0x27ea7d1b)-(-0x8000000)-(0x9f39d730))>>>((0xba1331e3) / (0xd7348428)))))) >> 2]) = ((1073741825.0));\n          case 1:\n            return (((i1)+((+abs(((1.2089258196146292e+24)))) <= (+(0.0/0.0)))))|0;\n            break;\n          case 0:\n            i1 = ((((i1))>>>(((-2049.0) <= ((4277)))-(0xfd23592a)+((imul((i1), (0xfd3deeef))|0)))) <= (((i1)*0xfffff)>>>(((0xa94009e3))*0x6182f)));\n            break;\n          default:\n            {\n              d0 = (Infinity);\n            }\n        }\n    }\n    d0 = ((Float32ArrayView[((0xfa4f057e)+((((i1)) & ((0x59da4473)+(0xffffffff)+(i1))) >= (((((0xf89396c9))>>>((0x33a04cc4))) % ((((0x3544cad4))|0))) ^ ((!(1)))))) >> 2]));\n    return (((i1)-(i1)))|0;\n  }\n  return f;print(undefined);");
/*fuzzSeed-116111302*/count=7; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(( ~ Math.fround(Math.pow(Math.fround(Math.min(Math.fround((Math.min(( ! ( + ( + 42))), Math.fround((Math.fround(y) ? Math.fround(Math.asinh(Math.fround((x % (Number.MAX_VALUE | 0))))) : Math.fround(y)))) >>> 0)), Math.fround(Math.log1p(Number.MIN_SAFE_INTEGER)))), Math.fround(Math.log(Math.fround(( + ( + ( + x)))))))))); }); testMathyFunction(mathy0, [0, -(2**53), -0x100000000, 0/0, 1/0, -1/0, -0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, 42, -0, 0.000000000000001, 0x080000001, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_VALUE, -0x080000001, 0x100000001, -(2**53+2), 2**53-2, -Number.MIN_VALUE, 0x0ffffffff, Math.PI, 2**53, 0x080000000, 1, 2**53+2]); ");
/*fuzzSeed-116111302*/count=8; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(( ~ Math.fround(Math.tan(( ! (Math.pow(y, (x | 0)) | 0)))))); }); testMathyFunction(mathy1, ['\\0', (new String('')), (function(){return 0;}), null, [0], 0.1, NaN, ({valueOf:function(){return 0;}}), [], (new Number(-0)), ({toString:function(){return '0';}}), (new Boolean(false)), false, (new Number(0)), objectEmulatingUndefined(), 0, true, /0/, '0', '', -0, undefined, (new Boolean(true)), '/0/', ({valueOf:function(){return '0';}}), 1]); ");
/*fuzzSeed-116111302*/count=9; tryItOut("let c = ({} = Math.atan2( /x/ .throw(2), -12));this.o2.g0.offThreadCompileScript(\"function f1(o1)  { \\\"use strict\\\"; continue ; } \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 20 != 6), sourceIsLazy: x, catchTermination: (x % 4 == 3), element: o2 }));");
/*fuzzSeed-116111302*/count=10; tryItOut("\"use strict\"; for (var p in a1) { Object.prototype.watch.call(o1, \"toSource\", (function(j) { if (j) { try { this.g1.i0.send(p2); } catch(e0) { } try { i2.valueOf = f0; } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(b0, s0); } else { try { i1 + e2; } catch(e0) { } try { i2.send(s2); } catch(e1) { } g0.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 78 == 28), sourceIsLazy: false, catchTermination: false })); } })); }");
/*fuzzSeed-116111302*/count=11; tryItOut("mathy0 = (function(x, y) { return Math.hypot((( - ((y << (Math.max((y ? y : (( ~ (y | 0)) | 0)), (Math.min(-1/0, y) >>> 0)) >>> 0)) | 0)) | 0), (Math.min(Math.imul(((Math.imul(0x080000000, ( + ( ~ ( + Math.min(x, x))))) >>> 0) | 0), ((((Math.clz32((x >>> 0)) >>> 0) | 0) <= ((( + (0x07fffffff ? (-(2**53-2) | 0) : ( + y))) ? x : x) | 0)) >>> 0)), Math.fround(((Math.min(Math.sin((0x100000001 | 0)), (-0x0ffffffff >>> 0)) >>> 0) / y))) >>> 0)); }); testMathyFunction(mathy0, [-(2**53), Math.PI, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, -0, 0x080000000, 0, -Number.MAX_VALUE, Number.MAX_VALUE, 1/0, -0x0ffffffff, 0.000000000000001, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, -0x07fffffff, -(2**53+2), 1.7976931348623157e308, -0x080000000, 0x07fffffff, -(2**53-2), -0x100000001, -0x100000000, 0x080000001, 42, 2**53+2, 0x100000000, 0/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-116111302*/count=12; tryItOut("\"use strict\"; ( /x/g .__defineGetter__(\"c\", Date.prototype.setUTCSeconds));");
/*fuzzSeed-116111302*/count=13; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(this.a0, v0, { configurable: true, enumerable: false, writable: /*MARR*/[new Boolean(false), objectEmulatingUndefined(), (void 0), (1/0), (1/0), (void 0), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), (void 0), (1/0), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), (void 0), (1/0), objectEmulatingUndefined(), (void 0), (1/0), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), (1/0), objectEmulatingUndefined(), (void 0), (1/0), (void 0), (1/0), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), (1/0), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), (void 0), (void 0), (1/0), (1/0), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (void 0), (1/0), new Boolean(false), (1/0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), new Boolean(false), (1/0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), new Boolean(false), objectEmulatingUndefined(), (1/0), (1/0), (void 0), new Boolean(false), (1/0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), (void 0), new Boolean(false), (1/0), new Boolean(false), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), (void 0), (1/0), (void 0), (1/0), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), new Boolean(false), new Boolean(false), (1/0), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), objectEmulatingUndefined(), objectEmulatingUndefined(), new Boolean(false), new Boolean(false), (1/0), objectEmulatingUndefined(), (1/0)].sort, value: p2 });");
/*fuzzSeed-116111302*/count=14; tryItOut("/*tLoop*/for (let e of /*MARR*/[new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1)]) { m2.has(e1); }");
/*fuzzSeed-116111302*/count=15; tryItOut("h0 + this.m1;");
/*fuzzSeed-116111302*/count=16; tryItOut("Array.prototype.sort.apply(a1, [(function() { try { Array.prototype.push.apply(a1, [SharedArrayBuffer(eval(\"/* no regression tests found */\") ? (void version(185)) : (/*RXUE*/this.exec(\"\"))), p1, this.s0]); } catch(e0) { } try { g0.m2.set(this.i0, h0); } catch(e1) { } try { o2.m0 = new WeakMap; } catch(e2) { } a1 = Array.prototype.filter.call(a0); throw h1; })]);");
/*fuzzSeed-116111302*/count=17; tryItOut("\"use strict\"; {a0.reverse(); }");
/*fuzzSeed-116111302*/count=18; tryItOut("v1 = g1.t1.byteOffset;");
/*fuzzSeed-116111302*/count=19; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.abs(Math.fround(( + Math.max(( + Math.fround(Math.min(Math.fround(((((Math.fround(Math.pow(Math.fround(0x07fffffff), ( + 42))) !== ( + ( - ( + 0/0)))) | 0) & ((Math.hypot((y | 0), (Math.fround(mathy2(Math.fround(y), Math.fround(x))) | 0)) | 0) | 0)) | 0)), Math.fround(( + Math.min(( + (Math.imul(Math.fround(x), Math.fround(Math.log10(Math.fround(Math.tanh(Math.fround(y)))))) >>> 0)), (( + -0x100000000) + x))))))), ( + (( - ((Math.atanh(-0x080000001) >>> 0) >>> 0)) >>> 0)))))) >>> 0); }); testMathyFunction(mathy4, [Math.PI, -0x07fffffff, 0x080000001, -1/0, 2**53, 0/0, 0, -(2**53-2), 2**53-2, -0x080000001, -0x0ffffffff, 1/0, 0x100000001, 0x080000000, -(2**53), -0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, 1, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, -0x100000000, 0x100000000, 0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53+2, -0, -Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=20; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((( + ( + (Math.cos(( + Math.hypot(Math.min(x, x), y))) != ((( + -0x100000001) || ( + ( + ( - y)))) | 0)))) != (( + mathy0(Math.fround(( ~ Math.fround(x))), ((((( - (x | 0)) >>> 0) | 0) < (mathy1(((x % Math.expm1(( + x))) >>> 0), ( + Math.PI)) >>> 0)) | 0))) | 0)) | 0); }); ");
/*fuzzSeed-116111302*/count=21; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -1.0078125;\n    return +((NaN));\n    (Float32ArrayView[0]) = ((d1));\n    i0 = (0xffffffff);\n    return +((d1));\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116111302*/count=22; tryItOut("\"use strict\"; m0 + g2;");
/*fuzzSeed-116111302*/count=23; tryItOut("(Math.trunc(19));");
/*fuzzSeed-116111302*/count=24; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.max((mathy2(mathy0((x | 0), (mathy1((x | 0), Math.max(( + ( + ( ~ x))), ( + y))) | 0)), (Math.min(Math.imul(0x0ffffffff, ((y ? ( + y) : 1.7976931348623157e308) | 0)), (( ~ (2**53-2 | 0)) | 0)) >>> 0)) | 0), (Math.fround(Math.sin(Math.fround((( ~ (( ~ (y >>> 0)) | 0)) | 0)))) >>> (( ~ Math.log2((((y >>> 0) >> (y >>> 0)) >>> 0))) | 0))) | 0); }); testMathyFunction(mathy4, [-0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000, 42, -Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, -(2**53+2), -0x080000000, -0, -0x0ffffffff, 1/0, -Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53-2), 2**53, 0/0, -(2**53), Math.PI, 0x07fffffff, 0, -1/0, 0x080000001, Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x100000001, 1, -0x100000000, 0x100000000]); ");
/*fuzzSeed-116111302*/count=25; tryItOut("m2.set(i0, t1);");
/*fuzzSeed-116111302*/count=26; tryItOut("for (var v of g2.i0) { Object.defineProperty(this, \"v1\", { configurable: false, enumerable: true,  get: function() {  return evaluate(\"\\\"use strict\\\"; /*tLoop*/for (let c of /*MARR*/[ '\\\\0' ,  '\\\\0' , new Number(1), new Number(1), false, new Number(1), new Number(1),  '\\\\0' , false, false, (0/0), (0/0), (0/0), (0/0),  '\\\\0' , false, (0/0), (0/0),  '\\\\0' , false, (0/0), (0/0),  '\\\\0' , (0/0), (0/0), false, new Number(1), (0/0), (0/0), new Number(1),  '\\\\0' , (0/0), new Number(1), new Number(1), false, false, new Number(1), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0),  '\\\\0' , new Number(1), (0/0), new Number(1), new Number(1), (0/0),  '\\\\0' ,  '\\\\0' , (0/0),  '\\\\0' , false, false, new Number(1), new Number(1), new Number(1),  '\\\\0' , new Number(1), (0/0), new Number(1),  '\\\\0' ]) { v1 = t0.length; }\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: x, catchTermination: false })); } }); }");
/*fuzzSeed-116111302*/count=27; tryItOut("\"use strict\"; a1 = this.a0.concat(a2);");
/*fuzzSeed-116111302*/count=28; tryItOut("mathy5 = (function(x, y) { return Math.atan(Math.tan(( + Math.exp(Math.hypot(y, ( - x)))))); }); testMathyFunction(mathy5, [-0x080000001, 0x100000000, 0/0, 0x080000001, 1, 2**53+2, 0x080000000, 0.000000000000001, -0x080000000, 1/0, -0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53-2, -0x07fffffff, -0, -0x100000000, 42, Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53), 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000001, 2**53, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-116111302*/count=29; tryItOut("\"use strict\"; /*vLoop*/for (qepitd = 0, undefined; qepitd < 12; ++qepitd) { let y = qepitd; a1 = r2.exec(s0); } ");
/*fuzzSeed-116111302*/count=30; tryItOut("testMathyFunction(mathy4, [NaN, 0, ({toString:function(){return '0';}}), (new Number(-0)), /0/, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), undefined, false, -0, (new Boolean(true)), ({valueOf:function(){return 0;}}), '', true, '0', 1, (new Number(0)), null, [], (function(){return 0;}), '/0/', (new Boolean(false)), (new String('')), '\\0', [0], 0.1]); ");
/*fuzzSeed-116111302*/count=31; tryItOut("\"use strict\"; /*ADP-1*/Object.defineProperty(this.a1, x > x, ({configurable: true, enumerable: (\n-22)}));");
/*fuzzSeed-116111302*/count=32; tryItOut("/*infloop*/for(d; x; ((void options('strict_mode')) - (z = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function() { throw 3; }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: SimpleObject, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: \u0009function (x = ({\u3056: undefined, window: x })) { return ({ get toString() { \"use strict\"; yield x } , \".2\": (4277) }) } , enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(\"\\u607D\"), (NaN = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })([null]), encodeURI, (1 for (x in [])))))))) {v2 = Object.prototype.isPrototypeOf.call(t0, g1); }");
/*fuzzSeed-116111302*/count=33; tryItOut("b0 + '';/*RXUB*/var r = null; var s = \"\"; print(r.exec(s)); print(r.lastIndex); function x(c, d = x ? x & x : ++Array.prototype.lastIndexOf, a, x, x, x, x, x = (4277), NaN, x =  \"\"  == [[1]], x = (makeFinalizeObserver('tenured')), w, NaN, this.NaN, w = true, NaN, a, x = [1], a = true, x, x = null,  , x)(yield this.__defineSetter__(\"z\", eval))/* no regression tests found */");
/*fuzzSeed-116111302*/count=34; tryItOut("{[]; }");
/*fuzzSeed-116111302*/count=35; tryItOut("a0.toString = (function(j) { f1(j); });");
/*fuzzSeed-116111302*/count=36; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.cbrt(let (d = let (w = undefined, cytoff, rhzczs, x, z, w, jlzbpl, z, rixyuv, bxgevj) x) (makeFinalizeObserver('tenured'))); }); testMathyFunction(mathy0, [-0x080000001, 0x0ffffffff, Number.MIN_VALUE, -0x100000000, -(2**53), 0x080000001, -0, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 0/0, 0x080000000, -1/0, 2**53+2, -(2**53+2), 1.7976931348623157e308, 0, Number.MAX_SAFE_INTEGER, 2**53, 1/0, 0x100000001, -(2**53-2), -0x07fffffff, 0x07fffffff, -0x100000001, 1, -0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 2**53-2, -Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=37; tryItOut("/*ODP-2*/Object.defineProperty(t2, \"((makeFinalizeObserver('tenured')))\", { configurable: (4277), enumerable: true, get: (function() { try { a1.pop(); } catch(e0) { } try { for (var v of m1) { this.e2.delete(a1); } } catch(e1) { } v0 = this.g0.eval(\"function f0(t0) \\\"use asm\\\";   var imul = stdlib.Math.imul;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, i1)\\n  {\\n    d0 = +d0;\\n    i1 = i1|0;\\n    var d2 = 17592186044416.0;\\n    d0 = (d0);\\n    return +((1073741825.0));\\n    {\\n      d2 = (d2);\\n    }\\nv2 = evalcx(\\\"return null;\\\", g0);    return +((Float64ArrayView[((((((0x8c23676) ? (0xf94c1971) : (0xfda941d9))-((0x0) == (0xc7ec142a)))>>>((i1)+((0x6e59f5c2) ? (0xbcbc66b4) : (0xb84cdf5))-(0x60acae50))) < (0x823e1236))-((~(0xe9ded*(i1))) <= (imul(((((0x7b9de09f))>>>((0x741e7207)))), (0xe226fa58))|0))) >> 3]));\\n  }\\n  return f;\"); return b1; }), set: (function mcc_() { var tqfbit = 0; return function() { ++tqfbit; if (false) { dumpln('hit!'); try { f0.__proto__ = a0; } catch(e0) { } a1[18]; } else { dumpln('miss!'); try { m0.set(v1, p2); } catch(e0) { } try { g1 + ''; } catch(e1) { } g1.v0 = x; } };})() });");
/*fuzzSeed-116111302*/count=38; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(this.h2, m1);");
/*fuzzSeed-116111302*/count=39; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?=[^]|\\\\b)|\\\\3+)+\", \"gi\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-116111302*/count=40; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var log = stdlib.Math.log;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -590295810358705700000.0;\n    d0 = (d1);\n    return ((((!(!(0xcf9a3754))) ? (!(0xffffffff)) : (-0x8000000))))|0;\n    {\n      (Uint32ArrayView[((/*FFI*/ff(((d1)), (((-(0xffcfe4f0)) << (((0xf90cf594) ? (0xff5a41ef) : (0x223667b0))))), ((524289.0)), ((NaN)), ((-7.555786372591432e+22)), ((-17179869185.0)), ((-8.0)))|0)+(/*FFI*/ff(((((0xf9d52198)-(0x53d241e8)+(0x64d10152)) >> (((0x0))-((0xfc71fd92) ? (0x1fd220a5) : (-0x3302d54))))), ((~~(549755813887.0))))|0)) >> 2]) = ((i2));\n    }\n    d0 = (+((((0x326d4bee))+((imul(((((0xb1b3e24b)) | ((0xf838ec37)))), (i2))|0))) | (({-2: -28 }))));\n    {\n      d3 = (+pow(((Infinity)), ((((((0x4e8720da)-(0x9ec053a8)+(0xfa4b5ce6)) | (-0xf1ed4*(0xff82a22d))) <= (((0x2a597eb5)) << ((0xe4788fc3)+(0xff5957fa)))) ? (+log(((+(((0xffffffff)*-0x5cc6c)>>>((0xc21b8609)+(0xfc1f9a51))))))) : ((1025.0) + (+(0.0/0.0)))))));\n    }\n    (Float64ArrayView[0]) = (((Float32ArrayView[0])));\n    {\n      d0 = (d1);\n    }\n    {\n      (Float64ArrayView[2]) = ((+/*FFI*/ff((({} = allocationMarker())), ((d3)), (((\"\\u82A7\"))), ((~(((((0xf6b18c08)) & ((0xfb9ff62b))) > (~((0xde9afd3b)+(0xfdd817ef))))+(((((17592186044417.0) > (2049.0)))>>>((i2))))))))));\n    }\n    return ((((abs((((Int16ArrayView[0])) << ((((0xe4aabb99) % (0x46381216))>>>(new (offThreadCompileScript)(null))) % (0xffffffff))))|0)) % (((((i2)*-0xfffff)>>>((0xc0decd79))) / ((((0xb9b21422) <= (0x6ef85ee8))+((-0x8000000) ? (0xfe69e8cf) : (0xfd116c0a)))>>>((0x5c110179) / (0xf30d946b))))>>>(((-0x8000000) ? ((-144115188075855870.0) > (-16385.0)) : (i2))-(i2)+(0x2713dc9b)))))|0;\n  }\n  return f; })(this, {ff: (1 for (x in []))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53), 0, -Number.MIN_VALUE, 0x080000000, 0x080000001, 1.7976931348623157e308, -1/0, 2**53, 0x100000001, -Number.MAX_SAFE_INTEGER, 42, 0/0, 0x100000000, 0.000000000000001, -0x080000000, 1, -0x100000000, 0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -(2**53+2), 2**53+2, -0x080000001, Number.MIN_VALUE, -(2**53-2), Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0, 1/0]); ");
/*fuzzSeed-116111302*/count=41; tryItOut("\"use strict\"; a1.push(i0, o0, s1, s2);");
/*fuzzSeed-116111302*/count=42; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x100000001, 1.7976931348623157e308, -(2**53+2), 1/0, 2**53, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, Number.MIN_VALUE, -(2**53-2), 0x100000001, -0x07fffffff, Number.MAX_VALUE, 0, -0x080000000, Number.MIN_SAFE_INTEGER, 1, 0/0, 2**53-2, 0.000000000000001, 2**53+2, -(2**53), -0x100000000, Math.PI, 0x07fffffff, 0x080000001, 42, -0, -Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=43; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (((( + (( ! (( ~ 0) !== y)) >>> 0)) || (( ~ ((Math.hypot((Math.min(Math.atanh(y), (( ~ ( + x)) | 0)) | 0), (( + Math.imul(x, -0x100000001)) << Math.pow((( + Math.imul(x, Math.fround(y))) >>> 0), x))) | 0) | 0)) | 0)) | 0) === (Math.fround(Math.fround(Math.hypot(Math.fround((Math.log2(y) | 0)), Math.fround((mathy0(Math.round(mathy1(0, 2**53-2)), ( + Math.sign(( + Math.atan2(Math.fround(y), y))))) >>> 0))))) >>> Math.fround(Math.cos(( ~ ((x >>> Math.fround(y)) >>> 0)))))); }); testMathyFunction(mathy2, [2**53-2, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000000, 0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -0x0ffffffff, 2**53, -(2**53-2), 0, 42, -0x080000001, -0x080000000, Math.PI, -0x100000001, -1/0, 0x080000001, -0, Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 2**53+2, 1, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 1/0, 0x07fffffff]); ");
/*fuzzSeed-116111302*/count=44; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-116111302*/count=45; tryItOut("a2.push();");
/*fuzzSeed-116111302*/count=46; tryItOut("g2 + '';");
/*fuzzSeed-116111302*/count=47; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-116111302*/count=48; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround(Math.fround((( + ( - ((Math.atan2(((Math.fround(x) >>> Math.fround(((y | 0) & Number.MAX_VALUE))) >>> 0), ( + Math.min(( + -1/0), ( + x)))) | 0) | 0))) ^ ( + Math.max(( + (( + Math.min(( + y), 42)) !== ( + (Math.hypot(((x <= y) | 0), (y | 0)) | 0)))), y))))))); }); testMathyFunction(mathy0, [0x080000001, 0x07fffffff, Number.MAX_VALUE, 2**53-2, 0.000000000000001, -0, 0/0, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, -1/0, 42, -(2**53-2), 0x0ffffffff, Number.MIN_VALUE, -0x100000000, 0, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000001, -Number.MIN_VALUE, -0x080000000, 1, 1.7976931348623157e308, -0x07fffffff, Math.PI, 1/0, 0x080000000, -0x0ffffffff, 2**53, -Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=49; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return Math.log1p((Math.cbrt((Math.fround(Math.max((Math.imul(Math.fround((Math.fround(( + (( + 0) ** ( + -0)))) ? Math.fround(y) : Math.fround(y))), Math.fround(( ~ y))) >>> 0), (( ~ ((Math.fround((Math.atan2((( ! y) | 0), (-(2**53+2) | 0)) | 0)) && x) | 0)) | 0))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-0x07fffffff, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, 0x080000001, 1, -0x100000001, -Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, -0x080000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0x07fffffff, 2**53-2, -0x080000001, 0, Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, 0.000000000000001, -1/0, Number.MIN_VALUE, -(2**53+2), 1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, 0x100000000, -0x0ffffffff, 2**53]); ");
/*fuzzSeed-116111302*/count=50; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = ((0x6feb9d3) <= (0x4b74d429));\n    (Int8ArrayView[((((0xdecb0550)+(0x709a9b70)-(0xf9ed113a))>>>((-0x8000000) / (0x1fd3ca9d))) / (((i0))>>>((0xfb267ee1)-(0xf7aba4db)))) >> 0]) = ((i0));\n    i2 = (!(i2));\n    return (((0x1e052926) / ((((((0x3bfa46e9))>>>((0x1195c5c5))) <= (((0xf9fa547b))>>>((0x1b2c9a3c))))-(/*FFI*/ff(((((+/*FFI*/ff(((-1.03125))))) / ((Infinity)))), ((((0xf95a1206)) << ((0xfecc3f75)))), ((((0x1461918b)) | ((0x24a3a848)))), ((-1.1805916207174113e+21)))|0)-(0x4006f7f3))>>>((0xffe5e647)))))|0;\n  }\n  return f; })(this, {ff: Date.prototype.setUTCDate}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), 2**53-2, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, -(2**53), 2**53+2, -0x07fffffff, -0x100000001, -0x0ffffffff, -0x080000001, -0x080000000, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, Math.PI, 0/0, 0x080000000, 0x100000000, 1/0, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, 0x080000001, 42, -(2**53+2), 0, -0x100000000, 0x07fffffff, 1]); ");
/*fuzzSeed-116111302*/count=51; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround((Math.atan2(( ! y), Math.hypot(( + Math.acos(y)), Math.atan2(x, x))) >= Math.fround(((Math.fround(( + (( + Math.fround(Math.hypot((Math.sqrt((Math.fround(Math.max(Math.fround(-1/0), Math.fround(y))) | 0)) | 0), Math.trunc(y)))) >>> ( + ( + (( + y) >>> ( + x))))))) ^ Math.fround(Math.acosh((((Math.expm1(( + Math.log10(x))) >>> 0) ? (Math.tan(-0x100000000) >>> 0) : Math.fround(Math.atan2(Math.round(x), 1))) >>> 0)))) >>> 0)))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , objectEmulatingUndefined()]); ");
/*fuzzSeed-116111302*/count=52; tryItOut("\"use strict\"; for (var p in a2) { a2.unshift(m0); }");
/*fuzzSeed-116111302*/count=53; tryItOut("mathy0 = (function(x, y) { return ( + ( - Math.max(((Math.tan(y) >>> 0) || ((((Math.min((0x080000000 >>> 0), -0x080000000) >>> 0) >>> 0) === ((Math.sqrt((y | 0)) | 0) >>> 0)) >>> 0)), ((((( - (y >>> 0)) >>> 0) | 0) ? ((((x | 0) > (Math.acosh(( + Number.MIN_VALUE)) >>> 0)) | 0) | 0) : Math.fround((((y >>> 0) ? Math.fround(Math.atan(( + 0x080000000))) : (( - ((( + -Number.MIN_VALUE) + ( + x)) >>> 0)) >>> 0)) >>> 0))) | 0)))); }); ");
/*fuzzSeed-116111302*/count=54; tryItOut("b1 = t1.buffer;");
/*fuzzSeed-116111302*/count=55; tryItOut("Array.prototype.forEach.apply(a2, [(function(j) { if (j) { try { s2 = g2.objectEmulatingUndefined(); } catch(e0) { } this.m2.valueOf = this.f1; } else { try { m2 = new Map(s1); } catch(e0) { } try { e2.__proto__ = v1; } catch(e1) { } e2.add(h2); } }), a0]);");
/*fuzzSeed-116111302*/count=56; tryItOut("\"use strict\"; v2 = g2.eval(\"mathy2 = (function(x, y) { return (Math.sinh((Math.fround(Math.pow(Math.fround(Math.tan(( + Math.max(( + mathy0(x, (1.7976931348623157e308 >>> 0))), ( + ( + Math.min(( + x), ( + -Number.MAX_SAFE_INTEGER)))))))), Math.fround(( ~ x)))) | 0)) * Math.min(( ! x), Math.fround(( ! Math.atan2(Math.atan2(( + y), x), (((y << y) >>> 0) ? (y >>> 0) : (y >>> 0))))))); }); testMathyFunction(mathy2, [0x080000000, -0x080000001, 2**53-2, 1, -0x100000000, -1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, 1.7976931348623157e308, -(2**53+2), -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 0/0, -0, Number.MIN_VALUE, 0x0ffffffff, 0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 0x100000000, 0x07fffffff, -0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, Math.PI, -0x080000000, 0x080000001, 2**53+2]); \");");
/*fuzzSeed-116111302*/count=57; tryItOut("Array.prototype.reverse.call(a2);");
/*fuzzSeed-116111302*/count=58; tryItOut("\"use strict\"; v2 = evaluate(\"(4277)\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (\n-2 , /^*/g), noScriptRval: \"\\uBAF3\", sourceIsLazy: (x % 3 == 2), catchTermination: (x % 27 != 21) }));");
/*fuzzSeed-116111302*/count=59; tryItOut("\"use asm\"; for (var p in e0) { try { /*RXUB*/var r = r2; var s = s1; print(uneval(s.match(r)));  } catch(e0) { } try { a0 = new Array; } catch(e1) { } v1.toString = (function() { for (var j=0;j<9;++j) { this.f0(j%4==0); } }); }");
/*fuzzSeed-116111302*/count=60; tryItOut("print(x);");
/*fuzzSeed-116111302*/count=61; tryItOut("/*tLoop*/for (let z of /*MARR*/[(-1/0), (-1/0), (-1/0), (({lastIndexOf:  /x/g  })), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), (-1/0), function(){}, (({lastIndexOf:  /x/g  })), -(2**53), -(2**53), -(2**53), function(){}, (-1/0), (({lastIndexOf:  /x/g  })), (({lastIndexOf:  /x/g  })), function(){}, -(2**53), function(){}, -(2**53), -(2**53), (({lastIndexOf:  /x/g  })), -(2**53), -(2**53), (-1/0), (({lastIndexOf:  /x/g  })), (-1/0), function(){}, (-1/0), function(){}, (-1/0), -(2**53), function(){}, (-1/0), -(2**53), (-1/0), -(2**53), (({lastIndexOf:  /x/g  })), function(){}, -(2**53), -(2**53), function(){}, -(2**53), -(2**53), -(2**53), function(){}, function(){}, (-1/0), function(){}, (-1/0), function(){}, -(2**53), function(){}, -(2**53), function(){}, (-1/0), -(2**53), function(){}, -(2**53), function(){}, function(){}, (({lastIndexOf:  /x/g  })), function(){}, (-1/0), -(2**53), (-1/0), -(2**53), (-1/0), (-1/0), function(){}, -(2**53), (-1/0), -(2**53), -(2**53), function(){}, -(2**53), (-1/0), (-1/0), (({lastIndexOf:  /x/g  })), (-1/0), -(2**53), (({lastIndexOf:  /x/g  })), (({lastIndexOf:  /x/g  })), (-1/0), (-1/0), (-1/0), (-1/0), (({lastIndexOf:  /x/g  })), -(2**53), -(2**53), function(){}, function(){}, function(){}, function(){}, -(2**53), -(2**53), (({lastIndexOf:  /x/g  })), -(2**53), function(){}, -(2**53), function(){}, function(){}, -(2**53), -(2**53), function(){}, (-1/0), (-1/0), (-1/0), function(){}, (({lastIndexOf:  /x/g  })), (-1/0), function(){}, function(){}, (({lastIndexOf:  /x/g  })), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), function(){}, (-1/0), (-1/0), (({lastIndexOf:  /x/g  }))]) { o1.e2.has(a0); }");
/*fuzzSeed-116111302*/count=62; tryItOut("{/*bLoop*/for (let dstcsj = 0, z = []; dstcsj < 22; ++dstcsj) { if (dstcsj % 6 == 4) { g0 = this; } else { print(Math.min(-20, this) || DFGTrue(\"\\uE4FD\", 033)); }  } /*infloop*/do s1 + ''; while((makeFinalizeObserver('nursery'))); }");
/*fuzzSeed-116111302*/count=63; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d1 = (+exp(((Float64ArrayView[2]))));\n    }\n    d1 = (d0);\n    return ((((((0xfd4c822d))>>>((Int16ArrayView[2]))) == ((0x2bde2*(/*FFI*/ff(((~(((4277))))))|0))>>>((~((0x40d88ee2))) / (((0x838d87de)-(0xc161d109)) & ((0x7fb2951e))))))))|0;\n  }\n  return f; })(this, {ff:  /x/g }, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0.000000000000001, -(2**53+2), -Number.MIN_VALUE, 2**53, -0x100000001, -Number.MIN_SAFE_INTEGER, Math.PI, -0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, -(2**53), 1/0, Number.MAX_VALUE, -0x080000000, 0x100000001, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1, -0x100000000, 0x100000000, -1/0, -0x080000001, Number.MAX_SAFE_INTEGER, 42, -0, 0x080000000, -(2**53-2), 2**53-2, 0, 0x080000001, 0/0, 2**53+2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-116111302*/count=64; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.round((( ~ (x ** ((x | 0) * ((y > x) | 0)))) ^ (y , ( + ( + Math.imul(( + ( + Math.exp((( + Math.trunc(x)) | 0)))), ( + y)))))))); }); testMathyFunction(mathy0, [1/0, 0x080000001, -Number.MAX_SAFE_INTEGER, 0/0, 1, 0.000000000000001, -0x080000001, -Number.MIN_VALUE, 0x07fffffff, 2**53, 0x100000001, -(2**53+2), Math.PI, -0x080000000, -0, -Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, -0x07fffffff, 2**53-2, -(2**53), Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, 42, -0x100000001, 0x080000000, 2**53+2, 0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=65; tryItOut("\"use strict\"; v1 = g1.r1.constructor;");
/*fuzzSeed-116111302*/count=66; tryItOut("mathy4 = (function(x, y) { return mathy0((++Symbol), mathy1(( + ((((-Number.MAX_VALUE || Math.tanh(Math.max(x, -(2**53)))) >>> 0) != ( + mathy0(Math.atan2((x >>> 0), ( + x)), ( + ( + x))))) >>> 0)), Math.fround((Math.acos((Math.abs(((x < Math.fround(-(2**53+2))) >>> 0)) >>> 0)) >= mathy2(( + Math.fround(x)), x))))); }); testMathyFunction(mathy4, /*MARR*/[true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' ,  'A' , true,  'A' , true, true,  'A' , true,  'A' , true,  'A' , true, true]); ");
/*fuzzSeed-116111302*/count=67; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + Math.fround(Math.pow(Math.fround(( - Math.fround((y ? y : (Number.MAX_SAFE_INTEGER ^ y))))), Math.fround((mathy0(Math.pow((( ~ ( + x)) >>> 0), (Math.hypot((y >>> 0), (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)), ( ! ( + x))) % Math.fround((( - mathy0(-0x080000000, y)) ? Math.fround(y) : Math.min(y, (y >>> 0))))))))); }); testMathyFunction(mathy1, [-(2**53-2), 2**53, 2**53-2, -0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, 42, 0x080000000, -Number.MAX_VALUE, -0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53+2, -(2**53+2), 0x07fffffff, -0x080000000, 0x0ffffffff, -0, Number.MAX_VALUE, -0x0ffffffff, -1/0, 0.000000000000001, -Number.MIN_VALUE, 0/0, 1, 0x100000001, 1/0, 0, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-116111302*/count=68; tryItOut("i1.next();");
/*fuzzSeed-116111302*/count=69; tryItOut("/*RXUB*/var r = /\ud73c{4,}/i; var s = \"\\ud73c\\u0098\\ud73c\\ud73c\\ud73c\\u0098\"; print(s.match(r)); ");
/*fuzzSeed-116111302*/count=70; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.imul((( ~ (1 | 0)) | 0), Math.atan2(( + x), (Math.min(((x ? x : Math.fround(((0x07fffffff >>> 0) < (0x100000000 >>> 0)))) >>> 0), (Math.fround(Math.max(Math.fround(x), Math.max(1.7976931348623157e308, y))) >>> 0)) >>> 0))) , ((x / Math.atan2(Math.ceil((-0x080000000 >>> 0)), Math.atan2(-0x100000001, x))) - Math.tanh(( - (Math.fround(Math.ceil(Math.fround(x))) | 0))))); }); ");
/*fuzzSeed-116111302*/count=71; tryItOut("/*infloop*/ for  each(var \u3056 in (Math.acos(28))) print(uneval(i1));");
/*fuzzSeed-116111302*/count=72; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.trunc(( + Math.fround((( ~ ( + Math.max(( - x), ( + Math.abs(Math.fround((y % x))))))) >>> ((( ~ ( + (42 ^ (( - (2**53+2 >>> 0)) >>> 0)))) ? Math.fround(mathy1(( - 0x080000000), Math.asin(x))) : ( + x)) >>> 0)))))); }); testMathyFunction(mathy5, [-(2**53), 0, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, 1, 0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, -0, 2**53, -0x100000001, 0.000000000000001, -1/0, 1/0, -(2**53-2), -0x080000001, -(2**53+2), 0/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 0x100000000, 0x080000000, Number.MIN_VALUE, Number.MAX_VALUE, 0x100000001, 2**53-2]); ");
/*fuzzSeed-116111302*/count=73; tryItOut("a2.splice();");
/*fuzzSeed-116111302*/count=74; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.sinh(( ! y)), (Math.max(Math.clz32((Math.abs(Math.min(x, ( ~ Math.fround(y)))) >>> 0)), ((((( + (((Math.imul(Math.abs(2**53), 2**53-2) | 0) ^ ( + y)) | 0)) | 0) >>> 0) ? mathy0(y, x) : ((( ~ y) | 0) >>> 0)) >>> 0)) | 0)); }); testMathyFunction(mathy1, /*MARR*/[[(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], new Boolean(true), [(void 0)], [(void 0)], new Boolean(true), [(void 0)], new Boolean(true), [(void 0)], new Boolean(true), new Boolean(true), new Boolean(true), [(void 0)], new Boolean(true), [(void 0)], [(void 0)], new Boolean(true), new Boolean(true), [(void 0)], [(void 0)], new Boolean(true), [(void 0)], new Boolean(true), [(void 0)], [(void 0)], [(void 0)], [(void 0)], new Boolean(true), new Boolean(true), [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], new Boolean(true), new Boolean(true), [(void 0)], [(void 0)], new Boolean(true)]); ");
/*fuzzSeed-116111302*/count=75; tryItOut("mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + Math.min(( + ( - mathy0((Math.fround(( + Math.fround((((x | 0) ? (mathy0(x, y) | 0) : x) | 0)))) ? ( + ( ! -0x080000001)) : Math.log1p((Math.max(y, 2**53+2) | 0))), x))), mathy0(Math.fround((( + (y ** ((( + Math.log2(x)) | 0) ** Math.fround((Math.fround(-0x0ffffffff) ? (x >>> 0) : Math.fround(y)))))) - Math.fround(( + Math.fround(Math.hypot(y, x)))))), ((y + ( + mathy0(( + (Math.atan2((function() { return \n[,] !==  /x/ ; } >>> 0), (Math.log(0.000000000000001) >>> 0)) >>> 0)), ( + (mathy0(x, x) >>> 0))))) >>> 0)))); }); testMathyFunction(mathy1, [2**53+2, 0x080000001, -0x080000001, Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 0, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, -Number.MIN_VALUE, 0/0, Number.MAX_VALUE, 0x07fffffff, -0x080000000, -Number.MAX_VALUE, 1.7976931348623157e308, -0x07fffffff, Math.PI, -(2**53-2), 2**53-2, -0x0ffffffff, 1, 0x0ffffffff, -1/0, -0x100000001, Number.MIN_VALUE, -(2**53), 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), 42, 0.000000000000001, 1/0]); ");
/*fuzzSeed-116111302*/count=76; tryItOut("mathy1 = (function(x, y) { return ((( - (( + ((x >>> 0) || x)) && ( + ( + x)))) <= ( ! Math.atan2(mathy0(Math.pow(1/0, y), (0/0 >>> 0)), ( + (( + Math.tanh((y | 0))) >>> ( + y)))))) > (Math.asinh(Math.fround(mathy0((((( ~ (y >>> 0)) >>> 0) && x) >>> 0), (( + Math.atanh(( + y))) | 0)))) | 0)); }); testMathyFunction(mathy1, [-0x080000001, -0x100000000, -0x0ffffffff, Math.PI, Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, -1/0, -0x07fffffff, 1/0, -Number.MAX_VALUE, 0, -(2**53), Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 42, 1, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -(2**53+2), -0x100000001, 0x080000001, 0.000000000000001, -0, 2**53, 2**53+2, 0x080000000, 0x100000000, 0x100000001]); ");
/*fuzzSeed-116111302*/count=77; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0x0ffffffff, 1, -(2**53+2), -0x080000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, -0x0ffffffff, 0x100000000, 0x100000001, -0x080000000, -0x100000000, 0.000000000000001, -Number.MIN_VALUE, -0, -0x07fffffff, 0/0, 2**53, -0x100000001, 0x080000000, Number.MIN_VALUE, 42, -1/0, 1/0, 2**53-2, 0x07fffffff, 0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-116111302*/count=78; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((((( ~ (Math.atan2(Math.fround(( - y)), ( + Math.atan2(mathy0(y, x), (Math.atanh((( + (( + Number.MAX_SAFE_INTEGER) ? ( + ( + Number.MIN_VALUE)) : ( + ( - x)))) >>> 0)) | 0)))) | 0)) >>> 0) | 0) >>> (( + Math.hypot((Math.sin((( - (x | 0)) | 0)) >>> 0), ( + (( + ( ~ mathy1(y, Math.fround(2**53-2)))) > ( + x))))) | 0)) | 0); }); testMathyFunction(mathy2, [0.1, (new Boolean(true)), null, undefined, '\\0', NaN, (new Number(-0)), (new String('')), [], (function(){return 0;}), '', ({valueOf:function(){return 0;}}), -0, false, 1, '0', objectEmulatingUndefined(), [0], ({toString:function(){return '0';}}), '/0/', 0, true, /0/, (new Number(0)), (new Boolean(false)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-116111302*/count=79; tryItOut("h2.delete = (function mcc_() { var dagrto = 0; return function() { ++dagrto; if (/*ICCD*/dagrto % 2 == 1) { dumpln('hit!'); try { m1.get(v0); } catch(e0) { } try { for (var v of g1) { try { /*MXX3*/this.g1.Array.prototype.toLocaleString = g1.Array.prototype.toLocaleString; } catch(e0) { } try { o2.v0 = r1.constructor; } catch(e1) { } try { this.v2 = t1.length; } catch(e2) { } Array.prototype.push.call(a0, v2, x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: objectEmulatingUndefined, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: Math.asin, delete: function() { throw 3; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: [,,z1], }; })(-13), false.watch(\"0\", URIError.prototype.toString)), o2, g1.i1, this.f0); } } catch(e1) { } try { /*MXX1*/o0 = g2.Root.name; } catch(e2) { } m1 = new Map; } else { dumpln('miss!'); try { v2 = (g1.o1 instanceof this.e1); } catch(e0) { } try { a0.unshift(s2, i1); } catch(e1) { } try { t2 + g1.s0; } catch(e2) { } g1.f1.__proto__ = e2; } };})();");
/*fuzzSeed-116111302*/count=80; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.hypot(Math.imul(( ~ ( ! y)), (Math.imul((( + mathy0(Math.fround(( + ( ! Math.fround(Number.MAX_VALUE)))), ( + x))) | 0), -(2**53-2)) >>> 0)), Math.pow((mathy1((Math.fround(( - Math.fround(Math.hypot(x, y)))) >>> 0), (Math.abs(( + (Math.fround((Math.fround(Math.min(y, ( + -0x100000001))) && ( + 0x0ffffffff))) % Math.fround(( ~ Math.fround(Math.asin(y))))))) >>> 0)) >>> 0), (Math.max((( + y) >>> 0), Math.fround(Math.expm1(Math.fround(Math.log1p(Math.fround(y)))))) >>> 0))); }); testMathyFunction(mathy2, [0, -1/0, Number.MAX_VALUE, 0x0ffffffff, 0x080000001, 1/0, Math.PI, -Number.MIN_SAFE_INTEGER, 42, -(2**53+2), 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, 0.000000000000001, 0x07fffffff, -0, -0x080000000, -0x07fffffff, 2**53-2, 1, 0/0, -0x100000000, 0x100000000, Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), 2**53, -0x100000001, -(2**53), -0x080000001, 0x100000001, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=81; tryItOut("a2 = arguments.callee.arguments;");
/*fuzzSeed-116111302*/count=82; tryItOut("selectforgc(o2);");
/*fuzzSeed-116111302*/count=83; tryItOut("print(window ? (--RangeError) : (4277));");
/*fuzzSeed-116111302*/count=84; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.fround(Math.cbrt(((( + -0x080000001) == (x & x)) && ( ! x)))) < ( + mathy0(Math.fround((( + (Math.hypot(x, Math.fround(( + ( + x)))) | 0)) >>> 0)), (x - x)))); }); ");
/*fuzzSeed-116111302*/count=85; tryItOut("\"use strict\"; a2.push(s0);");
/*fuzzSeed-116111302*/count=86; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.acos(Math.fround((Math.fround((Math.sqrt(Math.clz32((Math.fround(y) == y))) + (Number.MAX_SAFE_INTEGER ? x : ( + Math.min(( + x), ( + y)))))) | Math.fround(Math.fround(y))))); }); testMathyFunction(mathy0, [[0], 1, ({toString:function(){return '0';}}), '0', (new Number(0)), 0.1, undefined, ({valueOf:function(){return '0';}}), false, objectEmulatingUndefined(), true, (new Boolean(true)), (new Number(-0)), '\\0', 0, (new Boolean(false)), -0, /0/, '/0/', [], ({valueOf:function(){return 0;}}), '', (new String('')), (function(){return 0;}), NaN, null]); ");
/*fuzzSeed-116111302*/count=87; tryItOut("v0 = a1.every((function mcc_() { var muhybf = 0; return function() { ++muhybf; if (/*ICCD*/muhybf % 10 == 8) { dumpln('hit!'); try { s0 = o1.a1.join(s1); } catch(e0) { } try { s0 += s2; } catch(e1) { } try { a2.reverse(m0); } catch(e2) { } v2 = true; } else { dumpln('miss!'); try { v0 = t0.length; } catch(e0) { } try { o0.a0.shift(); } catch(e1) { } v1 = (function shapeyConstructor(vgjgpc){for (var ytqhegjyv in this) { }Object.seal(this);this[\"caller\"] = let (z) true | allocationMarker();if (vgjgpc) { print(x); } delete this[\"caller\"];this[\"caller\"] = /*FARR*/[\"\\u4542\", -18, ...[], ...[], -13, , ...[], ...[], x, [], \"\\u10F1\", ].sort(function(q) { \"use strict\"; return q; }, null);return this; }/*tLoopC*/for (let b of x if (x)) { try{let xjbnon = shapeyConstructor(b); print('EETT'); print(xjbnon);}catch(e){print('TTEE ' + e); } }); } };})(), s1);");
/*fuzzSeed-116111302*/count=88; tryItOut("a2 = a0.map((function mcc_() { var dpyfgg = 0; return function() { ++dpyfgg; if (/*ICCD*/dpyfgg % 5 == 0) { dumpln('hit!'); /*RXUB*/var r = this.r2; var s = \"aaaa\\u00c1aaaaa\"; print(r.exec(s)); print(r.lastIndex);  } else { dumpln('miss!'); try { s1 = s0.charAt(2); } catch(e0) { } try { g1.g1.p2.toSource = (function() { a2.splice(8, ({valueOf: function() { i1 = new Iterator(b0);function x(x, x)\"use asm\";   function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 4503599627370497.0;\n    i1 = (0xffffffff);\n    d2 = (d2);\n    {\n      {\n        {\n          d2 = (((d2)) / ((-1.888946593147858e+22)));\n        }\n      }\n    }\n    return +((-4294967296.0));\n  }\n  return f;s0 += 'x';return 17; }}), o0, this.f2); return h0; }); } catch(e1) { } try { i2 = m0.iterator; } catch(e2) { } e2 + v2; } };})());");
/*fuzzSeed-116111302*/count=89; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (( + ( + ( ~ (Math.acosh(Math.fround(Math.max(Math.fround((mathy0(((( ! (1 >>> 0)) >>> 0) | 0), (y | 0)) | 0)), Math.fround((Math.sign((Math.cosh(y) >>> 0)) >>> 0))))) >>> 0)))) >= mathy0(( + Math.max(Math.fround(Math.fround((y | Math.fround(( + ( ! ( + ( + mathy0(( + ( + Math.min(x, -(2**53+2)))), (y | 0)))))))))), ( + y))), Math.fround(Math.ceil(Math.fround(Math.clz32(Math.sin((x >>> 0)))))))); }); ");
/*fuzzSeed-116111302*/count=90; tryItOut("i2 = new Iterator(i0);");
/*fuzzSeed-116111302*/count=91; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var sin = stdlib.Math.sin;\n  var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -18446744073709552000.0;\n    var d3 = -2.3611832414348226e+21;\n    d2 = (2.4178516392292583e+24);\n    i0 = (0x65bfb22);\n    {\n      (Uint8ArrayView[2]) = (((0x37bd53ce) >= (0x96039243)));\n    }\n    {\n      d1 = (+sin(((+(((new ((runOffThreadScript).bind())([z1,,])) / (0x14cb98df))>>>((0xe38d9a3d)))))));\n    }\n    d2 = (+((d1)));\n    d2 = (d2);\n    {\n      {\n        d1 = (+(~((i0))));\n      }\n    }\n    (Float64ArrayView[4096]) = ((d3));\n    (Int16ArrayView[4096]) = ((i0)+(0xffffffff)-((i0) ? ((((0xb5d7605a)+(0xf92983d6)) << (-0xfffff*(0x7e24f930))) > ((Float32ArrayView[4096]))) : (!(!(i0)))));\n    return (((((((((0x1323f543)-(0x62348005)-(0xb1b87c45))>>>(-0x8af03*(0xf9330cf9))))-(0x60b9b6ca)+((((0xfe697f78))>>>((0xbc76871e))) > (((0xfc60bab3))>>>((-0x8000000))))) & ((0xffffffff))))-((0x3b53336c))))|0;\n    i0 = ((((((i0)) & ((\"\\uE939\" >>> {}))) / (imul((0x403b28c2), ((~((0xcb77055b)))))|0))>>>((i0))) == (0xd9d06e0f));\n    {\n      d3 = (+(0.0/0.0));\n    }\n    i0 = (0x4ef373b);\n    {\n      d1 = (d2);\n    }\nv0 = g1.g0.runOffThreadScript();function d(z, b = window, x, window, x, e = \"\\u9624\", x, this, w, window, \u3056, yield, x, y, x = new RegExp(\"(?:(\\\\B)|((?=\\u4837)){4,6})*\", \"y\"), NaN, NaN, x, c, b, NaN, \u3056, c, z, w) { \"use strict\"; return false } print(x);    d3 = (+abs(((0.001953125))));\n    return (((0xb037769b)))|0;\n  }\n  return f; })(this, {ff: Object.getOwnPropertyNames}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [2**53, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, -(2**53+2), 0x0ffffffff, 0x100000000, -0x080000000, -0x07fffffff, -0x100000000, -0, -Number.MIN_VALUE, 2**53-2, 2**53+2, -Number.MIN_SAFE_INTEGER, 1, -(2**53), Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -0x100000001, 0.000000000000001, -0x0ffffffff, -1/0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000001, Number.MIN_VALUE, 1/0, 0x080000000, 0x080000001, Math.PI, -(2**53-2), 1.7976931348623157e308, 42]); ");
/*fuzzSeed-116111302*/count=92; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ! Math.hypot(( + Math.imul((Math.tan(y) >>> 0), Math.imul(y, x))), Math.expm1(y))) != Math.tanh((Math.imul((Math.log10(( + y)) | 0), (Math.sign((( + mathy2(-0, y)) != y)) >>> 0)) | 0))); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, -0x100000001, -0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, -(2**53-2), -0, -0x080000000, -1/0, 0x080000000, Math.PI, 1, 0x0ffffffff, -0x0ffffffff, 0x080000001, 0, 0.000000000000001, 0x07fffffff, 0x100000001, 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0/0, 2**53, Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000000, -(2**53+2), Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=93; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ Math.tanh(( + (mathy0((mathy0(Math.fround((((y >>> 0) < Math.fround(Math.hypot((Math.sinh((-0x0ffffffff >>> 0)) | 0), (Math.hypot((y | 0), (y | 0)) | 0)))) >>> 0)), Number.MIN_SAFE_INTEGER) >>> 0), (Math.abs((( + Number.MAX_SAFE_INTEGER) ? ( + (x <= (( ~ (y | 0)) | 0))) : ( + ( ! (Math.ceil((-(2**53+2) >>> 0)) | 0))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [2**53+2, 1/0, 2**53, 0x100000000, -Number.MAX_VALUE, 0x080000000, 0.000000000000001, 42, -1/0, -0x080000000, 0x080000001, Number.MAX_VALUE, -(2**53+2), -(2**53-2), -(2**53), Math.PI, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000001, 2**53-2, -0x0ffffffff, 1, 0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, 0/0, -0x100000000, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=94; tryItOut("this.i2 = new Iterator(b2, true);");
/*fuzzSeed-116111302*/count=95; tryItOut("if((x % 6 == 2)) {/* no regression tests found */g2.a1 + this.h0; } else  if ('fafafa'.replace(/a/g, \"\\u9F33\".throw(new RegExp(\"(?=[G-\\u4a31\\u31ca-\\\\u7209\\\\u8eF3-\\ubd24])|(?:(?!(P)))*?\", \"gi\") ^= \"\\uB116\"))) {/*MXX2*/g2.DataView.prototype.getUint8 = o1; }");
/*fuzzSeed-116111302*/count=96; tryItOut("print(uneval(e2));");
/*fuzzSeed-116111302*/count=97; tryItOut("t0 + h2;");
/*fuzzSeed-116111302*/count=98; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((((Math.imul((Math.fround(( - (2**53+2 | 0))) >>> 0), (((Math.ceil(y) | 0) >> Math.expm1((y >>> 0))) >>> 0)) >>> 0) | 0) >>> (-0x07fffffff | 0)) + Math.tanh((( ! Math.fround(Math.fround(Math.fround(( + ((y | 0) !== x)))))) | 0))) % (( + ( + (Math.fround(( + Math.hypot(( + -0x100000001), ( + -1/0)))) - (( + Math.fround(Math.pow(( + ( + Math.abs(-Number.MIN_SAFE_INTEGER))), ( + x)))) ? ( + ( ! 2**53)) : ( + Math.fround(( + Math.fround(y)))))))) ? (Math.cosh(((Math.fround(y) ? Math.fround(( + Math.hypot((-(2**53+2) >>> 0), (x < -(2**53+2))))) : Math.fround(Math.max(y, x))) >>> 0)) >>> 0) : Math.hypot((((x | 0) < Math.fround(y)) >> x), ((y % (x >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), false, (void 0), (void 0), false, (void 0), (void 0), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), (void 0), (void 0), false, false, (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), (void 0), (void 0), objectEmulatingUndefined(), (void 0), false, (void 0), objectEmulatingUndefined(), (void 0), false, objectEmulatingUndefined(), objectEmulatingUndefined(), (void 0), false, objectEmulatingUndefined(), false, false, false, (void 0), false, (void 0), objectEmulatingUndefined(), false, false, false, objectEmulatingUndefined(), (void 0), false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), false, false, false, objectEmulatingUndefined(), (void 0), (void 0), objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, (void 0), objectEmulatingUndefined(), (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), false, (void 0), (void 0), objectEmulatingUndefined(), false, objectEmulatingUndefined()]); ");
/*fuzzSeed-116111302*/count=99; tryItOut("this.g0.t2.set(a1, 2);");
/*fuzzSeed-116111302*/count=100; tryItOut("\"use strict\"; g1.v2 = (m2 instanceof t2);");
/*fuzzSeed-116111302*/count=101; tryItOut("mathy2 = (function(x, y) { return (Math.asin((((Math.ceil(y) ? (Math.acosh(((Math.max(x, -0x07fffffff) | 0) | 0)) > x) : ( + mathy0(((( + Math.acos((y >>> 0))) & ( + -0x100000001)) ^ ( + Math.acosh(( + (y ? y : x))))), ( + Math.min(2**53, ( + (Number.MAX_VALUE || Math.fround(Math.fround(Math.fround(y)))))))))) >>> 0) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [1.7976931348623157e308, -0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, 0/0, -1/0, 0x080000001, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53+2), 1/0, 0x100000000, Number.MAX_VALUE, 0x0ffffffff, -0x100000000, 0x100000001, 2**53+2, 0x080000000, -0x0ffffffff, 1, -Number.MAX_VALUE, -(2**53), 42, -0x080000001, 2**53-2, -(2**53-2), Number.MIN_VALUE, -0x07fffffff, -Number.MIN_VALUE, 0]); ");
/*fuzzSeed-116111302*/count=102; tryItOut("{print( \"\" );v0 = Object.prototype.isPrototypeOf.call(i1, s2);for (var v of a1) { this.f1 + ''; } }");
/*fuzzSeed-116111302*/count=103; tryItOut("o2.v0 = true;");
/*fuzzSeed-116111302*/count=104; tryItOut("mathy5 = (function(x, y) { return (( ! (Math.log10(Math.fround(( ! Math.log((Math.imul(2**53, Math.fround(mathy0(y, y))) & x))))) | 0)) >>> 0); }); testMathyFunction(mathy5, [42, -0x080000000, 1/0, 0, Number.MIN_VALUE, 2**53+2, 0x080000000, 0.000000000000001, -0x07fffffff, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), -0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, -(2**53+2), 0/0, 0x0ffffffff, 1, -(2**53), -Number.MAX_VALUE, -0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, -1/0, 2**53, -0x080000001, 0x07fffffff]); ");
/*fuzzSeed-116111302*/count=105; tryItOut("v0 = evaluate(\"a1.unshift(s2, t2, t1);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 4 == 0), sourceIsLazy: false, catchTermination: (x % 14 != 7) }));");
/*fuzzSeed-116111302*/count=106; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.max(Math.tanh((((( + Math.pow(y, -Number.MAX_SAFE_INTEGER)) | 0) >= ((((((x >>> 0) , x) >>> 0) >> (((( + Math.sinh(x)) % Math.fround(Math.log2(-1/0))) | 0) >>> 0)) >>> 0) | 0)) | 0)), ( + Math.min(( + Math.fround((Math.fround(( - Math.fround(mathy1(((Math.pow(( + -0x100000001), 2**53-2) >>> 0) >>> 0), ( + ((x >>> 0) ** x)))))) != Math.fround(Math.abs(Math.fround(Math.pow(Math.fround(Math.fround(( + Math.fround(x)))), Math.fround(-(2**53+2))))))))), ( + (mathy2((-0x100000000 > (x ? -0 : x)), x) ? (( + (x | 0)) | 0) : ( + (( + x) >= ( + 2**53)))))))); }); testMathyFunction(mathy4, [-0x080000001, Math.PI, 2**53, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000000, 2**53-2, -0x100000001, -0x080000000, -(2**53+2), Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_VALUE, -0, 0x0ffffffff, 1/0, 0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 0/0, 0, 42, 1, -Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, -0x100000000, 1.7976931348623157e308, -0x0ffffffff, 0x100000001, Number.MIN_VALUE, -0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-116111302*/count=107; tryItOut("\"use strict\"; e2 = new Set(a2);");
/*fuzzSeed-116111302*/count=108; tryItOut("\"use strict\"; new x();");
/*fuzzSeed-116111302*/count=109; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116111302*/count=110; tryItOut("m1.set(g2, s1);");
/*fuzzSeed-116111302*/count=111; tryItOut("return;x.constructor;");
/*fuzzSeed-116111302*/count=112; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.trunc(( ~ (Math.min(Math.fround(( ~ (x >>> 0))), ((mathy0((x >>> 0), (( + Math.pow((((x >>> 0) && (y >>> 0)) >>> 0), x)) >>> 0)) | 0) | 0)) >>> 0))) & Math.asinh((mathy0(( + ( - ( + y))), y) ** (((x >>> 0) & ( + x)) >>> 0)))); }); testMathyFunction(mathy1, [1, 0.000000000000001, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -0x0ffffffff, -Number.MAX_VALUE, 0x0ffffffff, -0x100000000, -(2**53), Number.MIN_VALUE, -0x080000001, 2**53, 1.7976931348623157e308, -(2**53+2), Number.MAX_VALUE, -0x080000000, 2**53+2, 0/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, 0x07fffffff, 0x100000001, -0x07fffffff, 0x080000001, -0, Math.PI, 2**53-2, 0, 1/0, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-116111302*/count=113; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -2047.0;\n    d2 = (((((d2)) % ((Float64ArrayView[(((((0x56228ef1)))|0) % (abs((0x73e67a78))|0)) >> 3])))) - ((d2)));\n    return (((abs(((0xfffff*(i0))|0))|0) / (abs((((0xffffffff)-(0xff82f932)) | ((!(0x59e1ed75))-(0xb7a41f71))))|0)))|0;\n  }\n  return f; })(this, {ff: function ()\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((-0x422056)-((0x6d8873ae))-((0xda6fc02a) ? ((0xfdd66ecd) > (0xf98d8889)) : (i0))))|0;\n  }\n  return f;}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116111302*/count=114; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-116111302*/count=115; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.pow(Math.fround((mathy1(( + Math.sinh(( - -Number.MAX_VALUE))), (Math.min((Math.asinh(((Math.max((Math.tan((0x080000000 | 0)) | 0), (-0x100000000 >>> 0)) >> y) | 0)) | 0), (Math.fround(Math.pow(x, Math.fround(( ~ Math.fround(-Number.MIN_VALUE))))) | 0)) | 0)) | 0)), Math.fround(Math.acos(( + Math.expm1(( + Math.clz32((-(2**53) >>> 0)))))))); }); ");
/*fuzzSeed-116111302*/count=116; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.max(Math.fround(((Math.clz32(( + Math.expm1(y))) & (Math.ceil(2**53+2) | 0)) | 0)), Math.fround(Math.fround((Math.fround(( ~ Math.fround(Math.sign((((x == Math.fround(0x07fffffff)) | 0) !== ( + ( + Math.ceil(x)))))))) | 0))))); }); ");
/*fuzzSeed-116111302*/count=117; tryItOut("g2.offThreadCompileScript(\"this.a1[16] = this.p1;\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: (x % 26 != 4) }));");
/*fuzzSeed-116111302*/count=118; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.log(( ! Math.atan2(( + Math.sinh(( - Math.pow(y, 0x07fffffff)))), Math.fround((2**53+2 * (( ~ (Math.atanh(Math.tanh(0.000000000000001)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy3, [0, -0x080000000, 0.000000000000001, -Number.MAX_VALUE, -(2**53), 0x100000001, 0x080000001, -0x100000001, 2**53, -0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, 42, -Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, Number.MIN_VALUE, 1/0, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 1.7976931348623157e308, 2**53+2, -0x0ffffffff, -0, 0x100000000, 0/0, -1/0, 1, -(2**53+2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=119; tryItOut("\"use strict\"; a0[13] = x instanceof d;");
/*fuzzSeed-116111302*/count=120; tryItOut("([1,,]);return;");
/*fuzzSeed-116111302*/count=121; tryItOut("f1.valueOf = (function mcc_() { var shuwdr = 0; return function() { ++shuwdr; if (/*ICCD*/shuwdr % 10 != 7) { dumpln('hit!'); h0.enumerate = (function(j) { if (j) { try { Array.prototype.pop.apply(a2, [f1, this.e0, g2.s1]); } catch(e0) { } for (var p in v2) { try { o1 = Proxy.create(h2, s1); } catch(e0) { } Array.prototype.shift.call(a2, t0); } } else { for (var v of m0) { try { v1 = t1.length; } catch(e0) { } try { o1.o2.g1.v1 = undefined; } catch(e1) { } try { f2 = Proxy.createFunction(h1, this.f0, this.f2); } catch(e2) { } f1 = DataView.prototype.getFloat32; } } }); } else { dumpln('miss!'); try { o1.v1 = Object.prototype.isPrototypeOf.call(t0, b0); } catch(e0) { } try { g2.v2 = Object.prototype.isPrototypeOf.call(v0, m0); } catch(e1) { } v2 = evaluate(\"m1.set(m1, f0);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: b = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function(y) { \"use strict\"; yield y;  /x/ ;; yield y; }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: String.prototype.localeCompare, hasOwn: function() { return true; }, get: undefined, set: function() { throw 3; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(y), (Math.imul(\"\\uB981\", 2))), noScriptRval: false, sourceIsLazy: true, catchTermination: ((1 for (x in [])))(/*RXUE*//(\\2|(?=\\B)){1,}./gym.exec(\"\") = (4277)) })); } };})();");
/*fuzzSeed-116111302*/count=122; tryItOut("/(?!\\S)/gm;function x([], e) { yield; } m1.has( \"\" );");
/*fuzzSeed-116111302*/count=123; tryItOut("");
/*fuzzSeed-116111302*/count=124; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( - ( + (Math.round((( - Math.pow((y >>> 0), 2**53-2)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [-(2**53-2), 0, 0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, -0x0ffffffff, 0/0, Math.PI, -Number.MIN_VALUE, 2**53-2, 0x100000001, 0x100000000, -0x100000001, 42, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -1/0, 0x0ffffffff, -0x100000000, 1/0, 2**53+2, 0x07fffffff, Number.MIN_VALUE, -0x080000001, -(2**53), Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001]); ");
/*fuzzSeed-116111302*/count=125; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.fround(( + (mathy3(( ! (y >> (( ! x) | 0))), (((y >>> 0) != (( + Math.max(( + y), ( + y))) >>> 0)) >>> 0)) != Math.trunc((Math.sign(Math.fround(( - (Math.atanh(-(2**53+2)) | 0)))) >>> 0))))); }); testMathyFunction(mathy5, [NaN, 1, (new Boolean(false)), '', undefined, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new String('')), [], '0', /0/, [0], 0.1, '/0/', (new Number(-0)), (function(){return 0;}), (new Boolean(true)), false, '\\0', ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), true, (new Number(0)), null, -0, 0]); ");
/*fuzzSeed-116111302*/count=126; tryItOut("M:with('fafafa'.replace(/a/g, (--(x))))var ljvxjx = new ArrayBuffer(16); var ljvxjx_0 = new Uint16Array(ljvxjx); var ljvxjx_1 = new Int16Array(ljvxjx); print(ljvxjx_1[0]); ljvxjx_1[0] = 5; for (var p in f1) { this.m1.set(o2, i1); }throw new RegExp(\"\\\\1\", \"i\")\u000c;e1.add(this.m1);");
/*fuzzSeed-116111302*/count=127; tryItOut("/*infloop*/M: for  each(var x in new (eval)((let (x = NaN) [,,z1]), delete z.setter)) t0 = new Uint32Array(a0);");
/*fuzzSeed-116111302*/count=128; tryItOut("mathy3 = (function(x, y) { return Math.asinh(Math.sin(Math.fround((Math.cosh((((((x | 0) & Math.fround(( + Math.hypot((( ! x) >>> 0), x)))) | 0) | ( + Math.max(( + Math.hypot(x, x)), ( + y)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [0/0, -0x100000001, -0x100000000, -1/0, Number.MAX_SAFE_INTEGER, 42, -0x080000001, -0x080000000, 2**53+2, 0x0ffffffff, 0x080000001, -(2**53+2), -Number.MIN_VALUE, -(2**53), -(2**53-2), 1, -0x07fffffff, 1/0, 0.000000000000001, 0x080000000, Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, 0x07fffffff, 0, -0x0ffffffff, 2**53, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI]); ");
/*fuzzSeed-116111302*/count=129; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ! ((( - (Math.fround(( + (( ! ( ! (2**53 % y))) >>> 0))) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy2, ['/0/', (new Number(0)), (new Number(-0)), 0.1, (function(){return 0;}), -0, false, ({valueOf:function(){return '0';}}), '', ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), '0', (new Boolean(false)), [], NaN, (new Boolean(true)), null, objectEmulatingUndefined(), 1, 0, [0], '\\0', /0/, true, undefined, (new String(''))]); ");
/*fuzzSeed-116111302*/count=130; tryItOut("mathy5 = (function(x, y) { return Math.max(((Math.log(x) | Math.fround(mathy2(x, ( + ((( ! (( + y) | 0)) | 0) % Math.min(Math.fround(x), Math.fround(Math.atan2(y, (Math.fround((Math.fround(y) & Math.fround(-(2**53-2)))) >>> 0))))))))) | 0), (Math.fround(Math.imul(((Math.sqrt((Math.atan2(Math.fround(Math.trunc(( + 1))), ( ~ ((mathy1(x, (x >>> 0)) >>> 0) | 0))) >>> 0)) >>> 0) >>> 0), Math.fround(mathy3(( + y), mathy3(((y >>> 0) ** (mathy4(y, x) >>> 0)), x))))) >>> 0)); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), 1, 0/0, -(2**53), 0, 2**53, -(2**53+2), 0x0ffffffff, -0x100000000, 0.000000000000001, Math.PI, 42, 1/0, -0x080000000, 0x100000000, -0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -1/0, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, 0x100000001, 0x07fffffff, 2**53+2, -0x100000001, -0x080000001, 2**53-2, -0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-116111302*/count=131; tryItOut("\"use strict\"; ");
/*fuzzSeed-116111302*/count=132; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(\\\\3)[^]*){33}\", \"gyi\"); var s = \"P\\nP\\nP\\u00a9P\\u00a9P\\nP\\nP\\nP\\nP\\nP\\nP\\nP\\nP\\nP\\nP\\nP\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-116111302*/count=133; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 1048575.0;\n    (Float32ArrayView[(((((Int32ArrayView[((0x81495d8)) >> 2]))>>>((0xfffad2c6)-((1099511627777.0) < (-4503599627370496.0)))))-(0x63de0c3e)) >> 2]) = ((d2));\n    {\n      switch ((~~(4.722366482869645e+21))) {\n        case 0:\n          {\n            (Float32ArrayView[1]) = ((d2));\n          }\n          break;\n        default:\n          i1 = (0xffffffff);\n      }\n    }\n    i0 = ((Infinity));\n    {\n      {\n        return +((d2));\n      }\n    }\n    {\n      {\nprint(x);      }\n    }\n    i1 = (((+(0.0/0.0)) > (+/*FFI*/ff(((-73786976294838210000.0)), ((((0xffffffff)+(0xfe4eefbf)+(0x1e4c89f1)) | ((!(0xffffffff)))))))) ? (i0) : ((0xbe386ba3)));\n    d2 = (2199023255553.0);\n    return +((17592186044417.0));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var nmiysx = x; var pfzvil = (function handlerFactory(x) {return {getOwnPropertyDescriptor:  '' , getPropertyDescriptor: objectEmulatingUndefined, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: this, fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: function() { return true; }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function shapeyConstructor(lfxfml){\"use strict\"; Object.defineProperty(this, \"padStart\", ({configurable:  /x/ }));Object.preventExtensions(this);Object.preventExtensions(this);if (lfxfml) this[\"padStart\"] =  \"\" ;for (var ytqvfqmdv in this) { }for (var ytqdwyyhw in this) { }if (lfxfml) for (var ytqkjawdk in this) { }if (lfxfml) this[\"padStart\"] = offThreadCompileScript;for (var ytqmbstun in this) { }return this; }, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; }); return pfzvil;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Math.PI, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000000, -0, Number.MAX_VALUE, -(2**53), -0x080000001, 0x07fffffff, 0, -0x0ffffffff, 2**53, 2**53-2, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x0ffffffff, 0x100000001, -(2**53-2), 0x080000001, -Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 1/0, 0.000000000000001, 1, -Number.MIN_VALUE, 0/0, -0x100000000, -1/0, 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, 2**53+2]); ");
/*fuzzSeed-116111302*/count=134; tryItOut("i1.toString = (function() { for (var j=0;j<34;++j) { f0(j%4==1); } });");
/*fuzzSeed-116111302*/count=135; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-116111302*/count=136; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.hypot(Math.fround(Math.acosh(Math.fround(Math.cos(Math.fround((2**53 && ( + y))))))), y) + ((Math.atan2((1/0 || Math.fround(( ~ Math.fround(x)))), (y | 0)) | 0) >>> 0)) || Math.max(((Math.imul(x, (x | 0)) | 0) ? x : ((x * x) >>> 0)), (( + Math.hypot(( ! Math.hypot((Math.fround(x) !== x), -Number.MIN_SAFE_INTEGER)), Math.exp(Math.fround(x)))) | 0))); }); ");
/*fuzzSeed-116111302*/count=137; tryItOut("\"use strict\"; /*hhh*/function ibslhv(){print(x);}ibslhv( '' , (4277))");
/*fuzzSeed-116111302*/count=138; tryItOut("testMathyFunction(mathy1, [1/0, 2**53+2, 0, -0x080000000, -(2**53-2), -0x07fffffff, -0x100000000, -0x080000001, 0x080000000, -0, 42, 0x100000001, 0/0, 1.7976931348623157e308, 0x07fffffff, -(2**53), -0x100000001, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE, 2**53-2, 1, Number.MIN_SAFE_INTEGER, 2**53, -(2**53+2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-116111302*/count=139; tryItOut("for (var v of i2) { try { g1.s0[new String(\"6\")] = o0.b0; } catch(e0) { } this.m2 = new Map(o1.o2.o2.e1); }");
/*fuzzSeed-116111302*/count=140; tryItOut("(x);");
/*fuzzSeed-116111302*/count=141; tryItOut("{v1.__proto__ = v1;for (var v of g1) { delete h0.getOwnPropertyDescriptor; } }");
/*fuzzSeed-116111302*/count=142; tryItOut("mathy5 = (function(x, y) { return ( + Math.fround(Math.hypot((Math.imul(( + Math.trunc(x)), Math.fround(Math.acosh(Math.fround(Math.tanh(y))))) >>> 0), Math.min(Math.fround(Math.asinh(Math.fround(((x | 0) < ((Math.fround(x) == ( + ( - ( + x)))) | 0))))), 0x07fffffff)))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0x0ffffffff, Math.PI, Number.MIN_VALUE, -0x100000000, 0x100000001, -0x0ffffffff, 0x080000000, -0, 0/0, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, -1/0, -(2**53), 0x080000001, 0.000000000000001, 1.7976931348623157e308, 2**53, 0, -0x080000000, 2**53+2, -(2**53+2), -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), 1/0, 1, -0x100000001, -0x07fffffff]); ");
/*fuzzSeed-116111302*/count=143; tryItOut("/*RXUB*/var r = w << window; var s = \"\\u000b\\u000b\\u000b\\u000b\\u000b\"; print(s.replace(r, /*wrap3*/(function(){ var hsutwq = x / w; (/*FARR*/[timeout(1800)].filter(Date.prototype.setHours))(); }), \"gyim\")); ");
/*fuzzSeed-116111302*/count=144; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 70368744177665.0;\n    var i3 = 0;\n    var i4 = 0;\n    {\n      i1 = (i1);\n    }\n    return +((d2));\n    {\n      d0 = (4398046511105.0);\n    }\n    i4 = (i3);\n    return +((8388609.0));\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MAX_VALUE, -0x100000000, Math.PI, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -1/0, 0x0ffffffff, 0x080000001, 0/0, -(2**53-2), 1, 2**53+2, 42, -Number.MIN_SAFE_INTEGER, 0, -0x080000000, -Number.MAX_VALUE, -(2**53+2), -0, 2**53-2, 1/0, -0x100000001, -0x07fffffff, 0x07fffffff, 0x100000000, 0x080000000, 0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53), 1.7976931348623157e308, -0x080000001, -0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=145; tryItOut("s2 += s2;");
/*fuzzSeed-116111302*/count=146; tryItOut("\"use strict\"; for (var v of this.a2) { try { v1 = g1.runOffThreadScript(); } catch(e0) { } e2 + ''; }");
/*fuzzSeed-116111302*/count=147; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.fround(( ! (Math.max((( + ((mathy2(( + y), ( + -0x100000001)) >>> 0) > ( + x))) | 0), ( + Math.cbrt(y))) | 0)))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, -0x07fffffff, 0, -Number.MIN_SAFE_INTEGER, -0x080000001, -1/0, 2**53, 2**53-2, -(2**53), 0x080000000, Math.PI, 1.7976931348623157e308, -0, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 2**53+2, 1/0, -(2**53+2), -0x0ffffffff, 1, 42, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, 0/0, 0.000000000000001, 0x100000001, -0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-116111302*/count=148; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:(\\\\B)*?))\", \"gyim\"); var s = (void shapeOf(14)); print(uneval(s.match(r))); ");
/*fuzzSeed-116111302*/count=149; tryItOut("/*tLoop*/for (let y of /*MARR*/[function(){}, -0x07fffffff, -0x07fffffff, -0x07fffffff, function(){}, -0x07fffffff, new Boolean(false),  \"use strict\" , function(){}, -0x07fffffff,  \"use strict\" , function(){}, new Boolean(true), -0x07fffffff, new Boolean(true), new Boolean(true), new Boolean(false), -0x07fffffff, -0x07fffffff, new Boolean(false),  \"use strict\" , new Boolean(true),  \"use strict\" , new Boolean(true),  \"use strict\" , new Boolean(true), -0x07fffffff, new Boolean(false), function(){}, new Boolean(false), new Boolean(false), function(){}, new Boolean(false),  \"use strict\" , -0x07fffffff,  \"use strict\" , function(){}, new Boolean(true), function(){}, -0x07fffffff,  \"use strict\" , function(){}, function(){},  \"use strict\" , new Boolean(true), function(){}, -0x07fffffff, function(){}, new Boolean(false), function(){}, new Boolean(false), new Boolean(true), function(){}, -0x07fffffff, new Boolean(true), new Boolean(false),  \"use strict\" , -0x07fffffff,  \"use strict\" , new Boolean(true), function(){}, new Boolean(true), new Boolean(false), function(){}, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  \"use strict\" , new Boolean(true),  \"use strict\" , new Boolean(true), new Boolean(false), new Boolean(false), function(){}, new Boolean(false), function(){}, function(){}, function(){}, function(){}, -0x07fffffff,  \"use strict\" , new Boolean(false), function(){}, -0x07fffffff, function(){}, new Boolean(false), new Boolean(true),  \"use strict\" ]) { s1 += 'x'; }");
/*fuzzSeed-116111302*/count=150; tryItOut("/*hhh*/function pmerkp(w){print(w);}pmerkp(2**53-2);\ng2.offThreadCompileScript(\"function f2(p1) arguments\");\n");
/*fuzzSeed-116111302*/count=151; tryItOut("x = ({w: x});print(x);");
/*fuzzSeed-116111302*/count=152; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\b|(?!.|(?:[^]){4})\", \"yi\"); var s = \"\\n \\n\"; print(s.search(r)); ");
/*fuzzSeed-116111302*/count=153; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x100000000, -0x100000001, -(2**53-2), 1, -Number.MIN_VALUE, -0x0ffffffff, 0, 0x100000001, 0x100000000, Number.MAX_VALUE, 1/0, Math.PI, 2**53+2, -0x080000001, -1/0, -(2**53), 1.7976931348623157e308, 2**53-2, 0.000000000000001, -Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), -0x080000000, -0, 42, -0x07fffffff, 0/0, Number.MIN_VALUE, 0x080000001, 0x0ffffffff, 2**53]); ");
/*fuzzSeed-116111302*/count=154; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.max((( + ( - ( + Math.sqrt(( + ( ! ( + y))))))) >>> 0), (Math.fround((( + Math.imul(y, ( + Math.round(( ! (x >>> 0)))))) ^ (Math.ceil(Math.imul((((y | 0) * ((y || x) | 0)) | 0), -Number.MIN_VALUE)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -0x100000000, Number.MAX_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, 2**53-2, -0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1, 0x100000000, 0, -Number.MAX_VALUE, -0x080000000, -(2**53+2), 0.000000000000001, 0x080000001, -0x080000001, Math.PI, 1/0, -0, -(2**53), 0x080000000, 0x100000001, -(2**53-2), -0x100000001, -1/0, 1.7976931348623157e308, 2**53+2, 0x0ffffffff, 0x07fffffff, 42, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=155; tryItOut("");
/*fuzzSeed-116111302*/count=156; tryItOut("a0.forEach((function() { try { m2 = new Map(a2); } catch(e0) { } try { t1 + ''; } catch(e1) { } o0.g0.offThreadCompileScript(\"/*RXUB*/var r = x; var s = \\\"\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\\n\\\"; print(s.match(r)); print(r.lastIndex); \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: true })); return b0; }), h2, b = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function() { throw 3; }, defineProperty: q => q, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { throw 3; }, has: function() { return true; }, hasOwn: function() { return false; }, get: function shapeyConstructor(qqvtta){if (((yield x = this))) qqvtta[\"add\"] = (void 0);return qqvtta; }, set: this, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })((void options('strict_mode'))), new (Array.prototype.keys)()), v2, f2);");
/*fuzzSeed-116111302*/count=157; tryItOut("s1 += s1;");
/*fuzzSeed-116111302*/count=158; tryItOut("v1 = 0;");
/*fuzzSeed-116111302*/count=159; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.expm1(( + ((x & Number.MAX_SAFE_INTEGER) ? Math.fround((Math.fround(mathy0(Math.sinh(( + x)), ( ! Math.ceil((Math.fround(-1/0) ? Math.fround(x) : Math.fround(y)))))) < Math.fround(( ! ((( ! x) | 0) | 0))))) : Math.fround(( ! ( + -0x080000001))))))); }); testMathyFunction(mathy2, [Math.PI, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000001, 0x080000000, -Number.MAX_VALUE, 0, -0x07fffffff, -0x080000001, 42, 0x100000001, -0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0, 2**53+2, 1.7976931348623157e308, 0x100000000, 2**53-2, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), -1/0, 1, Number.MIN_VALUE, -0x0ffffffff, 0/0, 2**53, -0x100000000, -(2**53+2), 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-116111302*/count=160; tryItOut("/*vLoop*/for (rnazkk = 0; rnazkk < 29; ++rnazkk) { let d = rnazkk; let (w) { print(~undefined); } } \nwith({}) { return eval || x; } \n");
/*fuzzSeed-116111302*/count=161; tryItOut("/*ODP-3*/Object.defineProperty(i2, \"call\", { configurable: false, enumerable: (x % 75 == 65), writable: true, value: i0 });");
/*fuzzSeed-116111302*/count=162; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=163; tryItOut("g2 = this;");
/*fuzzSeed-116111302*/count=164; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (2199023255553.0);\n    return +((d1));\n  }\n  return f; })(this, {ff: (function shapeyConstructor(zoyrds){\"use strict\"; Object.seal(this);return this; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000000, -0, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, 2**53, 1, 0x080000001, 0x100000000, -0x100000000, -(2**53), 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), Math.PI, 0, 2**53+2, 0/0, 42, 0x07fffffff, -0x080000001, 1/0]); ");
/*fuzzSeed-116111302*/count=165; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.imul(mathy2((Math.max(Math.fround(Math.tan(( + -Number.MIN_SAFE_INTEGER))), y) === ( ! (Math.atan2(x, ( + mathy2(( + x), x))) >>> 0))), (Math.sign(y) >= y)), ( ~ Math.fround((mathy0(((((Math.max(((Math.atan(x) >>> 0) >>> 0), ((y / 0x080000001) >>> 0)) >>> 0) | 0) << y) | 0), y) >>> 0)))); }); testMathyFunction(mathy3, [-0x100000000, 2**53-2, -0x0ffffffff, -0x080000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 0, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 1/0, 1.7976931348623157e308, Number.MIN_VALUE, 42, 1, -(2**53), 2**53+2, Number.MAX_VALUE, -0, 0x07fffffff, -0x080000000, -(2**53+2), 0.000000000000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -1/0, -(2**53-2), -0x07fffffff, -Number.MIN_VALUE, 0x080000001, 2**53, 0/0, 0x100000001]); ");
/*fuzzSeed-116111302*/count=166; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.5474250491067253e+26;\n    var d3 = -18014398509481984.0;\n    var d4 = 33.0;\n    var i5 = 0;\n    (Float64ArrayView[0]) = ((+(((!(0x7e9f6dfa))-(-0x8000000)-(0xc04d446b))>>>((!(i5))))));\n    d2 = (NaN);\n    d2 = (+(-1.0/0.0));\n    return +((d2));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var umpcek = (4277) >>= this; var ryxkjx = ([ /x/ ]); return ryxkjx;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MAX_VALUE, Number.MAX_VALUE, 0x100000001, 0x100000000, -0x080000001, 1.7976931348623157e308, -(2**53-2), -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), 2**53+2, 1, 42, 0x080000000, -Number.MIN_VALUE, -0x100000000, 0x07fffffff, 0/0, 1/0, -1/0, 0.000000000000001, -0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 0x0ffffffff, Math.PI, 2**53, 0, -(2**53+2), 2**53-2]); ");
/*fuzzSeed-116111302*/count=167; tryItOut("\"use strict\"; v0 = (t0 instanceof m1);");
/*fuzzSeed-116111302*/count=168; tryItOut("\"use asm\"; for(y = x in eval(window) = -0.612) {\"\\uF3D8\";m0 + ''; }");
/*fuzzSeed-116111302*/count=169; tryItOut("\"use strict\"; h2.enumerate = f1;");
/*fuzzSeed-116111302*/count=170; tryItOut("/*oLoop*/for (okptzk = 0; okptzk < 45; ++okptzk) { a2[10] = eval; } ");
/*fuzzSeed-116111302*/count=171; tryItOut("/*MXX2*/g2.String.prototype.toLowerCase = a0;");
/*fuzzSeed-116111302*/count=172; tryItOut("mathy0 = (function(x, y) { return Math.max((( + (( ! (-Number.MAX_SAFE_INTEGER | 0)) | 0)) | 0), ((( ~ (Math.hypot((y | 0), (( + Math.hypot(-0x080000000, y)) | 0)) | 0)) | ( ~ Math.sinh((Math.log10(x) >>> 0)))) | 0)); }); testMathyFunction(mathy0, [-0x0ffffffff, 0x0ffffffff, -(2**53+2), 1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0, 0x080000000, -(2**53-2), 1.7976931348623157e308, -0x080000000, 42, -(2**53), 0/0, -0x100000001, 2**53-2, 0x100000001, -0x100000000, 2**53, Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, 0x100000000, 0x080000001, 0x07fffffff, -0x07fffffff, -0x080000001, 1, Number.MAX_VALUE, -1/0, 2**53+2, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0]); ");
/*fuzzSeed-116111302*/count=173; tryItOut("\"use strict\"; this.s2 += s1;");
/*fuzzSeed-116111302*/count=174; tryItOut("this.e2.toString = (function() { for (var j=0;j<41;++j) { f0(j%2==1); } });");
/*fuzzSeed-116111302*/count=175; tryItOut("\"use strict\"; ((4277));function x() { \"use strict\"; yield ((function sum_slicing(ftwodg) { ; return ftwodg.length == 0 ? 0 : ftwodg[0] + sum_slicing(ftwodg.slice(1)); })(/*MARR*/[new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false)])) } (void version(185));");
/*fuzzSeed-116111302*/count=176; tryItOut("\"use asm\"; m2.set(a2, o2.h1);");
/*fuzzSeed-116111302*/count=177; tryItOut("mathy2 = (function(x, y) { return (((( ! ( ~ (0 >>> 0))) >>> 0) * ( + ( - ( + ( + Math.exp(Math.fround(( + Math.fround(( + (( + ((((0/0 >>> 0) | ( + x)) >>> 0) << x)) > (2**53+2 >>> 0)))))))))))) >>> 0); }); testMathyFunction(mathy2, [0, 0/0, -0, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, 0x080000000, -(2**53-2), -0x080000001, Number.MAX_VALUE, 1/0, -1/0, 1.7976931348623157e308, Math.PI, -(2**53+2), 0x07fffffff, 2**53, 1, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, 0x0ffffffff, -0x080000000, -0x100000000, -0x0ffffffff, 0x100000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 42]); ");
/*fuzzSeed-116111302*/count=178; tryItOut("v2 = t0.byteLength;");
/*fuzzSeed-116111302*/count=179; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.acosh(Math.fround(Math.cos(( + Math.fround(Math.fround(( + ( ~ ( + ( + Math.log1p(mathy0(x, x)))))))))))); }); testMathyFunction(mathy2, [0x080000001, 0x100000000, -(2**53-2), -Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 1/0, 0.000000000000001, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, Math.PI, -Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, Number.MAX_VALUE, -0x100000000, 0/0, 0x100000001, 0x080000000, 1.7976931348623157e308, Number.MIN_VALUE, -0x100000001, -(2**53), -0x080000001, 0x0ffffffff, 0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, 0, 1]); ");
/*fuzzSeed-116111302*/count=180; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=181; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return (( + ( + ((Math.imul(( - Math.expm1(y)), (y | 0)) | 0) && ( + ( - Math.fround(( + 0.000000000000001))))))) > (( ! ( + Math.acos(y))) === ( + Math.atan2(Math.fround(( ! ((Math.hypot((y >>> 0), ( + 0x100000000)) >>> 0) | 0))), (Math.fround((Math.fround((Math.fround(Math.tan(x)) << Math.fround(Math.sin(Math.PI)))) ? ( + y) : ( ! ( ! Math.fround(x))))) ^ (Math.imul(x, Math.exp(x)) | 0)))))); }); testMathyFunction(mathy0, [0x0ffffffff, 0x080000001, -0x100000000, 0x07fffffff, -0x07fffffff, 0/0, -0, -0x0ffffffff, Number.MAX_VALUE, 1/0, 0, 42, 2**53, 0x080000000, 2**53+2, -0x080000001, -(2**53-2), 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, Math.PI, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), 0x100000001, Number.MIN_VALUE, 0x100000000, 1, -0x080000000, -(2**53), -0x100000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=182; tryItOut("/*ODP-1*/Object.defineProperty(s2, \"z\", ({configurable: (x % 50 == 19), enumerable: (eval(\"print( \\\"\\\" );\"))}));");
/*fuzzSeed-116111302*/count=183; tryItOut("{ void 0; try { gcparam('markStackLimit', 1); } catch(e) { } }");
/*fuzzSeed-116111302*/count=184; tryItOut("Array.prototype.sort.apply(a1, [(function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { a7 = a10 & 1; print(a0); a15 = a19 / a11; var r0 = 8 / a7; var r1 = a12 % a8; var r2 = 6 & a2; var r3 = a19 + a3; var r4 = 4 | 6; print(a16); var r5 = r2 + a17; var r6 = a3 | a16; var r7 = 6 ^ a11; r2 = a3 / r3; var r8 = 4 | 5; var r9 = a15 ^ 0; var r10 = r1 & a12; r6 = 8 + 0; var r11 = 8 - 3; var r12 = a9 + a12; var r13 = 2 % 2; var r14 = r6 - r3; var r15 = r2 & 3; var r16 = r11 ^ 7; x = a14 / 5; var r17 = r16 % 1; var r18 = a0 - 9; a15 = r0 & r12; var r19 = 1 & 8; var r20 = a8 + a17; var r21 = r20 % 3; var r22 = 1 * a2; var r23 = 9 * 4; var r24 = a17 ^ 7; var r25 = r10 ^ r6; var r26 = a10 & 4; var r27 = 4 - 1; var r28 = r7 * a18; x = a8 + a4; print(r12); var r29 = a13 & a10; var r30 = r15 - 8; var r31 = 0 / 7; var r32 = 1 ^ 0; var r33 = r27 * r12; var r34 = 1 / 5; var r35 = a19 % 6; var r36 = a12 % 0; var r37 = a6 + r5; a10 = r12 ^ r11; var r38 = a8 + 5; var r39 = 0 / r38; var r40 = r27 - r22; var r41 = r0 | r34; r38 = r29 | r6; var r42 = r32 / r16; r32 = r38 & r13; var r43 = 4 ^ a4; var r44 = a16 - 5; var r45 = r29 / r36; var r46 = 9 ^ r23; a3 = a1 + 6; print(a19); var r47 = 5 % r19; var r48 = a6 + 9; a8 = r40 * a6; var r49 = 9 + 9; var r50 = r31 | a7; var r51 = 2 / 2; var r52 = 2 * a19; var r53 = 7 * 4; a17 = r22 & a12; var r54 = a16 * r12; var r55 = r15 / a15; var r56 = 3 & r14; var r57 = 9 % 6; r37 = r52 ^ 2; var r58 = r26 % r39; var r59 = a18 + 7; var r60 = r59 & a13; var r61 = r57 | r50; r31 = a16 - 6; var r62 = r24 ^ r38; var r63 = a4 % r31; r57 = a12 - 8; print(r56); var r64 = 4 ^ r22; var r65 = 7 - 9; var r66 = 6 ^ r12; var r67 = r6 % a17; var r68 = r15 & a6; var r69 = 8 - r46; r50 = r41 / r51; var r70 = 1 % a9; var r71 = 6 | r2; var r72 = r54 | r28; var r73 = x + 7; var r74 = r64 + 4; var r75 = r51 % a19; var r76 = r18 % r32; a18 = r43 + 3; r51 = r45 | r38; var r77 = 9 ^ 8; var r78 = r73 % r67; var r79 = a19 % r68; r27 = r59 % a14; var r80 = 6 & 7; var r81 = a13 | r28; var r82 = r72 | 1; r31 = r59 - r32; var r83 = r82 | r15; r14 = r58 + r22; var r84 = r77 * r13; var r85 = r62 - r61; var r86 = r14 & r78; var r87 = r62 * a18; var r88 = r13 | 6; var r89 = r33 - r37; var r90 = 0 - 5; var r91 = r47 % r0; var r92 = r78 ^ 9; a13 = r47 % r44; var r93 = 0 | a10; var r94 = 9 * 0; var r95 = 1 ^ 7; var r96 = 9 & r86; var r97 = r25 + a19; var r98 = r90 / r25; var r99 = 8 & 0; var r100 = 0 | 1; r93 = r18 * 5; var r101 = 8 & 7; var r102 = r1 + r51; var r103 = r32 + r14; var r104 = 9 - 0; var r105 = r9 / r1; a11 = r26 % r46; var r106 = 6 | r22; var r107 = a17 * 8; var r108 = r93 + r100; var r109 = 0 - r33; var r110 = 4 | r53; var r111 = 1 / r34; r34 = 7 * a13; r29 = r24 | 3; print(r90); r82 = r80 + r38; var r112 = r103 * r86; var r113 = 9 % 0; var r114 = r10 * 0; var r115 = r98 * r28; r64 = r0 ^ a10; var r116 = r115 & r101; r10 = r26 & r27; r14 = r26 / r14; var r117 = r16 ^ 8; var r118 = r59 + 5; var r119 = 5 ^ r14; var r120 = 0 ^ r3; r65 = r31 % r8; print(a18); r70 = r52 ^ 9; var r121 = 6 % 5; var r122 = r1 * r103; var r123 = r38 ^ r79; var r124 = r83 + r48; var r125 = r113 & a6; var r126 = r25 % r16; var r127 = r64 - r98; var r128 = 3 % 8; var r129 = 9 & 8; var r130 = 9 + 7; var r131 = 1 - r7; var r132 = 2 & 7; var r133 = r81 * a12; var r134 = r41 | r129; var r135 = r133 + r91; var r136 = 0 ^ r25; var r137 = r0 | a5; r36 = 9 - 3; var r138 = r14 + r130; r79 = r8 / 6; x = 0 + r48; r80 = r107 ^ r135; var r139 = r83 ^ r136; a19 = r21 * r123; r53 = r46 % r9; var r140 = r10 % a10; var r141 = a17 % 9; r81 = r121 * r15; var r142 = r116 * r51; r93 = r97 * 6; r127 = r10 | 9; var r143 = r91 % 9; var r144 = r15 + r12; var r145 = 5 | a1; var r146 = 8 * r32; r119 = r38 - 5; var r147 = r70 | r134; var r148 = r106 ^ r103; r6 = 6 / r120; var r149 = a8 + r84; var r150 = 5 & r90; r64 = r53 | r99; var r151 = 5 & 5; var r152 = r123 + r107; var r153 = r9 | r75; var r154 = r43 & r104; a9 = 2 / r90; var r155 = r62 | r3; var r156 = r66 / 7; r74 = r118 * 6; var r157 = r71 - r23; var r158 = 0 ^ r157; var r159 = r98 + r59; print(r138); var r160 = 1 / 5; r97 = 7 & 9; var r161 = r102 ^ r119; var r162 = 9 ^ 1; var r163 = r77 + 9; var r164 = r63 / r153; var r165 = 0 + r161; var r166 = r71 + r134; var r167 = r113 - r81; print(r167); r19 = 3 / 1; var r168 = 5 - r18; var r169 = r89 * r14; var r170 = r140 * r112; var r171 = 9 + r0; var r172 = r142 & r35; var r173 = r27 + 0; r125 = r92 - r82; var r174 = r110 & r97; r136 = r101 & r172; var r175 = r32 & r121; var r176 = 0 | 3; var r177 = r63 % r163; x = 6 + r137; r137 = 0 + 3; var r178 = r152 & r36; var r179 = r140 / r118; r32 = r3 + r167; var r180 = r99 * r110; var r181 = 8 % r153; var r182 = a13 | r151; r128 = r14 % a3; var r183 = 0 | r81; var r184 = 3 | a13; var r185 = 0 + r0; var r186 = 7 / 4; var r187 = r127 + r18; var r188 = 4 - r53; var r189 = 7 ^ 0; var r190 = r59 | 2; var r191 = a11 - 2; var r192 = r32 * r112; var r193 = r106 | r158; var r194 = 5 & r84; r26 = 7 & 8; r64 = 2 * r46; var r195 = r90 | r163; r55 = 6 - r143; print(r78); r186 = 7 - 1; var r196 = 4 ^ r26; var r197 = r165 * 0; r47 = 6 / r143; r96 = r24 / 9; var r198 = r28 ^ r147; r124 = 9 + 1; var r199 = r15 % 5; var r200 = r144 * r132; r27 = r25 * r21; print(r126); return a7; })]);");
/*fuzzSeed-116111302*/count=185; tryItOut("a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ");
/*fuzzSeed-116111302*/count=186; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.tan(Math.tanh(x)) && (Math.min((((( + Number.MIN_VALUE) + ( + y)) >>> ( - Math.trunc(y))) | 0), (Math.sign(Math.fround((((-0 | 0) / (( + x) | 0)) | 0))) | 0)) | 0)); }); testMathyFunction(mathy4, [0.1, (new Number(-0)), false, (new String('')), 1, [], objectEmulatingUndefined(), (function(){return 0;}), ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '0', (new Boolean(true)), null, -0, true, ({toString:function(){return '0';}}), '\\0', /0/, 0, NaN, '', '/0/', (new Boolean(false)), [0], (new Number(0)), undefined]); ");
/*fuzzSeed-116111302*/count=187; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( + (Math.exp((Math.fround(mathy2(x, y)) | 0)) | 0)) & ( + Math.clz32(( + (Math.fround((Math.max(( + (Math.pow((Number.MAX_VALUE >>> 0), Math.fround(y)) <= y)), (( ~ y) | 0)) | 0)) , (( + y) + ( + Math.PI))))))); }); testMathyFunction(mathy3, ['\\0', [], NaN, true, (new Boolean(true)), -0, '/0/', /0/, (function(){return 0;}), '0', '', objectEmulatingUndefined(), false, (new Number(0)), 0, [0], 1, (new Number(-0)), undefined, null, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), (new Boolean(false)), 0.1, (new String(''))]); ");
/*fuzzSeed-116111302*/count=188; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((-549755813889.0));\n  }\n  return f; })(this, {ff: new Function}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-116111302*/count=189; tryItOut("\"use strict\"; g0.v2 = g1.runOffThreadScript();");
/*fuzzSeed-116111302*/count=190; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.acosh(( + (( + ( ~ Math.fround(Math.atanh(Math.fround(x))))) & ( + Math.cos(((mathy0((y >>> 0), (x >>> 0)) >>> 0) >> Math.fround(Math.sign((Math.tanh((x >>> 0)) | 0))))))))); }); testMathyFunction(mathy3, [-0x080000000, -(2**53-2), -0x07fffffff, -0x0ffffffff, 2**53+2, 2**53-2, -Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, -1/0, Number.MIN_VALUE, 1/0, 0x080000001, 1.7976931348623157e308, 0x07fffffff, -0x080000001, 0x0ffffffff, 0x080000000, 0/0, -0, 0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, 2**53, 1, 42, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x100000000, Math.PI, 0x100000001, 0x100000000]); ");
/*fuzzSeed-116111302*/count=191; tryItOut("{ void 0; minorgc(true); } /*RXUB*/var r = new Array(19); var s = \"\"; print(s.replace(r, function(q) { return q; })); ");
/*fuzzSeed-116111302*/count=192; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.sinh(( + ( + ( ! (Math.hypot(Math.atan2((x | 0), Number.MIN_SAFE_INTEGER), ( + x)) | 0))))); }); ");
/*fuzzSeed-116111302*/count=193; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var atan = stdlib.Math.atan;\n  var sin = stdlib.Math.sin;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return +((((d0) + (+atan((((0x5068180d)))))) + (+sin((new function(y) { return /*MARR*/[function(){}, function(){}, eval, eval, eval, function(){}, function(){}, (0/0), eval, y, function(){}, function(){}, function(){}, eval, eval, (0/0), y].sort(({})) }((x = false)))))));\n    return +((d1));\n    {\n      d1 = (+(1.0/0.0));\n    }\n    d0 = (+((((+(imul(((imul((-0x8000000), ((0x329191fb) != (0x3c9776a2)))|0)), (0x245fb771))|0)))) ^ ((0x562fdb1b)*0x1929f)));\n    return +((d0));\n  }\n  return f; })(this, {ff: (function(x, y) { return Math.max(Math.fround(Math.min(x, Math.imul((x | 0), (2**53 | 0)))), Math.fround(( + x))); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [-(2**53-2), Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, 0x080000000, -0x100000000, 1.7976931348623157e308, -1/0, -0x080000001, -0x100000001, 1, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53), 2**53, Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x07fffffff, -Number.MIN_VALUE, 42, 2**53-2, 1/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -0, 0.000000000000001, -(2**53+2), 0x0ffffffff, 0x100000000, 0, 0/0, 0x080000001]); ");
/*fuzzSeed-116111302*/count=194; tryItOut("\"use strict\"; m0.set(b1, a1);");
/*fuzzSeed-116111302*/count=195; tryItOut("function shapeyConstructor(eauvum){this[(4277)] = NaN;this[(4277)] = /*wrap3*/(function(){ \"use strict\"; var fgnanl =  ''  |= \"\\u02A3\"; ((1 for (x in [])))(); });Object.defineProperty(this, mathy1 = (function(x, y) { return Math.fround((( + ( ! (Math.trunc(( + Math.atanh(0))) | 0))) !== Math.log2(Math.fround(Math.min(Math.fround(((( ~ 0/0) | (y >>> 0)) >>> 0)), ( + Math.max(x, ((( + Math.clz32(-Number.MAX_VALUE)) || ( + (mathy0((x | 0), (1/0 | 0)) | 0))) ? Math.tan(( + x)) : 0/0)))))))); }); , ({configurable: false, enumerable: true}));if (this.__defineGetter__(\"a\", window)) Object.defineProperty(this, (4277), ({set: EvalError.prototype.toString, configurable: true, enumerable: (x % 6 != 4)}));for (var ytqzjnulc in this) { }for (var ytqeozcwv in this) { }{ return; } this[\"anchor\"] =  \"\" ;return this; }/*tLoopC*/for (let x of /*PTHR*/(function() { for (var i of /*MARR*/[this, -(2**53-2), window, window, this, this, objectEmulatingUndefined(), window, objectEmulatingUndefined(), window, this, objectEmulatingUndefined(), -(2**53-2), this, window, -(2**53-2), objectEmulatingUndefined(), window, this, this, objectEmulatingUndefined(), -(2**53-2), -(2**53-2), objectEmulatingUndefined(), -(2**53-2), objectEmulatingUndefined(), objectEmulatingUndefined(), -(2**53-2), objectEmulatingUndefined(), this, objectEmulatingUndefined(), this, -(2**53-2), window, window, this, objectEmulatingUndefined(), window, window, objectEmulatingUndefined(), objectEmulatingUndefined(), this, -(2**53-2), window, objectEmulatingUndefined(), this, window, objectEmulatingUndefined()]) { yield i; } })()) { try{let idawdb = shapeyConstructor(x); print('EETT'); a1 + '';}catch(e){print('TTEE ' + e); } }m2.delete(b1);");
/*fuzzSeed-116111302*/count=196; tryItOut("/*ODP-3*/Object.defineProperty(b2, \"valueOf\", { configurable: let (c = new ((allocationMarker()))(), [, [\"\\u3942\" ? (\"\\uA8EB\".valueOf(\"number\")) : Math[\"__iterator__\"], , y, ], {x: setter}, w, {}] = (4277)) (p={}, (p.z = yield Math)()) > (void version(185)), enumerable: (x % 16 != 3), writable: true, value: t0 });");
/*fuzzSeed-116111302*/count=197; tryItOut("\"use strict\"; print(14);");
/*fuzzSeed-116111302*/count=198; tryItOut("\"use strict\"; delete h2.hasOwn;");
/*fuzzSeed-116111302*/count=199; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var log = stdlib.Math.log;\n  var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -0.125;\n    d2 = ((0x5e7b4a36) ? (((+((+pow(((-4294967295.0)), ((+pow(((67108865.0)), ((9.0)))))))))) * ((d2))) : (((562949953421313.0)) - ((-33554431.0))));\n    (Float32ArrayView[((0xfe03f5cf)-(-0x8000000)-(0x7558b62e)) >> 2]) = ((+log(((+/*FFI*/ff())))));\n    i1 = (i0);\n    i0 = (i1);\n    return +((d2));\n    {\n      d2 = (Infinity);\n    }\n    {\n      i0 = ((-16385.0) < (+(((i1)-(((0x3db14088) >= (0x5ba0ba52)) ? (i1) : (i1)))>>>(((0x8925d32e))-(i0)))));\n    }\n    i0 = (/*FFI*/ff(((abs((imul((i0), (/*FFI*/ff()|0))|0))|0)), ((~~(d2))), (((((+(-1.0/0.0)))+(i1)+((0x3d0eb47e) ? (0xf1b1cbf8) : (0xfff12a9b))) ^ ((i1)*-0xf2d4a))))|0);\n    {\n      i1 = ((imul(((d2) <= (d2)), ((((0x47cc5ac7))>>>(((Float32ArrayView[((/*FFI*/ff(((536870913.0)))|0)-((0x91dac02a))) >> 2]))))))|0));\n    }\n    return +((((+((i0)))) / (( /x/g ))));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-1/0, 1/0, -(2**53), -0x100000001, 0x07fffffff, 0x080000000, -(2**53+2), 2**53, -(2**53-2), -0x100000000, -0x0ffffffff, 0x080000001, -Number.MAX_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, 42, Math.PI, -0x080000001, 0, Number.MIN_VALUE, -0x080000000, -0, 0x100000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 1]); ");
/*fuzzSeed-116111302*/count=200; tryItOut("\"use strict\"; /*infloop*/for(new Math.atan(Object.defineProperty(x, \"toSource\", ({value: (uneval(this)).eval(\"/* no regression tests found */\"), configurable: ((void shapeOf(23)))}))\u000c); x; /\\b/gm) /* no regression tests found */");
/*fuzzSeed-116111302*/count=201; tryItOut("\"use strict\"; v2 = Array.prototype.every.apply(this.a2, [(function() { for (var j=0;j<3;++j) { f0(j%2==0); } }), f0, this.a2, eval(\"(z);\")]);let c = (void options('strict_mode'));");
/*fuzzSeed-116111302*/count=202; tryItOut("\"use strict\"; const w = [eval(\"window;\", -9)];a0 = arguments;");
/*fuzzSeed-116111302*/count=203; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min(((Math.fround((Math.atan2(( + Math.min((x >>> 0), ( + Math.fround(((y | 0) | (x | 0)))))), ( + Math.imul(( + x), ( + ( ! x))))) | 0)) * Math.fround(x)) === ((( + (((Math.tan(( + x)) >>> 0) * (( + y) >>> 0)) >>> 0)) , y) >= ( + ( + ( + x))))), (Math.asinh(((( ~ (y | 0)) >>> Math.fround(Math.hypot((x , (y == x)), Math.fround(Number.MAX_SAFE_INTEGER)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [({toString:function(){return '0';}}), (new Boolean(true)), 1, '/0/', 0, 0.1, [0], ({valueOf:function(){return '0';}}), '\\0', /0/, [], '0', ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), false, NaN, (function(){return 0;}), '', (new Number(0)), (new Number(-0)), (new Boolean(false)), -0, (new String('')), true, null, undefined]); ");
/*fuzzSeed-116111302*/count=204; tryItOut("\"use strict\"; if((x % 33 == 20)) {Array.prototype.shift.apply(a1, [g2.m2]);v1 = b2.byteLength;function a(b, x) { p2 = m2.get(t0); } this.s1 += 'x'; } else {g0.v1 = this.r0.ignoreCase;v2 = Array.prototype.some.call(a2, (function(a0, a1) { a0 = a1 & a0; var r0 = x % 4; var r1 = 7 & 6; var r2 = 8 ^ 2; var r3 = r1 ^ r0; var r4 = r2 * a1; var r5 = r1 & r3; var r6 = r0 * 8; var r7 = r2 % 1; var r8 = r0 ^ r0; print(r2); var r9 = r4 ^ 6; var r10 = x - 7; var r11 = r2 / r1; var r12 = r7 ^ r2; var r13 = x * r0; var r14 = 7 - r13; var r15 = r4 * r4; r5 = a1 % 1; var r16 = r14 / r4; print(r12); r14 = 6 + a0; var r17 = r2 + 0; var r18 = r4 + a1; var r19 = 5 * a0; var r20 = x * r7; var r21 = r20 & 6; a0 = 8 * 0; r16 = r21 | 5; print(r13); var r22 = a0 + 8; var r23 = r10 ^ r14; r11 = r22 + r2; print(r4); var r24 = r8 ^ 6; var r25 = r14 * r18; r16 = r11 | r15; var r26 = r11 ^ 9; var r27 = 3 / r23; var r28 = x & r21; var r29 = r5 ^ 0; var r30 = 3 - 8; var r31 = 3 + 0; r25 = 4 / r16; return a1; }), a0, m1); }");
/*fuzzSeed-116111302*/count=205; tryItOut("testMathyFunction(mathy2, [0x07fffffff, 0/0, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53, Math.PI, -0, 0x0ffffffff, -0x100000001, 1/0, 1, 2**53-2, -0x080000000, -(2**53-2), -(2**53), -Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 42, -0x07fffffff, 0, -1/0, 2**53+2, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53+2), 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, 0x080000000, 0x100000000, -0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=206; tryItOut("var klthwp = new ArrayBuffer(3); var klthwp_0 = new Float32Array(klthwp); klthwp_0[0] = 7; for (var v of o0.o2.o0.o1.s0) { try { g1.h1 + t1; } catch(e0) { } try { f0(o2); } catch(e1) { } e1.valueOf = (function mcc_() { var jarzrx = 0; return function() { ++jarzrx; f1(/*ICCD*/jarzrx % 6 == 4);};})(); }v1 = (b1 instanceof o0.o1.m1);");
/*fuzzSeed-116111302*/count=207; tryItOut("const e = new () => ( ''  && new RegExp(\"[^\\\\w\\\\d]\", \"y\"))();this.o0.i0.send(t2);");
/*fuzzSeed-116111302*/count=208; tryItOut("\"use strict\"; /((?:\\b?)*)?/g;g2.offThreadCompileScript(\"function f2(g2.h2)  { \\\"use strict\\\"; yield this } \", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: undefined, noScriptRval: false, sourceIsLazy: true, catchTermination: x }));a0.forEach((function() { try { i2.valueOf = (function() { try { v1 = (v2 instanceof o0.e1); } catch(e0) { } x = h1; return m0; }); } catch(e0) { } try { v1 = g2.runOffThreadScript(); } catch(e1) { } m2.set(i1, t0); return s2; }));");
/*fuzzSeed-116111302*/count=209; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.pow(Math.fround(Math.atan2(( - ( + Math.log10((( + Math.atan2((x | 0), ( + y))) | 0)))), ((((Math.hypot((((( + ( + mathy1((x | 0), ( ~ y)))) ? (y | 0) : ( + y)) >>> 0) >>> 0), ((((Math.pow(x, Math.fround(Math.imul(x, x))) >>> 0) ^ (0 >>> 0)) >>> 0) >>> 0)) >>> 0) | 0) ? (( ! (-(2**53-2) | 0)) | 0) : ((x && Math.asin(( + x))) | 0)) | 0))), Math.fround(((( ~ (window.eval(\"/* no regression tests found */\") | 0)) | 0) ^ (Math.hypot((Math.log1p(y) | 0), ( + Math.sqrt(mathy0(Math.fround(( + Math.fround(Math.round(y)))), ((y | 0) & 0x080000001))))) | 0)))); }); ");
/*fuzzSeed-116111302*/count=210; tryItOut("mathy3 = (function(x, y) { return mathy2((( ~ (( ! (( + Math.atanh(( + (x ? ( + y) : Math.round(Math.PI))))) >>> 0)) / Math.fround(( + Math.fround(Math.imul(-0x0ffffffff, Math.fround((-Number.MAX_SAFE_INTEGER == Math.fround((Math.sqrt(y) | 0)))))))))) | 0), Math.pow((Math.min(Math.fround((Math.fround((x <= Math.fround(y))) - (( - (x | 0)) | 0))), (Number.MAX_VALUE | 0)) | 0), Math.fround(( ~ Math.fround(y))))); }); testMathyFunction(mathy3, /*MARR*/[new Boolean(true), ({ get 16(...x)x }), ({ get 16(...x)x }),  /x/ , ({ get 16(...x)x }), new Boolean(true), x,  /x/ , new Boolean(true),  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x,  /x/ , x,  /x/ ,  /x/ , x, x, x, new Boolean(true),  /x/ , ({ get 16(...x)x }), new Boolean(true), new Boolean(true), ({ get 16(...x)x }), ({ get 16(...x)x }), new Boolean(true), new Boolean(true), ({ get 16(...x)x }), ({ get 16(...x)x }),  /x/ ,  /x/ ]); ");
/*fuzzSeed-116111302*/count=211; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.acos((Math.fround(Math.min(( ! (Math.fround(Math.fround(mathy0((Math.fround(x) >= y), Math.atan(( + Number.MAX_VALUE))))) | 0)), (Math.atan2(((y ? -0x100000000 : (x | 0)) >>> 0), ((Math.sinh(y) ** (mathy3((mathy2(y, Math.fround(( - Math.fround(y)))) | 0), (( + x) | 0)) | 0)) >>> 0)) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [1/0, 2**53+2, -Number.MAX_VALUE, 0x100000000, 0x100000001, -0x100000000, Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, 1, 0x080000001, -(2**53), -0x080000000, -0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -0, Number.MAX_SAFE_INTEGER, 0, 0x080000000, -(2**53+2), -0x0ffffffff, 42, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, 0.000000000000001, 2**53, 0x0ffffffff, Math.PI, -1/0]); ");
/*fuzzSeed-116111302*/count=212; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.tanh(Math.fround(Math.acosh((( - Math.atanh(x)) >>> 0))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -0x100000001, -(2**53+2), Number.MIN_VALUE, 0x0ffffffff, 0, -(2**53), -1/0, 1, -(2**53-2), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -0x080000000, Math.PI, -Number.MAX_VALUE, 42, 1/0, 0x080000000, 2**53+2, -0x080000001, 1.7976931348623157e308, 0x100000000, 2**53-2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, 0x080000001, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, 0x07fffffff, 0x100000001]); ");
/*fuzzSeed-116111302*/count=213; tryItOut("\"use strict\"; /*oLoop*/for (qvovij = 0; qvovij < 5; ++qvovij) { o0.t0 = t0.subarray(16); } ");
/*fuzzSeed-116111302*/count=214; tryItOut("\"use strict\"; b1.valueOf = (function() { try { Array.prototype.splice.apply(a0, []); } catch(e0) { } try { b0 + e0; } catch(e1) { } try { i1.next(); } catch(e2) { } v0 = a1.some((function mcc_() { var mfdndh = 0; return function() { ++mfdndh; if (/*ICCD*/mfdndh % 4 == 3) { dumpln('hit!'); var v2 = g0.o0.t2.length; } else { dumpln('miss!'); try { a0.push(s1, window, h1, this.o1.p2); } catch(e0) { } try { t1.toSource = (new Function(\"o2 + '';\")); } catch(e1) { } e2.has(\n /x/g ); } };})(), 'fafafa'.replace(/a/g, x) >>>= c /= x, h2); return h2; })\nx;\nthis.zzz.zzz;\n");
/*fuzzSeed-116111302*/count=215; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - Math.min(Math.fround(( + Math.atan2((Math.hypot((y >>> 0), Math.sqrt(x)) >>> 0), ( + Math.clz32(Math.atan2(-0, (-0x07fffffff % y))))))), Math.fround(Math.fround(( - Math.fround(( + (( + x) , Math.PI)))))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 1/0, 2**53+2, 1, -(2**53-2), 42, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 0x080000001, 0x080000000, 0/0, -(2**53), -0x0ffffffff, 0, 2**53-2, -0x100000001, -1/0, -0, -0x080000000, -(2**53+2), -Number.MAX_VALUE, 0x0ffffffff, Math.PI, Number.MIN_SAFE_INTEGER, -0x100000000, 2**53, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, 1.7976931348623157e308, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=216; tryItOut("mathy3 = (function(x, y) { return ( + ( ~ ((((( + Math.tanh(( + x))) , 1.7976931348623157e308) | 0) == Math.PI) != Math.fround((y <= ( + (Math.asinh(x) >> y))))))); }); ");
/*fuzzSeed-116111302*/count=217; tryItOut("for (var v of g2.g1.g2.t0) { try { i1.next(); } catch(e0) { } try { this.a0.length = 8; } catch(e1) { } try { o0.s0 += s2; } catch(e2) { } i2 = new Iterator(p0, true); }/*iii*/for (var p in o2) { try { f0 = f0; } catch(e0) { } o2.valueOf = (function() { for (var j=0;j<15;++j) { f0(j%2==1); } }); }/*hhh*/function buoumn([e], x){((makeFinalizeObserver('nursery'))) = t0[0];}\nfor (var p in s2) { try { t2 = new Int16Array(19); } catch(e0) { } try { g0.h2.get = this.f1; } catch(e1) { } try { /*ADP-3*/Object.defineProperty(a1, 5, { configurable: true, enumerable: (x % 104 != 57), writable: true, value: s1 }); } catch(e2) { } Array.prototype.splice.apply(g2.a1, [NaN, 1, a2]); }\nbreak L;\n\n");
/*fuzzSeed-116111302*/count=218; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=219; tryItOut("{ void 0; void gc(); }");
/*fuzzSeed-116111302*/count=220; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.imul(Math.fround(Math.min(( + Math.acosh((Math.tanh(y) & Math.fround(mathy0(-0x080000001, Math.fround(( + Math.max(( + x), ( + y))))))))), ((Math.cos(( ! ( + ( + -Number.MAX_VALUE)))) >>> (Math.trunc(y) | 0)) | 0))), (((Math.fround(mathy0(Math.fround(Math.atan2(y, x)), Math.fround((mathy0((y | 0), (y | 0)) | 0)))) >>> 0) << ((0x100000000 ? y : y) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-(2**53), 1, -0x0ffffffff, 0.000000000000001, -1/0, 42, 1.7976931348623157e308, 0x100000001, -0, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, -0x080000000, 0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, 0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), -0x100000000, Math.PI, -0x080000001, -0x100000001, Number.MIN_VALUE, 0, -Number.MIN_VALUE, 0x100000000, Number.MAX_VALUE, -(2**53+2), 2**53-2, 1/0, -0x07fffffff]); ");
/*fuzzSeed-116111302*/count=221; tryItOut("\"use strict\"; this.o2 = g0.__proto__;");
/*fuzzSeed-116111302*/count=222; tryItOut("\"use asm\"; (yield 13);");
/*fuzzSeed-116111302*/count=223; tryItOut("testMathyFunction(mathy2, [Math.PI, -1/0, -0x07fffffff, -(2**53-2), 2**53+2, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, 0.000000000000001, 0x0ffffffff, -(2**53+2), 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 1.7976931348623157e308, 0x080000001, 2**53, Number.MIN_VALUE, Number.MAX_VALUE, 0/0, 0x07fffffff, 42, -0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, -(2**53), -0, -0x080000000, Number.MAX_SAFE_INTEGER, 0, 0x100000000, -0x100000000, 1/0]); ");
/*fuzzSeed-116111302*/count=224; tryItOut("v0 = (b1 instanceof h2);");
/*fuzzSeed-116111302*/count=225; tryItOut("\"use strict\"; v2 = t2.length;");
/*fuzzSeed-116111302*/count=226; tryItOut("\"use strict\"; \"use asm\"; t1[v1];function x(x) { yield 14 } a0 = g1.t0[7];");
/*fuzzSeed-116111302*/count=227; tryItOut("\"use strict\"; for(c = x in (({window: new Array(8), 28: (Array.prototype.toLocaleString)(23, /(?!\\B){4}(?:\\t)*/m) }))) {/*tLoop*/for (let c of /*MARR*/[true, function(){}, true, new String(''), true, function(){}, new String(''), function(){}, true, function(){}, new String(''), new String(''), true, false, function(){}, function(){}, true, new String(''), new String('')]) { mathy3 } }");
/*fuzzSeed-116111302*/count=228; tryItOut("mathy0 = (function(x, y) { return (Math.fround(Math.atan2(Math.fround((( + Math.sinh(Math.cosh(-Number.MAX_VALUE))) , ( ! Math.fround(( + Math.fround(Math.asin(y))))))), Math.fround(Math.max(( ! (( ~ ( ! -0x0ffffffff)) >>> 0)), ( ~ (Math.fround((Math.fround(-0x100000001) << (( ~ ((( + y) , ( + 1/0)) | 0)) | 0))) | 0)))))) <= (((( + ( ~ 0x0ffffffff)) == (((( + ( ! Math.asin(y))) << (((Math.max(y, (0 | 0)) | 0) < (((x | 0) | (( + (( + -0x0ffffffff) !== ( + x))) | 0)) | 0)) >>> 0)) >>> 0) | 0)) | 0) >> (( + ((Math.sign(y) && ( - y)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, 1, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, -0x0ffffffff, 0, -(2**53+2), -1/0, -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, -0x080000001, -(2**53), 0x07fffffff, 1/0, Number.MAX_VALUE, 0x080000000, 0x0ffffffff, -0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, -0x100000001, -Number.MIN_VALUE, Math.PI, 2**53+2, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000001, 42, 0/0, -(2**53-2), 2**53]); ");
/*fuzzSeed-116111302*/count=229; tryItOut("\"use strict\"; /*oLoop*/for (var cyoxve = 0; cyoxve < 1; ++cyoxve) { print( \"\" ); } ");
/*fuzzSeed-116111302*/count=230; tryItOut("\"use asm\"; let (c) { print(x /= \"\\u0AD2\" ^= new RegExp(\"(?!\\\\B)+?|[^]+?(?!(?!\\\\d|(?=.)){1,})?\", \"m\")); }");
/*fuzzSeed-116111302*/count=231; tryItOut("mathy3 = (function(x, y) { return Math.max((( - mathy2(x, ( ! x))) | (( + (Math.imul(42, mathy0((( - Math.fround(x)) >>> 0), Math.imul(y, (x >= y)))) | 0)) | 0)), Math.fround(Math.exp((mathy1((Math.max(y, Math.hypot((y >>> 0), (x >>> 0))) >>> 0), ((((x >>> 0) / (x >>> 0)) >>> 0) << (2**53-2 << ((x <= -0x100000001) >>> 0)))) | 0)))); }); ");
/*fuzzSeed-116111302*/count=232; tryItOut("\"use strict\"; var x, x, c = x.__defineSetter__(\"eval\", c => \"use asm\";   var NaN = stdlib.NaN;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -1125899906842625.0;\n    var d4 = -0.0078125;\n    d3 = (+(1.0/0.0));\n    i1 = (((0x74f15*(0xd64ed73f))) <= (+(((((-0x7642d1c)+(0x34c6531))>>>((0xa5495e7f)*0xfffff)) % (((0x82465025)-(0xaf76ab31))>>>((0xfab16595)-(0xffffffff))))>>>(((NaN) > (new Uint8Array((b = Proxy.createFunction(({/*TOODEEP*/})(this), decodeURI, (1 for (x in [])))),  '' )))+(1)))));\n    return +((-144115188075855870.0));\n  }\n  return f;), x, window =  '' , pgvkzb, dsckpu, w, dlnyum, bkakyc;v1 = g1.a2.length;");
/*fuzzSeed-116111302*/count=233; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( + ( + Math.atan2(y, y))) <= Math.fround((Math.fround(Math.max(Math.fround((Math.log(((( - (Math.hypot(Number.MAX_VALUE, x) | 0)) >>> 0) >>> 0)) >>> 0)), Math.fround(((((Math.pow((-0x080000000 >>> 0), (( ! y) >>> 0)) >>> 0) | 0) >>> (Math.fround(mathy0(y, x)) | 0)) | 0)))) & Math.atan2((Math.asin((x | 0)) | 0), ( ! x))))); }); testMathyFunction(mathy4, [-0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 42, -0x100000001, Number.MAX_VALUE, 0x080000001, -(2**53-2), 0x080000000, Math.PI, -(2**53), 2**53+2, -1/0, -0x080000001, 2**53-2, 0x0ffffffff, 0x100000000, -0x080000000, -(2**53+2), -Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, 1/0, -Number.MIN_VALUE, -0, 0/0, 0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, 0x07fffffff, 2**53]); ");
/*fuzzSeed-116111302*/count=234; tryItOut("/*infloop*/for(x in x) {delete this.v2[\"setFloat32\"]; }");
/*fuzzSeed-116111302*/count=235; tryItOut("a0.toString = (function(j) { if (j) { try { a1.reverse(); } catch(e0) { } try { i2.send(o1.o0); } catch(e1) { } try { v2 = new Number(v2); } catch(e2) { } Array.prototype.unshift.call(a2, a1, a1, v1, t0, b0, i2); } else { try { this.v1 = evaluate(\"(w = x)\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  /x/ , noScriptRval: true, sourceIsLazy: \"\\u6F4F\", catchTermination: true })); } catch(e0) { } s1 += 'x'; } });a2 = Array.prototype.filter.call(a0);");
/*fuzzSeed-116111302*/count=236; tryItOut("\"use strict\"; g1.t2 = new Int32Array(o2.b1);\nvar x = ((let (d = new -27(\"\\u61E5\")) intern(\"\\u40F3\")))( \"\" , (\u3056 = /((?:\\b)*|^{4,4}|.(?:.|\\s)|(?:.|\\xc4$[])?)/gi).__defineSetter__(\"x\", Date.prototype.getTimezoneOffset));for(let z in []);let(c) { v2 = this.t2[11];}\n");
/*fuzzSeed-116111302*/count=237; tryItOut("\"use strict\"; (let (d = \"\\u233D\") /(((\\b)){1,5})\\2(?:^+)|([^])*\\d*|\\3*\\B\\B\\b|^/gyi);");
/*fuzzSeed-116111302*/count=238; tryItOut("with({a: (NaN & x)}){Array.prototype.pop.apply(a2, [a2]); }");
/*fuzzSeed-116111302*/count=239; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.fround(Math.trunc(( + (( ! (y >> Math.min(y, -(2**53-2)))) >>> 0))))) , ( + Math.sin((( + ((Math.acosh((Math.log1p(y) <= y)) >>> 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0/0, -0, 2**53-2, 0x100000000, -(2**53), Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, Number.MAX_VALUE, -0x100000000, 1/0, Number.MIN_VALUE, 0x0ffffffff, -0x080000001, -0x100000001, 2**53+2, 0x080000001, -0x080000000, Math.PI, 0x100000001, 1, 42, -1/0, -0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, 0, -0x0ffffffff, 0x080000000, -Number.MAX_VALUE, -Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=240; tryItOut("m0.has(h1);");
/*fuzzSeed-116111302*/count=241; tryItOut("\"use asm\"; g1.a1.splice(o2, m2);");
/*fuzzSeed-116111302*/count=242; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((( ~ ((((Math.acos((Math.pow((x | 0), y) | 0)) >>> 0) != (Math.fround(Math.fround(( ! y))) | 0)) | 0) | 0)) ? ( + (( ! Math.sinh((( + Math.expm1(( + x))) >>> 0))) | 0)) : mathy0((( ~ ((Math.log2((y >>> 0)) >>> 0) >>> 0)) >>> 0), ((mathy4((Math.hypot((Math.fround(Math.max(Math.fround(Math.fround(((Math.fround(Math.pow((x >>> 0), Math.fround(1.7976931348623157e308))) | 0) != Math.fround(y)))), Math.fround(x))) >>> 0), (x >>> 0)) >>> 0), (Math.pow(-0x0ffffffff, (2**53+2 >>> 0)) >>> 0)) >>> 0) >>> 0))) | 0); }); testMathyFunction(mathy5, [0x080000001, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0x080000000, 0.000000000000001, -Number.MAX_VALUE, 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, 2**53, -0x100000000, -0, -0x07fffffff, 0, 2**53-2, -0x0ffffffff, 42, -0x100000001, Number.MIN_VALUE, 0x07fffffff, 2**53+2, 1, -0x080000000, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, 0x0ffffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=243; tryItOut("\"use strict\"; testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 2**53, Number.MAX_VALUE, 0/0, 0x080000001, -1/0, 0x100000000, -(2**53-2), -0x080000001, 0, -(2**53+2), 1.7976931348623157e308, -0x100000000, 1/0, Number.MIN_VALUE, 2**53+2, -0, -Number.MAX_VALUE, -0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, 0x0ffffffff, -0x0ffffffff, 42, 0x080000000, 0x07fffffff, 0x100000001, -0x080000000, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=244; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 549755813888.0;\n    var i3 = 0;\n    d1 = (+abs(((d2))));\n    {\n      {\n        (Uint8ArrayView[4096]) = ((((0x9cdd1a8b) / (0x252f2fb7))|0) % ((((Math.max(25, ((function too_much_recursion(llimcf) { v0 + '';; if (llimcf > 0) { ; too_much_recursion(llimcf - 1);  } else {  } print(x); })(2)))) ? (/*FFI*/ff(((1048577.0)), ((590295810358705700000.0)), ((-4294967297.0)), ((-1.2089258196146292e+24)), ((-140737488355329.0)), ((281474976710657.0)), ((-3.8685626227668134e+25)), ((140737488355329.0)), ((-32769.0)))|0) : (i3))+(0x37ee2217)-(0xfcb171a0)) & ((((0x4dba2b82)-(0x65d59856)+(0xfffd423d)) >> ((0xd633e6dd)-(0xb698e52e)+(0xf8c67c33))) / (0x7fffffff))));\n      }\n    }\n    return +((((+(1.0/0.0))) % ((-35184372088831.0))));\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0/0, -1/0, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000001, -(2**53-2), 0x07fffffff, -0x07fffffff, 0x0ffffffff, -(2**53+2), 42, -0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 0.000000000000001, 0, -Number.MAX_VALUE, Number.MAX_VALUE, -0x100000000, 2**53+2, 1, -0, 1/0, 2**53, 0x080000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, 1.7976931348623157e308, -0x080000001, 2**53-2]); ");
/*fuzzSeed-116111302*/count=245; tryItOut("mathy0 = (function(x, y) { return Math.atan2(( + Math.sign((( - (((Math.imul(Math.acos((((0x080000001 | 0) * (y | 0)) | 0)), x) / y) >>> 0) >>> 0)) | 0))), ( ~ ( + Math.imul(( + y), ( + Math.fround(Math.pow(Math.fround(( + ( + -Number.MAX_SAFE_INTEGER))), Math.fround(new undefined(\"\\u340C\", true))))))))); }); ");
/*fuzzSeed-116111302*/count=246; tryItOut("\"use strict\"; /*bLoop*/for (mzvzgn = 0; mzvzgn < 8; ++mzvzgn) { if (mzvzgn % 3 == 2) { this.e0.has(((yield  \"\" )).yoyo({})); } else { this.a0.shift(); }  } ");
/*fuzzSeed-116111302*/count=247; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = (0x2cfc12d2);\n    }\n    return ((0x25a84*(i0)))|0;\n    i0 = (i0);\n    d1 = (NaN);\n    (Float64ArrayView[1]) = ((+(~~(-1.5474250491067253e+26))));\n;    d1 = (-4.835703278458517e+24);\n    switch ((((0x8f061838)) << (((((0xa7bf1333))>>>((0xb239915e))))))) {\n      case 0:\n        i0 = ((!((((((0xfe56eff3)+(-0x8000000)+(0xa63e4216))>>>((0xf8df2e63))) % (0x9c8e0c68)) ^ (-(-0x8000000))) != ((-((-9223372036854776000.0) <= (3.022314549036573e+23))) >> (((+/*FFI*/ff(((131073.0)), ((288230376151711740.0)), ((1.888946593147858e+22)), ((-6.189700196426902e+26)), ((-36028797018963970.0)), ((-9007199254740991.0)), ((-4398046511105.0)), ((-1099511627777.0)), ((18446744073709552000.0)), ((-17592186044417.0)), ((1.00390625)), ((1152921504606847000.0)), ((-17592186044417.0)))) > (d1))+(i0))))));\n        break;\n      case 1:\n        {\n          d1 = (2.3611832414348226e+21);\n        }\n        break;\n    }\n    /*FFI*/ff(((-((d1)))));\n    {\n      d1 = (144115188075855870.0);\n    }\n    i0 = (0x50c4a23);\n    return (((abs((((!(i0))*0x5fb91) | ((imul((i0), (i0))|0) % ((((0x10b26f7d) >= (-0x8000000))) | ((i0))))))|0) % ((((((0x57aefccb))+((0xdbfb1816)))>>>((0x89a3b79a)*-0x98952)) / (((0xffffffff)-(0xffffffff)+(0x357b8c31))>>>((-0x6a71aac) % (0x6dfee1ee)))) << ((i0)-(0x742c017f)+(!(0xffffffff))))))|0;\n  }\n  return f; })(this, {ff: encodeURIComponent}, new ArrayBuffer(4096)); ");
/*fuzzSeed-116111302*/count=248; tryItOut("mathy1 = (function(x, y) { return Math.exp(Math.max(Math.max((y || Math.fround(((( + y) != (y >>> 0)) >>> 0))), 0x080000001), ( + mathy0(( + ( + Math.cosh(x))), ( + Math.sin((y | 0))))))); }); testMathyFunction(mathy1, [0x0ffffffff, -0x100000000, -0x080000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 1, 1/0, 0.000000000000001, 2**53+2, -Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -0x0ffffffff, Math.PI, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, -0x080000000, 0/0, 2**53, -Number.MAX_VALUE, -0, -(2**53-2), Number.MIN_VALUE, -(2**53), 0, 42, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-116111302*/count=249; tryItOut("testMathyFunction(mathy1, [-(2**53), Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -1/0, 0x0ffffffff, 0x080000000, -0x100000000, 0/0, -(2**53-2), Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, Number.MAX_VALUE, 0x07fffffff, -0, -0x07fffffff, 2**53+2, 1/0, 2**53-2, -0x080000000, 42, 0, 1, -Number.MIN_VALUE, 0x100000001, 2**53, Math.PI, 0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=250; tryItOut("testMathyFunction(mathy5, [-0x0ffffffff, 2**53-2, -0x100000001, -(2**53+2), 2**53, Number.MAX_VALUE, 42, Math.PI, -(2**53-2), 1/0, 0x07fffffff, Number.MIN_VALUE, 0.000000000000001, 0x100000000, 0x080000000, -(2**53), -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, Number.MAX_SAFE_INTEGER, -1/0, 0x0ffffffff, -0x080000001, 0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 1, 0x080000001, 0, 0/0, 2**53+2, -0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=251; tryItOut("mathy4 = (function(x, y) { return ( ~ kzpbor); }); testMathyFunction(mathy4, [1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -(2**53-2), -(2**53), -(2**53+2), 0x080000001, -0x07fffffff, 0.000000000000001, 0, -Number.MAX_VALUE, 1, -0x080000000, 0x080000000, -1/0, Number.MIN_VALUE, -0x0ffffffff, -Number.MIN_VALUE, 2**53, -0, -0x100000000, 0/0, 0x100000000, 0x100000001, 2**53-2, -0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 42, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI]); ");
/*fuzzSeed-116111302*/count=252; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.sqrt(Math.fround(((( - ( - y)) >>> 0) ? (Math.cos((x | 0)) | 0) : ( + Math.log(( + y))))))); }); testMathyFunction(mathy1, /*MARR*/[ /x/ , (void 0),  /x/ ]); ");
/*fuzzSeed-116111302*/count=253; tryItOut("t2 = new Uint8ClampedArray(t0);");
/*fuzzSeed-116111302*/count=254; tryItOut("for (var v of i2) { try { m1.has(SyntaxError()); } catch(e0) { } v0 = a2.every((function(stdlib, foreign, heap){ \"use asm\";   var cos = stdlib.Math.cos;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 549755813889.0;\n    var d5 = -8589934591.0;\n    var d6 = -15.0;\n    i3 = ((+cos(((Float32ArrayView[4096])))) == (+abs(((d4)))));\n    (Float64ArrayView[2]) = ((d6));\n    (Float64ArrayView[((((i3)) >> (((((0xd6478ccb))>>>((0xbb93c00a)))))) % (~~(4611686018427388000.0))) >> 3]) = ((-32769.0));\n    i1 = (0xfd654718);\n    return (((/*FFI*/ff()|0)-(0xeb7d9651)))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use strict\"; var dafnaw = x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })((void options('strict_mode'))), ({constructor: b.__defineGetter__(\" \\\"\\\" \", Set.prototype.entries) }).getOwnPropertyNames, eval); (DataView.prototype.setInt16)(); })}, new ArrayBuffer(4096)), this, o1); }");
/*fuzzSeed-116111302*/count=255; tryItOut("\"use strict\"; (/[\\cW]/gyi);");
/*fuzzSeed-116111302*/count=256; tryItOut("/*infloop*/for(var z = [1,,].__proto__; /*FARR*/[ /x/  |= this, x, .../*MARR*/[ '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  /x/g , objectEmulatingUndefined(),  '' , objectEmulatingUndefined()]].some; x) v1 = (g0.h1 instanceof a1)\ng1.a1.forEach();");
/*fuzzSeed-116111302*/count=257; tryItOut("throw b;for(let w in []);");
/*fuzzSeed-116111302*/count=258; tryItOut("\"use strict\"; for (var v of i0) { try { for (var v of v0) { try { v1 = g0.eval(\"/* no regression tests found */\"); } catch(e0) { } try { m0.set(o1, v0); } catch(e1) { } for (var p in v1) { try { v0 = Object.prototype.isPrototypeOf.call(this.a1, b2); } catch(e0) { } o1.t1[8] = a2; } } } catch(e0) { } try { e0.delete(Math.acosh((x ** x))); } catch(e1) { } /*RXUB*/var r = r0; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex);  }");
/*fuzzSeed-116111302*/count=259; tryItOut("print(x);");
/*fuzzSeed-116111302*/count=260; tryItOut("L:for(let c in ((String.prototype.substring)((yield x))))a2.sort((function mcc_() { var zpagpo = 0; return function() { ++zpagpo; if (/*ICCD*/zpagpo % 4 == 1) { dumpln('hit!'); try { v1 = t0.length; } catch(e0) { } try { o1 = this.g1.p0.__proto__; } catch(e1) { } s0 = g0.o1.s2.charAt(({valueOf: function() { /*RXUB*/var r = (w = c); var s = \"\\u503d\\u503d\\u503d\\u503d\\u503d\\u503d\\u503d \\u503d\\u503d\\n\"; print(s.replace(r, function(y) { /*infloop*/M:for(let ReferenceError( '' )[\"1\"] in ((String.prototype.search)(y))){ /x/ ; } })); return 11; }})); } else { dumpln('miss!'); try { i0.__iterator__ = (function(j) { if (j) { o0.o2.m1.has(this.m1); } else { try { Array.prototype.splice.call(a0, 10, g2.v2, g1, g1, i0, this.t1, h1); } catch(e0) { } a0.forEach(f0); } }); } catch(e0) { } try { print(uneval(s0)); } catch(e1) { } m2.has(m0); } };})(), e2, h1, this.s0);");
/*fuzzSeed-116111302*/count=261; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.min(Math.pow(Math.tanh(Math.fround((Math.fround(( - Math.hypot((Math.pow((y >>> 0), -Number.MAX_SAFE_INTEGER) >>> 0), (y >>> 0)))) >> Math.fround(x)))), mathy0(Math.fround((( + (y >>> 0)) >>> 0)), Math.fround(Math.pow((x >= x), y)))), Math.min(Math.fround(Math.sinh(( + Math.fround((Math.fround((((((-0 >>> 0) > (( + mathy0(x, ( + Number.MIN_VALUE))) >>> 0)) >>> 0) && ( ! Math.fround(y))) | 0)) << Math.fround((( ~ (x | 0)) >>> 0))))))), Math.fround(Math.round(( + Math.imul(( + y), Math.min(( + x), ((Math.imul(Math.fround(x), Math.fround(x)) | 0) & 0/0)))))))); }); testMathyFunction(mathy1, [42, -0x07fffffff, -0x080000000, 2**53+2, 0x080000001, 0x07fffffff, Number.MIN_VALUE, -0x100000000, 0/0, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, 0.000000000000001, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, -1/0, 0x080000000, 0, -Number.MIN_VALUE, -(2**53), -(2**53-2), 2**53-2, 0x100000000, -(2**53+2), -0x080000001, -0x0ffffffff, 1/0, -0, -Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=262; tryItOut("\"use strict\"; print(window);print(-21);");
/*fuzzSeed-116111302*/count=263; tryItOut("mathy5 = (function(x, y) { return ( ! Math.fround((mathy1((Math.fround(mathy1((( + Math.min(0x080000000, Math.fround(Math.max(y, Math.acos((Math.clz32(x) >>> 0)))))) | 0), (y | 0))) >>> 0), (mathy1(((((( - (2**53+2 | 0)) ? y : x) >>> 0) ? (y >>> 0) : (x | 0)) >>> 0), Math.atan2(Math.fround(Math.fround((( + x) !== Math.fround(-0x100000001)))), x)) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-116111302*/count=264; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-116111302*/count=265; tryItOut("/*RXUB*/var r = this.r0; var s = s2; print(s.match(r)); ");
/*fuzzSeed-116111302*/count=266; tryItOut("/*RXUB*/var r = /(?=..?|\\s)\\b|.{2}?|\\2/im; var s = \"\\n\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-116111302*/count=267; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(m2, p0);");
/*fuzzSeed-116111302*/count=268; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.min((( + ( - ( + (((Math.fround(Math.log2(y)) | 0) >>> (Math.hypot(-Number.MIN_VALUE, Math.abs((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function() { throw 3; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { return true; }, hasOwn: function (c)window, get: function(receiver, name) { return x[name]; }, set: undefined, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { throw 3; }, }; }))) | 0)) | 0)))) | 0), Math.cosh((Math.pow(Math.min((Math.hypot(( + x), ( + -1/0)) | 0), x), ( + ((((x | 0) < (y >>> 0)) >>> 0) !== 0/0))) ? (Math.fround(( ! (( ~ mathy0(y, -0x080000000)) | 0))) ? (( + y) >> ((( ~ (-0 >>> 0)) >>> 0) >>> 0)) : (((x !== y) - Math.fround(Math.sinh(2**53))) >>> 0)) : ( + (Math.round((Math.imul(( + y), Math.imul(x, y)) | 0)) | 0)))))); }); testMathyFunction(mathy1, [-0x100000000, 1, -0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000000, Number.MIN_VALUE, -0, -(2**53+2), 0/0, -0x100000001, -Number.MAX_VALUE, Math.PI, -0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, 2**53+2, -(2**53), -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, -0x07fffffff, 2**53, -(2**53-2), 42, 0x080000001, 0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=269; tryItOut("\"use strict\"; for(let w in []);return;");
/*fuzzSeed-116111302*/count=270; tryItOut("h0.__proto__ = b0;");
/*fuzzSeed-116111302*/count=271; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=272; tryItOut("mathy0 = (function(x, y) { return ((Math.log1p((( ~ (Math.imul((Math.hypot(y, ((y % -0x07fffffff) | 0)) | 0), ((Math.round((2**53-2 | 0)) | 0) | 0)) | 0)) <= (Math.sqrt((((x - x) | 0) ? Math.ceil(x) : Math.sign(x))) >>> 0))) >= Math.fround(Math.sign(((((Math.round(( + ( - ( + y)))) >>> 0) >>> 0) == ((( + (Math.hypot(Number.MAX_SAFE_INTEGER, y) | 0)) | 0) >>> 0)) >>> 0)))) >>> 0); }); ");
/*fuzzSeed-116111302*/count=273; tryItOut("/*bLoop*/for (var jpipfr = 0; jpipfr < 11; ++jpipfr, new /\\3|(?![^])(?=\\b|$|$*?)?/yi) { if (jpipfr % 6 == 0) { e0.add(o2.h0); } else { g1.offThreadCompileScript(\"Array.prototype.shift.call(g0.o0.a1);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: /[^\\b-\\t]|^{4}$*?{2}|(\\3)*?{34359738368,34359738370}/, sourceIsLazy: \"\\u30AD\", catchTermination: true })); }  } ");
/*fuzzSeed-116111302*/count=274; tryItOut("\"use strict\"; s1 = new String;");
/*fuzzSeed-116111302*/count=275; tryItOut("testMathyFunction(mathy2, [0x080000000, -0x080000001, Math.PI, -(2**53+2), 0x100000000, 42, -1/0, -0x07fffffff, 2**53, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0x080000001, -0x100000001, 1.7976931348623157e308, 1/0, -(2**53), 0x100000001, -0x0ffffffff, -(2**53-2), -0x080000000, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, 1, 0x0ffffffff, 0.000000000000001, -0, 0/0, -0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=276; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=277; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-(2**53), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0/0, -0x080000001, 1, -(2**53-2), -0, Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, 42, -(2**53+2), -0x100000001, 2**53, 0x080000000, 0x100000001, Number.MIN_VALUE, 0, Math.PI, 2**53-2, -Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, -Number.MIN_VALUE, 0.000000000000001, 0x07fffffff, 2**53+2, -0x0ffffffff, 0x100000000]); ");
/*fuzzSeed-116111302*/count=278; tryItOut("\"use asm\"; return;");
/*fuzzSeed-116111302*/count=279; tryItOut("testMathyFunction(mathy4, ['\\0', undefined, (new Boolean(false)), '', /0/, objectEmulatingUndefined(), '0', [], ({valueOf:function(){return 0;}}), (new Boolean(true)), 0, ({toString:function(){return '0';}}), true, false, 0.1, '/0/', (new String('')), [0], (new Number(-0)), 1, null, (function(){return 0;}), NaN, ({valueOf:function(){return '0';}}), -0, (new Number(0))]); ");
/*fuzzSeed-116111302*/count=280; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[function(){}, x, function(){}, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, (timeout(1800)), objectEmulatingUndefined()]) { m0.get(a2); }");
/*fuzzSeed-116111302*/count=281; tryItOut(";function window(a, x)\"use asm\";   var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var tan = stdlib.Math.tan;\n  var atan2 = stdlib.Math.atan2;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 68719476735.0;\n    var i3 = 0;\n    var i4 = 0;\n    i0 = (((((0x0)))|0) != (imul((((((~((-0x1c35383)+(0xfeb020c9)+(0xfb2f5b29)))))>>>(((-0x8000000) ? (0x530457ca) : (0xfbd0689a))))), (i0))|0));\n    d2 = (4194305.0);\n    i0 = (!((((!((((0xbd558741))>>>((0xffffffff)))))+(0xf958dd02)-(i1))>>>(((0x0))))));\n    {\n      i1 = ((((((i0)-(!(1)))>>>((i4))) % ((((0xfc65cf48) ? (0xfd587aac) : (0xd2ce04f2))+(i1)-(i0))>>>(((0x83d6bf40) ? (0xe182179e) : (0x266fcbd6))))) >> (((i3)-(0xe2e8e46)))));\n    }\n    d2 = (+pow(((((7.737125245533627e+25) <= (+(0.0/0.0))) ? (129.0) : (d2))), ((2.0))));\n    i4 = (0xdf43eac9);\n    (Float32ArrayView[4096]) = ((536870913.0));\n    {\n      d2 = ((i1) ? (-1.0009765625) : (+abs(((+((Infinity)))))));\n    }\n    i4 = ((274877906943.0) <= ((((Float32ArrayView[((i1)*0x3422e) >> 2])) - ((+tan(((+atan2(((+(1.0/0.0))), (((0xffffffff) ? (-131073.0) : (-590295810358705700000.0))))))))))));\n    return +((-1125899906842623.0));\n    d2 = (((+pow(((1.015625)), ((Infinity))))) % ((33.0)));\n    i1 = ((0xb13011bf));\n    return +((144115188075855870.0));\n  }\n  return f;/*infloop*/ for (eval of  /x/ ) s1.toString = (function() { for (var j=0;j<103;++j) { f0(j%5==1); } });");
/*fuzzSeed-116111302*/count=282; tryItOut("testMathyFunction(mathy2, [0.000000000000001, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, -Number.MIN_VALUE, 1, -0x080000000, 2**53, 2**53-2, 0x100000001, -0x100000001, Number.MIN_VALUE, 1/0, -0x080000001, -0x07fffffff, 0x0ffffffff, 0x100000000, 0x080000001, 1.7976931348623157e308, 0x07fffffff, -1/0, Number.MIN_SAFE_INTEGER, 42, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, -0, -(2**53), -0x0ffffffff, 0, -0x100000000, Math.PI]); ");
/*fuzzSeed-116111302*/count=283; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (mathy2((Math.fround(Math.log1p((( - ( + Math.cosh(x))) >>> 0))) > Math.fround(mathy3(x, (mathy0(Math.atan(Math.fround(y)), Math.asinh(y)) >>> 0)))), ((((Math.trunc((x | 0)) | 0) | 0) ? (0.000000000000001 | 0) : (( ~ (( + Math.min((Math.imul(-0x100000000, y) >>> 0), y)) | 0)) | 0)) | 0)) ? Math.cosh(( + ( ~ Math.min(Math.fround(( ! Math.fround(x))), Math.fround(Math.imul((((y - x) >>> 0) | 0), (x | 0))))))) : (Math.tanh((x >= (Math.atan2(mathy0(mathy0((y ^ x), ( + ( + mathy4(( + y), ( + 0/0))))), -0x07fffffff), (Math.hypot((x >>> 0), -0x080000001) !== x)) >>> 0))) >>> 0)); }); testMathyFunction(mathy5, [42, -(2**53), -0, 0x0ffffffff, -0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, Math.PI, 2**53, 0x080000000, 2**53+2, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_VALUE, 0/0, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 0, -(2**53+2), 0x080000001, 1, 1/0, -1/0, 0x100000001, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000001, -Number.MAX_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=284; tryItOut("m0 + i0;");
/*fuzzSeed-116111302*/count=285; tryItOut("\"use strict\"; { /* Comment */timeout(1800).setUint8(x ^= \u3056); }");
/*fuzzSeed-116111302*/count=286; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = 33554433.0;\n    var i4 = 0;\n    var d5 = -8388609.0;\n    return (((0xfacd780f)+(-0x60e90d8)))|0;\n  }\n  return f; })(this, {ff: (function(x, y) { return Math.imul(y, Math.log10(( + -0x100000001))); })}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0x100000000, 0x080000000, -0, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, -(2**53), -Number.MIN_VALUE, 1/0, 0, Number.MAX_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, 0x080000001, 0x100000000, -(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Math.PI, 2**53, Number.MIN_VALUE, -0x080000001, -0x0ffffffff, 1, 42, 2**53+2, -0x080000000, 2**53-2, 0x100000001]); ");
/*fuzzSeed-116111302*/count=287; tryItOut("b1 = o2.t0.buffer;");
/*fuzzSeed-116111302*/count=288; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + mathy0(( + ( ! mathy1(x, (mathy1(Math.fround((((-0x07fffffff | 0) ? Number.MAX_VALUE : (-0x0ffffffff | 0)) | 0)), (x >>> 0)) >>> 0)))), ((Math.fround(( + Math.hypot(Math.fround(Math.asinh(( - y))), Math.fround(( ~ ((mathy3((x >>> 0), (y >>> 0)) >>> 0) >>> 0)))))) != (( ! (x | 0)) | 0)) >>> 0))) | ( ! (Math.fround(0) << y))); }); testMathyFunction(mathy5, /*MARR*/[objectEmulatingUndefined(),  /x/g ,  \"\" , objectEmulatingUndefined(),  \"\" ,  \"\" ,  \"\" ,  \"\" , null, objectEmulatingUndefined(),  \"\" , objectEmulatingUndefined(), null,  \"\" ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(),  \"\" ,  \"\" ,  \"\" , null, objectEmulatingUndefined(),  /x/g ,  /x/g , null,  /x/g ,  /x/g ,  \"\" , null,  \"\" ,  \"\" ,  \"\" ,  /x/g , null,  /x/g ,  \"\" ,  /x/g , null,  /x/g ]); ");
/*fuzzSeed-116111302*/count=289; tryItOut("var nfaavb = new SharedArrayBuffer(32); var nfaavb_0 = new Uint16Array(nfaavb); nfaavb_0[0] = -7; a2.unshift(o2.f2);/*vLoop*/for (var piqtoq = 0, dclsgt; piqtoq < 7; ++piqtoq) { let d = piqtoq; o2.h2.defineProperty = f1;let a = (makeFinalizeObserver('nursery')); } ");
/*fuzzSeed-116111302*/count=290; tryItOut("v2 = g2.eval(\"yield;\\na1.pop();\\n\\nswitch(Math.hypot(\\\"\\\\u19DF\\\", 13)) { default: g1.b1 = t2.buffer;print(x);case 8: break;  }\\n\");");
/*fuzzSeed-116111302*/count=291; tryItOut("let e, x, hxxexs;s0 += s0;");
/*fuzzSeed-116111302*/count=292; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.imul((Math.imul(( + mathy0(Math.fround(((x > ( + (( + y) ** ( + x)))) === Math.fround(y))), (( ~ y) | 0))), (((x | 0) + Math.tanh(y)) - -Number.MAX_SAFE_INTEGER)) | 0), (mathy2((x * (( - ((( - y) >>> 0) > (y >>> 0))) >>> 0)), ( - Math.log(( + (( ~ (Math.cosh((1.7976931348623157e308 | 0)) | 0)) | 0))))) | 0)) >>> 0); }); testMathyFunction(mathy3, [2**53-2, 1/0, 0x100000001, 2**53+2, -0, -Number.MIN_VALUE, 0/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -0x080000000, -0x080000001, 0.000000000000001, -(2**53-2), Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 0x0ffffffff, Math.PI, -Number.MAX_VALUE, -0x100000000, -1/0, 0x07fffffff, 2**53, -0x0ffffffff, -0x100000001, -(2**53), -0x07fffffff, -(2**53+2), 1, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0, 42, -Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-116111302*/count=293; tryItOut("/*RXUB*/var r = r1; var s = s1; print(s.replace(r, '\\u0341')); print(r.lastIndex); ");
/*fuzzSeed-116111302*/count=294; tryItOut("/*RXUB*/var r = /\\1/g; var s = \"\\n\\u00e8\"; print(s.match(r)); ");
/*fuzzSeed-116111302*/count=295; tryItOut("o0.v1 = a2.reduce, reduceRight((function() { try { for (var p in g0.f0) { try { for (var v of g2) { try { v1 = g1.eval(\"p0 + o0.t2;\"); } catch(e0) { } neuter(g2.g1.g2.b0, \"change-data\"); } } catch(e0) { } v0 = (g0 instanceof f0); } } catch(e0) { } m2.has(g0.b0); return e2; }), i2, o1.g1);");
/*fuzzSeed-116111302*/count=296; tryItOut("g1.v2 = Object.prototype.isPrototypeOf.call(t1, o2.p2);");
/*fuzzSeed-116111302*/count=297; tryItOut("((delete x.z) |= delete x.of);");
/*fuzzSeed-116111302*/count=298; tryItOut("v1 = (e1 instanceof this.h0);");
/*fuzzSeed-116111302*/count=299; tryItOut("{ void 0; disableSPSProfiling(); }");
/*fuzzSeed-116111302*/count=300; tryItOut("f0 + '';");
/*fuzzSeed-116111302*/count=301; tryItOut("v1 = Object.prototype.isPrototypeOf.call(s1, v2);");
/*fuzzSeed-116111302*/count=302; tryItOut("g2.v2 = evaluate(\"f1(a0);\", ({ global: o1.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 5 == 4), sourceIsLazy: (Math.atan2((4277), 'fafafa'.replace(/a/g, Date.prototype.toTimeString))), catchTermination: (x % 4 != 3), elementAttributeName: s0, sourceMapURL: s2 }));");
/*fuzzSeed-116111302*/count=303; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = ((Float32ArrayView[(0x38a0f*(((((~(((-0x8000000) ? (0xcfc59bb1) : (0xfa0f8ef8))))))>>>((i0))))) >> 2]));\n    return ((-0x3c5d6*(i1)))|0;\n    (Uint8ArrayView[((imul((i1), ((0xaa615500)))|0) % (0x7fffffff)) >> 0]) = (((((i1)+(0x99e3bfff)-((0xffffffff) == (0x9d11e7bf)))|0) > (~~(1.5474250491067253e+26))));\n    {\n      i0 = (i0);\n    }\n    i0 = ((0xf7ef748) > (0x0));\n    i1 = (i1);\n    i1 = (i1);\n    return (((((562949953421312.0)) - ((Float32ArrayView[2])))))|0;\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ var webbuz = x; (arguments.callee.caller)(); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000000, -0x100000001, -0, -Number.MAX_SAFE_INTEGER, 0, -1/0, -(2**53+2), -(2**53), 42, 0x100000001, -0x0ffffffff, 1/0, -0x07fffffff, 2**53-2, 2**53, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, 0x080000001, -Number.MIN_VALUE, -0x080000001, -(2**53-2), -0x080000000, -0x100000000, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, 0/0, 1, Number.MAX_VALUE, Number.MIN_VALUE, 0.000000000000001]); ");
/*fuzzSeed-116111302*/count=304; tryItOut("testMathyFunction(mathy1, [-Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 2**53-2, 42, -0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000000, 0x100000001, 0x07fffffff, -(2**53+2), Number.MAX_VALUE, 0x100000000, -0x080000001, 2**53, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 0x080000001, Math.PI, -(2**53-2), Number.MAX_SAFE_INTEGER, -1/0, -(2**53), 1, -0, 0/0, -0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53+2, 0, Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-116111302*/count=305; tryItOut("mathy5 = (function(x, y) { return ( + mathy3(Math.fround(( ~ (Math.imul((( + ((y >>> 0) + (x >>> 0))) >>> 0), (( - (Math.log1p(y) > y)) >>> 0)) >>> 0))), ( + ( + (mathy3(( ! -0x080000001), (( + Math.imul((x && (( + Math.clz32(( + x))) >>> 0)), ((x === (-1/0 | 0)) | 0))) | 0)) >>> 0))))); }); testMathyFunction(mathy5, [-0x080000000, 0x100000000, 42, -0x07fffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53-2, 0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -0, 0.000000000000001, 2**53+2, -0x080000001, 0x07fffffff, -1/0, -(2**53-2), -0x100000001, 1, -0x100000000, 0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53, -(2**53), 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, Math.PI, 1/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=306; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ ( - (Math.exp((((Math.log10(y) >>> 0) ? Math.imul((( - -0x07fffffff) | 0), y) : y) >>> 0)) * mathy0(0x100000000, (x << x))))); }); testMathyFunction(mathy4, [1.7976931348623157e308, 0.000000000000001, -0, -0x0ffffffff, -0x080000001, 0, 1, 42, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -0x07fffffff, -(2**53), 0x080000001, 0/0, -1/0, 2**53+2, -Number.MAX_VALUE, 0x07fffffff, -(2**53+2), 1/0, -Number.MIN_VALUE, -0x100000000, 0x100000000, Math.PI, -0x100000001, Number.MAX_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 2**53, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000000]); ");
/*fuzzSeed-116111302*/count=307; tryItOut("\"use strict\"; for (var p in m0) { try { b1 = t2.buffer; } catch(e0) { } try { a0 = Array.prototype.slice.apply(a2, [NaN, NaN, o1.m1, g0]); } catch(e1) { } try { v2 = Object.prototype.isPrototypeOf.call(this.g1, t2); } catch(e2) { } v0 = a0.length; }v1 = evalcx(\"\\\"\\u03a0\\\"\", g1);");
/*fuzzSeed-116111302*/count=308; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use asm\"; return Math.atan2((( ~ ( + (Math.exp((( + ((Math.hypot((( + x) | 0), (x | 0)) | 0) | 0)) | 0)) ** y))) >>> 0), (Math.cosh(mathy0(((Math.log1p((y | 0)) % -0x100000001) >>> 0), (-0x100000000 !== Math.imul(y, y)))) | 0)); }); testMathyFunction(mathy3, [-(2**53-2), -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000000, 2**53-2, 2**53+2, 2**53, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -0x0ffffffff, -0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, 42, 0, 0x07fffffff, -0x080000000, 0x100000001, -Number.MAX_VALUE, -(2**53+2), 1/0, 1, -1/0, 0.000000000000001, Number.MIN_VALUE, -(2**53), Math.PI, -0, 0/0, Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001]); ");
/*fuzzSeed-116111302*/count=309; tryItOut("\"use strict\"; selectforgc(this.o0);");
/*fuzzSeed-116111302*/count=310; tryItOut("for (var p in g2) { try { h1.getOwnPropertyNames = (function() { for (var j=0;j<118;++j) { o0.o1.f1(j%5==0); } }); } catch(e0) { } try { g0.offThreadCompileScript(\"\\\"use strict\\\"; Array.prototype.sort.apply(a0, [(function() { for (var v of o1.i1) { try { g2.v2 = r0.multiline; } catch(e0) { } try { s1 += s2; } catch(e1) { } try { ; } catch(e2) { } v0 = evaluate(\\\"return;\\\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 76 != 25), noScriptRval: (x % 3 == 2), sourceIsLazy: \\\"\\\\u29BC\\\", catchTermination:  /x/g  })); } return g1.s2; }), m1, s2, s1]);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: /*FARR*/[Math.imul(Math.min(( ~ Math.hypot(( + x), ( + x))), 0x07fffffff), x), ...(makeFinalizeObserver('nursery')), x = /*MARR*/[-(2**53), -(2**53), true].some(encodeURI), /\\d/ |= x, ...new Array(-1945238186), (x = 4), undefined.__defineSetter__(\"y\", new Function), +Math, window, .../*FARR*/[.../*FARR*/[, ...( /x/  for each (w in \u3056) for (SQRT2 of true) for (w of window) if (this)), ({d: ((yield d))}), ( + 0x100000000), intern(\"\\u8D20\")], , ...eval(\"mathy3 = (function(x, y) { return ( + Math.tanh(( + (Math.fround(( - (((((x | 0) - (Math.hypot(-0x100000001, (y >>> 0)) | 0)) | 0) || x) >>> 0))) > Math.fround(Math.pow(((Math.pow(Math.round(x), Number.MAX_VALUE) | 0) >> (mathy1((-0x0ffffffff >>> 0), x) >>> 0)), ((( + y) !== ( + y)) | 0))))))); }); testMathyFunction(mathy3, [-Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -0, -0x080000001, Math.PI, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, 1/0, 2**53-2, -(2**53+2), -(2**53), Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000000, 0x100000001, -0x080000000, 0x100000000, 0, -0x07fffffff, 0x07fffffff, -Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, -(2**53-2), 2**53+2, 42, -1/0, 0x0ffffffff]); \", x % window) for each (d in Math.floor) for (x of [c++ for (NaN of undefined) for (x of [])]) for each (setter in []), function(){}], (uneval([x])), (function () { h0.get = f2; } ).call((4277), (yield (let (d) window)),  \"\" ), eval(\"e2.add(this.s2);\",  /x/g ), x, , .../*PTHR*/(function() { \"use strict\"; for (var i of /*PTHR*/(function() { for (var i of /*FARR*/[ /* Comment */ /x/ , , true, (yield Object(window)), /*FARR*/[\"\\u0B86\", new RegExp(\"\\\\1|.|^|(?!(?=\\\\B{3}|[]|(?:.){1}))\", \"gyim\"), , eval].some(function(y) { {} }, (/(?!(?=\\u0041?|\\D\\B)(?=\\2))/gi >>>= \"\\u4E9B\"))]) { yield i; } })()) { yield i; } })(), (26\n), (4277), , ].map, sourceIsLazy: false, catchTermination: true, sourceMapURL: s1 })); } catch(e1) { } try { /*MXX3*/o0.g1.Uint32Array.prototype.BYTES_PER_ELEMENT = this.g2.Uint32Array.prototype.BYTES_PER_ELEMENT; } catch(e2) { } v1 = evaluate(\"/*RXUB*/var r = new RegExp(\\\"\\\\\\\\W\\\", \\\"gyim\\\"); var s = \\\"a\\\"; print(s.match(r)); \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: false, catchTermination: (x % 113 != 44) })); }");
/*fuzzSeed-116111302*/count=311; tryItOut("a0.splice(NaN, v0);");
/*fuzzSeed-116111302*/count=312; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.atan(Math.fround(( + (( + Math.sinh(( - ((( - (-0x080000001 >>> 0)) >>> 0) ? y : x)))) & ( + Math.max(x, (x != Math.sqrt(x))))))))); }); testMathyFunction(mathy3, [NaN, (new String('')), false, '/0/', 1, null, '', undefined, ({toString:function(){return '0';}}), (new Number(0)), '0', [0], (new Number(-0)), 0, /0/, (new Boolean(false)), 0.1, objectEmulatingUndefined(), (new Boolean(true)), '\\0', true, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), -0, [], (function(){return 0;})]); ");
/*fuzzSeed-116111302*/count=313; tryItOut("\"use strict\"; a2 = r1.exec(s0);let y = /*MARR*/[Infinity, 0, Infinity, 0, Infinity, x, Infinity, x, x, 0, 0, 0, x, 0, x, Infinity, 0, Infinity, 0, null, null, 0, Infinity, 0, Infinity, 0, 0, Infinity, null, 0, null, Infinity, 0, Infinity, x, 0, Infinity, x, null, x, null, Infinity, Infinity, 0, Infinity, 0, Infinity, 0, x, x, 0, null, x, x, null, x, 0, null, null, 0, 0, null, null, 0, Infinity, x, 0, Infinity, null, Infinity, 0, 0, x, Infinity, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, null, 0, x, 0].map;");
/*fuzzSeed-116111302*/count=314; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + ((((Math.pow((( + mathy2(y, ( + y))) >>> 0), Math.min(x, x)) | 0) ? (( - ( + -0x07fffffff)) | 0) : Math.fround((((Math.pow(x, y) >>> 0) ** (y >>> 0)) >>> 0))) | 0) / (((y >>> 0) - (Math.log1p(((Math.pow(0.000000000000001, y) | 0) >>> 0)) >>> 0)) >>> 0))) && ( + (( - ((y >>> 0) <= (Math.fround(Math.asinh(( + x))) >>> 0))) - Math.hypot((Math.min(((Math.fround(-Number.MAX_VALUE) ** (y | 0)) | 0), x) * Math.pow((x >>> 0), y)), 1.7976931348623157e308)))); }); ");
/*fuzzSeed-116111302*/count=315; tryItOut("this.f2.toString = (function() { try { e2.delete(g2.s0); } catch(e0) { } try { m1.has(e2); } catch(e1) { } v0 = (b0 instanceof f0); return this.o2.i1; });\ni0 = new Iterator(h0, true);\n");
/*fuzzSeed-116111302*/count=316; tryItOut("\"use strict\"; new new (function(id) { return id })(\"\\u6913\")();");
/*fuzzSeed-116111302*/count=317; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.acosh(Math.asinh(mathy2((x | 0), ( + Math.tan(( + mathy1(Math.fround(Math.imul(( + 2**53), x)), (x >>> 0)))))))); }); testMathyFunction(mathy3, ['/0/', false, ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '', (new Number(0)), /0/, [], ({valueOf:function(){return 0;}}), (function(){return 0;}), [0], (new Boolean(true)), true, (new Boolean(false)), '\\0', 0.1, (new String('')), null, undefined, NaN, 0, 1, (new Number(-0)), '0', -0]); ");
/*fuzzSeed-116111302*/count=318; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=319; tryItOut("/*vLoop*/for (let uunhie = 0, y; uunhie < 143; ++uunhie) { var x = uunhie; Array.prototype.sort.call(a2, (function() { o1.__proto__ = o1; return e2; })); } ");
/*fuzzSeed-116111302*/count=320; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 17179869183.0;\n    var d3 = 18446744073709552000.0;\n    var i4 = 0;\n    var i5 = 0;\n    return +((5.0));\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x080000001, 0/0, 1, Number.MIN_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000000, 0, -0x100000001, -(2**53-2), Math.PI, 1.7976931348623157e308, -Number.MIN_VALUE, Number.MAX_VALUE, 42, -0x100000000, 0x100000000, -0, -Number.MAX_VALUE, 2**53+2, -0x080000000, 0x07fffffff, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, 0x0ffffffff, -1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, -0x0ffffffff, 1/0]); ");
/*fuzzSeed-116111302*/count=321; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=322; tryItOut("\"use strict\"; e1.has(o1);");
/*fuzzSeed-116111302*/count=323; tryItOut("selectforgc(o2);");
/*fuzzSeed-116111302*/count=324; tryItOut("h2.getPropertyDescriptor = f2;");
/*fuzzSeed-116111302*/count=325; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=326; tryItOut("o0.o1.v0 = Object.prototype.isPrototypeOf.call(f2, a2);");
/*fuzzSeed-116111302*/count=327; tryItOut("/*ODP-1*/Object.defineProperty(s1, \"1\", ({configurable: ((decodeURIComponent).call(this, x, new  \"\" ())).yoyo(undefined), enumerable: (uneval(Math.log1p( '' .watch(\"getUTCDay\", \"\\uC5C1\"))))}));");
/*fuzzSeed-116111302*/count=328; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(?!(?=([^][^\\u3d16-\\uB8bB\\B\\dh]|[^])))|\\b{4,})|(?=.|\\b?){3,}|\\3*|(?:(?=(\\2))){0,0}((?!\\b?.+?){0,})*?/gi; var s = Symbol().throw( /x/g ); print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-116111302*/count=329; tryItOut("/*infloop*/for(let this.zzz.zzz in ((/(?:\\2?\\2?){3}/gim)(((x)) = yield x)))x;");
/*fuzzSeed-116111302*/count=330; tryItOut("\"use strict\"; a2 = Array.prototype.filter.apply(a0, [(function mcc_() { var zwztsg = 0; return function() { ++zwztsg; if (zwztsg > 1) { dumpln('hit!'); try { Array.prototype.unshift.apply(a0, [i0, e0, s1, s0, f1, o2.g1, g2]); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(o2, g0); } catch(e1) { } try { /*ADP-1*/Object.defineProperty(a1, 12, ({writable: true})); } catch(e2) { } b2 + ''; } else { dumpln('miss!'); try { print(i2); } catch(e0) { } try { v1 = f0[\"substring\"]; } catch(e1) { } /*MXX1*/Object.defineProperty(this, \"o0\", { configurable: (x % 3 == 2), enumerable: true,  get: function() {  return g0.Symbol.keyFor; } }); } };})(), let (b) b, o0.f0]);");
/*fuzzSeed-116111302*/count=331; tryItOut("let (e = (yield), lxiopt, mikqzr, NaN, z, window, NaN = x, z = ({/*toXFun*/toString: mathy5 })) { /*RXUB*/var r = b.valueOf(\"number\"); var s = (yield new  \"\" .valueOf(\"number\")(x)); print(s.search(r));  }");
/*fuzzSeed-116111302*/count=332; tryItOut("mathy0 = (function(x, y) { return ( - ((Math.max((Math.tanh(Math.exp(( + Math.min((y | 0), y)))) >>> 0), (((((Math.acos(y) | 0) | 0) || ( ~ Number.MIN_SAFE_INTEGER)) | 0) >>> 0)) >>> 0) - ( + Math.atan2((Math.hypot(Math.min(x, x), 0x100000000) | 0), (Math.atan2(-0x080000001, y) | 0))))); }); ");
/*fuzzSeed-116111302*/count=333; tryItOut("this.v1 = g1.eval(\"x\");");
/*fuzzSeed-116111302*/count=334; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=335; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -36893488147419103000.0;\n    return (((/*FFI*/ff(((abs((0x174c1d9b))|0)), (((((0xffffffff)-((-0x8000000) <= (-0x8000000)))>>>((((17592186044417.0) + (-1.125)) <= (+((4.0)))))) != (0xed885454))))|0)+(0xfedbda9a)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.setUTCMilliseconds}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, -1/0, 0x080000001, 0x100000000, 0x080000000, 0.000000000000001, 1, 42, 1.7976931348623157e308, -0, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, -0x080000001, -(2**53+2), 2**53-2, 2**53+2, Math.PI, -0x080000000, 0x100000001, 1/0, -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-116111302*/count=336; tryItOut("o0.g1.offThreadCompileScript(\"f0(s0);\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 2 != 0), noScriptRval: true, sourceIsLazy: void x, catchTermination: true, sourceMapURL: s2 }));m2.get(a1);");
/*fuzzSeed-116111302*/count=337; tryItOut("e1.has(/\\2/yim\n.hasOwnProperty());");
/*fuzzSeed-116111302*/count=338; tryItOut("mathy5 = (function(x, y) { return Math.hypot(Math.max(( ! Math.hypot(0x080000000, (( + Math.pow(( + ( + Math.imul(( + x), y))), ( + Math.fround(( ~ Math.fround(Math.clz32(y))))))) >>> 0))), Math.pow(( ! ( + Math.tan(x))), y)), ( ! ( ! (( + x) === (x ? x : (x | 0)))))); }); testMathyFunction(mathy5, [-(2**53), -0, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, 0x080000001, 2**53-2, -0x0ffffffff, 42, -(2**53-2), -0x100000000, 0x07fffffff, -Number.MAX_VALUE, -1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, 0, -0x080000001, 2**53+2, 1, 0x100000000, 0x100000001, 1/0, -0x07fffffff, -0x100000001, 0/0, 0.000000000000001, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-116111302*/count=339; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 3.094850098213451e+26;\n    return (((i1)))|0;\n    i1 = (0x711075dc);\n    return (((abs((~(((((0x64ca84d8)) << ((0xf8e5a640)))))))|0) % (((0xda70b3a7) % (((0x839c8b89) / (0x7b04fe22))>>>(y = new RegExp(\"(.){1}\", \"y\")))) ^ (0x50335*(!((((0xe5c1b992)-(-0x8000000))>>>((0xd48ecc96)-(0xfff6fded)-(0xffffffff)))))))))|0;\n    d2 = (Infinity);\n    return (((((((0x777daec9) ? (0xe97ef310) : (0x783fbe6a))-(i1)+(i1)) & (((((0x4103aa84)+(-0x8000000))|0) <= ((Float64ArrayView[2])))-((i1) ? (0xfd37dc0f) : ((0x7fffffff))))) <= ((((~~(18014398509481984.0)) > (abs((0x51fd712f))|0))) | ((((0x30bc1120) / (0x3e8a8662))>>>((0x9cc226ad)-(0xf9384d76)+(0xffffffff))) / (((0x725fd011)+(0xc24c603d)+(0x2bea8c6b))>>>((-0x7b15e2)-(0xeb75c465))))))+(0x6b4b5a24)))|0;\n  }\n  return f; })(this, {ff: Function}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, -(2**53), 1, -1/0, 0, 0x07fffffff, -(2**53+2), 0x100000000, -0, -0x080000000, -0x100000001, -Number.MIN_VALUE, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0/0, 2**53, -0x0ffffffff, 0x080000001, 1.7976931348623157e308, 2**53+2, -Number.MAX_VALUE, -0x100000000, -0x080000001, 1/0, 2**53-2, 0x0ffffffff, 42, 0x100000001, -0x07fffffff, 0.000000000000001]); ");
/*fuzzSeed-116111302*/count=340; tryItOut("\"use asm\"; if(true) a1.forEach((function() { g1.v2 = Object.prototype.isPrototypeOf.call(e0, e1); return i2; }), m0); else o1.m1.has(p2);");
/*fuzzSeed-116111302*/count=341; tryItOut("m1.has(g0.t1);");
/*fuzzSeed-116111302*/count=342; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(Math.ceil(( ~ (( - (Math.sin(( + x)) >>> 0)) >>> 0)))) && Math.fround(Math.fround((Math.fround(( + Math.sin(( + (((x | 0) < (Math.max((x >>> 0), (Math.atanh(0x080000001) >>> 0)) | 0)) | 0))))) <= Math.fround((Math.min((( + x) || ( + (y ? x : ( + Math.atan2(-(2**53), 2**53))))), (Math.hypot(Math.fround(Math.pow(Math.fround(( ! x)), 1.7976931348623157e308)), Math.trunc(Math.fround(( + Number.MIN_SAFE_INTEGER)))) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy0, [0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, 2**53, Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, 42, 1, Number.MIN_VALUE, -0, 0x100000001, -0x080000001, 0, -Number.MIN_VALUE, 1.7976931348623157e308, 1/0, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 0/0, 0x100000000, 0x080000001, -0x0ffffffff, -(2**53), Math.PI, -1/0, -0x100000001, 0x080000000, 0.000000000000001]); ");
/*fuzzSeed-116111302*/count=343; tryItOut("mathy5 = (function(x, y) { return Math.expm1(Math.min((((( + (Math.fround((Number.MAX_VALUE + x)) ? Math.fround((((x ? x : y) ? (Math.fround(Math.atan2(Math.fround(y), x)) >>> 0) : (y >>> 0)) >>> 0)) : Math.fround(y))) >>> 0) % (( + (x == ( + x))) >>> 0)) >>> 0), ( + Math.min((( + Math.acosh((Math.imul((x >>> 0), (( - y) >>> 0)) >>> 0))) >>> 0), (( ! x) >>> 0))))); }); testMathyFunction(mathy5, [1, '', [0], (new Number(-0)), ({toString:function(){return '0';}}), /0/, null, -0, ({valueOf:function(){return 0;}}), undefined, false, '/0/', true, (new Boolean(false)), 0, objectEmulatingUndefined(), (new Number(0)), 0.1, '0', (new Boolean(true)), '\\0', (new String('')), ({valueOf:function(){return '0';}}), NaN, [], (function(){return 0;})]); ");
/*fuzzSeed-116111302*/count=344; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=345; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[objectEmulatingUndefined(), x, -0x07fffffff, x, -0x07fffffff, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, x, x, x, x, -0x07fffffff, x, x, x, objectEmulatingUndefined(), -0x07fffffff, objectEmulatingUndefined(), -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x07fffffff, x, objectEmulatingUndefined(), -0x07fffffff, x, x, -0x07fffffff, objectEmulatingUndefined(), x, -0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), x, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, x, objectEmulatingUndefined(), -0x07fffffff, -0x07fffffff, objectEmulatingUndefined(), -0x07fffffff, x, x, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, -0x07fffffff, -0x07fffffff, -0x07fffffff, -0x07fffffff, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, -0x07fffffff, x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined()]) { v0 + h1; }");
/*fuzzSeed-116111302*/count=346; tryItOut("\"use strict\"; v2 = i1[\"x\"];");
/*fuzzSeed-116111302*/count=347; tryItOut("const v2 = evalcx(\"/*infloop*/for(var y = []; Math.pow((4277) , (({ get -16 x (z) { \\u000cyield /\\\\u0029\\\\B{0,}.|(?=.)\\\\u0007/i } , BYTES_PER_ELEMENT: null })), new Int16Array()); (Uint32Array(x))) {/*iii*/print(false);/*hhh*/function itjwba(y, y, x, y, y = new RegExp(\\\"(?:[^]?)\\\", \\\"gm\\\"), d, this.b, d, e, x, x, y, e, a = new RegExp(\\\"(?!((?=\\\\\\\")*))*?\\\", \\\"gy\\\"),  , ...y){selectforgc(o2);} }\\n\", g2);");
/*fuzzSeed-116111302*/count=348; tryItOut("mathy1 = (function(x, y) { return (Math.imul(((( - y) - ( - Math.fround(( + (( + Math.fround(mathy0(Math.fround(-Number.MAX_VALUE), Math.fround(-0)))) ? ( + Number.MIN_VALUE) : ( + mathy0(0.000000000000001, ( + y)))))))) | 0), (mathy0(( + ( ! ( + Math.fround(mathy0(Math.fround(y), ( + ( - ( + x)))))))), ((( - ((Math.atan2(Math.fround(Math.atan(Math.fround(y))), (-0x0ffffffff >>> 0)) >>> 0) | 0)) | 0) >>> 0)) | 0)) ^ (((mathy0((( ! x) >>> 0), (x >>> 0)) >>> 0) + ((Math.log(Math.fround(Math.max(( + ( + ( + x))), Math.expm1(( ~ x))))) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [0x100000001, 0.000000000000001, Math.PI, -(2**53), 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, -0x100000001, Number.MIN_VALUE, -0x100000000, -(2**53-2), 1.7976931348623157e308, -0x080000000, -1/0, 0, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000001, 0/0, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, 1, -0, 42, -0x0ffffffff, -0x07fffffff, 1/0, -Number.MAX_VALUE, 0x080000001, 0x080000000, 2**53]); ");
/*fuzzSeed-116111302*/count=349; tryItOut("m0.set(o2, i2);");
/*fuzzSeed-116111302*/count=350; tryItOut("this.a1 = new Array;");
/*fuzzSeed-116111302*/count=351; tryItOut("mathy2 = (function(x, y) { return ( + Math.max(( + Math.fround(Math.log10(( + (( + ( + ( + (x * x)))) % Math.max((x >>> 0), y)))))), ( + Math.acos(( + mathy1(mathy0(Math.fround((Math.fround(Math.fround(mathy1(Math.fround(x), Math.fround(y)))) - (-1/0 | 0))), y), (42 | 0))))))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, Number.MIN_VALUE, 1.7976931348623157e308, 1/0, -0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0, 42, 2**53, -0x0ffffffff, 0x07fffffff, 0x0ffffffff, Math.PI, -0x100000000, 1, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, -0x07fffffff, -(2**53-2), 0x100000001, -0x080000001, 0.000000000000001, 0x080000001, -1/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), 0/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0, 2**53+2, 2**53-2]); ");
/*fuzzSeed-116111302*/count=352; tryItOut("\"use strict\"; m2.set(e1, o2);");
/*fuzzSeed-116111302*/count=353; tryItOut("\"use strict\"; o1.o2.v2 = (s0 instanceof this.p2);var w = ((new Function(\"print(x);\")))( '' , [,,]);");
/*fuzzSeed-116111302*/count=354; tryItOut("\"use strict\"; ");
/*fuzzSeed-116111302*/count=355; tryItOut("\"use strict\"; s0 = new String(p1);");
/*fuzzSeed-116111302*/count=356; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((mathy1(( + Math.log2(Math.hypot(x, y))), Math.hypot(x, y)) >>> Math.imul(Math.fround(Math.cbrt(Math.fround(-Number.MAX_VALUE))), Math.fround(mathy2(y, (( - Math.log2(Math.hypot(x, (y >>> 0)))) | 0))))) >>> ( + Math.ceil(( + ((Math.ceil(y) | 0) % Math.exp(-Number.MIN_VALUE)))))); }); testMathyFunction(mathy3, /*MARR*/[x,  /x/g , (void 0), (void 0), (void 0), x, x, x, x, null, null,  /x/g , (void 0), x, null, (void 0),  /x/g ,  /x/g , null,  /x/g , x, (void 0),  /x/g ,  /x/g ,  /x/g , null, (void 0),  /x/g , x, null,  /x/g , null,  /x/g ]); ");
/*fuzzSeed-116111302*/count=357; tryItOut("\"use strict\"; ");
/*fuzzSeed-116111302*/count=358; tryItOut("this.v0 = (b2 instanceof e1);function d(x, y) { yield 15 = /*RXUE*/new RegExp(\"\\\\3{3}\\\\2|\\\\s?|\\\\1{4,6}\", \"gi\").exec(\"\") } (x = ([]) = (d = Proxy.createFunction(({/*TOODEEP*/})(false), Function)));");
/*fuzzSeed-116111302*/count=359; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.fround(Math.fround(Math.atan2(Math.atan(( + x)), (( ~ ( + Math.fround(Math.sin(Math.fround(-Number.MIN_VALUE))))) | 0))))); }); testMathyFunction(mathy1, [42, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, -0, Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, 2**53-2, -Number.MAX_SAFE_INTEGER, 1/0, -1/0, 0x100000001, 0x07fffffff, -0x100000000, -0x080000000, -(2**53-2), 0, -Number.MIN_VALUE, -(2**53+2), 1.7976931348623157e308, Number.MIN_VALUE, -0x100000001, 0/0, -0x080000001, 0x080000001, 2**53, 0x0ffffffff, Math.PI, 0x100000000, -Number.MAX_VALUE, 2**53+2, 0.000000000000001, -(2**53)]); ");
/*fuzzSeed-116111302*/count=360; tryItOut("mathy0 = (function(x, y) { return Math.tan(Math.hypot(Math.imul(( + x), x), ((Math.fround(( ~ ( + ( + Math.cbrt(( + y)))))) << (x !== ( + ( ~ Math.sign(-Number.MAX_VALUE))))) | 0))); }); testMathyFunction(mathy0, [0, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, -1/0, 0.000000000000001, -0x080000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, 0x100000000, -(2**53+2), -0x07fffffff, Number.MAX_VALUE, 42, 0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, 0x080000000, 0x100000001, Math.PI, 1, -0x100000000, 2**53+2, -Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53, -(2**53), 2**53-2]); ");
/*fuzzSeed-116111302*/count=361; tryItOut("mathy3 = (function(x, y) { return (Math.ceil(Math.atan2(-1/0, ( ~ (1.7976931348623157e308 >>> 0)))) + (mathy1((y , (x | 0)), ( ~ (Math.imul((( + ( + x)) >>> 0), (x | 0)) >>> 0))) | 0)); }); ");
/*fuzzSeed-116111302*/count=362; tryItOut("Array.prototype.reverse.apply(a0, []);for (var p in a0) { try { o1 = Object.create(f1); } catch(e0) { } r2 = new RegExp(\"^\", \"y\"); }const b = this;");
/*fuzzSeed-116111302*/count=363; tryItOut("g0.m1.get(e1);");
/*fuzzSeed-116111302*/count=364; tryItOut("\"use strict\"; print(uneval(b2));");
/*fuzzSeed-116111302*/count=365; tryItOut("{ void 0; abortgc(); } s2 += s1;");
/*fuzzSeed-116111302*/count=366; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?=\\\\s))|(?!.*)|(?:.)+|[\\\\d\\\\v-\\\\cN\\\\d\\\\S][\\\\w]^|[\\\\\\u001e\\\\B-\\\\u4656]{0,0}\\\\u007a*[^]\\\\1[^\\\\x36-\\u3db8}\\\\d\\\\cB-\\\\cR]\\\\3{2}+?$(?=\\\\w)*?\", \"i\"); var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-116111302*/count=367; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( - (Math.expm1((( ~ (x * x)) | 0)) | 0)) ? ((((( - (Math.pow((( ~ (x | 0)) | 0), x) ? (Math.atan2((x >>> 0), 2**53-2) >>> 0) : (((Math.acos(( + x)) >>> 0) ? y : (x >>> 0)) >>> 0))) >>> 0) !== ( - Math.abs((y >>> 0)))) >>> 0) | 0) : Math.fround(mathy2((((( ! Math.tanh((0.000000000000001 === -(2**53+2)))) | 0) && -0x080000000) | 0), (( - (-0x080000001 && 0x100000000)) >>> 0)))); }); testMathyFunction(mathy3, [0.000000000000001, -Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000000, -1/0, Math.PI, 2**53-2, -0x080000001, 1/0, -0x100000000, -(2**53), 1.7976931348623157e308, 0x080000000, 0x07fffffff, 2**53+2, -(2**53+2), -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, 0, -0x100000001, -(2**53-2), -0x07fffffff, 2**53, 0x100000001, 1, -0, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-116111302*/count=368; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan2((Math.atanh(Math.fround(( ~ 0x080000001))) | 0), Math.min((( + x) | 0), ( - ( + Math.fround(( + Math.fround((( - (y | 0)) | 0)))))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 1, -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, -0x080000000, 0x080000001, -Number.MIN_VALUE, 2**53-2, 42, Number.MAX_VALUE, 2**53, 0x080000000, 0x0ffffffff, -0x07fffffff, -(2**53), 1/0, -0x080000001, 0/0, 0x100000001, -(2**53-2), -0x100000000, -0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, 1.7976931348623157e308, 0x100000000, -(2**53+2), -0, -1/0]); ");
/*fuzzSeed-116111302*/count=369; tryItOut("testMathyFunction(mathy5, [0x080000001, 2**53+2, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x100000001, -0x080000000, 42, Number.MIN_VALUE, 0x0ffffffff, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000000, 0, -1/0, 0x100000000, -0x0ffffffff, 0.000000000000001, 0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 2**53, -(2**53), -Number.MIN_VALUE, -0x100000000, 2**53-2, -0x100000001, 0/0, 1/0, -0x080000001, Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=370; tryItOut("mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return (mathy0(( + Math.log(Math.hypot(y, ( + (( + 0x100000000) >>> ( + Math.max(Math.fround(((Math.acos(-(2**53-2)) | 0) >= Math.fround((-(2**53-2) | 0)))), y))))))), Math.fround(( + Math.min(( + (( ! (x >>> 0)) >>> 0)), Math.fround(((((x >>> 0) ? (y >>> 0) : x) >>> 0) >= -Number.MIN_VALUE)))))) | 0); }); testMathyFunction(mathy3, [Number.MIN_VALUE, -0x100000000, 0.000000000000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0, -0x080000000, -0, 0x100000001, 1/0, -0x07fffffff, 0x0ffffffff, 2**53-2, 0/0, 0x100000000, -(2**53+2), 2**53, 42, Math.PI, -Number.MIN_VALUE, -(2**53-2), -0x100000001, 0x080000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, 1, -(2**53), -1/0, 0x07fffffff]); ");
/*fuzzSeed-116111302*/count=371; tryItOut("a2.shift(g2.g0.b0);");
/*fuzzSeed-116111302*/count=372; tryItOut("\"use strict\"; L:for(var y = this.__defineGetter__(\"x\", get++) in x) g0.offThreadCompileScript(\"(( ''  /  /x/g ).__defineSetter__(\\\"y\\\", neuter))\");");
/*fuzzSeed-116111302*/count=373; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x0ffffffff, 0/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x100000001, 42, 0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, -0x07fffffff, -0, 1.7976931348623157e308, -1/0, Number.MIN_VALUE, 1/0, 0x080000000, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, 2**53, Number.MAX_VALUE, 0x100000001, -0x080000001, Math.PI, -0x080000000, -(2**53+2), -Number.MAX_VALUE, 1, 0, 0x080000001]); ");
/*fuzzSeed-116111302*/count=374; tryItOut("print(uneval(i1));");
/*fuzzSeed-116111302*/count=375; tryItOut("print(x);");
/*fuzzSeed-116111302*/count=376; tryItOut("\"use strict\"; e1.delete(h1);");
/*fuzzSeed-116111302*/count=377; tryItOut("a1 = Array.prototype.map.call(a0, (function(j) { if (j) { try { print(uneval(v0)); } catch(e0) { } try { g1 + ''; } catch(e1) { } v1 = 4.2; } else { try { v2 = g1.eval(\"/*RXUB*/var r = /(?:\\\\3^)+/gyi; var s = \\\"\\\"; print(s.replace(r, '')); \"); } catch(e0) { } try { Array.prototype.reverse.apply(a0, [g2, o0]); } catch(e1) { } /*RXUB*/var r = g1.r2; var s = \"B\"; print(s.search(r)); print(r.lastIndex);  } }));");
/*fuzzSeed-116111302*/count=378; tryItOut("\"use strict\"; g2.e0 + o0;");
/*fuzzSeed-116111302*/count=379; tryItOut("mathy4 = (function(x, y) { return (Math.max(((y * Math.fround(Math.fround(Math.fround(Math.fround(Math.round((y | 0))))))) | 0), Math.fround(Math.max((Math.hypot((Math.min(-Number.MAX_SAFE_INTEGER, Math.fround((x & x))) >>> 0), (x >>> 0)) >>> 0), Math.hypot((x | 0), (Math.atan2((0x07fffffff !== 0x07fffffff), Math.imul(y, x)) | 0))))) * Math.min(Math.hypot((y >= x), (( + Math.max(( + x), (Math.fround(Math.log10(((x >>> x) >>> 0))) | 0))) && ( + x))), ((Math.asinh((mathy3(Math.fround(mathy1(y, Number.MIN_VALUE)), Math.fround(( + Math.imul(( + x), y)))) >>> 0)) >>> 0) ** x))); }); testMathyFunction(mathy4, [0x07fffffff, -1/0, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, 1, -0x100000000, 2**53+2, 0, 0x0ffffffff, -Number.MAX_VALUE, 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53), -(2**53+2), 0x080000000, 0x080000001, 2**53-2, 1.7976931348623157e308, 1/0, -(2**53-2), 2**53, -0x0ffffffff, -0x080000001, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000, -0]); ");
/*fuzzSeed-116111302*/count=380; tryItOut("m2.delete(i1);");
/*fuzzSeed-116111302*/count=381; tryItOut("mathy2 = (function(x, y) { return ( + (( ! (( + (( + 42) ** ( + Math.clz32(Math.fround(Math.hypot(Math.fround(mathy1((Math.cbrt((x >>> 0)) >>> 0), (x << (Number.MAX_VALUE >>> 0)))), Math.fround(Math.atan2(y, y)))))))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116111302*/count=382; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((34359738369.0));\n  }\n  return f; })(this, {ff: Object.getPrototypeOf}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [2**53, -0x0ffffffff, 0.000000000000001, 0x080000001, 0x100000001, -0x07fffffff, -Number.MAX_VALUE, 1/0, -0x100000000, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0, 0, Math.PI, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -(2**53), -1/0, 0x080000000, 2**53+2, -0x080000001, -0x100000001, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), 42, -0x080000000]); ");
/*fuzzSeed-116111302*/count=383; tryItOut("testMathyFunction(mathy1, ['\\0', (new Number(0)), undefined, [0], ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), /0/, [], ({toString:function(){return '0';}}), 1, NaN, 0.1, (new Boolean(true)), (new Number(-0)), true, null, '0', '/0/', objectEmulatingUndefined(), '', (new String('')), (new Boolean(false)), false, (function(){return 0;}), 0, -0]); ");
/*fuzzSeed-116111302*/count=384; tryItOut("{ void 0; validategc(false); }");
/*fuzzSeed-116111302*/count=385; tryItOut("mathy1 = (function(x, y) { return Math.min(Math.imul(( ~ (x >>> 0)), ( + (((Math.hypot(Math.fround(mathy0(( - (x < y)), Math.exp((y >>> 0)))), Math.fround(x)) >>> 0) >>> 0) != Math.fround(Math.tanh((y >> y)))))), (Math.fround(( + ( + Math.hypot(( + x), ( + -(2**53+2)))))) > Math.fround((((( + Math.log10((x + (( + Math.pow((y >>> 0), x)) | 0)))) !== ((Math.atan2((y | 0), (y | 0)) | 0) >>> 0)) >>> 0) - (-0x0ffffffff >>> 0))))); }); testMathyFunction(mathy1, [1, 0x07fffffff, 2**53, -0x100000001, -(2**53-2), 2**53+2, -0x080000001, 0x0ffffffff, 1.7976931348623157e308, -0x07fffffff, 0x100000000, 0.000000000000001, 1/0, Math.PI, Number.MAX_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, Number.MIN_VALUE, 2**53-2, -0x080000000, 0/0, -0, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 42, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, 0, -(2**53+2)]); ");
/*fuzzSeed-116111302*/count=386; tryItOut("/*oLoop*/for (yauina = 0; yauina < 64; ++yauina) { delete h1.keys; } ");
/*fuzzSeed-116111302*/count=387; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h0, t2);");
/*fuzzSeed-116111302*/count=388; tryItOut("/*RXUB*/var r = new RegExp(\"([^\\\\xF6\\\\uABF1\\\\W](?=(?!.)*))?(?:[^]{0}\\\\1|\\u16c2|\\uc4db)(?:(?:(?:\\u00b9))+?)|(?!.+)|[^]|(?:[^])[^]\\\\1+|(\\\\1){34359738367,34359754751}\", \"m\"); var s = \"\\\"\\\"\\\"\\\"\\\"\\\"_\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\n\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-116111302*/count=389; tryItOut("mathy0 = (function(x, y) { return ( + (Math.fround(( + ( ~ Math.fround(( ! (0.000000000000001 ? Math.imul(Number.MAX_VALUE, y) : y)))))) << Math.fround((Math.fround((-0 != (( - Math.fround(Math.fround(Math.log2(Math.fround(Math.fround(Math.min(x, y))))))) | 0))) <= (Math.min((((((Math.acos(Math.PI) | 0) >>> 0) | ((( - x) | 0) >>> 0)) >>> 0) | 0), ( + Math.pow((( ~ (x >>> 0)) >>> 0), ( + (( + x) % ( + x)))))) | 0))))); }); testMathyFunction(mathy0, [0.1, 1, ({toString:function(){return '0';}}), (function(){return 0;}), undefined, ({valueOf:function(){return 0;}}), [], false, (new Boolean(false)), NaN, (new Boolean(true)), (new Number(0)), [0], true, 0, null, /0/, objectEmulatingUndefined(), (new String('')), '\\0', '/0/', (new Number(-0)), -0, ({valueOf:function(){return '0';}}), '0', '']); ");
/*fuzzSeed-116111302*/count=390; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.imul(Math.hypot((( + Math.atan2(( + Math.imul(Math.fround(((Math.fround(Math.cosh((y >>> 0))) | 0) / ( + (x | x)))), -1/0)), ( + ((y ? ( ~ y) : (x >>> 0)) <= (Math.sqrt(y) << x))))) >>> 0), (( + Math.acosh((((( + ( - x)) | 0) << (( ! y) | 0)) | 0))) >>> 0)), Math.fround(Math.min((( ! y) >>> 0), (( + Math.expm1(( + x))) - Math.imul(2**53+2, y))))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -Number.MAX_VALUE, 0/0, -0x100000000, 0, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, -(2**53), 0x100000001, -1/0, 1.7976931348623157e308, -(2**53+2), -0x080000001, 0x0ffffffff, -0x07fffffff, Number.MAX_VALUE, -0, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, 42, 0x080000000, Number.MIN_VALUE, -0x080000000, 2**53, 0x100000000, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, Math.PI, 0.000000000000001, 1]); ");
/*fuzzSeed-116111302*/count=391; tryItOut("\"use strict\"; /*MXX2*/g2.Symbol.for = g0.v0;");
/*fuzzSeed-116111302*/count=392; tryItOut("g2.o2.v1 = a1.reduce, reduceRight((function(j) { f2(j); }));");
/*fuzzSeed-116111302*/count=393; tryItOut("t2[7] = g1;");
/*fuzzSeed-116111302*/count=394; tryItOut("\"use strict\"; s0 += 'x';");
/*fuzzSeed-116111302*/count=395; tryItOut("\"use strict\"; Array.prototype.reverse.call(a2, o0, g2.g0.s0, t2);");
/*fuzzSeed-116111302*/count=396; tryItOut("\"use strict\"; i0.toSource = f0;");
/*fuzzSeed-116111302*/count=397; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=398; tryItOut("(void schedulegc(this.g1));");
/*fuzzSeed-116111302*/count=399; tryItOut("{ void 0; fullcompartmentchecks(false); } a2.sort((function() { for (var j=0;j<49;++j) { f2(j%2==0); } }), this.p2, i2);function x(NaN, x) { for(y in ((function ([y]) { } | this)( \"\" ))){print(y);7; } } print(x);");
/*fuzzSeed-116111302*/count=400; tryItOut("\"use strict\"; Array.prototype.sort.call(a1, f2, g2.g2.m1, p0);");
/*fuzzSeed-116111302*/count=401; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-(2**53-2), -0x0ffffffff, -(2**53), 0x100000000, 2**53+2, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, -Number.MAX_VALUE, 0.000000000000001, -0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, -(2**53+2), 0x080000000, -Number.MAX_SAFE_INTEGER, 1/0, -1/0, 2**53, -0x100000000, -0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, Math.PI, 42, 1, 0/0, Number.MIN_VALUE, 0, 0x0ffffffff, Number.MAX_VALUE, 2**53-2]); ");
/*fuzzSeed-116111302*/count=402; tryItOut("print(x);");
/*fuzzSeed-116111302*/count=403; tryItOut("mathy5 = (function(x, y) { return (Math.max(((( - (( ~ Math.fround(Math.fround(0x100000000))) >>> 0)) >>> 0) <= (( + (x | 0)) > x)), ((( ! (Math.fround(Math.min(Math.fround((Math.sqrt(((Math.sign((x | 0)) | 0) >>> 0)) >>> 0)), Math.fround(0x100000000))) >>> 0)) >>> 0) >>> 0)) | 0); }); testMathyFunction(mathy5, [0x080000000, -(2**53), -0x100000000, Math.PI, 1.7976931348623157e308, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000001, -0x080000000, 0x07fffffff, 1/0, 0, 42, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53, 1, -(2**53+2), 0.000000000000001, -0x07fffffff, -0, -0x0ffffffff, -1/0, -(2**53-2), 2**53+2, 0x0ffffffff, 0x100000000, 0/0, -Number.MIN_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=404; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return mathy4(Math.fround((Math.log10(((mathy4((( + Math.imul(( + (( + ( + 0.000000000000001)) / y)), ( + mathy0((( ! y) | 0), (x | 0))))) >>> 0), (( + ( ! (( - y) || y))) >>> 0)) >>> 0) >>> 0)) >>> 0)), Math.fround(Math.imul(Math.fround(( + Math.max(( + -1/0), ( + ( ~ 0x100000000))))), Math.fround(( + mathy1(( + y), ( + (Math.max(y, ((y << y) >>> 0)) << x)))))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MIN_VALUE, 0x080000000, -(2**53-2), -0x080000000, 2**53, Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 1, -0, Number.MAX_VALUE, 2**53-2, 1/0, -(2**53), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000001, -Number.MIN_VALUE, 0.000000000000001, -0x080000001, 0x080000001, 0, -0x100000000, 0x100000000, 42, -(2**53+2), 0x07fffffff, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000001, -1/0]); ");
/*fuzzSeed-116111302*/count=405; tryItOut("var ayfikm = new SharedArrayBuffer(6); var ayfikm_0 = new Int16Array(ayfikm); ayfikm_0[0] = -29; v0 = Array.prototype.reduce, reduceRight.call(a0, (function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+(((0xf8469378)) | ((0xda12be66)+(1)))));\n  }\n  return f; }), h2);");
/*fuzzSeed-116111302*/count=406; tryItOut("i2.send(g0);");
/*fuzzSeed-116111302*/count=407; tryItOut("\"use strict\"; g0.v1 = evalcx(\"/* no regression tests found */\", g0.g1);function a(x, NaN, eval = x, NaN = (\nnew RegExp(\"(?:(?!\\\\S|[^\\\\0-\\\\u0062\\\\w]))|(?!(?:$^)+[\\\\D\\u00f7\\\\ud5f9\\\\d]+)\", \"gi\"))\n, c = (4277), x = new (new Function)(), NaN, \u3056, x, x, c, eval, y, e, z = window, d, e = window, c, a, x, d, z = /\\3|(.)+|\\2|\\b|(?=[e\\cQ])^\u659e\\b|[^]|^+|(\\B|\\W*)/gim, window, this.x, x = 11, x, x, z, window, x, eval, x = function ([y]) { }, x, -15, this.w, c, w, d, z, b, window, x, x, x, c, a, x, z = 22, window = \"\\u8EC7\", x, c, x, c, x, d, window, NaN, a, e, x, c, \u3056, y, x, \u3056, x, \u3056, \u3056, a, eval, x =  /x/ , x, a = z, NaN, x, w =  \"\" , x, window =  '' , eval, NaN =  /x/ , x = call, x, e, y, \u3056, e, x =  '' , x = [[]], x, ...\u3056) { \"use strict\"; yield \"\\u49E6\" } v1 = t1.length;");
/*fuzzSeed-116111302*/count=408; tryItOut("v0 = Object.prototype.isPrototypeOf.call(t2, t2);");
/*fuzzSeed-116111302*/count=409; tryItOut("");
/*fuzzSeed-116111302*/count=410; tryItOut("\"use strict\"; Array.prototype.push.apply(a1, [a1]);");
/*fuzzSeed-116111302*/count=411; tryItOut("v2 = (o2.m2 instanceof g1);");
/*fuzzSeed-116111302*/count=412; tryItOut(";");
/*fuzzSeed-116111302*/count=413; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( + ( + Math.atanh(Math.atan(x))))); }); testMathyFunction(mathy4, [0/0, -Number.MAX_VALUE, 0x080000001, 42, -(2**53+2), 0x07fffffff, 2**53-2, 2**53, 1/0, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, Math.PI, 1, -0x080000000, Number.MAX_VALUE, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, -0x100000001, Number.MIN_VALUE, -Number.MIN_VALUE, -0x080000001, 0, 0x080000000, -(2**53-2), -(2**53), -1/0, 0x100000000, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=414; tryItOut("\"use strict\"; v1 = b2.byteLength;");
/*fuzzSeed-116111302*/count=415; tryItOut("v1 = this.g1.r0.exec;");
/*fuzzSeed-116111302*/count=416; tryItOut("mathy2 = (function(x, y) { return (( + Math.tan(( + Math.fround((Math.fround(y) % Math.fround((x << ( + y)))))))) / Math.tanh((Math.max((Math.ceil(y) | 0), (((((y >>> 0) ** (Math.fround(( ! Math.fround(x))) >>> 0)) >>> 0) >= Math.ceil(Math.fround(y))) | 0)) >>> 0))); }); testMathyFunction(mathy2, [Math.PI, -0x100000000, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), 0x0ffffffff, -1/0, 0/0, 0x07fffffff, -0, 0x100000000, 1/0, 0.000000000000001, 0x080000001, Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 2**53, -0x07fffffff, 2**53-2, 0x080000000, 42, -Number.MAX_SAFE_INTEGER, 0, 2**53+2, -Number.MAX_VALUE, 1]); ");
/*fuzzSeed-116111302*/count=417; tryItOut("\"use strict\"; g0.g2.g2.v2 = g1.eval(\"Object.defineProperty(this, \\\"v0\\\", { configurable: x(), enumerable: true,  get: function() {  return evalcx(\\\"(this.a) = new RegExp(\\\\\\\"(?!(\\\\\\\\\\\\\\\\2{3})*)\\\\\\\", \\\\\\\"gym\\\\\\\")\\\", g2); } });\");");
/*fuzzSeed-116111302*/count=418; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(?:.{2}){262145}){3,}|(?:.+?)?/gyim; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116111302*/count=419; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( - Math.min(Math.fround(Math.fround(Math.min(( + Math.round(( + Math.hypot((x | 0), (Math.pow((y >>> 0), y) | 0))))), ( + Math.sign((-0x0ffffffff >>> 0)))))), Math.max(Math.asinh(( + (( + 0x080000000) !== ( + y)))), Math.fround(( - Math.max(y, (Math.hypot(( + x), y) >>> 0))))))); }); testMathyFunction(mathy3, [-(2**53+2), 2**53-2, 0x080000001, 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -0, -0x100000000, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0/0, 0x0ffffffff, -(2**53), -0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, -1/0, 2**53+2, -0x100000001, 0x07fffffff, 2**53, 0x100000000, -Number.MAX_VALUE, -0x0ffffffff, 0, 42, 1]); ");
/*fuzzSeed-116111302*/count=420; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.tanh(Math.sin((Math.hypot(Math.atan2(x, (Math.round((x >>> 0)) | 0)), ( ~ x)) >= Math.fround(Math.acosh((((Math.tanh((y | 0)) | 0) == (x | 0)) | 0)))))); }); testMathyFunction(mathy0, [-0x100000000, -0x080000000, 0, Number.MAX_SAFE_INTEGER, 42, -0x07fffffff, -0x100000001, Number.MIN_VALUE, -0, -(2**53), 0x100000001, 0x07fffffff, Math.PI, -0x0ffffffff, 1, 0.000000000000001, 0/0, -1/0, 2**53-2, -Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, 2**53+2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), 0x080000000, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000001]); ");
/*fuzzSeed-116111302*/count=421; tryItOut("mathy2 = (function(x, y) { return ( + Math.asinh(((mathy1(( + -0x100000000), (Math.fround((( + (( + (Math.log2((x >>> 0)) >>> 0)) >= ( + x))) || ((( + y) ^ ( + (0x100000000 , Math.min(x, x)))) | 0))) >>> 0)) >>> 0) ** Math.fround(Math.fround(Math.sqrt((x ? x : ((y | 0) && ( + 2**53-2))))))))); }); testMathyFunction(mathy2, [0x100000001, 0x100000000, 0, 42, Number.MAX_SAFE_INTEGER, -0, 1, -0x0ffffffff, Math.PI, -0x080000000, 0x07fffffff, Number.MIN_VALUE, 2**53, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, -(2**53), -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, 2**53-2, Number.MAX_VALUE, -0x100000000, -Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 0x080000000, -0x080000001, -1/0, 1/0, -Number.MAX_VALUE, -0x07fffffff]); ");
/*fuzzSeed-116111302*/count=422; tryItOut("mathy1 = (function(x, y) { return ( ~ ( ! (( + Math.imul(( + (( ~ (Math.clz32(x) >>> 0)) >>> 0)), ( + Math.fround(Math.max(( + x), ( + 2**53-2)))))) - Math.fround(Math.log1p(y))))); }); testMathyFunction(mathy1, [(new Boolean(true)), false, 0, NaN, '', (new String('')), '/0/', (new Number(-0)), 0.1, '0', null, ({valueOf:function(){return '0';}}), undefined, [0], true, (new Boolean(false)), -0, (function(){return 0;}), /0/, 1, (new Number(0)), '\\0', objectEmulatingUndefined(), [], ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-116111302*/count=423; tryItOut("\"use strict\"; v1 = evalcx(\"function this.f1(t2)  { return (Math.max(w+=(intern( '' )).fromCodePoint(), 8)) } \", g0);");
/*fuzzSeed-116111302*/count=424; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.asin((( + Math.exp(Math.atan2(2**53+2, Math.sin(y)))) << ((( ~ x) | 0) ? x : ((( ~ (y | 0)) | 0) | 0)))) | 0) ** ( + ( ~ ( + ((4277) += NaN >>> e))))); }); testMathyFunction(mathy0, [0x080000001, -0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 1, 2**53+2, -0x0ffffffff, 42, 2**53, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -(2**53+2), -0, 2**53-2, 0, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53), -1/0, 0x07fffffff, -Number.MIN_VALUE, 1.7976931348623157e308, 0/0, 0x100000000, 1/0, Math.PI, -0x100000000, -Number.MAX_VALUE, -0x080000000, -0x100000001]); ");
/*fuzzSeed-116111302*/count=425; tryItOut("let (b = new RegExp(\"($)*?|((?=\\\\s))?\", \"gm\"), a, x, x, ravcmg, window) { /*RXUB*/var r = r0; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.split(r)); print(r.lastIndex);  }");
/*fuzzSeed-116111302*/count=426; tryItOut("i1.toSource = (function(j) { if (j) { try { v0 = t1.length; } catch(e0) { } try { for (var v of m0) { try { this.m1.has(g1); } catch(e0) { } for (var v of i1) { a2 = arguments; } } } catch(e1) { } Array.prototype.unshift.call(a1, m1, 26, t1, o0); } else { try { Array.prototype.pop.apply(a1, [-23]); } catch(e0) { } try { v2 = (t1 instanceof g1); } catch(e1) { } try { a0 = arguments.callee.arguments; } catch(e2) { } t0 + ''; } });");
/*fuzzSeed-116111302*/count=427; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.pow((( + ( + (( + ( + Math.fround(Math.max(x, ( + y))))) && ( + Math.atanh(mathy0(mathy2(( + y), y), 0x100000000)))))) % ( + ( + (((x >>> 0) || Math.log2((Math.min((x >>> 0), (y >>> 0)) >>> 0))) >>> Math.tanh(Math.fround(x)))))), ((Math.hypot(42, 0.000000000000001) ? Math.log2((mathy0(x, (( + x) | 0)) >>> 0)) : Math.tan(x)) | 0))); }); testMathyFunction(mathy4, [0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 1/0, -Number.MIN_VALUE, 0/0, -0x080000000, -0x07fffffff, 1, -(2**53+2), Math.PI, -0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000000, 0.000000000000001, Number.MAX_VALUE, -0x100000000, 0x0ffffffff, 0x080000001, -1/0, -0x100000001, 0x100000001, -0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 42, 2**53, Number.MIN_VALUE, 2**53-2, -(2**53-2), -(2**53), 0, -Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=428; tryItOut("selectforgc(o2);");
/*fuzzSeed-116111302*/count=429; tryItOut("mathy1 = (function(x, y) { return Math.imul((Math.pow(((( + ( ~ x)) != y) >>> 0), (((((x | 0) - (y | 0)) | 0) ^ Math.fround(((Math.ceil((Math.ceil(Number.MAX_SAFE_INTEGER) | 0)) | 0) << Math.fround(x)))) >>> 0)) >>> 0), Math.atan2((mathy0(x, ( + (( + x) >>> ( + Math.min(( + Math.PI), ( + mathy0(-Number.MIN_VALUE, (y | 0)))))))) >>> 0), (( + mathy0(( + ((x ** Math.fround(x)) | 0)), ( + y))) % ( + ( + ((Math.hypot(x, -(2**53-2)) >>> 0) << 1.7976931348623157e308)))))); }); testMathyFunction(mathy1, [1, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, 1.7976931348623157e308, -(2**53-2), 0/0, Number.MAX_VALUE, -0, -0x07fffffff, 0x100000001, -0x100000001, 0, -0x080000000, Math.PI, -Number.MAX_VALUE, -1/0, 0x07fffffff, Number.MIN_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, -0x080000001, -Number.MIN_VALUE, -0x100000000, 0.000000000000001, 2**53+2, 0x100000000, -(2**53), 2**53, Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-116111302*/count=430; tryItOut("\"use strict\"; for(var c in ((Array.prototype.reduce)((this.__defineGetter__(\"x\", Float32Array))))){a1.length = 7; }");
/*fuzzSeed-116111302*/count=431; tryItOut("\"use strict\"; let x =  '' ;print(window);");
/*fuzzSeed-116111302*/count=432; tryItOut("/*tLoop*/for (let z of /*MARR*/[new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), Math.pow(let (window = x, a = x) (4277), x)]) { (eval(\" '' \",  '' )) ? z : z; }");
/*fuzzSeed-116111302*/count=433; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\w\\\\3\", \"gyi\"); var s = \"\\u3970\"; print(r.exec(s)); ");
/*fuzzSeed-116111302*/count=434; tryItOut("/*tLoop*/for (let e of /*MARR*/[new Number(1), allocationMarker(), allocationMarker(), new Number(1), objectEmulatingUndefined(), new Number(1), new Number(1.5), objectEmulatingUndefined(), allocationMarker(), new Number(1), allocationMarker(), objectEmulatingUndefined(), allocationMarker(), new Number(1.5), new Number(1), new Number(1.5)]) { t1 = t2.subarray(({valueOf: function() { print(e);return 14; }}), ({valueOf: function() { print(e);return 3; }}));\nprint(-13);\n }");
/*fuzzSeed-116111302*/count=435; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=436; tryItOut("\"use strict\"; (p={}, (p.z = -1)()).__defineSetter__(\"NaN\", ('fafafa'.replace(/a/g, Map).throw((4277))));");
/*fuzzSeed-116111302*/count=437; tryItOut("let(yuxzvj, (NaN) = ((4277) <= x), \u3056 = (new x(eval(\"(\\u3056 >> x)\", (timeout(1800))))), {} = (/*wrap2*/(function(){ var bptgsi = this; var nfkyjz = objectEmulatingUndefined; return nfkyjz;})()( '' , window)), \u3056, [] = (Number.isInteger)(x), NaN, eval, ugniqr) ((function(){for(let a of /*MARR*/[[(void 0)], [(void 0)], (-1/0), [(void 0)], [(void 0)], (-1/0), (-1/0), (-1/0)]) let(x, vhcryv, a, z, y = this, x, dsvakh) ((function(){b.message;})());})());x = a;");
/*fuzzSeed-116111302*/count=438; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( ~ (( + Math.atan(( + ( - mathy3(y, (mathy2(( + 2**53+2), y) & 1.7976931348623157e308)))))) | 0)) | 0); }); testMathyFunction(mathy4, ['/0/', (new Boolean(false)), (function(){return 0;}), (new String('')), '', ({toString:function(){return '0';}}), '0', false, ({valueOf:function(){return '0';}}), [0], true, '\\0', [], 1, objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), 0, NaN, (new Boolean(true)), -0, (new Number(-0)), undefined, null, 0.1, (new Number(0)), /0/]); ");
/*fuzzSeed-116111302*/count=439; tryItOut("eval(\"x\");function x(x, \u3056) { \"use strict\"; return 1936273315.5.__defineGetter__(\"\\u3056\", function (b) { yield window } ) } v1 + '';");
/*fuzzSeed-116111302*/count=440; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.log2(Math.hypot(( + ( ~ ( + (0x080000001 || (y <= ( ! -0x07fffffff)))))), Math.imul(( + ( ! x)), (Math.log10(y) >>> 0)))); }); testMathyFunction(mathy0, [-1/0, -(2**53+2), Math.PI, Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_VALUE, -0x100000001, -0x0ffffffff, 0.000000000000001, 2**53+2, -0x080000001, 0x100000000, 0x080000001, Number.MIN_VALUE, 0x080000000, 42, -Number.MAX_VALUE, -(2**53), 2**53-2, 0, 0x100000001, -0x100000000, 0x0ffffffff, 0x07fffffff, 2**53, 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, -0x080000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, -0, 1.7976931348623157e308]); ");
/*fuzzSeed-116111302*/count=441; tryItOut("\"use strict\"; p2 = a2[x];");
/*fuzzSeed-116111302*/count=442; tryItOut("\"use strict\"; print(g0);");
/*fuzzSeed-116111302*/count=443; tryItOut("x;;");
/*fuzzSeed-116111302*/count=444; tryItOut("(void schedulegc(o2.g0.g1));");
/*fuzzSeed-116111302*/count=445; tryItOut("for (var v of g0) { a0[10]; }");
/*fuzzSeed-116111302*/count=446; tryItOut("selectforgc(o0);");
/*fuzzSeed-116111302*/count=447; tryItOut("\"use strict\"; while(((makeFinalizeObserver('tenured'))) && 0){var czyhds = new SharedArrayBuffer(8); var czyhds_0 = new Uint8Array(czyhds); var czyhds_1 = new Uint8ClampedArray(czyhds); czyhds_1[0] = -24; var czyhds_2 = new Int8Array(czyhds); czyhds_2[0] = -6; var czyhds_3 = new Uint32Array(czyhds); print(czyhds_3[0]); a0.length = 3; }");
/*fuzzSeed-116111302*/count=448; tryItOut("\"use strict\"; testMathyFunction(mathy3, [[], -0, ({valueOf:function(){return '0';}}), '', '\\0', (new String('')), ({toString:function(){return '0';}}), (new Number(-0)), /0/, 0, NaN, false, 0.1, 1, undefined, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), '/0/', (function(){return 0;}), (new Number(0)), '0', null, true, (new Boolean(true)), [0], (new Boolean(false))]); ");
/*fuzzSeed-116111302*/count=449; tryItOut("\"use strict\"; /*infloop*/for(c = this; -20; this) {{} }");
/*fuzzSeed-116111302*/count=450; tryItOut("\"use strict\"; f2 + '';");
/*fuzzSeed-116111302*/count=451; tryItOut("mathy1 = (function(x, y) { return ((Math.max((( + mathy0(( + Math.fround(( + (y >>> 0)))), ( + Math.max(( ~ (Math.fround(y) << (y >>> 0))), Math.atan2(0x100000000, -0x080000001))))) >>> 0), (( + (( + (Math.min((mathy0((Math.fround((Math.fround(y) <= Math.fround(0x07fffffff))) | 0), Number.MIN_SAFE_INTEGER) >>> 0), (( + ( ! ( + y))) >>> 0)) >>> 0)) % ((Math.fround(mathy0(Math.sinh(( ! Number.MIN_SAFE_INTEGER)), x)) >>> Math.fround((x << x))) | 0))) | 0)) >>> 0) / Math.acosh(Math.pow((Math.pow((x | 0), (Math.fround(( - ( + y))) | 0)) | 0), y))); }); ");
/*fuzzSeed-116111302*/count=452; tryItOut("{}function window(z, x, x, (x), x)('fafafa'.replace(/a/g, RegExp.prototype.toString))a0.pop(this.h1, this.e2, o0, ( '' .__defineGetter__(\"window\", 7.getYear)));");
/*fuzzSeed-116111302*/count=453; tryItOut("jkdyjp;Array.prototype.sort.call(a2, (function() { try { a1 + i0; } catch(e0) { } try { Array.prototype.push.call(a2, h2, o2.o0.m2); } catch(e1) { } v0 = Object.prototype.isPrototypeOf.call(o0.s2, h0); return s1; }));");
/*fuzzSeed-116111302*/count=454; tryItOut("\"use strict\"; L:switch(/*UUV2*/(NaN.endsWith = NaN.isInteger)) { case (4277): break;  }");
/*fuzzSeed-116111302*/count=455; tryItOut("\"use strict\"; let (w) { /*ODP-3*/Object.defineProperty(h1, \"1\", { configurable: true, enumerable: false, writable: (x % 17 == 14), value: s0 }); }");
/*fuzzSeed-116111302*/count=456; tryItOut("/*RXUB*/var r = new RegExp(\"(?=.){1,}(?=(?=(\\\\t)*)|(?=\\\\u00D1)|\\\\u00Cf\\\\2{4,}|\\\\3*)\", \"gym\"); var s = function(id) { return id }; print(s.split(r)); ");
/*fuzzSeed-116111302*/count=457; tryItOut("\"use strict\"; w, x = new RegExp(\"(?=(?:\\\\1))(?!\\\\b?)+?(?![\\\\uE434]){4}\\\\W+?|\\\\b\\\\x8C[\\\\B-\\\\\\uc584]+|[^]|\\\\B?(?!(?!\\\\D))\", \"gyim\"), \u3056 = length, {e: []} = (4277), x, x = (4277), pupziq, eval;a2.pop(this.o0);");
/*fuzzSeed-116111302*/count=458; tryItOut("v2 = Object.prototype.isPrototypeOf.call(this.f2, g2.h2);");
/*fuzzSeed-116111302*/count=459; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + (( + ( - ((((Math.atan2((Math.fround(Math.log(y)) | 0), -(2**53)) | 0) >>> 0) & (Math.fround(Math.abs(y)) >>> 0)) | 0))) / ( + (Math.sin(y) | 0)))) <= ( ~ Math.sinh((( - 1.7976931348623157e308) | 0)))); }); testMathyFunction(mathy0, /*MARR*/[new Number(1.5), new Number(1.5), (void 0), 0x2D413CCC, 0x2D413CCC, (void 0), 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, new Number(1.5), (void 0), (void 0), 0x2D413CCC, new Number(1.5), 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, (void 0), new Number(1.5), 0x2D413CCC, (void 0), (void 0), (void 0), 0x2D413CCC, (void 0), new Number(1.5), 0x2D413CCC, (void 0), (void 0), (void 0), (void 0), (void 0), 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), 0x2D413CCC, (void 0)]); ");
/*fuzzSeed-116111302*/count=460; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.imul(Math.pow(( + ( + Math.atan2(Math.fround(x), x))), Math.clz32(( ! y))), (Math.sign(Math.fround(mathy1(( + mathy2(Math.fround(Math.sin(-0x0ffffffff)), Math.fround(y))), ( - Math.min(Math.ceil(x), (Math.min((x | 0), (y | 0)) | 0)))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-116111302*/count=461; tryItOut("v0 = r1.toString;let c = new (eval(\"false\"))(({x: x}), t2 = new Uint32Array(a2));");
/*fuzzSeed-116111302*/count=462; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=463; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(i2, g0.i0);");
/*fuzzSeed-116111302*/count=464; tryItOut("testMathyFunction(mathy3, [0, Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, Number.MAX_VALUE, 1/0, -0x080000000, Math.PI, 2**53+2, 42, 1.7976931348623157e308, 0x100000000, 2**53, 1, -Number.MAX_VALUE, 0.000000000000001, Number.MIN_VALUE, -0x100000000, 0/0, -(2**53+2), 0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 2**53-2, -0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0, 0x080000001, -0x0ffffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=465; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use asm\"; return ( ~ (( ~ (((Math.asinh((Math.log10((-0 >>> 0)) >>> 0)) | 0) ^ Math.fround((Math.fround(y) ? Math.fround(x) : Math.fround(x)))) ** Math.cos(x))) | 0)); }); testMathyFunction(mathy2, [(function(){return 0;}), null, (new Boolean(false)), (new String('')), '\\0', (new Number(-0)), NaN, 0.1, 0, 1, [0], (new Number(0)), false, ({toString:function(){return '0';}}), '/0/', objectEmulatingUndefined(), true, [], undefined, (new Boolean(true)), /0/, ({valueOf:function(){return 0;}}), '0', '', ({valueOf:function(){return '0';}}), -0]); ");
/*fuzzSeed-116111302*/count=466; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=467; tryItOut("\"use strict\"; sxqqlp, x, polnbn, x, knytuv, fwtpwd, e, ptddmg, z, zfyctr;Array.prototype.unshift.call(a1, o1);");
/*fuzzSeed-116111302*/count=468; tryItOut("s2 += 'x';");
/*fuzzSeed-116111302*/count=469; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ((( + Math.imul(Math.atan2((Math.abs(x) >>> 0), 42), ( + ( ~ (Math.min((0/0 % y), (((-0x100000000 | 0) >>> (y | 0)) | 0)) ? Math.fround(Math.round(x)) : Math.fround(( ~ Math.fround((Math.fround((Math.hypot(x, y) | 0)) <= Math.fround(y)))))))))) < ((( ! Math.fround(Math.log10(Math.fround(Math.sign(y))))) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, [1, false, (new String('')), '', true, ({valueOf:function(){return 0;}}), null, objectEmulatingUndefined(), '\\0', ({valueOf:function(){return '0';}}), (new Number(0)), NaN, '0', [], (function(){return 0;}), ({toString:function(){return '0';}}), (new Boolean(true)), (new Number(-0)), -0, [0], '/0/', 0, 0.1, /0/, (new Boolean(false)), undefined]); ");
/*fuzzSeed-116111302*/count=470; tryItOut("var o0.o1.v1 = t0.length;");
/*fuzzSeed-116111302*/count=471; tryItOut("o1.i2 + s1;");
/*fuzzSeed-116111302*/count=472; tryItOut("a1 = o0.r0.exec(s0);");
/*fuzzSeed-116111302*/count=473; tryItOut("a((allocationMarker())) = window;v0 = evaluate(\"m0 = new Map(g0);\", ({ global: g0.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: x, sourceIsLazy: false, catchTermination: (x % 37 != 5) }));");
/*fuzzSeed-116111302*/count=474; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! (Math.max(( + Math.tan(( + (( + (( + (x | 0)) | 0)) & ((Math.min(Math.fround(Math.sinh(x)), Math.fround(y)) ? (x >>> 0) : Math.fround((y === Math.imul(y, (x >>> 0))))) >>> 0))))), (((Math.max(( + ( + (-0x100000000 >>> 0))), (x | 0)) >>> 0) * (Math.min(mathy0(Math.abs(y), (x | 0)), (x * x)) | 0)) | 0)) | 0)); }); testMathyFunction(mathy3, [-0x07fffffff, 0, Number.MAX_SAFE_INTEGER, 2**53, -0, -(2**53-2), 2**53+2, -0x100000000, 0x0ffffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, -(2**53+2), 0x100000000, 0x07fffffff, 1, 42, 1.7976931348623157e308, 0x080000001, 0x080000000, Number.MAX_VALUE, 0x100000001, -0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, 2**53-2, -0x100000001, -(2**53), -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Math.PI, 1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=475; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=476; tryItOut("\"use strict\"; /*infloop*/for(let b; x; this) {M:for(let z in window) m0 + h2; }");
/*fuzzSeed-116111302*/count=477; tryItOut("\"use strict\"; /*MXX1*/o0 = g1.Math.round;");
/*fuzzSeed-116111302*/count=478; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.abs(Math.min(Math.min((( ! (x - ( - ( + y)))) | 0), ( + ( ~ Math.fround(Math.PI)))), (Math.hypot(Math.atan2(Math.pow(y, x), ( + (y <= ( - (y | 0))))), y) >>> 0))); }); testMathyFunction(mathy0, [0x07fffffff, 0/0, -(2**53-2), 2**53-2, -0x080000000, 0x0ffffffff, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, Math.PI, 1, 0.000000000000001, 0x080000001, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -0x080000001, -1/0, 0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), 0x100000001, 2**53, -0, -0x100000001, 42, 1/0]); ");
/*fuzzSeed-116111302*/count=479; tryItOut("for(let [c, x] = x = /*RXUE*/new RegExp(\"\\\\B|(?!\\\\u2e31)|\\\\1*?\", \"ym\").exec(\"\\n1 \\n\") in (x.valueOf(\"number\"))) {for(let c = (4277) in this) {Number.prototype.toPrecision }v2 = new Number(this.g1.a1); }");
/*fuzzSeed-116111302*/count=480; tryItOut("\"use strict\"; return;");
/*fuzzSeed-116111302*/count=481; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 4503599627370497.0;\n    {\n      (Uint32ArrayView[2]) = (-(-0x2a4c8ad));\n    }\n    return +(((d2) + (72057594037927940.0)));\n    (Uint8ArrayView[1]) = ((0xffffffff) % (0x2c3c4ea4));\n    i0 = (!(0xe1f5afc7));\n    (Float32ArrayView[(((((0x16db37d8) > (0x98a62993))) | ((0x6bd9c56e)+((0x4868b2a7) == (-0x8000000)))) % (abs(((0xfffff*((0xea21914)))|0))|0)) >> 2]) = ((d1));\n    {\n      i0 = (Math.pow(0xB504F332, Math.max(10, -29)));\n    }\n    {\n      {\n        (Int32ArrayView[((0xffffffff)) >> 2]) = (((x) ? (0xc5dbcc65) : (arguments[\"caller\"] >>>= ({}) = x = Proxy.createFunction(({/*TOODEEP*/})(this),  /x/g , new RegExp(\"(?!\\\\1|.+)+|\\\\s*|.\", \"gm\"))))+((0x0)));\n      }\n    }\n    (Uint32ArrayView[((((0xf8a23e6a)+((0x947067) ? (-0x8000000) : (-0x8000000)))>>>((i0)*0x68ab0)) % (0xfbe25c17)) >> 2]) = (((+(((~~(((-1.25)) % ((65536.0)))) % (~~(d1))) ^ ((0xfad21406)))) > (((d2)) % ((((4.722366482869645e+21)) % ((d1))))))-(i0));\n    i0 = (((((Uint16ArrayView[((i0)) >> 1]))>>>((let (d =  \"\" ) 12)*0xba05f))) ? (0x33753f8) : (i0));\n    i0 = (/*FFI*/ff((((0x9c2e4*(((((0x0) >= (0xa93a6a55))) | ((0x4838509) % (0x64a35daa))) == (abs((imul((i0), ((0xb30cb07f) ? (0xfed1d9b8) : (0xfeb4ad3d)))|0))|0))) << (((0xcab3e70e) ? (0x1233ccad) : ((-0x8000000)))+(((0x81709732) >= (((0xff10d91b))>>>((0xceb70e52)))) ? (0xa996ddf3) : (0x6c165b1a))))), ((~((((((0x642df297))>>>((0x580d588b)))) ? (0x6c600b86) : ((0xfc4bd40b) ? (0xf11ba79a) : (0xffffffff)))-(0xf968e44d)-(i0)))), ((+(0.0/0.0))), ((d1)), ((d1)), ((+(1.0/0.0))), ((-1.5111572745182865e+23)), ((((17179869184.0)) - ((-32767.0)))), ((+(0xa16e9919))), ((4611686018427388000.0)), ((-1.0009765625)), ((36893488147419103000.0)), ((8589934593.0)), ((36028797018963970.0)), ((34359738367.0)), ((274877906945.0)), ((0.5)), ((-5.0)))|0);\n    return +((1.2089258196146292e+24));\n    /*FFI*/ff((((Int8ArrayView[(((((0xfbd963c1)+(0x9bb2bfc))|0) < (((0xa0e0a970)) ^ ((0xff779703))))-(i0)) >> 0]))), ((~(((0x40ddd9d4) ? ((2.3611832414348226e+21) < (6.044629098073146e+23)) : (0x7c788eb7))))), ((((+(-1.0/0.0))) / ((-562949953421313.0)))), (((((((0x76263823))>>>((0xd84b63dd))) % (0xffffffff))|0))), ((~(x))), (((0x541c8536) ? (3.8685626227668134e+25) : (4503599627370497.0))), ((((0xb0e9cf78))|0)), ((-1.9342813113834067e+25)), ((-512.0)), ((-1024.0)), ((-1099511627776.0)));\n    return +(((+(-1.0/0.0)) + (d1)));\n  }\n  return f; })(this, {ff: (/*UUV1*/(z.apply = \"\\u58E4\"))}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [1, -Number.MIN_VALUE, 0, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, 2**53, 42, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, -0x080000001, -0, 2**53-2, -0x07fffffff, 0x080000000, 0x07fffffff, 0.000000000000001, 2**53+2, -Number.MAX_VALUE, 1/0, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -(2**53-2), -(2**53), -(2**53+2), 1.7976931348623157e308, 0/0, -0x100000000, 0x100000001, -0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=482; tryItOut("do var wcfkvj = new SharedArrayBuffer(8); var wcfkvj_0 = new Int8Array(wcfkvj); var wcfkvj_1 = new Uint32Array(wcfkvj); print(wcfkvj_1[0]); wcfkvj_1[0] = -28; var wcfkvj_2 = new Int16Array(wcfkvj); t0.set(o1.a0, 14);print(uneval(o0));x = t0;h1.getOwnPropertyDescriptor = f2; while((Object.defineProperty( , ({/*toXFun*/toString: function() { return  /x/ ; },  get \"-7\"(x = d)\"use asm\";   var tan = stdlib.Math.tan;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0xd22e669d);\n    return (((0x2417c7cc)*-0xd5e75))|0;\n    {\n      {\n        d0 = (1.0);\n      }\n    }\n    (Int32ArrayView[0]) = (((((i1)+(-0x8000000)) >> ((0xe039d3fa) / (((i1))>>>((0x39a1d15f) / (0x2365fd11))))) <= (~~(-((-144115188075855870.0)))))+(0x19e550a1));\n    d0 = (2251799813685248.0);\n    i1 = ((((0xae756952))>>>((i1))));\n    {\n      {\n        i1 = (0xfa9a3bd8);\n      }\n    }\n    d0 = (-72057594037927940.0);\n    return ((-(-0x4d1ed8f)))|0;\n    i1 = (((+tan(((d0)))) < (((-31.0)) / ((d0)))) ? (i1) : (i1));\n    return (((0xfc5080a9)-((~(((((i1)+((0x87997a5a) ? (0x4be026eb) : (-0x8000000)))>>>((Uint32ArrayView[(((0x4e5aedac) ? (-0x8000000) : (0xfa8f7483))) >> 2]))))-(i1))))))|0;\n  }\n  return f; }), ({}))) && 0);");
/*fuzzSeed-116111302*/count=483; tryItOut("testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, 0x080000000, 2**53-2, 0x100000001, 1.7976931348623157e308, -(2**53), -1/0, Math.PI, -0, 1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 2**53+2, -0x080000001, -(2**53-2), -0x100000000, 42, 0x080000001, -Number.MAX_VALUE, -0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, 1, 0x100000000, 0x0ffffffff, -0x080000000, 0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 2**53, -(2**53+2)]); ");
/*fuzzSeed-116111302*/count=484; tryItOut("m1.delete(this.__defineGetter__(\"x\", Array.prototype.push).yoyo((x\u0009 = window)) && (void options('strict_mode')));");
/*fuzzSeed-116111302*/count=485; tryItOut("mathy2 = (function(x, y) { return (( ~ (( - (( + ((((((( + Math.hypot(( + x), ( + y))) | 0) & (y | 0)) | 0) | 0) ^ mathy1(x, y)) << ( + (( - x) >>> 0)))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [1, Number.MAX_SAFE_INTEGER, -0, 1/0, 0x100000001, 2**53-2, -(2**53-2), 0, 0x0ffffffff, 0x100000000, 0.000000000000001, -Number.MIN_VALUE, -1/0, -0x100000001, -0x080000001, Number.MIN_VALUE, 0x07fffffff, -0x080000000, 0x080000001, -Number.MAX_VALUE, -(2**53+2), 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53), 42, 0/0, -0x07fffffff, Math.PI, 2**53+2]); ");
/*fuzzSeed-116111302*/count=486; tryItOut("mathy2 = (function(x, y) { return mathy0(( ! Math.fround(Math.fround(Math.asin(((((Math.fround(Math.max(y, y)) | 0) == ((((1 || x) | 0) % x) >>> 0)) >>> 0) >>> 0))))), ((((Math.pow(y, (y == y)) - ((Math.imul(x, ( + ( - Math.min(x, 1)))) ? Math.tan(( + y)) : (Math.fround(( + (y >>> 0))) >>> 0)) | 0)) | 0) * (( + Math.cbrt(Math.fround(-0x100000001))) < x)) | 0)); }); testMathyFunction(mathy2, [-0, 1.7976931348623157e308, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x0ffffffff, -Number.MAX_VALUE, 0, 2**53-2, Number.MIN_VALUE, -0x100000001, 1/0, -0x080000000, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 1, -0x0ffffffff, 0/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, Number.MAX_VALUE, 42, -1/0, 2**53, 0x100000000, -Number.MIN_VALUE, -(2**53+2), 0x100000001, Math.PI, 2**53+2, -Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-116111302*/count=487; tryItOut("");
/*fuzzSeed-116111302*/count=488; tryItOut("mathy4 = (function(x, y) { return ((Math.fround(Math.ceil(Math.fround(( ! Number.MAX_SAFE_INTEGER)))) == (mathy1(((Math.fround(( - 0x080000000)) || (0x080000001 % (( + (( + y) - ( + y))) % y))) | 0), ( + ( ~ ( + Math.fround(( ! x)))))) | 0)) | 0); }); ");
/*fuzzSeed-116111302*/count=489; tryItOut("");
/*fuzzSeed-116111302*/count=490; tryItOut("mathy3 = (function(x, y) { return Math.trunc(mathy0(((Math.atan2(((( + y) + x) >>> 0), (y >>> 0)) >>> 0) + ( ! -0)), ( + (Math.sqrt(Math.fround(mathy1(mathy0(( - -(2**53-2)), x), Math.fround(Math.log2(Math.fround(y)))))) | 0)))); }); testMathyFunction(mathy3, [0x07fffffff, -0x080000001, 0x0ffffffff, -0x0ffffffff, Math.PI, 0x100000000, -1/0, 1, -(2**53+2), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53-2, 0x080000001, -Number.MAX_VALUE, 42, 0, 0x080000000, -0x100000000, 0/0, -(2**53), Number.MIN_VALUE, 2**53, 1/0, -0x100000001, 2**53+2, Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=491; tryItOut("\"use strict\"; a0 = Array.prototype.slice.call(a2, 2, NaN);");
/*fuzzSeed-116111302*/count=492; tryItOut("\"use strict\"; v1 = o0.g0.eval(\"/* no regression tests found */\");");
/*fuzzSeed-116111302*/count=493; tryItOut("/*iii*/v0 = Array.prototype.reduce, reduceRight.apply(a2, [(function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 137438953472.0;\n    d1 = (-1.125);\n    d2 = (-4095.0);\n    i0 = (i0);\n    d1 = (d2);\n    {\n      (Float64ArrayView[((0xfff4674b)-(0xf8adb129)) >> 3]) = ((-562949953421312.0));\n    }\n    (Float64ArrayView[4096]) = ((+abs(((1.0)))));\n    d2 = (1.0);\n    return +((+(1.0/0.0)));\n  }\n  return f; }), (4277).watch(\"eval\", /*wrap2*/(function(){ var rnfrhz = let (w) undefined\n; var nlpxor = ; return nlpxor;})())]);/*hhh*/function zkmlmg(z = (4277) ? let (x = window) this :  /x/  ** \"\\u8AD9\", d, ...x){throw StopIteration;print( '' .__defineSetter__(\"\\u3056\", objectEmulatingUndefined));}");
/*fuzzSeed-116111302*/count=494; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot((((Math.imul((Math.tan(Math.log(x)) | 0), (Math.tanh((Math.hypot((x >>> 0), (y >>> 0)) >>> 0)) | 0)) != Math.cosh((Math.imul((( + ( + y)) >> y), ( ~ Math.fround(1/0))) | 0))) ? ( - (( + Math.abs(( + Math.fround((x ? Math.min(x, ( ~ (y >>> 0))) : (( + ((mathy1((x | 0), (-Number.MAX_SAFE_INTEGER | 0)) | 0) >>> 0)) >>> 0)))))) | 0)) : (Math.cbrt(y) | 0)) | 0), ( ~ (Math.tan(( + Math.sqrt(Math.fround((Math.log(Math.fround(y)) >>> 0))))) | 0)))); }); testMathyFunction(mathy2, [0, 2**53+2, -(2**53), 2**53-2, 0/0, 0x07fffffff, -0x100000000, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 1.7976931348623157e308, 1/0, -Number.MIN_VALUE, 1, 0.000000000000001, 2**53, -0x080000001, -Number.MAX_VALUE, 0x100000000, -1/0, -0x080000000, 42, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, -(2**53+2), 0x100000001, 0x080000000, Math.PI, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x07fffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=495; tryItOut("o1.o2.t0[({valueOf: function() { let }, fnjgku, x = x, z = x, e = !x, d = x, appvkg, ocuyhh, c =  /* Comment */new RegExp(\"(?!\\\\u0067)*?\", \"gm\"), y;f1 + t2;return 6; }})] = f0;");
/*fuzzSeed-116111302*/count=496; tryItOut("\"use strict\"; /*MXX2*/g2.g2.RegExp.prototype.test = g2;");
/*fuzzSeed-116111302*/count=497; tryItOut("e1 = t1[1];");
/*fuzzSeed-116111302*/count=498; tryItOut("h2.toSource = (function(j) { if (j) { g2.valueOf = (function() { for (var j=0;j<0;++j) { f0(j%3==0); } }); } else { try { o1.a0[18] = t2; } catch(e0) { } try { this.b2.toSource = (function() { try { a1.push(t2); } catch(e0) { } try { /*MXX1*/o1 = g0.WeakMap.prototype.get; } catch(e1) { } try { v0 + ''; } catch(e2) { } o1.e0.has(v0); return o0; }); } catch(e1) { } try { v0 = a0.reduce, reduceRight((function mcc_() { var mxkyhv = 0; return function() { ++mxkyhv; if (false) { dumpln('hit!'); try { Array.prototype.push.apply(a2, [e0, o0]); } catch(e0) { } try { h0.getOwnPropertyNames = g2.f2; } catch(e1) { } try { g2.s1 = s2.charAt(18); } catch(e2) { } Array.prototype.reverse.call(a2, this.h2, h0, o2.i1); } else { dumpln('miss!'); try { h0.valueOf = (function() { for (var j=0;j<113;++j) { f0(j%3==0); } }); } catch(e0) { } v2 = evaluate(\"for (var v of v1) { g1.__proto__ = o0; }\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 4 != 3), noScriptRval: new RegExp(\"(?!(?!.))[^]|\\\\B|[^\\\\S\\\\n-\\u72d4]\\\\b|^?|(?=\\\\2)?\", \"gm\"), sourceIsLazy: false, catchTermination: (x % 4 == 3) })); } };})(), m2); } catch(e2) { } m0.get(m0); } });\nfunction f1(this.g0)  '' \n");
/*fuzzSeed-116111302*/count=499; tryItOut("/*oLoop*/for (var iikfbv = 0; iikfbv < 11; ++iikfbv) { /*RXUB*/var r = /(?![^]{4,}|\\D\\1(?:\\n|\\b{0,2}[^])\\v{7})|$([H-\\u005D\ue868\\\ua167]{0,})*?+?\\s|(?=\\B)|(?:\\S{1,}){0,}(?:\\1){0,}|([^])*/gym; var s = \"\"; print(s.search(r)); \ng1.h0 + '';\n } ");
/*fuzzSeed-116111302*/count=500; tryItOut("Array.prototype.push.call(a0, b1);");
/*fuzzSeed-116111302*/count=501; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(Math.fround(Math.max(Math.fround(((x | 0) ? Math.hypot(((Math.imul((Math.fround(((y >>> 0) != Math.fround((Math.fround(y) && Math.PI)))) >>> 0), (x >>> 0)) >>> 0) | 0), (Math.ceil(x) & (((y >>> 0) % (y >>> 0)) >>> 0))) : (-0x0ffffffff | 0))), Math.fround((Math.atan(Math.fround((Math.fround((x , x)) ? (Math.fround(( - (-Number.MAX_SAFE_INTEGER | 0))) >>> 0) : (Math.atan2((((x && Math.expm1(x)) | 0) >>> 0), (x >>> 0)) >>> 0)))) | 0)))), ( ! Math.fround(mathy0(y, ( + (Math.imul((( ~ Math.sqrt(x)) | 0), (-0x080000000 | 0)) | 0)))))); }); testMathyFunction(mathy1, [1, 0, 2**53+2, -0x100000001, -0x100000000, -Number.MAX_VALUE, -1/0, 0x07fffffff, Number.MIN_VALUE, Math.PI, -0x080000001, Number.MAX_VALUE, -0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), 1.7976931348623157e308, 0x100000001, 0/0, 0.000000000000001, -(2**53), 1/0, -0, -Number.MAX_SAFE_INTEGER, 0x100000000, 42, 2**53-2, 2**53, -Number.MIN_VALUE, -0x080000000]); ");
/*fuzzSeed-116111302*/count=502; tryItOut("\"use strict\"; for (var p in i1) { try { this.v2 = (v1 instanceof this.s1); } catch(e0) { } try { o0 + o0.g0.b0; } catch(e1) { } v1 = true; }");
/*fuzzSeed-116111302*/count=503; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ceil = stdlib.Math.ceil;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return ((((0xf8062277) ? (0xffffffff) : (i2))))|0;\n    {\n      (Float32ArrayView[4096]) = ((-9007199254740992.0));\n    }\n    d0 = (NaN);\n    d0 = ((+ceil((((Float32ArrayView[0]))))) + (+pow(((140737488355329.0)), ((-((-147573952589676410000.0)))))));\n    {\n      i2 = (i2);\n    }\n    return (((((((i2))>>>(0x1242f*(i2)))) ? ((NaN) < ((((-144115188075855870.0)) * ((-129.0))) + (-140737488355329.0))) : (0xf88549c2))-(!(0x428f8616))))|0;\n  }\n  return f; })(this, {ff: (Uint16Array).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000000, Math.PI, 2**53-2, 0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x0ffffffff, 0x080000001, 0/0, 0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, -0x07fffffff, -(2**53-2), -0x080000000, Number.MIN_VALUE, 1, 0.000000000000001, 0, -(2**53), -0, -0x0ffffffff, 1/0, -Number.MIN_SAFE_INTEGER, 42, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 0x100000001, 2**53, -1/0]); ");
/*fuzzSeed-116111302*/count=504; tryItOut("let (c) { print(x);function c() { {} } v0 = Object.prototype.isPrototypeOf.call(this.b2, p1); }");
/*fuzzSeed-116111302*/count=505; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!$u|[^]{2,}|\\1(?=\\3|[\\w\\B](?:(?!.{1,2})))+)/gyi; var s = \"\\n\\n\"; print(s.search(r)); ");
/*fuzzSeed-116111302*/count=506; tryItOut("/*hhh*/function vsgedm((x = eval(\"m1.set(i2, a1);\")), w, c, b = eval(\"print(new RegExp(\\\"\\\\\\\\d\\\", \\\"ym\\\"));\", null).__defineGetter__(\"e\", function(q) { return q; }) === x, {w: [{z: {}, this.NaN: {}}, , ], NaN: x, x: {x, x}, w: x}, x, c, x, e, {}, x, NaN, NaN =  '' , \u3056 = /(?=\\2){4,}/gym, e = false, NaN = \"\u03a0\", a = /(?![^\u00d6-\u6329])+?\\3.\\B|\\b|\\b?*?/gm, \u3056 = 11, x, w = x, e = this, x, x, z, x, x, \"\\u8CF7\", x, \u3056 = x, b, x =  \"\" , x, x, x, x, x, z, b, x, x, z, \u3056, window, eval, NaN, \u3056, b, e =  '' , window, d, NaN, eval = this.a, x, x = w, z, x, z, z, x, window, NaN, c, ...c){/*hhh*/function ozlulu(...b){this.m0.set(t0, a0);}ozlulu( /x/ .unwatch(\"__parent__\"), (4277));}/*iii*/switch(\n(allocationMarker())) { case 0: Array.prototype.pop.apply(a0, []);break; case 6: break; break; break; /*RXUB*/var r = /((.)|(?:\\s(?!(?=\\d)){3})){3,}/yi; var s = \"\\n000000000000000000000aaaaa\\n\"; print(s.split(r)); case 2: v0 = new Number(Infinity);Array.prototype.pop.apply(a2, []);h0.toString = (function(j) { f1(j); });break;  }");
/*fuzzSeed-116111302*/count=507; tryItOut("a1[({valueOf: function() { { void 0; abortgc(); } a0 = arguments;return 8; }})];");
/*fuzzSeed-116111302*/count=508; tryItOut("f2.toString = (function(j) { if (j) { try { g1.i1 = m0.values; } catch(e0) { } print(s2); } else { try { v2 = (x % 23 != 1); } catch(e0) { } for (var p in s1) { try { for (var p in o0) { /*RXUB*/var r = r1; var s = \"\"; print(s.replace(r, (arguments.callee).bind((4277))));  } } catch(e0) { } /*RXUB*/var r = r0; var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(uneval(r.exec(s)));  } } });");
/*fuzzSeed-116111302*/count=509; tryItOut("o2.m1.get(undefined)\na0.sort((function(j) { if (j) { try { var v0 = a2.length; } catch(e0) { } try { v0 = g2.runOffThreadScript(); } catch(e1) { } try { t0 = new Uint8ClampedArray(t0); } catch(e2) { } e2 + g2; } else { try { b1 = m2.get(b2); } catch(e0) { } (\"\\u6005\"); } }), a2, i2, s2, s1, f1);t2[({valueOf: function() { e1.delete(b0);return 10; }})] = (4277);");
/*fuzzSeed-116111302*/count=510; tryItOut("Array.prototype.splice.apply(a2, []);");
/*fuzzSeed-116111302*/count=511; tryItOut("for(let c in (false)(\"\\u12EF\", \"\\uF488\")) {v1 + ''; }");
/*fuzzSeed-116111302*/count=512; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.min(( ! ( ! ( + ((0x0ffffffff & (x >>> 0)) / (Math.fround(Math.atan((-(2**53) | 0))) & Math.fround(Math.log2((y - 0)))))))), Math.hypot(Math.atan2((Math.cos(Math.fround(mathy2(y, (Math.pow(Math.log1p(x), (x >>> 0)) >>> 0)))) | 0), x), Math.fround(Math.asinh(( + -1/0))))); }); ");
/*fuzzSeed-116111302*/count=513; tryItOut("Array.prototype.push.apply(a1, [s2]);var y = Math.atan2(-14, 29);");
/*fuzzSeed-116111302*/count=514; tryItOut("print(s1);");
/*fuzzSeed-116111302*/count=515; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.1805916207174113e+21;\n    d0 = ((0xfde6fb3c) ? (+exp(((((0x1af0b12e)) ? (d1) : (d1))))) : (+abs(((((d1)) - ((d0)))))));\n    d1 = (d2);\n    return (((0x57b6a909)-((d2) != ((Math.pow(x, x))))-(-0x8000000)))|0;\n    return (((0xffffffff)+(!(0xd9cef1e2))))|0;\n  }\n  return f; })(this, {ff: function(q) { \"use strict\"; return q; }}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000000, -0x080000001, 2**53, 1/0, Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53-2, 2**53+2, -Number.MIN_VALUE, Number.MIN_VALUE, 1, 0x080000000, 0x080000001, -Number.MAX_VALUE, 0.000000000000001, -0x080000000, -1/0, -(2**53), Math.PI, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000001, 0x100000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0, 0/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -(2**53+2), 42]); ");
/*fuzzSeed-116111302*/count=516; tryItOut("s0 += 'x';");
/*fuzzSeed-116111302*/count=517; tryItOut("switch(eval(\"m0.toSource = f0;\", Math.cos(\"\\u4415\"))) { default: break; case  /x/ : case 8: break; h0.has = f1;break; case 1: m0.set(o2.i0, (({c: Math.hypot(x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function() { throw 3; }, get: \"\\uF0C3\", set: function() { return true; }, iterate: undefined, enumerate: RegExp.prototype.test, keys: undefined, }; })(new RegExp(\"\\\\1|.\", \"m\")), offThreadCompileScript, neuter), -13)}) >>>= (Math.sinh(22))));break; case 5: { void 0; gcslice(442088907); } this.t1[13];break; /*infloop*/M: for  each(let (/([^].\\n|^?){8589934593,8589934593}[^]/gim)(x) in (this * (4277))) t0.set(t2, 9);break; case 1: case 0: e0.add(a1);case (y) = /(?!\\2)/i: v2 = a0.length;break; selectforgc(o0);break; case 0: continue L; }");
/*fuzzSeed-116111302*/count=518; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0/0, -0x0ffffffff, 0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 42, -0x100000000, Number.MIN_VALUE, 0x100000000, 1, 0x0ffffffff, -0x080000001, -0x100000001, -Number.MIN_VALUE, 2**53, 0, 0x100000001, -(2**53+2), -(2**53), Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, 2**53-2, -(2**53-2), 0x080000001, 2**53+2, -1/0, Number.MAX_VALUE, -0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0, 1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=519; tryItOut("testMathyFunction(mathy2, [-0x0ffffffff, 0.000000000000001, 0, 1, -(2**53-2), 2**53, -0x07fffffff, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, 2**53+2, 0/0, -0x100000000, 0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 2**53-2, 0x0ffffffff, 1/0, -0, -Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -0x080000001, 1.7976931348623157e308, Number.MIN_VALUE, -1/0, -(2**53), 42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-116111302*/count=520; tryItOut("/*infloop*/L:for({x: {x: [{}, [{a: y}, a], ], x, d}, of: z} =  ''  >> x; x; x) {switch((4277)) { default: a2 = [];break;  }print(x); }");
/*fuzzSeed-116111302*/count=521; tryItOut("\"use strict\"; (void schedulegc(g2));");
/*fuzzSeed-116111302*/count=522; tryItOut("/*RXUB*/var r = new RegExp(\"$.+|\\u2355?\", \"gyi\"); var s = \"\\u0090\"; print(s.search(r)); ");
/*fuzzSeed-116111302*/count=523; tryItOut("\"use strict\"; print(uneval(v2));");
/*fuzzSeed-116111302*/count=524; tryItOut("/*vLoop*/for (let vfcrxc = 0; vfcrxc < 136; this, ++vfcrxc) { let y = vfcrxc; {} } var a = ([] = x in z);");
/*fuzzSeed-116111302*/count=525; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.acosh(mathy4((Math.fround((mathy4(Math.acosh(x), ( + mathy0(( + y), ( + x)))) / x)) | 0), 2**53+2)) | 0) ? ((mathy1(x, Math.log10(y)) ? ( ! ( + (x >>> 0))) : ( + ( + Math.atan2(Math.pow(mathy0(( - Math.fround(x)), Math.fround(Number.MAX_SAFE_INTEGER)), 2**53-2), Math.fround(Math.fround(Math.fround(y))))))) | 0) : (((((Math.clz32(Math.atan2(y, ( + ( ! Math.fround(y))))) >>> 0) / ( + ( + Math.atanh(( + Math.expm1(( + x))))))) >>> 0) <= ((((mathy0(y, -Number.MAX_VALUE) >>> 0) >= (Math.exp((Math.cbrt((y | 0)) | 0)) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-(2**53-2), -Number.MIN_VALUE, 0.000000000000001, -0x0ffffffff, 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -(2**53+2), -0x080000001, Number.MIN_VALUE, Number.MAX_VALUE, 0/0, 2**53-2, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, -(2**53), -0x07fffffff, 0x100000001, -0x080000000, 2**53, 0x0ffffffff, 1, -0, 0x07fffffff, 1.7976931348623157e308, 0, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, Math.PI, 0x080000000, 42, 0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=526; tryItOut("\"use strict\"; ");
/*fuzzSeed-116111302*/count=527; tryItOut("mathy1 = (function(x, y) { return ( + Math.atan(( + Math.atan2(( + Math.hypot(Math.fround(Math.hypot(Math.fround(((x ? (Number.MAX_VALUE >>> 0) : (Math.log1p((y | 0)) >>> 0)) * y)), ( + x))), ( + y))), (y ? Math.fround(Math.sqrt(Math.sqrt(0x0ffffffff))) : ( + Math.fround(0x100000001))))))); }); ");
/*fuzzSeed-116111302*/count=528; tryItOut("mathy3 = (function(x, y) { return ( + ( ! ( + (Math.max(x, y) == ( - ( + (Math.sqrt(1) / (( + Math.clz32(( ! -1/0))) >>> 0)))))))); }); testMathyFunction(mathy3, [2**53-2, 0/0, 0, -0x080000001, 42, -(2**53), 0x0ffffffff, 1.7976931348623157e308, 1, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, Math.PI, 2**53+2, -1/0, Number.MIN_VALUE, -(2**53-2), -0x080000000, 0x080000000, -0x07fffffff, -Number.MAX_VALUE, -0, 0x100000000, 0x080000001, 1/0, -(2**53+2), Number.MAX_VALUE, -0x100000000, -0x0ffffffff, 2**53, -0x100000001]); ");
/*fuzzSeed-116111302*/count=529; tryItOut("\"use strict\"; b0.__iterator__ = f1;");
/*fuzzSeed-116111302*/count=530; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0x0ffffffff, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, 0/0, -(2**53), 1.7976931348623157e308, 1, -0x100000001, -Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), 0x100000000, 0x080000000, 42, Math.PI, -0, 0x07fffffff, -(2**53+2), -0x080000000, 2**53+2, -0x100000000, 0, 0x080000001, -1/0, 0.000000000000001, 2**53]); ");
/*fuzzSeed-116111302*/count=531; tryItOut("testMathyFunction(mathy2, [2**53+2, -0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, 0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 42, 2**53, 0, 1.7976931348623157e308, -1/0, 0x100000001, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, 1, Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, 0x100000000, -0x0ffffffff, -(2**53-2), -0x080000001, -0, -(2**53+2), 0x080000001, -(2**53), 0.000000000000001]); ");
/*fuzzSeed-116111302*/count=532; tryItOut("{ void 0; verifyprebarriers(); } ( \"\" );o1.toSource = (function() { try { /*ODP-1*/Object.defineProperty(e1, \"getUTCMinutes\", ({get: function(y) { print((4277)); }, configurable: (x % 4 != 1), enumerable: x})); } catch(e0) { } try { m1.get(v1); } catch(e1) { } try { m0.has(g0.g2.p1); } catch(e2) { } g0.a1 = r0.exec(g1.s1); return this.o2; });");
/*fuzzSeed-116111302*/count=533; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.hypot(Math.tan(mathy0(mathy1(x, ((y | 0) + Math.round(x))), y)), ( + ( + (mathy0((( - (x | 0)) | 0), (mathy0(x, (y << (0/0 >>> 0))) | 0)) | 0)))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, -(2**53+2), 0x080000001, -0x080000000, 0x0ffffffff, -0x0ffffffff, 2**53+2, 0, Number.MIN_VALUE, 0x07fffffff, -0, -Number.MIN_VALUE, 0x100000001, 1.7976931348623157e308, Math.PI, -0x100000000, 0x100000000, 2**53, -0x07fffffff, 1, -0x080000001, -(2**53-2), 0/0, -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, 42, Number.MAX_VALUE, -(2**53)]); ");
/*fuzzSeed-116111302*/count=534; tryItOut("\"use strict\"; print(true);");
/*fuzzSeed-116111302*/count=535; tryItOut("print((void options('strict')));");
/*fuzzSeed-116111302*/count=536; tryItOut("\"use strict\"; o1 = new Object;");
/*fuzzSeed-116111302*/count=537; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + (( + Math.asin(( + Math.atan2(( + ((x | 0) == (x | 0))), ( + -0x100000001))))) > ( + Math.fround(Math.ceil((((( - y) | 0) != y) << y)))))) ? (Math.min((Math.round(((((y >>> 0) ? y : x) > Math.round(Number.MIN_VALUE)) | 0)) | 0), (( ~ Math.fround(( - (x >>> 0)))) | 0)) | 0) : Math.fround(Math.clz32(Math.fround((Math.imul((( + (Math.atan2(x, y) * ( + Math.atan2((y >>> 0), Math.fround(((Math.expm1((-Number.MIN_SAFE_INTEGER | 0)) | 0) >> x)))))) >>> 0), (x | 0)) | 0))))); }); testMathyFunction(mathy5, /*MARR*/[ /x/g ,  /x/g ,  /x/g ,  /x/g , -Infinity, -Infinity, -Infinity, -Infinity,  /x/g , -Infinity,  /x/g ,  /x/g , -Infinity,  /x/g ,  /x/g , -Infinity, -Infinity,  /x/g , -Infinity,  /x/g ,  /x/g ,  /x/g ,  /x/g , -Infinity,  /x/g , -Infinity,  /x/g ,  /x/g ,  /x/g , -Infinity,  /x/g ,  /x/g , -Infinity,  /x/g , -Infinity,  /x/g ,  /x/g , -Infinity]); ");
/*fuzzSeed-116111302*/count=538; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"^?\", \"yim\"); var s = \"\\n\\n\\n\"; print(s.replace(r, (q => q).call)); ");
/*fuzzSeed-116111302*/count=539; tryItOut("\"use strict\"; e2.add(o0.a2);");
/*fuzzSeed-116111302*/count=540; tryItOut("x = o2;s2 += s1;");
/*fuzzSeed-116111302*/count=541; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ((( ~ (Math.exp(y) >>> 0)) >>> 0) ? Math.sinh((((Math.asin(x) | 0) - (Math.hypot(x, ( + x)) | 0)) | 0)) : Math.atan2(Math.fround(( + (Math.trunc((x >>> 0)) >>> 0))), Math.hypot(Math.fround(Math.atan2(Math.fround(( ! x)), Math.fround(Math.max(-(2**53+2), ( - y))))), (Math.sign(Math.fround((Math.min(-Number.MAX_VALUE, Math.imul(( + -1/0), ( + x))) >>> 0))) | 0)))); }); testMathyFunction(mathy4, [-0x100000000, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, -0x080000001, 0x080000000, -1/0, Number.MAX_SAFE_INTEGER, 0, -Number.MIN_VALUE, 42, -(2**53-2), 1.7976931348623157e308, 0.000000000000001, 0x07fffffff, 2**53-2, 2**53, -0x080000000, -0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, Math.PI, -0, 0x100000001, -(2**53), Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), 1/0, -0x100000001, 0/0, Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-116111302*/count=542; tryItOut("mathy1 = (function(x, y) { return Math.imul(Math.fround(( - Math.max(( ~ (Math.atanh((Math.fround(( + Math.fround(( - x)))) >>> 0)) >>> 0)), ( ~ y)))), (Math.asin(( ~ Math.log2(x))) / Math.tan((Math.min(Math.fround(Math.imul(( ~ 0x080000001), Math.fround((y >>> ( + y))))), (-1/0 >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [-0x0ffffffff, -0, 0.000000000000001, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 0x07fffffff, 1, 0/0, 2**53-2, 1/0, -(2**53), -0x080000000, 2**53+2, 42, -0x100000000, -Number.MAX_VALUE, -(2**53+2), 0x100000000, Number.MAX_VALUE, -1/0, 0x0ffffffff, -(2**53-2), 0x100000001, 0, 0x080000001, -0x100000001, Math.PI, -0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_VALUE, 0x080000000]); ");
/*fuzzSeed-116111302*/count=543; tryItOut("\"use strict\"; {let x = x = ({window:  /x/ }), w = ({y:  \"\" }), fhxoez, NaN, y;h1.getOwnPropertyDescriptor = f1; }");
/*fuzzSeed-116111302*/count=544; tryItOut("\"use strict\"; this.i0.__iterator__ = Date.prototype.setUTCSeconds.bind(o0);");
/*fuzzSeed-116111302*/count=545; tryItOut("v1 = evaluate(\"function f0(a0)  { \\\"use strict\\\"; {/*oLoop*/for (let osginx = 0; osginx < 119; ++osginx) { continue ; } print(x); } } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: [], noScriptRval: false, sourceIsLazy: false, catchTermination: true, element: o1.o0, elementAttributeName: s0 }));");
/*fuzzSeed-116111302*/count=546; tryItOut("/*RXUB*/var r = new RegExp(\"[^]\\\\u8D28[^][^](?=[^])|\\\\B+\\\\3|[]*|(?!\\\\D){3}|.[^]{4}|[^\\\\cZ3-\\u1722\\u3718-\\ucca3]\", \"g\"); var s = \"\\n\\u8d28\"; print(s.search(r)); ");
/*fuzzSeed-116111302*/count=547; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=548; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.asinh(Math.max(Math.hypot(Math.imul(Math.imul((y <= ( + Math.atan2((-0x100000000 | 0), ( + x)))), ((Math.imul(y, y) >>> 0) ? Math.PI : y)), ((Math.min((x | 0), (( + (Math.imul(y, y) ? ( + x) : ( + -0x080000000))) | 0)) | 0) | 0)), x), ((x ? ( + x) : Math.fround(((-(2**53-2) >>> 0) ? (0x0ffffffff == y) : (y >>> 0)))) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[({}), -(2**53-2), -(2**53-2), Number.MIN_SAFE_INTEGER, function(){}, -(2**53-2), [x], Number.MIN_SAFE_INTEGER, ({}), ({}), function(){}, -(2**53-2), [x], function(){}, ({}), Number.MIN_SAFE_INTEGER, ({}), function(){}, function(){}, Number.MIN_SAFE_INTEGER, [x], ({}), ({}), [x], ({}), [x], Number.MIN_SAFE_INTEGER, [x], [x], function(){}, function(){}, ({}), function(){}, function(){}, -(2**53-2), -(2**53-2), function(){}, -(2**53-2), ({}), -(2**53-2), ({}), Number.MIN_SAFE_INTEGER, ({}), function(){}, Number.MIN_SAFE_INTEGER, [x], function(){}, function(){}, -(2**53-2), -(2**53-2), Number.MIN_SAFE_INTEGER, [x], ({}), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, ({}), ({}), function(){}, function(){}, function(){}, -(2**53-2), [x], ({}), Number.MIN_SAFE_INTEGER, -(2**53-2), function(){}, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, ({}), function(){}, [x], function(){}, [x], [x], ({}), -(2**53-2), -(2**53-2), ({}), [x], function(){}, ({}), ({}), ({}), Number.MIN_SAFE_INTEGER, [x], [x], Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), function(){}, [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], ({}), -(2**53-2), -(2**53-2), function(){}, function(){}, -(2**53-2), -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53-2), Number.MIN_SAFE_INTEGER, function(){}, function(){}, function(){}, [x], ({}), [x], -(2**53-2), Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=549; tryItOut("/*MXX1*/o1.o2 = g2.Array.prototype.lastIndexOf;");
/*fuzzSeed-116111302*/count=550; tryItOut("\"use asm\"; v1 = Object.prototype.isPrototypeOf.call(e1, v2);");
/*fuzzSeed-116111302*/count=551; tryItOut("let (d, [] = (([] = (4277))), hhsmtq, x = true.eval(\"/* no regression tests found */\"), x, {} =  /x/g .unwatch(\"add\")) { let (z) { a2.pop(); } }");
/*fuzzSeed-116111302*/count=552; tryItOut("v1 = (t0 instanceof e1);");
/*fuzzSeed-116111302*/count=553; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116111302*/count=554; tryItOut("((4277));");
/*fuzzSeed-116111302*/count=555; tryItOut("");
/*fuzzSeed-116111302*/count=556; tryItOut("testMathyFunction(mathy5, [2**53+2, 2**53-2, 0, 0x100000001, -0x0ffffffff, -0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000001, 1.7976931348623157e308, -0x080000000, 0/0, 0x080000000, Number.MAX_VALUE, 1, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -(2**53-2), 0x100000000, -0x100000000, 2**53, Math.PI, -Number.MIN_VALUE, 1/0, -0x080000001, -1/0, 0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, -(2**53), -0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=557; tryItOut("v0 = g0.runOffThreadScript();");
/*fuzzSeed-116111302*/count=558; tryItOut("print(uneval(e0));");
/*fuzzSeed-116111302*/count=559; tryItOut("a2.sort(p2);");
/*fuzzSeed-116111302*/count=560; tryItOut("mathy5 = (function(x, y) { return Math.pow(Math.min(Math.fround(((( + Math.atanh((x >>> 0))) >= Math.abs((x >>> 0))) | 0)), ( + Math.imul(( ~ ( - (x === 42))), Math.fround((Math.atan2((y | 0), (y | 0)) | 0))))), ( + Math.hypot(((Math.pow(x, x) === ( + Math.asin(( + ( ~ Math.fround(( ! x))))))) >>> 0), ( + Math.fround(Math.atan2(Math.fround(( - Math.sinh(y))), Math.fround(-0x080000000))))))); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 1/0, 0.000000000000001, 0x100000001, -0x080000001, 0x07fffffff, -(2**53+2), 42, 0x080000000, -0, -0x100000000, 1.7976931348623157e308, 2**53+2, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, -(2**53-2), Number.MIN_VALUE, 1, 0, 0x080000001, -0x100000001, Number.MAX_VALUE, -1/0, -(2**53), 0x0ffffffff, 2**53-2]); ");
/*fuzzSeed-116111302*/count=561; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      (Int32ArrayView[4096]) = ((0x0) % (0xfa8c30b1));\n    }\n    {\n      d1 = (d1);\n    }\n    return (((-0x8000000)+((~~(+(0.0/0.0))))+(/*FFI*/ff(((d1)), ((+(0.0/0.0))), ((70368744177665.0)), ((18446744073709552000.0)), ((~~(5.0))), ((d1)))|0)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.setUTCHours}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, 1/0, -1/0, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -(2**53+2), 2**53-2, -Number.MIN_VALUE, 0x100000001, -(2**53), -0x100000001, 0.000000000000001, -0x080000000, Math.PI, 0x100000000, 0x0ffffffff, 42, 1, -0x080000001, 0/0, 0, -(2**53-2), 0x07fffffff, -0x07fffffff, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-116111302*/count=562; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.sin(Math.max(Math.imul((42 <= y), (( ! (y ? x : (( + (y | 0)) >>> 0))) >>> 0)), Math.fround(((Math.trunc((y | 0)) | 0) / Math.fround((( - (( + (y ^ x)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [-1/0, 0, -Number.MAX_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -0x100000001, -(2**53+2), 2**53+2, 0.000000000000001, Math.PI, -0, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, 1/0, 0x100000001, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000, 0/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, -0x080000001, -0x07fffffff, 2**53-2, -0x080000000, 2**53, -(2**53-2), 0x07fffffff, 0x080000000, 42, Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=563; tryItOut("\"use strict\"; this.v1 = Object.prototype.isPrototypeOf.call(this.g2, o0.h2);");
/*fuzzSeed-116111302*/count=564; tryItOut("h2.get = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return +((((134217727.0)) % ((-288230376151711740.0))));\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096));");
/*fuzzSeed-116111302*/count=565; tryItOut("mathy0 = (function(x, y) { return (Math.trunc(((Math.atan2(Math.fround(Math.asin((Math.atan2((x >>> 0), Math.cosh(-0)) >>> 0))), (Math.imul((( ~ (( + y) | 0)) | 0), ((Math.fround(0x080000001) ? (x < ( + Math.pow(( + 0x080000000), ( + x)))) : Math.fround(Math.imul(y, Math.fround(x)))) | 0)) | 0)) | 0) | 0)) >>> 0); }); testMathyFunction(mathy0, [1/0, -1/0, -0x080000001, 0x0ffffffff, 0, -0, -0x100000000, -(2**53-2), -0x0ffffffff, -0x07fffffff, -Number.MAX_VALUE, 0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 2**53-2, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, 0/0, 0x080000000, -(2**53), -0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, 0x100000001, 42, -Number.MIN_VALUE, 1, -0x080000000, 2**53, 0x07fffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-116111302*/count=566; tryItOut("\"use strict\"; with({}) let(w) { let(x = this, d, \u3056 = (makeFinalizeObserver('nursery')), x = timeout(1800), a =  '' ) ((function(){window.stack;})());}");
/*fuzzSeed-116111302*/count=567; tryItOut("mathy4 = (function(x, y) { return ( - ( + ( + (( + y) ? ( + (Math.pow(( + ((-0x080000000 || x) > (x >>> 0))), (((x >>> 0) % (Math.hypot((Math.sqrt(y) | 0), (Math.max(Math.fround(Math.tan(Math.fround(x))), (Math.tan(x) >>> 0)) | 0)) | 0)) >>> 0)) >>> 0)) : ( + (Math.min(((y >> y) | 0), (Math.fround(Math.sign(y)) | 0)) | 0)))))); }); testMathyFunction(mathy4, ['', /0/, false, (new Boolean(true)), (new Number(0)), [0], [], ({valueOf:function(){return 0;}}), '\\0', '/0/', '0', ({toString:function(){return '0';}}), (new Number(-0)), 0, 0.1, null, (new Boolean(false)), 1, ({valueOf:function(){return '0';}}), true, objectEmulatingUndefined(), NaN, -0, (new String('')), (function(){return 0;}), undefined]); ");
/*fuzzSeed-116111302*/count=568; tryItOut("v0 = Object.prototype.isPrototypeOf.call(t0, t1);");
/*fuzzSeed-116111302*/count=569; tryItOut("i0.send(g1.m2);");
/*fuzzSeed-116111302*/count=570; tryItOut("\"use strict\"; b0.toSource = (function() { try { a2.length = 11; } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(o1.a1, s0); return g2.s2; });");
/*fuzzSeed-116111302*/count=571; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (d0);\n    return +((+/*FFI*/ff()));\n    (Uint8ArrayView[0]) = ((((-0x2fd92f9)) ^ ((0xcc3e456c)+((abs((0x22a774a8))|0) <= (((0xff4d6de2)) >> ((0x6dcb6233))))+(0x258ac9b4))) % (((0x7466826b)-((((0x7fffffff) % (0x35832c92))>>>((0xc78e8b9b))))+(0xff764b10)) & ((((((4294967297.0)) * ((-9007199254740992.0)))) ? (0x59868b89) : (0xfae721a0))-((0x1a07c4b9)))));\n    d0 = (d0);\n    return +((d0));\n  }\n  return f; })(this, {ff: (x = Proxy.createFunction(({/*TOODEEP*/})( /x/ ), Date.prototype.getUTCDay))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-116111302*/count=572; tryItOut("\"use strict\"; a0.toSource = (function() { try { v0 = Object.prototype.isPrototypeOf.call(v0, this.o2); } catch(e0) { } a0.splice(NaN, 11, b1, this.a2, i2); return this.s0; });function x(x) { \"use strict\"; h1.hasOwn = (function() { for (var j=0;j<51;++j) { f2(j%2==1); } }); } /* no regression tests found */");
/*fuzzSeed-116111302*/count=573; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (( + Math.fround(( ~ ( + Math.fround(Math.log2((( - (( + Math.atan2(0x100000000, -0x07fffffff)) | 0)) | 0))))))) >>> Math.atan2(( + ( + (y | 0))), Math.sqrt((Math.imul((( - 0.000000000000001) | 0), (Math.imul(-Number.MIN_VALUE, (( ~ (-Number.MIN_VALUE | 0)) | 0)) | 0)) | 0))))); }); testMathyFunction(mathy3, [true, (new String('')), false, [0], '\\0', '', 0, '/0/', '0', (new Number(0)), objectEmulatingUndefined(), (new Boolean(false)), (function(){return 0;}), 0.1, ({valueOf:function(){return '0';}}), NaN, (new Boolean(true)), ({toString:function(){return '0';}}), ({valueOf:function(){return 0;}}), -0, (new Number(-0)), [], /0/, 1, undefined, null]); ");
/*fuzzSeed-116111302*/count=574; tryItOut("\"use strict\"; /*infloop*/ for (let b of new RegExp(\"((\\\\cJ)|$)|[^]|\\\\b{4,}*\\\\1?|(?:(?:\\u00c9).**){0,}>.{3,3}*(?![\\\\W]){2}\", \"ym\")) {i1 = x;; }");
/*fuzzSeed-116111302*/count=575; tryItOut("\"use strict\"; let (z) { /*vLoop*/for (opcvgb = 0; opcvgb < 46; ++opcvgb) { const e = opcvgb; t1 + ''; }  }\na1.pop(o0);\n");
/*fuzzSeed-116111302*/count=576; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var cos = stdlib.Math.cos;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ceil = stdlib.Math.ceil;\n  var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 72057594037927940.0;\n    var i3 = 0;\n    (Float64ArrayView[4096]) = ((-257.0));\n    d1 = (Infinity);\n    return ((0x446ce*(0xcf61129)))|0;\ng2.b0 = t2.buffer;    d2 = (+(1.0/0.0));\n    d1 = (((+cos(((((((+/*FFI*/ff(((d2)), ((3.8685626227668134e+25)), ((-73786976294838210000.0)), ((32769.0)), ((33.0)), ((32769.0)), ((-513.0)), ((2097153.0)), ((-1152921504606847000.0)), ((-140737488355328.0)), ((-2.0)), ((-2.0)))) == (d1))+(!((((-0x8000000))>>>((0x6ae00571)))))) >> ((0xfab028e7)+((0xcc0aa541) ? (0x3000f57) : (w + (new String((arguments.callee.prototype), (objectEmulatingUndefined())))))))))))) - ((+((+(0.0/0.0))))));\n    d0 = (+(1.0/0.0));\n    (Float64ArrayView[2]) = ((d2));\n    {\n      i3 = ((((i3)-(!((0xddc7a1be) ? (-0x7b66ea6) : (0xffffffff)))+((abs((imul((-0x2563ea2), (0xfb1ddb0f))|0))|0) <= (((0xc9dc88e6)) | ((0xffffffff))))) & (((-134217729.0) != (d1)))) <= (imul((i3), (0xe0839bf5))|0));\n    }\n    i3 = (0xf9f0191a);\n    (Uint32ArrayView[4096]) = ((0x3876bc73)-(0x35b0eae9));\n    return (((!((((0xcd5bed80)) >> ((/*FFI*/ff((((0xa4210*(0x49aab2dc)) & ((!(0x204780d8))))), ((+ceil(((d0))))), ((((0x117856fb)) << ((0xf721efc7)))), ((-274877906944.0)), ((4.722366482869645e+21)), ((-2251799813685247.0)))|0))) == (0x29f25381)))*0xfffff))|0;\n    d2 = (2251799813685249.0);\n    d2 = (NaN);\n    return (((i3)-(0xffffffff)-(0xfb5dd56b)))|0;\n    {\n      switch ((0x29032d38)) {\n        case -3:\n          d1 = (((d2)) % ((Float64ArrayView[((0xfa8d5e16)) >> 3])));\n          break;\n        case -3:\n          d1 = (d0);\n          break;\n        case -3:\n          d0 = (((({a2:z2}))) - ((d1)));\n        case -3:\n          (Uint16ArrayView[2]) = (((((/*FFI*/ff(((Infinity)), ((+/*FFI*/ff(((d2)), ((((0xffebc3fb)) << ((0xffffffff)))), ((((134217728.0)) / ((1.5111572745182865e+23)))), ((274877906945.0)), ((-35184372088833.0)), ((-1.00390625)), ((144115188075855870.0)), ((-17592186044415.0)), ((-288230376151711740.0)), ((-1.5474250491067253e+26)), ((67108865.0)), ((288230376151711740.0)), ((262145.0)), ((-513.0))))), ((((0xffffffff)) ^ ((-0x8000000)-(-0x6a4daa5)))), ((((0xffffffff)) | ((0xa1a78fb8)))), ((imul((0x12595231), (0xfd525e59))|0)), ((131071.0)), ((-2251799813685249.0)), ((-17592186044417.0)), ((-35184372088833.0)), ((16385.0)), ((32769.0)), ((1.125)), ((-9007199254740992.0)))|0)+(0x2a6799a8))>>>((!(0xf379df64))))));\n          break;\n        case 1:\n          {\n            return ((((0xb4adc20e) ? (0x6d7ac906) : (0xce03e14a))))|0;\n          }\n          break;\n        case 1:\n          d1 = (d2);\n          break;\n        case -2:\n          {\n            d1 = (1.25);\n          }\n          break;\n        case 1:\n          d0 = (-1.015625);\n          break;\n        case 1:\n          {\n            return (((0xfcf605da)))|0;\n          }\n          break;\n        case -3:\n          return (((imul(((((0x49459213))>>>(((((0xf849c949))|0))-((((0xe6d177d0))>>>((0xf9ab8c41))))))), (!(i3)))|0) % ((((d2) < (+((d1))))-(0xf982beec)-(0xfdc2d300)) >> ((i3)+((+(-1.0/0.0)) < (+pow(((Float32ArrayView[1])), ((Float32ArrayView[0])))))))))|0;\n        default:\n          d1 = (-4.0);\n      }\n    }\n    i3 = ((abs((((+(0.0/0.0)))|0))|0));\n    i3 = (0x26a907ff);\n    switch ((0x7fffffff)) {\n      case -2:\n        (Int16ArrayView[((0xa5a9e516) % (0x9c52639e)) >> 1]) = ((0x4021acb2));\n        break;\n      default:\n        {\n          d1 = (+(1.0/0.0));\n        }\n    }\n    i3 = (0xfca4511c);\n    return (((Math.min( /x/g , -26))*-0xb67d6))|0;\n  }\n  return f; })(this, {ff: Map.prototype.values}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000000, 0.000000000000001, -Number.MAX_VALUE, 0x080000000, 0x080000001, 2**53+2, 1.7976931348623157e308, 42, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, 0/0, 2**53-2, 0x100000000, -0, Number.MAX_SAFE_INTEGER, -0x07fffffff, Math.PI, 0x07fffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 0, 2**53, -(2**53), -(2**53+2), -0x0ffffffff, 1, -1/0, 1/0, -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000000]); ");
/*fuzzSeed-116111302*/count=577; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), undefined, new Boolean(false), undefined, undefined, new Boolean(false), undefined, new Boolean(false), undefined, undefined, undefined, undefined, undefined, new Boolean(false), undefined, undefined, new Boolean(false), undefined, undefined, new Boolean(false), new Boolean(false), undefined, new Boolean(false), undefined, undefined, undefined, undefined, new Boolean(false)]); ");
/*fuzzSeed-116111302*/count=578; tryItOut("\"use asm\"; s2.toString = (function() { for (var j=0;j<17;++j) { o1.f0(j%3==0); } });");
/*fuzzSeed-116111302*/count=579; tryItOut("\"use strict\"; this.i0.next();");
/*fuzzSeed-116111302*/count=580; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ((( + mathy4(( + ( + Math.hypot(( + Math.fround(( - Math.fround((((2**53-2 | 0) << Math.fround(y)) | 0))))), ( + y)))), ( + ( ! (( - Math.fround((Math.fround(x) ? y : ((y == y) >>> 0)))) - (mathy0(Math.trunc(y), -0x100000000) | 0)))))) | 0) & ( + (( + Math.max(x, (( + Math.imul(Math.atan2(-(2**53-2), Math.fround(Math.cbrt(Math.imul(x, ( + 42))))), y)) | 0))) ? Math.atan2((( ! (x | 0)) | 0), ( + mathy1(( + ((y << x) / ( + x))), ( + (( + (( + y) << ( + x))) && Math.fround((Math.hypot(Number.MAX_SAFE_INTEGER, x) | 0))))))) : ((y | 0) ? (((y | 0) << (mathy2(( + x), ( + (y ? 0x080000001 : y))) | 0)) | 0) : Math.imul(y, y))))); }); testMathyFunction(mathy5, [0/0, -Number.MIN_VALUE, -0x080000001, 0x100000001, 42, 1, 0x0ffffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, Number.MIN_SAFE_INTEGER, 0x080000000, 0, 2**53-2, -Number.MAX_VALUE, -0x100000001, -(2**53-2), 0.000000000000001, Number.MIN_VALUE, -0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, -0, 1.7976931348623157e308, -1/0, Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -(2**53), -0x080000000, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-116111302*/count=581; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((Math.fround((( - (( + x) | 0)) == Math.min((x == y), ((Math.trunc(x) >>> 0) <= Math.fround(Math.fround(y)))))) | 0) === (mathy0((( ! (( + Math.atan((x / y))) | 0)) | 0), Math.fround(mathy0(Math.fround((Math.min(0.000000000000001, Math.fround(mathy0((x | 0), Math.fround((( + y) | 0))))) < (Math.max(x, x) === -(2**53-2)))), Math.fround((y * -0))))) | 0)) | 0); }); testMathyFunction(mathy1, [(new String('')), ({valueOf:function(){return '0';}}), 1, [0], '', '\\0', (new Number(-0)), /0/, ({valueOf:function(){return 0;}}), '/0/', NaN, [], ({toString:function(){return '0';}}), 0.1, false, null, -0, 0, (new Number(0)), undefined, (new Boolean(true)), true, (new Boolean(false)), (function(){return 0;}), objectEmulatingUndefined(), '0']); ");
/*fuzzSeed-116111302*/count=582; tryItOut("var r0 = 7 / x; var r1 = r0 | r0; r0 = r0 - 2; r0 = 8 - r1; var r2 = 7 - r1; r2 = 8 | 1; var r3 = r1 / r2; var r4 = 0 / r3; var r5 = r0 % r2; var r6 = r5 ^ 0; var r7 = 2 ^ r2; r1 = r3 % r3; r3 = 7 % r6; var r8 = r0 + r2; var r9 = r3 | 7; print(r4); var r10 = 8 * 6; var r11 = r0 - r3; r8 = r1 | 4; var r12 = x / 2; var r13 = r1 / r7; var r14 = 4 ^ 7; var r15 = r7 + r5; r1 = 1 & 5; var r16 = r5 & x; var r17 = 5 + r13; var r18 = r7 & 4; var r19 = 3 - r9; r13 = r19 * r1; print(r0); var r20 = r16 * r10; var r21 = r3 % r12; var r22 = 2 - 7; r22 = r8 ^ 7; var r23 = 8 * 9; r20 = r18 - r1; var r24 = r19 % 3; var r25 = r17 / r6; var r26 = r5 | 8; var r27 = r5 & 0; var r28 = r14 % r9; print(r27); var r29 = r22 - r11; r18 = r22 * r5; var r30 = 5 % r8; var r31 = r24 + 8; r4 = x % 8; var r32 = r5 ^ r28; var r33 = r25 * r19; var r34 = r8 - 4; r7 = 9 / r4; var r35 = r3 * r6; var r36 = r16 * r17; var r37 = 6 + r10; var r38 = r1 ^ r4; var r39 = r18 - r18; var r40 = 4 + r37; var r41 = 5 ^ r24; var r42 = r18 * r28; var r43 = r24 & 8; var r44 = r23 - r36; var r45 = r21 | 7; r7 = r33 ^ r10; var r46 = 1 + 9; var r47 = r33 % r44; var r48 = r21 & r22; var r49 = 3 | r24; var r50 = r33 * r29; var r51 = 5 | r34; print(r3); r34 = r10 * 4; var r52 = r21 - r24; var r53 = 4 | 1; var r54 = r21 - r9; var r55 = 1 % r54; var r56 = r17 % r13; x = r2 + 7; print(r39); print(r56); var r57 = 2 / r4; print(r2); var r58 = 4 / 1; var r59 = r53 * 9; r46 = r43 % r22; var r60 = 9 & r43; var r61 = r24 * r26; var r62 = 0 % r35; var r63 = 4 ^ r49; var r64 = r20 / r35; var r65 = 3 & 0; r48 = r10 | r19; r20 = 9 + r27; var r66 = r7 | 5; var r67 = r35 + r49; var r68 = r44 & r44; var r69 = 3 % r39; r1 = r6 / r30; var r70 = 7 & r65; var r71 = r44 - 5; r57 = 2 & r50; r50 = r18 * 1; var r72 = r69 - 0; var r73 = r56 * r0; var r74 = r1 | r30; var r75 = 7 * r69; var r76 = 9 & 6; var r77 = 4 ^ 4; print(r6); var r78 = r64 & r59; r51 = r23 - r71; var r79 = r65 % r55; var r80 = r57 & r28; var r81 = r34 ^ 8; r7 = 0 % r53; var r82 = r41 / 4; var r83 = r56 + r78; r20 = r68 & x; var r84 = r74 ^ 5; var r85 = 2 / r25; var r86 = r61 & r71; var r87 = 7 | 2; var r88 = r19 / r82; r78 = r20 % r43; var r89 = 6 % r12; r84 = 8 * 9; var r90 = 1 * 3; r32 = r47 & r2; var r91 = r51 | r79; var r92 = 4 % r3; var r93 = r57 + r57; var r94 = r13 * r89; var r95 = 6 * r42; var r96 = r43 * r0; var r97 = 1 ^ 0; var r98 = 1 * r92; var r99 = 7 | r27; r51 = 6 - r11; var r100 = r19 ^ r15; var r101 = 6 / 3; r35 = 5 / 7; print(r28); var r102 = r43 ^ 3; var r103 = r45 & 2; var r104 = r57 | r20; r1 = 3 ^ r21; var r105 = r31 - r88; var r106 = 5 & r86; r102 = r33 + 8; var r107 = r74 | r66; var r108 = 7 | r36; var r109 = r105 * 8; var r110 = r3 & r42; var r111 = 4 - x; var r112 = r40 ^ r69; r21 = r106 % r89; var r113 = 3 - r71; var r114 = r45 * x; var r115 = r1 / 6; r61 = 5 ^ r67; print(r24); r55 = x * r3; var r116 = r77 - 5; var r117 = r68 & r115; var r118 = 9 ^ 1; var r119 = r28 + r107; var r120 = r49 ^ r23; var r121 = r44 - 1; var r122 = r62 % 2; var r123 = 7 * 9; print(r89); r64 = r59 + r62; var r124 = r2 / r51; var r125 = r66 & r0; r96 = r31 + 8; var r126 = r56 % r5; r73 = r107 & 5; var r127 = r125 & 7; var r128 = r53 + 7; var r129 = r85 ^ r76; var r130 = r3 | 3; print(r35); var r131 = r63 ^ r0; var r132 = 7 + r121; var r133 = r20 | r27; var r134 = r78 | r33; var r135 = 9 / 8; r128 = r8 ^ 0; var r136 = r44 + 1; var r137 = 1 * r41; var r138 = 4 ^ 5; print(r130); r25 = r73 & r8; var r139 = r100 / r7; var r140 = 7 & r22; var r141 = 1 + r6; var r142 = r129 % 9; var r143 = 3 * r139; var r144 = r50 | 8; var r145 = 6 % r32; var r146 = r7 + r5; var r147 = 9 ^ r95; var r148 = 5 | 0; var r149 = r45 * 9; print(r103); print(r85); var r150 = 8 / r143; var r151 = r23 & r78; var r152 = r126 & r34; var r153 = r95 * r12; var r154 = 8 & 6; var r155 = r61 + r85; var r156 = r146 + r10; var r157 = 6 + r31; r34 = 8 % r134; r129 = 8 * r150; var r158 = r69 / r113; var r159 = r133 | r117; r58 = 6 ^ r39; var r160 = r66 - r70; r23 = 8 ^ r82; r149 = 0 + 7; var r161 = 9 - r73; var r162 = 6 * r11; print(r115); var r163 = 8 + r158; var r164 = r123 | r38; var r165 = r75 / r71; var r166 = r117 / r152; var r167 = r3 - r139; var r168 = r16 * r39; var r169 = r137 * r2; print(r63); var r170 = r56 / 4; var r171 = r23 - r71; r166 = r119 & r28; var r172 = r136 | 6; var r173 = 5 - 1; var r174 = r89 - r19; var r175 = r8 * r127; var r176 = 5 & r44; var r177 = r98 / 2; var r178 = r83 & r94; var r179 = r147 & r104; r162 = r36 + r141; var r180 = r124 % r179; print(r37); var r181 = 5 & 6; r137 = r170 * r148; var r182 = r128 | 5; var r183 = r15 * r36; var r184 = r159 - r30; var r185 = r175 + r60; var r186 = r20 | 5; print(r95); var r187 = r184 - r31; print(r92); print(r12); var r188 = 4 ^ r55; var r189 = r89 - r133; var r190 = r30 * r128; r176 = r95 / r61; var r191 = r13 / 6; var r192 = r110 * r160; r176 = 5 - r14; var r193 = r104 & r161; var r194 = r79 - r114; var r195 = r165 - 8; var r196 = 2 / r75; r152 = r37 - r43; var r197 = r17 - 6; var r198 = r109 & r84; var r199 = r0 - r102; var r200 = 1 % 5; r88 = r120 / 6; print(r161); var r201 = 2 % r7; var r202 = r199 + x; r124 = r108 & r93; var r203 = r192 ^ 1; var r204 = r86 * 7; var r205 = r37 | 0; var r206 = r155 / r109; var r207 = r87 & r67; r112 = 8 - 0; var r208 = r61 | r165; var r209 = r118 / r144; var r210 = r61 * r118; var r211 = r198 / r193; r169 = r177 % 1; var r212 = r210 + r114; var r213 = r171 % r37; var r214 = r100 | r186; var r215 = 8 ^ r47; r137 = 6 * 3; r186 = r91 | r183; var r216 = 0 | 5; r106 = 2 - 3; var r217 = 2 * r50; r12 = r188 + r52; r63 = r27 ^ r138; r118 = r180 - r104; r141 = r52 * 9; var r218 = r20 / 5; var r219 = r153 | r97; r3 = r150 * 1; print(r69); var r220 = r51 | 2; var r221 = 4 / r183; var r222 = r24 % 2; var r223 = r222 | r14; r66 = 2 / r80; r55 = r66 / r131; r151 = r59 % 6; var r224 = 3 / 2; r135 = r21 & r85; r216 = r102 / 2; var r225 = 2 & 9; var r226 = 1 / r154; var r227 = r5 * 9; var r228 = r139 | r147; r74 = r72 - r122; var r229 = r55 & 3; var r230 = r149 + 2; var r231 = r167 | 3; r217 = 0 / r217; var r232 = r102 + r48; var r233 = r199 + 4; r231 = r16 % r79; var r234 = r81 & 9; var r235 = r8 * r144; var r236 = 6 ^ r130; var r237 = r158 * r88; var r238 = r189 | 9; var r239 = 1 + 0; var r240 = r181 | 4; var r241 = 8 ^ 3; var r242 = 7 - r72; var r243 = 9 ^ r19; var r244 = r8 - r199; var r245 = 5 & 0; var r246 = 2 % r56; var r247 = 0 * 1; var r248 = r68 - r74; var r249 = 0 | r56; r232 = 4 % r197; var r250 = r82 % r228; var r251 = r38 / r66; var r252 = r108 % r205; var r253 = 7 & r101; var r254 = r26 - r166; var r255 = r133 - r162; var r256 = 0 + r176; var r257 = 6 - r113; r89 = r85 ^ r66; r63 = r153 ^ r132; var r258 = r105 ^ r71; var r259 = r246 / r52; var r260 = r44 & r118; var r261 = r4 + 2; var r262 = 7 % 5; var r263 = 4 % r189; r225 = r117 / r232; var r264 = 2 % r219; var r265 = 1 & r48; var r266 = r196 * 4; r57 = 9 / r189; var r267 = 4 - r113; var r268 = 3 & r110; var r269 = 9 % r191; var r270 = r245 ^ 3; r140 = r58 - r165; var r271 = r13 * r187; var r272 = r197 / r251; var r273 = r198 * 0; var r274 = r52 | 5; var r275 = r50 / r274; var r276 = r17 + 0; r264 = r138 | r72; var r277 = r20 % r172; print(r78); var r278 = r170 ^ r147; var r279 = 8 % 9; var r280 = r63 * r278; var r281 = r40 - r278; r243 = 3 % 3; var r282 = r123 - 5; var r283 = r128 - r50; r163 = r153 - 2; r28 = r176 & r26; r254 = r11 % 0; var r284 = r212 | r162; var r285 = 3 / 6; print(r66); r84 = r173 % r210; var r286 = r163 + r185; r165 = 6 / r48; var r287 = r147 - 7; var r288 = r58 % 2; r128 = 2 - 6; var r289 = x * r11; r134 = r69 ^ r10; var r290 = r255 + 7; var r291 = r55 & r242; var r292 = 8 % r244; var r293 = 3 & r108; var r294 = r149 & r190; var r295 = r85 % 4; var r296 = r204 ^ r241; var r297 = r221 % r108; var r298 = 0 % r126; var r299 = r217 - r260; var r300 = r73 & r144; var r301 = 2 / 6; var r302 = r35 | r45; var r303 = r156 / r49; var r304 = r69 | r225; var r305 = r291 * r73; var r306 = r210 + r96; var r307 = r107 - 3; var r308 = 0 + r223; var r309 = 1 & r146; var r310 = 5 - r82; r212 = r207 / r72; var r311 = 8 & r160; var r312 = r228 + r268; var r313 = r105 + r17; var r314 = r284 * r145; r6 = 7 * 0; var r315 = r274 - r98; var r316 = r22 - r84; print(r314); r297 = 7 % r151; var r317 = r177 * 6; print(r71); var r318 = r87 - r182; var r319 = 4 * 4; var r320 = r42 ^ 3; var r321 = r20 + 8; var r322 = r173 * r41; var r323 = r80 / r132; r273 = r20 + r40; var r324 = r99 * r264; var r325 = 3 + 0; var r326 = r272 * 4; var r327 = r304 ^ r149; var r328 = r6 - r77; var r329 = 9 - r102; var r330 = r155 & 3; var r331 = r325 % 5; var r332 = 1 / r48; print(r308); r316 = 7 - r108; var r333 = r269 | 6; print(r242); var r334 = 7 * r194; var r335 = r211 / r304; var r336 = r125 - 4; var r337 = r121 & r90; var r338 = r55 - r244; var r339 = r60 | r180; var r340 = r100 / r151; var r341 = r17 + 0; var r342 = 1 + r237; r17 = 4 ^ 0; var r343 = r232 % r261; r307 = r338 ^ 3; r109 = r177 % r33; var r344 = r117 & r7; var r345 = r231 + r296; var r346 = 2 % 7; var r347 = 4 | 1; print(r272); r123 = r197 % r96; r103 = 4 + r57; var r348 = r230 / r177; r320 = 7 / r104; var r349 = r112 - r14; var r350 = r48 ^ 7; r180 = 2 / r234; r168 = 9 | r58; var r351 = 6 | r114; var r352 = 0 * r85; r84 = r220 * r64; r215 = r239 & r264; var r353 = r349 | 0; var r354 = r186 - r97; var r355 = r287 - r343; var r356 = r135 + 4; var r357 = r284 | r269; var r358 = r26 | r283; var r359 = r127 / r331; var r360 = r263 % r359; var r361 = r219 / 0; var r362 = r178 - 1; r12 = r339 / 0; var r363 = 2 & 9; var r364 = 7 % r310; r151 = r197 & 0; var r365 = r44 + r356; var r366 = 3 ^ r125; var r367 = 7 - r344; var r368 = r266 | 4; var r369 = r160 - r263; r179 = r259 * 7; ");
/*fuzzSeed-116111302*/count=583; tryItOut("mathy2 = (function(x, y) { return ( - Math.atan2((((( ~ (x >>> 0)) >>> 0) && x) || ( + Math.min(x, ( + (( + y) > ( + -(2**53))))))), (mathy0((Math.tanh(( + x)) | 0), (( - Math.fround(( ~ Math.fround(x)))) | 0)) >>> 0))); }); ");
/*fuzzSeed-116111302*/count=584; tryItOut("m1 + a0;");
/*fuzzSeed-116111302*/count=585; tryItOut("\"use strict\"; /*hhh*/function knssjx(x, x = {NaN: x, new Function.prototype: b, \u3056: {x}, this.x: [, , ]} = x){c < window;}/*iii*/print(uneval(v0));");
/*fuzzSeed-116111302*/count=586; tryItOut("/*tLoop*/for (let y of /*MARR*/[x, function(){}, false, function(){}, false, function(){}, function(){}, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, function(){}, function(){}, false, false, function(){}, function(){}, function(){}, x, function(){}, false, false, function(){}, function(){}, false, function(){}, x, function(){}, function(){}, false, x, false, x, x, false, false, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, x, x, function(){}, false, x, false, x, function(){}, false, x, false, false, false, function(){}, x, false, function(){}, false, function(){}, function(){}, function(){}, function(){}, x, x, function(){}, x, function(){}, x, function(){}, function(){}, false, function(){}, function(){}, x, x, function(){}, false, x, false, false, function(){}, x, x, false, false, x, false, function(){}, function(){}, function(){}, false, false, function(){}, function(){}, x, false, x, function(){}, x, function(){}, false, function(){}, x, false, function(){}, function(){}, false, x, x, function(){}, function(){}]) { /*MXX2*/g2.EvalError.prototype.message = p2; }");
/*fuzzSeed-116111302*/count=587; tryItOut("e2.has(s1);");
/*fuzzSeed-116111302*/count=588; tryItOut("x = y;");
/*fuzzSeed-116111302*/count=589; tryItOut("\"use strict\"; print(Math.log2(\"\\u025A\"));");
/*fuzzSeed-116111302*/count=590; tryItOut("e1.add(o2.o2.o0.b0);");
/*fuzzSeed-116111302*/count=591; tryItOut("const ephyoe, x = x = x = eval, d = x;x;const z =  /x/ ;");
/*fuzzSeed-116111302*/count=592; tryItOut("mathy0 = (function(x, y) { return ((((( + Math.fround(Math.min(y, Math.fround(Math.log1p(y))))) != (( + ( + Number.MIN_SAFE_INTEGER)) >>> 0)) >>> 0) > Math.pow((((Math.fround(Math.clz32(Math.pow(Math.fround(x), ( + x)))) | 0) > y) >>> 0), Math.atan2(Math.sinh(Math.atan2((Math.log2(-0x080000000) >>> 0), x)), 0x07fffffff))) >>> 0); }); testMathyFunction(mathy0, [-0x07fffffff, 0/0, -0x0ffffffff, -(2**53-2), -1/0, -0x080000001, -0x080000000, -0x100000001, -(2**53), 2**53, Math.PI, 0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, Number.MIN_VALUE, 2**53+2, 1.7976931348623157e308, 42, -0x100000000, -(2**53+2), -Number.MAX_VALUE, 0x07fffffff, 0x080000001, 1/0, 1, 0x100000000, 2**53-2, -0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=593; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.fround(Math.hypot(Math.fround(Math.fround(Math.max(((-(2**53) >>> 0) , (y | 0)), Math.log2(Math.ceil(-0x100000000))))), ( ~ ( - -0x080000000)))) && mathy1(Math.fround(Math.min(Math.fround(( + Math.fround((Math.atan2((y >>> 0), (Math.max(x, x) >>> 0)) >>> 0)))), x)), (( + Math.sinh(Math.imul(( + Math.round(x)), Math.cosh(Number.MAX_VALUE)))) - ( + Math.asinh(( + y)))))) | 0); }); ");
/*fuzzSeed-116111302*/count=594; tryItOut("/*MXX3*/g1.Date.prototype.toString = g2.Date.prototype.toString;");
/*fuzzSeed-116111302*/count=595; tryItOut("const c, lullgn, x = (void options('strict')), xluaxw, x, b = undefined, w = x, getter = /(?=(.)[^]{0,3}*?)|.|\\ub131|${1}+?|(?!(?=\\b)*?){1,2}(?:[^]|^)+?|$|\\f{4,}(?=(?=${2,}).){2}/yim, y, yzcbks;throw window;yield (void shapeOf(\u3056));");
/*fuzzSeed-116111302*/count=596; tryItOut("/*infloop*/for(var y =  /* Comment */((yield \"\\u4154\")); new NaN = Proxy.createFunction(({/*TOODEEP*/})(this), Object.getOwnPropertySymbols)(x.unwatch(\"x\"), -10 %= window); /(?!((?![^])*|^|.*?))*?/m\n) {/*MXX2*/g0.String.length = g1;/*ADP-3*/Object.defineProperty(a2, ({valueOf: function() { p0 + i2;return 0; }}), { configurable: true, enumerable: (x % 3 == 0), writable: (x % 4 == 3), value: t2 }); }");
/*fuzzSeed-116111302*/count=597; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ~ (Math.atanh(Math.sinh(Math.fround((( + 0) || ( + (x > -0x100000001)))))) | 0)) >>> 0); }); testMathyFunction(mathy3, [undefined, (new Number(0)), '/0/', '0', false, [0], NaN, ({toString:function(){return '0';}}), (new String('')), '\\0', /0/, objectEmulatingUndefined(), (new Number(-0)), (new Boolean(false)), 0, '', [], 1, null, -0, ({valueOf:function(){return '0';}}), true, (function(){return 0;}), 0.1, ({valueOf:function(){return 0;}}), (new Boolean(true))]); ");
/*fuzzSeed-116111302*/count=598; tryItOut("s1.toSource = (function() { t1.set(a0, v2); return s1; });");
/*fuzzSeed-116111302*/count=599; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return Math.min((((( ~ (Math.cos((x || Math.round(x))) >>> 0)) >>> 0) >>> 0) * mathy3((x | 0), Math.fround(x))), (Math.min((mathy2((( ~ y) >>> 0), (mathy1(y, ( + Math.exp(y))) >>> 0)) >>> 0), (( ! Math.fround(x)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-116111302*/count=600; tryItOut("testMathyFunction(mathy2, [[0], NaN, ({valueOf:function(){return 0;}}), (new Boolean(true)), ({valueOf:function(){return '0';}}), true, 0, '0', objectEmulatingUndefined(), '', 0.1, (new Number(0)), [], /0/, (function(){return 0;}), (new String('')), '/0/', (new Boolean(false)), 1, (new Number(-0)), -0, '\\0', null, false, ({toString:function(){return '0';}}), undefined]); ");
/*fuzzSeed-116111302*/count=601; tryItOut("\"use strict\"; for (var v of b2) { try { v1 = (e1 instanceof this.i0); } catch(e0) { } try { m0.set(t2, i2); } catch(e1) { } try { /*RXUB*/var r = r1; var s = s2; print(s.replace(r,  /x/ ));  } catch(e2) { } ; }");
/*fuzzSeed-116111302*/count=602; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( ! (( + (y | 0)) | 0)) <= ( - ( + ((Math.min(x, 0/0) , (( + ( + ( + ( - ( + y))))) >>> 0)) === ((Math.atan2((Math.hypot((((Number.MIN_VALUE ** y) | 0) && ( + Math.fround((Math.fround(x) + y)))), x) | 0), (mathy2(y, (Math.hypot((( - y) >>> 0), y) >>> 0)) | 0)) | 0) >>> 0))))); }); testMathyFunction(mathy3, [Math.PI, 42, -(2**53-2), -(2**53), Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff, 0x100000000, 1.7976931348623157e308, -0x080000000, 0x100000001, -1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, -(2**53+2), 0x080000000, 0, -0x0ffffffff, -Number.MAX_VALUE, -0x100000000, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, 0/0, 1, 2**53, -Number.MIN_SAFE_INTEGER, 2**53+2, 1/0]); ");
/*fuzzSeed-116111302*/count=603; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0(((( ! ((((Math.atanh(( + x)) >>> 0) + Math.fround(Math.round(Math.fround((( ! ( + Math.cos(x))) >>> 0))))) >>> 0) >>> 0)) >= Math.fround(( + Math.fround(mathy0(Math.fround(mathy0(x, x)), Math.fround(y)))))) >>> 0), (( ~ (Math.max(( ~ x), Math.asinh(Math.fround(x))) | 0)) | 0)); }); testMathyFunction(mathy1, /*MARR*/[0x40000000,  /x/g , 0x40000000, 0x40000000, new Boolean(true),  /x/g , 0x40000000, new Boolean(true), new Boolean(true),  /x/g , 0x40000000, new Boolean(true),  /x/g , 0x40000000, 0x40000000, new Boolean(true), new Boolean(true)]); ");
/*fuzzSeed-116111302*/count=604; tryItOut("testMathyFunction(mathy1, [1.7976931348623157e308, 0x080000000, -(2**53), 2**53-2, -0, -0x07fffffff, 0x100000000, 0.000000000000001, 0/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, 2**53, -Number.MAX_VALUE, 1/0, 2**53+2, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), -Number.MIN_VALUE, -0x100000000, 0x080000001, 0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, 0x0ffffffff, Math.PI, -Number.MAX_SAFE_INTEGER, 1, -(2**53+2), -0x080000000, -1/0]); ");
/*fuzzSeed-116111302*/count=605; tryItOut("v1 = evalcx(\"function f0(b2)  { \\\"use asm\\\"; yield  \\\"\\\"  } \", g0);");
/*fuzzSeed-116111302*/count=606; tryItOut("mathy5 = (function(x, y) { return Math.expm1(Math.min(( + y), Math.imul(Math.fround(( + (( - y) >>> 0))), (Math.clz32(( + ( + (( + x) <= Math.fround(a))))) | 0)))); }); testMathyFunction(mathy5, [0x080000000, 2**53+2, -0, 2**53, -(2**53-2), -0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -0x100000001, -1/0, -0x080000000, 0x100000000, 0/0, -0x100000000, 1/0, 0x080000001, 2**53-2, 0x0ffffffff, 0.000000000000001, 0x07fffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, 42, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), -0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-116111302*/count=607; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((Math.atan(( + (( + x) * ( + mathy0(( + Math.min((Math.pow((x >>> 0), x) >>> 0), -1/0)), ( + x)))))) ** (( + ((Math.fround(( + ( ! x))) + y) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-(2**53+2), -Number.MIN_VALUE, 2**53, -(2**53), -0x0ffffffff, Number.MAX_VALUE, -0x080000001, 0x080000000, 1/0, 42, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, Number.MIN_VALUE, 0x0ffffffff, -0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, -0x07fffffff, 0x080000001, -Number.MAX_VALUE, 0, 1, 0.000000000000001, -(2**53-2), 0/0, Math.PI, 2**53-2, 0x100000000, 1.7976931348623157e308, -0]); ");
/*fuzzSeed-116111302*/count=608; tryItOut("mathy4 = (function(x, y) { return Math.max((( - (((Math.atan2(y, Math.fround((Math.fround((mathy2(x, (Math.PI | 0)) | 0)) >>> Math.fround(42)))) | 0) > Math.pow(( + (x >= ( + y))), Math.fround((y | (x >>> 0))))) >>> 0)) >>> 0), Math.atan2((Math.fround(Math.hypot(x, -0x0ffffffff)) >>> 0), (Math.acos((Math.pow(((Math.fround(((y >>> 0) , (-Number.MIN_SAFE_INTEGER >>> 0))) >>> 0) >>> y), x) | 0)) | 0))); }); testMathyFunction(mathy4, [undefined, ({valueOf:function(){return 0;}}), true, (new Number(0)), (new Boolean(false)), null, /0/, ({valueOf:function(){return '0';}}), (new String('')), '0', ({toString:function(){return '0';}}), 0, (new Boolean(true)), NaN, 0.1, objectEmulatingUndefined(), '\\0', (function(){return 0;}), -0, 1, (new Number(-0)), '', [], '/0/', [0], false]); ");
/*fuzzSeed-116111302*/count=609; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -33554431.0;\n    var i4 = 0;\n    {\n      d1 = (9.671406556917033e+24);\n    }\n    i4 = ((0x494b1110));\n    return (((new x.charCodeAt((makeFinalizeObserver('tenured')))(x = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { throw 3; }, hasOwn: true, get: undefined, set:  \"\" , iterate: undefined, enumerate: x, keys: undefined, }; })(-17), (decodeURIComponent).call, (function(x, y) { return (( - (-0x100000000 >>> 0)) >>> 0); }))))+(0xffffffff)-(((((d0))) ^ ((((0x60b6b714)) & ((-0x8000000))) % (~((0xffffffff)*-0xe916c)))) != (0x7fffffff))))|0;\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [1/0, -0x100000001, 0.000000000000001, 0x080000000, -(2**53-2), 0x100000001, 42, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000001, 0, -1/0, -0x100000000, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0, 0x100000000, 2**53+2, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), -0x0ffffffff, -(2**53+2), Math.PI, -0x080000000, 1, 0/0, Number.MIN_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=610; tryItOut("var e = let (y) this, x, wqykup, a, NaN, x;o0.f0 = Proxy.createFunction(h0, f2, f1);");
/*fuzzSeed-116111302*/count=611; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=612; tryItOut("for (var p in b1) { try { print(uneval(a0)); } catch(e0) { } try { m1.delete(this.t2); } catch(e1) { } try { o2.m0.set((21.watch(\"caller\", (4277))), b1); } catch(e2) { } Object.preventExtensions(i1); }");
/*fuzzSeed-116111302*/count=613; tryItOut("h1 = {};");
/*fuzzSeed-116111302*/count=614; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?!(^|[^].+(^){4})^(?:.)))\", \"gim\"); var s = \"\\n\\u00e8\\n\\ucf1b\\n\\n\\n\\u00e8\\n\\ucf1b\\n\\n\\n\\u00e8\\n\\ucf1b\\n\\n\\n\\u00e8\\n\\ucf1b\\n\\n\\n\\n\\n\\n\"; print(uneval(s.match(r))); \nthis.h2.getOwnPropertyDescriptor = (function() { try { for (var p in i2) { try { e2 + a2; } catch(e0) { } try { for (var v of p0) { try { i1 + t2; } catch(e0) { } e0.has(m2); } } catch(e1) { } b0 = t2[4]; } } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(this.b2, a0); } catch(e1) { } const m0 = new Map; return b2; });\n");
/*fuzzSeed-116111302*/count=615; tryItOut("{v0 = Array.prototype.some.call(this.o2.a1, (function() { try { ; } catch(e0) { } v1 = t1.length; throw v2; }));M:for(e in /(?:..)|[^]*|(?!\\W)*|(?:[^-R\u00b4-\u4e9b]^?)*?[^]+\u85e8+[^][^][^\\W]+?|([^][B-\\\u05c8\u5121-\\t]|[^]{4,8})\\D?/i) {s2 += 'x';p2 = this.a2[v1]; } }");
/*fuzzSeed-116111302*/count=616; tryItOut("\"use strict\"; let o1.h2 = {};");
/*fuzzSeed-116111302*/count=617; tryItOut("mathy2 = (function(x, y) { return Math.pow(Math.cosh((( + Math.min(( + -1/0), (( - Math.fround((2**53+2 ? x : ( + ( - ( + 0)))))) | 0))) >>> 0)), ( + ( ! ( + (y >>> Math.fround(Math.min((y >>> 0), ( + Math.hypot(x, ( + x)))))))))); }); testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-116111302*/count=618; tryItOut("var sgreda, x = x, window = decodeURIComponent;g2.v2 = (g1 instanceof e2);");
/*fuzzSeed-116111302*/count=619; tryItOut("\"use strict\"; o0.s0 = '';");
/*fuzzSeed-116111302*/count=620; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( ~ (mathy1((Math.tanh(x) >>> 0), mathy3(x, (Math.asin(y) | 0))) | 0))); }); ");
/*fuzzSeed-116111302*/count=621; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=622; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=623; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[x % x, x % x, new Number(1.5), x % x, new Number(1.5), new Number(1.5), x % x, new Number(1.5), new Number(1.5), new Number(1.5), x % x, x % x, x % x, x % x, x % x, new Number(1.5), x % x, new Number(1.5), x % x, x % x, new Number(1.5), new Number(1.5), new Number(1.5), x % x, x % x, x % x, x % x, x % x, x % x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x % x, x % x, new Number(1.5), x % x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x % x, new Number(1.5), x % x, x % x, new Number(1.5), x % x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, x % x, new Number(1.5), x % x, x % x, x % x, x % x, x % x, x % x, x % x, new Number(1.5), new Number(1.5), x % x, x % x, new Number(1.5), new Number(1.5), new Number(1.5), x % x, x % x, x % x, x % x, new Number(1.5), new Number(1.5), x % x, new Number(1.5), new Number(1.5), x % x, x % x, x % x, new Number(1.5), x % x, new Number(1.5), new Number(1.5), new Number(1.5), x % x, new Number(1.5), new Number(1.5), x % x, new Number(1.5), x % x, new Number(1.5), x % x, x % x, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), x % x]) { v0 = Array.prototype.reduce, reduceRight.call(g2.o1.a1); }");
/*fuzzSeed-116111302*/count=624; tryItOut("mathy4 = (function(x, y) { return ( - (((x ** Math.cos(x)) | 0) | ( ~ Math.log10(y)))); }); testMathyFunction(mathy4, [1.7976931348623157e308, -(2**53-2), 1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 0, 42, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, Number.MAX_VALUE, 0x07fffffff, 0x100000000, Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), 2**53+2, -0x100000001, -(2**53), -0x080000000, 0x0ffffffff, -0x100000000, 1, -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE, 0.000000000000001, -0, -1/0, -0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=625; tryItOut("const m1 = new Map;");
/*fuzzSeed-116111302*/count=626; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.min(((( + (( ! (2**53 | 0)) | 0)) ^ Math.pow(Math.fround((( ! ((Math.hypot(Math.fround(0x100000000), (0x080000000 >>> 0)) >>> 0) >>> 0)) >>> 0)), ( + Math.fround(( - Math.fround(y)))))) | 0), ( + ( ! (((( + ( + Math.abs(( + y)))) ^ (mathy2((Math.abs((y | 0)) | 0), (y | 0)) >>> 0)) || (x || (x ? x : x))) | 0)))); }); testMathyFunction(mathy5, [-(2**53), 0/0, 1, 0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, 42, 2**53-2, Math.PI, 0x100000000, 0x0ffffffff, Number.MIN_VALUE, -0x080000001, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0x100000001, -0x0ffffffff, -Number.MIN_VALUE, 0, 2**53, -Number.MAX_VALUE, 1/0, 0x07fffffff, -0x080000000, -0x100000000]); ");
/*fuzzSeed-116111302*/count=627; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var abs = stdlib.Math.abs;\n  var asin = stdlib.Math.asin;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (+pow(((9.671406556917033e+24)), ((+pow(((((1.125)) * (()))), ((+abs(((-17179869183.0))))))))));\n    }\n    /*FFI*/ff(((+asin(((-1.0))))), ((((0xe910c526)-(0xf97e88a8)) ^ ((Int16ArrayView[2])))), ((0x7ca2a9a0)), ((imul((/*FFI*/ff()|0), ((0xefc65d4d) < (0x954eae0e)))|0)));\n    return (((i1)+((i1) ? (i1) : ((((!(0x7d60d893))) & (((0x0) >= (0x0))+(i1)))))+(0xcda65d3b)))|0;\n  }\n  return f; })(this, {ff: Date.prototype.toJSON}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-(2**53+2), -1/0, 2**53, -0x080000000, 2**53-2, -0x100000001, Math.PI, -0, 0x080000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x080000000, 1/0, 1.7976931348623157e308, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_VALUE, 0x0ffffffff, 0, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 1, -(2**53), 42, -0x100000000, -0x080000001]); ");
/*fuzzSeed-116111302*/count=628; tryItOut("/*tLoop*/for (let y of /*MARR*/[ /x/ ,  /x/ , null, null, true, true,  /x/ , true, true, null, true, true, true, true, null,  /x/ ,  /x/ ,  /x/ ,  /x/ , null,  /x/ ,  /x/ , null,  /x/ , true,  /x/ , true,  /x/ , true,  /x/ ,  /x/ , null, true, null, null,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , null, null, true,  /x/ , null, null, true, null, null,  /x/ , true, true, true,  /x/ ,  /x/ , null, true,  /x/ ,  /x/ ,  /x/ , true,  /x/ ,  /x/ , null, null, null, true,  /x/ , null,  /x/ , null, true,  /x/ ,  /x/ , true, true, null,  /x/ ,  /x/ ,  /x/ ,  /x/ , true, true,  /x/ ,  /x/ , null,  /x/ ,  /x/ ,  /x/ , null,  /x/ , null,  /x/ ,  /x/ , true,  /x/ , null,  /x/ , null, true,  /x/ ,  /x/ , null,  /x/ , true, null, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, null]) { true%=({/*TOODEEP*/})(d); }");
/*fuzzSeed-116111302*/count=629; tryItOut("a1.splice(NaN, 11);");
/*fuzzSeed-116111302*/count=630; tryItOut("mathy2 = (function(x, y) { return Math.exp((Math.fround(Math.pow((( + Math.imul(( + x), ( + (Math.pow(( ~ (((Math.imul(y, x) >>> 0) - (x >>> 0)) >>> 0)), x) | 0)))) | 0), (Math.log((( + y) , ( + Math.ceil(( + y))))) >>> 0))) >>> 0)); }); testMathyFunction(mathy2, [0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, -(2**53), Math.PI, 0x100000000, 2**53+2, -0x07fffffff, 1.7976931348623157e308, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, -1/0, 0/0, 0x0ffffffff, 42, 1/0, -0x100000000, -(2**53-2), -0, 0x080000001, 0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, -0x080000001, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001]); ");
/*fuzzSeed-116111302*/count=631; tryItOut("const iokbdg, x = (4277), NaN;Object.prototype.watch.call(v0, \"delete\", (function() { try { v2 = (o2 instanceof t2); } catch(e0) { } try { Object.preventExtensions(g0.o2.a2); } catch(e1) { } v0 = g2.eval(\"g2.a1 + '';\"); return t2; }));");
/*fuzzSeed-116111302*/count=632; tryItOut("let(w = (4277), \u3056, sqfpuy, NaN, asmqse) { }/*hhh*/function wzjztn(x, a, ...NaN){print(p2);}/*iii*/a2.reverse();");
/*fuzzSeed-116111302*/count=633; tryItOut("for(var y = intern(c) in true) {new RegExp(\"(?!$)+?\", \"g\");(this); }");
/*fuzzSeed-116111302*/count=634; tryItOut("with(new (window)( \"\" ,  \"\" )){\u000cfor(var a = window in 22) {e2 = new Set(m0); }return window; }");
/*fuzzSeed-116111302*/count=635; tryItOut("for (var v of g1.o1) { try { v0 = (g0.e2 instanceof e0); } catch(e0) { } try { o2 + ''; } catch(e1) { } b0 = new ArrayBuffer(0); }\n");
/*fuzzSeed-116111302*/count=636; tryItOut("/*hhh*/function qsjgms(){for (var v of o2.g1) { try { t1.set(t0, ({valueOf: function() { Array.prototype.popreturn 13; }})); } catch(e0) { } a2 = prototype; }}/*iii*/(\"\\u8031\");");
/*fuzzSeed-116111302*/count=637; tryItOut("\"use strict\"; ");
/*fuzzSeed-116111302*/count=638; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.sinh((Math.fround(((( ~ Math.max((x | 0), ((Math.fround(0x0ffffffff) ? (x | 0) : /*FARR*/[]) >>> 0))) | 0) < Math.fround(Math.pow(((Math.exp(x) >>> 0) && y), ((Math.fround(Math.clz32(( + Math.imul(( + y), ( + x))))) >>> 0) >>> ( + Math.max(( + Math.sin(y)), ( + x)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, 0x080000001, -0x100000000, -0x100000001, -(2**53+2), -0x07fffffff, -1/0, 2**53+2, 42, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, 0, 0.000000000000001, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, -0x0ffffffff, -(2**53-2), 1/0, 0/0, 0x100000000, Math.PI, 0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=639; tryItOut("this.s2 = s0.charAt(13);");
/*fuzzSeed-116111302*/count=640; tryItOut("/*tLoop*/for (let y of /*MARR*/[new Number(1), new Number(1), /*UUV2*/(a.sin = a.keys), /*UUV2*/(a.sin = a.keys), /*UUV2*/(a.sin = a.keys)]) { b2 = new ArrayBuffer(5); }");
/*fuzzSeed-116111302*/count=641; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.min((( ! ( + Math.pow(-Number.MAX_VALUE, ( ! y)))) >= ( + (( + (( ~ (Math.fround(Math.sign(Math.fround(0x100000001))) >>> 0)) >>> 0)) ^ ((((x >>> 0) == ((1/0 ? 0x080000000 : y) >>> 0)) | x) | 0)))), (Math.cosh(((( - (Math.cosh(Math.log10(y)) ? x : ( + Math.imul(x, ( + x))))) | 0) !== ( ! mathy1(y, 0x0ffffffff)))) | 0)); }); testMathyFunction(mathy4, [-0x100000000, 2**53-2, -1/0, -Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53), -0x07fffffff, 2**53+2, 1.7976931348623157e308, Math.PI, -0x100000001, 2**53, 0x080000001, Number.MIN_SAFE_INTEGER, 42, -Number.MAX_VALUE, 0x080000000, 0x100000001, -(2**53-2), 0, 0x07fffffff, -0, -0x0ffffffff, -0x080000000, -(2**53+2), Number.MAX_VALUE, 1/0, 0.000000000000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 1, 0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=642; tryItOut("var xhalzg = new ArrayBuffer(8); var xhalzg_0 = new Int8Array(xhalzg); print(xhalzg_0[0]); xhalzg_0[0] = -9; var xhalzg_1 = new Uint8ClampedArray(xhalzg); print(xhalzg_1[0]); xhalzg_1[0] = 17; var xhalzg_2 = new Int16Array(xhalzg); var xhalzg_3 = new Float32Array(xhalzg); xhalzg_3[0] = -20; var xhalzg_4 = new Uint32Array(xhalzg); print(xhalzg_4[0]); xhalzg_4[0] = -6; var xhalzg_5 = new Uint8Array(xhalzg); print(xhalzg_5[0]); xhalzg_5[0] = 23; var xhalzg_6 = new Float32Array(xhalzg); xhalzg_6[0] = -2; for (var v of this.g2) { try { g1.a1.shift(); } catch(e0) { } try { t2 = new Int32Array(t2); } catch(e1) { } try { a2.sort(\"\\uA6FC\", s1, e1); } catch(e2) { } for (var v of this.f1) { this.s1 = ''; } }print(xhalzg_3);a0.push(f1, m0, g0, a1, o1, h0, t2, /*MARR*/[ '' , eval,  '' , new Number(1), new Number(1), new Number(1),  '' , eval, eval, new Number(1), eval,  '' , new Number(1), eval,  '' , eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval,  '' , eval,  '' , eval, new Number(1), eval, new Number(1),  '' , new Number(1), new Number(1),  '' ,  '' , eval, eval,  '' , eval,  '' ,  '' ,  '' ,  '' ,  '' , new Number(1), new Number(1), eval,  '' ,  '' ,  '' ,  '' , new Number(1),  '' , eval,  '' , new Number(1), new Number(1), new Number(1), new Number(1),  '' ,  '' , new Number(1), new Number(1), new Number(1),  '' ,  '' , new Number(1), new Number(1),  '' , new Number(1),  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' ,  '' , new Number(1), new Number(1),  '' ].map(Promise.resolve));(\"\\u4041\"); /x/g ;a2.__proto__ = this.v0;/*RXUB*/var r = r2; var s = s1; print(uneval(s.match(r))); print(r.lastIndex); throw  '' ;");
/*fuzzSeed-116111302*/count=643; tryItOut("a2[Math.sin((x))] = e0;");
/*fuzzSeed-116111302*/count=644; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ( - (( ! (( + (( + ( + mathy0(( + Math.sqrt(Math.sign(y))), Math.PI))) > (( + Math.log10(Math.fround(y))) >>> 0))) | 0)) | 0)); }); testMathyFunction(mathy5, /*MARR*/[function(){},  '\\0' , function(){},  '\\0' , function(){}, x, function(){},  '\\0' ,  '\\0' , function(){},  '\\0' , x, x, x, function(){}, function(){}, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  '\\0' ,  '\\0' ,  '\\0' , x, function(){},  '\\0' , function(){}, function(){}, function(){}, function(){}, x,  '\\0' , function(){}, function(){},  '\\0' , x, function(){}, function(){},  '\\0' ,  '\\0' , x,  '\\0' , function(){},  '\\0' ,  '\\0' ,  '\\0' , function(){},  '\\0' , function(){}, function(){}, x,  '\\0' ,  '\\0' , x, function(){}, x, function(){}, function(){}, x, function(){},  '\\0' , function(){}, function(){},  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , x,  '\\0' , function(){},  '\\0' , function(){},  '\\0' , x,  '\\0' , function(){}, function(){}, function(){}, function(){},  '\\0' , function(){}, x,  '\\0' ,  '\\0' ,  '\\0' , function(){}, x, x, function(){}, x]); ");
/*fuzzSeed-116111302*/count=645; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.log1p(Math.fround(Math.fround(mathy1(mathy3(mathy1(( ! (( + (y >>> 0)) >>> 0)), Math.hypot(x, -0)), y), (Math.fround(Math.min(x, Math.fround(Math.trunc((-Number.MIN_VALUE == 0))))) ? ( ! Math.imul(Math.pow(0x100000001, (mathy3(y, y) | 0)), y)) : Math.clz32((( ~ (( + Math.hypot(( + x), ( + 0x080000000))) >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy4, /*MARR*/[NaN, NaN, undefined, NaN, NaN, NaN, undefined, undefined, NaN, NaN, NaN, undefined, NaN, NaN, NaN, undefined, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN, undefined, NaN, NaN, NaN, NaN, undefined, NaN, undefined, undefined, NaN, NaN, NaN]); ");
/*fuzzSeed-116111302*/count=646; tryItOut("\"use strict\"; const d, w, rkutwd, a, y, y;m0.get(m2);");
/*fuzzSeed-116111302*/count=647; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( - Math.log1p(Math.fround((mathy0(( + ( ! Math.fround(-0x100000000))), ( + Math.max(( ! y), Math.fround(Math.expm1(Math.fround(-(2**53-2))))))) >>> 0)))); }); testMathyFunction(mathy3, [0x07fffffff, -0x100000001, Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1/0, 1, -Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, 2**53, -0x080000000, -(2**53), 0, 0x100000001, 0x080000001, 0.000000000000001, 0x100000000, 42, Math.PI, -0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, 2**53+2, -(2**53-2), -1/0, 2**53-2, -0, -Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=648; tryItOut("m0.set(t1, (Math.cos(( + (e - eval))) << ( + (( + Math.log10(eval(\"a2 + g2;\", this.__defineGetter__(\"b\", \"\\u9C7B\")))) < ( + (Math.exp(x) | ( + Math.abs(( + x)))))))))");
/*fuzzSeed-116111302*/count=649; tryItOut("for (var v of t0) { try { x = a0; } catch(e0) { } Array.prototype.reverse.call(a2, i1); }");
/*fuzzSeed-116111302*/count=650; tryItOut("\"use strict\"; L:switch(new Error( /x/g , (/*RXUE*//(?!(((?:[^])\\2|[][^\\d\\d]|(?!\uf1c9{2}))))/i.exec(\"\")))) { default: break; /* no regression tests found */ }");
/*fuzzSeed-116111302*/count=651; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.fround(Math.max(Math.atan2(mathy2(Math.fround(( + Math.min(Number.MAX_SAFE_INTEGER, x))), (x ? Math.fround(( ~ (Math.atan(Math.fround(2**53-2)) | 0))) : y)), (0x100000001 && (Math.log10((Math.fround(Math.log1p(Math.fround(y))) >>> 0)) >>> 0))), Math.hypot(Math.asin(( + x)), (( ~ Math.expm1((0.000000000000001 === y))) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[ '\\0' ]); ");
/*fuzzSeed-116111302*/count=652; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]\", \"i\"); var s = ({}); print(uneval(r.exec(s))); ");
/*fuzzSeed-116111302*/count=653; tryItOut("\"use asm\"; Array.prototype.forEach.call(a1, offThreadCompileScript);");
/*fuzzSeed-116111302*/count=654; tryItOut("testMathyFunction(mathy5, [0, -0, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, 0x0ffffffff, -0x100000000, 0x100000000, -(2**53-2), 2**53, -0x0ffffffff, 2**53-2, -0x07fffffff, 0x080000001, Math.PI, -0x100000001, -0x080000001, 1.7976931348623157e308, 0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), -0x080000000, 0/0, 1/0, Number.MAX_VALUE, 0x07fffffff, 1, 42]); ");
/*fuzzSeed-116111302*/count=655; tryItOut("\"use strict\"; /*MXX1*/o1 = g0.Uint32Array.prototype.BYTES_PER_ELEMENT;\nprint(Math.unwatch(\"keys\"));\n");
/*fuzzSeed-116111302*/count=656; tryItOut("e1.add(v0);");
/*fuzzSeed-116111302*/count=657; tryItOut("mathy4 = (function(x, y) { return (Math.acos((( + Math.fround(( + (( - Math.cos(0x07fffffff)) == Math.fround(( ~ Math.fround(( ~ mathy2(Math.fround(x), y))))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [1, Math.PI, -(2**53+2), 0x080000000, 2**53, -0x080000001, -0x07fffffff, 0x080000001, -0x100000000, -(2**53-2), 42, -0x100000001, 0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 2**53+2, -Number.MIN_VALUE, 0/0, 0x07fffffff, 1/0, Number.MAX_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, 0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -1/0]); ");
/*fuzzSeed-116111302*/count=658; tryItOut("e1.delete(o1);");
/*fuzzSeed-116111302*/count=659; tryItOut("mathy4 = (function(x, y) { return (((Math.imul(Math.min(mathy0((x | 0), y), mathy2(y, (( + Math.hypot(( + y), ( + -Number.MIN_VALUE))) >>> 0))), Math.fround(( ~ y))) << (( ! mathy0(Number.MIN_VALUE, -(2**53))) << (mathy1((mathy2(( + x), x) | 0), Math.fround(0/0)) >>> 0))) , ( ! Math.fround(Math.min((mathy1((y | 0), ((x ? 1/0 : (x ? 42 : 0x080000000)) | 0)) | 0), x)))) && Math.min((Math.hypot(((1.7976931348623157e308 <= y) >>> 0), (( ~ y) >>> 0)) + (Math.pow((( + ((Math.fround(Math.imul(Math.fround(y), Math.fround(y))) >>> 0) & (x >>> 0))) | 0), y) | 0)), (Math.atan((( + Math.imul((( - (x >>> 0)) >>> 0), ( + (( + Math.fround(( + x))) >>> 0)))) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [0.000000000000001, 0/0, -0, 0x080000000, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 1, -0x100000000, -(2**53+2), 2**53-2, -(2**53), 0x07fffffff, 0x100000000, -Number.MAX_VALUE, -0x080000001, 2**53+2, -1/0, Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), -0x07fffffff, Number.MIN_VALUE, 42, 0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, 1/0]); ");
/*fuzzSeed-116111302*/count=660; tryItOut("\"use strict\"; const v1 = r1.exec;");
/*fuzzSeed-116111302*/count=661; tryItOut("mathy4 = (function(x, y) { return ( - Math.acosh(((y <= Number.MAX_SAFE_INTEGER) << (Math.fround(( - (( + Math.pow(Number.MAX_VALUE, x)) | 0))) | 0)))); }); testMathyFunction(mathy4, [/0/, -0, (new Boolean(false)), 1, ({valueOf:function(){return '0';}}), '', (new Boolean(true)), (function(){return 0;}), [], ({valueOf:function(){return 0;}}), '\\0', (new String('')), 0.1, '0', true, undefined, (new Number(0)), NaN, objectEmulatingUndefined(), [0], 0, '/0/', null, (new Number(-0)), ({toString:function(){return '0';}}), false]); ");
/*fuzzSeed-116111302*/count=662; tryItOut("a0.sort((function() { try { for (var p in o0) { try { v2 = evalcx(\"h2.getPropertyDescriptor = f2;\", g0); } catch(e0) { } a2 = g1.g2.objectEmulatingUndefined(); } } catch(e0) { } try { this.b2 = g2; } catch(e1) { } try { t2 = a0[1]; } catch(e2) { } /*ADP-1*/Object.defineProperty(g1.a0, 18, ({value: (a) = x, writable: (x % 3 != 1), configurable: true})); return e2; }), h0, this.t0);");
/*fuzzSeed-116111302*/count=663; tryItOut("\"use strict\"; \"use asm\"; /*hhh*/function ufnljo(window, b, [], w, x, x, x, x, x, \u3056, x, d = -10, e, y = \"\\u2A9B\", x, x, x, d, \u3056, eval, eval, x, e, w, d, a, e = undefined, y, w, x =  /x/ , window, \u3056 = \"\\uFAE3\", a, a, \u3056, eval = x, eval = \"\\u2B26\", NaN, e, x = window, c, \u3056, get = window, d, x, x = undefined, x, b = /\u0aeb|((?=\ue081))(?!\\u0089[^]*?)[^]{1,}?[\\u17a1\\S\\u4Ec2-\uf6da\ue926]?|(?:(?!(?:^))+)(?!(?:$))/gym, c, x, y, y, y, x, x, \u3056, z = \"\\uAAF5\", x, x, w, y = this, getter, x = -9, x, x = \"\\uDB43\", a, this.d = new RegExp(\".\", \"gym\"), y, \u3056, y, eval, b, z, b, d, window, x, x, x =  \"\" , c = -16, x, x, b, w, x, window, e, window = \"\\uE052\", eval =  /x/g , y, x, NaN =  /x/g , e, a, x, x, e = [1], y, x){Array.prototype.unshift.apply(o0.a0, [e2, g2.i1, o1, m0]);}/*iii*/v0 = g0.runOffThreadScript();");
/*fuzzSeed-116111302*/count=664; tryItOut("{do Array.prototype.push.apply(a2, [b0, this.m1, o0.a1]); while((NaN++) && 0); }");
/*fuzzSeed-116111302*/count=665; tryItOut("mathy5 = (function(x, y) { return ( + (Math.sign((( + ( + ( + mathy1(-0x080000000, Math.atan2(Math.fround(Math.pow(y, x)), x))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -Number.MIN_VALUE, -0x100000001, 0x100000000, 0.000000000000001, -0x080000000, -0x100000000, -0x0ffffffff, -0x080000001, 1, 0, 2**53, -Number.MIN_SAFE_INTEGER, 42, 0x080000000, 0/0, 1/0, -(2**53), -(2**53+2), 0x100000001, Number.MAX_VALUE, -0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), Math.PI, 2**53+2, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, Number.MIN_VALUE, -1/0, 0x07fffffff, -0]); ");
/*fuzzSeed-116111302*/count=666; tryItOut("mathy1 = (function(x, y) { return ( + mathy0((Math.expm1(Math.fround((( + ( ~ Math.fround(( + (x , ( + -(2**53))))))) != (( - ( ~ x)) >>> 0)))) | 0), ( - Math.min((( - 0x0ffffffff) >>> 0), x)))); }); testMathyFunction(mathy1, [0/0, 1/0, 0x080000000, Number.MIN_VALUE, -(2**53), 0x080000001, 1, -Number.MIN_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -(2**53+2), 0x0ffffffff, -Number.MAX_VALUE, -(2**53-2), -1/0, 0x100000001, -0x080000000, 2**53-2, 0, 0x07fffffff, -0, 2**53, 0.000000000000001, -0x100000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MIN_VALUE, 42]); ");
/*fuzzSeed-116111302*/count=667; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + Math.atan2((Math.log2(((( + ( + ( ! (( ~ Math.fround(y)) >>> 0)))) | ( + x)) | 0)) | 0), ( + (((mathy1(y, ( + Math.tanh(y))) >>> 0) >= (( - ( + Math.log1p((Math.tan(Math.hypot(x, (x >>> 0))) | 0)))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy3, [NaN, [0], 1, (new Number(-0)), [], objectEmulatingUndefined(), ({toString:function(){return '0';}}), '/0/', ({valueOf:function(){return 0;}}), (new Number(0)), '0', 0, (function(){return 0;}), /0/, '', (new Boolean(true)), ({valueOf:function(){return '0';}}), false, true, null, 0.1, -0, (new String('')), undefined, (new Boolean(false)), '\\0']); ");
/*fuzzSeed-116111302*/count=668; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.max(Math.log10(( + Math.pow(( + Math.pow(Math.pow(x, y), ( + ( ~ ( + 2**53+2))))), ( + (( - (x | 0)) | 0))))), Math.fround(Math.min(( + Math.asinh((( + mathy1(( + ( ~ ((Math.sign((y | 0)) , y) >>> 0))), ( + 0))) >>> 0))), (Math.min(((( ~ Math.asin(( + (Number.MIN_VALUE ? x : y)))) >>> 0) | 0), (Math.acosh(x) | 0)) | 0)))); }); testMathyFunction(mathy3, [0, -0, 0x080000000, -1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0/0, 1, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000001, 2**53-2, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, -0x080000000, 0x100000000, -(2**53-2), Math.PI, -0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53+2), -0x100000000, 0x100000001, -(2**53), 1/0, Number.MAX_VALUE, 42, 2**53, -0x0ffffffff]); ");
/*fuzzSeed-116111302*/count=669; tryItOut("s1 += s2;");
/*fuzzSeed-116111302*/count=670; tryItOut("\"use strict\"; for (var v of this.f2) { try { v1 = g1.runOffThreadScript(); } catch(e0) { } try { for (var v of m2) { this.g0 + ''; } } catch(e1) { } try { g2.i0.send(i2); } catch(e2) { } selectforgc(o1); }");
/*fuzzSeed-116111302*/count=671; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((mathy0((Math.fround(( - (( ! (x >>> 0)) >>> 0))) | 0), (Math.min(( + ( + Math.fround(Math.tan(Math.fround(Math.max((x ? y : x), x)))))), (y >>> 0)) >>> 0)) | 0) == Math.fround(( - Math.fround(Math.fround(Math.log2(mathy3(y, x))))))); }); ");
/*fuzzSeed-116111302*/count=672; tryItOut("\"use strict\"; /*RXUB*/var r = r1; var s = s0; print(s.replace(r, x)); ");
/*fuzzSeed-116111302*/count=673; tryItOut("mathy5 = (function(x, y) { return Math.ceil((Math.cbrt((Math.sign((( + (( + (Math.fround(x) ? Math.fround(x) : ( + y))) | 0)) || y)) >>> 0)) | 0)); }); testMathyFunction(mathy5, [({valueOf:function(){return '0';}}), undefined, true, ({valueOf:function(){return 0;}}), 0, '0', null, '/0/', (new Boolean(false)), false, objectEmulatingUndefined(), '', '\\0', 0.1, -0, (function(){return 0;}), NaN, [0], 1, (new Number(0)), (new Boolean(true)), (new Number(-0)), (new String('')), /0/, ({toString:function(){return '0';}}), []]); ");
/*fuzzSeed-116111302*/count=674; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=675; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.log2(( + Math.min(( + ( + Math.log10(( + (Math.asin((( ~ Math.hypot((2**53 * x), x)) | 0)) | 0))))), ( + (Math.atanh(Math.fround(Math.sign(y))) >>> 0))))); }); testMathyFunction(mathy0, ['', (new Number(-0)), true, NaN, 1, '\\0', ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), '0', (new Boolean(true)), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), (new String('')), /0/, 0.1, (new Boolean(false)), false, [0], null, '/0/', undefined, -0, (new Number(0)), (function(){return 0;}), [], 0]); ");
/*fuzzSeed-116111302*/count=676; tryItOut("Object.prototype.unwatch.call(p1, \"13\");");
/*fuzzSeed-116111302*/count=677; tryItOut(";function NaN()(-5.watch(\"includes\", /*wrap3*/(function(){ \"use strict\"; var eapzuo = true; (Function)(); }))).throw(x)/*infloop*/for(let window in window) /*vLoop*/for (wofcuj = 0; wofcuj < 34; ++wofcuj) { c = wofcuj; print( /x/ ); } ");
/*fuzzSeed-116111302*/count=678; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.min(( + Math.sqrt(( + Math.fround(mathy2(Math.fround(( - Math.cosh((y ? -Number.MAX_SAFE_INTEGER : ( + x))))), Math.fround(y)))))), ( ~ (Math.tan(x) | 0))); }); testMathyFunction(mathy4, [-1/0, 0x0ffffffff, 0x080000001, Math.PI, 1.7976931348623157e308, -0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, 0x080000000, 2**53, 42, -(2**53), Number.MAX_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53+2), 1, 0.000000000000001, -(2**53-2), -0x080000000, 2**53+2, 0/0, -0, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1/0]); ");
/*fuzzSeed-116111302*/count=679; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.hypot(( ! Math.fround((Math.fround(Math.cos(x)) ? Math.fround(x) : Math.fround(((x | 0) > ( + y)))))), mathy1(( + Math.asinh(( + (Math.acosh((y >>> 0)) >>> 0)))), Math.fround(Math.exp(( - (( ~ ( + y)) >>> 0)))))); }); testMathyFunction(mathy5, [-0x080000000, 0x0ffffffff, 0x100000000, 2**53+2, 0/0, -0x080000001, 42, 1, Math.PI, -0x100000000, -0x07fffffff, 2**53-2, -0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, 0x100000001, -Number.MIN_VALUE, -1/0, -0, Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0, Number.MAX_VALUE, -(2**53), 0.000000000000001, 0x080000001, -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53]); ");
/*fuzzSeed-116111302*/count=680; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=681; tryItOut("/*RXUB*/var r = /([^]+){1,5}/yi; var s = /(?=(?:[^]{2,5}|\\B*){4,7})/gim; print(s.match(r)); print(r.lastIndex); \nprint(x);\ns2 += 'x';\n\n");
/*fuzzSeed-116111302*/count=682; tryItOut("v2 = evaluate(\"a1.splice(NaN, v1, f2, a1, ({}));\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 3 == 0), noScriptRval: ({})(Math.sin(-24)), sourceIsLazy: true, catchTermination: (x % 2 != 1) }));");
/*fuzzSeed-116111302*/count=683; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use asm\"; return Math.atan((( + (Math.cosh(x) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, [-0x07fffffff, 0x07fffffff, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0, 0x0ffffffff, 2**53, -(2**53-2), 1/0, 0.000000000000001, 2**53-2, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1, 42, -(2**53), -0, Number.MIN_SAFE_INTEGER, 0x100000000, 0/0, Number.MAX_VALUE, 0x080000001, -0x080000000, 0x080000000, -1/0, -0x100000000, 0x100000001, -(2**53+2), Math.PI, 2**53+2]); ");
/*fuzzSeed-116111302*/count=684; tryItOut("o0.v0 = (b1 instanceof g1);");
/*fuzzSeed-116111302*/count=685; tryItOut("mathy4 = (function(x, y) { return ( ~ Math.acos(Math.ceil(x))); }); ");
/*fuzzSeed-116111302*/count=686; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = 281474976710655.0;\n    i0 = (!((i0) ? ((i0)) : (-0x8000000)));\n    i1 = (i1);\n    d2 = (+(0.0/0.0));\n    {\n      i0 = (0xfa2beb3c);\n    }\n    return +((d2));\n  }\n  return f; })(this, {ff: (function(x, y) { return ( ! 0.000000000000001); })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -0x080000000, 2**53-2, 0x07fffffff, 0, -0x080000001, 1.7976931348623157e308, 0x100000000, 0x080000001, 42, 1/0, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, Number.MIN_VALUE, -0, -1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, 1, -0x100000000, 0x100000001, 0.000000000000001, -0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000001, -Number.MIN_VALUE, -(2**53+2), Math.PI, 2**53, 0x080000000, 0/0]); ");
/*fuzzSeed-116111302*/count=687; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    {\n      {\n        i0 = (i2);\n      }\n    }\n    return (((/*FFI*/ff(((+(0x0))), ((+(-1.0/0.0))), ((((131073.0)) - ((x.eval(\"/* no regression tests found */\").eval(\"/* no regression tests found */\"))))), (((({/*toXFun*/toString: function() { return  /x/ ; },  set \"-24\"(a)\"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    return +((Float64ArrayView[((((!(0xb1cd3267))+(0xa4a8ddd))|0) % ((-(i0)) ^ ((abs((((0xe9a9a1fa)) >> ((0xffffffff))))|0) % (imul((-0x8000000), (0xb8284017))|0)))) >> 3]));\n  }\n  return f; }).__defineSetter__(\"-23\", undefined/*\n*/)))), ((-7.555786372591432e+22)), ((((0xaca0bf29)) | ((i2)-(!(0xb95281f7))))), ((0x64619891)))|0)))|0;\n  }\n  return f; })(this, {ff: new Function}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [-1/0, 0x080000001, 1/0, 0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53+2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 42, 2**53, -(2**53-2), Number.MAX_VALUE, 0x080000000, 1, -0x100000001, -(2**53+2), 0x07fffffff, -(2**53), -0x0ffffffff, 2**53-2, 0x0ffffffff, -0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0, 1.7976931348623157e308, -0x100000000, 0/0, -0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=688; tryItOut("\"use strict\"; m0 + '';");
/*fuzzSeed-116111302*/count=689; tryItOut("x = x;/*RXUB*/var r = r0; var s = \"\\n\\n\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-116111302*/count=690; tryItOut("\"use strict\"; /*oLoop*/for (odntbt = 0, new RegExp(\"$\", \"yi\"); odntbt < 30; ++odntbt) { print(x); } ");
/*fuzzSeed-116111302*/count=691; tryItOut("selectforgc(o2.o0);");
/*fuzzSeed-116111302*/count=692; tryItOut("\"use strict\"; t2 + a0;");
/*fuzzSeed-116111302*/count=693; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -1.0;\n    var i4 = 0;\n    d0 = ((!(0xa6bb2277)) ? (+(((-0x8000000)+((0xf260de9e) ? (0xdffc7d0d) : (0xef08840a))) | (((((0xe38d3102)+(0xdae637ad)) | (((8193.0) != (-1.25)))))*0x12b1f))) : (2.4178516392292583e+24));\n    return +((d0));\n  }\n  return f; })(this, {ff: DataView.prototype.getUint32}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-116111302*/count=694; tryItOut("\"use strict\"; /*tLoop*/for (let c of /*MARR*/[new String('q'), [1],  '' , [1],  '' , Number.MAX_VALUE]) { /*RXUB*/var r = (void options('strict_mode')); var s = \"\\u0009\"; print(uneval(s.match(r)));  }");
/*fuzzSeed-116111302*/count=695; tryItOut("mathy3 = (function(x, y) { return ( - Math.log(Math.acosh((((((( + 1.7976931348623157e308) - ( + ( + Math.max(Math.fround(-0x100000000), ( + ((y >>> 0) ^ y)))))) >>> 0) ? ((mathy1(Math.tan(( + Math.clz32(( + -0x07fffffff)))), (Math.fround(((-Number.MIN_VALUE | 0) , (x | 0))) >>> 0)) >>> 0) >>> 0) : (y >>> 0)) >>> 0) | 0)))); }); ");
/*fuzzSeed-116111302*/count=696; tryItOut("m1.delete(p0);");
/*fuzzSeed-116111302*/count=697; tryItOut("print(x);");
/*fuzzSeed-116111302*/count=698; tryItOut("(65188010.5);");
/*fuzzSeed-116111302*/count=699; tryItOut("/*RXUB*/var r = /(?=.|(?=\\d+)(?=\\b\\W)|\\S{3}|((\\B))|\\B*?\\B{3,}{2,6}|.*?)?/i; var s = \"aaaaaaa\\n\\u00e2a  J\\u0094aaaaa\"; print(s.replace(r, '\\u0341', \"i\")); ");
/*fuzzSeed-116111302*/count=700; tryItOut("(Math.pow(0, new function ([y]) { }()));function y(e, NaN) { \"use strict\"; s2 += s2; } e1.has(this.p1);");
/*fuzzSeed-116111302*/count=701; tryItOut("v0 = 4;\ns0 = s2.charAt(12);\n");
/*fuzzSeed-116111302*/count=702; tryItOut("this.g1.e2 = new Set;");
/*fuzzSeed-116111302*/count=703; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=704; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( - (Math.ceil((Math.imul(( + Math.min(( + Math.ceil(y)), Math.fround(y))), Math.fround(Math.atan2((Math.tanh((x >>> 0)) >>> 0), ((x ? ((( - y) >>> 0) | 0) : 42) >>> 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [0x100000001, -Number.MIN_VALUE, -0x080000001, 42, 0x07fffffff, 0x080000000, -0x100000001, -0, 1.7976931348623157e308, Number.MAX_VALUE, -0x100000000, 0x100000000, 2**53-2, 1/0, 0/0, 1, -0x0ffffffff, -Number.MAX_VALUE, 0x080000001, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53-2), Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), Number.MIN_VALUE, -(2**53), 0, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, -0x07fffffff, 2**53, -0x080000000]); ");
/*fuzzSeed-116111302*/count=705; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.imul((Math.expm1(Math.fround(Math.atan((Math.fround(y) > Math.fround(( ! Math.fround((y < x)))))))) >>> 0), (Math.cosh(( + (-0x07fffffff | 0))) % mathy2(x, Math.log2(x)))); }); testMathyFunction(mathy3, [-0x07fffffff, -0x100000000, 0x07fffffff, 2**53+2, -(2**53+2), 2**53-2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, 0, 2**53, 0/0, Math.PI, -0x0ffffffff, -0x080000000, -(2**53-2), -1/0, -0x100000001, Number.MIN_VALUE, 1, 0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, -(2**53), 0x100000001, -0x080000001, 0x080000000, 1/0, -Number.MIN_SAFE_INTEGER, -0, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=706; tryItOut("with({}) x.name;y = a;");
/*fuzzSeed-116111302*/count=707; tryItOut("g1.offThreadCompileScript(\"\\\"use strict\\\"; g2.e0.has(m2);print(true);\");");
/*fuzzSeed-116111302*/count=708; tryItOut("m1 = new WeakMap;{Array.prototype.splice.call(a1, new RegExp(\"\\\\2\", \"i\"));t2[3]; }");
/*fuzzSeed-116111302*/count=709; tryItOut("for (var v of b0) { try { v1 = evaluate(\"Object.prototype.watch.call(v0, \\\"catch\\\", (function() { try { /*MXX3*/g1.Date.prototype.toLocaleTimeString = g1.Date.prototype.toLocaleTimeString; } catch(e0) { } /*ADP-2*/Object.defineProperty(a0, v1, { configurable: true, enumerable: false, get: (function() { for (var j=0;j<31;++j) { f0(j%3==1); } }), set: (function() { try { this.g0.v0 = 4.2; } catch(e0) { } i0 = new Iterator(this.t0, true); return v1; }) }); return v0; }));\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 22 == 16), catchTermination: true })); } catch(e0) { } try { delete h0.delete; } catch(e1) { } i0 = new Iterator(f1); }");
/*fuzzSeed-116111302*/count=710; tryItOut("for (var p in o0.t2) { v0 = -0; }");
/*fuzzSeed-116111302*/count=711; tryItOut("\"use strict\"; m0.has(v0);");
/*fuzzSeed-116111302*/count=712; tryItOut("b2 = x;");
/*fuzzSeed-116111302*/count=713; tryItOut("(undefined /= x ** (delete y.NaN));");
/*fuzzSeed-116111302*/count=714; tryItOut("\"use strict\"; var jxpeul = new SharedArrayBuffer(4); var jxpeul_0 = new Uint8ClampedArray(jxpeul); jxpeul_0[0] = this; var jxpeul_1 = new Int16Array(jxpeul); jxpeul_1[0] = 11; var jxpeul_2 = new Uint16Array(jxpeul); print(jxpeul_2[0]); jxpeul_2[0] = -28; var jxpeul_3 = new Uint16Array(jxpeul); jxpeul_3[0] = -11; var jxpeul_4 = new Float64Array(jxpeul); jxpeul_4[0] = -9; o2 = new Object;this.h1.iterate = f1;");
/*fuzzSeed-116111302*/count=715; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=716; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ~ (((( ~ (Math.fround((0 | (( - Math.fround((y ? 1.7976931348623157e308 : y))) | 0))) >>> 0)) >>> 0) | 0) | ( + (( - (( ! ((-0x0ffffffff | 0) && y)) | 0)) | 0)))); }); testMathyFunction(mathy5, [0x080000001, -0x100000000, 1.7976931348623157e308, -0x080000000, 0, -Number.MIN_VALUE, -(2**53+2), 0.000000000000001, -0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, -(2**53-2), 42, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -Number.MAX_VALUE, 1, 0/0, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 1/0, 0x07fffffff, -0x0ffffffff, 2**53+2, 0x100000000, -0x100000001, -0, 2**53, -0x080000001]); ");
/*fuzzSeed-116111302*/count=717; tryItOut("var lwelrx = new SharedArrayBuffer(8); var lwelrx_0 = new Int8Array(lwelrx); lwelrx_0[0] = -3; var lwelrx_1 = new Uint8Array(lwelrx); lwelrx_1[0] = -12; var lwelrx_2 = new Uint8ClampedArray(lwelrx); lwelrx_2[0] = 0x2D413CCC; var lwelrx_3 = new Int32Array(lwelrx); lwelrx_3[0] = -24; var lwelrx_4 = new Uint32Array(lwelrx); print(lwelrx_4[0]); lwelrx_4[0] = -29; var lwelrx_5 = new Int8Array(lwelrx); print(lwelrx_5[0]); var lwelrx_6 = new Float64Array(lwelrx); lwelrx_6[0] = -17; o1.g2.v0 = a1.length;v0 = h2[\"lwelrx_5\"];t2.set(t1, 16);");
/*fuzzSeed-116111302*/count=718; tryItOut("\"use strict\"; o1.o0.o2.h1.hasOwn = (function() { try { Array.prototype.push.apply(o0.a0, [e2]); } catch(e0) { } Array.prototype.shift.apply(a1, [((function \u0009(w) { d; } ).call((Element) -=  /x/ , x)), (Object.defineProperty(d, new String(\"8\"), ({configurable: true, enumerable: (void options('strict'))})))]); return e1; });");
/*fuzzSeed-116111302*/count=719; tryItOut("\"use strict\"; v0 = t1.length;");
/*fuzzSeed-116111302*/count=720; tryItOut("\"use strict\"; m2 = new Map(s0);");
/*fuzzSeed-116111302*/count=721; tryItOut("mathy2 = (function(x, y) { return ( ~ ( + Math.hypot(mathy0((x === (( + Math.fround(mathy0((x | 0), (y | 0)))) | 0)), (y | 0)), ( + ( + Math.fround(Math.expm1(x))))))); }); testMathyFunction(mathy2, [0, objectEmulatingUndefined(), (new Boolean(true)), undefined, '', '0', 1, (new Number(0)), [0], false, (new String('')), ({valueOf:function(){return 0;}}), null, NaN, ({valueOf:function(){return '0';}}), 0.1, (function(){return 0;}), -0, true, (new Number(-0)), '\\0', [], /0/, '/0/', (new Boolean(false)), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-116111302*/count=722; tryItOut("print(( /x/ .__defineSetter__(\"eval\", /*wrap3*/(function(){ \"use strict\"; var hssogw = undefined; (e)(); }))));");
/*fuzzSeed-116111302*/count=723; tryItOut("s0 = '';");
/*fuzzSeed-116111302*/count=724; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"^|^|(?!\\\\2\\\\1)\", \"gym\"); var s = \"\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-116111302*/count=725; tryItOut("/*RXUB*/var r = /\\3/yi; var s = \"\\\"\"; print(s.split(r)); \no2.v1 = null;\n");
/*fuzzSeed-116111302*/count=726; tryItOut("mathy0 = (function(x, y) { return (Math.expm1(Math.pow(( + ( + (( + ((Math.round(x) | 0) / (Math.fround((Math.fround(y) <= Math.fround(y))) / (y >>> 0)))) || -(2**53+2)))), (( + ( - ( ~ Math.fround(y)))) | 0))) | 0); }); testMathyFunction(mathy0, [0x0ffffffff, -0x07fffffff, -0, 42, Math.PI, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), 1, -1/0, -Number.MIN_VALUE, 0/0, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000001, 0x080000001, Number.MAX_VALUE, 2**53+2, -(2**53), -0x100000000, 0.000000000000001, 0, 1/0, -0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 2**53-2, 0x080000000, 2**53, 0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=727; tryItOut("mathy1 = (function(x, y) { return Math.atan2(( + (( + (( + ((( ! x) >>> 0) << (y || Number.MIN_SAFE_INTEGER))) || Math.fround(0/0))) ? Math.fround(Math.sinh(x)) : ( + mathy0(( + ( ~ Math.fround(Math.clz32(Math.fround(( + x)))))), ( + ( + (( + (y | -0x080000000)) - x))))))), ( + (( - Math.fround(Math.imul(Math.fround(Math.atan2(y, Math.fround(Math.sign(Math.log10((y | 0)))))), (Math.sin(( ~ y)) ^ 0x100000000)))) | 0))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, 1, 0x100000001, 0.000000000000001, -1/0, 2**53-2, 0x100000000, 0x0ffffffff, -0x0ffffffff, -0x07fffffff, 2**53+2, 0, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53+2), 42, -0x080000000, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), Math.PI, -0, 2**53, 0x080000001, -(2**53), -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000001, -0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, 1/0]); ");
/*fuzzSeed-116111302*/count=728; tryItOut("testMathyFunction(mathy0, [-0x0ffffffff, Number.MAX_SAFE_INTEGER, 1, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000001, -(2**53), 42, -1/0, 0x07fffffff, -0x080000001, -0x07fffffff, -0x080000000, 2**53, 2**53+2, 0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, -0, 1/0, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), 0x080000001, 0x100000001, 0.000000000000001, -(2**53+2), 0x0ffffffff, 0, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=729; tryItOut("mathy1 = (function(x, y) { return Math.log1p(( ~ ((((( ! Math.fround(x)) >>> 0) & (y >>> 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy1, [-0x080000000, -(2**53+2), 0x100000000, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -0x100000001, 42, 0x080000001, -0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, -(2**53), 0x0ffffffff, -0x100000000, 2**53-2, 1, 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, -0x080000001, 0.000000000000001, -Number.MIN_VALUE, 0x080000000, -0x0ffffffff, -0, 1/0, 0x100000001]); ");
/*fuzzSeed-116111302*/count=730; tryItOut("mathy4 = (function(x, y) { return (((Math.sign(((Math.imul(y, ((((( + x) ? ( + y) : ( + Math.PI)) | 0) ** (x | 0)) | 0)) ? Math.fround(( + (Math.fround(Math.imul(Math.fround(x), Math.fround(Math.hypot(y, x)))) / ( + Math.abs(y))))) : Math.fround(y)) | 0)) | 0) == Math.min((( ! Math.fround(( - ( + x)))) | 0), (( + x) | 0))) >>> 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_VALUE, 0x100000000, 0x080000000, -0, -Number.MAX_VALUE, 0, -0x080000000, 42, Number.MAX_SAFE_INTEGER, -(2**53+2), 0.000000000000001, -0x100000001, Math.PI, 0x080000001, 2**53-2, 1, 0x07fffffff, -0x080000001, -1/0, -0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, -(2**53), -0x100000000, 2**53, -0x07fffffff, -(2**53-2), 1/0, 0x100000001]); ");
/*fuzzSeed-116111302*/count=731; tryItOut("\"use strict\"; h1.toString = (function() { try { var v1 = null; } catch(e0) { } try { s2 = this.g2.g2.g0.t0[(void options('strict'))]; } catch(e1) { } try { e0.add(f0); } catch(e2) { } a1 = arguments; return g1.o1; });");
/*fuzzSeed-116111302*/count=732; tryItOut("\"use strict\"; /*oLoop*/for (dmzgvz = 0; dmzgvz < 161; ++dmzgvz, new RegExp(\"(?!(?:[^])+?)|[^]?|(.+?|[^]+?)|(?!(\\u71ef))[\\\\d\\u00e9-\\\\uCaCE]|\\\\w*?*+\", \"y\")) { {}\nprint(0);\n } ");
/*fuzzSeed-116111302*/count=733; tryItOut("L: g1.i2.toSource = (function() { try { a0.sort((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { a10 = 7 * a5; var r0 = a6 % a19; var r1 = a15 / a11; print(a3); a13 = a18 | 0; var r2 = 3 + r0; var r3 = a2 + 1; var r4 = r3 - a6; var r5 = 1 & a17; var r6 = 5 % 3; r1 = a19 | 0; print(a19); var r7 = a17 * a7; return a11; })); } catch(e0) { } try { delete h2.get; } catch(e1) { } try { m2.get(t1); } catch(e2) { } s1 += s0; return f1; });");
/*fuzzSeed-116111302*/count=734; tryItOut("o1.e2 + '';");
/*fuzzSeed-116111302*/count=735; tryItOut("h2.keys = f0;");
/*fuzzSeed-116111302*/count=736; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return (Math.expm1(mathy3(Math.log(Math.fround(( + Math.expm1(((((y >>> 0) & (( - 1.7976931348623157e308) >>> 0)) >>> 0) >>> 0))))), ((((Math.round(Math.fround(Math.atanh(y))) >>> 0) >>> 0) ** Math.min((( ! x) | 0), Math.max(y, y))) >>> 0))) | 0); }); testMathyFunction(mathy4, [0/0, 0x080000000, 0x100000001, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 42, -0x07fffffff, 1.7976931348623157e308, 0x100000000, -Number.MAX_SAFE_INTEGER, 0, 2**53+2, 1, -(2**53), -0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -1/0, 2**53-2, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, 1/0, -(2**53+2), 0x080000001, -(2**53-2), 0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, -0, -0x0ffffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-116111302*/count=737; tryItOut("/*RXUB*/var r = /(\\d(?:$(\\1*?)){3,258})/gym; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-116111302*/count=738; tryItOut("\"use strict\"; \"use asm\"; var imtpxh = new ArrayBuffer(12); var imtpxh_0 = new Uint8Array(imtpxh); for (var p in o2) { o0.v2 = (h0 instanceof t1); }");
/*fuzzSeed-116111302*/count=739; tryItOut("\"use strict\"; b1 + s2;\n(4277);\n");
/*fuzzSeed-116111302*/count=740; tryItOut("x = linkedList(x, 3782);");
/*fuzzSeed-116111302*/count=741; tryItOut("mathy2 = (function(x, y) { return Math.trunc(((Math.imul((x | 0), (Math.max(Math.fround(( - x)), x) | 0)) | 0) + (Math.pow((x < x), ( + Math.min(Number.MAX_SAFE_INTEGER, x))) | 0))); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, -0x080000000, 0.000000000000001, 0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, 2**53+2, -(2**53+2), 0x080000000, 42, Number.MIN_VALUE, -(2**53-2), -0x100000001, 0, -0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, 0x080000001, 1.7976931348623157e308, -0x100000000, -0x080000001, 2**53, 0/0, 0x100000000, 1/0, 0x07fffffff, -1/0, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1]); ");
/*fuzzSeed-116111302*/count=742; tryItOut("\"use strict\"; o0.o1.s1 + a2;");
/*fuzzSeed-116111302*/count=743; tryItOut("/*bLoop*/for (lfnayr = 0; (true) && lfnayr < 18; ++lfnayr) { if (lfnayr % 99 == 69) { ( /x/g ); } else { v2 = Object.prototype.isPrototypeOf.call(v1, o1.a0); }  } \n/*tLoop*/for (let a of /*MARR*/[true,  /x/g , true, new Number(1.5), new Number(1.5), new Number(1.5),  \"use strict\" , true,  \"use strict\" ,  /x/g ,  /x/g ,  /x/g ,  \"use strict\" ,  \"use strict\" , true,  \"use strict\" , new Number(1.5), true,  \"use strict\" , true, true, true,  /x/g ,  \"use strict\" ,  /x/g , new Number(1.5), true,  \"use strict\" , true, true,  \"use strict\" , true,  \"use strict\" , true]) { m2.toSource = (function() { t0.set(t0, \"\\uC1DD\"); return p0; }); }\n");
/*fuzzSeed-116111302*/count=744; tryItOut("g1.t2.__proto__ = p0;");
/*fuzzSeed-116111302*/count=745; tryItOut("\"use strict\"; v0 = a1.length;");
/*fuzzSeed-116111302*/count=746; tryItOut("Array.prototype.reverse.call(o2.a2, s0, m2);");
/*fuzzSeed-116111302*/count=747; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-116111302*/count=748; tryItOut("mathy1 = (function(x, y) { return ( ~ (( ~ (Math.pow((( ~ x) - Number.MIN_SAFE_INTEGER), y) | 0)) | 0)); }); ");
/*fuzzSeed-116111302*/count=749; tryItOut("print(x);");
/*fuzzSeed-116111302*/count=750; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-116111302*/count=751; tryItOut("\"use strict\"; m2.has(o2.o2);");
/*fuzzSeed-116111302*/count=752; tryItOut("\"use strict\"; v1 = i2[\"getTime\"];");
/*fuzzSeed-116111302*/count=753; tryItOut("\u3056 = linkedList(\u3056, 144);");
/*fuzzSeed-116111302*/count=754; tryItOut("\"use strict\"; i0.send(f1);");
/*fuzzSeed-116111302*/count=755; tryItOut("this.b0.__proto__ = g1.t0;");
/*fuzzSeed-116111302*/count=756; tryItOut("g1.offThreadCompileScript(\"(arguments.prototype)\");");
/*fuzzSeed-116111302*/count=757; tryItOut("\"use strict\"; f1.valueOf = (function mcc_() { var wqmhej = 0; return function() { ++wqmhej; if (/*ICCD*/wqmhej % 4 == 3) { dumpln('hit!'); (void schedulegc(g0)); } else { dumpln('miss!'); try { v0 = r1.test; } catch(e0) { } try { p0 + ''; } catch(e1) { } f0 = Proxy.createFunction(h2, f1, f1); } };})();");
/*fuzzSeed-116111302*/count=758; tryItOut("print(x);\na1.sort((1 for (x in [])), v1);\n");
/*fuzzSeed-116111302*/count=759; tryItOut("mathy5 = (function(x, y) { return ( ! Math.cbrt(mathy0((mathy0(Math.max(x, -Number.MIN_VALUE), (Math.hypot(y, Math.fround(x)) | 0)) | 0), -0x100000001))); }); testMathyFunction(mathy5, [Number.MAX_VALUE, -0x0ffffffff, 0x0ffffffff, -1/0, 1, -(2**53+2), 0.000000000000001, 0x100000001, 1/0, -(2**53), -0x080000001, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0, 0x07fffffff, 0x080000001, 2**53, -Number.MAX_VALUE, -0x100000001, 0x080000000, -0x080000000, 2**53-2, 1.7976931348623157e308, Math.PI, -0x100000000, 42, -Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=760; tryItOut("\"use strict\"; L:for([e, b] = (4277) in (\u3056 =  /x/g  | /*FARR*/[c, new RegExp(\"\\\\2|(\\\\3)\\\\3**|\\\\W\", \"gy\"), true, ...[]].filter(x))) {v0 = Object.prototype.isPrototypeOf.call(s2, p2); }");
/*fuzzSeed-116111302*/count=761; tryItOut("y = (\"\\u085B\" >=  /x/ );h2 + e0;");
/*fuzzSeed-116111302*/count=762; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=763; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-116111302*/count=764; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((( - ( + Math.imul(Math.imul(x, x), Math.trunc(2**53)))) | 0) >>> (Math.clz32(( ~ ((x >>> 0) ** (y >>> 0)))) / Math.fround((mathy2((x && (((mathy0((x | 0), (x | 0)) | 0) ** (y | 0)) | 0)), Math.expm1(Math.hypot(y, 0/0))) - Math.fround(mathy2(y, Math.fround(-0x080000000))))))); }); testMathyFunction(mathy3, /*MARR*/[x, x, x, x, new Number(1), x, new Number(1), new Boolean(true), x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), x, x, objectEmulatingUndefined(), x, x, new Number(1), objectEmulatingUndefined(), x, new Boolean(true), new Number(1)]); ");
/*fuzzSeed-116111302*/count=765; tryItOut("v1 = a2[6];");
/*fuzzSeed-116111302*/count=766; tryItOut("a2.forEach(/*RXUE*//(?:\\b)/gi.exec(\"\"));");
/*fuzzSeed-116111302*/count=767; tryItOut("/*infloop*/L: for (eval of (new ((function ([y]) { })())())) {/*vLoop*/for (var tkprkb = 0; tkprkb < 37; ++tkprkb) { let w = tkprkb; v1 = Object.prototype.isPrototypeOf.call(o0.i1, v2); }  }");
/*fuzzSeed-116111302*/count=768; tryItOut("\"use strict\"; for (var v of e0) { try { o0 = x; } catch(e0) { } try { m0 = new Map(h2); } catch(e1) { } try { Array.prototype.push.apply(a1, [g1.s2]); } catch(e2) { } v0 = t2.length; }");
/*fuzzSeed-116111302*/count=769; tryItOut("var xqttzz = new SharedArrayBuffer(12); var xqttzz_0 = new Int32Array(xqttzz); xqttzz_0[0] = 7; var xqttzz_1 = new Uint8ClampedArray(xqttzz); print(xqttzz_1[0]); xqttzz_1[0] = 6; print(xqttzz_0[0]);a1.unshift(g2.g0.b2, this.o0.o0.v2, i2, b0, s0);/*RXUB*/var r = r2; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-116111302*/count=770; tryItOut("testMathyFunction(mathy3, [-0x100000001, -0x080000001, 1.7976931348623157e308, 2**53-2, 2**53+2, 42, -1/0, -0x07fffffff, 0x080000000, -0x100000000, -(2**53-2), -Number.MIN_VALUE, -Number.MAX_VALUE, 0/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, 0, 0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, -0, Number.MIN_VALUE, 0x100000000, -0x080000000, Math.PI, -Number.MAX_SAFE_INTEGER, 1/0, 0x0ffffffff, 2**53, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 0x080000001]); ");
/*fuzzSeed-116111302*/count=771; tryItOut("e0.add(m0);");
/*fuzzSeed-116111302*/count=772; tryItOut("\"use strict\"; if(false) { if (((makeFinalizeObserver('tenured')))) g2.b2 = new ArrayBuffer(18);\na1 = arguments;\n} else t0 = new Int16Array(v0);");
/*fuzzSeed-116111302*/count=773; tryItOut("\"use strict\"; t1[(\u3056--)] = (4277);");
/*fuzzSeed-116111302*/count=774; tryItOut("\"use strict\"; y = (makeFinalizeObserver('nursery'));/*bLoop*/for (inabnj = 0; inabnj < 102; ++inabnj) { if (inabnj % 4 == 3) { a1[v1] = p2; } else { print(27); }  } b2 + '';");
/*fuzzSeed-116111302*/count=775; tryItOut("mathy2 = (function(x, y) { return ((Math.max((Math.acos(Math.fround(Math.imul((y | 0), Math.fround(x)))) >>> 0), Math.tan(Math.fround(( + ( ~ (Math.acos(Number.MAX_VALUE) >>> 0)))))) >> (( ! (mathy0(((( + (( + y) > ( + x))) % y) >>> 0), ((Math.log(( + y)) | 0) | 0)) >>> 0)) ^ x)) || (Math.acos(((( ~ (Math.atan2(y, (y && x)) | 0)) << (Number.MIN_SAFE_INTEGER ? (x << Math.fround(Math.max(Math.fround(y), ((y ** x) | 0)))) : (mathy1((Math.cbrt(y) >>> 0), (Number.MAX_VALUE >>> 0)) >>> 0))) | 0)) | 0)); }); testMathyFunction(mathy2, [1/0, -0x07fffffff, 0x080000000, 2**53-2, -Number.MIN_VALUE, -0, 1.7976931348623157e308, 0x080000001, 0x07fffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, -Number.MAX_VALUE, 0/0, -1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, 0, 0x0ffffffff, 1, -(2**53+2), -0x0ffffffff, 2**53, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, 42, -0x100000001, Number.MIN_VALUE, -0x080000001, -(2**53), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=776; tryItOut("e2.has(p1);");
/*fuzzSeed-116111302*/count=777; tryItOut("x = h2;");
/*fuzzSeed-116111302*/count=778; tryItOut("h2.fix = (function(j) { if (j) { g2.h1.getOwnPropertyDescriptor = f0; } else { try { v0 = Object.prototype.isPrototypeOf.call(f0, a0); } catch(e0) { } try { o0.v0 = g2.eval(\"/* no regression tests found */\"); } catch(e1) { } for (var p in s1) { for (var p in m2) { try { for (var v of o1.e0) { try { o0.a1 = []; } catch(e0) { } try { g1.offThreadCompileScript(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: undefined, noScriptRval: true, sourceIsLazy: false, catchTermination: true })); } catch(e1) { } b2 = t2.buffer; } } catch(e0) { } try { a0 + ''; } catch(e1) { } v2 = new Number(0); } } } });");
/*fuzzSeed-116111302*/count=779; tryItOut("v0 = evaluate(\"\\\"use strict\\\"; testMathyFunction(mathy3, [-0x0ffffffff, 2**53+2, 0x0ffffffff, 0x080000000, 0x07fffffff, Math.PI, -Number.MIN_VALUE, -(2**53), 1/0, -0x100000000, 0/0, 0x080000001, -0x100000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0.000000000000001, 0, -0x080000001, 1, Number.MIN_VALUE, -1/0, 0x100000001, 2**53, 0x100000000, -(2**53-2), 42, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, 1.7976931348623157e308, -0]); \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 == 1), sourceIsLazy: false, catchTermination: (x % 3 == 1) }));");
/*fuzzSeed-116111302*/count=780; tryItOut("mathy1 = (function(x, y) { return (((Math.ceil(Math.atan2((Math.atan2(Math.max(Math.fround(y), Math.fround(x)), x) >>> 0), (( + (Math.atanh((x >>> 0)) | 0)) >>> 0))) >>> 0) << ((( ~ Math.acosh((x | 0))) - Math.hypot(((Math.tan(Math.fround(y)) | 0) >> -0x07fffffff), Math.hypot(y, Math.hypot(x, x)))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [0x07fffffff, 2**53+2, 1.7976931348623157e308, -(2**53-2), -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0x100000000, 0x080000001, -0, -Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, 2**53-2, -1/0, 2**53, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x0ffffffff, -0x080000000, 0x080000000, -0x100000001, 0, 0x100000001, 0/0, -(2**53+2), -0x080000001, Number.MAX_VALUE, 1]); ");
/*fuzzSeed-116111302*/count=781; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(g1, m1);const b = x = x mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return ((mathy1(mathy1(mathy0((Math.imul(0x100000001, 0/0) | 0), x), 0x100000000), ( ! y)) / ( + ( ~ ((((Math.log10(x) | 0) | (( + Math.hypot(( + (Math.min(y, Math.fround(( + Math.abs((x >>> 0))))) | 0)), ( + x))) | 0)) >>> 0) ? (Math.pow(( + Math.hypot(( + 0.000000000000001), ( + ( ~ (0/0 >>> 0))))), ( + y)) >>> 0) : (((( ~ (-(2**53) >>> 0)) | 0) <= ((( ! (((Math.fround(-(2**53-2)) >> Math.fround(x)) | 0) | 0)) | 0) >>> 0)) | 0))))) | 0); });  ;");
/*fuzzSeed-116111302*/count=782; tryItOut("mathy5 = (function(x, y) { return Math.pow(Math.trunc(Math.fround((( + Math.atan2(Math.pow(x, (-(2**53) | 0)), ( + (( + Math.imul(x, Number.MIN_SAFE_INTEGER)) ? ( + 0) : ( + -Number.MIN_VALUE))))) ? Math.sign(x) : (Math.hypot(x, (y | 0)) >>> 0)))), mathy2(Math.log10(Math.atanh(( + Math.cosh(( + Math.fround(( ! Math.fround(x)))))))), mathy0(((( + ( + (0x07fffffff | 0))) <= (y >>> (( + ( - -Number.MIN_VALUE)) ? y : ( + x)))) | 0), (Math.max(y, y) ? (1/0 >>> 0) : (( + -Number.MAX_SAFE_INTEGER) / Math.fround(((( + x) < ( + ( + (( + Number.MAX_SAFE_INTEGER) , ( + 2**53+2))))) >>> 0))))))); }); testMathyFunction(mathy5, [0x100000000, -(2**53+2), -0x080000001, -0x0ffffffff, -0x080000000, -Number.MIN_VALUE, 0/0, 42, 1.7976931348623157e308, -0, 1, 0x080000001, -Number.MAX_VALUE, 0x07fffffff, -0x100000001, Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, Math.PI, 0.000000000000001, 2**53, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, -1/0, -(2**53), 0x080000000, 1/0]); ");
/*fuzzSeed-116111302*/count=783; tryItOut("mathy0 = (function(x, y) { return Math.acosh(( + ( ~ ( + (( + ( + (y | 0))) >>> 0))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -(2**53-2), 0.000000000000001, -0x100000001, -(2**53), -0x07fffffff, 0/0, 0x100000001, 1/0, -0, 0x080000000, 2**53+2, -0x100000000, -0x0ffffffff, Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, Number.MAX_SAFE_INTEGER, Math.PI, -1/0, 42, -(2**53+2), -0x080000001, 0x080000001, Number.MIN_VALUE, 2**53, 2**53-2]); ");
/*fuzzSeed-116111302*/count=784; tryItOut("\"use strict\"; {/* no regression tests found */m0.has(g0); }");
/*fuzzSeed-116111302*/count=785; tryItOut("/*hhh*/function muinhl(c = z = \u3056, x){f1 = Proxy.createFunction(h2, f1, this.f2);}muinhl(-11, ( \"\"  > \"\\uB546\"));");
/*fuzzSeed-116111302*/count=786; tryItOut("p1.valueOf = f1;");
/*fuzzSeed-116111302*/count=787; tryItOut("var azoflf;/*ADP-1*/Object.defineProperty(a1, 5, ({writable: true, enumerable: true}));M:if(false) a1.shift(this.h2); else  if (-NaN) v1 = g0.runOffThreadScript(); else {let g0 = this;g2.offThreadCompileScript(\"undefined\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: (x % 5 != 4), sourceIsLazy: false, catchTermination: /(?:.|\\B+|[]{16777217,})\\d{3}/i })); }");
/*fuzzSeed-116111302*/count=788; tryItOut("\"use strict\"; o1.e0.has(o0.m2);");
/*fuzzSeed-116111302*/count=789; tryItOut("mathy3 = (function(x, y) { return ( + (( + ((Math.fround(( + (x ? Math.cbrt(Math.abs(x)) : mathy1((x / (mathy2(0x100000001, x) ** y)), Math.asin(( + Math.acos(y))))))) * Math.fround((((Math.acos((x >>> 0)) >>> 0) ? Math.fround((Math.exp(2**53-2) | 0)) : Math.fround(( ~ ( + (Math.sign(y) | 0))))) | 0))) >>> 0)) < ( + (((( + ( - ( + y))) & y) >>> 0) - (( - Math.imul(Math.min(y, y), Math.fround(( + (Math.fround((x | 0)) ? (Math.acosh(Math.fround(Math.atan(Math.PI))) | 0) : x))))) | 0))))); }); testMathyFunction(mathy3, [0x07fffffff, 0/0, -(2**53-2), Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x080000000, 0, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), Number.MAX_VALUE, 0x0ffffffff, 0x080000001, 0x100000001, -0x100000001, -(2**53+2), 1/0, -0x100000000, 0x100000000, -1/0, 1, -0x0ffffffff, 2**53+2, 1.7976931348623157e308, -0x080000000, -Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, -0, 42]); ");
/*fuzzSeed-116111302*/count=790; tryItOut("this.e0[\"setUint16\"] = o1;");
/*fuzzSeed-116111302*/count=791; tryItOut("\"use strict\"; ;function x(...x)(new ({/*TOODEEP*/})(null) << [window])function f2(v2)  { yield (x) } ");
/*fuzzSeed-116111302*/count=792; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-116111302*/count=793; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.pow(Math.fround(Math.min(Math.fround((Math.hypot(Math.imul(((Math.atan((( + -Number.MAX_VALUE) % -0x080000000)) | 0) >>> 0), ((( + Math.atanh(x)) - (x >>> 0)) >>> 0)), (((( + ( ! ( + x))) >= ( + (y <= (y | 0)))) >>> 0) >>> 0)) >>> 0)), Math.fround(Math.ceil(Math.fround(( ~ Math.fround(x))))))), Math.atan(Math.min((( ! (y | 0)) | 0), ((((y | 0) ? (Math.min((Math.clz32(x) >>> 0), x) | 0) : Math.min(( + Math.asin(-Number.MAX_VALUE)), ((Math.sin((y | 0)) | 0) >>> 0))) | 0) >>> 0)))); }); ");
/*fuzzSeed-116111302*/count=794; tryItOut("/* no regression tests found */");
/*fuzzSeed-116111302*/count=795; tryItOut("testMathyFunction(mathy4, [-Number.MAX_VALUE, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, 42, -0x07fffffff, 0x080000000, -0x080000000, -Number.MIN_VALUE, -0x0ffffffff, 2**53+2, -1/0, -(2**53+2), 0x07fffffff, -0x080000001, 0, 0x0ffffffff, 2**53, 1, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, -(2**53), -0, 2**53-2, 0.000000000000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000001, -(2**53-2), -0x100000000, 0x100000000, 1.7976931348623157e308]); ");
/*fuzzSeed-116111302*/count=796; tryItOut("\"use strict\"; print(p1);");
/*fuzzSeed-116111302*/count=797; tryItOut("testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, Number.MAX_SAFE_INTEGER, 0x080000001, -0, 1.7976931348623157e308, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 2**53+2, 0x100000000, 0x0ffffffff, -(2**53-2), -0x080000000, -Number.MAX_VALUE, Math.PI, 0.000000000000001, -1/0, 0x100000001, 0, -0x07fffffff, -Number.MIN_VALUE, 0/0, 0x07fffffff, 42, 2**53-2, -(2**53), Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -0x100000001, 1, 0x080000000, -(2**53+2)]); ");
/*fuzzSeed-116111302*/count=798; tryItOut("let(e) { for(let x in /*MARR*/[-Infinity,  /x/g , new Boolean(true)]) throw StopIteration;}this.zzz.zzz;");
/*fuzzSeed-116111302*/count=799; tryItOut("\"use asm\"; o0.h2.getPropertyDescriptor = f2;");
/*fuzzSeed-116111302*/count=800; tryItOut("v0 = 0;");
/*fuzzSeed-116111302*/count=801; tryItOut("mathy2 = (function(x, y) { return ( + Math.tan(mathy1(Math.atan2((Math.fround(( ~ 2**53)) || Math.hypot(( + (( + (((-Number.MAX_SAFE_INTEGER | 0) , (x >>> 0)) | 0)) === ( + y))), (( ~ (x | 0)) | 0))), Math.max(-(2**53), (Math.cbrt(1.7976931348623157e308) === x))), (( + Math.atan2(Math.fround(x), Math.fround((mathy1((Math.asin(0x080000001) | 0), y) < ((y , 0x100000001) & x))))) >>> 0)))); }); testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, -0x100000001, 0, -0x080000000, 0.000000000000001, 1, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53-2, 0/0, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_VALUE, -1/0, 1.7976931348623157e308, 0x080000001, 42, -(2**53+2), Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), 1/0, -0x080000001, Number.MIN_SAFE_INTEGER, -0, 2**53+2, 0x100000000, 0x080000000, -0x07fffffff, 2**53, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53)]); ");
/*fuzzSeed-116111302*/count=802; tryItOut("mathy0 = (function(x, y) { return Math.acos(Math.fround(Math.pow(((( - Math.fround((( ! (x >>> 0)) ? ( + ( + (( + y) * ( + x)))) : -(2**53-2)))) || ( + ((Math.atan2(x, ((x ? ( + x) : ((((x | 0) ? (x | 0) : x) | 0) | 0)) | 0)) !== Math.fround(( + Math.fround(( ~ Math.fround(Math.trunc(Math.fround(-0x080000000)))))))) | 0))) >>> 0), Math.log2(-1/0)))); }); testMathyFunction(mathy0, [-(2**53+2), -0, -Number.MIN_VALUE, 0x100000001, 0x0ffffffff, -0x100000000, -0x080000001, 2**53, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, -0x07fffffff, -(2**53-2), -0x080000000, -0x0ffffffff, 0x080000000, -1/0, 2**53-2, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, 1, 0.000000000000001, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, 0x100000000, Math.PI, -(2**53), 42, 0, 0x07fffffff]); ");
/*fuzzSeed-116111302*/count=803; tryItOut("/*bLoop*/for (bmfkzr = 0; bmfkzr < 87 && (x); ++bmfkzr) { if (bmfkzr % 70 == 18) { /*tLoop*/for (let e of /*MARR*/[0x100000001, [(void 0)], ({apply: ((Number.parseFloat)()),  set 17 x (z)x }), [(void 0)], ({apply: ((Number.parseFloat)()),  set 17 x (z)x }), 0x100000001, ({apply: ((Number.parseFloat)()),  set 17 x (z)x }), 0x100000001, [(void 0)], ({apply: ((Number.parseFloat)()),  set 17 x (z)x })]) { /*infloop*/for(e in ((function shapeyConstructor(gjlkab){\"use strict\"; Object.defineProperty(this, \"b\", ({set: e =>  { yield this } , configurable: undefined}));Object.preventExtensions(this);{ ; } Object.preventExtensions(this);this[\"b\"] = 20;this[\"b\"] =  \"\" ;Object.defineProperty(this, new String(\"9\"), ({set: \"\\u5129\"}));this[new String(\"9\")] = new RegExp(\"\\\\b?|((?=(?=\\\\b){2,4})+?)|(.|(?:\\\\d+?|\\u00c5[^\\\\u00D6-\\\\\\u891a\\\\s\\\\b])|(?:\\\\2)*)\", \"gim\");return this; }/*tLoopC*/for (let a of x in  /x/g ) { try{let yyzose = shapeyConstructor(a); print('EETT'); i1 + s0;}catch(e){print('TTEE ' + e); } })(\"\\u007C\"))){print(uneval(t1));m0 = new WeakMap; } } } else { t0 = new Float64Array(15);\n/*infloop*/for(a = 15; function ([y]) { }; this) {yield; }\n }  } ");
/*fuzzSeed-116111302*/count=804; tryItOut("/*MXX3*/g1.g0.Symbol.toStringTag = g2.g2.Symbol.toStringTag;");
/*fuzzSeed-116111302*/count=805; tryItOut("mathy1 = (function(x, y) { return Math.pow(( + (Math.log2(Math.fround(( + x))) + (((mathy0((x | 0), (( ~ x) | 0)) | 0) | 0) >> (( + (((( ! x) | 0) !== (( - y) | 0)) | 0)) | 0)))), Math.fround((((((( + -(2**53+2)) == Math.hypot((x / x), (Math.acosh((x | 0)) | 0))) | 0) ? (Math.max(( + Math.tan(x)), Math.atan(Math.fround(Math.atan2(Math.fround(y), Math.fround(Math.fround(( - ( + -Number.MAX_VALUE)))))))) | 0) : ((Math.cosh(((Math.min((( + Math.max(( + Number.MIN_VALUE), ( + y))) >>> 0), (-0x0ffffffff >>> 0)) >>> 0) | 0)) >>> 0) >>> 0)) | 0) ? ((Math.max(Math.max(0x07fffffff, Math.fround(Math.sqrt(mathy0(0x080000000, x)))), y) >>> 0) !== (Math.fround(( ~ Math.fround(mathy0(x, Math.fround((x + (-(2**53-2) | 0))))))) >>> 0)) : Math.log1p(( + ( + x)))))); }); testMathyFunction(mathy1, /*MARR*/[-0x100000000, new Boolean(true), objectEmulatingUndefined(), x, x, x, x, objectEmulatingUndefined(), -0x100000000, false, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000000, objectEmulatingUndefined(), x, new Boolean(true), -0x100000000, new Boolean(true), false, objectEmulatingUndefined(), objectEmulatingUndefined(), false, x, new Boolean(true), -0x100000000, x, -0x100000000, x, false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000000, -0x100000000, false, x, x, new Boolean(true), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, new Boolean(true), false, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x, new Boolean(true), -0x100000000, objectEmulatingUndefined(), objectEmulatingUndefined(), false, new Boolean(true), x, x, new Boolean(true), new Boolean(true), x, x, x, new Boolean(true), -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, false, false, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), false, -0x100000000, false, new Boolean(true), x, x, -0x100000000, new Boolean(true), objectEmulatingUndefined(), -0x100000000, objectEmulatingUndefined(), new Boolean(true), -0x100000000, x, false, -0x100000000, new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -0x100000000, false, x, x, -0x100000000, -0x100000000, -0x100000000, new Boolean(true), -0x100000000, objectEmulatingUndefined(), -0x100000000, x, new Boolean(true), new Boolean(true), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined()]); ");
/*fuzzSeed-116111302*/count=806; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((Math.acos((( - ( ~ Number.MIN_VALUE)) | 0)) >>> 0) * mathy0(Math.fround(mathy0(Math.fround(( + Math.ceil(x))), Math.fround(Math.fround((-0x080000001 <= ( + Math.fround(( + Math.fround(x))))))))), (( + (y | 0)) | 0))); }); testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-116111302*/count=807; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-116111302*/count=808; tryItOut("\"use strict\"; o1.o1.r1 = /\\d|(?!(?:(\\B[^\\ww-\u00b3]+)))|[^]|\\b|(?=[^]\\uBae9[^\\D\0\\d]|[^\\0-\\u00A6\\d])/;");
/*fuzzSeed-116111302*/count=809; tryItOut("//h\n for  each(var d in x) a1.splice(NaN, 16);");
/*fuzzSeed-116111302*/count=810; tryItOut("e1.add(h0);");
/*fuzzSeed-116111302*/count=811; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0, false, ({valueOf:function(){return 0;}}), [0], (new Number(0)), /0/, '', undefined, (function(){return 0;}), null, objectEmulatingUndefined(), '\\0', [], (new Boolean(false)), true, (new Boolean(true)), NaN, (new String('')), ({valueOf:function(){return '0';}}), 1, 0.1, '/0/', '0', ({toString:function(){return '0';}}), 0, (new Number(-0))]); ");
/*fuzzSeed-116111302*/count=812; tryItOut("a0 = o0.m0.get(f1);");
/*fuzzSeed-116111302*/count=813; tryItOut("\"use asm\"; /*tLoop*/for (let a of /*MARR*/[[1], x, x, x, [1], [1], [1], x, x, x, [1], [1], x, [1], [1], x, [1], [1], [1], x, x, [1]]) { /*RXUB*/var r = /(?!\\B\\xD4|[^](?=(\\W))){0}|\\f|[^]+?(\\S*?){67108864}+/gy; var s = \"\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\\u44df\\n0\"; print(r.test(s)); print(r.lastIndex);  }");
/*fuzzSeed-116111302*/count=814; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround(( ! Math.fround(Math.exp(Math.fround(Math.fround(Math.min((Math.fround(x) == Math.fround((mathy0((x | 0), (x | 0)) | 0))), -0x100000000))))))) ? (mathy0(( + Math.fround(Math.exp(Math.fround(2**53)))), ( + Math.hypot(Math.fround((x ? (Math.fround(Math.max(Math.fround(y), Math.fround(-(2**53+2)))) && y) : (Math.fround(( - (y >>> 0))) | Math.fround(Math.atan2(y, (y >>> 0)))))), (( + Math.atan2(( + Math.clz32(-1/0)), ( + x))) >>> 0)))) | 0) : (Math.fround(((((0/0 % Math.max(y, -0x100000001)) ^ (y % y)) < Math.fround((Math.fround((( - y) !== ( ! -Number.MAX_VALUE))) && Math.fround(mathy0(Math.fround(Math.acosh(Math.fround(x))), ( + ((y >>> 0) , ( + Math.PI)))))))) == Math.min((Math.round(x) | 0), ( + x)))) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[x, new Boolean(false), -Infinity, x, -Infinity, new Boolean(false), x, -Infinity, x, false, x = /*UUV2*/(w.isFinite = w.toString), x, -Infinity, x = /*UUV2*/(w.isFinite = w.toString), x, new Boolean(false), x = /*UUV2*/(w.isFinite = w.toString), false, new Boolean(false), x = /*UUV2*/(w.isFinite = w.toString), -Infinity, -Infinity, new Boolean(false), x = /*UUV2*/(w.isFinite = w.toString), x = /*UUV2*/(w.isFinite = w.toString), x, x, x, new Boolean(false), -Infinity, new Boolean(false)]); ");
/*fuzzSeed-116111302*/count=815; tryItOut("\"use strict\"; const c = (x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(y) { \"use strict\"; return (4277) }, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return true; }, hasOwn: decodeURIComponent, get: function() { throw 3; }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })((Object.defineProperty(eval, \"toString\", ({get: Function, set: (new Function(\"\")), configurable: -15, enumerable: true}))).__defineSetter__(\"x\", window.setUint32)), ({\"1\": (4277) }))), NaN = Math.fround(Math.atan2(Math.fround(( - ((Math.tanh((x >>> 0)) >>> 0) ? ((( + 0x080000000) ? ( + ((x != 0.000000000000001) | 0)) : ( + (((Math.atan2((Math.max(Math.fround(Math.fround(Math.cbrt(Math.fround(x)))), ( + x)) | 0), x) | 0) >>> Math.fround(Math.pow(x, (x >>> 0)))) | 0))) >>> 0) : ( + (( + (((Math.fround((Math.fround(( - -0x100000001)) || ( + (( + 0x100000000) >>> 0)))) | 0) | (((( + x) < x) | 0) | 0)) | 0)) >= ( + x)))))), Math.fround(Math.max(Math.fround((( - ( + Math.tanh(Math.fround((Math.cos(x) >>> 0))))) || (( + (Math.min((Math.sinh((x | 0)) >>> 0), (x >>> 0)) >>> Math.hypot(x, Math.asinh(x)))) >> ( + x)))), (( + ( ! ( + (Math.fround(((Math.atan2(x, x) >>> 0) & Math.fround(Math.fround(Math.round(Math.imul(x, x)))))) >> x)))) | 0))))), b = x, a, butogk;;");
/*fuzzSeed-116111302*/count=816; tryItOut("\"use strict\"; /*ODP-2*/Object.defineProperty(s0, \"18\", { configurable: x, enumerable: true, get: (function() { try { p1.__proto__ = o0.e2; } catch(e0) { } try { h2 = ({getOwnPropertyDescriptor: function(name) { s2 += o2.s2;; var desc = Object.getOwnPropertyDescriptor(this.t1); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { Object.defineProperty(g1, \"o2.a1\", { configurable: false, enumerable: false,  get: function() {  return Array.prototype.filter.call(a1, f1); } });; var desc = Object.getPropertyDescriptor(this.t1); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Array.prototype.sort.apply(a0, [o1.f0, v1, i2]);; Object.defineProperty(this.t1, name, desc); }, getOwnPropertyNames: function() { throw this.a2; return Object.getOwnPropertyNames(this.t1); }, delete: function(name) { a2.pop();; return delete this.t1[name]; }, fix: function() { s1.toSource = (function() { for (var j=0;j<18;++j) { this.f1(j%5==0); } });; if (Object.isFrozen(this.t1)) { return Object.getOwnProperties(this.t1); } }, has: function(name) { g2.a2.push(p0, i1, undefined, h1, a0);; return name in this.t1; }, hasOwn: function(name) { a2 + '';; return Object.prototype.hasOwnProperty.call(this.t1, name); }, get: function(receiver, name) { v0 = true;; return this.t1[name]; }, set: function(receiver, name, val) { Array.prototype.splice.call(a0, NaN, 8, g0, this.h0, h2);; this.t1[name] = val; return true; }, iterate: function() { Object.preventExtensions(p2);; return (function() { for (var name in this.t1) { yield name; } })(); }, enumerate: function() { return o2; var result = []; for (var name in this.t1) { result.push(name); }; return result; }, keys: function() { v2 = Object.prototype.isPrototypeOf.call(this.f2, t0);; return Object.keys(this.t1); } }); } catch(e1) { } m2.get(m1); throw this.o1; }), set: (function(j) { if (j) { try { e0 = new Set(v2); } catch(e0) { } this.f2(i1); } else { try { Array.prototype.forEach.apply(a0, [(function() { for (var j=0;j<6;++j) { this.f0(j%2==1); } }), m1]); } catch(e0) { } s1 = ''; } }) });");
/*fuzzSeed-116111302*/count=817; tryItOut("g1.t0[18] = e1;\ne1.has(f0);\n");
/*fuzzSeed-116111302*/count=818; tryItOut("\"use strict\"; /*RXUB*/var r = (y = null) += \"\\u4CBC\"; var s = \"\"; print(uneval(s.match(r))); function z(d, x = w < x, [, [{}, , ], {\u3056: {}}, [, (20)]], x, \u3056, a = (4277), let, c = x, b = undefined, a, x, c, eval, this.w, x, b = null, b, x =  /x/ , NaN, d, e = 29, x, x, d = x, x, x, window, NaN = \"\\uA5BF\", NaN, \"-24\", \u3056, a, d = undefined, x, x, e, e, x, of, x, x, ...x) { return /*UUV2*/(\u3056.setUTCSeconds = \u3056.toLocaleLowerCase) } let x = new RegExp(\"[^\\\\D\\\\n-\\\\xce\\\\u0032-\\\\\\ubc8a\\\\f-\\\\u00Ba]|\\\\3\", \"i\"), kvjfsz, -7, window;( '' );");
/*fuzzSeed-116111302*/count=819; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]\", \"y\"); var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-116111302*/count=820; tryItOut("mathy5 = (function(x, y) { return (mathy2((Math.fround(( ! Math.fround((( - Math.tan(x)) % y)))) >= Math.fround(Math.expm1((((x >>> 0) !== (y >>> 0)) >>> 0)))), ( ~ Math.min(Math.fround((Math.fround(y) - Math.fround(Math.pow(x, x)))), Math.exp((((x | 0) ? (2**53+2 | 0) : (y | 0)) | 0))))) | 0); }); testMathyFunction(mathy5, /*MARR*/[true, true, (void 0), true, (void 0), null, (void 0), true, (void 0), true, (void 0), true, null, true, null, (void 0), true, null, true, null, true]); ");
/*fuzzSeed-116111302*/count=821; tryItOut("\"use strict\"; let v2 = new Number(h1);");
/*fuzzSeed-116111302*/count=822; tryItOut("/*RXUB*/var r = /(?:[^])/; var s = \"\\u7b19\"; print(uneval(s.match(r))); ");
/*fuzzSeed-116111302*/count=823; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -(2**53+2), -0x100000001, Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, 42, -0x100000000, 0, 0/0, 2**53+2, 1.7976931348623157e308, 1/0, Math.PI, Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 1, -0x07fffffff, 0x07fffffff, 0.000000000000001, 0x100000000, 0x080000000, -(2**53-2), -0x080000000, -(2**53), 2**53-2, -Number.MIN_VALUE]); ");
/*fuzzSeed-116111302*/count=824; tryItOut("print(((function a_indexing(kxkzue, xsxkxd) { e0.add(this.f0);; if (kxkzue.length == xsxkxd) { ; return ((void version(180))); } var ypfbue = kxkzue[xsxkxd]; var fpkeop = a_indexing(kxkzue, xsxkxd + 1); return [z1,,].eval(\"new RegExp(\\\".\\\", \\\"yim\\\")\").yoyo((new RegExp(\"\\\\D|((\\u0ddf{2,5}))|((?!$)|\\\\B|\\uc616)|^\", \"\") / [])); })(/*MARR*/[true, true, true, true, new Number(1), new Number(1), new Number(1), new Number(1), true, Number.MAX_VALUE, new Number(1), new Number(1), new Number(1), new Number(1), true, ['z'], Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, Number.MAX_VALUE, new Number(1)], 0)));");
/*fuzzSeed-116111302*/count=825; tryItOut("v1 = Object.prototype.isPrototypeOf.call(o1.h2, m2);");
/*fuzzSeed-116111302*/count=826; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = r0; var s = s2; print(s.match(r)); ");
/*fuzzSeed-116111302*/count=827; tryItOut("/*RXUB*/var r = /[^]/m; var s = \"\\n\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-116111302*/count=828; tryItOut("v0 = (a1 instanceof t2);");
/*fuzzSeed-116111302*/count=829; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var sqrt = stdlib.Math.sqrt;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var d3 = -536870911.0;\n    var i4 = 0;\n    var i5 = 0;\n    i5 = (i4);\n    (x) = ((((9223372036854776000.0) == (+((Infinity)))) ? (((+abs(((+sqrt(((((2.0)) % (((-1073741825.0) + (-134217729.0))))))))))) % ((d3))) : (+(0.0/0.0))));\n    return +((34359738369.0));\n  }\n  return f; })(this, {ff: Math.imul(-24, (x = 10))}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53+2, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, 0/0, 0x100000001, -(2**53-2), 2**53-2, 0x080000001, Number.MIN_VALUE, 42, 0.000000000000001, -(2**53+2), 2**53, -0, -0x100000000, -Number.MIN_VALUE, Math.PI, 0x07fffffff, -1/0, -0x0ffffffff, 1/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, -0x080000000, -Number.MAX_VALUE, -0x100000001, -0x080000001, 0x0ffffffff, 0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=830; tryItOut("t2 = new Uint32Array(g0.o1.t2);");
/*fuzzSeed-116111302*/count=831; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( - Math.asinh((Math.pow(Math.fround(y), Math.abs(( + Math.atan2(( + (x > -1/0)), ( + ((-Number.MAX_SAFE_INTEGER - y) ^ (x >>> 0))))))) >>> 0))); }); ");
/*fuzzSeed-116111302*/count=832; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ Math.log1p(( + Math.ceil(( + Number.MAX_VALUE))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, Math.PI, 2**53+2, -0x0ffffffff, 0x100000001, 0, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, -(2**53-2), -0x100000000, Number.MIN_VALUE, -0, 42, 2**53-2, Number.MAX_VALUE, 1/0, -0x07fffffff, 0x080000001, 1.7976931348623157e308, -(2**53+2), 1, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001, 0x0ffffffff, 2**53, -Number.MAX_VALUE, -0x080000000, -Number.MIN_VALUE, 0x100000000, -1/0, 0/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-116111302*/count=833; tryItOut("a2.unshift(v1, x, t0);");
/*fuzzSeed-116111302*/count=834; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a1, [(function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 576460752303423500.0;\n    d2 = (d1);\n    d2 = (NaN);\n    d1 = (+(1.0/0.0));\n    (Float64ArrayView[(((((+(0x2cfab66c))) / ((+pow(((67108865.0)), ((-144115188075855870.0)))))) <= (+pow(((d2)), ((d2)))))-(0x3c811bc4)) >> 3]) = ((-8193.0));\n    return +((d1));\n    return +((-1.00390625));\n    return +((1.1805916207174113e+21));\n  }\n  return f; })(this, {ff: mathy4}, new SharedArrayBuffer(4096))]);");
/*fuzzSeed-116111302*/count=835; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i1 = (i1);\n    }\n    i0 = (i1);\n    (Uint8ArrayView[((i1)) >> 0]) = ((i1));\n    return (((i0)-(/*FFI*/ff(((4398046511105.0)), (((~((i0))))))|0)+((((0x4c41fe96))>>>((i0))))))|0;\n  }\n  return f; })(this, {ff: arguments.callee}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x100000000, Number.MAX_VALUE, 1, 1/0, 0x080000001, 0, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, -0x100000000, 42, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), 2**53, -0x0ffffffff, 0.000000000000001, -(2**53), 0x07fffffff, -0x07fffffff, 0x100000001, -0x100000001, 0/0, -0x080000000, -Number.MAX_VALUE, Number.MIN_VALUE, 0x0ffffffff, 0x080000000, 1.7976931348623157e308, -0, 2**53-2, -1/0]); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
