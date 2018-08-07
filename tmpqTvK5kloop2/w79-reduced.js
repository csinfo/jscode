

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
/*fuzzSeed-157142351*/count=1; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((((Math.atan(((( ! (Math.sqrt(( - y)) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0) ? (Math.hypot(0x080000000, Math.hypot(y, Math.imul((y == x), x))) >>> 0) : ((Math.min(mathy0(( + ( + ( + Math.max(( + -Number.MAX_SAFE_INTEGER), ( + y))))), Math.hypot(y, Math.fround(Math.max(Math.fround(x), Math.fround((Math.acos(( + x)) | 0)))))), (x | 0)) | 0) >>> 0)), ( + (Math.trunc(Math.max(x, ((( ! (x | 0)) | 0) ** (x ? x : (((x | 0) >>> ( + y)) | 0))))) | 0))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, 1, 0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 42, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0, 2**53+2, 0x080000001, 0x100000001, -1/0, -(2**53), Number.MAX_VALUE, -(2**53-2), -(2**53+2), Number.MIN_VALUE, 2**53-2, -0x080000000, -0x100000000, 0x07fffffff, -0x07fffffff, -0x100000001, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, -0, 2**53, -Number.MIN_VALUE, -0x080000001]); ");
/*fuzzSeed-157142351*/count=2; tryItOut("\"use strict\"; /*MXX1*/o1 = g0.RegExp.prototype;");
/*fuzzSeed-157142351*/count=3; tryItOut("return x;");
/*fuzzSeed-157142351*/count=4; tryItOut("let (x, quugdr, x = window, iiybdx, ovkves, z, window, kgayht) { throw (x) = Array.from; }");
/*fuzzSeed-157142351*/count=5; tryItOut("mathy4 = (function(x, y) { return (((( + (Math.fround(x) ? Math.fround(mathy2(y, -0x100000000)) : Math.fround((Number.MIN_VALUE !== (( + Number.MAX_SAFE_INTEGER) >>> 0))))) ? 1.7976931348623157e308 : (Math.log10(-1/0) ? Math.max(x, Math.atanh(2**53)) : (Math.imul(x, x) | 0))) ? mathy2(x, ( + Math.hypot(x, (Math.pow(-0, 1/0) | 0)))) : ((((Math.fround(((Math.fround((x >>> 0)) >>> 0) === -1/0)) | 0) + (x | 0)) | 0) % ( + ( ! Math.fround(Math.sinh(x)))))) ? Math.sin(( + Math.atan((mathy0((((Math.min(y, -0x100000001) | 0) >= Math.fround(mathy3(Math.fround(Math.fround(Math.trunc(x))), Math.fround(y)))) >>> 0), 2**53+2) >>> 0)))) : mathy2(Math.acosh((y / ((Math.max((-0x080000000 >>> 0), -Number.MAX_SAFE_INTEGER) >>> Math.sin(x)) >>> 0))), (( ! ( + Math.exp(( + (y ** (x >>> 0)))))) | 0))); }); testMathyFunction(mathy4, /*MARR*/[(1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0),  /x/g ,  /x/g , (1/0),  \"use strict\" , (1/0),  /x/g , (1/0), (1/0),  /x/g ,  /x/g ,  \"use strict\" , (1/0), (1/0),  \"use strict\" ,  /x/g , (1/0), (1/0),  /x/g ,  /x/g ,  /x/g ,  \"use strict\" ,  /x/g , (1/0),  /x/g ,  \"use strict\" , (1/0),  /x/g ,  \"use strict\" , (1/0),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/g , (1/0),  \"use strict\" ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (1/0), (1/0),  /x/g , (1/0),  \"use strict\" ,  /x/g ,  \"use strict\" ,  /x/g ,  \"use strict\" ,  \"use strict\" ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (1/0), (1/0), (1/0),  \"use strict\" ,  \"use strict\" , (1/0),  /x/g ,  \"use strict\" ]); ");
/*fuzzSeed-157142351*/count=6; tryItOut("\"use strict\"; (Element());");
/*fuzzSeed-157142351*/count=7; tryItOut("t2 = new Uint16Array(t1);");
/*fuzzSeed-157142351*/count=8; tryItOut("\"use strict\"; this.o1.a1[({valueOf: function() { /*RXUB*/var r = r0; var s = s2; print(s.split(r)); return 2; }})] = e2;");
/*fuzzSeed-157142351*/count=9; tryItOut("mathy2 = (function(x, y) { return (Math.fround(((Math.log1p(( + Math.fround(( + (( ~ x) | 0))))) | 0) >> (( + ( - (Math.sign((Number.MIN_VALUE | 0)) | x))) | 0))) != Math.hypot(mathy0(( + Number.MAX_SAFE_INTEGER), ( + ( ! x))), (((((Math.hypot(x, Math.atan(( + 2**53))) ? ( ! y) : x) >>> 0) ** ((((Math.min(0x0ffffffff, (y >>> 0)) >>> 0) > (Math.atan2(Math.pow(y, x), Math.max(42, y)) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0))); }); testMathyFunction(mathy2, [1.7976931348623157e308, -0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x100000000, 2**53+2, -0x080000001, 0x100000000, 1/0, -(2**53-2), 0x080000000, Number.MIN_VALUE, 2**53-2, -(2**53+2), -1/0, -Number.MAX_SAFE_INTEGER, 1, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 42, 0/0, 2**53, -(2**53), -0x080000000, 0x0ffffffff, -Number.MIN_VALUE, Math.PI, -0, -0x100000001, -0x0ffffffff, 0x080000001, Number.MAX_VALUE, 0]); ");
/*fuzzSeed-157142351*/count=10; tryItOut("\"use strict\"; let c = (eval-- ? (uneval(false)) : x);i0.send(p0);");
/*fuzzSeed-157142351*/count=11; tryItOut("var ajmngs = new ArrayBuffer(16); var ajmngs_0 = new Uint16Array(ajmngs); print(ajmngs_0[0]); ajmngs_0[0] = 18; var ajmngs_1 = new Uint8Array(ajmngs); print(ajmngs_1[0]); ajmngs_1[0] = (z || c); var ajmngs_2 = new Float64Array(ajmngs); ajmngs_2[0] = -3900924749; var ajmngs_3 = new Float32Array(ajmngs); print(ajmngs_3[0]); ajmngs_3[0] = -23; var ajmngs_4 = new Int16Array(ajmngs); ajmngs_4[0] = -29; selectforgc(o0);s2 += 'x';break M;");
/*fuzzSeed-157142351*/count=12; tryItOut("s0 += 'x';");
/*fuzzSeed-157142351*/count=13; tryItOut("e1.has(o1);");
/*fuzzSeed-157142351*/count=14; tryItOut("/*hhh*/function cwatvx(y, this.of, ...x){(new RegExp(\".|[^]*?\", \"yim\"));}/*iii*/(void options('strict'));\na1 = [];\n");
/*fuzzSeed-157142351*/count=15; tryItOut("for(let y in /*MARR*/[0x50505050, -Infinity, -Infinity, x, -Infinity, Number.MIN_VALUE, 0x50505050, -Infinity, 0x50505050, x, x, -Infinity, -Infinity, 0x50505050, x, x, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, 0x50505050, x, x, 0x50505050, 0x50505050, Number.MIN_VALUE, x, x, -Infinity, -Infinity, -Infinity, -Infinity, x, 0x50505050, -Infinity, Number.MIN_VALUE, -Infinity, 0x50505050, x, x, 0x50505050, x, Number.MIN_VALUE]) for(let a in []);return;");
/*fuzzSeed-157142351*/count=16; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return (mathy0(( - (y ? x : ((y | x) , 42))), Math.fround((x < (( + Math.hypot(( + Math.fround(Math.log(Math.fround(y)))), ( + y))) | 0)))) & Math.sinh(Math.min((x >> (Math.asinh(Math.fround(1/0)) | 0)), 2**53+2))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, -0x080000000, -0x100000001, 0/0, 0x07fffffff, -0x080000001, 0x100000001, Number.MIN_VALUE, 0x080000001, -0x100000000, 0x080000000, 2**53+2, 0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, -0, -0x07fffffff, 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), 1, Math.PI, 2**53, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, 0x0ffffffff, 1.7976931348623157e308]); ");
/*fuzzSeed-157142351*/count=17; tryItOut("mathy0 = (function(x, y) { return Math.hypot(Math.fround(Math.round(((Math.imul(Math.fround(((Math.fround(( ! Math.fround(x))) >>> ( + x)) >= (x % Math.ceil(( ! y))))), x) >>> 0) | 0))), Math.tan(Math.atan2(Math.fround((( - ( + y)) >>> 0)), (Math.fround(y) == (Math.log(Math.fround((x !== x))) | 0))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, -(2**53-2), 0x080000000, -0, -1/0, 1, 0/0, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000000, 0x100000001, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, -0x0ffffffff, -(2**53), -0x080000001, 0x080000001, -0x080000000, 2**53, 0, Number.MAX_SAFE_INTEGER, 42, 1/0, 0.000000000000001, 0x100000000, 0x07fffffff, 0x0ffffffff, -(2**53+2), Number.MAX_VALUE, Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=18; tryItOut("mathy5 = (function(x, y) { return Math.hypot(( ! ( + mathy1(( + Math.acosh(( + Math.fround(y)))), ( + Math.ceil((Math.imul(( + Math.ceil(( + 0x100000001))), Math.fround(-0)) === Math.log10(x))))))), Math.min(( + (( ~ (y >>> 0)) | ((mathy2((x >>> 0), (x > x)) >>> 0) > Math.fround(( ~ (Math.log10(y) >>> 0)))))), ( + ( ~ ( + (( + ( - y)) , 0/0)))))); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, -Number.MAX_VALUE, Number.MIN_VALUE, 0x07fffffff, -1/0, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, -0, 0.000000000000001, 0/0, -0x07fffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, 0, -0x0ffffffff, 1/0, 0x080000000, Number.MAX_VALUE, 1, -0x080000001, -(2**53), -0x080000000, 0x0ffffffff, -0x100000001, 2**53+2, -0x100000000, 2**53-2, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 42, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-157142351*/count=19; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.imul(( - Math.min((Math.acos(mathy2(( + (x >>> 0)), mathy0((y >>> 0), y))) >>> 0), (((Math.fround(Math.atan2(Math.log1p(x), (x ? x : (((1 | 0) * (y | 0)) | 0)))) ** ( ~ ((( - y) | 0) | 0))) | 0) >>> 0))), ( + ((( + (Math.fround(x) ? x : ( ~ ( + x)))) >>> ( + Math.fround(Math.hypot(x, Math.fround(y))))) ^ ( + ((( + (( + y) < ( + Math.min(x, x)))) ? ((-0 | 0x0ffffffff) || Math.tanh(( ~ y))) : (Math.log(x) >>> 0)) | 0))))) | 0); }); testMathyFunction(mathy3, [Math.PI, -(2**53+2), 2**53+2, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, 0, 2**53, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, -0x07fffffff, -0x100000001, 42, 0x080000001, -(2**53), 2**53-2, -Number.MAX_VALUE, -0x0ffffffff, Number.MAX_VALUE, -0x080000000, -0, 0/0, 0x0ffffffff, 1, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 0x07fffffff, -0x100000000]); ");
/*fuzzSeed-157142351*/count=20; tryItOut("\"use strict\"; a2[({valueOf: function() { /* no regression tests found */return 17; }})] = x;");
/*fuzzSeed-157142351*/count=21; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-157142351*/count=22; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.atan2(( + Math.atan2(( + Math.atanh(( ! Math.fround(-0x080000001)))), ( + Math.imul((x ? (y && -(2**53-2)) : Math.fround(y)), -0x080000001)))), Math.fround(Math.tanh((y < y)))) & Math.imul(( + ( ! mathy0(y, ( + ( ~ ( + y)))))), ((( + ( - ( + x))) / y) >>> 0))) | 0); }); testMathyFunction(mathy3, [Math.PI, 0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53+2, 0x07fffffff, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0, 0, -Number.MAX_VALUE, -0, -(2**53+2), 0x100000000, 42, -0x100000001, 0.000000000000001, Number.MAX_VALUE, 1, -0x080000000, 0x080000000, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 2**53, 0/0, -(2**53-2), -0x100000000, -0x080000001, 2**53-2, -0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=23; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=24; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=25; tryItOut("/*MXX1*/o0 = o2.g2.RangeError;");
/*fuzzSeed-157142351*/count=26; tryItOut("\"use strict\"; v0 = t2[{x: [, {x}]} = undefined.yoyo(Math.min(-24, -6))];/* no regression tests found */");
/*fuzzSeed-157142351*/count=27; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.clz32(( + ((( ~ Math.hypot(( + ((x >>> 0) <= y)), ( + (( ~ x) >>> 0)))) >>> 0) ? /*oLoop*/for (axcwco = 0; axcwco < 72; ++axcwco) { o1 + ''; }  : (mathy1((((-0x100000001 | 0) << ((((y >>> 0) && y) >>> 0) >>> 0)) | 0), Math.imul((y | 0), ( + ( + ( + (( ~ (x | 0)) | 0)))))) >>> 0)))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 2**53-2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, -0, -Number.MIN_SAFE_INTEGER, 0, -Number.MIN_VALUE, -(2**53+2), -(2**53-2), -0x100000001, -0x0ffffffff, 0x0ffffffff, 0/0, -Number.MAX_VALUE, 0x07fffffff, -0x080000000, 0x080000001, -1/0, -0x100000000, 1, Number.MAX_VALUE, -0x080000001, 0.000000000000001, 1/0, 1.7976931348623157e308, Number.MIN_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000000, 0x100000001, Math.PI, 42, -(2**53)]); ");
/*fuzzSeed-157142351*/count=28; tryItOut("dxpqei();/*hhh*/function dxpqei(){/*RXUB*/var r = /(?![^](?!(?![^]*){1,5}|\\S){1,})+/gym; var s = \"\"; print(s.match(r)); }");
/*fuzzSeed-157142351*/count=29; tryItOut("\"use strict\"; e.stack;x.fileName;function w() { return (yield /*MARR*/[ /x/g , -Infinity,  /x/g , -Infinity, -Infinity,  /x/g ].sort) } m0.get((eval(\"/* no regression tests found */\", ()))(x));");
/*fuzzSeed-157142351*/count=30; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.ceil(Math.fround(Math.trunc(((( + ( ~ ( + x))) / (Math.atan2(x, x) <= y)) >>> 0)))) | 0); }); testMathyFunction(mathy3, [0, -0x100000001, 0x080000001, -Number.MAX_VALUE, -0x07fffffff, 0x100000001, -1/0, 0x07fffffff, 1.7976931348623157e308, 0/0, -0x080000000, 0x0ffffffff, -0, 0x080000000, 1/0, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, -(2**53+2), 1, 0x100000000, -Number.MIN_VALUE, -(2**53-2), 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, Number.MIN_VALUE, -0x080000001, 0.000000000000001, Number.MAX_VALUE, 2**53+2, -0x0ffffffff, 42]); ");
/*fuzzSeed-157142351*/count=31; tryItOut("/*bLoop*/for (var peynyc = 0, (yield  /x/g ); peynyc < 94; ++peynyc) { if (peynyc % 97 == 2) { Object.defineProperty(this, \"this.v1\", { configurable: false, enumerable: true,  get: function() { o1.v0 = r2.sticky; return evalcx(\"/* no regression tests found */\", g2); } }); } else { throw undefined; }  } v2 = r1.constructor;");
/*fuzzSeed-157142351*/count=32; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + Math.fround(( ~ Math.fround((Math.fround(1.7976931348623157e308) ? y : Math.fround(( ! y))))))); }); testMathyFunction(mathy1, [0x100000000, -(2**53-2), 0x07fffffff, Math.PI, -0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, Number.MAX_VALUE, -1/0, -(2**53), 1.7976931348623157e308, -0x080000000, 2**53, 1, 0x080000001, -0x080000001, 42, -(2**53+2), -0x100000000, 0/0, -Number.MAX_VALUE, 2**53-2, 2**53+2, -Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, 1/0, 0x080000000, -0x100000001]); ");
/*fuzzSeed-157142351*/count=33; tryItOut("\"use strict\"; o0 + o1;");
/*fuzzSeed-157142351*/count=34; tryItOut("for (var v of i0) { try { a2[6]; } catch(e0) { } try { s2 += 'x'; } catch(e1) { } e1 + ''; }");
/*fuzzSeed-157142351*/count=35; tryItOut("/*RXUB*/var r = new RegExp(\"(?:\\\\x5D)\", \"y\"); var s = \"\\u7ed7\"; print(s.search(r)); ");
/*fuzzSeed-157142351*/count=36; tryItOut("\"use strict\"; /*oLoop*/for (var jebsni = 0; jebsni < 44; ++jebsni) { e2.has(s2); } ");
/*fuzzSeed-157142351*/count=37; tryItOut("\"use strict\"; { void 0; void 0; } a1.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) { var r0 = a11 / a7; var r1 = a0 * a0; var r2 = a10 | a4; var r3 = a11 & 2; var r4 = 2 / 8; var r5 = 2 / 5; var r6 = a8 / a5; var r7 = 5 | a4; var r8 = 9 * r0; var r9 = r3 + a7; var r10 = a10 * 7; var r11 = r7 - r8; var r12 = a3 / r8; var r13 = a11 - 6; a3 = r2 - 4; var r14 = 0 & 7; var r15 = 8 % 8; r2 = 2 | r12; var r16 = 2 * 1; r8 = r3 % 6; var r17 = 2 / r8; var r18 = r8 - a5; a11 = 9 + r16; var r19 = r2 & r3; var r20 = r8 + a3; var r21 = a0 & r9; a0 = r10 - a11; var r22 = r10 * r18; var r23 = r12 * 0; var r24 = r12 % r7; var r25 = r13 | x; var r26 = 8 - 5; print(r23); var r27 = a6 / a8; var r28 = a8 / 7; var r29 = a0 % r3; var r30 = a6 ^ r10; var r31 = r26 % a2; var r32 = 9 - a10; r14 = a1 + a9; x = r13 - a4; var r33 = 3 * r24; var r34 = a6 + r4; var r35 = 1 + a3; var r36 = x % r22; var r37 = 5 - a9; a0 = 6 % r30; r25 = r13 & r22; var r38 = 7 ^ a8; var r39 = r23 - r35; var r40 = r1 * 2; var r41 = r40 + r29; var r42 = 0 | a5; var r43 = 4 % 9; r28 = 9 % x; var r44 = r18 / r11; var r45 = r34 & r30; var r46 = 2 / r43; print(r43); var r47 = r37 % 2; var r48 = 5 | r13; var r49 = 3 ^ r15; a11 = r42 / r16; var r50 = a3 / r5; var r51 = 0 | 1; var r52 = a8 * 1; var r53 = r46 & r45; var r54 = 4 * r20; var r55 = 6 * 7; r29 = r42 % a2; print(r7); var r56 = r20 & 8; var r57 = r7 ^ a7; var r58 = r53 - r12; var r59 = 5 % 4; var r60 = 9 / r45; return a7; }));");
/*fuzzSeed-157142351*/count=38; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return Math.fround(( + Math.fround((( + (Math.pow(x, ( + ( - ( + Math.log10(y))))) >>> 0)) | 0)))); }); testMathyFunction(mathy3, [0x0ffffffff, 0x100000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 2**53-2, -0, 2**53, -0x080000001, -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, Number.MIN_VALUE, 0x080000001, 1, 0/0, -(2**53-2), -(2**53+2), 2**53+2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, -0x100000000, -0x080000000, 42, -0x100000001, Math.PI, 0x080000000, 0x07fffffff]); ");
/*fuzzSeed-157142351*/count=39; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[('fafafa'.replace(/a/g, Boolean.prototype.valueOf)), null, ('fafafa'.replace(/a/g, Boolean.prototype.valueOf)), null,  \"\" ]); ");
/*fuzzSeed-157142351*/count=40; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((( + Math.log1p(( + x))) ? y : (Math.fround(( ! y)) << x)) ^ ( + mathy3(( + ( + (Math.fround(( ~ 0.000000000000001)) - Math.ceil(( + ((Math.pow((-Number.MAX_VALUE | 0), (y | 0)) | 0) | 0)))))), ((y | Math.fround((0/0 | 0))) >>> 0)))) == ( + ( ~ ((((Math.max(Math.fround(y), Math.fround(y)) + mathy1(-(2**53), Math.fround(Math.min(x, ( ! (x >>> 0)))))) | 0) - ((( - ( ! y)) | 0) | 0)) | 0)))); }); ");
/*fuzzSeed-157142351*/count=41; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var d3 = -36893488147419103000.0;\n    return +((-70368744177664.0));\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [2**53+2, Math.PI, 0x100000000, -0x07fffffff, -0x100000000, -0, 1/0, 0.000000000000001, -1/0, -(2**53), -0x080000001, 42, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, -0x100000001, 0/0, 0x080000000, 2**53, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 2**53-2, -0x080000000, 0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 1, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=42; tryItOut("g2.e0 + h1;");
/*fuzzSeed-157142351*/count=43; tryItOut("for(a in /(?!(?=\\d))|\\s/g) throw window;");
/*fuzzSeed-157142351*/count=44; tryItOut("\"use strict\"; /*RXUB*/var r = ((function factorial_tail(ffkktp, otzpcq) { ; if (ffkktp == 0) { print( /x/ );; return otzpcq; } ; return factorial_tail(ffkktp - 1, otzpcq * ffkktp);  })(29087, 1)); var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-157142351*/count=45; tryItOut("for(let a in (((new Function(\"p0 + a2;\")))((4277)))){Array.prototype.splice.call(a2, 15, 0); }");
/*fuzzSeed-157142351*/count=46; tryItOut("this.a1.shift(this.f2);");
/*fuzzSeed-157142351*/count=47; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0, -Number.MAX_SAFE_INTEGER, 2**53+2, 1, 2**53-2, -0x100000000, -0x0ffffffff, 0x100000001, -(2**53), -Number.MAX_VALUE, -1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, 0x080000001, -Number.MIN_VALUE, 0x100000000, 0/0, -0x100000001, 2**53, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -(2**53+2), -0, -0x080000000, Number.MAX_SAFE_INTEGER, -0x080000001, 42, -0x07fffffff, -(2**53-2), 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-157142351*/count=48; tryItOut("\"use strict\"; t0 = new Int32Array(this.a2);");
/*fuzzSeed-157142351*/count=49; tryItOut("\"use strict\"; o0.a2 + '';");
/*fuzzSeed-157142351*/count=50; tryItOut("\"use strict\"; Array.prototype.forEach.call(a2, (function() { for (var j=0;j<98;++j) { f1(j%5==1); } }));");
/*fuzzSeed-157142351*/count=51; tryItOut("print(x);");
/*fuzzSeed-157142351*/count=52; tryItOut("/*oLoop*/for (var blsuaa = 0; (x) && blsuaa < 1; ++blsuaa) { /(?=.+){4,}/m } ");
/*fuzzSeed-157142351*/count=53; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 2048.0;\n    var d3 = 1.0078125;\nconst s0 = a0.join(s2);    return (((0x33af737b)+(i0)-(i0)))|0;\n  }\n  return f; })(this, {ff: (function(y) { \"use strict\"; yield y;  '' ;; yield y; }).apply}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53+2), 2**53+2, 1, -1/0, -0x07fffffff, 1/0, 2**53-2, -0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53, 42, Number.MAX_VALUE, 0, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, Math.PI, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x100000001, -(2**53-2), 0x080000001, -Number.MAX_VALUE, 0/0, Number.MIN_VALUE, 0.000000000000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, -0x100000000, 0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-157142351*/count=54; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.sinh(Math.fround(((((( ! (Math.pow((( + 0x100000001) ^ y), Math.fround(Math.max(Math.fround(y), Math.fround(Math.max(( ! x), 0))))) >>> 0)) >>> 0) >>> 0) , (Math.hypot((( + Math.log(x)) <= ( + mathy2(y, x))), y) | 0)) >>> 0)))); }); testMathyFunction(mathy3, [0/0, 0x100000000, 0x100000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 2**53+2, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 42, 0x0ffffffff, Number.MIN_VALUE, 0x080000001, -0x07fffffff, Math.PI, 1/0, -0x0ffffffff, -0, 1.7976931348623157e308, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, -Number.MIN_VALUE, 2**53, 0, 1, 2**53-2, -(2**53+2), -0x100000000, -1/0, -0x080000001]); ");
/*fuzzSeed-157142351*/count=55; tryItOut("mathy3 = (function(x, y) { return (Math.log((( - ( + (( + x) < ( + ((y >>> 0) <= y))))) | 0)) | 0); }); ");
/*fuzzSeed-157142351*/count=56; tryItOut("/*hhh*/function pbmvgp(d, x){a2[7] = this.m0;}/*iii*/v0 = (v2 instanceof t2);{}");
/*fuzzSeed-157142351*/count=57; tryItOut("\"use strict\"; var d = false;i2.send(i2);");
/*fuzzSeed-157142351*/count=58; tryItOut("print(/*MARR*/[({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), new String(''), ({}), ({}), new String(''), new String(''), new String(''), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), ({}), new String(''), new String(''), ({}), new String(''), new String(''), new String(''), ({}), ({}), new String(''), ({}), new String(''), ({}), ({}), ({}), ({})].some(() => \nx, (new -15(new RegExp(\"\\\\B\", \"gyi\"),  \"\" ))));\na0[13];\n");
/*fuzzSeed-157142351*/count=59; tryItOut("\"use strict\"; let(dbjuls, eofyyh, e, iwzjii, NaN, x) { {}}\nlet (fceivq) { m0.get(o1); }\n");
/*fuzzSeed-157142351*/count=60; tryItOut("\"use strict\"; testMathyFunction(mathy2, /*MARR*/[(void 0), -0, -0, function(){}, (void 0), function(){},  /x/g , (void 0),  /x/g , ({}),  /x/g , (void 0), ({}), -0, (void 0), -0, -0, -0,  /x/g , ({}), ({}),  /x/g , function(){}, (void 0),  /x/g , function(){},  /x/g , function(){}, (void 0), function(){},  /x/g , -0, -0, ({}), -0, -0, function(){}, ({}), (void 0), function(){}, ({}), (void 0), (void 0), function(){}, (void 0), function(){}, ({}),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , -0, function(){}, ({}), -0,  /x/g , function(){},  /x/g , function(){}, function(){}, function(){}, (void 0), ({}), ({}), (void 0), -0,  /x/g , ({}),  /x/g ,  /x/g , function(){}]); ");
/*fuzzSeed-157142351*/count=61; tryItOut("\"use strict\"; /*RXUB*/var r = /$/g; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-157142351*/count=62; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Int8ArrayView[((0xffffffff)+(0xcdde3aae)+(0x1c6104d)) >> 0]) = (((~((0xe798336a))) != (~~(d0)))-(((Int32ArrayView[4096])) > (((/*FFI*/ff(((((0xfe323a41)+((0x227ed77) == (-0x23ac845))) | ((0xfd500135)-(-0x8000000)+(0xd38d125f)))), (((((0x7fffffff))) << ((0x6a29ffba)))), ((((0x1ef77aa9)) >> ((0xff204ef1)))))|0)) >> ((Int8ArrayView[((abs((0x7fffffff))|0) % (abs((0x394cb40e))|0)) >> 0])))));\n    d1 = (d1);\n    /*FFI*/ff(((imul(((d0) == (d1)), (0x43882fe2))|0)), ((d1)), ((Infinity)), ((((0xd963335f)-((0x489616e) ? (0xfd58da92) : (0xfb8053c6))) | ((0xfb73ea79)))), ((d1)), ((d1)), ((d1)), ((-549755813889.0)), ((4.722366482869645e+21)), ((-1025.0)), ((-4.722366482869645e+21)), ((-65537.0)), ((576460752303423500.0)));\n    d1 = (+(~(((((-0x8000000)*0xfffff)>>>((0x5fe3fff6) % (0x95ac7c2a))) < (0xe7c7214b))-((((Uint32ArrayView[1])) & ((0x78620e5d)+(-0x8000000))))+(0x3e18485f))));\n    {\n      d1 = (+/*FFI*/ff());\n    }\n    (Float32ArrayView[0]) = ((Float32ArrayView[(((((Uint8ArrayView[((Uint8ArrayView[1])) >> 0])) ^ ((((0x83d666fd))>>>((0xca22210))) % (((0xfa5f3526))>>>((0x619af3ff))))) != (~~(d1)))*0xba543) >> 2]));\n    d1 = (+(-1.0/0.0));\n    return +((+abs(((Float32ArrayView[(((-0x8000000) ? (!(0xfc008155)) : (0xffffffff))) >> 2])))));\n  }\n  return f; })(this, {ff: decodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[2**53, new Boolean(false), 2**53, x, 2**53, new Boolean(false), x, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, x, 2**53, x, x, 2**53, x, new Boolean(false), new Boolean(false), 2**53, 2**53, 2**53, 2**53, x, new Boolean(false), x, x, new Boolean(false), 2**53, 2**53, 2**53, new Boolean(false), x, new Boolean(false), 2**53, x, 2**53, 2**53, 2**53, 2**53, new Boolean(false), new Boolean(false), x, new Boolean(false), new Boolean(false), x, 2**53, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), x, new Boolean(false), 2**53, 2**53, new Boolean(false), new Boolean(false), 2**53, 2**53, new Boolean(false), x, new Boolean(false), 2**53, 2**53, new Boolean(false), 2**53, 2**53, new Boolean(false), x, 2**53, x, 2**53, 2**53, 2**53, x, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), 2**53, 2**53, new Boolean(false), x, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), 2**53, new Boolean(false), x, x, 2**53, x, new Boolean(false), 2**53, new Boolean(false), new Boolean(false), new Boolean(false), 2**53, x, new Boolean(false), x, x, 2**53, x, x, x, 2**53, new Boolean(false), x, x, x, new Boolean(false), new Boolean(false), x, 2**53, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), 2**53]); ");
/*fuzzSeed-157142351*/count=63; tryItOut("\"use strict\"; while(((-1/0)) && 0)/*RXUB*/var r = /(?:\\b)/im; var s = \"a \"; print(s.replace(r, x)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=64; tryItOut("\"use strict\"; this.e2.add(m2);");
/*fuzzSeed-157142351*/count=65; tryItOut("/*RXUB*/var r = function(id) { return id }; var s = \"\"; print(s.split(r)); continue ;");
/*fuzzSeed-157142351*/count=66; tryItOut("i2.send(t2);/* no regression tests found */");
/*fuzzSeed-157142351*/count=67; tryItOut("mathy5 = (function(x, y) { return Math.fround((Math.imul((((y != y) ? x : Math.fround((( + (( + mathy2(( + x), x)) >>> x)) != Math.fround(mathy0(y, ( + x)))))) , (Math.abs((y >>> 0)) >>> 0)), Math.hypot(Math.atan2((Math.fround(( + -1/0)) >>> 0), x), -Number.MAX_VALUE)) >= (Math.fround(Math.hypot(Math.fround(Math.asin(( ! ( ~ y)))), ( + (( + (( + ((0 | 0) , (0/0 >>> 0))) ? Math.fround(y) : x)) >>> ( + Math.sinh(( + Math.trunc(y)))))))) | 0))); }); ");
/*fuzzSeed-157142351*/count=68; tryItOut("M:for(let w = window in (w => -7(\"\\uF683\"))) print(window);");
/*fuzzSeed-157142351*/count=69; tryItOut("this.g0 + this.o1;");
/*fuzzSeed-157142351*/count=70; tryItOut("");
/*fuzzSeed-157142351*/count=71; tryItOut("s1 += 'x';");
/*fuzzSeed-157142351*/count=72; tryItOut("/*oLoop*/for (fjxvgv = 0; fjxvgv < 121; ++fjxvgv) { print(x); } ");
/*fuzzSeed-157142351*/count=73; tryItOut("f2 = (function() { try { Array.prototype.forEach.call(a2, (function() { try { Array.prototype.shift.apply(a2, []); } catch(e0) { } print(e2); return f1; }), ([undefined])); } catch(e0) { } try { g2.toSource = (function() { for (var j=0;j<40;++j) { f1(j%3==1); } }); } catch(e1) { } try { h1 = g2.objectEmulatingUndefined(); } catch(e2) { } v1 = (g2.b1 instanceof e2); return o1; });function c() { \"use strict\"; b2 = t2.buffer; } t1[5] = f2;");
/*fuzzSeed-157142351*/count=74; tryItOut("\"use strict\"; testMathyFunction(mathy4, [undefined, 1, 0.1, '\\0', ({valueOf:function(){return '0';}}), false, 0, (new Boolean(false)), ({valueOf:function(){return 0;}}), NaN, '/0/', (new Number(-0)), -0, (new Boolean(true)), '0', (new Number(0)), true, (function(){return 0;}), [0], /0/, ({toString:function(){return '0';}}), (new String('')), objectEmulatingUndefined(), [], null, '']); ");
/*fuzzSeed-157142351*/count=75; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (( + ( ! ( + Math.fround(Math.fround(Math.fround(( - x))))))) | 0)); }); testMathyFunction(mathy2, [null, /0/, [], ({valueOf:function(){return 0;}}), (new Boolean(false)), '/0/', (new String('')), ({toString:function(){return '0';}}), '', 0.1, '\\0', 1, '0', undefined, (function(){return 0;}), false, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), (new Number(-0)), (new Boolean(true)), -0, true, (new Number(0)), [0], 0, NaN]); ");
/*fuzzSeed-157142351*/count=76; tryItOut("e = linkedList(e, 735);");
/*fuzzSeed-157142351*/count=77; tryItOut("pqltoe((let (epmzli, b, w) arguments));/*hhh*/function pqltoe(...c){a1 = arguments.callee.arguments;}");
/*fuzzSeed-157142351*/count=78; tryItOut("\"use strict\"; v0 = (p0 instanceof b1);");
/*fuzzSeed-157142351*/count=79; tryItOut("/*RXUB*/var r = -27; var s = \"\"; print(s.split(r)); ");
/*fuzzSeed-157142351*/count=80; tryItOut("\"use asm\"; x, ablafz, pzxyjq, x, x, x, tjxfzl, z;/*RXUB*/var r = new RegExp(\"\\\\1|(?:(?!\\\\u2D25))+?|[^]*?|[\\u1eb2\\\\b-\\u009d\\u78ed-\\\\v\\\\\\u00ac-\\\\\\u22e5][^]|(?=\\u4904[\\\\cG-\\\\u0053]){0}|(?=(?:[^]|\\\\D|\\\\D))(?:[\\\\n-\\\\cT]{2,}){16777217}\", \"gym\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\u0010\\u0010\\n\\n\\n\\n\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-157142351*/count=81; tryItOut("\"use asm\"; /*bLoop*/for (var euljws = 0, eval = /(?!\\B{1})*?/ >= x, xyfhjn,  \"\" ; (eval = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( '' ), e += new RegExp(\"\\\\D*\\\\W|${3,3}+?\\\\w|[^]+{2,5}|(?![^\\u008f\\\\w][^])*[^]{1,}\\\\2|(?!\\u00da|\\\\3+?\\ueaf5+?(?![^])$)\", \"im\"), Date.prototype.toLocaleString)) && euljws < 15; ++euljws) { if (euljws % 3 == 0) { /*RXUB*/var r = new RegExp(\"((?![^\\u00bf\\\\d\\\\b-\\\\cC\\u3455-\\\\uD01A]*?((?![^])+)(?!\\\\r|[^\\u001d-\\ufffe])+?)(?=(?!(?=(?:@?)))[\\\\0\\u000f-\\\\xcD]?))\", \"y\"); var s = \"-\"; print(r.test(s)); print(r.lastIndex);  } else { for (var p in a1) { try { m0.set(a1, s0); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(t1, p0); } catch(e1) { } v2 = Object.prototype.isPrototypeOf.call(this.a1, o1); } }  } ");
/*fuzzSeed-157142351*/count=82; tryItOut("o0.i0.toString = f2;");
/*fuzzSeed-157142351*/count=83; tryItOut("testMathyFunction(mathy5, [-(2**53-2), -1/0, -(2**53), -(2**53+2), -0x080000001, -0x100000000, -0x07fffffff, 2**53, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_VALUE, 0x0ffffffff, 0, 0.000000000000001, 0x080000000, 0x07fffffff, 1, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, 0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, 0/0, 1/0, 0x100000001, -0x0ffffffff, 2**53+2, -0x080000000, -0, Number.MAX_VALUE, Math.PI]); ");
/*fuzzSeed-157142351*/count=84; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( - (Math.acos(((Math.imul((mathy2((0x080000001 | 0), (-0x080000000 | 0)) >>> 0), ((x > ( + x)) | 0)) && x) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [Number.MAX_VALUE, 2**53+2, 2**53, -0x080000000, -Number.MAX_SAFE_INTEGER, 1/0, 42, -0x080000001, 0x080000000, 0.000000000000001, 0/0, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, -(2**53+2), 0, -0x100000000, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x07fffffff, 1, Math.PI, 0x080000001, 0x100000001, -0, Number.MIN_VALUE, -(2**53), 2**53-2, -0x0ffffffff]); ");
/*fuzzSeed-157142351*/count=85; tryItOut("\"use strict\"; ");
/*fuzzSeed-157142351*/count=86; tryItOut("if((x % 6 != 1)) ;");
/*fuzzSeed-157142351*/count=87; tryItOut("mathy0 = (function(x, y) { return Math.min(Math.min(Math.log1p(Math.max(x, ( + ( ~ (2**53-2 | 0))))), ( + ( + Math.acos(Math.fround(x))))), Math.fround(((Math.fround(( + (( + Math.min(-0x100000000, (x | 0))) ? ( + x) : ( + x)))) % Math.acosh(Math.imul(x, Math.fround(0x100000001)))) / Math.sqrt(Math.fround(y))))); }); testMathyFunction(mathy0, [({valueOf:function(){return 0;}}), '', '/0/', /0/, true, (new Boolean(true)), ({toString:function(){return '0';}}), '0', (new Boolean(false)), [], (new Number(-0)), 1, false, (new Number(0)), null, ({valueOf:function(){return '0';}}), '\\0', NaN, [0], 0, (new String('')), objectEmulatingUndefined(), -0, (function(){return 0;}), undefined, 0.1]); ");
/*fuzzSeed-157142351*/count=88; tryItOut("\"use strict\"; switch(timeout(1800)) { default: break;  }");
/*fuzzSeed-157142351*/count=89; tryItOut("/*RXUB*/var r = r2; var s = this.s1; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=90; tryItOut("o2.__iterator__ = (function() { try { o0.o1 + p2; } catch(e0) { } print(t0); return m0; });");
/*fuzzSeed-157142351*/count=91; tryItOut("v2 = g1.runOffThreadScript();");
/*fuzzSeed-157142351*/count=92; tryItOut("e0.valueOf = (function mcc_() { var jnnpqy = 0; return function() { ++jnnpqy; if (/*ICCD*/jnnpqy % 10 == 8) { dumpln('hit!'); try { g0.v0 = Object.prototype.isPrototypeOf.call(v0, o1.t1); } catch(e0) { } try { g0.v2 = Object.prototype.isPrototypeOf.call(t1, h0); } catch(e1) { } try { a2.push(h0); } catch(e2) { } m2.toString = f0; } else { dumpln('miss!'); try { v1 = (h1 instanceof f2); } catch(e0) { } try { g1.e0.has(b0); } catch(e1) { } try { o1.v0 = a0.length; } catch(e2) { } for (var p in i0) { try { Object.seal(b2); } catch(e0) { } try { a0.reverse(m0); } catch(e1) { } a1[4]; } } };})();");
/*fuzzSeed-157142351*/count=93; tryItOut("this.a2.pop();");
/*fuzzSeed-157142351*/count=94; tryItOut("\"use strict\"; h0.hasOwn = (function() { try { /*MXX1*/o2 = g1.DataView.prototype.setInt16; } catch(e0) { } try { Array.prototype.unshift.apply(a0, [t1, h1]); } catch(e1) { } try { for (var v of e0) { i2.send(h0); } } catch(e2) { } v1 = Object.prototype.isPrototypeOf.call(v1, p1); throw this.g0; });");
/*fuzzSeed-157142351*/count=95; tryItOut("\"use strict\"; print(uneval(this.g2));");
/*fuzzSeed-157142351*/count=96; tryItOut("\"use strict\"; testMathyFunction(mathy1, ['\\0', (new String('')), [0], (new Boolean(false)), /0/, NaN, (function(){return 0;}), true, '/0/', ({valueOf:function(){return 0;}}), '0', false, objectEmulatingUndefined(), (new Number(0)), 1, '', undefined, [], (new Boolean(true)), 0.1, ({valueOf:function(){return '0';}}), -0, null, (new Number(-0)), ({toString:function(){return '0';}}), 0]); ");
/*fuzzSeed-157142351*/count=97; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.sqrt(( ~ Math.fround(( + Math.fround(( + ( ! Math.fround(x)))))))); }); testMathyFunction(mathy0, [-0x07fffffff, 2**53, 1.7976931348623157e308, -0x100000000, 0x100000000, Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, 0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), 42, 0x080000000, Math.PI, 0/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, -0x080000001, 2**53-2, Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, -0x0ffffffff, -0, 0x07fffffff, -1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, -(2**53), 1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-157142351*/count=98; tryItOut("\"use strict\"; ( '' );yield;");
/*fuzzSeed-157142351*/count=99; tryItOut("\"use strict\"; g1.s0 += s0;");
/*fuzzSeed-157142351*/count=100; tryItOut("this.m0.get(-13);");
/*fuzzSeed-157142351*/count=101; tryItOut("/*MXX3*/o0.g0.Array.prototype.toLocaleString = o1.g1.Array.prototype.toLocaleString;");
/*fuzzSeed-157142351*/count=102; tryItOut("/*tLoop*/for (let d of /*MARR*/[function(){}, ({}), function(){}, ({}), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, ({}), x, x, 0.000000000000001, x, x, x, x, x, ({}), 0.000000000000001, ({}), 0.000000000000001, 0.000000000000001, x, ({}), ({}), x, x, 0.000000000000001, ({}), 0.000000000000001, x, x, function(){}, 0.000000000000001, x, 0.000000000000001, 0.000000000000001, x]) { (void schedulegc(g0)); }");
/*fuzzSeed-157142351*/count=103; tryItOut("g2.t1[\"acosh\"] = g2;");
/*fuzzSeed-157142351*/count=104; tryItOut("/*RXUB*/var r = new RegExp(\"(?:[^\\\\n\\\\u00CA-\\\\r]*?)+?\", \"ym\"); var s = \"\"; print(s.split(r)); \nvar a = (timeout(1800)), x = (eval).unwatch(\"-8\"), jhcszn, NaN = \"\\uDE52\", {x: {e}, x: []} = (\u3056 << x);this.m0 + h2;\n");
/*fuzzSeed-157142351*/count=105; tryItOut("mathy4 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + Math.atanh((Math.atan2((( + Math.fround(Math.max(Math.fround(x), (((0/0 >>> 0) != (((x ** (-0x07fffffff >>> 0)) >>> 0) | 0)) >>> 0)))) | 0), Math.tan(( + eval(\"null\",  '' )))) | 0))); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000001, -(2**53-2), -0, 42, 0x07fffffff, 0x100000000, 0x0ffffffff, 1/0, -0x0ffffffff, -(2**53), -Number.MAX_VALUE, 0.000000000000001, -0x07fffffff, -(2**53+2), 0x080000000, -1/0, -0x100000001, -Number.MIN_VALUE, Math.PI, 0x080000001, 2**53-2, Number.MAX_SAFE_INTEGER, 0, 0/0, 1, 2**53, -0x080000000, Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=106; tryItOut("\"use strict\"; v1 = a0.every(x);v2 = (g1 instanceof e2);");
/*fuzzSeed-157142351*/count=107; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot((( ~ ( + ( ! (Math.atan2((Math.trunc((Math.clz32(y) | 0)) | 0), ( + y)) >>> 0)))) | 0), (Math.acos(x) >>> ( + Math.pow((mathy1(Math.hypot(Math.min((Math.pow((x >>> 0), (y >>> 0)) >>> 0), Math.asin(Number.MIN_SAFE_INTEGER)), Number.MAX_VALUE), x) >>> 0), ( + y))))); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -1/0, 0/0, 0x080000000, -0x080000000, -Number.MAX_VALUE, 0x080000001, -(2**53), -(2**53-2), 0.000000000000001, 0x0ffffffff, 0x100000001, 1/0, -0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, 0, 1, -0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, -0, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, 0x100000000, 42, -Number.MIN_VALUE, -0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-157142351*/count=108; tryItOut("h0.iterate = (function() { try { this.e0 + ''; } catch(e0) { } a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray;  return h2; });");
/*fuzzSeed-157142351*/count=109; tryItOut("mathy5 = (function(x, y) { return (((Math.log1p((Math.atan2(Math.fround(mathy2(x, ((Math.fround(x) >>> ((y ? y : x) >>> 0)) >>> 0))), Math.clz32(y)) >>> 0)) >>> 0) / (Math.fround(( + (((Math.fround(mathy4(( + ( - (x | 0))), ( + x))) >>> 0) << Math.fround((Math.pow(0x0ffffffff, ( - ( ~ y))) | 0))) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0, 1, Number.MAX_VALUE, -0, -1/0, 2**53-2, 0x100000001, 0x080000001, 0/0, 0x080000000, 2**53+2, 42, -0x0ffffffff, -(2**53-2), 0x100000000, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, Math.PI, -0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 0x0ffffffff, Number.MIN_VALUE, -0x080000000, 0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, 2**53]); ");
/*fuzzSeed-157142351*/count=110; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.max(((Math.asinh((Math.log(mathy2(2**53+2, Math.fround(Math.ceil(( + y))))) | 0)) << ( + Math.hypot(mathy1(Math.trunc((y >>> 0)), ((( ! Math.log2(( + 0x080000001))) >>> 0) | 0)), Math.fround((Math.pow((0 >>> 0), ((Math.acosh((-(2**53+2) >>> 0)) >>> 0) >>> 0)) >>> 0))))) | 0), ((( - (( ! Math.atan2((Math.trunc((x | 0)) >>> 0), (Math.log1p(y) >>> 0))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, [objectEmulatingUndefined(), NaN, ({valueOf:function(){return 0;}}), '\\0', 0.1, (new Number(0)), -0, (new String('')), (new Boolean(false)), false, 0, '/0/', null, '', (new Number(-0)), (new Boolean(true)), undefined, /0/, (function(){return 0;}), ({valueOf:function(){return '0';}}), '0', true, [], [0], ({toString:function(){return '0';}}), 1]); ");
/*fuzzSeed-157142351*/count=111; tryItOut("/*RXUB*/var r = /(?=[^]\\s\u00eb|[^]+[^\u00d4\\n-\\\u00b4\\xDd])*?/gi; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=112; tryItOut("/*MXX3*/g2.Proxy.revocable = g0.Proxy.revocable;");
/*fuzzSeed-157142351*/count=113; tryItOut("v1 = evalcx(\"for (var v of g2.g0.t0) { for (var p in p0) { try { Object.prototype.watch.call(s2, \\\"__count__\\\", (function() { for (var j=0;j<8;++j) { f2(j%5==1); } })); } catch(e0) { } o0 = s0.__proto__; } }\", g2.o1.g0);");
/*fuzzSeed-157142351*/count=114; tryItOut("/*RXUB*/var r = /((?!.|[^]{4}|(?=\\s+))+?)|\\w\\2+?/g; var s = Math.atan2( '' , 15); print(r.test(s)); print(r.lastIndex); function x(\u3056, ...c) { \"use strict\"; return /*\n*/d = window } Array.prototype.sort.apply(o0.a1, [(function() { v0 = t1.byteLength; return f2; }), g1, v2]);");
/*fuzzSeed-157142351*/count=115; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((0xa87f672b) != (0x1fe9079f))))|0;\n    i1 = ((((i0)+((((0xd35558d1)-(0x10a412f5)-(-0x1fed044))>>>((0xfc128725)-(0xbc7844a8))) <= (((/*FFI*/ff(((-1.2089258196146292e+24)))|0))>>>(-(0xeebccb8b))))-((0x329cd72b))) | ((0x1f245463) % (imul(((((0xb676af4a)) ^ ((0x91bee609)))), (!(delete y.x)))|0))));\n    i1 = (!((+((((+abs(((+(0xffffffff)))))) % ((+/*FFI*/ff((((0xfb8a1f33) ? (-1099511627777.0) : (-1.0078125))), ((~~(-1.00390625))), ((imul((0xfe35f495), (0xb3f77133))|0)), ((-9.44473296573929e+21)), ((3.777893186295716e+22)), ((9.671406556917033e+24)), ((-1.001953125)), ((-137438953473.0)), ((3.777893186295716e+22)), ((-4294967295.0)), ((8388609.0)), ((3.022314549036573e+23)), ((16384.0)), ((-1.9342813113834067e+25)), ((-6.044629098073146e+23)), ((-0.0625)), ((-134217729.0)), ((7.737125245533627e+25)), ((-18014398509481984.0)), ((-4611686018427388000.0)), ((-35184372088831.0)), ((9.0)))))))) > (((32.0)) - ((-4611686018427388000.0)))));\n    i1 = (i1);\n    {\n      i1 = (0xffffffff);\n    }\n    i0 = (!(i1));\n    return (((i1)-((4277))))|0;\n  }\n  return f; })(this, {ff: Boolean}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [42, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, Math.PI, -(2**53+2), Number.MIN_VALUE, -0x07fffffff, 0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 0x100000001, -(2**53), -0x080000001, 1, 2**53-2, -0x0ffffffff, 2**53, 0x100000000, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 0x080000000, 1/0, 0x07fffffff, 0/0, 0, 1.7976931348623157e308]); ");
/*fuzzSeed-157142351*/count=116; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[[(void 0)], [(void 0)], x, x, [(void 0)], [(void 0)], [(void 0)], new String(''), new String(''), x, [(void 0)], [(void 0)], new String(''), new String(''), x, [(void 0)], [(void 0)], x, new String(''), x, x, new String(''), [(void 0)], [(void 0)], [(void 0)], new String(''), [(void 0)], x, x, new String(''), [(void 0)], new String(''), [(void 0)], [(void 0)], x, x, [(void 0)], x, x, new String(''), new String(''), x, x, x, [(void 0)], new String(''), x, x, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], new String(''), new String(''), [(void 0)], new String(''), new String(''), x, new String(''), x, new String(''), new String(''), x, [(void 0)], new String(''), new String(''), new String(''), x, new String(''), x, [(void 0)], [(void 0)], x, new String(''), new String(''), new String(''), [(void 0)], new String(''), x, x, x, x, [(void 0)], [(void 0)], new String(''), [(void 0)], x, x, x, x, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), [(void 0)], x, x, x, x, new String(''), x, new String(''), new String(''), x, [(void 0)], new String(''), new String(''), [(void 0)], x, new String(''), [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], x, new String(''), x, [(void 0)], [(void 0)], x, x, new String(''), [(void 0)], x, x, new String(''), x, [(void 0)], [(void 0)], [(void 0)], new String(''), new String(''), [(void 0)], x, [(void 0)], [(void 0)], new String(''), x, [(void 0)], x, new String(''), new String(''), new String(''), [(void 0)], x, [(void 0)], x, new String(''), [(void 0)], new String(''), new String(''), new String(''), new String(''), x, [(void 0)], [(void 0)], x]) { h0.enumerate = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((delete eval.e));\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)); }");
/*fuzzSeed-157142351*/count=117; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( + (mathy0(Math.pow(( + ( ~ Math.fround(mathy3(x, ( + 2**53-2))))), Math.min(Math.fround(1/0), ((( + 0x07fffffff) ? (0.000000000000001 | 0) : (( + (( + y) ? ( + y) : ( + 0/0))) | 0)) | 0))), Math.sqrt(Math.fround(Math.fround((y == y))))) ? Math.fround((( + Math.sqrt((((2**53 | 0) >>> (Math.min(Math.atan2(x, y), x) | 0)) | 0))) & (Math.pow(Math.fround(x), x) , ( + Number.MAX_SAFE_INTEGER)))) : (Math.fround(( + ((((-0x080000000 ? y : Math.fround(Math.sign(Math.fround(y)))) >>> 0) == (Math.fround(( + (x >>> 0))) >>> 0)) >>> 0))) >>> 0))) == (( + (( + ( + x)) === ( + ( ! 0x080000001)))) | 0)); }); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, -Number.MAX_VALUE, 0x080000001, -0x080000001, -0x07fffffff, -0x0ffffffff, 1/0, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, Math.PI, -0, -(2**53), 2**53+2, 42, 0x0ffffffff, -0x100000000, 1, -1/0, 2**53-2, 0x080000000, 2**53, 1.7976931348623157e308, 0x07fffffff, 0, -(2**53+2), Number.MAX_VALUE, 0x100000000, 0x100000001, -(2**53-2)]); ");
/*fuzzSeed-157142351*/count=118; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ (Math.sin(( + Math.min(x, 0/0))) | 0)); }); testMathyFunction(mathy1, [-(2**53-2), -0, Math.PI, 0x07fffffff, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, 0x100000001, -(2**53), Number.MAX_VALUE, Number.MIN_VALUE, 1/0, 0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 0.000000000000001, -(2**53+2), 1, -1/0, 0, -0x080000000, 2**53, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000000, 0x0ffffffff, 0x080000000, 2**53+2, -0x080000001, 0/0, -0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=119; tryItOut("/*hhh*/function atgfef(x, x, x, x, c, b, this, eval, d, window = undefined, x, z, x, x, x, x, y, y, x, x, w = window, x, x =  /x/g , x, x = -13, c, print(x);, x, b, a, get, e, this.d, x, x, x, e, x, x =  \"\" , y = \"\\u163B\", x, w, e, a, x,  /x/g , x =  /x/ , \u3056 =  \"\" , c, x, \u3056 = new RegExp(\"(?:[^])+\", \"ym\"), z, d, x, x, w, x, d, y, b, b, x, eval, window, x = /(?!.|\\b[\\u943f]|[\u00f8-\\v\\s\ud8be\u335b].?|\\1|(?=(?=(?=\\S)))|(?:[\\v-R\\s\\s1]))/gyi, window, eval, x, x, y =  /x/g , b, NaN, e = \"\\uD411\", c){g0.h2.iterate = (function() { try { p2 = t1[3]; } catch(e0) { } a2 = arguments.callee.arguments; return o1; });}/*iii*/v1 = Object.prototype.isPrototypeOf.call(g0.g2, f0);");
/*fuzzSeed-157142351*/count=120; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=121; tryItOut("\"use asm\"; b0 = new ArrayBuffer(3);");
/*fuzzSeed-157142351*/count=122; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((((mathy1(( ~ Math.hypot(( + (( + y) ? ( + (y / ((( + (x >>> 0)) >>> 0) | 0))) : ( + y))), Math.fround(Math.min(((0x080000000 === Math.fround(Number.MIN_VALUE)) >>> 0), Math.fround(Math.fround(( - ( + -Number.MAX_SAFE_INTEGER)))))))), ((x && ((((Math.imul((( + (Math.log10(( + x)) | 0)) | 0), 0x100000001) | 0) >>> 0) ? (Math.fround(Math.atan2(Math.fround(y), Math.fround(y))) >>> 0) : (((y ? -0x0ffffffff : y) | 0) >>> 0)) >>> 0)) >>> 0)) >>> 0) >>> 0) & (Math.round(Math.fround((( ! Math.fround(Math.sign(Math.fround(( + x))))) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [2**53, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, -0x100000000, 1.7976931348623157e308, -0x080000001, Number.MAX_VALUE, -(2**53-2), 2**53+2, 42, Number.MIN_SAFE_INTEGER, 0, -0x0ffffffff, -1/0, -0, -0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x0ffffffff, 0x080000001, 0x100000000, 2**53-2, -0x080000000, 0/0, 0x080000000, Math.PI, 1, -(2**53)]); ");
/*fuzzSeed-157142351*/count=123; tryItOut("\"use strict\"; /*iii*/delete g2.b0[\"has\"];/*hhh*/function gryxvx({x}, x){x = linkedList(x, 1155);}");
/*fuzzSeed-157142351*/count=124; tryItOut("testMathyFunction(mathy4, [Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, -1/0, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0x100000001, 0x07fffffff, 42, -0x100000000, 0, -0x080000000, -(2**53-2), -0x100000001, 0x0ffffffff, 0x080000001, -(2**53+2), Math.PI, 2**53-2, 1, 1.7976931348623157e308, 2**53+2, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, 1/0, 0x100000000, -0, -0x0ffffffff]); ");
/*fuzzSeed-157142351*/count=125; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( + (((( + ( ! ( + (Math.fround(( + x)) < (Math.sign(-Number.MAX_SAFE_INTEGER) | 0))))) | 0) === (( ! ( + ((( - (Math.tan(x) !== ( ~ ( + x)))) | 0) ? (( + ((Math.acosh(y) | 0) ? ( + Math.max(-Number.MIN_SAFE_INTEGER, y)) : ( + x))) | 0) : (2**53 | 0)))) | 0)) | 0)) <= ( + Math.cos(Math.log2(( + Math.asin(( + Math.fround(Math.min(Math.fround(y), Math.fround(1)))))))))); }); testMathyFunction(mathy0, [-0x080000001, 0x080000001, -0x07fffffff, 0/0, 42, -1/0, 0x100000000, -0x100000000, 2**53-2, 1.7976931348623157e308, -Number.MAX_VALUE, 1, -0x080000000, Number.MIN_VALUE, -(2**53+2), -(2**53), -Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, Number.MAX_VALUE, -Number.MIN_VALUE, 0, 1/0, -0, 2**53+2, 0x100000001, 2**53, 0x07fffffff, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-157142351*/count=126; tryItOut("\"use strict\"; a0 = t0[0];");
/*fuzzSeed-157142351*/count=127; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(?=[^\\s\\u421e\u0002]\\B(?:$)+?^{0,}*)|(?:(?!${2,}))){1}/gim; var s = \"\\u6fcf\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=128; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! ( ~ Math.fround(( ! Math.fround(Math.fround((Math.fround(y) / ( + ( + (Number.MAX_VALUE >>> 0)))))))))); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 0.000000000000001, -0x080000000, -0x080000001, -Number.MAX_VALUE, -0, -(2**53-2), 0x0ffffffff, -0x100000001, 2**53-2, 0x080000001, -1/0, 0x07fffffff, 0x100000000, -0x07fffffff, -0x100000000, 1, 0x100000001, -(2**53), Math.PI, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000, 2**53, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 42, 2**53+2, -(2**53+2), 0, 1.7976931348623157e308]); ");
/*fuzzSeed-157142351*/count=129; tryItOut("/*MXX3*/g2.Root = g1.g2.Root;");
/*fuzzSeed-157142351*/count=130; tryItOut("\"use strict\"; f2(b0);");
/*fuzzSeed-157142351*/count=131; tryItOut("/*tLoop*/for (let c of /*MARR*/[new String('q'), function(){}, function(){}, function(){}, new String('q'), new String('q'), new String('q'), function(){}, new String('q'), new String('q'), Math.atan(Math.sign((-(2**53+2) | 0))), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), Math.atan(Math.sign((-(2**53+2) | 0))), Math.atan(Math.sign((-(2**53+2) | 0)))]) { s0.toSource = f0; }");
/*fuzzSeed-157142351*/count=132; tryItOut("print(uneval(o1));");
/*fuzzSeed-157142351*/count=133; tryItOut("return;with({}) { with({}) let(x) { return;} } ");
/*fuzzSeed-157142351*/count=134; tryItOut("m2.delete(t2);");
/*fuzzSeed-157142351*/count=135; tryItOut("p2.toString = f1;");
/*fuzzSeed-157142351*/count=136; tryItOut("a0.length = this.v2;");
/*fuzzSeed-157142351*/count=137; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.min((Math.min(((( ! (Math.hypot(Math.fround(Math.tanh(Math.fround((Math.log1p((0x080000000 >>> 0)) >>> 0)))), Math.fround(( + y))) | 0)) | 0) | 0), (Math.log10((( ! Math.min(y, 1.7976931348623157e308)) >>> 0)) | 0)) | 0), (((Math.fround((Math.min(( - y), ( ~ (((x >>> 0) ** (x >>> 0)) >>> 0))) ? Math.fround((x && (0x0ffffffff | 0))) : (x | 0))) | 0) >= ((( ~ (( + Math.pow(Math.fround((( + y) >= Math.fround(( ~ Math.fround(Math.fround(( ~ Math.fround(x)))))))), Math.fround(x))) | 0)) | 0) | 0)) | 0)); }); ");
/*fuzzSeed-157142351*/count=138; tryItOut("mathy0 = (function(x, y) { return ( + Math.max(( + ( - Math.tanh(Math.atan2((x >> x), y)))), ((Math.fround(Math.asinh(y)) ? (( - (x >>> 0)) >>> 0) : (((y | 0) ? (x | 0) : x) | 0)) & ((Math.hypot(((( ! (( + Math.exp(( + x))) | 0)) | 0) >>> 0), 0x0ffffffff) >>> 0) >>> (( + Math.log10(Math.fround(( - 2**53)))) < 0x100000000))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000001, 0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), 2**53, 2**53+2, Number.MAX_VALUE, 0x100000001, 0x0ffffffff, 0x07fffffff, -0x100000001, 1, -1/0, Math.PI, -0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2), 0/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 42, 0x100000000, -0x080000000, -0, 0.000000000000001, -0x07fffffff, 0x080000000, 2**53-2, -0x100000000]); ");
/*fuzzSeed-157142351*/count=139; tryItOut("\"use strict\"; { void 0; bailAfter(5); }");
/*fuzzSeed-157142351*/count=140; tryItOut("\"use asm\"; with(/*UUV2*/(c.toString = c.includes)){s2 = new String(f2); }");
/*fuzzSeed-157142351*/count=141; tryItOut("v1 = this.g2.eval(\"function f0(g0)  { return (4277) } \");s2 = Array.prototype.join.apply(a2, [s1]);");
/*fuzzSeed-157142351*/count=142; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; minorgc(false); } void 0; } v1 = (o0.b2 instanceof o2);");
/*fuzzSeed-157142351*/count=143; tryItOut("hbgefq();/*hhh*/function hbgefq(w, window, e, z, y, e = ((20(false,  /x/g ))()), a, x, c, \u3056, {}, [], NaN, e, NaN, x, x, this.x, x, \u3056 =  /x/ , z, NaN =  /x/ ){Array.prototype.shift.apply(a0, []);}");
/*fuzzSeed-157142351*/count=144; tryItOut("/*RXUB*/var r = new RegExp(\"[]\", \"\"); var s = \"e\"; print(uneval(s.match(r))); ");
/*fuzzSeed-157142351*/count=145; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return mathy0(( + Math.max(( + Math.trunc((((Math.log1p(x) | 0) + ((((( + Math.min(( + -(2**53+2)), ( + 1.7976931348623157e308))) | 0) <= (Math.max(x, -0x07fffffff) | 0)) | 0) | 0)) | 0))), ( + Math.asin((( ~ ((( + x) ^ (x > (y ? (-Number.MIN_VALUE | 0) : (-0x100000001 | 0)))) | 0)) | 0))))), Math.cosh(( + Math.sin(x)))); }); testMathyFunction(mathy2, [0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, -(2**53), 42, -0, 0/0, -0x0ffffffff, Math.PI, -0x100000001, 1.7976931348623157e308, 1, Number.MIN_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -(2**53-2), 0, 0x0ffffffff, Number.MIN_VALUE, 2**53+2, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, 0x080000001, -0x080000001, 0.000000000000001, 0x100000001]); ");
/*fuzzSeed-157142351*/count=146; tryItOut("e2.delete(p1);\nm1.set(f0, a1);\n");
/*fuzzSeed-157142351*/count=147; tryItOut("\"\\u348A\";");
/*fuzzSeed-157142351*/count=148; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.sqrt(Math.fround((mathy2(0.000000000000001, (mathy1(Math.fround(( + ( ! mathy2(x, y)))), Math.fround(Math.ceil((y | 0)))) | 0)) === ( + Math.atan(Math.fround(Math.log2(Math.fround(((y >>> 0) != y)))))))))); }); testMathyFunction(mathy4, [0/0, -(2**53+2), 42, 0x080000000, -1/0, 2**53, -Number.MAX_VALUE, 0x080000001, -0x100000000, -0x080000000, -0, Math.PI, Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53), 1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, 2**53-2, 0x0ffffffff, 0.000000000000001, -Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000001, -0x080000001, Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, -0x0ffffffff, 0, 1, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=149; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(Math.fround((Math.fround(Math.pow(x, (( + (Math.fround(( ~ Math.fround(y))) | 0)) >>> 0))) % Math.fround((y / (y >>> Math.hypot(((( + x) >> (Math.fround(Math.expm1(Math.fround(y))) | 0)) >>> 0), (Math.imul(Math.fround(x), ( + x)) >>> 0)))))))), (((Math.fround(Math.ceil(Math.pow(( + y), x))) !== Math.fround(( - Math.fround(Math.fround(Math.hypot(x, x)))))) + ( + Math.fround(Math.log(Math.fround(((((y | 0) << x) | 0) ? Math.fround(Math.acosh(Math.fround(mathy0(x, y)))) : mathy1(Math.fround(Math.min(Math.fround(-0x100000001), Number.MAX_SAFE_INTEGER)), Math.fround(y)))))))) >>> 0))); }); testMathyFunction(mathy2, /*MARR*/[(void 0), (-1/0), (-1/0), (void 0), (void 0), (void 0), (void 0), (-1/0), (-1/0), (void 0), (void 0), (void 0), (void 0), (-1/0), (void 0), (-1/0), (void 0), (-1/0), (-1/0), (void 0), (-1/0), (-1/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (-1/0), (void 0), (void 0), (-1/0), (-1/0), (void 0), (void 0), (-1/0), (-1/0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (-1/0), (void 0), (void 0), (void 0), (-1/0), (void 0), (void 0), (void 0), (void 0), (-1/0), (void 0), (-1/0), (void 0), (void 0), (void 0), (void 0), (void 0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (void 0), (void 0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (void 0), (-1/0), (void 0), (-1/0), (-1/0), (-1/0), (void 0), (void 0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (void 0)]); ");
/*fuzzSeed-157142351*/count=150; tryItOut("mathy5 = (function(x, y) { return Math.fround(( - Math.pow(Math.fround(mathy1(Math.fround(Math.fround((this >= ( + ( ! -Number.MIN_VALUE))))), Math.fround(Math.tanh(x)))), (Math.ceil(Math.atan2(x, -Number.MAX_SAFE_INTEGER)) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[new Boolean(true), x, new Boolean(true),  'A' , x, x,  'A' ,  'A' , this, x, this, new Boolean(true), new Boolean(true), x, Infinity, Infinity, new Boolean(true), x, new Boolean(true),  'A' ,  'A' , this,  'A' , Infinity,  'A' ,  'A' , x, new Boolean(true), this, Infinity, this, Infinity, new Boolean(true), this, new Boolean(true), x, x, Infinity, this, Infinity, x,  'A' , Infinity, new Boolean(true),  'A' , new Boolean(true),  'A' , Infinity,  'A' ]); ");
/*fuzzSeed-157142351*/count=151; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-157142351*/count=152; tryItOut("\"use strict\"; /*bLoop*/for (seedhv = 0; seedhv < 34; ++seedhv) { if (seedhv % 3 == 0) { /*ODP-3*/Object.defineProperty(v1, \"from\", { configurable: true, enumerable: true, writable: false, value: h2 });function x(x, d, x = \"\\u3B00\", \u3056, eval, d, x, x, window, NaN = [1,,], x, w,  , e, c = arguments, this.x, w, NaN, \"29\", x, b,  , x, y, w = /(?!\\3*?)/m, NaN = -5, \u3056, x, \u3056, d, this.x, eval, e, y = new RegExp(\"(?:\\\\3\\\\d|[^]|($)^{1,}(\\\\1)+)\", \"gyim\"), e, d, x = this, x, x =  \"\" , c = this, x, NaN, b, x, w, window, x, window, \u3056, \u3056, x = window, window, a, window, yield = this, x, d = \"\\u7C62\", eval = \"\\u1BAF\", x, x, x, x, x = window, x, x, a, x, w, x, c, y, y, x, NaN, d, x = true, e, x, x, w = NaN)\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = (i0);\n    return (((i0)-((d1) <= (+(1.0/0.0)))-((0x634b5bdb) != (((((0x8cfcad24) / (0xf0847f8d))|0) / (((0xb3ba47e7)) ^ ((-0x8000000))))>>>(0xeb0d4*((((0xfaadaa79))>>>((0x6d045766))) < (0x80f6bb11)))))))|0;\n  }\n  return f;e2.has(false); } else { h0.fix = f2; }  } ");
/*fuzzSeed-157142351*/count=153; tryItOut("print(x);\na2 = Array.prototype.map.call(a2, (function(j) { f1(j); }));\n");
/*fuzzSeed-157142351*/count=154; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return (mathy0((((( + x) || Math.fround(mathy1(( - (x | 0)), ( + (Math.fround((x << y)) ? Math.fround(( ! x)) : Math.fround(x)))))) % Math.fround(( + mathy3(( + ( ~ (0 | 0))), Math.pow(-Number.MAX_SAFE_INTEGER, (x < ( + (( + (y >>> 0)) >>> 0)))))))) >>> 0), ((Math.atan((x > (( + (y | 0)) | 0))) >>> 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-157142351*/count=155; tryItOut("/*MXX1*/o2 = g0.Date.prototype;");
/*fuzzSeed-157142351*/count=156; tryItOut("h0.getOwnPropertyNames = f0;");
/*fuzzSeed-157142351*/count=157; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.min(Math.cos((mathy1(x, (x >>> 0)) >> Math.atanh(( + Math.min(Math.fround(( ! Math.fround((Math.imul(-0x100000001, (y | 0)) | 0)))), Math.atanh(y)))))), (Math.log1p((Math.fround((Math.fround(mathy0(y, 0x080000001)) != Math.fround(Math.atan((x >>> 0))))) | 0)) >>> 0)); }); ");
/*fuzzSeed-157142351*/count=158; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( ! ((((Math.max((Math.fround(( ~ 0x080000001)) >>> 0), (( + Math.sqrt(Math.fround(( - ( + Math.max(2**53, x)))))) >>> 0)) >>> 0) & Math.atan((Math.atan2((Math.imul(Math.max(1, Math.fround(Math.cos(Math.fround(y)))), (( ! y) | 0)) >>> 0), (Math.max(-(2**53+2), y) >>> 0)) >>> 0))) >>> 0) | 0)) | 0); }); ");
/*fuzzSeed-157142351*/count=159; tryItOut("mathy5 = (function(x, y) { return Math.pow(Math.min(Math.log2(Math.atan2(Math.fround(Math.min(Math.fround(y), ( + Math.cos(Math.tanh(y))))), Math.fround(Math.log2(Math.fround(( + ( + -Number.MAX_VALUE))))))), ( + ( + Math.fround(Math.min(Math.fround(x), Math.fround(mathy2(( ~ x), (x ** x)))))))), ((Math.cosh((mathy2(Math.fround((Math.hypot(( + ( - x)), x) ^ 0.000000000000001)), Math.fround(( + (( + x) + ( + -0x080000001))))) | 0)) | 0) - x)); }); testMathyFunction(mathy5, [-0x100000001, 0, Math.PI, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, 2**53-2, 0x100000000, -(2**53-2), 0x07fffffff, 0x080000001, 0x0ffffffff, -0x100000000, 42, -0x07fffffff, 2**53, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0, 1, -0x080000000, -1/0, 2**53+2, 0/0, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53)]); ");
/*fuzzSeed-157142351*/count=160; tryItOut("mathy3 = (function(x, y) { return (((( + Math.pow((Math.fround(( ~ Math.fround(y))) >>> 0), ((((Math.acos((( ~ Math.PI) | 0)) | 0) && (2**53 | 0)) === ( + Math.imul((Math.imul((x | 0), Math.fround(y)) | 0), ( + y)))) >>> 0))) >>> ( - y)) | 0) / ( + (Math.trunc((( + mathy2(( + Math.fround(Math.imul((Math.sign(0x080000000) | 0), ( + Math.imul(x, (( ! 1/0) >>> 0)))))), ((( + ( ! ( + (Math.hypot((Math.fround((x >>> Math.fround(y))) | 0), (1.7976931348623157e308 | 0)) | 0)))) >>> 0) ^ x))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [0x080000001, 0, 0x100000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, -Number.MIN_VALUE, 1/0, -0x080000000, 2**53-2, -(2**53), Number.MAX_SAFE_INTEGER, -0, Number.MIN_VALUE, 2**53+2, Number.MAX_VALUE, Math.PI, 2**53, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53-2), -Number.MAX_VALUE, -0x100000001, 0.000000000000001, 42, 0x100000001, 0/0, 1.7976931348623157e308, -(2**53+2), -1/0, 0x080000000, 1, -Number.MIN_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-157142351*/count=161; tryItOut(" for  each(let e in (p={}, (p.z = x((4277)))())) m2.get(t2);");
/*fuzzSeed-157142351*/count=162; tryItOut("\"use strict\"; e0.delete(let (d) (String.prototype = true));");
/*fuzzSeed-157142351*/count=163; tryItOut("t2[5];/*hhh*/function iixuru(){print(x);}iixuru((x.__defineSetter__(\"x\", function(y) { \"use strict\"; return /*UUV2*/(w.exec = w.setInt16) })));");
/*fuzzSeed-157142351*/count=164; tryItOut("print(i2);");
/*fuzzSeed-157142351*/count=165; tryItOut("/*bLoop*/for (mbthym = 0; mbthym < 136; ++mbthym) { if (mbthym % 2 == 1) { a2[19]; } else { Object.prototype.unwatch.call(o1, \"4\"); }  } ");
/*fuzzSeed-157142351*/count=166; tryItOut("\"use strict\"; o0.i1.next();");
/*fuzzSeed-157142351*/count=167; tryItOut("\"use strict\"; /*oLoop*/for (let omolhz = 0; omolhz < 39; ++omolhz) { (DataView.prototype); } ");
/*fuzzSeed-157142351*/count=168; tryItOut("for(let z = Date.prototype.getMilliseconds.prototype in x) Math.atan(-3);");
/*fuzzSeed-157142351*/count=169; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      {\n        {\n          return (((i1)+(-0x8000000)))|0;\n        }\n      }\n    }\n    i0 = (((((((i0))>>>(-(i0))) == (((-0x14206f7) / (0x2eacfeb))>>>(((0xf00d4012) ? (0x1ba5d5d9) : (0xf82f9706))))))>>>((((/*wrap3*/(function(){ var jtpnpv = x; (/*wrap3*/(function(){ var tuorya = \"\\u2EB6\"; (mathy3)(); }))(); })).call\u000c( /x/g .__defineSetter__(\"x\", decodeURIComponent), ((void options('strict'))), null))(((decodeURI)((allocationMarker()), arguments)), (4277))) % (0xc7ab481a))) < (0xf07ce09));\n;    return (((i1)))|0;\n  }\n  return f; })(this, {ff: function(y) { Object.prototype.watch.call(m2, \"acos\", (function mcc_() { var zxclzq = 0; return function() { ++zxclzq; f1(/*ICCD*/zxclzq % 11 == 3);};})()); }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [-1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 1, 1/0, -0x100000001, -0x07fffffff, 2**53, Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, -0x100000000, Number.MIN_VALUE, -(2**53), -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53+2, -0x080000000, 0x0ffffffff, -(2**53+2), 0x100000000, 0x080000001, 2**53-2, Math.PI, 0, 0.000000000000001, 0x100000001, 42, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-157142351*/count=170; tryItOut("g0.t1 = o0.t1.subarray(g1.v0, 13);");
/*fuzzSeed-157142351*/count=171; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + ( ~ ( + ( ! Math.hypot((Math.atanh(x) >>> 0), (Math.hypot((((mathy4(Math.fround(x), y) >>> 0) >>> (y >>> 0)) >>> 0), (Math.expm1((Math.acos(( + y)) >>> 0)) | 0)) | 0)))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, 0x100000001, -0x080000001, 0.000000000000001, 0x100000000, -(2**53), 1, 42, -0x100000000, Number.MAX_VALUE, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0/0, 0x0ffffffff, -(2**53+2), 2**53+2, 0, Math.PI, -1/0, -0x100000001, 0x07fffffff, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 2**53-2, -0, 0x080000000, -Number.MIN_VALUE, -(2**53-2), 1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=172; tryItOut("g2 + '';");
/*fuzzSeed-157142351*/count=173; tryItOut("this.v1 = evaluate(\"v0 = a2.length;\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: false, sourceIsLazy: true, catchTermination: (x % 6 == 0), element: o1, sourceMapURL: s0 }));");
/*fuzzSeed-157142351*/count=174; tryItOut("mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return ( ! Math.sqrt(mathy0(( ~ (Math.max(x, x) >>> 0)), mathy2((Math.ceil(((( + y) ^ (y >>> 0)) >>> 0)) >>> 0), ( + 0.000000000000001))))); }); testMathyFunction(mathy3, [-0x100000001, 2**53+2, 1, 2**53-2, -Number.MAX_VALUE, 0x07fffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, Math.PI, Number.MIN_SAFE_INTEGER, 0, -(2**53), -0x080000001, 0/0, 0x100000001, 42, -0x080000000, -1/0, Number.MAX_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, 0x080000000, -0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1/0, 0x100000000]); ");
/*fuzzSeed-157142351*/count=175; tryItOut("\"use asm\"; M:with(/([^])/yi)print(x);");
/*fuzzSeed-157142351*/count=176; tryItOut("Array.prototype.reverse.apply(o2.a0, []);");
/*fuzzSeed-157142351*/count=177; tryItOut("\"use asm\"; v0 = (m0 instanceof o1);function b(d, w) { return this } i0.send(this.h1);");
/*fuzzSeed-157142351*/count=178; tryItOut("mathy4 = (function(x, y) { return Math.imul(( ~ ( ! (( ! Math.sinh((y | 0))) | 0))), (( + ( + ( - ( + ( ~ Math.pow(x, (y | 0))))))) | 0)); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 0/0, -(2**53-2), 2**53-2, 0x100000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, -0x0ffffffff, 0x080000000, 0x0ffffffff, 0x07fffffff, 0.000000000000001, -0, -Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, -0x100000000, 0, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, 42, 2**53, -0x100000001, -(2**53+2), 0x100000000, 1, -Number.MAX_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-157142351*/count=179; tryItOut("\"use strict\"; Array.prototype.sort.apply(a1, [(function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return ((((~~(1.5111572745182865e+23)) == ((((((0xf8ffa256)) & ((0xfacd2a7e))) >= (((0xffffffff)) ^ ((0x41dd2a03))))-(i0)) ^ ((!(i0))+((0xffffffff)))))-(!((((0xffffffff)-((0x32ca9999))) ^ (((imul((0x8712bb2), ((0x7fffffff) > (0x605f72c7)))|0))))))+(0xd470446b)))|0;\n  }\n  return f; }), s2, b1, t2]);");
/*fuzzSeed-157142351*/count=180; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.sqrt((Math.min(( ~ (y | 0)), (( + (( + -0x0ffffffff) || ( + Math.fround(Math.pow(x, Math.fround(x)))))) ** (mathy1((Math.fround(mathy0(Math.fround(-(2**53)), Math.fround((y ^ Math.fround(-0x100000000))))) | 0), (( - (Math.max(Number.MAX_VALUE, (x | 0)) | 0)) | 0)) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0, -0x07fffffff, 1, 2**53+2, -0x100000000, Number.MIN_VALUE, -1/0, 2**53, -0x080000001, 1/0, -(2**53+2), 0x100000001, 0x100000000, 0/0, -(2**53-2), Number.MAX_VALUE, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000000, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 42, 0, Math.PI, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 0x080000001, 0x0ffffffff, 2**53-2, 0x080000000, -(2**53)]); ");
/*fuzzSeed-157142351*/count=181; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.max((( - (((Math.fround(Math.max(Math.fround(x), Math.fround(x))) | 0) * (Math.min((((x || y) % (x | 0)) >>> 0), ( ! ( + (x > 0x080000001)))) | 0)) | 0)) >>> 0), (( + Math.pow(( + Math.fround(mathy3(Math.max((-(2**53+2) | 0), (mathy3(x, Math.acos(-0x100000000)) | 0)), Math.fround(Math.hypot((mathy3(Math.imul(y, y), y) >>> 0), -0x100000000))))), ( + ( + mathy2(Math.fround(x), -0x0ffffffff))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0x080000001, 1, 42, 0x0ffffffff, 2**53+2, 0.000000000000001, 2**53, -1/0, -0x100000001, -(2**53+2), -Number.MIN_VALUE, 0x080000000, Math.PI, 1.7976931348623157e308, -0x07fffffff, 2**53-2, -0x080000001, 0x07fffffff, -0x080000000, -0x100000000, Number.MIN_VALUE, -(2**53), 0x100000000, -0, -0x0ffffffff, 0, 0/0, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=182; tryItOut("");
/*fuzzSeed-157142351*/count=183; tryItOut("\"use strict\"; a2 = Array.prototype.concat.apply(a1, [a0, t0, t0, e2]);");
/*fuzzSeed-157142351*/count=184; tryItOut("function ([y]) { };");
/*fuzzSeed-157142351*/count=185; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return (( - (mathy1(Math.round((x % ( + ((Math.fround(Math.acos((x >>> 0))) | 0) | y)))), ( + (( + y) === ( + Math.min((( + (x | 0)) | 0), x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[ /x/ , 1,  /x/ , 1, 1,  /x/ ,  /x/ ,  /x/ ,  /x/ , 1, 1,  /x/ ,  /x/ , 1,  /x/ , 1, 1,  /x/ , 1,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , 1, 1, 1, 1, 1, 1, 1,  /x/ , 1, 1,  /x/ ]); ");
/*fuzzSeed-157142351*/count=186; tryItOut("/*hhh*/function ocefzs(w, ...x){this.s2 += s0;}ocefzs((Math.min(y, Math.cosh(this))));");
/*fuzzSeed-157142351*/count=187; tryItOut("/*oLoop*/for (let ipsfst = 0; ipsfst < 94; ++ipsfst) { v1 = (h1 instanceof g0); } ");
/*fuzzSeed-157142351*/count=188; tryItOut("a1.push(e2);");
/*fuzzSeed-157142351*/count=189; tryItOut("\"use strict\"; switch((x >= b)) { default: v2 = evaluate(\"function f0(s1)  { yield \\nnew String('') } \", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 4 == 0), noScriptRval: (x % 32 == 13), sourceIsLazy: true, catchTermination: true, element: g1.o1 }));break; break;  }");
/*fuzzSeed-157142351*/count=190; tryItOut("m2.set(a2, this.h1);");
/*fuzzSeed-157142351*/count=191; tryItOut("\"use strict\"; with({c: eval < x});\nFloat64Array\n");
/*fuzzSeed-157142351*/count=192; tryItOut("for (var p in h0) { try { this.b2 = new SharedArrayBuffer(6); } catch(e0) { } try { v0 = a1.length; } catch(e1) { } try { v1 = g1.eval(\"e2.has(neuter() <<= /(?!\\\\3)*?/ < ({ set \\\"26\\\"(b, x) { (undefined); }  }).valueOf(\\\"number\\\"));\"); } catch(e2) { } Object.prototype.unwatch.call(o1, \"length\"); }");
/*fuzzSeed-157142351*/count=193; tryItOut("/*RXUB*/var r = /(^{0}){0,}|((\\W)+?){2,}.|^[^]\\3{3}|(?:(?=(?:(?=[^]{0})))(?!\\B)|(?![^]?|\\b\uf024)?)*?/gym; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-157142351*/count=194; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\3(?!\\\\b{3,})+*\", \"i\"); var s = \"_00a1a11a11a11a11aaa_00a1a11a11a11a11aaa\"; print(uneval(r.exec(s))); print(r.lastIndex); v0 = -0;");
/*fuzzSeed-157142351*/count=195; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.imul(Math.fround((Math.pow(((mathy3(Math.min(-0, x), ((( + ( + x)) >> x) | 0)) & Math.fround(Math.max(Math.max(y, ( ~ ( - y))), Math.fround((mathy0((y | 0), x) | 0))))) | 0), ((Math.exp(( + -0x0ffffffff)) | 0) | 0)) | 0)), Math.fround(Math.pow((mathy1(( + mathy1(( + Math.pow(x, y)), ( - (y | 0)))), mathy1(mathy2(x, ( + y)), ( + x))) ** x), (( + (Math.acosh(y) | 0)) | 0))))); }); testMathyFunction(mathy5, [0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, -Number.MAX_VALUE, -0x100000001, 2**53, -(2**53-2), 0x07fffffff, 0.000000000000001, -Number.MIN_VALUE, -0x100000000, 0x100000001, 0x100000000, -(2**53), -0x07fffffff, Number.MIN_VALUE, Math.PI, Number.MAX_VALUE, 2**53-2, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -1/0, 0x0ffffffff, 1, -(2**53+2), 42, 2**53+2, 0x080000000, 1/0, -Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-157142351*/count=196; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.fround((((Math.pow((( + Math.min((y + -(2**53+2)), (( ! y) | 0))) >>> 0), (-0x07fffffff >>> 0)) >>> 0) >= Math.fround(((Math.fround(x) < ((Math.PI ** (x * x)) >>> 0)) >>> 0))) | 0)) ^ ((Math.min((Math.cos((((y | 0) << (Math.exp(-(2**53+2)) | 0)) | 0)) | 0), ((( - ((( + 0x100000000) | 0) >>> 0)) >>> 0) | 0)) | 0) ^ ((((Math.atan((( + Math.max(Math.imul(y, -0x07fffffff), ( + 1/0))) | 0)) | 0) >>> 0) ^ (( + y) + ( + y))) | 0))); }); ");
/*fuzzSeed-157142351*/count=197; tryItOut("\"use strict\"; Array.prototype.push.apply(this.a1, [b0]);");
/*fuzzSeed-157142351*/count=198; tryItOut("/*RXUB*/var r = /\\3/m; var s = \"_00\"; print(s.search(r)); ");
/*fuzzSeed-157142351*/count=199; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (((Math.fround(( ! Math.fround(Math.pow(Math.min(y, Math.fround(( + (0x100000000 >>> 0)))), ((Math.expm1(y) >>> 0) || x))))) | 0) + ((( - ((Math.min(Math.sinh(y), ((Math.min(( + (Math.imul(((Math.min(x, y) ? ( + ( ~ -0)) : (0x080000000 | 0)) | 0), (y | 0)) >>> 0)), ( + Math.hypot(x, (Math.max((Math.round(( + 2**53)) | 0), (y | 0)) | 0)))) | 0) | 0)) | 0) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy4, [1.7976931348623157e308, -0x080000001, 0x100000000, 1/0, 42, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, -1/0, -0x100000001, 2**53, Number.MIN_VALUE, 0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, 2**53-2, Number.MAX_VALUE, 0x080000001, 0, -Number.MIN_VALUE, 1, 2**53+2, -0, -Number.MAX_VALUE, 0x07fffffff, -0x0ffffffff, -0x100000000, 0/0, 0x100000001, 0.000000000000001]); ");
/*fuzzSeed-157142351*/count=200; tryItOut("s0 + '';");
/*fuzzSeed-157142351*/count=201; tryItOut("for (var v of g1.b0) { v0 = (b1 instanceof b0); }");
/*fuzzSeed-157142351*/count=202; tryItOut("\"use strict\"; {var szejsw = new ArrayBuffer(2); var szejsw_0 = new Float32Array(szejsw); szejsw_0[0] = -18; neuter }");
/*fuzzSeed-157142351*/count=203; tryItOut("mathy2 = (function(x, y) { return ( - (Math.hypot(Math.imul(Math.fround(Math.fround(mathy1(Math.fround(y), (( ~ (x >>> 0)) | 0)))), (x != (( + Math.min(Math.fround(y), ( + Math.fround(Math.imul(y, Math.fround(y)))))) | 0))), Math.pow(y, (Math.hypot(y, Math.log1p(x)) >>> 0))) >>> 0)); }); testMathyFunction(mathy2, /*MARR*/[ '\\0' ,  \"use strict\" , true, new Number(1.5),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  '\\0' , true, new Number(1.5), x, new Number(1.5),  '\\0' , x,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  '\\0' , x, new Number(1.5),  '\\0' , true,  \"use strict\" , x,  '\\0' , x, x, true, true,  '\\0' ,  \"use strict\" , true,  \"use strict\" , new Number(1.5), true, x,  \"use strict\" , x,  \"use strict\" , new Number(1.5),  \"use strict\" ,  \"use strict\" ,  \"use strict\" , true,  '\\0' ]); ");
/*fuzzSeed-157142351*/count=204; tryItOut("\"use strict\"; /*iii*/for (var v of t2) { try { a0 = r1.exec(s1); } catch(e0) { } try { i1.send(b1); } catch(e1) { } a2.unshift(this.m0, m0, p2); }/*hhh*/function gsqoqw(a, x, x, \u3056, NaN, e, window, x, x = \"\\u487A\", x, eval = window, d, e, window, x, x = /(?!(?=(?=[\\xfc\\ue1f1\\s])?){0,1})/g, eval, z, x = kcehfk, z, print( '' );, c, this, a, eval, x = -6, window, a, c, x, x, x = \"\\u773D\", y, x = e, window, x, z, NaN, x, b, x = /\\2/gim, x, d, e, eval, w){a1.unshift(s2, p0, o2, g2);}");
/*fuzzSeed-157142351*/count=205; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ( + (Math.pow(( + Math.sin(( + (Math.fround(( ~ Math.fround(-(2**53)))) ^ x)))), (( + ( + ( - ( + (( ! Math.fround(1.7976931348623157e308)) >>> 0))))) ** ( + Math.trunc((( ~ 1.7976931348623157e308) | 0))))) & Math.fround(Math.log(((Math.imul(x, (Math.imul(Math.fround(x), Math.atan2(2**53+2, -0x0ffffffff)) >>> 0)) >>> 0) | 0))))); }); testMathyFunction(mathy0, [1.7976931348623157e308, 2**53, 0, -Number.MAX_VALUE, -0x080000001, -(2**53), 0x080000000, 0.000000000000001, -0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 1, 2**53-2, -(2**53+2), -0x07fffffff, 0x07fffffff, 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x080000000, 2**53+2, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_VALUE, Math.PI, 42, -Number.MIN_VALUE, 0x0ffffffff, -1/0, -0x100000001, 0x100000001]); ");
/*fuzzSeed-157142351*/count=206; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=207; tryItOut("o2.e2.has(g2.o1.f0);");
/*fuzzSeed-157142351*/count=208; tryItOut("\"use strict\"; v1 = (f1 instanceof e1);");
/*fuzzSeed-157142351*/count=209; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0/0, 2**53+2, -0x07fffffff, -(2**53-2), 0x0ffffffff, Number.MAX_VALUE, -1/0, -(2**53), -(2**53+2), 2**53, -Number.MIN_SAFE_INTEGER, 0x100000001, -0, 2**53-2, Number.MIN_SAFE_INTEGER, 1, 1.7976931348623157e308, 0x100000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000001, -Number.MIN_VALUE, Number.MIN_VALUE, -0x0ffffffff, -0x080000001, 0x080000001, -0x080000000, -Number.MAX_VALUE, 0.000000000000001, 0x080000000, 1/0, 42, -Number.MAX_SAFE_INTEGER, Math.PI, 0, -0x100000000]); ");
/*fuzzSeed-157142351*/count=210; tryItOut("\"use strict\"; g1.a2.pop(d = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(({c: function(id) { return id }})), x));");
/*fuzzSeed-157142351*/count=211; tryItOut("\"use strict\"; Object.prototype.unwatch.call(f2, \"__defineSetter__\");/*infloop*/for(arguments.callee.arguments in ((String.prototype.repeat\n)((4277)))){m0.delete(this.g2);(x); }\u0009");
/*fuzzSeed-157142351*/count=212; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=213; tryItOut("\"use strict\"; g0.v2 = evaluate(\"v1 = evaluate(\\\"(4277)\\\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 12 != 2), noScriptRval: x, sourceIsLazy: (x % 27 == 22), catchTermination: (x % 17 == 5), sourceMapURL: s0 }));\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: (x % 104 != 7), catchTermination: (x % 2 != 1) }));");
/*fuzzSeed-157142351*/count=214; tryItOut("x;");
/*fuzzSeed-157142351*/count=215; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.max(Math.clz32(Math.imul(Math.sinh(Math.max(x, x)), y)), ( + (( + Math.cos(Math.fround((Math.pow((( ~ y) >>> 0), y) >>> 0)))) ** ( + (( + ( + Math.min(( + x), ((( + (((y | 0) ? (x | 0) : (-0x080000000 | 0)) | 0)) + (y >>> 0)) >>> 0)))) | 0))))); }); testMathyFunction(mathy3, ['', [], 0.1, (new Number(-0)), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '/0/', undefined, NaN, null, true, (new String('')), (function(){return 0;}), (new Boolean(false)), '0', -0, objectEmulatingUndefined(), /0/, [0], (new Number(0)), 1, false, ({valueOf:function(){return 0;}}), '\\0', (new Boolean(true)), 0]); ");
/*fuzzSeed-157142351*/count=216; tryItOut("testMathyFunction(mathy2, /*MARR*/[null, [undefined], null, [undefined], null, Number.MIN_VALUE, [undefined], Number.MIN_VALUE, true, null]); ");
/*fuzzSeed-157142351*/count=217; tryItOut("a0.push(o2, g2, v2, a0, this.f0, i1);");
/*fuzzSeed-157142351*/count=218; tryItOut("testMathyFunction(mathy2, [2**53+2, -(2**53-2), 0/0, -Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, -(2**53), 0x080000000, -0x080000000, 42, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, -0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, Number.MAX_VALUE, 0x080000001, -0x100000000, 0x100000001, 0, Number.MIN_VALUE, -1/0, 2**53, -0x080000001, -0x100000001, 2**53-2, Math.PI, 0x100000000, 1/0, -(2**53+2)]); ");
/*fuzzSeed-157142351*/count=219; tryItOut("\"use strict\"; (4277);");
/*fuzzSeed-157142351*/count=220; tryItOut("v2 = Object.prototype.isPrototypeOf.call(h0, o1);");
/*fuzzSeed-157142351*/count=221; tryItOut("/*RXUB*/var r = new RegExp(\"(?!\\\\w|[^]+(?!\\\\b)|(\\\\u0615?).{3,5})+?|[\\\\f-Q\\\\S\\\\f-\\u00f8]*?\", \"gim\"); var s = [,,z1]; print(s.search(r)); ");
/*fuzzSeed-157142351*/count=222; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:(\\\\S(?=[\\\\d\\\\w]{1,4})+|[^]*)))\\\\3+(?:[^\\\\\\ud174\\\\xf1-\\\\\\u6bba\\\\W\\\\s])*?\", \"g\"); var s = \"____\\u0d70\"; print(uneval(s.match(r))); ");
/*fuzzSeed-157142351*/count=223; tryItOut("\"use strict\"; v1 = t0.byteOffset;");
/*fuzzSeed-157142351*/count=224; tryItOut("\"use strict\"; g1.v0 = g0.eval(\"(window);\");let x = window;");
/*fuzzSeed-157142351*/count=225; tryItOut("a2.push((4277));");
/*fuzzSeed-157142351*/count=226; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.sinh(Math.fround(Math.max(( + Math.pow(( + mathy1(((Math.pow((1.7976931348623157e308 >>> 0), (0x100000000 >>> 0)) >>> 0) >>> 0), ( + Math.min(x, Math.fround(Math.fround(Math.fround(( + ( + x))))))))), ( + Math.hypot((x | 0), (y >>> ( + mathy1(x, 42))))))), Math.fround(Math.atanh(( + (Math.acosh(((Math.min((y >>> 0), (( + ( + y)) >>> 0)) >>> 0) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy3, [0/0, 2**53+2, -0x07fffffff, 0x100000000, 42, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 0x0ffffffff, -0x100000001, 0, 0x07fffffff, -0x080000001, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, -0x100000000, 2**53-2, 0x080000001, -(2**53-2), -(2**53), Number.MAX_VALUE, -0x0ffffffff, 2**53, -(2**53+2), Number.MIN_VALUE, 0x100000001, -0, -0x080000000, Math.PI, -1/0]); ");
/*fuzzSeed-157142351*/count=227; tryItOut("s0.__proto__ = v2;");
/*fuzzSeed-157142351*/count=228; tryItOut("\"use strict\"; x = g1.b2;");
/*fuzzSeed-157142351*/count=229; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+atan2(((+atan2((((0xf8685d19) ? (((d1)) - ((d1))) : (+(((-0x697cb08))>>>((0xfe78ca1a)))))), ((+(-1.0/0.0)))))), ((((+(-1.0/0.0))) * ((d1))))));\n    (Float32ArrayView[1]) = ((d1));\n    return (((-0x29cfaef)))|0;\n    (Uint16ArrayView[4096]) = ((-0x8000000)+(0x2011d162)+(((d1))));\n    d0 = (+(1.0/0.0));\n    (Float64ArrayView[((0xd25872c2)+((0xffffffff))) >> 3]) = ((d1));\n    d1 = (+(abs((((0xb819fd7e)-(0x816bb7c0)) ^ ((0xd0c01be8)+((((0xca83ada1)-(0x8c542ff5)+(0x415cd629))>>>((0x3d256043) / (0x5aecdc1c))))-((((0xa8d23903)) ^ ((0xfce28b79))) >= (~((0xf944a7ee)-(0xfad60acb)))))))|0));\n    d1 = (((+/*FFI*/ff(((abs((((!(0x457860cf))*-0x8261f) >> (((Float64ArrayView[2])) % (0x527e5ff7))))|0)), (((p={}, (p.z = 'fafafa'.replace(/a\u0009/g, encodeURIComponent))()))), ((d1)), ((0x11d525ee)), ((((0xffffffff)-(0xfce91c4a)) | ((0x37d9ea66)))), ((d1)), ((NaN))))) % ((d0)));\n    return (((((0xfa61600c))>>>((0x39f05c52))) % (((0x9c817c07)-(0xffffffff)-(0x4f8a499a))>>>((0xbdffc113)))))|0;\n  }\n  return f; })(this, {ff: (function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function() { throw 3; }, getOwnPropertyNames: this, delete: function() { return true; }, fix: (let (e=eval) e), has: undefined, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: undefined, enumerate: function() { throw 3; }, keys: window, }; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53-2), Number.MIN_VALUE, 2**53-2, 1/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), -Number.MIN_VALUE, 1, -0x07fffffff, Number.MIN_SAFE_INTEGER, 42, 0x080000000, -(2**53), -0, -Number.MAX_VALUE, -0x080000000, 2**53, 0x100000000, 0x100000001, Math.PI, 2**53+2, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, -0x100000001, 0/0, 0x080000001, 1.7976931348623157e308, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 0]); ");
/*fuzzSeed-157142351*/count=230; tryItOut("/*RXUB*/var r = (/*UUV1*/(x.getMilliseconds = (function(x, y) { return Math.pow(y, x); }))); var s = \"_\\u8743\\u0002\\u0002\\u0002\\u0002\\u0002\"; print(r.test(s)); ");
/*fuzzSeed-157142351*/count=231; tryItOut("\"use strict\"; if(\"\\uC87A\") { if (window) h1.toSource = (function mcc_() { var aueayg = 0; return function() { ++aueayg; if (/*ICCD*/aueayg % 3 == 2) { dumpln('hit!'); try { e2.has(p0); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(i0, v1); } catch(e1) { } Array.prototype.splice.call(a0, -5, 17, o0.t1, m2); } else { dumpln('miss!'); try { a1 + ''; } catch(e0) { } try { delete a1[\"1\"]; } catch(e1) { } v1 = evalcx(\"\\\"use strict\\\"; mathy3 = (function(stdlib, foreign, heap){ \\\"use asm\\\";   var ff = foreign.ff;\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\nprint(((function too_much_recursion(radade) { ; if (radade > 0) { ; too_much_recursion(radade - 1);  } else { v2 = g1.eval(\\\"/(?:(\\\\\\\\B))*?/y\\\"); } (x); })(0)));    return (((-0x8000000)))|0;\\n  }\\n  return f; })(this, {ff: /(\\\\2)|[^]|(?=\\\\3){0,3}/g}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [1.7976931348623157e308, Number.MAX_VALUE, 0x07fffffff, -Number.MAX_VALUE, -0x080000000, -0x0ffffffff, 0x100000000, -(2**53+2), Math.PI, -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, 0, 0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, -0x080000001, -Number.MIN_VALUE, 1/0, 2**53-2, 2**53+2, -0x100000001, 42, 1, 0x080000001, 0.000000000000001, -0, -0x100000000, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER]); \", g1); } };})(); else {print(x); }}\nt0.__proto__ = a1;\n");
/*fuzzSeed-157142351*/count=232; tryItOut("\"use strict\"; s2 += 'x';");
/*fuzzSeed-157142351*/count=233; tryItOut("/*RXUB*/var r = new RegExp(\"[^]\", \"y\"); var s = \"\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-157142351*/count=234; tryItOut("\"use strict\"; g0.g1.v0 = g0.eval(\"o2.s2.__iterator__ = (function(j) { if (j) { try { h2.defineProperty = f0; } catch(e0) { } try { g0.offThreadCompileScript(\\\"/* no regression tests found */\\\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 24 != 1), noScriptRval: new (\\\"\\\\uA073\\\")(), sourceIsLazy: false, catchTermination: false })); } catch(e1) { } /*MXX3*/g2.Date.prototype.setUTCMinutes = g0.Date.prototype.setUTCMinutes; } else { try { (void schedulegc(g2)); } catch(e0) { } f2(g1.s1); } });\");");
/*fuzzSeed-157142351*/count=235; tryItOut("let edoklf, x, c, NaN, x, NaN, ztakgx;v1.toString = (function() { for (var j=0;j<8;++j) { f1(j%5==1); } });");
/*fuzzSeed-157142351*/count=236; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (( ! (( ~ Math.min(Math.imul(Math.fround(x), Math.fround(Number.MIN_VALUE)), (((x | 0) == (Math.fround(Math.min(y, x)) | 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, 0x100000000, -0, Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, -(2**53), -1/0, 0x07fffffff, 1/0, 1, -(2**53-2), 0/0, 42, Number.MIN_VALUE, 0, -Number.MAX_VALUE, 0x100000001, 0x080000000, 2**53+2, -0x0ffffffff, Number.MAX_VALUE, 0x080000001, -0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -(2**53+2), -0x080000000, 0.000000000000001, 1.7976931348623157e308]); ");
/*fuzzSeed-157142351*/count=237; tryItOut("s0 += 'x';");
/*fuzzSeed-157142351*/count=238; tryItOut("a2.pop();");
/*fuzzSeed-157142351*/count=239; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=240; tryItOut("var tyjyyp = new SharedArrayBuffer(2); var tyjyyp_0 = new Uint8Array(tyjyyp); var tyjyyp_1 = new Int32Array(tyjyyp); print(tyjyyp_1[0]); var tyjyyp_2 = new Uint8Array(tyjyyp); var tyjyyp_3 = new Int32Array(tyjyyp); tyjyyp_3[0] = -9; /*oLoop*/for (thuike = 0; thuike < 30; ++thuike) { g1.s2 += 'x'; } ");
/*fuzzSeed-157142351*/count=241; tryItOut("\"use strict\"; /*hhh*/function szqgog(...b){h2.has = f1;}/*iii*/h0.toString = (function() { for (var j=0;j<28;++j) { f0(j%5==1); } });function szqgog(d, szqgog)d >>>= thist1[0] = i2;");
/*fuzzSeed-157142351*/count=242; tryItOut("a2.sort((function() { for (var j=0;j<3;++j) { g2.f2(j%4==0); } }));");
/*fuzzSeed-157142351*/count=243; tryItOut("\"use strict\"; v2 + '';");
/*fuzzSeed-157142351*/count=244; tryItOut("\"use strict\"; /*MXX1*/o1.o2 = g1.EvalError.prototype.constructor;");
/*fuzzSeed-157142351*/count=245; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.imul(( + Math.fround((x >= Math.fround(Math.fround((x >> Math.fround(( + Math.log2(( + -(2**53))))))))))), Math.min(( + Math.tan(x)), ( + Math.fround(( ! ((( ~ x) >>> 0) | 0)))))) >= ((( + ((((Math.fround(( - Math.fround(( - Math.min(x, x))))) | 0) ? (mathy2(( + 2**53+2), y) | 0) : (Math.imul(((((y >>> 0x080000000) >>> 0) !== x) >>> 0), x) | 0)) | 0) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy5, [2**53+2, 0x100000001, 0x100000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, 0x080000000, -(2**53+2), -0x080000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, 1, 42, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0x0ffffffff, Number.MIN_VALUE, -0x100000001, -1/0, 2**53-2, Math.PI, -(2**53), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0/0, 2**53, -Number.MAX_VALUE, -0x07fffffff, -0x080000000, -0x100000000, -(2**53-2), 0]); ");
/*fuzzSeed-157142351*/count=246; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[this,  /x/ , this, (void 0), (void 0),  /x/ ,  /x/ , (void 0), (void 0),  /x/ , (-1/0), (-1/0), (-1/0),  /x/ ,  /x/ , this, this]) { ((4277)); }");
/*fuzzSeed-157142351*/count=247; tryItOut("testMathyFunction(mathy5, [-1/0, -0x080000001, 2**53, 0x080000001, -(2**53-2), 0.000000000000001, -0, Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 2**53-2, 1, 1/0, -0x100000000, 0/0, -Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, -0x07fffffff, -Number.MAX_VALUE, 0x07fffffff, -0x100000001, 0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0x100000000, 0, -Number.MAX_SAFE_INTEGER, 42, 2**53+2, 0x080000000, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=248; tryItOut("print(x);");
/*fuzzSeed-157142351*/count=249; tryItOut("e2.add(g0);");
/*fuzzSeed-157142351*/count=250; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[0x10000000, (void 0), 2**53, (void 0), (void 0),  /x/g , 2**53, 0x10000000, (void 0), 0x10000000, 2**53,  /x/g ,  /x/g , 0x10000000, 0x10000000, (void 0), (void 0),  /x/g , 2**53,  /x/g , (void 0), 2**53, 2**53, (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g , (void 0), 0x10000000, 2**53, 0x10000000, 2**53, 0x10000000, 2**53,  /x/g , 2**53, (void 0),  /x/g , 0x10000000,  /x/g , 2**53, 2**53, 2**53, (void 0), (void 0), (void 0), 2**53,  /x/g , 0x10000000,  /x/g , 2**53, (void 0), 2**53, 2**53,  /x/g , 2**53, (void 0), 0x10000000, 0x10000000, 2**53, 2**53, (void 0),  /x/g , (void 0), (void 0), 2**53, 2**53, 2**53, 2**53, (void 0), (void 0),  /x/g , 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000, 0x10000000,  /x/g ,  /x/g , 0x10000000,  /x/g , 0x10000000,  /x/g , 2**53, 0x10000000, 0x10000000, (void 0), (void 0), (void 0),  /x/g ,  /x/g , (void 0), 0x10000000, (void 0), 0x10000000, (void 0), (void 0),  /x/g , (void 0), (void 0),  /x/g , (void 0), 0x10000000, 0x10000000, (void 0), 0x10000000, 2**53, 0x10000000, 2**53, 0x10000000,  /x/g ,  /x/g , 2**53, 2**53]); ");
/*fuzzSeed-157142351*/count=251; tryItOut("\"use strict\"; print(uneval(v1));function x() { yield new RegExp(\"(${3,}){0}|(?=[^])[^].|.{3}\\u00a4{4,4}{3}\", \"gi\") } print(\"\\u3FB5\");");
/*fuzzSeed-157142351*/count=252; tryItOut("g1.g0.g0.offThreadCompileScript(\"m0.__proto__ = f1;\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 4 != 1), sourceIsLazy: ((function(q) { return q; })(x)), catchTermination: false }));");
/*fuzzSeed-157142351*/count=253; tryItOut("a1.sort((function mcc_() { var boyhta = 0; return function() { ++boyhta; if (/*ICCD*/boyhta % 4 != 1) { dumpln('hit!'); try { /*MXX1*/o2 = g2.Map.prototype.forEach; } catch(e0) { } a0.sort(Array.from.bind(h2), (4277), s0); } else { dumpln('miss!'); try { g2.t1 = new Int8Array(a0); } catch(e0) { } try { f0 = Proxy.createFunction(h2, f1, f1); } catch(e1) { } /*MXX1*/o1 = g0.RangeError.prototype.toString; } };})(), f1, t0);");
/*fuzzSeed-157142351*/count=254; tryItOut("\"use strict\"; ");
/*fuzzSeed-157142351*/count=255; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    i1 = (i1);\n    d0 = (((d0)) - ((-36028797018963970.0)));\n    i2 = (i2);\n    i2 = (i2);\n    i2 = ((0x9e7567a3) <= ((((!(i1)) ? (i1) : (0xb7135d77)))>>>((i2)+(0xffffffff))));\n    return (((((!(0xfee382db))-((36028797018963970.0) > ((4277).unwatch(\"fromCharCode\")))+((((0x4d9e38b4))>>>((0x49e06c51))) != (((0x500c2268))>>>((0xffffffff)))))>>>((i1))) / (0xf2901fba)))|0;\n    d0 = (+(0x7fffffff));\n    switch (((((+(1.0/0.0)) >= (-16777217.0)))|0)) {\n      case 0:\n        (Int8ArrayView[((((Float32ArrayView[(((((0xcee4d3d1))>>>((0x94f4d5c6))))*-0x5e457) >> 2])))) >> 0]) = (-0xfffff*(0x3eb66d5d));\n        break;\n      case 1:\n        i1 = (i2);\n        break;\n      case -1:\n        {\n          return (((i2)-((+((0.25))))-(i2)))|0;\n        }\n      case 1:\n        (Float32ArrayView[(((-1.1805916207174113e+21) > (1099511627777.0))) >> 2]) = ((d0));\n        break;\n      case -3:\n        d0 = (+(1.0/0.0));\n    }\n    return (((0x836b3e18)+((+((window ^ x))) != (+abs(((Float32ArrayView[((i2)-(0x5852b435)) >> 2])))))))|0;\n    return (((0x3a352d38) % (0xffffffff)))|0;\n  }\n  return f; })(this, {ff: (new /(?!\uaf5e.+?|\\B)|^.|\\1+?|\\S?*[^]\\w/gym(window, /\\uD44b\\s|\\w.(?:^)|[^\\d\\cE-\\\u5ab9]?\\1/g))}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-157142351*/count=256; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return (( + Math.sqrt(( + ( + Math.pow(( + -0x080000000), ( + y)))))) ? ( ~ (( ~ ((-1/0 % ( + ( + Math.log2(y)))) >>> 0)) >>> 0)) : Math.fround(Math.sinh(Math.fround((((( - (((x >>> 0) || ( + ( - y))) | 0)) | 0) ? ((Math.imul((x | 0), Math.fround(x)) >>> 0) >>> 0) : ((Math.fround((Math.fround(y) & Math.fround(x))) >>> ((Math.cbrt((x | 0)) | 0) >>> 0)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [1, 0.000000000000001, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, 0x0ffffffff, -0x0ffffffff, 2**53+2, -0x07fffffff, -(2**53-2), 0/0, 0, Number.MAX_SAFE_INTEGER, Math.PI, 0x07fffffff, 0x100000001, Number.MIN_VALUE, -(2**53), -(2**53+2), 0x080000001, 42, 1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -1/0, 2**53-2, Number.MAX_VALUE, -0x080000000, -Number.MAX_VALUE, 0x100000000, 1.7976931348623157e308, -0]); ");
/*fuzzSeed-157142351*/count=257; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.fround(((((( ! ( + ( + ( - ( + y))))) >>> 0) >>> 0) !== ((Math.min((x | 0), (((Math.fround(-Number.MIN_VALUE) % (( ~ -(2**53)) >>> 0)) >>> 0) | 0)) | 0) >>> 0)) >= (Math.fround(( ! (Math.imul((x & Math.fround(Math.atan2((y >>> 0), x))), mathy0(-0, y)) >>> 0))) | Math.fround(Math.atan2(( + Math.fround(( + Math.fround((Math.min((( + 2**53+2) >>> 0), (1/0 >>> 0)) >>> 0))))), (y !== x)))))); }); testMathyFunction(mathy3, /*MARR*/[Math.max(neuter, \"\u03a0\"),  /x/ , function(){},  /x/g , function(){}, Math.max(neuter, \"\u03a0\"), function(){},  /x/ ,  /x/g ,  /x/ , -(2**53),  /x/g ,  /x/g , Math.max(neuter, \"\u03a0\"), function(){},  /x/ , function(){}, function(){},  /x/g , Math.max(neuter, \"\u03a0\"),  /x/ , function(){},  /x/ , function(){}, -(2**53), function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/g , Math.max(neuter, \"\u03a0\"),  /x/ , -(2**53),  /x/g ,  /x/ ,  /x/g ,  /x/g , -(2**53),  /x/ , Math.max(neuter, \"\u03a0\"), -(2**53),  /x/ ,  /x/g ,  /x/g ,  /x/ , Math.max(neuter, \"\u03a0\"),  /x/ , Math.max(neuter, \"\u03a0\"),  /x/ ,  /x/g , -(2**53),  /x/g ,  /x/ , -(2**53),  /x/g , function(){}, -(2**53), -(2**53),  /x/ , -(2**53),  /x/g , -(2**53),  /x/ ,  /x/g , function(){}, -(2**53), function(){}, function(){},  /x/ , Math.max(neuter, \"\u03a0\"), Math.max(neuter, \"\u03a0\"),  /x/g ,  /x/g , function(){},  /x/ , -(2**53),  /x/ ,  /x/ , function(){},  /x/ , Math.max(neuter, \"\u03a0\"),  /x/g , Math.max(neuter, \"\u03a0\"),  /x/ , Math.max(neuter, \"\u03a0\"),  /x/ ,  /x/ ]); ");
/*fuzzSeed-157142351*/count=258; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.max((Math.imul((x ? (Math.max(y, (Math.pow((Math.max(((Math.sign(y) >>> 0) >>> 0), (x >>> 0)) >>> 0), ( + ( ! x))) >>> 0)) | 0) : Math.pow(y, Math.pow((0x100000000 | 0), 0x100000001))), Math.fround((Math.pow(Math.fround(Math.sign((-(2**53+2) && y))), (x >>> 0)) >= Math.fround(Math.asinh((mathy1(y, y) >>> 0)))))) >>> 0), ((Math.atan((( + Math.min(Math.fround((Math.tanh((mathy0(2**53, x) | 0)) | 0)), ( + (((x >= Math.fround(-(2**53))) == (Math.max(y, ( + ( + Math.acosh(x)))) >>> 0)) >>> 0)))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy2, [0x080000001, 2**53+2, -(2**53+2), -(2**53), Number.MIN_VALUE, 2**53-2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, -0x100000000, -0x080000001, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 0x100000000, -Number.MIN_VALUE, 2**53, 0.000000000000001, -0x080000000, -1/0, 0/0, -0x100000001, 0x080000000, -0, 42, -(2**53-2), 1, 1/0]); ");
/*fuzzSeed-157142351*/count=259; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.pow((Math.abs(( + ( - ( + Math.asinh((y >>> 0)))))) >>> 0), ((Math.asinh(Math.imul(y, 2**53)) - Math.pow(x, Math.fround(Math.imul(Math.fround(y), Math.fround(mathy1(y, ( + (( + y) & ( - x))))))))) >>> 0)); }); testMathyFunction(mathy4, [0.000000000000001, 1/0, -0x0ffffffff, 0x07fffffff, -(2**53+2), -0x080000000, 1.7976931348623157e308, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x080000001, 42, -Number.MAX_VALUE, -0x100000000, -0, 0x0ffffffff, Number.MIN_VALUE, 0, -0x100000001, -1/0, -(2**53-2), 2**53, 0x100000000, Number.MIN_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, Math.PI, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, 2**53+2, 0/0, 0x100000001, Number.MAX_VALUE, -0x07fffffff, 2**53-2]); ");
/*fuzzSeed-157142351*/count=260; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.trunc(( + ( ~ (( + (x >>> 0)) >>> 0)))) | 0); }); testMathyFunction(mathy0, /*MARR*/[function(id) { return id }, (void 0), (void 0), function(id) { return id }, function(id) { return id }, (void 0), function(id) { return id }, function(id) { return id }, (void 0), (void 0), function(id) { return id }, (void 0), function(id) { return id }, function(id) { return id }, (void 0), function(id) { return id }, function(id) { return id }, (void 0), function(id) { return id }, (void 0), (void 0), function(id) { return id }, (void 0), function(id) { return id }, function(id) { return id }, (void 0), function(id) { return id }, (void 0), (void 0), function(id) { return id }, (void 0), (void 0), (void 0), (void 0), function(id) { return id }, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, (void 0), (void 0), function(id) { return id }, (void 0), (void 0), function(id) { return id }, (void 0), function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, (void 0), function(id) { return id }, (void 0), function(id) { return id }, (void 0), (void 0), (void 0), function(id) { return id }, (void 0), function(id) { return id }, (void 0), (void 0), function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, function(id) { return id }, (void 0), function(id) { return id }, (void 0), function(id) { return id }, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), function(id) { return id }, (void 0), (void 0), function(id) { return id }, (void 0), function(id) { return id }, function(id) { return id }, (void 0), (void 0), (void 0), (void 0), function(id) { return id }, function(id) { return id }, function(id) { return id }, (void 0), (void 0), function(id) { return id }, (void 0), function(id) { return id }, (void 0), (void 0), function(id) { return id }, function(id) { return id }, (void 0), (void 0)]); ");
/*fuzzSeed-157142351*/count=261; tryItOut("y;");
/*fuzzSeed-157142351*/count=262; tryItOut("\"use strict\"; while((new Object(/*FARR*/[ '' , ].filter(mathy0, (4277)))) && 0){print(x);print(x); }");
/*fuzzSeed-157142351*/count=263; tryItOut("\"use strict\"; t0.set(a2, 8);");
/*fuzzSeed-157142351*/count=264; tryItOut("Array.prototype.pop.call(this.a0, s1);");
/*fuzzSeed-157142351*/count=265; tryItOut("");
/*fuzzSeed-157142351*/count=266; tryItOut("var vmxhlc = new ArrayBuffer(2); var vmxhlc_0 = new Uint16Array(vmxhlc); vmxhlc_0[0] = -16; var vmxhlc_1 = new Uint16Array(vmxhlc); vmxhlc_1[0] = 18; delete o1.h2.getOwnPropertyDescriptor;print(vmxhlc_0);/*ODP-1*/Object.defineProperty(g0, \"x\", ({enumerable: false}));;");
/*fuzzSeed-157142351*/count=267; tryItOut("\"use strict\"; Object.defineProperty(g2, \"this.v0\", { configurable: true, enumerable: true,  get: function() {  return a1.length; } });");
/*fuzzSeed-157142351*/count=268; tryItOut("Array.prototype.reverse.call(a1, f2);");
/*fuzzSeed-157142351*/count=269; tryItOut("print(x);");
/*fuzzSeed-157142351*/count=270; tryItOut("/*oLoop*/for (kvupun = 0; kvupun < 4; ++kvupun) { s1 += 'x'; } ");
/*fuzzSeed-157142351*/count=271; tryItOut("\"use strict\"; g1.v2 = Array.prototype.some.apply(a2, [(function mcc_() { var gmiyup = 0; return function() { ++gmiyup; f1(/*ICCD*/gmiyup % 11 == 5);};})(), b0]);");
/*fuzzSeed-157142351*/count=272; tryItOut("mathy4 = (function(x, y) { return ( + ((( ~ ( ~ (((y | 0) << x) | 0))) | 0) / ((Math.fround(( - -0)) ? x : Math.fround(mathy2(y, ( + (Math.fround(x) > x))))) != (( ~ (( + Math.imul(((Math.fround((Math.sign(y) && x)) | x) >>> 0), (((2**53 >>> 0) >= (y >>> 0)) >>> 0))) >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-157142351*/count=273; tryItOut("i2.next();");
/*fuzzSeed-157142351*/count=274; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.cosh(( + ( ! ( + ( + Math.log(( ~ ( + mathy2(( + y), ( + ( ~ (y | 0)))))))))))); }); ");
/*fuzzSeed-157142351*/count=275; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + Math.fround(( - Math.fround(Math.fround(Math.cbrt(x)))))); }); testMathyFunction(mathy3, [-0x100000001, 2**53+2, -0x080000001, -0x0ffffffff, -0x100000000, 0x07fffffff, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, 0x100000001, 0, -(2**53+2), 0x100000000, 0x080000000, -(2**53), 42, 0.000000000000001, 0/0, -0, Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, -0x07fffffff, 1/0, -(2**53-2), 1.7976931348623157e308, 0x080000001, -1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -Number.MIN_VALUE]); ");
/*fuzzSeed-157142351*/count=276; tryItOut("x;");
/*fuzzSeed-157142351*/count=277; tryItOut("g1.i2.send(f2);");
/*fuzzSeed-157142351*/count=278; tryItOut("\"use strict\"; this.v2 = new Number(4);");
/*fuzzSeed-157142351*/count=279; tryItOut("\"use strict\"; a1.sort((function mcc_() { var axrkdw = 0; return function() { ++axrkdw; if (/*ICCD*/axrkdw % 5 == 0) { dumpln('hit!'); try { a1[v0] =  \"use strict\" ; } catch(e0) { } x = s2; } else { dumpln('miss!'); f0 = Proxy.createFunction(g1.h2, f2, this.f0); } };})(), o0.i1);");
/*fuzzSeed-157142351*/count=280; tryItOut("m2 + '';");
/*fuzzSeed-157142351*/count=281; tryItOut("\"use strict\"; /*MXX2*/g2.WeakSet.prototype = v2;print( /x/ );function x(x, eval)\"use asm\";   var abs = stdlib.Math.abs;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    i0 = ((abs((~~(-7.737125245533627e+25)))|0));\n    {\n      i0 = ((((i1)+((~~((+abs(((256.0)))) + (((4398046511105.0)) - ((68719476736.0))))) == (((i0))|0)))|0) >= ((((((0x6fcf7888) / (0xc27bbd5))>>>((i1)*0xfffff)))-(i0)) << ((((0x8de5552b) != (0x7efa8e7f)) ? (i0) : ((((i0)) >> ((Uint8ArrayView[0]))))))));\n    }\n    return +((1.0009765625));\n  }\n  return f;( /x/g );");
/*fuzzSeed-157142351*/count=282; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return mathy0(((((y ** ( + Math.fround((Math.fround(Math.imul((((mathy0(1, 2**53) | 0) ? (x | 0) : Math.atan2(x, y)) | 0), x)) || Math.fround(((Math.imul(x, (( ! (-Number.MAX_VALUE >>> 0)) >>> 0)) >>> 0) & x)))))) | 0) ? (Math.abs((Math.exp(( ! Math.fround(( ~ Math.fround(( ! y)))))) >>> 0)) >>> 0) : ( + ( + ( ! (-0x080000000 >>> 0))))) | 0), ( + Math.fround((Math.fround(( + ( + Math.hypot((Math.hypot((y >>> 0), Math.fround(( + Math.fround(Math.hypot((-1/0 | 0), x))))) >>> 0), x)))) % Math.fround(((x >>> 0) ** (Math.hypot((x >>> 0), x) | 0))))))); }); testMathyFunction(mathy3, [2**53-2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x0ffffffff, Number.MAX_VALUE, -(2**53-2), 2**53+2, 1/0, -(2**53), -0x080000000, -(2**53+2), 0/0, -0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0.000000000000001, Math.PI, -0x07fffffff, -Number.MIN_VALUE, -0x080000001, 1, -1/0, 42, 0x080000000, 2**53, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0x100000000, -0, 0x100000001]); ");
/*fuzzSeed-157142351*/count=283; tryItOut("try { return; } catch(z if x) { throw y; } finally { try { this.a0.toSource = Uint16Array; } finally { throw x; }  } ");
/*fuzzSeed-157142351*/count=284; tryItOut("for (var v of m2) { Array.prototype.pop.apply(a2, []); }");
/*fuzzSeed-157142351*/count=285; tryItOut("print(uneval(m0));function z({}, x = (4277))this << falseArray.prototype.push.call(a1, v1);");
/*fuzzSeed-157142351*/count=286; tryItOut("i2 = new Iterator(s1, true);");
/*fuzzSeed-157142351*/count=287; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.pow((( ! ((Math.min(mathy2(Math.sign(2**53+2), x), Math.pow((((-1/0 >>> 0) ? (x >>> 0) : x) >>> 0), y)) ? Math.max((( ! ( + y)) >>> 0), y) : Math.fround(mathy1((Number.MAX_SAFE_INTEGER >>> 0), (y >>> 0)))) >>> 0)) >>> 0), (( ! Math.fround((-0x100000001 || Math.fround(Math.log1p(Math.fround(Math.min(y, y))))))) >>> 0)); }); testMathyFunction(mathy3, [-0x0ffffffff, Math.PI, 2**53, 0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 2**53+2, 1, -0x07fffffff, -0x100000001, 0x080000000, Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, -(2**53+2), -Number.MAX_SAFE_INTEGER, 42, -0x080000001, 0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 2**53-2, 0, 0/0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, -1/0, Number.MIN_VALUE, -0, 0x080000001, -(2**53), -(2**53-2)]); ");
/*fuzzSeed-157142351*/count=288; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=289; tryItOut("\"use strict\"; a1.reverse();");
/*fuzzSeed-157142351*/count=290; tryItOut("mathy3 = (function(x, y) { return ((Math.fround(( + ((mathy2((x >>> 0), (( ~ 0x100000000) >>> 0)) >>> 0) >>> 0))) != ((Math.min((Math.tanh(Math.expm1(Math.fround(y))) | 0), ((Math.pow((( + ( + Math.atan2(( + y), ( + x)))) | 0), window = \u3056) | 0) | 0)) | 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-157142351*/count=291; tryItOut("");
/*fuzzSeed-157142351*/count=292; tryItOut("/*infloop*/ for (x of \"\\uDF41\") (20);");
/*fuzzSeed-157142351*/count=293; tryItOut("(true);");
/*fuzzSeed-157142351*/count=294; tryItOut("switch((4277)) { case 2: break; case Promise.prototype.catch(let (wshxty, jikpji, d, wrczjj, a, \u3056, eikazf, lwdzww, cxseft, \"-25\")  /x/  !== undefined, x): t0 = new Int16Array(g0.t0);var prjwwn = new SharedArrayBuffer(4); var prjwwn_0 = new Uint16Array(prjwwn); /*RXUB*/var r = r2; var s = \"\\uffe8\\u00eb\\n\"; print(r.exec(s)); selectforgc(o1);default: h2.get = f2;z = Float32Array(new RegExp(\"(?=\\\\2)\", \"gim\")).__defineGetter__(\"x\", \u000cMath.sinh);case 3: case x: break; break; ((\u3056) = /(?![^])/gm);break;  }");
/*fuzzSeed-157142351*/count=295; tryItOut("mathy5 = (function(x, y) { return mathy1(Math.imul(Math.trunc(x), ((Math.fround((Math.min((1 - y), ( + (-Number.MIN_SAFE_INTEGER * y))) | 0)) ^ ((((0x080000000 >>> 0) != ((( + 42) >>> Math.sin(x)) >>> 0)) >>> 0) >>> 0)) | 0)), (( + ((Math.round((x >>> 0)) >>> 0) & (y > ( + ( + ( ~ ( + ( ~ y)))))))) | (Math.hypot(x, ( + Math.pow(Math.trunc(((( + y) ? (0x080000001 | 0) : (-Number.MAX_SAFE_INTEGER | 0)) | 0)), x))) | 0))); }); testMathyFunction(mathy5, [Math.PI, 2**53, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, -(2**53-2), 2**53+2, 0x100000001, 0.000000000000001, 0x0ffffffff, 1, 0, 0x07fffffff, -0x07fffffff, 42, -(2**53), Number.MAX_VALUE, 2**53-2, -0x100000001, 0x080000000, 0x080000001, 0/0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -0x0ffffffff, -0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_VALUE, -(2**53+2), -0]); ");
/*fuzzSeed-157142351*/count=296; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.max((Math.log((x / Math.fround(Math.imul(0x100000001, mathy3(2**53, ( + Math.imul(( + y), ( + x)))))))) | 0), (( ~ ( + ( ~ Math.cos((Math.atan2(0x100000001, (Math.sin((y >>> 0)) >>> 0)) | 0))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-157142351*/count=297; tryItOut("\"use strict\"; g1.v0 = Object.prototype.isPrototypeOf.call(g0, p0);\ndelete this.h0.get;\nlet (x) { print(x); }");
/*fuzzSeed-157142351*/count=298; tryItOut("mathy3 = (function(x, y) { return ( + ( ~ (( + ( + Math.imul((Math.sqrt(Number.MAX_VALUE) | 0), Math.fround(Math.asinh(((Math.hypot(0, -0x080000000) >>> 0) * ( + Math.pow(x, x)))))))) >>> 0))); }); ");
/*fuzzSeed-157142351*/count=299; tryItOut("v0 + '';");
/*fuzzSeed-157142351*/count=300; tryItOut("print(x);");
/*fuzzSeed-157142351*/count=301; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + mathy0(( + ((/* no regression tests found */ ? x : Math.fround(Math.sinh(Math.min(Math.fround(y), Math.fround(x))))) <= Math.max(Math.cosh(x), ( ! (( ! (-(2**53-2) >>> 0)) >>> 0))))), ( + Math.imul((((((( ! (y >>> y)) + (( + (y | 0)) >>> 0)) >= (Math.sign((-(2**53-2) | 0)) | 0)) >>> 0) < (Math.imul(x, Math.fround(-0x100000001)) | 0)) | 0), Math.min(((-Number.MIN_SAFE_INTEGER | 0) <= y), (Math.round(((((-0x07fffffff >>> 0) + (y >>> 0)) >>> 0) | 0)) | 0)))))); }); testMathyFunction(mathy1, [-0x080000000, 0x100000001, -0x080000001, -Number.MIN_VALUE, 0x100000000, 0x080000001, Math.PI, -(2**53-2), 2**53-2, 1/0, 42, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, 1, 0x0ffffffff, 0/0, -0x0ffffffff, -(2**53+2), -1/0, 0, -0x100000001, 0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0, 0x080000000, -(2**53), -0x07fffffff, 2**53+2]); ");
/*fuzzSeed-157142351*/count=302; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( - (((( - (x >>> 0)) >>> 0) && (x + Math.fround((Math.fround(Math.fround(Math.max(Math.fround(y), ( + Math.atanh(x))))) === Math.fround(Math.min(x, -0x080000001)))))) >>> ((x < (y ? y : ( + (x % -(2**53))))) === Math.min((Math.fround(x) , Math.fround(0x080000001)), Math.acos((Math.imul((y >>> 0), (y >>> 0)) >>> 0)))))); }); testMathyFunction(mathy0, [1.7976931348623157e308, 42, 2**53+2, -0x080000000, -0x100000000, 0x100000000, 0x0ffffffff, -(2**53+2), 0.000000000000001, -0, 0, -0x07fffffff, 1/0, -0x0ffffffff, -(2**53-2), 2**53, 0/0, -Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, 1, Number.MAX_VALUE, -(2**53), 2**53-2, 0x07fffffff, -0x100000001, 0x080000001, -1/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-157142351*/count=303; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.fround((Math.sin((Math.fround(((x | 0) >> Math.fround(y))) << (x >>> 0))) >>> 0))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 1, 0x080000001, -(2**53+2), 2**53, -0, -(2**53), -1/0, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, 0x100000001, -(2**53-2), -0x100000001, 2**53-2, 1/0, 0x07fffffff, -0x100000000, 0.000000000000001, -Number.MAX_VALUE, -0x07fffffff, 0, 0x080000000, -0x080000000, 0x100000000, 2**53+2, 0/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 0x0ffffffff]); ");
/*fuzzSeed-157142351*/count=304; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((((((Math.acosh(x) / ( + Math.atan(( + Math.tanh(Math.tanh(y)))))) >>> 0) == (( - Math.fround(( + Math.max(x, ( + (x ? mathy4(-0x100000001, x) : (x >>> 0))))))) >>> 0)) >>> 0) >>> 0) ? Math.asin(( + Math.sqrt(( + Math.atan2(( + -Number.MAX_VALUE), ( + (( + Math.imul(x, y)) & ( + ( + (( + 0x100000001) ? ( + Number.MIN_VALUE) : ( + y))))))))))) : (((mathy1(((y >= ( + 0x0ffffffff)) | 0), Math.fround((Math.imul(((( + y) | 0) >>> 0), (y >>> 0)) >>> 0))) | 0) & ((Math.sinh((Math.log(( - y)) | 0)) * (y | 0)) | 0)) | 0)); }); ");
/*fuzzSeed-157142351*/count=305; tryItOut("\"use strict\"; var mwoxyh = new ArrayBuffer(8); var mwoxyh_0 = new Int16Array(mwoxyh); mwoxyh_0[0] = -24; /*ADP-2*/Object.defineProperty(a2, 3, { configurable: false, enumerable: true, get: (function() { try { v2 = (s0 instanceof g2.f2); } catch(e0) { } try { a1.__proto__ = v0; } catch(e1) { } print(h1); return f2; }), set: g2.f1 });");
/*fuzzSeed-157142351*/count=306; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d1 = (d1);\n    }\n    return +((Float64ArrayView[4096]));\n  }\n  return f; })(this, {ff: (window).bind}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [-0x080000001, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, 1, 2**53+2, -0x080000000, -Number.MIN_VALUE, -(2**53), 0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0x080000000, Number.MAX_VALUE, -0x0ffffffff, 1/0, Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x100000000, -0x07fffffff, 0/0, 42, 0x100000000, -(2**53-2), 2**53-2, 2**53, Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0, 0x100000001, 0, 0x080000001]); ");
/*fuzzSeed-157142351*/count=307; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=308; tryItOut("\"use strict\"; i2 = o1.a2.values;");
/*fuzzSeed-157142351*/count=309; tryItOut("\"use strict\"; i0 = new Iterator(s2);");
/*fuzzSeed-157142351*/count=310; tryItOut("if((x % 6 != 3)) {/*MXX2*/g2.SharedArrayBuffer.prototype.slice = g0.h0;(eval);\nx;\n } else {g1.v2 = new Number(Infinity)\nthis.s2 += s2;function shapeyConstructor(ybbqwh){\"use asm\"; this[\"__proto__\"] = [1];for (var ytqoixrvb in this) { }for (var ytqubktns in this) { }for (var ytqvwxchn in this) { }this[new String(\"17\")] = (1/0);if ((let (x = function(y) { yield y; print(ybbqwh);; yield y; }, jwjmfo, {} = /(?=(?!(?:\\B)))/ym.valueOf(\"number\"), z = /(\\b{4}|.^+?(?![^\\s\\n])(\\w(?:\\s)*))/yim, x, mszcig, bllrtl) Math.max(19, x))) for (var ytqpxqfwe in this) { }return this; }/*tLoopC*/for (let e of /*FARR*/[(uneval(({e: a, x:  /x/g  }))), new (Date.prototype.setYear)(), ]) { try{let ppterm = new shapeyConstructor(e); print('EETT'); o2.a0.push(-(b) >>= new Proxy(function(id) { return id }), s0, m0);}catch(e){print('TTEE ' + e); } } }");
/*fuzzSeed-157142351*/count=311; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 36893488147419103000.0;\n    var i5 = 0;\n    {\n      (Float64ArrayView[1]) = ((Float64ArrayView[((i5)+(!((imul((i3), (0xfec1f5d4))|0) != (((0xfc48c2cc)-(0xfdca5add)) | ((0xffffffff)*-0xfa0a))))-((0xcad70b93))) >> 3]));\n    }\n    {\n      {\n        d1 = ( \"\"  * Object((4277),  '' ));\n      }\n    }\n    return (((i0)-(/*FFI*/ff(((((/*FFI*/ff(((6.044629098073146e+23)))|0)) & ((((function() { yield /((?=(?!.))*?|\\u24f3)/gym; } })())) / (0x4e5af2e0)))), (((((((0xfa378cbe))>>>((-0x8000000))) <= (((0xab2fa3b2))>>>((0x943bf76c))))+(0x4ed37d4c)) & (((0xcefc95cb) ? (-0x8000000) : (0xc2b210e8))+(i2)+(i0)))), ((d1)))|0)-(0xfbb226a0)))|0;\n  }\n  return f; })(this, {ff: (x)}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-157142351*/count=312; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((( + ( + Math.sqrt(Math.fround(( ~ (x | 0)))))) | 0) >= (( + Math.max(( + Math.fround(Math.pow((x | 0), (mathy0((( ~ x) >>> 0), x) | 0)))), ( + ( + ( ~ Math.atan2(x, y)))))) <= (Math.fround(x) == (y >>> 0)))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 2**53+2, -0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1/0, 0, -Number.MIN_SAFE_INTEGER, 1, Math.PI, 42, -0, -0x0ffffffff, -0x100000001, 2**53-2, 0x07fffffff, -(2**53+2), 0.000000000000001, 0x080000001, -0x080000000, Number.MAX_VALUE, -0x080000001, 0/0, -0x07fffffff, 0x100000001, 0x080000000, Number.MIN_VALUE, -(2**53-2), -1/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, 0x0ffffffff, -(2**53)]); ");
/*fuzzSeed-157142351*/count=313; tryItOut("while((v0 = g1.eval(\"print(x);\")) && 0){o0.v0 = g2.runOffThreadScript();h2 + ''; }");
/*fuzzSeed-157142351*/count=314; tryItOut("/*MXX1*/o1 = g0.Object.prototype.toLocaleString;");
/*fuzzSeed-157142351*/count=315; tryItOut("g2.v0 = evalcx(\"/* no regression tests found */\", g2);function x(...x)\"use asm\";   var abs = stdlib.Math.abs;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -65537.0;\n    return ((((-0x8000000) ? (0x249ff07c) : ((((0x189540f6) / (-0x8000000))>>>(-0x9d2cf*(-0x8000000))) >= ((((-0x8000000)))>>>((0xf8a25e44)*0x1a45e))))+((Uint8ArrayView[((-0x8000000)+(0xffffffff)) >> 0]))))|0;\n    switch ((abs((0x7fffffff))|0)) {\n    }\n    return (((0xfc82ae14)+((d1) > (d1))))|0;\n  }\n  return f;Array.prototype.reverse.apply(a1, [h0]);");
/*fuzzSeed-157142351*/count=316; tryItOut("o1.a0.reverse(s1);");
/*fuzzSeed-157142351*/count=317; tryItOut("\"use strict\"; v0 = (p0 instanceof g1);");
/*fuzzSeed-157142351*/count=318; tryItOut("v0 = this.a1.length;");
/*fuzzSeed-157142351*/count=319; tryItOut("\"use strict\"; x = g2;");
/*fuzzSeed-157142351*/count=320; tryItOut("Object.defineProperty(this, \"g2.t1\", { configurable: (x % 5 != 3), enumerable: (4277),  get: function() {  return new Int32Array(this.a1); } });");
/*fuzzSeed-157142351*/count=321; tryItOut("\"use strict\"; selectforgc(o0);");
/*fuzzSeed-157142351*/count=322; tryItOut("t1[19] = x;");
/*fuzzSeed-157142351*/count=323; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.pow((Math.tanh(y) ? (mathy1(((( ! x) >>> 0) / Math.round(x)), ( + (x < x))) >>> 0) : (Math.cosh(y) | 0)), Math.ceil((( ! (( ~ (0 >>> 0)) >>> 0)) | 0))) >>> 0); }); ");
/*fuzzSeed-157142351*/count=324; tryItOut("/*infloop*/ for (let (e) of (/*MARR*/[(4277), [undefined], [undefined], (4277), (4277), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), (4277), objectEmulatingUndefined(), (4277), objectEmulatingUndefined(), [undefined], [undefined], x, x, x, (4277), (4277), (4277), x, objectEmulatingUndefined(), objectEmulatingUndefined(), [undefined], [undefined], x, x, (4277), objectEmulatingUndefined(), x, [undefined], (4277), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), [undefined], [undefined], x, x, objectEmulatingUndefined(), x, x, x, (4277), (4277), objectEmulatingUndefined(), objectEmulatingUndefined(), x, (4277), x, [undefined], [undefined], objectEmulatingUndefined(), (4277), x, [undefined], (4277), x, (4277), (4277), objectEmulatingUndefined(), [undefined], [undefined], (4277), objectEmulatingUndefined(), [undefined], x, (4277), [undefined], (4277), (4277), objectEmulatingUndefined(), (4277), x, x, objectEmulatingUndefined(), [undefined], (4277), [undefined], (4277), [undefined], x, objectEmulatingUndefined(), x, x, x, x, (4277), (4277), x, x, (4277), (4277), [undefined]].some(/*FARR*/[false, -3,  '' , ...[]].some(eval, x)))) g1 = evalcx('lazy');");
/*fuzzSeed-157142351*/count=325; tryItOut("\"use strict\"; v2 = t1.length;");
/*fuzzSeed-157142351*/count=326; tryItOut("mathy1 = (function(x, y) { return ( + Math.min(Math.asinh(( ~ Math.trunc(y))), ( + y))); }); ");
/*fuzzSeed-157142351*/count=327; tryItOut("a0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var NaN = stdlib.NaN;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (+exp(((d0))));\n    d0 = (144115188075855870.0);\n    d0 = (295147905179352830000.0);\n    return +((((NaN)) * ((+(1.0/0.0)))));\n  }\n  return f; });");
/*fuzzSeed-157142351*/count=328; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return (((Math.sign(Math.hypot(Math.imul(Math.cbrt(x), -(2**53+2)), (Math.log(((Math.ceil(Math.fround((x / x))) | 0) | 0)) | 0))) >>> 0) >>> (( - (( ~ Math.atan(-(2**53+2))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy2, [2**53+2, 0/0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000001, -Number.MAX_VALUE, -0x080000000, -(2**53), 2**53-2, Number.MAX_VALUE, 1/0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0, 0x0ffffffff, 0x100000000, 42, 1.7976931348623157e308, 0x080000001, -(2**53+2), 1, Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, 0x080000000, 2**53, -0x0ffffffff, -(2**53-2), -0x100000001, -1/0]); ");
/*fuzzSeed-157142351*/count=329; tryItOut("/*hhh*/function mnnrzl(b){g1.offThreadCompileScript(\"g0 + b0;\");}mnnrzl(x ? allocationMarker() : Proxy.name = (Math.log1p(window)), let (e = new RegExp(\"\\\\3\", \"y\")) [1]);");
/*fuzzSeed-157142351*/count=330; tryItOut("testMathyFunction(mathy5, [objectEmulatingUndefined(), (new Boolean(false)), '/0/', '0', ({toString:function(){return '0';}}), (new Boolean(true)), [0], undefined, true, (function(){return 0;}), NaN, (new String('')), [], '\\0', '', 0, (new Number(0)), (new Number(-0)), null, /0/, -0, 0.1, ({valueOf:function(){return '0';}}), false, 1, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-157142351*/count=331; tryItOut("a2.pop(s2, b0, o1, t2);");
/*fuzzSeed-157142351*/count=332; tryItOut("testMathyFunction(mathy2, [/0/, (new Number(0)), (new String('')), 0.1, -0, ({toString:function(){return '0';}}), [], NaN, objectEmulatingUndefined(), '/0/', undefined, 0, ({valueOf:function(){return 0;}}), true, false, (new Boolean(false)), [0], (new Boolean(true)), '', 1, '0', null, (function(){return 0;}), ({valueOf:function(){return '0';}}), (new Number(-0)), '\\0']); ");
/*fuzzSeed-157142351*/count=333; tryItOut("testMathyFunction(mathy4, /*MARR*/[[(void 0)], 1e+81, [(void 0)], (eval(\"(uneval( /x/g .yoyo( \\\"\\\" )))\")), false, false, [(void 0)], false, (eval(\"(uneval( /x/g .yoyo( \\\"\\\" )))\")), false, 1e+81, false, 1.2e3, 1e+81, false, false, 1e+81, [(void 0)]]); ");
/*fuzzSeed-157142351*/count=334; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy0(Math.atan2(Math.fround((Math.fround(((Math.exp((( - ( + (y * y))) >>> 0)) >>> 0) | 0)) | 0)), (Math.min((Math.atan2((mathy2((x >>> 0), (y | 0)) >>> 0), Math.clz32(( ~ Math.fround(x)))) | 0), (( + ( ! ( + y))) | 0)) | 0)), ( + Math.log1p(( + (( + ((( ~ (( + ((y | 0) || y)) | 0)) | 0) | 0)) | 0))))); }); testMathyFunction(mathy4, ['0', (function(){return 0;}), NaN, '/0/', /0/, -0, '\\0', objectEmulatingUndefined(), 0.1, (new Boolean(false)), ({toString:function(){return '0';}}), false, undefined, (new Number(-0)), '', true, 0, null, [], (new Number(0)), ({valueOf:function(){return 0;}}), (new Boolean(true)), 1, ({valueOf:function(){return '0';}}), (new String('')), [0]]); ");
/*fuzzSeed-157142351*/count=335; tryItOut("\"use asm\"; this.v0 = t2.length;");
/*fuzzSeed-157142351*/count=336; tryItOut("\"use strict\"; o1.h0.getOwnPropertyNames = g1.f2;\nprint(x);\n");
/*fuzzSeed-157142351*/count=337; tryItOut("\"use strict\"; f1(s0);");
/*fuzzSeed-157142351*/count=338; tryItOut("mathy0 = (function(x, y) { return Math.max(( + ((( ~ Math.fround(( ! Math.fround(( ! Math.fround(Math.pow(x, y))))))) >>> 0) ^ ((Math.imul(Math.fround((Math.fround(y) == Math.fround((Math.cosh(y) | 0)))), (( ! (y | 0)) | 0)) > ((Number.MIN_SAFE_INTEGER == Math.fround(Math.clz32(Math.fround(Math.min(0x07fffffff, x))))) | 0)) | 0))), Math.fround(( + ( - (Math.expm1((y >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, /*MARR*/[new Boolean(true), x, new Boolean(true), x, -0x0ffffffff, x, new Boolean(true), [1], [1], x, x, -0x0ffffffff, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Boolean(true), x, new Boolean(true), -0x0ffffffff, x, [1], new Boolean(true), x, -0x0ffffffff, new Boolean(true), [1], -0x0ffffffff, new Boolean(true), x]); ");
/*fuzzSeed-157142351*/count=339; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((( ~ (( + (Math.atanh((0x080000001 * x)) >>> 0)) ? (Math.hypot(( + -0x100000000), Math.fround((((Math.pow(Math.fround(y), Math.fround(-0x100000000)) >>> 0) | 0) != ( + 0)))) | 0) : (Math.min(y, x) >>> 0))) >>> 0) & Math.sign((((((y <= ( + (y , y))) ? ( + Math.fround(Math.ceil(Math.fround(( ! (-Number.MAX_VALUE >>> 0)))))) : Math.fround((Math.imul(x, (y | 0)) | 0))) | 0) | 0) % (( - (Math.cbrt((Number.MAX_SAFE_INTEGER | 0)) | 0)) | 0)))); }); ");
/*fuzzSeed-157142351*/count=340; tryItOut("{(\"\\u4640\");\nprint(x);\nselectforgc(o1); }");
/*fuzzSeed-157142351*/count=341; tryItOut("\"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.hypot((( + Math.atan2(( + Math.atan2(Math.trunc(Math.fround(( ! ((x >>> x) >>> 0)))), Math.fround(( + (( + Math.log2((x >>> 0))) >> ( + (y && y))))))), Math.pow(y, ( - 2**53-2)))) >>> 0), ((Math.imul(Math.fround(( + Math.fround(x))), (Math.min(Math.hypot(x, x), Math.fround(((x >>> 0) % ( + ((Math.imul(( + ( - ( + y))), y) | 0) < ( + y)))))) >>> 0)) >>> 0) >>> 0)) >>> 0); }); ");
/*fuzzSeed-157142351*/count=342; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.cosh(Math.atan(( + ( ~ ( + x))))) >= ( + Math.max((Math.round((Math.atan2(x, ( + x)) | 0)) && x), ((Math.max(Math.asin(y), (((x >>> 0) ? ( + y) : ( + y)) >>> 0)) ^ x) ? ( ~ Math.fround(y)) : ( + Math.max((Math.log2(Number.MIN_SAFE_INTEGER) | 0), ( + x))))))) ^ (((( ! Math.imul(Math.fround(Math.min(Math.fround(0x0ffffffff), ((Math.min(( + y), ( + y)) | 0) / 0x100000001))), Math.fround(( - y)))) && (Math.tan(Math.min(Math.max((Math.fround(Math.max(Math.fround(x), Math.clz32((-1/0 >>> 0)))) >>> 0), Math.fround(Math.fround(y))), (Math.min((Math.log2(0x080000001) ? ( + -0) : (y >> x)), Math.fround(y)) | 0))) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy0, [-(2**53-2), -0x100000000, 0x080000000, -0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 42, 1/0, -Number.MAX_VALUE, 2**53, 1, Number.MIN_VALUE, 2**53+2, 2**53-2, -(2**53+2), Number.MAX_VALUE, 0x100000001, 0/0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -(2**53), 0x080000001, -0x080000000, Number.MIN_SAFE_INTEGER, -1/0, -0x100000001, -Number.MIN_VALUE, 0x100000000, 0x0ffffffff, 0]); ");
/*fuzzSeed-157142351*/count=343; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (mathy0(((((y && ( ~ (0/0 >> (x >>> 0)))) == Math.fround(Math.min((x | 0), (0x100000001 | 0)))) ** -0x080000001) | 0), Math.fround(Math.imul(Math.fround(0/0), (Math.max(((( + (x ^ ( + Math.cos((y | 0))))) || ( + ( - ( + x)))) | 0), ((Math.tan(((( + x) | 0) | 0)) | 0) | 0)) | 0)))) == ( ~ Math.fround(Math.fround((x << ( + (( ~ ((( + y) >>> 0) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy4, /*MARR*/[new Boolean(false), 0.1, x, false, false, 0.1, new Boolean(false), x, false, 0.1, new Boolean(false), false, x, 0.1, new Boolean(false), new Boolean(false), new Boolean(false), 0.1, new Boolean(false), x, new Boolean(false), x, new Boolean(false), new Boolean(false), 0.1, false, false, 0.1, x, 0.1, new Boolean(false), new Boolean(false), x, new Boolean(false), new Boolean(false), x, new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-157142351*/count=344; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2((((Math.acos(-Number.MIN_VALUE) ? y : Math.min(( + ( + ( + y))), y)) ? ( + ( + (Math.atan2(((( ~ Number.MAX_VALUE) | 0) | 0), ((Math.min(((( ~ (x >>> 0)) >>> 0) >>> 0), (-0x0ffffffff >>> 0)) >>> 0) | 0)) | 0))) : Math.sqrt(( + (( + Math.cos((( ! Number.MAX_SAFE_INTEGER) >>> 0))) | 0)))) >>> 0), ((( + (Math.log10((( + Math.fround(( + x))) >>> 0)) >>> 0)) !== ( - (Math.fround(((((x | 0) >>> (x | 0)) | 0) === y)) >>> (((( ~ 1) >>> 0) % (Math.log10(0/0) >>> 0)) >>> 0)))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-Number.MIN_VALUE, 0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, -0, 2**53-2, 0x080000001, 0.000000000000001, Math.PI, 0x0ffffffff, -1/0, 0x100000000, -(2**53-2), 1/0, -(2**53+2), 42, 0x07fffffff, 2**53, 0/0, -0x080000000, -0x100000000, -0x080000001, -Number.MIN_SAFE_INTEGER, 1, 0, -Number.MAX_VALUE, -(2**53), Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=345; tryItOut("/*RXUB*/var r = /\\w\\B|^|(?![^]|(?:(\u6223)))*?+?((\\W)|[^]{0,3})|(?=[^])|(?![^](?:^))?(?:(?:.|$(?!\\W)|\ua6dc?|\\cH+?)){3,}/ym; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-157142351*/count=346; tryItOut("this.v2 = t0.length;");
/*fuzzSeed-157142351*/count=347; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.exp((( ! x) * ( ! (Math.pow(y, y) >>> 0)))); }); testMathyFunction(mathy0, [Math.PI, -Number.MIN_SAFE_INTEGER, 42, -1/0, 0x07fffffff, 0.000000000000001, 1.7976931348623157e308, -Number.MIN_VALUE, -0x07fffffff, 1, 0x080000000, -0, Number.MAX_SAFE_INTEGER, 0/0, 1/0, -(2**53+2), -Number.MAX_VALUE, 0x100000001, 2**53+2, Number.MIN_VALUE, -0x0ffffffff, -(2**53), -(2**53-2), 2**53-2, -0x080000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, -0x100000000, -0x080000000, 0x080000001, 0, -0x100000001, 0x100000000, 2**53, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=348; tryItOut("\"use strict\"; testMathyFunction(mathy3, [1/0, -1/0, 1, 0x0ffffffff, 0x080000001, Math.PI, -(2**53), -0x080000001, 2**53-2, -Number.MIN_VALUE, 2**53, 0x07fffffff, Number.MIN_VALUE, -0x100000001, 2**53+2, 0x100000001, -0, -Number.MAX_VALUE, Number.MAX_VALUE, 0/0, -(2**53-2), -0x100000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000000, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0, 42, 0x100000000, 0x080000000, -0x0ffffffff]); ");
/*fuzzSeed-157142351*/count=349; tryItOut("m2.delete(o1);");
/*fuzzSeed-157142351*/count=350; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.log10(Math.fround((Math.log10((((Math.atan2(y, Math.fround(42)) >>> 0) < (Math.log10(Math.imul(x, Math.fround(Math.pow((y >>> 0), Math.fround(x))))) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [0x0ffffffff, 42, Math.PI, -0x07fffffff, 0/0, 0, 1, 0x080000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x100000000, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 2**53-2, 2**53, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, 1/0, -1/0, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, -Number.MIN_VALUE, -0x100000001, -(2**53), -0x080000001, 2**53+2]); ");
/*fuzzSeed-157142351*/count=351; tryItOut("with(allocationMarker()){h0 = {};m2.delete(g0.v2); }");
/*fuzzSeed-157142351*/count=352; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return mathy0((mathy0((((Math.max((( - y) | 0), (Math.min(x, ( + Math.abs(y))) | 0)) | 0) > Math.fround(( + mathy0(( + ( ~ ( + Math.min(Math.fround(y), Math.fround(y))))), ( + Math.PI))))) >>> 0), ( + ((( ~ (( - (y >>> 0)) >>> 0)) | 0) | 0))) >>> 0), ((Math.min((( + mathy0(x, ( + (Math.tanh(Math.fround(y)) | 0)))) | 0), (x | 0)) | 0) , (Math.asin((Math.pow((y | 0), (0 | 0)) | 0)) < (( - x) >>> 0)))); }); testMathyFunction(mathy1, [-0x07fffffff, 42, 0x100000000, -0x0ffffffff, -0x100000001, 0x080000000, Number.MIN_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x07fffffff, 0x0ffffffff, 2**53, -0x100000000, -(2**53-2), 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, Number.MAX_SAFE_INTEGER, 1/0, -(2**53+2), -0, -Number.MAX_VALUE, 2**53+2, -(2**53), Number.MAX_VALUE, 0x100000001, 2**53-2, -1/0, -0x080000001, 0/0, Math.PI, 0.000000000000001, Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-157142351*/count=353; tryItOut("\"use strict\"; a2 + '';");
/*fuzzSeed-157142351*/count=354; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( ~ Math.fround(( ~ Math.fround(( + Math.sinh(( + x))))))); }); testMathyFunction(mathy5, [-(2**53+2), -0, 0x100000000, -(2**53), -1/0, -Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 1/0, 0x100000001, 0.000000000000001, 0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 2**53+2, 0x080000001, -0x100000000, -0x080000001, -0x080000000, 1, Math.PI, 2**53-2, -Number.MIN_VALUE, -0x07fffffff, Number.MIN_VALUE, 0/0]); ");
/*fuzzSeed-157142351*/count=355; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( - Math.fround(Math.sin(Math.fround((x ** ( + Math.min(Math.sinh(y), x))))))); }); testMathyFunction(mathy1, [-(2**53-2), -0x100000001, 0.000000000000001, 0x07fffffff, 0x100000001, -(2**53+2), -Number.MAX_VALUE, 0x0ffffffff, 1, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), -Number.MIN_VALUE, 0, 0x080000000, 42, 2**53+2, Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53-2, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53, 0x080000001, -0, Math.PI, 1.7976931348623157e308, 0x100000000, -0x080000000, -0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-157142351*/count=356; tryItOut("v1 = g1.runOffThreadScript();");
/*fuzzSeed-157142351*/count=357; tryItOut("mathy2 = (function(x, y) { return Math.min(Math.atan2(((( ~ y) === (( + (Math.fround((Math.fround((1.7976931348623157e308 || x)) , (1.7976931348623157e308 >>> 0))) != ( + ( ! ((Math.pow((y >>> 0), ( + -0x0ffffffff)) >>> 0) >>> 0))))) ** Math.fround(mathy1(( + -0x080000000), Number.MIN_VALUE)))) >>> 0), (Math.tan(Math.hypot(x, (mathy0(x, x) | 0))) | 0)), Math.tan(((Math.asinh((Math.fround(((y || x) ? y : Math.fround(Math.max(Math.fround(y), Math.fround(( - y)))))) | 0)) | 0) ? ((( + (Math.clz32((( + ( ~ -0x100000000)) | 0)) | 0)) ? mathy1(y, x) : ( + Math.log(( - x)))) >>> 0) : Math.trunc(Math.fround(( - Math.fround(Number.MIN_VALUE))))))); }); ");
/*fuzzSeed-157142351*/count=358; tryItOut("\"use asm\"; /*oLoop*/for (txucyf = 0; txucyf < 49 && (((Math.log((( ! ( + (( + ( - ( + x))) <= Math.min(Math.fround((Math.fround((Math.sinh(x) < x)) | Math.fround(x))), (( + (((x === (Math.hypot(x, x) | 0)) >>> 0) | 0)) | 0))))) | 0)) | 0))); ++txucyf) { for(d = 627806772 in function(id) { return id }) v1 = evaluate(\"var i2 = new Iterator(h1);\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: false })); } ");
/*fuzzSeed-157142351*/count=359; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[null, Infinity, new Number(1), NaN, null, Infinity, null, NaN, NaN, Infinity, new Number(1), NaN, NaN, null, NaN, NaN, Infinity, NaN, Infinity, null, Infinity, NaN, null, null, NaN, NaN, NaN, new Number(1), null, NaN]) { g0[\"constructor\"] = this.i2; }");
/*fuzzSeed-157142351*/count=360; tryItOut("\"use strict\"; /*oLoop*/for (let howngb = 0; howngb < 51; ++howngb) { e1 = new Set; } ");
/*fuzzSeed-157142351*/count=361; tryItOut("testMathyFunction(mathy4, [1.7976931348623157e308, 0/0, -0x07fffffff, -(2**53-2), 0x100000000, -0x080000001, -0x100000000, -Number.MAX_VALUE, 0, 1, -0, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, 0x07fffffff, 0x080000000, -0x080000000, -1/0, -(2**53+2), 42, 2**53, 0x080000001, -(2**53), 2**53-2, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0x100000001, -Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=362; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + (( + Math.pow(Math.max(( + mathy1(( + (Math.sin(0x080000001) >>> 0)), y)), Math.fround(Math.log10(( - (y + (y >>> 0)))))), Math.min(x, Math.fround(( ~ -Number.MAX_SAFE_INTEGER))))) + ( + ( - Math.pow(y, Math.fround(((y | 0) && Math.fround(x)))))))); }); testMathyFunction(mathy3, /*MARR*/[new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q')]); ");
/*fuzzSeed-157142351*/count=363; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( - ( + ((Math.fround((( ! Math.fround(Math.asinh(0x080000001))) | 0)) && Math.atan2(Math.max(Math.fround((-0x0ffffffff === x)), Math.fround(mathy0(x, Math.fround(-Number.MAX_VALUE)))), x)) & (( - (Math.fround(mathy3(2**53, (( ! y) | 0))) | 0)) >>> 0))))); }); ");
/*fuzzSeed-157142351*/count=364; tryItOut("testMathyFunction(mathy1, [0x100000001, 0x0ffffffff, 0/0, 0.000000000000001, 2**53-2, -0x07fffffff, -0x100000000, -0, -0x080000000, Number.MIN_VALUE, 1.7976931348623157e308, 42, -Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, 1/0, -0x100000001, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53+2), -(2**53-2), 0x080000001, 2**53, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 0x100000000, Math.PI, 2**53+2, 0, -Number.MAX_VALUE, Number.MAX_VALUE, 0x07fffffff, 0x080000000]); ");
/*fuzzSeed-157142351*/count=365; tryItOut("i2 = e1.keys;");
/*fuzzSeed-157142351*/count=366; tryItOut("for (var p in h2) { try { v0 = g0.runOffThreadScript(); } catch(e0) { } e0.has(h2); }\nv1 = Object.prototype.isPrototypeOf.call(m1, s0);\n");
/*fuzzSeed-157142351*/count=367; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.max((Math.min((Math.exp(( + Math.atan2(( + (mathy0(mathy2(y, x), x) | 0)), ( + 0.000000000000001)))) >>> 0), (( + Math.exp((Math.fround(Math.max(Math.fround(x), Math.sinh(mathy0((Math.imul((y >>> 0), (y >>> 0)) >>> 0), -(2**53))))) | 0))) >>> 0)) >>> 0), Math.imul(( + ( ! ( + (( ! (y | 0)) | 0)))), (mathy2((Math.atan((x | 0)) | 0), (Math.log10((mathy2(( + y), y) << x)) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, Number.MAX_VALUE, -0x0ffffffff, 0/0, 0x080000000, 0x080000001, 2**53, 0, -(2**53+2), 42, -0x100000000, -Number.MIN_VALUE, -(2**53), -0x07fffffff, -0x100000001, 1, 2**53-2, 1/0, 0x07fffffff, 0x100000001, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, Math.PI, -0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -(2**53-2), -0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=368; tryItOut("for(z in /*UUV1*/(w.setUTCMilliseconds = runOffThreadScript)) /*bLoop*/for (var esfpbq = 0, x; esfpbq < 16; ++esfpbq) { if (esfpbq % 47 == 22) { print(i0)\n } else { this.s1.valueOf = (function mcc_() { var gbzlsi = 0; return function() { ++gbzlsi; f2(/*ICCD*/gbzlsi % 9 != 3);};})(); }  } ");
/*fuzzSeed-157142351*/count=369; tryItOut("s0 = new String(v0);");
/*fuzzSeed-157142351*/count=370; tryItOut("print(uneval(m0));");
/*fuzzSeed-157142351*/count=371; tryItOut("arguments;\nf0 = Proxy.createFunction(this.h1, f1, f2);\n");
/*fuzzSeed-157142351*/count=372; tryItOut("testMathyFunction(mathy4, [2**53, 0.000000000000001, -(2**53), Math.PI, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, 0x07fffffff, -0x100000001, -0, 0x080000001, 1.7976931348623157e308, -1/0, 1, 2**53-2, -(2**53-2), Number.MIN_VALUE, 0, -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, -0x07fffffff, 1/0, -(2**53+2), 0x100000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 0x100000001, 0x080000000]); ");
/*fuzzSeed-157142351*/count=373; tryItOut("\"use strict\"; let (x, whecgy, x, c, qrlcli, eval) { v0 = g1.eval(\"function f1(e1) null\"); }");
/*fuzzSeed-157142351*/count=374; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.tanh(Math.imul(Math.atan((Math.hypot((y >>> 0), Math.log10(2**53-2)) >>> 0)), mathy2((y !== ( + (( + x) / (Math.log10(Math.fround(Math.hypot((y >>> 0), -Number.MAX_SAFE_INTEGER))) >>> 0)))), mathy2(( + x), x))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0, 1.7976931348623157e308, 0x100000000, 1/0, -0, -(2**53), Number.MAX_SAFE_INTEGER, -0x07fffffff, 1, -Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, 0/0, Number.MAX_VALUE, 42, -1/0, 0x080000000, -0x0ffffffff, -(2**53+2), -Number.MAX_VALUE, 2**53+2, -0x100000001, 0x080000001, -0x080000001, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_VALUE, -0x100000000, 0x100000001, 2**53, -0x080000000, 0x0ffffffff, 2**53-2, 0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=375; tryItOut("print(t2);");
/*fuzzSeed-157142351*/count=376; tryItOut("M:switch(x) { case Object.defineProperty(z, /*wrap3*/(function(){ var sfxrcm = -10; (/[^]{4}|\\1/y)(); })().yoyo(URIError(x, null)), ({get: x, set: (uneval((new RegExp(\"(?!.\\\\B{4,}|[^]|.|\\\\uCB5d{4,4}+?(?!.{3,})|[^\\\\0-\\\\x8f\\u00ba\\\\r-\\\\cP\\\\D]|[^][^]{1,1}\\\\3)\", \"gi\").toUpperCase( /x/g )))), configurable: (x % 2 == 1), enumerable: (x % 34 == 23)})): /* no regression tests found */break; /*ODP-3*/Object.defineProperty(m2, new (function  x (c) { return String.prototype.blink.prototype } ).apply(), { configurable: (x % 24 != 18), enumerable: (x % 13 == 8), writable: (x % 5 != 3), value: p1 });case (({25: /*RXUE*/new RegExp(\"(?:(\\\\3*?(?=.|^){3}|[^]|.{2}|\\\\1(?!$)))\", \"g\").exec(\"\\n\\n\\n\") })):  }");
/*fuzzSeed-157142351*/count=377; tryItOut("if(false) { if ([] = x) {print(g0); }} else {print(offThreadCompileScript.prototype); }");
/*fuzzSeed-157142351*/count=378; tryItOut("testMathyFunction(mathy1, [Number.MAX_VALUE, 1, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), -0x080000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001, -0x0ffffffff, -(2**53), 0.000000000000001, 1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0, -0x100000000, 2**53, 0x07fffffff, 0x100000001, 2**53-2, -0, -1/0, -Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, -0x100000001, Math.PI, 0x100000000, -0x080000000, -Number.MAX_VALUE, 0x080000000, 42, -Number.MIN_VALUE]); ");
/*fuzzSeed-157142351*/count=379; tryItOut("testMathyFunction(mathy3, [0, 0x0ffffffff, 0/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), 1/0, -0x100000000, 2**53, 0.000000000000001, -0, 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000000, Number.MAX_VALUE, 2**53+2, -0x080000000, -0x0ffffffff, 1, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -(2**53-2), -Number.MAX_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 2**53-2, 42, -0x080000001, 0x07fffffff, -0x07fffffff, 0x080000001]); ");
/*fuzzSeed-157142351*/count=380; tryItOut("b0 + s1\n");
/*fuzzSeed-157142351*/count=381; tryItOut("testMathyFunction(mathy1, [1, 1/0, -0x0ffffffff, 1.7976931348623157e308, 0, -0x080000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), Number.MIN_VALUE, -1/0, 0x100000001, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53, 0x100000000, Number.MAX_VALUE, Math.PI, 0/0, 2**53+2, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), -0x100000001, -0x07fffffff, -Number.MIN_VALUE, 2**53-2, -0x080000001, -0, 0.000000000000001, 0x07fffffff, 0x080000001, 42]); ");
/*fuzzSeed-157142351*/count=382; tryItOut("\"use strict\"; ");
/*fuzzSeed-157142351*/count=383; tryItOut("h1.getPropertyDescriptor = (function() { for (var j=0;j<68;++j) { f2(j%2==1); } });");
/*fuzzSeed-157142351*/count=384; tryItOut("mathy1 = (function(x, y) { return Math.atan(( + (((Math.round(Math.expm1(x)) | 0) | ( + (( + -(2**53-2)) % Math.fround(Math.cbrt(Math.fround(Math.log1p(Math.ceil(y)))))))) >>> 0))); }); testMathyFunction(mathy1, [-0x07fffffff, 0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -(2**53-2), 2**53+2, -0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 0x100000000, 1, 0x100000001, 1.7976931348623157e308, -(2**53), -1/0, -0x080000001, 0.000000000000001, 0x080000001, -Number.MIN_VALUE, 42, 1/0, 2**53, -Number.MAX_SAFE_INTEGER, 0/0, Math.PI, -0x080000000, Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -0x100000000, 2**53-2, 0]); ");
/*fuzzSeed-157142351*/count=385; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      return ((((-4.722366482869645e+21) > (Infinity))+(i1)+(i0)))|0;\n    }\n    return (((i1)+(i1)))|0;\n  }\n  return f; })(this, {ff: (String.prototype.charCodeAt).bind}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53+2), Number.MIN_VALUE, -1/0, 0/0, Number.MAX_VALUE, 2**53-2, -0x100000000, 1/0, 1, -Number.MIN_VALUE, 0, -0, 0x100000000, 0x100000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 0x080000000, 0x080000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, -0x080000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Math.PI, -0x080000000, 2**53, -(2**53), -(2**53-2), 42, -0x100000001]); ");
/*fuzzSeed-157142351*/count=386; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( ~ (Math.atan(Math.min(Math.sign(Math.fround(2**53)), ( + Math.log1p((0x080000000 >>> 0))))) | 0))); }); ");
/*fuzzSeed-157142351*/count=387; tryItOut("\"use strict\"; let (x = \"\\u52D8\", NaN, window, iciqop, x, rfqnfo, xsmrkz, x) { m0.set(h0, t2); }this.zzz.zzz;with({}) { this.zzz.zzz; } ");
/*fuzzSeed-157142351*/count=388; tryItOut("\"use strict\"; v2 = g2.eval(\"intern([] = [])\");");
/*fuzzSeed-157142351*/count=389; tryItOut("mathy0 = (function(x, y) { return (( - ((Math.fround(( ! ((-(2**53+2) << x) >>> 0))) | 0) >>> (Math.hypot(( - y), (x == -0x0ffffffff)) >>> 0))) >>> 0); }); ");
/*fuzzSeed-157142351*/count=390; tryItOut("for (var p in i0) { try { for (var v of f1) { p2 + ''; } } catch(e0) { } try { print(f0); } catch(e1) { } Object.defineProperty(this, \"r1\", { configurable: false, enumerable: (x % 2 == 1),  get: function() { t2.set(t1, 8); return new RegExp(\"\\\\B{4,}\", \"y\"); } }); }");
/*fuzzSeed-157142351*/count=391; tryItOut("p0 = g0.objectEmulatingUndefined();");
/*fuzzSeed-157142351*/count=392; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?!^+)*\", \"im\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=393; tryItOut("for(let x of /*MARR*/[-Number.MIN_VALUE,  '' , (4277),  '' ,  '' , ({}), -Number.MIN_VALUE,  '' , (4277), (4277), (4277),  '' , ({}),  '' , x, -Number.MIN_VALUE, ({}), (4277), (4277), (4277), ({}), x, -Number.MIN_VALUE, ({}), ({}), (4277), ({}), (4277), -Number.MIN_VALUE, (4277), x, -Number.MIN_VALUE, -Number.MIN_VALUE,  '' , x, ({}), ({})]) yield eval(\"x, x, fxipmq, this.eval, vtoant;(null);\", (x ? \"\\u5C79\" : /*UUV2*/(b.copyWithin = b.clear)));");
/*fuzzSeed-157142351*/count=394; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -68719476737.0;\n    var i3 = 0;\n    (Float32ArrayView[(0x11848*(0xf931591d)) >> 2]) = ((NaN));\n    {\n      i3 = (/*FFI*/ff()|0);\n    }\n    {\n      i0 = (((-(0xf8667991)) | ((/*FFI*/ff(((d2)), ((0x49670566)), ((((+(-1.0/0.0))))), ((d2)), ((Symbol(\"\\uB6A2\", new RegExp(\"(?=(?:[\\\\0][^]))*?[^][^]*?|[^]|\\\\D\\\\B|(.\\\\u1B9a)(?:\\\\b)*?{1,}\", \"im\")))), ((((-0x8000000)) ^ ((0x6095d1d4)))), ((2097151.0)), ((-72057594037927940.0)))|0))));\n    }\n    (Int8ArrayView[4096]) = ((i3));\n    return +((Float64ArrayView[((new RegExp(\"(?=(?=(?:[^]?)))\", \"ym\"))) >> 3]));\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); ");
/*fuzzSeed-157142351*/count=395; tryItOut("\"use strict\"; testMathyFunction(mathy3, [Number.MIN_VALUE, 0/0, 0x080000001, -0x0ffffffff, -0x080000001, 1.7976931348623157e308, -(2**53-2), -0, -1/0, -(2**53), Math.PI, -0x07fffffff, 0x080000000, 0, -0x100000001, 0x100000001, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, 1/0, -(2**53+2), 1, 0.000000000000001, -0x100000000, 42, 2**53+2, Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x080000000, 0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=396; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.abs(((( + Math.pow(Math.cosh((((Math.sign(x) >>> 0) , (1/0 >>> 0)) >>> 0)), (-0 >>> 0))) ^ ( + Math.atan2(( - ( + (( + Math.sqrt(y)) + x))), Math.log((( + (y | 0)) | 0))))) | 0)); }); testMathyFunction(mathy0, [({valueOf:function(){return '0';}}), '\\0', -0, (function(){return 0;}), ({toString:function(){return '0';}}), false, objectEmulatingUndefined(), undefined, true, NaN, '0', (new Boolean(true)), 0.1, 1, [0], null, (new Boolean(false)), /0/, 0, (new String('')), [], (new Number(0)), (new Number(-0)), ({valueOf:function(){return 0;}}), '/0/', '']); ");
/*fuzzSeed-157142351*/count=397; tryItOut("yvvbcp, x, x = x, z, x = x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { throw 3; }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: mathy3, set: undefined, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: \"\\u897C\", keys: function() { return Object.keys(x); }, }; })(c), (20.revocable).apply), d, window, x = (4277).watch(\"toString\", Date.prototype.getDay), asfllw;g0.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-157142351*/count=398; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[(-0), (-1/0), Infinity, (-1/0), new Number(1.5), (-1/0), true, (-1/0), true, (-1/0), (-1/0), new Number(1.5), (-1/0), new Number(1.5), true, true, (-1/0), (-1/0), new Number(1.5), Infinity, (-0), (-0), true, (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-0), (-1/0), Infinity, true, Infinity, (-1/0), (-0), (-0), (-1/0), (-0), (-0), (-0), Infinity, Infinity, (-1/0), true, (-0), Infinity, (-1/0), true, Infinity, new Number(1.5), true, (-0), Infinity, true, (-1/0), Infinity, new Number(1.5), new Number(1.5), (-1/0), (-0), new Number(1.5), (-1/0), (-1/0), (-1/0), (-0), true, true, new Number(1.5), (-0), Infinity, (-0), (-0), new Number(1.5), true, (-0), true, true, (-1/0), Infinity, (-1/0), true, true, (-0), Infinity, Infinity, Infinity, Infinity, true, true]) { w; }e0 + f1;{ void 0; deterministicgc(false); }");
/*fuzzSeed-157142351*/count=399; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4((Math.pow(( + Math.atan2(Math.cos(Math.fround(( - Math.fround(y)))), mathy3(x, ( + mathy4(y, (( + Math.tanh(( + (x ? y : 0x07fffffff)))) | 0)))))), ( + ( ! y))) | 0), Math.cosh((Math.pow(x, Math.imul(mathy3(x, mathy1(y, ( + Math.pow(x, (1/0 | 0))))), Math.fround(Math.hypot(( + ( + (( + Math.PI) ? x : ( + 0x100000001)))), x)))) | 0))); }); testMathyFunction(mathy5, [2**53-2, 0/0, -0x0ffffffff, 1.7976931348623157e308, -0x100000000, -(2**53+2), 0x080000000, 0x100000001, Number.MIN_VALUE, -0, -1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, 42, -(2**53), -Number.MAX_VALUE, 0x100000000, -0x07fffffff, -0x080000000, 0.000000000000001, 0x07fffffff, Math.PI, 2**53+2, 2**53, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x0ffffffff, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, -0x100000001, 1, -0x080000001, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=400; tryItOut("Array.prototype.sort.call(a2, (function() { for (var j=0;j<50;++j) { f0(j%5==0); } }));");
/*fuzzSeed-157142351*/count=401; tryItOut("(typeof (Math.log10(-16)));");
/*fuzzSeed-157142351*/count=402; tryItOut("\"use strict\"; f1 = function(q) { return q; };");
/*fuzzSeed-157142351*/count=403; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ~ ( + (( + (( + ((Math.log1p(Math.fround(x)) | 0) | 0)) | 0)) - ( + (( + Math.fround(Math.acos(x))) >>> 0))))); }); ");
/*fuzzSeed-157142351*/count=404; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-157142351*/count=405; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 67108864.0;\n    return +(((((d1)) / ((((d1)) * ((d1))))) + (((+(0.0/0.0))) / ((d1)))));\n  }\n  return f; })(this, {ff: Set.prototype.has}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[new Boolean(false), 2, 2, new Number(1), new Number(1)]); ");
/*fuzzSeed-157142351*/count=406; tryItOut("a2.pop();");
/*fuzzSeed-157142351*/count=407; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; setIonCheckGraphCoherency(false); } void 0; }");
/*fuzzSeed-157142351*/count=408; tryItOut("\"use strict\"; testMathyFunction(mathy4, [2**53, Number.MIN_SAFE_INTEGER, -(2**53+2), 0/0, -(2**53), 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, 0x0ffffffff, -0x100000000, 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, 0, -(2**53-2), -1/0, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 1/0, 1.7976931348623157e308, 0x080000001, -Number.MIN_VALUE, -0x0ffffffff, -0x07fffffff, -0x080000000, Number.MAX_VALUE, 1, 42, 0x100000000, 0.000000000000001, 0x080000000, -0x100000001]); ");
/*fuzzSeed-157142351*/count=409; tryItOut("\"use strict\"; /*RXUB*/var r = x; var s = \"\"; print(s.replace(r, mathy0)); ");
/*fuzzSeed-157142351*/count=410; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-157142351*/count=411; tryItOut("o2 + '';");
/*fuzzSeed-157142351*/count=412; tryItOut("for (var v of v1) { try { /*RXUB*/var r = r1; var s = s2; print(s.replace(r, []));  } catch(e0) { } try { Array.prototype.forEach.apply(a1, [x]); } catch(e1) { } g2.o1.f0 = a0[6]; }");
/*fuzzSeed-157142351*/count=413; tryItOut("/*tLoop*/for (let w of /*MARR*/[ /x/g ,  /x/ , new Number(1.5), new Number(1.5),  /x/g , new Boolean(true), new Number(1.5), new Number(1.5)]) { v1 = a2.every(f0); }");
/*fuzzSeed-157142351*/count=414; tryItOut("for (var p in e2) { try { v0 = Object.prototype.isPrototypeOf.call(o2.a2, i2); } catch(e0) { } try { b2 = new SharedArrayBuffer(22); } catch(e1) { } try { v2 = new Number(-Infinity); } catch(e2) { } g1.a0[19] = x; }");
/*fuzzSeed-157142351*/count=415; tryItOut("\"use strict\"; a1[v1] = (x = undefined);switch((Math.max(z, 5)).__defineSetter__(\"x\", function(y) { \"use strict\"; return d }) ? this : (function(y) { return undefined }( /x/g ,  '' ))) { default: break; g0.v2 + this.t2;break; /* no regression tests found */let(x, Promise.race = (0x100000000), mlwykh, c, x = eval(\"h0 = m1.get(s0);\")) { let(y) { throw StopIteration;}}case (let (w =  '' ) w >> (4277)): this.m2.toSource = (function() { try { e0.has(g1.e2); } catch(e0) { } v1 = g1.eval(\"function f0(b0) \\\"use asm\\\";   var Float32ArrayView = new stdlib.Float32Array(heap);\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(i0, i1)\\n  {\\n    i0 = i0|0;\\n    i1 = i1|0;\\n    var i2 = 0;\\n    var i3 = 0;\\n    var i4 = 0;\\n    var d5 = 9.671406556917033e+24;\\n    var d6 = -7.555786372591432e+22;\\n    var d7 = 1152921504606847000.0;\\n    var i8 = 0;\\n    {\\n      {\\n        i1 = (i8);\\n      }\\n    }\\n    {\\n      {\\n        switch ((((i2)) & ((i0)*-0xfcaf5))) {\\n          case -2:\\n            {\\n              i4 = (0xd0baca0a);\\n            }\\n            break;\\n        }\\n      }\\n    }\\n    {\\n      {\\n        (Float32ArrayView[(({x:  /x/g }).yoyo(x)) >> 2]) = ((9.0));\\n      }\\n    }\\n    i3 = (0xfbc536f2);\\n    (Float32ArrayView[2]) = ((((-129.0) > (144115188075855870.0)) ? (+(((0xffeb6024)) >> ((0xfe753e05)-(function(y) { v1 = new Number(this.i0); }())))) : (-17592186044415.0)));\\n    i0 = (i4);\\n    return +((Float64ArrayView[0]));\\n    return +((2.3611832414348226e+21));\\n    i1 = (i4);\\n    switch ((((i1)+((0xd916fc5f))-(i2))|0)) {\\n      default:\\n        {\\n          i1 = (1);\\n        }\\n    }\\n    i0 = (i1);\\n    switch ((((i1)) & ((0x91e141bd)-(0x4aaef9a1)))) {\\n      default:\\n        d6 = (1.0);\\n    }\\n    i8 = ((i3) ? (i8) : (i8));\\n    (Float32ArrayView[2]) = ((-67108865.0));\\n    i3 = (i0);\\n    return +(((18446744073709552000.0) + (-18014398509481984.0)));\\n  }\\n  return f;\"); return i1; });break; /*oLoop*/for (let wgzxfr = 0; wgzxfr < 36; ++wgzxfr) { s1 = s2.charAt(v2); } (/*UUV1*/(e.toUpperCase = () =>  { print(x); } ));break; case 2: break; (eval(\"\\\"use strict\\\"; for (var v of m0) { try { this.g1.a0.reverse(o0,  \\\"\\\" , m0); } catch(e0) { } v1 = evalcx(\\\"/* no regression tests found */\\\", g1); }\"));break;  }");
/*fuzzSeed-157142351*/count=416; tryItOut("t2.set(t1, v2);");
/*fuzzSeed-157142351*/count=417; tryItOut("/*infloop*/while((makeFinalizeObserver('nursery')))print((Math.abs)());");
/*fuzzSeed-157142351*/count=418; tryItOut("for (var p in e1) { try { s2 += s0; } catch(e0) { } try { neuter(b1, \"change-data\"); } catch(e1) { } try { g0.offThreadCompileScript(\"function f2(f1)  { yield ((new (f1)(/*MARR*/[Infinity].some(arguments.callee.caller)))(\\nx, (Object.defineProperty(f1, 12, ({configurable: false, enumerable: false}))))) } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 81 == 67), noScriptRval: (x % 3 != 2), sourceIsLazy: false, catchTermination: (x % 5 == 1) })); } catch(e2) { } g1.i1.send(b1); }");
/*fuzzSeed-157142351*/count=419; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.hypot(Math.hypot(0x100000000, ( ! Math.fround(Math.log10((Math.abs(y) | 0))))), ((( ~ ( - Math.fround((Math.tan(y) || y)))) | 0) ? (Math.fround(Math.min((y >>> 0), Math.fround((Math.fround((((x >>> 0) ? (x >>> 0) : x) >>> 0)) & Math.fround((Math.fround(Math.max(x, x)) ? x : -(2**53+2))))))) | 0) : (Math.asinh(( + ( - Math.imul(((Math.hypot((42 >>> 0), ( + -0x080000001)) | 0) >>> 0), ( + y))))) | 0))) ? ((( ! (Math.fround(((Math.fround(x) ? Math.fround(y) : Math.fround(x)) <= (Math.pow(2**53, 2**53+2) ? Math.min(Math.fround((Math.fround(-1/0) ** y)), Math.fround(y)) : (( ~ Math.imul(Math.sqrt(-Number.MAX_SAFE_INTEGER), 0)) >>> 0)))) | 0)) | 0) >>> 0) : Math.fround(Math.pow(Math.fround(( ~ (( ~ (Math.fround(mathy1(x, -0x080000000)) | 0)) >>> 0))), Math.fround((x ? Math.fround(( + mathy3((Math.log1p(x) | 0), ( + Math.atan(y))))) : x))))); }); testMathyFunction(mathy5, /*MARR*/[(4277), 0x5a827999, (4277), 0x5a827999, 0x5a827999, (4277), (4277), (0/0), (4277), (4277), (4277), (0/0), (4277), (4277), (0/0), (4277), (0/0), 0x5a827999, (0/0), 0x5a827999, (4277), 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, (0/0), (4277), 0x5a827999, (0/0), (0/0), (0/0), (0/0), 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, (4277), 0x5a827999, 0x5a827999, (0/0), 0x5a827999, (4277), 0x5a827999, (4277), 0x5a827999, (0/0), (4277), (4277), 0x5a827999, 0x5a827999, 0x5a827999, (0/0), (4277), (4277), (4277), (0/0), 0x5a827999, (4277), 0x5a827999, (0/0), (0/0), 0x5a827999, (0/0), (4277), (0/0), 0x5a827999, (4277), 0x5a827999, (4277), (4277), (4277), (0/0), 0x5a827999, (0/0), 0x5a827999, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), 0x5a827999, (4277), (0/0)]); ");
/*fuzzSeed-157142351*/count=420; tryItOut("\"use strict\"; m2 = a2[17];");
/*fuzzSeed-157142351*/count=421; tryItOut("/*RXUB*/var r = /(($+)|((?:\\b)${2,3}^*?{1,3}\\b|[^]**))/yim; var s = \"\\n\\n\\n\\n\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=422; tryItOut("\"use strict\"; Object.defineProperty(o0, \"a2\", { configurable: true, enumerable: x,  get: function() {  return new Array; } });");
/*fuzzSeed-157142351*/count=423; tryItOut("\"use strict\"; h0.fix = (function(j) { if (j) { try { t1.set(t2, o0.g0.v1); } catch(e0) { } t1 = s2; } else { try { e2.has(s0); } catch(e0) { } try { b1 = new SharedArrayBuffer(76); } catch(e1) { } try { delete g2.f0[\"1\"]; } catch(e2) { } m2.get(this.p2); } });");
/*fuzzSeed-157142351*/count=424; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return +((Float32ArrayView[1]));\n  }\n  return f; })(this, {ff: (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 0/0, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0x100000000, Math.PI, -0x07fffffff, 0, 2**53+2, 0.000000000000001, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, 0x080000001, -0x100000000, 2**53, -Number.MIN_VALUE, -0x080000001, 0x0ffffffff, 42, 0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 0x080000000, -(2**53-2), Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=425; tryItOut("t2.set(a2, ((Math.clz32(-25)\u000c)([arguments] = false([[1]]))));");
/*fuzzSeed-157142351*/count=426; tryItOut("\"use strict\"; v1 = (g1 instanceof e2);");
/*fuzzSeed-157142351*/count=427; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      i2 = (i1);\n    }\n    i1 = (i1);\n    {\n      d0 = ((+(0.0/0.0)) + (d0));\n    }\n    i1 = (0xfec2b209);\n    d0 = (d0);\n    {\n      i1 = ((0xe2f663af) == (0x224e452a));\n    }\n    return (((i2)-(i2)))|0;\n  }\n  return f; })(this, {ff: Array.prototype.copyWithin}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-157142351*/count=428; tryItOut("Object.defineProperty(this, \"v1\", { configurable: (x % 30 == 3), enumerable: true,  get: function() {  return f2[\"14\"]; } });");
/*fuzzSeed-157142351*/count=429; tryItOut("mathy4 = (function(x, y) { return (Math.max((((((( ~ (Math.max(x, ( + Math.fround(( + Math.min(Math.fround(( ! y)), Math.fround(y)))))) | 0)) | 0) >>> 0) - (((( - (Math.pow(((Math.atan2((y >>> 0), y) | 0) >>> 0), -Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0) ? (Math.min(Math.fround(Math.atan2(y, -0x080000000)), Math.fround((((Math.tan(y) >>> 0) ? (-(2**53-2) >>> 0) : ((y , y) >>> 0)) >>> 0))) >>> 0) : (y >>> 0)) >>> 0)) >>> 0) | 0), ((( ~ (Math.clz32((mathy2(Math.asinh(((y >>> 0) - (x | 0))), (x >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy4, [-0x100000001, 0, -1/0, Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, 0.000000000000001, 1, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), 1/0, 42, 0x080000001, -Number.MAX_VALUE, -0, 1.7976931348623157e308, -0x080000000, 0/0, -(2**53+2), 2**53-2, 2**53+2, -0x0ffffffff, Math.PI, 0x0ffffffff, -0x100000000, 2**53, Number.MAX_VALUE, 0x100000001, -0x080000001, -Number.MIN_VALUE, -0x07fffffff, 0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-157142351*/count=430; tryItOut("for (var p in p2) { try { selectforgc(this.o2); } catch(e0) { } try { m0.set(e0, p0); } catch(e1) { } try { i0.next(); } catch(e2) { } for (var p in s2) { try { (void schedulegc(g1)); } catch(e0) { } a2 = new Array; } }");
/*fuzzSeed-157142351*/count=431; tryItOut("/*bLoop*/for (let oxlngd = 0; oxlngd < 122; ++oxlngd) { if (oxlngd % 12 == 11) { e1.delete(a2); } else { Object.defineProperty(this, \"v0\", { configurable: false, enumerable: true,  get: function() {  return new Number(v1); } }); }  } ");
/*fuzzSeed-157142351*/count=432; tryItOut("f0 = Proxy.createFunction(h2, f0, f2);");
/*fuzzSeed-157142351*/count=433; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( + Math.atan((Math.cbrt((Math.asin((( + (( + Math.clz32(x)) >= y)) | 0)) | 0)) | 0))); }); ");
/*fuzzSeed-157142351*/count=434; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( ! (( - Math.tanh(Math.sqrt(x))) | 0)); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, -0x100000001, -0, 42, -Number.MIN_VALUE, -0x080000001, -(2**53), 0x100000001, -Number.MIN_SAFE_INTEGER, 2**53, Math.PI, 1, -0x080000000, 0x0ffffffff, -0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, 1/0, 0x100000000, 2**53+2, -0x100000000, -(2**53+2), 0x080000000, 0, 2**53-2, 0x080000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-157142351*/count=435; tryItOut("testMathyFunction(mathy5, [0x100000001, -(2**53+2), 2**53, -0x100000001, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, Math.PI, 0x0ffffffff, 0x080000001, 0x100000000, 0/0, -Number.MIN_VALUE, -1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, -0, -0x080000001, 0x080000000, 42, -(2**53), 2**53+2, Number.MIN_VALUE, -0x07fffffff, -0x080000000, 1.7976931348623157e308, 1/0, -0x100000000, 0.000000000000001, -Number.MAX_VALUE, 0, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff]); ");
/*fuzzSeed-157142351*/count=436; tryItOut("selectforgc(o1);");
/*fuzzSeed-157142351*/count=437; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return ( + Math.max((( + (Math.atanh(Math.fround((((Math.log2((y | 0)) >>> 0) , y) + ( ~ x)))) >>> 0)) | 0), ( + Math.fround((( + ( - Math.fround(Math.cbrt(Math.fround(-Number.MAX_VALUE))))) ? ( + ( - ( + y))) : Math.fround(Math.ceil((( + (( + (( + y) ** ( + 0x0ffffffff))) ? y : x)) >>> 0)))))))); }); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -0x100000000, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -0, Math.PI, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -0x07fffffff, 2**53-2, 1, 0x080000001, -Number.MIN_VALUE, 0x100000001, -0x080000000, -(2**53), -0x0ffffffff, -(2**53-2), 0.000000000000001, 0, 0x07fffffff, 2**53+2, 2**53, -1/0, Number.MIN_SAFE_INTEGER, -0x100000001, 42, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-157142351*/count=438; tryItOut("let b, {d: [{}, ], x: e, \u3056: NaN} = x, qicwie, qfayjw, eval, NaN = [null];m1.delete(g0);function x() { \"use strict\"; yield x } o1.g1.m2.has(o0);");
/*fuzzSeed-157142351*/count=439; tryItOut("mathy5 = (function(x, y) { return (Math.fround(((Math.imul(Math.fround(((((y >>> 0) ? x : (42 >>> 0)) >>> 0) ^ Math.fround(-0x080000001))), ( + Math.pow(( + x), ( + y)))) || (mathy0(( + (y && Math.fround(y))), ( + (Math.fround(y) , Math.fround(x)))) | 0)) || ((( + 0x080000001) || ( - (y ? Number.MAX_VALUE : ( + Math.hypot((y >>> 0), (y | 0)))))) >>> 0))) ? ( + ((Math.pow(Math.fround(mathy0(Math.fround(x), (0.000000000000001 | 0))), Math.fround(Math.atan2(Math.max(( ~ y), ((Number.MAX_VALUE | 0) && x)), x))) >>> 0) ? (Math.pow(Math.max(Math.fround(x), Math.fround(( ~ x))), (Math.tanh(0x080000000) >>> 0)) >>> 0) : (Math.imul((( ~ y) >>> 0), (Math.fround(mathy0((y | 0), Math.fround(x))) >>> 0)) >>> 0))) : Math.fround((Math.fround(((Math.imul(x, (((x >>> 0) && (x >>> 0)) >>> 0)) , x) | 0)) >> Math.fround((-Number.MIN_VALUE >> (Math.clz32((x >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [-1/0, 0x07fffffff, 0.000000000000001, -(2**53+2), 0, -(2**53), 42, 0x100000000, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, -0x080000001, 0/0, 0x080000000, 1, 2**53+2, 0x0ffffffff, -0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, 0x080000001, Math.PI, Number.MAX_VALUE, 2**53, 1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53-2), -0x0ffffffff, -0x07fffffff, -Number.MAX_VALUE, -0x100000001, -0]); ");
/*fuzzSeed-157142351*/count=440; tryItOut("var ujshde = new SharedArrayBuffer(0); var ujshde_0 = new Uint8ClampedArray(ujshde); var ujshde_1 = new Int8Array(ujshde); m1.set(s2, m2);undefined;Array.prototype.reverse.call(a1, e2);");
/*fuzzSeed-157142351*/count=441; tryItOut("mathy4 = (function(x, y) { return ((Math.fround(( ~ mathy3((y >>> 0), y))) >>> ( ! (y | 0))) , (( ! ((( ~ ( ! Math.max(mathy2(Number.MAX_VALUE, y), y))) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [1, (new String('')), '/0/', (function(){return 0;}), [], (new Number(-0)), [0], 0, '', '\\0', (new Number(0)), /0/, undefined, objectEmulatingUndefined(), true, false, ({valueOf:function(){return '0';}}), null, ({toString:function(){return '0';}}), (new Boolean(false)), NaN, -0, (new Boolean(true)), '0', 0.1, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-157142351*/count=442; tryItOut("mathy0 = (function(x, y) { return ((Math.log1p(Math.pow(Number.MIN_VALUE, ( ! 2**53+2))) !== (Math.fround(Math.hypot(Math.fround(( ! ( + Math.max(y, ( + ( + Math.acosh(( ! y)))))))), Math.fround(Math.sinh(y)))) ? Math.acos(( - y)) : (( ~ ((Math.min(((Math.pow(x, ( + x)) | 0) | 0), y) >>> 0) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy0, [-0x080000001, 42, 0, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x080000000, -Number.MIN_VALUE, -0x07fffffff, 2**53+2, -0x100000001, 2**53, 0x07fffffff, -Number.MAX_VALUE, -1/0, -0x0ffffffff, 0.000000000000001, 0x100000000, 1/0, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, -0, -(2**53), 0x100000001, 1, Math.PI, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, Number.MIN_VALUE, -0x100000000, -(2**53+2), Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=443; tryItOut("g0 = fillShellSandbox(evalcx('lazy'));");
/*fuzzSeed-157142351*/count=444; tryItOut("\"use strict\"; v2 = r0.ignoreCase;");
/*fuzzSeed-157142351*/count=445; tryItOut("\"use strict\"; testMathyFunction(mathy0, ['\\0', [0], 0, /0/, (new Number(0)), -0, NaN, (new String('')), undefined, '', ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '0', true, '/0/', [], (new Boolean(false)), (new Boolean(true)), (function(){return 0;}), objectEmulatingUndefined(), 1, ({valueOf:function(){return '0';}}), false, null, (new Number(-0)), 0.1]); ");
/*fuzzSeed-157142351*/count=446; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var floor = stdlib.Math.floor;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i0 = (i0);\n    i2 = (i2);\n    i1 = (!(i0));\n    i2 = (i0);\n    return +((((73786976294838210000.0)) * ((18014398509481984.0))));\n    i1 = (/*FFI*/ff()|0);\n    i0 = (!(i2));\n    /*FFI*/ff(((((i1)+(i0)+(i0)) >> ((i2)))), ((4611686018427388000.0)), ((+floor((((((0x1fe97306) ? (-35184372088831.0) : (-295147905179352830000.0))) * (((-36893488147419103000.0) + (0.001953125)))))))), (((((-0x8000000) != (0x54d9b0b2))*-0x86bed) & ((0xf8730604) / (0xc94e6578)))), ((~~(+/*FFI*/ff(((makeFinalizeObserver('tenured'))), ((134217729.0)), ((-1.888946593147858e+22)), ((-1.5474250491067253e+26)), ((268435457.0)))))));\n    i2 = (i1);\n    i1 = ((0xa38079a5) <= (0x26bd54ca));\n;    i1 = ((((i2)-(i2)+((i2) ? (!(0x622e6f40)) : ((0x7fffffff) == (0x7fffffff)))) & (((((0xf9608f19)*0xeb6ef)|0) != (0x6f2a145a))-(0xfa45cd9d)-((-73786976294838210000.0) < (-536870911.0)))) != ((Uint8ArrayView[0])));\n    i2 = (i1);\n    return +((Infinity));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ var gpxfau = [z1,,]; var grkrbw = q => q; return grkrbw;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000000, 1/0, 2**53, 0/0, -Number.MAX_SAFE_INTEGER, 1, -(2**53+2), -0x100000001, -0, 0.000000000000001, Number.MAX_VALUE, -(2**53), -(2**53-2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000001, 0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, 2**53+2, 0, 0x100000001, 42, Number.MIN_VALUE, -1/0, -0x080000000, -0x0ffffffff, 0x100000000, 0x0ffffffff, 2**53-2, 0x07fffffff, -0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=447; tryItOut("/*tLoop*/for (let c of /*MARR*/[x, x,  \"\" ,  \"\" ]) { (let (e=eval) e) }");
/*fuzzSeed-157142351*/count=448; tryItOut("h2.valueOf = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    (Float32ArrayView[0]) = ((8796093022209.0));\n    d1 = (18014398509481984.0);\n    i0 = (/*FFI*/ff((((((0x148c9ffa))+(((~((0x538b2aee)))) ? (0x6c551062) : (!(((-0x8bd77*(0x29b64a28))>>>((0xa0d74064) / (0xc812b9df))))))))))|0);\n    switch (((((((0x560b0840)) ^ ((0xfab12974))))) ^ ((0xffffffff)*-0xe0884))) {\n    }\n    i0 = (0xfa0e9019);\n    return ((((0x313e9646) ? (/*FFI*/ff(((imul((i0), ((((0x8798fefe)) & ((0x964f1003))) <= (((0xffffffff)) << ((0x5d97728e)))))|0)), ((0x7fffffff)), ((513.0)), ((((0xf947d466)-(0xf884ec7c)) ^ (((0x6ebb66df) ? (0x12a289ce) : (0x9dff1a2))))), ((+(0.0/0.0))), ((562949953421311.0)), ((-9.671406556917033e+24)), ((-4.835703278458517e+24)), ((-68719476736.0)), ((2251799813685249.0)), ((18014398509481984.0)))|0) : ((0xffffffff)))))|0;\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096));");
/*fuzzSeed-157142351*/count=449; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.max((Math.pow(Math.fround(( + Math.trunc((( + Math.cos(Math.asinh(y))) | 0)))), (Math.expm1(1.7976931348623157e308) | 0)) >>> ( + ( ~ -0))), (Math.ceil((Math.clz32(( + ( + mathy0(( + y), ( + Math.log10(( + -0x080000001))))))) >>> 0)) | 0)); }); testMathyFunction(mathy5, /*MARR*/[(0/0), (0/0), (0/0), false, (0/0), (0/0), false, (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), (0/0), -0, false, false, (0/0), (0/0), -0, false, -0, false, -0, false, -0, -0, false, -0, false, (0/0), false, -0, (0/0), -0, -0]); ");
/*fuzzSeed-157142351*/count=450; tryItOut("testMathyFunction(mathy2, [-Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000001, -0x0ffffffff, 0x0ffffffff, 2**53, 0x080000001, -0, -0x080000000, -1/0, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, Number.MAX_VALUE, 0, Number.MIN_VALUE, 0x100000000, 0x080000000, -(2**53-2), 0x07fffffff, 0.000000000000001, -(2**53+2), -0x100000001, -0x07fffffff, 1/0, 0/0, 42, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -Number.MIN_VALUE, 1]); ");
/*fuzzSeed-157142351*/count=451; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[eval, objectEmulatingUndefined(), function(){}, function(){}]) { a0.forEach((function(j) { if (j) { for (var v of t1) { try { Array.prototype.reverse.apply(a2, [f1]); } catch(e0) { } try { /*MXX2*/g2.g1.g2.Array.prototype.includes = b1; } catch(e1) { } v2 = t0.length; } } else { p2 + ''; } }), this.o0, 'fafafa'.replace(/a/g, (new Function).bind(undefined, this)), o2.m0, g1); }");
/*fuzzSeed-157142351*/count=452; tryItOut("with({c: Math.pow(window.__defineSetter__(\"x\", (function(y) { return window }).apply), 11)})/* no regression tests found */");
/*fuzzSeed-157142351*/count=453; tryItOut("/*tLoop*/for (let z of /*MARR*/[-Infinity, NaN, arguments, arguments, NaN, arguments, 17, NaN, 17, arguments, -Infinity, NaN, 17, NaN, -Infinity, arguments, 17, NaN, 17, -Infinity, -Infinity, 17, arguments, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, NaN, -Infinity, -Infinity, 17, 17, NaN, -Infinity, -Infinity, -Infinity, NaN, NaN, -Infinity, NaN, 17, 17, arguments, 17, arguments]) { yield; }");
/*fuzzSeed-157142351*/count=454; tryItOut("mathy1 = (function(x, y) { return Math.hypot(().unwatch(new String(\"14\")), Math.hypot(mathy0(((Math.max((Math.max(( + y), (y | 0)) | 0), mathy0(0x0ffffffff, x)) >>> 0) ^ ((Math.expm1((Math.max(( + 2**53+2), ( + x)) | 0)) | 0) >>> 0)), (mathy0(0x080000000, x) % Math.fround(mathy0(y, mathy0(( + x), -(2**53)))))), ((Math.fround(( + Math.fround(Math.fround(mathy0(Math.fround((x > y)), x))))) | 0) + Math.fround(Math.min(( + Math.fround(Math.imul(( + ( + Math.imul(Math.fround(0/0), Math.fround(mathy0(y, x))))), Math.fround(1.7976931348623157e308)))), Math.fround((mathy0(Math.fround(1), Math.sinh(( + ( + -Number.MIN_VALUE)))) | 0))))))); }); testMathyFunction(mathy1, [1.7976931348623157e308, -0x080000000, Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x0ffffffff, 0x100000000, -0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53), Math.PI, 2**53-2, 42, Number.MIN_VALUE, Number.MAX_VALUE, -0, 0x080000000, -1/0, 0x080000001, -(2**53-2), 0.000000000000001, 0, 2**53+2, 2**53, -(2**53+2), 0x0ffffffff, -0x080000001, 1/0, 0x100000001, 0x07fffffff, -0x07fffffff]); ");
/*fuzzSeed-157142351*/count=455; tryItOut("a0.reverse();");
/*fuzzSeed-157142351*/count=456; tryItOut("\"use strict\"; /*MXX2*/g1.Date.length = t1;");
/*fuzzSeed-157142351*/count=457; tryItOut("\"use strict\"; t2 + '';");
/*fuzzSeed-157142351*/count=458; tryItOut("m0.delete(s0);");
/*fuzzSeed-157142351*/count=459; tryItOut("mathy2 = (function(x, y) { return ((Math.clz32(Math.hypot(Math.ceil(Math.log10(Math.fround(mathy1(( + (( + 1) != x)), ( + -Number.MIN_VALUE))))), ((( ! ( ~ (((y >>> 0) < (x >>> 0)) >>> 0))) >>> 0) | 0))) >>> 0) & ((Math.log10((mathy0(x, y) | 0)) | ( + Math.min(( + Math.fround(( + Math.max((-0x100000000 | 0), (-(2**53-2) | 0))))), Math.fround(Math.imul((-Number.MIN_SAFE_INTEGER >>> 0), (mathy0((x | 0), ((x < y) | 0)) >>> 0)))))) ? ( - x) : (Math.min((( + mathy1(( + y), ( + Math.tanh(( + Math.pow(x, x)))))) >>> 0), (y | 0)) >>> 0))); }); ");
/*fuzzSeed-157142351*/count=460; tryItOut("mathy1 = (function(x, y) { return ((Math.fround((Math.fround(( + ((x !== -Number.MAX_VALUE) | 0))) <= (( ! (mathy0(( + y), ( + Math.min(( + y), ( + Number.MIN_SAFE_INTEGER)))) | 0)) | 0))) < (Math.min(Math.atanh(Math.fround(y)), Math.fround(Math.atan((Math.cosh((0x080000000 >>> 0)) >>> 0)))) & (( + Math.fround(mathy0((x >>> 0), ( ~ x)))) | 0))) >>> 0); }); ");
/*fuzzSeed-157142351*/count=461; tryItOut("mathy5 = (function(x, y) { return (mathy2((( - Math.fround(Math.log(Math.fround(x)))) >>> 0), (( + ((Math.fround(Math.atan2(Math.fround(((y ^ x) ^ (x * x))), Math.fround(((mathy0(x, mathy4(y, y)) | 0) != x)))) >>> 0) ? ((Math.ceil((mathy2((y | 0), y) | 0)) >>> 0) >>> 0) : mathy1((-0x100000000 >> Math.max(x, (mathy0((x >>> 0), (x >>> 0)) >>> 0))), ( ~ y)))) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x100000000, -Number.MAX_VALUE, 1/0, -0x100000001, -(2**53), 0x100000000, 0, 0x100000001, -0x0ffffffff, -(2**53+2), Number.MIN_VALUE, -0, 2**53-2, Number.MIN_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 42, 0x080000000, -0x07fffffff, 1, 0/0, 0x080000001, -0x080000000, 2**53, Number.MAX_VALUE, 0x07fffffff, -1/0, 2**53+2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x0ffffffff, -0x080000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=462; tryItOut("\"use asm\"; ;");
/*fuzzSeed-157142351*/count=463; tryItOut("");
/*fuzzSeed-157142351*/count=464; tryItOut("mathy2 = (function(x, y) { return ((mathy0(( + (( + ((Math.atan2(((((2**53 | 0) ** x) | 0) >>> 0), (x >>> 0)) >>> 0) || (Math.hypot(Math.cbrt(-Number.MAX_SAFE_INTEGER), Math.fround(x)) | 0))) | Math.pow((Math.min(x, x) ? 2**53+2 : ( + ( + mathy0(( + -0x07fffffff), y)))), Math.fround(Math.cbrt(x))))), ( + (x << y))) | 0) / (( + Math.pow(Math.fround(( + (( + -Number.MAX_SAFE_INTEGER) ^ Math.fround(x)))), Math.tanh(Math.fround((Math.min(y, x) ? ( + Math.tan(Math.fround(y))) : y))))) || ( + (mathy0((x | 0), (Math.max((x >>> 0), (( ! ((((y >>> 0) && (y >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0)) | 0)))); }); testMathyFunction(mathy2, [-(2**53-2), 0x080000001, 0x080000000, -(2**53), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -0, 0x100000000, 0x07fffffff, 1.7976931348623157e308, 2**53-2, Number.MAX_VALUE, -0x0ffffffff, 2**53+2, -0x080000000, 0/0, Math.PI, -Number.MAX_VALUE, -(2**53+2), 1, Number.MIN_VALUE, -1/0, Number.MIN_SAFE_INTEGER, 42, 0, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000001, -0x080000001, -0x07fffffff, 0x0ffffffff, 0.000000000000001, 2**53]); ");
/*fuzzSeed-157142351*/count=465; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = -72057594037927940.0;\n    return ((((0xffffffff))))|0;\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -0, -(2**53), -0x080000001, 0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, Math.PI, 1/0, 2**53-2, 0.000000000000001, -0x080000000, 0, 2**53, 0x07fffffff, 42, Number.MIN_VALUE, -0x07fffffff, -0x0ffffffff, -(2**53+2), 2**53+2, -1/0, -Number.MIN_SAFE_INTEGER, 0/0, 1, 0x080000000, 0x100000000, -0x100000000, -0x100000001, 0x100000001, 1.7976931348623157e308, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=466; tryItOut("mathy3 = (function(x, y) { return Math.max(Math.fround(Math.fround(Math.atan2(Math.fround((Math.cosh(((Math.atan(Math.fround(x)) >>> 0) | 0)) | 0)), ( + (( + ( - Math.fround(y))) ? ( + Math.max((-(2**53) ? ( - x) : Math.fround(( + ( ! ( + 0x080000001))))), Math.fround((( ! Math.fround(( + (y ? x : (x ^ x))))) >>> 0)))) : ( + x)))))), (Math.hypot((Math.fround(Math.asinh(Math.fround(Math.sin(Math.fround(( ! Math.fround(mathy2(2**53+2, Math.fround(mathy2((y >>> 0), x)))))))))) >>> 0), mathy2((( ~ y) >>> 0), Math.ceil((( ! (Math.atan2((Math.round(Number.MIN_SAFE_INTEGER) | 0), x) | 0)) | 0)))) >>> 0)); }); testMathyFunction(mathy3, [/0/, [], NaN, '0', (new Boolean(false)), false, ({toString:function(){return '0';}}), (new Number(0)), -0, '\\0', 1, ({valueOf:function(){return 0;}}), (function(){return 0;}), (new Boolean(true)), '', true, '/0/', (new String('')), (new Number(-0)), objectEmulatingUndefined(), [0], null, 0, undefined, 0.1, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-157142351*/count=467; tryItOut("\"use strict\"; a2 = Array.prototype.map.apply(a1, []);");
/*fuzzSeed-157142351*/count=468; tryItOut("v0.__iterator__ = (function() { for (var j=0;j<46;++j) { f2(j%4==1); } });");
/*fuzzSeed-157142351*/count=469; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=470; tryItOut("mathy5 = (function(x, y) { return ( ! Math.max(Math.atan2((( - Math.fround(( ~ Math.min(Number.MIN_SAFE_INTEGER, Math.fround(y))))) | 0), ( - ((( + Math.sinh(y)) - x) | 0))), mathy0((( ~ ( + ((( ~ (Math.ceil((Number.MIN_VALUE >>> 0)) >>> 0)) >>> 0) ? mathy3(y, 2**53+2) : Math.fround(Math.atanh(Math.fround(2**53+2)))))) >>> 0), ((Math.acos(( + ({/*TOODEEP*/}))) + Math.atan2(x, Math.fround((-0x07fffffff < Math.fround(-0x07fffffff))))) >>> 0)))); }); ");
/*fuzzSeed-157142351*/count=471; tryItOut("\u3056, [{b: [, window, z, [], {x: x, x: e}], \u3056: NaN, x: {}}, x] = ({\"29\": (\n/(?:(?!(?=\\W\\s\u40c1{2,}|\\1)))/im),  set name() { \"use strict\"; return (makeFinalizeObserver('nursery')) }  }), x, b, e = NaN =  \"\" .__defineSetter__(\"x\", \"\\u8923\"), c = (void version(170));const v2 = t2.length;");
/*fuzzSeed-157142351*/count=472; tryItOut("o1.f0(t1);");
/*fuzzSeed-157142351*/count=473; tryItOut("mathy4 = (function(x, y) { return Math.sin(Math.fround(mathy0(( ! -1/0), ( + (Math.imul((y | 0), (( + y) | 0)) | 0))))); }); testMathyFunction(mathy4, [-0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, 2**53, -0, 0x080000000, Number.MIN_VALUE, -(2**53+2), -Number.MAX_VALUE, -1/0, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x080000000, 42, -0x07fffffff, 1, -(2**53), Number.MAX_VALUE, 0x07fffffff, 0x100000000, 0x080000001, -0x0ffffffff, 0.000000000000001, Math.PI, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_VALUE, -0x100000001, 0]); ");
/*fuzzSeed-157142351*/count=474; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=475; tryItOut("a2 = a2.slice(-7, -4);");
/*fuzzSeed-157142351*/count=476; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.5111572745182865e+23;\n    /*FFI*/ff(((((/*FFI*/ff(((d0)))|0)+(!(0xc6db9ff6))-(0xbadee8c4)) | ((0xfe082e08)))));\n    d1 = (d2);\n    {\n      return +((d0));\n    }\n    {\n      d2 = (+pow(((d2)), ((d2))));\n    }\n    (Int8ArrayView[0]) = (((+(0xffffffff)) <= (+(((0xf22b2e89)) | ((0xf91d92df)*-0xedad9)))));\n    return +((+(~((0x9846ec0a)-((0xffffffff) <= (((0xeba63047)*-0x368bb)>>>((0x60b9a14c) % ((Int32ArrayView[0])))))))));\n    d0 = (d2);\n    (Int16ArrayView[((0xb9783763)+(!((((0xbf029804) / (0xbc0745cd))>>>((/*FFI*/ff(((-281474976710657.0)))|0)))))) >> 1]) = ((((/*FFI*/ff(((+(0.0/0.0))))|0)+((0xf95bbbc5) ? (0xfd905e5f) : (0xf8080b2f)))>>>((0xfb4e0bf6)-((((0xffffffff)-(0x3247068e)) ^ (((0x1f1839e5)))) == (((0xd3a7fd4b)+(0xffffffff)-(0xff34d1c7)) << (-(0x438b0eb)))))) % (((0xfc3c0bf1)+(0x4b94e434))>>>((0xf998dfaa))));\n    d0 = (d0);\n    d0 = (-((((d1)) - ((((((yield let (z = window) \"\\uB7E5\")) - ((-((yield null())))))) / ((NaN)))))));\n    {\n      (Uint8ArrayView[(((((0xf962f584)) | ((0xff79ddf4))) == (((0xb9d67242)) & ((0xfb5a29a1))))-((((0xffbe53de))>>>((0xf8f7b27d))) != (0xe88537f9))+(-0x8000000)) >> 0]) = ((/*RXUE*//[^]*?|\\D|.|[\\s\\d\\d\\u003E]\u9ed7*+?{1}/gm.exec(\"\\n\\n\"))-(0xfc478dea));\n    }\n    d1 = (d1);\n    {\n      d2 = (d1);\n    }\n    {\n      d0 = (d2);\n    }\n    return +(x);\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [Math.PI, -Number.MAX_VALUE, -1/0, -(2**53+2), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, -0x0ffffffff, 0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0x07fffffff, 0, 0x080000001, -0x080000000, 0/0, -(2**53), 1.7976931348623157e308, -0x100000000, 0x07fffffff, 0x0ffffffff, 42, 1, 0x080000000, -0x100000001, -0x080000001, -0, -(2**53-2), 0x100000000, 2**53, 0.000000000000001]); ");
/*fuzzSeed-157142351*/count=477; tryItOut("o2 = new Object;");
/*fuzzSeed-157142351*/count=478; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    i3 = (((-0x8000000)) ? (i4) : (0x705f22b));\n    i2 = ((0x5d6337bd) == (0x3b3ae8e0));\n    d1 = (d0);\n    return +(((Int16ArrayView[(-(i2)) >> 1])));\n  }\n  return f; })(this, {ff: eval}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [2**53+2, -(2**53-2), 0, 1, Math.PI, -0x100000001, 0/0, 2**53, -0, Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000001, 0x100000001, 0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 0x0ffffffff, 0x07fffffff, 2**53-2, Number.MAX_VALUE, -(2**53+2), 0x080000001, 1/0, 1.7976931348623157e308, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), -1/0, 42, Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-157142351*/count=479; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ~ ( + (Math.exp((Math.acosh(Math.imul((( + x) >> (Math.fround(( - Math.fround(-0x0ffffffff))) ? Math.atan2(x, y) : 0)), ( + x))) >>> 0)) >>> 0))); }); testMathyFunction(mathy1, /*MARR*/[true, ({x:3}), true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true]); ");
/*fuzzSeed-157142351*/count=480; tryItOut("const x =  \"\" ;o0.g0 = this;");
/*fuzzSeed-157142351*/count=481; tryItOut("m2.get(f1);");
/*fuzzSeed-157142351*/count=482; tryItOut("\"use strict\"; var o1 = new Object;function x(x, eval)Math.pow(-20,  \"\" )a2[(/*RXUE*//(?![^\\u006e-\ub184\\cM-\\xFD\udfd2])/g.exec(\"\\udfb2\"))];");
/*fuzzSeed-157142351*/count=483; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0(Math.fround(Math.imul((y >>> 0), (( + Math.fround(( + x))) >>> 0))), (mathy0(Math.imul(0x100000001, (( ! (( + Math.log10(x)) >>> 0)) >>> 0)), (Math.max((Math.atanh(( + x)) >>> 0), (Math.fround(( + Math.pow((x | 0), ( + (Math.max((x | 0), x) >>> 0))))) ? (( ~ (Math.max(y, ( + x)) >>> 0)) | 0) : 1.7976931348623157e308)) | 0)) | 0)) ? Math.fround(( - Math.fround(((x >>> 0) && (Math.imul(Math.fround((Math.min(x, x) >>> 0)), Math.fround(( + x))) >>> 0))))) : Math.ceil(Math.imul((((y ? ( ~ (0/0 | 0)) : y) ? x : ( ! y)) | 0), (( ! x) | 0)))); }); testMathyFunction(mathy1, [2**53+2, 0, -0x100000000, 0x100000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, 0x100000000, -0x100000001, 0x07fffffff, -0x080000000, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000, 42, 2**53, 0.000000000000001, 1/0, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53), -(2**53-2), 1, -0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 0/0, -Number.MAX_VALUE, -1/0, -0x0ffffffff, Math.PI, 0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=484; tryItOut("print(x);");
/*fuzzSeed-157142351*/count=485; tryItOut("v2 = new Number(NaN);");
/*fuzzSeed-157142351*/count=486; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=487; tryItOut("mathy3 = (function(x, y) { return (( ~ ( + Math.acosh(( + (x << Math.hypot(mathy1(0x080000001, x), (( + x) ? ( + Math.imul(Math.abs(-(2**53-2)), ( + x))) : (x >>> 0)))))))) | 0); }); testMathyFunction(mathy3, [0x07fffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, -Number.MAX_VALUE, 2**53+2, -(2**53), 42, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 0, Math.PI, -0x080000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), -0x07fffffff, 1/0, -(2**53-2), 0/0, -Number.MIN_VALUE, -0, -0x100000000, -0x080000001, 0.000000000000001, -0x0ffffffff, 0x080000001, 0x0ffffffff, 1, 0x100000000, Number.MAX_VALUE, 0x100000001, 0x080000000, 1.7976931348623157e308]); ");
/*fuzzSeed-157142351*/count=488; tryItOut("\"use strict\"; if(/*MARR*/[ /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , new Boolean(true), new Boolean(true),  /x/ ,  /x/ , new Boolean(true),  /x/ , new Boolean(true), new Boolean(true),  /x/ , new Boolean(true),  /x/ , new Boolean(true), new Boolean(true),  /x/ , new Boolean(true),  /x/ ,  /x/ , new Boolean(true),  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/ ,  /x/ , new Boolean(true),  /x/ , new Boolean(true), new Boolean(true), new Boolean(true),  /x/ ,  /x/ , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/ ,  /x/ ,  /x/ , new Boolean(true), new Boolean(true),  /x/ , new Boolean(true),  /x/ ,  /x/ ].map.getPrototypeOf(yield x)) {o2.a1.length = v1;for (var v of t0) { try { v1 = Object.prototype.isPrototypeOf.call(v2, b0); } catch(e0) { } try { v0 = a0.length; } catch(e1) { } h1 = ({getOwnPropertyDescriptor: function(name) { return o0.g1.b0; var desc = Object.getOwnPropertyDescriptor(i0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { print(uneval(g2.o2.p1));; var desc = Object.getPropertyDescriptor(i0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { return this.b1; Object.defineProperty(i0, name, desc); }, getOwnPropertyNames: function() { a1 = new Array;; return Object.getOwnPropertyNames(i0); }, delete: function(name) { Array.prototype.unshift.apply(a0, [e2, p2, m2, g1.t1, f1]);; return delete i0[name]; }, fix: function() { for (var p in p0) { try { this.v0 = g1.runOffThreadScript(); } catch(e0) { } try { h1 = {}; } catch(e1) { } this.v1 = Object.prototype.isPrototypeOf.call(a2, g1.t0); }; if (Object.isFrozen(i0)) { return Object.getOwnProperties(i0); } }, has: function(name) { v2 = t1.length;; return name in i0; }, hasOwn: function(name) { v1 = g1.g0.runOffThreadScript();; return Object.prototype.hasOwnProperty.call(i0, name); }, get: function(receiver, name) { v2 = (g2.a0 instanceof o0);; return i0[name]; }, set: function(receiver, name, val) { m0.delete(t2);; i0[name] = val; return true; }, iterate: function() { g0 = t1[0];; return (function() { for (var name in i0) { yield name; } })(); }, enumerate: function() { m0.set(o0.t0, p1);; var result = []; for (var name in i0) { result.push(name); }; return result; }, keys: function() { m0.set(t2, p0);; return Object.keys(i0); } }); } }");
/*fuzzSeed-157142351*/count=489; tryItOut("o1.v0 = g0.eval(\"b0 = new SharedArrayBuffer(20);\");");
/*fuzzSeed-157142351*/count=490; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return ( ~ ((Math.pow((y >>> 0), (0 >>> 0)) >>> 0) >= (( ~ y) | 0))); }); testMathyFunction(mathy4, /*MARR*/[null, null, null, null, x, x, x, x, x, x, (void 0), objectEmulatingUndefined(), (void 0), x, objectEmulatingUndefined(), x, (void 0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, x, x, null, null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined(), null, objectEmulatingUndefined(), x, x, (void 0), x, x, x, x, objectEmulatingUndefined(), null, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, (void 0), null, objectEmulatingUndefined(), (void 0), (void 0), x, (void 0), x, x, x, x, null, null, null, null, x, (void 0), null, null, null, x, null, null, x, null, (void 0), x, objectEmulatingUndefined(), (void 0)]); ");
/*fuzzSeed-157142351*/count=491; tryItOut("o0.g2.s2 += 'x';");
/*fuzzSeed-157142351*/count=492; tryItOut("/*RXUB*/var r = /[^]|[^]\\d{1}|.?+[^]|(?:.){1,}|\\s?\u089d/yim; var s = \"\\n\\u087d\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=493; tryItOut("v0 = evalcx(\"v0 + a0;\", g1);");
/*fuzzSeed-157142351*/count=494; tryItOut("\"use strict\"; h2 + this.s1;");
/*fuzzSeed-157142351*/count=495; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + ( ! ((Math.atan2(((mathy3(((((x >>> 0) != Math.pow(( + y), ( + Math.max(y, ( + x))))) >>> 0) | 0), (x | 0)) | 0) >>> 0), (Math.fround(mathy1(((( + (Math.log10(Math.fround(y)) ? x : -0)) == ( + Math.sin(x))) >>> 0), ( ~ y))) >>> 0)) | 0) | 0))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -(2**53), 0x07fffffff, 0x100000001, -0, 2**53, -0x07fffffff, -0x100000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 0, Number.MIN_VALUE, 2**53-2, Math.PI, Number.MIN_SAFE_INTEGER, -0x080000000, 42, -1/0, 1.7976931348623157e308, 0x0ffffffff, 1/0, 0x080000001, -0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x100000000, 0/0, -(2**53-2), 0x080000000, -0x100000000, -0x0ffffffff, 1, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=496; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?!.){0,})|((?:^+([^])+?|\\\\x21))*\", \"y\"); var s = \"\"; print(s.replace(r, true)); ");
/*fuzzSeed-157142351*/count=497; tryItOut("print((Date.prototype.getHours(18)));");
/*fuzzSeed-157142351*/count=498; tryItOut("o0.toSource = (function() { try { i2 = m1.entries; } catch(e0) { } try { a2.splice(NaN, ({valueOf: function() { v1 = r1.test;return 17; }})); } catch(e1) { } try { g2 = t1[15]; } catch(e2) { } a0 = g2.objectEmulatingUndefined(); return this.h1; });");
/*fuzzSeed-157142351*/count=499; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = -140737488355328.0;\n    var d6 = -2305843009213694000.0;\n    {\n      {\n        switch ((~~(d5))) {\n          case -1:\n            {\n              return +(((Int16ArrayView[((((!(i1))-(/*FFI*/ff(((x)), ((73786976294838210000.0)), ((590295810358705700000.0)), ((-129.0)))|0)-(i3))>>>((i3))) % ((((abs((-0x8000000))|0))+(i1)+((0xfa11126a) ? (0xfb6466a9) : (0xff4add6d)))>>>(((4277) ? (window.__defineSetter__(\"e\", /*wrap2*/(function(){ var lgkfct = false; var brzcjo = decodeURIComponent; return brzcjo;})())) : c = Proxy.createFunction(({/*TOODEEP*/})( '' ), Object.is, (let (e=eval) e)))*0x71ec1))) >> 1])));\n            }\n            break;\n          case 0:\n            i4 = (/*FFI*/ff(((((i2)-((!(-0x8000000)) ? ((562949953421311.0) == (-4611686018427388000.0)) : (-0x8000000))-((0xa8b4af05))) | (((((0xb3a82224)-(0x38aeac00)+(0xd22bc56c)) | (-(i3))) == ((((0x1fd7e3f1))) ^ ((0xffffffff) / (0x0))))*0x5e0e2))), ((0x29a8d273)), ((d6)), ((((+atan2(((+(0.0/0.0))), ((-1048577.0))))) * ((-7.737125245533627e+25)))))|0);\n            break;\n          case -3:\n            i1 = (!((((0xffffffff) / ((((3.8685626227668134e+25) == (7.555786372591432e+22)))>>>((0xf8af00c4)))) & ((i0)))));\n            break;\n          case -1:\n            d5 = ((Float64ArrayView[(((31.0) >= (-1048577.0))*0x8abf5) >> 3]));\n          default:\n            i3 = ((0x9d62f39));\n        }\n      }\n    }\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: q => q}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53+2), -0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, -0x080000001, 0, Number.MAX_VALUE, -0x07fffffff, 0x080000000, 42, 2**53+2, 0x0ffffffff, Math.PI, 0.000000000000001, 0x080000001, 1.7976931348623157e308, -1/0, -Number.MAX_SAFE_INTEGER, 1, -(2**53-2), -(2**53), 0/0, -0x080000000, Number.MIN_VALUE, 0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000001, 2**53, 2**53-2, -0x100000000, 0x100000000]); ");
/*fuzzSeed-157142351*/count=500; tryItOut("/*tLoop*/for (let b of /*MARR*/[x, -Infinity, x, x, x, x, -Infinity, new String('q'), x, new String('q'), x, x, x, -Infinity, x, -Infinity, x, x, -Infinity, new String('q'), new String('q'), new String('q'), new String('q'), x, x, x, -Infinity, -Infinity, x, -Infinity, x, -Infinity, new String('q'), x, new String('q'), -Infinity, new String('q'), new String('q'), new String('q'), -Infinity, new String('q'), new String('q'), x, -Infinity, x, new String('q'), -Infinity, x, -Infinity, new String('q'), x, x, new String('q'), -Infinity, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String('q'), new String('q'), -Infinity, new String('q'), new String('q'), x, x, x, new String('q'), x, new String('q'), x, new String('q'), x, new String('q'), x, x, -Infinity, x, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, x, -Infinity, x, x, new String('q'), x, x, new String('q'), x, x, x, new String('q'), -Infinity, new String('q'), new String('q'), -Infinity, x, x, x, new String('q'), x, x, x, x, new String('q'), -Infinity, x, x, x, new String('q'), x, x, new String('q'), x, -Infinity, x, new String('q'), x, x, new String('q'), new String('q'), -Infinity, new String('q'), x, x, new String('q'), -Infinity, x, -Infinity, x, x, x, x, x, x, new String('q'), -Infinity, x, new String('q'), new String('q'), x, x, new String('q'), new String('q'), -Infinity, new String('q'), new String('q'), -Infinity, x, -Infinity, x, new String('q'), -Infinity]) { v1 = r0.unicode; }");
/*fuzzSeed-157142351*/count=501; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 2305843009213694000.0;\n    {\n      {\n        {\n          {\n            d0 = (+((NaN)));\n          }\n        }\n      }\n    }\n    d2 = (d2);\n    i1 = ((+(0.0/0.0)) >= ((i1) ? (((0xa6889336) != (0xffffffff)) ? (d2) : (+/*FFI*/ff(((d2)), ((281474976710657.0)), ((-524289.0)), ((-36893488147419103000.0)), ((-9.44473296573929e+21)), ((147573952589676410000.0)), ((-4294967297.0))))) : (d2)));\n    d2 = (d0);\n    d0 = (+((((d2)) / ((+/*FFI*/ff(((d0)), ((~~(-1099511627776.0))), ((~~(-2049.0))), ((+(0x427e675e))), ((((-137438953472.0)) % ((-17592186044417.0)))), ((+abs(((-0.25))))), ((4294967296.0)), ((-65537.0)), ((1.5474250491067253e+26)), ((3.8685626227668134e+25))))))));\n    d2 = (((+/*FFI*/ff())) / ((d0)));\n    switch ((~(0x67ae9*(0x5a650130)))) {\n      default:\n        (Int8ArrayView[4096]) = ((0xffffffff)+(0x3842d3d3));\n    }\n    (Float64ArrayView[((i1)+(((-(-0x8000000)) << ((0xe735cf15) % (0xffffffff))))) >> 3]) = ((((+/*FFI*/ff(((imul((0x5834d079), ((~~(28))))|0)), ((((-67108863.0)) * ((d2)))), ((+(-1.0/0.0))), ((((0x78e93a22) % (0x417c36bb)) | ((0x7fffffff) % (0x31f4a1d4)))), ((+(0.0/0.0))), ((-0x8000000)), (eval(\"mathy4 = (function(x, y) { return (( ~ ((((y > (((x | 0) | (y | 0)) | 0)) | 0) * ((Math.sinh(((((y | 0) === (Math.min((Math.asin(-1/0) >>> 0), ( + y)) >>> 0)) | 0) >>> 0)) >>> 0) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[objectEmulatingUndefined(), false, false, false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, false, false, false, false, objectEmulatingUndefined(), false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), false, objectEmulatingUndefined(), false, false, objectEmulatingUndefined(), objectEmulatingUndefined(), false]); \") - allocationMarker()), ((524289.0)), ((9007199254740992.0)), ((-17.0)), ((-17592186044417.0)), ((-2049.0))))) * ((-288230376151711740.0))));\n    {\n      i1 = ((((0x807b99a3))>>>((-0x7432fe0)+(0xf92d45ff))));\n    }\n    (Uint16ArrayView[((0xfd0818a3)+(0xc3334fa7)) >> 1]) = ((Float64ArrayView[((0x17457433)+(0x1405175e)) >> 3]));\n    return +((Float32ArrayView[(((0xfc3fab07) ? (((((((0xfe5888c8))>>>((0xffffffff)))))|0)) : (!(!((0x849430e2)))))+((~~(d2)) == (imul((/*FFI*/ff(((+pow(((288230376151711740.0)), ((-65537.0))))), (((([] = x)) + \"\\u7F2A\")), ((-549755813889.0)), ((288230376151711740.0)), ((137438953471.0)))|0), ((0xc59e2966)))|0))) >> 2]));\n    d2 = (Infinity);\n    d2 = (+(-1.0/0.0));\n    return +(((((-0xc87a7*((((0x7d63e1bb))>>>((0xf87c3fc6))) != (0x972ffc09))) ^ (-(eval(\"-19\", ({})))))) ? (d0) : (+(-1.0/0.0))));\n  }\n  return f; })(this, {ff: Int32Array}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [2**53, 0x100000001, -0x080000000, 0x100000000, 0x080000001, 0x0ffffffff, -0x080000001, 1.7976931348623157e308, -0, -Number.MAX_VALUE, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 1/0, 0/0, -(2**53+2), -0x100000000, -0x100000001, 2**53+2, -(2**53), -0x07fffffff, 2**53-2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, 0x080000000, 0.000000000000001, 42, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -(2**53-2), 0, Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-157142351*/count=502; tryItOut("/*RXUB*/var r = /[\\W\\u005f]|(?!(?:.|(?![^])?)|(?=(?!\\D)+|\\d|\\B.*){2,})/gm; var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-157142351*/count=503; tryItOut("throw StopIteration;for(let z of function(y) { yield y; Object.preventExtensions(g2.s1);; yield y; }) return;");
/*fuzzSeed-157142351*/count=504; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + ( ~ Math.fround((( + ( + mathy2(( + Math.acos(( ! x))), ( + (2**53 , x))))) ? Math.fround(Math.sin(Math.fround(Math.pow(Math.fround((( + x) - 0x080000000)), ( ~ y))))) : ( + ( + mathy3(y, Math.pow(y, y)))))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1.7976931348623157e308, -0x0ffffffff, -(2**53+2), 0x100000000, 0x080000001, 0/0, -0x100000001, -(2**53), Number.MIN_VALUE, 0.000000000000001, 2**53-2, 1, -0, 42, 0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x0ffffffff, -0x080000000, -1/0, 0x100000001, -(2**53-2), 2**53, -0x080000001, Math.PI, 2**53+2, -0x100000000, 1/0, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=505; tryItOut("t0 = new Uint8ClampedArray(b0, 6, 3);\nreturn true;\n");
/*fuzzSeed-157142351*/count=506; tryItOut(" for  each(let c in  /x/ ) {for (var p in g0.h0) { try { o0.v1 = undefined; } catch(e0) { } ; } }");
/*fuzzSeed-157142351*/count=507; tryItOut("\"use strict\"; const z = (4277);/*infloop*/L:do {v2.valueOf = (function(q) { \"use strict\"; return q; }).call; } while(this);");
/*fuzzSeed-157142351*/count=508; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.imul(Math.atan2(Math.fround(Math.pow(Math.fround(y), ( + Math.atan2(( + Math.sinh(x)), ( + y))))), (( ~ Math.fround(Math.sign((Math.min(Math.min(x, x), y) | 0)))) >>> 0)), ( + Math.exp(( + Math.clz32(Math.hypot((( + y) == y), Math.fround(y))))))); }); ");
/*fuzzSeed-157142351*/count=509; tryItOut("let x = x;print(x = w);");
/*fuzzSeed-157142351*/count=510; tryItOut("\"use strict\"; { void 0; minorgc(true); } /*tLoop*/for (let d of /*MARR*/[x, Number.MIN_SAFE_INTEGER, this, Number.MIN_SAFE_INTEGER, this, x, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, Number.MIN_SAFE_INTEGER, this, Number.MIN_SAFE_INTEGER, this, x, Number.MIN_SAFE_INTEGER, x, this, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, x, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, this, x, this, this, x, x, x, x, Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, this, x, this, Number.MIN_SAFE_INTEGER, this, x, this, x]) { v0 = evalcx(\"function f2(o2)  { \\\"use strict\\\"; return x } \", g0); }");
/*fuzzSeed-157142351*/count=511; tryItOut("\"use strict\"; /*MXX3*/g1.Set = g2.Set;");
/*fuzzSeed-157142351*/count=512; tryItOut("for (var p in m0) { Array.prototype.pop.call(a0); }");
/*fuzzSeed-157142351*/count=513; tryItOut("a2.forEach((function mcc_() { var ccrame = 0; return function() { ++ccrame; if (/*ICCD*/ccrame % 11 == 3) { dumpln('hit!'); try { s0 = a0.join(this.o1.s2); } catch(e0) { } try { b2 = t2.buffer; } catch(e1) { } try { Array.prototype.forEach.apply(a0, [objectEmulatingUndefined, s2, ({\"-29\": (void version(170)), \"-0\": (p={}, (p.z = new RegExp(\"(\\\\1)((?=(?!\\u0759|[^]?)))*?\", \"y\"))()) }), h1]); } catch(e2) { } g0 = o2.a1[({valueOf: function() { var wijsil = new ArrayBuffer(2); var wijsil_0 = new Float32Array(wijsil); wijsil_0[0] = 1e4; var wijsil_1 = new Uint8Array(wijsil); wijsil_1[0] = 19; Array.prototype.push.apply(a2, [m2, e2, i0, e1, a1, f0, v1, this.o1.t1, this.o0, this.i0]);/*RXUB*/var r = new RegExp(\".\", \"gym\"); var s = \"\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); /\\cG|(?:.\\b?){4,8}/i;window;a0[11] = f0;7;return 8; }})]; } else { dumpln('miss!'); try { Object.defineProperty(this, \"v1\", { configurable: new Boolean(false), enumerable: false,  get: function() { (void schedulegc(this.g1)); return a1.reduce, reduceRight((function mcc_() { var rysyqe = 0; return function() { ++rysyqe; if (/*ICCD*/rysyqe % 8 == 6) { dumpln('hit!'); try { e0.add(b2); } catch(e0) { } /*ADP-3*/Object.defineProperty(a1, v0, { configurable: (new RegExp(\"(?=(\\\\b|${2,}|[^]*?|[^]|(?:\\\\1))){4,}\", \"gym\") !== 20), enumerable: this.__defineGetter__(\"eval\", arguments.callee.caller), writable: (x % 30 != 21), value: o1 }); } else { dumpln('miss!'); g2.a1.shift(); } };})()); } }); } catch(e0) { } try { m1.delete(g0.g0); } catch(e1) { } try { this.g2.s2 += 'x'; } catch(e2) { } v1 = (this.a2 instanceof v0); } };})());");
/*fuzzSeed-157142351*/count=514; tryItOut("\"use strict\"; { void 0; void 0; } let (x, y = (Math.atan2(\"\\u0436\", 2**53-2)), constructor = w = Proxy.createFunction(({/*TOODEEP*/})( '' ), String.prototype.slice), faemvn, cxsczs, b, x) { this.i2 = new Iterator(g0.o0.s0, true); }");
/*fuzzSeed-157142351*/count=515; tryItOut("\"use strict\"; \"use asm\"; L:for(var b = x in  /x/ ) print(-0);");
/*fuzzSeed-157142351*/count=516; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -0.0625;\n    var i3 = 0;\n    {\n      d2 = (73786976294838210000.0);\n    }\n    i0 = (i3);\n    {\n      i1 = (i0);\n    }\n    i0 = (((((0xfffff*(i3)) << ((Uint32ArrayView[((0xe655c68c)) >> 2]))) / (0x237e464f)) & ((/*FFI*/ff(((-35184372088833.0)))|0)-(!(0xfc6a7440)))) <= (imul((/*FFI*/ff()|0), (i0))|0));\n    i3 = (i1);\n    i0 = ((0xd12e8f57));\n    i1 = (i0);\n    switch ((imul(((0xc446cafb) >= (0x43560958)), (i3))|0)) {\n      case 0:\n        i0 = (/*FFI*/ff(((Infinity)), ((-1073741825.0)))|0);\n        break;\n    }\n    return (((i1)+((0x3fbc9a2f))))|0;\n  }\n  return f; })(this, {ff: (((/*wrap3*/(function(){ var pnzgxa =  /x/g ; (false)(); }))(\"\\uF16C\"))).bind(Math.tan(-13), ((w) = null))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [(new Number(0)), 1, '', 0.1, [0], -0, ({valueOf:function(){return '0';}}), false, (function(){return 0;}), '0', NaN, [], '/0/', (new String('')), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), /0/, undefined, 0, (new Boolean(true)), (new Boolean(false)), (new Number(-0)), objectEmulatingUndefined(), null, '\\0', true]); ");
/*fuzzSeed-157142351*/count=517; tryItOut("\"use strict\"; /*vLoop*/for (let gcorof = 0; gcorof < 5; (e === x), ++gcorof) { d = gcorof; const w = \"\\uE1D0\";neuter(b1, \"same-data\") } ");
/*fuzzSeed-157142351*/count=518; tryItOut("\"use strict\"; s0 += s1;");
/*fuzzSeed-157142351*/count=519; tryItOut("this.v1 = Object.prototype.isPrototypeOf.call(t0, this.o1.a1);");
/*fuzzSeed-157142351*/count=520; tryItOut("/*vLoop*/for (let ecapoa = 0; ecapoa < 66; ++ecapoa) { let e = ecapoa; /* no regression tests found */ } ");
/*fuzzSeed-157142351*/count=521; tryItOut("\"use strict\"; o1.s0 + '';");
/*fuzzSeed-157142351*/count=522; tryItOut("print(x - x);\na2 = Array.prototype.concat.apply(a0, []);\n");
/*fuzzSeed-157142351*/count=523; tryItOut("\"use strict\"; testMathyFunction(mathy3, [({toString:function(){return '0';}}), '0', 0.1, null, [], objectEmulatingUndefined(), '/0/', (new Number(0)), true, 0, (function(){return 0;}), (new Boolean(true)), '\\0', 1, ({valueOf:function(){return 0;}}), NaN, [0], ({valueOf:function(){return '0';}}), (new Boolean(false)), (new String('')), '', undefined, false, (new Number(-0)), -0, /0/]); ");
/*fuzzSeed-157142351*/count=524; tryItOut("/*tLoop*/for (let b of /*MARR*/[function(){}, function(){}, function(){}]) { this.v2 = r1.ignoreCase; }");
/*fuzzSeed-157142351*/count=525; tryItOut("/*RXUB*/var r = /(?:^).{4,6}|(?=\\2)(?:^)+{4,}/; var s = \"*@\\n\\u0004\\n\\n*@\\n\\u0004\\n\\n*@\\n\\u0004\\n\\n*@\\n\\u0004\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=526; tryItOut("\"use strict\"; a2 = Array.prototype.slice.apply(a1, [4, NaN, i2]);");
/*fuzzSeed-157142351*/count=527; tryItOut("m1 + '';");
/*fuzzSeed-157142351*/count=528; tryItOut("i0.send(g0.e0);");
/*fuzzSeed-157142351*/count=529; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.acosh((( + mathy3(( + Math.fround(((x | 0) << Math.fround(( + ( ! -0x100000000)))))), ( + ( + (Math.max(Math.min(Math.fround(Math.pow(Math.fround(y), x)), Math.fround(x)), -0) % x))))) | 0)); }); ");
/*fuzzSeed-157142351*/count=530; tryItOut("mathy1 = (function(x, y) { return ( ! ( ~ ( + (( + ( ! ( + y))) / (Math.pow(((((y | 0) !== (x >>> 0)) >>> 0) | 0), (y | 0)) | 0))))); }); testMathyFunction(mathy1, [1, -0x0ffffffff, -Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, 42, 0x080000001, -(2**53+2), 0x080000000, 0x100000000, Math.PI, 2**53, -0x07fffffff, -(2**53-2), 0x0ffffffff, 1.7976931348623157e308, Number.MIN_VALUE, 0/0, Number.MAX_VALUE, -0x100000000, -1/0, 0x07fffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1/0, -(2**53), -0, 0, 0x100000001, 2**53-2, -Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-157142351*/count=531; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + ( ~ ( + (Math.fround((-(2**53) & (mathy0(mathy0(Math.fround(Math.cbrt(y)), y), y) | 0))) ^ Math.fround(Math.tanh(Math.fround(Math.max(mathy0(x, ( ~ ( ! x))), Math.fround((mathy0((y | 0), (y | 0)) | 0)))))))))); }); ");
/*fuzzSeed-157142351*/count=532; tryItOut("var bcvljy = new SharedArrayBuffer(4); var bcvljy_0 = new Uint16Array(bcvljy); bcvljy_0[0] = 5; var bcvljy_1 = new Uint16Array(bcvljy); var bcvljy_2 = new Uint8ClampedArray(bcvljy); print(bcvljy_2[0]); bcvljy_2[0] = -13; /*ODP-2*/Object.defineProperty(m2, \"catch\", { configurable: 7, enumerable: true, get: (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64, a65, a66, a67, a68, a69, a70, a71, a72, a73, a74, a75, a76, a77, a78, a79, a80, a81, a82, a83, a84, a85, a86, a87) { a61 = 4 / a85; var r0 = a4 + bcvljy_2[6]; var r1 = a61 & bcvljy_2; var r2 = a24 + a28; var r3 = 5 - a16; var r4 = a13 + a3; var r5 = a7 * a42; a17 = 5 % 4; var r6 = a53 ^ a15; var r7 = a87 % 4; var r8 = a41 ^ 0; a79 = 2 | 0; var r9 = r8 * 1; var r10 = a56 * r0; var r11 = a11 ^ a13; a33 = 0 * a49; var r12 = a76 / 4; var r13 = r5 + bcvljy; print(r3); a82 = bcvljy_0[0] & a83; var r14 = a14 ^ 3; var r15 = a42 / a43; var r16 = a74 % a54; var r17 = 0 ^ 6; var r18 = a71 | a34; var r19 = a8 ^ 7; var r20 = 6 - r13; var r21 = 8 % a72; var r22 = 9 | bcvljy_0[0]; var r23 = a66 & r1; var r24 = a54 - a34; var r25 = 5 / a80; var r26 = 4 / a32; a29 = 2 / a68; a48 = r13 * r25; a28 = 1 | 4; a85 = 9 + bcvljy_0[6]; var r27 = 4 | 1; var r28 = a79 & r11; a34 = a32 | r28; var r29 = bcvljy * a52; a33 = r10 + r10; var r30 = a24 - 6; var r31 = a86 * a11; var r32 = a74 ^ a33; var r33 = 8 & a60; var r34 = 5 / a57; print(a73); var r35 = a77 * a22; var r36 = a33 ^ 6; var r37 = a25 ^ 6; var r38 = r4 & a29; a38 = a31 & r17; var r39 = a11 & a85; var r40 = 3 & a26; var r41 = 2 * a59; var r42 = 1 * a4; var r43 = a84 ^ r36; var r44 = bcvljy_0 % bcvljy_2[6]; a33 = a74 ^ 4; var r45 = a20 / a57; r43 = a66 * a13; var r46 = r45 | 6; var r47 = bcvljy_2[0] | 7; var r48 = a11 % 2; a17 = r40 % a50; var r49 = r37 - 5; var r50 = r1 % r43; var r51 = a66 ^ 9; a19 = a16 - 2; var r52 = 6 ^ a66; print(a71); a72 = r49 | r33; var r53 = a10 ^ a10; r45 = 3 * 3; var r54 = 7 - a70; var r55 = a13 - r19; r7 = 8 + 8; var r56 = a17 * 6; bcvljy_1 = 7 ^ a67; var r57 = 8 & a21; var r58 = 0 - 5; var r59 = r55 * r26; var r60 = a28 * 6; var r61 = 2 - r42; var r62 = a20 + 7; var r63 = 4 - a21; var r64 = bcvljy_0[6] | a16; var r65 = 3 / r51; var r66 = 4 % a71; var r67 = 4 + a66; var r68 = a70 & a36; var r69 = a24 % 0; a61 = a64 % r45; print(a87); print(a37); a13 = 7 - 6; var r70 = r66 / 3; var r71 = r44 * 0; var r72 = a56 - a10; var r73 = 6 + a25; var r74 = 6 | a10; var r75 = 1 | 5; a44 = a83 - a26; print(r48); print(a27); var r76 = a77 ^ r65; var r77 = 7 * 2; a17 = a42 % a26; var r78 = a45 & 0; var r79 = r33 - a81; bcvljy_0[6] = r61 * r79; var r80 = a58 * 4; var r81 = a85 & a81; var r82 = a30 % 4; var r83 = r47 | a85; var r84 = a33 + r31; var r85 = a86 | r32; var r86 = r59 / a18; var r87 = r86 & 6; var r88 = a20 % a40; a81 = r42 / r0; var r89 = r9 ^ 2; var r90 = 3 * a87; var r91 = a33 | 8; print(r36); var r92 = bcvljy_0[6] ^ r21; var r93 = a87 & r84; var r94 = 5 + a71; var r95 = a63 ^ 2; var r96 = a53 | r36; var r97 = r89 + 4; var r98 = r28 | a75; var r99 = r55 * a64; print(bcvljy_2[0]); var r100 = 7 & 6; var r101 = a47 * a25; a59 = a66 ^ a71; var r102 = 8 % 7; var r103 = 2 + a84; var r104 = r46 + 2; var r105 = bcvljy_2[6] % a27; var r106 = a47 ^ a77; var r107 = r8 + r75; var r108 = r9 | r104; var r109 = r53 - a10; var r110 = r83 / r67; var r111 = 8 & r85; var r112 = 4 - 2; var r113 = r51 + r46; a57 = 8 / a79; a4 = r43 + r79; var r114 = a70 / r77; print(r97); var r115 = r33 % r80; var r116 = a39 - 8; var r117 = a52 - 0; a1 = bcvljy_2[0] * r32; var r118 = r10 / r63; var r119 = r47 % 6; var r120 = 2 * r94; var r121 = r80 | r54; var r122 = a46 ^ r33; var r123 = r94 & r16; var r124 = r89 & a71; var r125 = r18 % r9; var r126 = 6 / 2; var r127 = 0 | 9; var r128 = bcvljy_2[0] + 9; var r129 = 5 * r78; print(a65); r112 = 8 + 6; var r130 = a52 % a75; var r131 = 3 % r62; var r132 = r19 - a32; var r133 = 0 * r104; var r134 = a80 / a32; var r135 = a81 - r117; var r136 = a32 & r9; var r137 = a72 % r43; var r138 = r112 + a52; a45 = a73 ^ 6; var r139 = 5 * 5; var r140 = r106 ^ 5; r80 = r104 % r126; var r141 = 8 & 7; print(r63); var r142 = r24 - a39; print(r107); var r143 = 0 ^ r27; var r144 = a18 * a35; var r145 = a24 & r64; var r146 = r145 ^ r73; var r147 = 0 % a41; r99 = r90 + r9; var r148 = 7 + 1; var r149 = a32 ^ a27; var r150 = r116 | r72; var r151 = r39 + r66; var r152 = r64 | 2; a69 = a56 % a22; var r153 = r69 + 2; var r154 = r57 + r139; var r155 = a57 - bcvljy; a75 = r154 * 5; var r156 = 9 & a11; var r157 = r136 + r76; print(r136); r140 = r111 & 4; r39 = a47 | r34; var r158 = 8 % 9; a72 = a14 % 4; var r159 = 4 / r144; r122 = bcvljy_1 | 8; r102 = a56 % bcvljy_1; var r160 = bcvljy_0 * 9; var r161 = a21 & 4; r138 = 1 * 0; a62 = r58 - 1; var r162 = a78 - r47; a62 = r28 | 6; a59 = 3 % r99; r62 = r120 & r6; a74 = a29 ^ a82; r156 = 7 ^ 5; var r163 = r33 + r129; var r164 = r162 + r11; var r165 = r59 + a82; var r166 = 5 + r127; r153 = 3 * a52; return a76; }), set: (function(j) { if (j) { v0 = evaluate(\"v2 = g1.eval(\\\"print(uneval(t1));\\\");\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: this, catchTermination: \"\\u23B7\" })); } else { v2 = new Number(4); } }) });/*ODP-2*/Object.defineProperty(b0, \"prototype\", { configurable: -13, enumerable: true, get: f2, set: (function() { try { e2.__proto__ = a0; } catch(e0) { } try { for (var v of v1) { try { (let (e=eval) e) } catch(e0) { } try { this.t0 = new Uint16Array(9); } catch(e1) { } g0.a1 = r0.exec(this.s2); } } catch(e1) { } try { m1 = x; } catch(e2) { } s1 += 'x'; return t0; }) });/*RXUB*/var r = /(?=(?!(\uf21b+?)[^]\\d|\\1))|(?=.{2}(?!^^){65536,}[^](?:$)^{4,}|(?!\\B)*?)\\1/yim; var s = \"\"; print(r.test(s)); print(r.lastIndex); function(y) { yield y; o1.s0 + '';; yield y; }/* no regression tests found */");
/*fuzzSeed-157142351*/count=533; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=534; tryItOut("h0.get = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30) { var r0 = a29 * a15; var r1 = a18 ^ a1; a14 = x * 3; var r2 = a22 - a1; var r3 = a21 & a16; var r4 = a25 + a29; var r5 = a5 & 3; var r6 = 4 % a1; var r7 = a24 / r0; var r8 = 7 - a13; a9 = a3 ^ r8; var r9 = 6 + 1; a17 = a0 % a29; var r10 = 6 / a20; var r11 = a1 - a20; var r12 = r7 * a9; var r13 = r0 - a28; var r14 = a16 + a22; var r15 = r11 & r14; var r16 = 1 % 8; var r17 = r13 & a11; a11 = a27 | a2; var r18 = a30 + a3; var r19 = a19 | a5; var r20 = a6 | a15; a3 = 9 | 3; var r21 = a13 + a17; var r22 = a17 + 3; var r23 = r18 | a11; a1 = 4 / a24; var r24 = a30 - 9; var r25 = 1 ^ a20; var r26 = a21 % 7; var r27 = 7 ^ a28; var r28 = 7 / a23; a20 = r5 + r25; var r29 = 6 + 5; var r30 = a11 / 6; var r31 = a8 | 1; var r32 = 2 / r24; var r33 = 0 - r14; var r34 = r15 & a23; var r35 = 8 ^ a6; r9 = 5 ^ r1; var r36 = a8 + r12; a17 = r1 | r23; a15 = r16 ^ r15; var r37 = 0 % r10; var r38 = 6 | a21; var r39 = 0 - 3; var r40 = a5 | x; a27 = a28 | r22; var r41 = a19 ^ a29; var r42 = a11 - r15; var r43 = 1 ^ a2; var r44 = 9 + r18; var r45 = r0 - 0; var r46 = 7 * 9; var r47 = a11 % r19; r16 = 8 + r10; print(r0); var r48 = r37 - r16; var r49 = r43 | r8; var r50 = a25 * r47; a29 = r43 - r35; print(r33); var r51 = 0 % r27; a7 = a2 + a0; var r52 = r33 * 9; var r53 = a12 & 1; var r54 = 5 % a10; r18 = r0 * r7; var r55 = r3 * r30; var r56 = r41 / r49; var r57 = 6 - r7; r20 = a9 | r24; a17 = r56 + a23; var r58 = r52 ^ 6; a7 = 6 & 8; a15 = 1 | r19; a17 = 8 + r5; var r59 = r47 + a24; var r60 = r34 % r14; var r61 = r24 - r53; var r62 = 6 - 8; a7 = r58 ^ a16; var r63 = r30 | r7; var r64 = a24 & r3; a10 = 7 | r42; var r65 = r45 % a12; var r66 = r38 % 2; var r67 = a11 / 6; a14 = a12 % 6; var r68 = r20 & 7; var r69 = r36 & r45; return x; });");
/*fuzzSeed-157142351*/count=535; tryItOut("\"use strict\"; /*oLoop*/for (var bfvusv = 0, bliiaq; bfvusv < 21; ++bfvusv) { /*infloop*/for(var c;  /x/g ;  /x/ ) {Array.prototype.splice.apply(a2, [s0]); } } ");
/*fuzzSeed-157142351*/count=536; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; fullcompartmentchecks(true); } void 0; }");
/*fuzzSeed-157142351*/count=537; tryItOut("(delete e.{x: z});");
/*fuzzSeed-157142351*/count=538; tryItOut("o2.m2.valueOf = URIError;");
/*fuzzSeed-157142351*/count=539; tryItOut("Array.prototype.sort.apply(a2, []);");
/*fuzzSeed-157142351*/count=540; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy4(((Math.cos(y) % (Math.min(((( ~ (( ~ -(2**53+2)) >>> 0)) >>> 0) | 0), (( ~ Math.imul(y, y)) << Math.fround(Math.pow(Math.fround(-1/0), Math.fround(2**53))))) | 0)) >>> 0), (Math.min(( + ((Math.fround(Math.hypot(Math.fround(y), Math.fround(y))) >>> 0) << x)), (( + Math.fround(((( - (( ~ x) >>> 0)) >>> 0) & Math.fround((((Math.acos((( + Math.exp(( + y))) | 0)) | 0) ? ( ~ y) : (Math.acosh((2**53+2 | 0)) | 0)) >>> 0))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [null, (new Boolean(true)), [0], '0', ({valueOf:function(){return 0;}}), /0/, 0, (new Number(0)), undefined, '', [], ({toString:function(){return '0';}}), -0, NaN, (new String('')), objectEmulatingUndefined(), (new Number(-0)), '/0/', (new Boolean(false)), '\\0', 1, false, true, 0.1, ({valueOf:function(){return '0';}}), (function(){return 0;})]); ");
/*fuzzSeed-157142351*/count=541; tryItOut("s0 += s1;");
/*fuzzSeed-157142351*/count=542; tryItOut("v0 = a0.reduce, reduceRight((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1.888946593147858e+22;\n    var i3 = 0;\n    var i4 = 0;\n    return +((d0));\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new ArrayBuffer(4096)), this.i2);");
/*fuzzSeed-157142351*/count=543; tryItOut("h1 + m2;");
/*fuzzSeed-157142351*/count=544; tryItOut("mathy3 = (function(x, y) { return (Math.fround((Math.fround(Math.fround(Math.hypot(0x100000000, (mathy0((( + ( ~ Math.abs(Math.fround((Math.fround(x) > Math.fround(y)))))) | 0), (( + Math.pow((Math.pow(y, Math.fround(y)) >>> 0), (( ! ( + Number.MIN_SAFE_INTEGER)) >>> 0))) | 0)) | 0)))) ? Math.fround(Math.fround(Math.imul(x, ( ~ Math.atan2(y, (Math.clz32((x | 0)) | 0)))))) : Math.fround(Math.tan(( ! x))))) && (mathy2(( - ( + (( + (( + mathy0(( + 0x100000000), ( + x))) >>> 0)) >>> 0))), Math.log1p(Math.fround((Math.fround(-0x080000001) == Math.fround((( + (Math.hypot(Math.cosh(-1/0), x) >>> 0)) >>> 0)))))) >>> 0)); }); testMathyFunction(mathy3, /*MARR*/[0, Infinity, 0, Infinity, 0, Infinity, Infinity, 0, 0, 0, Infinity, 0, 0, Infinity, 0, Infinity, 0, Infinity, 0, Infinity, Infinity, Infinity, 0, Infinity, Infinity, Infinity, Infinity, 0, Infinity, Infinity, 0, Infinity, 0, 0, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, 0, Infinity, 0, Infinity, 0, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, 0, Infinity, 0, Infinity, Infinity, Infinity, 0, 0, Infinity, 0, 0, 0, 0, 0, Infinity, Infinity, 0, 0, Infinity, Infinity, Infinity, Infinity, 0, Infinity]); ");
/*fuzzSeed-157142351*/count=545; tryItOut("mathy5 = (function(x, y) { return mathy4(Math.fround((Math.imul(Math.fround((( ! -(2**53+2)) & x)), Math.fround((( ~ y) >>> 0))) || (((y % Math.cos(( + ( ! Math.fround(( - y)))))) >>> 0) | 0))), (Math.atan2(Math.fround(((Math.imul((mathy2(Math.fround((Math.atan((Number.MIN_SAFE_INTEGER | 0)) | 0)), Number.MIN_SAFE_INTEGER) >>> 0), x) >>> 0) >= Math.sin((( ! Math.fround(y)) >>> 0)))), (Math.min((Math.fround(((( + ((( + Math.asin(-Number.MIN_VALUE)) | 0) == ( + -(2**53-2)))) ** (((mathy1(1/0, y) >>> 0) ? (x >>> 0) : (y >>> 0)) >>> 0)) / (0 <= x))) >>> 0), Math.hypot(Math.PI, Math.imul(Math.fround(Math.pow(Math.fround(x), Math.fround(2**53))), x))) >>> 0)) | 0)); }); testMathyFunction(mathy5, [-0x080000001, 1, -(2**53), Number.MAX_SAFE_INTEGER, -0, 2**53+2, -0x100000000, 0x07fffffff, -0x100000001, 0x0ffffffff, 1/0, -(2**53-2), 0.000000000000001, -1/0, -(2**53+2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 42, 0x080000000, -0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000001, 0x080000001, Math.PI, -0x07fffffff, 0/0, -Number.MIN_VALUE, 0, 2**53]); ");
/*fuzzSeed-157142351*/count=546; tryItOut("h1.getOwnPropertyDescriptor = (function() { try { e0.delete(g0.v1); } catch(e0) { } try { Array.prototype.push.call(a1, i0); } catch(e1) { } try { m0.get(o1.h2); } catch(e2) { } t0 = t0.subarray(x, (4277)); return b1; });");
/*fuzzSeed-157142351*/count=547; tryItOut("v1 = this.a1.length;");
/*fuzzSeed-157142351*/count=548; tryItOut("/*infloop*/for(var a in Math.imul(\"\\u73E2\", -8)) {a0.push(\"\\uF005\" /= Math.log1p(-15), s2, g0, m2); }");
/*fuzzSeed-157142351*/count=549; tryItOut("v2 = -0;");
/*fuzzSeed-157142351*/count=550; tryItOut("\"use strict\"; /*hhh*/function sdwppu(w = this.__defineSetter__(\"e\", decodeURIComponent), b, z, w, c = x, y, y, NaN, x, x, y, x, a, x =  '' , x, \u3056, z, x, x = [z1,,], window, x, x = [1,,], w, \u3056, x = 14, x, a, x = [[1]], x = undefined, a, window, y = Math, eval, this.x, y, x, x =  /x/g , e, x, d = window, x, x, d, x, c, x = window, eval, x, this.a = function ([y]) { }, window, x, c, x, y = x, z = [], x = window, x, e, y, x, d, x = x, e, e = [[1]], w, e, x, eval, c, x, x, e, x, y, b, eval = this, x = -0, x, x){((function(x, y) { \"use strict\"; return (Math.imul(( + Math.expm1(0x080000001)), Math.fround(x)) >>> 0); }))(a = []);}sdwppu(/*UUV1*/(\u3056.has = (function (a) { \"use asm\"; \"\\uA9DE\"; } ).apply));");
/*fuzzSeed-157142351*/count=551; tryItOut("(Math.pow(a, -26));a = eval(\"(void version(185))\", window);");
/*fuzzSeed-157142351*/count=552; tryItOut("\"use strict\"; /*oLoop*/for (let nxhfuq = 0, x; nxhfuq < 42 && ([]); Math.clz32(21), ++nxhfuq) { switch(undefined ? new RegExp(\"(.?|(\\\\W)*)*?\", \"\") :  /x/g ) { case /*RXUE*/new RegExp(\"^\", \"im\").exec([[]]):  } } ");
/*fuzzSeed-157142351*/count=553; tryItOut("mathy5 = (function(x, y) { return (Math.atanh((( + mathy4(Math.acosh(Math.fround(Math.fround(mathy4(Math.fround(x), ((Math.atanh(x) | 0) <= ( + x)))))), Math.max(y, ((y ? x : Math.min(Math.fround(Math.fround(Math.acos(Math.fround(Math.PI)))), Math.fround(x))) | 0)))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[-0x080000000, new Number(1), -0x080000000, -0x080000000, -0x080000000, new Number(1), new Number(1)]); ");
/*fuzzSeed-157142351*/count=554; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.min((mathy1(Math.fround(((( ! x) / (Math.fround(Math.log1p(Math.fround(y))) | 0)) | 0)), x) ? Math.exp(((y | Math.fround((( - y) >>> 0))) >>> 0)) : Math.sinh(mathy1(y, x))), (mathy1(Math.atan2((Math.fround(x) !== Math.fround(( + Math.sin(( + x))))), ( + ( ~ Math.fround(-0x07fffffff)))), (Math.fround((Math.fround(Math.atanh(y)) % Math.fround((( + ( + ( + y))) ? x : Math.fround((Math.fround(Math.fround(Math.hypot(y, x))) ? (Math.pow(x, (y | 0)) >>> 0) : Math.fround(x))))))) ? (Math.ceil((( + Math.max(( + y), (x >>> 0))) >>> 0)) >>> 0) : (( + ( ! (y ** Math.fround(Math.acos(( + y)))))) && (mathy1((y >>> 0), (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))) | 0)); }); testMathyFunction(mathy2, /*MARR*/[-(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), -(2**53), Infinity, objectEmulatingUndefined(), Infinity, Infinity, Infinity, -(2**53), objectEmulatingUndefined(), -(2**53), Infinity, -(2**53), -(2**53), Infinity, Infinity, objectEmulatingUndefined(), -(2**53), Infinity, objectEmulatingUndefined(), -(2**53), Infinity, -(2**53), objectEmulatingUndefined(), Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), -(2**53), Infinity, -(2**53)]); ");
/*fuzzSeed-157142351*/count=555; tryItOut("/*ADP-3*/Object.defineProperty(a1, (function ({}) { \"use strict\"; i0.send(f2); /x/g ;function x(...x) { return Set.prototype.clear } print(x); } ).call(timeout(1800), (yield a), x), { configurable: (x % 46 == 24), enumerable: true, writable: (4277), value: v2 });");
/*fuzzSeed-157142351*/count=556; tryItOut("\"use strict\"; print(this);");
/*fuzzSeed-157142351*/count=557; tryItOut("delete h0.hasOwn;");
/*fuzzSeed-157142351*/count=558; tryItOut("mathy2 = (function(x, y) { return ((Math.imul((((-0x080000000 !== (Math.atan2((-0x07fffffff | 0), (y | 0)) | 0)) && Math.cbrt(( + x))) | 0), ((-Number.MAX_VALUE % (( ! (x | 0)) | 0)) >= x)) | 0) ^ mathy0(( + Math.max(( ~ x), Math.imul(x, 42))), ( + mathy0(Math.pow(x, Math.expm1(( ~ Math.fround(x)))), Math.fround(( ~ x)))))); }); ");
/*fuzzSeed-157142351*/count=559; tryItOut("{ void 0; try { startgc(5498370, 'shrinking'); } catch(e) { } } ( /x/ .unwatch(\"x\"));");
/*fuzzSeed-157142351*/count=560; tryItOut("const w = ((uneval(x)));this.t0[v0];");
/*fuzzSeed-157142351*/count=561; tryItOut("\"use strict\"; /*iii*/v0 = (a0 instanceof f1);/*hhh*/function wwpvpq(x, [], b, x, NaN, x, b, \u3056 =  /x/g , w, w, x = [,], e, y =  \"\" , ...x){print(g1.g2);}");
/*fuzzSeed-157142351*/count=562; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.min((Math.min(( + ((y < y) ? (Math.fround(Math.atan(y)) >>> x) : (y === Math.fround(Math.fround((Math.fround(x) ? Math.fround(-(2**53)) : (x | 0))))))), (Math.min(-0x07fffffff, Math.pow(( - ( ! x)), x)) >>> 0)) >>> 0), (Math.imul(Math.abs((((-(2**53+2) >> x) < Math.fround((( + (y >>> 0)) >>> 0))) | 0)), Math.sinh(( + Math.min(Math.sign((((0.000000000000001 | 0) > (1/0 >>> 0)) >>> 0)), ( + y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x07fffffff, Math.PI, 2**53-2, -0x07fffffff, 0x080000001, -0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -1/0, 2**53, -(2**53), 1, 2**53+2, -0, Number.MAX_VALUE, 0x100000000, 0x0ffffffff, -0x0ffffffff, 0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, 1/0, 42, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, 0, -(2**53+2), -(2**53-2), 0/0, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-157142351*/count=563; tryItOut("\"use strict\"; e1.has(b1);");
/*fuzzSeed-157142351*/count=564; tryItOut("testMathyFunction(mathy2, [0x0ffffffff, -0x080000000, 0x080000001, 2**53, 0x07fffffff, 1, 0x080000000, 0.000000000000001, 2**53-2, 0, -(2**53+2), -(2**53), Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53-2), -0x100000001, 42, -0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, -Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, -0, -1/0, Number.MIN_SAFE_INTEGER, 1/0, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000001, 2**53+2, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=565; tryItOut("\"use strict\"; e2.add(e1);");
/*fuzzSeed-157142351*/count=566; tryItOut(" for (let x of \"\\uA7DD\") e0.has(i1);");
/*fuzzSeed-157142351*/count=567; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.max(Math.fround(Math.abs(Math.fround(( - Math.fround(( + ( ~ (Math.min(Math.pow(x, x), Math.PI) | 0)))))))), Math.fround(( + ((( + (y | 0)) | 0) , Math.fround(( ~ Math.acos(1.7976931348623157e308)))))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 1, 0x100000001, 0x07fffffff, -(2**53), 42, 0x100000000, 1/0, 0x080000000, 0.000000000000001, -(2**53-2), -1/0, 0, 1.7976931348623157e308, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000000, -Number.MIN_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, -0x080000001, 2**53+2, -0x100000001, 0x080000001, Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, 0/0, 2**53-2, 2**53]); ");
/*fuzzSeed-157142351*/count=568; tryItOut("mathy5 = (function(x, y) { return Math.hypot(((( + ( ~ ( + Math.fround(Math.pow(Math.fround((y >= Math.tanh(x))), Math.fround(( - 0.000000000000001))))))) ? Math.fround(Math.sin(y)) : mathy4(x, Number.MIN_VALUE)) >>> 0), Math.ceil((( + (((x >>> 0) ? (x >>> 0) : ((((x | 0) === (( + Math.cbrt(( + -(2**53-2)))) | 0)) | 0) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -Number.MAX_VALUE, -0x07fffffff, Math.PI, -Number.MIN_VALUE, 0x080000001, -1/0, Number.MAX_VALUE, 0, 1.7976931348623157e308, 0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, 0x100000001, 42, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53, -0x100000000, -0, -(2**53-2), 1, -Number.MIN_SAFE_INTEGER, 2**53-2, 0/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, 2**53+2, 1/0, 0x080000000, 0x0ffffffff, -(2**53), 0x07fffffff, -0x080000001]); ");
/*fuzzSeed-157142351*/count=569; tryItOut("\"use strict\"; \"use asm\"; return [,,];for (var p in i1) { try { (void schedulegc(g0)); } catch(e0) { } try { o2.o2.h2.getOwnPropertyDescriptor = f0; } catch(e1) { } try { this.a0.splice(-6, 3); } catch(e2) { } m0.set(o0, f1); }");
/*fuzzSeed-157142351*/count=570; tryItOut("testMathyFunction(mathy4, /*MARR*/[new Number(1.5), function(){}, 0x100000000, 0x100000000, new Number(1.5), 0x100000000, function(){}, 0x100000000,  /x/g , function(){}, function(){},  /x/g , new Number(1.5), function(){}, function(){}, new Number(1.5), 0x100000000, new Number(1.5), new Number(1.5),  /x/g , 0x100000000,  /x/g , 0x100000000, function(){}, 0x100000000,  /x/g ]); ");
/*fuzzSeed-157142351*/count=571; tryItOut("mathy4 = (function(x, y) { return Math.fround((( + (( + mathy2(y, (((-1/0 >>> 0) ? ( + (((Math.fround(y) ^ y) , (x * (x >>> 0))) | 0)) : y) >>> 0))) == (( ~ (Math.fround(( + (Math.min(x, 0x080000001) >>> 0))) >>> 0)) >>> 0))) | Math.fround(( ~ Math.fround(Math.fround(Math.min(Math.fround((( + (Math.sqrt(y) - (Math.pow(( + y), ( + 0)) >>> 0))) ? Math.fround(mathy2(( + x), ( + y))) : Math.sqrt(0x080000000))), Math.fround(y)))))))); }); ");
/*fuzzSeed-157142351*/count=572; tryItOut("window");
/*fuzzSeed-157142351*/count=573; tryItOut("/*RXUB*/var r = /(?:(?!.{3,4}|\\u6D09)*?){4,}[^][^]\\b|^{0}|\\w|([^]\\b)*??*[\\x0e-\\B\\w\\xFC-\\,\\]]|^+/m; var s =  /x/ ; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=574; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=575; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((( - Math.fround((( - (Math.atanh((((Math.imul((-0x100000000 | 0), (x , x)) | 0) | 0) << (y | 0))) | 0)) | 0))) >>> 0) * Math.fround(Math.fround(Math.atan2(Math.fround(( + ( + mathy1(x, ( + y))))), Math.fround((( ~ ( + -0)) ? (((Math.tan((x | 0)) | 0) ** (Math.min((( ! x) >>> 0), y) >>> 0)) >>> 0) : x)))))); }); testMathyFunction(mathy2, [1/0, 0x07fffffff, -0x0ffffffff, -0, -1/0, Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, -0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, -Number.MAX_VALUE, 1, -(2**53+2), 0, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), -0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, 0/0, 0x0ffffffff, -0x080000000, -0x100000001, 42, 0.000000000000001, -Number.MIN_VALUE, 0x100000001, 2**53, 1.7976931348623157e308, -(2**53-2), 2**53+2]); ");
/*fuzzSeed-157142351*/count=576; tryItOut("testMathyFunction(mathy4, [Math.PI, -Number.MAX_SAFE_INTEGER, 0/0, -0x07fffffff, 0.000000000000001, -0x100000001, -(2**53+2), 2**53-2, Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000000, 0x080000000, -Number.MIN_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 42, 1, -0x100000000, -0x0ffffffff, -Number.MAX_VALUE, 1/0, -(2**53-2), 0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 0x100000001, -0x080000001, -(2**53), -1/0, 2**53, -0]); ");
/*fuzzSeed-157142351*/count=577; tryItOut("/*tLoop*/for (let c of /*MARR*/[(-1/0), (-1/0), (-1/0), new String(''), new String(''), new String(''), (-1/0), new String(''), (-1/0), new String(''), new String(''), new String(''), (-1/0), (-1/0), new String(''), new String(''), (-1/0), (-1/0), (-1/0), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (-1/0), (-1/0), new String(''), (-1/0), (-1/0), (-1/0), new String(''), new String(''), (-1/0), (-1/0), new String(''), (-1/0), (-1/0), new String(''), new String(''), new String(''), new String(''), new String(''), (-1/0), (-1/0), (-1/0), new String(''), new String(''), (-1/0), (-1/0), new String(''), (-1/0), (-1/0), new String(''), new String(''), new String(''), (-1/0), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (-1/0), new String('')]) { L:if(true) { if ([z1,,]) {/*MXX3*/g0.Uint8ClampedArray.length = g1.g2.Uint8ClampedArray.length;print( \"\" );\nprint(/\\1/gim);\n }} else v1 = (m0 instanceof v2); }");
/*fuzzSeed-157142351*/count=578; tryItOut("mathy5 = (function(x, y) { return (((Math.fround(Math.max(Math.fround((( + x) | 0)), Math.fround(y))) == Math.pow((( + (x >>> 0)) >>> 0), Math.tanh(y))) * (Math.log1p((mathy1(( + ( + ( + Math.fround(mathy0(x, -(2**53+2)))))), Math.log(Math.fround(Math.fround((Math.fround(( + (( + y) > ( + x)))) >>> Math.fround(x)))))) | 0)) | 0)) >>> 0); }); ");
/*fuzzSeed-157142351*/count=579; tryItOut("v2 = t1.byteOffset;");
/*fuzzSeed-157142351*/count=580; tryItOut("\"use strict\"; print(f0);");
/*fuzzSeed-157142351*/count=581; tryItOut("\"use strict\"; (void options('strict'));");
/*fuzzSeed-157142351*/count=582; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=(?!(?:^+?)|[^\\\\S]|.))(?=[^\\\\s]\\\\b{3}(?:\\\\w)?|[-\\u310c\\\\f-\\\\u0D5C\\\\xD8-\\\\u1D72\\\\S]*?^)|\\ue14e|(?=(?=(?!\\\\b))?)+(?:\\ue1d1)\", \"gy\"); var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=583; tryItOut("\"use strict\"; a1.sort(f0, v2, x, o2.s2, p1, timeout(1800));");
/*fuzzSeed-157142351*/count=584; tryItOut("g2.g2.s0 += s2;");
/*fuzzSeed-157142351*/count=585; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { return (mathy1(Math.hypot(Math.atan2((x >>> 0), Math.expm1(( + 1))), y), ((( + (( + x) | ( + Math.fround(Math.log2(Math.fround(( ! y))))))) | 0) ** Math.fround(Math.pow(Math.fround(( + Math.round(( + Math.fround(Math.min(Math.fround((( ~ (y | 0)) | 0)), Math.fround(x))))))), ( + y))))) >= Math.fround(Math.clz32(Math.sin(Math.fround((x >> Math.fround(y))))))); }); ");
/*fuzzSeed-157142351*/count=586; tryItOut("/*tLoop*/for (let e of /*MARR*/[ \"\" , (-1/0), (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (-1/0), (-1/0), (-1/0),  \"\" , (void 0),  \"\" ,  \"\" , (void 0), (void 0),  \"\" ,  \"\" ,  \"\" , (void 0), (void 0)]) { (1 for (x in [])) }");
/*fuzzSeed-157142351*/count=587; tryItOut("e1.has(e0);");
/*fuzzSeed-157142351*/count=588; tryItOut("\"use strict\"; a0.unshift(e0, a1, s2, new (b)(undefined), b0, a0, g2);");
/*fuzzSeed-157142351*/count=589; tryItOut("x;\u000c\nvar bvtwcq = new ArrayBuffer(16); var bvtwcq_0 = new Uint16Array(bvtwcq); bvtwcq_0[0] = 2; /*MXX2*/o2.g2.Math.abs = this.i0;v1 = (a0 instanceof s1);\n");
/*fuzzSeed-157142351*/count=590; tryItOut("\"use strict\"; throw StopIteration;with({}) arguments;/*MXX3*/g2.Symbol.hasInstance = g1.Symbol.hasInstance;");
/*fuzzSeed-157142351*/count=591; tryItOut("\"use strict\"; switch(x) { \u0009default: print(t2);break; case 2: break; break;  }");
/*fuzzSeed-157142351*/count=592; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return mathy0((Math.fround(Math.max(Math.fround((y >= (-0x0ffffffff / x))), (Math.pow(y, (( ! x) >= (Math.hypot(y, 2**53-2) | 0))) >>> ((Math.sin(0/0) % (x | 0)) | 0)))) < (( + (Math.fround(Math.cosh(Math.asin(mathy0(x, -0x0ffffffff)))) | ( + Math.acosh(( + Math.trunc(x)))))) >>> 0)), (mathy0(( - (mathy0((Math.min((y | 0), (y >>> 0)) >>> 0), (y >>> 0)) <= Math.fround(Math.acosh(x)))), (( + Math.sqrt(( + x))) < Math.hypot(x, x))) > (mathy0(y, (Math.atan((y >>> 0)) >>> 0)) / y))); }); testMathyFunction(mathy1, [/0/, true, 1, (function(){return 0;}), '/0/', '\\0', (new Boolean(false)), ({valueOf:function(){return 0;}}), (new String('')), 0, '', [], 0.1, (new Number(0)), NaN, null, [0], ({toString:function(){return '0';}}), '0', objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), undefined, (new Boolean(true)), (new Number(-0)), false, -0]); ");
/*fuzzSeed-157142351*/count=593; tryItOut("var otilur = new SharedArrayBuffer(4); var otilur_0 = new Float32Array(otilur); otilur_0[0] = 21; var otilur_1 = new Uint8ClampedArray(otilur); var otilur_2 = new Int8Array(otilur); print(otilur_2[0]); var otilur_3 = new Uint32Array(otilur); otilur_3[0] = -20; var otilur_4 = new Uint8Array(otilur); print(otilur_4[0]); otilur_4[0] = -415231105; var otilur_5 = new Uint8ClampedArray(otilur); print(otilur_5[0]); otilur_5[0] = 28; v0 = Object.prototype.isPrototypeOf.call(v0, a2);this.v1 = g0.eval(\"throw \\\"\\\\u5A05\\\";\");Array.prototype.shift.call(a1, true, g0.e2);o0.v0 = g2.eval(\"print(x);\");let (d = \"\\uA66E\", nlrion, get, jdswul, uztxnr, vopnai, oaozff, lprlcm) { g2.h2.toString = (function() { try { o1.i2.toString = (function() { for (var j=0;j<56;++j) { f2(j%2==1); } }); } catch(e0) { } try { a1[15]; } catch(e1) { } try { g2.t2[({valueOf: function() { this.a1 = Array.prototype.slice.apply(g0.a1, [NaN, NaN, t1]);return 19; }})] = t0; } catch(e2) { } a2[4]; return i1; }); }print(a1);window = otilur_3;m0 + t1;(otilur_0[7] <<=  /x/g );for (var p in m2) { f0(this.p2); }");
/*fuzzSeed-157142351*/count=594; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?:(?=(?:[\\\\u00CF-\\u71c2\\\\z\\\\\\u5e4b\\\\W]{4,4})*)?))\", \"y\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-157142351*/count=595; tryItOut("\"use strict\"; m1.delete(t2);");
/*fuzzSeed-157142351*/count=596; tryItOut("/*MXX1*/o1 = g0.Math.LOG2E;");
/*fuzzSeed-157142351*/count=597; tryItOut("mathy0 = (function(x, y) { return ( + ( - ( + Math.cbrt((Math.sin(((Math.atan2(Math.fround(Math.fround(( - ( + Math.expm1(( + y)))))), (-0 >>> 0)) >>> 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [42, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, -(2**53-2), -(2**53+2), -Number.MAX_VALUE, 0, Number.MAX_SAFE_INTEGER, Math.PI, 1/0, -0x0ffffffff, -1/0, 1.7976931348623157e308, 0x100000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000000, 2**53-2, 0.000000000000001, 0x07fffffff, -0x100000001, 1, 2**53+2, 0x100000001, -0, 0/0, 2**53, 0x0ffffffff, 0x080000001, -0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, -0x080000001]); ");
/*fuzzSeed-157142351*/count=598; tryItOut("this.a0 = new Array;\ng1.o1.v0 = g2.runOffThreadScript();\n");
/*fuzzSeed-157142351*/count=599; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.tanh((Math.atan2(( + Math.hypot((Math.ceil(x) | 0), ( + ( + ( + Math.fround(( + x))))))), ((Math.hypot((mathy0(Math.fround(( + mathy0((mathy0(y, x) | 0), (-Number.MAX_VALUE | 0)))), Math.fround(( + Math.ceil((Math.log((mathy0((y >>> 0), 2**53-2) >>> 0)) | 0))))) | 0), x) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-(2**53+2), 0x100000001, 1/0, -(2**53-2), -Number.MAX_VALUE, -0x100000001, -Number.MIN_SAFE_INTEGER, -0, -0x080000001, Number.MAX_VALUE, 2**53+2, Math.PI, 42, -Number.MIN_VALUE, -0x0ffffffff, 0x100000000, 2**53, 0, Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff, 1, 0x080000000, -0x100000000, -0x080000000, 0x07fffffff, 0.000000000000001, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53-2, -1/0, 0/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=600; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.hypot(( + Math.hypot((((((((x ^ (Math.hypot(y, y) | 0)) >>> 0) | 0) < ( + Math.clz32(x))) >>> 0) ? (0.000000000000001 | 0) : Math.fround(y)) >>> 0), Math.pow(x, y))), ( + (Math.fround(( + Math.cbrt(Math.fround(Math.asinh(x))))) | 0)))); }); testMathyFunction(mathy3, [-0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, 1/0, -0x080000001, Number.MIN_VALUE, -0x080000000, -0x100000001, -0, 42, Math.PI, 0x0ffffffff, 0x080000001, -0x100000000, 1.7976931348623157e308, 2**53, 2**53+2, 0/0, -(2**53-2), -0x07fffffff, 0x100000001, 2**53-2, -1/0, -Number.MAX_VALUE, 0x07fffffff, 0x080000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, 0, 0x100000000, -(2**53)]); ");
/*fuzzSeed-157142351*/count=601; tryItOut("let (x) { var lnruhn = new ArrayBuffer(4); var lnruhn_0 = new Int16Array(lnruhn); print(lnruhn_0[0]); lnruhn_0[0] = 23; m1.delete(t0);a1.unshift(v2, this.g0,  '' , a0, s2, t0); }");
/*fuzzSeed-157142351*/count=602; tryItOut("\u000cwhile((x) && 0)let e = ((yield ((decodeURIComponent).call(({a2:z2}), /(?=(?:(?!.\\b))+?){3,68}|(?:(?:(?:\\b[^]{3,514}|\\cE\\w{1,})))/gim, [,])))), gsvmrx, w, window =  \"\" ;g0 + m1;");
/*fuzzSeed-157142351*/count=603; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\b$\", \"yim\"); var s = \"\\n\\n\"; print(r.exec(s)); ");
/*fuzzSeed-157142351*/count=604; tryItOut("/*oLoop*/for (fgcyav = 0, new RegExp(\"\\\\3\", \"im\"); fgcyav < 37; ++fgcyav) { print(Math); } ");
/*fuzzSeed-157142351*/count=605; tryItOut("print(x);");
/*fuzzSeed-157142351*/count=606; tryItOut("i0.__proto__ = g1;\n/*oLoop*/for (var thmyji = 0; thmyji < 28; ++thmyji) { /*MXX3*/g2.String.prototype.bold = g0.String.prototype.bold; } \n");
/*fuzzSeed-157142351*/count=607; tryItOut("mathy3 = (function(x, y) { return ((Math.imul((Math.pow(( + (( + Math.clz32(( + x))) ** ( + Math.cbrt(y)))), Math.atan2(( - x), Math.fround((( + Math.round(( + (Math.log((x >>> 0)) >>> 0)))) || 2**53-2)))) | 0), (Math.log2(((mathy1(( + 42), Math.PI) | 0) | 0)) >>> 0)) | 0) ** (Math.imul(( + mathy0(Math.fround(Math.imul(x, y)), -Number.MIN_SAFE_INTEGER)), Math.clz32((((y | 0) ? -0x100000001 : ( + mathy1((0x080000000 >>> 0), (((y >>> 0) === x) >>> 0)))) | 0))) | 0)); }); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0, -0x100000000, -0x0ffffffff, 1.7976931348623157e308, -(2**53-2), 0/0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -0x100000001, Number.MIN_VALUE, 0x07fffffff, 0x080000001, 42, 0x100000001, -(2**53+2), -1/0, 0x100000000, Math.PI, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, 2**53, -0x080000001, 0.000000000000001, 1/0, 1, 0x0ffffffff, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, 0]); ");
/*fuzzSeed-157142351*/count=608; tryItOut("print(x);function x(a) { return NaN%=-3 } continue ;function x(window, d = (Math.sin(3)), ...x)xs1 += 'x';");
/*fuzzSeed-157142351*/count=609; tryItOut("/*ODP-3*/Object.defineProperty(t2, \"call\", { configurable: true, enumerable: (x % 2 == 1), writable: false, value: this.o2 });");
/*fuzzSeed-157142351*/count=610; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( + (( + (Math.fround(Math.min(Math.fround(( + (( + Math.expm1(x)) ** ( + Math.log10(x))))), Math.fround(-0))) ? ( + ( ! (x % (y >>> 0)))) : (x && ((( ! (y >>> 0)) >>> 0) | 0)))) << ( + Math.pow(( + ( - Math.fround(Math.sign(Math.fround(x))))), (( + ( + (( + Math.atanh(y)) ? ( + (( ~ (x | 0)) | 0)) : y))) ? Math.fround(Math.atan2(( + y), 1)) : Math.clz32((Math.pow((x >>> 0), (x >>> 0)) | 0))))))) ? Math.exp(Math.fround(Math.abs((Math.fround(Math.min(Math.fround(y), Math.fround(y))) | 0)))) : (Math.asinh((((Math.log((Math.hypot(Math.sign(y), -Number.MIN_SAFE_INTEGER) | 0)) | 0) % Math.asinh(0.000000000000001)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-157142351*/count=611; tryItOut("v0 = evalcx(\"v0 = Object.prototype.isPrototypeOf.call(this.o1, i0);\", g2);");
/*fuzzSeed-157142351*/count=612; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.fround(Math.abs(Math.fround(( + 0.000000000000001)))) / ((mathy0(Math.asinh((Math.atan2(y, y) <= -Number.MIN_VALUE)), (((x | y) % (Math.imul((x >>> 0), 0/0) >>> 0)) | 0)) + ((Math.hypot(y, y) >>> 0) , (Math.max(mathy0(-0x0ffffffff, (Math.fround(Math.hypot(0, y)) | 0)), Math.tanh(x)) >>> 0))) >>> 0)); }); testMathyFunction(mathy1, [0x080000001, -(2**53+2), -0x100000001, 1/0, 1, 2**53+2, -1/0, -0x080000001, 0, 0x07fffffff, 0.000000000000001, -Number.MIN_VALUE, -0x07fffffff, 42, Number.MIN_SAFE_INTEGER, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, Number.MIN_VALUE, 2**53, -0, 0x100000001, -0x080000000, 0x0ffffffff, -Number.MAX_VALUE, -0x0ffffffff, 0/0, 0x080000000, 0x100000000]); ");
/*fuzzSeed-157142351*/count=613; tryItOut("\"use strict\"; m2 + '';\n/* no regression tests found */\na2.sort(b1);");
/*fuzzSeed-157142351*/count=614; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.min((Math.atanh(((( + x) == ( + Math.log(mathy0((Math.atan2((x | 0), x) | 0), ( + ( - -0x080000001)))))) >>> 0)) >>> 0), (Math.asinh((((Math.expm1((Math.min(((x ? x : -(2**53)) >>> 0), x) >>> 0)) | 0) <= mathy0(Math.min((x | 0), y), y)) | 0)) | 0)); }); testMathyFunction(mathy1, [-0x100000001, -0, -0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, 1, 42, -(2**53+2), 2**53+2, 1.7976931348623157e308, 0x0ffffffff, -1/0, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, 1/0, 2**53, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 0/0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 0x080000001, 0, -0x100000000, -0x080000000, 0x080000000, Math.PI, -0x07fffffff, -(2**53)]); ");
/*fuzzSeed-157142351*/count=615; tryItOut("/*iii*//*iii*/i1 = new Iterator(b2);/*hhh*/function jczwjo(NaN, y){i1.send(s1);}/*hhh*/function jlpyvy(y){a0.unshift(b2, ([x] = (e = (x) = y)));}");
/*fuzzSeed-157142351*/count=616; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ((Math.log1p(((x , x) | 0)) | 0) || (mathy2(( + ( - mathy0(Math.sin(Math.acos(( + x))), ( + (( + (Math.acosh((x >>> 0)) >>> 0)) && ( + ((y >>> 0) > Math.fround(Math.abs(x))))))))), ( + Math.fround(((Math.expm1(-0x100000000) >>> 0) % mathy3(( ~ Math.fround((( + -1/0) << x))), (y || Math.fround((Math.hypot(y, y) >>> 0)))))))) >>> 0)); }); testMathyFunction(mathy5, [-(2**53-2), 2**53, -0x080000001, -0x100000001, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1, -0x100000000, 1/0, 0x07fffffff, -0, 2**53+2, -(2**53+2), Number.MIN_VALUE, -0x080000000, 42, 0, 0x100000001, 0x080000000, 1.7976931348623157e308, -(2**53), 0x0ffffffff, 0x080000001, -Number.MAX_VALUE, 0x100000000, Math.PI, 0.000000000000001, Number.MAX_VALUE, -1/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-157142351*/count=617; tryItOut("mathy4 = (function(x, y) { return ( + mathy1(( + Math.fround(Math.sinh(Math.fround(Math.imul(-Number.MAX_SAFE_INTEGER, (((((y | 0) | (x | 0)) | 0) <= Math.min(( + x), (( ~ 2**53-2) >>> 0))) | 0)))))), ( + ((((Math.atan2((x >>> 0), x) >>> 0) == (Math.fround(Math.pow(Math.fround(Math.log10(y)), y)) >>> 0)) >>> 0) ? mathy1(0x0ffffffff, ((y ^ Math.acosh(x)) | ((-Number.MAX_SAFE_INTEGER | 0) << (x ? (( + (y | 0)) | 0) : (y | 0))))) : ((( + ( + Math.expm1(Math.fround(x)))) | 0) >>> 0))))); }); testMathyFunction(mathy4, [-(2**53), -0, 0x07fffffff, -Number.MIN_VALUE, 0x0ffffffff, 0/0, 0x080000001, -0x080000000, 1, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1/0, 1.7976931348623157e308, -0x100000001, -0x080000001, -0x100000000, Number.MIN_SAFE_INTEGER, 0, Math.PI, -(2**53+2), 2**53, Number.MAX_SAFE_INTEGER, -1/0, 0x100000000, 2**53-2, 0x080000000, -0x07fffffff, -(2**53-2), 2**53+2, -0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, 42]); ");
/*fuzzSeed-157142351*/count=618; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (((d0)) * ((Float32ArrayView[1])));\n    return +((((d0)) % ((d1))));\n  }\n  return f; })(this, {ff: Object.prototype.__defineSetter__}, new ArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[x, x, Infinity, Infinity, x, Infinity, Infinity, x, x, {x:3}, x, ({x:3}), Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, x, {x:3}, {x:3}, {x:3}, Infinity, x, x, x, Infinity, {x:3}, x, Infinity, x, {x:3}, {x:3}, {x:3}, ({x:3}), Infinity, Infinity, Infinity, {x:3}, Infinity, x, Infinity, Infinity, Infinity, {x:3}, Infinity, x, Infinity, Infinity, {x:3}, {x:3}, {x:3}, ({x:3}), ({x:3}), ({x:3}), {x:3}, {x:3}, x, x, Infinity, x, {x:3}, {x:3}, Infinity, x, {x:3}, {x:3}, {x:3}, x, {x:3}, Infinity, Infinity, Infinity, x, Infinity, x, {x:3}, Infinity, Infinity, ({x:3}), Infinity, {x:3}, {x:3}, ({x:3}), {x:3}, ({x:3}), {x:3}, ({x:3}), ({x:3}), ({x:3})]); ");
/*fuzzSeed-157142351*/count=619; tryItOut("\"use strict\"; o2 = {};");
/*fuzzSeed-157142351*/count=620; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return [[]] = y; }); testMathyFunction(mathy2, [-0x100000000, 1/0, Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), 0/0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, -0x07fffffff, 0x100000000, 2**53, -(2**53+2), Math.PI, 0, 42, 0x080000001, 1.7976931348623157e308, 0x100000001, -(2**53), 0x07fffffff, 0x0ffffffff, -0, -Number.MIN_VALUE, 2**53+2, 2**53-2, 0.000000000000001]); ");
/*fuzzSeed-157142351*/count=621; tryItOut("mathy4 = (function(x, y) { return Math.hypot(Math.expm1((Math.round((Math.min(42, x) >>> 0)) >>> 0)), Math.sqrt(( - -0x100000001))); }); testMathyFunction(mathy4, [1.7976931348623157e308, 0x080000000, 0x0ffffffff, -1/0, -0x080000000, Math.PI, 2**53-2, -0x07fffffff, 0x100000000, 1, 0/0, 0x100000001, 2**53, -Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, -(2**53), Number.MAX_VALUE, -0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x100000000, 0.000000000000001, -0, -(2**53-2), 42, -(2**53+2), 0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, 0, -0x100000001]); ");
/*fuzzSeed-157142351*/count=622; tryItOut("let(b = delete x.b, x =  \"\" , c =  /x/g , lwyzxg, x = e|= \"\" , eval, NaN, prsxql, doxunn) ((function(){x = of;})());");
/*fuzzSeed-157142351*/count=623; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround(( + Math.asinh((( + mathy0(( + x), ( + Math.exp((-Number.MIN_SAFE_INTEGER ? y : y))))) | 0)))) & ( + Math.min((( ~ (-0x100000000 >>> 0)) >>> 0), ( + Math.log2(( + Math.pow((( ~ x) | 0), Math.fround(( + Math.fround((Math.fround((( - (y | 0)) | 0)) && y)))))))))))); }); testMathyFunction(mathy1, [-0x100000001, Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MAX_VALUE, -0, 1/0, Number.MIN_VALUE, -(2**53+2), -0x100000000, 0.000000000000001, Math.PI, -(2**53-2), 1.7976931348623157e308, 2**53, -0x080000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, 42, 0/0, Number.MIN_SAFE_INTEGER, 0x080000000, -1/0, -Number.MIN_VALUE, 0x100000001, -0x0ffffffff, 0x0ffffffff, 2**53-2, 0, 0x100000000, 1, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53)]); ");
/*fuzzSeed-157142351*/count=624; tryItOut("switch(this.__defineSetter__(\"d\", () =>  { \"use strict\"; print(11); } )) { default: break;  }");
/*fuzzSeed-157142351*/count=625; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (Math.log10(Math.fround((Math.sin((Math.max(( + (( + x) || ( + (mathy0(Math.fround(Math.sign(0)), x) >>> 0)))), ( + Math.fround(( + (Math.asin(Math.fround(x)) >>> 0))))) >>> 0)) | 0))) | 0); }); testMathyFunction(mathy1, /*MARR*/[]); ");
/*fuzzSeed-157142351*/count=626; tryItOut("\"use strict\"; v0 = evaluate(\"s1 += 'x';\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: x, sourceIsLazy: true, catchTermination: (x % 74 != 0), element: g2.o0, sourceMapURL: s2 }));");
/*fuzzSeed-157142351*/count=627; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return mathy2((Math.atan2(((Math.fround((Math.min((Math.acosh(x) | 0), (x | 0)) | 0)) , Math.fround((( ~ (Math.fround(mathy2(Math.fround(x), y)) | 0)) | 0))) | 0), (Math.fround(((1 * Math.atan2((y >>> 0), (Math.hypot(-0x100000000, y) >>> 0))) <= x)) ? (y / Math.asinh(-1/0)) : x)) | 0), mathy0(( ! Math.max(((y >>> 0) ? (( + 42) >>> 0) : (y >>> 0)), x)), Math.sinh(((mathy0((Math.PI >>> 0), Math.fround((x === ( + x)))) >>> 0) % ((( - Math.fround(Math.atan(( + y)))) | 0) * x))))); }); testMathyFunction(mathy3, [Math.PI, Number.MIN_VALUE, -0x080000001, 0x080000001, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1, -1/0, 2**53, 2**53-2, 0x100000000, -0x0ffffffff, -0, 1.7976931348623157e308, -(2**53), -0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 42, 0.000000000000001, -Number.MIN_VALUE, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 0, -0x07fffffff, 0x07fffffff, 1/0, 0x100000001, 0/0, 0x080000000]); ");
/*fuzzSeed-157142351*/count=628; tryItOut("/*RXUB*/var r = /\\s*/gyim; var s = \"aaaaaaaa0a\"; print(s.search(r)); ");
/*fuzzSeed-157142351*/count=629; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, 0x100000001, 0x07fffffff, 1, Math.PI, 0x080000001, -Number.MIN_VALUE, -0x100000000, Number.MAX_VALUE, 0x080000000, -0x080000001, 42, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0, 2**53, 0, -(2**53), Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -0x080000000, 2**53+2, -0x07fffffff, 2**53-2, Number.MIN_VALUE, -0x0ffffffff, 1/0, -Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-157142351*/count=630; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.acos((Math.imul((( + (( + x) & (y >>> 0))) | 0), (Math.imul((Math.sinh(y) | 0), (Math.clz32(((x , ( + y)) >>> 0)) | 0)) | 0)) >>> 0)); }); testMathyFunction(mathy0, [-0x080000000, -Number.MIN_SAFE_INTEGER, 1, -(2**53+2), 2**53+2, 0x0ffffffff, -0x100000000, 0/0, -(2**53-2), 42, 0x100000000, -0x100000001, -0x07fffffff, Number.MAX_VALUE, 2**53, -0, Math.PI, 0.000000000000001, 0x080000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, Number.MIN_VALUE, 2**53-2, 0x07fffffff, -(2**53), 1.7976931348623157e308, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, 1/0, 0, -0x0ffffffff, -1/0]); ");
/*fuzzSeed-157142351*/count=631; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = /(\\u7f2b[^\\s\udfba-\ufe7d\u00bf\\d]+(?:[^])|.{2,}{1,5}|(?:(?:(\\B)))|(?=[^\\cK-\\\u0233])[^\\w\\w\\w\\u0005-\u008c]\\b{0,32767}{0,0}).\\bw.*|[^]|[\\uE667\\u0045\\u8692\u1ed9]*(?=^{3,6}){0,3}|^{4,}?/gyi; var s = \"\"; print(r.test(s)); function eval(y)xo1.v1 = Object.prototype.isPrototypeOf.call(g0, o2.f1);");
/*fuzzSeed-157142351*/count=632; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a1, [(Array.prototype.join),  '' , a0, v0, s2]);");
/*fuzzSeed-157142351*/count=633; tryItOut("\"use asm\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (({\u3056: []} = x));\n    return +((-0.0009765625));\n  }\n  return f; })(this, {ff: (\u3056, e) =>  { yield this.x == this } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0/0, 0x07fffffff, 0x0ffffffff, -(2**53-2), -0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, 0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53, -0x100000000, 0, 0.000000000000001, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, 0x100000000, -0x100000001, -0, -(2**53), -0x0ffffffff, 1/0, -0x080000000, 42, 2**53+2, Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), 0x080000000]); ");
/*fuzzSeed-157142351*/count=634; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=635; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.fround(((mathy2((Math.imul((((-Number.MAX_VALUE >>> 0) - ( + y)) >>> 0), (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0), ((( ~ Math.fround(y)) >>> 0) | 0)) ? ( + mathy2(Math.hypot((Math.sin((x | 0)) | 0), y), ((Math.hypot(y, ( + ( + mathy1(( + -Number.MAX_SAFE_INTEGER), ( + Math.min(y, ( + y))))))) >>> 0) ^ ((((mathy0(y, x) >>> 0) | 0) / Math.fround(0.000000000000001)) | 0)))) : Math.log10(x)) >>> 0))); }); testMathyFunction(mathy3, [0x080000000, 1, -(2**53+2), 1.7976931348623157e308, 0x100000001, -(2**53-2), -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0, 0x080000001, 0x0ffffffff, 42, -Number.MAX_VALUE, 0/0, 2**53-2, -0x100000001, -1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), 2**53+2, 2**53, 1/0, -0x080000001, -0, -0x07fffffff, 0x100000000]); ");
/*fuzzSeed-157142351*/count=636; tryItOut("for (var v of o2) { try { v1 = Object.prototype.isPrototypeOf.call(p1, this.e2); } catch(e0) { } a1.forEach((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((((0xf87407d6)-(0xdae2744f))>>>(-(0xeee018ec))))+((0x94f51ca))))|0;\n  }\n  return f; })(this, {ff: a =>  { v1 = a0.length; } }, new SharedArrayBuffer(4096))); }");
/*fuzzSeed-157142351*/count=637; tryItOut("\"use strict\"; t1.set(t1, 0);\n for  each(var w in \"\\u412C\") Map.prototype.delete\n");
/*fuzzSeed-157142351*/count=638; tryItOut("/*tLoop*/for (let b of /*MARR*/[null, (void 0), objectEmulatingUndefined()]) { Object.seal(i0); }");
/*fuzzSeed-157142351*/count=639; tryItOut("\"use strict\"; {}var x = this;");
/*fuzzSeed-157142351*/count=640; tryItOut("yield x;/*oLoop*/for (gegpin = 0; gegpin < 89; ++gegpin) { h1.defineProperty = (function() { for (var j=0;j<52;++j) { this.f1(j%2==1); } }); } ");
/*fuzzSeed-157142351*/count=641; tryItOut("\"use strict\"; this.s0 += s2;");
/*fuzzSeed-157142351*/count=642; tryItOut("\"use strict\"; s2.__proto__ = i0;");
/*fuzzSeed-157142351*/count=643; tryItOut("\"use strict\"; for (var v of v2) { try { m1.has(a2); } catch(e0) { } try { h2.get = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64, a65, a66, a67, a68, a69) { a37 = a44 / a27; var r0 = 7 | a20; a34 = 4 * a30; var r1 = a6 % a50; a30 = a23 - 3; var r2 = a53 - 1; var r3 = 4 / a49; var r4 = a68 - a53; var r5 = 8 / a3; var r6 = 4 / 3; var r7 = a12 ^ a40; a5 = x & 5; var r8 = a57 - a32; a65 = a50 | 9; a24 = 1 * 8; var r9 = a34 ^ 1; var r10 = r1 | a59; var r11 = a4 & 4; a34 = a15 ^ a44; var r12 = a54 / a55; var r13 = a38 * a60; var r14 = r12 % a27; print(a61); return a0; }); } catch(e1) { } g1.m1 = new WeakMap; }");
/*fuzzSeed-157142351*/count=644; tryItOut("{ void 0; minorgc(true); } a1.splice(NaN, 19, i2, o1.i1, o1.f1, x);");
/*fuzzSeed-157142351*/count=645; tryItOut("\"use strict\"; let (w) { o1.v1 = new Number(h0); }");
/*fuzzSeed-157142351*/count=646; tryItOut("\"use strict\"; a2.splice(NaN, this.v1, (Math.round(Math.pow(-6, /*MARR*/[objectEmulatingUndefined(),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , objectEmulatingUndefined(),  \"\" ,  \"\" ,  \"\" ,  \"\" , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  \"\" ].filter(function (eval, this.b)\"use asm\";   var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var cos = stdlib.Math.cos;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    {\n      {\n        return +((d1));\n      }\n    }\n    d1 = (+atan2((((NaN))), ((+cos(((d1)))))));\n    return +((d1));\n  }\n  return f;).__defineSetter__(\"d\", function(y) { \"use strict\"; return [,,z1] })))));");
/*fuzzSeed-157142351*/count=647; tryItOut("mathy0 = (function(x, y) { return (Math.pow((Math.fround(((( + (x | 0)) | 0) >>> (Math.min((y >>> 0), (((Math.min(y, ((Math.log((0x100000001 >>> 0)) >>> 0) >>> 0)) >>> 0) != ( + Math.atan2(( + x), x))) >>> 0)) >>> 0))) | 0), ((Math.pow(Math.atan2(Math.fround(( + Math.fround(0x07fffffff))), y), Math.max(x, Math.fround(Math.pow((y >>> 0), Math.fround((Math.imul((x | 0), (x | 0)) | 0)))))) / Math.atan(x)) | 0)) | 0); }); testMathyFunction(mathy0, [({valueOf:function(){return 0;}}), true, 1, undefined, '\\0', (new String('')), '', objectEmulatingUndefined(), '/0/', 0, (new Number(0)), (function(){return 0;}), (new Boolean(false)), ({toString:function(){return '0';}}), 0.1, '0', ({valueOf:function(){return '0';}}), false, [0], (new Boolean(true)), NaN, -0, (new Number(-0)), [], /0/, null]); ");
/*fuzzSeed-157142351*/count=648; tryItOut("mathy1 = (function(x, y) { return ((Math.fround(( ! Math.fround(mathy0(mathy0(y, x), y)))) == (Math.pow((mathy0((y | 0), (Math.asinh(y) | 0)) | 0), Math.tanh(( - x))) >>> 0)) == ( + Math.min(Math.log10((Math.pow((( - ((Math.sin(Math.fround((( + y) | 0))) | 0) >>> 0)) >>> 0), ( + Math.log((( ! x) | 0)))) >>> 0)), ( ~ ((( + Math.max(2**53+2, y)) ^ ( + (( ~ (x | 0)) | 0))) >>> 0))))); }); testMathyFunction(mathy1, [-0x07fffffff, 0/0, Math.PI, 0x080000000, 0x100000000, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 42, -Number.MIN_VALUE, -(2**53), -0x080000001, -Number.MAX_VALUE, 1.7976931348623157e308, 0x0ffffffff, 2**53-2, -0x080000000, 0x100000001, 2**53, Number.MIN_SAFE_INTEGER, 0, 1, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), 1/0, 0x080000001, -0x100000000, Number.MIN_VALUE, -(2**53+2), -0, 2**53+2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x100000001]); ");
/*fuzzSeed-157142351*/count=649; tryItOut("g2.v2 = (this.e0 instanceof p2);");
/*fuzzSeed-157142351*/count=650; tryItOut("\"use strict\"; (/*UUV1*/(x.blink\u0009 = Date.prototype.getUTCMinutes));");
/*fuzzSeed-157142351*/count=651; tryItOut("print(g1.b1);");
/*fuzzSeed-157142351*/count=652; tryItOut("mathy2 = (function(x, y) { return (((Math.fround(Math.trunc(Math.fround(x))) % ( + (( + Number.MAX_SAFE_INTEGER) ? mathy0((Math.asin((( - 2**53+2) | 0)) | 0), y) : ( + x)))) / ( + ( + Math.abs(( + 2**53+2))))) <= (( ! (( + Math.clz32(( + (mathy1((x >>> 0), (x >>> 0)) >>> 0)))) || ( ~ y))) >= ( ~ y))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, 0x100000000, 0.000000000000001, 42, -0x080000000, Number.MIN_VALUE, 0, -0x100000001, 1, 0x0ffffffff, -0, Math.PI, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, 0x100000001, 2**53+2, -0x080000001, 0/0, 0x07fffffff, 0x080000000, 1/0, -0x0ffffffff, 0x080000001, -(2**53), Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=653; tryItOut("for (var p in p1) { try { e2.add(f0); } catch(e0) { } try { /*RXUB*/var r = r1; var s = g0.s0; print(s.split(r));  } catch(e1) { } try { m1.has(o2.t2); } catch(e2) { } e0.add(i2); }");
/*fuzzSeed-157142351*/count=654; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.tanh(( + mathy0(Math.fround(( - y)), ( - Math.tanh(y))))); }); testMathyFunction(mathy3, [-0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53), 0x100000000, 0, 0x080000001, -(2**53+2), 2**53, 2**53+2, -0x100000000, 0x07fffffff, 1/0, Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -(2**53-2), -0x07fffffff, -0x100000001, 0/0, 1, 0.000000000000001, Number.MIN_VALUE, 42]); ");
/*fuzzSeed-157142351*/count=655; tryItOut("\"use strict\"; h0 = {};");
/*fuzzSeed-157142351*/count=656; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy1(((Math.pow((( + ( + ( + Math.log10(Math.acosh((( - 2**53+2) | 0)))))) >>> 0), ((Math.ceil(Math.fround(Math.min(x, 0/0))) | 0) >>> 0)) >>> 0) | 0), (Math.asinh(( ! Math.tanh((( - Math.PI) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy3, [0x0ffffffff, -0x100000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1, -0, 2**53+2, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x080000001, Number.MIN_VALUE, -0x080000000, -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, Math.PI, -0x0ffffffff, 0x100000001, 2**53-2, -0x080000001, -Number.MIN_VALUE, -1/0, 2**53, 42, 0.000000000000001, 0/0, 0, 1.7976931348623157e308, -(2**53), -(2**53+2), 1/0]); ");
/*fuzzSeed-157142351*/count=657; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( ! (((Math.imul(x, Math.fround((Math.fround(Math.fround(Math.max(Math.fround(x), Math.fround((Math.atan(y) >>> 0))))) ? y : Math.fround(Math.min(( + y), Math.fround(y)))))) ? Math.log(Math.hypot(x, Math.tanh((y >>> 0)))) : (Math.tan(( + Math.max(( + y), ( + Math.fround((Math.fround(Math.ceil(((Math.fround(y) % Math.fround(x)) >>> 0))) > Math.fround(0x100000001))))))) >>> 0)) >>> 0) | 0)); }); testMathyFunction(mathy5, [0x080000001, 0x100000001, 0.000000000000001, 1/0, 0/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -0x100000001, 0x100000000, -(2**53-2), Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, Math.PI, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, -1/0, 0, 2**53, -0, 2**53+2, 0x07fffffff, 0x0ffffffff, 2**53-2, -(2**53), Number.MIN_VALUE, -(2**53+2), -0x080000000, 42, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, 1]); ");
/*fuzzSeed-157142351*/count=658; tryItOut("a0 + m1;");
/*fuzzSeed-157142351*/count=659; tryItOut("(x);");
/*fuzzSeed-157142351*/count=660; tryItOut("h0.hasOwn = f0;");
/*fuzzSeed-157142351*/count=661; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.max((Math.round((Number.MAX_SAFE_INTEGER ? Number.MAX_VALUE : ( + Math.atan2(y, Math.fround(x))))) >>> 0), (Math.asin(Math.hypot(0/0, ( + -0))) | ( + Math.sign(Math.fround(x))))) | 0); }); ");
/*fuzzSeed-157142351*/count=662; tryItOut("\"use strict\"; /*MXX2*/g0.Int16Array.BYTES_PER_ELEMENT = b0;");
/*fuzzSeed-157142351*/count=663; tryItOut("\"use strict\"; nbjccb, x = (void version(185)), euvxpn, a, x;true.valueOf(\"number\") **= ((eval).call(undefined, arguments));");
/*fuzzSeed-157142351*/count=664; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.min(Math.hypot(Math.fround((Math.fround((x - (y * x))) % Math.fround(Math.atan2(Math.tan((Math.hypot(mathy0(x, 0x100000001), 0x080000000) >>> 0)), (Math.atan2((x >>> 0), (y >>> 0)) >>> 0))))), mathy0(Math.hypot(((x / Math.min(42, y)) >>> 0), (Math.atan2(( + y), (x | 0)) >>> 0)), ( - (( + ( + (( + -0x100000000) ? (x >>> 0) : (-0 >>> 0)))) | 0)))), Math.atan2(mathy0(( + ( - Math.min(x, ( + ( - y))))), ( + y)), (( ~ Math.fround(Math.round(Math.atan(( + ( ! ( + x))))))) | 0))); }); testMathyFunction(mathy3, [-(2**53+2), -0x080000001, -0, -0x080000000, 0x100000001, -1/0, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, 2**53-2, -0x0ffffffff, -Number.MIN_VALUE, 0.000000000000001, 1/0, 2**53+2, -(2**53), -(2**53-2), 0, 0/0, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, Math.PI, 0x080000001, -0x100000001, -Number.MAX_VALUE, 42, 1, Number.MIN_VALUE, 0x080000000]); ");
/*fuzzSeed-157142351*/count=665; tryItOut("\"use strict\"; t2 = t2.subarray(({valueOf: function() { this.__defineGetter__(\"x\", x);return 3; }}), 12);");
/*fuzzSeed-157142351*/count=666; tryItOut("testMathyFunction(mathy5, [false, NaN, null, '0', 1, objectEmulatingUndefined(), -0, '', '\\0', ({toString:function(){return '0';}}), (new Boolean(false)), [], true, (new Number(0)), undefined, 0, /0/, (new Boolean(true)), ({valueOf:function(){return 0;}}), [0], ({valueOf:function(){return '0';}}), (function(){return 0;}), 0.1, '/0/', (new Number(-0)), (new String(''))]); ");
/*fuzzSeed-157142351*/count=667; tryItOut("/*infloop*/ for (window of x) {Array.prototype.shift.apply(a0, []); }");
/*fuzzSeed-157142351*/count=668; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (void version(170)); }); testMathyFunction(mathy4, /*MARR*/[ '\\0' , undefined,  '\\0' , undefined, undefined, Infinity, undefined,  '\\0' ,  '\\0' , Infinity, Infinity, undefined, Infinity, undefined, undefined, undefined, Infinity, (void 0), Infinity, Infinity, (void 0),  '\\0' ,  '\\0' , (void 0), undefined, (void 0), Infinity, undefined, (void 0),  '\\0' , Infinity, (void 0), (void 0), (void 0), undefined, Infinity, undefined,  '\\0' , undefined, Infinity, Infinity, undefined,  '\\0' , Infinity,  '\\0' , (void 0), (void 0), Infinity, Infinity,  '\\0' , (void 0), Infinity,  '\\0' , Infinity, undefined, Infinity, (void 0), undefined,  '\\0' , Infinity, (void 0), undefined,  '\\0' , (void 0), undefined, (void 0), undefined, undefined, Infinity,  '\\0' , (void 0)]); ");
/*fuzzSeed-157142351*/count=669; tryItOut("let x = (Function)([]), x = let (wcoqrn, ziauwv, x, utvdfa, x) x = c, a = Math.ceil(-19), b;v1 = false;");
/*fuzzSeed-157142351*/count=670; tryItOut("/*RXUB*/var r = /(\\w[^\\cY\u108c\\w]\\w{0,3})|.{2}|.|$/gyi; var s = window; print(s.search(r)); ");
/*fuzzSeed-157142351*/count=671; tryItOut("mathy4 = (function(x, y) { return (Math.trunc((((( - ( + (Math.acos((y >>> 0)) >>> 0))) | 0) ? Math.sqrt(( + (( + Math.fround(Math.min((( ! -0x100000000) | 0), Math.fround(y)))) && x))) : Math.fround(Math.fround(Math.min(Math.fround(Math.hypot(Math.fround((( + Math.imul(x, ( + x))) - y)), mathy1(y, x))), Math.fround(0x100000000))))) | 0)) | 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0x100000001, 2**53-2, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000000, 0x0ffffffff, -(2**53), -0x07fffffff, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 0, 1, -Number.MAX_VALUE, -(2**53+2), Math.PI, -0x100000001, 0x080000000, 2**53+2, 0.000000000000001, -0x080000001, -0, 1/0, 0x07fffffff, -Number.MIN_VALUE, -0x080000000, 42, 1.7976931348623157e308, Number.MAX_VALUE, 0/0, -1/0]); ");
/*fuzzSeed-157142351*/count=672; tryItOut("\"use asm\"; testMathyFunction(mathy1, [1.7976931348623157e308, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 2**53+2, 0x100000000, 1/0, -(2**53+2), 0.000000000000001, -0x080000001, 0, -0x0ffffffff, 42, Math.PI, -0x080000000, 0x07fffffff, -1/0, 1, Number.MAX_VALUE, 0x100000001, -0, -(2**53), 0/0, -0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=673; tryItOut("\"use strict\"; function f2(i2) d = i2");
/*fuzzSeed-157142351*/count=674; tryItOut("a2.sort(f0);");
/*fuzzSeed-157142351*/count=675; tryItOut("var tqqspq = new ArrayBuffer(4); var tqqspq_0 = new Int16Array(tqqspq); tqqspq_0[0] = 23; var tqqspq_1 = new Uint8ClampedArray(tqqspq); print(tqqspq_1[0]); var tqqspq_2 = new Uint32Array(tqqspq); tqqspq_2[0] = 5; var tqqspq_3 = new Float32Array(tqqspq); tqqspq_3[0] = 21; var tqqspq_4 = new Int16Array(tqqspq); print(tqqspq_4[0]); var tqqspq_5 = new Uint8ClampedArray(tqqspq); tqqspq_5[0] = 3; var tqqspq_6 = new Int8Array(tqqspq); tqqspq_6[0] = -3; var tqqspq_7 = new Uint8Array(tqqspq); tqqspq_7[0] = 9; var tqqspq_8 = new Uint16Array(tqqspq); print(tqqspq_8[0]); tqqspq_8[0] = 1; var tqqspq_9 = new Float64Array(tqqspq); tqqspq_9[0] = -19; const jkftvf, szcdbz;/*MXX2*/g2.Int32Array.prototype.BYTES_PER_ELEMENT = b2;new RegExp(\"(\\\\D(?:(?:((?!(?=\\\\B))))))\", \"yim\") ? \"\\uDD64\" : -2;v0 = a2.some((function() { for (var j=0;j<86;++j) { o0.f2(j%2==1); } }));");
/*fuzzSeed-157142351*/count=676; tryItOut("testMathyFunction(mathy4, [Math.PI, -Number.MIN_VALUE, -0x100000001, 0x080000000, -0x080000000, 1, 0x0ffffffff, -Number.MAX_VALUE, 2**53+2, -0x100000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 1/0, -0x07fffffff, 0.000000000000001, -(2**53), -(2**53-2), Number.MIN_VALUE, 0x100000000, 0/0, Number.MAX_VALUE, -0x0ffffffff, 2**53-2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0, -0x080000001, -0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 42, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-157142351*/count=677; tryItOut("print(this);");
/*fuzzSeed-157142351*/count=678; tryItOut("this.v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (new function (y)\u000d { yield y } ((( /x/g ).call(25, window)),  '' )(Object.defineProperty(this, \"-0\", ({writable: 'fafafa'.replace(/a/g, w => \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((((+(((((((0xe2cde071))-((0x1931b5) > (0x3f74efd6))) & ((i0)-(true.unwatch(14)))))) & (((~~(d1)) != (((0x92753663)) << ((0xfa64fed4))))-(0xa7a45aa2))))) / ((-(((590295810358705700000.0) + (((-8388609.0)) % (((~x))))))))));\n    return +((-562949953421312.0));\n  }\n  return f;)})))) instanceof ((uneval(x))), noScriptRval: true, sourceIsLazy: false, catchTermination: {} = x }));");
/*fuzzSeed-157142351*/count=679; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return Math.hypot(Math.atanh(Math.pow(Math.max((0.000000000000001 | 0), (Math.cos((Math.min(Math.fround(x), (x >>> 0)) | 0)) | 0)), (((-0x07fffffff >>> 0) ^ (y >>> 0)) >>> 0))), Math.fround(Math.hypot(Math.fround(Math.asin(Math.fround(Math.imul(( + mathy3(Math.fround((Math.clz32(y) >>> 0)), Math.fround(y))), x)))), ( - ( + mathy1(Math.log((( + x) | 0)), ( + y))))))); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 0x100000001, -0x0ffffffff, -(2**53+2), 1/0, 0x0ffffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, Math.PI, -0, -1/0, -Number.MAX_VALUE, 0/0, 0x100000000, 1, 2**53-2, Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, 2**53+2, 0, -0x100000000, 42, -Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, -0x080000000]); ");
/*fuzzSeed-157142351*/count=680; tryItOut("for (var v of f2) { try { a2.push(f1, f1); } catch(e0) { } try { t1 + s1; } catch(e1) { } try { /*ADP-3*/Object.defineProperty(this.a1, v1, { configurable: false, enumerable: false, writable: false, value: g0.b2 }); } catch(e2) { } for (var v of g1.b1) { try { s2 += s2; } catch(e0) { } try { print(f1); } catch(e1) { } try { v1 = Object.prototype.isPrototypeOf.call(h1, p1); } catch(e2) { } m1.delete(a2); } }");
/*fuzzSeed-157142351*/count=681; tryItOut("v2 = Object.prototype.isPrototypeOf.call(i1, h1);");
/*fuzzSeed-157142351*/count=682; tryItOut("mathy1 = (function(x, y) { return ( + ( ~ (( ~ mathy0(mathy0(((x << x) >>> 0), ( ! y)), y)) | 0))); }); testMathyFunction(mathy1, [(function(){return 0;}), '\\0', (new Number(-0)), false, [0], ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), NaN, 1, objectEmulatingUndefined(), '', null, '/0/', -0, ({toString:function(){return '0';}}), 0, [], /0/, true, (new Number(0)), (new Boolean(false)), 0.1, (new String('')), (new Boolean(true)), '0', undefined]); ");
/*fuzzSeed-157142351*/count=683; tryItOut("\"use strict\"; f1(this.o2.g0);");
/*fuzzSeed-157142351*/count=684; tryItOut("\"use strict\"; g0.m0 + '';");
/*fuzzSeed-157142351*/count=685; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=686; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.asinh(((Math.imul((( + (( + -(2**53+2)) ^ ( + ( + x)))) | 0), (((-0x080000001 - ( + (0 == (Math.abs(Math.fround(y)) >>> 0)))) ? (Math.imul(( + ( ~ x)), ( + ( ! ( + 0x07fffffff)))) >>> 0) : (( - y) >>> 0)) | 0)) | 0) >>> 0))); }); ");
/*fuzzSeed-157142351*/count=687; tryItOut("\"use strict\"; v0.__proto__ = e1;");
/*fuzzSeed-157142351*/count=688; tryItOut("/*iii*//*hhh*/function yagykg(eval = (let (y = w)  /x/g ), x, a, x, x, x = \"\\u66C8\", c, NaN, \u3056, x, e =  /x/ , x, \u3056, window, z, x, NaN, z, this.z, z, x, w, a, x, x, d, a, z, w = \"\\uBE88\", x = new RegExp(\"(?!(?=(?:.)){1}$|\\\\B{1}.{4,6}{2})|(?![^])\", \"g\"), x, x, \u3056 = [[]], y, w, eval, x, x, c, b, this.e, x, \u3056, b = ({a1:1}), x, x, x = [z1], e, b, w, c, window, eval, d, a, b, x = [[]], w, x, x, NaN, x =  '' , x, b, x, eval, e, eval, a, d, c, x){e2.delete(20);}\nfor (var p in o0) { try { s0 += 'x'; } catch(e0) { } try { o1.s2 + ''; } catch(e1) { } try { t0[1]; } catch(e2) { } e2.add(t1); }\n");
/*fuzzSeed-157142351*/count=689; tryItOut("\"use asm\"; m0 = new Map(s1);");
/*fuzzSeed-157142351*/count=690; tryItOut("mathy4 = (function(x, y) { return mathy2(Math.fround(Math.min(( - ( ~ (x !== ( + ((( + ( + y)) >>> 0) - ((42 | 0) ? (y >>> 0) : (x | 0))))))), ((Math.pow(((( + (( - ( + (( - (2**53-2 | 0)) >>> 0))) | 0)) - ( + y)) | 0), x) * mathy2(Math.fround(Math.log2(x)), Math.fround(0x080000000))) | 0))), Math.hypot(Math.hypot((Math.acosh(mathy2(y, ( ! x))) >>> 0), y), (( - (( - x) >>> 0)) >>> 0))); }); testMathyFunction(mathy4, [2**53+2, -0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, Number.MAX_VALUE, -0x0ffffffff, -0x100000000, 0x080000001, Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000000, 1, 2**53-2, -0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x07fffffff, -(2**53), Number.MIN_VALUE, 1/0, 42, 2**53, 1.7976931348623157e308, -0, 0x100000000, Math.PI, 0x07fffffff, -0x100000001, 0.000000000000001, 0x0ffffffff, 0]); ");
/*fuzzSeed-157142351*/count=691; tryItOut("testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, -0x07fffffff, -0, 0x100000001, 1.7976931348623157e308, 42, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, 0.000000000000001, 0x080000001, Math.PI, 0x07fffffff, Number.MIN_VALUE, 2**53-2, -(2**53), 0/0, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), -0x080000001, -0x100000001, 1/0, 0x080000000, Number.MAX_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000000, 0x100000000, 0x0ffffffff, 0, 2**53]); ");
/*fuzzSeed-157142351*/count=692; tryItOut("let g1.a0 = /*wrap2*/(function(){ var alpytm =  /x/g ; var mzmddz = function  d (c) { yield c } ; return mzmddz;})();");
/*fuzzSeed-157142351*/count=693; tryItOut("v2 = o2.t0.length;");
/*fuzzSeed-157142351*/count=694; tryItOut("{ void 0; try { setJitCompilerOption('ion.enable', 1); } catch(e) { } }");
/*fuzzSeed-157142351*/count=695; tryItOut("\"use strict\"; return window;function b(y, eval)(Date.prototype.toLocaleDateString\u000c(window))print(x);");
/*fuzzSeed-157142351*/count=696; tryItOut("/*RXUB*/var r = r1; var s = \"\\n\\n\\n\\n\\n\\n00\\n\\n\\n\\n\\n\\n00\\n\\n\\n\\n\\n\\n\\n\\n\\n0_000)\\n\\n\\n\\n\\n\\n00\\n\\n\\n\\n\\n\\n00\\n\\n\\n\\n\\n\\n00\\n\\n\\n\\n\\n\\n00\\n\\n\\n\\n\\n\\n00\"; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-157142351*/count=697; tryItOut("for (var v of g0.m2) { try { i1.send(f0); } catch(e0) { } try { v2 = (a0 instanceof a2); } catch(e1) { } try { o1.s1 += 'x'; } catch(e2) { } for (var p in s1) { try { m2.has(e1); } catch(e0) { } try { i1 = new Iterator(a1); } catch(e1) { } s1 = Array.prototype.join.call(a1, s2, g1); } }");
/*fuzzSeed-157142351*/count=698; tryItOut("a1.splice(-16, 4, v1, s0);");
/*fuzzSeed-157142351*/count=699; tryItOut("Array.prototype.sort.call(a1, (function() { try { s1 = new String(m0); } catch(e0) { } g2.m0.has(g2.o1.m1); return t0; }), t1);");
/*fuzzSeed-157142351*/count=700; tryItOut("v1 = (o0 instanceof a0);");
/*fuzzSeed-157142351*/count=701; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(( ! (Math.atan2(( ~ Math.fround((x === Math.PI))), (Math.acosh((Math.hypot(y, Math.hypot(x, ( ~ -0x100000000))) | 0)) | 0)) | 0))); }); testMathyFunction(mathy4, [0x07fffffff, -1/0, 42, 0x100000001, -(2**53+2), 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, -0x080000001, 2**53, 2**53+2, 1.7976931348623157e308, 2**53-2, 1/0, 1, -0, 0/0, 0x080000001, -Number.MAX_VALUE, Math.PI, -0x080000000, 0x080000000, -(2**53), Number.MAX_VALUE, -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0x100000001]); ");
/*fuzzSeed-157142351*/count=702; tryItOut("\"use strict\"; testMathyFunction(mathy1, [42, Number.MIN_VALUE, 1.7976931348623157e308, -1/0, Math.PI, 1/0, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000000, -0x07fffffff, 0.000000000000001, 0, -0, 0x100000001, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), 1, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -0x100000000, -0x080000001, 0x080000001, 0x0ffffffff, 2**53, 0/0, 2**53-2, -(2**53-2), 0x07fffffff, -(2**53+2)]); ");
/*fuzzSeed-157142351*/count=703; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=704; tryItOut("print(uneval(e1));");
/*fuzzSeed-157142351*/count=705; tryItOut("s2 += 'x';");
/*fuzzSeed-157142351*/count=706; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[(void 0),  \"use strict\" ,  \"use strict\" , (void 0), (void 0),  \"use strict\" ,  \"use strict\" , (void 0),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , (void 0)]) { print(((x) = null)); }");
/*fuzzSeed-157142351*/count=707; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.acosh(Math.fround((( + ( ~ ( + ( ! (Math.min((y || (y | 0)), x) | 0))))) << ((Math.imul(y, (( ~ (Number.MAX_SAFE_INTEGER >>> 0)) >>> 0)) | 0) != (Math.fround(mathy4(Math.fround(Math.cbrt(Number.MAX_VALUE)), Math.fround((Math.max((y | 0), (x | 0)) | 0)))) | 0))))); }); testMathyFunction(mathy5, [-0x080000001, -0x100000000, -(2**53+2), 1, -0, 0x080000000, -1/0, -0x080000000, -Number.MAX_VALUE, -0x100000001, Number.MAX_VALUE, 0/0, 1.7976931348623157e308, Math.PI, Number.MIN_VALUE, -(2**53), 0x080000001, -Number.MIN_VALUE, 2**53, -(2**53-2), 0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000001, 2**53-2, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000000, -0x07fffffff, 42, 1/0]); ");
/*fuzzSeed-157142351*/count=708; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[ /x/ , -(2**53-2), objectEmulatingUndefined(), -(2**53-2), null, null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, -(2**53-2), null, -(2**53-2), null, timeout(1800),  /x/ , timeout(1800), objectEmulatingUndefined(), objectEmulatingUndefined(), timeout(1800), timeout(1800), null, -(2**53-2),  /x/ , null, null, -(2**53-2), objectEmulatingUndefined(), timeout(1800), null, -(2**53-2),  /x/ ,  /x/ , objectEmulatingUndefined(), -(2**53-2),  /x/ , -(2**53-2), timeout(1800), -(2**53-2), null, objectEmulatingUndefined(), null, timeout(1800), -(2**53-2), null,  /x/ , null, null, objectEmulatingUndefined(), null, -(2**53-2),  /x/ , null, -(2**53-2), timeout(1800), timeout(1800), timeout(1800), timeout(1800), -(2**53-2), -(2**53-2), objectEmulatingUndefined(),  /x/ , null, timeout(1800),  /x/ ,  /x/ , -(2**53-2), objectEmulatingUndefined(), -(2**53-2), objectEmulatingUndefined(), null, -(2**53-2), timeout(1800), timeout(1800), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, timeout(1800), -(2**53-2), -(2**53-2), objectEmulatingUndefined(), null,  /x/ , objectEmulatingUndefined(),  /x/ , null, objectEmulatingUndefined(), objectEmulatingUndefined(), -(2**53-2), -(2**53-2), null,  /x/ ,  /x/ , objectEmulatingUndefined(), -(2**53-2), -(2**53-2), -(2**53-2),  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/ , -(2**53-2),  /x/ , -(2**53-2), objectEmulatingUndefined(),  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , objectEmulatingUndefined(), objectEmulatingUndefined(), timeout(1800), -(2**53-2), null,  /x/ , timeout(1800), objectEmulatingUndefined(),  /x/ , null, objectEmulatingUndefined(), -(2**53-2),  /x/ , -(2**53-2), null, -(2**53-2), -(2**53-2),  /x/ , objectEmulatingUndefined(), timeout(1800), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), -(2**53-2), null, null, timeout(1800), -(2**53-2),  /x/ , -(2**53-2), null, -(2**53-2), objectEmulatingUndefined(),  /x/ ]); ");
/*fuzzSeed-157142351*/count=709; tryItOut("this.v1 = new Number(e1);");
/*fuzzSeed-157142351*/count=710; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -2199023255552.0;\n    return +((d2));\n  }\n  return f; })(this, {ff: String.prototype.blink}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0, (new Boolean(true)), 1, ({valueOf:function(){return '0';}}), true, [], '', /0/, undefined, (new String('')), '/0/', (new Number(0)), '\\0', -0, NaN, [0], (new Number(-0)), '0', (new Boolean(false)), false, (function(){return 0;}), null, objectEmulatingUndefined(), 0.1, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-157142351*/count=711; tryItOut("v2 = m1[\"keys\"];");
/*fuzzSeed-157142351*/count=712; tryItOut("/*bLoop*/for (let vxnexv = 0; vxnexv < 149; ++vxnexv) { if (vxnexv % 2 == 0) { v2 = (e1 instanceof v0); } else { c; }  } ");
/*fuzzSeed-157142351*/count=713; tryItOut("testMathyFunction(mathy0, [({toString:function(){return '0';}}), NaN, (new Boolean(true)), true, [], '0', false, ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '/0/', 0, '\\0', 1, (function(){return 0;}), undefined, (new Boolean(false)), /0/, null, (new Number(-0)), 0.1, '', (new String('')), (new Number(0)), objectEmulatingUndefined(), -0, [0]]); ");
/*fuzzSeed-157142351*/count=714; tryItOut("mathy1 = (function(x, y) { return ( + Math.hypot((Math.cosh((Math.fround(Math.max(Math.imul(y, Math.fround((Math.min(Math.fround(x), ( + y)) | 0))), Math.fround(mathy0(Math.min((-0x100000000 | 0), x), (( + x) >> 0/0))))) | 0)) | 0), (Math.fround(mathy0(Math.fround(((1 << x) ? 2**53-2 : (Math.acos(x) >>> 0))), ((Math.atan2((Math.min(( - Math.trunc(y)), y) >>> 0), (x >>> 0)) >>> 0) | 0))) !== Math.fround(Math.hypot((((((y >>> 0) == (Math.max(( + x), ( + x)) | 0)) >>> 0) ? y : (( ~ Math.fround(( ~ ( + (x & 0x100000001))))) >>> 0)) >>> 0), (Math.atan2((Math.sinh(y) | 0), Math.fround(Math.fround(Math.clz32(Math.fround(x))))) | 0)))))); }); testMathyFunction(mathy1, [-(2**53), 0x0ffffffff, 0/0, 0x100000000, -0x07fffffff, -0, 1/0, 0, 0x07fffffff, 2**53, -0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x0ffffffff, 2**53-2, -(2**53+2), 1, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0x080000000, -0x100000000, -0x080000001, 0x100000001, Number.MAX_VALUE, -0x100000001, -1/0, 0.000000000000001, -Number.MIN_VALUE, 42, Math.PI, 0x080000001, -(2**53-2)]); ");
/*fuzzSeed-157142351*/count=715; tryItOut("mathy0 = (function(x, y) { return Math.cosh((Math.fround((Math.fround((Math.fround(y) >= Math.fround(-0x0ffffffff))) & (( + ( + Math.fround(( ~ -Number.MIN_SAFE_INTEGER)))) | 0))) * Math.min(( ! 0x080000001), ((Math.min((x | 0), (( + Math.log(x)) | 0)) | 0) >>> 0)))); }); testMathyFunction(mathy0, /*MARR*/[{x:3}, {x:3}, arguments.callee, arguments.callee, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, arguments.callee, {x:3}, arguments.callee, {x:3}, {x:3}, arguments.callee, {x:3}, arguments.callee, {x:3}, {x:3}, {x:3}, arguments.callee, {x:3}, arguments.callee, {x:3}, {x:3}, arguments.callee, {x:3}, arguments.callee, {x:3}, {x:3}, {x:3}, arguments.callee, {x:3}, {x:3}, arguments.callee, arguments.callee, {x:3}, {x:3}, {x:3}, arguments.callee, {x:3}, arguments.callee, arguments.callee, arguments.callee, {x:3}, arguments.callee, arguments.callee, arguments.callee, {x:3}, arguments.callee, arguments.callee, arguments.callee, arguments.callee, {x:3}, arguments.callee, {x:3}, {x:3}, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, {x:3}, arguments.callee, {x:3}, arguments.callee, arguments.callee, {x:3}, {x:3}, {x:3}, arguments.callee, {x:3}, arguments.callee, {x:3}, arguments.callee, arguments.callee, {x:3}, arguments.callee]); ");
/*fuzzSeed-157142351*/count=716; tryItOut("mathy5 = (function(x, y) { return (Math.sin((Math.expm1((0/0 >>> 0)) | 0)) === ( + Math.min(Math.atan2(x, (x >>> 0)), ( + ( + Math.min(( + (( + mathy0(( + x), ( + y))) <= (Math.max(((( ~ (x | 0)) | 0) >>> 0), ( + Math.log10(( + ( + (( + x) < ( + x))))))) >>> 0))), ( + (y , x)))))))); }); testMathyFunction(mathy5, [-0x080000000, -1/0, 1.7976931348623157e308, -0x100000001, -0x080000001, 0x080000000, -(2**53+2), 2**53, 0x100000001, -0x100000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1, 0x080000001, -(2**53), 0/0, 0, 2**53+2, 0x0ffffffff, -(2**53-2), Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, -0, 2**53-2, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, 0.000000000000001, 1/0, Math.PI]); ");
/*fuzzSeed-157142351*/count=717; tryItOut("print((4277));");
/*fuzzSeed-157142351*/count=718; tryItOut("\"use strict\"; /*tLoop*/for (let w of /*MARR*/[objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q')]) { /*RXUB*/var r = o1.r1; var s = s2; print(s.split(r)); print(r.lastIndex);  }");
/*fuzzSeed-157142351*/count=719; tryItOut("\"use strict\"; h2 + '';");
/*fuzzSeed-157142351*/count=720; tryItOut("this.t2 = new Int8Array(this.t1);");
/*fuzzSeed-157142351*/count=721; tryItOut("testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 0x0ffffffff, Number.MAX_VALUE, -0x080000001, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, 42, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, -0x100000001, 0x080000000, 2**53, 2**53-2, 1/0, 1, -0x07fffffff, 1.7976931348623157e308, -(2**53+2), 0, Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, -0x080000000, 0.000000000000001, -0, 0x07fffffff, 2**53+2, 0x100000001, 0x080000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-157142351*/count=722; tryItOut("mathy2 = (function(x, y) { return (((Math.log10((((( - (y >>> x)) << ( + x)) >= Math.round(Math.fround((( + Math.fround(Math.pow(-0x07fffffff, y))) >>> 0)))) >>> 0)) >>> 0) ? (Math.hypot(Math.min((((-1/0 | 0) >= (Math.min(-1/0, y) > y)) | 0), Math.hypot(2**53+2, y)), mathy0((x > x), mathy0((x | 0), Math.fround(Math.imul(Math.fround(y), Math.fround(Math.pow(x, ( + -Number.MIN_SAFE_INTEGER)))))))) >>> 0) : (Math.acosh((( + Math.min(mathy1(Math.atan2(x, x), x), (Math.pow(y, x) >>> 0))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [0/0, 0x080000000, -Number.MAX_VALUE, 2**53, -1/0, -0x0ffffffff, -Number.MIN_VALUE, 42, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, 0x07fffffff, Number.MAX_VALUE, Math.PI, 2**53+2, 1.7976931348623157e308, 0.000000000000001, 0x0ffffffff, 2**53-2, 0, Number.MAX_SAFE_INTEGER, -(2**53), 1/0, -0, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, -(2**53-2), -0x080000001, -0x100000000, 1, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x100000001]); ");
/*fuzzSeed-157142351*/count=723; tryItOut("a2.toString = () =>  { \"use strict\"; return \"\\u6B3A\" } ;");
/*fuzzSeed-157142351*/count=724; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var acos = stdlib.Math.acos;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (0x1513362f);\n    i1 = (((0x6624e881)+(0xfbfafb81)));\n    d0 = (+acos(((d0))));\n    i1 = ((((((/*MARR*/[this, new Number(1)].filter).__defineGetter__(\"x\", x)) & ((/*FFI*/ff(((((0xc407650a)+(0xffffffff)+(0xfb010106)))), ((abs((0x7fffffff))|0)))|0)*-0xd31c3)) % (0x476564dc))|0));\n    return ((-(0x765c0431)))|0;\n  }\n  return f; })(this, {ff: Array.prototype.toLocaleString}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x080000001, 0x080000000, 42, 1/0, 0.000000000000001, Math.PI, 2**53+2, 2**53, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000000, -1/0, -0x07fffffff, -(2**53-2), -(2**53), Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, -Number.MAX_VALUE, -(2**53+2), -0x080000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -0, 2**53-2, -0x100000001, 0, -Number.MIN_VALUE, 1, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff]); ");
/*fuzzSeed-157142351*/count=725; tryItOut("\"use strict\"; v2 = h0[\"1\"];");
/*fuzzSeed-157142351*/count=726; tryItOut("\"use strict\"; /*RXUB*/var r = /((\\b|[]\\b\\xb7|\\1+[^]))(?:(?:((?=(?:[^])))|(?!(?:\\t|\\d)*?))(?:\\W)|.{0,0}|\\d|\\D+|([^\u00c4-\u00e0\0-\\uA232])$)/gym; var s = \"\"; print(s.replace(r, ([1].eval(\"/* no regression tests found */\")))); ");
/*fuzzSeed-157142351*/count=727; tryItOut("for(let x in /*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}]) with({}) { this.zzz.zzz; } ");
/*fuzzSeed-157142351*/count=728; tryItOut("for(let z in z + x) {Object.preventExtensions(this.v1); }");
/*fuzzSeed-157142351*/count=729; tryItOut("mathy4 = (function(x, y) { return mathy3((((Math.cbrt((( ~ ( + ( + (y >>> 0)))) >>> 0)) | 0) < (Math.log2(((mathy2((x | 0), (y | 0)) | 0) >>> (Math.round((y >>> 0)) >>> 0))) | 0)) >>> 0), Math.trunc(((( + (Math.hypot(Math.fround(Math.max(Math.fround(y), y)), (( + y) + ( + x))) | 0)) | 0) | 0))); }); testMathyFunction(mathy4, [1.7976931348623157e308, Math.PI, 2**53+2, Number.MAX_VALUE, -0x080000000, -0x100000001, -1/0, 0/0, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, -(2**53+2), -(2**53), Number.MIN_SAFE_INTEGER, 0.000000000000001, 0, 0x080000001, 2**53, 0x0ffffffff, 1/0, 1, -0x0ffffffff, 0x100000000, 42, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 2**53-2, -0x100000000, -0x080000001, Number.MIN_VALUE, -0x07fffffff]); ");
/*fuzzSeed-157142351*/count=730; tryItOut("\"use strict\"; t2 = new Uint32Array(1);");
/*fuzzSeed-157142351*/count=731; tryItOut("\"use strict\"; delete h2.fix;");
/*fuzzSeed-157142351*/count=732; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround(mathy0(Math.asin((( - (Math.log10(x) >>> 0)) | 0)), ( ~ ( ! ( ! 0x100000001))))) ? ( + Math.max(((( + -0) >>> Math.fround(Math.acos(x))) - ( ! (( - y) | 0))), (Math.fround(mathy0(Math.fround(y), Math.fround(Math.fround(Math.atan2(Math.fround(y), Math.fround(x)))))) | 0))) : Math.fround(( ~ Math.asinh((((((y >>> 0) << ((Number.MAX_VALUE - 0.000000000000001) >>> 0)) >>> 0) ? ( + (( + (0x080000000 | 0)) | 0)) : (Math.imul((Math.sign((x | 0)) | 0), -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0)))))); }); ");
/*fuzzSeed-157142351*/count=733; tryItOut("\"use strict\"; testMathyFunction(mathy1, /*MARR*/[ /x/g , new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(),  'A' , objectEmulatingUndefined(), new Number(1), new Number(1), new Number(1), objectEmulatingUndefined(),  'A' ,  'A' ,  /x/g ,  'A' , objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(),  /x/g ,  'A' ,  'A' ,  /x/g , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  'A' , new Number(1),  /x/g , new Number(1), objectEmulatingUndefined(),  /x/g , new Number(1), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new Number(1), objectEmulatingUndefined(),  'A' ,  'A' ,  'A' ,  /x/g ,  'A' , new Number(1),  /x/g ]); ");
/*fuzzSeed-157142351*/count=734; tryItOut("mathy4 = (function(x, y) { return Math.log(( + Math.imul(Math.log((((Math.sin((y ? y : -Number.MAX_VALUE)) ** Math.fround(Math.log(y))) >>> 0) | 0)), ((Math.log((Math.pow(Math.sinh(Math.fround(Math.fround(Math.min(x, y)))), 0x080000000) >>> 0)) | 0) | 0)))); }); testMathyFunction(mathy4, /*MARR*/[NaN, x, [(void 0)], new Number(1), x, x, new Number(1), new Number(1), NaN, NaN, NaN, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], new Number(1), new Number(1), new Number(1), [(void 0)], new Number(1), x, x, new Number(1), x, [(void 0)], new Number(1), [(void 0)], new Number(1), [(void 0)], NaN, NaN, [(void 0)], new Number(1), NaN, [(void 0)], x, new Number(1), x, NaN, x, new Number(1), [(void 0)], [(void 0)], new Number(1), x, new Number(1), [(void 0)], new Number(1), new Number(1), [(void 0)], [(void 0)], [(void 0)], x, NaN, [(void 0)], NaN, x, [(void 0)], new Number(1), new Number(1), NaN, new Number(1), [(void 0)], x, NaN, [(void 0)], [(void 0)], new Number(1), x, NaN, new Number(1), new Number(1), new Number(1), [(void 0)], NaN, x, NaN, x, NaN, new Number(1), NaN, new Number(1), NaN, NaN, x, NaN, NaN, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), x, NaN, [(void 0)], x, new Number(1), [(void 0)], NaN, x, new Number(1), [(void 0)], x, x, NaN, [(void 0)]]); ");
/*fuzzSeed-157142351*/count=735; tryItOut("for(let x in /*FARR*/[]) throw window;let(bcasjl, x =  /x/ , x = this, x, a = (3)(this.__defineGetter__(\"x\"//h\n, q => q), x), pwxayx, [[]] = 24, d, e) { for(var [y, w] = x in  \"\" ) {e2.has([z1,,]); }}");
/*fuzzSeed-157142351*/count=736; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (Math.imul((Math.atan((( ! (Math.min((x | 0), (y != (( - y) >>> 0))) >>> 0)) | 0)) | 0), (( + Math.imul(((Math.pow(mathy2((y >>> 0), (y >>> 0)), ( + Math.acosh(y))) - Math.pow(x, 0x100000001)) , Math.min(( - Math.fround(Math.atan2(Math.fround(-0), Math.fround(( ! y))))), Math.atan2(Math.round(y), Math.fround(( ! x))))), (((Math.min(Number.MIN_SAFE_INTEGER, Math.fround(( ~ (-0x0ffffffff | 0)))) >>> 0) | ((Math.cosh(( + Math.fround(Math.atan2(Math.fround(y), Math.fround(x))))) ** Math.fround(y)) >>> 0)) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[new String('q'), new String('q'), null,  /x/ ,  /x/ , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, null,  /x/ , 1.7976931348623157e308, null,  /x/ , new String('q'), 1.7976931348623157e308, 1.7976931348623157e308,  /x/ ,  /x/ ,  /x/ , 1.7976931348623157e308, null, null, null, null, null, null, null, null, null, null, null, null, null]); ");
/*fuzzSeed-157142351*/count=737; tryItOut("\"use strict\"; e1 + o2.h0;print( '' );");
/*fuzzSeed-157142351*/count=738; tryItOut("mathy2 = (function(x, y) { return Math.fround(( ! Math.atanh(( ! Math.hypot(((Math.asinh(Math.fround(y)) >>> 0) >>> 0), y))))); }); testMathyFunction(mathy2, /*MARR*/[(1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), (1/0), (1/0)]); ");
/*fuzzSeed-157142351*/count=739; tryItOut("for (var v of a2) { g1.v0 = Object.prototype.isPrototypeOf.call(h0, g1.e0); }");
/*fuzzSeed-157142351*/count=740; tryItOut("\"use strict\"; o2.t2[5] =  /x/ ;");
/*fuzzSeed-157142351*/count=741; tryItOut("\"use strict\"; /*vLoop*/for (var umimgt = 0; (eval(\"print(x);\",  '' )) && umimgt < 163; ++umimgt) { var c = umimgt; /* no regression tests found */ } ");
/*fuzzSeed-157142351*/count=742; tryItOut("a0.push(s1, m0, this.s0, d = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: w =>  { yield b } \u0009, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: mathy1, delete: Map.prototype.keys, fix: undefined, has: undefined, hasOwn:  \"\" , get: /*wrap2*/(function(){ var jmleoi = null; var dibqqb = (function(x, y) { return x; }); return dibqqb;})(), set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { throw 3; }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { throw 3; }, }; })(\"\\uD20D\"), window -= d.setInt16, arguments.callee));");
/*fuzzSeed-157142351*/count=743; tryItOut("v2 = Object.prototype.isPrototypeOf.call(g0, o1);");
/*fuzzSeed-157142351*/count=744; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=745; tryItOut("mathy1 = (function(x, y) { return (Math.tanh(( ! mathy0(0.000000000000001, mathy0(y, x)))) > (mathy0((( + Math.acosh(( + ( - y)))) | 0), (((((Math.atanh((( - y) | 0)) | 0) >>> 0) == (mathy0(x, (Math.hypot(y, (x >>> 0)) >>> 0)) >>> 0)) >>> 0) | 0)) | 0)); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), new String('q'), new String('q'),  /x/g , new String('q'), new String('q'), new String('q'), objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), new String('q'),  /x/g ,  /x/g ,  /x/g ,  /x/g ]); ");
/*fuzzSeed-157142351*/count=746; tryItOut("/*RXUB*/var r = this.r2; var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=747; tryItOut("o0 + v2;");
/*fuzzSeed-157142351*/count=748; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (+pow(((d0)), ((((d0)) / ((d0))))));\n    d1 = (d1);\n    return (((0xfea5c0d0)+(0x5b636565)))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -Number.MAX_VALUE, -0x100000001, 0/0, 1.7976931348623157e308, 0x07fffffff, 0x0ffffffff, 0x080000001, -0x080000000, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53, Math.PI, -0x080000001, 1, -Number.MIN_VALUE, -1/0, 1/0, -0x07fffffff, 0, -0, 0.000000000000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, 0x080000000, 42, 0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-157142351*/count=749; tryItOut("\"use strict\"; testMathyFunction(mathy2, [2**53, Math.PI, 0x100000001, 0, 0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 2**53+2, 1.7976931348623157e308, -0, 0/0, -(2**53), 0.000000000000001, -Number.MIN_VALUE, -1/0, -0x080000000, 2**53-2, 0x07fffffff, -0x100000000, 42, -(2**53-2), 0x0ffffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 1, Number.MAX_VALUE, -(2**53+2), -0x080000001, Number.MIN_VALUE, -0x07fffffff, 0x080000000]); ");
/*fuzzSeed-157142351*/count=750; tryItOut("mathy1 = (function(x, y) { return ( + Math.cbrt((( + Math.log2(( ! y))) | 0))); }); ");
/*fuzzSeed-157142351*/count=751; tryItOut("with({x: (/*FARR*/[this.__defineGetter__(\"\\u3056\", Float64Array), , , [ '' ], Math.min(d, -19), x, .../*FARR*/[this, , [z1,,], ...[], undefined], .../*MARR*/[function(){}, -Infinity, function(){}, function(){}, function(){}, -Infinity, function(){}, -Infinity, function(){}, -Infinity, function(){}, -Infinity, function(){}], (x)(z, undefined), Math.max(25, -15)].map(Number))})(Math.fround(NaN));");
/*fuzzSeed-157142351*/count=752; tryItOut("/*MXX3*/g1.Error.name = g0.Error.name;\nv2 = g2.eval(\"function f1(o1.s1) this\");\n");
/*fuzzSeed-157142351*/count=753; tryItOut("\"use strict\"; /*ADP-2*/Object.defineProperty(a0, 7, { configurable: true, enumerable: (x % 4 != 3), get: (function() { try { v2 = (m2 instanceof i0); } catch(e0) { } try { h1.toString = (function() { try { v2 = Proxy.create(h1, h1); } catch(e0) { } r2 = new RegExp(\"[^\\\\v\\\\cS-\\u0094\\\\\\u00c5\\\\D][\\\\%-\\\\\\u8cd9]*?([^])\\\\W*|\\\\W\\\\d{4,7}|$*|[^]^(?:\\\\B)|\\\\D?|(?!^)|.+\", \"\"); return o0.h0; }); } catch(e1) { } try { s1 += s1; } catch(e2) { } v1 = -Infinity; throw p2; }), set: Array.prototype.indexOf.bind(e0) });");
/*fuzzSeed-157142351*/count=754; tryItOut("\"use strict\"; i0 = new Iterator(m2);");
/*fuzzSeed-157142351*/count=755; tryItOut("\"use asm\"; new Functionnull\u0009;");
/*fuzzSeed-157142351*/count=756; tryItOut("\"use asm\"; a1.forEach((function(j) { if (j) { try { v1 = evaluate(\"function this.f2(o0) o0\", ({ global: o1.g1, fileName: null, lineNumber: 42, isRunOnce: (x % 6 == 4), noScriptRval: false, sourceIsLazy: \"\\u5F2F\", catchTermination: false })); } catch(e0) { } g0 + h2; } else { try { v2 = g1.eval(\"Array.prototype.shift.apply(a1, [p1]);\"); } catch(e0) { } try { s1 += s1; } catch(e1) { } Array.prototype.sort.call(a0, (function() { try { o2[\"caller\"] = f0; } catch(e0) { } try { s2 = s1.charAt(({valueOf: function() { L:for(var y in (((void version(180)))((4277))))v0 = (g1.p1 instanceof i1);return 0; }})); } catch(e1) { } try { this.a1 = arguments.callee.caller.arguments; } catch(e2) { } s0 + ''; return v0; })); } }));");
/*fuzzSeed-157142351*/count=757; tryItOut("\"use strict\"; for (var v of b0) { try { i2.send(a0); } catch(e0) { } try { v1 = (this.i0 instanceof f2); } catch(e1) { } try { a2.splice(NaN, 2, h1, f2, s0); } catch(e2) { } p1.toString = (function() { for (var j=0;j<43;++j) { f0(j%2==0); } }); }");
/*fuzzSeed-157142351*/count=758; tryItOut("\"use strict\"; for (var v of e2) { v0 = undefined; }");
/*fuzzSeed-157142351*/count=759; tryItOut("a = (4277);p1 + f0;");
/*fuzzSeed-157142351*/count=760; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(( ! Math.fround((Math.tan(Math.fround(Math.hypot(Math.fround(mathy0((((Math.fround(x) ? x : y) >>> 0) ? (((y >>> y) >>> 0) >>> 0) : (y >>> 0)), x)), ((Math.max(Math.fround(Math.tan(Math.fround(y))), ((Math.pow(((1.7976931348623157e308 << y) | 0), (0x0ffffffff | 0)) >= (y || Math.fround(y))) | 0)) | 0) >>> 0)))) >>> 0)))); }); ");
/*fuzzSeed-157142351*/count=761; tryItOut("for (var p in o0) { try { ; } catch(e0) { } try { /*MXX1*/o1 = o0.g0.Math.pow; } catch(e1) { } try { o2.e2.add(t1); } catch(e2) { } a2 + ''; }");
/*fuzzSeed-157142351*/count=762; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( + ((Math.fround(Math.max(x, y)) >>> 0) * Math.fround(( + Math.fround(x))))) | Math.cbrt((Math.atan2((Math.sinh(Math.sinh(x)) >>> 0), (y >>> 0)) >>> 0))); }); ");
/*fuzzSeed-157142351*/count=763; tryItOut("\"use strict\"; testMathyFunction(mathy3, [(new Boolean(false)), (function(){return 0;}), (new Number(-0)), '', 1, ({valueOf:function(){return 0;}}), [0], false, '/0/', [], '0', null, true, NaN, '\\0', 0, undefined, (new Number(0)), 0.1, objectEmulatingUndefined(), ({toString:function(){return '0';}}), -0, /0/, (new String('')), (new Boolean(true)), ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-157142351*/count=764; tryItOut("\"\\uF208\";");
/*fuzzSeed-157142351*/count=765; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((( + Math.max(Math.cosh(Math.fround(((x && -(2**53+2)) % Math.fround(( ! Math.fround(-0x100000000)))))), Math.trunc(Math.fround(Math.sin(((Math.tan(y) | 0) | 0)))))) + ((((( + ( ~ ( + y))) >>> 0) << ((((( + (((( ~ (y >>> 0)) >>> 0) >>> 0) / -0x080000000)) >>> 0) ** (y >>> 0)) >>> 0) >>> 0)) != ((y & x) - Math.fround(Math.atan2(y, Math.fround(y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-0, [0], 0, (new Boolean(true)), true, (new String('')), ({valueOf:function(){return 0;}}), undefined, (function(){return 0;}), '\\0', '0', null, (new Number(0)), NaN, 0.1, /0/, objectEmulatingUndefined(), (new Boolean(false)), (new Number(-0)), ({valueOf:function(){return '0';}}), [], ({toString:function(){return '0';}}), false, '', '/0/', 1]); ");
/*fuzzSeed-157142351*/count=766; tryItOut("mathy5 = (function(x, y) { return (( - ((((-(2**53) ? Math.fround(mathy1(Math.fround(y), Math.fround((Math.acosh(Math.fround(mathy4(y, 0/0))) | 0)))) : (((void shapeOf( \"\" ))) , ( + y))) | ((mathy0(( ~ x), (((Math.atan2((Math.tanh((-Number.MAX_SAFE_INTEGER | 0)) | 0), Math.sign(-0x080000000)) >>> 0) !== (x >>> 0)) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy5, ['\\0', 0, ({toString:function(){return '0';}}), 1, '0', /0/, (new Boolean(false)), NaN, (function(){return 0;}), true, ({valueOf:function(){return 0;}}), (new Number(0)), (new Number(-0)), 0.1, ({valueOf:function(){return '0';}}), (new String('')), (new Boolean(true)), null, -0, false, [0], '/0/', objectEmulatingUndefined(), [], undefined, '']); ");
/*fuzzSeed-157142351*/count=767; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\1?)*\", \"gyi\"); var s = \"\\ua251\\ua251\\n\\n\\n\\ua251\\ua251\\ua251\\ua251\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=768; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.min((Math.ceil((Math.acos((((Math.atan2(( + y), Math.hypot(-0x100000001, -0x080000001)) | 0) | (Math.atan2((Number.MIN_SAFE_INTEGER | 0), y) | 0)) | 0)) | 0)) >>> 0), Math.sin(Math.fround(( ! (Math.atanh(y) | 0))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, -Number.MAX_VALUE, -0x080000000, -(2**53), 0x100000000, 0/0, -0x07fffffff, Number.MAX_VALUE, -0x0ffffffff, -1/0, -(2**53-2), -0x100000001, 0x100000001, 2**53-2, 42, 1/0, 2**53, 1, 0x0ffffffff, 0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, 0, 0x080000001, -(2**53+2), -0]); ");
/*fuzzSeed-157142351*/count=769; tryItOut("a2 + g1.g0.h2;");
/*fuzzSeed-157142351*/count=770; tryItOut("var jpzemy = new SharedArrayBuffer(2); var jpzemy_0 = new Uint8ClampedArray(jpzemy); print(jpzemy_0[0]); jpzemy_0[0] = 4; var jpzemy_1 = new Int32Array(jpzemy); jpzemy_1[0] = -28; var jpzemy_2 = new Int32Array(jpzemy); var jpzemy_3 = new Float64Array(jpzemy); print(jpzemy_3[0]); jpzemy_3[0] = -4; var jpzemy_4 = new Float32Array(jpzemy); jpzemy_4[0] = 2; var jpzemy_5 = new Uint8Array(jpzemy); f2 + o0;a1.shift();/* no regression tests found */s0 += 'x';");
/*fuzzSeed-157142351*/count=771; tryItOut("testMathyFunction(mathy3, [1/0, -Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, 42, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, -Number.MIN_VALUE, Number.MAX_VALUE, 0.000000000000001, 0x07fffffff, 1, 0x0ffffffff, 0, -(2**53+2), -0x080000000, -0, Math.PI, -0x0ffffffff, -1/0, -0x100000000, 0x100000000, 2**53, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000001, 2**53-2, 0/0, 2**53+2, -0x080000001, -Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-157142351*/count=772; tryItOut("e2.delete(b1);var z = /(\\d){2,}/gyi;let b = x;");
/*fuzzSeed-157142351*/count=773; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ! Math.sqrt(( + (Math.ceil(x) == Math.round(( + ( + y))))))); }); ");
/*fuzzSeed-157142351*/count=774; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = /\\3/ym; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=775; tryItOut("m0.set(/*UUV2*/(NaN.padEnd = NaN.ceil), o2);v1 = evalcx(\"this.__defineGetter__(\\\"x\\\", encodeURI)\", g1);");
/*fuzzSeed-157142351*/count=776; tryItOut("\"use strict\"; /*ODP-2*/Object.defineProperty(m1, \"z\", { configurable: true, enumerable: false, get: (function(j) { if (j) { try { Array.prototype.shift.apply(a0, []); } catch(e0) { } m2 = g2.objectEmulatingUndefined(); } else { try { m2.has(p1); } catch(e0) { } v2 = t1[\"__count__\"]; } }), set: (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -34359738368.0;\n    var i3 = 0;\n    d1 = (+(-1.0/0.0));\n    d1 = (((590295810358705700000.0)) / ((((d2)) % ((134217727.0)))));\n    {\n      return (((i0)-((i0) ? (i3) : (/*FFI*/ff(((((0x29af12b9)) ^ (((0x103f7bc4) > (0x56632bf4))-((-2097152.0) > (2.0))))), ((+((((4277)\n))))))|0))))|0;\n    }\n    {\n      {\n        d1 = (null);\n      }\n    }\n    i0 = ((abs((((0x797b0be3)+(i3)) ^ ((((0xfac1f9cf) ? (-0x8000000) : (0x8289d15c)) ? ((0x7fb115f6) == (0xffffffff)) : (-0x8000000))*-0xee8b8)))|0) == (((0x731a4f8b)+((((0xf8f63134))|0))) & ((0x10bc2e4b) / (((i3)) >> ((0x681f987e)-(0x7da62009)-(0xffffffff))))));\n    i0 = (0xbdfbb373);\n    d1 = ((((Array.prototype.unshift).call(new (4277)(x), (let (d) (delete d.d)), ((b)) = eval %= b))) % ((+(0.0/0.0))));\n    d1 = (((Float32ArrayView[((-0x72cd4d1)+((((+abs(((i0)))))) >= (((0xffffffff)-(0xef21f679)-(-0x8000000)) & ((-0x8000000) % (0x2dd232e6))))) >> 2])) - ((Infinity)));\n    return (((i3)+(/*FFI*/ff()|0)))|0;\n  }\n  return f; })(this, {ff: arguments.callee}, new SharedArrayBuffer(4096)) });");
/*fuzzSeed-157142351*/count=777; tryItOut("with(/*MARR*/[function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/g , objectEmulatingUndefined()].map((let (e=eval) e)))m2 = new WeakMap;");
/*fuzzSeed-157142351*/count=778; tryItOut("/*oLoop*/for (let xcngdw = 0; xcngdw < 78; ++xcngdw) { with({c: (void shapeOf(((void options('strict_mode')))))})m2.get(m2);\nv2 = Object.prototype.isPrototypeOf.call(f2, a0);\n } ");
/*fuzzSeed-157142351*/count=779; tryItOut("Array.prototype.shift.call(a1, h1, p0, t0);\nprint(x);\n");
/*fuzzSeed-157142351*/count=780; tryItOut("var d = (y = e);print(d);");
/*fuzzSeed-157142351*/count=781; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=782; tryItOut(";");
/*fuzzSeed-157142351*/count=783; tryItOut("\"use strict\"; \"use asm\"; {Array.prototype.reverse.apply(a2, []);for([c, e] = d in /((?!\\S))|((?=(?:\\S)|^*?\\2|[^\\xf2]^{3,7}))/gy) {{print(x);a1 = []; } } }");
/*fuzzSeed-157142351*/count=784; tryItOut("i2.next();");
/*fuzzSeed-157142351*/count=785; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + (( + Math.tanh((Math.fround((Math.atan2((y >>> 0), ( + (Math.hypot((( + Math.exp((1 >>> 0))) | 0), (y % (( ! y) >>> 0))) | 0))) >>> 0)) | ( + y)))) ? ((Math.exp(((( - (((x | 0) << (y | 0)) | 0)) <= Math.atan2(Math.max(Math.acos(y), (x - y)), ( + 1/0))) >>> 0)) >>> 0) | 0) : ( + ( ~ Math.atan2(x, ( + ( + ( + (x ? y : y))))))))); }); testMathyFunction(mathy1, [2**53-2, 0x080000000, 1, -Number.MIN_VALUE, -(2**53+2), 1/0, -0x07fffffff, -Number.MAX_VALUE, -(2**53), -1/0, 0/0, 0x080000001, -0x100000001, 1.7976931348623157e308, Math.PI, -0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x080000001, 42, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000001, -0x100000000, 2**53, 0, -(2**53-2), -0x080000000, 0x100000000, 2**53+2, -0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-157142351*/count=786; tryItOut("v0 = a2.length;");
/*fuzzSeed-157142351*/count=787; tryItOut("m1.delete(m2);");
/*fuzzSeed-157142351*/count=788; tryItOut("while(( /x/ ) && 0)([,]);");
/*fuzzSeed-157142351*/count=789; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ ((Math.log2(( + (( + (y < y)) ^ (Math.sinh((y ? (0/0 >>> 0) : y)) | 0)))) * (Math.pow(1/0, y) | 0)) >>> 0)); }); testMathyFunction(mathy4, [-0, 0, 0x100000000, -Number.MAX_VALUE, -0x080000001, 0x100000001, Number.MIN_VALUE, 2**53+2, -0x07fffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, 0x0ffffffff, 0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -(2**53), 2**53-2, 0/0, 42, 0.000000000000001, 2**53, 1/0, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, Number.MIN_SAFE_INTEGER, 1, -0x0ffffffff, Number.MAX_VALUE, -1/0, -0x100000001, -(2**53-2), 0x080000000, 0x07fffffff]); ");
/*fuzzSeed-157142351*/count=790; tryItOut("(x);");
/*fuzzSeed-157142351*/count=791; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.sqrt(( + ( + ( ! ((((Math.acos(( ~ Math.fround(x))) >>> 0) << ((Math.atan2((x >>> 0), (Math.sqrt(x) | 0)) >>> 0) >>> 0)) >>> 0) >>> 0))))); }); testMathyFunction(mathy1, [0, 2**53+2, 1.7976931348623157e308, 0x07fffffff, -0, Number.MIN_VALUE, -0x080000000, 42, -0x0ffffffff, -0x100000000, -(2**53-2), -(2**53+2), 0x080000000, -Number.MAX_VALUE, 0x100000001, 1/0, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000000, -0x100000001, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1, -1/0, 0.000000000000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53, 0/0, 0x0ffffffff, 2**53-2]); ");
/*fuzzSeed-157142351*/count=792; tryItOut("a1.reverse(g0, (SimpleObject = ([, c\u0009, , x]) = (new ( /x/ )())(this.__defineSetter__(\"b\", \"\\u8598\"), window)));");
/*fuzzSeed-157142351*/count=793; tryItOut("throw StopIteration;");
/*fuzzSeed-157142351*/count=794; tryItOut("const x = x, \u3056 = (4277), b;Array.prototype.sort.apply(a0, [(function(stdlib, foreign, heap){ \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    d1 = (1.0);\n    i3 = ((((i3)-(0x323a1277))>>>((i3))));\n    return +((137438953471.0));\n  }\n  return f; })]);");
/*fuzzSeed-157142351*/count=795; tryItOut("m1.has(f1)\nwith(x)/*ADP-1*/Object.defineProperty(a2, 4, ({configurable: false}));");
/*fuzzSeed-157142351*/count=796; tryItOut("m2 = Proxy.create(h0, g0);");
/*fuzzSeed-157142351*/count=797; tryItOut("v1 = 0;print(o0.g2);function x() { return new RegExp(\"\\\\2\", \"yi\") } g0.offThreadCompileScript(\"print(g2.t1);t0[18];\");");
/*fuzzSeed-157142351*/count=798; tryItOut("\"use strict\"; h1 + s1;");
/*fuzzSeed-157142351*/count=799; tryItOut("mathy3 = (function(x, y) { return (((( + (( + (Math.atanh(x) >>> 0)) | 0)) | 0) - (mathy1(Math.fround(( + ( ! ( + (Math.cosh(((y ? (x ** y) : (( ! (y >>> 0)) >>> 0)) | 0)) | 0))))), (Math.sqrt((( + Math.log(( + (y * (Math.ceil(Math.cosh(Math.fround(y))) >>> 0))))) >>> 0)) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy3, [0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 2**53+2, 0/0, -0x100000001, 0, -(2**53+2), 42, 2**53, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, 0x100000000, Math.PI, 2**53-2, -0x0ffffffff, -0x100000000, -0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, -0, 1, -Number.MAX_VALUE, -0x07fffffff, 1/0, 0x07fffffff, 0x0ffffffff, -(2**53), -0x080000000, -1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-157142351*/count=800; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(o0.o1.a0, s2);");
/*fuzzSeed-157142351*/count=801; tryItOut("testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, 1/0, -0x080000000, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0, -Number.MIN_VALUE, 2**53, 0x080000001, -0x07fffffff, 0/0, Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, -0x080000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53-2), -Number.MAX_VALUE, -0x100000001, -1/0, -(2**53), -Number.MAX_SAFE_INTEGER, Math.PI, 1, Number.MIN_VALUE, 0x0ffffffff, 2**53-2, -0x0ffffffff, 42, 0x100000000, -(2**53+2), 2**53+2, -0]); ");
/*fuzzSeed-157142351*/count=802; tryItOut("g2.o0.m1 = Proxy.create(h0, g2.g2);");
/*fuzzSeed-157142351*/count=803; tryItOut("/*RXUB*/var r = new RegExp(\"(?!^+|(?=\\\\xFc)\\\\s*+{0,1})|\\\\1{3}+(?:^+){2,5}[^]{1,262146}(?=\\\\b)*\\\\1+?+\", \"i\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-157142351*/count=804; tryItOut("mathy1 = (function(x, y) { return ( + Math.imul((( + ( + ( ! (Math.cos((x >> (Math.max((x >>> 0), (x >>> 0)) >>> 0))) | 0)))) | 0), ( + (Math.min((Math.imul((( ~ Math.min(y, y)) | 0), (y >>> 0)) >>> 0), Number.MIN_VALUE) * Math.asin(x))))); }); ");
/*fuzzSeed-157142351*/count=805; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=806; tryItOut("var xhxjsc = new ArrayBuffer(16); var xhxjsc_0 = new Int16Array(xhxjsc); print(xhxjsc_0[0]); print(xhxjsc_0);");
/*fuzzSeed-157142351*/count=807; tryItOut("/*vLoop*/for (gjvyqu = 0; gjvyqu < 8; ++gjvyqu) { c = gjvyqu; with(/*FARR*/[c++, .../*FARR*/[, new Map.prototype.forEach( /x/ ), , g2.v0 = new Number(-0);, a = \"\\uD392\", eval > c, (/*UUV2*/(eval.min = eval.setUTCMonth)), ...[(Math.pow(-24, \"\\u1046\")) for (a in -16) for (c of  /x/g )], w = window, ...c], ...(function() { yield (NaN) = {}; } })()].filter(offThreadCompileScript, 2047))a0.reverse(Math.min(-5, ({a1:1})), f0); } ");
/*fuzzSeed-157142351*/count=808; tryItOut("\"use strict\"; g0.t1 = t2.subarray(({valueOf: function() { g0.m2.has(e2);return 12; }}), 6);");
/*fuzzSeed-157142351*/count=809; tryItOut("g0.toSource = (function mcc_() { var yhhdfv = 0; return function() { ++yhhdfv; if (/*ICCD*/yhhdfv % 7 == 4) { dumpln('hit!'); try { h0.fix = (function() { try { a1[14]; } catch(e0) { } try { v2 = a2.reduce, reduceRight(Function.prototype.toString, m0); } catch(e1) { } try { let m1 = new WeakMap; } catch(e2) { } a1 = a1.filter((function() { try { this.f0 + ''; } catch(e0) { } try { for (var v of o2.b0) { s0 = new String(t1); } } catch(e1) { } v0 = false; throw h2; }), m2, yield ((new Function(\"b2 + i0;\")).prototype), b0, m1, false, v0, t0, t1); return v1; }); } catch(e0) { } g2 = this; } else { dumpln('miss!'); try { m1.has(this.p2); } catch(e0) { } v1 = g1.g0.runOffThreadScript(); } };})();");
/*fuzzSeed-157142351*/count=810; tryItOut("e0.delete(g0.s1);");
/*fuzzSeed-157142351*/count=811; tryItOut("var gxlfem = new ArrayBuffer(16); var gxlfem_0 = new Int16Array(gxlfem); gxlfem_0[0] = 14; (window);");
/*fuzzSeed-157142351*/count=812; tryItOut("mathy1 = (function(x, y) { return (Math.atan2((( - (( ! -(2**53)) >>> 0)) >>> 0), mathy0((Math.cosh(Math.hypot(x, -0x080000001)) >>> 0), y)) === ((Math.min(Math.fround((( + (y >= 2**53-2)) * ( + (42 | 0)))), Math.fround(y)) + (Math.atan2((mathy0((Math.fround(( + Math.fround(((x | 0) ? (x * x) : x)))) >>> 0), (( - x) >>> 0)) >>> 0), y) >>> 0)) | 0)); }); testMathyFunction(mathy1, [0.000000000000001, -(2**53), 0x100000001, -0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, -1/0, -0x080000000, -Number.MIN_VALUE, 0, 2**53-2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000001, 2**53+2, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x0ffffffff, 0x100000000, 1, -(2**53-2), 1/0, -Number.MAX_VALUE, -(2**53+2), -0, 42, -0x100000001, 0x07fffffff, 2**53]); ");
/*fuzzSeed-157142351*/count=813; tryItOut("\"use strict\"; m1.set(t0, i1);");
/*fuzzSeed-157142351*/count=814; tryItOut("mathy4 = (function(x, y) { return ( - Math.fround(Math.trunc(((Math.sin(( ! x)) >>> 0) !== (-0x100000001 >>> 0))))); }); testMathyFunction(mathy4, [0, /0/, ({toString:function(){return '0';}}), NaN, (new Number(0)), 1, 0.1, -0, undefined, [0], (function(){return 0;}), '', objectEmulatingUndefined(), (new String('')), (new Boolean(true)), [], ({valueOf:function(){return '0';}}), '0', '\\0', true, null, '/0/', (new Boolean(false)), false, (new Number(-0)), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-157142351*/count=815; tryItOut("if((x % 2 == 0)) s2 += 'x'; else {(this); }");
/*fuzzSeed-157142351*/count=816; tryItOut("\"use strict\"; {}print((4277));");
/*fuzzSeed-157142351*/count=817; tryItOut("mathy2 = (function(x, y) { return ( - ( + Math.min(( + ( + (Math.fround((-0x100000000 % 0x080000001)) ? Math.log2(( + Math.min(( + Number.MAX_VALUE), ( + Number.MAX_SAFE_INTEGER)))) : Math.fround(Math.min(Math.fround(( + x)), Math.fround(x)))))), ( + ( + (( + (( ~ (Math.atan2((Math.asinh(x) | 0), Math.atanh(x)) | 0)) | 0)) ? (( ! 1) | 0) : ( + ( + (( + ( ~ y)) > x))))))))); }); testMathyFunction(mathy2, [2**53+2, -0x080000000, 0x0ffffffff, -0x080000001, Number.MAX_VALUE, 0, 0x080000001, 0x07fffffff, -1/0, 0x100000000, -(2**53), 1, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, 0/0, -Number.MIN_VALUE, -0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), 42, 2**53, 0.000000000000001, -0x0ffffffff, -0x07fffffff, Math.PI, 2**53-2, -(2**53-2), Number.MIN_SAFE_INTEGER, 1/0]); ");
/*fuzzSeed-157142351*/count=818; tryItOut("mathy0 = (function(x, y) { return (( + (Math.min((Math.cos((Math.fround((-0x07fffffff ? y : Math.fround((x * y)))) | 0)) | 0), Math.atan2(( + Math.fround(( ~ (x - x)))), ((( + -0) !== Math.fround(0.000000000000001)) | 0))) | 0)) ? ( + (( + Math.sin(( + ( - x)))) + (x & Math.fround(Math.max(Math.fround((Math.atanh(2**53) | 0)), Math.fround(( ! (Math.fround((Math.fround(Number.MIN_VALUE) ^ x)) | 0)))))))) : ( + Math.hypot((((x | 0) >>> (y | 0)) | 0), (( ~ Math.fround(( + ( ! -0x100000001)))) >>> 0)))); }); ");
/*fuzzSeed-157142351*/count=819; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.cbrt(((((mathy0((x >>> 0), (( + Math.tanh((Math.sin((y | 0)) | 0))) | 0)) >>> 0) - x) >= (Math.fround(Math.cbrt(Math.fround(Math.abs(Math.fround(((Math.atan2(x, y) > (Math.atan2((y >>> 0), ( + -(2**53))) | 0)) | 0)))))) << x)) >>> 0)); }); ");
/*fuzzSeed-157142351*/count=820; tryItOut("print(/[^]/ym);");
/*fuzzSeed-157142351*/count=821; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (((( - (((Math.sin((mathy0(( + Math.max(y, y)), ( + Math.atanh(Math.fround(y)))) >>> 0)) >>> 0) >>> 0) || Math.fround((mathy3((Math.hypot(( + y), x) >>> 0), (Math.fround(( ! Math.fround(x))) >>> 0)) >>> 0)))) | 0) & (( ! (( - ((( ! (x >>> 0)) >= (( + ( ~ ( + Math.max(x, 2**53-2)))) | 0)) | 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[x, x, (x += 3), x, -0x0ffffffff, x,  \"\" ,  \"\" , x, x, (x += 3), x, -0x0ffffffff,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , -0x0ffffffff,  \"\" ,  \"\" , x, -0x0ffffffff, x, -0x0ffffffff, (x += 3), x, (x += 3), (x += 3), -0x0ffffffff, (x += 3), x, -0x0ffffffff, x, -0x0ffffffff,  \"\" , -0x0ffffffff, (x += 3), (x += 3), x, x, (x += 3), -0x0ffffffff, x, x, x, x, (x += 3), x, (x += 3), -0x0ffffffff,  \"\" , (x += 3), x,  \"\" , -0x0ffffffff, (x += 3), x, (x += 3), x, (x += 3), (x += 3),  \"\" ,  \"\" ,  \"\" , (x += 3), x, x, x, -0x0ffffffff,  \"\" , x, x, (x += 3)]); ");
/*fuzzSeed-157142351*/count=822; tryItOut("throw StopIteration;");
/*fuzzSeed-157142351*/count=823; tryItOut("Array.prototype.forEach.call(a2, (function() { for (var j=0;j<1;++j) { f1(j%5==0); } }));");
/*fuzzSeed-157142351*/count=824; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=825; tryItOut("/*infloop*/for(var e; this; window) {print(new RegExp(\"(?:(?=^?)|(?:\\\\W+?)*)\\\\B+?\", \"yim\")); }");
/*fuzzSeed-157142351*/count=826; tryItOut("g0 + '';");
/*fuzzSeed-157142351*/count=827; tryItOut("\"use strict\"; /*infloop*/for(let w = /\\3|\\w|$|(?!(?:.))/gy; ((void version(185)).valueOf(\"number\")) |=  '\\0' ; Date.prototype.setMilliseconds-=y = Proxy.create(({/*TOODEEP*/})(this),  /x/ )) g0.v2 = (t1 instanceof o2.m1);");
/*fuzzSeed-157142351*/count=828; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return (Math.fround((Math.fround(((( + ( ! ( + y))) ? mathy0((2**53 | 0), x) : x) | ( + (( - x) ? (Math.imul(( + 2**53), Math.abs((y >>> 0))) >>> 0) : (((x >>> 0) + (( + (( + x) != ( + ( + ( ! ( + 2**53)))))) | 0)) >>> 0))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-(2**53), -1/0, -Number.MIN_VALUE, Math.PI, 1/0, 0x100000001, Number.MIN_VALUE, 2**53+2, -0x100000000, -0x080000001, -0x080000000, 0x080000000, -Number.MAX_VALUE, 0.000000000000001, -0x100000001, 2**53, -(2**53-2), Number.MAX_VALUE, -0x0ffffffff, 0x080000001, 0, -0, -(2**53+2), 0/0, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 1, 0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 42, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308]); ");
/*fuzzSeed-157142351*/count=829; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=830; tryItOut("/*vLoop*/for (var mbdyxc = 0; mbdyxc < 74; ++mbdyxc) { w = mbdyxc; m1.get(f1); } ");
/*fuzzSeed-157142351*/count=831; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 4097.0;\n    d2 = (+(1.0/0.0));\n    switch ((~((0xbe2da1ec)))) {\n    }\n    i0 = (0x9fb1fed3);\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); ");
/*fuzzSeed-157142351*/count=832; tryItOut("/*bLoop*/for (dcqvot = 0; (((makeFinalizeObserver('nursery')))) && dcqvot < 127 && (/[^]*/gyim) && (let (c) {}\n); ++dcqvot) { if (dcqvot % 6 == 0) { m1.has(o2); } else { print(x); }  } ");
/*fuzzSeed-157142351*/count=833; tryItOut("\"use strict\"; /*iii*//*tLoop*/for (let x of /*MARR*/[ \"use strict\" , function(){}, function(){},  \"use strict\" , function(){}, objectEmulatingUndefined(),  \"use strict\" ,  \"use strict\" , window, \"\\u28EE\", function(){}, function(){}, window,  \"use strict\" , window, objectEmulatingUndefined(), \"\\u28EE\", window, \"\\u28EE\", window, function(){}, function(){}, \"\\u28EE\", objectEmulatingUndefined(), objectEmulatingUndefined(), \"\\u28EE\", objectEmulatingUndefined(), objectEmulatingUndefined(), function(){},  \"use strict\" , window, objectEmulatingUndefined(), function(){}, function(){},  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , objectEmulatingUndefined(), window,  \"use strict\" , window, window, window,  \"use strict\" ,  \"use strict\" , function(){}, function(){},  \"use strict\" ,  \"use strict\" ,  \"use strict\" , function(){}, objectEmulatingUndefined(), function(){},  \"use strict\" , objectEmulatingUndefined(), function(){}, \"\\u28EE\",  \"use strict\" ,  \"use strict\" , window, window,  \"use strict\" , \"\\u28EE\", function(){}, \"\\u28EE\", objectEmulatingUndefined(), objectEmulatingUndefined(), function(){}, objectEmulatingUndefined(),  \"use strict\" , \"\\u28EE\", window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, \"\\u28EE\", window, window,  \"use strict\" , objectEmulatingUndefined(), window,  \"use strict\" ,  \"use strict\" , window, objectEmulatingUndefined()]) { \"\\uB328\"; }/*hhh*/function nrxogc(){b = (void options('strict_mode'));;}");
/*fuzzSeed-157142351*/count=834; tryItOut("a2.toString = (function() { try { s1 = Array.prototype.join.call(g0.a0, s1, this.b1, f2); } catch(e0) { } try { v0 = (m0 instanceof m0); } catch(e1) { } p1 + ''; return p2; });");
/*fuzzSeed-157142351*/count=835; tryItOut("var eemohm = new SharedArrayBuffer(24); var eemohm_0 = new Uint8ClampedArray(eemohm); var eemohm_1 = new Uint8Array(eemohm); print(eemohm_1[0]); var eemohm_2 = new Uint8ClampedArray(eemohm); {}i0 = new Iterator(t2, true);print(eemohm_2[4]);");
/*fuzzSeed-157142351*/count=836; tryItOut("g0.h2.getOwnPropertyDescriptor = f1;");
/*fuzzSeed-157142351*/count=837; tryItOut("o0 = new Object;");
/*fuzzSeed-157142351*/count=838; tryItOut("v2 = this.r1.toString;");
/*fuzzSeed-157142351*/count=839; tryItOut("\"use strict\"; o2.a0 = arguments.callee.arguments;");
/*fuzzSeed-157142351*/count=840; tryItOut("\"use strict\"; print(let (w) \"\\uCA07\");\nv2 = this.t2.length;\n");
/*fuzzSeed-157142351*/count=841; tryItOut("\"use strict\"; /*oLoop*/for (let augewb = 0; augewb < 69; ++augewb) { this.t2.__proto__ = g1.p1; } ");
/*fuzzSeed-157142351*/count=842; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.fround((( ! Math.fround(mathy1(y, Math.atan2(mathy0(x, y), ((((y >>> 0) || (y >>> 0)) >>> 0) >>> 0))))) >>> 0)) != Math.fround(Math.acos(Math.tanh((( ! Math.atan2(Math.cosh(( + y)), Math.fround(1))) >>> 0))))); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), new String('q'), x, new String('q'), x, new String('q'), x, new String('q'), new String('q'), new String('q'), new String('q'), x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), x, x, new String('q'), new String('q'), new String('q'), x, new String('q'), new String('q'), new String('q'), x, new String('q'), new String('q'), new String('q'), new String('q'), x, x, x, new String('q'), x, new String('q'), new String('q'), new String('q'), x, x, new String('q'), x, new String('q'), x, x, x, x, x, x, x, new String('q'), new String('q'), new String('q'), new String('q'), x, x, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), x, new String('q'), new String('q'), new String('q'), x, new String('q'), new String('q'), x, new String('q'), x, x, new String('q'), new String('q'), new String('q'), x, new String('q'), x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-157142351*/count=843; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! Math.pow((( ~ (( ~ (-Number.MAX_VALUE >>> 0)) | 0)) | 0), (Math.atan2((Number.MAX_VALUE | 0), (( + Math.tanh(( + y))) | 0)) | 0))); }); testMathyFunction(mathy3, /*MARR*/[-0x080000001, new Number(1), new Number(1), (void 0), (void 0), (void 0), -0x080000001,  \"\" , (void 0), new Number(1), (void 0), -0x080000001, (void 0), -0x080000001, new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1),  \"\" , (void 0), new Number(1), new Number(1), (void 0), -0x080000001,  \"\" , new Number(1), new Number(1),  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , -0x080000001, (void 0), new Number(1), new Number(1),  \"\" , (void 0), new Number(1), (void 0),  \"\" , (void 0), -0x080000001, -0x080000001, (void 0),  \"\" , (void 0), -0x080000001, new Number(1), (void 0), -0x080000001, new Number(1), (void 0),  \"\" , (void 0),  \"\" ,  \"\" , (void 0), -0x080000001, new Number(1), (void 0),  \"\" ]); ");
/*fuzzSeed-157142351*/count=844; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-157142351*/count=845; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.min(( + Math.atan2(Math.exp((x !== (Math.asinh((-0 | 0)) | 0))), ( + (( ~ ((Math.atan2((x | 0), ( + (Math.atan2((y >>> 0), (x >>> 0)) >>> 0))) >>> 0) >>> 0)) >>> 0)))), ( + (Math.hypot((Math.hypot(y, Math.fround(Math.hypot(Math.fround(Math.sqrt(Math.fround(Math.atan2(Math.fround((Math.tanh((x | 0)) | 0)), Math.fround(y))))), ( + Math.min(( ''  >>> 0), (y >>> 0)))))) | 0), (Math.imul(-0x100000000, Number.MAX_VALUE) | 0)) | 0))); }); testMathyFunction(mathy2, [0x080000001, 2**53, 2**53-2, -0, 2**53+2, -Number.MAX_VALUE, 0, Number.MAX_VALUE, -(2**53), 0.000000000000001, 1/0, -Number.MIN_VALUE, -0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, -0x100000001, -0x07fffffff, -0x100000000, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -(2**53+2), 0x100000001, 0/0, Math.PI, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x080000001, -(2**53-2), 1, 0x07fffffff, 0x080000000, -0x080000000, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-157142351*/count=846; tryItOut("mathy0 = (function(x, y) { return ((( + Math.asin(( + (Math.sinh(y) + Math.fround(Math.imul((( ! y) >>> 0), ((Math.max(Math.fround(-(2**53)), Math.fround(x)) ? Math.fround((Math.fround((Math.pow((y >>> 0), -0x07fffffff) >>> 0)) + Math.fround(y))) : -1/0) >>> 0))))))) >>> 0) == ((Math.acosh(((Math.fround(Math.imul((Math.sinh(Math.fround(( ! y))) >>> 0), ( - ( + Math.fround(-0x080000001))))) || ((( + ( + ( + x))) % (((Math.fround(y) ? Math.fround(0x0ffffffff) : Math.fround(x)) === y) | 0)) | 0)) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy0, /*MARR*/[]); ");
/*fuzzSeed-157142351*/count=847; tryItOut("\"use strict\"; /*MXX1*/o0 = g0.Uint16Array.name;");
/*fuzzSeed-157142351*/count=848; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = (i1);\n    {\n      {\n        d0 = (Infinity);\n      }\n    }\n    i1 = (i1);\n    d0 = (-((+((((((0x421cf75e) % (0x1d95d0ea)) << ((0x6ad9d46a) % (0x7fffffff))) <= (((0xf614ef09)+(0xfb7f8d88)) & ((0x498a12db) % (0x0))))-(i1))>>>((0xfd18a27e))))));\n    {\n      i1 = ((0x1075a5c0));\n    }\n    switch ((~~(d0))) {\n      default:\n        {\n          {\n            {\n              (Uint32ArrayView[((i1)+(i1)+((/*FFI*/ff(((576460752303423500.0)), ((70368744177665.0)))|0) ? (i1) : (0xa7761ac))) >> 2]) = ((((0xfbbe644c)-(0x55c04c9a)) << ((((!(i1))) ^ ((Float32ArrayView[((-0x8000000)) >> 2]))) % (0x3635f81c))) % (~~(d0)));\n            }\n          }\n        }\n    }\n    return (((((Float32ArrayView[1])))-(i1)))|0;\n  }\n  return f; })(this, {ff: Int32Array}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [0x0ffffffff, Math.PI, 1.7976931348623157e308, -(2**53+2), Number.MIN_VALUE, -Number.MIN_VALUE, 1, 0, 2**53+2, -Number.MAX_VALUE, -0x100000001, -0x080000001, 2**53, 0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), 0/0, 42, -0x100000000, Number.MAX_VALUE, -0x07fffffff, -0x080000000, 0.000000000000001, -0, 0x100000001, 0x07fffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, -(2**53), -0x0ffffffff]); ");
/*fuzzSeed-157142351*/count=849; tryItOut("\"use strict\"; let(b) { throw b;}let(c = eval ** x, x = x, e = x.valueOf(\"number\"), d = this) ((function(){with({}) { let(rwnwnj, ednmam, NaN, rugwqp, e, acxpnf, b = b, ftzabp) ((function(){b = \u3056;})()); } })());");
/*fuzzSeed-157142351*/count=850; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; void schedulegc(2); } void 0; }");
/*fuzzSeed-157142351*/count=851; tryItOut("a1[2] = this.m2;");
/*fuzzSeed-157142351*/count=852; tryItOut("neuter(this.b0, \"change-data\");");
/*fuzzSeed-157142351*/count=853; tryItOut("(null);");
/*fuzzSeed-157142351*/count=854; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-157142351*/count=855; tryItOut("M:with((a = Proxy.create(({/*TOODEEP*/})( \"\" ), \"\\uF4D0\")))");
/*fuzzSeed-157142351*/count=856; tryItOut("a0.length = w;");
/*fuzzSeed-157142351*/count=857; tryItOut("\"use strict\"; this.t1.valueOf = f2;");
/*fuzzSeed-157142351*/count=858; tryItOut("\"use strict\"; testMathyFunction(mathy5, /*MARR*/[new String(''),  /x/g , new Number(1.5), new Number(1.5), [1], [1], [1], [1],  /x/g , [1],  /x/g , new Number(1.5), new Number(1.5), [1], new Number(1.5), new Boolean(true), new String(''),  /x/g , new Boolean(true), [1],  /x/g , new Number(1.5), [1], new Boolean(true), [1], new Boolean(true), new Boolean(true), [1], new Number(1.5), new String(''), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new String(''), [1],  /x/g , new Number(1.5), new Boolean(true), new Number(1.5),  /x/g , new Number(1.5), [1], new Number(1.5), new String(''), [1],  /x/g , new Number(1.5), new Number(1.5), new Number(1.5),  /x/g , new Boolean(true), new Number(1.5), new Number(1.5), new Boolean(true), new Boolean(true), new Number(1.5), new String(''), [1],  /x/g ,  /x/g , [1], [1], new Boolean(true),  /x/g , new Boolean(true),  /x/g , new Number(1.5), [1], new Number(1.5), new String(''), new Boolean(true), new String(''), [1], new Number(1.5), new Number(1.5),  /x/g , new Boolean(true), new Number(1.5), new Boolean(true), new Boolean(true), new Boolean(true),  /x/g ,  /x/g , new String(''), new Number(1.5),  /x/g , new String(''), [1], new Number(1.5), [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], [1], new Boolean(true), new String(''),  /x/g , new String(''),  /x/g , new Boolean(true),  /x/g , [1],  /x/g ,  /x/g , new Boolean(true), [1], new Number(1.5),  /x/g , [1],  /x/g , [1], [1], new Boolean(true), [1],  /x/g , new Boolean(true), new Boolean(true), new Number(1.5), new Number(1.5), new Boolean(true), [1]]); ");
/*fuzzSeed-157142351*/count=859; tryItOut("/*RXUB*/var r = /(?:(?!\\1|.?)*?)/ym; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-157142351*/count=860; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=861; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( ! Math.log1p(((Math.fround(((Math.asinh(y) | 0) | 0)) | 0) , Math.acos(( + -0x07fffffff)))))); }); testMathyFunction(mathy0, [0x100000000, 0/0, 0x0ffffffff, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), 1/0, Number.MIN_VALUE, 1, -0, Math.PI, 2**53, 2**53-2, 0, 0x07fffffff, -Number.MAX_VALUE, 0x080000001, -0x07fffffff, -0x100000001, 0x080000000, Number.MIN_SAFE_INTEGER, -1/0, 0.000000000000001, -0x0ffffffff, -0x080000001, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 42, -(2**53+2), -0x100000000, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, 2**53+2]); ");
/*fuzzSeed-157142351*/count=862; tryItOut("\"use strict\"; return;");
/*fuzzSeed-157142351*/count=863; tryItOut("a1.unshift(i2, a2);");
/*fuzzSeed-157142351*/count=864; tryItOut("\"use strict\"; \"use asm\"; print(uneval(b0));");
/*fuzzSeed-157142351*/count=865; tryItOut("mathy1 = (function(x, y) { return ( ! (( ~ (((y == (Math.atan2((y | 0), (Math.exp(x) | 0)) | 0)) >>> 0) != x)) ? Math.hypot((Math.log1p(y) | 0), Math.fround(Math.cos(0x100000001))) : Math.imul(x, Math.asin(x)))); }); ");
/*fuzzSeed-157142351*/count=866; tryItOut("m0 + '';");
/*fuzzSeed-157142351*/count=867; tryItOut("\"use strict\"; o1.v2 = t2.length;");
/*fuzzSeed-157142351*/count=868; tryItOut("mathy0 = (function(x, y) { return ((Math.atan2(( - (y | 0)), ( ~ ( + ((0x07fffffff * Number.MAX_VALUE) ^ Math.ceil((x ^ y)))))) | 0) || Math.fround(Math.pow((((-Number.MAX_SAFE_INTEGER >>> x) | Math.fround(((( ~ (x >>> 0)) >>> 0) == ( ~ Math.max(x, y))))) >>> 0), Math.fround(((((( + ((( ~ (0x080000001 | 0)) | 0) | 0)) >>> 0) | 0) >= (Math.hypot(Math.atanh(x), y) | 0)) | 0))))); }); testMathyFunction(mathy0, [-(2**53), 0.000000000000001, -1/0, 1/0, -0x100000001, 1.7976931348623157e308, 0x100000000, Number.MIN_VALUE, 2**53-2, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), 0x07fffffff, -0x080000000, -Number.MIN_SAFE_INTEGER, Math.PI, 42, 0x100000001, 0x0ffffffff, -(2**53-2), 1, 0x080000001, 0x080000000, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 0, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000001, -0, -0x07fffffff]); ");
/*fuzzSeed-157142351*/count=869; tryItOut("this.eval = this;for(let y in []);");
/*fuzzSeed-157142351*/count=870; tryItOut("\"use strict\"; \"use asm\"; let x, x = \"\u03a0\" %=  '' , gheryy, x, d, x, onrvbj, ywnwgh;o1.i1.__proto__ = this.b1;");
/*fuzzSeed-157142351*/count=871; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=872; tryItOut("selectforgc(o0);");
/*fuzzSeed-157142351*/count=873; tryItOut("/* no regression tests found */");
/*fuzzSeed-157142351*/count=874; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.round(Math.fround(Math.trunc((((x >> (y | 0)) >>> 0) !== Math.fround((Math.exp(0x07fffffff) >> y))))))); }); testMathyFunction(mathy5, /*MARR*/[new String(''), ({}), new String(''), ({}), new Boolean(true), new String(''), arguments.caller, ({}), arguments.caller, new String(''), ({}), new String(''), new String(''), ({x:3}), new String(''), ({x:3}), new String(''), new String(''), new Boolean(true), new String(''), ({}), arguments.caller, arguments.caller, new Boolean(true), new String(''), new String(''), new Boolean(true), new String(''), new String(''), ({x:3}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), ({}), new String(''), new Boolean(true), ({x:3}), new String(''), ({}), ({}), new Boolean(true), new Boolean(true), ({}), ({}), new Boolean(true), new String(''), ({x:3}), new Boolean(true), ({x:3}), ({x:3}), new String(''), arguments.caller, ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), ({x:3}), arguments.caller, arguments.caller, arguments.caller, ({}), new String(''), new Boolean(true), ({}), ({x:3}), arguments.caller, ({}), ({x:3}), new Boolean(true), arguments.caller, new Boolean(true), new String(''), new String(''), arguments.caller, arguments.caller, new String(''), ({x:3}), ({}), ({}), new Boolean(true), arguments.caller, new Boolean(true)]); ");
/*fuzzSeed-157142351*/count=875; tryItOut("x = x / 3; var r0 = x * x; var r1 = x + x; var r2 = 4 ^ r1; var r3 = 5 * r0; var r4 = x | r3; var r5 = 7 - r4; var r6 = 0 | 0; r0 = 1 * r2; var r7 = 4 % r4; var r8 = r1 | 4; var r9 = 1 * r8; var r10 = r1 - r7; var r11 = r0 % r9; r2 = r7 / r3; var r12 = r11 % r0; r11 = r6 / r11; var r13 = 7 * r3; r6 = 7 % r9; var r14 = r4 % r4; var r15 = r10 % 7; r10 = 2 / r12; r14 = r12 | r9; var r16 = x / r8; var r17 = 7 | r13; print(x); var r18 = r9 * r2; var r19 = 5 ^ r18; var r20 = 9 | r3; r11 = r8 | 3; var r21 = r0 ^ 0; var r22 = 7 + r3; var r23 = 0 % 0; var r24 = 4 + r3; var r25 = 8 | 5; var r26 = r6 | r23; var r27 = r9 / r18; var r28 = 8 * r14; var r29 = r28 & r4; var r30 = 6 % r20; r5 = 8 / 7; var r31 = 0 % r12; var r32 = r12 / r22; var r33 = r25 / 1; var r34 = r6 & r10; var r35 = 9 ^ r20; var r36 = r7 - r14; var r37 = r9 ^ r33; var r38 = 0 / 9; var r39 = r28 & 3; var r40 = r0 | 4; var r41 = r32 & r10; var r42 = x & r12; r23 = r42 + r41; var r43 = r35 + 7; print(r13); var r44 = r40 / r10; var r45 = 7 & r36; var r46 = r28 / r0; var r47 = 3 ^ r23; r11 = r27 * r30; var r48 = r8 ^ r5; var r49 = r11 - 8; var r50 = r49 / 7; var r51 = 7 % r5; r6 = r19 ^ r24; var r52 = r39 / r50; var r53 = r32 | r29; var r54 = r15 + 0; var r55 = 0 - 2; var r56 = r6 & r16; var r57 = r9 ^ r7; var r58 = 9 / 0; var r59 = r46 * r57; r14 = r45 & r0; var r60 = r5 & r22; var r61 = r20 ^ r54; r25 = r13 ^ 3; var r62 = r59 * r5; var r63 = r61 - 0; r3 = 8 % r45; var r64 = 8 - r8; var r65 = 5 / r30; r48 = 3 & r20; print(r31); var r66 = r33 - 2; var r67 = r31 ^ 7; var r68 = 2 | r34; r65 = r47 ^ r38; var r69 = r0 & r27; var r70 = r8 * r55; var r71 = 2 & r42; var r72 = r40 | 0; var r73 = r36 % 4; var r74 = 2 ^ r48; r29 = r42 % 0; var r75 = r4 % r3; var r76 = r66 ^ 2; r27 = 0 + 0; var r77 = r68 + r47; var r78 = 9 % r26; r11 = r20 % r12; var r79 = r64 % 8; r71 = r16 & r79; var r80 = 7 | 5; var r81 = r14 - r35; r54 = r46 - r66; r4 = 4 + r21; var r82 = r63 - 1; var r83 = 1 / r10; var r84 = r62 ^ 3; var r85 = r32 / 4; var r86 = r8 & 8; print(r16); r26 = r85 & r25; var r87 = r83 - 8; var r88 = r61 & r2; print(r27); r70 = r47 & r41; r87 = 6 * r11; var r89 = 3 - r15; r76 = r63 % r63; var r90 = 6 | r89; var r91 = r50 ^ 5; var r92 = r11 * r72; r61 = r3 / 8; var r93 = 6 - r6; var r94 = 8 & r80; var r95 = r10 ^ r2; var r96 = 0 / r45; var r97 = r33 & r66; r82 = 7 - r72; var r98 = r20 % 9; var r99 = r9 / r25; var r100 = r9 | r39; var r101 = r81 + r90; var r102 = 8 ^ 7; var r103 = 8 % r90; r96 = 0 - r79; var r104 = r101 & r79; r79 = 7 + r51; var r105 = r80 | r87; r46 = r78 % 7; var r106 = 0 - r52; var r107 = r39 ^ r99; var r108 = 1 % r38; r51 = r90 | r70; var r109 = r45 * 6; var r110 = 4 & r15; var r111 = 1 ^ r94; var r112 = r111 ^ 1; r94 = r14 | r42; var r113 = r87 + r32; var r114 = r8 + r41; var r115 = r93 % r79; r23 = 8 | 0; r55 = r64 & r78; var r116 = 5 * 5; var r117 = 9 ^ r76; var r118 = r114 + 1; var r119 = 5 * 5; var r120 = r85 * 1; r102 = 1 | 1; var r121 = 5 * r12; var r122 = r34 / r16; var r123 = 6 ^ r7; var r124 = 2 + r3; r92 = 9 * r103; r20 = r91 & r68; var r125 = r38 / 3; r96 = 3 & 2; r31 = 9 - r56; var r126 = 4 * r46; var r127 = r97 / 1; var r128 = r47 & r7; print(r35); var r129 = r17 ^ r82; var r130 = r37 - r110; r17 = 4 ^ r45; var r131 = 3 & r11; var r132 = r43 % r68; var r133 = r46 & r67; var r134 = r37 ^ 4; var r135 = 2 | r120; var r136 = r72 * r35; var r137 = r25 * r30; print(r92); var r138 = r60 + r21; var r139 = r112 ^ 5; var r140 = r61 - 6; var r141 = r127 + r33; var r142 = r35 + 0; var r143 = r55 | r73; var r144 = r55 - r114; print(r87); var r145 = 6 / 3; print(r92); var r146 = 9 ^ 5; var r147 = r8 % 1; r44 = r135 % r88; var r148 = r6 + x; var r149 = 4 * 0; var r150 = r108 % r35; var r151 = 1 * r90; r112 = 6 - r48; r61 = 4 % r57; var r152 = r64 + 6; r121 = r103 & r111; var r153 = r124 - 3; var r154 = r66 % r30; print(r132); r117 = 3 | 7; r97 = 8 / r51; var r155 = r23 ^ 1; var r156 = r43 % r42; var r157 = 9 / r108; print(r137); var r158 = r28 - r128; var r159 = 9 | r156; r6 = r64 | r113; var r160 = 9 % 8; var r161 = 6 * 6; r95 = 8 / r55; var r162 = 3 + r57; r118 = x & r37; var r163 = r138 ^ r21; var r164 = r106 ^ r84; var r165 = r137 + r67; r154 = 4 * 4; r110 = 0 + r59; r57 = 9 % r59; var r166 = 5 | r50; var r167 = 1 % r6; var r168 = 3 ^ r127; var r169 = r123 | r29; var r170 = 1 / r55; r143 = r16 ^ r149; var r171 = r59 | r152; ");
/*fuzzSeed-157142351*/count=876; tryItOut(" for (let c of x) {this.h0.getOwnPropertyNames = f1;/*infloop*/for(this.d in ((x--)(c)))g2.o2.a2.splice(8, 6); }");
/*fuzzSeed-157142351*/count=877; tryItOut("mathy5 = (function(x, y) { return ((((( + 1.7976931348623157e308) | 0) + (( - (y | 0)) | 0)) | 0) >>> (( - Math.fround((( + Number.MIN_SAFE_INTEGER) >= Math.fround(y)))) ? Math.imul(Math.cosh(( ! y)), (Math.acos((( + Math.acosh(Math.fround(x))) | 0)) | 0)) : Math.round(( + Math.sqrt(Math.fround(Math.cos(Math.fround((Math.hypot((x >>> 0), (y >>> 0)) >>> 0))))))))); }); testMathyFunction(mathy5, [42, 0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, -Number.MAX_VALUE, 0x100000001, -0x100000001, 0x080000001, 2**53-2, 0.000000000000001, Number.MAX_VALUE, 0x080000000, -(2**53), -0x080000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0, -(2**53+2), -0x080000001, 2**53, 0x100000000, Math.PI, -1/0, 0/0, -(2**53-2), 2**53+2, -Number.MIN_VALUE, -0x100000000, -Number.MAX_SAFE_INTEGER, 1, -0x07fffffff]); ");
/*fuzzSeed-157142351*/count=878; tryItOut("");
/*fuzzSeed-157142351*/count=879; tryItOut("\"use strict\"; i1 = new Iterator(t0);");
/*fuzzSeed-157142351*/count=880; tryItOut("print(uneval(h1));");
/*fuzzSeed-157142351*/count=881; tryItOut("/*vLoop*/for (var wereih = 0; wereih < 101; ++wereih) { w = wereih; print(/(?:(?:\u5a27))(?![^][\u00ed\\S]\\3)|(?:\\1)/gm); } ");
/*fuzzSeed-157142351*/count=882; tryItOut("r0 = /\\B|(?=\\w)|\u0001\\B\\B\0(?=.){3}|(?!.)\\ue0D9\\W|[\\w]|\u1bab|\\b|\\D.{2,2}|(?:.){3,}/gy;");
/*fuzzSeed-157142351*/count=883; tryItOut("\"use strict\"; t0[9];");
/*fuzzSeed-157142351*/count=884; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + ((Math.fround(Math.sinh(x)) ? Math.min((Math.atan((x | 0)) | 0), -Number.MAX_SAFE_INTEGER) : (Math.round(Math.sin((y | 0))) == Math.hypot((mathy0((y >>> 0), (y >>> 0)) >>> 0), (Math.pow(x, 1) , Math.atan2(y, ( + (Math.expm1((x >>> 0)) >>> 0))))))) >> ( + Math.log2(Math.log10(Math.acosh((Number.MAX_VALUE | 0))))))); }); testMathyFunction(mathy1, [(new Number(0)), (new Boolean(true)), objectEmulatingUndefined(), (new Boolean(false)), '\\0', [0], (new String('')), 1, (function(){return 0;}), -0, null, ({valueOf:function(){return '0';}}), '', true, 0.1, undefined, (new Number(-0)), NaN, '/0/', false, [], 0, '0', ({toString:function(){return '0';}}), /0/, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-157142351*/count=885; tryItOut("/*RXUB*/var r = /\\1/gim; var s = \"\\ua251\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-157142351*/count=886; tryItOut("v2 = a0.length;");
/*fuzzSeed-157142351*/count=887; tryItOut("i0.next();");
/*fuzzSeed-157142351*/count=888; tryItOut("{}");
/*fuzzSeed-157142351*/count=889; tryItOut("/*RXUB*/var r = new RegExp(\"(((?:\\u3a99[]{1,})?|((?:([\\\\Z])){4,8}(?=.)))){16777215}\", \"gym\"); var s = \"ZZZZ\\nZZZZ\\nZZZZ\\nZZZZ\\nZZZZ\\nZZZZ\\nZZZZ\\n\"; print(s.split(r)); Array.prototype.push.call(a0, a0, b2, h2, o1);");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
