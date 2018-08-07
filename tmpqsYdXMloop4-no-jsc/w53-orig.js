

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
/*fuzzSeed-169986037*/count=1; tryItOut("\"use strict\"; a0.forEach(runOffThreadScript);");
/*fuzzSeed-169986037*/count=2; tryItOut("\"use strict\"; testMathyFunction(mathy3, [false, (new Number(-0)), (function(){return 0;}), 1, [], (new String('')), '\\0', null, '/0/', (new Number(0)), '', (new Boolean(false)), (new Boolean(true)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), NaN, 0.1, /0/, ({valueOf:function(){return '0';}}), undefined, '0', -0, objectEmulatingUndefined(), true, [0], 0]); ");
/*fuzzSeed-169986037*/count=3; tryItOut("\"use strict\"; print(x);print(uneval(f2));");
/*fuzzSeed-169986037*/count=4; tryItOut("a2.forEach((function() { try { m2.get(b2); } catch(e0) { } try { o0.v0 = Object.prototype.isPrototypeOf.call(e0, v2); } catch(e1) { } a1.forEach(); return v1; }));");
/*fuzzSeed-169986037*/count=5; tryItOut("b0 = t1.buffer;");
/*fuzzSeed-169986037*/count=6; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=7; tryItOut("this.b2.toString = (function() { for (var j=0;j<66;++j) { f0(j%2==1); } });");
/*fuzzSeed-169986037*/count=8; tryItOut("g1.v2 = Array.prototype.some.apply(a2, [(function(j) { if (j) { this.h1.valueOf = (function() { for (var j=0;j<64;++j) { f1(j%5==0); } }); } else { try { if(true) Object.seal(b0); else {m0.set(i2, Uint32Array()); } } catch(e0) { } try { v0 = o2.a1.reduce, reduceRight(f1); } catch(e1) { } try { f2(o0.i0); } catch(e2) { } v1 = (s0 instanceof o1.f0); } })]);");
/*fuzzSeed-169986037*/count=9; tryItOut("o1.a2.shift();");
/*fuzzSeed-169986037*/count=10; tryItOut("\"use strict\"; let(y) { (void options('strict')).x = y;}throw c;");
/*fuzzSeed-169986037*/count=11; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.hypot((Math.log1p(( + ((Math.min(y, (Math.min(Math.fround((Math.fround(x) ^ 2**53+2)), (42 >>> 0)) >>> 0)) << Math.min((( + (-Number.MIN_SAFE_INTEGER | 0)) | 0), x)) >>> 0))) === Math.fround(Math.atan2(( + Math.hypot(( + Math.atan2(Math.fround((((x >>> 0) | (x >>> 0)) >>> 0)), y)), ( + x))), Math.max(mathy0(x, ( + -0x080000001)), y)))), mathy0(mathy0(( ~ Math.fround(y)), y), Math.fround(Math.max(( ! ( + x)), (Math.min(( + ( + Math.sign(( + x)))), ( + y)) | 0))))); }); ");
/*fuzzSeed-169986037*/count=12; tryItOut("s1 = new String(f2);");
/*fuzzSeed-169986037*/count=13; tryItOut("");
/*fuzzSeed-169986037*/count=14; tryItOut("testMathyFunction(mathy2, [0x080000001, 1, -0x080000000, -(2**53-2), -1/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, -0x07fffffff, 0x07fffffff, Number.MIN_VALUE, 1/0, -(2**53), 0x0ffffffff, -0x080000001, 0, Math.PI, -0x100000000, -0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0/0, 0x100000000, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53+2, 0.000000000000001, -0x0ffffffff, -0x100000001, 42, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000001, Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=15; tryItOut("a1.unshift(t1);");
/*fuzzSeed-169986037*/count=16; tryItOut("for (var v of this.e1) { try { v0.__iterator__ = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19) { a9 = a18 - a15; var r0 = a4 / a19; var r1 = 5 % a16; a5 = a1 - 0; var r2 = 8 & a0; a5 = a4 - 1; var r3 = 1 % a2; var r4 = a19 & 8; a2 = r1 / r3; var r5 = r2 % a19; var r6 = a3 ^ 3; var r7 = a7 * r0; a7 = a9 + a12; var r8 = 0 & a0; r8 = a4 ^ r2; var r9 = r7 | a8; var r10 = x + a18; var r11 = a16 * a16; var r12 = r10 & 3; var r13 = 3 & 3; var r14 = 7 - a7; var r15 = 2 * 0; var r16 = a7 | r5; var r17 = 4 ^ 2; r11 = r6 - a17; var r18 = a2 ^ a16; var r19 = r11 % r0; var r20 = r11 ^ a4; var r21 = a15 + 2; var r22 = r11 % r15; var r23 = r15 % 5; var r24 = 4 / r3; a18 = r20 - a7; print(r8); r13 = a17 & a16; r3 = 8 ^ a15; var r25 = r6 + r16; var r26 = r24 | r18; var r27 = a16 & r6; return a12; }); } catch(e0) { } try { s0 += 'x'; } catch(e1) { } this.m0 = new Map; }function e(x, e = (Math.imul(1156293541.5, (({x: (window.yoyo(length))})))))(x.eval(\"/* no regression tests found */\"))a1.splice(NaN, 10);");
/*fuzzSeed-169986037*/count=17; tryItOut("testMathyFunction(mathy4, [-Number.MAX_VALUE, -0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 42, -Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, 2**53-2, 0x0ffffffff, Math.PI, 1, Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), -0x080000000, -0x07fffffff, 0x100000001, -0, -0x100000000, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, 0x07fffffff, 2**53+2, 0x080000000, -0x100000001, 0/0, 2**53]); ");
/*fuzzSeed-169986037*/count=18; tryItOut("\"use asm\"; v2 = g1.t1.length;");
/*fuzzSeed-169986037*/count=19; tryItOut("let (d, cntlra,   =  /x/g , c, x = (0x0ffffffff), bzoujm, y = Set(\"\\u6819\",  /x/ ), scpspt, \"26\" = timeout(1800)) { f2(p1); }");
/*fuzzSeed-169986037*/count=20; tryItOut("v1 = (v2 instanceof g1.t1);");
/*fuzzSeed-169986037*/count=21; tryItOut("mathy0 = (function(x, y) { return Math.min(( + Math.sign(( + ( + ( ~ ( + Math.max(Number.MAX_SAFE_INTEGER, ( + Math.log(x))))))))), ( ! ( ! x))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, 42, -0x07fffffff, -Number.MAX_VALUE, -0x100000001, 2**53-2, -0, 2**53, Math.PI, 0/0, 0x07fffffff, 1.7976931348623157e308, 1/0, 1, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_VALUE, -0x080000000, -Number.MIN_VALUE, 0x080000001, 0x100000000, -0x0ffffffff, -1/0, 0x100000001, 2**53+2, -(2**53), -(2**53+2), 0x080000000, -0x080000001, -Number.MIN_SAFE_INTEGER, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-169986037*/count=22; tryItOut("([z1,,].watch(\"__proto__\", Object.prototype.__lookupGetter__))\nfunction x(...x) { \"use strict\"; return (4277);let(c) ((function(){with({}) let(d) { ( \"\" );}})()); } t0[v1];");
/*fuzzSeed-169986037*/count=23; tryItOut("\"use strict\"; function shapeyConstructor(vtxpsf){vtxpsf[\"getTime\"] = /(?![^])+/yi;Object.defineProperty(vtxpsf, \"getTime\", ({value: Object.defineProperty(z, \"getFullYear\", ({value: e = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { throw 3; }, delete: undefined, fix: undefined, has: function() { return false; }, hasOwn: function() { return false; }, get: undefined, set: function() { return true; }, iterate: undefined, enumerate: function() { return []; }, keys: function() { return []; }, }; })(true), new RegExp(\"(?:\\\\1)\", \"gyim\")), writable: false, configurable: (x % 5 != 2)})), writable:  /x/ , enumerable: false}));for (var ytqledmgb in vtxpsf) { }Object.defineProperty(vtxpsf, \"arguments\", ({get: String.prototype.trim, enumerable: (vtxpsf % 5 != 0)}));vtxpsf[\"defineProperty\"] = -(2**53);if (window) vtxpsf[\"getTime\"] =  \"\" ;Object.defineProperty(vtxpsf, \"defineProperty\", ({}));delete vtxpsf[\"getTime\"];return vtxpsf; }/*tLoopC*/for (let b of (void options('strict_mode'))) { try{let kuzyjw = new shapeyConstructor(b); print('EETT'); /*infloop*/M:for(let e = (makeFinalizeObserver('nursery')); (4277); ( ''  = new RegExp(\"(?=\\\\2)\", \"gym\"))) (kuzyjw);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-169986037*/count=24; tryItOut("\"use strict\"; \"use asm\"; mathy3 = (function(x, y) { return (Math.fround(Math.hypot(Math.fround(mathy0((mathy2(1/0, (x >>> 0)) >>> 0), (( ! (y >>> 0)) | 0))), Math.fround(mathy1((((x && Math.atan2(( - 0x07fffffff), Math.atan2(0x080000001, ( + Math.PI)))) | 0) | 0), Math.atan2(( ! Math.max(y, x)), Math.hypot(x, 1.7976931348623157e308)))))) & Math.round((Math.hypot((Math.max(Math.fround(-(2**53+2)), Math.fround((Math.log((2**53+2 >>> 0)) >>> 0))) | 0), (( + Math.fround(((Math.imul(Math.min(y, x), y) >>> 0) << Math.fround(y)))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-169986037*/count=25; tryItOut("\"use asm\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=26; tryItOut("//h\n;o0.t1 = new Int32Array(b0, 18, ({valueOf: function() { a0 = arguments;return 8; }}));");
/*fuzzSeed-169986037*/count=27; tryItOut("\u000c(\"\\uFF3A\"(-10, undefined)\u000c)((4277));");
/*fuzzSeed-169986037*/count=28; tryItOut("m0 + '';\ncontinue L;\n");
/*fuzzSeed-169986037*/count=29; tryItOut("\"use strict\"; /*tLoop*/for (let x of /*MARR*/[]) { print(Number(15)); }");
/*fuzzSeed-169986037*/count=30; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (Math.sin(Math.atanh(Math.fround(( - Math.fround(y))))) ? (Math.fround(Math.atan(x)) ? ( + (( + (( + (( + y) || ( + 0x100000000))) >= mathy0(((y ^ -0x080000000) >>> 0), y))) ^ ( + y))) : Math.fround(( + ( + Math.cos(mathy0(((x | 0) & (1 | 0)), Math.log1p(x))))))) : ( + Math.atan2(( + ( + (Math.asin((Math.acos(Math.fround((y || Math.fround(x)))) >>> 0)) != ((y >= Number.MIN_VALUE) >>> 0)))), ( + ( ~ mathy1(Math.atanh(x), ((( ~ x) >>> 0) >>> 0)))))))); }); testMathyFunction(mathy3, [0x0ffffffff, 0x100000001, -(2**53), 0, -0x100000001, -1/0, -0x0ffffffff, -(2**53+2), 42, -0x080000000, Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, 2**53+2, 0/0, 1/0, 0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000001, 0x080000001, Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, Math.PI, 2**53, -(2**53-2), -0x07fffffff, -0x100000000, Number.MAX_VALUE, -Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, 2**53-2]); ");
/*fuzzSeed-169986037*/count=31; tryItOut("-7;");
/*fuzzSeed-169986037*/count=32; tryItOut("m0 = p1;");
/*fuzzSeed-169986037*/count=33; tryItOut("mathy4 = (function(x, y) { return ((Math.round((Math.imul(y, mathy3(y, y)) >>> 0)) >>> 0) ** mathy1((((( + (( + Math.min((Math.atan2(y, x) | 0), -(2**53))) ? ( + (Math.ceil((x | 0)) | 0)) : y)) | 0) ? (Math.asinh(((( + (y | 0)) | 0) >>> 0)) | 0) : y) >>> 0), ((( + (Math.fround((mathy2((( - x) , Math.imul(Math.fround(x), 0.000000000000001)), y) >>> Math.fround((2**53 === y)))) | 0)) | 0) | 0))); }); testMathyFunction(mathy4, /*MARR*/[null, ({}), undefined, null]); ");
/*fuzzSeed-169986037*/count=34; tryItOut("f2 + '';");
/*fuzzSeed-169986037*/count=35; tryItOut("\"use strict\"; /*RXUB*/var r = /([^\\d]*){0}/yi; var s = \"__\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=36; tryItOut("ucbuwc((function ([y]) { })());/*hhh*/function ucbuwc(y, x){this.s2 = '';}");
/*fuzzSeed-169986037*/count=37; tryItOut("\"use strict\"; v2 = evaluate(\"function f1(a1)  { return a1 } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: (x % 2 != 0), sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-169986037*/count=38; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float64ArrayView[1]) = ((d1));\n    d0 = (-((d1)));\n    d1 = (d0);\n    return +((NaN));\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[new Boolean(true), null, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, null, new Boolean(true), null, function(){}, null, null, null, new Boolean(true), function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, new Boolean(true), function(){}, null, function(){}, null, new Boolean(true), function(){}, function(){}, function(){}, null, null]); ");
/*fuzzSeed-169986037*/count=39; tryItOut("\"use strict\"; /*infloop*/ for (this.zzz.zzz of (p={}, (p.z = eval)())) g1.v2 = p0[\"0\"];");
/*fuzzSeed-169986037*/count=40; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-0, 2**53-2, -0x100000000, -Number.MIN_VALUE, 2**53+2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -1/0, Math.PI, 0/0, 0, 0x080000001, Number.MAX_VALUE, -(2**53+2), 0x080000000, -0x080000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 0.000000000000001, Number.MIN_VALUE, -0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 42, 1, 0x07fffffff, 2**53, Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, -Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, 1/0]); ");
/*fuzzSeed-169986037*/count=41; tryItOut("/*MXX3*/g2.Number.prototype.toExponential = g0.Number.prototype.toExponential;");
/*fuzzSeed-169986037*/count=42; tryItOut("/*tLoop*/for (let x of /*MARR*/[undefined,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  \"\" ,  \"\" ,  \"\" , undefined, undefined,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  \"\" ,  \"\" ,  \"\" , 1.7976931348623157e308, undefined,  \"\" ,  \"\" , 1.7976931348623157e308,  \"\" , 1.7976931348623157e308, undefined,  \"\" ,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, undefined, undefined, undefined, undefined, undefined, undefined, undefined, 1.7976931348623157e308,  \"\" , 1.7976931348623157e308,  \"\" ,  \"\" ,  \"\" , undefined,  \"\" ,  \"\" , 1.7976931348623157e308, undefined, undefined,  \"\" , undefined, undefined, undefined, 1.7976931348623157e308, 1.7976931348623157e308,  \"\" , undefined,  \"\" , undefined, 1.7976931348623157e308,  \"\" ,  \"\" , 1.7976931348623157e308,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308,  \"\" , undefined,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308,  \"\" , 1.7976931348623157e308,  \"\" ,  \"\" , undefined, undefined, undefined, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, undefined, undefined, 1.7976931348623157e308,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 1.7976931348623157e308, undefined,  \"\" , undefined,  \"\" ,  \"\" , 1.7976931348623157e308,  \"\" ,  \"\" , 1.7976931348623157e308, undefined,  \"\" ,  \"\" ,  \"\" , undefined,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308,  \"\" ,  \"\" , undefined, 1.7976931348623157e308,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  \"\" , undefined,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , 1.7976931348623157e308,  \"\" , undefined, 1.7976931348623157e308,  \"\" , undefined,  \"\" ,  \"\" ,  \"\" ,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308,  \"\" , 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, undefined, undefined, undefined, 1.7976931348623157e308, 1.7976931348623157e308, 1.7976931348623157e308, undefined, 1.7976931348623157e308,  \"\" , 1.7976931348623157e308, undefined,  \"\" ,  \"\" , undefined, 1.7976931348623157e308, 1.7976931348623157e308, undefined, 1.7976931348623157e308, undefined,  \"\" ,  \"\" , undefined, 1.7976931348623157e308, undefined,  \"\" , 1.7976931348623157e308,  \"\" , undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,  \"\" , 1.7976931348623157e308,  \"\" , undefined, undefined, undefined, undefined]) { x =  /x/g ;yield /(?:[^])/yim; }");
/*fuzzSeed-169986037*/count=43; tryItOut("const m2 = new Map;");
/*fuzzSeed-169986037*/count=44; tryItOut("v0 = true;");
/*fuzzSeed-169986037*/count=45; tryItOut("mathy0 = (function(x, y) { return ( + Math.log(( + Math.imul(Math.fround((( + ( ~ Math.fround(0x080000000))) >>> Math.fround((((y >>> 0) >= (( + ( ! y)) >>> 0)) >>> 0)))), ((((((((0/0 | 0) ? (y | 0) : Math.fround((Math.max(y, (2**53-2 >>> 0)) >>> 0))) | 0) >> (y | 0)) | 0) | 0) ? ((( - Math.fround((Math.acos(x) >>> 0))) >>> 0) | 0) : (-0x080000001 | 0)) | 0))))); }); testMathyFunction(mathy0, ['', (new Boolean(true)), '\\0', false, [0], objectEmulatingUndefined(), true, '0', ({toString:function(){return '0';}}), (function(){return 0;}), 0.1, (new Number(0)), 1, 0, undefined, NaN, null, ({valueOf:function(){return '0';}}), [], ({valueOf:function(){return 0;}}), (new Number(-0)), (new Boolean(false)), -0, (new String('')), /0/, '/0/']); ");
/*fuzzSeed-169986037*/count=46; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.cos((( + Math.hypot(( + ( + (Math.min(( + Math.atan2(( + Number.MAX_SAFE_INTEGER), ( + y))), x) , ( + (y < y))))), ( + Math.fround(Math.atan2(x, (( + mathy4(Math.fround(y), -0)) >>> 0)))))) , mathy4(((mathy2(Math.fround(y), (Math.hypot(-(2**53+2), (x | 0)) >>> 0)) + x) | 0), ( - x)))); }); testMathyFunction(mathy5, [0x080000001, 0x0ffffffff, -(2**53-2), -0x100000001, -0x080000001, -0, 1, 0x07fffffff, -Number.MIN_VALUE, 1/0, -0x0ffffffff, 2**53, 0/0, 0, 1.7976931348623157e308, -Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, -1/0, Math.PI, 0.000000000000001, 2**53-2, 0x100000000, 42, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, -0x080000000, -(2**53+2), -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 0x080000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=47; tryItOut("x.name;let(y) ((function(){try { yield x; } finally { throw StopIteration; } })());");
/*fuzzSeed-169986037*/count=48; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=49; tryItOut("/*infloop*/L:for(e = x; x.eval(\"/* no regression tests found */\"); x >> x) {Array.prototype.splice.apply(a2, [4, 6]);Array.prototype.unshift.apply(a0, [t2]); }");
/*fuzzSeed-169986037*/count=50; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.cos((( ~ (( - Math.asinh(-(2**53))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [42, -0x080000000, 2**53-2, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, 0.000000000000001, -(2**53), -Number.MAX_VALUE, -0x0ffffffff, 0/0, -(2**53+2), -0x100000001, -(2**53-2), 0, Math.PI, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0x100000000, 1, -0, Number.MIN_VALUE, 0x080000001, 2**53+2, 0x0ffffffff, -0x07fffffff, -1/0, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000000, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=51; tryItOut("mathy2 = (function(x, y) { return Math.expm1(( + Math.atan2(( + ( - Math.fround(Math.fround(Math.round(Math.fround(( - x))))))), Math.fround(((Math.hypot((((y | 0) < (x | 0)) | 0), x) >>> 0) && y))))); }); ");
/*fuzzSeed-169986037*/count=52; tryItOut("a1[7] = t2;");
/*fuzzSeed-169986037*/count=53; tryItOut("/*RXUB*/var r = /((?=(^|[^]^[^])|(\ua661)\\3?))?/; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-169986037*/count=54; tryItOut("alrocn([,]);/*hhh*/function alrocn(){g0.v2 = a1.length;}");
/*fuzzSeed-169986037*/count=55; tryItOut("const y = x;o0.v0 = Object.prototype.isPrototypeOf.call(p2, h2);");
/*fuzzSeed-169986037*/count=56; tryItOut("\"use strict\"; /*bLoop*/for (deybvh = 0; deybvh < 27; ++deybvh) { if (deybvh % 4 == 2) { a1.sort((function(j) { f1(j); }), f2); } else { m1.get(t1); }  } \n/*bLoop*/for (var nejrbr = 0; nejrbr < 29; ++nejrbr) { if (nejrbr % 3 == 2) { Array.prototype.unshift.apply(g0.a0, [t1, o2.p1]); } else { this.o2.t1.set(a2, 3); }  } function b(x, x = eval(\"print(g2);\", (eval = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: ({/*TOODEEP*/}), has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: Float64Array, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: ({/*TOODEEP*/}), enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(window), x)))) { yield new [z1]() } /*iii*/s0.valueOf = g1.f0;/*hhh*/function rycnot(y){e2 = new Set(m2);}\n");
/*fuzzSeed-169986037*/count=57; tryItOut("var iirxov = new ArrayBuffer(2); var iirxov_0 = new Int32Array(iirxov); iirxov_0[0] = -12; var iirxov_1 = new Int16Array(iirxov); var iirxov_2 = new Int16Array(iirxov); print(iirxov_2[0]); iirxov_2[0] = 19; var iirxov_3 = new Float64Array(iirxov); print(iirxov_3[0]); var iirxov_4 = new Float64Array(iirxov); iirxov_4[0] = -5; var iirxov_5 = new Int16Array(iirxov); iirxov_5[0] = -18; var iirxov_6 = new Float32Array(iirxov); iirxov_6[0] = -15; var iirxov_7 = new Uint8Array(iirxov); iirxov_7[0] = -20; var iirxov_8 = new Int32Array(iirxov); print(iirxov_8[0]); print((iirxov_8.__defineGetter__(/*FARR*/[ /x/g ,  /x/g ].map( '' ,  /x/g ), window)));this.m2.has(v1);/* no regression tests found */(eval++);;print(iirxov_1[0]);");
/*fuzzSeed-169986037*/count=58; tryItOut("for(let c in Math.atan2((window\u000c <<= e), x)) {Object.defineProperty(this, \"h2\", { configurable: (x % 12 != 3), enumerable: c,  get: function() {  return ({getOwnPropertyDescriptor: function(name) { i1 = m1.iterator;; var desc = Object.getOwnPropertyDescriptor(this.b0); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { v0 = g2.runOffThreadScript();; var desc = Object.getPropertyDescriptor(this.b0); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { a0 = []; o0 = {}; s0 = ''; r0 = /x/; g0 = this; f0 = function(){}; m0 = new WeakMap; e0 = new Set; v0 = null; b0 = new ArrayBuffer(64); t0 = new Uint8ClampedArray; a1 = []; o1 = {}; s1 = ''; r1 = /x/; g1 = this; f1 = function(){}; m1 = new WeakMap; e1 = new Set; v1 = null; b1 = new ArrayBuffer(64); t1 = new Uint8ClampedArray; a2 = []; o2 = {}; s2 = ''; r2 = /x/; g2 = this; f2 = function(){}; m2 = new WeakMap; e2 = new Set; v2 = null; b2 = new ArrayBuffer(64); t2 = new Uint8ClampedArray; ; Object.defineProperty(this.b0, name, desc); }, getOwnPropertyNames: function() { p1 + '';; return Object.getOwnPropertyNames(this.b0); }, delete: function(name) { h0.delete = (function mcc_() { var mcgbzu = 0; return function() { ++mcgbzu; f2(/*ICCD*/mcgbzu % 2 == 0);};})();; return delete this.b0[name]; }, fix: function() { Object.defineProperty(this, \"g2.g1.v2\", { configurable: true, enumerable: false,  get: function() {  return g0.eval(\"function f1(f1)  { \\\"use strict\\\"; yield (z <= c) } \"); } });; if (Object.isFrozen(this.b0)) { return Object.getOwnProperties(this.b0); } }, has: function(name) { ;; return name in this.b0; }, hasOwn: function(name) { /*RXUB*/var r = r0; var s = s1; print(s.replace(r, r, \"gm\")); ; return Object.prototype.hasOwnProperty.call(this.b0, name); }, get: function(receiver, name) { /*RXUB*/var r = r0; var s = s0; print(uneval(r.exec(s))); print(r.lastIndex); ; return this.b0[name]; }, set: function(receiver, name, val) { t2.set(t2, new RegExp(\"(?=.)\", \"gi\") % timeout(1800));; this.b0[name] = val; return true; }, iterate: function() { selectforgc(o0);; return (function() { for (var name in this.b0) { yield name; } })(); }, enumerate: function() { v2 = evalcx(\"((uneval(y)));\", g2.g2);; var result = []; for (var name in this.b0) { result.push(name); }; return result; }, keys: function() { h2.iterate = this.o1.f2;; return Object.keys(this.b0); } }); } });v0 = t0.length; }");
/*fuzzSeed-169986037*/count=59; tryItOut("for([y, x] = x in x) if((y % 14 == 7)) {M:if(function ([y]) { }) { if (Math.min((4277), (((yield ({y: /(\\1*((?=\\W|[^])*?))|(?:\\w+)|(?:^+?){4,8}\\B/ym}))).watch(\"toSource\", (new Uint32Array( '' )) -= x)))) {e0.toString = (function() { m1.has(o0); return h0; });v1 = a0.length; } else print(uneval(s2));} }");
/*fuzzSeed-169986037*/count=60; tryItOut("\"use strict\"; let v0 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 4 != 1), noScriptRval: false, sourceIsLazy: true, catchTermination: (x % 2 != 1) }));");
/*fuzzSeed-169986037*/count=61; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (Math.log1p(( ! Math.fround(Math.fround((Math.fround(0x080000000) != Math.fround(y)))))) != (Math.min(((Math.fround(Math.atan2(Math.fround(-0), Math.fround(y))) ? (((Math.max(x, y) >>> 0) ? y : x) | 0) : x) >>> 0), ((( + x) !== Math.asin(y)) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [0x080000000, 1, 42, 2**53-2, 1.7976931348623157e308, 0, -0x080000001, -(2**53), 0x100000001, 0x080000001, Number.MAX_VALUE, 0/0, 0.000000000000001, 0x100000000, -Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, -0x0ffffffff, -(2**53+2), Number.MIN_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, -0, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -1/0, 2**53+2, -0x080000000, -Number.MAX_VALUE, -0x07fffffff, 2**53, -0x100000000]); ");
/*fuzzSeed-169986037*/count=62; tryItOut("o1.s1 = s0.charAt(v1);");
/*fuzzSeed-169986037*/count=63; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use asm\"; return (Math.imul((4277), ((Math.fround(Math.hypot(Math.fround(Math.round(( + y))), Math.fround((( + (Math.fround(mathy1(-0x07fffffff, (( ~ 42) | 0))) >>> 0)) >>> 0)))) * Math.fround((Math.round(Math.fround((Math.fround(Math.exp(y)) / Math.fround(Math.fround(x))))) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-(2**53-2), 2**53+2, -0x080000000, 0x100000001, 0.000000000000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, Number.MIN_SAFE_INTEGER, -0, -0x07fffffff, 0x100000000, 0x0ffffffff, -(2**53+2), 0, 1, 0x080000000, 0x080000001, -(2**53), 42, Number.MAX_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0/0, -1/0, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, Number.MIN_VALUE, Math.PI, 2**53-2]); ");
/*fuzzSeed-169986037*/count=64; tryItOut("testMathyFunction(mathy0, [-0x080000000, 0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1, 0x080000000, Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -(2**53+2), -(2**53-2), 0, 1/0, -0x100000001, -0x080000001, 0x07fffffff, -0x0ffffffff, 0x100000000, 42, 1.7976931348623157e308, 0.000000000000001, -0, 2**53+2, 2**53-2, Number.MIN_VALUE, -(2**53), -0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, -1/0, Math.PI, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=65; tryItOut("e1.toSource = (function(a0, a1) { var r0 = 9 - 4; var r1 = 0 % a0; var r2 = a1 + a1; var r3 = x + x; x = a0 % r0; var r4 = r0 - a0; var r5 = r2 * r4; var r6 = a0 ^ r1; r5 = 7 | r3; r3 = a1 ^ r0; var r7 = x % 2; var r8 = 9 / r3; var r9 = r5 + r6; var r10 = x - a1; var r11 = r7 + 9; var r12 = 4 | 5; var r13 = r0 * r10; var r14 = r13 & r2; var r15 = r12 / 1; var r16 = r0 - a1; var r17 = r5 ^ r9; var r18 = 3 / r16; print(r17); var r19 = r2 % r11; var r20 = 7 + x; a0 = r4 - r6; var r21 = r12 / r3; var r22 = a0 - 5; r21 = r17 * r9; r21 = 5 ^ x; var r23 = 8 ^ 0; var r24 = 8 + 6; var r25 = r9 - r11; var r26 = r7 ^ 3; var r27 = r1 & 0; var r28 = r11 & r11; x = 1 - 7; a1 = 1 | 8; var r29 = r5 - r4; var r30 = r20 * 1; var r31 = r24 + 0; var r32 = 3 ^ r26; r6 = r31 | 8; var r33 = r20 + r14; var r34 = r9 * 6; var r35 = 4 | r31; r26 = r29 ^ r27; r0 = r9 - r25; var r36 = 6 ^ r2; var r37 = r20 - r12; r10 = 6 / r11; var r38 = r27 / r20; var r39 = 6 | r11; var r40 = 6 + r8; x = r32 - r5; var r41 = r1 & r39; var r42 = r33 - 7; var r43 = r4 / r5; r1 = r3 - r41; var r44 = r27 * 6; var r45 = 9 / r37; var r46 = r24 | r15; var r47 = r36 % 3; var r48 = r40 * r6; var r49 = 8 | r11; var r50 = 7 | r32; r24 = 1 / r27; var r51 = r19 * 8; var r52 = r12 * r0; var r53 = r14 * 6; var r54 = r29 / r10; var r55 = 8 ^ r25; r1 = r37 & r21; var r56 = 5 + 0; r25 = r20 * 6; r17 = 0 ^ r11; var r57 = r37 * r4; var r58 = 8 / r34; var r59 = r36 * 7; var r60 = r6 & r42; var r61 = r54 % r21; r3 = r44 ^ r21; r26 = r47 + r8; r55 = r53 * r9; print(r36); r13 = 0 % r16; var r62 = 3 ^ 6; var r63 = 7 & r10; var r64 = r13 | r22; var r65 = r52 & r47; var r66 = 5 / r1; var r67 = 7 / 1; var r68 = 4 + r19; var r69 = 6 - r39; var r70 = r37 + r60; var r71 = 1 | r4; var r72 = r19 ^ r4; var r73 = 5 & 9; var r74 = 9 ^ r48; var r75 = r26 | r21; var r76 = r35 | r14; var r77 = 5 * r70; print(r4); var r78 = 4 ^ r76; var r79 = r25 / r21; r52 = 0 - r18; var r80 = 6 % r71; var r81 = r42 / r29; var r82 = 4 ^ r49; var r83 = 9 - r48; r17 = r78 - 5; r15 = r12 % r66; r27 = r32 & r15; var r84 = r51 / 0; var r85 = r69 - r64; var r86 = r74 & r36; r13 = r5 - 5; var r87 = r29 % r83; var r88 = r18 % r37; var r89 = r5 % r32; var r90 = r40 + a1; var r91 = r44 + r3; var r92 = r46 / r84; var r93 = r18 ^ r73; var r94 = r92 & 0; var r95 = r75 + 4; var r96 = a0 - 0; var r97 = r9 & r25; r69 = 1 * 1; var r98 = r51 % 0; var r99 = r38 - r78; r28 = r84 / 5; var r100 = r72 - 5; var r101 = r52 + r37; var r102 = r32 * r27; var r103 = r9 % 9; var r104 = r95 / r82; var r105 = 9 + r13; var r106 = r22 % 5; var r107 = 5 & r21; var r108 = r101 ^ r41; var r109 = 7 - 3; r50 = r99 ^ r92; var r110 = r18 / r16; var r111 = 0 | r100; var r112 = r43 / 2; var r113 = r81 - r89; var r114 = r76 % 4; var r115 = r61 | r93; var r116 = r55 - r65; var r117 = r46 & r9; var r118 = 0 | r22; var r119 = 5 | r26; var r120 = r3 ^ r94; var r121 = r56 + r7; var r122 = 7 ^ r82; print(r87); print(r2); var r123 = r92 - r60; var r124 = r41 ^ r67; var r125 = r84 - r67; var r126 = r84 ^ r64; r104 = r68 + 9; var r127 = r42 & 3; var r128 = r95 + 4; var r129 = r28 + r117; var r130 = r10 & 7; var r131 = r119 | r84; var r132 = r79 - 7; var r133 = r8 + r17; r73 = r16 - 3; var r134 = r128 | r64; r48 = r121 ^ 9; var r135 = r4 & r87; var r136 = r110 & r36; return a1; });");
/*fuzzSeed-169986037*/count=66; tryItOut("\"use strict\"; p2 + '';");
/*fuzzSeed-169986037*/count=67; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-169986037*/count=68; tryItOut("\"use strict\"; h1.enumerate = (function(j) { f0(j); });");
/*fuzzSeed-169986037*/count=69; tryItOut("mathy3 = (function(x, y) { return ( + (Math.asinh((Math.fround(Math.max((((Math.min((((x | 0) < (( + ( + ( + y))) | 0)) | 0), Math.fround(Math.tanh(( + y)))) | 0) < (y | 0)) | 0), ( + x))) | 0)) | 0)); }); testMathyFunction(mathy3, [0x100000000, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000001, -1/0, 2**53-2, -0, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 1.7976931348623157e308, -(2**53+2), 0x07fffffff, -Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0x080000000, -0x0ffffffff, 0x100000001, 0.000000000000001, 42, -(2**53-2), 0x0ffffffff, 1, Number.MIN_VALUE, 0, -0x100000000, 2**53+2, 1/0, -0x07fffffff, Math.PI, 2**53, 0x080000001, 0/0]); ");
/*fuzzSeed-169986037*/count=70; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h0, this.s2);");
/*fuzzSeed-169986037*/count=71; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + (((( + (Math.trunc((( + (-0x080000001 | 0)) | 0)) >>> 0)) | 0) <= (Math.round(y) | 0)) % (mathy0(Math.fround(Math.atan2(2**53-2, (Math.log(Math.fround((((0x080000000 | 0) !== (Math.ceil(x) | 0)) | 0))) | 0))), Math.atan2(Math.min(x, (-0x100000000 <= (((y | 0) - 0x100000000) | 0))), y)) | 0))); }); testMathyFunction(mathy3, [-0, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, Math.PI, -Number.MAX_VALUE, -0x100000001, 2**53-2, 0x080000001, -1/0, 0x100000000, 0, 0.000000000000001, -0x080000001, 42, -Number.MIN_VALUE, 0x0ffffffff, 1, Number.MAX_VALUE, 1/0, -0x080000000, 0x080000000, 2**53, Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, -0x0ffffffff, -(2**53+2), -(2**53), 2**53+2, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=72; tryItOut("\"use strict\"; \"use asm\"; let(y) ((function(){for(let b in []);})());let(d) { with({}) { let(c) { return;} } }");
/*fuzzSeed-169986037*/count=73; tryItOut("/*infloop*/M: for  each(\u3056 in x) h0.defineProperty = f1;");
/*fuzzSeed-169986037*/count=74; tryItOut("{/* no regression tests found */ }");
/*fuzzSeed-169986037*/count=75; tryItOut("a1.sort((function mcc_() { var vkeaes = 0; return function() { ++vkeaes; if (true) { dumpln('hit!'); try { s2.toString = (function() { for (var j=0;j<24;++j) { f2(j%2==1); } }); } catch(e0) { } try { o2.v0 = true; } catch(e1) { } try { /*ADP-3*/Object.defineProperty(a2, ({valueOf: function() { var gqlzkf = new ArrayBuffer(6); var gqlzkf_0 = new Int32Array(gqlzkf); gqlzkf_0[0] = -1; var gqlzkf_1 = new Uint8Array(gqlzkf); gqlzkf_1[0] = -8; var gqlzkf_2 = new Float64Array(gqlzkf); gqlzkf_2[0] = -28; g0.f1(o1.p1);v0 = evalcx(\"i1 + '';\", g1);v1 = g2.g1.runOffThreadScript();t0[({valueOf: function() { print(gqlzkf_1[0]);return 11; }})] = b2;return 12; }}), { configurable: (x % 6 != 0), enumerable: false, writable: true, value: p0 }); } catch(e2) { } o0.v2 = evalcx(\"s2 = a2.join(o1.s0);\", this.g2); } else { dumpln('miss!'); this.o1 + ''; } };})(), i1);");
/*fuzzSeed-169986037*/count=76; tryItOut("\"use strict\"; Array.prototype.sort.apply(a1, [(function(stdlib, foreign, heap){ \"use asm\";   var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    i1 = (!((((((0xf924b96b)*-0xaa7c0)>>>((0x4852e18e)+(0xc194bb6b))) / (((0x6a8683a1)*0x91e4e)>>>((0x7ba1747d)+(0xfc9953d6)+(0x9c5a60f9)))) & ((((Uint8ArrayView[4096]))>>>(((0x39c6bcab) != (0x65770e1c)))) % (0x58278cb))) != (0x6795a129)));\n    i1 = (i1);\n    return +((2049.0));\n  }\n  return f; })]);");
/*fuzzSeed-169986037*/count=77; tryItOut("const e, orhzyf, dpdlhj, wonlrw, c, {} = x;/*RXUB*/var r = /(?=\\u005D)/gyim; var s = \"\"; print(uneval(s.match(r))); print(uneval(m0));");
/*fuzzSeed-169986037*/count=78; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + (( + Math.min(Math.log10((Math.atan2(Number.MIN_SAFE_INTEGER, (y >>> 0)) >>> 0)), Math.expm1(Math.fround(Math.fround((x ? Math.fround(((x | 0) !== x)) : ((x < (0x07fffffff | 0)) | 0))))))) != ( + ( - (y > Math.clz32(Math.sign((x | 0)))))))); }); testMathyFunction(mathy0, [Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, Math.PI, 0.000000000000001, 0x080000001, 42, 2**53-2, 0x100000001, -0x07fffffff, -0, -0x0ffffffff, -(2**53+2), -0x100000000, -(2**53), Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 2**53+2, -(2**53-2), 1, 0x0ffffffff, 2**53, -Number.MAX_VALUE, 0, 1/0, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -1/0, -0x080000001, 0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-169986037*/count=79; tryItOut("mathy1 = (function(x, y) { return Math.fround(Math.max(( ~ Math.cbrt(Math.fround((Math.fround(Math.fround(Math.pow(Number.MIN_VALUE, x))) === Math.fround(x))))), (Math.log(( + y)) >= ((y > ( + Math.max(( + y), ( + y)))) << x)))); }); testMathyFunction(mathy1, [true, (function(){return 0;}), ({toString:function(){return '0';}}), null, (new Boolean(true)), '0', (new Number(-0)), /0/, (new String('')), -0, '\\0', '/0/', undefined, (new Number(0)), 1, ({valueOf:function(){return '0';}}), '', [], 0.1, (new Boolean(false)), objectEmulatingUndefined(), false, [0], 0, NaN, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-169986037*/count=80; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.exp(Math.log2(((y ? Math.max(( + ((( + Math.exp((Math.min(y, x) | 0))) >>> 0) > (-0x080000000 >>> 0))), Math.fround(( ~ (Math.atan2((y >>> 0), y) >>> 0)))) : (Math.atan(y) >>> 0)) | 0))); }); testMathyFunction(mathy0, [1, -1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), 0, -0x080000001, 42, Number.MIN_VALUE, 0x07fffffff, -Number.MIN_VALUE, -(2**53), -0x0ffffffff, 2**53, 0x100000000, 0.000000000000001, -0x100000001, -0x07fffffff, -0x080000000, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, Number.MAX_VALUE, 0/0, -0, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, 2**53+2, 0x100000001, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=81; tryItOut("t2 = g1.objectEmulatingUndefined();");
/*fuzzSeed-169986037*/count=82; tryItOut("v1 = (a2 instanceof p0);");
/*fuzzSeed-169986037*/count=83; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=84; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.atan2(((( - (( + Math.acos(x)) >>> 0)) ** mathy2((Math.fround(Math.cosh(((Math.imul(Math.fround(mathy1(Math.fround(y), (0x100000000 >>> 0))), y) >>> 0) >>> 0))) >>> 0), ((( + ( - ( + y))) ? y : Math.imul(( + mathy1((x | 0), ( + y))), Math.fround((y % ((( - (0x07fffffff | 0)) | 0) >>> 0))))) >>> 0))) | 0), (( + (Math.tan(mathy2(( ~ (y % Math.min(x, 0x100000000))), Math.fround(y))) - (((y >>> 0) < 0x07fffffff) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [({valueOf:function(){return '0';}}), '\\0', '', (new Boolean(true)), 1, [0], (new String('')), true, 0.1, (new Number(0)), (new Boolean(false)), (function(){return 0;}), ({toString:function(){return '0';}}), NaN, undefined, objectEmulatingUndefined(), '0', -0, null, (new Number(-0)), /0/, [], ({valueOf:function(){return 0;}}), false, 0, '/0/']); ");
/*fuzzSeed-169986037*/count=85; tryItOut("print(x);t2[2];");
/*fuzzSeed-169986037*/count=86; tryItOut("\"use strict\"; g0.v2 = false;");
/*fuzzSeed-169986037*/count=87; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( - (Math.fround(Math.cosh(Math.fround(mathy0(Math.fround(Math.atanh(Math.hypot(x, Math.fround(((y | 0) ^ Math.fround(1)))))), (( ! 1.7976931348623157e308) | 0))))) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=88; tryItOut("\"use strict\"; Array.prototype.pop.apply(a0, [(x--)]);\nv2 = g0.eval(\"o0.v1 + f0;\");\n");
/*fuzzSeed-169986037*/count=89; tryItOut("h1.defineProperty = (function() { for (var j=0;j<2;++j) { f2(j%2==1); } });");
/*fuzzSeed-169986037*/count=90; tryItOut("print([])\n");
/*fuzzSeed-169986037*/count=91; tryItOut("/*ODP-2*/Object.defineProperty(f0, /*FARR*/[...(let (e=eval) e), y >>>= x, this.zzz.zzz|=a++, ((\u3056 =  '' )()), (4277), x, , x = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: (z).bind(), defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { return false; }, hasOwn: function() { return false; }, get: (TypeError.prototype.toString).bind(w, window), set: function() { return false; }, iterate: String.prototype.toLocaleLowerCase, enumerate: function() { throw 3; }, keys: function() { return Object.keys(x); }, }; })(x), (4277)), .../*MARR*/[3, 3, 3, 3, 3,  /x/ , new String('q'), 3, new Number(1), new String('q'), 3, new Number(1),  /x/ , 3,  /x/ ,  /x/ , 3,  /x/ ,  /x/ , new String('q'), 3,  /x/ , 3, new Number(1), new String('q'), 3,  /x/ , new Number(1),  /x/ , 3, new String('q'),  /x/ , new Number(1), new Number(1), new String('q'), new Number(1), new Number(1), new String('q'),  /x/ ,  /x/ ]].sort, { configurable: false, enumerable: z--, get: (function() { try { i1.__proto__ = p0; } catch(e0) { } g2.h0.getOwnPropertyNames = f1; return b1; }), set: f0 });");
/*fuzzSeed-169986037*/count=92; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    i1 = ((abs(((0x5a6bf017)))|0) <= ((Int8Array.prototype--) ^ ((i1))));\n    {\n      (Uint8ArrayView[(0x1249a*(0xa252071c)) >> 0]) = (((((i1))>>>(Math.imul(24, 24))) / (((0xc4653e0b))>>>(((((neuter).call( /x/g .valueOf(\"number\"), (timeout(1800)).valueOf(\"number\")))) ? (i1) : (i1))+((((0xc323ada4))>>>(-0x59da2*(-0x8000000))) >= (0x4e87564c))))));\n    }\n    d0 = (-576460752303423500.0);\n    (Float32ArrayView[((0xfc08ae1a)-(0x6445cc5)-((((0xfe5b0d9c))>>>((0xbfdb0ae4)-(0x2c8ae26b)-(0xf907f989))))) >> 2]) = ((6.044629098073146e+23));\n    d0 = ((+/*FFI*/ff(((((((0xf2154ae9)-(i1)-(/*FFI*/ff()|0))>>>(((0x89937b3) ? (-0x8000000) : (0x3322782e))+(i1))) / (0xfc5b16be)) | ((i1)+(0xfe0cd31c)-(i1)))), ((abs(((((imul((i1), (0x32897fc8))|0))) << ((!((((0xfaa4f8e)) << ((0x7be7a69c))) < (((-0x8000000)) >> ((-0x8000000)))))-(0xfb7495cf))))|0)), ((+/*FFI*/ff(((d0)), ((((Uint16ArrayView[1])) & ((Uint8ArrayView[4096]))))))), ((~~(18446744073709552000.0))))));\n    i1 = (0xc2bab2ab);\n    return +((0.001953125));\n  }\n  return f; })(this, {ff: encodeURIComponent}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=93; tryItOut("testMathyFunction(mathy2, /*MARR*/[1.7976931348623157e308, 033, 033,  \"\" , 1.7976931348623157e308,  \"\" ,  \"\" , 033, 1.7976931348623157e308, 1.7976931348623157e308, 033, 033, 033, 033, 033, new String(''), 1.7976931348623157e308, 1.7976931348623157e308,  \"\" , 033, 1.7976931348623157e308, 1.7976931348623157e308, new String(''), new String(''), new String(''),  \"\" , 1.7976931348623157e308, 033, 033,  \"\" , 033, 033, 033, 033, 033, 1.7976931348623157e308, 1.7976931348623157e308, new String(''), 033,  \"\" ,  \"\" , 033, new String(''), 033,  \"\" , 033, 033, 033,  \"\" , 1.7976931348623157e308,  \"\" ,  \"\" , 033, 033, new String(''),  \"\" ,  \"\" ]); ");
/*fuzzSeed-169986037*/count=94; tryItOut("/*oLoop*/for (wlddqj = 0, x; wlddqj < 28; ++wlddqj) { Object.defineProperty(o1, \"e0\", { configurable: false, enumerable: (x % 4 == 1),  get: function() {  return new Set; } }); } ");
/*fuzzSeed-169986037*/count=95; tryItOut("x = linkedList(x, 946);");
/*fuzzSeed-169986037*/count=96; tryItOut("\"use strict\"; while(((({a2:z2}) ? -5 : window)) && 0)g2.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-169986037*/count=97; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (( + Math.atan2((Math.sin(Math.fround(Math.hypot(Math.fround(x), Math.fround(y)))) <= Math.imul((x | 0), Math.fround(Math.max(x, x)))), ( ~ (Math.min(x, (Math.cos((( + y) <= ( + y))) > y)) | 0)))) & (((Math.atan(x) >= Math.fround(Math.pow(Math.fround(x), Math.fround(-(2**53))))) > (Math.hypot(Math.max(y, (Math.fround(y) ? Math.expm1(2**53-2) : x)), ( ~ (y | 0))) | 0)) | 0)); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 1/0, -1/0, -(2**53+2), -(2**53), 0x100000001, 2**53, 0/0, 1, -Number.MIN_VALUE, 2**53+2, 2**53-2, Number.MIN_VALUE, 0x0ffffffff, 0x07fffffff, 0x100000000, -0x080000001, -0x100000000, Math.PI, 0, -0x07fffffff, -0x100000001, -Number.MAX_VALUE, 0x080000001, -0x0ffffffff, 1.7976931348623157e308, -0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, 0x080000000, -0x080000000, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=98; tryItOut("Array.prototype.shift.apply(a1, []);");
/*fuzzSeed-169986037*/count=99; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=100; tryItOut("\"use strict\"; {16; }");
/*fuzzSeed-169986037*/count=101; tryItOut("selectforgc(g1.o2);");
/*fuzzSeed-169986037*/count=102; tryItOut("switch((b = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: function(){}, defineProperty: (Math.round(-7)), getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return true; }, get: DataView.prototype.setFloat32, set: function() { return true; }, iterate: function() { throw 3; }, enumerate: function() { return []; }, keys: undefined, }; })((void shapeOf(Math.log(1)))), /*wrap1*/(function(){ t2[8] =  /x/ ;return /*wrap2*/(function(){ \"use strict\"; var iqwszz = \n/\\w/g +=  /x/ ; var zjtpqk = function shapeyConstructor(hxzonc){delete this[(NaN = window)];this[\"__iterator__\"] = (4277);for (var ytqpvayga in this) { }{ print(iqwszz); } this[\"toString\"] = [];{ (this != new RegExp(\"([^]|.|[^]|\\\\w|$[^]{1,257}*?)|\\\\\\u916a\\\\B{3}|\\u0092{1048575,1048576}|[^]{3,}\", \"gi\")); } return this; }; return zjtpqk;})()})(), (1 for (x in []))))) { case 0: t0.set(a1, Math.atan2(-22, 29));break; default: case (4277): break; /*MXX2*/g0.Date.prototype.setUTCHours = i2;break;  }");
/*fuzzSeed-169986037*/count=103; tryItOut("this.e0 = new Set;");
/*fuzzSeed-169986037*/count=104; tryItOut("\"use strict\"; {v0.valueOf = (function() { try { v0 = (s0 instanceof this.p2); } catch(e0) { } try { this.m0.get(g0); } catch(e1) { } this.s2 += s0; return g1.h1; }); }");
/*fuzzSeed-169986037*/count=105; tryItOut("mathy0 = (function(x, y) { return Math.tanh(( + ( - ( + Math.asin(( + Math.sign((x >>> 0)))))))); }); testMathyFunction(mathy0, [0x0ffffffff, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 0/0, 42, Number.MAX_VALUE, 2**53+2, -(2**53), -0x100000001, -Number.MIN_SAFE_INTEGER, -1/0, -(2**53-2), -0, 0x100000000, -0x100000000, 0, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, 1, 0.000000000000001, -(2**53+2), 0x080000001, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53, Math.PI, 1/0, 2**53-2, 1.7976931348623157e308, -0x080000000]); ");
/*fuzzSeed-169986037*/count=106; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.imul(Math.fround(Math.log((( + (( + -0x080000001) & Math.tan(Math.atan2(Math.fround(y), ( + Math.hypot(y, x)))))) | 0))), ((Math.min(((((mathy0(Math.max(y, y), Math.fround(Math.pow(x, x))) >>> 0) + (( + ((( + x) >>> -1/0) >>> 0)) >>> 0)) | 0) >>> 0), x) >>> 0) >>> Math.acos(( ~ x)))); }); testMathyFunction(mathy5, [/0/, ({toString:function(){return '0';}}), NaN, true, null, (new Number(0)), (function(){return 0;}), (new Boolean(true)), '0', false, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), '/0/', (new Number(-0)), '', (new String('')), [], 0, '\\0', [0], undefined, 0.1, (new Boolean(false)), ({valueOf:function(){return 0;}}), 1, -0]); ");
/*fuzzSeed-169986037*/count=107; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.sqrt(Math.fround(Math.atan2(Math.sinh(y), ( ~ Math.sign(-Number.MIN_VALUE))))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, 0x080000001, -0, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, -0x080000001, 0x100000001, -0x0ffffffff, 0x0ffffffff, 0.000000000000001, 1/0, 0, 2**53, 2**53+2, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, -(2**53), -1/0, -Number.MAX_SAFE_INTEGER, 1, -0x100000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53-2, 42, 0x100000000, 0x07fffffff, -0x100000001, -(2**53+2), 0/0]); ");
/*fuzzSeed-169986037*/count=108; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var pow = stdlib.Math.pow;\n  var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -4398046511105.0;\n    /*FFI*/ff(((NaN)), (((((((0xcfa059f5)) << ((-0x8000000))) < (((0x9284e01)) | ((-0x8000000))))*0xe097f) & (((0x53ef65d8) ? (0x54a5fa6) : (0x52b0f9c7))+(((0x5f2be1be) ? (-1.00390625) : (-2047.0)) < ((-0x8000000) ? (2047.0) : (-0.5)))))), (((((+(-1.0/0.0))) - ((+pow(((-524287.0)), ((65.0)))))) + (d2))), (((-0xfffff*(i0)) ^ (x %= eval\u0009))), ((~((0xb9fa6502)-(/*FFI*/ff()|0)))), ((+(((0xffffffff))>>>((0x7006cd9d))))), ((d1)));\n    switch (((((-1.125) == (1.5111572745182865e+23))+(\nnew (/*UUV2*/( .valueOf =  .toLocaleTimeString)))) << ((new (((yield window)))())))) {\n      case -1:\n        d1 = (d1);\n        break;\n      case -3:\n        d1 = ((0xf8866a28) ? ((+(0.0/0.0)) + (Infinity)) : (+abs(((+((17.0)))))));\n      case 1:\n;        break;\n      case -2:\n        return (((i0)))|0;\n        break;\n      case 0:\n        d2 = (d1);\n      case 1:\n        d1 = (-((d1)));\n      default:\n        d1 = (d2);\n    }\n    return (((Uint32ArrayView[(((((i0)) << (-0x11c34*(-0x8000000))) < (~~(+(0.0/0.0))))+((0xe8ae8923))) >> 2])))|0;\n  }\n  return f; })(this, {ff: Uint8Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MAX_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, -0x080000001, -Number.MIN_VALUE, 0/0, -0x100000000, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_VALUE, 2**53+2, 0, 0x0ffffffff, -(2**53), Math.PI, 0x080000000, 0x07fffffff, -Number.MAX_VALUE, 1, 0x080000001, 2**53-2, -(2**53-2), 2**53, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 42, Number.MIN_VALUE, -0x0ffffffff, -1/0, -0x080000000, -0, 0x100000001, 1/0]); ");
/*fuzzSeed-169986037*/count=109; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy2(( ! (Math.abs(( + Math.atan2(x, Math.fround(2**53+2)))) | 0)), ( - mathy2(Math.atan2(-(2**53-2), ((x + x) | 0)), (( ! (-1/0 >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 0x100000000, 0x080000000, 42, 1.7976931348623157e308, 1/0, Number.MIN_SAFE_INTEGER, 1, -(2**53), -(2**53+2), Number.MAX_SAFE_INTEGER, 0/0, -0x0ffffffff, 0x080000001, -(2**53-2), -Number.MAX_VALUE, 2**53, Number.MAX_VALUE, -0x07fffffff, -0x100000001, -0, -1/0, Math.PI, 2**53+2, 0, -0x080000000, -0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000001, 0.000000000000001, 0x07fffffff, 2**53-2, 0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=110; tryItOut("\"use strict\"; let (e) { print(e); }");
/*fuzzSeed-169986037*/count=111; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, -0x100000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0, -Number.MAX_VALUE, 0x100000001, 1/0, -0, 2**53-2, -0x0ffffffff, Number.MIN_VALUE, 0/0, 0x07fffffff, -0x07fffffff, 1.7976931348623157e308, 1, 0x0ffffffff, -1/0, -0x080000001, Math.PI, -0x100000000, -(2**53-2), 2**53, 42, Number.MIN_SAFE_INTEGER, -(2**53+2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-169986037*/count=112; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.exp(( ~ ( + mathy0((( + Math.trunc(( + x))) % ( ! x)), mathy0((y | 0), x))))); }); testMathyFunction(mathy1, [0x100000000, 0x0ffffffff, 1, -0x0ffffffff, 1/0, -1/0, 0.000000000000001, 0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0, -0, 1.7976931348623157e308, 42, Number.MIN_SAFE_INTEGER, -0x080000001, Math.PI, 2**53, Number.MIN_VALUE, 0x100000001, -0x100000001, -0x080000000, -(2**53-2), -0x100000000, 0x07fffffff, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_VALUE, -(2**53), 0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53-2, 0/0]); ");
/*fuzzSeed-169986037*/count=113; tryItOut("\"use strict\"; o0.g1.a1[15] = Math.min(20, 12);");
/*fuzzSeed-169986037*/count=114; tryItOut("/*RXUB*/var r = r2; var s = \"\"; print(s.split(r)); print(r.lastIndex); print(false);");
/*fuzzSeed-169986037*/count=115; tryItOut("mathy5 = (function(x, y) { return Math.max(Math.imul(( + Math.imul((Math.hypot((((( ~ (0x080000001 | 0)) | 0) * y) | 0), ( + y)) >>> 0), ( + ( - y)))), Math.exp((x >>> 0))), ((Math.fround(( + (Math.sign((x | 0)) >>> 0))) ? (mathy3((( + ( ~ mathy3((Math.PI | 0), x))) | 0), Math.atan2((x | 0), y)) <= Math.imul((Math.ceil((y | 0)) >>> 0), 0x100000000)) : ( ! Math.fround((( ~ x) / Math.fround(mathy3((Number.MAX_VALUE | 0), (Math.hypot(mathy0(x, y), x) | 0))))))) | 0)); }); testMathyFunction(mathy5, [-(2**53+2), -0x080000001, 0x100000001, 42, Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 0x0ffffffff, Math.PI, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), Number.MIN_VALUE, 0x080000000, 0/0, -0, -0x100000000, 1, -0x07fffffff, 2**53+2, -0x080000000, -1/0, 0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, 0x080000001, Number.MAX_VALUE, 2**53, 0.000000000000001, -Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-169986037*/count=116; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:(?:\\3(?:[^])[^]|(?=.?)+?\\B+?))/gi; var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-169986037*/count=117; tryItOut("/*hhh*/function ohrphf(d){m1.set(this.m0, s0);}ohrphf();");
/*fuzzSeed-169986037*/count=118; tryItOut("\"use strict\"; print(uneval(h0));");
/*fuzzSeed-169986037*/count=119; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=120; tryItOut("m2.has(o1);");
/*fuzzSeed-169986037*/count=121; tryItOut("mathy5 = (function(x, y) { return ((( + Math.min((( + mathy3((mathy0(( + (0x100000000 >>> 0)), -(2**53-2)) | 0), ( + y))) >>> 0), Math.atan2(Math.fround(Math.sin((y * (Math.max(Math.fround(y), Math.fround(y)) | 0)))), -(2**53)))) << (Math.asin((mathy1((Math.fround(Math.imul(mathy1((( ~ ((Math.expm1(( + x)) | 0) >>> 0)) >>> 0), (( - ( + x)) >>> 0)), (Math.cosh((y | 0)) ** x))) >>> 0), Math.fround(-Number.MAX_VALUE)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, Math.PI, -(2**53-2), 1/0, 0x100000000, 0x080000001, 0x100000001, Number.MIN_VALUE, 42, -1/0, 1, 0, -0, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53+2, 0/0, -(2**53), -0x07fffffff, 0x0ffffffff, 2**53-2, 0x080000000, Number.MAX_VALUE, 2**53, 0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=122; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(o2, o2)");
/*fuzzSeed-169986037*/count=123; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var sin = stdlib.Math.sin;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    return (((~(((((((0x374a59ed)) ^ ((0xab84b8d8))) > (((0xfb428e17)) & ((0xffdd6625)))))>>>((i2))) % (0x0))) / (((i1)+((((0x621753aa)+(-0x8000000)) | ((i1))) <= (((((-4097.0)) * ((-268435457.0))) == (+sin(((2251799813685249.0)))))))) >> ((0xf93995a0)+(i2)))))|0;\n  }\n  return f;/* no regression tests found */\n })(this, {ff: let}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [(function(){return 0;}), (new Boolean(true)), [], (new Boolean(false)), true, null, NaN, (new Number(-0)), 1, '\\0', '0', [0], undefined, ({valueOf:function(){return '0';}}), (new Number(0)), (new String('')), /0/, '', objectEmulatingUndefined(), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), 0.1, '/0/', false, 0, -0]); ");
/*fuzzSeed-169986037*/count=124; tryItOut("mathy5 = (function(x, y) { return Math.hypot(Math.fround((mathy2(((Math.atan2(x, ( + ( + mathy1((y / -(2**53+2)), ( + (-1/0 != y)))))) | 0) >>> 0), (((Math.fround(mathy2((Math.min(((y >>> 0) >= (x >>> 0)), x) | 0), Math.fround(( + mathy2(( + ( + y)), ( + (((mathy4(x, ( + y)) >>> 0) >>> (y | 0)) >>> 0))))))) | 0) == mathy2((Math.log2((Math.atan((( + Number.MIN_SAFE_INTEGER) | 0)) | 0)) | 0), ( + ( ~ x)))) >>> 0)) >>> 0)), ( + ( + (( + (Math.round((Math.cosh((Math.ceil((( - ( + -0)) | 0)) | 0)) | 0)) >>> 0)) ? ( + (x & Math.fround(Math.imul(Math.abs(( + -0x0ffffffff)), (mathy1(-0, (-(2**53) >>> 0)) >>> 0))))) : ( + mathy4(( + (Math.abs((x >>> 0)) >>> 0)), (x ? x : y))))))); }); testMathyFunction(mathy5, [0x100000000, 0x080000000, -0x080000000, Number.MIN_SAFE_INTEGER, 0, -(2**53-2), -0x100000000, 2**53+2, 0x0ffffffff, -0x080000001, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, -0x100000001, -(2**53), 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1, 1/0, Number.MAX_VALUE, 42, -0x07fffffff, -(2**53+2), 0.000000000000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, Math.PI, Number.MIN_VALUE, 0x080000001, 2**53, 0/0, -0, 0x100000001, -1/0]); ");
/*fuzzSeed-169986037*/count=125; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.max(Math.sin(Math.fround(( ! Math.min((Math.log10((y | 0)) | 0), mathy0(-Number.MIN_VALUE, ((Math.pow(-Number.MIN_SAFE_INTEGER, y) >>> 0) >>> 0)))))), (( + ( + (y | 0))) ? (Math.cosh((( ! -(2**53+2)) >>> 0)) >>> 0) : (mathy1(x, (( ! (y >>> 0)) >>> 0)) | 0))); }); testMathyFunction(mathy2, [Number.MAX_VALUE, 1, 2**53+2, -0x080000001, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, 0.000000000000001, -(2**53), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0x080000000, 0x07fffffff, -0x080000000, Math.PI, 2**53, 1/0, 0x0ffffffff, -0, 2**53-2, -Number.MAX_VALUE, 0, -0x100000001, -0x100000000, 0x100000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), 1.7976931348623157e308, 42, 0x100000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=126; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((0xdc437806)))|0;\n    return ((((Float64ArrayView[0]))+(i1)-((0x2572fca4) ? (i1) : (i1))))|0;\n  }\n  return f; })(this, {ff: mathy4}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53-2), 2**53+2, -0x100000000, 0/0, -(2**53), -0x0ffffffff, -0x080000001, 0.000000000000001, 0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, -(2**53+2), -0, -0x07fffffff, 0x100000001, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_VALUE, -1/0, 2**53-2, -0x080000000, 0x100000000, 1/0, Math.PI, 0x07fffffff, 1, 1.7976931348623157e308, 0, 2**53, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=127; tryItOut("let (y) { o2.v1 = t0.length; }");
/*fuzzSeed-169986037*/count=128; tryItOut("const y = (4277);this.a0[v1] = e1;");
/*fuzzSeed-169986037*/count=129; tryItOut("\"use strict\"; /*bLoop*/for (wkrcgc = 0; wkrcgc < 113; ++wkrcgc) { if (wkrcgc % 105 == 35) { ; } else { {} }  } ");
/*fuzzSeed-169986037*/count=130; tryItOut("print( /x/ );");
/*fuzzSeed-169986037*/count=131; tryItOut("print(x);");
/*fuzzSeed-169986037*/count=132; tryItOut("\"use strict\"; h2 = m2.get(h2);");
/*fuzzSeed-169986037*/count=133; tryItOut("mathy4 = (function(x, y) { return Math.max((mathy2((( + Math.round(y)) >>> 0), (Math.fround(( ~ Math.fround(mathy3(Math.fround(2**53), Math.fround((Math.acosh(x) ^ (y | 0))))))) >>> 0)) | 0), Math.hypot(Math.fround((((( + Math.abs(x)) + Math.min((Math.min(0x080000000, y) ? ( + y) : x), y)) / (y && Math.fround((x * ( + y))))) >>> 0)), ( ! ( + (1 || x))))); }); testMathyFunction(mathy4, [-0x100000001, 1/0, -(2**53+2), -(2**53), -1/0, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, 0x080000001, -0x080000001, -(2**53-2), -0x080000000, 0x100000001, 0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, 0.000000000000001, 0x080000000, Math.PI, -Number.MAX_VALUE, -0, Number.MIN_VALUE, 42, -0x07fffffff, 2**53-2, 0x100000000, 2**53, 0, Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=134; tryItOut("\"use strict\"; print((this.__defineGetter__(\"b\", set)));");
/*fuzzSeed-169986037*/count=135; tryItOut("var nicdtq = new ArrayBuffer(6); var nicdtq_0 = new Uint8Array(nicdtq); var nicdtq_1 = new Int32Array(nicdtq); var nicdtq_2 = new Int8Array(nicdtq); print(nicdtq_2[0]); nicdtq_2[0] = 13; g1.o2.s2 + f0;m2 = a0[14];");
/*fuzzSeed-169986037*/count=136; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return (Math.clz32((( + Math.round(Math.sign(y))) >>> 0)) % (( ~ x) * Math.fround(mathy0((((x >= mathy1(x, y)) & y) >>> 0), x)))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -(2**53-2), 1/0, 2**53-2, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000000, -1/0, 0x080000000, Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53), 42, 0/0, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0, 0.000000000000001, -Number.MIN_VALUE, 2**53, 2**53+2, -(2**53+2), 0x0ffffffff, -0x080000000, Number.MAX_VALUE, -0x100000001, 1, 1.7976931348623157e308, -0, 0x07fffffff, -0x080000001, Math.PI, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=137; tryItOut("o0.v0 = evalcx(\"(allocationMarker()).watch(\\\"apply\\\", ((void options('strict_mode'))))\", g0);\n/*RXUB*/var r = new RegExp(\"(?:(?!\\\\B))+?\", \"gyi\"); var s = \"\\ubce0a\\ubce0a\\ubce0a\"; print(s.replace(r, Math)); \n");
/*fuzzSeed-169986037*/count=138; tryItOut("a2[0] = f1;");
/*fuzzSeed-169986037*/count=139; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((( + (x >= Math.acos((x | 0)))) <= Math.hypot(Math.fround((Math.max(Math.fround(( + (x >>> 0))), Math.fround((( + (Math.hypot(( + x), ((x | x) >>> 0)) | 0)) | 0))) | 0)), Math.fround((Math.tanh((x >>> 0)) >> -0x100000001)))) >>> 0); }); testMathyFunction(mathy0, [0x100000001, 0x100000000, -(2**53+2), -(2**53), -(2**53-2), 0x0ffffffff, -0x07fffffff, 1/0, -0x100000001, 0/0, -Number.MAX_VALUE, 2**53, -0, 0.000000000000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x080000001, 1, 42, -1/0, 2**53-2, 0x080000000, 0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 2**53+2, Math.PI, 1.7976931348623157e308]); ");
/*fuzzSeed-169986037*/count=140; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=141; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=142; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.ceil(Math.hypot(( + ( ~ (x || x))), ( ! Math.sqrt(x)))); }); testMathyFunction(mathy1, [0, 0x100000001, -0x07fffffff, -(2**53+2), 0x080000001, -1/0, 42, 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, -0, 0x080000000, 0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, 2**53+2, Number.MIN_VALUE, -(2**53), 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x080000000, 1/0, -0x100000000, 2**53, -Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, 2**53-2, -0x100000001, -0x080000001, 0x100000000, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0]); ");
/*fuzzSeed-169986037*/count=143; tryItOut("e1.add(i1);");
/*fuzzSeed-169986037*/count=144; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=145; tryItOut("print(x);break L;\na0.forEach((function() { try { a1.reverse(v2); } catch(e0) { } try { m1.delete(p1); } catch(e1) { } try { Object.defineProperty(g1, \"v2\", { configurable:  \"\" , enumerable: true,  get: function() {  return a0.length; } }); } catch(e2) { } o2 = Object.create(a1); return e1; }));\n\ndwxxix, [] = /[\\d](?!(?=[^]))|^?|(?=[^)\\W\\n\\W]\\S|[^]|\\1{2,16777217})*?/gm, eval = /*MARR*/[objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), x, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), x, new Number(1.5), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, new Number(1.5), new Number(1.5), new Number(1.5), x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), new Number(1.5), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Number(1.5), new Number(1.5), x, objectEmulatingUndefined(), x, new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), new Number(1.5), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), new Number(1.5), new Number(1.5), x, new Number(1.5), x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x], \u3056 = (let (eval) x), kcdlnt, qcnksc, oeccpj, x;h0.get = (function() { for (var j=0;j<48;++j) { f1(j%4==1); } });\n");
/*fuzzSeed-169986037*/count=146; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround(Math.fround(((((Math.tan((Math.imul(( + ( + Math.atan2(0x0ffffffff, Number.MIN_VALUE))), Math.cbrt(( + Math.atan(Math.fround(1.7976931348623157e308))))) >>> 0)) >>> 0) >>> 0) >= (Math.expm1(Math.fround(((-(2**53+2) | 0) > Math.fround(Math.cos(y))))) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-169986037*/count=147; tryItOut("");
/*fuzzSeed-169986037*/count=148; tryItOut("sgntdx();/*hhh*/function sgntdx(x){m1.set(b2, b2);}");
/*fuzzSeed-169986037*/count=149; tryItOut("/*oLoop*/for (var fonkys = 0, b = (x = (let (e=eval) e)), (x) = (/*wrap3*/(function(){ \"use strict\"; var kutsee = false; (Function)(); })).bind(false,  '' ); fonkys < 93; ++fonkys) { throw  /* Comment */ ''  ^ (undefined)(window, new RegExp(\"^[^]\", \"im\")); } ");
/*fuzzSeed-169986037*/count=150; tryItOut("mathy1 = (function(x, y) { return (((( ~ mathy0((Math.max((y | 0), (-Number.MAX_VALUE | 0)) | 0), (x - y))) | 0) >>> 0) + mathy0(Math.min((( - ((Math.tan((x >>> 0)) >>> 0) >>> 0)) >>> 0), ( ! ( + Math.pow(x, ( + (( + x) >>> ( + ( + y)))))))), ((((y % Math.atanh(mathy0((Math.pow(x, x) | 0), (y | 0)))) | 0) >>> (Math.imul(Math.hypot(Math.fround(( ~ -(2**53))), Math.fround(x)), ( + mathy0(( + mathy0((Math.imul(x, x) >>> 0), ((( - -1/0) >>> 0) >>> 0))), -Number.MAX_SAFE_INTEGER))) | 0)) | 0))); }); testMathyFunction(mathy1, [0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 0x100000000, -(2**53), 2**53, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0, 2**53-2, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, -0x080000001, -0x0ffffffff, 0x100000001, 0x07fffffff, 2**53+2, 1.7976931348623157e308, Number.MIN_VALUE, 42, -0x100000001, -0x100000000, 0x0ffffffff, 1/0, -0, Math.PI, -Number.MAX_VALUE, 1, -(2**53-2), 0.000000000000001]); ");
/*fuzzSeed-169986037*/count=151; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=152; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.sqrt((Math.min(( + Math.imul(Math.max(x, (Math.tan(1.7976931348623157e308) | 0)), Math.fround(( ! y)))), Math.fround(Math.fround((Math.fround(Math.max(y, Math.acosh(Math.imul(Math.exp(-Number.MIN_SAFE_INTEGER), y)))) ? ( - 1/0) : Math.fround(((( ~ Math.fround(((Number.MAX_SAFE_INTEGER == (y >>> 0)) >>> 0))) & y) >>> 0)))))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-169986037*/count=153; tryItOut("\"use strict\"; /*vLoop*/for (var kaqfjc = 0; kaqfjc < 65; ++kaqfjc) { d = kaqfjc; skyjqn(null, d);/*hhh*/function skyjqn(d = let = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: undefined, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: undefined, get: function() { return undefined }, set: function() { throw 3; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { return []; }, }; })(({a1:1})), d)){return Math.pow(14, d);} } ");
/*fuzzSeed-169986037*/count=154; tryItOut("/*RXUB*/var r = new RegExp(\"\\u4082\", \"yi\"); var s =  /* Comment */-22; print(s.replace(r, '\\u0341')); ");
/*fuzzSeed-169986037*/count=155; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a2, []);");
/*fuzzSeed-169986037*/count=156; tryItOut("L:do {t2.set(a2, 11);/*MXX1*/o2 = g1.Array.prototype; } while((x) && 0);");
/*fuzzSeed-169986037*/count=157; tryItOut("\"use asm\"; /*RXUB*/var r = /((?=(?!((?!(?=[^][^]*?))*?))))/m; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=158; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(Math.round(((Math.atan2((x | 0), (( - Math.min(x, ( + -(2**53)))) | 0)) | 0) != Math.atan2((Math.sqrt((x >>> 0)) >>> 0), (y >>> 0)))), Math.pow((Math.max((Math.acos((( + (0x080000000 | 0)) | 0)) | 0), (((Math.tanh((Math.pow((y | 0), (2**53 >>> 0)) >>> 0)) >>> 0) - x) | 0)) >>> 0), Math.fround(Math.fround(((Math.asinh((Math.tanh(0x080000001) | 0)) >>> 0) + Math.fround((( ~ x) >>> 0))))))); }); ");
/*fuzzSeed-169986037*/count=159; tryItOut("Object.prototype.watch.call(b2, \"call\", (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    i2 = (((-0xfffff*(((0x8964608b) >= (0xab0565d9)) ? (i2) : (i1)))>>>(((i2) ? ((~~(((73786976294838210000.0)) % ((-147573952589676410000.0))))) : (i1)))) > (((i0)+(i0))>>>((i2)+((((+(((/*FFI*/ff(((6.044629098073146e+23)), ((4398046511105.0)), ((16385.0)), ((-1.1805916207174113e+21)))|0))>>>((0x9f57babf)-(0xfb2ff81)-(0xce19065e))))))))));\n    return +((+((Float64ArrayView[2]))));\n    return +((NaN));\n  }\n  return f; })(this, {ff: Date.parse}, new SharedArrayBuffer(4096)));");
/*fuzzSeed-169986037*/count=160; tryItOut("v1 = g1.eval(\"(uneval(x))\");");
/*fuzzSeed-169986037*/count=161; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return ((((( + Math.fround(( + x))) >= ((( ~ Math.tan(Math.max(((y % x) | 0), (-1/0 > ((Math.fround(y) >= x) >>> 0))))) >>> 0) >>> 0)) | 0) % (Math.hypot(Math.fround(( + Math.asinh((( + ( + Math.atan2(( ~ y), (Math.hypot(x, y) >>> 0)))) | 0)))), mathy0(( + ( ~ Math.fround((((y < y) / x) ** Math.round(( + (( + x) ? ( + x) : y))))))), ( + (( ~ y) | 0)))) | 0)) | 0); }); testMathyFunction(mathy5, /*MARR*/[1e4, [undefined], 1e4,  \"use strict\" , (void 0), (void 0), new String('q'), [undefined], new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), [undefined]]); ");
/*fuzzSeed-169986037*/count=162; tryItOut("\"use strict\"; /*bLoop*/for (let aaojlx = 0, (4277); aaojlx < 1; ++aaojlx) { if (aaojlx % 6 == 1) { o0 = m2.get(e2); } else { for (var p in m2) { t0 = new Int8Array(b2); } }  } ");
/*fuzzSeed-169986037*/count=163; tryItOut("\"use strict\"; o2.m2.get(i0);");
/*fuzzSeed-169986037*/count=164; tryItOut("\"use strict\"; v2 = g1.runOffThreadScript();");
/*fuzzSeed-169986037*/count=165; tryItOut("g2.v1 = a2.reduce, reduceRight(g2.f0);");
/*fuzzSeed-169986037*/count=166; tryItOut("\"use strict\"; print(((w) =  /* Comment */window));");
/*fuzzSeed-169986037*/count=167; tryItOut("o1.g2.g0 = this;");
/*fuzzSeed-169986037*/count=168; tryItOut("\"use strict\"; /*RXUB*/var r = /(?!(\\1|$(?!\\b+)))|(\\2)/g; var s = \"\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=169; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 6.044629098073146e+23;\n    var i3 = 0;\n    var d4 = -1048577.0;\n    i1 = (/*FFI*/ff(((~~((x) / ((d4))))), ((imul((0x2e4f314e), (0xc599f0dc))|0)), ((~(((!((0xa8194629) ? (0xffffffff) : (0xffffffff))) ? (((Uint8ArrayView[2]))) : ((0xc8a41bb3) ? (0xff0c11a7) : (0xffd5b49a)))))), ((abs(((((x)(new Date( \"\" , null)))) >> (((((0xfeaabb04)) << ((0x2f7116d1))))-((0x481c871e)))))|0)))|0);\n    {\n      {\n        {\n          d4 = (-((+(0xffffffff))));\n        }\n      }\n    }\n    return ((((/*FFI*/ff(((+atan2(((Float32ArrayView[((-0x8000000)+(0xd91cf0c1)) >> 2])), ((((-65537.0)) % ((+(-1.0/0.0)))))))), ((d2)))|0) ? (i3) : (0x82d1bdb9))+(i1)))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ function shapeyConstructor(htlayt){Object.defineProperty(this, \"4\", ({enumerable: window}));this[new String(\"8\")] = WeakMap.prototype.set;if (x) this[new String(\"8\")] = WeakSet;delete this[new String(\"8\")];Object.defineProperty(this, \"call\", ({configurable: (htlayt % 3 == 1)}));this[new String(\"8\")] = (Uint8Array).call;this[new String(\"8\")] = objectEmulatingUndefined();return this; }/*tLoopC*/for (let y of /*MARR*/[new String(''), new String(''), new String(''), (-1/0), new String(''), (-1/0), new String(''), new String(''), new String(''), new String(''), (-1/0), new String(''), (-1/0), (-1/0), new String(''), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new String(''), new String(''), (-1/0), (-1/0), new String(''), new String(''), new String(''), (-1/0), (-1/0), new String(''), (-1/0), (-1/0), new String(''), new String(''), new String(''), (-1/0), new String(''), (-1/0), new String(''), new String(''), new String(''), new String(''), (-1/0), (-1/0), new String(''), new String(''), new String(''), (-1/0), new String(''), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), new String(''), new String(''), new String(''), (-1/0), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), (-1/0), (-1/0), new String(''), new String(''), new String(''), new String(''), (-1/0), (-1/0), new String(''), new String(''), (-1/0), new String(''), new String(''), (-1/0), (-1/0), new String(''), (-1/0), (-1/0), new String(''), new String(''), new String(''), (-1/0), (-1/0), (-1/0), new String(''), new String(''), new String(''), (-1/0), new String(''), (-1/0), new String(''), (-1/0), (-1/0), (-1/0), (-1/0), new String(''), new String(''), (-1/0), (-1/0), new String(''), (-1/0), (-1/0), new String('')]) { try{let bbtrsd = shapeyConstructor(y); print('EETT'); print(x);}catch(e){print('TTEE ' + e); } }return eval})()}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Math.PI, Number.MAX_SAFE_INTEGER, 0x080000001, -0x080000001, 1, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000000, 1.7976931348623157e308, 2**53+2, -1/0, -Number.MAX_VALUE, 42, -0x080000000, 0/0, 0x100000001, 0x0ffffffff, -0, Number.MAX_VALUE, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000001, 2**53-2, -0x100000000, 1/0, 0.000000000000001, 2**53, -(2**53-2), -(2**53), 0, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=170; tryItOut("a1.forEach((function() { try { for (var p in o0) { v0 = evalcx(\"f2(f2);\", g2); } } catch(e0) { } try { let g0.v1 = evaluate(\"/* no regression tests found */\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: 15, noScriptRval: false, sourceIsLazy: function ([y]) { }, catchTermination: false })); } catch(e1) { } e1.add(a0); return o1.v2; }), s0, i2);o1.m1.get(m1);");
/*fuzzSeed-169986037*/count=171; tryItOut("testMathyFunction(mathy3, /*MARR*/[new String('q'), objectEmulatingUndefined(), [1], [1], new String('q'), objectEmulatingUndefined(), [1], objectEmulatingUndefined(), undefined, objectEmulatingUndefined()]); ");
/*fuzzSeed-169986037*/count=172; tryItOut("\"use asm\"; switch(x) { case : v1.toString = Object.keys.bind(h2)\na0 = a1.map((function(j) { f0(j); }));break; default: break; case 5:  }");
/*fuzzSeed-169986037*/count=173; tryItOut("m0.delete(e1);");
/*fuzzSeed-169986037*/count=174; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( ~ Math.atan2(Math.fround(( + Math.exp(( + (Math.atan2(( + ( - (y <= (Math.min((y >>> 0), (x | 0)) | 0)))), y) | 0))))), (( ~ ( + ( + (y ? ( + Math.imul(mathy0(x, x), ( + (( + (Math.atan((-1/0 | 0)) | 0)) ? ( + x) : y)))) : ( + 0x080000000))))) | 0))); }); testMathyFunction(mathy4, /*MARR*/[x, new Boolean(false), new Boolean(false), x, -Number.MAX_SAFE_INTEGER,  /x/g , x, x, -Number.MAX_SAFE_INTEGER, x, x,  /x/g , new Boolean(false), -Number.MAX_SAFE_INTEGER, x,  /x/g , new Boolean(false), new Boolean(false), -Number.MAX_SAFE_INTEGER,  /x/g , new Boolean(false), -Number.MAX_SAFE_INTEGER, x, x, x, x, -Number.MAX_SAFE_INTEGER,  /x/g , new Boolean(false), new Boolean(false), -Number.MAX_SAFE_INTEGER, new Boolean(false), -Number.MAX_SAFE_INTEGER, new Boolean(false), -Number.MAX_SAFE_INTEGER, x, x, new Boolean(false),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , new Boolean(false), -Number.MAX_SAFE_INTEGER, x, -Number.MAX_SAFE_INTEGER, new Boolean(false), x, x, new Boolean(false), -Number.MAX_SAFE_INTEGER,  /x/g , -Number.MAX_SAFE_INTEGER, new Boolean(false), new Boolean(false),  /x/g , new Boolean(false),  /x/g , x,  /x/g , -Number.MAX_SAFE_INTEGER, new Boolean(false), new Boolean(false), -Number.MAX_SAFE_INTEGER, new Boolean(false),  /x/g , new Boolean(false), -Number.MAX_SAFE_INTEGER, x,  /x/g , -Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, new Boolean(false), x, new Boolean(false), x, new Boolean(false),  /x/g , new Boolean(false), new Boolean(false), -Number.MAX_SAFE_INTEGER,  /x/g , x, x, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), -Number.MAX_SAFE_INTEGER, x]); ");
/*fuzzSeed-169986037*/count=175; tryItOut("\"use strict\"; a1.unshift(s0, b0, t0, h2);");
/*fuzzSeed-169986037*/count=176; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=177; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((Math.fround(mathy0((x % y), ( + (y ? Math.imul((Math.atan2(Math.fround(y), (x >>> 0)) >>> 0), -0x07fffffff) : y)))) - Math.fround(Math.hypot(((( + x) >>> 0) | 0), (y | 0)))) & Math.log10(((Math.fround(Math.max(Math.fround(y), Math.fround(( + Math.hypot(( + ( + ( + 2**53+2))), ( + x)))))) == 0) | 0))); }); testMathyFunction(mathy1, [-0, (function(){return 0;}), ({toString:function(){return '0';}}), '\\0', '/0/', '0', 0.1, '', true, [], (new String('')), (new Boolean(true)), NaN, false, (new Number(-0)), [0], (new Number(0)), 0, ({valueOf:function(){return '0';}}), undefined, ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), (new Boolean(false)), null, /0/, 1]); ");
/*fuzzSeed-169986037*/count=178; tryItOut("((4277));");
/*fuzzSeed-169986037*/count=179; tryItOut("break L\ne2.delete(t0);/*infloop*/for(let d; eval >= z.eval(\"this.r1 = new RegExp(\\\"((\\\\u4944.|[\\\\\\\\cP-\\\\\\\\u00a9].)|.{0,0}{2})?\\\", \\\"g\\\");\"); (new ( '' )(-26, 14))) /*RXUB*/var r = /[^\\0-\u09f9\\x59-\u00ad]/ym; var s = \"p\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=180; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + Math.log10((( + (-Number.MAX_VALUE | (Math.tan(x) | 0))) >>> 0))); }); ");
/*fuzzSeed-169986037*/count=181; tryItOut("\"use strict\"; /*RXUB*/var r = r2; var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-169986037*/count=182; tryItOut("{ if (isAsmJSCompilationAvailable()) { void 0; bailAfter(2); } void 0; } print(x);");
/*fuzzSeed-169986037*/count=183; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( ~ (((((Math.imul(Math.hypot(x, x), (0x080000001 * x)) >>> 0) <= Math.acos(x)) >>> 0) % (( + (( ! Math.fround(Math.hypot((-0x080000000 >>> 0), ( + Math.max(( ! (y | 0)), x))))) >>> 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-1/0, 2**53-2, Number.MIN_VALUE, 0x0ffffffff, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0, 2**53+2, 2**53, -0x100000000, -(2**53-2), 0x100000001, -0x0ffffffff, 0x080000001, 1.7976931348623157e308, Math.PI, 0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53+2), 0, -0x080000000, -0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, 0.000000000000001, -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, 1, -Number.MAX_VALUE, 0x07fffffff, 0x100000000, 42]); ");
/*fuzzSeed-169986037*/count=184; tryItOut("mathy4 = (function(x, y) { return (Math.min((Math.min(( ~ (Math.hypot(( + 2**53+2), Math.cos((y | 0))) | 0)), ( + ( + ( + ( + ( + ((y < Math.min(1/0, y)) | 0))))))) | 0), (( - (mathy2(Math.pow(( ~ y), ( + (( + -0x0ffffffff) ? ( + (Math.clz32(x) ? x : x)) : ( + (((y | 0) * Math.fround(-0)) | 0))))), ( + Math.asinh((y ? Math.fround(( + x)) : (x ^ y))))) | 0)) >>> 0)) | 0); }); testMathyFunction(mathy4, [Math.PI, 2**53-2, -Number.MIN_VALUE, 0x100000001, -0, 42, -(2**53+2), -0x100000000, 0x080000000, Number.MAX_VALUE, 0, 0x100000000, Number.MIN_VALUE, 0x0ffffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, -Number.MAX_VALUE, 1/0, -0x080000001, -0x080000000, 0/0, -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 0x07fffffff, -1/0, -0x0ffffffff, 0.000000000000001, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=185; tryItOut("testMathyFunction(mathy4, [-0x100000001, -(2**53-2), 0x100000000, 0x080000001, 0x07fffffff, 0, -Number.MIN_VALUE, -0x080000001, -(2**53), 2**53+2, 2**53-2, -0x100000000, Math.PI, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, 0x100000001, 1.7976931348623157e308, -Number.MAX_VALUE, 1, 0x0ffffffff, -0, 0/0, -0x07fffffff, Number.MIN_VALUE, 2**53, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x080000000, 42]); ");
/*fuzzSeed-169986037*/count=186; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return ((Math.fround(( ! ( + ( - ( + ( + ( ! Math.fround(((y >>> (((0/0 | 0) >= x) | 0)) | 0))))))))) / (Math.fround(Math.imul(Math.fround((Math.pow(( ~ x), (Math.pow(Math.log(x), (((-0x07fffffff | 0) & (x | 0)) | 0)) >>> 0)) >= Math.imul(Math.fround((x || Math.fround(-0x0ffffffff))), (Math.sqrt(-(2**53)) <= -0x07fffffff)))), Math.fround(( ! ((((( - x) >>> 0) / (x >>> 0)) >>> 0) | 0))))) | 0)) | 0); }); testMathyFunction(mathy4, [[], (new Boolean(false)), (new Boolean(true)), 1, -0, '\\0', undefined, (new String('')), /0/, false, true, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (function(){return 0;}), (new Number(0)), 0.1, null, '0', NaN, (new Number(-0)), '/0/', ({toString:function(){return '0';}}), [0], '', ({valueOf:function(){return 0;}}), 0]); ");
/*fuzzSeed-169986037*/count=187; tryItOut("for(let w in /*MARR*/[(-1/0),  /x/g ,  /x/g , NaN,  /x/g ,  /x/g , NaN, (-1/0),  /x/g , (-1/0), (-1/0),  /x/g , NaN, NaN, NaN,  /x/g , (-1/0),  /x/g , new Boolean(false),  /x/g , new Boolean(false), (-1/0),  /x/g ,  /x/g ]) (setter);for(let d of /*FARR*/[/(\\d)/gim,  '' , ...[],  \"\" , ]) (/(?=(?:\\xA1)(?![^])*??)/gym);");
/*fuzzSeed-169986037*/count=188; tryItOut("mathy0 = (function(x, y) { return (Math.asinh(((Math.fround(( - Math.fround(Math.fround(Math.atan(Math.fround(x)))))) / ( - Math.fround(( + (( + (( + y) + ( + -0x100000000))) !== Number.MIN_SAFE_INTEGER))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [2**53+2, -(2**53+2), -Number.MIN_VALUE, 1, 42, -0x100000000, 2**53-2, 2**53, 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0, -(2**53-2), 0/0, -0x0ffffffff, 0x080000000, 0x100000000, -0x100000001, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 0x100000001, 0x080000001, -0x07fffffff, -1/0, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53), -0x080000001]); ");
/*fuzzSeed-169986037*/count=189; tryItOut("h1.get = (function() { try { v2 = (e0 instanceof h2); } catch(e0) { } try { /*MXX1*/o2 = o2.g2.WebAssemblyMemoryMode; } catch(e1) { } g2.h1.keys = f1; return g0.t0; });");
/*fuzzSeed-169986037*/count=190; tryItOut("/*tLoop*/for (let a of /*MARR*/[new Number(1), {}, new Number(1), function(){}, function(){}, function(){}, {}, new Number(1), function(){}, new Number(1), function(){}, function(){}, function(){}, function(){}, function(){}, new Number(1), function(){}, new Number(1), new Number(1), function(){}, function(){}, function(){}, function(){}, new Number(1), function(){}, function(){}, function(){}, {}, function(){}, {}, function(){}, function(){}, function(){}, new Number(1), function(){}]) { { void 0; gcslice(3); } v2 = false; }");
/*fuzzSeed-169986037*/count=191; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ! ( ! ( + Math.abs(( ~ ( + mathy1(( + y), -0x07fffffff))))))); }); testMathyFunction(mathy4, /*MARR*/[(4277), ['z'], (4277), (4277), ['z'], (4277), ['z'], ['z'], ['z'], new String('q'), ['z'], objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q'), objectEmulatingUndefined(), (4277), objectEmulatingUndefined(), objectEmulatingUndefined(), new String('q')]); ");
/*fuzzSeed-169986037*/count=192; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.atanh((Math.asin(((2**53 | 0) & (Math.fround(Math.atan2(Math.fround(x), Math.fround((x & y)))) | 0))) | 0)); }); testMathyFunction(mathy1, [2**53+2, 0x080000001, 1, -Number.MAX_VALUE, 0x07fffffff, 42, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_VALUE, Math.PI, 0x080000000, -0x080000001, -1/0, 0x0ffffffff, 0/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53-2, 2**53, -0x100000001, -0, 1/0, -(2**53+2), 0.000000000000001, -(2**53), 0, -(2**53-2), 0x100000001, 1.7976931348623157e308, 0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-169986037*/count=193; tryItOut("print(i0);");
/*fuzzSeed-169986037*/count=194; tryItOut("m2.get(o0);");
/*fuzzSeed-169986037*/count=195; tryItOut("var pggsif = new ArrayBuffer(4); var pggsif_0 = new Float64Array(pggsif); pggsif_0[0] = -29; ([z1]);");
/*fuzzSeed-169986037*/count=196; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[Infinity, Infinity, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), Infinity, new String('q'), new String('q'), new String('q'), Infinity, new String('q'), Infinity, new String('q'), new String('q'), Infinity, new String('q'), Infinity, new String('q'), new String('q'), Infinity, new String('q'), new String('q'), Infinity, new String('q'), new String('q'), Infinity, Infinity, Infinity, Infinity, Infinity, new String('q'), Infinity, Infinity, new String('q'), new String('q'), Infinity, Infinity, Infinity]) { Array.prototype.unshift.call(a1, e1, (/*wrap3*/(function(){ var rfiaxd = e; (Uint32Array)(); }))(x())); }");
/*fuzzSeed-169986037*/count=197; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return mathy1(((Math.cosh(((( ~ y) | 0) | 0)) | 0) | ( + ( - ( + (y === ( + (1 , Math.fround(Number.MAX_SAFE_INTEGER)))))))), ( + Math.atanh((( + (( + ( ~ y)) === x)) >>> 0)))); }); testMathyFunction(mathy3, [2**53+2, -(2**53-2), 0x07fffffff, -Number.MIN_VALUE, 42, 0x080000001, -1/0, -0x080000001, 0, -0x0ffffffff, 2**53, 0x100000001, Number.MIN_VALUE, -0x100000001, -0x080000000, Math.PI, 0x100000000, 1, -(2**53+2), -Number.MAX_VALUE, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, -0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, 0x0ffffffff, 1.7976931348623157e308, -(2**53), 0/0, 0.000000000000001, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=198; tryItOut("/*RXUB*/var r = /(?:(?!$|(?:\u8ef9){2}))/gyim; var s = \"\\u5863\\n\\n\\u00ce*\\n\\n\\u0090\\u0090\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=199; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=200; tryItOut("\"use strict\"; g2.g2.h2 = {};");
/*fuzzSeed-169986037*/count=201; tryItOut("\"use strict\"; testMathyFunction(mathy2, [-0x100000000, -0x080000001, -(2**53-2), 0x07fffffff, 0x100000001, -Number.MAX_VALUE, 1/0, 0, 2**53+2, -0x080000000, 1.7976931348623157e308, -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000000, -(2**53+2), 0x0ffffffff, -0, 0x080000001, 0/0, -Number.MIN_VALUE, 2**53-2, -0x07fffffff, 2**53, -0x100000001, Math.PI, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE, -0x0ffffffff, 42]); ");
/*fuzzSeed-169986037*/count=202; tryItOut("Object.defineProperty(this, \"v1\", { configurable: (function(y) { yield y; Array.prototype.forEach.call(a1, (function() { for (var j=0;j<25;++j) { g2.f1(j%4==0); } }), g1);; yield y; })(({\"-20\": undefined }), eval(\"for (var p in o1.e0) { try { v1 = Object.prototype.isPrototypeOf.call(t2, e2); } catch(e0) { } try { (void schedulegc(o0.o2.g0)); } catch(e1) { } try { /*RXUB*/var r = r2; var s = s1; print(s.split(r));  } catch(e2) { } f2(e1); }\")), enumerable: \"\\uCCE0\",  get: function() {  return Proxy.create(h0, a0); } });");
/*fuzzSeed-169986037*/count=203; tryItOut("\"use strict\"; v0.__proto__ = o0.a0;");
/*fuzzSeed-169986037*/count=204; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -3.094850098213451e+26;\n    var d3 = -33554433.0;\n    d3 = (d3);\n    d3 = (d3);\n    i0 = (-0x8000000);\n    return +((d2));\n  }\n  return f; })(this, {ff: (let (e=eval) e)}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [0x080000001, 2**53-2, -Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, 2**53+2, -(2**53-2), 42, -0x080000000, -Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 0/0, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, 1, -0x100000001, 0x07fffffff, Math.PI, -(2**53+2), -1/0, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 0, Number.MAX_VALUE, 0x100000000, 0.000000000000001, -0x07fffffff, -0]); ");
/*fuzzSeed-169986037*/count=205; tryItOut("\"use strict\"; /*RXUB*/var r = /./yi; var s = \"\\n\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=206; tryItOut("/*MXX3*/g0.RegExp.prototype.sticky = g0.RegExp.prototype.sticky;");
/*fuzzSeed-169986037*/count=207; tryItOut("g2.i2.send(o0.e1);");
/*fuzzSeed-169986037*/count=208; tryItOut("mathy0 = (function(x, y) { return ( + ( + ( + ( - Math.fround(( + ( - Math.fround(Math.hypot(Math.sin(x), Math.fround(((x | 0) / (x | 0)))))))))))); }); testMathyFunction(mathy0, [-(2**53), 0x100000001, 0/0, -Number.MIN_VALUE, 0, 2**53+2, 2**53-2, Math.PI, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, Number.MIN_SAFE_INTEGER, 0x080000001, 1, 1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53+2), 0x100000000, -0x0ffffffff, 0.000000000000001, 2**53, -0x080000000, Number.MIN_VALUE, -0x080000001, 0x080000000, -0x100000001, 0x0ffffffff, -1/0, -Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, 42, -0]); ");
/*fuzzSeed-169986037*/count=209; tryItOut("mathy2 = (function(x, y) { return Math.imul((Math.fround((1 >>> x)) ? Math.fround(( + Math.atan2(-Number.MAX_SAFE_INTEGER, y))) : Math.fround((((-0x100000001 + y) >>> 0) * (Math.min(Math.clz32(Math.fround(y)), 42) >>> 0)))), ( ~ ( + Math.hypot(-0x100000000, (( ~ (x | 0)) | 0))))); }); testMathyFunction(mathy2, [1, -0x080000000, -(2**53-2), 0x100000001, 0x0ffffffff, -0, 2**53, Number.MIN_SAFE_INTEGER, 42, 0x080000000, 2**53+2, 0x100000000, Math.PI, 2**53-2, 1.7976931348623157e308, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, -1/0, 0/0, -0x080000001, Number.MAX_VALUE, -Number.MAX_VALUE, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1/0, 0, -Number.MIN_VALUE, -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53), -0x100000001]); ");
/*fuzzSeed-169986037*/count=210; tryItOut("/*RXUB*/var r = /\\b(?!.)|(\\\uc64a+?[^]){0,}{2}|$|(\\S)/gm; var s = \"a\"; print(s.match(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=211; tryItOut("v0 = g2.objectEmulatingUndefined();");
/*fuzzSeed-169986037*/count=212; tryItOut("mathy0 = (function(x, y) { return ( ! ( + Math.log2(Math.atan2(0x0ffffffff, y)))); }); testMathyFunction(mathy0, /*MARR*/[x, (-1/0), x, (-1/0), (-1/0), x, x, new String(''), (-1/0), x, (-1/0),  /x/g , x,  /x/g ,  /x/g , (-1/0), x,  /x/g , (-1/0),  /x/g ,  /x/g , x, x,  /x/g ,  /x/g , (-1/0),  /x/g , x,  /x/g , x, (-1/0), x, x, x, (-1/0)]); ");
/*fuzzSeed-169986037*/count=213; tryItOut("a1[2] = e2;");
/*fuzzSeed-169986037*/count=214; tryItOut("\"use asm\"; for(x = (void version(185)) in let (c = \"\\uDDB7\")  /x/ ) {/*ODP-1*/Object.defineProperty(g1.b2, \"set\", ({configurable: false, enumerable: false})); }");
/*fuzzSeed-169986037*/count=215; tryItOut("mathy0 = (function(x, y) { return ( + ( ! ( + ( - ( + Math.imul(Math.pow((y | 0), ((((x / y) | 0) ? (-Number.MIN_VALUE | 0) : ( + x)) | 0)), Math.max(x, Math.log10(y)))))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -0x080000000, 2**53+2, -0x080000001, 0x100000000, 2**53-2, 0x100000001, 0x080000000, Number.MAX_VALUE, -1/0, 1/0, -0x07fffffff, -(2**53+2), 0/0, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 42, -0x100000000, 2**53, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, -(2**53-2), 0x0ffffffff, -0, Number.MIN_VALUE, 0.000000000000001, -0x100000001, 1, -Number.MIN_VALUE, 0, 0x080000001]); ");
/*fuzzSeed-169986037*/count=216; tryItOut("testMathyFunction(mathy5, [1, 0x0ffffffff, 0x100000000, 42, 1/0, 2**53+2, -0x07fffffff, -0x080000001, Number.MIN_VALUE, 0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000000, 2**53-2, -(2**53), 2**53, -Number.MIN_SAFE_INTEGER, -0, -0x100000000, 0x080000001, 0.000000000000001, 0/0, -(2**53-2), -0x100000001, 0x080000000, -(2**53+2), 0x100000001, 0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=217; tryItOut("a1[4];\nv2 = t1.length;\n");
/*fuzzSeed-169986037*/count=218; tryItOut("mathy2 = (function(x, y) { return (( + ( + ( + (x * Math.fround((x % (42 < y))))))) <= Math.hypot(Math.fround(mathy1(Math.fround(((y >>> 0) >> (y | 0))), ( + (y ? (Math.pow(( + y), ( + x)) | 0) : (Math.imul((x >>> 0), y) >>> 0))))), Math.fround((Math.fround(x) , Math.fround(Math.round(y)))))); }); testMathyFunction(mathy2, [-(2**53+2), 42, 0x0ffffffff, Math.PI, 1/0, 0/0, 2**53+2, -0x080000000, -0, -0x07fffffff, -(2**53-2), 0.000000000000001, 0x100000000, -1/0, -0x080000001, 0x100000001, 0x080000001, -Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, 1, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, -0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=219; tryItOut("this.h1.delete = this.f0;");
/*fuzzSeed-169986037*/count=220; tryItOut("L: {print(x);{} }");
/*fuzzSeed-169986037*/count=221; tryItOut("for (var v of s2) { try { g0.h0 = {}; } catch(e0) { } this.g0.g0 = t0[11]; }");
/*fuzzSeed-169986037*/count=222; tryItOut("mathy3 = (function(x, y) { return mathy1((( ~ ( + Math.cos((Math.log1p((x | 0)) | 0)))) ? ((Math.sin((x >>> 0)) > Math.fround(x)) >>> 0) : Math.tanh(( + Math.fround(( - y))))), ( + ( + mathy0(( + Math.clz32(x)), ( + (((((x <= 0x100000001) >>> 0) >= x) | 0) < (( - (( + x) >>> 0)) >>> 0))))))); }); ");
/*fuzzSeed-169986037*/count=223; tryItOut("var g0.a0 = arguments.callee.caller.caller.caller.arguments;");
/*fuzzSeed-169986037*/count=224; tryItOut("\"use strict\"; x;");
/*fuzzSeed-169986037*/count=225; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=226; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.log1p((Math.pow((Math.exp(((y ? x : (Math.sqrt(y) | 0)) | 0)) | 0), Math.atan(Math.fround((Math.fround(( ! (Math.acosh(x) >>> 0))) & Math.fround((Math.sin((y | 0)) | 0)))))) | 0)); }); testMathyFunction(mathy3, [-0x100000001, -Number.MAX_SAFE_INTEGER, -0, 0x0ffffffff, -(2**53), 0, -Number.MAX_VALUE, 0x100000001, -0x0ffffffff, 0x100000000, 1/0, -0x100000000, 2**53+2, -1/0, Number.MAX_VALUE, 42, -Number.MIN_SAFE_INTEGER, Math.PI, 0/0, 0x080000000, 2**53, Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, 2**53-2, -(2**53-2), 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 0.000000000000001, -0x080000000, Number.MIN_VALUE, -Number.MIN_VALUE, -(2**53+2), 1]); ");
/*fuzzSeed-169986037*/count=227; tryItOut("this.a0 = new Array;");
/*fuzzSeed-169986037*/count=228; tryItOut("Array.prototype.sort.apply(a0, [(function() { try { a0.toString = (function() { try { for (var v of m0) { try { v2 = (v1 instanceof a2); } catch(e0) { } /*ADP-2*/Object.defineProperty(a0, 1, { configurable: (x % 2 == 0), enumerable: (d.__defineSetter__(\"b\", 5)), get: (function(j) { if (j) { try { (void schedulegc(g2)); } catch(e0) { } try { f0(this.g0); } catch(e1) { } v0 + ''; } else { a1.sort((function() { try { x = i1; } catch(e0) { } try { v1 = g1.eval(\"/* no regression tests found */\"); } catch(e1) { } v0 = t1.byteOffset; return g1.p0; })); } }), set: (function() { m0.delete(o2); return m2; }) }); } } catch(e0) { } try { h2 = m2.get(t1); } catch(e1) { } try { m2.has(g2); } catch(e2) { } this.g0.t0 = t1.subarray(17); return v2; }); } catch(e0) { } try { Array.prototype.reverse.apply(a1, []); } catch(e1) { } /*RXUB*/var r = r0; var s = s2; print(uneval(r.exec(s))); print(r.lastIndex);  return f2; }), m2, this.b2]);");
/*fuzzSeed-169986037*/count=229; tryItOut("\"use strict\"; /*MXX1*/o0 = g0.URIError.prototype.name;");
/*fuzzSeed-169986037*/count=230; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.ceil((Math.fround(Math.pow((Math.ceil((y | 0)) | 0), mathy1(mathy1((Math.round((y >>> 0)) >>> 0), Math.fround(Math.abs((Math.sqrt((0x07fffffff >>> 0)) | 0)))), mathy0(Math.fround(Math.acosh((x | 0))), Math.acosh(Math.asinh((x >>> 0))))))) | 0)); }); testMathyFunction(mathy2, [0x07fffffff, -0x0ffffffff, 0x100000000, -0x080000001, 0x080000001, 1/0, 1.7976931348623157e308, -0, -0x100000000, 0.000000000000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x100000001, 2**53+2, 0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 42, -0x100000001, 1, 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, -Number.MIN_VALUE, -(2**53), 2**53-2, Math.PI, -(2**53+2), 0/0, -1/0, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=231; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0);");
/*fuzzSeed-169986037*/count=232; tryItOut("a0[16] = x;");
/*fuzzSeed-169986037*/count=233; tryItOut("\"use strict\"; v1 = -0;");
/*fuzzSeed-169986037*/count=234; tryItOut("o1.v2 = Object.prototype.isPrototypeOf.call(o2.g0, m0);m2 = new Map(t2);/*wrap3*/(function(){ var rphmbq = x; (runOffThreadScript)(); })");
/*fuzzSeed-169986037*/count=235; tryItOut("a0[1] = b1;");
/*fuzzSeed-169986037*/count=236; tryItOut("/*oLoop*/for (var utkete = 0; utkete < 38; ++utkete) { M:if(x) { if (c--) ( /x/g ); else {print( /x/g ); }} } ");
/*fuzzSeed-169986037*/count=237; tryItOut("/*vLoop*/for (let lzdipp = 0, x; ({} = (new  '' (this))) && lzdipp < 4; ++lzdipp) { let b = lzdipp; t1[v1];function e(y, ...NaN)x/*MXX3*/g1.Math.asinh = g2.Math.asinh; } ");
/*fuzzSeed-169986037*/count=238; tryItOut("\"use strict\"; this.i0 = t0[({valueOf: function() { this.e2.delete(p1);return 15; }})];");
/*fuzzSeed-169986037*/count=239; tryItOut("/*bLoop*/for (let kheuab = 0; kheuab < 78; c, ++kheuab) { if (kheuab % 20 == 13) { s1 + this.t2; } else { m1.set(e1, g0); }  } ");
/*fuzzSeed-169986037*/count=240; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + (( + ( ~ ( + Math.tan(Math.sin(x))))) ? ( + Math.fround(Math.asinh(Math.fround(( + y))))) : ( + Math.round((( - y) | 0))))); }); testMathyFunction(mathy0, [(new Number(-0)), 0, ({valueOf:function(){return 0;}}), -0, (new Boolean(false)), ({valueOf:function(){return '0';}}), [], false, NaN, '', objectEmulatingUndefined(), 1, ({toString:function(){return '0';}}), '\\0', '/0/', /0/, (function(){return 0;}), (new Boolean(true)), [0], null, undefined, (new String('')), true, (new Number(0)), '0', 0.1]); ");
/*fuzzSeed-169986037*/count=241; tryItOut("delete h2.fix;");
/*fuzzSeed-169986037*/count=242; tryItOut("selectforgc(o0);");
/*fuzzSeed-169986037*/count=243; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=244; tryItOut("print(uneval(o2.g1));");
/*fuzzSeed-169986037*/count=245; tryItOut("const c;({set: objectEmulatingUndefined, configurable: true})");
/*fuzzSeed-169986037*/count=246; tryItOut("\"use strict\"; var fzvgiz = new SharedArrayBuffer(8); var fzvgiz_0 = new Uint32Array(fzvgiz); var fzvgiz_1 = new Float64Array(fzvgiz); var fzvgiz_2 = new Int32Array(fzvgiz); fzvgiz_2[0] = 1e-81; var fzvgiz_3 = new Uint8Array(fzvgiz); fzvgiz_3[0] = -29; var fzvgiz_4 = new Int32Array(fzvgiz); print(fzvgiz_4[0]); var fzvgiz_5 = new Uint16Array(fzvgiz); var fzvgiz_6 = new Int32Array(fzvgiz); var fzvgiz_7 = new Uint32Array(fzvgiz); fzvgiz_7[0] = -7; var fzvgiz_8 = new Uint16Array(fzvgiz); fzvgiz_8[0] = -21; for (var v of t1) { try { h1 + ''; } catch(e0) { } try { v1 = Object.prototype.isPrototypeOf.call(h2, m0); } catch(e1) { } try { a2 = arguments; } catch(e2) { } h2.defineProperty = f0; }f0(g2.b1);fzvgiz_4;([[]]);/\\3(?=[^\u09fd-\\u8142])+^/yi;s1 + '';this.v1 = (f1 instanceof m1);v2 = this.a0.length;s0 + '';");
/*fuzzSeed-169986037*/count=247; tryItOut("/*RXUB*/var r = /[\u1cf6-\ucdc1-\ua0ec\\r]/gyim; var s = \"\\ua769\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=248; tryItOut("\"use strict\"; g2.s0 += s1;");
/*fuzzSeed-169986037*/count=249; tryItOut("\"use strict\"; \"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return Math.sign(( - mathy0(Math.fround(( - Math.fround(Math.fround(Math.sqrt(Math.fround(Number.MIN_VALUE)))))), mathy0(mathy1(((Math.fround(y) ^ Math.fround(y)) - Math.fround(y)), y), Math.fround((Math.fround(x) - (x >>> 0))))))); }); testMathyFunction(mathy2, ['\\0', ({valueOf:function(){return '0';}}), undefined, null, (new Number(-0)), (function(){return 0;}), ({toString:function(){return '0';}}), [], (new Boolean(true)), '0', 1, '', true, [0], 0.1, 0, (new Boolean(false)), NaN, (new String('')), '/0/', -0, false, ({valueOf:function(){return 0;}}), /0/, objectEmulatingUndefined(), (new Number(0))]); ");
/*fuzzSeed-169986037*/count=250; tryItOut("\"use strict\"; for (var p in v0) { o2.s2 += 'x'; }");
/*fuzzSeed-169986037*/count=251; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: mathy5}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [2**53+2, -(2**53), -Number.MAX_VALUE, 1, 2**53-2, 1/0, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, 0, -0x100000000, Number.MAX_VALUE, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000001, 0/0, -0x080000001, 0x080000001, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 0x100000000, -0, 0x07fffffff, -0x07fffffff, 0x100000001, -1/0, 0x080000000, 42, Math.PI, -(2**53-2), 2**53, -0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=252; tryItOut("do yield; while((this) && 0);");
/*fuzzSeed-169986037*/count=253; tryItOut("let(d) { throw StopIteration;}");
/*fuzzSeed-169986037*/count=254; tryItOut("Array.prototype.push.call(a2, o0.a1);");
/*fuzzSeed-169986037*/count=255; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (mathy2(Math.fround(( - (Math.max(((((x === -Number.MAX_SAFE_INTEGER) | 0) << (1 | 0)) | 0), Math.imul(y, ( - x))) ^ (( + ( + (( + Math.atan2(( + 0x100000001), ( + 42))) | 0))) >>> 0)))), Math.pow(( ! ( ! Math.fround(x))), (Math.asin(( + ( - ( + Math.asin(Math.tan((42 | 0))))))) >>> 0))) >>> 0); }); testMathyFunction(mathy4, [[0], 0.1, ({valueOf:function(){return 0;}}), '\\0', ({valueOf:function(){return '0';}}), [], undefined, false, (new Number(-0)), '0', null, true, (function(){return 0;}), /0/, ({toString:function(){return '0';}}), NaN, -0, 1, (new Number(0)), (new Boolean(true)), (new Boolean(false)), '/0/', 0, '', (new String('')), objectEmulatingUndefined()]); ");
/*fuzzSeed-169986037*/count=256; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.min(((Math.asinh(((Math.max(( + x), ((( + y) > ( + ((y | 0) ? (y | 0) : 2**53-2))) | 0)) | 0) >>> 0)) | 0) >>> 0), (Math.exp((Math.trunc(x) ** Math.acosh(( + (((((( - ( + y)) | 0) | 0) >>> ( + 0/0)) | 0) | 0))))) | 0)); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, 1, -1/0, 0x100000000, -0x100000000, -(2**53+2), 1/0, -0x080000000, 0x07fffffff, Number.MIN_VALUE, -Number.MAX_VALUE, -0x0ffffffff, -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, -Number.MIN_VALUE, 0, 0x080000001, -(2**53-2), -0, 0x0ffffffff, 42, 0/0, 2**53-2, 2**53+2, Math.PI, 0x100000001, 2**53, 0x080000000, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=257; tryItOut("s1 += s2;\n\u0009for (var v of this.g0.h2) { try { v0 = o2.t1.byteOffset; } catch(e0) { } try { g1.v2 = evaluate(\";\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: \"\\uD649\", noScriptRval: false, sourceIsLazy: (x % 22 == 6), catchTermination: false })); } catch(e1) { } /*MXX2*/g1.g1.RegExp.$+ = b0; }\n");
/*fuzzSeed-169986037*/count=258; tryItOut("\"use strict\"; this.a1[g1.v2] = e2;");
/*fuzzSeed-169986037*/count=259; tryItOut("\"use asm\"; mathy2 = (function(x, y) { return ( ~ ( ~ ((( + (( + -0x100000000) << x)) << ( + ( ~ y))) | 0))); }); testMathyFunction(mathy2, [/0/, (new Number(-0)), undefined, -0, 0.1, 1, [0], (function(){return 0;}), '\\0', ({valueOf:function(){return '0';}}), (new Boolean(true)), (new Number(0)), 0, ({toString:function(){return '0';}}), '/0/', true, null, objectEmulatingUndefined(), false, (new Boolean(false)), ({valueOf:function(){return 0;}}), (new String('')), '', NaN, [], '0']); ");
/*fuzzSeed-169986037*/count=260; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(f2, e0);");
/*fuzzSeed-169986037*/count=261; tryItOut("with({}) { let(y, d = (/*RXUE*/new RegExp(\"\\\\3[^]*{32769,32772}\", \"gyim\").exec(\"0\\n0_\\n\\n0\\n0_\\n\\n0\\n0_\\n\\n0\\n0_\\n\\n0\\n0_\\n\\n0\\n0_\\n\\n0\\n0_\\n\\n0\\n0_\\n\\n0\\n0_\\n\\n0\\n\")), w, x, window, b = (makeFinalizeObserver('nursery'))) { x.message;} } return (4277);");
/*fuzzSeed-169986037*/count=262; tryItOut("\"use strict\"; t1 + '';");
/*fuzzSeed-169986037*/count=263; tryItOut("\"use asm\"; t2 = new Uint32Array(o0.o0.a1);\n/* no regression tests found */\n");
/*fuzzSeed-169986037*/count=264; tryItOut("\"use strict\"; \"use asm\"; a1.shift(f2, p2, f2);");
/*fuzzSeed-169986037*/count=265; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.acos((((y & (Math.fround(Math.hypot((Math.fround(Math.hypot(x, Math.fround(1.7976931348623157e308))) + x), ( + ((x >>> 0) < ( + mathy1((( + Math.cosh(y)) >>> 0), ( + x))))))) >>> 0)) % (Math.atan2(Math.pow(Math.acosh(( ~ y)), Math.pow(( ! -0x080000001), y)), (( + (( + (( ! (Math.hypot((y >>> 0), (x | 0)) | 0)) | 0)) ? ( + -Number.MAX_VALUE) : (mathy1(y, y) >>> (mathy1(( + x), (y >>> 0)) >>> 0)))) | 0)) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [-0x0ffffffff, 1.7976931348623157e308, 2**53+2, -0, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, 0x07fffffff, -1/0, 1/0, Number.MAX_VALUE, 0x100000000, -Number.MIN_SAFE_INTEGER, 1, 42, 0, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, -0x100000000, Math.PI, -0x07fffffff, 0.000000000000001, 0x100000001, -(2**53+2), Number.MIN_VALUE, 2**53, -(2**53-2), -Number.MIN_VALUE, 2**53-2, 0x080000000, 0/0]); ");
/*fuzzSeed-169986037*/count=266; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0((Math.pow(( + Math.round(( + ( ! Math.fround(x))))), mathy0(( + (( + y) * ( + y))), ((((-0x100000001 | 0) / (x | 0)) | 0) & x))) >>> 0), Math.fround(Math.imul(Math.fround((((((Math.asin(x) >>> 0) !== (Math.exp(Math.fround(x)) >>> 0)) >>> 0) | 0) != ( + (( + x) & Math.trunc(y))))), (Math.atan((Math.fround((Math.fround(Math.fround(Math.log(Math.fround(-Number.MIN_SAFE_INTEGER)))) ? ( ! -0x0ffffffff) : Math.fround(Math.fround(y)))) ** Math.fround(Math.tan(Math.fround(Math.fround(( ~ Math.fround(y)))))))) | 0)))); }); testMathyFunction(mathy1, [0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53), 2**53-2, 2**53+2, -0, 0x100000001, -0x07fffffff, 0.000000000000001, 0/0, -1/0, 0, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), 0x07fffffff, Math.PI, Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_VALUE, -0x100000000, -0x080000001, 1, 1.7976931348623157e308, Number.MAX_VALUE, 0x100000000, 42, -(2**53+2), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 0x080000000, -Number.MIN_VALUE, 2**53]); ");
/*fuzzSeed-169986037*/count=267; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(( ! (( + (((( + ((( + (x >>> 0)) >>> 0) ? Math.imul(Math.log2(y), -1/0) : ( ! x))) | 0) & (y >= Math.fround(( + Math.fround(x))))) | 0)) | 0))); }); testMathyFunction(mathy2, [0.000000000000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, -1/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -(2**53+2), 0x100000000, 1/0, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, 1.7976931348623157e308, -0x100000000, -Number.MIN_VALUE, 42, 0/0, 2**53-2, Number.MIN_VALUE, -0x07fffffff, 0x100000001, 2**53, 1, -(2**53), 0x080000001, -0x080000001, -0, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=268; tryItOut("v2 = evaluate(\"function f0(o2)  { for (var p in g0.a0) { try { t0 = t1.subarray(v1); } catch(e0) { } try { Array.prototype.unshift.apply(a0, [a1, i2, o2]); } catch(e1) { } o0.v1 = (i0 instanceof s2); } } \", ({ global: o1.g2.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: (x % 5 != 4) }));");
/*fuzzSeed-169986037*/count=269; tryItOut("h1.getPropertyDescriptor = this.f0;function eval(x, x) { return new Array.prototype.values(12.prototype,  /x/g ) } m2 = new Map;( \"\" );");
/*fuzzSeed-169986037*/count=270; tryItOut("\"use asm\"; /*hhh*/function oaxrbo(){i2.send(b1);}/*iii*/(\"\\u203D\");let w =  '' ;");
/*fuzzSeed-169986037*/count=271; tryItOut("/*RXUB*/var r = /\\1{4,7}/gm; var s = \"\\uc64a\\na\\n\\n\\n\\n\\n\"; print(s.split(r)); ");
/*fuzzSeed-169986037*/count=272; tryItOut("h0.delete = f0;function \u3056(x, a) { yield this } i1.next();");
/*fuzzSeed-169986037*/count=273; tryItOut("\"use strict\"; v0 = 4.2;");
/*fuzzSeed-169986037*/count=274; tryItOut("/*infloop*/for(var {x: [{c: {w: [, [, , []], y, ]}, c: x, eval: {d: [, []], w, z: {d, \u3056}, y: z}}, [, (NaN), ], NaN, , [], , , SharedArrayBuffer]} = intern((Math.atanh(-21))); (Math.pow(c = Proxy.createFunction(({/*TOODEEP*/})(window), Uint8Array) <= eval(\"print(x);\"), -0.895)); x) {v0 = Array.prototype.reduce, reduceRight.call(a0, (function() { try { s0 += s0; } catch(e0) { } print(uneval(h0)); return s0; }));e2.has(e0); }");
/*fuzzSeed-169986037*/count=275; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[x, new String('q'), x, 1, new Number(1.5), new String('q'), x, x, new Number(1.5), new Number(1.5), new Number(1.5), 1, 1, true, 1, x, 1, true, x, true, 1, 1, new Number(1.5), x, new String('q'), true, 1, 1, true, x, new Number(1.5), true, new Number(1.5), true, new String('q'), new String('q'), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, true, 1, new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), true, 1, x, new Number(1.5), 1]) { i1 = a1.iterator; }");
/*fuzzSeed-169986037*/count=276; tryItOut("/*RXUB*/var r = /\u00e3(?=[\u993e-\\uA46F\\n])/im; var s = \"\\u00e3\\n\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=277; tryItOut("/*RXUB*/var r = new RegExp(\"(?!^+)+?\", \"gm\"); var s = \"\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-169986037*/count=278; tryItOut("\"use strict\"; testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x080000000, Math.PI, Number.MIN_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1/0, 2**53-2, -(2**53+2), 0.000000000000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -1/0, -0x080000001, -0x100000001, 0x100000000, 2**53, 0x0ffffffff, -0, 42, 0, -0x07fffffff, -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE, 0/0, 0x07fffffff, -0x100000000, 1, 0x080000001, -(2**53)]); ");
/*fuzzSeed-169986037*/count=279; tryItOut("\"use asm\"; mathy1 = (function(x, y) { \"use strict\"; return ( ~ ((((mathy0((y >>> 0), (((y ? y : x) >>> 0) >>> 0)) >>> 0) | 0) - (((mathy0(mathy0(Math.fround(x), y), (Math.log10(Math.min(Math.atan2(0x080000001, x), x)) >>> 0)) < (y | 0)) | 0) | 0)) | 0)); }); testMathyFunction(mathy1, [-0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x080000001, -0x100000000, 0, 0x100000000, 0/0, 42, 0x080000000, -0x100000001, -0x080000001, -(2**53-2), 1/0, Number.MIN_VALUE, -1/0, Math.PI, 0.000000000000001, Number.MAX_VALUE, 2**53-2, -Number.MAX_VALUE, -(2**53+2), -0, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -(2**53), -0x0ffffffff, -Number.MIN_VALUE, 2**53, 0x0ffffffff, 1, 0x100000001]); ");
/*fuzzSeed-169986037*/count=280; tryItOut("var shclut = new SharedArrayBuffer(8); var shclut_0 = new Uint32Array(shclut); print(shclut_0[0]); shclut_0[0] = 7; var shclut_1 = new Float64Array(shclut); print(shclut_1[0]); shclut_1[0] = -10; /*RXUB*/var r = /(([^])([^\\w\\cD-\\xe0\u00af]{4,})|\\b|[^\\s\\0\\s\u00fe]|^.|\\S?+)(?=\\2\\D\\cX*){255,}|\\D*?/ym; var s = \"\"; print(r.exec(s)); print(uneval(g1));g2.offThreadCompileScript(\"g0.s1.toString = (function mcc_() { var alcsax = 0; return function() { ++alcsax; g0.f0(/*ICCD*/alcsax % 4 == 3);};})();\");");
/*fuzzSeed-169986037*/count=281; tryItOut("v0 = Object.prototype.isPrototypeOf.call(h0, g0);");
/*fuzzSeed-169986037*/count=282; tryItOut("\"use strict\"; t1.set(t2, 12);");
/*fuzzSeed-169986037*/count=283; tryItOut("mathy5 = (function(x, y) { return Math.fround(( ! Math.fround(Math.acos(Math.pow(x, (mathy4(Math.fround((( + Math.log(Math.min(y, 0x080000001))) ** Math.fround(y))), ((( + (Math.fround(x) >= (y | 0))) >>> ( + y)) | 0)) >>> 0)))))); }); testMathyFunction(mathy5, [(new Number(0)), ({toString:function(){return '0';}}), 0, ({valueOf:function(){return 0;}}), (function(){return 0;}), '', true, [], (new String('')), NaN, (new Number(-0)), ({valueOf:function(){return '0';}}), 0.1, false, 1, objectEmulatingUndefined(), (new Boolean(false)), -0, /0/, '0', null, '/0/', (new Boolean(true)), '\\0', undefined, [0]]); ");
/*fuzzSeed-169986037*/count=284; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=285; tryItOut("\"use strict\"; for (var v of f2) { try { m1.get((4277) >>= Math.min(x, x)); } catch(e0) { } try { for (var v of f0) { f2(f1); } } catch(e1) { } o2 + g1.e0; }");
/*fuzzSeed-169986037*/count=286; tryItOut("mathy1 = (function(x, y) { return (mathy0((((mathy0((Math.imul(x, (( + Math.asinh(( + 0x080000000))) ? y : x)) | 0), y) >>> 0) ? ((( - Math.atanh(( ~ mathy0((x >= (y | 0)), Math.fround(x))))) | 0) >>> 0) : (( ~ ((x >>> 0) & (( ! x) >>> 0))) >>> 0)) >>> 0), Math.imul(Math.asinh(( - Math.sinh(Math.pow(x, ( + 42))))), ( + ( + x)))) | 0); }); testMathyFunction(mathy1, [-0x100000000, -(2**53-2), -Number.MIN_VALUE, Math.PI, Number.MIN_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, -0, 1.7976931348623157e308, -Number.MAX_VALUE, 0/0, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, -0x080000000, 0x0ffffffff, 0x07fffffff, 2**53-2, 0, 1, Number.MAX_VALUE, -0x080000001, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, -0x0ffffffff, 0x100000001, 2**53, 0.000000000000001, 42, -1/0, 1/0]); ");
/*fuzzSeed-169986037*/count=287; tryItOut("mathy0 = (function(x, y) { return Math.tan(Math.min(Math.atan(Math.log1p((Math.log10((x | 0)) | 0))), ( + Math.atan(( + ( + Math.min((Math.ceil((Math.trunc(( + (y < Math.fround(y)))) >>> 0)) | 0), (0x080000000 | 0)))))))); }); testMathyFunction(mathy0, [-Number.MAX_VALUE, Number.MIN_VALUE, -0x07fffffff, 0x07fffffff, -0, 0x080000000, -(2**53-2), 0.000000000000001, 1, 1.7976931348623157e308, -0x080000001, -Number.MIN_VALUE, -0x0ffffffff, Math.PI, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000001, 42, 2**53, -0x080000000, Number.MAX_SAFE_INTEGER, 0x100000000, 0x100000001, 0/0, -0x100000000, -(2**53+2), 0x080000001, 2**53+2, 0, 1/0, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -1/0, -(2**53)]); ");
/*fuzzSeed-169986037*/count=288; tryItOut("print(x);");
/*fuzzSeed-169986037*/count=289; tryItOut("testMathyFunction(mathy2, [0.000000000000001, 1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), Math.PI, Number.MAX_SAFE_INTEGER, 0x100000001, -1/0, -0x080000000, -0x0ffffffff, 0x100000000, 42, 2**53-2, -0x080000001, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -0, 0/0, -0x07fffffff, 2**53, 0x07fffffff, 2**53+2, 0x080000001, 0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 1, 0, -Number.MAX_VALUE, Number.MIN_VALUE, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=290; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return ( + (Math.max(( + ((Math.imul((x | 0), Math.round(2**53-2)) ^ ((42 / 2**53-2) | 0)) && (Math.asin(Math.max((x >>> 0), Math.atan2(Math.fround(x), y))) != -0x100000001))), ( - Math.fround((-1/0 ? 1/0 : (1/0 | 0))))) >>> 0)); }); testMathyFunction(mathy0, [-0x100000001, 0, -0x0ffffffff, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, 42, 0x07fffffff, 2**53, -0x080000001, 0x100000001, -(2**53), 0x100000000, Math.PI, -(2**53+2), -Number.MAX_VALUE, -(2**53-2), Number.MIN_VALUE, Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, -0x100000000, 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, -1/0, 0x0ffffffff, -0, 1.7976931348623157e308, -0x080000000]); ");
/*fuzzSeed-169986037*/count=291; tryItOut("mathy4 = (function(x, y) { return (( ! Math.atan2(( - Math.tan(( + ( ~ y)))), Math.hypot(Math.fround(Math.imul(Math.atan2(y, Math.fround((x ? y : Math.fround(x)))), (( - Math.fround(mathy1(0x100000001, Math.fround(x)))) | 0))), Math.hypot(0x07fffffff, -0x080000000)))) | 0); }); ");
/*fuzzSeed-169986037*/count=292; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s0; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=293; tryItOut("/*MXX3*/g2.URIError.name = g0.URIError.name;");
/*fuzzSeed-169986037*/count=294; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=295; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?!^{2}|.*\\uc723|.|\\\\b{2}))|(?=\\\\3^+?\\u00e9|(?:(?=(?!\\\\b))){4,6})^\", \"yim\"); var s = \"\\n\"; print(s.match(r)); ");
/*fuzzSeed-169986037*/count=296; tryItOut("\"use strict\"; M:with({x: x}){v2 = Array.prototype.reduce, reduceRight.call(a0, String.prototype.repeat.bind(g2), g0.i2, a1); }");
/*fuzzSeed-169986037*/count=297; tryItOut("/*RXUB*/var r = new RegExp(\"(([^]))\", \"gi\"); var s = \"\\n\"; print(r.exec(s)); ");
/*fuzzSeed-169986037*/count=298; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ Math.fround(Math.trunc(Math.fround(mathy1(((x < (Math.imul(-Number.MIN_VALUE, y) >>> 0)) >>> 0), Math.round(x)))))); }); ");
/*fuzzSeed-169986037*/count=299; tryItOut("\"use strict\"; \"use asm\"; t1 = new Int16Array(o2.a2);");
/*fuzzSeed-169986037*/count=300; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=301; tryItOut("\"use strict\"; a1.pop(s1);");
/*fuzzSeed-169986037*/count=302; tryItOut("for (var v of f2) { v0 = Infinity; }");
/*fuzzSeed-169986037*/count=303; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    return (((0x7243da59)))|0;\n    return (((i2)))|0;\n  }\n  return f; })(this, {ff: (((x).apply).bind).bind(w = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: /*wrap1*/(function(){ print(\"\\u2DB0\");return Number.prototype.valueOf})(), getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: /\\3/gm, fix: function() { }, has: function() { return false; }, hasOwn: Float64Array, get: window, set: function() { return false; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: runOffThreadScript, keys: function() { throw 3; }, }; })(new RegExp(\"\\\\2\", \"gyim\")), Proxy.revocable, decodeURIComponent))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=304; tryItOut("/*oLoop*/for (let mifaec = 0; mifaec < 169; ++mifaec, (let (x, zvnpmq, sgzqcc, NaN, kbbosm, fjxuxl, xzqgoo, yxgjec, y, chmghb) window)) { throw new RegExp(\"\\\\2\", \"g\"); } ");
/*fuzzSeed-169986037*/count=305; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( + ( ! mathy0(mathy2((y >>> 0), x), (Math.expm1((x | 0)) | 0)))); }); testMathyFunction(mathy3, [-0x080000000, -0x0ffffffff, -Number.MAX_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 1/0, 0x100000000, -0, 0x07fffffff, -0x100000000, 0x100000001, 42, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000001, 0x080000000, 2**53, 0/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), 1, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 0x0ffffffff, -(2**53+2), -0x100000001, -0x07fffffff, -(2**53-2), Math.PI, 2**53+2, Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=306; tryItOut("mathy4 = (function(x, y) { return Math.imul(Math.min(( + (Math.min(( + (( + ( + mathy1(( + Math.pow(x, x)), ( + -Number.MIN_SAFE_INTEGER)))) ^ ( + x))), x) | 0)), ( + Math.max(Math.fround(mathy0(Math.round(( + (x - 1.7976931348623157e308))), Math.min((( ! (y | 0)) | 0), x))), 0.000000000000001))), Math.hypot((( + (mathy3(Math.log10(Math.fround(( + (x >>> 0)))), ( + (2**53-2 ? x : x))) >>> 0)) >>> 0), (( ~ ( + Math.imul(( + Math.pow((mathy1(x, y) | 0), x)), ( + Math.atan2(y, Math.cosh(x)))))) | 0))); }); testMathyFunction(mathy4, [Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 1, 0/0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, 0x080000000, -0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, 0, 2**53-2, -0x080000001, -(2**53+2), Math.PI, -Number.MIN_VALUE, 42, 0.000000000000001, -0x100000000, -Number.MAX_VALUE, 2**53+2, 0x080000001, -0x100000001, Number.MAX_VALUE, -1/0, -(2**53-2), -(2**53), -0x0ffffffff, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, 0x100000000, 0x100000001, -0]); ");
/*fuzzSeed-169986037*/count=307; tryItOut("\"use strict\"; this.e0 + '';");
/*fuzzSeed-169986037*/count=308; tryItOut("{ void 0; void relazifyFunctions('compartment'); } print(x);");
/*fuzzSeed-169986037*/count=309; tryItOut("testMathyFunction(mathy2, [-(2**53-2), -Number.MIN_SAFE_INTEGER, 1/0, -0x100000001, Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, 0, -0x080000000, Number.MAX_VALUE, 0x100000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53), -1/0, 0x100000000, -0x0ffffffff, 2**53+2, -Number.MAX_VALUE, 42, 0.000000000000001, -0x07fffffff, 0x07fffffff, 0x080000000, -0, 2**53, Number.MIN_VALUE, 1.7976931348623157e308, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, Math.PI, 0x080000001, -0x100000000, -0x080000001]); ");
/*fuzzSeed-169986037*/count=310; tryItOut("i0.send(h1);function x(x, x, x =  '' , x, x, a = ((makeFinalizeObserver('nursery')) >>>= z = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function() { throw 3; }, getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: undefined, fix: function() { throw 3; }, has: function() { throw 3; }, hasOwn: /*wrap2*/(function(){ var uravjf = x; var qfzdod = Float32Array; return qfzdod;})(), get: function() { throw 3; }, set: undefined, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( '' ), (4277))), window, x, b, {}, eval, x, x, w, y, z, window, x, w, \u3056 = {}, x) { v0 = Object.prototype.isPrototypeOf.call(v1, e2); } a1.reverse();");
/*fuzzSeed-169986037*/count=311; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -8192.0;\n    var i3 = 0;\n    return (((/*FFI*/ff(((-1.5111572745182865e+23)), ((d1)))|0)))|0;\n  }\n  return f; })(this, {ff: mathy3}, new ArrayBuffer(4096)); testMathyFunction(mathy5, /*MARR*/[arguments.callee, undefined, 0xB504F332,  \"use strict\" ,  \"use strict\" , arguments.callee, [],  \"use strict\" , 0xB504F332, undefined, [], [], undefined, undefined, 0xB504F332, [], [], [], [], arguments.callee, [], [], 0xB504F332,  \"use strict\" , undefined, arguments.callee, arguments.callee, [],  \"use strict\" , arguments.callee,  \"use strict\" , arguments.callee, undefined, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, 0xB504F332, arguments.callee, undefined, [], 0xB504F332,  \"use strict\" , [], undefined, undefined, 0xB504F332, 0xB504F332, [], undefined, arguments.callee, 0xB504F332, [], 0xB504F332, undefined, undefined]); ");
/*fuzzSeed-169986037*/count=312; tryItOut("/*RXUB*/var r = r2; var s = \"\\u0005\\u0005\\u0005\\u0005\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=313; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.fround(((Math.fround(Math.hypot(Math.fround((Math.atan2((((x ? y : (x >>> 0)) >>> 0) >>> 0), (( - Math.hypot((y >>> 0), (Math.sinh(x) | 0))) >>> 0)) >>> 0)), Math.fround(Math.tanh(0x100000000)))) | 0) ? mathy0(Math.fround(((( - mathy1(Math.exp(-0x080000001), (Math.atan2(x, x) >>> 0))) >>> 0) == (-0x0ffffffff >>> 0))), (( - ((Math.fround((Math.fround(y) % Math.fround(x))) ? ( + mathy1(y, (( + Math.tan(( + -Number.MIN_VALUE))) | 0))) : (Math.sin((Math.fround(( ~ Math.fround((Math.max((x | 0), x) >>> 0)))) >>> 0)) >>> 0)) >>> 0)) >>> 0)) : Math.fround(( + Math.pow((Math.fround(Math.log1p(((Number.MAX_VALUE % -0x07fffffff) >>> 0))) >>> 0), ( + (Math.max((( ! (Math.tan((x >>> 0)) >>> 0)) | 0), Math.PI) | 0))))))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1.5), new Number(1.5), (-1/0), (-1/0)]); ");
/*fuzzSeed-169986037*/count=314; tryItOut("\"use strict\"; let (y) { x = b1; }");
/*fuzzSeed-169986037*/count=315; tryItOut("\"use strict\"; /*bLoop*/for (var dnhqly = 0, x = x & eval; dnhqly < 11; ++dnhqly) { if (dnhqly % 8 == 4) { /*hhh*/function wrmksn(){(\"\\uA403\");}/*iii*/\"\\uF0FC\"; } else { m2.delete(-4); }  } ");
/*fuzzSeed-169986037*/count=316; tryItOut("m2 = new Map;");
/*fuzzSeed-169986037*/count=317; tryItOut("o1.v0 = evalcx(\"/* no regression tests found */\", g2);");
/*fuzzSeed-169986037*/count=318; tryItOut("(delete c.x);");
/*fuzzSeed-169986037*/count=319; tryItOut("mathy3 = (function(x, y) { return Math.pow(mathy1(( + (( ~ (x % 42)) | 0)), Math.pow((((Math.imul((y >= y), Math.fround(Math.log2(0/0))) | 0) ^ (Math.fround(Math.min(Math.fround(x), Math.fround(y))) | 0)) | 0), Math.acos(Math.fround(Math.cosh((x | 0)))))), ((Math.asinh(Math.fround(Math.acos(Math.fround((Number.MIN_VALUE !== 42))))) | 0) ? ( + Math.cosh(((Math.atan((y | 0)) | 0) << (mathy2((x >>> 0), (y >>> 0)) >>> 0)))) : (Math.acos(Number.MAX_SAFE_INTEGER) | 0))); }); testMathyFunction(mathy3, [-1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 1, 0.000000000000001, 0x07fffffff, 42, -0x100000000, Number.MIN_VALUE, 0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -0x080000001, 0x100000000, 1.7976931348623157e308, Math.PI, -0, -0x080000000, -(2**53-2), -0x07fffffff, -0x100000001, -Number.MIN_VALUE, 2**53-2, 1/0, -0x0ffffffff, 0/0, -(2**53+2), 0x0ffffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53), 0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, 0x080000000]); ");
/*fuzzSeed-169986037*/count=320; tryItOut("i0.next();");
/*fuzzSeed-169986037*/count=321; tryItOut("/*bLoop*/for (let boryoh = 0; boryoh < 8; ++boryoh) { if (boryoh % 5 == 2) { (((p={}, (p.z =  '' )()))); } else { i0.next(); }  } ");
/*fuzzSeed-169986037*/count=322; tryItOut("\"use strict\"; s1 += g0.o0.s0;var r0 = 6 + x; var r1 = r0 / r0; var r2 = r0 & x; var r3 = x ^ 4; var r4 = r3 - r2; var r5 = 8 + r2; r5 = r5 % r0; var r6 = r4 + r4; r6 = 1 % x; var r7 = 4 + 6; var r8 = r1 | r0; var r9 = r0 ^ r3; var r10 = r3 & r5; r2 = r8 & r6; r4 = r7 / r10; var r11 = 7 % r8; var r12 = r6 + 8; var r13 = r4 + r5; var r14 = r0 + r2; var r15 = r4 | r1; var r16 = r2 & 3; var r17 = r8 + 6; var r18 = 2 - 6; var r19 = r1 + r11; var r20 = r2 ^ 3; var r21 = r10 ^ 0; r1 = r12 / 1; r18 = 4 ^ 3; var r22 = r12 & r13; var r23 = r15 % 8; var r24 = r22 & r8; var r25 = r10 ^ r21; var r26 = 1 - r6; r3 = r26 ^ 4; var r27 = r18 & r19; var r28 = 8 * r18; var r29 = 6 - r6; var r30 = r19 * 2; var r31 = r7 ^ r15; var r32 = r12 ^ 1; var r33 = r1 + 2; r15 = r13 % r22; var r34 = r1 ^ r7; var r35 = r5 & r25; var r36 = 7 + 0; r26 = r36 - r23; var r37 = 2 - r9; var r38 = x % r16; var r39 = 5 & 2; r36 = 6 - 1; ");
/*fuzzSeed-169986037*/count=323; tryItOut("\"use strict\"; print([,]);");
/*fuzzSeed-169986037*/count=324; tryItOut("\"use asm\"; t2.toSource = (function() { m2.set(f2, f2); return e1; });");
/*fuzzSeed-169986037*/count=325; tryItOut("\"use strict\"; testMathyFunction(mathy1, [0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, 42, 2**53-2, -Number.MAX_VALUE, 0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, 1/0, -Number.MAX_SAFE_INTEGER, -0, -(2**53), -0x100000001, -0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0x100000001, 2**53, -(2**53-2), -0x0ffffffff, -1/0, 0, 2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 0x0ffffffff, -0x080000001, Math.PI, 0.000000000000001, 1, 0x080000001, 0x080000000, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=326; tryItOut("s2 += s2;");
/*fuzzSeed-169986037*/count=327; tryItOut("for (var p in s2) { try { v2 = Object.prototype.isPrototypeOf.call(f1, v1); } catch(e0) { } try { Array.prototype.push.call(a2, o1, h2, s0); } catch(e1) { } a1.forEach((function(j) { f2(j); }), t2, -24, m0); }");
/*fuzzSeed-169986037*/count=328; tryItOut("\"use strict\"; /*vLoop*/for (let yfnodg = 0; yfnodg < 139; ++yfnodg) { a = yfnodg; s0 += s0;\nprint(a);\n } ");
/*fuzzSeed-169986037*/count=329; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( ~ (Math.log10((( + ((-Number.MAX_SAFE_INTEGER % Math.hypot(x, y)) >>> 0)) % ( + Math.fround(Math.cbrt(( + -Number.MAX_SAFE_INTEGER)))))) | 0)) | 0); }); testMathyFunction(mathy1, [0x080000001, 1, 0.000000000000001, Math.PI, 1/0, 0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0/0, 0x100000000, 0, -0x0ffffffff, -Number.MIN_VALUE, -0, 0x100000001, -(2**53+2), -0x07fffffff, 2**53+2, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, Number.MIN_VALUE, 2**53, -0x100000000, 0x0ffffffff, -1/0, -(2**53), -Number.MAX_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53-2, -0x080000000, -0x080000001]); ");
/*fuzzSeed-169986037*/count=330; tryItOut("/*RXUB*/var r = r1; var s = \"\\n0\\n0\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=331; tryItOut("\"use strict\"; mathy5 = (function(x, y) { \"use strict\"; return Math.atan(Math.expm1(Math.atan(Math.fround((mathy3(2**53-2, y) >>> 0))))); }); testMathyFunction(mathy5, [-0x100000000, -0x07fffffff, Number.MIN_VALUE, 0x0ffffffff, -1/0, 2**53, -0x0ffffffff, -0, 0x080000001, 0x07fffffff, Number.MAX_VALUE, 0x080000000, -(2**53), -0x080000001, 0.000000000000001, 0x100000001, 1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000000, 0, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), 2**53+2, 1, 42, -(2**53-2), Math.PI, -0x100000001]); ");
/*fuzzSeed-169986037*/count=332; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = ((0x9401181f) > (0xb42f783f));\n    d1 = (d1);\n    d1 = (-576460752303423500.0);\n    d1 = (d1);\n    return +((Float32ArrayView[((0xfa164925)-(i0)) >> 2]));\n  }\n  return f; })(this, {ff: SharedArrayBuffer.prototype.slice}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x080000001, -0, -(2**53), -(2**53+2), -0x100000001, -Number.MAX_VALUE, 0x100000001, 0, 0.000000000000001, 2**53, Number.MIN_VALUE, 42, -0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x100000000, -(2**53-2), 0x0ffffffff, Math.PI, 2**53+2, -0x07fffffff, -0x080000000, 0/0, Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, -1/0, -0x0ffffffff, 1, 2**53-2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=333; tryItOut("M:for(let d =  \"\"  in []) {Array.prototype.pop.call(a2, f0, b2); }");
/*fuzzSeed-169986037*/count=334; tryItOut("mathy1 = (function(x, y) { return Math.min((( ! (( ! (((x === y) ? x : (42 >>> 0)) | 0)) | 0)) | 0), ( ! ( + (((Math.sign(( - ( + x))) >>> 0) >> ((Math.max(Math.cos(x), (x >>> 0)) >>> 0) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x07fffffff, -Number.MAX_VALUE, Math.PI, 0.000000000000001, -Number.MIN_VALUE, -0x100000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, 42, 1/0, 0x0ffffffff, 0x100000000, -0x080000000, -(2**53), -(2**53+2), 0, -0x100000001, 2**53-2, -0x080000001, 1, -0, 0x080000001, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0x100000001, Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 2**53, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=335; tryItOut("/*RXUB*/var r = \"\\u66A5\"; var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=336; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((Math.fround(Math.atan2(Math.max(((( - (y >>> 0)) >>> 0) >>> 0), (( + ( ~ ( + y))) >>> 0)), y)) / (Math.fround(Math.tanh((mathy0(( + ( - ( + Math.log(( + 0x0ffffffff))))), (y | 0)) | 0))) >>> 0)) % ( + Math.fround(( ~ Math.sqrt(((x >>> 0) ^ (y >>> 0))))))) >>> 0); }); testMathyFunction(mathy1, [-0x100000001, -1/0, 1, 0/0, Number.MAX_VALUE, 0x080000001, 42, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53), 2**53+2, -(2**53-2), 0x100000001, 0, 2**53, -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, -0x080000000, -0x100000000, -Number.MAX_VALUE, -0, 0x07fffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53-2, 1/0, -0x080000001, -(2**53+2), 0x100000000, 0x0ffffffff, 0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=337; tryItOut("mathy3 = (function(x, y) { return Math.ceil(Math.fround(Math.imul(Math.fround(mathy0(Math.fround(Math.min(Math.fround((y > y)), Math.fround(x))), Math.fround(( ~ ( + ( ! (0x100000001 >>> 0))))))), mathy1((y << Number.MAX_VALUE), Math.fround((Math.fround(((y >>> 0) * (Math.log2(-0x100000001) | 0))) - Math.fround(0x100000001))))))); }); ");
/*fuzzSeed-169986037*/count=338; tryItOut("mathy1 = (function(x, y) { return Math.fround((mathy0(Math.fround(( + Math.fround((x ? (x >= (Math.max(-Number.MAX_VALUE, (x | 0)) | 0)) : x)))), Math.sinh(((y / x) | 0))) - (Math.atan(((Math.cbrt(( + x)) | 0) | 0)) / (mathy0(Math.min((-(2**53+2) >>> 0), x), (( + y) >>> 0)) >>> 0)))); }); testMathyFunction(mathy1, [1.7976931348623157e308, -Number.MAX_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, -1/0, -(2**53), 0x07fffffff, 2**53+2, 0x100000001, -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, 0x100000000, -0, 2**53-2, 42, 0x080000000, -Number.MIN_VALUE, -(2**53-2), -(2**53+2), Number.MIN_VALUE, -0x080000000, -0x100000000, Math.PI, -0x100000001, -0x0ffffffff, 0.000000000000001, 1/0, -0x080000001, Number.MAX_VALUE, 0/0, 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1]); ");
/*fuzzSeed-169986037*/count=339; tryItOut("mathy1 = (function(x, y) { return Math.log(((Math.imul((mathy0(( + (( - (( - 0x100000000) >>> 0)) >>> 0)), Math.fround(Math.min(( + x), Math.fround(Number.MIN_VALUE)))) >>> 0), ((Math.abs(Math.fround(( + ( ! Math.pow(x, (x >>> 0)))))) ^ (((Math.sign(Math.atan2(Number.MIN_SAFE_INTEGER, (y | 0))) ** ( + ( - ( + 0x080000000)))) >>> Math.fround(-0x080000001)) >>> 0)) >>> 0)) >>> 0) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=340; tryItOut("v2 = t0.BYTES_PER_ELEMENT;");
/*fuzzSeed-169986037*/count=341; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ( + (Math.max((Math.fround(Math.max(Math.fround(Math.fround(Math.hypot(-Number.MAX_VALUE, Math.fround(Math.imul((0 >>> 0), Number.MIN_SAFE_INTEGER))))), Math.fround((Math.log10(Math.fround(x)) >>> 0)))) | 0), ((( + Math.ceil((((x | 0) % (Math.cos(x) >>> 0)) | 0))) < Math.fround((( + Math.atanh(( + (x || y)))) << y))) | 0)) | 0)); }); testMathyFunction(mathy0, [0x080000000, 0.000000000000001, -0x080000000, -(2**53-2), 2**53+2, 0x100000001, 1.7976931348623157e308, -(2**53), 1, 2**53-2, 0, -Number.MIN_VALUE, -0, -Number.MAX_SAFE_INTEGER, 0x100000000, 0/0, Number.MAX_VALUE, -0x080000001, Math.PI, 0x0ffffffff, -0x100000001, -0x100000000, Number.MIN_VALUE, 42, -1/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 2**53, 0x07fffffff]); ");
/*fuzzSeed-169986037*/count=342; tryItOut("mathy0 = (function(x, y) { return (Math.fround(Math.round(Math.fround(( - (((x & ( + (( + Math.fround(Math.fround((Math.min((Number.MAX_SAFE_INTEGER | 0), (y | 0)) | 0)))) << ( + -0)))) | 0) >>> 0))))) == (( ~ Math.fround(Math.min(( + Math.asinh(( + y))), Math.clz32(y)))) >>> 0)); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, 0/0, 42, 1.7976931348623157e308, 0x100000001, 1/0, -0x100000001, -(2**53-2), -0, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000000, Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, -1/0, 2**53+2, 0x080000001, -0x07fffffff, Math.PI, -0x100000000, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53-2, -(2**53), 0, 1, -0x080000001, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=343; tryItOut("var wxixie = new SharedArrayBuffer(2); var wxixie_0 = new Uint16Array(wxixie); print(wxixie_0[0]); print(({prototype: ((new Function(\"v2 = (this.g1 instanceof g0.e0);\"))(/\\3*/gym)) }));o0.toSource = (function(j) { g1.f2(j); });v2 = Array.prototype.reduce, reduceRight.apply(a1, [(function() { try { ; } catch(e0) { } try { /*MXX1*/o1 = g2.TypeError.length; } catch(e1) { } s2.toString = Boolean.prototype.toString; return a2; }), v0]);e2.__proto__ = a1;b = linkedList(b, 4420);cnkgwl;a1.valueOf = (function() { for (var j=0;j<77;++j) { f2(j%5==1); } });this.v1 = (o1 instanceof a0);/*ADP-1*/Object.defineProperty(a2,  /* Comment */\"\\u174F\", ({configurable: true}));");
/*fuzzSeed-169986037*/count=344; tryItOut("testMathyFunction(mathy2, [-0x100000001, 2**53+2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), 1.7976931348623157e308, 1/0, Math.PI, -0x100000000, -0, 1, 2**53, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0, -Number.MIN_VALUE, -(2**53+2), 2**53-2, 0.000000000000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 0x080000000, 42, -0x080000000, -Number.MAX_VALUE, -(2**53), 0x080000001, -0x080000001, 0/0, 0x100000000, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=345; tryItOut("mathy3 = (function(x, y) { return Math.atan2((Math.atan((mathy1((Math.ceil(( + (x | 0))) | 0), (Math.atan2(( + ((Math.fround(x) >> x) ? mathy2((x | 0), (y | 0)) : Math.pow((x >>> 0), (x >>> 0)))), x) >>> 0)) >>> 0)) >>> 0), ( + (( + ( ~ ( ! (( ! ( + x)) >>> 0)))) != ( + Math.tan(( + (x * ( + ( + Math.cosh(( + x))))))))))); }); testMathyFunction(mathy3, [0x080000000, -0x07fffffff, Math.PI, -(2**53), 0/0, 2**53-2, 1.7976931348623157e308, -Number.MAX_VALUE, 1/0, -0x080000001, 1, 2**53+2, 0x080000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000001, -Number.MIN_VALUE, -1/0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -(2**53+2), Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0, -0x0ffffffff, 2**53, 0x100000000, -0x100000001, -0x100000000]); ");
/*fuzzSeed-169986037*/count=346; tryItOut("a2.pop();");
/*fuzzSeed-169986037*/count=347; tryItOut("mathy5 = (function(x, y) { return (Math.max(Math.fround(Math.fround(Math.max(Math.fround(Math.fround(Math.log2(((Math.sinh((x | 0)) | 0) >= y)))), ((Math.cbrt(( + Math.min(Number.MIN_VALUE, x))) | 0) | (y & (x & Math.fround(Math.asinh(mathy2(x, x))))))))), ((((((Math.fround(Math.pow(( + ( + x)), (y | 0))) >>> 0) === (y >>> 0)) >>> 0) >>> 0) | (((Math.hypot(Math.fround(x), Math.fround(x)) >>> 0) || ( ~ (Math.cbrt(x) | 0))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [-Number.MIN_VALUE, 0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, -0, Math.PI, -0x080000000, -(2**53-2), 0x080000000, Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x080000001, 0, 1, 0/0, 1.7976931348623157e308, 2**53-2, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53+2, 0x100000000, 42, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000000, -1/0, -0x100000001, -0x07fffffff, -(2**53), 0.000000000000001, -0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=348; tryItOut("\"use strict\"; Array.prototype.shift.apply(a1, []);\nv2 = Object.prototype.isPrototypeOf.call(m0, s1);\n");
/*fuzzSeed-169986037*/count=349; tryItOut("{if(true) g1.h0 + ''; else  if (new RegExp(\"(?:\\\\3|(?=\\\\b)+?)\", \"yi\")) return; else a1 = Array.prototype.concat.apply(g2.a1, [a2]); }");
/*fuzzSeed-169986037*/count=350; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use asm\"; return ( ! (Math.pow(Math.fround(Math.atan2(Math.fround((Math.max(y, x) ** Math.fround(x))), Math.fround(( + ( ~ ( + Math.pow(Math.fround(x), mathy1(x, Math.fround(y))))))))), ( ~ Math.hypot(( + ( ~ Math.fround(Math.cos(Math.fround(y))))), x))) | 0)); }); ");
/*fuzzSeed-169986037*/count=351; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( ~ ( + Math.trunc((Math.imul((((y >>> 0) / (Math.fround((Math.fround(x) ? Math.fround(Math.fround(((-0x100000001 | 0) & Math.fround(x)))) : Math.fround(x))) >>> 0)) >>> 0), y) >>> 0)))); }); testMathyFunction(mathy1, [1, 2**53, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53+2), 0.000000000000001, Number.MAX_SAFE_INTEGER, -(2**53), -(2**53-2), 0x0ffffffff, -Number.MAX_VALUE, 0/0, -0x100000000, 0x080000000, 0, -0x100000001, Math.PI, 1/0, 0x100000001, 1.7976931348623157e308, 42, -0, 0x100000000, Number.MAX_VALUE, 0x080000001, 2**53+2, -1/0, Number.MIN_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=352; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((( + (Math.hypot((Math.sinh(x) | 0), (Math.max((x | 0), Math.atan2(Math.fround(y), Math.fround(y))) | 0)) | 0)) ? ( + Math.fround((Math.fround(mathy1(x, ( + ( ~ y)))) * Math.fround(Math.hypot(( ~ Math.cosh(x)), ( + y)))))) : (Math.cbrt((Math.atan2(((Math.asinh((x >>> 0)) >>> 0) >>> 0), ((Math.atan((( ! y) | 0)) >> Math.max(1/0, x)) >>> 0)) >>> 0)) | 0)) >>> 0); }); ");
/*fuzzSeed-169986037*/count=353; tryItOut("mathy3 = (function(x, y) { return ( - Math.fround(Math.hypot(mathy1((Math.atanh((mathy1(x, Number.MAX_SAFE_INTEGER) | 0)) << 2**53+2), (mathy2(x, ((((x | 0) == (x | 0)) >>> 0) !== ( + y))) | 0)), ((Math.fround(y) * ( + -Number.MAX_VALUE)) >>> 0)))); }); testMathyFunction(mathy3, [0x0ffffffff, Math.PI, 1.7976931348623157e308, -0, 2**53+2, 0, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 1, 0x080000000, -1/0, -0x0ffffffff, Number.MAX_VALUE, -0x07fffffff, -0x100000000, 0.000000000000001, -(2**53+2), -(2**53-2), Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0x100000000, -0x080000001, 0x100000001, 0/0, 0x080000001, 42, -0x100000001, -Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, 2**53-2, -0x080000000]); ");
/*fuzzSeed-169986037*/count=354; tryItOut("/*ADP-2*/Object.defineProperty(a0, 0, { configurable: false, enumerable: false, get: (function(j) { f0(j); }), set: (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -70368744177663.0;\n    var i3 = 0;\n    i3 = (i1);\n    return +((NaN));\n  }\n  return f; })(this, {ff: Number.prototype.toString}, new ArrayBuffer(4096)) });");
/*fuzzSeed-169986037*/count=355; tryItOut("t1 = new Uint8ClampedArray(7);");
/*fuzzSeed-169986037*/count=356; tryItOut("\"use strict\"; /*infloop*/L:for(({}) in ((++x)((4277)))){print((function ([y]) { })());v2 = e0[2]; }");
/*fuzzSeed-169986037*/count=357; tryItOut("\"use strict\"; /*RXUB*/var r = /\\B/gyi; var s = \"a\"; print(s.split(r)); ");
/*fuzzSeed-169986037*/count=358; tryItOut("\"use strict\"; \"use asm\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=359; tryItOut("/*RXUB*/var r = r2; var s = s2; print(s.replace(r, ((NaN) = s) || ((void options('strict_mode'))) |= ((function() { yield  /x/g ; } })()), \"yim\")); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=360; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x07fffffff, 1, -Number.MIN_VALUE, 2**53-2, -1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53), Number.MAX_VALUE, 0x100000001, Math.PI, -0x100000001, -0x07fffffff, 0x100000000, 42, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, -0x0ffffffff, 0x080000001, 0x0ffffffff, -0x080000000, 2**53+2, 0, 1.7976931348623157e308, -0, 0.000000000000001, -(2**53+2), -0x100000000, 0/0, 2**53, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=361; tryItOut("g2.offThreadCompileScript(\"v1 + '';\");");
/*fuzzSeed-169986037*/count=362; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return Math.log1p(( + (Math.round(((( - y) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy0, [0x080000000, -(2**53-2), -1/0, -0, 42, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, 1, -0x080000000, 0x07fffffff, 1/0, 0x100000001, 1.7976931348623157e308, -(2**53), -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, 2**53+2, 2**53, -0x080000001, -0x07fffffff, -(2**53+2), 0.000000000000001, 0/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 2**53-2, 0, Math.PI, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=363; tryItOut("\"use strict\"; v2 = t2.length;");
/*fuzzSeed-169986037*/count=364; tryItOut("mathy1 = (function(x, y) { return (( ! Math.fround((Math.log2((( + Math.fround(Math.log2(Math.fround((Math.fround(y) || Math.fround(x)))))) == (x | ( + y)))) ? Math.trunc((( + Math.imul(( + (x || -0x080000000)), ( + x))) >>> 0)) : mathy0((y | 0), (Math.abs(mathy0(-1/0, (Math.ceil((y >>> 0)) >>> 0))) | 0))))) !== ((mathy0((Math.acos((Math.max(-0x080000000, (x > y)) >>> 0)) >>> 0), (Math.acos(( - x)) | 0)) | 0) , Math.fround(Math.atan(Math.fround((( + x) << 0x080000001)))))); }); testMathyFunction(mathy1, [null, (function(){return 0;}), 0, '0', '/0/', (new String('')), objectEmulatingUndefined(), [0], [], ({valueOf:function(){return 0;}}), false, /0/, '', '\\0', -0, (new Number(0)), NaN, (new Number(-0)), ({valueOf:function(){return '0';}}), 0.1, undefined, (new Boolean(false)), (new Boolean(true)), ({toString:function(){return '0';}}), 1, true]); ");
/*fuzzSeed-169986037*/count=365; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return ( ! (Math.atanh((Math.trunc(Math.expm1(y)) >>> 0)) >>> 0)); }); testMathyFunction(mathy4, [Number.MIN_VALUE, 2**53-2, Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -0x080000000, 0/0, -Number.MIN_VALUE, -0x100000001, 2**53+2, -(2**53), -(2**53+2), -1/0, 1.7976931348623157e308, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, 1/0, 42, -0, 0, -0x07fffffff, 1, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x080000001, Math.PI, -0x080000001, 2**53, 0x100000000, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-169986037*/count=366; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -70368744177665.0;\n    {\n      d0 = (-576460752303423500.0);\n    }\n    i1 = ((((imul((0x93bc83b5), (i1))|0) / (imul((/*FFI*/ff(((((0x212bb380)) | ((0xf351ffd0)))))|0), (!(0xd670f283)))|0))>>>((0xfa1f549f))));\n    i1 = (((((-0x8000000)*-0xfffff))>>>((((!(0xffce490b))-(0xa25b0ef5)) >> ((/*FFI*/ff(((imul((0xb1bc6676), (0x1a7eefa8))|0)), ((-9007199254740992.0)), ((-70368744177665.0)), ((-64.0)), ((-4.0)))|0)+(-0x8000000))) / (((((0x2b2fb4f3))>>>((0xb32b76da))) % (0x6fa39cd4)) | (0x2282c*((((0xffffffff)) >> ((0xfe25c672)))))))));\n    {\n      {\n        return (((((0xfbfa44e2)) & ((((((0xa3b40e32) ? (0x4688e4fd) : (0x8312e421))-(i1)+(0xff8fdbfe)) & ((0xfd07752f)))))) / (((0x928d772c)) ^ ((Int16ArrayView[(/(?!\\W|\\u0051|[^]\\b*){4,}|(?:(^)|.?)\\b|(?=\\2)|(?:(^)+?)|[\\s\\0-\u6e74\u00db-\\0\ue674]{1,3}|(?=\\u00f2)|$\\2*/gym) >> 1])))))|0;\n      }\n    }\n    {\n      (Float64ArrayView[((0xfd8cdee2)+(0xf676cff1)+((0xa2bc5e30) ? (0xfc343661) : (!(0xfa63af3d)))) >> 3]) = ((d0));\n    }\n    i1 = ((/\\3/gyi & x));\n    return (((0xa7a667a1)))|0;\n    switch ((((+pow(((-6.044629098073146e+23)), ((-16777215.0))))) << ((0xe5e85d85)))) {\n      case -2:\n        switch (((((0xf9989275) ? (0xf817236b) : (0xfc8661c9))) ^ ((0x5d2c321e)+(i1)))) {\n          case -1:\n            d2 = (268435455.0);\n            break;\n        }\n        break;\n      default:\n        return (((0x8d3b775b) % (0xb81e61fe)))|0;\n    }\n    i1 = (0xf80e5c75);\n    return ((((((0xb628ff0d)+(0x2e945b75)) << (((d0) == (d0)))) != (((i1)+(/*FFI*/ff(((((0xace655c9)) & ((0xfd1bdf67)))))|0)-(0xffdef752)) << (((((0xfc097c9f))|0) < (((0xc3c7a715))|0))-((((0x4d9b0738))>>>((0x689b8eda))) < (((0xfd728a19))>>>((0x7e8fc816)))))))-((~(Math.min(x, -8))))+(0xffffffff)))|0;\n  }\n  return f; })(this, {ff: Object.prototype.__lookupGetter__}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-169986037*/count=367; tryItOut(";");
/*fuzzSeed-169986037*/count=368; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      (Float64ArrayView[1]) = ((-295147905179352830000.0));\n    }\n    i0 = (i1);\n    i1 = (/*FFI*/ff(((abs((imul((0xa369a244), (i1))|0))|0)), ((-2199023255553.0)), ((~((i1)+(i0)))), ((((i1)-(i1)) << ((((-0x8000000))>>>((0x95cc18f5))) % (((0xfd2f4d5a))>>>((0x91ebd5a0)))))), ((abs((((i1)) | ((~~(((-4503599627370497.0)) * ((1.5474250491067253e+26)))))))|0)), ((2.3611832414348226e+21)), ((((+(-1.0/0.0))) * ((-((73786976294838210000.0)))))))|0);\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; g0.v0 = (this.g2 instanceof i2);; yield y; }}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MAX_VALUE, -0x07fffffff, -0x080000001, 0x100000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0, 1, 1/0, 2**53+2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000000, Math.PI, -1/0, 0/0, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53), -Number.MIN_VALUE, 0x080000001, 0x080000000, 42, 1.7976931348623157e308, 0x100000001, -(2**53-2), -Number.MAX_VALUE, 2**53-2, -0x0ffffffff, Number.MIN_VALUE, 0, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-169986037*/count=369; tryItOut("s0 = new String(o1.a2);");
/*fuzzSeed-169986037*/count=370; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -536870913.0;\n    var d3 = -17.0;\n    {\n      d1 = (Infinity);\n    }\n    d3 = (+/*FFI*/ff(((((0xa673b626)) & ((z)))), ((d3)), (((((0xf0b6a630))-(0xa3bb86d5)) >> ((0x772598ff)))), ((0x6aa3b373)), (((((Uint8ArrayView[1]))) << ((((0xfbc36985)+(0xf33834b1)) | ((0x73971b7c)))))), ((~~(d0))), (((((0x17d49ca5))) & (((0x5b2f2481)))))));\n    {\n      {\n        return +((Infinity));\n      }\n    }\n    return +((d3));\n    {\n      d0 = (((Math.max((x), -9))) * (((Uint8ArrayView[2]))));\n    }\n    (Uint8ArrayView[((0x7c1743f3)+((((0x6b43e809) / (0xcb9e5b82))>>>((0x823cf1a5)+(!(0xcc0cdf56)))))) >> 0]) = ((0xa850a51a)-(/*FFI*/ff()|0));\n    d3 = (d0);\n    {\n      {\n        d3 = ((0xfef7cb3a) ? (d1) : (d0));\n      }\n    }\n    return +((d3));\n  }\n  return f; })(this, {ff: /*wrap2*/(function(){ \"use asm\"; var obrdsv = null || new RegExp(\"[^]\\\\uA107|\\u2c40+?|(?:\\\\b){4,}|(?:\\\\s)\", \"gim\"); var vwcfqa = function (a) { \"use strict\"; this.e1.delete(f1); } ; return vwcfqa;})()}, new ArrayBuffer(4096)); testMathyFunction(mathy4, [Math.PI, 2**53, -Number.MIN_VALUE, 2**53-2, 0/0, -0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, -(2**53-2), -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -Number.MAX_VALUE, 1/0, 0x080000001, 0x100000000, 0, 0x100000001, 1, -1/0, 2**53+2, -(2**53+2), -0x080000000, -0x100000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000000, 42, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000000, 0x07fffffff, 0x0ffffffff, -(2**53), -0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=371; tryItOut("for (var v of e2) { s1 = Array.prototype.join.apply(g0.a0, [s0, h2, \nnew (/*FARR*/[].map(this,  /x/ ))((let (xqqirf, rmvkfv) /(?:(?!$))?|(?=((?![^\\W\\u26fa-\\cR]*?|[^\\b\\xF8])))(?!(?!\\3)\\3^|.\u00e1[^]^|[\\w-j])/m), null)]); }");
/*fuzzSeed-169986037*/count=372; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-169986037*/count=373; tryItOut("Array.prototype.unshift.call(o0.o1.g1.a2, e1, o0);");
/*fuzzSeed-169986037*/count=374; tryItOut("e2.add((x) = new RegExp(\"$\", \"g\").eval(\"/* no regression tests found */\"));");
/*fuzzSeed-169986037*/count=375; tryItOut("g1.o2 = p0.__proto__;");
/*fuzzSeed-169986037*/count=376; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.trunc(Math.fround(Math.fround(( - (( ! Math.log2(Math.hypot(( + x), y))) | 0))))); }); testMathyFunction(mathy4, [0x080000000, 2**53+2, -Number.MAX_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0x100000000, 0x080000001, 42, 0/0, 0.000000000000001, -0, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53), Number.MIN_VALUE, 1, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000000, -0x080000000, 2**53, Math.PI, 0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 1/0, -(2**53-2), -0x07fffffff, -(2**53+2), -1/0]); ");
/*fuzzSeed-169986037*/count=377; tryItOut("\"use strict\"; /*vLoop*/for (var ceobpl = 0; ceobpl < 37; ++ceobpl) { var w = ceobpl; print(x); } ");
/*fuzzSeed-169986037*/count=378; tryItOut("{ void 0; setGCCallback({ action: \"minorGC\", phases: \"both\" }); } a1.sort((function(j) { if (j) { this.s0 = a0[19]; } else { v2 = (o1.i0 instanceof t2); } }), g0.v1, f1);");
/*fuzzSeed-169986037*/count=379; tryItOut("for (var p in f1) { this.h2.get = (new Function).bind(); }");
/*fuzzSeed-169986037*/count=380; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return ( + ( + (Math.hypot((((( ~ (x >>> 0)) >>> 0) ? x : (0x080000001 >>> 0)) ? (Math.sin(y) >>> -Number.MAX_SAFE_INTEGER) : (( + (( + Math.abs((x >>> 0))) ? ( + ( + Math.log1p(Math.sign(x)))) : y)) ? y : y)), Math.fround(Math.imul(Math.fround(( - x)), Math.fround(Math.expm1(((Math.abs(((Math.expm1((y | 0)) | 0) | 0)) | 0) & (x | 0))))))) | 0))); }); testMathyFunction(mathy5, [42, Math.PI, -0x07fffffff, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, 0x100000001, -(2**53-2), -0x0ffffffff, 2**53-2, 1.7976931348623157e308, -0x080000001, -0, 0x080000000, 1, -Number.MIN_VALUE, 2**53+2, -1/0, 0x100000000, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0x100000001, -Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, -0x100000000, -(2**53), Number.MAX_VALUE, 0x07fffffff, -0x080000000, 2**53, 0x080000001, 1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=381; tryItOut("for (var v of this.v1) { try { ; } catch(e0) { } try { g1.v1 = g2.eval(\"function f0(p0)  { yield /*UUV2*/(x.propertyIsEnumerable = x.forEach) } \"); } catch(e1) { } try { g1.a0.forEach((function() { for (var j=0;j<147;++j) { this.f0(j%3==1); } }), (let (damlok, oywbmp, x) (window = [1]))); } catch(e2) { } selectforgc(o1); }");
/*fuzzSeed-169986037*/count=382; tryItOut("m2.has(h2);");
/*fuzzSeed-169986037*/count=383; tryItOut("/*RXUB*/var r = /\\b{3,6}/; var s = \"\\u0008\\u0008\\u0008\\u0008\\u0008\\u0008\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=384; tryItOut("f0 = Proxy.createFunction(g1.h2, f1, f2);");
/*fuzzSeed-169986037*/count=385; tryItOut("Int32Array;");
/*fuzzSeed-169986037*/count=386; tryItOut("v1 + t0;");
/*fuzzSeed-169986037*/count=387; tryItOut("v1 = new Number(-Infinity);");
/*fuzzSeed-169986037*/count=388; tryItOut("testMathyFunction(mathy4, [1/0, 2**53, 1, 0.000000000000001, Math.PI, -0x100000000, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 42, -1/0, -(2**53+2), 0, 2**53-2, -(2**53), 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000001, Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, 0x07fffffff, -0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, 0/0, -0x100000001, -0, 0x100000000, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=389; tryItOut("\"use strict\"; i1 = new Iterator(this.t2);");
/*fuzzSeed-169986037*/count=390; tryItOut("/*RXUB*/var r = /(?!\\ua263)|$|\\b\\3?+?/gyim; var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-169986037*/count=391; tryItOut("m0.delete(this.h2);");
/*fuzzSeed-169986037*/count=392; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=393; tryItOut("\"use strict\"; x;");
/*fuzzSeed-169986037*/count=394; tryItOut("mathy2 = (function(x, y) { \"use asm\"; return Math.atan2((( ! (((Math.hypot(0x07fffffff, (Math.log2((Math.log(x) >>> 0)) >>> 0)) >>> 0) ** ((0x100000001 ? (( + ( - (Math.atan2(1.7976931348623157e308, (y >>> 0)) >>> 0))) !== ( + Math.sign(( + y)))) : ((-0x080000001 >= (((x >>> 0) !== (y >>> 0)) >>> 0)) >>> 0)) >>> 0)) >>> 0)) | 0), (( ~ x) ? (x + ( ! (mathy0((( ! x) >>> 0), (( + ( ~ -Number.MAX_SAFE_INTEGER)) >>> 0)) >>> 0))) : Math.atan2(Math.hypot(Math.fround(((x | 0) && (( ~ (x | 0)) | 0))), (x | 0)), x))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, 0x080000000, -(2**53+2), -0x07fffffff, 2**53+2, Number.MAX_VALUE, 0.000000000000001, -0x100000000, 0x07fffffff, 1, 1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 42, -(2**53), -0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53-2, -0x0ffffffff, -1/0, Math.PI, 0, 0/0, -0, 0x100000001, 0x080000001, -(2**53-2), Number.MAX_SAFE_INTEGER, 2**53, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x080000000]); ");
/*fuzzSeed-169986037*/count=395; tryItOut("\"use strict\"; /*bLoop*/for (let lhvmcs = 0; lhvmcs < 55; ++lhvmcs) { if (lhvmcs % 3 == 1) { Array.prototype.reverse.call(a2, t0); } else { this.s2 += 'x'; }  } ");
/*fuzzSeed-169986037*/count=396; tryItOut("/*RXUB*/var r = r1; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=397; tryItOut("\"use strict\"; v1 = t0.length;");
/*fuzzSeed-169986037*/count=398; tryItOut("testMathyFunction(mathy1, [0x100000001, -Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, -0x080000000, -0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -0x100000000, 0, -(2**53+2), -Number.MAX_VALUE, 2**53-2, 2**53, 0x080000001, -0x100000001, -(2**53-2), -0x080000001, 0/0, Math.PI, 0x080000000, 0.000000000000001, 2**53+2, -(2**53), -0, 1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, -1/0, 0x100000000, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1]); ");
/*fuzzSeed-169986037*/count=399; tryItOut("testMathyFunction(mathy3, /*MARR*/[new Number(1), /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), new String(''), new String(''), function(){}, /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), function(){}, /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), new Number(1), new Number(1), function(){}, /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), new Number(1), function(){}, new String(''), /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), new String(''), new String(''), /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), new Number(1), /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), new String(''), new Number(1), /*FARR*/[].some(Math.floor, \"\\u6327\")(intern( /x/g )), new Number(1), function(){}, new String(''), function(){}, new Number(1), new String('')]); ");
/*fuzzSeed-169986037*/count=400; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(a0, e2);");
/*fuzzSeed-169986037*/count=401; tryItOut("/*RXUB*/var r = /.+/yim; var s = -12; print(s.match(r)); ");
/*fuzzSeed-169986037*/count=402; tryItOut("testMathyFunction(mathy4, [-(2**53), -0x080000000, -0x080000001, 2**53+2, 0x0ffffffff, -0, -Number.MIN_VALUE, -0x100000000, -(2**53-2), 0x080000001, 0x080000000, 1.7976931348623157e308, 0.000000000000001, -(2**53+2), -0x100000001, 1/0, 2**53-2, -0x07fffffff, 1, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 2**53, -1/0, Math.PI, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, 0x100000001, -Number.MIN_SAFE_INTEGER, 0/0, 42, Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=403; tryItOut("( /x/g );");
/*fuzzSeed-169986037*/count=404; tryItOut("\"use strict\"; this.e1.has(p1);");
/*fuzzSeed-169986037*/count=405; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\3\", \"gm\"); var s = \"\\n\"; print(s.search(r)); ");
/*fuzzSeed-169986037*/count=406; tryItOut("Array.prototype.unshift.call(o2.a0, i2, i2, i1, p0, e1, f1, f1, t1, g1);13;for(let [e, c] = ([1] **=  /x/  ? x : x) in \"\\uEB1B\") print(function(){});");
/*fuzzSeed-169986037*/count=407; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-169986037*/count=408; tryItOut("print(x);print(\"\\uA48F\");");
/*fuzzSeed-169986037*/count=409; tryItOut("v1 = o0.a1.some(c = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { throw 3; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: undefined, keys: function() { return []; }, }; })(\"\\uA413\"), -27.valueOf(\"number\")) || null /= [[1]], g0.i1, a2);");
/*fuzzSeed-169986037*/count=410; tryItOut("if((x % 5 != 0)) {if(new RegExp(\"(?=(?!(?=.|\\\\t)){4,}|\\\\\\uc5a5*)\", \"gyi\")) { if (NaN *= window) print(x); else {Array.prototype.push.apply(a0, [t0, p0]); }} }");
/*fuzzSeed-169986037*/count=411; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=412; tryItOut("o0.toSource = (function(j) { if (j) { try { m1.set(t2, s1); } catch(e0) { } try { h1 + ''; } catch(e1) { } try { v0 = t1.length; } catch(e2) { } a0.shift(((z = new RegExp(\"(?:(?:(?:(?:\\\\B?))){1,})\", \"yi\").__defineGetter__(\"y\", Object.prototype.isPrototypeOf))).call((-28 ? Math.min(29, this) : x), x), h1, h0, g0, e0); } else { try { a1 = a2.slice(11, 1); } catch(e0) { } try { /*ODP-3*/Object.defineProperty(b2, \"toLocaleDateString\", { configurable: (x % 15 == 3), enumerable: false, writable: false, value: o0 }); } catch(e1) { } try { a2.valueOf = (function() { /*ADP-2*/Object.defineProperty(a0, ({valueOf: function() { return 7; }}), { configurable: (x % 6 == 0), enumerable: x, get: (function(j) { f2(j); }), set: (function() { try { s1 += 'x'; } catch(e0) { } try { a1[w = \"\u03a0\"] = s1; } catch(e1) { } Object.freeze(a0); return g0.b2; }) }); return f2; }); } catch(e2) { } a2.unshift(); } });");
/*fuzzSeed-169986037*/count=413; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=414; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    switch (((0xb749f*(!(x ? [] : [])))|0)) {\n    }\n    {\n      {\n        (Float32ArrayView[0]) = ((32769.0));\n      }\n    }\n    {\n      d1 = (-9.0);\n    }\n    return (((((0xffffffff)) & (((~~((Float32ArrayView[2]))) <= (((i0)+(i0)) ^ ((Uint16ArrayView[4096]))))-(i0)-((i0) ? (0xfe87c0f3) : (-0x8000000))))))|0;\n    i2 = (/*FFI*/ff((((-0x3e792*(i0)) ^ (0x9ab4e*((((0xfda432db)*0x66d23)>>>((!(i2)))))))), ((abs((((i0)) >> ((0xffffffff)+((0x33f35130)))))|0)), (((((((i2)+((-0x8000000)))>>>((0xd97e41b9) / (0x5258af1c))) == (((-0x8000000)+((-0.0625) > (9.671406556917033e+24)))>>>((-0x8000000)))))|0)), (((0x910e8*((0xf9437895) ? (0xffd4090f) : (0xadeb4dcc))) & ((Float32ArrayView[(((0x26cb8ad6) == (0x88cb8b3f))) >> 2])))), ((~~(d1))), ((~~(-1073741825.0))), ((-2147483649.0)))|0);\n    i2 = (i0);\n    return (((((((((274877906945.0) != (-72057594037927940.0))+((0x7fffffff))) | ((0xc273e116) % (0xc4a0cedc))) / (abs((((i0)-((0xdd5d4fbc)))|0))|0)) & (((4277)))))*0x3ca92))|0;\n  }\n  return f; })(this, {ff: arguments.callee}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1/0, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000000, 2**53+2, Number.MAX_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0, 0x080000001, -0x100000001, 2**53-2, -(2**53-2), 0x080000000, -1/0, 2**53, -(2**53), -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1, 0/0, 0x100000001, -0x080000001, 42, 0, 0x07fffffff, -0x07fffffff, Math.PI, 1.7976931348623157e308, -0x080000000, 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=415; tryItOut("\"use strict\"; for (var p in t1) { try { e0.add(b2); } catch(e0) { } try { o2.a2.splice(-3, 7, a1, v1); } catch(e1) { } Object.prototype.watch.call(t0, \"call\", (function() { try { s2 += s0; } catch(e0) { } try { t2 = new Float32Array(a0); } catch(e1) { } s0 += 'x'; return g0.h2; })); }");
/*fuzzSeed-169986037*/count=416; tryItOut("mathy1 = (function(x, y) { return (Math.hypot(mathy0(Math.hypot(( ~ (( + (x | 0)) | 0)), ((Math.pow(x, (y >>> 0)) | 0) | 0)), (Math.acos((Math.atan2(( + Math.hypot(-Number.MAX_SAFE_INTEGER, Math.cos(x))), (((x | 0) ^ x) | 0)) >>> 0)) >>> 0)), ( + mathy0((( + (x >>> 0)) >>> 0), x))) || Math.fround(mathy0((( + ( + ( + y))) , (((Math.ceil(y) >>> 0) != (mathy0(x, Math.fround(Math.pow(y, (x >>> 0)))) >>> 0)) >>> 0)), (((Math.fround(( - Math.fround(( ~ (0x100000001 , x))))) | 0) & (((( ! Math.fround(y)) >>> 0) / (((Math.imul(x, x) >>> 0) & (x | 0)) >>> 0)) | 0)) | 0)))); }); testMathyFunction(mathy1, /*MARR*/[ 'A' , arguments.caller, false, false,  'A' , arguments.caller]); ");
/*fuzzSeed-169986037*/count=417; tryItOut("mathy3 = (function(x, y) { return (Math.acosh((( + ( ! ( + Math.trunc(( + Math.sqrt(( + (Math.atan2(Math.tan(x), 42) >>> 0)))))))) | 0)) | 0); }); testMathyFunction(mathy3, [0x07fffffff, -0x0ffffffff, 2**53-2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), -1/0, -Number.MAX_SAFE_INTEGER, Math.PI, 0, Number.MIN_VALUE, 2**53+2, 42, -Number.MAX_VALUE, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000000, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000000, 0x080000001, -0x080000001, -(2**53-2), -0x07fffffff, 0x0ffffffff, -0, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, -0x100000001, 1/0, 0.000000000000001, 0/0, 1, -(2**53+2), -0x100000000]); ");
/*fuzzSeed-169986037*/count=418; tryItOut("print(uneval(s1));");
/*fuzzSeed-169986037*/count=419; tryItOut("\"use strict\"; m0.set(e0, h2);");
/*fuzzSeed-169986037*/count=420; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround((Math.fround(((((Math.asinh(x) % (x ? y : ((x | 0) >> (( + Math.min(Math.fround(y), Math.fround(y))) | 0)))) >>> 0) === (( + mathy1((( + (-1/0 < 0x07fffffff)) >>> 0), ((Math.imul(x, Math.fround(Math.min(( + Math.max(0, x)), (y >>> 0)))) == (Math.log1p((x | 0)) | 0)) >>> 0))) >>> 0)) | 0)) ? Math.fround((mathy1(((mathy2(((((y , y) >>> 0) ? x : (x >>> 0)) | 0), (( + ( - ( + x))) | 0)) | 0) >>> 0), (Math.sin(mathy4(Number.MAX_VALUE, y)) >>> 0)) >>> 0)) : Math.fround(( + Math.min((Math.exp(( + Math.min(y, y))) | 0), (Math.asinh((mathy4((x | 0), 0) | 0)) | 0)))))); }); testMathyFunction(mathy5, [2**53-2, 0x100000001, -0x100000000, 0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Math.PI, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MAX_VALUE, -0, 0/0, Number.MAX_VALUE, 0, 1.7976931348623157e308, -0x07fffffff, 1, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -Number.MIN_SAFE_INTEGER, 1/0, 42, -0x080000001, -1/0, 0x07fffffff, 0.000000000000001, -(2**53-2), 2**53, Number.MIN_VALUE, -Number.MIN_VALUE, -0x100000001, -(2**53+2), -(2**53), 0x100000000]); ");
/*fuzzSeed-169986037*/count=421; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"((?!\\\\S|(?=^)*)|\\\\1*${3,}[]+)\", \"yi\"); var s = \"}\\n\\uf3fc\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=422; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1.7976931348623157e308, 0, -Number.MAX_SAFE_INTEGER, 0x100000000, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53+2), -Number.MAX_VALUE, 0.000000000000001, 42, -1/0, -0x080000001, Number.MAX_VALUE, 2**53, 0x100000001, Number.MIN_VALUE, 1/0, 0x07fffffff, Math.PI, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1, -(2**53-2), 0x080000000, -0x100000000, -0x07fffffff, -(2**53), 0/0, -0x080000000, -0x100000001, 2**53+2]); ");
/*fuzzSeed-169986037*/count=423; tryItOut("v2 = g1.eval(\"function f1(v2)  { print(new (decodeURIComponent)());var e = Element(a = (new RegExp(\\\"(?:\\\\\\\\W|.|(?![])[^\\\\\\\\\\\\u2f0c\\\\\\\\t\\\\u00b6]^[\\\\\\\\d\\\\\\\\v-\\\\\\\\u48b1\\\\\\\\\\\\u000d-\\\\ubd57\\\\\\\\n]+)|\\\\ub49d(?:[])?\\\", \\\"im\\\"))) &  '' ; } \");const y = (let (a, NaN = (4277), window = [,], vqnqxk, xuocec, jbksee, y, x) x **= Math.exp(x));");
/*fuzzSeed-169986037*/count=424; tryItOut("\"use strict\"; f2.toString = (function(j) { if (j) { o0.a1.length = v1; } else { try { a0.pop(p1); } catch(e0) { } try { this.v2 = this.r2.unicode; } catch(e1) { } try { /*MXX3*/g2.Uint32Array.length = g2.Uint32Array.length; } catch(e2) { } x = t0[14]; } });\nv2 = g1.g1.runOffThreadScript();\n");
/*fuzzSeed-169986037*/count=425; tryItOut("var nyiyxe = new ArrayBuffer(2); var nyiyxe_0 = new Uint8ClampedArray(nyiyxe); print(nyiyxe_0[0]); var nyiyxe_1 = new Uint8ClampedArray(nyiyxe); nyiyxe_1[0] = 19; var nyiyxe_2 = new Uint32Array(nyiyxe); nyiyxe_2[0] = -5; var nyiyxe_3 = new Int32Array(nyiyxe); /*ADP-1*/Object.defineProperty(a1, 15, ({configurable: true, enumerable: (nyiyxe_3[6] % 55 != 45)}));g2.offThreadCompileScript(\"true\");t1 = new Uint8Array(this.b1);v0 = b1.byteLength;print(\u3056 - \u3056);{}t0 + o1.g0.o1;o2.h2.hasOwn = (function() { for (var j=0;j<3;++j) { f1(j%3==0); } });print(window.unwatch(\"1\"));");
/*fuzzSeed-169986037*/count=426; tryItOut("mathy5 = (function(x, y) { return /*bLoop*/for (let utqkae = 0; utqkae < 8; ++utqkae) { if (utqkae % 9 == 0) { e1.has(b0); } else { t2[10]; }  } ; }); testMathyFunction(mathy5, [-(2**53), 0x100000001, 0x0ffffffff, -(2**53+2), Math.PI, -Number.MAX_SAFE_INTEGER, 0, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1, 0x080000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0x100000000, -0x080000001, -1/0, 2**53+2, -0x100000000, 0.000000000000001, -Number.MAX_VALUE, 2**53-2, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0/0, -0, 42, -0x080000000, -0x0ffffffff, -(2**53-2), 0x080000000, Number.MIN_VALUE, -0x100000001, 1/0, 2**53]); ");
/*fuzzSeed-169986037*/count=427; tryItOut("Array.prototype.push.call(a1, m1);");
/*fuzzSeed-169986037*/count=428; tryItOut("o1.m0 = new WeakMap;print(x);");
/*fuzzSeed-169986037*/count=429; tryItOut("/*RXUB*/var r = /(?=\\1)/ym; var s = (void options('strict')); print(r.test(s)); ");
/*fuzzSeed-169986037*/count=430; tryItOut("\"use strict\"; Object.defineProperty(this, \"v1\", { configurable: true, enumerable: false,  get: function() {  return t2.length; } });");
/*fuzzSeed-169986037*/count=431; tryItOut("\"use strict\"; o0 = new Object;");
/*fuzzSeed-169986037*/count=432; tryItOut("mathy5 = (function(x, y) { return ( + (( + ( ! (Math.fround((((( + Math.cbrt((x | 0))) === (( ~ ((Math.hypot(x, ( + y)) | 0) >>> 0)) >>> 0)) ^ (0 - x)) ? x : Math.fround(mathy4(Math.fround((Math.fround(((Math.fround(y) - Math.fround(x)) | 0)) ? ( + /*RXUE*//(?=(?:\\W+?|(?=(?:\\b*))))|$|\\b/ym.exec(\"\")) : Math.fround(Number.MAX_VALUE))), y)))) >>> 0))) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=433; tryItOut("/*RXUB*/var r = /*FARR*/[x].filter; var s = \"00\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-169986037*/count=434; tryItOut("mathy0 = (function(x, y) { return ( + (( - ( + Math.log1p(( + Math.max((Math.asin((-1/0 < y)) ? ( + ( + Math.PI)) : (y >>> 0)), y))))) >>> 0)); }); testMathyFunction(mathy0, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000000, -0, 0.000000000000001, 0x100000001, 0/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -(2**53-2), Number.MIN_VALUE, Math.PI, 0, 2**53-2, 2**53, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), -0x080000001, Number.MAX_VALUE, -0x100000001, -1/0, -0x07fffffff, 0x100000000, 0x07fffffff, -0x080000000, -(2**53+2), Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, 2**53+2, 1, 1/0, -0x100000000]); ");
/*fuzzSeed-169986037*/count=435; tryItOut("\"use strict\"; /*infloop*/for(var Uint8Array.name in ((Map.prototype.forEach)(x = Proxy.createFunction(({/*TOODEEP*/})(20), Array.isArray, /*wrap3*/(function(){ \"use strict\"; var skfvyf = length; (Math.exp)(); }))))){ /x/ ;/(?!\\x60)*|(.)+/gi; }");
/*fuzzSeed-169986037*/count=436; tryItOut("mathy1 = (function(x, y) { return ( ! ((Math.fround(Math.atan2(Math.sign(( + (( ~ (0x0ffffffff ^ x)) | 0))), Math.fround((( - (mathy0(( + (-(2**53) >= y)), ( + (( + y) !== ( + Math.exp(y))))) >>> 0)) >>> 0)))) / mathy0((Math.pow((( + ( + ( ~ x))) >>> 0), (((y | 0) * (Math.min((y >>> 0), (x >>> 0)) >>> 0)) | 0)) | 0), (( + Math.log2(( + (-(2**53-2) ? -Number.MAX_SAFE_INTEGER : ( + Math.log2(( + y))))))) >>> 0))) | 0)); }); testMathyFunction(mathy1, [(new String('')), (new Number(0)), (function(){return 0;}), (new Boolean(false)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '', false, -0, (new Number(-0)), '0', [], ({valueOf:function(){return 0;}}), (new Boolean(true)), 1, [0], /0/, 0.1, '/0/', null, 0, NaN, undefined, true, '\\0', ({toString:function(){return '0';}})]); ");
/*fuzzSeed-169986037*/count=437; tryItOut("\"use strict\"; /*RXUB*/var r = allocationMarker(); var s = \"\\n\\n\\n\\n\"; print(r.test(s)); ");
/*fuzzSeed-169986037*/count=438; tryItOut("\"use strict\"; testMathyFunction(mathy4, [(function(){return 0;}), 0, '/0/', '\\0', '0', [0], false, undefined, ({valueOf:function(){return '0';}}), (new Number(0)), -0, 1, NaN, ({valueOf:function(){return 0;}}), '', objectEmulatingUndefined(), (new String('')), true, /0/, null, 0.1, (new Number(-0)), ({toString:function(){return '0';}}), (new Boolean(false)), (new Boolean(true)), []]); ");
/*fuzzSeed-169986037*/count=439; tryItOut("v2 = Object.prototype.isPrototypeOf.call(o1, i1);");
/*fuzzSeed-169986037*/count=440; tryItOut("o2.o2.a1 = arguments.callee.caller.caller.caller.caller.caller.arguments;");
/*fuzzSeed-169986037*/count=441; tryItOut("\"use strict\"; t1 = new Int8Array(b0, 72, ({valueOf: function() { v2 = this.g0.eval(\"/* no regression tests found */\");return 11; }}));v2 = Object.prototype.isPrototypeOf.call(e0, b0);");
/*fuzzSeed-169986037*/count=442; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var acos = stdlib.Math.acos;\n  var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -274877906945.0;\n    var i3 = 0;\n    {\n      {\n        d2 = ((0xc9fa21b4) ? (-8388608.0) : (-1152921504606847000.0));\n      }\n    }\n    {\n      d0 = (d0);\n    }\n    {\n      (Uint8ArrayView[(((imul((0xfbbd2060), ((((0x54a44273)) | ((0x59d2535)))))|0))) >> 0]) = ((0xffffffff)-(!(/*FFI*/ff()|0)));\n    }\n    d0 = (2047.0);\n    i1 = (/*FFI*/ff((((-72057594037927940.0) + (((((65.0)) % ((+abs(((d0))))))) * ((-0.5))))), ((SyntaxError(this.__defineGetter__(\"x\", arguments.callee), -26))), (((-0x49b17*((abs((abs((((0xfe2ebe85)) & ((0x43e100b0))))|0))|0))) | ((i1)+(i3)))), (((/*FARR*/[window, new RegExp(\"\\\\2\", \"\"), x].sort( /x/ )) >> (((((67108865.0) != (-16385.0))) > (-65.0))+((d2) == (((9.0)) % ((-2.0))))))), ((((i3)+(0x85b8df7a)) ^ (((4277))+((0x5b74b34c))))), (((((262145.0) != (137438953472.0))) & (0x10bf8*(0xb06e9145)))), ((0x23948c77)), ((d0)), ((((0xa541b5ed)) | ((0xc759a542)))), ((31.0)), ((-2305843009213694000.0)), ((9.671406556917033e+24)), ((281474976710657.0)), ((268435457.0)), ((-9.44473296573929e+21)))|0);\n/* no regression tests found */    d0 = (-2097153.0);\n    d0 = (new RegExp(\".\", \"\"));\n    i1 = (i3);\n    {\n      (Int16ArrayView[0]) = ((Uint16ArrayView[1]));\n    }\n    {\n      (Float32ArrayView[1]) = ((+pow(((i3)), ((d0)))));\n    }\n    return +((1.015625));\n    return +((+acos(((+pow(((+(0.0/0.0))), ((((d0) != (+((Float32ArrayView[((0x54b94b72) % (0x76d026e0)) >> 2]))))))))))));\n    (Int16ArrayView[2]) = ((i3)-((((w+=\"\\u5B4D\".yoyo(\"\\uB40A\"))) % ((Float32ArrayView[(((0xffffffff))) >> 2]))) == (+(~~(+abs(((+acos(((-6.189700196426902e+26)))))))))));\n    i1 = ((((i1)+(0x5607ec1b)-(0x1e1022c)) >> ((4277) == x.eval(\"print(x);\"))));\n    return +((-65535.0));\n  }\n  return f; })(this, {ff: ({\"22\": window,  set \"1430801044.5\" window (c) { yield undefined }  })}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, /*MARR*/[true]); ");
/*fuzzSeed-169986037*/count=443; tryItOut("\"use strict\"; /*hhh*/function vdexod(z){g0.o1.e0.delete(p0);}/*iii*/print(/(\\s*?(?:\\3|[\\w\u540c-\\x67]){2,3})/gym);");
/*fuzzSeed-169986037*/count=444; tryItOut("/*oLoop*/for (let kiduad = 0; kiduad < 2; ++kiduad) { let(x = -15, uknfvk, xtqjaz, x, valuni, jkhmht, daabij, e, lhjdug, jubzuq) { true;} } ");
/*fuzzSeed-169986037*/count=445; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-169986037*/count=446; tryItOut("print(a1);");
/*fuzzSeed-169986037*/count=447; tryItOut("m1 = new Map(o0);");
/*fuzzSeed-169986037*/count=448; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((i0) ? ((0x4518abc9)) : (i1))-(/*FFI*/ff(((3.777893186295716e+22)), ((((0x184bc4a3))|0)), ((~((((0x9ca5995f))>>>((0x1e95bf15))) % (((0xece667e3))>>>((-0x8000000)))))))|0)+((abs(((((x) == (+pow(((-36028797018963970.0)), ((137438953472.0)))))) << ((((0xf97ea6fb))>>>((0x3e136a88))) / (0xa084ce93))))|0))))|0;\n  }\n  return f; })(this, {ff: (((b, x, ...x) =>  { print(\"\\u5F41\"); } ).call).bind((4277), x)}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[false, false, false, x, false, false, false, false, false, false, false, false, false, false, false, false, x, false, false, false, -3/0, false, x, x, -3/0, x, x, x, x, x, x, -3/0, false, false, x, x, false, false, false, false, x, x, false, x, false, false, false, x, -3/0, -3/0, false, false, x, false, false, false, false, -3/0, x, false, false, false, x, false, false, x, -3/0, false, false, -3/0, false, false, -3/0, false, -3/0, false, false, -3/0, false, -3/0, false, false, false, false, false, false, false, false, x, x, false, -3/0, -3/0, x, false, false, -3/0, false, -3/0, false, false, -3/0, false, false, false, x, -3/0, -3/0, false, false, x, false, false, false, false, false, x]); ");
/*fuzzSeed-169986037*/count=449; tryItOut("\"use strict\"; v1 = o2.v2[\"caller\"];");
/*fuzzSeed-169986037*/count=450; tryItOut("{ void 0; minorgc(false); } t0.set(t2, 14);");
/*fuzzSeed-169986037*/count=451; tryItOut("\"use strict\"; i0.next();");
/*fuzzSeed-169986037*/count=452; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((16.0));\n  }\n  return f; })(this, {ff: (x) = window}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0, -Number.MAX_VALUE, -(2**53+2), -Number.MIN_VALUE, -(2**53-2), 2**53, -0x0ffffffff, 1/0, 0x080000001, 42, -1/0, Number.MAX_VALUE, 2**53-2, -0x080000001, 1.7976931348623157e308, 0x080000000, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, Number.MIN_VALUE, 2**53+2, 1, -0x07fffffff, 0.000000000000001, 0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, Math.PI, -0x100000001, 0/0, 0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -0x080000000]); ");
/*fuzzSeed-169986037*/count=453; tryItOut("print(uneval(this.i2));");
/*fuzzSeed-169986037*/count=454; tryItOut("var jfyafo = new ArrayBuffer(4); var jfyafo_0 = new Int16Array(jfyafo); print(jfyafo_0[0]); var jfyafo_1 = new Int8Array(jfyafo); jfyafo_1[0] = 27; var jfyafo_2 = new Uint8ClampedArray(jfyafo); print(jfyafo_2[0]); jfyafo_2[0] = -26; var jfyafo_3 = new Int32Array(jfyafo); g2.offThreadCompileScript(\"/* no regression tests found */\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: \"\u03a0\", noScriptRval: (jfyafo_1[0] % 3 != 0), sourceIsLazy: (jfyafo_3[9] % 2 == 1), catchTermination: false }));s1 += s2;this.__defineSetter__(\"c\", function shapeyConstructor(tmyovn){\"use strict\"; Object.seal(this);for (var ytqasvbez in this) { }delete this[\"-6\"];this[\"valueOf\"] = /*FARR*/[tmyovn].filter((new Function(\"e2.delete(o0.t1);\")));for (var ytqgagesj in this) { }for (var ytqrffaej in this) { }return this; });");
/*fuzzSeed-169986037*/count=455; tryItOut("mathy5 = (function(x, y) { return (Math.sign((Math.hypot(Math.atan2((Math.fround((Math.fround(x) < 42)) | Math.fround(Math.hypot(x, x))), x), (Math.log2(((Math.hypot((-0 | 0), ((((-(2**53-2) | 0) ? ((y ? -0x100000001 : y) >>> 0) : (Math.imul(y, (Math.log((y >>> 0)) >>> 0)) | 0)) | 0) | 0)) | 0) | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0, -0, 0x07fffffff, 0x100000000, 2**53-2, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_VALUE, -(2**53+2), 1/0, Math.PI, -0x100000000, -0x0ffffffff, 1.7976931348623157e308, 0x0ffffffff, -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x080000000, 0x080000001, -0x100000001, 0x080000000, 0x100000001, -(2**53-2), -Number.MAX_VALUE, -1/0, -(2**53), 1, 2**53, Number.MAX_VALUE, 0/0, 2**53+2, 42]); ");
/*fuzzSeed-169986037*/count=456; tryItOut("mathy1 = (function(x, y) { return Math.pow(Math.fround(Math.cbrt((Math.clz32(Math.pow((((y >>> 0) % Math.hypot((Math.min(x, (2**53-2 >>> 0)) >>> 0), ( + -0x100000001))) | 0), -Number.MIN_VALUE)) | 0))), ( + Math.log2(mathy0(Math.fround(Math.sqrt(Math.fround(x))), Math.sqrt((x >>> 0)))))); }); ");
/*fuzzSeed-169986037*/count=457; tryItOut("");
/*fuzzSeed-169986037*/count=458; tryItOut("v2 = (this.g2.b1 instanceof s2);");
/*fuzzSeed-169986037*/count=459; tryItOut("\"use strict\"; let x, x = ((makeFinalizeObserver('nursery'))), uuetwm, safbvb;/*hhh*/function vqqsws(){/*RXUB*/var r = /\\2{3}/gyi; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); }/*iii*/(x);");
/*fuzzSeed-169986037*/count=460; tryItOut("this.v1 = g2.eval(\"testMathyFunction(mathy2, [1, 1/0, 0.000000000000001, 0x100000001, -(2**53-2), 0x100000000, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, -1/0, Number.MAX_SAFE_INTEGER, 0, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, 42, 2**53, Math.PI, -Number.MAX_VALUE, -(2**53), 0x080000000, 0/0, -0x0ffffffff, -0, 2**53-2, -0x100000001, 2**53+2, -0x080000000, 0x080000001, -Number.MIN_VALUE, 0x07fffffff, -0x100000000]); \");");
/*fuzzSeed-169986037*/count=461; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0(( ! (mathy0(Math.fround(Math.clz32(y)), (0.000000000000001 >>> 0)) >>> 0)), Math.max(Math.fround(( + Math.fround(Math.fround(Math.log(Math.fround(( - y))))))), Math.max(Math.abs((y >>> 0)), ( + ( + ( + y)))))); }); testMathyFunction(mathy1, [0/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -1/0, 0.000000000000001, -(2**53+2), -0x100000000, Math.PI, 2**53, 42, Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0, -(2**53-2), 0x0ffffffff, 0x080000001, 0x07fffffff, 0, 0x100000001, -0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, -(2**53), 0x100000000, Number.MAX_VALUE, 2**53-2, -Number.MAX_VALUE, -0x080000001, 2**53+2, Number.MAX_SAFE_INTEGER, 1/0, 1, 0x080000000, -Number.MIN_VALUE, -0x080000000]); ");
/*fuzzSeed-169986037*/count=462; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.fround((mathy2(Math.fround(( + mathy0(-Number.MIN_SAFE_INTEGER, ( - 0.000000000000001)))), (Math.fround(((y >>> 0) && Math.fround(x))) | 0)) >>> 0)); }); testMathyFunction(mathy4, [2**53, Number.MIN_VALUE, 0x100000000, -(2**53-2), -0x080000000, 2**53-2, -(2**53+2), -0, 1/0, Number.MAX_VALUE, 0, 1, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 42, 0/0, 1.7976931348623157e308, -0x080000001, Number.MIN_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x0ffffffff, 0x100000001, -(2**53), -0x100000001, 0.000000000000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -1/0, 2**53+2, 0x080000001, Math.PI, 0x07fffffff, -Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=463; tryItOut("t1 = t2[g1.g0.v0];");
/*fuzzSeed-169986037*/count=464; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + mathy3(( + ( ! (Math.log(Math.max(y, ( + ((x === -(2**53+2)) !== x)))) >>> 0))), ( + Math.log1p(mathy2((Math.imul(( + Math.max(( + Math.pow(Math.fround(x), Math.fround(x))), ( + y))), -1/0) !== ( ! (x && x))), (Math.pow((Math.fround((Math.fround((mathy1(y, Number.MIN_VALUE) != Math.pow(x, x))) < Math.fround(( + (( + y) + ( + ( ! x))))))) >>> 0), (y >>> 0)) >>> 0)))))); }); testMathyFunction(mathy4, [-(2**53+2), 0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), -(2**53-2), 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, 0x080000000, 0x100000000, -0x080000001, 0, -0x100000000, 0/0, 0x0ffffffff, Number.MIN_VALUE, 2**53+2, 1/0, -0, Number.MAX_VALUE, 2**53-2, 2**53, 0.000000000000001, -0x0ffffffff, -1/0, Math.PI, -Number.MIN_SAFE_INTEGER, 42, Number.MAX_SAFE_INTEGER, 1, -0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-169986037*/count=465; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=466; tryItOut("print(x);");
/*fuzzSeed-169986037*/count=467; tryItOut("\"use strict\"; a0 = r1.exec(s0);");
/*fuzzSeed-169986037*/count=468; tryItOut("mathy4 = (function(x, y) { return ((( ! Math.log10(( + mathy0(( + mathy2(x, y)), ( + y))))) | 0) === (( + Math.asin((((Math.fround(y) || (x | 0)) << y) >>> 0))) <= ( + (mathy2(Math.fround(x), Math.fround(( ! y))) >>> 0)))); }); testMathyFunction(mathy4, [2**53+2, -(2**53+2), -Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000001, Number.MAX_VALUE, 1, -0x100000000, 1.7976931348623157e308, -Number.MIN_VALUE, 1/0, 2**53-2, -0, 2**53, -1/0, 0x07fffffff, Math.PI, -0x0ffffffff, 0x080000001, -Number.MAX_VALUE, -0x100000001, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 0.000000000000001, 0, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), 42, -0x080000001]); ");
/*fuzzSeed-169986037*/count=469; tryItOut("\"use strict\"; print(v2);");
/*fuzzSeed-169986037*/count=470; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=471; tryItOut("\"use strict\"; x.stack;");
/*fuzzSeed-169986037*/count=472; tryItOut("print((4277));");
/*fuzzSeed-169986037*/count=473; tryItOut("-12function c(x) /x/g this.a1[8] = undefined.eval(\"for (var v of m1) { try { t2.set(t2, window); } catch(e0) { } a0 = arguments; }\");");
/*fuzzSeed-169986037*/count=474; tryItOut("mathy5 = (function(x, y) { return Math.asinh(( + mathy2(Math.pow(( + x), ( + Math.sqrt(y))), (( - Math.atan2(( ! ( + (0x080000001 < (mathy4(( + Number.MAX_SAFE_INTEGER), x) >>> 0)))), mathy2(y, (Math.hypot(x, ((Math.atan2(x, 2**53) >>> 0) | 0)) | 0)))) | 0)))); }); testMathyFunction(mathy5, [0x100000000, 0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, 0x0ffffffff, -0x080000001, 0x080000000, 42, -(2**53-2), 2**53-2, -(2**53+2), 0x07fffffff, 0, 2**53+2, -0x080000000, Math.PI, 2**53, Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, -0x100000001, -(2**53), -Number.MIN_VALUE, 0.000000000000001, 1/0, -0x07fffffff, 0x080000001, -0, 1]); ");
/*fuzzSeed-169986037*/count=475; tryItOut("M:with({c: (NaN = new Float64Array())})print(x);\n;\n");
/*fuzzSeed-169986037*/count=476; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ((mathy0(Math.fround(( + ( ! ( + x)))), ( + ( + Math.min(( + ((( + -1/0) != x) >>> 0)), Math.PI)))) | 0) ? (Math.max((( ~ ( + ((mathy0(mathy0(Number.MIN_SAFE_INTEGER, (0x07fffffff | 0)), Math.max(( + Number.MAX_SAFE_INTEGER), y)) >>> 0) != (Math.min(( - y), -Number.MAX_VALUE) | 0)))) >>> 0), (Math.fround(( + Math.fround((Math.hypot(((Math.cos(mathy0((Number.MIN_VALUE >>> 0), (x >>> 0))) | 0) >>> 0), (( + mathy0((y | 0), x)) >>> 0)) >>> 0)))) >>> 0)) >>> 0) : (Math.log((0x0ffffffff != (Math.fround(Math.fround((y >>> 0))) >> (y | 0)))) % ( - Math.hypot((( - x) | 0), (y >>> 0))))); }); ");
/*fuzzSeed-169986037*/count=477; tryItOut("s0.toSource = (function() { try { f2 + ''; } catch(e0) { } try { g2 = this; } catch(e1) { } Array.prototype.push.apply(a0, [x, this.p1, g1]); return a2; });");
/*fuzzSeed-169986037*/count=478; tryItOut("/*infloop*/for((y) in x) for (var p in o0.o1) { e2.delete(h2); }\n(\u3056 = undefined);\n\"\\u2F5F\";\n");
/*fuzzSeed-169986037*/count=479; tryItOut("\"use strict\"; for (var v of p0) { v0 = o2.o0.t0.byteOffset; }");
/*fuzzSeed-169986037*/count=480; tryItOut("\"use strict\"; t1.set(t2, 5);\nreturn (Math.log10(this)\n);\n");
/*fuzzSeed-169986037*/count=481; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(s2, p2);");
/*fuzzSeed-169986037*/count=482; tryItOut("m0.set(a0, i2);");
/*fuzzSeed-169986037*/count=483; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (((Math.sign((( + ( ! Math.fround(Math.imul(Math.fround(y), ((Math.fround(y) * ( + Math.clz32((y == 0)))) | 0))))) >>> 0)) | 0) >>> 0) < (( + Math.cos(( + ( ~ (((y | 0) + (Math.pow(x, x) % y)) | 0))))) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=484; tryItOut("/*infloop*/ for  each(let ({})[\"0\"] in (c = x)) (void schedulegc(this.g0));");
/*fuzzSeed-169986037*/count=485; tryItOut("o1.o0.g0.v2 = r1.constructor;");
/*fuzzSeed-169986037*/count=486; tryItOut("var ovwkyz = new ArrayBuffer(4); var ovwkyz_0 = new Int8Array(ovwkyz); var ovwkyz_1 = new Float64Array(ovwkyz); ovwkyz_1[0] = 0.994; var ovwkyz_2 = new Float64Array(ovwkyz); this.m1.set(m2, i2);s0 += 'x';");
/*fuzzSeed-169986037*/count=487; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.asin((Math.sign(Math.fround((( ~ (Math.ceil(x) >>> 0)) / y))) | 0)) | 0); }); testMathyFunction(mathy3, [42, 0x080000001, Number.MAX_VALUE, 0x100000001, -1/0, 0/0, 2**53+2, 1/0, Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53), -0x0ffffffff, -0x080000001, -(2**53-2), 0, 1, -Number.MIN_VALUE, 2**53, 0x07fffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -0, 0x100000000, 1.7976931348623157e308, -0x080000000, -0x07fffffff, 2**53-2, -0x100000000, Math.PI]); ");
/*fuzzSeed-169986037*/count=488; tryItOut("o0.e0.add(v1);");
/*fuzzSeed-169986037*/count=489; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=490; tryItOut("testMathyFunction(mathy4, [-0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, Math.PI, -Number.MAX_VALUE, -(2**53-2), 0/0, 0, -0x080000000, 0x100000000, -0x07fffffff, -0x0ffffffff, 2**53+2, 0x100000001, -(2**53), -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 1.7976931348623157e308, -(2**53+2), 2**53-2, -0x100000000, 2**53, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, 42, Number.MAX_VALUE, -0, -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, -1/0, 0x080000000]); ");
/*fuzzSeed-169986037*/count=491; tryItOut("const v0 = new Number(this.b1);");
/*fuzzSeed-169986037*/count=492; tryItOut("i2.send(a2);");
/*fuzzSeed-169986037*/count=493; tryItOut("testMathyFunction(mathy3, [1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 0x080000001, -(2**53-2), -0, Number.MIN_VALUE, 0x080000000, 0x0ffffffff, 2**53, 1, -0x100000001, -(2**53), -Number.MAX_VALUE, -1/0, 42, 2**53+2, Number.MAX_VALUE, 0/0, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, -0x0ffffffff, 2**53-2, 0, -0x080000001, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000]); ");
/*fuzzSeed-169986037*/count=494; tryItOut("mathy1 = (function(x, y) { return (mathy0((( - (( ! mathy0(( + (( + (Math.hypot((x >>> 0), (y >>> 0)) >>> 0)) / ( + y))), y)) >>> 0)) | 0), Math.imul(Math.asin(mathy0(( + (x << Math.fround(x))), x)), (( - (x >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy1, [-(2**53-2), 0x100000000, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1/0, 0, 0x100000001, 1, 0x07fffffff, -0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x080000000, -0x080000001, -0x100000001, -Number.MAX_SAFE_INTEGER, -1/0, Math.PI, -0x0ffffffff, 0x080000000, -(2**53), 0x0ffffffff, 0/0, -(2**53+2), 2**53+2, 0x080000001, 2**53-2, -0, -0x07fffffff, Number.MAX_VALUE, 0.000000000000001, 2**53, 42]); ");
/*fuzzSeed-169986037*/count=495; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-169986037*/count=496; tryItOut("/*MXX3*/g2.Error.length = g2.Error.length;");
/*fuzzSeed-169986037*/count=497; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.min(Math.tan(Math.fround(Math.exp((Math.fround((x ? Math.fround(Math.log10(y)) : Math.fround((Math.min(y, y) >>> 0)))) >>> 0)))), Math.log10(Math.log10(x))); }); ");
/*fuzzSeed-169986037*/count=498; tryItOut("t1 = new Int16Array(({valueOf: function() { a0.splice(NaN, 3, g0);return 17; }}));");
/*fuzzSeed-169986037*/count=499; tryItOut("var scnyzu = new ArrayBuffer(4); var scnyzu_0 = new Uint16Array(scnyzu); s0 = new String(f1);");
/*fuzzSeed-169986037*/count=500; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=501; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-169986037*/count=502; tryItOut("v1 = evaluate(\"testMathyFunction(mathy2, [-Number.MIN_VALUE, 1/0, Number.MIN_SAFE_INTEGER, 0/0, 1, 2**53-2, 0x080000000, 2**53+2, -0x0ffffffff, -0, Math.PI, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MIN_VALUE, 0.000000000000001, -(2**53+2), 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000001, 1.7976931348623157e308, 0, 2**53, Number.MAX_VALUE, 0x100000000, 0x07fffffff, -Number.MAX_VALUE, 0x0ffffffff, 42, -0x07fffffff, -0x080000001, -1/0, -(2**53), -0x080000000]); \", ({ global: this.g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 4 != 3), noScriptRval: true, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-169986037*/count=503; tryItOut("\"use asm\"; var v0 = a1.reduce, reduceRight(f2);");
/*fuzzSeed-169986037*/count=504; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=505; tryItOut("v2 = a0.length;function w(x) { yield  ''  } if((x % 46 != 4)) { if ((uneval(new (() =>  { print(Math); } )(this)))) {a2.pop();yield -0; } else {(x); }}");
/*fuzzSeed-169986037*/count=506; tryItOut("print(uneval(e1));function x(d, x = (void options('strict_mode')))\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 4194304.0;\n    var d3 = 34359738369.0;\n    var i4 = 0;\n    return +((Float32ArrayView[2]));\n  }\n  return f;x.__defineSetter__(\"y\", ((x) = -8));");
/*fuzzSeed-169986037*/count=507; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ~ Math.fround((( ~ y) >>> 0))) > ( + (( + (x > Math.round((-0 | 0)))) >>> ( + mathy0(0x07fffffff, (0x0ffffffff & Math.imul(x, Math.max(( - y), y)))))))); }); testMathyFunction(mathy3, [({valueOf:function(){return 0;}}), (new Number(-0)), [], -0, (new Number(0)), '\\0', [0], ({valueOf:function(){return '0';}}), undefined, (new String('')), '0', 1, true, /0/, null, 0.1, NaN, '', false, (new Boolean(true)), (new Boolean(false)), objectEmulatingUndefined(), (function(){return 0;}), 0, ({toString:function(){return '0';}}), '/0/']); ");
/*fuzzSeed-169986037*/count=508; tryItOut("/*RXUB*/var r = new RegExp(\"(?=\\\\d)\", \"gym\"); var s = \"0\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-169986037*/count=509; tryItOut("\"use strict\"; print(b);function x() { \"use strict\"; yield \"\\u1DC3\" } a0.shift(b1);");
/*fuzzSeed-169986037*/count=510; tryItOut("m2.get(t0);");
/*fuzzSeed-169986037*/count=511; tryItOut("\"use strict\"; e0.add(g1);");
/*fuzzSeed-169986037*/count=512; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ((Math.imul(((y == (Math.imul((-(2**53) | 0), y) | 0)) >>> 0), (Math.min((( - ( ~ y)) | 0), ( - (( + (Math.sign(y) | 0)) | 0))) | 0)) ? (( + ((Math.fround(((( + Math.fround(Math.max((x >>> 0), Math.fround((Math.atan2((y >>> 0), y) >>> 0))))) == 1.7976931348623157e308) !== Math.fround(y))) | 0) ? ( + Math.abs((( - (0.000000000000001 >>> 0)) >>> 0))) : ( + ((Math.fround(( + x)) | 0) > ( + ( - x)))))) >>> 0) : Math.pow((( + ( - ( + y))) | 0), Math.fround(( ~ Math.fround((( + Math.max(( + -Number.MAX_VALUE), ( + (( + y) != ( + x))))) >= (( ~ x) | 0))))))) >>> 0); }); testMathyFunction(mathy0, [-Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 0x100000000, 0.000000000000001, -(2**53-2), -0x100000001, 0x080000000, Number.MAX_SAFE_INTEGER, 0, 1/0, -0, 1, 42, 2**53+2, -(2**53), 2**53, -Number.MAX_VALUE, -0x080000000, 0x100000001, Number.MIN_SAFE_INTEGER, -1/0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000001, 0x07fffffff, Math.PI, -0x080000001, -(2**53+2), -0x0ffffffff, 2**53-2, -Number.MIN_VALUE, 0x0ffffffff, -0x100000000, Number.MAX_VALUE, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=513; tryItOut("\"use strict\"; this.p1.__proto__ = g2;");
/*fuzzSeed-169986037*/count=514; tryItOut("mathy5 = (function(x, y) { return Math.fround((Math.fround(Math.trunc((Math.log((Math.log10(x) | 0)) | 0))) << Math.fround(( + Math.hypot(( + ( ! Math.exp(Math.fround((0x100000000 == Math.fround(y)))))), Math.fround(Math.imul((( + Math.imul(( + (y % x)), ((x ^ x) >>> 0))) >>> 0), (( + Math.min(( + (Math.hypot((Number.MAX_VALUE | 0), (x | 0)) | 0)), ( + Math.max((x === y), 0/0)))) >>> 0)))))))); }); testMathyFunction(mathy5, [1/0, 1, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, 0x080000001, 0/0, -1/0, 2**53, -Number.MIN_VALUE, 0, -0x07fffffff, 2**53-2, -(2**53+2), -0x0ffffffff, Number.MAX_VALUE, 0x100000001, Math.PI, -0, -0x080000000, 2**53+2, Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, 42, -0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -(2**53), -0x100000000, Number.MIN_VALUE, 0x080000000, -0x080000001]); ");
/*fuzzSeed-169986037*/count=515; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=516; tryItOut("dbbiqk((makeFinalizeObserver('nursery')), /./i);/*hhh*/function dbbiqk(b, eval = {}){g1.o0.s2 += this.s2;}");
/*fuzzSeed-169986037*/count=517; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=518; tryItOut("let (eval, b, zrcpnq, x = w, x = new RegExp(\"\\\\2\", \"gy\")) { switch((4277)) { default: for (var p in i1) { try { e1.add(b2); } catch(e0) { } for (var p in o1) { try { print(uneval(g2.m1)); } catch(e0) { } try { Array.prototype.shift.apply(a2, []); } catch(e1) { } try { for (var p in t0) { g0.s0 = ''; } } catch(e2) { } s0 += 'x'; } }break; case 6: t1 + ''; } }");
/*fuzzSeed-169986037*/count=519; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( + ((Math.cosh(mathy0(( + (x !== (-Number.MIN_VALUE < x))), ( + Math.sqrt(Math.fround((Math.trunc((( ! x) | 0)) | 0)))))) >>> 0) | 0)); }); testMathyFunction(mathy3, [0, -0x100000000, -(2**53-2), -0, -0x07fffffff, -(2**53+2), 1/0, Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MIN_VALUE, 42, -0x080000000, 1, 1.7976931348623157e308, 0x100000000, Math.PI, 2**53+2, -Number.MIN_VALUE, 0x100000001, 0x0ffffffff, Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, -1/0, 0/0, 0x07fffffff, 0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000000, -0x080000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=520; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.acosh(((y , y) >>> 0)), ( + Math.hypot((Math.pow(( + Math.log10(0.000000000000001)), ((x ? -0 : x) > y)) >>> 0), (((Math.asin(x) / x) ^ -(2**53+2)) | 0)))); }); testMathyFunction(mathy1, [-0, null, undefined, '\\0', /0/, true, ({valueOf:function(){return 0;}}), '', 1, false, (new Number(-0)), ({toString:function(){return '0';}}), (new Boolean(false)), NaN, '/0/', '0', ({valueOf:function(){return '0';}}), 0.1, [0], [], objectEmulatingUndefined(), (new Boolean(true)), (new String('')), (new Number(0)), (function(){return 0;}), 0]); ");
/*fuzzSeed-169986037*/count=521; tryItOut("/*infloop*/for(let y; (new Float64Array() , Math.exp(18) &= (4277)); let (b = (4277)) allocationMarker() ^= this.__defineGetter__(\"z\",  '' )) {f0(g0.g2.m2);/*RXUB*/var r = /(?!(?:(?!(?=\\B)[^])[^]\u001e{4}*)|\\2)((?:\\2{2,6})|\\3)*\\3|.{0}/m; var s = \"\\n00\\u5bac\\n\\u5bac00\\u5bac\\n\\u5bac00\\u5bac\\n\\u5bac00\\u5bac\\n\\u5bac00\\u5bac\\n\\u5bac00\\u5bac\\n\\u5bac\\n00\\u5bac\\n\\u5bac\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(uneval(s.match(r)));  }");
/*fuzzSeed-169986037*/count=522; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.pow(Math.fround(((((Math.atanh(((Math.imul(( + x), y) | 0) >>> 0)) >>> 0) >>> 0) ? (((y >>> 0) | -0) >>> 0) : (x >>> 0)) !== Math.tan(Math.fround((Math.atan(y) | 0))))), (Math.abs(((( + ( + (y / Math.fround(Math.sign(Math.fround(y)))))) >>> 0) | 0)) | 0))); }); testMathyFunction(mathy0, [2**53, 0, 0x100000001, -(2**53), 0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 1, -(2**53-2), -(2**53+2), 0/0, -0x07fffffff, 0x0ffffffff, 0x080000000, -1/0, -0x100000001, -0x080000000, 0x100000000, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 2**53+2, Number.MAX_VALUE, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0, Math.PI, Number.MIN_VALUE, 42, -0x080000001, 0x080000001, 1/0]); ");
/*fuzzSeed-169986037*/count=523; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=524; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (((( + ((Math.asin(x) | 0) ** Math.fround((Math.pow(Math.fround(Math.asin(( ~ (-0x100000001 >>> 0)))), Math.fround((Math.fround(x) ^ Math.fround(Math.log(Math.fround(x)))))) >>> 0)))) | 0) << ( + ( ! ( + Math.pow(x, x))))) - ( + Math.max(Math.fround((((-Number.MIN_VALUE >>> 0) != (( + (Math.log2(y) | 0)) ? ( + Math.tanh(x)) : ( + Math.sign((x >>> 0))))) >>> 0)), Math.fround((( ~ (Math.fround((Math.fround(( + Math.fround(y))) ? Math.fround(Math.atan2((x >>> 0), ( + (Math.atan2((x | 0), (Math.fround((Math.fround(x) - 0.000000000000001)) | 0)) | 0)))) : Math.fround(y))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy0, [-0x080000000, -0x100000001, -0, -0x07fffffff, 0x100000001, 0x0ffffffff, 2**53-2, 0x080000000, -1/0, -(2**53), 0.000000000000001, Number.MIN_VALUE, -(2**53+2), 1/0, 2**53+2, -Number.MAX_VALUE, -0x080000001, -0x0ffffffff, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0/0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 1, 0, 42, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, 0x07fffffff, -0x100000000, 0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=525; tryItOut("\"use strict\"; v1 = evaluate(\"a1 = r0.exec(s2);\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 32 != 23), noScriptRval: (x % 31 == 6), sourceIsLazy: false, catchTermination: true }));function NaN(x)(void version(170)) %  \"\" ((void options('strict')),  /x/ \n)var bxamvi, y, lvylxv,  /x/g , errvdn;g0.offThreadCompileScript(\"function f2(this.e2)  { (d); } \", ({ global: o0.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 2 != 1), noScriptRval:  /x/ , sourceIsLazy: false, catchTermination: /^/g }));");
/*fuzzSeed-169986037*/count=526; tryItOut("a2[d && x / x] = ({e: (void version(185))});");
/*fuzzSeed-169986037*/count=527; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.clz32(Math.fround((mathy1(mathy0(( + (Math.hypot((Math.sinh((x | 0)) | 0), Math.exp(y)) >>> 0)), Math.max(Math.tan(x), Math.abs(y))), ((Math.expm1(0x07fffffff) * Math.fround(Math.fround(Math.pow(mathy0(x, x), ( ! ( + ( ~ x))))))) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [1/0, Number.MAX_VALUE, -0x080000001, -0x080000000, -0, 0, 0.000000000000001, -(2**53-2), 2**53-2, -(2**53), -0x100000001, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, -0x100000000, -0x07fffffff, -(2**53+2), 2**53, -1/0, -Number.MAX_VALUE, 0x100000000, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_SAFE_INTEGER, 42, 1, Number.MIN_VALUE, 0x07fffffff, 1.7976931348623157e308, 2**53+2, 0x080000001, Math.PI]); ");
/*fuzzSeed-169986037*/count=528; tryItOut("b1.toSource = (function(j) { this.f2(j); });");
/*fuzzSeed-169986037*/count=529; tryItOut(" for (var a of (new (NaN =  \"\" ))) {y; }");
/*fuzzSeed-169986037*/count=530; tryItOut("v2 = g0.eval(\"delete m2[\\\"caller\\\"];\");");
/*fuzzSeed-169986037*/count=531; tryItOut("\"use strict\"; g2.f2 + a2;/*bLoop*/for (var tudvat = 0, x, (uneval(/(\\2?|(?:[\\cB-\u12f3\uc6dcD-\\\u81a4])|\\xa6{3,5})+?[]/)); tudvat < 32 && ((4277)); ++tudvat) { if (tudvat % 9 == 8) { v2 = (m0 instanceof m2); } else { /*vLoop*/for (let lbsdsn = 0; lbsdsn < 87; ++lbsdsn) { const c = lbsdsn; o1.b2 = new SharedArrayBuffer(12); }  }  } ");
/*fuzzSeed-169986037*/count=532; tryItOut("return this.__defineSetter__(\"x\", Math.pow(((4277).__defineGetter__(\"\\u3056\", String.prototype.fixed)), x));");
/*fuzzSeed-169986037*/count=533; tryItOut("\"use strict\"; x;");
/*fuzzSeed-169986037*/count=534; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.acosh((( ! -0x100000000) | 0)) | 0) != Math.fround(( + Math.imul((x >>> 0), (-0 | 0))))); }); testMathyFunction(mathy1, /*MARR*/[[undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined],  \"\" , [undefined],  \"\" , [undefined],  \"\" ,  \"\" , [undefined],  \"\" ,  \"\" , [undefined],  \"\" ,  \"\" , [undefined],  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , [undefined],  \"\" ,  \"\" ,  \"\" , [undefined],  \"\" , [undefined],  \"\" ,  \"\" , [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined],  \"\" ,  \"\" , [undefined],  \"\" , [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined],  \"\" , [undefined],  \"\" , [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined], [undefined],  \"\" , [undefined], [undefined], [undefined], [undefined],  \"\" ,  \"\" , [undefined], [undefined],  \"\" , [undefined],  \"\" , [undefined],  \"\" ,  \"\" , [undefined], [undefined], [undefined], [undefined],  \"\" ,  \"\" , [undefined],  \"\" , [undefined], [undefined],  \"\" , [undefined],  \"\" ,  \"\" , [undefined],  \"\" , [undefined],  \"\" , [undefined],  \"\" ,  \"\" ,  \"\" , [undefined], [undefined], [undefined],  \"\" , [undefined], [undefined],  \"\" , [undefined], [undefined],  \"\" ,  \"\" , [undefined], [undefined],  \"\" , [undefined],  \"\" ,  \"\" , [undefined], [undefined],  \"\" ,  \"\" ,  \"\" , [undefined],  \"\" , [undefined], [undefined],  \"\" , [undefined],  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , [undefined],  \"\" , [undefined],  \"\" ,  \"\" ,  \"\" ,  \"\" ]); ");
/*fuzzSeed-169986037*/count=535; tryItOut("print(uneval(i0));");
/*fuzzSeed-169986037*/count=536; tryItOut("let (fzgcft, z =  /x/g , b, a, dhokti, y = (/((?:(\ub7f0){2}){3,}){2}/gyim).bind( '' ), window = z = /(?!\\S\\\u41d9)\\1?{4}/g) { var uzqnqd = new ArrayBuffer(4); var uzqnqd_0 = new Float32Array(uzqnqd); var uzqnqd_1 = new Uint16Array(uzqnqd); uzqnqd_1[0] = 8; var uzqnqd_2 = new Int8Array(uzqnqd); var uzqnqd_3 = new Uint8ClampedArray(uzqnqd); uzqnqd_3[0] = 25; Array.prototype.reverse.apply(a2, []);m1.toString = (function(j) { f0(j); });print(a | a.eval(\"\\\"use strict\\\"; print(Math.sinh( '' ));\"));v0 = (s0 instanceof i1);a1.push(uzqnqd_3, h1, i2); }");
/*fuzzSeed-169986037*/count=537; tryItOut("mathy5 = (function(x, y) { return ((Math.fround(mathy0((Math.atan((mathy4((Math.acosh((( ! Math.pow(x, (x >>> 0))) | 0)) | 0), Math.max(Math.fround((Math.fround(1) === Math.fround(Math.atan(-(2**53+2))))), y)) >>> 0)) >>> 0), Math.fround(Math.hypot(Math.fround((Math.max(x, Math.fround(y)) / Math.pow(Math.fround(( + ( + ( + y)))), -Number.MAX_VALUE))), Math.fround((Math.imul((Math.fround(((-(2**53) ? Math.fround(Math.log(Math.fround(1))) : ( + x)) == Math.fround(Math.fround(Math.tan((x ? ( + x) : y)))))) | 0), (( - (( + 0x100000000) >>> 0)) | 0)) | 0)))))) >>> 0) === (( - mathy3((Math.pow(Math.fround(( + x)), ( ! 0x100000000)) ? Math.fround(Math.fround(Math.log2(-0x0ffffffff))) : ( + Math.fround(y))), ( + ( + ((0x07fffffff | 0) || ( + ( ~ y))))))) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=538; tryItOut("mathy5 = (function(x, y) { return Math.tanh(Math.fround(( ! Math.clz32(y)))); }); testMathyFunction(mathy5, [0x0ffffffff, Number.MAX_SAFE_INTEGER, 0/0, 0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -0x0ffffffff, -0x100000001, -(2**53+2), -(2**53), 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_VALUE, 0x100000001, -0x07fffffff, 2**53+2, 1.7976931348623157e308, -Number.MIN_VALUE, 1, 0x100000000, 0x080000001, 2**53, 2**53-2, -0, 42, 0x080000000, -Number.MAX_VALUE, -0x080000000, 0.000000000000001, -0x100000000, -(2**53-2), -0x080000001, -1/0, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=539; tryItOut("for (var v of p2) { try { for (var p in g1.o1) { this.v0 = Object.prototype.isPrototypeOf.call(b2, g1); } } catch(e0) { } a2 = []; }");
/*fuzzSeed-169986037*/count=540; tryItOut("v1 = a0.reduce, reduceRight();");
/*fuzzSeed-169986037*/count=541; tryItOut("{ void 0; void relazifyFunctions(); }");
/*fuzzSeed-169986037*/count=542; tryItOut("i2 = new Iterator(e1);");
/*fuzzSeed-169986037*/count=543; tryItOut("print(x);");
/*fuzzSeed-169986037*/count=544; tryItOut("mathy5 = (function(x, y) { return (Math.pow((( + y) & Math.fround((Math.min(Math.fround(mathy1(Math.fround(x), Math.fround(x))), (Math.hypot((x >>> 0), (x >>> 0)) >>> 0)) | 0))), (((x | 0) & Math.atan2(Math.fround(( ~ (-Number.MIN_VALUE | 0))), Math.fround(x))) | 0)) % Math.min(Math.fround(Math.clz32(x)), ( ! ( + Math.atan2((y ? (Math.atan2(-(2**53), ( ! x)) >>> 0) : x), y))))); }); testMathyFunction(mathy5, [0x07fffffff, 0x080000001, -0x100000000, -0x080000000, -0x080000001, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0, 1, -0, -Number.MIN_VALUE, -1/0, 42, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, Math.PI, -(2**53), 1.7976931348623157e308, -Number.MAX_VALUE, -0x0ffffffff, 1/0, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), 2**53+2, 0x080000000, -0x07fffffff, 0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53+2), 0/0, 0x100000001]); ");
/*fuzzSeed-169986037*/count=545; tryItOut("Array.prototype.pop.apply(a0, []);");
/*fuzzSeed-169986037*/count=546; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((((Math.acosh(( + x)) % (Math.log1p(((( + Math.imul(( + x), (x >>> 0))) | ( ~ y)) | 0)) && mathy1(x, (Math.pow(Math.fround(x), ((y ** x) >>> 0)) >>> 0)))) >>> 0) ^ (Math.max(((( + ( + (x >= y))) | x) >>> 0), (( ~ 0x100000001) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [(new Boolean(true)), ({toString:function(){return '0';}}), -0, 0.1, (new Number(0)), null, undefined, [], ({valueOf:function(){return 0;}}), 1, [0], '\\0', (function(){return 0;}), 0, '', NaN, /0/, '/0/', (new Boolean(false)), false, (new String('')), true, ({valueOf:function(){return '0';}}), '0', (new Number(-0)), objectEmulatingUndefined()]); ");
/*fuzzSeed-169986037*/count=547; tryItOut("/*hhh*/function zxkssw(x, \u3056){delete a1[\"constructor\"];}zxkssw();");
/*fuzzSeed-169986037*/count=548; tryItOut("o2.t0 = o2.t2.subarray(5,  /x/g );");
/*fuzzSeed-169986037*/count=549; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return Math.imul(Math.fround(( + Math.log10((x >> Math.max(2**53+2, y))))), ( + Math.hypot(( + mathy0(Math.fround(Math.sqrt(Math.fround(y))), (( - (( + ( ~ (x | 0))) >>> 0)) >>> 0))), ( + Math.pow(Math.fround((((( + (Math.max(x, x) >>> 0)) | 0) !== (y >>> 0)) | 0)), Math.fround((( ! (( ! ( + y)) | 0)) >>> 0))))))); }); ");
/*fuzzSeed-169986037*/count=550; tryItOut("print(uneval(o1));");
/*fuzzSeed-169986037*/count=551; tryItOut("switch(x >>> (function ([y]) { })()) { case 5: break; print(x);case x = Proxy.createFunction(({/*TOODEEP*/})(w), \"\\uD4BF\"): break; case ({a2:z2}): for (var v of f1) { try { v1 = g0.runOffThreadScript(); } catch(e0) { } try { t0 = t0.subarray(1, 19); } catch(e1) { } g0.v2 = g2.eval(\"v1 = (f1 instanceof e1);\"); } }");
/*fuzzSeed-169986037*/count=552; tryItOut("\"use strict\"; c = new ((4277))((4277)), klovjn, e = this.__defineSetter__(\"x\", ReferenceError), hhwrzr, z, dgrfvf, c, NaN, aeyfdf;/*RXUB*/var r = /\u0095{4,4}{1}|\\W(\\b\\b|((?=\\b))+?){0,0}{2,}|\\3^(?=.){1,}\\B{0,1}{0,}/yim; var s = \"aaaaaa\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=553; tryItOut("e1.has(i1);");
/*fuzzSeed-169986037*/count=554; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.hypot(Math.fround(mathy0((((Math.imul(y, x) | 0) ^ (Math.fround(mathy1(Math.fround(Math.fround(Math.atanh(Math.fround(x)))), Math.fround(x))) | 0)) | 0), ( - (x | 0)))), ( + (( + Math.sinh(Math.imul(Math.fround(( + ( ~ (x | 0)))), (1 >>> 0)))) >>> 0))) | 0); }); testMathyFunction(mathy2, [0x100000001, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53, -0x100000001, -(2**53+2), Number.MAX_VALUE, 0x080000001, 2**53+2, 0, -(2**53), -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0/0, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000000, 1, 1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x100000000, -0x100000000, 42, 2**53-2, 0x080000000, Number.MIN_VALUE, -1/0, -0x080000001, 0x0ffffffff, -0, 0x07fffffff, -Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=555; tryItOut("mathy5 = (function(x, y) { return ( - Math.fround(( + Math.fround(Math.exp(((( - 2**53) | 0) & (Math.max(y, Math.fround(Math.sinh(Math.fround(y)))) | 0))))))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x080000001, -(2**53+2), -0x080000000, 1, 2**53-2, 0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0x0ffffffff, 2**53, 0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, Math.PI, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0, 42, 0x100000001, -(2**53-2), 0/0, 0x07fffffff, 0x100000000, -0x100000000, -(2**53), 0, 0x0ffffffff, -1/0, -Number.MIN_VALUE, 1.7976931348623157e308, -0]); ");
/*fuzzSeed-169986037*/count=556; tryItOut("\"use strict\"; for (var v of h0) { try { m0.delete(i1); } catch(e0) { } m0.set(e1, m1); }");
/*fuzzSeed-169986037*/count=557; tryItOut("\"use strict\"; function shapeyConstructor(dewmus){return this; }/*tLoopC*/for (let x of /*FARR*/[ ''  & /(?=(.(?!\\D)|\u7ede|\\b|\u1053|[\\w\uf61c].{2,4}{8,}))|(?=\\b|(?=^)*X|\\w+)*/gyim, Math.round(length), (new ( /x/ )( /x/g )), /*MARR*/[Math.PI, new String(''), true, new String(''), Math.PI, true, true, true, true, new String(''), ({}), new String(''), new String(''), true, Math.PI, ({}), ({}), new String(''), true, new String(''), true, true, new String(''), true, new String(''), Math.PI, true, Math.PI, new String(''), Math.PI, Math.PI, ({}), new String(''), ({}), true, true, Math.PI, new String(''), new String(''), new String(''), true, ({}), true, ({}), true, Math.PI, ({}), true, true, new String(''), new String(''), true, new String(''), ({}), Math.PI, new String(''), new String(''), ({}), new String(''), ({}), Math.PI, true, true, ({}), Math.PI, ({}), new String(''), ({}), Math.PI, ({}), ({}), Math.PI, ({}), ({}), new String(''), Math.PI, new String(''), new String(''), true, Math.PI, Math.PI, Math.PI, ({}), Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, Math.PI, ({}), true, Math.PI, new String(''), Math.PI, Math.PI, true, true, ({}), new String(''), new String(''), Math.PI, true, Math.PI, ({}), Math.PI].sort(Uint16Array), this, (x), (yield {}), x]) { try{let krqdbp = shapeyConstructor(x); print('EETT'); print( /x/ );}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-169986037*/count=558; tryItOut("i2 = this.a2[this.v1];");
/*fuzzSeed-169986037*/count=559; tryItOut("/*hhh*/function wckhfy(e = x.unwatch(new String(\"7\")), { : window, x, eval: \u3056, y: {arguments[\"__proto__\"], x: x, \u3056: {x}, window: {}}, a: y}, ...\u3056){Array.prototype.pop.call(a2, o2);}wckhfy((4277) >>>= (4277).throw(()));");
/*fuzzSeed-169986037*/count=560; tryItOut("testMathyFunction(mathy2, [1.7976931348623157e308, 0x080000001, -(2**53+2), 2**53-2, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, 0.000000000000001, -0x100000000, -0x07fffffff, Number.MIN_VALUE, 0/0, -(2**53), 0x0ffffffff, -0x0ffffffff, 0, -1/0, 0x07fffffff, 0x080000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 42, -(2**53-2), Number.MAX_VALUE, 0x100000001, -Number.MAX_VALUE, 1/0, 2**53, 0x100000000, 1, -0x080000001, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, Math.PI]); ");
/*fuzzSeed-169986037*/count=561; tryItOut("mathy3 = (function(x, y) { return mathy0(mathy1((Math.cbrt(Math.imul(( + x), x)) >>> 0), Math.max((Math.sin(x) >>> 0), x)), ( ~ Math.fround(mathy0(( + Math.sqrt(( + Math.fround(Math.min(Math.fround(y), 0x080000000))))), ( + Math.imul(( + Math.atanh(y)), ( + Math.atan2(( + x), ( + Math.tanh(Math.PI)))))))))); }); testMathyFunction(mathy3, [0x0ffffffff, -0x080000001, 1/0, 1, -0x0ffffffff, 0x080000000, Number.MAX_VALUE, 0, -Number.MAX_SAFE_INTEGER, 0/0, Math.PI, -0x100000000, 0x100000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53-2), 2**53-2, Number.MIN_VALUE, 0x100000001, -0, -(2**53+2), 2**53+2, 0x080000001, -0x100000001, -1/0, 0.000000000000001, -Number.MAX_VALUE, -0x080000000, 42, 2**53, 0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=562; tryItOut("\"use asm\"; let (y) { print(false); }");
/*fuzzSeed-169986037*/count=563; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (((Math.fround(( - Math.fround((Math.fround((Math.fround((y == mathy2(( + x), (y >>> 0)))) === Math.imul(( ! x), ( + ( ~ ( + x)))))) < Math.fround(0.000000000000001))))) >>> 0) | (Math.fround((Math.fround(((Math.atanh(y) <= Math.fround(( ! (y | 0)))) | 0)) * Math.fround(Math.asinh(Math.imul(Math.atan2(mathy1((y >>> 0), Math.log1p(0x07fffffff)), ( + 0)), y))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000001, 2**53+2, 0x080000000, -0, Number.MIN_SAFE_INTEGER, 42, -0x080000000, -(2**53+2), 2**53-2, 0/0, 2**53, -0x0ffffffff, 0x07fffffff, 0x080000001, -0x080000001, 1.7976931348623157e308, -(2**53-2), Number.MIN_VALUE, Math.PI, -1/0, -(2**53), 0, 1, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, -Number.MAX_VALUE, 1/0, -0x100000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-169986037*/count=564; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Uint32ArrayView[((!(0xffffffff))) >> 2]) = ((((NaN) != (+(0.0/0.0))) ? (+((-(((0xfa8b497b) ? (0xf96c8968) : (0x6103a897)))) >> ((0xb36f0de8)))) : (d1)));\n    d0 = (+((((0x31cf0d85)))>>>((0xf56c196c)-(0xdf655606))));\n    return +((d1));\n    {\n      d1 = (d1);\n    }\n    {\n      return +((((d1)) * ((NaN))));\n    }\n    (Uint32ArrayView[2]) = ((0x4e96c31f)*0x34984);\n    return +((((+(((-0x8000000)) & (window = Proxy.create(({/*TOODEEP*/})(x), this))))) / ((d1))));\n  }\n  return f; })(this, {ff: -21}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [42, -Number.MIN_VALUE, 1, 1.7976931348623157e308, 0.000000000000001, Number.MIN_VALUE, 2**53-2, -1/0, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0/0, 0x100000000, -0x07fffffff, -(2**53), -0, 0x07fffffff, 0x100000001, -Number.MAX_SAFE_INTEGER, 0, Number.MAX_VALUE, 2**53+2, 0x080000001, -(2**53+2), 0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x100000000, 2**53, 1/0, -0x0ffffffff, -0x080000000]); ");
/*fuzzSeed-169986037*/count=565; tryItOut("(({a1:1}));\no1.p1 = Proxy.create(h2, a1);\n");
/*fuzzSeed-169986037*/count=566; tryItOut("v2 = evalcx(\"(eval(\\\"print(x);\\\", window))\", g0);");
/*fuzzSeed-169986037*/count=567; tryItOut("testMathyFunction(mathy4, [1, 0/0, 1/0, -0, 0x0ffffffff, -Number.MAX_VALUE, 0x080000001, -0x100000001, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53-2), 0x080000000, -(2**53), 0.000000000000001, 0x100000001, 2**53+2, Number.MIN_VALUE, -(2**53+2), -0x100000000, 0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, Number.MAX_SAFE_INTEGER, 42, -Number.MIN_VALUE, 2**53-2, -0x080000000, -0x080000001, 1.7976931348623157e308, Math.PI, -0x07fffffff, -1/0, 0x07fffffff, 0x100000000, -0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=568; tryItOut("\"use strict\"; g0.v2 = r0.test;");
/*fuzzSeed-169986037*/count=569; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((((((( + (Math.fround(Math.exp(( ~ Math.fround(Math.hypot(Math.fround(-0x07fffffff), x))))) >> ( + ( + ( ~ y))))) | 0) * (Math.cosh(Math.cos(( + Math.hypot((Math.exp(2**53-2) >>> 0), (Math.imul(( + 2**53), (x >>> 0)) >>> 0))))) | 0)) | 0) >>> 0) ? mathy2((((Math.sign(0x100000001) | 0) == (( ~ x) | 0)) | 0), Math.trunc(Math.asin(( + Math.max(( + y), ( + x)))))) : (( ~ Math.pow(mathy0((Number.MIN_SAFE_INTEGER < ( + Math.expm1(( + y)))), ( - Math.fround(Math.atan(( + y))))), (Math.max(x, ( - -0x080000000)) >>> 0))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-169986037*/count=570; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.fround(Math.hypot((mathy0((y < Math.atan2(( + ((x - y) % (x & y))), Math.fround(mathy1(Math.fround(( + Math.max(( + 0), ( + x)))), Math.fround(Math.pow((0.000000000000001 >>> 0), y)))))), (Math.pow((Math.fround(y) + y), (Math.round((y >>> 0)) >>> 0)) % Math.fround(( ! -Number.MIN_VALUE)))) | 0), (Math.fround((( + y) && Math.fround(( + y)))) == Math.trunc(Math.acos(Math.fround(Math.max(Math.fround(( + ( ~ (Math.exp(y) | 0)))), x))))))); }); testMathyFunction(mathy2, [0/0, 2**53-2, -(2**53-2), 0x07fffffff, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, 0x080000001, 0x0ffffffff, -0x080000001, 0x080000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0, 1/0, 0, 2**53, -(2**53), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Math.PI, Number.MAX_VALUE, 42, -0x080000000, -0x07fffffff, 1, -1/0, -0x100000001, 2**53+2, -Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-169986037*/count=571; tryItOut("v2 = g0.eval(\"mathy0 = (function(x, y) { \\\"use strict\\\"; return Math.trunc(((((0/0 | 0) ? (( + ( - ( + ( + y)))) >>> 0) : Math.fround(( ! Math.log10(Math.max(Math.fround(y), Math.fround(y)))))) & (Math.atan2(Math.fround(( ! -0x100000000)), (( - (x ** -1/0)) | 0)) >>> 0)) | 0)); }); testMathyFunction(mathy0, [0, Number.MIN_SAFE_INTEGER, 1, 0.000000000000001, Math.PI, -0x07fffffff, 2**53, -0x100000000, 0x080000000, -0x080000000, 0x100000000, 1.7976931348623157e308, -0x100000001, -0x0ffffffff, 0x07fffffff, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, 0/0, Number.MAX_VALUE, -(2**53+2), -0, -0x080000001, -Number.MAX_VALUE, 42, 0x0ffffffff, 2**53-2, -Number.MIN_VALUE, 2**53+2, -(2**53), -1/0, Number.MIN_VALUE]); \");");
/*fuzzSeed-169986037*/count=572; tryItOut("var t0 = t1.subarray(x);");
/*fuzzSeed-169986037*/count=573; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-(2**53-2), 2**53-2, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 1.7976931348623157e308, -0x07fffffff, -0x100000000, -Number.MIN_VALUE, 2**53+2, 0/0, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 2**53, -0x100000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000000, 0, -(2**53), 42, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001, 0x100000000, 1/0, Math.PI, -0, -0x080000001, 0x080000000]); ");
/*fuzzSeed-169986037*/count=574; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=575; tryItOut("mathy5 = (function(x, y) { return (( + (Math.atan2(Math.max(( + (x == ( + mathy0(y, Math.ceil(y))))), ( + ( ~ Math.fround(Math.sqrt(y))))), Math.imul(( + ( ~ -Number.MIN_VALUE)), Math.min(Math.log(y), x))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-169986037*/count=576; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    {\n      i0 = (i0);\n    }\n    (Float32ArrayView[((i1)) >> 2]) = ((-144115188075855870.0));\n    {\n      switch ((0x7a5ac802)) {\n        case 1:\n          (Float32ArrayView[(0xfffff*(((((((0xfdfb31bd))>>>((0x30cf04f1))))+(i1))|0))) >> 2]) = ((+(0.0/0.0)));\n          break;\n        case 0:\n          (Int8ArrayView[((i1)) >> 0]) = ((/*FFI*/ff(((Infinity)), ((((i1)) ^ ((((i1)*-0xd18b2)|0) / (((i0))|0)))), (((((-0x8000000) > (((0xfbb94737)+(0xb26ea521)) >> ((0xfd614251)+(0xfa9f9e96)-(0xdaae61db))))) << ((i1)+(0x94e19a9d)))))|0));\n          break;\n        default:\n          (Float64ArrayView[1]) = ((-1.0078125));\n      }\n    }\n    /*FFI*/ff((((i1))));\n    i1 = ((abs((imul((i1), ((+(0.0/0.0)) == (-3.8685626227668134e+25)))|0))|0));\n    return ((-0x3760d*(i0)))|0;\n  }\n  return f; })(this, {ff: ({x: \"\\u3A31\".throw(null)})}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x0ffffffff, 2**53-2, -(2**53+2), 0.000000000000001, -(2**53), Number.MIN_SAFE_INTEGER, 42, -(2**53-2), 0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MAX_VALUE, 0x0ffffffff, 0x100000001, 1.7976931348623157e308, 0x080000000, -0x07fffffff, -0, 2**53, -0x100000000, 0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -0x080000001, -0x080000000, -1/0, 2**53+2, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, 1/0, 0x07fffffff, 0/0, 0x080000001, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=577; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +((+(1.0/0.0)));\n  }\n  return f; })(this, {ff: offThreadCompileScript}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0.000000000000001, 0/0, Number.MAX_VALUE, 1/0, -0x07fffffff, Math.PI, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -(2**53-2), -1/0, -(2**53), 0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x080000001, 0x0ffffffff, -Number.MIN_VALUE, 0x100000001, 2**53-2, -0, -0x080000001, 2**53, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, 42, -(2**53+2), 1, -0x100000001, 0x07fffffff, -0x080000000, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-169986037*/count=578; tryItOut("\"use strict\"; e0.delete(a0);");
/*fuzzSeed-169986037*/count=579; tryItOut("\"use strict\"; /*ODP-3*/Object.defineProperty(t2, \"clz32\", { configurable: false, enumerable: true, writable: e, value: this.g1.t1 });");
/*fuzzSeed-169986037*/count=580; tryItOut("/* no regression tests found */for(let e in []);");
/*fuzzSeed-169986037*/count=581; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( ~ Math.min(( + ( - (Math.imul((x >>> 0), y) >= 0/0))), ( + ( + Math.pow(( + ( - ( ~ (( + -0x0ffffffff) == ( + (( + (Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))))), ( + x)))))) | 0); }); testMathyFunction(mathy3, [1/0, 0x100000000, -1/0, -0, Math.PI, -(2**53), 2**53-2, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x0ffffffff, 0x080000001, -0x080000000, 1, 0/0, -(2**53+2), -Number.MAX_VALUE, -(2**53-2), 1.7976931348623157e308, 0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, 42, -0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000000, 2**53+2, -0x100000000, -Number.MIN_VALUE, 0.000000000000001, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=582; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.log1p(( ~ (((Math.atanh(y) | 0) >>> 0) >= ((( + ( + (( + (Math.cos((Math.fround(Math.cos(Math.fround(x))) >>> 0)) | 0)) != ( + y)))) ^ (( + (Math.atan2(( + -1/0), x) >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), -0x100000000, 2**53, -0x07fffffff, -0x100000001, -0x080000000, Math.PI, 0x080000001, 1.7976931348623157e308, 1, -(2**53), 0x100000001, -Number.MAX_VALUE, -(2**53+2), 0.000000000000001, 1/0, -Number.MAX_SAFE_INTEGER, 2**53+2, 0x07fffffff, -1/0, 0x100000000, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, -0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, 0, 0/0, -0, 0x080000000, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=583; tryItOut("mathy5 = (function(x, y) { return Math.max(Math.hypot(( ! Math.fround(Math.min((x - y), Math.fround(mathy1(Math.fround(( - Math.fround(y))), (x && x)))))), ( + (y / (Math.clz32((mathy3(( + (0.000000000000001 + y)), x) | 0)) | 0)))), (Math.pow(((Math.ceil((Math.abs((42 >>> 0)) | 0)) | 0) | 0), (( ~ ( + ( + x))) | 0)) | 0)); }); ");
/*fuzzSeed-169986037*/count=584; tryItOut("var mfefuj = new SharedArrayBuffer(0); var mfefuj_0 = new Int32Array(mfefuj); print(mfefuj_0[0]); mfefuj_0[0] = 7; var mfefuj_1 = new Uint32Array(mfefuj); mfefuj_1[0] = 24; var mfefuj_2 = new Uint16Array(mfefuj); print(mfefuj_2[0]); mfefuj_2[0] = -17; this.e2.has(b0);g2.b2.toSource = f2;this.o1.v1 = evalcx(\"function f2(this.t2) \\\"use asm\\\";   function f(i0, d1)\\n  {\\n    i0 = i0|0;\\n    d1 = +d1;\\n    return (((0x652a2afb)))|0;\\n  }\\n  return f;\", g2);");
/*fuzzSeed-169986037*/count=585; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(v2, this.o0);");
/*fuzzSeed-169986037*/count=586; tryItOut("\"use strict\"; if(false) {print(length.valueOf(\"number\"));print(x); } else  if (x) {m0.get(i0);print(x); } else {print(x);this.v2 = evalcx(\"a1.push(m0, s0, h0);\", g1); }");
/*fuzzSeed-169986037*/count=587; tryItOut("mathy1 = (function(x, y) { return (( + (( + (Math.pow(( - x), (Math.min(( + -0x0ffffffff), -0x080000001) !== x)) | 0)) | 0)) | 0); }); testMathyFunction(mathy1, [0, -0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 0x0ffffffff, -Number.MIN_VALUE, 0x080000000, -0x080000000, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53), -0x07fffffff, Math.PI, 1/0, 42, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -1/0, Number.MIN_VALUE, 1, 0x100000001, 0/0, 0.000000000000001, -(2**53-2), -0x080000001, -0x100000001, -0x100000000, Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000001, 2**53+2, -Number.MAX_VALUE, 1.7976931348623157e308, 2**53, 2**53-2]); ");
/*fuzzSeed-169986037*/count=588; tryItOut("v1 = evalcx(\"function f2(b0)  { \\\"use strict\\\"; yield x } \", o0.o2.g1);");
/*fuzzSeed-169986037*/count=589; tryItOut("mathy2 = (function(x, y) { return ( ~ Math.min(Math.sin(y), (( + (Math.cos((Math.tanh(x) >>> 0)) >>> 0)) , ( + mathy0(x, Math.sqrt((Math.max(-0x100000000, ( + -Number.MIN_VALUE)) | 0))))))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1.5), null, new Boolean(true), new Number(1.5), new Number(1.5), x, null, x, null, null, new Number(1.5), x, null, new Number(1.5), new Number(1.5), new Number(1.5), 0x40000001, new Number(1.5), x, null, 0x40000001, null, x, x, x, null, new Boolean(true), new Boolean(true), new Boolean(true), x, null, null, new Number(1.5), null, new Number(1.5), 0x40000001, 0x40000001, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, x, null, 0x40000001, x, new Number(1.5), null, null, new Boolean(true), null, null, new Number(1.5), new Number(1.5), new Boolean(true), x, x, null, x, new Boolean(true), null, null, 0x40000001, null, x, null, new Boolean(true), 0x40000001, new Number(1.5), x, null, x, null, 0x40000001, 0x40000001, new Number(1.5), null, null, 0x40000001, new Number(1.5), 0x40000001, x, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0x40000001, null, new Number(1.5), new Boolean(true), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Boolean(true), 0x40000001, new Boolean(true), x, x, new Boolean(true), x, new Number(1.5), new Boolean(true), null, null, new Boolean(true), null, null, null, new Number(1.5), new Number(1.5), new Boolean(true), x, x]); ");
/*fuzzSeed-169986037*/count=590; tryItOut("/*ADP-3*/Object.defineProperty(a2, 15, { configurable: true, enumerable: (x % 23 == 4), writable: (4277), value: g0.f2 });");
/*fuzzSeed-169986037*/count=591; tryItOut("\"use strict\"; v1 = new Number(-Infinity);");
/*fuzzSeed-169986037*/count=592; tryItOut("Array.prototype.forEach.apply(a0, [(function(a0, a1, a2, a3) { var r0 = x * a0; var r1 = a1 - r0; print(a3); var r2 = a1 % 4; var r3 = x / a1; var r4 = a1 & x; var r5 = r4 % a1; a3 = r2 + 9; var r6 = a0 ^ 7; print(r2); var r7 = r2 / a1; r7 = r3 * 0; var r8 = 4 - r1; print(a3); var r9 = a2 + r6; r5 = a2 * a0; var r10 = 6 / r9; var r11 = x * r8; var r12 = a0 / 3; var r13 = 2 ^ 4; r9 = 6 & 1; var r14 = r0 - a3; var r15 = a0 % r7; var r16 = a0 * 4; a0 = r4 * r15; r11 = r0 / 3; var r17 = r16 ^ 3; var r18 = 5 / r13; return a0; })]);");
/*fuzzSeed-169986037*/count=593; tryItOut("mathy3 = (function(x, y) { return ( ! ( - ( ~ Math.min(( ! x), Math.fround((Math.fround(y) > Math.fround(Math.cbrt(Math.cbrt(x))))))))); }); testMathyFunction(mathy3, [-Number.MAX_SAFE_INTEGER, 42, 0x080000000, -(2**53), 2**53-2, -0x100000001, Number.MIN_VALUE, -0x080000001, 0x080000001, 2**53+2, -0x080000000, -0x0ffffffff, -0x100000000, 2**53, 1.7976931348623157e308, -(2**53-2), 0x100000000, 0/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 1, 0x0ffffffff, 0x100000001, Math.PI, -1/0, 1/0, -0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=594; tryItOut("a0 = arguments;const a = ( '' )();\n/*infloop*/for(let c = x; let (d = window) b ? ++(y) : (void shapeOf(window)); ((function a_indexing(mijnhm, vzfulp) { print((/*UUV2*/(b.toString = b.sqrt)));; if (mijnhm.length == vzfulp) { ; return (4277); } var vevlle = mijnhm[vzfulp]; var lwbyvp = a_indexing(mijnhm, vzfulp + 1); for (var p in s0) { for (var v of t0) { try { e0.add(t2); } catch(e0) { } try { v1 = (t0 instanceof v2); } catch(e1) { } try { h2.valueOf = (function mcc_() { var kjyujl = 0; return function() { ++kjyujl; if (/*ICCD*/kjyujl % 9 == 8) { dumpln('hit!'); s1 + h0; } else { dumpln('miss!'); try { a0.forEach((function() { try { h0 + ''; } catch(e0) { } try { for (var v of b1) { try { m0.has(s1); } catch(e0) { } try { e0.add(v1); } catch(e1) { } try { v0 = g2.eval(\"a0.push(v0, new RegExp(\\\"(?![^]^*.^|[\\\\\\\\b-\\\\u4be9]{2}(?=(?=\\\\\\\\B)))[^]|((\\\\\\\\b))\\\", \\\"gi\\\"));\"); } catch(e2) { } Object.freeze(t0); } } catch(e1) { } v2 = g0.runOffThreadScript(); return v1; })); } catch(e0) { } try { o0[new String(\"-11\")] = p2; } catch(e1) { } print(s2); } };})(); } catch(e2) { } v1 = (i1 instanceof g2); } } })(/*MARR*/[new Number(1), true, true, Number.MAX_VALUE, true, true, null, Number.MAX_VALUE, null, true, Number.MAX_VALUE, null, true, null], 0))) (void schedulegc(g0));\n");
/*fuzzSeed-169986037*/count=595; tryItOut("\"use strict\"; print(x !== -18.valueOf(\"number\"));");
/*fuzzSeed-169986037*/count=596; tryItOut("/*ODP-2*/Object.defineProperty(o0.i2, \"__parent__\", { configurable: ((makeFinalizeObserver('nursery'))), enumerable: true, get: f2, set: (function() { for (var j=0;j<25;++j) { f2(j%5==1); } }) });");
/*fuzzSeed-169986037*/count=597; tryItOut("g0.m0.get(v1);");
/*fuzzSeed-169986037*/count=598; tryItOut("\"use strict\"; print(x -= w /= x);");
/*fuzzSeed-169986037*/count=599; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.cos(( ~ (( - (((y | 0) + Math.pow(( + 0.000000000000001), 2**53+2)) | 0)) | 0))); }); testMathyFunction(mathy1, [-1/0, 0, 1, -Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53), 0x07fffffff, 0x0ffffffff, -(2**53-2), -0x07fffffff, -0x100000000, 0.000000000000001, -0, -0x080000001, 0/0, Number.MAX_VALUE, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 0x080000001, 1.7976931348623157e308, -Number.MAX_VALUE, 0x100000001, -(2**53+2), 2**53+2, -0x0ffffffff, 1/0, 2**53-2, Math.PI, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_VALUE, -0x100000001, 2**53]); ");
/*fuzzSeed-169986037*/count=600; tryItOut("o0.f1 = (function(j) { f0(j); });");
/*fuzzSeed-169986037*/count=601; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return (( + Math.log1p(( + mathy0(( + ( - x)), x)))) && Math.min(( + (x | 0)), Math.min((((Math.asinh(Math.hypot(x, 2**53-2)) | 0) | 0) ? ( ! y) : ( + -0x080000001)), (( + Math.imul(1, y)) % (Math.tan((y >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [-(2**53), 2**53-2, -0x100000000, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, -Number.MAX_VALUE, 1, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -0, 2**53+2, 0, 0/0, 2**53, -0x0ffffffff, 0x080000001, 0x100000001, Math.PI, 0.000000000000001, 42, -Number.MIN_VALUE, -0x080000001, 0x100000000, 0x07fffffff, -0x080000000, Number.MIN_VALUE, 0x080000000, -(2**53+2), 0x0ffffffff, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=602; tryItOut("const x;\na0 = arguments.callee.caller.arguments;");
/*fuzzSeed-169986037*/count=603; tryItOut("if(true) { if (((intern(Math.max(({a2:z2}), true))).eval(\"\\\"use strict\\\"; \"))) {v2 = g2.runOffThreadScript();/*ODP-2*/Object.defineProperty(h0, \"toString\", { configurable: true, enumerable: (x % 3 == 0), get: f2, set: Object.getOwnPropertyDescriptor }); }} else {for (var p in m0) { print(g2.o0); }/*MXX1*/o2 = g0.Promise.prototype.constructor;\nprint((a % x));\n }");
/*fuzzSeed-169986037*/count=604; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.fround(Math.pow((( ! ( ! (Math.tan(y) >>> 0))) >>> 0), Math.fround(((((mathy2((( + Math.min((y || Math.atan2(y, (Math.imul(2**53, y) | 0))), ( + x))) | 0), ((Math.fround((Math.fround(Math.fround(( + x))) ? Math.fround((((y | 0) ** (x | 0)) >>> 0)) : y)) * ((( - y) >>> 0) ? (((y | 0) && 0) | 0) : Math.fround((x >= -0x100000001)))) | 0)) | 0) >>> 0) ** (Math.cos((Math.fround(Math.pow(( + Math.fround((Math.fround(x) - Math.fround(x)))), ( + y))) == Math.fround(( ! Math.fround(Math.fround(( ! (x >>> 0)))))))) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, /*MARR*/[Math.PI, Math.PI, x,  /x/ , 2**53-2, x,  /x/ ,  /x/ , x, x,  /x/ , 2**53-2, Math.PI, 2**53-2,  /x/ ,  /x/ , x, x, 2**53-2, 2**53-2, (4277),  /x/ , x, Math.PI, 2**53-2, Math.PI, Math.PI, x,  /x/ , (4277),  /x/ ,  /x/ , (4277),  /x/ , (4277), (4277), (4277), (4277), x, x, Math.PI, (4277), 2**53-2, (4277), Math.PI, 2**53-2, 2**53-2, x]); ");
/*fuzzSeed-169986037*/count=605; tryItOut("\"use strict\"; v1 = g1.runOffThreadScript();");
/*fuzzSeed-169986037*/count=606; tryItOut(";");
/*fuzzSeed-169986037*/count=607; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.fround(Math.clz32(((Math.cbrt(Math.fround(Math.fround(mathy3(Math.fround(y), Math.fround((Math.asinh((y | 0)) | 0)))))) === ( + Math.max(( + x), ( + x)))) | 0)))); }); testMathyFunction(mathy4, [0x080000000, 2**53-2, 2**53, Number.MAX_SAFE_INTEGER, -0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0, 0/0, 1, 42, -(2**53), 0.000000000000001, -0x0ffffffff, -0x080000001, 0x080000001, -1/0, -0x100000001, 1.7976931348623157e308, 0x100000000, 1/0, Math.PI, -0x100000000, -0x080000000, -0x07fffffff, 2**53+2, Number.MAX_VALUE, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=608; tryItOut("\"use strict\"; h2.set = f2;");
/*fuzzSeed-169986037*/count=609; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(( ! Math.fround(( ~ (( + ( + (x == ( + y)))) / ( + ( ! Math.fround((1/0 >> (x ? y : x)))))))))); }); testMathyFunction(mathy1, [[], '/0/', NaN, (new Number(0)), 1, (new String('')), 0, '', undefined, [0], /0/, true, (function(){return 0;}), null, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Boolean(false)), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '\\0', -0, (new Number(-0)), '0', false, (new Boolean(true)), 0.1]); ");
/*fuzzSeed-169986037*/count=610; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-169986037*/count=611; tryItOut("g2.v1 = Object.prototype.isPrototypeOf.call(s0, m0);");
/*fuzzSeed-169986037*/count=612; tryItOut("\"use strict\"; \"use asm\"; mathy4 = (function(x, y) { return (Math.tan((( + mathy1(( + (2**53+2 & Math.hypot(x, (Math.imul(x, Math.imul(Math.fround(Number.MIN_VALUE), y)) >>> 0)))), Math.sign((mathy3(Math.pow(x, y), (x || Math.fround(( ! ( + y))))) | 0)))) | 0)) | 0); }); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000000, -0x080000001, -0x080000000, -(2**53-2), 0x0ffffffff, 0x100000001, Number.MAX_SAFE_INTEGER, 1, 0, -0x100000001, -Number.MAX_VALUE, 2**53-2, -(2**53), Number.MAX_VALUE, Math.PI, -(2**53+2), 1/0, -0x07fffffff, 2**53+2, 0/0, 0x100000000, 2**53, -1/0, -0x0ffffffff, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, 0x080000001, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, -Number.MIN_VALUE, -0]); ");
/*fuzzSeed-169986037*/count=613; tryItOut("m1.set((eval(\"\\\"use strict\\\"; a0 = r2.exec(this.s1);\", x)), t1);");
/*fuzzSeed-169986037*/count=614; tryItOut("((-27 % null).yoyo(--c));");
/*fuzzSeed-169986037*/count=615; tryItOut("o0.v1 = Object.prototype.isPrototypeOf.call(f2, g0.i2);");
/*fuzzSeed-169986037*/count=616; tryItOut("w;");
/*fuzzSeed-169986037*/count=617; tryItOut("L:for(var e in (new (Array.of)(-24, /[^\\D\\w]/yim))) /*infloop*/for(y; Object.defineProperty(x, \"floor\", ({enumerable: \"\\u1341\"})); -20.__defineGetter__(\"window\", Object.seal)) {m1.delete(g0);s0 += s2; }");
/*fuzzSeed-169986037*/count=618; tryItOut("mathy2 = (function(x, y) { return ( - ( ~ ( + ( - ( ~ x))))); }); testMathyFunction(mathy2, [-1/0, Math.PI, -0x080000001, 0x080000000, 1/0, 0x100000001, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_VALUE, -0x100000001, 2**53-2, -0x080000000, 2**53+2, 1.7976931348623157e308, -0x100000000, 0.000000000000001, 0x100000000, -(2**53+2), -Number.MAX_VALUE, -0x07fffffff, 0x07fffffff, 0, 0/0, -0, Number.MIN_VALUE, 2**53, 42, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, -Number.MIN_VALUE, 1]); ");
/*fuzzSeed-169986037*/count=619; tryItOut("const vekosu, x = Math.hypot(9, /\\1|\\b|\\2|(?=${3,}(?=[\ub6cd\\b-\ua127\\u0069-\u00a1\u0017-\\x9E]))(?=\\2+?)/im /  '' );v0 = Object.prototype.isPrototypeOf.call(g0, this.t1);");
/*fuzzSeed-169986037*/count=620; tryItOut("Array.prototype.reverse.apply(a1, []);");
/*fuzzSeed-169986037*/count=621; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, 0x07fffffff, -0x100000000, 0x080000000, -0x080000001, -Number.MAX_VALUE, 42, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, Math.PI, 2**53+2, 0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x100000000, -0x100000001, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53, -0, -(2**53-2), Number.MIN_VALUE, -0x0ffffffff, 0.000000000000001, 0/0, Number.MAX_VALUE, -(2**53), 1/0, 0x100000001, 2**53-2]); ");
/*fuzzSeed-169986037*/count=622; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.pow(Math.fround((mathy0((mathy0(((y ? x : 2**53-2) / Math.fround(Math.fround(0x100000001))), 1.7976931348623157e308) >>> 0), (Math.fround(Math.acosh((Math.expm1(x) >= ( + (( + Number.MAX_VALUE) , ( + y)))))) >>> 0)) >>> 0)), Math.fround(Math.max(y, y))) | 0) - (Math.fround((Math.fround(mathy0((( + ( - -0x100000001)) | 0), (( ~ 2**53+2) | 0))) >>> (( + (( - x) >>> 0)) >>> 0))) | 0)); }); testMathyFunction(mathy1, [-(2**53), 1/0, Number.MIN_SAFE_INTEGER, -0x100000001, 2**53, -0x07fffffff, 1, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000000, 42, 0/0, -(2**53+2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MIN_VALUE, 0, 0x100000000, 0x0ffffffff, -(2**53-2), -1/0, 0x080000000, 1.7976931348623157e308, -0x080000001, -0, 0x080000001, 2**53-2, 0x07fffffff, 0x100000001, 2**53+2, 0.000000000000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=623; tryItOut("o0.e1.add(x);");
/*fuzzSeed-169986037*/count=624; tryItOut("\"use strict\"; selectforgc(o1);");
/*fuzzSeed-169986037*/count=625; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2((( ~ (( + ((( + Math.ceil(x)) | 0) != ( + x))) >>> 0)) | 0), ((Math.tan((mathy1((Math.log10((( + Math.tan(y)) | 0)) | 0), Math.fround(Math.max((((x >>> 0) !== x) >>> 0), (Math.fround(( ! Math.fround(-0x080000001))) || ((y | 0) <= y))))) >>> 0)) >>> 0) | 0)) | 0); }); testMathyFunction(mathy3, /*MARR*/[function(){}, objectEmulatingUndefined(), f2(o1);, f2(o1);, function(){}, function(){}, function(){}, f2(o1);, objectEmulatingUndefined(), function(){}]); ");
/*fuzzSeed-169986037*/count=626; tryItOut("\"use strict\"; /*tLoop*/for (let b of /*MARR*/[new String('q'), this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, [[]], [[]], new String('q'), new String('q'), this, [[]], new String('q'), this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, this, new String('q'), this, this, this, [[]], this]) { h0.toSource = (function() { try { v2 = a2.length; } catch(e0) { } try { this.s2 += s0; } catch(e1) { } try { v0 = t1.byteOffset; } catch(e2) { } for (var p in o2) { try { a2.sort((function(j) { f0(j); })); } catch(e0) { } try { var v2 = evalcx(\"{}\", g2); } catch(e1) { } try { /*MXX1*/o1 = g0.String.prototype.indexOf; } catch(e2) { } t2 = s1; } return m1; }); }");
/*fuzzSeed-169986037*/count=627; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (( - (((Math.sign(( ~ Math.atan2((Math.fround(Math.hypot((Math.log10((y >>> 0)) | 0), 0/0)) | 0), -Number.MAX_SAFE_INTEGER))) | 0) ^ Math.max(Math.hypot((Math.cosh(x) >>> 0), x), Math.asinh(x))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53-2, 1/0, 0x080000000, 2**53+2, 0.000000000000001, 0x07fffffff, 1, 0x080000001, -0, -0x080000001, Number.MAX_VALUE, -(2**53+2), -0x07fffffff, -(2**53), Number.MAX_SAFE_INTEGER, 0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, -0x100000001, 42, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, 0, -(2**53-2), 2**53, Number.MIN_VALUE, -0x080000000, -0x100000000, 0x0ffffffff, 0/0]); ");
/*fuzzSeed-169986037*/count=628; tryItOut("/*bLoop*/for (gjyrek = 0; gjyrek < 46; ++gjyrek) { if (gjyrek % 3 == 1) { v0 = Array.prototype.every.apply(this.a1, [(function() { for (var j=0;j<4;++j) { f0(j%4==1); } })]); } else {  /x/g ; }  } ");
/*fuzzSeed-169986037*/count=629; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=630; tryItOut("\"use strict\"; a2.unshift(m2, b0);");
/*fuzzSeed-169986037*/count=631; tryItOut("m2.set(s1, o1.m1);");
/*fuzzSeed-169986037*/count=632; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.imul(Math.atan2((( ! ( - Math.fround(Number.MIN_SAFE_INTEGER))) | 0), ( ~ (( + Math.max(x, x)) | 0))), Math.fround(((( ! (Math.max(x, x) ? Math.imul(x, x) : Math.fround(Math.tanh((x ^ y))))) | 0) != Math.fround(( ~ Math.fround(Math.ceil(((Math.pow(((Math.atan2(x, x) | 0) < -0x100000001), y) | 0) >>> 0)))))))); }); testMathyFunction(mathy5, [0x07fffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, 0x0ffffffff, 42, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, -0x100000001, -0x080000000, -0x0ffffffff, 0x100000001, -(2**53+2), -Number.MAX_VALUE, 2**53+2, 0.000000000000001, -Number.MIN_VALUE, 0, 0x080000000, Number.MIN_SAFE_INTEGER, -0, 1, -0x07fffffff, 1/0, -1/0, 2**53, 2**53-2, Number.MIN_VALUE, 0x080000001, -(2**53), Math.PI, Number.MAX_VALUE, 0/0]); ");
/*fuzzSeed-169986037*/count=633; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(Math.cosh(Math.imul((2**53 ? Math.trunc((-0x080000000 | 0)) : ( + (( ~ (x >>> 0)) >>> 0))), (Math.atan(Math.fround(( ! Math.atan2(y, y)))) | 0)))); }); testMathyFunction(mathy1, [0, 0x080000000, -Number.MIN_SAFE_INTEGER, 1, 0x100000001, 1/0, -0x07fffffff, 0/0, Number.MIN_SAFE_INTEGER, 2**53+2, 0.000000000000001, -0, -0x080000000, -0x0ffffffff, 0x07fffffff, Number.MAX_VALUE, 0x080000001, -(2**53+2), 1.7976931348623157e308, -Number.MAX_VALUE, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53), -1/0, -0x080000001, -Number.MIN_VALUE, 2**53, Number.MIN_VALUE, -(2**53-2), 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x100000000, 2**53-2, 0x100000000, 42, -0x100000001]); ");
/*fuzzSeed-169986037*/count=634; tryItOut("print(uneval(e1));");
/*fuzzSeed-169986037*/count=635; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( ~ ( + ( + ( + (( ~ ( + Math.asinh((Math.atan2(x, x) | 0)))) ? ( + (Math.pow(Math.fround((x <= (-(2**53+2) | 0))), 0x07fffffff) >>> 0)) : Math.fround((Math.asin(x) >>> 0))))))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, -0x080000001, 2**53, 2**53-2, 0x080000000, -0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, Math.PI, -Number.MIN_VALUE, -1/0, 0x100000000, 2**53+2, 0x0ffffffff, 0.000000000000001, 42, 1/0, 0, -(2**53-2), -0x07fffffff, -0x080000000, -(2**53+2), -(2**53), 0x07fffffff, 1, 0/0, -0x100000000, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001]); ");
/*fuzzSeed-169986037*/count=636; tryItOut("e2.add((yield (({z:  /x/g }))));");
/*fuzzSeed-169986037*/count=637; tryItOut("\"use strict\"; with({a:  \"\" })f1 = o0.v1;");
/*fuzzSeed-169986037*/count=638; tryItOut("e1.has(e1);");
/*fuzzSeed-169986037*/count=639; tryItOut("mathy0 = (function(x, y) { return Math.exp(Math.fround(( - ( + Math.imul(((((x <= x) | 0) ? Math.fround(( ~ x)) : -(2**53-2)) >>> 0), (( + Math.fround(( ~ Math.fround(( + Math.abs(( + y))))))) ? y : Math.fround(( + Math.fround(y))))))))); }); testMathyFunction(mathy0, [Number.MAX_VALUE, -1/0, 2**53-2, -0, -(2**53-2), 0x0ffffffff, -0x080000000, 0x080000001, 0/0, 0, Math.PI, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x080000001, 0.000000000000001, 1/0, 1.7976931348623157e308, -(2**53), 42, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 1, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53+2), Number.MAX_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, Number.MIN_VALUE, -0x100000000, -0x0ffffffff, -0x07fffffff, 2**53+2, 0x100000001]); ");
/*fuzzSeed-169986037*/count=640; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.atanh(( ~ ( + Math.atan2(mathy2((x , Math.fround(((Math.acos(x) == (Math.fround(mathy2(Math.fround(y), (x | 0))) >>> 0)) | 0))), y), (((Math.imul(y, ( ~ x)) >>> 0) * (x >>> 0)) ** (Math.pow(y, ( + ((y | 0) + Math.fround(x)))) >>> 0)))))); }); ");
/*fuzzSeed-169986037*/count=641; tryItOut("o0.v2 = t2.length;");
/*fuzzSeed-169986037*/count=642; tryItOut("mathy2 = (function(x, y) { return mathy1((Math.imul(((Math.cbrt(( + Math.fround(( ! Math.fround(( ~ Math.fround((y ? x : ( + (( + -0x07fffffff) < -Number.MAX_SAFE_INTEGER)))))))))) >>> 0) | 0), ((( + (( + Math.atan(Math.fround(Math.fround(( ! Math.fround(Math.acosh(Math.fround((y ? y : y))))))))) >>> 0)) >>> 0) | 0)) | 0), Math.sinh((Math.atan2((mathy0(y, (Math.hypot((x >>> 0), Math.fround(0x0ffffffff)) >>> 0)) >>> 0), y) > (((mathy1(x, y) >>> 0) - Math.imul(Math.fround(Math.fround((x !== Math.fround(1.7976931348623157e308)))), x)) >>> 0)))); }); testMathyFunction(mathy2, [Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, -0x100000000, -(2**53+2), 0x07fffffff, -0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53+2, -0, 0x100000001, 0x0ffffffff, 42, -1/0, -(2**53-2), 0, -0x0ffffffff, 2**53-2, 0/0, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1, Number.MIN_VALUE, 1/0, Number.MAX_VALUE, 0x080000001, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, 0x080000000, -(2**53), -0x080000000, 1.7976931348623157e308, 2**53]); ");
/*fuzzSeed-169986037*/count=643; tryItOut("mathy3 = (function(x, y) { return ( + ( ~ (( + Math.fround(( + Math.fround(mathy0(y, x))))) !== Math.cbrt((((mathy2(( + -Number.MIN_VALUE), -0x07fffffff) >>> 0) < (Math.pow(Math.sqrt(x), (y >>> -1/0)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [1, -0x100000001, Math.PI, -Number.MAX_VALUE, -0x100000000, 1/0, -(2**53-2), 0/0, -(2**53), 0x080000001, -0x080000000, -0x080000001, 2**53-2, -(2**53+2), -Number.MIN_VALUE, 0x100000001, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, 0, -0, 0.000000000000001, 0x07fffffff, 2**53+2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, -1/0, 0x080000000]); ");
/*fuzzSeed-169986037*/count=644; tryItOut("mathy0 = (function(x, y) { return Math.hypot((Math.atan2((( - y) >>> 0), Math.fround(((( + Math.fround((y >>> 0))) | 0) || ((Math.max(Math.fround(1/0), y) | 0) | 0)))) >>> 0), Math.max(( - Math.fround(( ~ Math.fround((0x080000000 ? y : Math.fround((Math.fround(( + Math.imul(y, y))) === Math.fround((y % -0x0ffffffff))))))))), (Math.min(((( + (x | 0)) | 0) >>> 0), ( + Math.hypot(x, x))) >>> 0))); }); testMathyFunction(mathy0, [Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_VALUE, 0/0, -0x100000001, 2**53, -0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, Math.PI, 1, 0x080000000, 2**53+2, 0x100000001, 0x0ffffffff, -0x100000000, 0.000000000000001, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, -1/0, -0x080000000, 0, -Number.MIN_VALUE, 42, 2**53-2, -(2**53-2), 0x07fffffff, -0, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, -0x0ffffffff, -(2**53+2), 0x100000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=645; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (((( + Math.tan(Math.atan2((( + mathy0(( + x), x)) / Math.fround(Math.acos(Math.fround(mathy2(2**53+2, x))))), Math.fround((y >>> ( + y)))))) >>> 0) >>> (Math.log2(( ! Math.fround(( ! Math.fround((( + mathy0(y, y)) , x)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy4, /*MARR*/[ \"\" ,  \"\" , NaN, 0x10000000, (1/0),  \"\" , 0x10000000]); ");
/*fuzzSeed-169986037*/count=646; tryItOut("h2.toString = (function() { v0 = g0.s2[\"x\"]; return o1.b0; });");
/*fuzzSeed-169986037*/count=647; tryItOut("mathy5 = (function(x, y) { return ( + ( ! (Math.clz32(mathy2(Math.fround(Math.log(( + x))), ( + Math.atan2(Math.pow((( + Math.round(y)) | 0), ((Math.fround(-0x100000000) == (y >>> 0)) >>> 0)), mathy1(-0x07fffffff, (0 == Math.imul(-Number.MIN_SAFE_INTEGER, y))))))) | 0))); }); testMathyFunction(mathy5, /*MARR*/[(1/0), (1/0), x, (1/0)]); ");
/*fuzzSeed-169986037*/count=648; tryItOut("");
/*fuzzSeed-169986037*/count=649; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((0x40697654) == (((/*FFI*/ff(((~~(1125899906842625.0))), ((((4294967297.0)) / ((7.737125245533627e+25)))), ((+(abs((((0xfa817388)) | ((-0x8000000))))|0))))|0))>>>((i1)+(!((NaN) <= (4398046511103.0)))-(!(i1)))))))|0;\n  }\n  return f; })(this, {ff: ArrayBuffer.isView}, new ArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=650; tryItOut("mathy0 = (function(x, y) { return ( - ( ~ ( + ( + ( + Math.fround(Math.max(Math.fround(2**53), Math.fround((Math.fround((Number.MIN_SAFE_INTEGER | 0)) | 0))))))))); }); testMathyFunction(mathy0, /*MARR*/[this, this, (-1/0), arguments, (-1/0), arguments, arguments, arguments, (-1/0), (-1/0), this, (-1/0), (-1/0), (-1/0)]); ");
/*fuzzSeed-169986037*/count=651; tryItOut("\"use strict\"; swsvdm(([]) = Set(10, ({a2:z2})), z);/*hhh*/function swsvdm(x, NaN){m1.get(a0);}");
/*fuzzSeed-169986037*/count=652; tryItOut("var i1 = new Iterator(o2.h2);");
/*fuzzSeed-169986037*/count=653; tryItOut("\"use strict\"; var r0 = 6 & x; r0 = r0 % 5; var r1 = 3 + x; var r2 = r1 & r1; var r3 = r1 | 3; r3 = 3 % r1; var r4 = 2 + r2; var r5 = r0 * 0; var r6 = r2 ^ r1; r6 = 0 % r3; var r7 = 7 & 3; print(r7); var r8 = x * r1; var r9 = 3 / 7; var r10 = r4 + r3; var r11 = 2 / r0; var r12 = r3 / r3; var r13 = r12 / r8; var r14 = 6 * r2; var r15 = r4 % 0; var r16 = r5 + r9; r14 = 6 ^ r16; print(r4); print(r16); var r17 = r0 % 6; var r18 = 5 / r14; var r19 = 6 / 8; var r20 = 8 | 9; var r21 = r9 - r0; var r22 = r2 ^ r17; var r23 = 3 + r3; var r24 = r23 | r3; var r25 = r22 - r13; var r26 = r24 % r24; var r27 = r4 ^ 1; print(r11); var r28 = r14 | r13; r0 = r1 / 2; r24 = r28 % r20; var r29 = r5 ^ 8; var r30 = 6 + 7; var r31 = r12 / r7; r9 = r16 + r15; r5 = r14 + r2; var r32 = 3 ^ r31; r29 = r15 * r18; var r33 = r11 + r0; var r34 = 2 / r26; ");
/*fuzzSeed-169986037*/count=654; tryItOut("v2 = Object.prototype.isPrototypeOf.call(t1, this.p0);");
/*fuzzSeed-169986037*/count=655; tryItOut("\"use strict\"; for (var v of f1) { try { selectforgc(o0.o1); } catch(e0) { } try { e0.has(b2); } catch(e1) { } try { a2 = a1.filter((function() { for (var j=0;j<39;++j) { f2(j%4==1); } }), t0); } catch(e2) { } for (var v of m2) { try { o1 + ''; } catch(e0) { } try { Array.prototype.push.apply(a0, [f0]); } catch(e1) { } i2.toString = f0; } }");
/*fuzzSeed-169986037*/count=656; tryItOut("\"use strict\"; Array.prototype.unshift.call(a0, g0);");
/*fuzzSeed-169986037*/count=657; tryItOut("this.t0[16] = offThreadCompileScript;");
/*fuzzSeed-169986037*/count=658; tryItOut("\"use strict\"; /*MXX3*/g1.g2.WeakSet.prototype.constructor = g2.WeakSet.prototype.constructor;");
/*fuzzSeed-169986037*/count=659; tryItOut("testMathyFunction(mathy5, [42, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -1/0, 0.000000000000001, 0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, 0/0, 0x080000000, -(2**53), 2**53, 0x100000001, -0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, 1, 1/0, 0, Math.PI, 2**53+2, -0x080000001, 0x100000000, -(2**53+2), -(2**53-2), -0x100000000, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=660; tryItOut("i0.valueOf = (function(j) { if (j) { try { v2 = t2.length; } catch(e0) { } v2 = a1.length; } else { try { /*MXX3*/g1.Object.create = g1.Object.create; } catch(e0) { } try { this.a2.__proto__ = s1; } catch(e1) { } try { f0.valueOf = (function() { g2.offThreadCompileScript(\"\\\"use strict\\\"; /*vLoop*/for (var frlsio = 0; frlsio < 0; ++frlsio) { const e = frlsio; a1 = r0.exec(s0); } \", ({ global: g2.g2, fileName: null, lineNumber: 42, isRunOnce: (makeFinalizeObserver('tenured')), noScriptRval: false, sourceIsLazy: false, catchTermination: /(?:\\1)/i })); return b2; }); } catch(e2) { } m0 + i0; } });");
/*fuzzSeed-169986037*/count=661; tryItOut("a2.splice(1, v1);");
/*fuzzSeed-169986037*/count=662; tryItOut("/*iii*//*iii*/e2 = m1.get(o1.p0);/*hhh*/function qctsrj(...ynauql){return undefined;}/*hhh*/function ynauql({z, NaN, w: x, z: x}, x = []){a2 = Array.prototype.map.apply(a2, [(function(j) { if (j) { try { v0.toString = mathy1; } catch(e0) { } try { Array.prototype.sort.call(a2, (function() { try { m2.set(t2, i0); } catch(e0) { } try { v0 = t0.length; } catch(e1) { } try { t1 = t2.subarray(10, 9); } catch(e2) { } f2 = Proxy.createFunction(h2, f2, f2); return a2; }), f2, o1, m1); } catch(e1) { } try { Object.defineProperty(this, \"o1.v2\", { configurable: true, enumerable: (x % 10 == 6),  get: function() {  return g0.runOffThreadScript(); } }); } catch(e2) { } for (var p in i1) { try { f0 = Proxy.createFunction(h1, f2, f1); } catch(e0) { } try { for (var p in h2) { try { Array.prototype.reverse.call(a1, g1.o0, s1, o0.f0); } catch(e0) { } v1 = new Number(v0); } } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(v1, f1); } catch(e2) { } t0[11]; } } else { try { for (var v of this.g1) { try { h2.getOwnPropertyDescriptor = g0.f0; } catch(e0) { } Array.prototype.pop.apply(a0, [m2, s2, i2, b1]); } } catch(e0) { } try { a0.reverse(m1, this.s0); } catch(e1) { } try { v1 = evalcx(\"/* no regression tests found */\", g1); } catch(e2) { } Object.defineProperty(this, \"v0\", { configurable: (x % 6 == 0), enumerable: false,  get: function() {  return t0.length; } }); } }), b2, a0, o0, b1, h0]);}");
/*fuzzSeed-169986037*/count=663; tryItOut("mathy5 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.abs((( + y) >= Math.cbrt(((( + (( ~ ( - x)) >>> 0)) >>> 0) | 0)))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, 2**53-2, -0x100000001, -Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), 0.000000000000001, -1/0, -Number.MAX_SAFE_INTEGER, 1/0, -0, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), -0x0ffffffff, -(2**53-2), 0x100000000, 1.7976931348623157e308, 0x080000001, 42, 0x100000001, -0x07fffffff, -0x100000000, -0x080000000, 0x07fffffff, 0, -0x080000001, Math.PI, 2**53+2, 2**53, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=664; tryItOut("\"use strict\"; g2.h2.defineProperty = f2;");
/*fuzzSeed-169986037*/count=665; tryItOut("/*bLoop*/for (var yhcrmb = 0, xifdkx, x, x, let; yhcrmb < 101; ++yhcrmb) { if (yhcrmb % 5 == 1) {  } else { ( \"\" ); }  } ");
/*fuzzSeed-169986037*/count=666; tryItOut("mathy5 = (function(x, y) { return (Math.pow(((Math.sin(y) >= (Math.sqrt(Math.fround(Math.atanh(Math.fround(x)))) | 0)) | 0), (Math.imul(mathy2((((0x07fffffff - Math.fround(Math.imul(Math.fround((x < x)), Math.fround(mathy2(x, (( + Math.hypot(( + x), ( + x))) | 0)))))) | 0) >>> 0), ( + ( + mathy2(Math.fround(( ~ (((x | 0) || ( + -Number.MAX_VALUE)) | 0))), ( + Number.MIN_VALUE))))), Math.cosh(mathy3(Math.imul(x, -0x07fffffff), Math.atan2(y, Math.fround(Math.trunc(Math.fround(y))))))) | 0)) | 0); }); testMathyFunction(mathy5, [-1/0, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x07fffffff, 0x0ffffffff, -Number.MAX_VALUE, 0/0, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, 2**53, 1.7976931348623157e308, -0x100000000, -0x080000000, -(2**53-2), 2**53-2, -(2**53), 42, 0, -0x100000001, -Number.MIN_VALUE, -0, 1, 2**53+2, Number.MAX_VALUE, Math.PI, 0.000000000000001, -(2**53+2), 1/0, 0x07fffffff, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-169986037*/count=667; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return mathy0(Math.min(( ~ (( + ( - ( + ((((x >>> 0) === (x >>> 0)) >>> 0) / y)))) | 0)), ( ! (Math.asinh(( ~ x)) >>> 0))), Math.fround(( ~ ( + ( - x))))); }); testMathyFunction(mathy4, /*MARR*/[0x40000001, true, true, 0x40000001, true, true, 0x40000001, true, 0x40000001, 0x40000001, 0x40000001, true, 0x40000001, 0x40000001, true, 0x40000001, 0x40000001, true, true, 0x40000001, true, true, true, true, true, true, 0x40000001, 0x40000001, 0x40000001, 0x40000001, true, true, true, 0x40000001, true, true, 0x40000001, true, 0x40000001, true, true, true, true, 0x40000001, 0x40000001, 0x40000001, 0x40000001, true, 0x40000001, true, 0x40000001, true, 0x40000001]); ");
/*fuzzSeed-169986037*/count=668; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.pow((( ~ (mathy0(Math.hypot(Math.fround(( + Math.fround(-0x0ffffffff))), (Math.sinh(((mathy1((y >>> 0), (1 >>> 0)) >>> 0) | 0)) >= ( + mathy1(y, y)))), (Math.cbrt(y) >>> 0)) >>> 0)) | 0), (( ! ( ! Math.pow(y, y))) >>> 0)); }); testMathyFunction(mathy2, [1/0, -0x07fffffff, -0x100000000, 0x100000001, -(2**53), 0x07fffffff, 0, -1/0, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, 42, -0, 0x080000000, 2**53, Number.MAX_SAFE_INTEGER, -0x080000001, Math.PI, 0x080000001, 2**53+2, 0/0, Number.MAX_VALUE, -(2**53-2), 1, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 0x0ffffffff, -0x100000001, -0x080000000, -Number.MAX_VALUE, 0.000000000000001, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=669; tryItOut("e2.add(g0.v2);");
/*fuzzSeed-169986037*/count=670; tryItOut("with({}) { x.lineNumber; } ");
/*fuzzSeed-169986037*/count=671; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=672; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=673; tryItOut("for (var v of b1) { try { a0.pop(); } catch(e0) { } try { Object.defineProperty(this, \"m2\", { configurable: false, enumerable: (x % 2 == 0),  get: function() {  return new WeakMap; } }); } catch(e1) { } t1.set(t1, 12); }");
/*fuzzSeed-169986037*/count=674; tryItOut("\"use strict\"; let v0 = r1.multiline;\nL:switch( /x/  %= /$|(?!\\xeE*?)+?/m >> /(?!(?!(?:\\s))*?|\\cI?|([^]|\\S){1,}\\s)/gim) { default: s2.valueOf = (function mcc_() { var kfitak = 0; return function() { ++kfitak; f1(/*ICCD*/kfitak % 2 == 1);};})();case 0x080000001: print(x);break;  }\n");
/*fuzzSeed-169986037*/count=675; tryItOut("let (x = this.__defineSetter__(\"a\", Number.parseFloat), b = x, xhugzq, window = String()) { /*RXUB*/var r = (/*FARR*/[].filter(new Function, -24)); var s = \"\"; print(s.search(r));  }");
/*fuzzSeed-169986037*/count=676; tryItOut("mathy1 = (function(x, y) { return ( + ( + ( + (Math.fround(Math.min(Math.fround((Math.fround((( - y) ? (y ** 0x100000000) : x)) / Math.fround(y))), Math.fround(( + Math.imul(( + x), ( + y)))))) / ( ! Math.fround(Math.max(Math.fround(x), (x !== -(2**53))))))))); }); testMathyFunction(mathy1, [-(2**53-2), -0, 0x100000000, 0x080000000, -Number.MIN_VALUE, 0, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0/0, Math.PI, Number.MIN_VALUE, 2**53, 1, Number.MAX_VALUE, -Number.MAX_VALUE, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, 1/0, -(2**53+2), -(2**53), 1.7976931348623157e308, -0x07fffffff, -0x0ffffffff, -0x080000001, -0x080000000, 0x100000001, -1/0, 2**53+2, 2**53-2, 42, -0x100000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -0x100000001, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=677; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      i0 = ((0xffffffff) >= (((0x6d62ea7)-((Int32ArrayView[4096])))>>>((0x64020dbf)-(((0x63eec169) < (0x0)) ? (-0x8000000) : (i0)))));\n    }\n    return +(((((((-0x8000000)) ? (i0) : (0x67916265)) ? (d1) : (d1))) % ((73786976294838210000.0))));\n  }\n  return f; })(this, {ff: objectEmulatingUndefined}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=678; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(?=(?=(^))))\\\\3\", \"i\"); var s = \"\"; print(s.replace(r, '')); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=679; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ( ! (( ~ (Math.fround(( ! (x || (( ! (( + mathy2(( + y), ( + 0x080000001))) | 0)) | 0)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [-(2**53), 0x080000000, -0x100000001, -1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 0x080000001, Number.MIN_VALUE, -(2**53+2), -0x0ffffffff, 0, 0x100000000, -Number.MAX_VALUE, -(2**53-2), 0x100000001, -0x100000000, Math.PI, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000001, 2**53+2, 0x07fffffff, -0, 0x0ffffffff, 1/0, 2**53, -0x07fffffff, 1, 42, -0x080000000, 0.000000000000001, Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-169986037*/count=680; tryItOut("\"use strict\"; (x);");
/*fuzzSeed-169986037*/count=681; tryItOut("\"use strict\"; s1 += this.s1;");
/*fuzzSeed-169986037*/count=682; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( - (Math.imul(((Math.pow(Math.fround(Math.abs(x)), Math.fround(mathy0(y, y))) | 0) | 0), ( + Math.fround(Math.atan2(Math.tanh(Math.fround(y)), Math.fround(((Math.min(((mathy2(y, 2**53+2) >> x) | 0), Math.fround(0x100000001)) | 0) | -(2**53+2))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000001, 2**53, 0.000000000000001, 0, -0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, 0x07fffffff, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, 2**53-2, 0x080000000, -0x100000001, -0, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, -0x100000000, 42, Math.PI, 0x080000001, Number.MAX_VALUE, -0x07fffffff, -1/0, -0x080000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1, 1/0, -0x080000000, -(2**53-2), -Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-169986037*/count=683; tryItOut("\"use strict\"; testMathyFunction(mathy2, [[], false, '\\0', NaN, true, (new Number(-0)), (function(){return 0;}), '/0/', '0', (new String('')), (new Boolean(false)), -0, undefined, 0.1, (new Boolean(true)), ({valueOf:function(){return 0;}}), (new Number(0)), null, '', objectEmulatingUndefined(), [0], ({valueOf:function(){return '0';}}), 0, ({toString:function(){return '0';}}), /0/, 1]); ");
/*fuzzSeed-169986037*/count=684; tryItOut("for(let y in this) {print(-27);print(y); }");
/*fuzzSeed-169986037*/count=685; tryItOut("\"use strict\"; (false);");
/*fuzzSeed-169986037*/count=686; tryItOut("\"use asm\"; for(let c in []);throw StopIteration;");
/*fuzzSeed-169986037*/count=687; tryItOut("\"use strict\"; ;/*vLoop*/for (var ddtlmq = 0; ddtlmq < 137; ++ddtlmq) { var w = ddtlmq; print(w); } ");
/*fuzzSeed-169986037*/count=688; tryItOut("var ywtniu = new ArrayBuffer(3); var ywtniu_0 = new Int32Array(ywtniu); ywtniu_0[0] = -17; var ywtniu_1 = new Float32Array(ywtniu); ywtniu_1[0] = 0.726; ((4277));");
/*fuzzSeed-169986037*/count=689; tryItOut("Array.prototype.push.call(o0.a1, t1, h2, h1);");
/*fuzzSeed-169986037*/count=690; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 4.722366482869645e+21;\n    {\n      i1 = (0xda930912);\n    }\n    {\n      d0 = (+(-1.0/0.0));\n    }\n    return +((Float64ArrayView[((0xffffffff)) >> 3]));\n    d2 = (+abs(((+(abs((0x672d758c))|0)))));\n    {\n      switch ((((0x6d031a6e) % (0x61b8732b)) >> (((void version(180)))))) {\n        case 0:\n          d2 = (d0);\n          break;\n        default:\n          {\n            i1 = (0x2caef420);\n          }\n      }\n    }\n    d0 = (d0);\n    i1 = (/*FFI*/ff(((d0)), ((((Uint32ArrayView[4096])) | ((0xffffffff)+(-0x8000000)))), ((abs((abs(((((~((0x42dd5877))))+(( /x/ .getOwnPropertySymbols()))) | ((0x9d067df5)+(0xfb388b3f)-(i1))))|0))|0)))|0);\n    d0 = (+pow(((d2)), ((d0))));\n    {\n      i1 = (0xffffffff);\n    }\n    switch (((0x885c8*((0x5fd90a30) != (0x2c42dea4)))|0)) {\n      case 0:\n        (Uint16ArrayView[4096]) = ((-0x12c134f));\n      case -3:\n        return +((d0));\n        break;\n    }\n    {\n      {\n        d2 = (x);\n      }\n    }\n    return +((Float32ArrayView[((-0x8000000)-(i1)) >> 2]));\n  }\n  return f; })(this, {ff: Promise}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-(2**53-2), 0x0ffffffff, 2**53+2, -(2**53+2), 0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, 42, -1/0, 0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 0x080000000, Number.MIN_SAFE_INTEGER, 1, -0x080000000, Number.MAX_VALUE, -0x100000000, 0, -0x080000001, -(2**53), 1/0, 2**53, 0x100000001, 2**53-2, -0, 1.7976931348623157e308, -0x100000001, Math.PI]); ");
/*fuzzSeed-169986037*/count=691; tryItOut("\"use strict\"; v0 = (s0 instanceof t2);");
/*fuzzSeed-169986037*/count=692; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=693; tryItOut("\"use strict\"; s1 + '';");
/*fuzzSeed-169986037*/count=694; tryItOut("\"use strict\"; /*vLoop*/for (var pzamci = 0; pzamci < 49; ++pzamci) { var b = pzamci; var yyzskb = new ArrayBuffer(0); var yyzskb_0 = new Int8Array(yyzskb); var yyzskb_1 = new Uint8ClampedArray(yyzskb); var yyzskb_2 = new Float32Array(yyzskb); yyzskb_2[0] = 27; var yyzskb_3 = new Float32Array(yyzskb); print(yyzskb_3[0]); yyzskb_3[0] = 23; var yyzskb_4 = new Int16Array(yyzskb); var yyzskb_5 = new Int16Array(yyzskb); yyzskb_5[0] = 20; var yyzskb_6 = new Float32Array(yyzskb); print(yyzskb_6[0]); yyzskb_6[0] = 28; var yyzskb_7 = new Int16Array(yyzskb); yyzskb_7[0] = 0; e0.has(g2);a2.sort(f2);print({} = {});print( /x/ );/*tLoop*/for (let d of /*MARR*/[objectEmulatingUndefined(), 2**53-2, 2**53-2]) { print(yyzskb_4[6]); } } ");
/*fuzzSeed-169986037*/count=695; tryItOut("\"use asm\"; v1 = 0;function x() { \"use strict\"; print(b0); } /* no regression tests found */");
/*fuzzSeed-169986037*/count=696; tryItOut("mathy5 = (function(x, y) { return (Math.min((((( - (Math.atan2((( + (x >>> 0)) >>> 0), Number.MAX_VALUE) >>> 0)) | 0) !== (Math.hypot(Math.atan2(x, x), y) | 0)) | 0), Math.abs(Math.imul(x, x))) < (Math.imul(((Math.expm1(Math.sqrt(( + ( + (x >>> 0))))) >>> 0) | 0), (Math.sinh(Math.imul(((x | 0) != (y >>> 0)), x)) | 0)) >>> 0)); }); testMathyFunction(mathy5, [-0x080000001, 1.7976931348623157e308, -0x080000000, 2**53+2, 0x080000000, Math.PI, -0, -0x07fffffff, -(2**53-2), -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x100000001, 0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 0x080000001, -Number.MIN_VALUE, -0x100000000, -(2**53+2), 0x07fffffff, 0/0, 1/0, 2**53, 42, 1, Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, 2**53-2, 0x100000000, 0.000000000000001, Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=697; tryItOut("mathy1 = (function(x, y) { return ((Math.fround((Math.fround((Math.log(( + mathy0(y, ( + y)))) >>> 0)) !== Math.fround((mathy0((mathy0((Math.fround(x) == y), 0.000000000000001) >>> 0), ( + Math.atanh((Math.trunc(Math.fround(mathy0(Math.fround(x), y))) >>> 0)))) | 0)))) - Math.atan(( ! (0x07fffffff , ( ~ ( + Math.asin(( + x)))))))) >>> 0); }); ");
/*fuzzSeed-169986037*/count=698; tryItOut("mathy4 = (function(x, y) { return (( ! (Math.round(( + (( + ( + Math.cosh(( + ( ! (y >>> 0)))))) <= ( + Math.tan(Math.fround(mathy3(y, x))))))) | 0)) | 0); }); testMathyFunction(mathy4, /*MARR*/[-(2**53), false, -(2**53), false, false, x, -(2**53), x, x, x, -(2**53), false, function(){}, function(){}, x, false, -(2**53), x, function(){}]); ");
/*fuzzSeed-169986037*/count=699; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.hypot((Math.hypot(( + ((Math.cosh((y | 0)) | 0) ? (Math.log((Math.fround((Math.fround(x) > Math.fround((Math.atan2((y | 0), Math.fround(Number.MAX_VALUE)) | 0)))) >>> 0)) | 0) : ((y >>> (Number.MAX_VALUE >>> 0)) | 0))), ( + mathy0(( + ( + (( + y) % ( + -Number.MAX_SAFE_INTEGER)))), ( + (y ? Math.abs(y) : (Math.fround((Math.fround(y) / Math.fround(-0x080000001))) | 0)))))) >>> 0), (Math.asin((Math.fround(( ! Math.fround(-Number.MAX_SAFE_INTEGER))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -0x100000001, 0x07fffffff, 0x080000001, 2**53+2, -Number.MAX_VALUE, -0, Number.MIN_VALUE, Math.PI, 0x0ffffffff, Number.MAX_VALUE, 2**53, -(2**53+2), -0x07fffffff, 0x100000000, 0.000000000000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53), -0x080000001, 0/0, 1/0, 1, 42, 0, 0x100000001, -1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000000, -0x080000000, 2**53-2, -(2**53-2), -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=700; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.asinh((Math.fround(Math.min(( + x), mathy0((Math.sqrt(x) | 0), (y | 0)))) || Math.hypot(Math.fround(mathy1(-Number.MAX_VALUE, y)), y)))); }); ");
/*fuzzSeed-169986037*/count=701; tryItOut("\"use strict\"; (eval.parseFloat).call(x, Proxy(this), (b) = undefined);");
/*fuzzSeed-169986037*/count=702; tryItOut("h0[\"prototype\"] = o2.h0;");
/*fuzzSeed-169986037*/count=703; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.expm1(Math.pow((( ~ (y >>> 0)) >>> 0), ( + ((y | 0) * (y >>> 0))))) == (Math.min((Math.min(Math.log1p(Math.ceil((y >>> 0))), (y - (Math.log(((( + x) | 0) | 0)) | 0))) >>> 0), ((((y >>> 0) , ((y + Math.fround(Math.max(Math.fround(x), mathy0(-(2**53-2), x)))) >>> 0)) >>> 0) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=704; tryItOut("mathy4 = (function(x, y) { return (( + (( ~ mathy0(Math.fround(Math.cos(Math.fround(0x100000000))), x)) + ( ~ ( ~ ( + x))))) || Math.log2(Math.fround(( + ( - (x ? y : y)))))); }); testMathyFunction(mathy4, /*MARR*/[-0xB504F332, function(){}, -0xB504F332,  /x/g ,  /x/g , -0xB504F332,  /x/g , -0xB504F332, -0xB504F332, -0xB504F332, function(){}, function(){},  /x/g ,  /x/g , -0xB504F332, function(){}, function(){}, function(){}, function(){}, function(){}, -0xB504F332,  /x/g , -0xB504F332,  /x/g ,  /x/g , -0xB504F332, function(){},  /x/g ,  /x/g , function(){}, function(){}, -0xB504F332,  /x/g , -0xB504F332,  /x/g , function(){}, function(){},  /x/g , -0xB504F332, -0xB504F332, function(){},  /x/g , function(){}, -0xB504F332, function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){}, -0xB504F332,  /x/g , -0xB504F332, function(){}, function(){}, function(){}, -0xB504F332, function(){}, function(){}, -0xB504F332, function(){},  /x/g , function(){}, -0xB504F332, -0xB504F332,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){}, function(){}, -0xB504F332, function(){}, -0xB504F332, -0xB504F332,  /x/g ,  /x/g ,  /x/g , function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, -0xB504F332]); ");
/*fuzzSeed-169986037*/count=705; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.min(( + mathy4(mathy3(Math.imul(Math.fround((y - mathy0((y >>> 0), (Number.MAX_SAFE_INTEGER >>> 0)))), Math.fround(( - y))), x), (Math.fround(( + ( - ( + Math.max((y >>> 0), ( + ((Math.abs(x) >>> 0) >>> 0))))))) ? Math.tan(( + Math.log1p(0x100000001))) : (Math.min(x, ( + Math.atan2(( + Math.fround(Math.pow(Math.fround((y ^ y)), 0x100000000))), ( + mathy4(x, ( + ( + ( ~ ( + x))))))))) >>> 0)))), (Math.max(( ! (mathy1((Math.fround(( + Math.fround((Math.sinh((y | 0)) | 0)))) >>> 0), (Math.hypot(( + x), Math.sin(( + ( + y)))) >>> 0)) >>> 0)), ((Math.fround(Math.asinh(Math.fround(( + Math.atan2(( + Math.fround(( - Math.fround(y)))), ( + y)))))) > (Math.imul((mathy4(y, (0x080000000 ** -0)) | 0), (( + Math.acosh(( + ( - x)))) | 0)) | 0)) | 0)) >>> 0))); }); testMathyFunction(mathy5, /*MARR*/[0x10000000, undefined, undefined]); ");
/*fuzzSeed-169986037*/count=706; tryItOut("\"use strict\"; /*oLoop*/for (var cntdhr = 0; cntdhr < 22; ++cntdhr) { h2.getOwnPropertyDescriptor = DataView.prototype.setFloat32; } ");
/*fuzzSeed-169986037*/count=707; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=$\\b)+?/gym; var s = \"\\n \\n\\u12b5\\ue6e4aA\\n\\u00a1z\\n\\n\\n\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=708; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.fround(Math.atan2(Math.fround(Math.imul((Math.imul((Math.atan2(Math.fround(Math.pow((Math.fround((Math.fround(Math.min(-Number.MIN_VALUE, x)) ? Math.fround(mathy3(x, x)) : (y | 0))) >>> 0), y)), ( + Math.fround(Math.cos(Math.fround(( + Math.hypot(( + 42), ( + Math.fround(mathy0((x >>> 0), x)))))))))) >>> 0), (0/0 >>> 0)) >>> 0), Math.cosh(Math.fround(((((x >>> 0) >= (-(2**53) >>> 0)) >>> 0) + ((mathy3((( ~ y) >>> 0), (y >>> 0)) >>> 0) >>> 0)))))), Math.fround(Math.trunc(Math.imul(((-(2**53-2) ? (Math.atan2(Math.trunc(Math.min(x, x)), x) >>> 0) : ((( + (mathy3(-Number.MAX_VALUE, x) | 0)) >>> 0) | 0)) >>> 0), ( + ( ! (( + (( + y) == ( + x))) >>> 0)))))))); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, Number.MIN_VALUE, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 42, 1, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, 0.000000000000001, -(2**53+2), 2**53+2, 2**53, 0, 0x080000000, Math.PI, -0x080000000, Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, -(2**53-2), 0/0, 0x07fffffff, -0x100000000, -(2**53), 0x080000001, -0x100000001, 1/0]); ");
/*fuzzSeed-169986037*/count=709; tryItOut("Array.prototype.splice.apply(a0, [1, 2]);");
/*fuzzSeed-169986037*/count=710; tryItOut("\"use strict\"; /* no regression tests found */Array.prototype.unshift.call(a1, h1, h2);");
/*fuzzSeed-169986037*/count=711; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(this.p0, this.o0);");
/*fuzzSeed-169986037*/count=712; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.min(((( + (Number.MIN_SAFE_INTEGER * -1/0)) && Math.pow(-1/0, x)) | 0), (Math.fround(Math.log((Math.fround(Math.sign(Math.asin(x))) + (Math.abs(1) ? ( + 1.7976931348623157e308) : ( + Math.imul(Math.fround(( - Math.fround(Math.exp(y)))), ( + Math.tan(x)))))))) | 0)) | 0); }); testMathyFunction(mathy3, [(new Number(-0)), 0.1, undefined, false, [], (new Boolean(false)), null, 1, 0, '/0/', true, (function(){return 0;}), NaN, (new String('')), (new Boolean(true)), '', ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), objectEmulatingUndefined(), -0, '0', (new Number(0)), '\\0', /0/, ({valueOf:function(){return 0;}}), [0]]); ");
/*fuzzSeed-169986037*/count=713; tryItOut("\"use strict\"; var bpsrrg, let, \"27\" = this.__defineSetter__(\"a\", Set.prototype.has);/*RXUB*/var r = new RegExp(\"((?=\\\\B|\\\\\\u938a))\\\\b{4,}\\\\W|[^]{0,}\\\\2\", \"yim\"); var s = \"\"; print(s.match(r)); ");
/*fuzzSeed-169986037*/count=714; tryItOut("mathy1 = (function(x, y) { return Math.abs(Math.fround(( ! mathy0((1.7976931348623157e308 !== (( ! x) | 0)), (( + Math.sin(( + y))) >>> 0))))); }); testMathyFunction(mathy1, [(new String('')), (function(){return 0;}), ({valueOf:function(){return 0;}}), (new Boolean(true)), 1, undefined, null, true, -0, '0', 0, NaN, '', (new Number(-0)), [0], objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), '\\0', /0/, '/0/', ({toString:function(){return '0';}}), [], false, (new Boolean(false)), (new Number(0)), 0.1]); ");
/*fuzzSeed-169986037*/count=715; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:^).${1,}\\\\b{2}(?:[^]{0,}[^\\\\xeD]^)|\\\\x91|.\\\\cW[\\\\t-\\u00e8-\\u00f9\\\\w]|^|\\\\d{2,}+?{2,6}\\\\1|^+\\\\b|\\\\1\\\\1.(?=\\\\W){3}|.(?=[^]{4,}){2,}+\\\\3|(?!\\\\t|[^])*?|^(?=(?:\\\\u00EC\\\\2(?!\\\\1|\\\\1)))\", \"gyi\"); var s = \"\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=716; tryItOut("mathy2 = (function(x, y) { return (((Math.cbrt(Math.fround(( ~ (( - ( + ( + (Math.atan2(( + 1), (y >>> 0)) >>> 0)))) | 0)))) | 0) ? (((Math.round(-0) ? (Math.log2(y) | 0) : ( ~ y)) | 0) | 0) : (Math.fround((Math.fround(Math.min(Math.fround(x), (Math.sign((Math.max(Math.fround(Math.asin(Math.fround((y >>> x)))), (( + Math.fround(Math.max(Math.fround(0.000000000000001), x))) | 0)) >>> 0)) >>> 0))) | Math.fround(mathy0(( + (( + Math.atan2(y, y)) < ((Math.min(Math.fround(-0x0ffffffff), (x >>> 0)) >>> 0) >>> 0))), Math.expm1(Math.asin(( + y))))))) | 0)) | 0); }); testMathyFunction(mathy2, [0/0, 2**53, 1, 0.000000000000001, -Number.MIN_VALUE, 1/0, 0x080000001, 0x100000000, -0x100000001, -0x0ffffffff, 0x07fffffff, Math.PI, 0, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, -(2**53-2), -(2**53+2), 42, -0x07fffffff, -1/0, 0x100000001, -(2**53), Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, 2**53-2, 2**53+2, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000]); ");
/*fuzzSeed-169986037*/count=717; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var asin = stdlib.Math.asin;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d1);\n    {\n      (Float64ArrayView[((0xfae46130)-(0xffffffff)) >> 3]) = ((d0));\n    }\n    (Int8ArrayView[1]) = ((!(0x943a8bd4))-((d0) > (((( '' )) / ((d0))) + (d0)))+(((new \"\\u26F1\"( '' )) >> ((0xcbc6923f)-((-0x8000000) ? (!(0x65e383ca)) : (!(0xffffffff)))))));\n    d0 = (d0);\n    d1 = (+/*FFI*/ff(((d1)), ((+asin(((+(1.0/0.0)))))), ((+(1.0/0.0))), ((~((0xeeac16b3)-((((0x36be5feb))>>>((0xffffffff)))))))));\n    return (((0xf8b419b7)))|0;\n  }\n  return f; })(this, {ff: /*wrap1*/(function(){ print((uneval( /x/g )));return WeakMap.prototype.has})()}, new ArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=718; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - ( + Math.hypot(( + ( ! ((((Math.cbrt(x) >>> 0) - (-(2**53+2) >>> 0)) >>> 0) > y))), Math.fround((( + Math.pow(( + y), ( + (((Math.imul(y, -0x100000000) >>> 0) & (Math.imul(Math.log10((x >>> 0)), y) >>> 0)) >>> 0)))) | y))))); }); testMathyFunction(mathy5, [0x100000001, 0x100000000, 0.000000000000001, -0x080000001, -Number.MIN_VALUE, 0/0, -Number.MAX_VALUE, -0x080000000, 0x07fffffff, -0x100000000, 2**53, 42, Math.PI, 1.7976931348623157e308, -0x07fffffff, Number.MIN_VALUE, Number.MAX_VALUE, 1, 1/0, 2**53+2, Number.MAX_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), 0x0ffffffff, 0x080000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, 2**53-2, 0, -1/0, -(2**53+2), -0x100000001]); ");
/*fuzzSeed-169986037*/count=719; tryItOut("/*infloop*/ for (let Float32Array.prototype of x) e1.toString = (function() { for (var j=0;j<102;++j) { f1(j%3==1); } });");
/*fuzzSeed-169986037*/count=720; tryItOut("m1 = new Map(f0);");
/*fuzzSeed-169986037*/count=721; tryItOut("return [] = (function shapeyConstructor(vyopvx){vyopvx[new String(\"16\")] =  \"use strict\" ;if (undefined) { \u3056; } if (vyopvx) vyopvx[\"toTimeString\"] = /((.){4,8}|(p|[-\\W\\s])?|([^\ud0ac\u2d3a-\u8755\\W\\u00C1-\ue7ed])|$|$|\\2{0})/gym;delete vyopvx[\"tanh\"];{ this.s2 += s2; } if ( /x/g ) Object.freeze(vyopvx);{ v2 = Object.prototype.isPrototypeOf.call(p2, v1); } vyopvx[\"log1p\"] = (-1/0);return vyopvx; }).bind().prototype;");
/*fuzzSeed-169986037*/count=722; tryItOut("\"use asm\"; e0 = new Set;");
/*fuzzSeed-169986037*/count=723; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + (Math.asinh(Math.fround(Math.expm1(( + Math.imul(( + 0x080000000), ( + Math.cosh(x))))))) >>> 0)); }); testMathyFunction(mathy1, [0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -Number.MIN_VALUE, 2**53, 0.000000000000001, -(2**53+2), 0x080000001, -0x100000000, 0x080000000, 0, 1, Number.MIN_VALUE, 0/0, -0x0ffffffff, -(2**53-2), 42, 2**53-2, 0x100000000, 1/0, -0x080000000, 0x100000001, -0x080000001, -0x100000001, -(2**53), -0, -1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x07fffffff, 1.7976931348623157e308, Math.PI, 2**53+2, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=724; tryItOut("mathy0 = (function(x, y) { return (((Math.pow(Math.round(( + (( + x) ? ( + Math.hypot(x, 0x100000001)) : ( + x)))), ( + Math.atan2(((Math.atan2((Math.fround(Math.sinh(Math.fround(y))) | 0), (Number.MAX_SAFE_INTEGER | 0)) | 0) | 0), 0x0ffffffff))) >>> 0) ^ ( + Math.imul(Math.fround(Math.imul(Math.cbrt(Math.min((Math.PI >>> 0), x)), Math.fround((Math.fround(y) << Math.fround(((( + ( - x)) >>> 0) != Math.fround(x))))))), Math.imul(((y || y) >>> 0), Math.fround(y))))) >>> 0); }); testMathyFunction(mathy0, [-0, ({valueOf:function(){return '0';}}), undefined, null, '/0/', ({valueOf:function(){return 0;}}), '0', 0.1, '', (function(){return 0;}), (new String('')), /0/, objectEmulatingUndefined(), true, [], (new Number(-0)), '\\0', false, NaN, 0, 1, (new Boolean(true)), (new Boolean(false)), ({toString:function(){return '0';}}), [0], (new Number(0))]); ");
/*fuzzSeed-169986037*/count=725; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float64ArrayView[(((imul(((0x0) >= (0x5f8a188e)), (/*FFI*/ff(((1.5111572745182865e+23)), ((1073741825.0)), ((513.0)), ((295147905179352830000.0)))|0))|0) < ((i1)))+((0x7188544))) >> 3]) = ((((d0)) / ((((((1099511627775.0)) / ((9.44473296573929e+21)))) * (((d0) + (-67108863.0)))))));\n    return +((d0));\n    i1 = (i1);\n    return +((d0));\n  }\n  return f; })(this, {ff: Math.max}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, ['', [0], undefined, ({valueOf:function(){return '0';}}), -0, (function(){return 0;}), null, objectEmulatingUndefined(), 0, '/0/', (new String('')), 1, ({toString:function(){return '0';}}), (new Number(0)), /0/, (new Boolean(true)), ({valueOf:function(){return 0;}}), true, (new Number(-0)), 0.1, '0', NaN, false, [], '\\0', (new Boolean(false))]); ");
/*fuzzSeed-169986037*/count=726; tryItOut("\"use strict\"; qotkyu(try { throw b; } catch(a) { throw b; } finally { x.message; } );/*hhh*/function qotkyu(this.window, z){{print((e) = this); }}");
/*fuzzSeed-169986037*/count=727; tryItOut("\"use strict\"; var r0 = x | x; var r1 = r0 - r0; var r2 = r1 - 6; var r3 = r2 | 6; print(r2); var r4 = 0 % 1; var r5 = 5 / r1; r0 = r2 - r5; var r6 = r4 + x; x = r4 - r6; var r7 = r6 * r4; var r8 = r4 - r6; var r9 = r8 - r2; var r10 = 0 % 5; r1 = r2 + r8; var r11 = r9 / r5; var r12 = r8 ^ r0; r5 = 1 - r6; r11 = r7 | r3; var r13 = 6 + r5; var r14 = r11 - r5; var r15 = 4 % r6; var r16 = 5 / r2; var r17 = r3 | r7; var r18 = r1 / r9; var r19 = r14 | 3; var r20 = 2 & r19; print(r4); print(r14); r2 = r16 / 4; var r21 = r6 - r7; var r22 = r18 + r21; r5 = 1 + r1; var r23 = 9 + r20; var r24 = 0 + r19; var r25 = r5 - r6; var r26 = r0 / 2; var r27 = r10 ^ r4; var r28 = r17 & 8; ");
/*fuzzSeed-169986037*/count=728; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\W+?\", \"yi\"); var s = ; print(r.exec(s)); ");
/*fuzzSeed-169986037*/count=729; tryItOut("\"use strict\"; /*MXX3*/g1.Array.prototype.toLocaleString = g2.Array.prototype.toLocaleString;");
/*fuzzSeed-169986037*/count=730; tryItOut("mathy5 = (function(x, y) { return Math.abs((Math.max(Math.fround(( ! y)), (Math.tan((x | 0)) >>> 0)) !== (( + (mathy1(0x0ffffffff, x) | 0)) | 0))); }); testMathyFunction(mathy5, ['\\0', '/0/', false, 0.1, (new Boolean(true)), ({toString:function(){return '0';}}), [0], 0, '0', [], '', ({valueOf:function(){return '0';}}), (new Boolean(false)), ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), 1, /0/, NaN, (function(){return 0;}), -0, (new Number(-0)), true, null, (new String('')), undefined, (new Number(0))]); ");
/*fuzzSeed-169986037*/count=731; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.hypot(Math.min((( ~ y) === (0x100000001 != -Number.MIN_VALUE)), ( ! Math.min((2**53 | 0), y))), Math.log10(((( + Math.pow(mathy0(y, x), ( - x))) ? (((Math.sin((Math.min(((Math.min((y >>> 0), (x >>> 0)) >>> 0) >>> 0), (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)) | 0) - (x | 0)) | 0) : x) >>> 0))); }); testMathyFunction(mathy2, [2**53, 1, 2**53+2, 0/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, Math.PI, 1.7976931348623157e308, -Number.MIN_VALUE, 0x100000000, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, -0x080000001, -Number.MAX_VALUE, -0x100000000, -(2**53+2), 0x07fffffff, -0x100000001, 0.000000000000001, 1/0, -(2**53), 0, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x07fffffff, Number.MAX_VALUE, 0x080000000, 42]); ");
/*fuzzSeed-169986037*/count=732; tryItOut("\"use strict\"; if(true) ; else {e0.has(/(?=(?:\\3))+?/yi);g2.v0 = Object.prototype.isPrototypeOf.call(b1, i0); }");
/*fuzzSeed-169986037*/count=733; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (d0);\n    d0 = (d0);\n    d0 = (d0);\n    i1 = (i1);\n    i1 = ((~~(+abs(((d0))))) <= (((!(/*FFI*/ff(((-17592186044416.0)), ((((-0x8000000)) & ((0xcf511f0b)))))|0))-((~((0x8348fefd)+(0x22b6a065)+(0xfd44ef25))) < (abs((((0x7ae07e60)) << ((0x12fe0ba2))))|0))) >> ((Int32ArrayView[((i1)-(i1)) >> 2]))));\n    return ((((imul(((0xfc73c07) < (imul(((((0x7a1e9904) / (0x13070d32)) >> (-0xa9a39*(0xcc5ab948)))), (([]) = new RegExp(\"\\\\2\", \"\")))|0)), (i1))|0))))|0;\n  }\n  return f; })(this, {ff: function(y) { L:if(true) (-23); else  if (({ get 23(\u3056,  /x/  = e, y, x, y, w = a, x, x, b, NaN =  /x/ , y, x, y, x = -17, c, d =  /x/g , d, x, eval, b, x, /(?:[^]*?(?:d){0,})/gym, y, b, x, y, x, y, y, x, y, window, w, y, y, z, c, y = this, NaN = x, y = undefined, NaN =  /x/ , c, x = /[^]|\\b|[\\D\\$-\u577a\\S]+?.|[\\u0070-\u3cde](?:[^J-\\0\\w\\u007E])+?(?=(.$[^]))|(?=([^\\d\\d]|$|^))|(?!(\\s){1,}(?=.))(?=\\B){3}/gi, this.NaN, b = /(\\W{1,1}(?:(?:\\W)){3}\\s{1,})/i, y, window, w, y,  , x, x, window, y, x, y, x =  /x/ , eval, y, eval, e, x = /(?=[\\s\\D]){3,5}/gi, a, y, d, x = undefined, \u3056, x, b, y, e, \u3056 = [,,z1], window, x, c, y, x, eval = window, w, x, x, NaN, y =  /x/g , y, x, window, eval = this)3, -3: -14 })) yield; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-0x080000001, 0, -0x100000001, -0x080000000, 42, 2**53-2, -1/0, 2**53+2, 1, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, -0, 1/0, 0x0ffffffff, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, -(2**53-2), Number.MIN_VALUE, -(2**53), 0x080000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000001, -0x07fffffff, 0x100000001, -0x100000000, 0x07fffffff, 2**53, Math.PI, Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=734; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=735; tryItOut("\"use strict\"; {print(x);Array.prototype.sort.call(a2, (function() { try { Array.prototype.unshift.apply(a1, [p1]); } catch(e0) { } try { r0 = new RegExp(\"(\\\\2(?!(?=[\\\\\\ufa89-\\\\u0037]|$))|(?:\\\\b*)^[^T-\\u00c3\\u00f0\\\\D\\u168e]|\\\\b|^?)\", \"im\"); } catch(e1) { } try { i0 = m1.values; } catch(e2) { } Array.prototype.sort.call(o1.a2); return a0; }), f2); }a0.pop();");
/*fuzzSeed-169986037*/count=736; tryItOut("/*oLoop*/for (var akvcfi = 0, x = [[1]]; akvcfi < 6; ++akvcfi) { {} } ");
/*fuzzSeed-169986037*/count=737; tryItOut("x = c;");
/*fuzzSeed-169986037*/count=738; tryItOut("\"use strict\"; Object.defineProperty(this, \"b0\", { configurable: x, enumerable: true,  get: function() {  return t2.buffer; } });");
/*fuzzSeed-169986037*/count=739; tryItOut("h0.hasOwn = (function() { try { t1[[(b((x >>>= this.__defineGetter__(\"x\", Error))) = \u3056)]] = (((/*FARR*/[].filter[\"wrappedJSObject\"]) = x).__defineGetter__(\"window\", q => q)); } catch(e0) { } try { v0 = g0.eval(\"s1 = new String;\"); } catch(e1) { } e1.add(p0); return t0; });");
/*fuzzSeed-169986037*/count=740; tryItOut("\"use strict\"; s2 += s0;");
/*fuzzSeed-169986037*/count=741; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=742; tryItOut("\"use strict\"; /*vLoop*/for (lenawi = 0; lenawi < 91; (new RegExp(\"(?!(?:[^])+?)($)(\\u0004+)*|(?=(?:[\\\\d\\\\S\\\\w]|^)|($)+)*?\", \"gy\").__proto__ = true in window), ++lenawi) { const y = lenawi; M:with(y)this.v0 = (p0 instanceof p2); } ");
/*fuzzSeed-169986037*/count=743; tryItOut("a2.forEach(f2);");
/*fuzzSeed-169986037*/count=744; tryItOut("\"use strict\"; Array.prototype.splice.apply(this.g1.o0.a2, [NaN, 1]);\nv0 = evaluate(\"h1 = {};\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 2 != 0), sourceIsLazy: false, catchTermination: (x % 15 != 9) }));\nvar eumdhy = new ArrayBuffer(0); var eumdhy_0 = new Uint8ClampedArray(eumdhy); print(eumdhy_0[0]); eumdhy_0[0] = 3; v2 = a2.some((function() { try { x = g2.g0.v1; } catch(e0) { } for (var v of t0) { try { s1.toSource = f0; } catch(e0) { } try { g0.v2 = g0.eval(\"this.v0 = g1.runOffThreadScript();\"); } catch(e1) { } g1.offThreadCompileScript(\" /x/g \", ({ global: g2.g1, fileName: null, lineNumber: 42, isRunOnce: (eumdhy_0[0] % 6 == 3), noScriptRval: false, sourceIsLazy: false, catchTermination: true })); } return p2; }));\n\n");
/*fuzzSeed-169986037*/count=745; tryItOut("/*tLoop*/for (let a of /*MARR*/[[undefined], [1], objectEmulatingUndefined(), [1], -1, [1], [1], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [undefined], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [1], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), [undefined], objectEmulatingUndefined(), objectEmulatingUndefined(), [undefined], -1, -1, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, -1, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [1], [1], [undefined], objectEmulatingUndefined(), [undefined], [undefined], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), [1], objectEmulatingUndefined(), [1], [1], [undefined], objectEmulatingUndefined(), objectEmulatingUndefined(), -1, -1, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [undefined], [undefined], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [undefined], objectEmulatingUndefined(), -1, [1], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [undefined], -1, objectEmulatingUndefined(), [1], -1, [undefined], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), objectEmulatingUndefined(), -1, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [undefined], -1, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [undefined], objectEmulatingUndefined(), objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [undefined], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [1], [undefined], [1], objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, -1, -1, [undefined], [1], [1], [1], [undefined], -1, [1], -1, -1, [undefined], objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, -1, [undefined], -1, objectEmulatingUndefined(), [1], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [undefined], objectEmulatingUndefined(), [undefined], [1], -1, -1, objectEmulatingUndefined(), -1, [1], -1, [undefined], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, [1], [undefined], [1], -1, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, -1, [1], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [undefined], /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), [undefined], [1], -1, objectEmulatingUndefined(), [undefined], objectEmulatingUndefined(), [1], [undefined], objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, objectEmulatingUndefined(), /(\\d|\\D|(?!\\s+)|[^]|\ueb56)\\3[\\u92c0]{2,5}\\uF2EB{0,}*?/ym, -1, objectEmulatingUndefined(), [undefined], [undefined], objectEmulatingUndefined(), objectEmulatingUndefined(), [1], -1, [undefined], [undefined], [undefined], -1, [undefined], [1]]) { print(a); }");
/*fuzzSeed-169986037*/count=746; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ( + Math.fround(( + (( + Math.log10((Math.fround((( ! Math.fround((-Number.MAX_VALUE ? (Math.hypot(y, (x >>> 0)) >>> 0) : y))) | 0)) > ( + (( ~ x) , x))))) ? ( + Math.imul(Math.atan(Math.cosh(y)), ( ~ x))) : ( + Math.pow((Math.imul(Math.max(Math.fround(y), Math.PI), ( ~ y)) >>> mathy0((( ~ x) >>> 0), 0x0ffffffff)), Math.fround(mathy1(Math.fround(x), y)))))))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 2**53, 0x080000001, 0/0, 0x100000001, -Number.MAX_VALUE, 0x100000000, -(2**53), -(2**53+2), 2**53-2, -1/0, 2**53+2, Number.MAX_VALUE, 0x0ffffffff, -0, 0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Math.PI, -(2**53-2), 1/0, -0x080000000, 42, -0x100000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, -0x07fffffff, -0x100000001, 1.7976931348623157e308, 0x07fffffff, -Number.MIN_VALUE, 0x080000000]); ");
/*fuzzSeed-169986037*/count=747; tryItOut("mathy1 = (function(x, y) { \"use asm\"; return Math.atan2((( ~ (Math.imul(mathy0(( + mathy0((Math.min(( + ( - ( + Number.MAX_SAFE_INTEGER))), (Math.fround((y >>> 0)) >>> 0)) | 0), ( + -0x07fffffff))), x), ( ! Math.fround(Math.cos(y)))) | 0)) | 0), mathy0(Math.atanh(Math.min(mathy0(mathy0(y, y), x), x)), mathy0(((((y < y) && -0) | 0) === x), ( ~ (y >>> 0))))); }); testMathyFunction(mathy1, /*MARR*/[(4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), new String('q'), (0/0), (0/0), new String('q'), new String('q'), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (0/0), (0/0), new String('q'), new String('q'), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), new String('q'), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), (0/0), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), new String('q'), new String('q'), (4277), new String('q'), new String('q'), (0/0), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), new String('q'), (4277), (4277), new String('q'), (4277), (4277), (0/0), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), new String('q'), (0/0), (0/0), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (4277), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), new String('q'), new String('q'), (0/0), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (4277), (4277), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (4277), (0/0), (4277), (0/0), (0/0), /*UUV2*/(\u3056.toJSON = \u3056.keys), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (0/0), (0/0), (0/0), (4277), (0/0), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), new String('q'), (4277), (0/0), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), new String('q'), (0/0), new String('q'), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), (4277), (0/0), (0/0), /*UUV2*/(\u3056.toJSON = \u3056.keys), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (0/0), (4277), new String('q'), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), (4277), new String('q'), (0/0), new String('q'), (4277), (0/0), (4277), (4277), new String('q'), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (0/0), (4277), (0/0), new String('q'), (0/0), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (4277), (0/0), (0/0), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), (0/0), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (0/0), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), (0/0), (0/0), (0/0), /*UUV2*/(\u3056.toJSON = \u3056.keys), (0/0), /*UUV2*/(\u3056.toJSON = \u3056.keys), (4277), /*UUV2*/(\u3056.toJSON = \u3056.keys), (0/0), (0/0), (0/0), (0/0), (4277), (0/0), (4277), new String('q')]); ");
/*fuzzSeed-169986037*/count=748; tryItOut("\"use strict\"; \"use asm\"; i1.next();");
/*fuzzSeed-169986037*/count=749; tryItOut("");
/*fuzzSeed-169986037*/count=750; tryItOut("\"use strict\"; x = ({x: undefined}), x, x = (Math.min(\"\\u00F8\", ('fafafa'.replace(/a/g, objectEmulatingUndefined)))());v2 = evaluate(\"function f1(p2)  { return (void version(170)) } \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: a = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: (1 for (x in [])), getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: arguments.callee.caller.caller.caller, fix: function() { }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return false; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })(undefined), neuter, function(y) { \"use strict\"; yield y; o1 = new Object;; yield y; }), sourceIsLazy: (x % 5 != 1), catchTermination: false }));");
/*fuzzSeed-169986037*/count=751; tryItOut("testMathyFunction(mathy3, [-0x07fffffff, -1/0, Number.MIN_VALUE, 0/0, 2**53+2, -Number.MIN_VALUE, 0x100000000, 2**53-2, 0, Math.PI, 1/0, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, -(2**53+2), 1, 0x07fffffff, Number.MAX_VALUE, -0, -0x100000001, 2**53, -Number.MAX_VALUE, -0x080000001, -0x100000000, 0x080000001, -(2**53-2), 0.000000000000001, 0x0ffffffff, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, -(2**53), Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=752; tryItOut("\"use strict\"; { void 0; try { startgc(1658); } catch(e) { } } t2 = t2.subarray(Math.imul(28,  /x/g ), (4277));");
/*fuzzSeed-169986037*/count=753; tryItOut("L:with(x = c)print(x);");
/*fuzzSeed-169986037*/count=754; tryItOut("mathy1 = (function(x, y) { return (((( + Math.sign((y >>> 0))) === ( ! Math.imul(( + Math.max(( + x), (x >>> 0))), ( ~ Number.MAX_VALUE)))) >= (Math.imul(( - ( - x)), ( + ( + (( + y) ? ( + ( ~ -(2**53-2))) : x)))) | 0)) | 0); }); testMathyFunction(mathy1, /*MARR*/[false, intern(window), false, false, ({x:3}), intern(window), ({x:3}), intern(window), false, false, intern(window), intern(window), false, false, intern(window), intern(window), false, ({x:3}), ({x:3}), false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, ({x:3}), (void 0), intern(window), (void 0), ({x:3}), (void 0), intern(window), false, intern(window), (void 0), (void 0), false, ({x:3}), (void 0), false, ({x:3}), false, (void 0), (void 0), intern(window), intern(window), ({x:3}), (void 0), (void 0), ({x:3}), intern(window), ({x:3}), intern(window), intern(window), intern(window), ({x:3}), (void 0), ({x:3}), ({x:3}), false, intern(window), (void 0), (void 0), (void 0), false, false, intern(window), ({x:3}), false, intern(window), (void 0), false, ({x:3}), ({x:3}), intern(window), intern(window), false, false, false, (void 0), false, false, ({x:3})]); ");
/*fuzzSeed-169986037*/count=755; tryItOut("a0.toString = g0.f2;/*hhh*/function owurut(x){b0.toString = (function() { v2 = evalcx(\"\\\"\\\\uB9FA\\\"\", o2.g0); return e0; });}/*iii*/i2 + '';");
/*fuzzSeed-169986037*/count=756; tryItOut("\"use strict\"; i2[\"assign\"] = a2;");
/*fuzzSeed-169986037*/count=757; tryItOut("\"use strict\"; y = linkedList(y, 3450);");
/*fuzzSeed-169986037*/count=758; tryItOut("mathy4 = (function(x, y) { return Math.fround(mathy0(Math.fround(Math.fround((Math.fround((Math.pow(Math.log2(mathy2(((( + y) << ( + y)) >>> 0), -Number.MIN_SAFE_INTEGER)), (Math.pow(y, (-0x100000000 | 0)) | 0)) % ((( ~ y) >>> 0) ? Math.hypot(x, 0) : Math.pow(( + (( + y) !== ( + Math.pow(-0x100000000, Math.PI)))), y)))) ? Math.fround(Math.fround((Math.fround(Math.fround(Math.min((( ~ Math.fround((1.7976931348623157e308 ** (Math.hypot(x, y) | 0)))) | 0), (((( + Math.fround(y)) | 0) || -Number.MIN_SAFE_INTEGER) | 0)))) ? ((Math.fround(Math.sqrt(0x100000001)) ** Math.sinh((x >>> 0))) >>> 0) : Math.fround((Math.pow(Math.fround(Math.hypot(x, 42)), y) === y))))) : Math.fround(((((mathy3((x | 0), (x | 0)) | 0) >>> 0) > ((( + Math.max(( + x), ( + x))) != ( ! ( + x))) >>> 0)) >>> 0))))), Math.fround(Math.log2((Math.imul(y, ((0x100000000 & ( + (( + mathy3(( + (y , y)), ( + y))) | 0))) | 0)) >>> 0))))); }); ");
/*fuzzSeed-169986037*/count=759; tryItOut("for (var p in g2.t0) { try { Object.defineProperty(this, \"v2\", { configurable: false, enumerable: (x % 4 == 2),  get: function() {  return r1.flags; } }); } catch(e0) { } try { var s2 = new String(p0); } catch(e1) { } e0.add(i1); }");
/*fuzzSeed-169986037*/count=760; tryItOut("for(let e = x in  /x/ ) o1.a1 = new Array;");
/*fuzzSeed-169986037*/count=761; tryItOut("\"use strict\"; /*infloop*/do v2 = (this.o0 instanceof v2); while(((void shapeOf((y = function ([y]) { })))));");
/*fuzzSeed-169986037*/count=762; tryItOut("testMathyFunction(mathy0, /*MARR*/[new Number(1.5),  /x/ , objectEmulatingUndefined(), -Infinity, -Infinity, objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity, new Number(1.5), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Infinity,  /x/ , objectEmulatingUndefined(),  /x/ ,  /x/ , -Infinity, new Number(1.5),  /x/ , objectEmulatingUndefined(),  /x/ , new Number(1.5), new Number(1.5),  /x/ , -Infinity, new Number(1.5), objectEmulatingUndefined(),  /x/ ]); ");
/*fuzzSeed-169986037*/count=763; tryItOut("\"use strict\"; print(uneval(b2));");
/*fuzzSeed-169986037*/count=764; tryItOut("\"use asm\"; this.s1 = s2.charAt(18);function x((typeof this.__defineGetter__(\"e\", String.prototype.trimRight)), e)\"use asm\";   var Infinity = stdlib.Infinity;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    (Float64ArrayView[((0x5bb45c62)) >> 3]) = ((d1));\n    d0 = (d0);\n    d0 = ((makeFinalizeObserver('tenured')) <<= (/*FARR*/[x, (uneval( /x/g )), -18 && this].sort(String.prototype.repeat, let (c =  '' )  /x/g )));\n    return +((Infinity));\n  }\n  return f;/*bLoop*/for (let uqgtfn = 0; uqgtfn < 1; ++uqgtfn) { if (uqgtfn % 5 == 3) { o1.a2 = arguments.callee.caller.caller.arguments; } else {  }  } \u0009");
/*fuzzSeed-169986037*/count=765; tryItOut("Array.prototype.sort.apply(a1, [this.f1, m0]);function x(w, a, d, x,  , d, c, NaN, b, x = undefined, e, \u3056, b, x = \"\\uF575\", x, x, x = window, y, e, e, \u3056, d, x = -17, z = \"\\u1175\", eval, a, x, e = true, w, c, window, b) { for (var v of h1) { try { a2.reverse(); } catch(e0) { } try { Array.prototype.shift.call(a1); } catch(e1) { } print(uneval(g2.h1)); } } return [,,];");
/*fuzzSeed-169986037*/count=766; tryItOut("\"use strict\"; /*MXX2*/g0.Function.length = o0.e1;");
/*fuzzSeed-169986037*/count=767; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=768; tryItOut("\"use strict\"; let(a) ((function(){eval = z;})());");
/*fuzzSeed-169986037*/count=769; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ( + Math.pow(( + Math.pow((Math.imul(Math.fround(Math.log(Math.fround(x))), ( ! (y , 0))) >>> 0), Math.sin(Math.fround((Math.imul((x >>> 0), (Math.min(-0x080000001, (y ^ x)) >>> 0)) >>> 0))))), ( + Math.min(((( + ( ! ( + x))) ? Math.imul(y, x) : (((( ! Math.fround(y)) | 0) !== ((y <= Math.max(x, (x | 0))) >>> 0)) | 0)) >>> 0), Math.asinh(( ~ -0x100000000)))))); }); testMathyFunction(mathy4, [-(2**53+2), 2**53+2, -0, 0x07fffffff, -Number.MIN_VALUE, 0x100000000, -0x100000001, 1, -0x080000000, 2**53-2, -1/0, 42, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 0x080000001, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, 0x080000000, -0x0ffffffff, 0, 2**53, -Number.MAX_VALUE, Math.PI, 0x100000001, -(2**53), -(2**53-2), -Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-169986037*/count=770; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3{3}\\\\1+((?:$)|\\\\2)\\\\3|\\\\b\\\\B|.|[^\\\\u002A-\\\\v\\\\cY]*?*?\", \"gm\"); var s = (yield ((uneval(Math.atan2(-4, 0.354))))); print(r.test(s)); ");
/*fuzzSeed-169986037*/count=771; tryItOut("a1.push(f0, a0);");
/*fuzzSeed-169986037*/count=772; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?:(?:\\\\2{0,}\\\\1*|[^]|\\\\W{3,4}+(?:(?=\\\\b{1024,}(?![^]){3})))|((?:\\\\3(?:(?:\\\\W)|[^\\\\d]\\\\w*))))\", \"gy\"); var s = \"\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=773; tryItOut("while((window) && 0)Math;");
/*fuzzSeed-169986037*/count=774; tryItOut("with((void options('strict_mode')))/*tLoop*/for (let x of /*MARR*/[Infinity, -0x080000001, Infinity, -0x080000001, -(2**53), -0x080000001, -(2**53+2), function(){}, function(){}, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001, -0x080000001]) { g1.a2 + f2; }");
/*fuzzSeed-169986037*/count=775; tryItOut("\"use strict\"; var r0 = 1 + 9; var r1 = r0 & r0; var r2 = 5 % 2; r2 = 7 + 8; var r3 = x * 7; var r4 = 4 | 6; var r5 = 7 + r4; var r6 = r1 + r2; print(r1); var r7 = r4 ^ r2; r6 = r1 & r4; var r8 = 0 + r7; var r9 = x & r3; var r10 = r6 + x; var r11 = 1 % 5; var r12 = r1 + 3; var r13 = 2 | 1; r2 = r11 + 7; var r14 = r6 * r4; var r15 = r3 ^ r9; var r16 = 8 | r7; print(r4); var r17 = r15 / r6; var r18 = r6 & r9; var r19 = r2 % r14; r15 = r16 * r9; var r20 = r17 / r4; r15 = 0 & r16; var r21 = 1 + x; var r22 = 4 / r6; r16 = r13 | r12; var r23 = 1 | r16; var r24 = x | r21; var r25 = r1 | 5; var r26 = 1 * 0; var r27 = 0 * r8; var r28 = 8 ^ 1; var r29 = r11 ^ 8; r13 = r21 % 2; var r30 = 0 & 5; var r31 = r25 * 4; var r32 = r13 ^ r30; var r33 = r13 % 0; var r34 = r22 & 7; var r35 = 4 - r3; var r36 = 1 % 2; var r37 = r1 / r13; var r38 = 0 + r30; ");
/*fuzzSeed-169986037*/count=776; tryItOut("mathy5 = (function(x, y) { return (( + (((Math.cos((Math.hypot(Math.pow((Math.fround((Math.fround(y) ** Math.fround(x))) | 0), -0x07fffffff), ( - Math.fround(x))) > mathy0(-(2**53+2), 0x100000001))) >>> 0) === ((mathy1(Math.tanh(( + mathy1(( + (( ~ 0x080000001) >>> 0)), ( + 0x080000001)))), (((Math.hypot(( + y), Math.asinh(x)) >>> 0) == y) >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy5, [0x080000000, 2**53+2, -(2**53+2), -0x07fffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0, -0x080000000, -0x080000001, 42, 0x100000001, -(2**53), 2**53-2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 0, -(2**53-2), 0x100000000, -0x100000000, 0/0, -0x100000001, Math.PI, Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 1, 0x080000001, 0.000000000000001]); ");
/*fuzzSeed-169986037*/count=777; tryItOut("with({}) { x = x; } b = eval;");
/*fuzzSeed-169986037*/count=778; tryItOut("/*infloop*/M:do v0 = NaN; while((/*FARR*/['fafafa'.replace(/a/g, (new Function(\"b0 = g2.a0[v0];\"))), ((void shapeOf(({} = \"\\u9992\")))), , x, (4277), .../*MARR*/[ 'A' , arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee,  'A' ,  'A' , x,  'A' , x, arguments.callee,  'A' , x, x,  'A' , x, x,  'A' , x, x,  'A' ,  'A' , x, arguments.callee, arguments.callee, arguments.callee, arguments.callee, x, arguments.callee, arguments.callee, arguments.callee,  'A' , arguments.callee, x, x,  'A' , x, arguments.callee,  'A' , arguments.callee,  'A' , arguments.callee, arguments.callee,  'A' , arguments.callee, arguments.callee, arguments.callee, arguments.callee, arguments.callee,  'A' , arguments.callee]].sort(x =>  { \"use strict\"; return Object.defineProperty(b, \"constructor\", ({writable: (x % 6 == 5)})) } )));");
/*fuzzSeed-169986037*/count=779; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( ! ((Math.atan(Math.sinh((( + Math.expm1(( + y))) >>> 0))) | 0) | 0)) | 0); }); testMathyFunction(mathy4, [42, 0x080000000, -0x0ffffffff, Number.MIN_VALUE, 1/0, 1, -0x07fffffff, -(2**53), -Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, 0, 2**53+2, Number.MIN_SAFE_INTEGER, -0, -0x080000000, -1/0, 0/0, 0x07fffffff, -(2**53+2), 0x100000001, -0x100000000, 1.7976931348623157e308, 0x0ffffffff, Math.PI, -(2**53-2), -Number.MAX_VALUE, 0x080000001, Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x080000001, 2**53-2, -0x100000001]); ");
/*fuzzSeed-169986037*/count=780; tryItOut("for (var v of this.a1) { v2 = evalcx(\"/* no regression tests found */\", this.g1); }");
/*fuzzSeed-169986037*/count=781; tryItOut("\"use strict\"; /*infloop*/ for (e of true.unwatch(\"y\").valueOf(\"number\")) {v2 = a1.length; }");
/*fuzzSeed-169986037*/count=782; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    return ((((+(0.0/0.0)) != (+/*FFI*/ff()))-((((0x2d9224fc))|0))))|0;\n  }\n  return f; })(this, {ff: function  d ()\"\\u7D80\".__defineGetter__(\"c\", (encodeURIComponent).bind)}, new ArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=783; tryItOut("for(let b of /*FARR*/[[z1]]) return \"\\u68E1\";try { ( /x/g ); } catch(x) { window; } ");
/*fuzzSeed-169986037*/count=784; tryItOut("\"use strict\"; selectforgc(o2);");
/*fuzzSeed-169986037*/count=785; tryItOut("g1.v0 = evalcx(\"/* no regression tests found */\", g1.g2);\nthis.a2.push(a2);\n");
/*fuzzSeed-169986037*/count=786; tryItOut("mathy1 = (function(x, y) { return (( ! (Math.cos(( + y)) ** (Math.min((( + (y || y)) >>> 0), ((Math.atan2((Math.atanh(mathy0((((y >>> 0) % x) | 0), (y >>> 0))) >>> 0), (Math.fround(Math.round(y)) | 0)) | 0) >>> 0)) >>> 0))) >>> 0); }); testMathyFunction(mathy1, [-(2**53), -0x07fffffff, 0x0ffffffff, 2**53-2, 2**53+2, Number.MIN_VALUE, -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, 0/0, -(2**53-2), -0x0ffffffff, -0x100000000, 0x100000000, 0.000000000000001, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 0x07fffffff, -0, Number.MAX_SAFE_INTEGER, 0x100000001, 0, 1/0, Math.PI, 0x080000000, 1, 0x080000001, -0x100000001, 42, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=787; tryItOut("\"use strict\"; /*RXUB*/var r = /\\1/gym; var s = \"0\\n\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-169986037*/count=788; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=789; tryItOut("\"use strict\"; var w = \"\\uD5A1\", eval = \n((void version(170))), x = x, reqvua, [, ] = [] = Math.atanh(/(?:[^])/g), window = /*UUV1*/(z.hypot = {});(\"\\u9FEB\");\nv1 = (b0 instanceof t0);\n");
/*fuzzSeed-169986037*/count=790; tryItOut("\"use strict\"; /*MXX3*/g0.Function.prototype.toString = g0.Function.prototype.toString;");
/*fuzzSeed-169986037*/count=791; tryItOut("\"use strict\"; e2.add(this.b2);");
/*fuzzSeed-169986037*/count=792; tryItOut("/*oLoop*/for (var imymru = 0, nkktqj; imymru < 8; ++imymru, new ( /x/ )()) { for (var p in v2) { try { v2 = evaluate(\"this.e2 = new Set;\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 2 == 0), noScriptRval: true, sourceIsLazy: e, catchTermination: false })); } catch(e0) { } try { this.a1.unshift(x, s0, t0, t0, h0, f0, h1, e2); } catch(e1) { } a2 = r0.exec(s1); } } ");
/*fuzzSeed-169986037*/count=793; tryItOut("for (var p in p0) { try { delete h1[\"19\"]; } catch(e0) { } try { v0 = (i2 instanceof this.o2.b0); } catch(e1) { } a1.reverse(b2); }");
/*fuzzSeed-169986037*/count=794; tryItOut("m0.get(i2);");
/*fuzzSeed-169986037*/count=795; tryItOut("o1 = Object.create(f0);");
/*fuzzSeed-169986037*/count=796; tryItOut("a0 = Array.prototype.concat.call(a2, t1, a1, this.g2.a1, a2);");
/*fuzzSeed-169986037*/count=797; tryItOut("b1 = new SharedArrayBuffer(14);");
/*fuzzSeed-169986037*/count=798; tryItOut("L: {print(g2);a1 = []; }");
/*fuzzSeed-169986037*/count=799; tryItOut("testMathyFunction(mathy4, [Number.MIN_VALUE, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53, -(2**53-2), -0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53), -0x100000001, 0x0ffffffff, -Number.MAX_VALUE, 0/0, 0x080000001, 1.7976931348623157e308, -0, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, 42, 0x07fffffff, 0x100000000, -Number.MAX_SAFE_INTEGER, 1, 1/0, 0, -0x080000000, 0.000000000000001, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -1/0, 0x080000000, 2**53-2, -0x100000000, Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=800; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.log10(Math.fround(Math.fround(Math.atan2(Math.pow(Math.fround((Math.cos((x | 0)) >>> 0)), (( ! ( + -1/0)) >>> 0)), ( + Math.abs((0x07fffffff >>> 0))))))); }); testMathyFunction(mathy4, [-0, Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, 0/0, 0x080000000, Number.MIN_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, 0x080000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 0, 1, 0.000000000000001, 0x100000000, 2**53+2, -(2**53), -(2**53-2), 2**53-2, -Number.MAX_VALUE, -(2**53+2), -0x100000001, 42, -1/0, 1/0, 0x100000001, Math.PI, 2**53]); ");
/*fuzzSeed-169986037*/count=801; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.min(( ~ Math.sqrt(mathy4((((( - y) ? -0 : (Math.atanh((x | 0)) | 0)) | 0) >>> 0), (Math.fround(Math.imul(x, x)) >>> 0)))), ( + ((( - Math.fround(((x ? mathy1((0x100000000 | 0), -0x100000000) : x) ? mathy1(0.000000000000001, y) : Math.sign(y)))) >>> 0) ? Math.fround(Math.atan(((y >> y) | 0))) : (y !== Math.clz32(((y == (x > Math.trunc((x | 0)))) | 0)))))) | 0); }); testMathyFunction(mathy5, ['0', '\\0', 0.1, null, '/0/', NaN, (new Number(-0)), (new Boolean(true)), ({toString:function(){return '0';}}), -0, [], true, (new Number(0)), 1, undefined, ({valueOf:function(){return 0;}}), 0, [0], (new String('')), /0/, (function(){return 0;}), ({valueOf:function(){return '0';}}), (new Boolean(false)), false, '', objectEmulatingUndefined()]); ");
/*fuzzSeed-169986037*/count=802; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return mathy3(((Math.max(Math.fround(( + Math.pow((mathy0(Math.fround(Math.exp(Math.fround(x))), ( ! Math.fround((y & x)))) | 0), y))), Math.fround(( ~ Number.MIN_SAFE_INTEGER))) | 0) | Math.fround(Math.abs((Math.sign((Number.MAX_VALUE - x)) | 0)))), (( ! ( + Math.hypot((x >>> 0), ((y != (-(2**53+2) >>> 0)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -0x080000000, -(2**53-2), -0x080000001, 0x080000001, 0/0, -0x0ffffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53, 2**53-2, -1/0, 0x0ffffffff, -0x100000000, 42, -0x07fffffff, 0, 0x100000000, 1, -Number.MAX_SAFE_INTEGER, -0, 0x100000001, Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -(2**53), 0.000000000000001, 2**53+2, 0x07fffffff, Number.MIN_VALUE, Math.PI, 1/0, 0x080000000]); ");
/*fuzzSeed-169986037*/count=803; tryItOut("\"use strict\"; neuter(g2.b0, \"change-data\");");
/*fuzzSeed-169986037*/count=804; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(((( + ( + (y , Math.pow(x, -0x100000000)))) - Math.fround(Math.imul(Math.fround(x), (Math.pow(x, x) | 0)))) <= Math.fround((((( ~ ((-0x07fffffff >>> 0) % x)) | 0) && ( ! mathy0((y | 0), x))) | 0)))); }); testMathyFunction(mathy1, [({valueOf:function(){return 0;}}), (function(){return 0;}), 1, (new Number(0)), undefined, (new Number(-0)), ({valueOf:function(){return '0';}}), true, (new Boolean(true)), objectEmulatingUndefined(), NaN, '', -0, '/0/', null, '\\0', /0/, ({toString:function(){return '0';}}), false, [], '0', 0, 0.1, [0], (new Boolean(false)), (new String(''))]); ");
/*fuzzSeed-169986037*/count=805; tryItOut("/*RXUB*/var r = new RegExp(\"(?=(\\\\s|[\\\\S])+(^)((?:(?=^|\\u5d46*?)))?|(?:(?!(?:.))|^|\\\\1{3})|\\\\S(?=[^]?){1,1048576})\", \"g\"); var s = \"____a\\n\\n\\n_____\"; print(s.split(r)); ");
/*fuzzSeed-169986037*/count=806; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.cbrt((((Math.log2((Math.trunc(Math.imul(x, ( + 0.000000000000001))) >>> 0)) >>> 0) >> (( + Math.cosh(( + (Math.sinh(( + (( + y) ? Math.fround(y) : ( + y)))) & y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [-Number.MIN_VALUE, Number.MAX_VALUE, -0x100000001, 2**53+2, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, 0.000000000000001, 0x080000000, 1, -0x0ffffffff, -(2**53), -0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, 42, 2**53-2, 0x100000000, 1/0, -(2**53+2), 0, Math.PI, -1/0, Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0/0, -0x080000001, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=807; tryItOut("/*infloop*/for(let (a.throw(this)).valueOf(\"number\") in x) {v0 = g1.g2.a1.length; }");
/*fuzzSeed-169986037*/count=808; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return ((((((((( ! (y | 0)) | 0) - ( + Math.max(y, Math.cbrt(Math.sin((y | 0)))))) >>> 0) >>> Math.fround(Math.atan2(x, ( + (( + x) ? ( + y) : ( + 0.000000000000001)))))) >>> 0) | 0) === ( + Math.imul(( - Number.MAX_SAFE_INTEGER), (( + Math.fround(Math.sinh((( + (mathy0(y, (( + (( + -0x100000001) < ( + x))) >>> 0)) >>> 0)) << Math.fround(Math.max(( + Math.fround(mathy1(x, Math.fround(x)))), x)))))) | 0)))) | 0); }); testMathyFunction(mathy2, [-1/0, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 42, 1/0, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -0x100000001, 1.7976931348623157e308, -Number.MIN_VALUE, 0x080000000, -0x100000000, -0, 1, 0x07fffffff, 0, -0x080000000, 2**53+2, 0x080000001, 0x100000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, Math.PI, -0x07fffffff, 2**53-2, -(2**53-2), -(2**53), -Number.MAX_VALUE, 0/0, -(2**53+2), 0x100000000, -0x080000001]); ");
/*fuzzSeed-169986037*/count=809; tryItOut("neuter(b2, \"same-data\");");
/*fuzzSeed-169986037*/count=810; tryItOut("");
/*fuzzSeed-169986037*/count=811; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.fround(Math.imul((Math.imul((x | 0), ( + Math.min(Math.exp((y , Math.fround(y))), ( + y)))) !== ( + Math.min(( ! 2**53-2), ( + (Math.asinh((Math.max(y, x) >>> 0)) >>> 0))))), Math.fround(( ~ (( ! ((((Math.fround(Math.min(2**53, x)) >>> 0) || (x >>> 0)) >>> 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy2, [(function(){return 0;}), objectEmulatingUndefined(), 1, NaN, '/0/', 0, undefined, '\\0', ({valueOf:function(){return '0';}}), false, (new Boolean(true)), ({toString:function(){return '0';}}), 0.1, true, -0, (new String('')), '0', (new Number(-0)), /0/, ({valueOf:function(){return 0;}}), '', (new Number(0)), null, (new Boolean(false)), [0], []]); ");
/*fuzzSeed-169986037*/count=812; tryItOut("\"use strict\"; (/(?!\\0|[^]?)+?|(?!(?!^{0}|.\\w+?{2,6}))/gm);\nthis.o2.t0 = t0.subarray(12);\n");
/*fuzzSeed-169986037*/count=813; tryItOut("/*infloop*/L: for (var new x.__defineGetter__(\"x\", (Math.clz32).apply)( ''  + 28,  /x/g ).x of --x) {/* no regression tests found */this.g1.offThreadCompileScript(\"function f1(t1)  { \\\"use strict\\\"; \\\"use asm\\\"; delete g2[\\\"caller\\\"]; } \"); }");
/*fuzzSeed-169986037*/count=814; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      (Uint8ArrayView[(0x72f66*(i0)) >> 0]) = (0xce820*(0xf972700c));\n    }\n    return +((4503599627370496.0));\n  }\n  return f; })(this, {ff: /*wrap3*/(function(){ \"use strict\"; var vccvnj = (p={}, (p.z = this)()); ((Set.prototype.add).bind((neuter)()))(); })}, new ArrayBuffer(4096)); testMathyFunction(mathy2, [0x100000001, -Number.MIN_SAFE_INTEGER, -0x100000001, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 42, -0x100000000, 2**53+2, Math.PI, -0x07fffffff, -0x080000001, 0x100000000, 1/0, -0x0ffffffff, -0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x080000000, 0.000000000000001, 0x080000001, Number.MAX_VALUE, -0, 1, -Number.MAX_VALUE, 2**53, -1/0, 0/0, -(2**53+2), -(2**53-2), 1.7976931348623157e308, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=815; tryItOut("/*vLoop*/for (let rqxdef = 0, x; rqxdef < 3; ++rqxdef) { var b = rqxdef; var cpfdis = new SharedArrayBuffer(4); var cpfdis_0 = new Int8Array(cpfdis); o1 = Object.create(g2); } ");
/*fuzzSeed-169986037*/count=816; tryItOut("p0 + '';");
/*fuzzSeed-169986037*/count=817; tryItOut("mathy2 = (function(x, y) { return ( + (( + Math.fround(( - Math.fround(Math.fround(Math.log10(( ! x))))))) + ( + (Math.fround((( + x) ** Math.fround(Math.fround(( ! ( + mathy1(( + y), ( + x)))))))) >= ( + ( + ( + (mathy1((Math.fround(Math.imul(( + x), x)) == ( + Math.cos(y))), (y ? ( + (y >> y)) : (Math.fround((( + y) & y)) >>> 0))) ? Math.atanh((0 >>> 0)) : Math.fround(( ~ 1/0)))))))))); }); testMathyFunction(mathy2, [-0, 0x0ffffffff, 0x080000000, 0x07fffffff, 0x100000001, -(2**53-2), 1/0, -0x100000000, Number.MAX_SAFE_INTEGER, 42, -Number.MAX_VALUE, -0x07fffffff, Math.PI, 0x080000001, -(2**53+2), Number.MIN_VALUE, 0x100000000, 1, Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_VALUE, 1.7976931348623157e308, 2**53, -1/0, 0, -0x100000001, -(2**53), -0x080000001, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53-2, 0/0, 0.000000000000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=818; tryItOut("\"use strict\"; t1.set(t0, 8);");
/*fuzzSeed-169986037*/count=819; tryItOut("this.s2.__proto__ = m1;");
/*fuzzSeed-169986037*/count=820; tryItOut("x;");
/*fuzzSeed-169986037*/count=821; tryItOut("\"use strict\"; o1.valueOf = (function() { for (var j=0;j<45;++j) { f0(j%4==1); } });");
/*fuzzSeed-169986037*/count=822; tryItOut("mathy3 = (function(x, y) { return (Math.cos(((Math.sqrt(((( + ( ~ (Math.fround(-0x0ffffffff) % y))) ? (Math.imul((Math.fround(( ! Math.fround(y))) >>> 0), (Math.fround(Math.max((y | 0), ((Math.fround(x) !== Math.fround((y !== (x >>> 0)))) >>> 0))) | 0)) >>> 0) : ( + ((( + mathy1(x, y)) ? ( + ( ~ -Number.MAX_SAFE_INTEGER)) : ( + x)) >= ( - y)))) >>> 0)) | 0) | 0)) >>> 0); }); testMathyFunction(mathy3, [-(2**53), -(2**53-2), -0x080000001, 2**53, 2**53-2, 0, -0x07fffffff, 0x080000001, 1/0, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000001, -1/0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53+2, -0, 0x100000001, -0x080000000, -(2**53+2), 0x100000000, Math.PI, -0x100000000, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x07fffffff, 0x0ffffffff, 0x080000000, 1.7976931348623157e308, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1, 42, 0/0]); ");
/*fuzzSeed-169986037*/count=823; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.cosh(( + ((( + ( + Math.pow(( + (y >>> 0)), (y ? x : y)))) | 0) - (( + (( + (Math.pow((x | 0), (Math.imul(x, Math.min(0.000000000000001, y)) | 0)) >>> 0)) ? ( + ( + mathy0((( - Math.fround(mathy0(1/0, y))) >>> 0), x))) : ( + Number.MAX_VALUE))) | 0)))); }); ");
/*fuzzSeed-169986037*/count=824; tryItOut("L:switch((arguments.callee)() - Math.atan2( '' , /[\\cO\\0-\\cE]/im)) { case ([z1,,]): break; case (Math.pow(-16, ((uneval( \"\" ))))): for (var p in a2) { try { o0.o0 = Object.create(s1); } catch(e0) { } try { v2 = Object.prototype.isPrototypeOf.call(t0, this.i2); } catch(e1) { } a0[v2]; }break;  }");
/*fuzzSeed-169986037*/count=825; tryItOut("(yield 15);\nt1.__proto__ = t2;\n");
/*fuzzSeed-169986037*/count=826; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=827; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1, 2**53-2, 42, -1/0, Number.MAX_VALUE, 2**53+2, 0x100000001, -(2**53+2), 2**53, -0x07fffffff, -0x080000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, -0x080000000, Math.PI, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, 0x080000001, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), 0.000000000000001, -(2**53-2), -0x100000001, 0, 0x100000000, 0/0]); ");
/*fuzzSeed-169986037*/count=828; tryItOut("f0 + g1;");
/*fuzzSeed-169986037*/count=829; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (1.1805916207174113e+21);\n    }\n    return ((-0x4a4f0*(0x6f922ed7)))|0;\n  }\n  return f; })(this, {ff: neuter}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=830; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return ((((0x7a719*((0xef061cd2))) & ((i0)-(i0)-(i0))) % (((!((((0xc3ae4b37) % (0x9363bf3b)) | ((/*FFI*/ff(((x)), ((6.189700196426902e+26)), ((16385.0)), ((-18446744073709552000.0)), ((-262144.0)))|0)))))) | (((b = (({/*toXFun*/toSource: function() { return this; }, 10: /(^([\\u0049-\\u84b3])*?\\b|E{2,}[^]{2,}){2,6}/ }))).__defineGetter__(\"x\", Math.asinh))-(0x550c094c)-(0xfe06fe80)))))|0;\n  }\n  return f; })(this, {ff: neuter}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), 0x080000000, 0/0, -0x100000000, 2**53+2, -0x080000000, -Number.MAX_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 42, -(2**53), Number.MAX_VALUE, 2**53-2, 0x100000001, -Number.MIN_VALUE, -(2**53-2), 0x07fffffff, -0x080000001, 0, 0x100000000, 1/0, 0.000000000000001, 2**53, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -0, -0x07fffffff, -1/0, Number.MIN_VALUE, 1, 1.7976931348623157e308, -0x100000001]); ");
/*fuzzSeed-169986037*/count=831; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return ( - Math.exp(( + ( + ( + y))))); }); testMathyFunction(mathy5, [Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 2**53+2, -0, 0, 0x100000001, 42, 2**53-2, 0.000000000000001, 0x07fffffff, 0x080000001, -0x100000000, 1.7976931348623157e308, -0x100000001, 0x0ffffffff, Number.MAX_VALUE, 0/0, 0x080000000, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53, -Number.MAX_VALUE, -(2**53+2), 0x100000000, Math.PI, -(2**53), -0x080000001, -0x07fffffff, -1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, -Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-169986037*/count=832; tryItOut("this.b0 + g1;");
/*fuzzSeed-169986037*/count=833; tryItOut("x.constructor;");
/*fuzzSeed-169986037*/count=834; tryItOut("");
/*fuzzSeed-169986037*/count=835; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.imul(( + (( + mathy0((y << x), -1/0)) && Math.fround((( ! (x >>> 0)) ? Math.fround(x) : Math.clz32(y))))), (mathy4((((( + (((Math.sinh(y) >>> 0) , (x | 0)) | 0)) >>> 0) >>> y) >>> 0), ( + (Number.MIN_SAFE_INTEGER ? -0x07fffffff : Math.fround(Math.cos(x))))) >>> 0))); }); testMathyFunction(mathy5, [-0x100000000, -0x0ffffffff, Math.PI, Number.MAX_VALUE, -(2**53-2), 0x07fffffff, 0, 0x080000000, -Number.MIN_VALUE, 0x100000000, 2**53+2, 2**53-2, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, 1/0, Number.MIN_VALUE, 0/0, 0.000000000000001, 0x100000001, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0, 0x080000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, 42, 1, -(2**53), -0x080000000, -1/0]); ");
/*fuzzSeed-169986037*/count=836; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.tan(( - Math.min(((x >>> 0) , x), ( + (( + ( - Math.max(y, -0x07fffffff))) > -(2**53+2)))))); }); testMathyFunction(mathy4, [1, 0x07fffffff, 0x080000000, 0/0, 0x0ffffffff, -0x100000000, 2**53-2, 0.000000000000001, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53+2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), Math.PI, -(2**53), Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -1/0, 0x080000001, 0x100000001, -0x100000001, 2**53+2, Number.MAX_VALUE, 42, 0x100000000, 0, -0, 2**53, 1/0]); ");
/*fuzzSeed-169986037*/count=837; tryItOut("\"use strict\"; /*vLoop*/for (etzwmc = 0; etzwmc < 6; ++etzwmc) { const d = etzwmc; print([,,]); } ");
/*fuzzSeed-169986037*/count=838; tryItOut("\"use strict\"; Array.prototype.sort.apply(g1.a0, [(function() { for (var j=0;j<20;++j) { f2(j%4==0); } }), v2, m2]);");
/*fuzzSeed-169986037*/count=839; tryItOut("mathy2 = (function(x, y) { return mathy0(Math.fround(( ~ Math.fround((((( + ((( + Math.atan2(x, -(2**53))) | 0) >>> ((Math.cosh(( + 0.000000000000001)) >>> y) | 0))) | 0) !== mathy0(-Number.MIN_SAFE_INTEGER, ( + (y <= ( + y))))) | 0)))), ( ~ ((Math.clz32(( + x)) | 0) ? (Math.atan(((Math.exp(( + -Number.MIN_VALUE)) !== x) >>> 0)) >>> 0) : ( ! Math.pow(((((y | 0) < (( ! y) | 0)) | 0) | 0), 2**53+2))))); }); testMathyFunction(mathy2, [-0x100000001, 0x080000000, 2**53-2, -0x07fffffff, 0.000000000000001, 42, -Number.MAX_VALUE, -(2**53-2), Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53), -1/0, -0x100000000, -(2**53+2), 0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -0, 0x0ffffffff, 0x100000001, 2**53+2, 1/0, -0x0ffffffff, 1, 0, -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000, 2**53, 0x080000001, 1.7976931348623157e308, 0x100000000]); ");
/*fuzzSeed-169986037*/count=840; tryItOut("\"use strict\"; e2.add(e2);");
/*fuzzSeed-169986037*/count=841; tryItOut("v2 = (t0 instanceof f1);");
/*fuzzSeed-169986037*/count=842; tryItOut("const e = ({z:  '' }), z = x, x = ((function factorial(kwppcg) { ; if (kwppcg == 0) { ; return 1; } ; return kwppcg * factorial(kwppcg - 1);  })(1)).eval(\"\\\"use strict\\\"; v2 = a2.reduce, reduceRight((function() { for (var j=0;j<6;++j) { f0(j%5==0); } }));\"), \u3056 = x, jwkphk, z, zsopff, {e: [], z: [x]} = (function(q) { return q; });/*oLoop*/for (var lljnmp = 0; lljnmp < 51; ++lljnmp, ~ \"\" ) { print(x); } ");
/*fuzzSeed-169986037*/count=843; tryItOut("\"use strict\"; this.t0.toString = (function() { m0.valueOf = (function() { Array.prototype.sort.call(a2, f1); return v2; }); return a2; });");
/*fuzzSeed-169986037*/count=844; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return mathy0((Math.cbrt((( ~ y) >>> 0)) >>> 0), (( + (( - (y | 0)) | 0)) >>> ((y ? (( ! y) + Math.fround(( - Math.fround((x & y))))) : (((y ? y : x) >= -0x07fffffff) ? x : y)) ** (y / x)))); }); testMathyFunction(mathy1, [-(2**53), -0x100000001, 0/0, 42, 0x100000001, 2**53-2, 0.000000000000001, -0x07fffffff, 2**53+2, Math.PI, -0x080000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, 0, -Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, 1, -(2**53+2), Number.MAX_SAFE_INTEGER, 1/0, Number.MIN_VALUE, -0x080000000, 0x07fffffff, -(2**53-2), 0x100000000, -1/0, -Number.MAX_VALUE, 2**53, 1.7976931348623157e308, -0x0ffffffff, Number.MAX_VALUE, -0, 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=845; tryItOut("v2 = g1.runOffThreadScript();");
/*fuzzSeed-169986037*/count=846; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-0x0ffffffff, 2**53+2, 0x07fffffff, 0x100000000, Number.MIN_VALUE, -(2**53+2), -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, -0x080000001, 42, -0x07fffffff, 1/0, 0x100000001, Math.PI, -Number.MAX_SAFE_INTEGER, 0, 0x080000000, -0x100000000, -(2**53), 0.000000000000001, 1.7976931348623157e308, -1/0, -Number.MIN_SAFE_INTEGER, 1, 2**53-2, 0x080000001, 0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53, -0x080000000, 0/0, -0]); ");
/*fuzzSeed-169986037*/count=847; tryItOut("g0.__proto__ = s2;\n/* no regression tests found */\n");
/*fuzzSeed-169986037*/count=848; tryItOut("(((x) = {} = (new Function(\"print(null);\")).prototype));");
/*fuzzSeed-169986037*/count=849; tryItOut("h0 + g2;");
/*fuzzSeed-169986037*/count=850; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=851; tryItOut("testMathyFunction(mathy3, [42, -(2**53), 2**53+2, -Number.MAX_VALUE, -0, -0x080000000, -(2**53+2), 0x0ffffffff, -0x100000001, 0, Number.MAX_VALUE, 0x100000001, 2**53, 2**53-2, 1/0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -(2**53-2), -0x100000000, -0x07fffffff, -0x080000001, 0x100000000, 1, 0.000000000000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 0/0, 1.7976931348623157e308, -1/0]); ");
/*fuzzSeed-169986037*/count=852; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"[^]|(\\\\3)\", \"g\"); var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=853; tryItOut("\"use strict\"; \"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return Math.log1p(( + ( ~ ((y >>> 0) ** (x >>> 0))))); }); ");
/*fuzzSeed-169986037*/count=854; tryItOut("for (var v of o2) { try { a1.splice(-7, v2); } catch(e0) { } t2[v0] = \"\\uA313\"; }");
/*fuzzSeed-169986037*/count=855; tryItOut("x = (yield ()), z = (let (abebun)  /x/g ), [] =  '' , d, jxgjyh, xewbjz, ppckdt, d, b;/*RXUB*/var r = new RegExp(\"(?:[^]|\\\\B|(?![^])*?*{0,}|[^]|(?=(?=\\\\0\\\\0)+?){0,0})|(?!\\\\2+){3,4}\", \"gyim\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-169986037*/count=856; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.atan2((Math.imul((Math.fround(Math.atanh(Math.fround(( ~ (( ~ (Math.fround((y | -Number.MAX_SAFE_INTEGER)) | 0)) | 0))))) >>> 0), (Math.fround((Math.fround((( + y) || ((Math.fround(y) ? Math.fround(y) : Math.fround((Math.cbrt((1.7976931348623157e308 | 0)) | 0))) >>> 0))) <= (Math.fround(Math.min(Math.fround(Math.hypot((y >>> 0), Math.fround(Math.hypot(Number.MAX_VALUE, Math.fround(x))))), Math.fround(0/0))) | 0))) >>> 0)) >>> 0), (Math.log10(( + ((Math.atan2(x, ( + mathy1(( + y), 0x080000001))) | 0) < (Math.sinh(-0x100000000) | 0)))) == (Math.fround(Math.imul(Math.fround(( - (y | 0))), Math.fround(y))) <= Math.fround((( + y) && Math.fround(Math.fround(( ! ( + ( + Math.atanh(Math.fround(x)))))))))))); }); testMathyFunction(mathy5, /*MARR*/[true, true, true, true, undefined, undefined, true, true, true, true, undefined, undefined, undefined, undefined, undefined, undefined, undefined, true, undefined, true, undefined, undefined, true, undefined, undefined, undefined, true, undefined, undefined, true, undefined, undefined, undefined, true, undefined, undefined, undefined, undefined, undefined, true, true, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, true, undefined, undefined, true, undefined, undefined, undefined, true, undefined, true, undefined, true, undefined, undefined, undefined, true, true, true, true, undefined, undefined, undefined, undefined, undefined, undefined, true, undefined, undefined, undefined, undefined, true, undefined, undefined, true, true, undefined, undefined, undefined, true, true, undefined, undefined, undefined, true, undefined, undefined, true, undefined, true, undefined, true, true, undefined, true, undefined, true, true, undefined, true, true, true, true, true, true, undefined, undefined, undefined, undefined, true, undefined, true, true, true, undefined, true, undefined, undefined, undefined, undefined, true, undefined, undefined, true, undefined, undefined, true, true, true, undefined, undefined, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, undefined, true, undefined, true, true]); ");
/*fuzzSeed-169986037*/count=857; tryItOut("do o0.m0 + p2;\n( \"\" );\n while((( /x/g .valueOf(\"number\"))) && 0);");
/*fuzzSeed-169986037*/count=858; tryItOut("h1 = {};");
/*fuzzSeed-169986037*/count=859; tryItOut("\"use strict\"; testMathyFunction(mathy1, [objectEmulatingUndefined(), [0], [], ({valueOf:function(){return 0;}}), ({valueOf:function(){return '0';}}), '', (new Boolean(true)), '0', '\\0', false, '/0/', (new Number(-0)), NaN, /0/, 0, (new Boolean(false)), (function(){return 0;}), -0, ({toString:function(){return '0';}}), 1, null, (new String('')), undefined, true, (new Number(0)), 0.1]); ");
/*fuzzSeed-169986037*/count=860; tryItOut("\"use strict\"; /*oLoop*/for (let txovnl = 0; txovnl < 81; ++txovnl) { v0 = evaluate(\"print(x);\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (NaN -  \"\" ), noScriptRval: false, sourceIsLazy: timeout(1800), catchTermination: \"\\uD8B2\", element: o2, elementAttributeName: s1 })); } ");
/*fuzzSeed-169986037*/count=861; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.ceil(Math.fround((mathy0((Math.fround(Math.atan2(Math.fround(( + -(2**53-2))), Math.fround(x))) >>> 0), Math.fround((Math.fround(Math.fround(( ! y))) ? Math.fround(Math.acosh(x)) : Math.fround(( + ( - (y / y))))))) >>> 0)))); }); testMathyFunction(mathy1, [-0x100000001, -0x080000000, -0, -1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53+2, 0x080000000, -(2**53+2), Number.MAX_VALUE, -0x080000001, 2**53, 1.7976931348623157e308, 0, 42, Number.MIN_SAFE_INTEGER, 2**53-2, 1/0, 0x100000001, 0/0, -(2**53-2), -0x07fffffff, 0x07fffffff, -Number.MIN_SAFE_INTEGER, Math.PI, -Number.MIN_VALUE, -0x100000000, 0x100000000, 0x080000001, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, -Number.MAX_VALUE, 1, -(2**53)]); ");
/*fuzzSeed-169986037*/count=862; tryItOut("/*vLoop*/for (let noltnm = 0; noltnm < 18; ++noltnm) { var e = noltnm; this.a2.sort((function mcc_() { var fhednq = 0; return function() { ++fhednq; if (false) { dumpln('hit!'); try { print(h0); } catch(e0) { } try { v2 = evalcx(\"function o2.f1(s1)  { yield a } \", g0); } catch(e1) { } this.g2.v1 = g2.a0[18]; } else { dumpln('miss!'); o0.m2.has(e0); } };})());\nprint(x);\n } ");
/*fuzzSeed-169986037*/count=863; tryItOut("g1.o0 + '';");
/*fuzzSeed-169986037*/count=864; tryItOut("this.g0.s0 += 'x';");
/*fuzzSeed-169986037*/count=865; tryItOut("\"use strict\"; print(x);h0.toString = f0;");
/*fuzzSeed-169986037*/count=866; tryItOut("\"use strict\"; let x, jpwrzg, x, e = x, x = (4277);var jthpno, x = \"\\u9E23\", huzsid;if((x % 2 != 1)) { if ([,]) {this.s2 += 'x';a2.reverse(); }} else o1.i0.toString = (function() { try { v0 = t1.byteLength; } catch(e0) { } /*MXX1*/o2 = g2.Date.prototype.setMinutes; return a0; });");
/*fuzzSeed-169986037*/count=867; tryItOut("g2.h0.getPropertyDescriptor = f2;");
/*fuzzSeed-169986037*/count=868; tryItOut("\"use strict\"; for (var p in b1) { try { g1.offThreadCompileScript(\"s2 += s0;\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: x, sourceIsLazy: x, catchTermination: true, element: o2 })); } catch(e0) { } try { t0 = new Uint8ClampedArray(b1, 64, 5); } catch(e1) { } try { v1 = Object.prototype.isPrototypeOf.call(o1, m0); } catch(e2) { } selectforgc(o1); }");
/*fuzzSeed-169986037*/count=869; tryItOut("function f0(m1)  { /*tLoop*/for (let z of /*MARR*/[Infinity, window,  /x/g , window, window]) { ((function ([y]) { })()); } } ");
/*fuzzSeed-169986037*/count=870; tryItOut("let (z = ( ''  && new RegExp(\"\\\\1\", \"ym\")), \u3056 = \"\u03a0\", ufrngu, fukezh, eval, butvhe, dmhwip, pdlpnn) { print(x); }");
/*fuzzSeed-169986037*/count=871; tryItOut("/*vLoop*/for (wrjibu = 0, eoefdi; wrjibu < 9; ++wrjibu) { const c = wrjibu; print(x); } ");
/*fuzzSeed-169986037*/count=872; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.log10(( + ( + Math.log10(Math.pow((y , x), ((Math.atan2(y, Math.max(y, x)) | 0) === (Math.atanh((y | 0)) | 0)))))))); }); testMathyFunction(mathy3, [/0/, true, '', undefined, ({valueOf:function(){return 0;}}), [0], (function(){return 0;}), ({valueOf:function(){return '0';}}), (new Number(0)), ({toString:function(){return '0';}}), (new Boolean(true)), -0, 0.1, '/0/', (new Boolean(false)), [], null, 1, (new Number(-0)), 0, false, (new String('')), '\\0', NaN, objectEmulatingUndefined(), '0']); ");
/*fuzzSeed-169986037*/count=873; tryItOut("testMathyFunction(mathy3, [Number.MAX_SAFE_INTEGER, -0x080000001, -Number.MAX_SAFE_INTEGER, 0x080000000, -0, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, 1, -0x07fffffff, 0x100000000, -1/0, Math.PI, 0x100000001, 0x0ffffffff, -0x100000001, -0x100000000, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 2**53, -(2**53+2), 0.000000000000001, 42, 0, Number.MIN_VALUE, 0x080000001, 2**53-2, -0x0ffffffff, 1.7976931348623157e308, -0x080000000, 0x07fffffff, -(2**53-2), -(2**53)]); ");
/*fuzzSeed-169986037*/count=874; tryItOut("a1.forEach((function() { try { /*ADP-3*/Object.defineProperty(a0, (++(new Object(-1309079677,  /x/ ))([[,,]])), { configurable: (4277), enumerable: (x % 2 != 1), writable: true, value: b1 }); } catch(e0) { } try { v2 = (a2 instanceof v0); } catch(e1) { } print(uneval(e2)); return t0; }), this.g0.g1.b0);");
/*fuzzSeed-169986037*/count=875; tryItOut("g1.a1.sort((function() { try { a1.shift(); } catch(e0) { } t2 = new Uint32Array(a0); return v0; }), t1, o2, this.m1, g2, g2.g1, b1);");
/*fuzzSeed-169986037*/count=876; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1.7976931348623157e308, 0x07fffffff, 2**53+2, -0x100000001, 1, 42, 0x100000000, -0x080000001, Number.MIN_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, 0.000000000000001, Number.MAX_SAFE_INTEGER, -0, 2**53, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, Math.PI, Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53), 0/0, -(2**53-2), 0x080000001, 0, 0x080000000, -1/0, 0x100000001, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=877; tryItOut("mathy4 = (function(x, y) { return ( + (( + Math.cbrt((( ! ( + ( - x))) >>> 0))) >>> ( + Math.acosh(Math.sin(Math.pow(Math.atan2(0x080000000, Number.MIN_SAFE_INTEGER), Math.log2(mathy3(0x07fffffff, ( - x))))))))); }); testMathyFunction(mathy4, [-0x100000001, -(2**53+2), -0, -0x07fffffff, Math.PI, 2**53, 0x080000001, 1.7976931348623157e308, Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, 0, 0x100000000, -(2**53-2), -Number.MIN_VALUE, -1/0, 1/0, -Number.MAX_VALUE, 0.000000000000001, 1, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53-2, -0x080000000, 42, -0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x080000001, 0x07fffffff, -(2**53)]); ");
/*fuzzSeed-169986037*/count=878; tryItOut("/*hhh*/function ivbnov(){{ void 0; try { startgc(35436); } catch(e) { } } {}this;}ivbnov((eval , this), ((makeFinalizeObserver('tenured'))));");
/*fuzzSeed-169986037*/count=879; tryItOut("mathy3 = (function(x, y) { return ( - (( + Math.atan(Math.exp(Math.imul(Number.MAX_VALUE, x)))) || (Math.atan2(( + y), y) >> Math.round(( + (Math.fround(y) >> Math.fround(x))))))); }); testMathyFunction(mathy3, [-(2**53+2), -0, Number.MIN_VALUE, 2**53+2, -0x080000000, 42, 0, -0x080000001, 1, 1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x100000000, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, -(2**53), 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_VALUE, Math.PI, 0x100000001, 0x07fffffff, 0x080000000, -(2**53-2), 2**53, 0x080000001, 0/0, 0x0ffffffff, -1/0, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=880; tryItOut("var ezkrsj, ecuhrw, c = Math.max(-28, -0);m2.set(w | x, o0);");
/*fuzzSeed-169986037*/count=881; tryItOut("");
/*fuzzSeed-169986037*/count=882; tryItOut("m1.set(g0, s1);");
/*fuzzSeed-169986037*/count=883; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -67108865.0;\n    (Int8ArrayView[4096]) = ((/*FFI*/ff(((((Int8ArrayView[0])) << (([]) = 'fafafa'.replace(/a/g, undefined >=  '' )))))|0)+(0xfe3272dd));\n    d0 = (d0);\n    i1 = (0xacd16ee2);\n    d0 = (((d0)) * ((1.5474250491067253e+26)));\n    i1 = (!(!(i1)));\n    d2 = ((i1) ? (-2.4178516392292583e+24) : (d2));\n    d2 = (d0);\n    d0 = (d2);\n    return +((Float32ArrayView[((((((((0xfd05b6ec)) << ((0x7bb9dec4))))+(!((0xa510697f)))) | (((0x28459880) < (0x1172fbc6))-(0xfd280ce6)+((0x36592812)))))-(0xb0ff150c)-(/*FFI*/ff(((+(0.0/0.0))))|0)) >> 2]));\n  }\n  return f; })(this, {ff: String}, new ArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=884; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\b\", \"gm\"); var s = \"11\\u00951\"; print(s.replace(r, w)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=885; tryItOut("mathy5 = (function(x, y) { return Math.fround((Math.fround((mathy2((( + Math.pow(((y ? (y >>> 0) : (y >>> 0)) >>> 0), ( + x))) >>> 0), (Math.fround(Math.sin(x)) | 0)) | 0)) >> Math.fround(( ~ ((( + (y | 0)) * Math.exp(x)) | 0))))); }); ");
/*fuzzSeed-169986037*/count=886; tryItOut("testMathyFunction(mathy1, [-0x100000000, 1.7976931348623157e308, 2**53, 1, -0x080000000, Math.PI, 0/0, -Number.MIN_VALUE, 2**53-2, -0x100000001, -1/0, 2**53+2, 0.000000000000001, 1/0, -(2**53-2), 0x0ffffffff, -Number.MAX_VALUE, -(2**53+2), -Number.MAX_SAFE_INTEGER, 0x100000001, 0x07fffffff, -0, 42, 0x080000000, -0x07fffffff, 0x080000001, Number.MAX_VALUE, 0, -(2**53), -0x080000001, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=887; tryItOut("testMathyFunction(mathy2, /*MARR*/[]); ");
/*fuzzSeed-169986037*/count=888; tryItOut("a0 = Array.prototype.map.call(a1, (function() { try { Array.prototype.shift.call(a0); } catch(e0) { } try { e1 = new Set(b1); } catch(e1) { } /*MXX2*/g1.Object.is = p0; return s2; }), this.h2);");
/*fuzzSeed-169986037*/count=889; tryItOut("\"use strict\"; testMathyFunction(mathy0, [-0x080000000, 0x0ffffffff, 0x080000001, -1/0, 0x07fffffff, -0x100000000, 0, Number.MIN_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, -0, 1.7976931348623157e308, -Number.MIN_VALUE, 0.000000000000001, 1, -Number.MIN_SAFE_INTEGER, 2**53-2, 42, 0/0, 0x100000001, Math.PI, 1/0, -0x080000001, -0x100000001, 0x080000000, Number.MIN_VALUE, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, -Number.MAX_VALUE, 2**53+2, Number.MAX_SAFE_INTEGER, -(2**53), -0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=890; tryItOut("var b =  \"\" ;print((4277));");
/*fuzzSeed-169986037*/count=891; tryItOut("\"use strict\"; \"use asm\"; selectforgc(o2);");
/*fuzzSeed-169986037*/count=892; tryItOut("\"use asm\"; Array.prototype.splice.apply(a2, [-5, 2, x]);");
/*fuzzSeed-169986037*/count=893; tryItOut("v2 = g1.runOffThreadScript();");
/*fuzzSeed-169986037*/count=894; tryItOut("o1 = new Object;");
/*fuzzSeed-169986037*/count=895; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( ! ((mathy1((Math.fround(Math.min(x, Math.fround(( + Math.cosh(( + Math.fround(Math.min(Math.fround(Math.atan(( + x))), Math.fround(-0x100000001))))))))) >>> 0), ((Math.imul(y, ((Math.asinh(( + y)) >>> 0) >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0)) ? (mathy2((mathy0(( + ( ~ Math.PI)), ( + ((-Number.MIN_SAFE_INTEGER % (y | 0)) >>> 0))) | 0), (((y ** (Math.min(x, (((x | 0) / (-0x100000001 | 0)) | 0)) | 0)) | 0) | 0)) | 0) : ( ~ ( + Math.atan2(( + ( ! -Number.MAX_SAFE_INTEGER)), ( + Number.MAX_VALUE))))); }); testMathyFunction(mathy3, [1/0, 0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 0x0ffffffff, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0, -Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 2**53-2, 0x080000001, -(2**53), -0x07fffffff, -0x100000000, 0/0, 1.7976931348623157e308, 42, -1/0, 1, Number.MAX_VALUE, Number.MIN_VALUE, -0x100000001, 0.000000000000001, 0x080000000, -(2**53-2), 2**53, -0x080000000, Math.PI, 0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=896; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.hypot((( - ((Math.atan2((x | 0), (Math.sin(-0x100000001) | 0)) | 0) | 0)) | 0), (((( + (x ** ( + ( - (Math.pow((Math.acos(0x100000001) | 0), x) >>> 0))))) | 0) && (( ~ (Math.fround(Math.expm1(Math.fround((( + Math.tan(y)) << (x >>> 0))))) >>> 0)) >>> 0)) | 0)); }); ");
/*fuzzSeed-169986037*/count=897; tryItOut("\"use strict\"; \"use strict\"; g0.offThreadCompileScript(\"print(x);\", ({ global: g0.o2.g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  /x/g , noScriptRval: (x % 5 != 4), sourceIsLazy: false, catchTermination:  ''  }));");
/*fuzzSeed-169986037*/count=898; tryItOut("let ([[]] =  /x/ , ukozuk, [] = /*MARR*/[x, x, (-1/0), (-1/0), x, x, (-1/0), (-1/0), x, x, (-1/0), (-1/0), x, (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0)].filter) { selectforgc(o2); }");
/*fuzzSeed-169986037*/count=899; tryItOut("for (var p in m1) { try { o1.t1 = new Uint8Array(({valueOf: function() { a0.unshift(o2.s1, g1.t0);return 17; }})); } catch(e0) { } e2 = new Set(g1); }");
/*fuzzSeed-169986037*/count=900; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var cos = stdlib.Math.cos;\n  var atan2 = stdlib.Math.atan2;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (+cos(((3.777893186295716e+22))));\n    return (((((/*FFI*/ff()|0) ? (+atan2(((+abs(((-536870913.0))))), ((Float64ArrayView[((i0)) >> 3])))) : (+((+(-1.0/0.0))))) != (d1))))|0;\n  }\n  return f; })(this, {ff: Array.prototype.forEach}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [0x0ffffffff, 2**53+2, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53), 0x07fffffff, 0x100000000, 0, -1/0, -Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, 1, 0.000000000000001, 2**53, -0, -0x100000001, 0x080000000, -0x100000000, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0, -0x080000001, -Number.MAX_VALUE, 0/0, Math.PI, -(2**53+2), 0x080000001, 42, 1.7976931348623157e308, Number.MAX_VALUE, -0x080000000, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=901; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=902; tryItOut("\"use strict\"; for (var v of i1) { try { /*RXUB*/var r = r0; var s = x; print(s.split(r)); print(r.lastIndex);  } catch(e0) { } try { for (var v of this.m0) { try { v1 = evalcx(\"Math.log2(({constructor: ((yield \\\"\\\\u97A7\\\")), /*toXFun*/toString: f2 }))\", g0); } catch(e0) { } g2.i2.next(); } } catch(e1) { } try { Array.prototype.shift.call(a1, b0); } catch(e2) { } v2 = Object.prototype.isPrototypeOf.call(i1, p1); }");
/*fuzzSeed-169986037*/count=903; tryItOut("g2.__iterator__ = (function(j) { if (j) { try { b2.toSource = f2; } catch(e0) { } a2 = new Array; } else { try { f1 = x; } catch(e0) { } try { this.o0.v0 = Array.prototype.reduce, reduceRight.apply(this.a1, [(function mcc_() { var cmpwgg = 0; return function() { ++cmpwgg; f1(/*ICCD*/cmpwgg % 10 == 1);};})(), o2.p0, i1]); } catch(e1) { } (void schedulegc(g0)); } });");
/*fuzzSeed-169986037*/count=904; tryItOut("for (var p in i0) { try { v0 = evalcx(\"function o1.f0(i2) NaN ^ x\", g1); } catch(e0) { } try { a2.pop(m1); } catch(e1) { } try { a0.shift(); } catch(e2) { } for (var p in o1.h1) { try { Array.prototype.pop.call(a0); } catch(e0) { } try { o1.t1.toSource = (function mcc_() { var lyyfml = 0; return function() { ++lyyfml; if (lyyfml > 7) { dumpln('hit!'); try { v1 = (v1 instanceof s1); } catch(e0) { } /*RXUB*/var r = r1; var s = g2.s0; print(s.search(r));  } else { dumpln('miss!'); a0 = arguments.callee.caller.caller.caller.arguments; } };})(); } catch(e1) { } try { o2.h0 + ''; } catch(e2) { } a0.shift(); } }");
/*fuzzSeed-169986037*/count=905; tryItOut("\"use strict\"; for(c in ((Array.prototype.every)(window)))t2.set(o1.t1, (let (b = c) /*UUV2*/(b.has = b.atan2)));");
/*fuzzSeed-169986037*/count=906; tryItOut("\"use strict\"; /*ADP-3*/Object.defineProperty(g2.a1, 1, { configurable: (4277), enumerable: true, writable: false, value: o1 });");
/*fuzzSeed-169986037*/count=907; tryItOut("s2 += 'x';");
/*fuzzSeed-169986037*/count=908; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (Math.atanh((( - Math.cos(Math.fround(((Math.sqrt(Math.fround(( ~ (x >>> 0)))) >>> 0) * Math.fround((Math.atan2((((( + mathy0((x >>> 0), ( + -0x100000001))) | 0) , ((y * x) | 0)) | 0), y) >>> 0)))))) | 0)) >>> 0); }); testMathyFunction(mathy3, [-(2**53+2), -0x080000001, -0x100000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, 2**53, 2**53+2, -(2**53), 0, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, 1, Math.PI, -(2**53-2), -Number.MAX_VALUE, -Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, -0x0ffffffff, 0/0, -0x07fffffff, 0.000000000000001, 1.7976931348623157e308, 42, -0x080000000, 0x100000000, -1/0, 0x080000000, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-169986037*/count=909; tryItOut("/*hhh*/function ylbvmn(...x){/*vLoop*/for (let jqrapv = 0; jqrapv < 37; ++jqrapv) { let z = jqrapv; /*RXUB*/var r = /(?:(?:(\\w*?)|[\\cJ\\u5Ea1-\\u352D\\cX-\\\u5f03\\D]))(?!\\B|(?=(\\v)*?)[^]\\D{3,}$*?|\\d|(?=\\S)[^]\\D)*/y; var s = \"\\u0096\"; print(s.split(r));  } \nv2 = Object.prototype.isPrototypeOf.call(i2, p2);\n}/*iii*//* no regression tests found */");
/*fuzzSeed-169986037*/count=910; tryItOut("\"use strict\"; const window, y, z, w = ( /x/g  ? true :  \"\" ), [] = x, wtjpdm, x;print(({x: new (\"\\u2A3D\")()}));");
/*fuzzSeed-169986037*/count=911; tryItOut("h1.set = (function(j) { if (j) { try { (void schedulegc(g0)); } catch(e0) { } try { o2 = h0.__proto__; } catch(e1) { } print(i0); } else { try { m1.has(s2); } catch(e0) { } this.a1.forEach((function mcc_() { var jwnami = 0; return function() { ++jwnami; if (/*ICCD*/jwnami % 3 == 1) { dumpln('hit!'); try { o1.v0 = t0.length; } catch(e0) { } Array.prototype.shift.apply(a0, []); } else { dumpln('miss!'); try { i2.toSource = (function() { v1 = a2.some(); return m1; }); } catch(e0) { } try { p2.__proto__ = i2; } catch(e1) { } v0 = (e1 instanceof a2); } };})(), p1, h1); } });");
/*fuzzSeed-169986037*/count=912; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.sin((((( ~ ( + ( - ( + ( + (( + (x ? x : y)) , ( + Math.atan2(x, x)))))))) | 0) >>> 0) ^ (Math.asin((y >>> 0)) >>> 0))) | (( + Math.atanh(( + (( ! Math.sign(y)) | 2**53-2)))) >>> 0)) >>> 0); }); ");
/*fuzzSeed-169986037*/count=913; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 1073741824.0;\n    var d3 = -1.5474250491067253e+26;\n    var i4 = 0;\n    var d5 = 2049.0;\n    i4 = (0x50205c2a);\n    {\n      (Float64ArrayView[(/(?=\\B*)*/im.unwatch(\"eval\")) >> 3]) = ((-1.125));\n    }\n    d2 = (d3);\n    (Int16ArrayView[2]) = ((0xfb75ea74));\n    return ((((((Uint32ArrayView[4096])) & ((((b = y)) ? (0xf81687bb) : (i4))-((+(1.0/0.0)) > (((2.0)) / ((5.0))))-((0x720f8aa3) ? ((0x3df95720)) : (i4)))))-(i1)))|0;\n  }\n  return f; })(this, {ff: function () { yield x } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [(new Boolean(true)), null, '/0/', [], (new Boolean(false)), (function(){return 0;}), 1, 0.1, true, ({valueOf:function(){return '0';}}), (new Number(-0)), undefined, '\\0', '0', NaN, ({toString:function(){return '0';}}), (new Number(0)), [0], -0, 0, objectEmulatingUndefined(), (new String('')), /0/, '', ({valueOf:function(){return 0;}}), false]); ");
/*fuzzSeed-169986037*/count=914; tryItOut("{this.t2 = t0.subarray(12, ({valueOf: function() { for (var p in f0) { try { o0 = Object.create( /x/ .throw(function(){})); } catch(e0) { } try { h2.defineProperty = f1; } catch(e1) { } try { o0 + e1; } catch(e2) { } v0 = evaluate(\"this.v1 = g1.runOffThreadScript();\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: 17, noScriptRval: x, sourceIsLazy: (x % 67 != 22), catchTermination: (x % 27 == 17) })); }return 16; }}));/* no regression tests found */function eval(x, x, ...NaN) { \"use strict\"; return (z > x **= eval) <= allocationMarker() } /*bLoop*/for (var vljgsp = 0; vljgsp < 5; ++vljgsp) { if (vljgsp % 2 == 0) { t2.__iterator__ = (function() { try { for (var p in o1) { g1.o2.m2.get(g2); } } catch(e0) { } try { t1[6]; } catch(e1) { } h1.valueOf = f1; return h0; }); } else { print(72057594037927940 in this); }  }  }");
/*fuzzSeed-169986037*/count=915; tryItOut("");
/*fuzzSeed-169986037*/count=916; tryItOut("s2 = s0.charAt(({valueOf: function() { m0.set(b0, a2);return 17; }}));");
/*fuzzSeed-169986037*/count=917; tryItOut("g0 = this;");
/*fuzzSeed-169986037*/count=918; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return Math.fround(( - Math.fround(Math.cbrt(Math.tanh((( ~ (x | 0)) | 0)))))); }); testMathyFunction(mathy0, [2**53+2, -0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, Number.MIN_VALUE, 0.000000000000001, 0x100000000, 1.7976931348623157e308, -0x100000001, -Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, -0x080000001, 0x080000000, -Number.MAX_VALUE, 0x100000001, 0, 0x0ffffffff, -(2**53+2), -1/0, -0x0ffffffff, 0/0, -0, Math.PI, Number.MAX_VALUE, 42, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, -(2**53)]); ");
/*fuzzSeed-169986037*/count=919; tryItOut("t2[3] = let (x = x, x, window = x) (4277);");
/*fuzzSeed-169986037*/count=920; tryItOut("testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, -0x100000001, 0x080000000, 1, -0x0ffffffff, -0x080000000, 0.000000000000001, Number.MAX_VALUE, 0x07fffffff, -(2**53+2), -0x07fffffff, -1/0, -0x100000000, -0x080000001, 2**53, -Number.MAX_VALUE, -0, Number.MIN_SAFE_INTEGER, 2**53-2, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0, -(2**53), 0x080000001, 1/0, Number.MIN_VALUE, 0x100000001, 42, -Number.MAX_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0/0, Math.PI, 2**53+2, 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=921; tryItOut("testMathyFunction(mathy0, [42, 0.000000000000001, -0x100000001, 0x07fffffff, 0x080000000, 2**53+2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000000, -0x080000001, 1, 0x080000001, -0, 0x100000001, 0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -1/0, Math.PI, Number.MAX_VALUE, -0x080000000, 0x100000000, -(2**53), -(2**53-2), 2**53, 0x0ffffffff, -Number.MIN_VALUE, -0x07fffffff, -(2**53+2), Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0, 2**53-2]); ");
/*fuzzSeed-169986037*/count=922; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=923; tryItOut("\"use strict\"; /*vLoop*/for (bnbfrk = 0, new RegExp(\"(?:[^])?\", \"gym\"); bnbfrk < 0; ++bnbfrk) { let d = bnbfrk; b2 = new SharedArrayBuffer(10); } ");
/*fuzzSeed-169986037*/count=924; tryItOut("s1 += 'x';");
/*fuzzSeed-169986037*/count=925; tryItOut("\"use strict\"; Object.prototype.watch.call(f2, \"toString\", (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (((0x71484bc) >= ((((0x3b8e8e27) > (0x640136b3))-(-0x8000000)+((0xffffffff) ? (0x63aed43d) : (0x1272a33f)))>>>(((0x7fffffff) > (0x4308840))+(0xb62f0e8)))) ? (d0) : ((0x5691a7fb) ? (((+(-1.0/0.0)))) : (d0)));\n    return (((0xf83df844)))|0;\n    d0 = (d0);\n    return ((((((0x4073c686) / ((((Float32ArrayView[((-0x7263184)) >> 2])) % (((68719476735.0) + (-1.015625)))))) ^ ((Int32ArrayView[0]))) > (~((-0x8000000)*0xe0696)))))|0;\n    d1 = (d1);\n    d1 = (d0);\n    (Uint32ArrayView[4096]) = ((Int32ArrayView[(-0xc8c85*(((0xd68f5d89)) ? (-0x8000000) : (0x204e21fa))) >> 2]));\n    return (((!((0xf7e22e4c)))))|0;\n    (Float32ArrayView[((((d0))) / (0xb40e4073)) >> 2]) = ((d0));\n    return (((0x954934d0)-(0xd72c6ad1)))|0;\n  }\n  return f; })(this, {ff: function (d) { return  /x/g  } }, new ArrayBuffer(4096)));");
/*fuzzSeed-169986037*/count=926; tryItOut("o2.s1 += o0.s1;");
/*fuzzSeed-169986037*/count=927; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=928; tryItOut("mathy5 = (function(x, y) { return ( + ( + mathy4((( + ( ! mathy3(x, Math.atan2(-Number.MAX_SAFE_INTEGER, x)))) | 0), (( - (mathy0(Math.atanh((( ~ x) >>> 0)), x) >>> 0)) >>> 0)))); }); testMathyFunction(mathy5, [-Number.MAX_VALUE, -0x100000001, 1.7976931348623157e308, 42, 2**53+2, -(2**53-2), -0x07fffffff, 1/0, 2**53-2, 0x100000001, 0x080000000, -0x0ffffffff, 0x080000001, -Number.MAX_SAFE_INTEGER, -0, Number.MAX_VALUE, 0x100000000, 0.000000000000001, -0x080000000, -1/0, -0x080000001, -(2**53+2), Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, 1, Number.MIN_SAFE_INTEGER, -(2**53), 0, -Number.MIN_VALUE, Math.PI, -0x100000000, 2**53, 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=929; tryItOut("\"use strict\"; o0.v2 = evalcx(\"Array.prototype.unshift.apply(a2, [this.b1, b2]);\", g2);");
/*fuzzSeed-169986037*/count=930; tryItOut("mathy4 = (function(x, y) { return mathy0(((Math.cbrt(( + (Math.max(Math.fround(y), (( + mathy3(( + y), x)) | 0)) >>> 0))) >>> 0) >>> 0), Math.hypot(Math.atan2(mathy2((( + (( + x) || ( + -Number.MAX_SAFE_INTEGER))) ? ( + y) : (-0x0ffffffff === x)), (mathy1(Math.fround(Math.min(Math.fround(y), Math.fround(y))), y) >>> 0)), ( + (y <= 1))), Math.sin((mathy0(( + x), (((Math.imul((x >>> 0), ( + x)) >>> 0) ? (x >>> 0) : (Math.exp((0/0 >>> 0)) >>> 0)) >>> 0)) >>> 0)))); }); testMathyFunction(mathy4, [0, 2**53-2, -(2**53-2), 0/0, 2**53, 0x100000000, Math.PI, 0x07fffffff, -0x080000000, -0x080000001, 0x0ffffffff, -Number.MIN_VALUE, 0x080000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53+2), -0x0ffffffff, -1/0, 1, 0.000000000000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0x100000001, 42, 1/0, -0x07fffffff, -0x100000000, -(2**53)]); ");
/*fuzzSeed-169986037*/count=931; tryItOut("\"use strict\"; e2.add(this.g1.m0);");
/*fuzzSeed-169986037*/count=932; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((( + ( ! ( + Math.hypot(Math.hypot(Math.acos(( + y)), ((2**53 <= x) && ((Math.min(( + y), x) | 0) | y))), (Math.fround(( - Math.fround((Math.sqrt(y) >>> 0)))) | 0))))) | 0) !== ((((-Number.MIN_VALUE >>> 0) == (( + (Math.fround(( + (x ? x : ( + Math.fround((Math.fround(x) === x)))))) ** ( + Math.cos(Math.min(Math.cos(2**53+2), y))))) >>> 0)) >>> 0) <= Math.tanh(y))); }); testMathyFunction(mathy0, ['/0/', '\\0', ({toString:function(){return '0';}}), (function(){return 0;}), undefined, (new Number(0)), -0, null, [], ({valueOf:function(){return 0;}}), 0, 0.1, ({valueOf:function(){return '0';}}), true, /0/, [0], false, NaN, '', (new String('')), '0', (new Boolean(true)), 1, (new Number(-0)), objectEmulatingUndefined(), (new Boolean(false))]); ");
/*fuzzSeed-169986037*/count=933; tryItOut("a0.reverse();\n/*MXX3*/g1.g2.Math.exp = g1.Math.exp;\n");
/*fuzzSeed-169986037*/count=934; tryItOut("\"use strict\"; /*MXX1*/o1 = g2.g2.Symbol.species;");
/*fuzzSeed-169986037*/count=935; tryItOut("\"use strict\"; v2 = Object.prototype.isPrototypeOf.call(h2, v2);");
/*fuzzSeed-169986037*/count=936; tryItOut("\"use strict\"; Object.prototype.unwatch.call(p2, \"pow\");");
/*fuzzSeed-169986037*/count=937; tryItOut("o0 = new Object;");
/*fuzzSeed-169986037*/count=938; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (( + ((Math.atan2((Math.atan2(( + -0x080000000), (1/0 >>> 0)) >>> 0), (Math.cos(( + Math.cos(y))) >>> 0)) >>> 0) ? ( + ( + Math.sin(Math.fround((Math.tanh((-0x080000000 | 0)) | 0))))) : ( + Math.sign(0x07fffffff)))) > Math.pow(Math.min(( + ( ! Math.fround(y))), ( - y)), Math.pow(Math.fround(( ~ y)), Math.log10((y >>> 0))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -0x080000001, 0x07fffffff, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x080000000, Number.MIN_VALUE, -0x100000001, Math.PI, 0x100000000, -1/0, 2**53-2, 0/0, 1.7976931348623157e308, 42, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x080000000, 0x100000001, -0x100000000, 0x080000001, 1, 0x0ffffffff, -(2**53-2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, 2**53, 0, -0x0ffffffff, -(2**53), 0.000000000000001, -0]); ");
/*fuzzSeed-169986037*/count=939; tryItOut("/*iii*/print(x);/*hhh*/function guvyei(){(undefined);}");
/*fuzzSeed-169986037*/count=940; tryItOut("var r0 = 4 - x; var r1 = x - x; r0 = x | r1; var r2 = 6 & r1; r1 = 7 - 2; r1 = r2 | r2; var r3 = r1 | 2; x = x * r2; var r4 = r1 / 0; var r5 = r0 - 7; var r6 = r4 % 9; r4 = r4 | r5; var r7 = r3 & r1; var r8 = 2 % 7; var r9 = 5 / r7; var r10 = r6 ^ r2; var r11 = r1 & r5; var r12 = 2 | r8; var r13 = r6 % 3; var r14 = 8 + 0; var r15 = 4 + 9; var r16 = r5 + 1; var r17 = r16 / 5; var r18 = r4 * 1; r2 = r18 / r16; var r19 = r11 & r9; var r20 = 7 + r6; var r21 = r7 - r0; r13 = 1 * 8; var r22 = 0 & r2; var r23 = 8 | r6; var r24 = r0 / r13; var r25 = 3 % r18; var r26 = r6 + x; var r27 = 8 & r10; var r28 = r27 - r15; var r29 = 8 % 8; var r30 = r15 | 3; var r31 = 3 / r8; var r32 = r26 & 4; r29 = r2 & x; var r33 = 4 ^ x; var r34 = r26 + r32; var r35 = 6 & x; var r36 = r35 ^ x; r4 = r30 | r35; var r37 = r8 + r0; r17 = r28 & r29; var r38 = r8 * 1; var r39 = r21 * r22; var r40 = r18 + r18; var r41 = r40 / r14; function x(e) { yield (4277) } /* no regression tests found */");
/*fuzzSeed-169986037*/count=941; tryItOut("m2.delete(\"\\u99F7\");");
/*fuzzSeed-169986037*/count=942; tryItOut("\"use strict\"; var fagcly, \u3056, slecvw, lrvwrm, tglmzg;print([[]]);");
/*fuzzSeed-169986037*/count=943; tryItOut("testMathyFunction(mathy2, [0.000000000000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x080000001, 0x100000001, 0x0ffffffff, -(2**53-2), -0, -Number.MAX_VALUE, 2**53-2, 2**53, Number.MAX_SAFE_INTEGER, -0x100000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0x07fffffff, -0x080000000, 0x080000000, Number.MIN_VALUE, 0, 42, 0/0, -1/0, 0x07fffffff, 1, 2**53+2, Number.MAX_VALUE, -(2**53), 1/0, Math.PI, 1.7976931348623157e308, -0x100000000, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001]); ");
/*fuzzSeed-169986037*/count=944; tryItOut("\"use strict\"; a2.valueOf = runOffThreadScript;");
/*fuzzSeed-169986037*/count=945; tryItOut("\"use strict\"; s0 = new String(b0);");
/*fuzzSeed-169986037*/count=946; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.cbrt(Math.atan2((Math.hypot(Math.atan2(Math.sinh(Math.fround(Math.clz32((( ~ ( + -(2**53))) | 0)))), Math.min(y, (( ! (Math.pow(y, x) | 0)) | 0))), x) | 0), (Math.pow((x > ((( - ( + Math.atanh(((Math.fround(x) ? Math.fround(x) : Math.fround(y)) >>> 0)))) >>> 0) | 0)), Math.fround(( - x))) | 0)))); }); testMathyFunction(mathy0, [0.000000000000001, -0x100000001, 1, -Number.MAX_SAFE_INTEGER, 0/0, 1.7976931348623157e308, 1/0, 2**53+2, -0x080000001, 0x080000000, 0, 2**53-2, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -0, 2**53, -1/0, -0x07fffffff, -0x100000000, -(2**53-2), 0x100000000, Number.MAX_VALUE, -0x080000000, -(2**53), 0x080000001, 0x0ffffffff, Math.PI, -(2**53+2), 42, -Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=947; tryItOut("v1 = g0.eval(\"Array.prototype.push.call(a1, t1, f0);\");");
/*fuzzSeed-169986037*/count=948; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0(((Math.fround(Math.min((((Math.hypot((x | 0), Math.abs(x)) | 0) ** y) >>> Math.atanh(Math.acos(( + 0x080000000)))), Math.fround(( + ( ! ( + Math.log(( ~ y)))))))) > (Math.clz32((x >>> 0)) >>> 0)) | 0), (mathy1(Math.hypot((Math.sin(Math.fround(mathy1(x, x))) > y), y), (Math.tanh(( + mathy1(Math.hypot(mathy1((2**53+2 >>> 0), (y | 0)), Math.fround(x)), Math.fround(y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [({valueOf:function(){return '0';}}), true, 0.1, (new Number(-0)), undefined, 1, ({valueOf:function(){return 0;}}), null, (function(){return 0;}), (new Boolean(false)), 0, objectEmulatingUndefined(), false, (new Number(0)), [], /0/, ({toString:function(){return '0';}}), (new String('')), '\\0', '0', -0, '/0/', [0], (new Boolean(true)), '', NaN]); ");
/*fuzzSeed-169986037*/count=949; tryItOut("mathy4 = (function(x, y) { \"use asm\"; return mathy3(( + ( ~ ((Math.log2((( ! Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0) | 0))), ( + mathy2(Math.fround((Math.max((( + (( + 1/0) / ( + y))) >>> 0), (( ! (mathy3((y | 0), (x | 0)) | 0)) >>> 0)) >>> 0)), ( + ( + (( + Math.max(( + (x ? ( + x) : Math.fround(y))), Math.fround(( + Math.sign(( + y)))))) ? ( + Math.pow(( + Math.pow(( + Math.atan2(y, x)), ( + mathy3(( + x), 0/0)))), x)) : ( + (Math.cosh((x | 0)) | 0)))))))); }); testMathyFunction(mathy4, [-(2**53), -0, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, 0, -(2**53-2), -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, Math.PI, 1/0, 0x100000000, -0x080000001, -(2**53+2), 2**53, 0/0, 0x100000001, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 2**53+2, -0x080000000, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 1, 1.7976931348623157e308, -0x100000001, -1/0, -0x100000000, 0x080000001, 0x080000000, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53-2]); ");
/*fuzzSeed-169986037*/count=950; tryItOut("print(x);");
/*fuzzSeed-169986037*/count=951; tryItOut("Array.prototype.splice.apply(a1, [NaN, 1]);function e(window, w)\"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    return +((-65537.0));\n    i2 = (i0);\n    (Float32ArrayView[1]) = ((+(0.0/0.0)));\n    i2 = ((0xfc06f9ae) ? ((-2.0) > (-0.0625)) : (i2));\n    return +((d1));\n    i2 = (1);\n    {\n      {\n        i2 = (i2);\n      }\n    }\n    d1 = (-65.0);\n    {\n      i0 = (!(i0));\n    }\n    {\n      d1 = (-562949953421313.0);\n    }\n    return +((1.125));\n  }\n  return f;var gqegoh = new ArrayBuffer(3); var gqegoh_0 = new Uint8ClampedArray(gqegoh); gqegoh_0[0] = 8; var gqegoh_1 = new Uint32Array(gqegoh); print(gqegoh_1[0]); gqegoh_1[0] = -14; v2 = (g2.g1.g1 instanceof a1);");
/*fuzzSeed-169986037*/count=952; tryItOut("/*ADP-3*/Object.defineProperty(a0, 0, { configurable: false, enumerable: WeakSet(), writable: (4277), value: m0 });");
/*fuzzSeed-169986037*/count=953; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[(this.__defineSetter__(\"x\", (x).call)), (this.__defineSetter__(\"x\", (x).call)), new Boolean(true),  '' , new Boolean(true), new String(''),  '' , new String(''), new Boolean(true), (this.__defineSetter__(\"x\", (x).call)), new String(''), new String(''), null, null]); ");
/*fuzzSeed-169986037*/count=954; tryItOut("mathy3 = (function(x, y) { return (( ~ ( + (( + ( + (( + (Math.max((Math.fround(((x <= (x >>> 0)) >>> 0)) , Math.fround(x)), Math.sinh(x)) >>> 0)) ^ ( + ( ! y))))) === ( + (( ! y) | 0))))) ** ( ! mathy2((x ? Math.cos(y) : (Math.hypot(Math.atanh(y), ( + y)) | 0)), ( + mathy2(-(2**53-2), ( + -1/0)))))); }); testMathyFunction(mathy3, [0x0ffffffff, 0.000000000000001, -(2**53-2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, Math.PI, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, -0, -0x07fffffff, 42, 2**53, -0x080000001, 0/0, Number.MAX_SAFE_INTEGER, -0x080000000, 2**53+2, 0x080000000, -Number.MAX_VALUE, 0x080000001, -(2**53+2), 1/0, 2**53-2, -0x0ffffffff, -0x100000000, 0x100000001, -0x100000001, -1/0, 1, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53), 0]); ");
/*fuzzSeed-169986037*/count=955; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.min(( + (( + x) % ( + ( ! 0x100000001)))), ((( ! (Math.atan(( + (Math.pow((-0x100000000 | 0), (y | 0)) | 0))) >>> 0)) | 0) - Math.abs(Math.fround(y)))); }); testMathyFunction(mathy3, [-(2**53+2), -1/0, -0x07fffffff, 1.7976931348623157e308, -0x100000000, -(2**53), 2**53+2, 0/0, Math.PI, 0x100000000, -0x0ffffffff, 1/0, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53-2, 0x100000001, 42, 2**53, 0x07fffffff, -0x100000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 0, -(2**53-2), 1, 0x0ffffffff, -0x080000001, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0, 0x080000001, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=956; tryItOut("/*tLoop*/for (let c of /*MARR*/[new Number(1.5),  '' , [1],  '' ,  '' ,  '' , [1], new Number(1.5),  '' , new Number(1.5), new Number(1.5),  '' ,  '' ,  '' ,  '' , new Number(1.5), [1],  '' , new Number(1.5), [1], new Number(1.5), [1],  '' , [1], [1], new Number(1.5), [1], [1],  '' ,  '' , new Number(1.5),  '' ,  '' , [1], [1],  '' ,  '' , [1], [1], [1], [1], [1], new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), [1],  '' , new Number(1.5), [1], [1], new Number(1.5),  '' , new Number(1.5), [1], new Number(1.5), [1], [1], [1], [1], [1], [1],  '' , new Number(1.5), new Number(1.5), new Number(1.5), [1],  '' , new Number(1.5),  '' ,  '' , [1], [1], [1],  '' , [1], [1], [1], new Number(1.5),  '' , new Number(1.5),  '' ,  '' , [1],  '' , new Number(1.5), new Number(1.5), new Number(1.5),  '' ,  '' , new Number(1.5), new Number(1.5), [1], new Number(1.5), new Number(1.5), [1], [1],  '' ,  '' , [1], [1],  '' , [1],  '' ,  '' , [1],  '' , [1], new Number(1.5), [1], new Number(1.5),  '' , [1],  '' , new Number(1.5),  '' ]) { ; }");
/*fuzzSeed-169986037*/count=957; tryItOut("\"use strict\"; with({d: new undefined.fromCharCode(x <= x, undefined)}){x, ayiznt, e, d, jbxpko, lxdmaq, c, pvatxo, x, anttsv;function (...w) { return false } /*hhh*/function txqrkq(eval, window, window, e, w, d, d =  /x/g , a, x, w, d, x, NaN, d, \u3056, $7, d, c, window, e){f2 = (function() { try { Array.prototype.pop.call(a0); } catch(e0) { } /*MXX2*/g1.Promise = m1; return o0.t1; });}txqrkq( /x/ ); }");
/*fuzzSeed-169986037*/count=958; tryItOut("mathy2 = (function(x, y) { return Math.imul(((mathy0(Math.fround((y !== Math.fround(x))), Math.fround((( + y) ** x))) + (Math.atan2((y >>> 0), ((Math.log2((( + Math.pow(( + (((x >>> 0) / x) >>> 0)), ( + -Number.MIN_SAFE_INTEGER))) | 0)) | 0) >>> 0)) >>> 0)) | 0), (Math.clz32(((( ! (Math.imul((y >>> 0), (x >>> 0)) >>> 0)) , x) >>> (Math.sqrt(x) ** y))) | 0)); }); ");
/*fuzzSeed-169986037*/count=959; tryItOut("mathy5 = (function(x, y) { return Math.fround((( + Math.pow(( - Math.hypot(Math.min(Math.tanh((x | 0)), -Number.MIN_VALUE), Math.fround(( ~ (x | 0))))), (Math.fround((Math.fround((Math.fround(y) | x)) >> Math.fround((mathy2(-Number.MIN_SAFE_INTEGER, 0x080000000) | 0)))) >>> 0))) | 0)); }); ");
/*fuzzSeed-169986037*/count=960; tryItOut("for (var p in this.g1.g0) { try { g2.offThreadCompileScript(\"mathy5 = (function(x, y) { return Math.fround(mathy0(Math.fround(( + ( ~ ( + ( - ( + Math.expm1(y))))))), (Math.max(Math.acos(( + (y | y))), Math.fround(Math.hypot(2**53-2, ( ! y)))) >>> 0))); }); \", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: new Uint16Array(), noScriptRval: (new (length)()), sourceIsLazy: false, catchTermination: (x % 3 != 2) })); } catch(e0) { } v1 = Object.prototype.isPrototypeOf.call(i1, p0); }");
/*fuzzSeed-169986037*/count=961; tryItOut("let (x) { for(z = \"\\u837A\" ? /\\3/gym : true in /(?:(?:\\3|\u0084*?^.|[^]|${0})[^]|\u008c|[^].+?|[^\\w\\D]\\3)/i) {/*MXX1*/o0 = g1.Error.name; } }");
/*fuzzSeed-169986037*/count=962; tryItOut("let x, x, x, w, [ /x/g , , ] = this.__defineSetter__(\"x\", arguments.callee), c, [x, , [], ] = new RegExp(\"\\\\b|\\\\B\", \"y\"), ecubvj;t2 = new Float64Array(b2);");
/*fuzzSeed-169986037*/count=963; tryItOut("var w = (b *= x);(.__defineSetter__(\"a\", eval));");
/*fuzzSeed-169986037*/count=964; tryItOut("s2 = '';");
/*fuzzSeed-169986037*/count=965; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.trunc(Math.tan(( - ( + (Math.min((y ^ (0 >>> 0)), (( + (x >>> 0)) | 0)) ? Math.pow(Math.fround(Math.atan2(( + y), y)), Math.exp(Number.MIN_SAFE_INTEGER)) : x))))) | 0); }); testMathyFunction(mathy3, [1.7976931348623157e308, -(2**53+2), 2**53-2, 0x100000000, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0/0, 42, Math.PI, 0x080000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1/0, 0x0ffffffff, -0x100000000, Number.MIN_VALUE, 0x07fffffff, 0x100000001, -1/0, Number.MAX_VALUE, 2**53+2, 0, -0x080000000, -0x080000001, -Number.MAX_VALUE, -0, -0x100000001, -(2**53-2), 2**53, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53), 1, -0x07fffffff, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=966; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.sign(( + (( ~ ((( + (mathy0(x, ( + x)) >>> 0)) >>> 0) >>> 0)) | 0)))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, 1/0, -1/0, -0x100000001, -Number.MIN_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 0x080000000, 1, 0.000000000000001, 2**53+2, 42, -(2**53+2), Number.MIN_VALUE, -(2**53-2), 2**53-2, -Number.MAX_SAFE_INTEGER, -0, -(2**53), 1.7976931348623157e308, Math.PI, -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_VALUE, 0x07fffffff, 0x100000000, -0x080000001, 0x100000001, 0/0, -0x080000000, 0x0ffffffff, 0, -0x100000000]); ");
/*fuzzSeed-169986037*/count=967; tryItOut("\"use strict\"; Array.prototype.reverse.apply(a0, [p2, i0]);");
/*fuzzSeed-169986037*/count=968; tryItOut("/*vLoop*/for (let rfopki = 0, z, window = (4277); rfopki < 15; ++rfopki) { w = rfopki; a1 + ''; } ");
/*fuzzSeed-169986037*/count=969; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[ /x/g , objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g , null, true, true,  /x/g , null,  /x/g , true, true, true, null,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, null,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), null, objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, objectEmulatingUndefined(), true, objectEmulatingUndefined(),  /x/g , null, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), null,  /x/g , null,  /x/g , true, null, null,  /x/g , true, objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , true,  /x/g , null, objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g ,  /x/g , true, objectEmulatingUndefined(), true,  /x/g ,  /x/g , true, null, objectEmulatingUndefined(),  /x/g , true, objectEmulatingUndefined(), null, objectEmulatingUndefined(), objectEmulatingUndefined(), true, true, objectEmulatingUndefined(),  /x/g ,  /x/g ,  /x/g , null, objectEmulatingUndefined(), objectEmulatingUndefined(), null, null, true, null, true, true, true, null, true, null,  /x/g , null, null, null, null, true, objectEmulatingUndefined(),  /x/g , objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), objectEmulatingUndefined(), true, objectEmulatingUndefined(), null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,  /x/g ]) { p1 + b1; }");
/*fuzzSeed-169986037*/count=970; tryItOut("\"use asm\"; /*oLoop*/for (var thzjvz = 0; thzjvz < 42; ++thzjvz) { o1.v0 = (v1 instanceof m2); } ");
/*fuzzSeed-169986037*/count=971; tryItOut("eval = linkedList(eval, 4851);");
/*fuzzSeed-169986037*/count=972; tryItOut("\"use strict\"; a0.pop();");
/*fuzzSeed-169986037*/count=973; tryItOut("/*infloop*/ for  each(let NaN in function(id) { return id }) /*MXX2*/g1.WeakMap.prototype.constructor = o2;");
/*fuzzSeed-169986037*/count=974; tryItOut("for (var v of v1) { try { t1 = g2.objectEmulatingUndefined(); } catch(e0) { } try { this.v2 = Object.prototype.isPrototypeOf.call(a0, p2); } catch(e1) { } this.e0 = new Set(h1); }");
/*fuzzSeed-169986037*/count=975; tryItOut("/*RXUB*/var r = /(?:[^]{0,})(?!\\3)+(?=\\b){0,3}(?:$|\\b?)*?*[^]|[^]{1,}/yim; var s = \"__________________\\u532a\"; print(s.match(r)); function d(x = (let (z) let (d = ([])()) z), x)\"use asm\";   var imul = stdlib.Math.imul;\n  var sqrt = stdlib.Math.sqrt;\n  var abs = stdlib.Math.abs;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = 1.03125;\n    var d3 = 3.0;\n    {\n;    }\n;    d2 = (((d2)) % ((+((((~~(d1)) == (imul(((0x67575c60) <= (0x1e3e195f)), (0x17d0c701))|0)))>>>(((((0xf99441fc)+(0x84c7b6f1)+(0xfe8b0635))>>>((0xfa9988e))) < (((0xf88d8522)*0x789bc)>>>((0x1d002ca9)-(-0x8000000)+(-0x8000000)))))))));\n/*hhh*/function wmgwyu(x){Array.prototype.push.call(a2, 27, \"\\uE3B9\", o0.v0, this.f2);}wmgwyu(x);    d0 = (d2);\n    switch (((0xfffff*((-0x8000000))) >> (((0xe906588) >= (0x32efad2b))-((0x1755f639))))) {\n      case 0:\n        (Uint8ArrayView[(((-((0x5431c0ea) < (0x7fffffff)))>>>((0xe4717945))) / (0x1cba2e93)) >> 0]) = ((0xfee03479)-(0x81b7a371));\n        break;\n      case -1:\n        d3 = (d1);\n        break;\n      case -3:\n        return +((d3));\n      case -3:\n        d3 = (d2);\n        break;\n    }\n    d3 = (d0);\n    {\n      (Int16ArrayView[1]) = ((0x203a5e94));\n    }\n    d0 = (((0xea7d243d)-(0x2994c27d)));\n    {\n      (Float64ArrayView[(((+sqrt(((+abs(((Float64ArrayView[0]))))))) <= (d2))) >> 3]) = ((Float64ArrayView[0]));\n    }\n    d1 = ((!((d2) == (d1))) ? (-28.watch(\"all\", /*wrap1*/(function(){ \"use strict\"; yield;return q => q})())) : (d3));\n    d1 = (+((+(1.0/0.0))));\n    return +((+((((4277))+(((0xd9b1591c) ? (0xf8d483db) : (-0x8000000)) ? ((imul((-0x8000000), (0x460b7d68))|0)) : (0xfee7e924)))>>>(((0x0) <= (((Uint32ArrayView[1]))>>>((0xbb5cde8e))))+(0xe6c68340)+(0x6f4219d7)))));\n  }\n  return f;/*bLoop*/for (let ukfdoq = 0; ukfdoq < 6; ++ukfdoq) { if (ukfdoq % 18 == 3) { o2.__proto__ = g0; } else { v2 = Object.prototype.isPrototypeOf.call(g2.f1, b0); }  } ");
/*fuzzSeed-169986037*/count=976; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.log10(( ! (( + y) ? y : (y ^ ((x | 0) + x))))) >> Math.fround(Math.acosh((Math.hypot((Math.atan(x) | 0), x) >>> 0)))); }); testMathyFunction(mathy0, [2**53, 2**53-2, -0, -0x0ffffffff, 1/0, -(2**53-2), 2**53+2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, 0x100000000, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0x0ffffffff, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000000, 0.000000000000001, 1, -(2**53), -0x07fffffff, 0x080000001, -0x100000001, Math.PI, -0x080000000, -(2**53+2), Number.MAX_VALUE, -0x080000001, 42, 0/0, 0, -1/0, -Number.MIN_VALUE, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=977; tryItOut("mathy5 = (function(x, y) { return mathy0((((Math.abs(Math.cbrt((x ** (x >>> 0)))) >>> 0) ** mathy3(-Number.MIN_SAFE_INTEGER, Math.min(mathy0((y | 0), (Math.pow(x, 0x100000000) | 0)), -(2**53)))) >>> 0), (((mathy2(Math.fround((x / Math.fround(Math.atan(Math.fround((Math.pow((Math.atanh((-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0), x) >>> 0)))))), ( + Math.pow(Math.fround(( ! (y >>> 0))), Math.fround(Math.fround(( ! (Math.cos(x) | 0))))))) >= ((y ? Math.tanh(mathy0(Math.fround((y >= 0x100000001)), ((x | 0) ? x : -0x080000001))) : Math.fround(y)) >>> 0)) >>> 0) >>> 0)); }); testMathyFunction(mathy5, [2**53, 0x100000001, 0x080000001, Math.PI, -0x100000001, 0x100000000, 2**53-2, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, -0x080000000, -0x07fffffff, 1, -Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x0ffffffff, Number.MAX_VALUE, -0x100000000, -0x0ffffffff, -Number.MIN_VALUE, 2**53+2, 0x080000000, 42, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 1.7976931348623157e308, 0/0, 0.000000000000001, -(2**53+2), 1/0, -0x080000001, -0, 0, -(2**53-2), -(2**53)]); ");
/*fuzzSeed-169986037*/count=978; tryItOut("testMathyFunction(mathy4, [0, -Number.MIN_VALUE, 2**53-2, -1/0, 0x0ffffffff, -Number.MAX_VALUE, 1/0, Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_VALUE, -0x100000000, Math.PI, 0x100000000, -Number.MIN_SAFE_INTEGER, -0, 0x07fffffff, 0x100000001, 42, -(2**53-2), -0x0ffffffff, 1, -0x080000001, 0/0, 1.7976931348623157e308, -0x080000000, -(2**53), Number.MIN_VALUE, 0.000000000000001, 0x080000000, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53, 0x080000001, 2**53+2, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=979; tryItOut("mathy3 = (function(x, y) { return ((Math.pow(((x | 0) < (Math.acosh((( + mathy1(( + y), ( + x))) | 0)) | 0)), Math.exp((( + ( + mathy2(( - x), x))) | 0))) | 0) & (mathy0((( ! Math.fround((-Number.MIN_VALUE << x))) | 0), (Math.tan(Math.fround(Math.asinh(( + -0)))) | 0)) | 0)); }); testMathyFunction(mathy3, [42, 2**53-2, -Number.MAX_VALUE, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x100000000, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Math.PI, 0/0, -Number.MIN_VALUE, 0x080000001, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 0, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 2**53+2, -(2**53+2), 1/0, -0x080000000, 1, -(2**53), 0x0ffffffff, -1/0, -0, 0x07fffffff, -0x07fffffff, 0x080000000]); ");
/*fuzzSeed-169986037*/count=980; tryItOut("/*MXX1*/o0 = g2.g0.Date.prototype.setTime;Array.prototype.pop.call(o0.a2);");
/*fuzzSeed-169986037*/count=981; tryItOut("\"use strict\"; /*infloop*/M:do t0 + ''; while(delete x.x);");
/*fuzzSeed-169986037*/count=982; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return mathy0(( + ( + ( + (( + y) << ( + ( + (x !== (y ? x : (((x >>> 0) != (( ! x) >>> 0)) >>> 0))))))))), ((( + Math.log10(Math.max(Math.sign((Math.max((-Number.MAX_VALUE >>> 0), (x | 0)) | 0)), x))) | 0) > (Math.trunc((Math.abs(( + Math.atan(y))) >>> 0)) >>> 0))); }); testMathyFunction(mathy5, [-0x100000001, Number.MIN_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53, 42, Number.MAX_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000001, 0x080000000, 0/0, 2**53+2, 0x0ffffffff, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000000, 1/0, -Number.MAX_VALUE, 0x100000000, -(2**53), -(2**53-2), 2**53-2, -0x07fffffff, 0x080000001, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000001, 0.000000000000001, 0, 0x07fffffff, -0x080000000, -0, -0x0ffffffff, Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=983; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(g0.p0, o1.p1);-4;");
/*fuzzSeed-169986037*/count=984; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var i4 = 0;\n    var d5 = 9223372036854776000.0;\n    i2 = (i4);\n    d5 = ((+(1.0/0.0)) + (+(-1.0/0.0)));\n    {\n      {\n        {\n          (Uint16ArrayView[((i3)-((-0x3cc4a26) != (imul(((-0x8000000) ? (0xcde876de) : (0xf9945338)), (i2))|0))) >> 1]) = ((i1));\n        }\n      }\n    }\n    i2 = (!(((((i4))>>>((i3)+((0x6bb670c5) == (0x7fffffff))))) ? (i0) : (i1)));\n    (Int16ArrayView[4096]) = ((i2)+(i2)+(i4));\n    {\n      i1 = (/*FFI*/ff((((((-2.3611832414348226e+21) < (+atan2(((+(0x5813bf4c))), ((-1.00390625)))))) << (((((i0)*-0xfffff) ^ ((0x32522384) % (0x4ccbbd3d))) == (((0x1909f2de) % (0x34fdd29a)) & (((0x7b3bf1d3) != (0xad7a025))-(i3))))*-0x295cb))))|0);\n    }\n    i2 = ((i2) ? (i0) : (!(0xf54fdf42)));\n    switch ((-0x8000000)) {\n      default:\n        i1 = (i3);\n    }\n    return (((i4)+(/*FFI*/ff(((-67108865.0)), ((~~(1023.0))))|0)))|0;\n  }\n  return f; })(this, {ff: x((({x: eval})),  \"\" )}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=985; tryItOut("p1 + m2;");
/*fuzzSeed-169986037*/count=986; tryItOut("var mvcdhf = new SharedArrayBuffer(4); var mvcdhf_0 = new Uint8Array(mvcdhf); mvcdhf_0[0] = 15; return;");
/*fuzzSeed-169986037*/count=987; tryItOut("mathy5 = (function(x, y) { return (Math.min((( + (( + ( ! ((((Math.fround(Math.fround(( + (1 | 0)))) >>> 0) * (x >>> 0)) >>> 0) | mathy0((Math.fround(( + x)) | 0), ( + ( ~ ( + -0x0ffffffff))))))) && ( + mathy0(mathy0(x, 0x080000001), Math.acos(x))))) | 0), ( + ( + ( + (((Math.atan((x >>> 0)) >>> 0) >= (x <= -(2**53+2))) && (Math.log(( + (( + ( + Math.acosh(( + y)))) >>> ( + x)))) >>> 0)))))) | 0); }); testMathyFunction(mathy5, [0x0ffffffff, -0x07fffffff, -(2**53-2), 0x080000001, 2**53+2, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -1/0, 0x100000001, 2**53, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 0.000000000000001, Number.MAX_VALUE, -Number.MAX_VALUE, 2**53-2, -0x080000000, 1/0, 0x100000000, Number.MIN_VALUE, 0/0, -0, 0x07fffffff, -0x0ffffffff, 42, -(2**53), 0x080000000, -(2**53+2), 0, -Number.MIN_VALUE, -0x100000000, -0x080000001, 1, 1.7976931348623157e308, Math.PI]); ");
/*fuzzSeed-169986037*/count=988; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i0 = (i1);\n    return +((+(-0x10a78a2)));\n  }\n  return f; })(this, {ff: function(y) { o2.b2 = t1.buffer; }}, new ArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=989; tryItOut("s1.toSource = (function() { try { e2.add(h0); } catch(e0) { } try { Array.prototype.unshift.call(a1, h1, p0, o1.o0, s0, this.a0); } catch(e1) { } b2.valueOf = f1; return b0; });");
/*fuzzSeed-169986037*/count=990; tryItOut("let window = x.throw(\"\\u272F\"), a = x;Array.prototype.forEach.call(a2, f1);");
/*fuzzSeed-169986037*/count=991; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return mathy2(( + Math.atan2(( ! (Math.imul((( ~ (-Number.MIN_VALUE | 0)) | 0), (((y == ( + x)) & y) | 0)) >>> 0)), Math.cos((((((x | 0) > (x | 0)) | 0) >>> 0) - (( ~ x) >>> 0))))), Math.imul(((Math.log(( + Math.imul((-0x100000001 >>> 0), (( ~ ( ~ -0x0ffffffff)) >>> 0)))) % (Math.abs((y | 0)) | 0)) | 0), ((Math.pow((x | 0), ( ! y)) ? (( + Math.hypot((x || x), Math.fround(y))) ? -Number.MIN_VALUE : Math.fround(-0x080000001)) : mathy3((y ? ( + (y <= (x | 0))) : mathy0(Math.fround((Math.asinh((x | 0)) | 0)), x)), ( + ( ! ( + ( + ( ! ( + Math.clz32(y))))))))) | 0))); }); testMathyFunction(mathy4, [-(2**53+2), -Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, 1, 0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x100000000, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001, 1/0, -0, Math.PI, -Number.MIN_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, 0, -0x100000001, 42, -1/0, Number.MIN_VALUE, 2**53+2, 0x080000000, -0x080000000, 0x0ffffffff, -(2**53-2), -(2**53), 1.7976931348623157e308, 2**53, 0x080000001, 0.000000000000001]); ");
/*fuzzSeed-169986037*/count=992; tryItOut("\"use strict\"; s1 + '';");
/*fuzzSeed-169986037*/count=993; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=994; tryItOut("\"use strict\"; /*hhh*/function lbbomd(y, eval){/*ADP-2*/Object.defineProperty(g0.a1, ({valueOf: function() { /*infloop*/while( '\\0' )/*RXUB*/var r = /(?:\\u0068){2}/gm; var s = \"h\\u00c6h\\u00c6\"; print(r.test(s)); return 9; }}), { configurable: (x % 6 != 0), enumerable: true, get: (function(j) { if (j) { try { let v0 = new Number(g2.o0.e1); } catch(e0) { } try { v1 = evalcx(\"m1.get(a2);\", g0); } catch(e1) { } i1 = t2[({valueOf: function() { (Math.log(2));return 19; }})]; } else { try { v0 = Object.prototype.isPrototypeOf.call(m1, e2); } catch(e0) { } try { m0.__iterator__ = (function() { try { o2 = Object.create(b2); } catch(e0) { } try { a2[2]; } catch(e1) { } a2.unshift(new \"\\uD422\"(window,  '' ), (new  /x/ (window,  '' ))); return i1; }); } catch(e1) { } try { for (var v of a0) { try { for (var p in e2) { o0 = h2.__proto__; } } catch(e0) { } g1.g1.offThreadCompileScript(\"print(this);\", ({ global: this.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce:  '' , noScriptRval: false, sourceIsLazy: false, catchTermination: (x % 59 == 28) })); } } catch(e2) { } m2.delete(o1.a0); } }), set: (function() { try { v0 = this.g2.runOffThreadScript(); } catch(e0) { } g0.v0 = r1.global; return h1; }) });}lbbomd(x--, --a);");
/*fuzzSeed-169986037*/count=995; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -9.44473296573929e+21;\n    {\n      d0 = (-2147483649.0);\n    }\n    switch ((((i1))|0)) {\n      case -3:\n        {\n          i1 = (i1);\n        }\n        break;\n      case -2:\n        i1 = (0xffffffff);\n        break;\n      case -2:\n        d2 = (-72057594037927940.0);\n        break;\n      default:\n        d2 = (-32768.0);\n    }\n    (Float64ArrayView[((0xfb37d723)+((imul((0xfecb3864), (-0x8000000))|0))-(0xfb904e34)) >> 3]) = ((x.__defineSetter__(\"d\", (1 for (x in [])))));\n    return (((i1)*0xfffff))|0;\n  }\n  return f; })(this, {ff: String.prototype.toLowerCase}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-0x080000000, 0x0ffffffff, 2**53, 2**53-2, 1/0, -Number.MAX_VALUE, -0x100000001, 0x100000000, 42, -1/0, -(2**53-2), Number.MAX_VALUE, -(2**53+2), -0x0ffffffff, 0x080000001, 1, -Number.MIN_VALUE, 0x07fffffff, -0, -0x07fffffff, -0x080000001, 0/0, 0x080000000, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, 1.7976931348623157e308, 0, -0x100000000, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=996; tryItOut("\"use strict\"; s2 += s2;");
/*fuzzSeed-169986037*/count=997; tryItOut("mathy2 = (function(x, y) { return ((Math.max(Math.ceil(( ~ mathy0((Math.asinh((x >>> 0)) >>> 0), Math.fround(y)))), Math.asin((mathy0(Math.atan2(y, y), Math.fround(( - Math.fround(x)))) | 0))) >>> 0) >> Math.imul(( + Math.ceil((y || Math.pow(Math.fround(Math.tan((x <= 2**53-2))), (x | 0))))), (((( ! y) >>> 0) % (0x100000000 | 0)) | 0))); }); testMathyFunction(mathy2, [2**53+2, 0.000000000000001, Number.MIN_VALUE, -(2**53-2), -0x07fffffff, -Number.MAX_VALUE, 1/0, 0x100000001, 0x100000000, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x100000001, -0x0ffffffff, 42, -0, -0x080000001, 2**53, -Number.MIN_VALUE, 1, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, -0x080000000, -1/0, 0/0, -(2**53+2), 0x0ffffffff, 1.7976931348623157e308, 0x080000000, Math.PI]); ");
/*fuzzSeed-169986037*/count=998; tryItOut(" for  each(let y in ((function sum_slicing(fyulpx) { ; return fyulpx.length == 0 ? 0 : fyulpx[0] + sum_slicing(fyulpx.slice(1)); })(/*MARR*/[new String(''),  '\\0' , new String('')]))) print(y);");
/*fuzzSeed-169986037*/count=999; tryItOut("\"use asm\"; testMathyFunction(mathy4, [1, -0x100000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0, -(2**53), 0x100000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000001, Number.MIN_VALUE, Math.PI, 0x080000000, -0x080000001, 0.000000000000001, -0x0ffffffff, 0x07fffffff, 0x100000001, Number.MAX_SAFE_INTEGER, -0x080000000, -1/0, 1/0, -0x07fffffff, 2**53-2, 2**53, Number.MIN_SAFE_INTEGER, -0x100000000, -(2**53+2), 1.7976931348623157e308, 0, -(2**53-2), 2**53+2, 42, 0/0]); ");
/*fuzzSeed-169986037*/count=1000; tryItOut("a0 = a0.concat(o2.a0, t0, t1);");
/*fuzzSeed-169986037*/count=1001; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ((Math.asin((Math.tanh(y) << (((( + (mathy2(x, x) >>> 0)) >>> 0) + x) | 0))) | 0) < Math.min(Math.log10(Math.imul(( + ((Math.atan2(y, -0x080000001) | 0) & ( + x))), ( + (x << y)))), Math.cbrt((( + Math.fround(mathy0(Math.fround(y), Math.fround(Math.fround(( ~ Math.fround(y))))))) ** ( + ( + (y && y))))))); }); testMathyFunction(mathy3, [2**53+2, 2**53, -(2**53-2), 0.000000000000001, -Number.MIN_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -1/0, 1, 0x07fffffff, 0x080000000, -(2**53+2), -Number.MAX_VALUE, Number.MIN_VALUE, -0, -(2**53), 42, -Number.MAX_SAFE_INTEGER, 1/0, 0x100000001, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, 0/0, -0x07fffffff, 2**53-2, -0x080000000, -0x0ffffffff, 0x0ffffffff, 1.7976931348623157e308, 0, 0x080000001, Math.PI, 0x100000000]); ");
/*fuzzSeed-169986037*/count=1002; tryItOut("L:for(y = (Math.min( /x/ , -15))() in function ([y]) { }) s1 += s2;");
/*fuzzSeed-169986037*/count=1003; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (( + Math.imul(( + Math.tan(Math.fround(((y == (Math.round(x) | 0)) ? x : (y !== (x >= -(2**53))))))), ( + Math.atan(((Math.fround(Number.MAX_VALUE) ** Number.MAX_VALUE) | 0))))) === ( + (Math.log10((Math.clz32(( ! y)) | 0)) >>> 0))); }); testMathyFunction(mathy5, [0x07fffffff, Number.MAX_VALUE, 0, -(2**53-2), 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 42, 0x080000001, 2**53-2, 0.000000000000001, -0x100000001, -Number.MAX_VALUE, 2**53, 2**53+2, 1/0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, -0x100000000, Math.PI, 0x100000000, -0x080000001, 0x100000001, 0/0, 1, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53), -0x080000000, 0x080000000, Number.MIN_VALUE, -0, -1/0]); ");
/*fuzzSeed-169986037*/count=1004; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1005; tryItOut("v0 = t2.length;");
/*fuzzSeed-169986037*/count=1006; tryItOut("\"use strict\"; \"use asm\"; mathy0 = (function(x, y) { return (((( ~ ((Math.hypot(y, ( + Math.acosh(x))) >>> 0) >>> 0)) | (Math.pow((x >>> 0), (Math.atan((Math.fround(Math.fround(Math.fround((1/0 & x)))) | 0)) >>> 0)) >>> 0)) % ( ~ ( + (( + (Math.hypot((x >>> 0), ((( ~ (( + y) >>> x)) >>> 0) >>> 0)) >= x)) >>> ( + (Math.max(( + 1), x) & x)))))) >>> 0); }); ");
/*fuzzSeed-169986037*/count=1007; tryItOut("");
/*fuzzSeed-169986037*/count=1008; tryItOut("testMathyFunction(mathy4, [-(2**53+2), -0, -Number.MAX_SAFE_INTEGER, 1/0, -0x100000001, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53-2), -0x100000000, -0x080000001, 1.7976931348623157e308, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x100000000, 1, 0x080000000, -Number.MAX_VALUE, 42, 0.000000000000001, -(2**53), Math.PI, 0, -0x080000000, 0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, 2**53-2, -1/0, -Number.MIN_VALUE, 0/0, 2**53, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=1009; tryItOut("Array.prototype.splice.apply(a0, [-1, 6]);");
/*fuzzSeed-169986037*/count=1010; tryItOut("/*RXUB*/var r = /\\3/im; var s = \"aaa\"; print(uneval(r.exec(s))); ");
/*fuzzSeed-169986037*/count=1011; tryItOut("this.o2 = {};");
/*fuzzSeed-169986037*/count=1012; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1013; tryItOut(" for  each(let x in /(\\B|^|\\b+(?:(.){536870912})){1}/gyim) {v1 = (f1 instanceof this.i0);\"\\u32C3\"; }");
/*fuzzSeed-169986037*/count=1014; tryItOut("Array.prototype.unshift.call(a0, this.b1, this.a2, \"\\u3D67\", o2.t2, this.i2, /(?=(?=(?!(?!.)))){4}(?=(?=(?=\u00dd\\S))*?)\\cE?$/yim, g2, h2);");
/*fuzzSeed-169986037*/count=1015; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.sqrt((mathy1(( + mathy1(( + x), ( + ( ~ 0x100000001)))), (mathy1((y >>> 0), (( + (x + x)) >>> 0)) >>> 0)) >= (mathy0(( + y), ( + ((Math.fround(Math.max(Math.fround((Math.hypot((y | 0), (x | 0)) | 0)), Math.fround(y))) ** ((x & Math.fround(x)) | 0)) | 0))) >>> 0))); }); testMathyFunction(mathy3, [-0, 0, null, undefined, (new Number(-0)), 1, 0.1, NaN, true, [0], '', '0', [], '\\0', (new Boolean(true)), /0/, (new Number(0)), false, ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), (new Boolean(false)), (new String('')), ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), (function(){return 0;}), '/0/']); ");
/*fuzzSeed-169986037*/count=1016; tryItOut("o2.v1 = Object.prototype.isPrototypeOf.call(o0, e1);");
/*fuzzSeed-169986037*/count=1017; tryItOut("/*RXUB*/var r = r1; var s = \"\\n\"; print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=1018; tryItOut("M:if((x % 36 != 14)) {v0 = Object.prototype.isPrototypeOf.call(a0, m2); } else  if (this) {a1.push(o2, o2.g0);null; } else {v2 = Array.prototype.reduce, reduceRight.apply(a0, [(function() { for (var j=0;j<100;++j) { f1(j%3==0); } })]); }");
/*fuzzSeed-169986037*/count=1019; tryItOut("\"use strict\"; f2(e0);");
/*fuzzSeed-169986037*/count=1020; tryItOut("let window, \u3056 = ([] = x), utjlco, x = x, x, z =  /x/g ;;");
/*fuzzSeed-169986037*/count=1021; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return ( + Math.log10((( ! Math.hypot((mathy0((Math.fround((Math.fround(Math.fround(mathy0(Math.fround(y), Math.fround(Math.min((x >>> 0), (x >>> 0)))))) || Math.fround(Math.cosh(x)))) >>> 0), ((Math.max(((Math.fround(y) >> x) >>> 0), (Math.max(y, y) >>> 0)) >>> 0) >>> 0)) >>> 0), Math.sign(( + -Number.MAX_SAFE_INTEGER)))) >>> 0))); }); testMathyFunction(mathy1, [-0x100000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, -0x07fffffff, 1.7976931348623157e308, -(2**53+2), -0x100000001, 0x0ffffffff, -0, 0x100000001, Math.PI, 0x07fffffff, 2**53+2, -Number.MAX_VALUE, 2**53-2, -Number.MIN_VALUE, -(2**53), 0x100000000, 42, 1/0, 2**53, 1, -1/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x080000001, 0x080000000, -(2**53-2), -0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=1022; tryItOut("mathy3 = (function(x, y) { return (Math.max(( ! ( + (((y >>> 0) < Math.atan2(Math.imul(2**53, y), y)) >>> 0))), ((Math.max((Math.fround(Math.log1p(( + ((x >>> 0) / mathy0(((Math.log(Math.fround(1/0)) | 0) >>> 0), (y >>> 0)))))) | 0), ((mathy0((Math.log2(y) >>> 0), (Math.fround(((Math.trunc(y) >>> 0) ** x)) >>> 0)) >>> 0) | 0)) | 0) | 0)) | 0); }); testMathyFunction(mathy3, [1/0, -0x07fffffff, 42, Number.MIN_VALUE, 0x07fffffff, 1, 0x080000001, -0x100000001, 0x100000000, 0, -0x100000000, Math.PI, 0x0ffffffff, -(2**53), 0x100000001, 0x080000000, -Number.MIN_VALUE, -0x080000000, 2**53-2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -0, -(2**53+2), 2**53, -1/0, 2**53+2, -Number.MAX_VALUE, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 0/0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=1023; tryItOut("mathy5 = (function(x, y) { return Math.fround(( ! ( + (Math.fround((( + y) > Math.max(((( + (y | 0)) | 0) >>> 0), Math.fround(mathy0(Math.fround(x), Math.fround(x)))))) ? mathy2(( + ((x | 0) == ( + Math.atan2(( + x), ( + x))))), ( ! x)) : (Math.max(-1/0, Math.fround(( ! Math.fround((x < -0x0ffffffff))))) | 0))))); }); testMathyFunction(mathy5, [-0, 0/0, -0x080000001, 0.000000000000001, -0x100000000, 1.7976931348623157e308, -0x07fffffff, 42, 0x07fffffff, -(2**53), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -1/0, 0x080000000, -0x100000001, 1, -0x080000000, -Number.MAX_VALUE, 0x080000001, 0, 1/0, 2**53, -(2**53-2), 0x100000001, 2**53+2, -(2**53+2), Number.MIN_SAFE_INTEGER, 0x0ffffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000000, Math.PI, -0x0ffffffff, 2**53-2]); ");
/*fuzzSeed-169986037*/count=1024; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return ((( + (Math.atanh((( ! ( ! ((Math.cbrt(((Math.fround(y) * y) | 0)) | 0) | 0))) >>> 0)) >>> 0)) + Math.fround(Math.sin(Math.fround((Math.fround(x) * Math.fround((Math.imul(((((y | 0) !== (-0x07fffffff | 0)) | 0) | 0), ((( ! Math.fround(-Number.MAX_VALUE)) >>> 0) | 0)) | 0))))))) ? Math.asin(( + Math.fround(Math.hypot(( - x), -(2**53-2))))) : (Math.cosh(( + Math.hypot(Math.hypot((( ! x) >>> 0), (( + Math.tanh(y)) >>> 0)), ( + Math.atanh(( + x)))))) | 0)); }); ");
/*fuzzSeed-169986037*/count=1025; tryItOut("\"use strict\"; Array.prototype.reverse.call(o1.a2, b2, ());");
/*fuzzSeed-169986037*/count=1026; tryItOut("\"use strict\"; print(this);");
/*fuzzSeed-169986037*/count=1027; tryItOut("with(x){Array.prototype.sort.call(a2, (function() { try { e1.add(g1.o0.s2); } catch(e0) { } v1 = Object.prototype.isPrototypeOf.call(p1, v2); return b0; })); }");
/*fuzzSeed-169986037*/count=1028; tryItOut("for (var v of g2.e2) { try { Object.freeze(h1); } catch(e0) { } try { h2.hasOwn = f1; } catch(e1) { } try { print(g2); } catch(e2) { } v0 = 4.2; }");
/*fuzzSeed-169986037*/count=1029; tryItOut("/*ODP-2*/Object.defineProperty(i0, \"a\", { configurable: true, enumerable: false, get: f0, set: (function(stdlib, foreign, heap){ \"use asm\";   function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1.0009765625;\n    return (((0xd02b3bd8)))|0;\n  }\n  return f; }) });");
/*fuzzSeed-169986037*/count=1030; tryItOut("\"use strict\"; print(x);Object.prototype.unwatch.call(i2, 14);");
/*fuzzSeed-169986037*/count=1031; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return ((Math.expm1(Math.log10(( ~ ( + ( - -0))))) >>> 0) >= Math.atan2(Math.fround((Math.hypot(Math.acosh((y < x)), y) && Math.pow(x, y))), ( + (Math.imul((mathy0(Math.sqrt(y), ( - ( + -0x080000001))) >>> 0), y) >>> 0)))); }); testMathyFunction(mathy4, [2**53-2, 0x07fffffff, -Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, 1.7976931348623157e308, 2**53+2, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 42, -0x080000001, Math.PI, -(2**53), -1/0, -0x080000000, -0x100000000, 0/0, 0x100000000, 1, -0, Number.MIN_VALUE, 0x0ffffffff, -(2**53+2), 0x100000001, -0x100000001, 0.000000000000001, -0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 1/0, 0]); ");
/*fuzzSeed-169986037*/count=1032; tryItOut("\"use asm\"; mathy3 = (function(x, y) { return (( + Math.fround(((Math.fround(( ~ Number.MIN_VALUE)) ? (Math.expm1(0) | 0) : Math.tan(mathy1(Math.fround(x), Math.fround(Math.fround(( - Math.fround(x))))))) >>> 0))) ? ((Math.fround(( - Math.fround(mathy0(x, Math.fround(Math.atan2(Math.fround(y), Math.max((-0x080000001 , -0x080000001), mathy2(x, -Number.MIN_SAFE_INTEGER)))))))) && ((Math.fround(Math.acosh(x)) ^ Math.fround(( + Math.pow(( + Math.cbrt(x)), ( + x))))) >>> 0)) >>> 0) : ( + Math.clz32(( + ((Math.pow(( + Math.asin((Math.max(0x07fffffff, y) | 0))), y) - (Math.fround((Math.fround(mathy1(y, x)) ** Math.fround(y))) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, ['/0/', null, ({toString:function(){return '0';}}), '\\0', false, (new Number(0)), (new String('')), (new Boolean(false)), /0/, '0', undefined, -0, NaN, (new Number(-0)), 1, ({valueOf:function(){return 0;}}), [], (new Boolean(true)), 0, [0], '', (function(){return 0;}), true, objectEmulatingUndefined(), 0.1, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-169986037*/count=1033; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ( + Math.hypot((Math.cos((( ! (Math.fround(( - ((( ~ (( ! x) >>> 0)) >>> 0) >>> 0))) | 0)) | 0)) | 0), ( + (x <= ((Math.min(( + ((x | 0) & y)), Math.fround(Math.imul((-0 | 0), (x | 0)))) >>> 0) / (Math.fround(mathy1((Math.fround(0x0ffffffff) > Math.fround(-Number.MAX_SAFE_INTEGER)), x)) >> Math.round(x)))))))); }); testMathyFunction(mathy2, /*MARR*/[new String('q'), new String('q'), new String(''), new String('q'), arguments.caller, new String(''), [(void 0)], new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), new String('q'), arguments.caller, new String(''), new String('q'), x, x, arguments.caller, new String('q'), [(void 0)], new String('q'), [(void 0)], new String('q'), [(void 0)], new String('q'), new String('q'), [(void 0)], [(void 0)], new String('q'), new String('q'), arguments.caller, new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String(''), new String('q'), new String(''), new String(''), [(void 0)], x, new String('q'), arguments.caller, [(void 0)], new String('q'), x, x, new String(''), arguments.caller, x, [(void 0)], new String(''), arguments.caller, [(void 0)], x, arguments.caller, new String('q'), new String(''), new String('q'), new String(''), x, arguments.caller, [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], [(void 0)], new String(''), new String('q')]); ");
/*fuzzSeed-169986037*/count=1034; tryItOut("v1.toString = f2;");
/*fuzzSeed-169986037*/count=1035; tryItOut("mathy2 = (function(x, y) { return (Math.hypot((Math.atan2((( ! x) === -Number.MIN_VALUE), ((Math.fround(( - Math.fround(y))) ? Math.fround((y >= Math.fround((((Number.MAX_VALUE >>> 0) > (mathy1(y, y) >>> 0)) >>> 0)))) : Math.fround(( - y))) >>> 0)) >>> 0), (( + Math.abs(( + ( + mathy1(((( ~ ( ! (( ! (y ? (x | 0) : (y | 0))) | 0))) >>> 0) | 0), (( - (x >>> 0)) >>> 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, /*MARR*/[x, new Boolean(false), new Boolean(false), (void 0), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  /x/ , (void 0), x, new Boolean(false), (void 0), (void 0),  /x/ , x, x, (void 0), x,  /x/ , new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), (void 0), new Boolean(false), x, (void 0), (void 0), new Boolean(false), x,  /x/ , (void 0), x, new Boolean(false),  /x/ , x,  /x/ , new Boolean(false),  /x/ , x, (void 0), x, (void 0), new Boolean(false), x, (void 0), (void 0), new Boolean(false), new Boolean(false), new Boolean(false),  /x/ , x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, new Boolean(false),  /x/ ,  /x/ , x, (void 0), x, new Boolean(false), (void 0), (void 0), new Boolean(false), new Boolean(false), (void 0),  /x/ ,  /x/ ,  /x/ , x, new Boolean(false), x,  /x/ , x, x, (void 0),  /x/ ,  /x/ , x, x, (void 0), (void 0), x, (void 0), x,  /x/ , x, x, (void 0), x, x, new Boolean(false),  /x/ , x, x, x, new Boolean(false), x, new Boolean(false),  /x/ , (void 0), (void 0), new Boolean(false), x, x, new Boolean(false), x, (void 0), x, x, (void 0),  /x/ , x,  /x/ , x, x,  /x/ ,  /x/ , (void 0), (void 0), new Boolean(false), x, (void 0), (void 0), (void 0),  /x/ ,  /x/ , new Boolean(false),  /x/ , x,  /x/ , (void 0),  /x/ , x, x, (void 0), new Boolean(false),  /x/ , x, x, x, (void 0),  /x/ ,  /x/ , (void 0), new Boolean(false), (void 0), new Boolean(false), (void 0), (void 0),  /x/ , (void 0), x,  /x/ , x, new Boolean(false), (void 0)]); ");
/*fuzzSeed-169986037*/count=1036; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"h0.getOwnPropertyDescriptor = (function() { for (var j=0;j<6;++j) { f2(j%5==0); } });\");function this.\u3056() { return ( \"\" .prototype) } /*RXUB*/var r = g2.r1; var s = s1; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1037; tryItOut("/*vLoop*/for (ntwwim = 0; ntwwim < 65; ++ntwwim) { e = ntwwim; m2.set(o1.g1, m1); } ");
/*fuzzSeed-169986037*/count=1038; tryItOut("mathy3 = (function(x, y) { return (Math.acos((Math.trunc(Math.max((( ! x) | 0), Math.ceil(y))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [0x0ffffffff, 1.7976931348623157e308, 0x100000001, 42, Number.MIN_VALUE, -(2**53-2), 2**53+2, -0x080000000, -(2**53+2), 1/0, -Number.MAX_VALUE, 1, -0x0ffffffff, 2**53-2, -Number.MIN_VALUE, -1/0, -0, Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, Math.PI, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x07fffffff, -0x100000001, 0x080000000, 0/0, -0x100000000, -0x080000001, -(2**53), Number.MAX_VALUE, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0, 2**53]); ");
/*fuzzSeed-169986037*/count=1039; tryItOut("const audguv, xfzxwe, x;print(this.e0);");
/*fuzzSeed-169986037*/count=1040; tryItOut("/*MXX1*/o2 = g0.URIError.prototype.toString;");
/*fuzzSeed-169986037*/count=1041; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (( + mathy4(y, (1 < Math.tan(x)))) != ( - ( + Math.fround((y || x))))); }); testMathyFunction(mathy5, [2**53-2, -0x07fffffff, 0x080000001, -1/0, 0x0ffffffff, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_VALUE, -0x100000000, 0/0, -Number.MAX_VALUE, -(2**53), Math.PI, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -Number.MIN_VALUE, 0, -0x080000001, 42, -(2**53-2), 1/0, 0.000000000000001, 0x07fffffff, 0x080000000, 1.7976931348623157e308, -0, 0x100000001, 1, -0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-169986037*/count=1042; tryItOut("\"use strict\"; print(x);\nv2 = t2.length;\n");
/*fuzzSeed-169986037*/count=1043; tryItOut("testMathyFunction(mathy5, [0x07fffffff, Number.MIN_SAFE_INTEGER, Math.PI, 0/0, -0, 2**53+2, 1/0, 0x100000001, -0x080000001, 2**53-2, 42, 1.7976931348623157e308, -0x07fffffff, -Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MAX_VALUE, -(2**53), 0, 1, 0x0ffffffff, -0x100000000, Number.MIN_VALUE, 0.000000000000001, 0x100000000, -Number.MIN_VALUE, 0x080000001, 0x080000000, 2**53, -0x080000000, -(2**53-2), -0x100000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1044; tryItOut("\"use strict\"; /*vLoop*/for (let ptbzks = 0, x; ptbzks < 56; ++ptbzks) { const z = ptbzks; /*ODP-3*/Object.defineProperty(p2, \"wrappedJSObject\", { configurable: (x % 6 == 3), enumerable: false, writable: true, value: /*UUV2*/(y.unshift = y.isFrozen) }); } ");
/*fuzzSeed-169986037*/count=1045; tryItOut("v0 = (p2 instanceof v2);");
/*fuzzSeed-169986037*/count=1046; tryItOut("\"use strict\"; a1[17] = x;");
/*fuzzSeed-169986037*/count=1047; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=1048; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.atanh((( ~ (((mathy2(Math.fround(( + ( - ( + -(2**53-2))))), (( + y) >>> 0)) >>> 0) - mathy1(y, ( + Math.log(y)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy3, [0x100000001, 0.000000000000001, Math.PI, 0x0ffffffff, -Number.MIN_VALUE, -0x080000001, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 2**53+2, -(2**53+2), 0x07fffffff, 0, 1.7976931348623157e308, 2**53-2, 1, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53), 0x100000000, -0x100000000, 0x080000000, 1/0, 42, -0, -0x080000000, 2**53, -(2**53-2), 0x080000001, -1/0, 0/0, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1049; tryItOut("m2.get(this.b0);");
/*fuzzSeed-169986037*/count=1050; tryItOut("m1.set(f0, /*UUV1*/(z.values = /*wrap3*/(function(){ var uvmhyq = --arguments[\"getTimezoneOffset\"]; ((Int8Array).call)(); })));");
/*fuzzSeed-169986037*/count=1051; tryItOut("\"use strict\"; m1.delete(m2);");
/*fuzzSeed-169986037*/count=1052; tryItOut("\"use strict\"; this.v0 = (p0 instanceof f1);");
/*fuzzSeed-169986037*/count=1053; tryItOut("mathy2 = (function(x, y) { return (Math.log10((Math.atan2(( + Math.fround(Math.fround(y))), ( ~ Math.fround(mathy0(Math.exp(0), ( - Math.fround(mathy1(y, (y | 0)))))))) | 0)) | 0); }); testMathyFunction(mathy2, /*MARR*/[function(){}]); ");
/*fuzzSeed-169986037*/count=1054; tryItOut("\"use asm\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround((Math.pow(Math.fround((Math.fround(Math.exp(y)) <= Math.fround(0x07fffffff))), (((( + Math.atanh(Math.fround((mathy2(( + -0x0ffffffff), (x >>> 0)) | 0)))) >>> 0) >= ( + y)) >>> 0)) ^ Math.expm1((mathy1((mathy1(( - Math.cbrt(x)), 1) | 0), (Math.imul(x, (( + (( + y) ? ( + y) : ( + 0x080000000))) >>> 0)) >>> 0)) | 0)))) != Math.fround(Math.ceil(Math.fround((x ? ( ~ Math.expm1(Number.MIN_VALUE)) : (( + ( ! (( + Math.tan(( + y))) >>> 0))) | 0))))))); }); testMathyFunction(mathy3, [-0, 0x080000000, 0/0, -0x100000000, 0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000001, 1, 0x0ffffffff, -Number.MIN_VALUE, 2**53-2, 0x100000000, -Number.MAX_VALUE, 1/0, -0x07fffffff, 0.000000000000001, Number.MAX_VALUE, 2**53+2, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x0ffffffff, 2**53, 0x100000001, -1/0, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, -(2**53+2), Number.MIN_VALUE, -0x080000001, 0, 42, -0x100000001]); ");
/*fuzzSeed-169986037*/count=1055; tryItOut("\"use strict\"; /*oLoop*/for (ydnory = 0; ydnory < 120; ++ydnory) { /*ADP-3*/Object.defineProperty(a2, this.__defineSetter__(\"b\", (function(x, y) { return Math.imul(( ! Math.fround(Math.cos(Math.fround(y)))), Math.fround((Math.cbrt((((Math.log1p(((x === (0x100000000 | 0)) | 0)) >>> 0) % (Math.min(Math.fround(( - x)), Math.fround(y)) | 0)) > (y <= Math.fround(1)))) >>> 0))); })), { configurable: false, enumerable: false, writable: (x % 53 == 45), value: v0 }); } ");
/*fuzzSeed-169986037*/count=1056; tryItOut("v0 = r2.sticky;");
/*fuzzSeed-169986037*/count=1057; tryItOut("mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n/* no regression tests found */\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +(((/*FFI*/ff()|0) ? (17592186044415.0) : (+(0.0/0.0))));\n    return +((-34359738369.0));\n  }\n  return f; })(this, {ff: Math.trunc}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, /*MARR*/[ /x/g , new Boolean(true), -Number.MIN_SAFE_INTEGER, function(){}, function(){}, new Boolean(true), new Boolean(true), -Number.MIN_SAFE_INTEGER, function(){}, function(){}, function(){}, function(){},  /x/g ,  /x/g , new Boolean(true), function(){},  /x/g , function(){},  /x/g , new Boolean(true), -Number.MIN_SAFE_INTEGER, function(){}, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, function(){}, new Boolean(true), -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, function(){}, function(){},  /x/g , -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER,  /x/g , -Number.MIN_SAFE_INTEGER, new Boolean(true), function(){}, function(){}, new Boolean(true), -Number.MIN_SAFE_INTEGER, new Boolean(true), function(){}, new Boolean(true), new Boolean(true),  /x/g ,  /x/g , function(){}, function(){}, new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){}, -Number.MIN_SAFE_INTEGER,  /x/g ,  /x/g , new Boolean(true), -Number.MIN_SAFE_INTEGER,  /x/g , function(){}, -Number.MIN_SAFE_INTEGER,  /x/g ,  /x/g ,  /x/g , -Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, function(){}, new Boolean(true), new Boolean(true), function(){},  /x/g , function(){}, new Boolean(true),  /x/g , new Boolean(true), new Boolean(true), function(){},  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , function(){}, new Boolean(true), new Boolean(true), new Boolean(true), function(){}, function(){}, function(){}, new Boolean(true), function(){},  /x/g , function(){}, -Number.MIN_SAFE_INTEGER, function(){}, new Boolean(true), -Number.MIN_SAFE_INTEGER, function(){}, new Boolean(true),  /x/g ,  /x/g ,  /x/g , function(){},  /x/g , new Boolean(true), function(){}, -Number.MIN_SAFE_INTEGER, new Boolean(true),  /x/g , function(){}, new Boolean(true), new Boolean(true), new Boolean(true),  /x/g , -Number.MIN_SAFE_INTEGER, new Boolean(true), function(){}]); ");
/*fuzzSeed-169986037*/count=1058; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.atan2(Math.min((x | 0), (Math.pow(x, (1 >>> 0)) ? Math.asinh(( + ( ~ ( + x)))) : ( + (y >>> 0x100000000)))), mathy1(( + (x ** Math.atan2(y, Math.fround((( + y) > y))))), Math.fround((( - (y | 0)) | 0)))) || (( - Math.max(0x0ffffffff, (( + ( + Math.sin(x))) || ( + y)))) ^ (( ! Math.fround((Math.fround(Math.min(y, y)) == Math.fround(Math.PI)))) >>> 0)))); }); testMathyFunction(mathy2, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), function(){}, new Number(1.5), new Number(1.5), function(){}, new Number(1.5), new Number(1.5), Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, new Number(1.5), new Number(1.5), new Number(1.5), function(){}, new Number(1.5), Number.MIN_VALUE, new Number(1.5), function(){}, function(){}, function(){}, Number.MIN_VALUE, function(){}, new Number(1.5), function(){}, new Number(1.5)]); ");
/*fuzzSeed-169986037*/count=1059; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=\\u41b6)*?|\\\\3|(?!(?=(?:.))|(?:(?!\\\\S){1,}))+?\", \"gyi\"); var s = \"a\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1060; tryItOut("v2 = 4.2;");
/*fuzzSeed-169986037*/count=1061; tryItOut("mathy2 = (function(x, y) { return ((( - Math.imul(x, x)) && (Math.acosh((Math.atan2(( + -0x100000001), Math.fround(Math.hypot((-0x080000001 >>> 0), y))) | 0)) | 0)) | 0); }); ");
/*fuzzSeed-169986037*/count=1062; tryItOut("var c = x;m2.has(v2);\no0 + '';\n");
/*fuzzSeed-169986037*/count=1063; tryItOut("a2.forEach((function() { for (var j=0;j<89;++j) { f1(j%3==0); } }));");
/*fuzzSeed-169986037*/count=1064; tryItOut(" '' ;");
/*fuzzSeed-169986037*/count=1065; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.min((Math.max((Math.sinh(x) | 0), ((Math.pow((( ~ ( ! (mathy2((x | 0), Math.acos(-(2**53))) | 0))) >>> 0), (Math.atan2(Math.hypot(( + Math.sin(Math.sign(y))), x), x) | 0)) >>> 0) >>> 0)) >>> 0), (Math.fround((y != Math.fround((( + (( + y) != ( + y))) >= ( + Math.fround(( + (Math.max(y, y) >>> 0)))))))) <= ( + (Math.atan2(( + Math.min(Math.fround(y), Math.acosh(x))), (y >>> 0)) >>> 0)))); }); ");
/*fuzzSeed-169986037*/count=1066; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=1067; tryItOut("\"use strict\"; this.v1 = t2.length;");
/*fuzzSeed-169986037*/count=1068; tryItOut("/*infloop*/for(-10.unwatch(\"valueOf\").valueOf(\"number\"); \"\\u8ED1\"; function shapeyConstructor(yemnvz){Object.defineProperty(this, new String(\"6\"), ({configurable: true, enumerable: false}));this[\"__count__\"] = DataView.prototype.getUint32;this[7] = b;this[\"call\"] = ( \"\" ).call;if (yemnvz) { o1.v0 = a0.reduce, reduceRight((function mcc_() { var lqrawp = 0; return function() { ++lqrawp; f0(/*ICCD*/lqrawp % 10 == 7);};})(), g2, g1.g0.g1, function ([y]) { }, a0); } this[7] = new Boolean(false);Object.defineProperty(this, 4, ({enumerable: 19}));this[new String(\"6\")] = ({});if (yemnvz) delete this[new String(\"6\")];return this; }) with(let (e)  /x/g ){print(x); }");
/*fuzzSeed-169986037*/count=1069; tryItOut("\"use strict\"; testMathyFunction(mathy0, [Math.PI, Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000001, -Number.MIN_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 2**53, 0x100000000, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x100000000, -0x100000001, 0x0ffffffff, 2**53-2, -0, -(2**53), Number.MIN_VALUE, 2**53+2, 0x100000001, 1.7976931348623157e308, -0x07fffffff, -0x080000000, 0/0, 0x080000000, -(2**53+2), 42, 0.000000000000001, -Number.MAX_VALUE, -0x0ffffffff, 1, 0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, 0]); ");
/*fuzzSeed-169986037*/count=1070; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + ( - Math.tanh((mathy2((x | 0), (Math.sinh(Number.MIN_SAFE_INTEGER) > ( + (((( + (( + 0x100000000) != x)) ** y) | 0) * y)))) | 0)))); }); testMathyFunction(mathy5, [2**53-2, Number.MIN_VALUE, -(2**53-2), Number.MAX_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 0x080000000, -Number.MIN_VALUE, 0, 1, 0x100000001, 42, -0x100000000, -0, 1.7976931348623157e308, -0x0ffffffff, 1/0, 2**53, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000001, 0x100000000, Number.MAX_VALUE, 0/0, Number.MIN_SAFE_INTEGER, 2**53+2, Math.PI, -Number.MAX_VALUE, -0x080000001, -0x080000000, -1/0, -0x07fffffff, 0x080000001, -(2**53), 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=1071; tryItOut("if(true) yield; else {/* no regression tests found */ }");
/*fuzzSeed-169986037*/count=1072; tryItOut("this.m1.set(b1, b2);");
/*fuzzSeed-169986037*/count=1073; tryItOut("\"use strict\"; h1.iterate = g1.f0;");
/*fuzzSeed-169986037*/count=1074; tryItOut("/*tLoop*/for (let c of /*MARR*/[ /x/ , this,  /x/ , this,  /x/ , this]) { selectforgc(o0); }");
/*fuzzSeed-169986037*/count=1075; tryItOut("testMathyFunction(mathy4, [2**53-2, -Number.MIN_VALUE, 0, 0x100000001, -0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 0x07fffffff, 0x100000000, Number.MAX_VALUE, 2**53+2, 0/0, 42, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -0x0ffffffff, -(2**53+2), -Number.MIN_SAFE_INTEGER, 1, 0.000000000000001, 0x080000001, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x080000000, -0x100000001, -(2**53-2), -(2**53), -0x080000001, 0x0ffffffff, 2**53, 1.7976931348623157e308, -0x07fffffff, 1/0]); ");
/*fuzzSeed-169986037*/count=1076; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + mathy0(( + Math.atan2(( + -Number.MIN_SAFE_INTEGER), Math.fround((-1/0 ? mathy0(Math.fround(Math.hypot(x, Math.fround(y))), (Number.MIN_VALUE < ((y | 0) ** y))) : ((mathy1((Math.max(Math.hypot(Math.min(x, 0.000000000000001), y), ( + -0x0ffffffff)) >>> 0), x) >>> 0) >>> 0))))), Math.cosh(( + Math.max((arguments.callee >>> 0), ((((Math.trunc(0x0ffffffff) | 0) >>> 0) != (( ~ ( + (x >>> 0))) | 0)) >>> 0)))))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, Math.PI, -(2**53-2), 1, -0x100000001, -1/0, 2**53+2, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, 0x100000000, -0x080000001, 0.000000000000001, -0x0ffffffff, -0x100000000, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000001, 2**53, 0x080000000, 42, -0x07fffffff, -(2**53+2), -Number.MIN_VALUE, 0/0, 1/0, 0x07fffffff, -(2**53), Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 0x080000001, 1.7976931348623157e308, -0, 2**53-2]); ");
/*fuzzSeed-169986037*/count=1077; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + Math.log1p((( ~ Math.fround((x !== ( + Math.fround(Math.cbrt(Math.hypot((x - ( + y)), 0x100000000))))))) | 0))); }); testMathyFunction(mathy2, [1, 42, 0.000000000000001, 0x100000001, -0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53), 0x080000000, 0x100000000, -Number.MAX_VALUE, Math.PI, -(2**53-2), 0x07fffffff, 0/0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, -0x100000000, -(2**53+2), 2**53, -0x100000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, -1/0, 1/0, -0x0ffffffff, -0, Number.MIN_VALUE, 0x0ffffffff, -Number.MIN_VALUE, 0]); ");
/*fuzzSeed-169986037*/count=1078; tryItOut("mathy2 = (function(x, y) { return Math.atan2(( + Math.fround(Math.min(((y >= (Math.log1p(Math.fround(mathy0(((y , (x >>> 0)) | 0), y))) | 0)) | 0), Math.fround((mathy0(mathy1(Math.fround(( ! Math.fround(x))), ( ~ y)), (Math.fround(y) / Math.fround((( + y) * 0)))) >>> 0))))), Math.min(Math.fround(Math.min(Math.fround(x), (( - Math.expm1(Math.PI)) | 0))), ( + Math.asinh(Math.pow((( + Math.fround(y)) | 0), x))))); }); testMathyFunction(mathy2, /*MARR*/[ /x/g ,  /x/g , x, [] = (Math.atan2(6,  /x/g )), x, [] = (Math.atan2(6,  /x/g )), [] = (Math.atan2(6,  /x/g )),  /x/g , x,  /x/g , x, x,  /x/g , x, x, [] = (Math.atan2(6,  /x/g )), x, x, [] = (Math.atan2(6,  /x/g )), true, [] = (Math.atan2(6,  /x/g )), x, [] = (Math.atan2(6,  /x/g )), x, x, true,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , [] = (Math.atan2(6,  /x/g )), x, [] = (Math.atan2(6,  /x/g )), [] = (Math.atan2(6,  /x/g )), [] = (Math.atan2(6,  /x/g )), true, [] = (Math.atan2(6,  /x/g )),  /x/g ,  /x/g , [] = (Math.atan2(6,  /x/g )), x, [] = (Math.atan2(6,  /x/g ))]); ");
/*fuzzSeed-169986037*/count=1079; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( ~ Math.hypot((Math.hypot((( + (( + x) ? x : (x , y))) >>> 0), mathy0((( + y) > ( + Math.imul(-0x100000001, 42))), mathy0((x / x), x))) | 0), ( + Math.min(( + x), ( + ( + Math.min(( + x), ( + Math.fround(( - Math.fround(( ~ x)))))))))))); }); testMathyFunction(mathy2, [-(2**53), 0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, -(2**53+2), -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53-2), 42, 0/0, 0x080000001, -0x100000001, -0x080000001, -0, 2**53-2, -0x0ffffffff, 0x080000000, 0x0ffffffff, -0x07fffffff, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, Math.PI, 0.000000000000001, -1/0, 2**53, 0, -Number.MIN_VALUE, -0x100000000, 1, 1.7976931348623157e308, 0x100000000, Number.MAX_VALUE, 2**53+2, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=1080; tryItOut("a0 = r0.exec(s0);");
/*fuzzSeed-169986037*/count=1081; tryItOut("\"use strict\"; if(false) {s2 += 'x';v1 = g2.eval(\"function f0(a2)  { \\\"use strict\\\"; return  } \"); } else  if (\"\\u843D\") 9; else {{ void 0; void schedulegc(72); } ;i0 + a1; }");
/*fuzzSeed-169986037*/count=1082; tryItOut("/*vLoop*/for (let fwquia = 0; fwquia < 71; ++fwquia) { let e = fwquia; m2 + ''; } ");
/*fuzzSeed-169986037*/count=1083; tryItOut("\"use strict\"; e0.has(i2);");
/*fuzzSeed-169986037*/count=1084; tryItOut("x;");
/*fuzzSeed-169986037*/count=1085; tryItOut("\"use strict\"; /*infloop*/for(let {NaN, \u3056: {x, x, \"\\uA624\": {}, [{}, {d: {}}]: x, w}, x: {x: {e, eval}, x: {\u3056}, y: arguments[\"1\"], x: x, e: \u3056}} = ({} = x); []; {} = /*MARR*/[function(){}, function(){}, ['z'], window, window, function(){}, window, ['z'], ['z'], function(){}, window, function(){}, ['z'], function(){}, ['z'], ['z'], window, ['z'], window, function(){}, function(){}, function(){}, ['z'], function(){}, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, window, function(){}, function(){}, function(){}].some( /x/g , new [z1,,]( /x/g ))) {v1 = 4;for(\u0009x = x in  /x/g ) break ; }");
/*fuzzSeed-169986037*/count=1086; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.pow((Math.acosh(( + Math.imul(Math.fround(Math.fround((Math.fround(x) ** Math.fround(-(2**53+2))))), Math.fround(Math.fround(( - (Math.imul(((y + x) | 0), (( + ( - x)) | 0)) | 0))))))) >>> 0), ( + Math.max(Math.fround(Math.imul(Math.min(Math.fround(Math.pow(Math.fround((mathy0((0x100000000 | 0), ((((x | 0) > y) | 0) >>> 0)) | 0)), Math.fround(y))), Math.hypot(x, y)), Math.sinh((Math.pow(-0x100000000, y) >>> 0)))), (( ~ ( + y)) << y)))); }); ");
/*fuzzSeed-169986037*/count=1087; tryItOut("\"use strict\"; /*hhh*/function ccahxd(x, []){ /x/ ;\n//h\nprint(x);\n}/*iii*/o0.t0 = new Uint8ClampedArray(19);");
/*fuzzSeed-169986037*/count=1088; tryItOut("sesivb();/*hhh*/function \u000csesivb(d = x, NaN){p2 + v0;}");
/*fuzzSeed-169986037*/count=1089; tryItOut("\"use strict\"; for (var v of o1) { try { neuter(b2, \"same-data\"); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(this.i1, m0); } catch(e1) { } try { o2 + v2; } catch(e2) { } s0 += o1.s0; }");
/*fuzzSeed-169986037*/count=1090; tryItOut("a1.forEach((function() { for (var j=0;j<38;++j) { f0(j%4==0); } }));");
/*fuzzSeed-169986037*/count=1091; tryItOut("\"use strict\"; a2 = a2.map((function() { try { s2 += 'x'; } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(o1.a2, f1); } catch(e1) { } f1.toString = (function() { try { f0.toString = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 16384.0;\n    var d3 = 65535.0;\n    var d4 = 129.0;\n    var d5 = 1.015625;\n    var i6 = 0;\n    var d7 = 144115188075855870.0;\n    i6 = (0x9efc2613);\n    return +((d4));\n    d7 = ((((((abs(((((0xf84252b8) ? (0x7b0d7491) : (-0x8000000))) | ((~~(1.125)) / (((0xffffffff)) ^ ((0xfa044e7e))))))|0))) - ((-1125899906842623.0)))) * ((d4)));\n    return +((d2));\n  }\n  return f; })(this, {ff: Math.sqrt}, new ArrayBuffer(4096)); } catch(e0) { } try { g1.m2.toSource = Array.isArray.bind(g1.t0); } catch(e1) { } try { v0 = g0.eval(\"(allocationMarker())\"); } catch(e2) { } v1 = r0.source; return f0; }); throw o2; }), v2);");
/*fuzzSeed-169986037*/count=1092; tryItOut("mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -7.555786372591432e+22;\n    var d3 = 262143.0;\n    return +((d2));\n  }\n  return f; })(this, {ff: function () { \"use strict\"; return (4277).__defineGetter__(\"x\", x => \"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return +(((({entries: (function handlerFactory(x) {return {getOwnPropertyDescriptor: (Date.prototype.setSeconds).call, getPropertyDescriptor: function(y) { print(x); }, defineProperty: undefined, getOwnPropertyNames: function() { throw 3; }, delete: function() { return false; }, fix: function() { }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: new Function, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; }), x: -8 })) + (d1)));\n  }\n  return f;) } }, new ArrayBuffer(4096)); testMathyFunction(mathy0, /*MARR*/[[(void 0)], [(void 0)], (eval)(), [(void 0)]]); ");
/*fuzzSeed-169986037*/count=1093; tryItOut("\"use strict\"; print(uneval(m2));");
/*fuzzSeed-169986037*/count=1094; tryItOut("/*RXUB*/var r = new RegExp(\"((?:\\\\D|[^])+?)*\\\\b|(\\\\1{3})*{3,3}|(?:(?!(?=[\\\\x]+)){0,}?)[^\\\\s\\u000b-\\\\xE6]{0}\", \"im\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-169986037*/count=1095; tryItOut("\"use asm\";  for (let x of +new RegExp(\"$|(?!$)+?|((?![\\uf35d\\\\S\\\\D\\\\W]){2,5})(?:\\ue030{4,6})+??\", \"im\") in new RegExp(\"[^](?=$*?)[^]{2,}{2}.*?\", \"im\")) {v0 = r2.toString; }");
/*fuzzSeed-169986037*/count=1096; tryItOut("m1.delete(g0);");
/*fuzzSeed-169986037*/count=1097; tryItOut("v2 + i2;");
/*fuzzSeed-169986037*/count=1098; tryItOut("\"use strict\"; this.e0.delete(p2);");
/*fuzzSeed-169986037*/count=1099; tryItOut("var nkpyru = new SharedArrayBuffer(12); var nkpyru_0 = new Uint16Array(nkpyru); nkpyru_0[0] = -12; var nkpyru_1 = new Uint16Array(nkpyru); nkpyru_1[0] = -(2**53-2); var nkpyru_2 = new Uint32Array(nkpyru); nkpyru_2[0] = 7; var nkpyru_3 = new Float64Array(nkpyru); nkpyru_3[0] = -13; var nkpyru_4 = new Uint16Array(nkpyru); nkpyru_4[0] = 22; var nkpyru_5 = new Float32Array(nkpyru); print(nkpyru_5[0]); var nkpyru_6 = new Int16Array(nkpyru); print(nkpyru_6[0]);  '' .padEnd([,,]);v1 = (o0 instanceof v0);h1.getOwnPropertyDescriptor = f1;print(nkpyru_5[0]);e1.add(s0);");
/*fuzzSeed-169986037*/count=1100; tryItOut("\"use strict\"; print(( ! Math.fround(Math.min(Math.max((x - ((x , x) >>> 0)), x), (x << x)))));");
/*fuzzSeed-169986037*/count=1101; tryItOut("g1.v2 = Object.prototype.isPrototypeOf.call(f0, f0);");
/*fuzzSeed-169986037*/count=1102; tryItOut("\"use strict\"; var x, x = (null.__defineGetter__(\"e\", Object.freeze)), a = eval, x = null, x = 27, e = /*UUV1*/(set.setInt32 = function(y) { \"use asm\"; this.b2.__proto__ = t1; }), window;this.m0.set(h1, g1);");
/*fuzzSeed-169986037*/count=1103; tryItOut("print(3);function eval(eval = function ([y]) { }, x, ...NaN) { yield x = Proxy.create(({/*TOODEEP*/})( \"\" ), /^(?:(?!.)|.).|(?:.)*+?|((?:(?!\\b)\\W){2})/gyim) } (null);");
/*fuzzSeed-169986037*/count=1104; tryItOut("t0[(4277)];");
/*fuzzSeed-169986037*/count=1105; tryItOut("o1.s1 += 'x';");
/*fuzzSeed-169986037*/count=1106; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return ( + Math.atan2(( + Math.imul(Math.fround(( ~ Math.fround(x))), (( + Math.sinh(( + Math.fround(( + x))))) * ((((mathy4(y, -0x080000001) >>> 0) != (Math.fround(Math.hypot(1, Math.imul(y, (x >>> 0)))) >>> 0)) >>> 0) | Math.expm1(Math.round(y)))))), ( + ( + (( + (( ~ Math.cosh((x | 0))) | 0)) ^ ( + (Math.atan2(((x + 0x080000001) >>> 0), (((y | 0) ? ((( + y) && ( + y)) | 0) : (x | 0)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy5, /*MARR*/[ /x/g , 1.7976931348623157e308, 0x40000001, x, 1.7976931348623157e308, 1.7976931348623157e308, x, 1.7976931348623157e308, 0x40000001, x, 1.7976931348623157e308, x,  /x/g ,  /x/g , x,  /x/g ,  /x/g , 0x40000001, 1.7976931348623157e308, 0x40000001, 0x40000001, 0x40000001, x, x,  /x/g ,  /x/g , 0x40000001, 1.7976931348623157e308, x, 0x40000001, x, 0x40000001, 0x40000001, 0x40000001, 1.7976931348623157e308, 0x40000001, 0x40000001, x, 0x40000001]); ");
/*fuzzSeed-169986037*/count=1107; tryItOut("mathy0 = (function(x, y) { return Math.log(((((( - ((x ? ( + ( + Math.hypot(( + ( - -0x07fffffff)), ( + Number.MIN_VALUE)))) : Math.atan2(y, (x >>> 0))) | 0)) | 0) | 0) + (( - Math.tan(Math.imul(y, Math.pow(y, -Number.MIN_SAFE_INTEGER)))) | 0)) | 0)); }); testMathyFunction(mathy0, [false, '/0/', ({toString:function(){return '0';}}), (new Number(0)), undefined, (new Boolean(false)), ({valueOf:function(){return 0;}}), null, (new Number(-0)), '\\0', (function(){return 0;}), NaN, [0], /0/, [], '0', true, (new Boolean(true)), 1, (new String('')), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), 0, -0, '', 0.1]); ");
/*fuzzSeed-169986037*/count=1108; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (( + Math.imul(Math.fround(( - Math.fround(0/0))), (( ! (mathy0((Math.ceil(x) >>> 0), ((Number.MAX_SAFE_INTEGER | 0) ? Math.fround(mathy0(x, ( + y))) : Math.fround(0x080000001))) | 0)) | 0))) > ((Math.cosh(( + Math.sqrt((Math.cosh((x >>> 0)) >>> 0)))) != Math.tanh((Math.max((x | 0), (y | 0)) | 0))) | 0)); }); testMathyFunction(mathy3, [0, -0, 2**53+2, -0x100000001, -Number.MAX_VALUE, -0x0ffffffff, 0x080000000, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x080000000, -(2**53-2), 2**53-2, 1.7976931348623157e308, -Number.MIN_VALUE, Math.PI, 0x100000000, 2**53, 0x100000001, 0/0, 0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, 42, 1, -1/0, Number.MAX_VALUE, 0x080000001, -0x100000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -0x080000001, -0x07fffffff, 1/0, 0.000000000000001]); ");
/*fuzzSeed-169986037*/count=1109; tryItOut("\"use strict\"; i0 = new Iterator(o1.o2);");
/*fuzzSeed-169986037*/count=1110; tryItOut("\"use strict\"; /*tLoop*/for (let a of /*MARR*/[[(void 0)], (void 0), [(void 0)], false, (1/0), null, (void 0), false, (1/0), [(void 0)], [(void 0)], (1/0), (void 0), (void 0), [(void 0)], (1/0), [(void 0)], [(void 0)], (void 0), (void 0), (void 0), [(void 0)], null, (void 0), (void 0), null, null, (void 0), (1/0), false, null, null, [(void 0)], null, (void 0), [(void 0)], false, null, [(void 0)], false, [(void 0)], (void 0), (void 0), [(void 0)], (1/0), null, null, (1/0), false, (1/0), [(void 0)], null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, false, [(void 0)], null, false, [(void 0)], null, false, null, [(void 0)], false, [(void 0)], false, [(void 0)], (void 0), null, [(void 0)], null, [(void 0)], (void 0), (void 0), [(void 0)], null, [(void 0)], (void 0), false]) { a0.__iterator__ = (function() { try { o1.v1 = Object.prototype.isPrototypeOf.call(o0, this.a0); } catch(e0) { } try { /*RXUB*/var r = r0; var s = g1.s0; print(r.exec(s));  } catch(e1) { } try { o1 + ''; } catch(e2) { } m2.set(t1, v0); return v0; }); }");
/*fuzzSeed-169986037*/count=1111; tryItOut("b0 = new ArrayBuffer(18);");
/*fuzzSeed-169986037*/count=1112; tryItOut("\"use strict\"; a1 + a0;");
/*fuzzSeed-169986037*/count=1113; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return ( + ( + ( + ( + Math.atan(( + (x && (x ^ y)))))))); }); testMathyFunction(mathy4, /*MARR*/[null, null, NaN, new Boolean(false), new Boolean(false), NaN, new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-169986037*/count=1114; tryItOut("v1 = Object.prototype.isPrototypeOf.call(b2, v0);print((uneval(-22)));print(((function too_much_recursion(gznmnd) { ; if (gznmnd > 0) { ; too_much_recursion(gznmnd - 1);  } else {  /x/g ; }  })(87069)));");
/*fuzzSeed-169986037*/count=1115; tryItOut("\"use strict\"; v1 = a0.reduce, reduceRight((function() { try { Array.prototype.unshift.call(g0.g2.a0, a1, e2); } catch(e0) { } m0.has(i1); return m2; }), v1);");
/*fuzzSeed-169986037*/count=1116; tryItOut("testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 1, -0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 42, 2**53-2, -0x100000000, 1/0, -0x0ffffffff, 0x07fffffff, -0x080000001, 0x0ffffffff, Number.MIN_VALUE, 0/0, -(2**53), -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MIN_VALUE, Math.PI, 2**53+2, 0x100000001, -0x07fffffff, 0, 0.000000000000001, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, -1/0, -(2**53-2), 0x100000000, -0x100000001, 0x080000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=1117; tryItOut("\"use strict\"; var c = ([]) = \nMath.atan2(/*RXUB*/var r = new RegExp(\"(?!(?!\\\\b)|[]{1,1}|\\\\b\\\\\\ua460*?)\", \"i\"); var s = \"\"; print(s.match(r)); print(r.lastIndex); , /.{0,0}/y);g1.__proto__ = i2;");
/*fuzzSeed-169986037*/count=1118; tryItOut("o1 + i2;");
/*fuzzSeed-169986037*/count=1119; tryItOut("g1.e2 = new Set(i2);");
/*fuzzSeed-169986037*/count=1120; tryItOut("i2.valueOf = (function() { for (var j=0;j<48;++j) { f1(j%5==1); } });");
/*fuzzSeed-169986037*/count=1121; tryItOut("{ void 0; try { (enableSingleStepProfiling()) } catch(e) { } } a0 = new Array;\nv2 = Object.prototype.isPrototypeOf.call(b1, a1);\n");
/*fuzzSeed-169986037*/count=1122; tryItOut("this.e1.delete(e2);");
/*fuzzSeed-169986037*/count=1123; tryItOut("var idozrd = new ArrayBuffer(12); var idozrd_0 = new Uint16Array(idozrd); print(idozrd_0[0]); idozrd_0[0] = -12; var idozrd_1 = new Float32Array(idozrd); idozrd_1[0] = 15; var idozrd_2 = new Float32Array(idozrd); idozrd_2[0] = -12; var idozrd_3 = new Uint16Array(idozrd); idozrd_3[0] = 15; var idozrd_4 = new Int32Array(idozrd); idozrd_4[0] = 7; var idozrd_5 = new Int16Array(idozrd); print(idozrd_5[0]); var idozrd_6 = new Uint8Array(idozrd); print(idozrd_6[0]); var idozrd_7 = new Float32Array(idozrd); idozrd_7[0] = -9007199254740992; var idozrd_8 = new Uint32Array(idozrd); idozrd_8[0] = -5; var idozrd_9 = new Uint8Array(idozrd); var idozrd_10 = new Int16Array(idozrd); v0 = new Number(-0);print((((Date.prototype.setSeconds)(idozrd_8[0]))((4277),  /* Comment */\"\\u1441\")));var evalgj = new ArrayBuffer(0); var evalgj_0 = new Uint16Array(evalgj); evalgj_0[0] = -21; yield  '' ;for (var p in a0) { o2 + p2; }g1.v2 = evalcx(\"[,,];\", g1);s1 = a1.join(o1.s1, o1.v1, s1, o0);a0[this.__defineGetter__(\"idozrd_2[0]\", objectEmulatingUndefined)] = e1;");
/*fuzzSeed-169986037*/count=1124; tryItOut("/*hhh*/function qbciur(c = new ((eval))(), window, ...eval){t1[v2];}qbciur();");
/*fuzzSeed-169986037*/count=1125; tryItOut("\"use strict\"; for(let z in []);");
/*fuzzSeed-169986037*/count=1126; tryItOut("v0 = (p2 instanceof g1);function x(\u3056) { yield [,,z1] }  \"\" ;");
/*fuzzSeed-169986037*/count=1127; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.exp((Math.imul(Math.fround(Math.min(x, Math.max(((y * Number.MAX_SAFE_INTEGER) , y), x))), ( + (( + ((-Number.MAX_VALUE | 0) + ( - (x >>> 0)))) !== ( + Math.log10(Math.fround((( + Math.cos(( + x))) !== (0/0 >>> 0)))))))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-(2**53), -0x080000001, Number.MAX_VALUE, 2**53+2, -0x07fffffff, -Number.MAX_VALUE, -0x080000000, 2**53-2, 0x0ffffffff, 0x07fffffff, -0, -(2**53+2), 1.7976931348623157e308, 0x100000001, 42, 0x080000001, 1, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, 0.000000000000001, 0x080000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53, 1/0, 0/0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -1/0, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=1128; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.hypot(( + ((((( + y) | 0) > Math.fround(Math.min(Math.fround(x), Math.fround((x !== (x >>> 0)))))) & mathy1(( + -0), (( ~ ((-Number.MAX_SAFE_INTEGER == -0x080000000) | 0)) , x))) ? Math.min((Math.asinh((( + Math.min(Math.fround(Math.acosh((y >>> 0))), x)) >>> 0)) >>> 0), Math.fround((Math.imul((x >>> 0), (( - (Math.sin(y) >= y)) >>> 0)) >>> 0))) : (( + ( - x)) >> Math.fround(mathy1(Math.hypot(x, -(2**53+2)), Math.fround(0x0ffffffff)))))), (mathy1((Math.asinh(( + mathy0(Math.fround(Math.sin((Number.MAX_SAFE_INTEGER >>> 0))), 2**53-2))) ? mathy1(((( + y) != (y >>> 0)) >>> 0), y) : Math.trunc(0x07fffffff)), ((((Math.pow(Math.fround(x), ( ! x)) | 0) | 0) & (((((Math.atan2(x, y) == x) | 0) >= (Math.fround((y / Math.fround(Math.asin(x)))) | 0)) | 0) | 0)) | 0)) | 0)); }); testMathyFunction(mathy2, [-0x100000000, 1.7976931348623157e308, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x080000000, 0x080000001, 1/0, -Number.MIN_SAFE_INTEGER, -0, -(2**53), 0x07fffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 0x100000001, -0x100000001, -(2**53+2), 1, -(2**53-2), 2**53-2, -0x07fffffff, 2**53+2, Number.MIN_SAFE_INTEGER, 42, -1/0, 0/0, 0x0ffffffff, 0, Math.PI, 0x100000000, 2**53, -0x080000000, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=1129; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.atanh((Math.atan(((( - Math.fround(-Number.MIN_SAFE_INTEGER)) | 0) == (mathy1(( + Math.fround(Math.trunc(Math.fround(x)))), ( + ( - Math.acos((y | 0))))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [2**53+2, -Number.MIN_SAFE_INTEGER, 2**53-2, Math.PI, -Number.MAX_VALUE, 0x07fffffff, -1/0, -0x07fffffff, 42, 1.7976931348623157e308, -0x080000000, -0x100000000, 0.000000000000001, 0x080000000, -0x080000001, -(2**53), 1, 0/0, -(2**53+2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0, 2**53, 0x100000001, 1/0, -(2**53-2), -0x0ffffffff, -0]); ");
/*fuzzSeed-169986037*/count=1130; tryItOut("mathy2 = (function(x, y) { return ( + ( - ( + mathy0((((0.000000000000001 | 0) ? (Math.max(-(2**53-2), ( + ( + x))) | 0) : ( - y)) | 0), Math.fround(Math.tanh(Math.round((x << x)))))))); }); testMathyFunction(mathy2, [0x080000001, 0, 2**53, -0x080000000, Number.MIN_VALUE, 0x080000000, 0x100000001, 0/0, Math.PI, 1.7976931348623157e308, -(2**53), -0x100000000, -1/0, 0x07fffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53+2, 0x0ffffffff, -(2**53-2), -0x100000001, 0x100000000, -0x0ffffffff, 2**53-2, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000001, 42, -0, -Number.MIN_SAFE_INTEGER, 1, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, 1/0]); ");
/*fuzzSeed-169986037*/count=1131; tryItOut("if((x % 62 == 5)) /*RXUB*/var r = r1; var s = \"\\u00ab\\u00ab\\u00ab\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1132; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (((Math.cos((( ! mathy1((Math.sign(Math.fround(x)) >>> 0), ( + Math.acosh((( + 1.7976931348623157e308) % ( + Math.PI)))))) >>> 0)) >>> 0) * ( + Math.cbrt(( + ( + Number.MAX_SAFE_INTEGER))))) >>> 0); }); testMathyFunction(mathy2, [1.7976931348623157e308, 1/0, -0x0ffffffff, 0x080000001, Number.MAX_VALUE, -0x100000001, Math.PI, 0x100000001, -1/0, -0x07fffffff, 1, -0x080000001, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 42, 0x080000000, 2**53, -(2**53+2), 2**53+2, -0x100000000, -0, -(2**53), 0x0ffffffff, 0x100000000, 0/0, Number.MIN_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x07fffffff, -0x080000000, 0, -Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=1133; tryItOut("mathy3 = (function(x, y) { return ( ~ ( + Math.imul(((y ? Math.fround(x) : Math.fround(Math.fround(( - ( + Math.fround((0 ? y : x))))))) === x), (( ~ (Math.fround(( ~ Math.fround(( + ((x >= x) ? y : -(2**53-2)))))) | 0)) | 0)))); }); ");
/*fuzzSeed-169986037*/count=1134; tryItOut("NaN = ({} = Math.imul(70368744177665, -7)), thjdwm, NaN = \"\\u894A\", dpsdcf, zuhrkr, window;print(x);");
/*fuzzSeed-169986037*/count=1135; tryItOut("o2.p2 + '';");
/*fuzzSeed-169986037*/count=1136; tryItOut("mathy0 = (function(x, y) { return Math.sin(Math.atanh(( ~ Math.fround(Math.log2(( + Math.acos(( + y)))))))); }); testMathyFunction(mathy0, [0x100000000, -0, -0x0ffffffff, 0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, 0x0ffffffff, Math.PI, -1/0, 42, -0x100000001, Number.MAX_VALUE, 2**53+2, -0x07fffffff, 0x080000000, 1.7976931348623157e308, 0.000000000000001, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, -(2**53), 2**53, -Number.MIN_VALUE, -0x100000000, 2**53-2, 1/0, -(2**53+2), 1, -0x080000001, 0, 0/0, 0x080000001]); ");
/*fuzzSeed-169986037*/count=1137; tryItOut("a2 + h2;");
/*fuzzSeed-169986037*/count=1138; tryItOut("\"use strict\"; Object.defineProperty(this, \"v2\", { configurable: false, enumerable: false,  get: function() {  return r2.constructor; } });");
/*fuzzSeed-169986037*/count=1139; tryItOut("for (var v of this.o0.v2) { /*ADP-1*/Object.defineProperty(a2, 13, ({set: Object.isExtensible, configurable: (x % 3 != 0)})); }");
/*fuzzSeed-169986037*/count=1140; tryItOut("p0.toSource = (function(j) { f2(j); });\nm2.set(p2, g1);\n");
/*fuzzSeed-169986037*/count=1141; tryItOut("\"use strict\"; a0.splice(10, Math.min((({ get 1 NaN (x =  \"\" , x) { \"use strict\"; yield x }  })\n), -21), p1, intern(x instanceof x));");
/*fuzzSeed-169986037*/count=1142; tryItOut("\"use strict\"; ;");
/*fuzzSeed-169986037*/count=1143; tryItOut("\"use strict\"; let (emoxbq, /(?=(?:(?=^?)))?|(?=\\w[^])|$|(?!(?:[^\\cV-\\x3f\\B-\u5e66]|\\B){2,}[^]+?)/gm = x) { v1 = g2.eval(\"v2 = (o0.t0 instanceof o1.h2);\"); }");
/*fuzzSeed-169986037*/count=1144; tryItOut("o0.f1 = g2.objectEmulatingUndefined();");
/*fuzzSeed-169986037*/count=1145; tryItOut("\"use strict\"; /*infloop*/for(var a; (uneval((4277))); let (x = /(?:\\u00B0)|((.){3}|\\s^{4,})|\\d?|[]|.+\\1|[^\\W\\d\\w\u88ab]\uf05d+?\\2?/gyim) -1(/(?:(?=.){3})/gi)) {Array.prototype.push.apply(g0.a0, [o0.o1.v0]); }");
/*fuzzSeed-169986037*/count=1146; tryItOut("/*hhh*/function jrfozx(x, x = x, ...x){window;}/*iii*/o0 = new Object;");
/*fuzzSeed-169986037*/count=1147; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy1(((Math.max(( + Math.fround(( + Math.fround(x)))), (Math.cosh(x) | 0)) || mathy1(x, mathy1(y, x))) | (mathy1((Math.tanh(-0x0ffffffff) >>> 0), Math.fround(mathy0(Math.cbrt(( + mathy1(x, x))), (((y >>> 0) - (( + Math.acosh(-0x100000000)) >>> 0)) >>> 0)))) >>> 0)), ( + Math.atan2(Math.cos(Math.fround((( + x) && ( + ( - x))))), Math.max((((-0x100000001 | 0) >>> Math.fround(( - Math.fround(x)))) >>> 0), x)))); }); testMathyFunction(mathy2, /*MARR*/[(-1/0), function(){}, (-1/0), (-1/0), new String('q'), function(){}, (-1/0), (-1/0), function(){}, (-1/0), new String('q'), (-1/0), new String('q'), function(){}, new String('q')]); ");
/*fuzzSeed-169986037*/count=1148; tryItOut("/*RXUB*/var r = /(?=((?:(?=\\u0082|^|$?*?)|(?=\\D{2,})+))*)/; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1149; tryItOut("mathy5 = (function(x, y) { return ( ! (( + Math.min(Math.atan2(Math.hypot(Math.hypot(Number.MAX_SAFE_INTEGER, x), y), (Math.asin((42 >>> 0)) | 0)), ((Math.exp(Math.fround(Math.asinh(( + -(2**53+2))))) >>> 0) | 0))) , Math.fround(Math.tan(( + (((x >>> 0) ? (mathy4(-0x07fffffff, 0x0ffffffff) >>> 0) : ((Math.fround(Math.hypot(Math.fround(x), x)) + (x | 0)) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [0x07fffffff, -(2**53), -1/0, -0x07fffffff, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, 0x100000001, 0x0ffffffff, 0/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53-2), 0, -0x100000001, 0x080000000, 0x080000001, 0.000000000000001, -0x080000000, Number.MIN_VALUE, 2**53, -(2**53+2), -0, Math.PI, -0x100000000, 1/0, 0x100000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, -0x0ffffffff, 2**53+2, -0x080000001, -Number.MIN_VALUE, 2**53-2, 42]); ");
/*fuzzSeed-169986037*/count=1150; tryItOut("o1.a2.sort((function mcc_() { var fmeydz = 0; return function() { ++fmeydz; f1(/*ICCD*/fmeydz % 2 == 0);};})());");
/*fuzzSeed-169986037*/count=1151; tryItOut("testMathyFunction(mathy5, [Number.MIN_SAFE_INTEGER, -0x100000000, 42, -(2**53-2), -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 0/0, -0x07fffffff, 0x100000000, 2**53, Math.PI, 0x100000001, 2**53-2, -0x080000000, -0x080000001, -0x0ffffffff, -(2**53), -0, 0.000000000000001, -0x100000001, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, 1, 0x0ffffffff, 0, 1/0, -Number.MIN_VALUE, -Number.MAX_VALUE, 1.7976931348623157e308, 0x080000001, 0x07fffffff, -(2**53+2), Number.MAX_VALUE, 2**53+2]); ");
/*fuzzSeed-169986037*/count=1152; tryItOut("\"use strict\"; this.o1 = o0.__proto__;");
/*fuzzSeed-169986037*/count=1153; tryItOut("/*tLoop*/for (let x of /*MARR*/[new Boolean(false), function(){}, function(){}, function(){}, arguments, false, arguments, false, function(){}, function(){}, arguments, arguments,  \"use strict\" , new Boolean(false),  \"use strict\" , arguments, false, false, function(){}, arguments, new Boolean(false),  \"use strict\" , new Boolean(false),  \"use strict\" , new Boolean(false), false,  \"use strict\" , function(){}, false,  \"use strict\" , false,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , new Boolean(false), new Boolean(false),  \"use strict\" ,  \"use strict\" , arguments,  \"use strict\" , arguments, function(){}, new Boolean(false),  \"use strict\" , function(){}, new Boolean(false),  \"use strict\" , false, new Boolean(false), false, arguments, arguments, false,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , arguments, new Boolean(false), function(){}, false, arguments, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, arguments, new Boolean(false),  \"use strict\" , arguments, arguments, arguments,  \"use strict\" , function(){}, function(){}, new Boolean(false), function(){}, false,  \"use strict\" , new Boolean(false), false, new Boolean(false), new Boolean(false), function(){}, arguments, false, new Boolean(false),  \"use strict\" , function(){}, new Boolean(false), new Boolean(false), new Boolean(false), false,  \"use strict\" , arguments, arguments, arguments, false, new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), function(){}, false, function(){}, new Boolean(false), new Boolean(false), new Boolean(false),  \"use strict\" , function(){}, function(){}, false, arguments, new Boolean(false), function(){}, arguments, arguments, new Boolean(false), arguments, arguments, false, false, function(){},  \"use strict\" ,  \"use strict\" , function(){}, new Boolean(false), new Boolean(false), arguments,  \"use strict\" , arguments, arguments, new Boolean(false), arguments, false, arguments]) { print(/./ym); }");
/*fuzzSeed-169986037*/count=1154; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var sin = stdlib.Math.sin;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d1 = (+((+atan2(((d0)), ((d0))))));\n    d1 = (+sin(((d1))));\n    return (((0xffffffff)))|0;\n    d1 = (((0x5e44c83f)) ? (d1) : (-((d0))));\n    return (((0xffffffff)))|0;\n  }\n  return f; })(this, {ff: arguments.callee.caller.caller.caller.caller.caller.caller.caller}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=1155; tryItOut("m2.get(v2);");
/*fuzzSeed-169986037*/count=1156; tryItOut("v1 = (o1 instanceof s2);");
/*fuzzSeed-169986037*/count=1157; tryItOut("s2 += s0;");
/*fuzzSeed-169986037*/count=1158; tryItOut("v2 = (i1 instanceof g1);");
/*fuzzSeed-169986037*/count=1159; tryItOut("/*MXX1*/o1 = g0.g0.WeakSet.prototype.add;");
/*fuzzSeed-169986037*/count=1160; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3\", \"gyi\"); var s = \"\\u069b\\u069b\\u069b\\u069b\\u069b\\u069b\\u069b\\u069b\"; print(r.exec(s)); ");
/*fuzzSeed-169986037*/count=1161; tryItOut("m2.get(t2);");
/*fuzzSeed-169986037*/count=1162; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.imul((Math.fround(( ! Math.fround(( ~ x)))) | 0), (Math.fround((( + (Math.log1p(Math.fround(((((Math.fround((x , (-Number.MIN_SAFE_INTEGER >>> 0))) % Math.fround(0x100000000)) >>> 0) & (-0 >>> 0)) >>> 0))) === (y * ((((y | x) >>> 0) ? (-0x0ffffffff >>> 0) : ( + x)) >>> 0)))) !== Math.fround(Math.atan((Math.fround(x) && Math.fround((mathy1((-0 >>> 0), (( + mathy1(( + Math.PI), ( + x))) >>> 0)) >>> 0))))))) | 0)) | 0); }); ");
/*fuzzSeed-169986037*/count=1163; tryItOut("g0.__proto__ = f1;");
/*fuzzSeed-169986037*/count=1164; tryItOut("print(x);/* no regression tests found */");
/*fuzzSeed-169986037*/count=1165; tryItOut("mathy0 = (function(x, y) { return Math.abs(Math.sin((( + -0x080000001) | 0))); }); testMathyFunction(mathy0, [-Number.MIN_VALUE, -0x080000001, -(2**53+2), 0/0, 1, 42, 2**53+2, 0x080000001, -(2**53-2), 0.000000000000001, 0, -Number.MAX_SAFE_INTEGER, -1/0, -0x080000000, -Number.MAX_VALUE, 2**53-2, -(2**53), 2**53, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, -0x0ffffffff, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, 0x0ffffffff, 0x100000001, -0x100000000, 1/0, 0x080000000, -0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1166; tryItOut("for(x = x in (4277)) {o2.s0 += s2;/* no regression tests found */ }");
/*fuzzSeed-169986037*/count=1167; tryItOut("\"use strict\"; Array.prototype.splice.apply(a0, [NaN, 2, f0, s2, g1.i1, (++window), h0, o1.o0]);");
/*fuzzSeed-169986037*/count=1168; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1169; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.acosh(Math.fround(Math.cos(Math.fround(( + ( + ( + (( ~ Math.fround(( ~ y))) >> (x < x)))))))))); }); testMathyFunction(mathy2, [Math.PI, -0x100000000, 2**53, -0x100000001, Number.MIN_VALUE, 1, -Number.MAX_VALUE, 0x07fffffff, 0, 0x0ffffffff, -0x080000001, -(2**53), -0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, 0/0, 2**53-2, 2**53+2, 0.000000000000001, -(2**53+2), -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x0ffffffff, 0x100000000, -0, -1/0, 1.7976931348623157e308, 42, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1/0, -(2**53-2), 0x080000001, 0x080000000]); ");
/*fuzzSeed-169986037*/count=1170; tryItOut("if(.2) /*RXUB*/var r =  '' ; var s = \"\\n\"; print(uneval(s.match(r))); print(r.lastIndex);  else  if (x) /* no regression tests found */ else /*bLoop*/for (let qjcoek = 0; qjcoek < 17; ++qjcoek) { if (qjcoek % 45 == 12) { print(typeof ()); } else { this.s1 += s2; }  } ");
/*fuzzSeed-169986037*/count=1171; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((( + Math.fround(Math.acos(y))) ** Math.max(( + x), y)) & ( + ((Math.fround(Math.asinh(Math.min(x, x))) === ( + ( + (( + ( + Math.min(( + 0x07fffffff), -Number.MAX_SAFE_INTEGER))) >>> (Math.acosh(( ~ (-0x100000001 * x))) >>> 0))))) + (Math.hypot(Math.asinh(Math.fround(x)), Math.fround((( - y) == (y << x)))) >>> 0)))); }); testMathyFunction(mathy0, [-0x07fffffff, -(2**53-2), -1/0, -0x080000000, 0x0ffffffff, 0x100000001, Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, 1/0, 0x080000001, Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53), -0x100000000, -Number.MAX_VALUE, 0x080000000, 1, 42, -(2**53+2), Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0/0, -0x0ffffffff, 2**53-2, -0, -0x080000001, Math.PI, -0x100000001, 2**53+2, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, 0]); ");
/*fuzzSeed-169986037*/count=1172; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=1173; tryItOut("((4277));");
/*fuzzSeed-169986037*/count=1174; tryItOut("mathy4 = (function(x, y) { return Math.fround(( ! (Math.max(((x >>> ((Math.imul(x, ( + Math.trunc(y))) >>> 0) | 0)) >>> 0), ( + Math.round(Math.fround((x && y))))) >>> 0))); }); testMathyFunction(mathy4, [0, 2**53+2, -(2**53+2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53-2), -(2**53), -Number.MIN_VALUE, -0x0ffffffff, 1.7976931348623157e308, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x0ffffffff, -0x080000001, 0.000000000000001, 2**53, Number.MIN_VALUE, 1, -0x100000001, 0x100000000, -1/0, -0x080000000, 2**53-2, 1/0, 42, Math.PI, 0x080000000, 0x080000001, Number.MIN_SAFE_INTEGER, -0, -0x100000000, 0/0]); ");
/*fuzzSeed-169986037*/count=1175; tryItOut("/*bLoop*/for (var zaewhg = 0; zaewhg < 31; ++zaewhg) { if (zaewhg % 20 == 19) { o2.i0 = new Iterator(this.g2.b0); } else { return; }  } ");
/*fuzzSeed-169986037*/count=1176; tryItOut("with({c: undefined})a1.reverse(o0, v2);");
/*fuzzSeed-169986037*/count=1177; tryItOut("return /*UUV2*/(\u3056.delete = \u3056.atan);eval = eval;");
/*fuzzSeed-169986037*/count=1178; tryItOut("\"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return ( ! Math.fround((((Math.atan2(Math.fround((Math.fround(x) && Math.fround(x))), (( ~ (Math.hypot(((Math.max(( + x), ( + 0x0ffffffff)) | 0) >>> 0), Number.MAX_SAFE_INTEGER) | 0)) | 0)) !== mathy0(Math.fround(mathy1(y, (((x >>> 0) << (y | 0)) >>> 0))), x)) > (( ! ((0x080000000 ^ (( - ((Math.min((( + Math.acosh(( + x))) >>> 0), (y >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy2, [0/0, -0x0ffffffff, Number.MIN_VALUE, Math.PI, -(2**53-2), 0, 1.7976931348623157e308, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0x080000000, 0x080000000, 0x0ffffffff, -Number.MAX_VALUE, 0x100000001, Number.MAX_VALUE, -0x100000000, 0x07fffffff, -(2**53), 0x080000001, 2**53, 0.000000000000001, 1, -Number.MIN_VALUE, -0x100000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, -1/0, -(2**53+2), 42, -0x080000001, 2**53+2, 0x100000000, Number.MAX_SAFE_INTEGER, 1/0, 2**53-2]); ");
/*fuzzSeed-169986037*/count=1179; tryItOut("\"use strict\"; v2 = t2.length;");
/*fuzzSeed-169986037*/count=1180; tryItOut("b2.__proto__ = g2.f0;");
/*fuzzSeed-169986037*/count=1181; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return (Math.log((mathy1(( + (((Math.fround(((Math.fround(1/0) / Math.fround(Math.fround(( - Math.fround(Number.MIN_SAFE_INTEGER))))) | 0)) >>> 0) | 0) ** x)), (( - (Math.atan2((x >>> 0), (Math.fround(Math.atan2((Math.trunc(( + 0/0)) | 0), x)) >>> 0)) >>> 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy2, [-0x0ffffffff, Number.MAX_VALUE, 0x100000000, 0.000000000000001, 0x07fffffff, -0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 2**53, -(2**53+2), -0, -(2**53), -0x100000001, 42, 0x0ffffffff, 0x100000001, -(2**53-2), 1, -0x100000000, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, Number.MIN_VALUE, 2**53+2, -0x080000000, Math.PI, 0/0, -1/0, Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, 0, 0x080000000, 0x080000001]); ");
/*fuzzSeed-169986037*/count=1182; tryItOut("mathy1 = (function(x, y) { return Math.acosh(( ~ ( - -Number.MAX_SAFE_INTEGER))); }); testMathyFunction(mathy1, [Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x080000001, 2**53+2, -Number.MAX_VALUE, -0x100000000, 1/0, Math.PI, -Number.MIN_VALUE, -(2**53), 2**53-2, 1, -(2**53+2), Number.MIN_VALUE, -(2**53-2), -1/0, 1.7976931348623157e308, 0x0ffffffff, 0x100000000, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53, 0/0, -0x07fffffff, 0x100000001, 0x080000000, -0x080000000, -0x100000001, 42, 0x080000001, 0, -0, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001]); ");
/*fuzzSeed-169986037*/count=1183; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\3\", \"gyi\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-169986037*/count=1184; tryItOut("\"use strict\"; var dcgnoc = new SharedArrayBuffer(4); var dcgnoc_0 = new Uint32Array(dcgnoc); if(false) new RegExp(\"\\\\3+?\", \"gym\");v1 = (o1.f2 instanceof s2);yield  /x/g  /= this;");
/*fuzzSeed-169986037*/count=1185; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x080000000, 0x080000001, 42, 0, Number.MIN_VALUE, -0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -1/0, 0x100000000, 0/0, 2**53, 0x100000001, 1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, -Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, -(2**53), 1, -0x0ffffffff, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53+2), -(2**53-2), 0.000000000000001, -0x080000001, -0x07fffffff, 2**53+2, Math.PI, -0x100000001, 0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1186; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.imul((((( ! (Math.hypot(x, x) | 0)) | 0) !== (Math.fround(( - Math.fround(Math.fround(( ~ Math.trunc(Math.fround(( + Math.fround(((x | 0) , -(2**53))))))))))) | 0)) | 0), ((( ~ (0x080000001 | 0)) | 0) & Math.fround(( + ( + Math.atan2(y, ((y || x) >>> 0))))))); }); testMathyFunction(mathy0, /*MARR*/[new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(false), new Number(1.5), new Number(1.5), new Number(1.5), null, new Boolean(false), new Boolean(false), new Boolean(false), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Boolean(false), new Number(1.5), null, new Number(1.5), new Boolean(false), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), null, new Boolean(false), new Boolean(false), null, new Boolean(false), new Boolean(false), new Boolean(false), new Number(1.5), new Boolean(false), new Boolean(false), new Number(1.5), null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(false), new Number(1.5), null, new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Boolean(false), new Number(1.5), new Number(1.5), new Number(1.5), null, new Boolean(false), new Number(1.5), new Boolean(false), null, null, new Boolean(false), null, new Number(1.5), new Number(1.5), new Boolean(false), new Boolean(false)]); ");
/*fuzzSeed-169986037*/count=1187; tryItOut("testMathyFunction(mathy4, [0/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x07fffffff, 2**53+2, Number.MIN_VALUE, -0x100000001, -1/0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x080000000, -0x07fffffff, Number.MAX_VALUE, 42, Math.PI, 1.7976931348623157e308, 0.000000000000001, -Number.MAX_VALUE, 0x0ffffffff, -(2**53), Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000001, -(2**53-2), 0x100000001, 1, -0, -Number.MIN_VALUE, 0, -0x0ffffffff, 0x080000000, -0x100000000, 0x100000000, 2**53, 1/0, 2**53-2]); ");
/*fuzzSeed-169986037*/count=1188; tryItOut("\"use strict\"; (-Infinity);v1 = a0.length;");
/*fuzzSeed-169986037*/count=1189; tryItOut(";");
/*fuzzSeed-169986037*/count=1190; tryItOut("/*oLoop*/for (var gdaids = 0; gdaids < 42; ++gdaids) { /*RXUB*/var r = new RegExp(\"\\\\b{4,}|\\\\1\", \"m\"); var s = \"\"; print(s.match(r));  } ");
/*fuzzSeed-169986037*/count=1191; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return ( + (( + ((((Math.fround(( ! Math.fround(Math.fround(( + x))))) - x) | 0) && (mathy1(Math.max(y, x), Math.asin((( + (x == ( + 0x100000000))) | 0))) | 0)) | 0)) & (Math.acosh((x && Math.max(function  c (\u3056) { \"use strict\"; return eval } , y))) >>> 0))); }); ");
/*fuzzSeed-169986037*/count=1192; tryItOut("for(var c = (window - b\n) in  /x/ ) /*tLoop*/for (let z of /*MARR*/[undefined, undefined, c, (-1/0), c, (-1/0), c, c, (-1/0), undefined, undefined, c, c, c, undefined, (-1/0), c, c, undefined, undefined, undefined, undefined, undefined, (-1/0), (-1/0), c, (-1/0), (-1/0), (-1/0), undefined, (-1/0), c, c]) { s1.toString = (function() { try { a1 = Array.prototype.slice.call(a1); } catch(e0) { } try { v0 + ''; } catch(e1) { } o2 = new Object; return i1; }); }");
/*fuzzSeed-169986037*/count=1193; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + ( ~ ( ! Math.cosh(Math.min((Math.tanh((x >>> 0)) >>> 0), Math.atan2((Math.pow((( + (y === (-Number.MIN_VALUE >>> 0))) >>> 0), (Math.fround((y >= 1.7976931348623157e308)) >>> 0)) | 0), (Math.atan2(( + x), ( + y)) === (Math.atan((Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy1, [0, (new Number(-0)), NaN, (new Boolean(false)), (new String('')), ({valueOf:function(){return 0;}}), (function(){return 0;}), '\\0', ({valueOf:function(){return '0';}}), -0, (new Boolean(true)), '/0/', '0', (new Number(0)), objectEmulatingUndefined(), null, false, '', 0.1, 1, [0], undefined, true, ({toString:function(){return '0';}}), [], /0/]); ");
/*fuzzSeed-169986037*/count=1194; tryItOut("i2.send(b2);");
/*fuzzSeed-169986037*/count=1195; tryItOut("\"use strict\"; f1(g1.h0);");
/*fuzzSeed-169986037*/count=1196; tryItOut("t2.set(a0, 2);");
/*fuzzSeed-169986037*/count=1197; tryItOut("\"use strict\"; v1 = (t0 instanceof f1);");
/*fuzzSeed-169986037*/count=1198; tryItOut("/*RXUB*/var r = r0; var s = s1; print(s.replace(r, r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1199; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.imul(( + Math.hypot((( - ( + 2**53)) * Math.atan2(x, (Math.hypot(2**53+2, ( + x)) >>> 0))), (Math.sign((Math.atanh(Math.fround(Math.max(Math.fround(( - x)), Math.fround(-(2**53-2))))) >>> 0)) >>> 0))), Math.imul(Math.sin((Math.imul(( + Math.round(( + Math.trunc(((Math.min(x, Math.PI) | 0) | 0))))), x) >>> 0)), ( + ( - ( + Math.max(-1/0, y)))))); }); testMathyFunction(mathy4, [(new Boolean(false)), 0, (new Number(-0)), (function(){return 0;}), (new Number(0)), '', null, '\\0', /0/, 0.1, -0, '0', undefined, objectEmulatingUndefined(), true, NaN, (new String('')), false, '/0/', 1, [], (new Boolean(true)), ({valueOf:function(){return '0';}}), [0], ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}})]); ");
/*fuzzSeed-169986037*/count=1200; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = -8192.0;\n    return ((((((0xffffffff)-(0xffffffff)) >> ((-0x8000000)+(0xfdbcc20b))) > (~(((0x85cb23f4) != (0xe094336a))+((0xffffffff) ? ((let (w =  \"\" ) \"\\uA4A6\")) : ((((0x780dbd74)*-0x65056)|0))))))))|0;\n    {\no1.e2.add(/*FARR*/[].some(Number.prototype.toLocaleString) ? yield this : 1206308840.5);    }\n    d1 = (d2);\n    return ((((((0x1ce6bf45)-(0xffffffff))>>>(-0xab30*(0xa01581f1))) < (((((0x6b1c5e81)*-0xc89e2)|0) % (((0xf9242815)+(0xeef21646)) ^ ((0xffffffff)+(0x945a57e4))))>>>((0x101b6b0c))))*-0xfffff))|0;\n    d1 = (+(0xbaa09a13));\n    return (((Float32ArrayView[2])))|0;\n  }\n  return f; })(this, {ff: Math.atan2}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, [0x080000001, 0, Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 2**53+2, 0x0ffffffff, 0.000000000000001, 0x080000000, 42, -0x100000001, -(2**53), -0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -1/0, Math.PI, -0, 0x100000001, -(2**53+2), 2**53, 1, -0x080000000, 0x100000000, -0x0ffffffff, -0x100000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -(2**53-2), -0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=1201; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( ~ Math.max((((( + ( ~ (mathy2(Math.min(( + (mathy2((Math.PI | 0), (-0 | 0)) | 0)), x), y) | 0))) | 0) / ((Math.pow(( + 0x100000000), (( + (( + x) >= (1.7976931348623157e308 | 0))) | 0)) | 0) | 0)) | 0), Math.pow((( + ( ~ ( + Math.expm1((x >>> 0))))) ? (Math.fround(Math.fround(Math.fround(x))) && y) : x), x))); }); testMathyFunction(mathy4, [0.000000000000001, 1, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, Number.MAX_VALUE, 2**53, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0, 1.7976931348623157e308, 0x100000000, -0x100000000, -0x0ffffffff, -0x080000001, 0x080000001, 0/0, 0x100000001, -(2**53), 0, 1/0, -(2**53+2), -0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, 0x0ffffffff, 0x080000000, 2**53-2, 42, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=1202; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1203; tryItOut("\"use strict\"; \"use asm\"; g2 + b0;function x(w, y = ({\"-14\": c, window: ({}) = ( \"\" .__defineSetter__(\"e\", (eval).call)) }).__defineGetter__(\"window\", (neuter).bind()))\"use asm\";   function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((i0)-(0x4dbdca2a)-(i0)))|0;\n    d1 = (-536870913.0);\n    d1 = (-(true));\n    return ((0x4a53f*((((0xba7b690a)) ^ ((0xfb02b3b0)+(0x36b17228)+((0x0)))) >= (((0x69f75077) / (((0x27bc717c))>>>((i0)-(i0))))|0))))|0;\n  }\n  return f;s2 = '';");
/*fuzzSeed-169986037*/count=1204; tryItOut("/*tLoop*/for (let b of /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), Infinity, Infinity]) { b.stack;for(let b in window.watch(\"18\", (let (e=eval) e)).getDay) with({}) { \"\\uFB47\"; }  }");
/*fuzzSeed-169986037*/count=1205; tryItOut("(x = d);");
/*fuzzSeed-169986037*/count=1206; tryItOut("mathy2 = (function(x, y) { return Math.fround(Math.imul(( + ( + ( ! ( + (Math.log2((mathy1(mathy0((x >>> 0), Math.exp((Math.atan(x) | 0))), mathy1(( + Math.min(Math.log10(y), mathy0(x, Math.PI))), y)) >>> 0)) | 0))))), ((Math.log10(x) || ( + Math.abs(Math.fround(((Math.exp(y) | 0) ? Math.fround(( + ((x + x) | 0))) : ( ! 1.7976931348623157e308)))))) | 0))); }); ");
/*fuzzSeed-169986037*/count=1207; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    return +(((((i0))>>>((i1)+((((33.0)) * ((-6.044629098073146e+23))) != (3.8685626227668134e+25)))) % (((i0))>>>((d = \"\\u9034\")))));\n  }\n  return f; })(this, {ff: String.prototype.big}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, Number.MIN_VALUE, 0x100000000, 2**53-2, 0x080000000, -0x07fffffff, -(2**53+2), -0x0ffffffff, 1.7976931348623157e308, 0x07fffffff, -0x100000001, 0x0ffffffff, 0/0, Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 42, -0, -(2**53), 1/0, 0x080000001, -0x080000000, 1, -(2**53-2), -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x100000000, 0, Number.MAX_VALUE, 0x100000001, -1/0, -0x080000001]); ");
/*fuzzSeed-169986037*/count=1208; tryItOut("s1 = '';");
/*fuzzSeed-169986037*/count=1209; tryItOut("\"use strict\"; var xbxooi = new ArrayBuffer(0); var xbxooi_0 = new Uint32Array(xbxooi); xbxooi_0[0] = 0; var xbxooi_1 = new Int16Array(xbxooi); var xbxooi_2 = new Int32Array(xbxooi); xbxooi_2[0] = 25; var xbxooi_3 = new Int8Array(xbxooi); xbxooi_3[0] = 15; var xbxooi_4 = new Uint8ClampedArray(xbxooi); print(xbxooi_4[0]); var xbxooi_5 = new Uint8ClampedArray(xbxooi); xbxooi_5[0] = 27; Array.prototype.splice.call(a2, -6, eval, g0);");
/*fuzzSeed-169986037*/count=1210; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.max(Math.max(Math.fround(Math.fround(( - ( ~ mathy1((y >>> 0), x))))), Math.fround(Math.cos(( + Math.imul(Math.fround((y !== y)), x))))), Math.pow((( ! (( - Math.fround(( ! ( + -Number.MIN_SAFE_INTEGER)))) >>> 0)) >>> 0), Math.expm1(( ~ 2**53-2)))); }); ");
/*fuzzSeed-169986037*/count=1211; tryItOut("");
/*fuzzSeed-169986037*/count=1212; tryItOut("\"use strict\"; for (var p in v2) { try { /*ADP-1*/Object.defineProperty(g1.a1, ({valueOf: function() { let v2 = r0.unicode;return 18; }}), ({get: z})); } catch(e0) { } o1.toString = Function.prototype; }\nb2.toString = f1;\n");
/*fuzzSeed-169986037*/count=1213; tryItOut("mathy2 = (function(x, y) { return (( ! (( + Math.fround(( - (Math.imul(( + (( ! x) | 0)), mathy0((( - (y | 0)) >>> 0), y)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy2, [42, -0x080000001, -0x100000001, Number.MIN_VALUE, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, -(2**53+2), 0x080000001, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x080000000, -0, Number.MAX_VALUE, 1, 2**53-2, 0x07fffffff, 2**53, Math.PI, 2**53+2, 0x100000001, 0/0, -0x100000000, 0, -Number.MIN_VALUE, -1/0, 0x100000000, Number.MAX_SAFE_INTEGER, -(2**53-2), 0.000000000000001, 0x080000000, -(2**53), -0x0ffffffff, -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1214; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return Math.atan2(( + Math.max(Math.fround(((Math.min(mathy0((Math.atan2(0x100000001, x) >>> 0), (y >>> 0)), y) >>> 0) ^ (-0x0ffffffff >>> 0))), Math.fround((Math.fround(Math.min(Math.fround(Math.fround(Math.min((Math.hypot(((( - -0x0ffffffff) >>> 0) >>> 0), y) >>> 0), Math.min(0x07fffffff, (x >>> 0))))), ( + x))) && Math.fround(mathy0(( ! Number.MIN_SAFE_INTEGER), x)))))), ( + ( + ( + ( + ( + ( ~ ( + { void 0; try { startgc(7001469); } catch(e) { } })))))))); }); testMathyFunction(mathy2, [-Number.MIN_SAFE_INTEGER, 42, 0x080000000, 0.000000000000001, Number.MAX_VALUE, -(2**53+2), -0x080000001, 1, Number.MAX_SAFE_INTEGER, 0, 0/0, 2**53+2, 0x080000001, -Number.MAX_SAFE_INTEGER, -1/0, Number.MIN_VALUE, 1/0, 0x100000001, -0x0ffffffff, -0x100000001, 2**53-2, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, -0x100000000, -0x080000000, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, -0, -(2**53-2), 0x100000000, -0x07fffffff, 1.7976931348623157e308, 2**53]); ");
/*fuzzSeed-169986037*/count=1215; tryItOut("\"use strict\"; /*oLoop*/for (var svyddt = 0; svyddt < 1; ++svyddt) { ; } ");
/*fuzzSeed-169986037*/count=1216; tryItOut("\"use strict\"; t2 = t0.subarray(6, ({valueOf: function() { o2 = b2.__proto__;s2.toString = (function mcc_() { var cdrfxr = 0; return function() { ++cdrfxr; if (/*ICCD*/cdrfxr % 7 == 2) { dumpln('hit!'); try { /*ADP-2*/Object.defineProperty(a0, v0, { configurable: (x % 5 != 0), enumerable: (x % 25 != 10), get: (function() { try { print(uneval(t2)); } catch(e0) { } try { m1 = m0.get(e0); } catch(e1) { } Array.prototype.unshift.call(a1); return s0; }), set: (function() { try { this.v1 = evalcx(\"function f0(g2)  { yield [] } \", g0); } catch(e0) { } /*MXX3*/g0.SyntaxError.prototype.message = g1.SyntaxError.prototype.message; return o1.i2; }) }); } catch(e0) { } try { b0 = new ArrayBuffer(48); } catch(e1) { } try { s0 += s2; } catch(e2) { } v1 = g0.g0.r0.unicode; } else { dumpln('miss!'); try { s2 += 'x'; } catch(e0) { } try { v2 = (v0 instanceof m1); } catch(e1) { } try { a0 = r1.exec(s1); } catch(e2) { } /*ODP-2*/Object.defineProperty(a1, \"caller\", { configurable: (x % 2 != 1), enumerable: (x % 36 != 4), get: (function mcc_() { var hjgzaw = 0; return function() { ++hjgzaw; if (/*ICCD*/hjgzaw % 7 == 2) { dumpln('hit!'); /*RXUB*/var r = r2; var s = \"\"; print(s.split(r));  } else { dumpln('miss!'); try { m0.has(m1); } catch(e0) { } try { a0 = Array.prototype.slice.apply(a0, [2, 7, e1]); } catch(e1) { } e0.delete(i2); } };})(), set: (function() { for (var j=0;j<132;++j) { this.f2(j%4==0); } }) }); } };})();\u000c/*RXUB*/var r = /^/gm; var s = \"\"; print(s.match(r)); print(r.lastIndex); return 11; }}));");
/*fuzzSeed-169986037*/count=1217; tryItOut("\"use strict\"; print((\"\u03a0\")(true, [,,z1]));print(x);");
/*fuzzSeed-169986037*/count=1218; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1219; tryItOut("/*vLoop*/for (yuxmft = 0; yuxmft < 4; ++yuxmft) { y = yuxmft; print(arguments.callee.arguments--); } ");
/*fuzzSeed-169986037*/count=1220; tryItOut("/*vLoop*/for (let xracvo = 0; xracvo < 13; ++xracvo) { var w = xracvo; m1.valueOf = (function() { for (var j=0;j<5;++j) { f0(j%4==0); } }); } ");
/*fuzzSeed-169986037*/count=1221; tryItOut("return x;return -4;");
/*fuzzSeed-169986037*/count=1222; tryItOut("\"use strict\";  for  each(var b in \"\\uC3D6\") xe = (x.eval(\"print(x);\")) ? (4277) : new RegExp(\"(?=$|^|(?!\\\\d)|[^])?\", \"g\");");
/*fuzzSeed-169986037*/count=1223; tryItOut("\"use strict\"; /*MXX1*/o2 = g0.Object.getOwnPropertyDescriptors;");
/*fuzzSeed-169986037*/count=1224; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ( + ((((x && mathy0(x, ( ~ Math.fround(Math.trunc(( + Number.MIN_SAFE_INTEGER)))))) | 0) ? ((Math.expm1(Math.fround(( + (2**53-2 >>> 0)))) >>> 0) === (Math.max(( + x), Math.fround((Math.fround((( + -0x080000001) ** ( + ( ! 2**53+2)))) ? x : Math.fround(-0x0ffffffff)))) >>> 0)) : (( ! ( + Math.min(0x100000001, (0x080000000 >>> 0)))) | 0)) | 0)); }); testMathyFunction(mathy2, [-(2**53+2), 1/0, -(2**53-2), 0x080000000, -0x080000000, 0x100000001, -0x07fffffff, 0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -0x080000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x100000000, 0.000000000000001, Number.MIN_VALUE, -1/0, Math.PI, 1.7976931348623157e308, 2**53, Number.MAX_VALUE, 1, 0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, -0x100000000, 42, -0x0ffffffff, -0x100000001, 0, 0/0, 2**53+2, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-169986037*/count=1225; tryItOut("i1.next();");
/*fuzzSeed-169986037*/count=1226; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1227; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1228; tryItOut("mathy3 = (function(x, y) { \"use strict\"; \"use asm\"; return ((((( ~ (Math.fround((Math.fround((Math.atan2((((( + y) == (x >>> 0)) >>> 0) | 0), ((Math.hypot(x, ((x >>> 0) ** (x >>> 0))) >>> 0) | 0)) | 0)) << Math.fround(Math.pow((( - ((Math.atan2((( ! (y | 0)) | 0), (y | 0)) | 0) >>> 0)) >>> 0), ( + (( + x) <= y)))))) | 0)) | 0) | 0) != (Math.sin((( ~ ( ~ Math.fround(Math.hypot(x, ( - x))))) | 0)) >>> 0)) | 0); }); testMathyFunction(mathy3, [-0x080000000, 42, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 0, -0x100000001, -(2**53+2), Number.MIN_VALUE, 0/0, 0x080000001, -Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, -1/0, -0, 0x100000001, 0.000000000000001, Number.MAX_VALUE, -0x080000001, -Number.MIN_VALUE, 2**53+2, Math.PI, 1.7976931348623157e308, 1, -(2**53), -0x07fffffff, 1/0, Number.MAX_SAFE_INTEGER, 2**53, 2**53-2, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x100000000, 0x07fffffff, 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=1229; tryItOut("\"use strict\"; for (var p in b0) { try { i0.send(o0.h2); } catch(e0) { } try { print(h2); } catch(e1) { } g2.b2 + p2; }");
/*fuzzSeed-169986037*/count=1230; tryItOut("\"use asm\"; a2.toSource = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var i2 = 0;\n    var i3 = 0;\n    return +((-3.777893186295716e+22));\n  }\n  return f; })(this, {ff: function  NaN (z)\"use asm\";   var floor = stdlib.Math.floor;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d1);\n    d0 = (d0);\n    d0 = (+(((0xffffffff))>>>((((0x2c32e282)-(((d0)))) & ((Int8ArrayView[2]))) % (((-0x8000000)) | ((0xfca65531))))));\n    (Float32ArrayView[4096]) = ((+floor(((+(0.0/0.0))))));\n    return +((d1));\n  }\n  return f;}, new ArrayBuffer(4096));");
/*fuzzSeed-169986037*/count=1231; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (( ~ (mathy0((( - ( + ( ! ( + ( + x))))) | 0), (( + (( + ( + Math.log(( + Math.max((x >>> 0), (x >>> 0)))))) - Math.fround(Math.max(x, x)))) != (Math.fround((Math.fround(Math.fround((Math.fround(y) ^ Math.fround(x)))) ? Math.fround(x) : Math.fround(0x100000001))) | 0))) | 0)) | 0); }); testMathyFunction(mathy1, [2**53, -0x100000001, -0x07fffffff, -0x0ffffffff, 0.000000000000001, 1/0, 1.7976931348623157e308, -1/0, -(2**53-2), 2**53+2, 0x100000000, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_VALUE, -Number.MIN_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000001, Number.MAX_VALUE, Math.PI, -(2**53+2), 0x080000000, -0x080000001, 2**53-2, 0x07fffffff, -(2**53), 42, 0x080000001, -0x100000000, -0x080000000, 1, -0]); ");
/*fuzzSeed-169986037*/count=1232; tryItOut("mathy5 = (function(x, y) { return (mathy3(mathy1(mathy3((Math.fround(x) <= y), x), Math.fround(((((Math.pow(-(2**53-2), ((Math.exp((0 >>> 0)) >>> 0) >>> 0)) >>> 0) >>> 0) < ((Math.atan2(y, y) >>> 0) >>> 0)) >>> 0))), mathy1(( + ( + ( + y))), ( + (( + x) / ( + y))))) || Math.atan2(Math.clz32((Math.cbrt((x >>> 0)) >>> 0)), ( + Math.hypot(Math.cosh(( ~ 0x07fffffff)), (Math.fround((x - y)) | y))))); }); testMathyFunction(mathy5, /*MARR*/[x, x, eval, x, x, eval, x, eval, x, eval, x, eval, eval, x, eval, eval, eval, x, eval, eval, x, x, x, x, x, eval, x, eval, x, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, x, eval, eval, eval, eval, eval, eval, eval, x, eval, x, x, x, x, eval, x, eval, x, eval, eval, x, eval, x, eval, eval, eval, x, x, x, x, eval, eval, eval, x, x, x, eval, eval, eval, eval, x, x, x, eval, x, eval, x, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, x, eval, eval, x, eval, x, x, eval, x, eval, x, x, x, eval, eval, eval, eval, x, eval, x, x, eval, x, eval, x, eval, eval, eval, x, eval, x, x, x, eval, x, eval, eval, x, eval, eval, eval, eval, eval, eval, eval, x, x, x, x, x, eval, x, x, eval, eval, x, eval, x, eval, eval, x, x, eval, eval, eval, eval, x, x, eval, eval, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, eval, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, eval, eval, eval]); ");
/*fuzzSeed-169986037*/count=1233; tryItOut("with({b: window})do {; } while((undefined) && 0);");
/*fuzzSeed-169986037*/count=1234; tryItOut("var i2 = new Iterator(o2.s2, true);");
/*fuzzSeed-169986037*/count=1235; tryItOut("Array.prototype.shift.apply(a0, []);");
/*fuzzSeed-169986037*/count=1236; tryItOut("a0.shift();");
/*fuzzSeed-169986037*/count=1237; tryItOut("v2 = new Number(this.o2);");
/*fuzzSeed-169986037*/count=1238; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return (Math.sqrt((mathy1(((Math.fround(Math.atan2(Math.fround(mathy4((y | 0), y)), Math.fround(Math.atan2(x, x)))) ? (x | 0) : (x || ((Math.fround(x) * Math.fround(x)) | 0))) | 0), (((y | 0) / (x | 0)) | 0)) >>> 0)) ? Math.pow(( + ((( + Math.round(x)) > x) >>> 0)), (Math.acosh(( + (( + y) ? ( + (( ! Math.fround(x)) | 0)) : ( + y)))) | 0)) : Math.log1p(Math.hypot(( ~ ((x ? y : ( + Math.log(y))) | 0)), Math.asin(Math.log2(y))))); }); testMathyFunction(mathy5, [0, 1, -0x080000000, 0x100000000, -(2**53), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Math.PI, 0x100000001, 2**53+2, -0x080000001, -0, -0x100000001, -(2**53+2), 2**53, 0x080000001, 42, 0x07fffffff, 0.000000000000001, Number.MAX_VALUE, -(2**53-2), -1/0, Number.MAX_SAFE_INTEGER, 0x0ffffffff, Number.MIN_VALUE, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, 1/0, 2**53-2, -0x100000000, 0x080000000, -0x07fffffff, -Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-169986037*/count=1239; tryItOut("g1.v1 = evalcx(\"m0.has(v2);\", g1);");
/*fuzzSeed-169986037*/count=1240; tryItOut("Array.prototype.shift.call(a2, m1);");
/*fuzzSeed-169986037*/count=1241; tryItOut("g2.offThreadCompileScript(\"x\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 12 != 4), noScriptRval: true, sourceIsLazy: delete w.x, catchTermination: true, sourceMapURL: s0 }));function x(y, c) { yield  \"\"  } ");
/*fuzzSeed-169986037*/count=1242; tryItOut("\"use strict\"; switch(\u000c(WeakSet.prototype.add)(intern(-23), (4277))) { default: case x: o1.a1 = /*FARR*/[, ((z = y)), {}, (Math.pow(/\\1*/gi, x))];break; Array.prototype.splice.call(a0, 6, 17, f1, h0, f0, g2, i0);case 4: break;  }");
/*fuzzSeed-169986037*/count=1243; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.log2(((Math.pow((Math.fround(( ! (Math.asinh(Math.fround(( ~ Math.fround(x)))) >>> 0))) >>> 0), (Math.fround(Math.round(Math.fround(Math.atan2(Math.max(x, Math.imul(y, y)), (mathy2(0x100000001, Number.MAX_VALUE) | 0))))) | 0)) | 0) >>> 0)); }); testMathyFunction(mathy3, [0x080000000, 0x100000000, -0x080000000, Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, 0x07fffffff, -1/0, 42, -0, -(2**53-2), -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, 0x080000001, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, -(2**53), 2**53, -0x0ffffffff, -0x100000000, Number.MIN_VALUE, 0, 0x0ffffffff, 1/0, 2**53-2, 1, -0x080000001, Math.PI, 0.000000000000001, 2**53+2, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1244; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.cbrt(((Math.fround(( ~ x)) && y) < ( + (( + 0x100000000) | 0)))) | 0); }); testMathyFunction(mathy0, [Number.MIN_VALUE, -0, -0x07fffffff, 0, -1/0, -0x100000000, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, 0x100000000, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 0/0, Number.MAX_VALUE, 2**53-2, 42, -0x080000001, 2**53, -(2**53-2), -Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53), 0x080000000, 0.000000000000001, -0x0ffffffff, Math.PI, 1/0, -Number.MIN_VALUE, 1, 0x080000001, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1245; tryItOut("v2 = a1.length;");
/*fuzzSeed-169986037*/count=1246; tryItOut("");
/*fuzzSeed-169986037*/count=1247; tryItOut("s0 + a0;");
/*fuzzSeed-169986037*/count=1248; tryItOut(" for  each(var d in x) {/*RXUB*/var r = new RegExp(\"[^\\\\cM-\\\\u00E5][^]|(?=(?=^|[\\u44bd])|\\\\cG){0,0}|(.)*?{3}|\\\\3|^{2,}|(?=[^])\", \"m\"); var s = (4277); print(uneval(r.exec(s))); print(r.lastIndex); g0.v0 = (t2 instanceof f0); }");
/*fuzzSeed-169986037*/count=1249; tryItOut("m0.has(v0);");
/*fuzzSeed-169986037*/count=1250; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.acosh(Math.fround(((2**53 << y) >>> 0))) << Math.max(Math.sqrt((( + ((x | 0) ? ( + ( - x)) : (( + x) | 0))) >>> 0)), Math.fround(Math.pow(Math.fround(( + Math.log2((y >>> 0)))), Math.fround(Math.max((y | 0), ( ! ( + ( + Math.imul(( + y), x)))))))))); }); testMathyFunction(mathy3, [-0, -(2**53+2), -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000, 1, 0x080000001, 0/0, 2**53+2, -(2**53-2), 0x0ffffffff, -0x0ffffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 2**53, Number.MAX_SAFE_INTEGER, 0x080000000, 0x100000001, 42, -0x080000000, -1/0, -Number.MIN_VALUE, Math.PI, 0, 0x07fffffff, 2**53-2, -0x100000001, 1/0, -0x080000001, 1.7976931348623157e308, -(2**53)]); ");
/*fuzzSeed-169986037*/count=1251; tryItOut("print(x);");
/*fuzzSeed-169986037*/count=1252; tryItOut("\"use strict\"; mathy4 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = 274877906944.0;\n    {\n      (Int8ArrayView[(-(i1)) >> 0]) = ((((abs((((z += (4277))+(/*FFI*/ff(((-4294967297.0)), ((-35184372088833.0)), ((-16384.0)), ((-36028797018963970.0)), ((-1.0078125)), ((281474976710657.0)), ((-1099511627777.0)), ((-3.094850098213451e+26)), ((-3.094850098213451e+26)), ((-1.03125)))|0)+(i1)) | ((0xe5c9eebf)-(-0x8000000))))|0)) ? (0x7ef608a6) : (-0x8000000)));\n    }\n    {\n      d0 = (1125899906842625.0);\n    }\n    return ((((0xa679c94e) <= (((((!((0x7ecac017) >= (-0x137a5bb)))-((imul((0xd38c638c), (0x95eda727))|0)))|0) % (((i1)-(i1)) << (((((0x48f7d3fd)) & ((0xffffffff)))))))>>>(((i1) ? (0xa5e6cec6) : (0xdb122732))-(i1))))))|0;\n  }\n  return f; })(this, {ff: function shapeyConstructor(jcbjgo){{ a0.unshift(h0, jcbjgo); } if (x+=/((\\cR+{1048576,})*)*/gyi) delete jcbjgo[new String(\"12\")];jcbjgo[new String(\"12\")] = (function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function() { return true; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function() { return false; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: function(receiver, name) { return x[name]; }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: undefined, }; });if (jcbjgo) Object.freeze(jcbjgo);delete jcbjgo[new String(\"12\")];if (x = Proxy.create((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, getPropertyDescriptor: function(name) { return {get: function() { throw 4; }, set: function() { throw 5; }}; }, defineProperty: (decodeURI).bind, getOwnPropertyNames: function() { throw 3; }, delete: function() { return true; }, fix: function() { throw 3; }, has: function() { return false; }, hasOwn: function() { return false; }, get: ({/*TOODEEP*/}), set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: Int8Array, keys: function() { return []; }, }; })([z1,,]), (false <= \"\\u34D3\"))) { o1.m0.delete(s1); } jcbjgo[new String(\"12\")] = (let (e=eval) e);if ([[] = let (b = new RegExp(\"[\\\\n\\\\u9398\\\\W]|(?:.).*\\\\b|\\u0090\\\\b*{3,4}(\\\\B)\", \"gym\")) \"\\u976C\"]) for (var ytqzlmppv in jcbjgo) { }if (jcbjgo) { print(jcbjgo); } jcbjgo[new String(\"12\")] =  /x/ ;return jcbjgo; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy4, [-Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 0x080000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, -(2**53), -0x080000001, 0x100000001, 1.7976931348623157e308, -(2**53-2), -0x100000001, -0x080000000, -1/0, Number.MAX_VALUE, 0/0, -(2**53+2), 1, -0x0ffffffff, 2**53-2, 2**53, Number.MIN_VALUE, -Number.MAX_VALUE, 0, -Number.MIN_SAFE_INTEGER, 0x100000000, 0x080000000, -0, 0.000000000000001, 0x0ffffffff, -0x100000000, 2**53+2, 1/0, 42, -Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=1253; tryItOut("Array.prototype.splice.call(this.a2, -7, 10);");
/*fuzzSeed-169986037*/count=1254; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.sin(( + Math.pow(((x ? (Math.sin(( + x)) >>> 0) : ((Math.sinh((Math.fround((Math.fround(( + Math.asin(Math.fround(Math.max(y, y))))) === Math.fround((( ~ ( + -0x080000001)) | 0)))) >>> 0)) >>> 0) >>> 0)) >>> 0), (0x100000000 ** y))))); }); testMathyFunction(mathy0, [Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x100000001, -(2**53+2), 2**53, 1.7976931348623157e308, 0x07fffffff, -0x0ffffffff, -1/0, -(2**53), 0x100000001, Number.MIN_VALUE, Number.MAX_VALUE, -0x100000000, -(2**53-2), 0/0, 1/0, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, 0, -0x080000000, Math.PI, 0x080000001, 42, 2**53-2, 2**53+2, -0x080000001, -0]); ");
/*fuzzSeed-169986037*/count=1255; tryItOut("mathy4 = (function(x, y) { return Math.tan(Math.fround(Math.fround(( - ( ! (Math.fround(( - y)) | 0)))))); }); testMathyFunction(mathy4, [-0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0, -0x100000001, 0/0, 0x080000000, 1.7976931348623157e308, 0.000000000000001, Math.PI, 0x100000000, 0x0ffffffff, 0x07fffffff, -(2**53-2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, -(2**53), -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, 2**53, -0x080000001, -1/0, 1/0, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, -0, 2**53+2, -0x100000000, 42, 1]); ");
/*fuzzSeed-169986037*/count=1256; tryItOut("\"use asm\"; mathy0 = (function(x, y) { return ((Math.min(( + Math.sign(( + ( + Math.fround(Math.sign(Math.pow(y, (Math.atan2((y | 0), ( + y)) | 0)))))))), (Math.min(y, Math.fround(( + Math.imul(( + Math.pow(x, Math.imul(x, x))), Math.fround(( ~ Math.fround(x))))))) != Math.fround((( ! x) >>> 0)))) < (( + ( ~ (Math.pow((((y <= y) || ( - Math.log1p(-0x080000000))) | 0), ((Math.atan2(( + 1/0), (-0x07fffffff | 0)) | 0) >>> 0)) | 0))) >> (Math.fround((Number.MAX_SAFE_INTEGER != Math.fround(y))) >= ( + y)))) | 0); }); testMathyFunction(mathy0, [1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x080000001, -Number.MAX_VALUE, 2**53, -0, Number.MIN_VALUE, -0x080000000, -(2**53), Number.MIN_SAFE_INTEGER, 2**53+2, Number.MAX_VALUE, -0x07fffffff, -0x100000000, -Number.MIN_VALUE, 0x100000000, 0/0, Math.PI, 0x07fffffff, -1/0, 2**53-2, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, 0, -0x080000001, 1/0, 0x080000000, -Number.MAX_SAFE_INTEGER, 0x100000001, -0x100000001, -(2**53-2), 42, 0.000000000000001, 1]); ");
/*fuzzSeed-169986037*/count=1257; tryItOut("\"use strict\"; testMathyFunction(mathy1, [1/0, -Number.MIN_VALUE, -0x0ffffffff, 42, 0/0, -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53+2, 2**53-2, 0x080000001, 2**53, 0x100000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 1, -0x080000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, -0, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MAX_VALUE, 0x100000000, 0x0ffffffff, -(2**53), Number.MAX_VALUE, -0x100000000, 0.000000000000001, -1/0, 0x07fffffff, 0, Number.MIN_VALUE, Math.PI, 1.7976931348623157e308, 0x080000000, -0x100000001]); ");
/*fuzzSeed-169986037*/count=1258; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1259; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.cosh(( ! Math.atan2(Math.tanh((x * mathy0(y, x))), Math.fround(Math.max(y, (mathy2((Math.fround(( - Math.fround((Math.PI && -(2**53+2))))) >>> 0), ((y & y) >>> 0)) >>> 0)))))); }); testMathyFunction(mathy5, [0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000000, 0x080000000, -(2**53-2), Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, 0/0, Math.PI, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, -0, -0x0ffffffff, 1, -0x100000001, -Number.MIN_VALUE, 1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, 2**53+2, 2**53-2, 1.7976931348623157e308, 2**53, 0, -0x080000001, -1/0, 42, -0x07fffffff, -0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1260; tryItOut("\"use strict\"; v2 = undefined;");
/*fuzzSeed-169986037*/count=1261; tryItOut("with({}) { with({}) return ({c: false}); } with({}) { let(w) ((function(){w.stack;})()); } ");
/*fuzzSeed-169986037*/count=1262; tryItOut("\"use strict\"; /*infloop*/for(var x = /*UUV2*/(w.exp = w.asin); x; (yield 20)) {o0.v0[\"sign\"] = f1;print(x); }");
/*fuzzSeed-169986037*/count=1263; tryItOut("o2.a0.pop(i1, b2, x);");
/*fuzzSeed-169986037*/count=1264; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=1265; tryItOut("g0.a0.pop();");
/*fuzzSeed-169986037*/count=1266; tryItOut("\"use strict\"; h0.defineProperty = (function() { v2 = a0.reduce, reduceRight((function mcc_() { var zcaike = 0; return function() { ++zcaike; if (/*ICCD*/zcaike % 8 == 2) { dumpln('hit!'); ; } else { dumpln('miss!'); v2 = g1.g1.runOffThreadScript(); } };})(), i0); return t1; });");
/*fuzzSeed-169986037*/count=1267; tryItOut("a2.unshift(s1, m2, o0.v1);");
/*fuzzSeed-169986037*/count=1268; tryItOut("let x = (4277);h0.has = f0;");
/*fuzzSeed-169986037*/count=1269; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1270; tryItOut("/*RXUB*/var r = r2; var s = \"\\n_\"; print(s.replace(r, '\\u0341', \"g\")); Array.prototype.shift.apply(a1, [p0, this.m0, this.v0, g1.i0]);");
/*fuzzSeed-169986037*/count=1271; tryItOut("t2.valueOf = f0;");
/*fuzzSeed-169986037*/count=1272; tryItOut("\"use strict\"; testMathyFunction(mathy0, [2**53, 0x100000000, -0x080000001, 1, -Number.MAX_VALUE, -(2**53), 1/0, 2**53+2, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0, Math.PI, -0x100000000, Number.MIN_VALUE, 0x080000001, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0/0, -0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x07fffffff, -0x0ffffffff, 42, 0x100000001, -1/0, 0x080000000, -0x080000000, 0, 0x0ffffffff, -(2**53-2), -Number.MIN_VALUE, 2**53-2]); ");
/*fuzzSeed-169986037*/count=1273; tryItOut("");
/*fuzzSeed-169986037*/count=1274; tryItOut("\"use strict\"; o0 = Object.create(a0);");
/*fuzzSeed-169986037*/count=1275; tryItOut("mathy5 = (function(x, y) { return ( + ( + ( + Math.fround(( - (Math.imul(Math.fround(Math.max(( + y), Math.fround(( + mathy0(x, ( + Math.log10((Math.clz32((y >>> 0)) >>> 0)))))))), (0x07fffffff | 0)) | 0)))))); }); testMathyFunction(mathy5, [0x100000001, -0, 0/0, 2**53+2, -(2**53), 42, 1, -Number.MAX_VALUE, 0x080000001, -Number.MIN_VALUE, 2**53, -Number.MAX_SAFE_INTEGER, 0x100000000, -1/0, 0.000000000000001, 0x0ffffffff, -0x07fffffff, -0x100000001, Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, Number.MIN_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, Number.MAX_VALUE, 0x080000000, -0x100000000, 0, 0x07fffffff, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000001, 1/0, -0x080000000, -0x0ffffffff, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=1276; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (Math.max((Math.fround(mathy3((Math.atan2(((( + (x | 0)) | 0) < ( + ( ~ (x | 0)))), Math.fround(Math.max(( + ( ~ y)), Math.fround(( ~ ( ! x)))))) >>> 0), (y >>> 0))) | 0), ( ! ( ~ Math.atan2(mathy1(( + x), ( + x)), ((y ? (y | 0) : (x | 0)) | 0))))) ? Math.imul((Math.expm1(y) | 0), Math.fround(( + Math.fround(Math.log1p(((mathy4(y, 0) + Math.fround((Math.fround(x) ? -0x080000000 : Math.fround(( + Math.hypot(( + x), ( + y))))))) | 0)))))) : Math.min(Math.fround(Math.min(Math.fround(( + (((-0x0ffffffff >> y) | 0) >> ( + y)))), Math.fround(Math.sin((Math.exp((x | 0)) | 0))))), ( + ( ! mathy3(x, ( + Math.tan(( + Math.fround(Math.log(Math.fround(2**53+2))))))))))); }); testMathyFunction(mathy5, [2**53+2, 2**53, 0x100000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, 0x07fffffff, 0, -(2**53), Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, Math.PI, 1.7976931348623157e308, -0, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x080000001, 0x080000000, -0x080000001, 42, -(2**53+2), 1, -0x0ffffffff, -(2**53-2), 2**53-2, -1/0, -0x100000001, 0/0, -0x100000000, -0x080000000, 0.000000000000001, 1/0, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=1277; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -513.0;\n    var i3 = 0;\n    (Float64ArrayView[0]) = ((Float64ArrayView[((0xdfb80d80)) >> 3]));\n    i1 = (/*FFI*/ff(((-1.015625)), ((((0xf8df59c3)) >> (((i1) ? ((0xcabea356)) : (0x9f68c8fa))+((((0x81b48a7)+(0xffffffff)) | (0x19d93*(0x40bcd56f))))+((!(0x1cf849b7)) ? ((Uint8ArrayView[0])) : (i1))))), ((((3.094850098213451e+26)) % ((+abs(((+abs(((((d0)) * ((+(-0x290154d))))))))))))), ((-1.5111572745182865e+23)))|0);\n    i3 = (0x26f84f45);\n    i3 = (i1);\n    (Float64ArrayView[((0x9f93ebf3)+(0x2a9f3584)) >> 3]) = ((36028797018963970.0));\n    /*FFI*/ff((((((0x66eccea2)-(/*FFI*/ff()|0)) << ((((i1))>>>(-(-0x8000000))) % (((0x5d0d9b65)+(0xfe7abe8c))>>>((/*FFI*/ff()|0))))))), ((0x520c4e9e)), ((+(-1.0/0.0))), (((((((0x73af8a4c)) << ((0xff564031))))) | (-(!(0xfa2e3acc))))), ((((0xffffffff)) ^ ((0xe22481a)-(-0x8000000)))));\n    {\n      i1 = (new [,](new RegExp(\"(?=[^]+?(?!$))(?:\\\\b*)\", \"gyim\"), [,,]));\n    }\n    {\n      i1 = ((0x566d6b0));\n    }\n    d2 = (-0.25);\n    {\nf2.toString = (function() { v2 = evalcx(\"function f0(this.o0.f2)  { Object.seal(b1); } \", o1.g0); return s1; });    }\n    return +((+(-1.0/0.0)));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0x0ffffffff, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0.000000000000001, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, 42, -(2**53+2), -Number.MIN_VALUE, Math.PI, -(2**53), 1, 0, -1/0, -0, Number.MIN_VALUE, 1.7976931348623157e308, -0x100000000, 2**53+2, -0x080000000, -(2**53-2), 0x07fffffff, -0x080000001, 2**53-2, 2**53, -0x100000001, 0x080000000, 0x100000001, -Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000]); ");
/*fuzzSeed-169986037*/count=1278; tryItOut("\"use strict\"; \"use asm\"; mathy5 = (function(x, y) { \"use strict\"; return (((((( + ( + Math.hypot(( + x), ( + y)))) >>> 0) || (42 ? ((( + (y % y)) | 0) | 0) : ( + y))) - ( + Math.sqrt(Math.fround(y)))) | 0) >> (( + Math.tan(y)) ? (mathy3((Math.imul((( - (Math.PI | 0)) >>> 0), Math.sign(x)) - ( + Math.ceil(Math.fround(x)))), y) >>> 0) : Math.tan(Math.asinh(mathy3(y, x))))); }); testMathyFunction(mathy5, [0x0ffffffff, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -(2**53+2), 1.7976931348623157e308, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x100000000, -(2**53-2), 0/0, -Number.MIN_VALUE, 0x100000001, -0, 0x080000001, 2**53+2, -0x080000000, Number.MAX_SAFE_INTEGER, -0x100000001, -0x080000001, 1/0, -(2**53), -0x0ffffffff, 0.000000000000001, Math.PI, 0x100000000, 2**53-2, -Number.MAX_VALUE, 0x07fffffff, 0, -0x07fffffff, 0x080000000, 2**53, Number.MAX_VALUE, 42, -1/0]); ");
/*fuzzSeed-169986037*/count=1279; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.atan2(Math.fround(( + Math.acos(( + ( ~ ( + Math.trunc(y))))))), Math.fround(Math.pow(Math.max((( - (x >>> 0)) | 0), -(2**53-2)), (Math.imul(Math.max(Math.pow(x, (Math.fround(Math.hypot(0x100000000, y)) << x)), (x || ( - -0x0ffffffff))), (Math.ceil(((Math.ceil(x) >>> 0) >>> 0)) >>> 0)) >>> 0))))); }); ");
/*fuzzSeed-169986037*/count=1280; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.tan((( ! (Math.ceil((-Number.MAX_VALUE | 0)) | 0)) || (((((( ! (y | 0)) >>> 0) !== y) | 0) | 0) == (Math.imul(x, mathy3(y, (x | 0))) >>> 0)))); }); testMathyFunction(mathy4, [2**53-2, -Number.MAX_VALUE, 0x080000001, 42, 0x100000001, 0x0ffffffff, 0/0, Number.MAX_VALUE, 0, 1/0, Number.MAX_SAFE_INTEGER, 2**53+2, -0, -Number.MIN_VALUE, -0x07fffffff, -0x100000000, 0x100000000, -0x0ffffffff, 0.000000000000001, 0x080000000, 2**53, -Number.MAX_SAFE_INTEGER, -0x080000001, 1, -Number.MIN_SAFE_INTEGER, 0x07fffffff, Math.PI, -(2**53), 1.7976931348623157e308, -(2**53-2), -(2**53+2), -0x080000000, Number.MIN_VALUE, -0x100000001, -1/0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1281; tryItOut("\"use strict\"; t1[18];");
/*fuzzSeed-169986037*/count=1282; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.log(( - Math.imul((mathy0(Math.imul(Math.imul(Math.fround(( + (Math.PI >>> 0))), x), 1/0), mathy0(y, ( ~ ( + -(2**53+2))))) >>> 0), ( + Math.hypot(y, (Math.min(x, 2**53) >>> 0)))))); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 0x080000000, 1, -0, -0x080000001, Math.PI, -0x100000000, 0, 0x080000001, 2**53-2, -0x07fffffff, 2**53, Number.MAX_VALUE, 0x0ffffffff, 2**53+2, 1.7976931348623157e308, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_SAFE_INTEGER, 42, 0.000000000000001, Number.MIN_VALUE, -(2**53-2), -Number.MIN_VALUE, 1/0, -0x100000001, 0x100000001, -(2**53), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -1/0, 0x07fffffff, 0x100000000, 0/0]); ");
/*fuzzSeed-169986037*/count=1283; tryItOut("/*infloop*/while(x){s1 += 'x';for(let x = Math in  \"\" ) print(\"\\uB257\"); }");
/*fuzzSeed-169986037*/count=1284; tryItOut("mathy2 = (function(x, y) { return Math.fround(( ! (Math.fround((( + mathy0((2**53-2 | 0), ( + Math.fround(Math.atanh(Math.fround(( ~ Math.fround(( ~ Math.fround(x)))))))))) < ( + Math.fround((Math.fround((((y >>> 0) << ((x ? (Math.atan2((x | 0), x) | 0) : Math.log1p(( + y))) >>> 0)) >>> 0)) , Math.fround(Math.ceil(Math.pow(x, (mathy1(( + y), y) | 0))))))))) >>> 0))); }); ");
/*fuzzSeed-169986037*/count=1285; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-169986037*/count=1286; tryItOut("mathy4 = (function(x, y) { return Math.cosh(( - Math.pow((( ! (y >>> 0)) >>> 0), (Math.round(Number.MAX_SAFE_INTEGER) >>> 0)))); }); testMathyFunction(mathy4, [0x100000001, -Number.MIN_VALUE, Math.PI, -0x100000000, -0, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -1/0, -0x100000001, -(2**53+2), Number.MAX_VALUE, -Number.MAX_VALUE, 1, 0x100000000, 0/0, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000000, -Number.MIN_SAFE_INTEGER, 2**53, 42, 2**53+2, 1/0, -0x080000000, -0x0ffffffff, 2**53-2, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -(2**53), 0, 0x080000001, -(2**53-2), 0x0ffffffff, 0.000000000000001]); ");
/*fuzzSeed-169986037*/count=1287; tryItOut("mathy1 = (function(x, y) { return ( ~ (((Math.pow(((( + ( - y)) ? ( + (-0x080000000 ? y : y)) : ( + mathy0(( + Math.fround(Math.fround(( ~ Math.fround(-0x080000000))))), ( + y)))) >>> 0), ((Math.fround(y) >> ( + Math.fround(Math.acosh((y | 0))))) | 0)) >>> 0) % ( + Math.max((x | 0), Math.atan2(Math.fround(( - Math.fround(y))), x)))) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=1288; tryItOut("\"use strict\"; g2.t1.set(t0, 6);");
/*fuzzSeed-169986037*/count=1289; tryItOut("\"use strict\"; /*oLoop*/for (var bogcmh = 0; bogcmh < 4; ++bogcmh) { function f1(a0)  { yield  ''  }  } ");
/*fuzzSeed-169986037*/count=1290; tryItOut("\"use strict\"; Array.prototype.pop.call(o1.g2.a2, o0, m0);\nm1.has(f2);\n");
/*fuzzSeed-169986037*/count=1291; tryItOut("i0.send(s1);");
/*fuzzSeed-169986037*/count=1292; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (((Math.asinh(Math.acosh(((((Math.fround(Math.atan2(Math.fround(-(2**53)), x)) >>> 0) & ((-0x07fffffff !== y) >>> 0)) >>> 0) >>> 0))) >>> 0) > Math.cosh((( ~ (x ? x : (y >>> 0))) | 0))) >>> 0); }); testMathyFunction(mathy1, [Number.MAX_SAFE_INTEGER, -(2**53), -1/0, 0x080000000, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x080000000, -0x080000001, 0.000000000000001, 2**53+2, 0/0, 42, 2**53, Number.MIN_VALUE, -0x0ffffffff, Math.PI, -Number.MIN_VALUE, 0x100000001, Number.MIN_SAFE_INTEGER, 0, 1/0, -(2**53+2), -Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, -0, 0x0ffffffff, -(2**53-2), 1, -0x100000000, 0x080000001, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_VALUE, -0x100000001, 0x100000000]); ");
/*fuzzSeed-169986037*/count=1293; tryItOut("/*RXUB*/var r = /(.)\\b(?!^{1,1})\\2?{1025}/gim; var s = \"\\n\"; print(r.test(s)); var rdgemf = new ArrayBuffer(4); var rdgemf_0 = new Int16Array(rdgemf); rdgemf_0[0] = 13; var rdgemf_1 = new Uint16Array(rdgemf); print(rdgemf_1[0]); rdgemf_1[0] = 0; for(d =  /x/  in \"\\u233A\") print(rdgemf_0[3]);print( /x/g );(\"\\uD855\");s0.__proto__ = p2;");
/*fuzzSeed-169986037*/count=1294; tryItOut("mathy1 = (function(x, y) { return ( + (( + Math.fround(mathy0(( + ( ~ Math.fround((y && Math.imul(Math.atan2(y, x), -(2**53-2)))))), Math.fround(((w)()))))) / ( + Math.trunc(Math.trunc(Math.imul(Math.pow(x, Math.atan2(-0x080000000, y)), mathy0(( ! y), y))))))); }); ");
/*fuzzSeed-169986037*/count=1295; tryItOut("/*RXUB*/var r = /(?!(?:(?:\\w))*)|\\b*\u00b3|(?=\\2)/gim; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1296; tryItOut("g1.toSource = (function(j) { f0(j); });");
/*fuzzSeed-169986037*/count=1297; tryItOut("testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 0x100000001, 0x0ffffffff, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x100000000, -0x07fffffff, Number.MIN_VALUE, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -(2**53-2), 2**53+2, 42, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MIN_VALUE, 0x100000000, -1/0, 1, -0x080000000, -Number.MAX_VALUE, Math.PI, -(2**53+2), 2**53, -(2**53), 0x07fffffff, 0/0, -0x080000001, 0, -0x0ffffffff, 0x080000001, 0.000000000000001, -0x100000001, -0]); ");
/*fuzzSeed-169986037*/count=1298; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return ((((Math.fround(Math.fround(Math.hypot((Math.fround(Math.atan2(-0x100000001, Math.fround((Math.max(( + Math.acos(( + 0x07fffffff))), Math.fround(y)) | 0)))) | 0), (Math.cos((-0x080000001 , x)) | 0)))) < (Math.sin((x | 0)) | 0)) >= (Math.imul(x, ( + ( ~ ( + mathy1(y, x))))) | 0)) | 0) | (mathy0(( + Math.ceil(( + Math.max(x, y)))), (mathy0((((Math.fround((Math.fround(-0x080000000) & Math.fround(Math.exp(0x100000001)))) >>> 0) ? (( + Math.max(x, Math.sinh(x))) >>> 0) : (( + Math.abs(42)) >>> 0)) | 0), Math.atan2((((y , Math.imul(0x080000000, (Math.fround(Math.cos(y)) | 0))) | 0) >>> 0), Math.expm1(( ~ 2**53)))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [({toString:function(){return '0';}}), (function(){return 0;}), '\\0', /0/, '/0/', '', objectEmulatingUndefined(), (new Number(0)), [], (new String('')), ({valueOf:function(){return '0';}}), 1, 0.1, ({valueOf:function(){return 0;}}), true, false, (new Boolean(false)), null, [0], -0, (new Number(-0)), '0', (new Boolean(true)), 0, NaN, undefined]); ");
/*fuzzSeed-169986037*/count=1299; tryItOut("");
/*fuzzSeed-169986037*/count=1300; tryItOut("o1.m0 = new Map(m1);");
/*fuzzSeed-169986037*/count=1301; tryItOut("Array.prototype.forEach.apply(a0, [e1, g0, b1]);");
/*fuzzSeed-169986037*/count=1302; tryItOut("\"use strict\"; uzykpj, eval = ([{}, {x: {}}]) = (this.__defineSetter__(\"NaN\", (b) =>  { ; } )), window;/*RXUB*/var r = new RegExp(\"(?:[^])+?\", \"gm\"); var s = \"\"; print(r.test(s)); ");
/*fuzzSeed-169986037*/count=1303; tryItOut("g1.m0.delete(s1);");
/*fuzzSeed-169986037*/count=1304; tryItOut("\"use strict\"; let (d) x;");
/*fuzzSeed-169986037*/count=1305; tryItOut("\"use strict\"; a2[8];");
/*fuzzSeed-169986037*/count=1306; tryItOut("\"use strict\"; a2 = Array.prototype.map.call(this.a1, g2.f0, t2);");
/*fuzzSeed-169986037*/count=1307; tryItOut("/*vLoop*/for (let uijcxi = 0; uijcxi < 15; ++uijcxi) { w = uijcxi; /*RXUB*/var r = /(?:\\b)/gm; var s = \"a1 \"; print(uneval(r.exec(s))); print(r.lastIndex);  } ");
/*fuzzSeed-169986037*/count=1308; tryItOut("\"use strict\"; if(true) {/*infloop*/do v1 = g2.runOffThreadScript(); while(window = Proxy.create((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function(receiver, name) { return x[name]; }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return []; }, }; })(true), x = Proxy.createFunction(({/*TOODEEP*/})(x), () =>  { return 1 } , (1 for (x in [])))));m2.toString = (function(j) { if (j) { try { for (var v of p2) { try { i2.next(); } catch(e0) { } try { t2 + ''; } catch(e1) { } m1.get(i1); } } catch(e0) { } Array.prototype.unshift.call(a1, (new RegExp(\"(?=(?!(?!\\\\u135C{4,4}))|[^])\", \"gym\") === [[1]].throw(\"\\uE0E1\" = Proxy.create(({/*TOODEEP*/})(new RegExp(\"(?=[\\\\xBE-\\\\u8F47\\\\D\\\\D]?)+?\", \"gym\")), this))), v2, m0); } else { try { Array.prototype.sort.call(g2.a0, (function() { try { a0 = arguments.callee.caller.arguments; } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(e1, a0); } catch(e1) { } o2.o0.m2.has(g2); return this.v1; })); } catch(e0) { } this.a1.forEach((function() { try { a2.unshift(/.*?/, g0.a0, e0); } catch(e0) { } try { /*MXX3*/g0.Date.prototype.toDateString = g2.Date.prototype.toDateString; } catch(e1) { } try { Object.prototype.watch.call(t2, \"getFloat64\", (function() { for (var j=0;j<87;++j) { f2(j%3==1); } })); } catch(e2) { } h0 = {}; return e0; })); } }); } else  if (void \"\\u8ED3\") let a;print(x); else v2 = (m2 instanceof f0);\nArray.prototype.splice.apply(this.a1, [NaN, 16]);\n\na1[({valueOf: function() { print(new RegExp(\".\", \"gym\"));return 5; }})] = x\nprint(eval(\"/* no regression tests found */\"));\n");
/*fuzzSeed-169986037*/count=1309; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"/* no regression tests found */\");");
/*fuzzSeed-169986037*/count=1310; tryItOut("M:if((x % 4 == 2)) {( /x/ ); } else  if (this.eval(\"o2.v1 = 4.2;\")) continue ; else e1.add(b2);");
/*fuzzSeed-169986037*/count=1311; tryItOut("\"use strict\"; o0 = this.i1.__proto__;");
/*fuzzSeed-169986037*/count=1312; tryItOut("mathy5 = (function(x, y) { return (( + (Math.abs((Math.imul(( ~ Math.fround(Math.fround(( ! 1)))), Math.fround((Number.MAX_SAFE_INTEGER | y))) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, [2**53+2, -1/0, -Number.MAX_VALUE, -(2**53), -0x100000000, 0x100000001, 2**53, -0x080000001, 42, -(2**53+2), 0x080000001, 0x080000000, 2**53-2, 1.7976931348623157e308, -0x07fffffff, -(2**53-2), 0x07fffffff, 1/0, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0, -0x100000001, 0/0, 0, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, 1, Number.MIN_VALUE, 0x100000000, -0x080000000, 0.000000000000001, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-169986037*/count=1313; tryItOut("with(x)v1 = a0.length;Array.prototype.push.call(a1, m1);");
/*fuzzSeed-169986037*/count=1314; tryItOut("\"use strict\"; o1.v1 = Array.prototype.reduce, reduceRight.call(a0);");
/*fuzzSeed-169986037*/count=1315; tryItOut("const v0 = evaluate(\"g2.offThreadCompileScript(\\\"x\\\", ({ global: o0.o2.g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (void options('strict_mode')), noScriptRval: false, sourceIsLazy: (x % 5 == 0), catchTermination: (x % 3 == 1) }));\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: ( '' ), element: o2 }));");
/*fuzzSeed-169986037*/count=1316; tryItOut("switch() { case 6: v2 = Object.prototype.isPrototypeOf.call(i0, g1.p2);case ((void options('strict_mode'))) %= (4277): case 7: case (yield (y) = this): break;  }");
/*fuzzSeed-169986037*/count=1317; tryItOut("m2.delete(b2);");
/*fuzzSeed-169986037*/count=1318; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1319; tryItOut("mathy3 = (function(x, y) { return ( - ( + Math.tan(mathy0(x, Math.fround((-(2**53+2) != Math.fround((Math.max((y | 0), (-0x080000001 | 0)) | 0)))))))); }); testMathyFunction(mathy3, [({valueOf:function(){return 0;}}), (new Boolean(false)), null, (new String('')), (new Boolean(true)), true, (new Number(-0)), '\\0', (new Number(0)), '/0/', [], 1, (function(){return 0;}), /0/, objectEmulatingUndefined(), ({toString:function(){return '0';}}), NaN, '', 0, [0], false, -0, '0', undefined, 0.1, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-169986037*/count=1320; tryItOut("\"use strict\"; ({});");
/*fuzzSeed-169986037*/count=1321; tryItOut("\"use strict\"; var isdnyi = new ArrayBuffer(2); var isdnyi_0 = new Uint8ClampedArray(isdnyi); var isdnyi_1 = new Uint8ClampedArray(isdnyi); isdnyi_1[0] = 9; var isdnyi_2 = new Int8Array(isdnyi); isdnyi_2[0] = -18; var isdnyi_3 = new Uint16Array(isdnyi); isdnyi_3[0] = -15; var isdnyi_4 = new Uint8ClampedArray(isdnyi); print(isdnyi_4[0]); for(let z in a%= \"\" ) m2 = t2[19];f1 + '';g1.g2 + o2;");
/*fuzzSeed-169986037*/count=1322; tryItOut("\"use strict\"; this.g1.toSource = (function() { try { o0.m1.has(v2); } catch(e0) { } o2.v2 = Object.prototype.isPrototypeOf.call(s1, g1); return o1.g0.g2.e2; });");
/*fuzzSeed-169986037*/count=1323; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return (((/*FFI*/ff(((0x42dc446f)), (((((d0) + (+/*FFI*/ff(((Infinity)), ((1125899906842624.0)))))) % ((+/*FFI*/ff(((~((i1)*-0xbe048))), ((+/*FFI*/ff(((-((1.015625)))), ((513.0)), ((2305843009213694000.0)), ((-1.2089258196146292e+24))))), (x), ((-7.555786372591432e+22)), ((-2097151.0)), ((-5.0)), ((-4194305.0)), ((-17179869184.0)), ((-67108865.0)), ((0.00390625)), ((295147905179352830000.0)), ((-2.3611832414348226e+21)), ((-33554431.0)), ((4.722366482869645e+21)), ((1025.0))))))), (((0xffffffff) / (0x535eb633))), (((((x & d))-((0x24fe82e7) == (-0x35ef40a))) >> ((0xffffffff) / (0x5dd876e)))), ((imul((0xd4ff7596), (i1))|0)))|0)+(i1)-(i1)))|0;\n  }\n  return f; })(this, {ff: x}, new ArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[false,  /x/ , false,  \"use strict\" ,  \"use strict\" ,  /x/ , -Infinity, false,  /x/ ,  /x/ ,  \"use strict\" , false,  \"use strict\" ,  /x/ ,  \"use strict\" ,  \"use strict\" , false,  /x/ , -Infinity, false,  /x/ ,  /x/ ,  /x/ ,  /x/ , false, -Infinity, false,  \"use strict\" ,  \"use strict\" , -Infinity, false, -Infinity, false,  /x/ , -Infinity, false, false, false,  \"use strict\" ,  /x/ ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" , -Infinity, false, -Infinity,  \"use strict\" , -Infinity, -Infinity, false,  /x/ ,  /x/ ,  /x/ ,  \"use strict\" ,  /x/ ,  /x/ ,  /x/ , -Infinity,  \"use strict\" ,  /x/ , -Infinity,  \"use strict\" , -Infinity, false, -Infinity,  /x/ , false,  \"use strict\" ,  /x/ , false,  /x/ ,  \"use strict\" ,  /x/ ,  /x/ ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/ , false, false,  \"use strict\" ,  /x/ , false, -Infinity,  /x/ ,  \"use strict\" , false,  /x/ , -Infinity,  /x/ , -Infinity, false, false, -Infinity, false, false,  \"use strict\" , -Infinity,  /x/ ,  \"use strict\" , false, false,  /x/ , false,  /x/ ,  /x/ ,  \"use strict\" , false, false,  \"use strict\" , false,  \"use strict\" ,  \"use strict\" , -Infinity,  /x/ , -Infinity,  /x/ , false,  \"use strict\" ,  \"use strict\" , false,  \"use strict\" ,  \"use strict\" , -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity,  /x/ , false,  \"use strict\" , -Infinity, -Infinity,  /x/ ]); ");
/*fuzzSeed-169986037*/count=1324; tryItOut("\"use strict\"; v0 = Object.prototype.isPrototypeOf.call(h0, o0);");
/*fuzzSeed-169986037*/count=1325; tryItOut("\"use strict\"; if((x % 5 == 3)) {window;v0 = evalcx(\"e1 = g2.objectEmulatingUndefined();\", g0); } else  if ((void options('strict_mode'))) e2.delete(p1);");
/*fuzzSeed-169986037*/count=1326; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0(( + (Math.atan2((Math.fround(Math.min(Math.fround(Number.MAX_SAFE_INTEGER), (x | 0))) >>> 0), Math.pow(y, x)) ? ((-0x080000000 >>> Math.log1p(x)) | 0) : ( + (y >>> 0)))), ( + Math.hypot(w, (Math.max(Math.fround(Math.min(Math.fround(x), ( + Math.fround(Math.atanh(Math.fround(y)))))), y) >>> 0)))) >> ( + mathy0(( ~ (Math.log2((y | 0)) | 0)), ( + 2**53+2)))); }); testMathyFunction(mathy1, [-Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, Number.MIN_VALUE, -(2**53), 0x080000000, -Number.MAX_SAFE_INTEGER, 0x080000001, -Number.MIN_VALUE, 1, 0x100000000, -1/0, Math.PI, 2**53+2, 42, 1/0, 0x100000001, -0x100000000, -0x07fffffff, 0.000000000000001, -0x080000001, -0x080000000, -0, -(2**53+2), 2**53-2, -(2**53-2), 1.7976931348623157e308, 0, Number.MAX_SAFE_INTEGER, -0x100000001, 0/0]); ");
/*fuzzSeed-169986037*/count=1327; tryItOut("e2.add(m1);m1.set(a1, a1);\np0 + b2;\n");
/*fuzzSeed-169986037*/count=1328; tryItOut("\"use strict\"; v2 = Array.prototype.reduce, reduceRight.call(a1, (function() { try { Array.prototype.sort.apply(a1, [(function mcc_() { var slflum = 0; return function() { ++slflum; if (/*ICCD*/slflum % 5 == 2) { dumpln('hit!'); try { v1 = (a1 instanceof h0); } catch(e0) { } try { o0.m2 = new Map; } catch(e1) { } /*MXX2*/this.g2.Number.MAX_SAFE_INTEGER = b2; } else { dumpln('miss!'); try { /*MXX1*/o0 = g0.ReferenceError.name; } catch(e0) { } Array.prototype.reverse.call(a2, i1, b1); } };})(), g2]); } catch(e0) { } try { /*MXX2*/this.g0.g2.Symbol.prototype = m1; } catch(e1) { } /*RXUB*/var r = r0; var s = \"\\uda42\\n\\uda42\\n\\n\"; print(s.match(r));  return this.m0; }));");
/*fuzzSeed-169986037*/count=1329; tryItOut("testMathyFunction(mathy3, [1, -0x100000000, -0x080000000, 0x07fffffff, Number.MAX_VALUE, 0x080000000, 2**53-2, -Number.MIN_SAFE_INTEGER, -(2**53), -(2**53+2), -1/0, Number.MAX_SAFE_INTEGER, -0x080000001, 0.000000000000001, Number.MIN_VALUE, -0x0ffffffff, -(2**53-2), 0x100000000, -0, -Number.MAX_SAFE_INTEGER, 0, 42, -0x07fffffff, 2**53+2, -Number.MAX_VALUE, -0x100000001, 0x080000001, -Number.MIN_VALUE, Math.PI, 1.7976931348623157e308, 1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000001, 0/0, 2**53]); ");
/*fuzzSeed-169986037*/count=1330; tryItOut("testMathyFunction(mathy3, [2**53, 1, Number.MAX_SAFE_INTEGER, 0/0, -0x080000000, -0x100000001, -0x080000001, Number.MIN_VALUE, -Number.MIN_VALUE, 0x100000000, -0x07fffffff, -0x100000000, -(2**53+2), -0, 0x080000000, -1/0, -(2**53-2), 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53), 2**53-2, Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0, 1/0, Number.MAX_VALUE, 2**53+2, Math.PI, 0x080000001, -Number.MAX_VALUE, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 42, 1.7976931348623157e308]); ");
/*fuzzSeed-169986037*/count=1331; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (Math.hypot((Math.atan2(Math.min(x, x), (Math.fround(Math.atan2(-0x100000001, Math.atan2(Math.fround(x), Math.fround(x)))) , Math.clz32(x))) | 0), (Math.fround(Math.clz32(Math.fround(Math.fround(Math.exp(Math.fround(-Number.MAX_SAFE_INTEGER)))))) | 0)) << (mathy0((Math.imul(( + -Number.MAX_SAFE_INTEGER), ( + ( - ( ~ mathy0((y ** x), (Math.imul((-(2**53+2) >>> 0), (x >>> 0)) >>> 0)))))) >>> 0), (( ~ (Math.tanh(x) >>> 0)) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=1332; tryItOut("\"use strict\"; mathy2 = (function(x, y) { return mathy0((((( ! ((Math.atanh((x >>> 0)) >>> 0) >>> 0)) | 0) ? ( + Math.atan(( + ((Math.fround(x) ? (1/0 >>> 0) : (mathy0(((( ! x) >>> 0) | 0), (x | 0)) | 0)) | 0)))) : Math.acos((((x ? y : 1) >>> 0) ? 0/0 : x))) | 0), (mathy0(((Math.fround(Math.acos(Math.fround(mathy1(( + Math.min(y, x)), ( + x))))) << ( ! (Math.log10(Math.fround(x)) >>> 0))) >>> 0), (Math.atan2(((( + -Number.MIN_SAFE_INTEGER) >= (x >= 2**53-2)) >>> 0), (y >>> 0)) >>> 0)) | 0)); }); testMathyFunction(mathy2, [1, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, 0/0, 1/0, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, 0x0ffffffff, Math.PI, 0, -0x100000000, 2**53, -0x080000000, -Number.MIN_VALUE, -0x080000001, Number.MIN_VALUE, -0x07fffffff, 2**53-2, 0.000000000000001, -(2**53), 2**53+2, -0x100000001, 42, -(2**53+2), -(2**53-2), 0x100000001, -0, -0x0ffffffff, 0x07fffffff, -Number.MAX_VALUE, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-169986037*/count=1333; tryItOut("\"use strict\"; o2.o0.b0 = x;o0.m1.has(o1);");
/*fuzzSeed-169986037*/count=1334; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=1335; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.sin((mathy0(( ! (x || ((Number.MIN_SAFE_INTEGER >>> 0) ? Math.fround(Math.acosh(Math.atan2(y, x))) : ( + (Math.acos(y) | 0))))), Math.acosh(x)) | 0)); }); testMathyFunction(mathy5, [-0x100000001, Number.MIN_SAFE_INTEGER, 0/0, -1/0, Number.MIN_VALUE, -(2**53-2), 2**53, -0, 0x100000001, 1.7976931348623157e308, -(2**53+2), -0x0ffffffff, 0, -Number.MAX_VALUE, -0x07fffffff, -(2**53), -0x080000001, 0x080000001, 0x080000000, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1, 2**53+2, 1/0, -0x080000000, 2**53-2, 0x07fffffff, Number.MAX_VALUE, -0x100000000, 0x100000000, Math.PI, 0.000000000000001, 0x0ffffffff, 42, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1336; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    switch ((((0xfe499c46)-(0xfb52ea85)+(0x139a1e8b)) & (((0x5d01df12) > (0x19d810f2))+((0x68f24f67) < (-0x8000000))))) {\n    }\n    return +((Float32ArrayView[4096]));\n  }\n  return f; })(this, {ff: runOffThreadScript}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [-Number.MAX_VALUE, Number.MAX_VALUE, -1/0, 0/0, -0x080000000, 0x080000000, 1, 1/0, 1.7976931348623157e308, -0x100000000, Math.PI, -0, -Number.MIN_SAFE_INTEGER, -(2**53), -0x100000001, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x07fffffff, 2**53-2, -(2**53-2), 0x100000001, 42, -Number.MIN_VALUE, 0, 0x0ffffffff, -0x07fffffff, -0x080000001, 2**53, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53+2, Number.MIN_VALUE, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=1337; tryItOut("\"use strict\"; v1 = h2[\"-13\"];");
/*fuzzSeed-169986037*/count=1338; tryItOut("mathy1 = (function(x, y) { return Math.fround((Math.fround(( + Math.max(((Math.min(Math.fround(( ~ Math.fround(y))), Math.fround(( ~ Math.fround(Math.fround(Math.clz32(Math.fround(y))))))) ^ Math.fround(Math.expm1(( + ((-Number.MAX_SAFE_INTEGER ? 0x07fffffff : -0x100000000) ? (Math.atan2((x >>> 0), -(2**53-2)) >>> 0) : (((y >>> 0) || x) >>> 0)))))) | 0), (( + Math.fround((Math.atan(0) === x))) | 0)))) ? Math.fround(( - ( + Math.atanh(( + Number.MIN_SAFE_INTEGER))))) : Math.fround(mathy0((Math.sign(0x080000000) | 0), ((Math.log((( - Math.max(x, 0x100000000)) >>> 0)) >>> 0) ^ ( + Math.min((Math.max(x, 0x100000000) >>> 0), 1/0))))))); }); testMathyFunction(mathy1, [0x0ffffffff, Number.MAX_SAFE_INTEGER, -0, 2**53+2, 0/0, 0x07fffffff, 0x100000001, -(2**53-2), 0.000000000000001, -0x080000001, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53+2), Number.MIN_VALUE, -0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, Math.PI, -Number.MIN_SAFE_INTEGER, 1, 42, -Number.MIN_VALUE, 2**53-2, 0x080000000, -0x100000000, -(2**53), 2**53, 0x100000000, 1/0, Number.MAX_VALUE, -0x07fffffff, -Number.MAX_VALUE, -0x0ffffffff, 1.7976931348623157e308, -1/0, 0]); ");
/*fuzzSeed-169986037*/count=1339; tryItOut("testMathyFunction(mathy3, /*MARR*/[-0x100000001, function(){}, false,  /x/ , -0x100000001, function(){}, Number.MAX_SAFE_INTEGER,  /x/ , false,  /x/ ,  /x/ , Number.MAX_SAFE_INTEGER,  /x/ , Number.MAX_SAFE_INTEGER, -0x100000001, function(){}]); ");
/*fuzzSeed-169986037*/count=1340; tryItOut("mathy0 = (function(x, y) { return ( - Math.sqrt(((Math.atan2(( + (Number.MIN_VALUE >= y)), ( + x)) >>> 0) | 0))); }); testMathyFunction(mathy0, [-0x100000000, -(2**53), 1, 0, 0/0, -1/0, 0x080000000, -(2**53-2), 1/0, 42, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -0x080000000, Number.MIN_VALUE, -0x0ffffffff, -0, 0x080000001, 0x100000000, -Number.MAX_VALUE, 0x100000001, -0x07fffffff, -(2**53+2), 0x0ffffffff, -0x100000001, 2**53-2, Number.MIN_SAFE_INTEGER, 0.000000000000001, 1.7976931348623157e308, Math.PI, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 2**53+2, 2**53, Number.MAX_VALUE, 0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1341; tryItOut("Array.prototype.push.apply(g1.a1, [a2, m1, b1]);");
/*fuzzSeed-169986037*/count=1342; tryItOut("mathy3 = (function(x, y) { return Math.hypot(Math.cos(Math.imul(( ! Math.clz32(y)), Math.fround(( + Math.hypot(Math.fround(( ~ y)), (Math.expm1(y) % ( + x))))))), ( + Math.min(( + Math.asin(( ~ ( + 0x100000000)))), ( + (y ** Math.fround((Math.fround(( ! Math.fround(x))) , mathy2(y, ( - -0x100000000))))))))); }); testMathyFunction(mathy3, [42, -0, 0/0, -(2**53-2), 2**53+2, 2**53-2, -Number.MIN_SAFE_INTEGER, -1/0, 1.7976931348623157e308, -0x07fffffff, 1/0, 0x100000001, -0x080000000, 1, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -(2**53), Math.PI, -0x100000000, -Number.MAX_VALUE, -(2**53+2), -0x080000001, -0x100000001, 0x080000001, -0x0ffffffff, 2**53, 0.000000000000001, -Number.MIN_VALUE, Number.MAX_VALUE, 0x07fffffff, 0x100000000, 0x080000000, 0x0ffffffff, 0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1343; tryItOut("var ypvqwp;( '' );");
/*fuzzSeed-169986037*/count=1344; tryItOut("a1.reverse();");
/*fuzzSeed-169986037*/count=1345; tryItOut("mathy4 = (function(x, y) { return ( + Math.imul((Math.pow((( + Math.trunc(Math.fround(Math.fround(Math.log10(Math.fround((Math.imul((x >>> 0), (y >>> 0)) >>> 0))))))) | 0), (Math.tanh((-1/0 | 0)) | 0)) | 0), ( + Math.atanh(((((Math.fround(Math.hypot(y, (( + Math.fround(-0)) >>> 0))) ? ((( + Math.pow((((x ** -0x080000000) >>> 0) >>> 0), x)) < Math.min((y >>> 0), (((x >>> 0) ? Math.fround(y) : (y >>> 0)) >>> 0))) >>> 0) : (((Math.fround(( ! Math.fround(y))) >>> 0) >>> (x >>> 0)) >>> 0)) | 0) >= Math.fround(( ! (x | 0)))) | 0))))); }); testMathyFunction(mathy4, [0x100000000, 0, -0x100000000, 1, 2**53-2, -(2**53+2), -Number.MIN_SAFE_INTEGER, Math.PI, 0x080000000, -Number.MAX_VALUE, 2**53, 0x100000001, 0.000000000000001, 42, 0x07fffffff, -0, -0x0ffffffff, -0x07fffffff, -0x080000000, -0x100000001, -(2**53), -(2**53-2), 2**53+2, 0x080000001, -Number.MIN_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, Number.MAX_VALUE, 1.7976931348623157e308, 1/0, 0/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1346; tryItOut("\"use strict\"; /*oLoop*/for (var yijpgl = 0; yijpgl < 54; ++yijpgl) { new Function } \ne1 = new Set;\n");
/*fuzzSeed-169986037*/count=1347; tryItOut("m0.set(a, p1);{}");
/*fuzzSeed-169986037*/count=1348; tryItOut("mathy5 = (function(x, y) { return ((Math.cbrt(Math.min(x, mathy4((y >>> 0), ( + Math.pow(y, ( + (((y >>> 0) || (x >>> 0)) >>> 0))))))) | 0) - ((( + (( + (Math.atan2((Math.fround(Math.imul(Math.fround(( - y)), Math.fround(x))) | 0), (( + x) | 0)) | 0)) !== ( + Math.fround(Math.atan((( + ( + Math.hypot(( + y), x))) | 0)))))) - Math.max((Math.min(mathy4(mathy3(x, 2**53-2), 0x080000000), x) >>> 0), x)) | 0)); }); ");
/*fuzzSeed-169986037*/count=1349; tryItOut("mathy2 = (function(x, y) { return Math.pow(Math.pow(Math.max(Math.max((Math.hypot((Math.acosh(y) >>> 0), (( ! ( + x)) >>> 0)) >>> 0), ( + ( - ( + y)))), Math.fround(Math.tanh(Math.fround(-(2**53-2))))), Math.hypot(((Math.fround(mathy0((y | 0), y)) + (x >>> 0)) >>> 0), x)), (Math.pow(((( + Math.asinh(Math.fround(Math.max(( + Math.atan2(( + x), ( + y))), y)))) >= (mathy1(y, ((y | 0) ? (( + y) | 0) : (x ? (x | 0) : y))) >>> 0)) >>> 0), (((( ~ (case 0: yield  /x/g  += e; >>> 0)) >>> 0) - (((y ? (Math.max((Math.acosh((y >>> 0)) >>> 0), Math.fround((Math.fround(y) < Math.fround(y)))) | 0) : 0) >>> 0) || ( + (x >>> y)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-169986037*/count=1350; tryItOut("t1.set(a2, 12);");
/*fuzzSeed-169986037*/count=1351; tryItOut("t2.set(t1, 3);");
/*fuzzSeed-169986037*/count=1352; tryItOut("\"use strict\"; /*RXUB*/var r = g1.r1; var s = \"\"; print(s.match(r)); print(r.lastIndex); \ne0.has(g2);\n\nv2 = r2.sticky;\n");
/*fuzzSeed-169986037*/count=1353; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.pow(Math.fround(Math.fround(mathy2((((( + x) && ( + x)) >>> 0) | Math.asinh(( - ( + -Number.MIN_VALUE)))), (Math.atan2((x >>> 0), (Math.fround((y ? Math.fround(y) : x)) >>> 0)) ? -(2**53-2) : (y & mathy0(((Math.pow(y, Number.MAX_VALUE) < ( ! x)) | 0), (x | 0))))))), Math.fround(( + Math.hypot((( + (Math.min((y | 0), ((((y >>> 0) + ((Number.MIN_VALUE >> -0x080000001) >>> 0)) >>> 0) | 0)) | 0)) | 0), ( + ( + (x >>> 0)))))))); }); testMathyFunction(mathy3, [-0, -(2**53+2), -1/0, 0x0ffffffff, -(2**53-2), -Number.MAX_VALUE, Number.MAX_VALUE, -0x07fffffff, 0/0, 1, -0x080000001, -0x100000001, 0x07fffffff, 2**53-2, 2**53+2, 2**53, -0x100000000, -Number.MAX_SAFE_INTEGER, Math.PI, 0x080000001, 0.000000000000001, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0, 1/0, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -(2**53), 42, -Number.MIN_VALUE, -0x080000000, 0x100000001]); ");
/*fuzzSeed-169986037*/count=1354; tryItOut("t2 = new Uint8ClampedArray(this.t2);function eval() { return x = /(?!(?=\\w\\1))\\B{4}+?{3,7}/g } h0.has = f2;");
/*fuzzSeed-169986037*/count=1355; tryItOut("/*RXUB*/var r = eval(\"[[]]\"); var s = \"\\n\\n\\n\\n\\n\\n\"; print(s.replace(r, 'x')); ");
/*fuzzSeed-169986037*/count=1356; tryItOut("h2 = {};");
/*fuzzSeed-169986037*/count=1357; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return ( ! Math.imul((( ! ((((( ~ x) >>> 0) | 0) || (y | 0)) | 0)) | 0), ( + Math.hypot(mathy1((x | 0), Math.fround(((( + (0x0ffffffff % ( + x))) | 0) ? Math.fround(y) : Math.fround(Math.max(x, y))))), -(2**53-2))))); }); testMathyFunction(mathy3, [42, 2**53-2, -0x080000001, -0, -Number.MIN_SAFE_INTEGER, -(2**53), 1.7976931348623157e308, -(2**53+2), 0x080000000, -Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, 2**53, 0x100000000, 0/0, -0x0ffffffff, 0x07fffffff, 1, 0x100000001, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -(2**53-2), -0x100000000, -0x080000000, -1/0, 0x0ffffffff, -0x100000001, Math.PI, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0.000000000000001, 1/0, 0x080000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0]); ");
/*fuzzSeed-169986037*/count=1358; tryItOut("\"use strict\"; testMathyFunction(mathy4, [0x0ffffffff, 1.7976931348623157e308, -0, Math.PI, -(2**53+2), -Number.MAX_VALUE, Number.MAX_VALUE, Number.MIN_VALUE, -0x0ffffffff, 0x080000001, 0x07fffffff, -(2**53-2), 1/0, 2**53+2, 42, -1/0, -0x100000000, -Number.MIN_VALUE, -(2**53), -0x080000001, 0x080000000, 2**53, 1, 0, 2**53-2, Number.MAX_SAFE_INTEGER, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x07fffffff, 0/0, 0x100000000, -0x100000001, -Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000000]); ");
/*fuzzSeed-169986037*/count=1359; tryItOut("\"use strict\"; /*tLoop*/for (let y of /*MARR*/[ /x/g , new Boolean(true), new Boolean(true), new Boolean(true),  /x/g , NaN, new Boolean(true),  /x/g , NaN, new Boolean(true), new Boolean(true), NaN, NaN, new Boolean(true), new Boolean(true), NaN, new Boolean(true), new Boolean(true),  /x/g ,  /x/g , NaN, NaN,  /x/g , NaN,  /x/g , new Boolean(true),  /x/g , new Boolean(true),  /x/g , new Boolean(true),  /x/g , new Boolean(true),  /x/g ,  /x/g , new Boolean(true), NaN, new Boolean(true),  /x/g , new Boolean(true), new Boolean(true), NaN, NaN,  /x/g , new Boolean(true),  /x/g , new Boolean(true), new Boolean(true),  /x/g , NaN, new Boolean(true),  /x/g ,  /x/g , new Boolean(true),  /x/g , NaN, new Boolean(true), new Boolean(true),  /x/g , new Boolean(true),  /x/g , new Boolean(true), new Boolean(true),  /x/g , NaN,  /x/g ,  /x/g , new Boolean(true), NaN, new Boolean(true),  /x/g ,  /x/g ,  /x/g ,  /x/g , new Boolean(true),  /x/g , NaN, NaN,  /x/g , NaN, NaN, NaN, NaN, NaN,  /x/g ,  /x/g , new Boolean(true),  /x/g , NaN, NaN,  /x/g ,  /x/g , NaN, NaN, new Boolean(true), NaN, new Boolean(true), new Boolean(true),  /x/g , new Boolean(true), new Boolean(true),  /x/g ,  /x/g , NaN, NaN,  /x/g ,  /x/g , NaN, NaN,  /x/g , NaN]) { i0.send(a2); }");
/*fuzzSeed-169986037*/count=1360; tryItOut("m1 = a2[(q => q).call(window = Proxy.createFunction(({/*TOODEEP*/})(-25),  \"\" ), (x ?  \"\"  / arguments : x), x * x)];");
/*fuzzSeed-169986037*/count=1361; tryItOut("a2.reverse(x, a1);");
/*fuzzSeed-169986037*/count=1362; tryItOut("s1 += 'x';");
/*fuzzSeed-169986037*/count=1363; tryItOut("\"use strict\"; f0 + o1.h1;");
/*fuzzSeed-169986037*/count=1364; tryItOut("m1.delete(v1);");
/*fuzzSeed-169986037*/count=1365; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (-70368744177665.0);\n    return (((imul((i0), (i0))|0) / (((0xfca0c6b8)-(0x49361118)-(i0)) & (((((0x45b22a1e) / (0x6c67d21a)) << ((0xf927438f))) < (((0x5ad62498)+(0xfb7e4508)-(0xfe927eed))|0))*0x85689))))|0;\n    (Float32ArrayView[0]) = ((d1));\n    return (((0x553a0e1b)*-0xfffff))|0;\n  }\n  return f; })(this, {ff: eval}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [Number.MIN_SAFE_INTEGER, 0x0ffffffff, 2**53+2, -(2**53-2), -0x07fffffff, 1, 1.7976931348623157e308, 0x100000001, 0, -0x100000000, 42, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -(2**53+2), 2**53-2, -0, -0x0ffffffff, -0x080000001, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -1/0, Math.PI, 0/0, -Number.MIN_VALUE, 0x100000000, -0x080000000, 2**53, 1/0, 0x080000001, -Number.MIN_SAFE_INTEGER, -(2**53), -Number.MAX_VALUE, 0x080000000, 0.000000000000001, -0x100000001]); ");
/*fuzzSeed-169986037*/count=1366; tryItOut("for(let c in /*FARR*/[(Uint32Array)((void version(170)), new RegExp(\".+?|[^]\\\\x0E.?|[^]|\\\\d|(?!.)|[^]+?(?=^)([^\\\\cQ-\\ud582\\\\0-\\uc921])\\\\W.|(?:\\\\b\\\\b)*|\\\\W\", \"gyim\")), x, (/*FARR*/[(Math.max(/(?!(\\s|[^]|\\b|.(?!\u8be7|$)?)){4,8}/gyim, length)) in  /x/g  >>= \"\u03a0\", ([]) = true + 29, , .../*MARR*/[new Number(1), let (a = true) this, new String(''), new String(''), let (a = true) this, ({x:3}), let (a = true) this, new String(''), new String(''), new String(''), ({x:3}), new String(''), new Number(1), ({x:3}), let (a = true) this, ({x:3}), let (a = true) this, ({x:3}), new Number(1), new String(''), new Number(1), ({x:3}), new Number(1), new String(''), new String(''), new String(''), let (a = true) this, let (a = true) this, new Number(1), new Number(1), new Number(1), let (a = true) this, new Number(1), new String(''), new String(''), ({x:3}), ({x:3}), new Number(1), ({x:3}), new String(''), new Number(1), new String(''), new String(''), let (a = true) this, let (a = true) this, new String(''), let (a = true) this, ({x:3}), new String(''), new Number(1), let (a = true) this, ({x:3}), new String(''), new String(''), let (a = true) this, new String(''), new String(''), ({x:3}), ({x:3}), let (a = true) this, let (a = true) this, new Number(1), new String(''), let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, let (a = true) this, new Number(1), new Number(1), ({x:3}), new Number(1), new String(''), new String(''), new Number(1), let (a = true) this, new String(''), new String(''), new String(''), ({x:3}), ({x:3}), new Number(1), let (a = true) this, ({x:3}), let (a = true) this, new String(''), ({x:3}), ({x:3}), let (a = true) this], let (lrqdnb, a = (d = w), a = 8, aswceo) delete length.y, ...((new DataView(Boolean(), (4277))) for (x of (delete x.y for (x of new Array(-25)) for each (z in []) if (Math))) for (this.zzz.zzz in [[1]]) for each (x in x) for each (c in  /x/g ))].some(( \"\" ).bind(e / e), (/*MARR*/[(1/0), Number.MIN_VALUE, Number.MIN_VALUE, arguments.callee, Number.MIN_VALUE, arguments.callee, Number.MIN_VALUE, Number.MIN_VALUE, null, null, arguments.callee, (1/0), Number.MIN_VALUE, arguments.callee, null, arguments.callee, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), arguments.callee, arguments.callee, null, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), null, Number.MIN_VALUE, (1/0), null, arguments.callee, null, null, (1/0), (1/0), Number.MIN_VALUE, Number.MIN_VALUE, null, null, null, arguments.callee, Number.MIN_VALUE, Number.MIN_VALUE, (1/0), null, null, null, null, (1/0), Number.MIN_VALUE, arguments.callee, null, null, null, arguments.callee, (1/0), (1/0), arguments.callee, arguments.callee, (1/0), (1/0), Number.MIN_VALUE, null, (1/0), (1/0), (1/0), null, arguments.callee, (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), (1/0), null]))), ...((Array.of.prototype).valueOf(\"number\")) for (x of Math.pow(-26,  \"\" )), (x = x), (new (new RegExp(\"(?:(?=^)(?![^]*?)((?!.)))*?\\\\cF{63}|\\\\1*?\", \"y\"))( '' , window) , this.__defineSetter__(\"x\", (/(?!.)?/gyim).call)), (-15.unwatch(\"wrappedJSObject\")), (makeFinalizeObserver('tenured')), .../*MARR*/[ '\\0' , new Number(1.5),  '\\0' , new Number(1.5),  '\\0' , new Number(1.5),  '\\0' , new Number(1.5), new Number(1.5),  '\\0' ,  '\\0' ,  '\\0' , new Number(1.5),  '\\0' , new Number(1.5),  '\\0' ,  '\\0' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  '\\0' , new Number(1.5), new Number(1.5), new Number(1.5),  '\\0' ,  '\\0' , new Number(1.5), new Number(1.5),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new Number(1.5),  '\\0' , new Number(1.5), new Number(1.5),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  '\\0' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  '\\0' ,  '\\0' , new Number(1.5), new Number(1.5),  '\\0' , new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5), new Number(1.5),  '\\0' , new Number(1.5),  '\\0' , new Number(1.5),  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new Number(1.5),  '\\0' , new Number(1.5),  '\\0' ]]) c.fileName;");
/*fuzzSeed-169986037*/count=1367; tryItOut("/*bLoop*/for (let hjhsto = 0; hjhsto < 19; ++hjhsto) { if (hjhsto % 74 == 11) { eval % x; } else { return; }  } ");
/*fuzzSeed-169986037*/count=1368; tryItOut("\"use strict\"; gfdbms, this.window, x, yahgic, eval, looeez, a;v2 = Infinity;");
/*fuzzSeed-169986037*/count=1369; tryItOut("\"use strict\"; this.i1 + '';");
/*fuzzSeed-169986037*/count=1370; tryItOut("g0.v2 = t2.byteLength;");
/*fuzzSeed-169986037*/count=1371; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.cosh((Math.fround(mathy0(Math.fround(Math.max(y, ( + (( + y) , (( ~ x) >>> 0))))), Math.fround(Math.fround((y ** ( + mathy0(Math.imul(( + Math.fround(Number.MAX_VALUE)), 1.7976931348623157e308), ( ! Math.fround((((y >>> 0) >>> (x >>> 0)) | 0)))))))))) | 0)) | 0); }); testMathyFunction(mathy1, [0x080000001, 0x100000001, 0/0, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 2**53+2, 0x080000000, 42, -(2**53-2), -Number.MIN_VALUE, -0x080000001, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -1/0, 2**53-2, 0, -Number.MAX_VALUE, -0x07fffffff, -0x080000000, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53, -(2**53), Math.PI, Number.MIN_VALUE, 1, -0, 0.000000000000001, 0x07fffffff, -0x0ffffffff, -0x100000001, -(2**53+2), -Number.MAX_SAFE_INTEGER, 1/0, 0x100000000]); ");
/*fuzzSeed-169986037*/count=1372; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1373; tryItOut("s1 += s1;");
/*fuzzSeed-169986037*/count=1374; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(\\\\cX{257})?\", \"gyim\"); var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1375; tryItOut("\"use strict\"; mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var exp = stdlib.Math.exp;\n  var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    (Float64ArrayView[2]) = ((+exp(((524289.0)))));\n    i1 = (i0);\n    i1 = ((((i0)+(((0x2b4c6*(i0))|0))-(i1))>>>(-(((+(((i1)+(i1))>>>(((~~(-127.0)))))))))) <= (0xffffffff));\n    {\n      (Float64ArrayView[(((((NaN)) / ((Float64ArrayView[2]))) >= (-0.0078125))+((0xc996cef7) == (((i0))>>>((0xf9f9ba97)-(0x2959b2fe))))) >> 3]) = ((eval(\"e1.has(v1);\")));\n    }\n;    {\n      i0 = (i0);\n    }\n    (Uint8ArrayView[0]) = ((!(i0)));\n    return ((-(i1)))|0;\n  }\n  return f; })(this, {ff: Uint8Array}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [0, [], (new Boolean(false)), NaN, true, '\\0', objectEmulatingUndefined(), undefined, ({toString:function(){return '0';}}), (new Number(-0)), '', 0.1, 1, ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), (function(){return 0;}), '/0/', false, null, -0, /0/, '0', (new String('')), (new Boolean(true)), (new Number(0)), [0]]); ");
/*fuzzSeed-169986037*/count=1376; tryItOut("mathy3 = (function(x, y) { return (Math.cosh(((mathy2(((((Math.fround(y) ? (x | 0) : (x | 0)) >>> 0) << ( + (( + Math.min(x, -0x07fffffff)) > ( + y)))) | 0), Math.log2(( + Math.fround(Math.tanh(y))))) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [2**53-2, -Number.MAX_SAFE_INTEGER, 2**53+2, 1, -(2**53-2), -0x07fffffff, -(2**53+2), 0.000000000000001, 0/0, 2**53, Math.PI, -Number.MIN_SAFE_INTEGER, -0, 0x100000001, -0x100000000, -0x0ffffffff, 1/0, Number.MIN_VALUE, -1/0, 42, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53), -0x080000001, 0x080000001, -Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, 0, -0x080000000, 0x100000000, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000001]); ");
/*fuzzSeed-169986037*/count=1377; tryItOut("print(x);\n/*RXUB*/var r = r0; var s = s1; print(r.test(s)); \n");
/*fuzzSeed-169986037*/count=1378; tryItOut("mathy4 = (function(x, y) { return (( + (((Math.fround((Math.atanh(-0x100000001) / mathy1(( + 0/0), 2**53))) % (Math.sign(( + ((-0x07fffffff == x) | 0))) >>> 0)) - (Math.max(( ! Math.fround(-0x080000000)), y) >>> 0)) | 0)) | 0); }); ");
/*fuzzSeed-169986037*/count=1379; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.asin(( + Math.fround(( ! ( + Math.tanh(x)))))); }); testMathyFunction(mathy2, [0x0ffffffff, -0x080000001, 0/0, -0x100000000, 2**53, Number.MAX_VALUE, 0x100000001, 0x07fffffff, 1, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, 0x100000000, 0x080000000, Math.PI, -0x07fffffff, 0.000000000000001, Number.MIN_VALUE, -(2**53-2), -0x0ffffffff, -0, -0x100000001, 1/0, 2**53+2, 0, 42, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308, 2**53-2, -(2**53), Number.MIN_SAFE_INTEGER, -(2**53+2), -0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1380; tryItOut("h2.iterate = (function(j) { if (j) { try { (void schedulegc(g1)); } catch(e0) { } try { m0 + ''; } catch(e1) { } try { selectforgc(o2); } catch(e2) { } for (var p in this.t2) { try { t0 = Proxy.create(h0, f0); } catch(e0) { } e0 + ''; } } else { var t0 = new Uint8ClampedArray(t2); } });");
/*fuzzSeed-169986037*/count=1381; tryItOut(";");
/*fuzzSeed-169986037*/count=1382; tryItOut("mathy5 = (function(x, y) { return ( + ((Math.fround((( + mathy4(( + x), Math.min(x, Math.fround(x)))) ? Math.fround(Math.fround(Math.imul(Math.fround(Math.min(((x + 0x100000001) | 0), 1.7976931348623157e308)), Math.fround(Math.pow(Math.fround(( ~ (((y >>> 0) >>> x) >>> 0))), ( ! Math.fround(-Number.MIN_VALUE))))))) : (Math.max(Math.atan2(((y < Math.fround(y)) | 0), ( - Math.fround(-(2**53)))), ( + y)) | 0))) + Math.fround(Math.fround((Math.fround(( + (Math.clz32((y >>> 0)) >>> 0))) ? Math.fround(x) : Math.fround((( + -0x100000001) - ( + x))))))) | 0)); }); testMathyFunction(mathy5, [(new String('')), (new Boolean(true)), false, '0', objectEmulatingUndefined(), /0/, ({toString:function(){return '0';}}), NaN, [], 0, '\\0', ({valueOf:function(){return 0;}}), undefined, '/0/', (new Boolean(false)), ({valueOf:function(){return '0';}}), 1, 0.1, null, (new Number(-0)), true, -0, (function(){return 0;}), (new Number(0)), '', [0]]); ");
/*fuzzSeed-169986037*/count=1383; tryItOut("this.zzz.zzz;x.message;");
/*fuzzSeed-169986037*/count=1384; tryItOut("v1 = g1.eval(\"undefined\\nprint(uneval(g1.a2));\");");
/*fuzzSeed-169986037*/count=1385; tryItOut("mathy2 = (function(x, y) { return ( + ( + ( ! ( ! x)))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 2**53+2, 0, -(2**53+2), 0.000000000000001, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x080000000, -Number.MAX_VALUE, 1, 2**53-2, -(2**53), -(2**53-2), -0x100000001, 1/0, Number.MAX_VALUE, Math.PI, -Number.MIN_VALUE, 0x0ffffffff, 1.7976931348623157e308, 0x100000000, -0, -0x0ffffffff, 42, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0x100000001, 0/0, 0x07fffffff, 0x080000001, 2**53, -0x080000001, 0x080000000, -0x100000000]); ");
/*fuzzSeed-169986037*/count=1386; tryItOut("v1 = a2.length;");
/*fuzzSeed-169986037*/count=1387; tryItOut("mathy5 = (function(x, y) { return mathy4(Math.fround(( - Math.fround((Math.fround(Math.cos(Math.fround(((( + x) ? ( + y) : ( + y)) - (x | 0))))) === ( + Math.atan2(( + Math.atan2(mathy1(x, y), ( + x))), ( + Math.exp(x)))))))), (Math.log2((( + ((( + Math.min(x, Math.fround(x))) | 0) == ( + ( ! ( ~ y))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy5, [-Number.MAX_SAFE_INTEGER, -1/0, 0, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 1/0, 0/0, 1.7976931348623157e308, -Number.MIN_VALUE, 2**53, 42, 0x100000000, -0, -0x07fffffff, -0x100000000, -(2**53+2), 0.000000000000001, 1, -0x100000001, 0x07fffffff, -0x080000001, -(2**53), 0x100000001, -Number.MAX_VALUE, -0x080000000, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, Math.PI, 0x080000000, 2**53+2, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 2**53-2, -(2**53-2)]); ");
/*fuzzSeed-169986037*/count=1388; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1389; tryItOut("mathy1 = (function(x, y) { return ( + Math.tanh(((((Math.log10(Math.fround(Math.fround(Math.atan2(Math.fround(x), Math.fround(y))))) === x) >>> 0) !== ((Math.imul(Math.fround(Math.asin(( + ((y | 0) < ((Math.min((x | 0), (Number.MAX_VALUE | 0)) | 0) | 0))))), ( ! Math.min((Math.cosh(x) >>> 0), 0x080000000))) >>> 0) | 0)) >>> 0))); }); ");
/*fuzzSeed-169986037*/count=1390; tryItOut("\"use strict\"; print(x);");
/*fuzzSeed-169986037*/count=1391; tryItOut("mathy0 = (function(x, y) { return (Math.atan2((( + (Math.fround(Math.max(Math.fround(Math.asinh(Math.cos(x))), Math.fround(Math.fround((( + Math.max((Math.round((x >>> 0)) >>> 0), (( ~ ( - y)) >>> 0))) && Math.fround(y)))))) & ( + ( ~ -(2**53))))) >>> 0), (( - Math.max(((Math.log(( + Math.abs(Math.fround((Math.asinh((x | 0)) | 0))))) | 0) | 0), ((( + (( ~ ( + 2**53+2)) >>> 0)) >>> 0) | 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-1/0, 0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER, 0.000000000000001, 2**53-2, -(2**53), 0x100000001, 1, -Number.MAX_VALUE, -Number.MIN_VALUE, 1.7976931348623157e308, 0x080000001, 42, 2**53, Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, 0, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, 2**53+2, 1/0, 0x080000000, Number.MIN_VALUE, 0x100000000, Math.PI, Number.MAX_SAFE_INTEGER, 0/0, -(2**53+2), -0x07fffffff, -0, -0x080000001]); ");
/*fuzzSeed-169986037*/count=1392; tryItOut("\"use strict\"; e0.has(b2);");
/*fuzzSeed-169986037*/count=1393; tryItOut("t1[15] = x;");
/*fuzzSeed-169986037*/count=1394; tryItOut("/*infloop*/do print(x); while(x);");
/*fuzzSeed-169986037*/count=1395; tryItOut("if(true) {/*RXUB*/var r = new RegExp(\"\\\\s(?![^\\\\\\u00ca\\\\w]|(?![\\\\cK]*\\\\B))+?|(?!(^{3,})|[\\\\b]){0,}?\", \"gim\"); var s = new RegExp(\"(?:\\\\b[^\\\\u5698\\\\x80\\u00ca]|[^])|[\\\\w]{0,}*?{2,}\", \"gyim\"); print(uneval(r.exec(s))); print(r.lastIndex);  } else  if (( /x/g )()) {/* no regression tests found */v2 = (v0 instanceof h0); } else a2[15] = e1;");
/*fuzzSeed-169986037*/count=1396; tryItOut("\"use strict\"; m2 + i2;");
/*fuzzSeed-169986037*/count=1397; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.max(Math.cbrt((Math.min((y ** y), ( + Math.cos(( + x)))) | 0)), (Math.asinh(Math.trunc(((( - x) >>> 0) > (Math.imul(( ~ -Number.MIN_SAFE_INTEGER), y) >>> 0)))) | 0)) | 0); }); testMathyFunction(mathy0, [2**53+2, -Number.MAX_VALUE, 0x0ffffffff, -0x0ffffffff, 0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, 2**53-2, -(2**53+2), Math.PI, -0x080000000, 1.7976931348623157e308, -0x100000001, 0, -0, 2**53, 0x100000001, 1, -1/0, 0x080000001, -(2**53), 0/0, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -0x100000000, -0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 1/0, 0.000000000000001, -(2**53-2), -0x080000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1398; tryItOut("this.o0.a2[7] = m0;");
/*fuzzSeed-169986037*/count=1399; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.cbrt(( - Math.imul(( + ( + ( + x))), Math.fround(Math.sin(( + y)))))); }); testMathyFunction(mathy4, [-0x0ffffffff, 0x080000001, -0x080000001, -(2**53), 1, 1/0, 0x080000000, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x100000001, -(2**53-2), 2**53-2, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 0x07fffffff, -0x07fffffff, Math.PI, -(2**53+2), 0x0ffffffff, 2**53+2, -0, -0x080000000, 0, 0/0, Number.MIN_VALUE, -Number.MIN_VALUE, 42, -0x100000000, -Number.MAX_VALUE, 0.000000000000001, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, 2**53, 1.7976931348623157e308]); ");
/*fuzzSeed-169986037*/count=1400; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1401; tryItOut("let (x = (/*UUV1*/(x.set = neuter)), \u3056 =  '' ,  , eval = {},   = x, jcyxbw, b = ((yield Math.max(new RegExp(\"(?:(?=[^]|[\\\\S]|^\\\\u1b69|^)|\\\\S)\", \"gyi\"),  '' ))), window = null, e = x, x) { e2.add(t0); }");
/*fuzzSeed-169986037*/count=1402; tryItOut("o0.o0.h1 + i0;");
/*fuzzSeed-169986037*/count=1403; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    i0 = (i0);\n    return +((+(0.0/0.0)));\n    d1 = (+atan2(((+((NaN)))), (((+(abs((0x6df2c1))|0)) + (d1)))));\n    {\n      {\n        d1 = (d1);\n      }\n    }\n    d1 = (+(((0x72e601d1)-(0xffffffff))>>>((i0)*0x1a40b)));\n    return +((+pow(((Float64ArrayView[((-0x8000000)) >> 3])), ((d1)))));\n    (window) = ((d1));\n    i0 = (i0);\n    i0 = ((+/*FFI*/ff(((d1)), ((~((i0)+((+(((0x657806d4))|0)) == (+(-1.0/0.0)))))))) != (d1));\n    {\n      {\n        (Float32ArrayView[(((0x4fe7d6ab) >= (((0x47c4618)-(0x1d44276b)+(0xffffffff)) & (-0xfffff*(0xefca8ded))))+((0x677abda7))) >> 2]) = ((Float32ArrayView[(-0xfffff*(/*FFI*/ff(((+(0x6be56866))), ((1.0009765625)), ((((0x5fff8c40)) | (((0x5987219e) == (0x64d7eb89))+(i0)))), ((+/*FFI*/ff())), ((0x536cbeab)), (((-33.0))), ((-1.0)), ((-281474976710656.0)), ((17592186044415.0)), ((-2305843009213694000.0)), ((1.1805916207174113e+21)), ((288230376151711740.0)))|0)) >> 2]));\n      }\n    }\n    return +((+((((Float64ArrayView[1])) / ((+(0xc36fb630)))))));\n  }\n  return f; })(this, {ff: (function(x, y) { \"use strict\"; return (x % x); })}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000001, 1, Number.MAX_SAFE_INTEGER, 0, 0x100000000, 42, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000001, 0.000000000000001, 2**53, Number.MIN_VALUE, -(2**53), -0x080000000, 2**53+2, -0x080000001, 0/0, 0x080000001, 2**53-2, Number.MAX_VALUE, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), 0x07fffffff, 1/0, 0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=1404; tryItOut("mathy2 = (function(x, y) { return (((Math.log2((Math.pow((( + ( + x)) | 0), (Math.pow(Math.fround((((Math.fround((x ? (x | 0) : x)) | 0) != Math.sinh(1)) >>> 0)), (Number.MIN_VALUE | 0)) >>> 0)) >>> 0)) >>> 0) < (Math.atanh((Math.fround(( + Math.fround((x << (( + Math.max((-0x0ffffffff | 0), (-(2**53+2) | 0))) >>> 0))))) !== (Math.atan((Math.sinh(Math.fround(mathy1(Math.fround((x % y)), Math.fround(x)))) >>> 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [objectEmulatingUndefined(), NaN, (new String('')), [], true, (new Boolean(false)), null, (new Number(-0)), (function(){return 0;}), undefined, '0', -0, (new Number(0)), ({valueOf:function(){return 0;}}), '\\0', ({valueOf:function(){return '0';}}), '/0/', [0], '', 0.1, (new Boolean(true)), false, 1, ({toString:function(){return '0';}}), /0/, 0]); ");
/*fuzzSeed-169986037*/count=1405; tryItOut("r0 = /(?=[^])(?=(?=(?=.))|(?:[\ue5d3\\s])(?:[^])?)/;");
/*fuzzSeed-169986037*/count=1406; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=1407; tryItOut("throw x;");
/*fuzzSeed-169986037*/count=1408; tryItOut("\"use asm\"; h0.toSource = (function mcc_() { var zpdydf = 0; return function() { ++zpdydf; f2(/*ICCD*/zpdydf % 3 == 2);};})();");
/*fuzzSeed-169986037*/count=1409; tryItOut("mathy2 = (function(x, y) { return ( + (Math.fround(Math.tanh(Math.acos(((0 >>> 0) % ( + (( + ( ~ ( + x))) - ( + y))))))) ? ( + ( + Math.hypot(Math.fround(Math.acos(Math.fround(y))), (Math.hypot(x, ( - (0/0 % y))) | 0)))) : ( + ( ~ ( + Math.atan2(mathy1(x, ((((y % (Math.asinh(Number.MIN_VALUE) | 0)) | 0) ^ 2**53+2) | 0)), (Math.sin((( + (( + y) >>> ((0.000000000000001 == x) | 0))) >>> 0)) >>> 0))))))); }); ");
/*fuzzSeed-169986037*/count=1410; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    {\n      d1 = (+(-1.0/0.0));\n    }\n    return +((Float64ArrayView[(((((0x9007a492)+((0x3fbfa404) ? (0xf939be0c) : (0xf859623a))) ^ (((Float64ArrayView[((0xfd0353ea)-((0x6df5bd71) >= (0xa50f6d59))) >> 3])))))-((0x17deb1ec))) >> 3]));\n  }\n  return f; })(this, {ff: Date.now}, new SharedArrayBuffer(4096)); testMathyFunction(mathy0, [2**53, 42, 1/0, -0x100000000, 1, -0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, Math.PI, -1/0, Number.MAX_VALUE, 0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0, -0x0ffffffff, -0x100000001, 0x100000001, -(2**53+2), 0/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 0x07fffffff, 0x100000000, -(2**53-2), -Number.MIN_VALUE, -0x07fffffff, 2**53+2, -0x080000001, 2**53-2, -(2**53), 0.000000000000001, 0x080000000]); ");
/*fuzzSeed-169986037*/count=1411; tryItOut("a2.shift();");
/*fuzzSeed-169986037*/count=1412; tryItOut("\"use strict\"; v2 = g1.runOffThreadScript();");
/*fuzzSeed-169986037*/count=1413; tryItOut("if(true) {o1 + i1;function a(d) { a0.forEach((function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13) { var r0 = 6 * a11; var r1 = 8 & 7; var r2 = 0 & 8; var r3 = 8 / r1; var r4 = 1 - r2; var r5 = a9 | 4; var r6 = 9 - a4; print(a1); var r7 = a1 - a7; x = 6 / 6; r2 = a3 & r2; r2 = a10 / r6; var r8 = a0 | a3; r7 = 5 * a1; var r9 = 9 * x; var r10 = r1 + 6; var r11 = 7 - 5; var r12 = 2 - 4; var r13 = a0 ^ a6; var r14 = a12 / a9; var r15 = 0 | 6; var r16 = a1 ^ a9; a6 = 5 * 9; var r17 = a1 * a9; r14 = 0 + a8; var r18 = a8 ^ 0; var r19 = 5 - a12; var r20 = 8 - r2; print(r8); var r21 = a3 * r2; var r22 = r17 ^ 2; var r23 = 5 / 5; var r24 = r3 ^ 8; var r25 = r13 - a0; var r26 = r13 % r0; var r27 = r10 & 8; var r28 = r13 + 5; var r29 = r0 + r0; var r30 = 7 | r15; var r31 = r20 % 5; var r32 = r1 * 6; var r33 = r32 % a5; var r34 = 3 ^ a11; r10 = a7 + r17; var r35 = r17 | 4; print(r35); r3 = r1 + 0; var r36 = 0 * r31; var r37 = a3 & r11; var r38 = 7 / x; var r39 = 7 / r13; var r40 = a9 % a3; var r41 = 3 * r20; a7 = a12 - x; var r42 = 1 % 3; var r43 = 0 & r13; var r44 = a3 | r5; var r45 = 0 | r42; var r46 = 9 / r18; var r47 = r26 - 2; var r48 = 5 % r1; r5 = 6 | r30; var r49 = r15 + a11; var r50 = r16 / 5; var r51 = r42 * 4; var r52 = r12 | r5; r40 = r9 - 1; var r53 = 1 & 0; var r54 = r13 ^ r10; var r55 = 3 & 3; var r56 = r49 + r20; var r57 = 1 % 3; var r58 = 0 + r10; var r59 = 5 | 5; print(r26); var r60 = a6 + r1; var r61 = r9 ^ r39; var r62 = r60 - r14; var r63 = 3 + 1; r15 = 7 / 9; var r64 = 8 & r34; var r65 = r34 / 0; var r66 = r34 - 2; var r67 = 9 - r39; r34 = 9 * a2; var r68 = 1 / r31; var r69 = r2 / 0; var r70 = r63 % r65; r35 = r0 * 2; var r71 = r14 - 2; var r72 = a0 + 0; var r73 = 5 % 6; r44 = r59 + r72; var r74 = r26 & a13; var r75 = r21 * a2; r34 = r31 & r4; var r76 = r44 / r37; r1 = r68 - r29; var r77 = r64 * a10; var r78 = 7 - 6; print(r49); var r79 = r24 & r43; var r80 = r13 | r25; var r81 = r13 ^ r29; var r82 = a5 & r10; r33 = 4 + r57; var r83 = a12 ^ r67; var r84 = 5 ^ a8; var r85 = r36 ^ 3; var r86 = r30 ^ 2; var r87 = 9 ^ 2; var r88 = r5 / r80; var r89 = r31 ^ 2; var r90 = 6 & a6; var r91 = 8 / r59; var r92 = r32 & r5; r86 = 4 % 4; var r93 = 7 | r28; var r94 = 2 / r70; var r95 = r29 & r26; var r96 = r78 / 5; var r97 = r74 | 8; r31 = 4 / r21; var r98 = r94 * 2; var r99 = r45 / r54; var r100 = a5 | 7; var r101 = r4 / r34; var r102 = 0 & r66; var r103 = r46 | 9; return a1; })); } /*RXUB*/var r = this.r0; var s = \"0\\u1e2e\\n\\udf00 \\n0\\u1e2e\\n\\udf00 \\n0\\u1e2e\\n\\udf00 \\n0\\u1e2e\\n\\udf00 \\n0\\u1e2e\\n\\udf00 \\n\\n0\\u1e2e\\n\\udf00 \\n0\\u1e2e\\n\\udf00 \\n0\\u1e2e\\n\\udf00 \\n0\\u1e2e\\n\\udf00 \\n0\\u1e2e\\n\\udf00 \\n\\n\"; print(s.match(r));  }");
/*fuzzSeed-169986037*/count=1414; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(s1, f1);");
/*fuzzSeed-169986037*/count=1415; tryItOut("\"use strict\"; \"use asm\"; /*RXUB*/var r = /((?=(?=(?=\\s|\\S{2,})))|(?!.)|[^\u00d2]+?)/gm; var s = /*RXUE*/new RegExp(\"(?=^+?)|($).?|$\\\\xD6{4,}|(?!^\\\\B)|[^]*?+\", \"gyi\").exec(\"\\uc524\\uc524\"); print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=1416; tryItOut("\"use strict\"; v1 = Object.prototype.isPrototypeOf.call(g1.i0, i1);");
/*fuzzSeed-169986037*/count=1417; tryItOut("testMathyFunction(mathy3, [0x100000001, -0x100000000, -0x0ffffffff, -(2**53-2), Number.MAX_VALUE, 0x07fffffff, 0, 0.000000000000001, 2**53+2, Number.MIN_VALUE, Math.PI, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), -1/0, -0x080000000, 1/0, 1.7976931348623157e308, -0x080000001, 2**53-2, -Number.MAX_VALUE, 42, 0x0ffffffff, 0/0, 0x100000000, -(2**53), -0x100000001, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0, 0x080000000, 1, 2**53, 0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1418; tryItOut("\"use strict\"; f0.toString = (function(j) { if (j) { a0.splice(2, v0); } else { try { print(a2); } catch(e0) { } try { m1.set(i0, e1); } catch(e1) { } try { v0 = true; } catch(e2) { } Array.prototype.push.call(a2, o0, s1, a1, b2, h2, a0, s0); } });");
/*fuzzSeed-169986037*/count=1419; tryItOut("\u3056.stack;");
/*fuzzSeed-169986037*/count=1420; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return ( + Math.pow((Math.fround(( ~ (( - ( ~ Math.fround(-0x080000000))) >>> 0))) | 0), ( + ( - ( + Math.asin(Math.max((0 / Math.fround(mathy2(Math.fround(x), Math.fround(y)))), y))))))); }); testMathyFunction(mathy4, /*MARR*/[(void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), false, function(){}, [1], (void 0), function(){}, function(){}, false,  /x/g , [1], [1], [1], false, (void 0), (void 0), function(){}, [1], (void 0), (void 0), function(){}, false,  /x/g , [1], function(){}, (void 0), function(){}, [1], (void 0),  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , (void 0), [1]]); ");
/*fuzzSeed-169986037*/count=1421; tryItOut("\"use strict\"; const a0 = a2.filter((function() { try { t0 = new Uint16Array(this.b0); } catch(e0) { } try { a0 = /*FARR*/[]; } catch(e1) { } try { s0 += 'x'; } catch(e2) { } g1.toSource = (function mcc_() { var tifpwo = 0; return function() { ++tifpwo; if (tifpwo > 6) { dumpln('hit!'); try { Object.defineProperty(this, \"v2\", { configurable: window, enumerable: true,  get: function() { v1 = t1.byteLength; return g1.runOffThreadScript(); } }); } catch(e0) { } try { h0.iterate = f2; } catch(e1) { } try { this.s2 += this.s1; } catch(e2) { } Array.prototype.unshift.call(a0, h2, f2, i1, (x && arguments ? -630792516 : 3)); } else { dumpln('miss!'); try { this.m1.has(m2); } catch(e0) { } try { m1.delete(o0); } catch(e1) { } g0.v2 = g2.runOffThreadScript(); } };})(); return h2; }), p2);let (e = x, kbvhsl, b = x, e, x, z) { for (var v of o2) { try { for (var p in s1) { v1 = (this.t0 instanceof t0); } } catch(e0) { } try { h1.getOwnPropertyDescriptor = (function mcc_() { var rzezit = 0; return function() { ++rzezit; f0(/*ICCD*/rzezit % 2 == 0);};})(); } catch(e1) { } try { m1.set(o0, o1); } catch(e2) { } a1 + a2; } }");
/*fuzzSeed-169986037*/count=1422; tryItOut("\"use asm\"; mathy0 = (function(x, y) { \"use strict\"; return Math.max(Math.sqrt((Math.fround(Math.min((Math.asinh(x) >>> 0), y)) != Math.fround(Math.asin((Math.cos((Math.pow((x >>> 0), (Math.acosh(( + y)) >>> 0)) >>> 0)) >>> 0))))), ((y >>> ( - y)) >> Math.cbrt(2**53))); }); testMathyFunction(mathy0, [0.000000000000001, -(2**53), 0x100000001, Number.MAX_VALUE, 2**53, -1/0, Number.MIN_VALUE, 0/0, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, 0x07fffffff, 2**53+2, -0x100000001, -0x0ffffffff, 1, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, 0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000000, -(2**53+2), -0x07fffffff, -Number.MAX_SAFE_INTEGER, 1/0, -0x080000000, -0, 0, 0x0ffffffff, -(2**53-2), 2**53-2, -Number.MAX_VALUE, 0x080000001, 42]); ");
/*fuzzSeed-169986037*/count=1423; tryItOut("for (var p in t1) { try { o1.o0 = {}; } catch(e0) { } try { s0 += 'x'; } catch(e1) { } try { o0.g2 + this.h1; } catch(e2) { } m1.delete(t0); }");
/*fuzzSeed-169986037*/count=1424; tryItOut("x = p0;");
/*fuzzSeed-169986037*/count=1425; tryItOut("print((c) = b);");
/*fuzzSeed-169986037*/count=1426; tryItOut("mathy0 = (function(x, y) { \"use asm\"; return Math.fround((( + ((((( ! Math.min(y, x)) >>> 0) ** ( + (Math.sin(0x080000000) % ( + x)))) >>> 0) % ( + Math.log10((( + (y && ( + y))) | 0))))) & Math.fround(( ~ (((Math.fround(Math.fround(Math.pow(Math.fround(y), Math.fround(Math.abs((Math.tan(x) >>> 0)))))) + Math.fround(y)) | 0) | 0))))); }); testMathyFunction(mathy0, [-0x100000000, Number.MAX_VALUE, 0x0ffffffff, -0x100000001, -0x080000001, 1.7976931348623157e308, -0x080000000, -(2**53), 2**53+2, 0x080000001, 2**53-2, -0x0ffffffff, -0, 0x100000000, 0.000000000000001, 2**53, 0x07fffffff, 1/0, 0x080000000, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53-2), 0/0, -1/0, -Number.MAX_VALUE, -Number.MIN_VALUE, Math.PI, -(2**53+2), 0, 42, 0x100000001, 1, -0x07fffffff, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1427; tryItOut("for(let b//h\n in ((offThreadCompileScript)(x)))\u000dconst kczmyp, 27, y, x, eval, jkmtoq, asnwot, qwisvu;t2.set(g2.a0, 16);");
/*fuzzSeed-169986037*/count=1428; tryItOut("neuter(b1, \"same-data\");");
/*fuzzSeed-169986037*/count=1429; tryItOut("\"use strict\"; this.b0 = new ArrayBuffer(16);");
/*fuzzSeed-169986037*/count=1430; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.sinh(((Math.fround(Math.tan(Math.fround((( + ( + Math.pow(( + Math.fround(Math.cosh(0x100000000))), ( + ( ~ -0x100000001))))) > Math.fround((Math.fround((y << -(2**53))) ? Math.fround(-Number.MAX_SAFE_INTEGER) : (x | 0))))))) ** (mathy1((( + (((( ~ ((x ? x : y) | 0)) | 0) | 0) >> ((Math.tan(x) >>> 0) | 0))) | 0), (x | 0)) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [Number.MAX_VALUE, -(2**53-2), 0x0ffffffff, 2**53, -(2**53), 2**53-2, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 1/0, -Number.MIN_VALUE, -0x0ffffffff, -0x100000000, 0/0, 42, 0x100000001, Number.MAX_SAFE_INTEGER, 2**53+2, 0x100000000, 0x080000001, 1.7976931348623157e308, Number.MIN_VALUE, Math.PI, 1, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -1/0, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0.000000000000001, -0x100000001, -(2**53+2), 0x080000000, -0x080000000, -0x080000001, -0, 0]); ");
/*fuzzSeed-169986037*/count=1431; tryItOut("\"use strict\"; Array.prototype.shift.apply(a2, []);");
/*fuzzSeed-169986037*/count=1432; tryItOut("f2.toString = (function(j) { if (j) { try { this.a1[5] = x; } catch(e0) { } f1 = Proxy.createFunction(h2, f2, f1); } else { try { m0 + p2; } catch(e0) { } g1.h0.iterate = this.f0; } });");
/*fuzzSeed-169986037*/count=1433; tryItOut("/*oLoop*/for (var nscdmt = 0; nscdmt < 7; ++nscdmt) { v0 = Array.prototype.some.call(a2, (function(j) { if (j) { try { /*ODP-3*/Object.defineProperty(f1, \"valueOf\", { configurable: true, enumerable: null, writable: true, value: p2 }); } catch(e0) { } try { ; } catch(e1) { } try { h2.hasOwn = f1; } catch(e2) { } selectforgc(o1); } else { try { /*ADP-2*/Object.defineProperty(a2, v1, { configurable: false, enumerable: false, get: (function() { for (var j=0;j<6;++j) { f1(j%2==1); } }), set: (function(j) { f0(j); }) }); } catch(e0) { } try { m2.has(p1); } catch(e1) { } try { for (var v of b2) { f1(e1); } } catch(e2) { } g0.o0.a2.splice(-12, ({valueOf: function() { s1 = '';return 6; }}), s2); } })); } ");
/*fuzzSeed-169986037*/count=1434; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return mathy1((( + (((((Math.imul(((x >= x) >>> 0), Math.fround(( - (mathy1((2**53+2 | 0), (-0x080000001 | 0)) | 0)))) >>> 0) + y) | 0) >> (( ! (-Number.MIN_SAFE_INTEGER >>> 0)) >>> 0)) >>> 0)) >>> 0), Math.pow(((mathy2(((0x100000001 >> Math.fround(( + ( + ( + 1.7976931348623157e308))))) | 0), (Math.tanh(-0x100000001) | 0)) | 0) != (Math.hypot(x, (Math.sin(((( + (x | 0)) | 0) | 0)) | 0)) >>> 0)), (Math.hypot((x >>> 0), ((Math.max(( ~ 2**53+2), (y ? y : Math.log10(-0x0ffffffff))) <= y) >>> 0)) >>> 0))); }); testMathyFunction(mathy3, [0x07fffffff, -0x100000001, -(2**53-2), 0/0, 2**53, -(2**53), 0x080000001, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0, 2**53+2, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, 42, 1, Number.MIN_VALUE, 1.7976931348623157e308, Math.PI, 1/0, 0x080000000, -0x07fffffff, Number.MAX_VALUE, -0x100000000, 2**53-2, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, 0, 0x0ffffffff, -(2**53+2), -0x080000001, 0x100000001, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=1435; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.exp(Math.ceil((x === mathy1(( + (((( ~ y) | 0) & (y | 0)) | 0)), y)))); }); testMathyFunction(mathy3, [-0, -0x080000001, 0, -(2**53-2), 1/0, -(2**53+2), 0/0, 0.000000000000001, -0x080000000, -0x07fffffff, -1/0, 1, 2**53, 0x080000000, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_VALUE, -0x100000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MAX_VALUE, 42, -(2**53), Math.PI, Number.MIN_VALUE, 0x080000001, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, -0x100000000, 2**53-2, 0x0ffffffff, -0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=1436; tryItOut("(void version(180));");
/*fuzzSeed-169986037*/count=1437; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = \"\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1438; tryItOut("v2 = -Infinity;");
/*fuzzSeed-169986037*/count=1439; tryItOut("\"use strict\"; a0.unshift(o1);");
/*fuzzSeed-169986037*/count=1440; tryItOut("mathy2 = (function(x, y) { return ((mathy0(Math.fround(((x >>> 0) && Math.min(-(2**53+2), ( ~ Math.fround(x))))), (mathy1(((Math.cbrt((2**53 | 0)) | 0) >>> 0), (Math.atan2(x, x) >>> 0)) >>> 0)) , Math.fround(Math.cbrt(Math.fround(((Math.fround((x % (Math.asinh((Math.tanh((-(2**53+2) >>> 0)) >>> 0)) | 0))) , Math.fround(( + Math.max(Math.fround((y ^ ( + (y === x)))), (y >>> 0))))) >>> 0))))) | 0); }); testMathyFunction(mathy2, [1.7976931348623157e308, 42, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53), 2**53+2, 2**53-2, 0/0, -Number.MAX_SAFE_INTEGER, -0, 0.000000000000001, Number.MAX_VALUE, 0x0ffffffff, Math.PI, Number.MAX_SAFE_INTEGER, 0x080000000, -0x100000000, -Number.MAX_VALUE, Number.MIN_VALUE, 1/0, -(2**53-2), 0x100000000, -0x07fffffff, -0x100000001, -Number.MIN_VALUE, 0x07fffffff, -0x080000000, -1/0, -(2**53+2), 0, 0x100000001, -Number.MIN_SAFE_INTEGER, -0x080000001, 1, 2**53, 0x080000001]); ");
/*fuzzSeed-169986037*/count=1441; tryItOut("\"use strict\"; g2.offThreadCompileScript(\"(function ([y]) { })()\", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: x, noScriptRval: (4277), sourceIsLazy: (x % 4 != 2), catchTermination: true, element: o1, elementAttributeName: this.s0 }));");
/*fuzzSeed-169986037*/count=1442; tryItOut("\"use strict\"; { void 0; gcslice(183); }");
/*fuzzSeed-169986037*/count=1443; tryItOut("print(x);");
/*fuzzSeed-169986037*/count=1444; tryItOut("mathy0 = (function(x, y) { return ( ~ /*MARR*/[(void 0), new Boolean(false), (x) = y, (x) = y, -0x07fffffff, (void 0), 1.2e3, (x) = y, new Boolean(false), (void 0), (x) = y, (void 0), 1.2e3, -0x07fffffff, (x) = y, -0x07fffffff, new Boolean(false), (x) = y, new Boolean(false), -0x07fffffff, (x) = y, (void 0), new Boolean(false), (x) = y, -0x07fffffff, new Boolean(false), new Boolean(false), 1.2e3, -0x07fffffff, 1.2e3, (void 0), -0x07fffffff, new Boolean(false), (void 0), new Boolean(false), new Boolean(false), (void 0), -0x07fffffff, (x) = y, -0x07fffffff, 1.2e3, -0x07fffffff, 1.2e3, (x) = y, (x) = y, new Boolean(false), -0x07fffffff, (void 0), (x) = y, 1.2e3, (void 0), 1.2e3, -0x07fffffff, new Boolean(false), 1.2e3, (x) = y, 1.2e3, new Boolean(false), (x) = y, 1.2e3, new Boolean(false), (void 0), (void 0), (x) = y, (void 0), 1.2e3, new Boolean(false), (void 0), (void 0), (void 0), (void 0), (x) = y, -0x07fffffff, 1.2e3, (x) = y, 1.2e3, (void 0), (x) = y, (x) = y, new Boolean(false), (x) = y, (x) = y, (void 0), (x) = y, (x) = y, (void 0), 1.2e3, -0x07fffffff, (x) = y, 1.2e3, 1.2e3, (void 0), (x) = y, (void 0), -0x07fffffff, -0x07fffffff, (x) = y, new Boolean(false), (x) = y, 1.2e3, (void 0), (void 0), 1.2e3, (void 0), (void 0), (void 0), (void 0), (void 0), (void 0), 1.2e3, 1.2e3]); }); testMathyFunction(mathy0, [1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, 0x100000000, -Number.MIN_VALUE, 0x100000001, -Number.MIN_SAFE_INTEGER, 0, 0x0ffffffff, 0/0, -0x100000000, -0x100000001, 0x080000000, 1/0, Number.MIN_VALUE, Math.PI, -0x0ffffffff, -1/0, Number.MAX_SAFE_INTEGER, -(2**53-2), 42, 2**53-2, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, 0.000000000000001, 2**53, 0x07fffffff, -(2**53), 2**53+2, -0x080000001, -0, Number.MAX_VALUE, 0x080000001]); ");
/*fuzzSeed-169986037*/count=1445; tryItOut("\"use strict\"; testMathyFunction(mathy1, [2**53-2, 0x100000001, 0/0, 1, -0x07fffffff, -0x0ffffffff, Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, 42, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -Number.MAX_VALUE, Number.MAX_VALUE, 0x07fffffff, 0x080000000, 0.000000000000001, -Number.MIN_VALUE, 0x0ffffffff, -1/0, 0x080000001, -(2**53+2), 0x100000000, 1/0, 0, -(2**53), -0, 2**53, -0x100000001, Number.MIN_VALUE, -0x100000000, Number.MAX_SAFE_INTEGER, -0x080000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1446; tryItOut("o1.p0 + '';");
/*fuzzSeed-169986037*/count=1447; tryItOut("mathy4 = (function(x, y) { return (Math.abs(((((Math.fround(( + Math.cbrt((y >>> 0)))) | 0) != (Math.fround(( - Math.fround(Math.max(y, x)))) | 0)) | 0) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [0, Math.PI, 2**53-2, -0x07fffffff, -1/0, 2**53+2, 0x07fffffff, -0, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 2**53, 1.7976931348623157e308, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 0x080000000, 0/0, Number.MAX_SAFE_INTEGER, -0x080000000, -(2**53-2), -0x100000000, 1/0, -(2**53), 42, -Number.MAX_VALUE, Number.MIN_VALUE, 0x080000001, -Number.MIN_VALUE, -(2**53+2), 0x0ffffffff, 0x100000000, 1, 0x100000001, -0x080000001, 0.000000000000001, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1448; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -1073741825.0;\n    var d3 = 549755813889.0;\n    var i4 = 0;\n    return (((i4)+(0xfe15e216)))|0;\n  }\n  return f; })(this, {ff: function(q) { \"use strict\"; return q; }}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=1449; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (( + (( + mathy1(( + (((( ~ (Math.sqrt(y) | 0)) | 0) + ((mathy0(0x100000000, y) >>> 0) | 0)) | 0)), Math.fround((x & ( ! Math.hypot(y, x)))))) % Math.fround(Math.expm1(Math.fround(( ! -Number.MAX_SAFE_INTEGER)))))) <= Math.max(mathy2(Math.atan(mathy2(( + x), x)), ( ! Math.exp(1))), Math.log1p((Math.imul(Math.fround(mathy1(x, (( + ( + x)) >>> 0))), Math.fround(Math.exp((y | 0)))) >>> 0)))); }); testMathyFunction(mathy3, [0x0ffffffff, -0x07fffffff, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 0/0, 1/0, -Number.MAX_SAFE_INTEGER, -0x100000001, 0, -(2**53), -0x080000001, Math.PI, 42, -Number.MIN_VALUE, 0x100000001, -(2**53+2), -1/0, 0.000000000000001, -0x080000000, 2**53, Number.MAX_SAFE_INTEGER, 2**53-2, 0x07fffffff, -(2**53-2), -0, 1, 1.7976931348623157e308, Number.MAX_VALUE, 0x080000000, -Number.MAX_VALUE, -0x100000000, 2**53+2, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-169986037*/count=1450; tryItOut("o2.s0 + e1;");
/*fuzzSeed-169986037*/count=1451; tryItOut("var mmxgor = new ArrayBuffer(2); var mmxgor_0 = new Uint16Array(mmxgor); mmxgor_0[0] = 1; var mmxgor_1 = new Float64Array(mmxgor); mmxgor_1[0] = 26; var mmxgor_2 = new Int32Array(mmxgor); mmxgor_2[0] = 25; var mmxgor_3 = new Uint32Array(mmxgor); print(\"\\u71AB\");e0.delete(t1);h0 + '';this.g0.offThreadCompileScript(\"v2 = evalcx(\\\"Object.seal(g1);\\\", g1);\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (mmxgor_1 % 2 == 1), noScriptRval: false, sourceIsLazy: true, catchTermination: false }));yield;v0 = a1.every();(new RegExp(\"(\\\\t){17,19}\", \"gyim\"));var tuupko = new SharedArrayBuffer(6); var tuupko_0 = new Float64Array(tuupko); print(tuupko_0[0]); tuupko_0[0] = -12; v2 = (this.g1 instanceof h0);e2 + '';/*ADP-3*/Object.defineProperty(a2, 10, { configurable: false, enumerable: (mmxgor_1 % 29 == 23), writable: (mmxgor_1 % 100 != 16), value: p1 });/*bLoop*/for (let qbacfs = 0, /(?:(?=(?=[^\u00a5-\u3b8b\u00b9-\\ud44d\u0098-\u0e2e]|[\\d][^])+)|\\3)/gym; qbacfs < 72 && (false) && (undefined); ++qbacfs) { if (qbacfs % 19 == 15) { v0 = -0; } else { g0.o1 = Object.create(this.p1); }  } [1];");
/*fuzzSeed-169986037*/count=1452; tryItOut("mathy2 = (function(x, y) { return ( ! (Math.pow(( ! 1.7976931348623157e308), ( ~ x)) === Math.pow(y, Math.fround(( ~ Math.fround(((y >>> 0) * x))))))); }); testMathyFunction(mathy2, [Number.MIN_SAFE_INTEGER, 42, -0, 2**53+2, 0x07fffffff, -0x080000001, -0x0ffffffff, 1, 0x080000001, -0x080000000, -0x100000001, -Number.MAX_VALUE, 1/0, 0x0ffffffff, 0.000000000000001, -0x07fffffff, 0, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000000, -0x100000000, -Number.MAX_SAFE_INTEGER, 2**53-2, 2**53, -Number.MIN_VALUE, Math.PI, -(2**53), Number.MIN_VALUE, -1/0, Number.MAX_VALUE, 0/0, 1.7976931348623157e308, 0x100000001, 0x080000000, -(2**53-2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1453; tryItOut("\"use strict\"; a0.push(g2.a2);");
/*fuzzSeed-169986037*/count=1454; tryItOut("testMathyFunction(mathy0, [({toString:function(){return '0';}}), null, ({valueOf:function(){return 0;}}), false, '', undefined, (new Number(0)), (new Boolean(true)), '0', -0, /0/, '\\0', 0.1, 1, (new Boolean(false)), (new String('')), '/0/', objectEmulatingUndefined(), NaN, (function(){return 0;}), ({valueOf:function(){return '0';}}), [], (new Number(-0)), 0, true, [0]]); ");
/*fuzzSeed-169986037*/count=1455; tryItOut("mathy5 = (function(x, y) { \"use strict\"; return Math.pow((Math.hypot((mathy2((((-(2**53-2) | 0) !== (( ! (-(2**53-2) >>> 0)) >>> 0)) | 0), y) | 0), mathy4(( + ( ! (mathy0( '' , y) >>> 0))), ( + (Math.atan(x) + ((x , 0x080000000) | 0))))) | 0), Math.max((Math.log((( + y) >> ( ! ( + (Math.imul(((y >>> 0) - y), y) | 0))))) | 0), ( ! /*bLoop*/for (pvxmte = 0; pvxmte < 52; ++pvxmte) { if (pvxmte % 4 == 0) { t1[17]; } else { ( /x/ ); }  } ))); }); testMathyFunction(mathy5, [-0x07fffffff, Number.MIN_VALUE, -0x080000001, Number.MAX_VALUE, 0/0, -0x100000000, -0x100000001, -(2**53+2), 1.7976931348623157e308, 0.000000000000001, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, Number.MAX_SAFE_INTEGER, 1/0, -Number.MAX_VALUE, 2**53-2, 1, -(2**53-2), 42, 0x080000000, -0, 2**53+2, 0, 0x080000001, -0x080000000, 2**53, -1/0, 0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1456; tryItOut("\"use strict\"; /*oLoop*/for (var jkkrvx = 0, x = ((new Function(\"print(this **= 17);\"))).call(x, ); jkkrvx < 19; ++jkkrvx) { Array.prototype.unshift.call(a1, b1, f1);\na0.push(a1, o1.o1.m1);\n } ");
/*fuzzSeed-169986037*/count=1457; tryItOut("mathy4 = (function(x, y) { return (Math.ceil((Math.fround(( - Math.fround(Math.fround(mathy3(( + (Math.fround(x) >>> 0)), (x >>> 0)))))) << (Math.abs(Math.round((Math.hypot((y | 0), 0x080000001) | 0))) >>> 0))) <= ( + (((Math.acos(((Math.hypot(((Math.fround(y) >>> Math.fround(2**53)) >>> 0), (Math.fround(mathy0((x | 0), ( + Math.imul((x | 0), (x | 0))))) >>> 0)) >>> 0) >>> 0)) >>> 0) | 0) < Math.log2((x === y))))); }); testMathyFunction(mathy4, [(new Boolean(true)), undefined, 1, (new Boolean(false)), '', [], null, '0', (new String('')), false, ({valueOf:function(){return 0;}}), [0], 0.1, ({valueOf:function(){return '0';}}), '\\0', true, '/0/', -0, (new Number(-0)), objectEmulatingUndefined(), 0, NaN, (new Number(0)), (function(){return 0;}), ({toString:function(){return '0';}}), /0/]); ");
/*fuzzSeed-169986037*/count=1458; tryItOut("m1.has(h1);");
/*fuzzSeed-169986037*/count=1459; tryItOut("\"use strict\"; with({}) { let(c) { c.constructor;} } ");
/*fuzzSeed-169986037*/count=1460; tryItOut("mathy2 = (function(x, y) { return ((Math.fround(((( ! ((y === (Math.sinh(mathy1(( + Number.MAX_VALUE), y)) | 0)) >>> 0)) >>> 0) ? (( + (y / Math.fround(y))) << (mathy0((((-1/0 >>> 0) <= ((x ? Math.max(0x100000000, x) : (y >>> 0)) >>> 0)) | 0), mathy1((Math.atan2((y | 0), (x | 0)) | 0), x)) | 0)) : Math.hypot(Math.max(y, (Math.imul((y >>> 0), (( + ( + x)) >>> 0)) >>> 0)), Math.imul((( + Math.PI) >= (y >>> 0)), (-Number.MIN_SAFE_INTEGER >= x))))) >>> Math.fround((Math.max(( + Math.ceil(( + mathy1((Math.clz32(( + Math.tan(y))) | 0), mathy0(x, (y / 1)))))), (mathy1(Math.fround(Math.fround((Math.fround((Math.hypot(( + (Math.min((x | 0), (Math.atan2((x >>> 0), ( + y)) | 0)) | 0)), ( + ( + y))) >>> 0)) << Math.fround(Math.fround((Math.fround(x) ? Math.fround(y) : x)))))), ((( ! Number.MAX_SAFE_INTEGER) | 0) >>> 0)) >>> 0)) >>> 0))) | 0); }); testMathyFunction(mathy2, [2**53+2, 0x07fffffff, 0/0, 0x080000001, -0x100000000, Number.MIN_VALUE, 1, 0x0ffffffff, -1/0, Math.PI, -Number.MIN_VALUE, 42, -0x080000000, 1/0, -(2**53-2), 2**53-2, -0, 1.7976931348623157e308, 0.000000000000001, 2**53, 0, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000001, -0x080000001, -Number.MAX_VALUE, 0x100000000, -(2**53+2), Number.MAX_VALUE, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x080000000]); ");
/*fuzzSeed-169986037*/count=1461; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (( ~ (( ~ ((Math.max(((Math.atan2((Math.fround(Math.atan2(Math.fround(( ~ (( + Number.MIN_SAFE_INTEGER) ? y : y))), y)) >>> 0), (x >>> 0)) >>> 0) >>> 0), ((((x === y) >>> 0) <= 1/0) >>> 0)) >>> 0) | 0)) | 0)) | 0); }); testMathyFunction(mathy4, [2**53+2, -Number.MIN_VALUE, Number.MAX_VALUE, -0x080000000, 1, -0x0ffffffff, -(2**53+2), 0x100000001, -(2**53), 1.7976931348623157e308, 0x080000000, 0x0ffffffff, 0, -Number.MAX_VALUE, 1/0, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -1/0, -Number.MIN_SAFE_INTEGER, -0, 0x100000000, -0x100000001, 2**53-2, -0x07fffffff, 0.000000000000001, -0x080000001, Number.MIN_SAFE_INTEGER, -(2**53-2), Math.PI, 0x080000001, 2**53, 0/0, -0x100000000, 42, 0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1462; tryItOut("\"use asm\"; e0.has(g1)\nfor (var v of v2) { try { v1 = g2.runOffThreadScript(); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(s2, v0); } catch(e1) { } try { Array.prototype.reverse.apply(a2, []); } catch(e2) { } this.v1 = g1.runOffThreadScript(); }");
/*fuzzSeed-169986037*/count=1463; tryItOut("v0 = this.o1.g0.runOffThreadScript();");
/*fuzzSeed-169986037*/count=1464; tryItOut("\"use strict\"; for (var p in b1) { i1 = new Iterator(s0, true); }\nevalcx('')\n");
/*fuzzSeed-169986037*/count=1465; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (((( - Math.log1p(mathy0(x, x))) >>> 0) ? (Math.hypot(mathy3(( + mathy1(Number.MAX_VALUE, y)), ( - y)), (mathy1((Math.fround((((x | 0) ** (y | 0)) , (((Math.fround(( - y)) | 0) + y) | 0))) >>> 0), ( + mathy1(( + x), Math.log(( + mathy1(Math.fround(y), (x >>> 0))))))) >>> 0)) >>> 0) : (( ! (Math.tan(((mathy2(((mathy1(x, x) | 0) | 0), (((( ~ (0x100000001 | 0)) | 0) == x) >>> 0)) >>> 0) >>> 0)) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [-0, -0x07fffffff, 0x0ffffffff, 2**53-2, -Number.MIN_VALUE, 0/0, 0x100000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x100000001, 1, 42, -(2**53), -Number.MIN_SAFE_INTEGER, 1/0, -0x080000001, Number.MIN_SAFE_INTEGER, 0x080000001, 2**53, Math.PI, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000001, -0x100000000, 0x080000000, Number.MIN_VALUE, 0, -1/0, -0x0ffffffff, 1.7976931348623157e308, -Number.MAX_VALUE, -(2**53-2), -0x080000000, -(2**53+2), 2**53+2]); ");
/*fuzzSeed-169986037*/count=1466; tryItOut("\"use strict\"; for (var p in e2) { try { ; } catch(e0) { } try { print(h2); } catch(e1) { } e1.has(o0); }function x(x, ...x) { \"use strict\"; return (void options('strict_mode')) } print(x);");
/*fuzzSeed-169986037*/count=1467; tryItOut("abwgjy((Math.log2(7) / eval));/*hhh*/function abwgjy(...\u3056){m0.get(p0);}");
/*fuzzSeed-169986037*/count=1468; tryItOut("Array.prototype.push.apply(a2, [a2, g2.g0.h2, g2.t0]);");
/*fuzzSeed-169986037*/count=1469; tryItOut("\"use strict\"; m0.delete(i0);");
/*fuzzSeed-169986037*/count=1470; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.asin(Math.sinh(((Math.fround(((Math.pow(-Number.MIN_SAFE_INTEGER, x) ? (( + y) | 0) : Math.ceil(x)) ** mathy3(Math.fround(0/0), -Number.MAX_VALUE))) ? ((Math.atan((-0x100000000 >>> y)) ? y : ( ~ mathy1(y, y))) | 0) : x) | 0))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000000, 2**53-2, Math.PI, 1.7976931348623157e308, -1/0, 0x0ffffffff, 0/0, Number.MIN_VALUE, -(2**53+2), 1/0, 0.000000000000001, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, -Number.MAX_VALUE, 0, 0x100000000, -Number.MIN_VALUE, -0x0ffffffff, 0x080000001, 2**53+2, -0, -0x100000001, 42, -(2**53-2), 1, 2**53, -(2**53), 0x100000001, -Number.MAX_SAFE_INTEGER, -0x080000001, 0x07fffffff, -0x080000000, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1471; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var atan2 = stdlib.Math.atan2;\n  var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var i2 = 0;\n    i0 = ((((0x248ba4d2)+(i0))>>>((0xffffffff) / ((((0x9a5abd56) ? (0x144b4bf4) : (0xfd84e1d6))+((0x1f7bc2d9))+(0xf38ed4a8))>>>(x = Proxy.createFunction(({/*TOODEEP*/})(Math), (1 for (x in [])), e =>  { print(window); } ))))));\n    d1 = ((0xe0ad3670));\n    i0 = (i0);\n    d1 = (((Float32ArrayView[1])) / (((0x60f4272) ? (18446744073709552000.0) : (524289.0))));\n    {\n      {\n        d1 = (d1);\n      }\n    }\n    i0 = (((0x66cc4b3) ? ((i0) ? (0xf58aeff9) : (i0)) : (0x38309511)) ? (i0) : (i2));\n    d1 = (-1.9342813113834067e+25);\n    i2 = (0x1f318634);\n    {\n      d1 = (-((+atan2(((+(((0x5d52c2ee)) << ((0xad1b65f3))))), ((d1))))));\n    }\n    i2 = ((NaN) < (-4194303.0));\n    return ((((((((d1)))>>>(((0xf8a69fe6) ? (0xa2c2a2fa) : (0x9f2075d9)))) != ((((0xffffffff) ? (0xffffffff) : (0x43ed86bb)))>>>((i2)))) ? ((imul(((18014398509481984.0) <= ((0xfd489418) ? (-590295810358705700000.0) : (262144.0))), (i2))|0)) : (i2))))|0;\n  }\n  return f; })(this, {ff: let (fphvlv, d, nhvibu, culnod, kzfjpr) w}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53-2), 0/0, 2**53+2, -0x080000000, Number.MIN_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 0x100000000, Number.MIN_SAFE_INTEGER, 0x100000001, -0, 0, -1/0, 0.000000000000001, -(2**53+2), 0x07fffffff, -Number.MAX_SAFE_INTEGER, 0x080000001, Number.MAX_VALUE, 1.7976931348623157e308, -(2**53), -0x080000001, -0x07fffffff, -Number.MAX_VALUE, 42, Math.PI, 1, 2**53-2, -0x0ffffffff, 0x0ffffffff, Number.MAX_SAFE_INTEGER, 2**53, -Number.MIN_VALUE, -0x100000001, 1/0, 0x080000000]); ");
/*fuzzSeed-169986037*/count=1472; tryItOut("throw NaN;function \u3056([]) { \"use strict\"; yield Math.tanh(5) } v1 = evalcx(\"Math\", g1);function NaN() { {/*vLoop*/for (let xmqgth = 0; xmqgth < 39; ++xmqgth) { x = xmqgth; print(x); } {const g0.a1 = a1.map((function(j) { if (j) { s2 + ''; } else { try { t2[/((.(?=\\b)))|[^](?:\\S)*(?!(?=.))|\\B*(?!\\cA(?:(?=\\w)){2,6})/gm] =  '' ; } catch(e0) { } g0.offThreadCompileScript(\"function f1(m1)  { print(m1); } \", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 5 == 4), noScriptRval: this, sourceIsLazy: true, catchTermination: (x % 23 != 1) })); } }), g0, s2); } } } for (var v of i2) { try { a0[19] = new (/*RXUE*//^|\\f|[^]?($)|[\\w][\\x39]|\\s{2}|\\B{0}/gyi.exec(\"O1\\udc7d  \"))(/*FARR*/[...[], , ...[], true].filter(x, /(\\B+?){4,}/)); } catch(e0) { } try { Object.defineProperty(this, \"e2\", { configurable: true, enumerable: false,  get: function() {  return new Set(m0); } }); } catch(e1) { } try { v0 = Object.prototype.isPrototypeOf.call(h0, b2); } catch(e2) { } s0 += 'x'; }");
/*fuzzSeed-169986037*/count=1473; tryItOut("\"use strict\"; m1 = new Map(this.s2);");
/*fuzzSeed-169986037*/count=1474; tryItOut("while(((x.eval(\"o1 = a2[12];\"))) && 0)Object.defineProperty(this, \"a2\", { configurable: true, enumerable: true,  get: function() {  return a2.map((function() { try { v0 = (m0 instanceof e0); } catch(e0) { } v2 = this.g0.runOffThreadScript(); return i2; }), t1); } });");
/*fuzzSeed-169986037*/count=1475; tryItOut("i0 + '';");
/*fuzzSeed-169986037*/count=1476; tryItOut("mathy1 = (function(x, y) { return ( ! Math.fround(( + Math.atan2((((y >>> 0) << (x !== x)) >>> 0), ( + (( + (( + x) ? ( + (Math.atan2((( - (x , Number.MIN_SAFE_INTEGER)) >>> 0), -Number.MAX_SAFE_INTEGER) >>> 0)) : Math.fround(x))) !== mathy0(Math.atan(y), Math.fround(( + Math.fround(42)))))))))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0x080000000, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000001, 1, 0/0, 1/0, Number.MIN_SAFE_INTEGER, 42, -0x080000001, -0x0ffffffff, -0, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 2**53, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0, 0x100000000, -0x080000000, -0x07fffffff, 0.000000000000001, 2**53+2, -(2**53), 0x07fffffff, 0x0ffffffff, Number.MIN_VALUE, -(2**53-2), -(2**53+2), -0x100000000, 2**53-2, 1.7976931348623157e308, Math.PI]); ");
/*fuzzSeed-169986037*/count=1477; tryItOut("do t1 = new Uint16Array(9); while((new (({max: x, toString: /*FARR*/[-3, null, \"\\u5014\",  /x/g ].sort }))(x)) && 0);");
/*fuzzSeed-169986037*/count=1478; tryItOut("this.o2 = Object.create(this.o2.i1);");
/*fuzzSeed-169986037*/count=1479; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return (Math.abs(( ~ (((Math.fround(Math.atanh(( - Math.fround(Math.max(Math.fround(-0x07fffffff), Math.fround(-0x0ffffffff)))))) >> Math.exp(y)) | 0) | 0))) | 0); }); testMathyFunction(mathy4, [1/0, Math.PI, Number.MAX_VALUE, 0x07fffffff, -0x100000000, 0x080000000, 0x100000001, 1.7976931348623157e308, 42, -1/0, -0x0ffffffff, Number.MIN_VALUE, -0x07fffffff, 2**53-2, -(2**53-2), 0/0, 2**53+2, -0x100000001, Number.MIN_SAFE_INTEGER, 1, -(2**53+2), -Number.MAX_VALUE, -0x080000000, -(2**53), 2**53, -Number.MIN_VALUE, -0x080000001, 0x080000001, -0, 0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, 0.000000000000001, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1480; tryItOut("v1 + this.o0.o2;");
/*fuzzSeed-169986037*/count=1481; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.pow(Math.fround((Math.tan((( - ((Math.atan2((x | 0), (y | 0)) | 0) >= ((-Number.MIN_VALUE ** (x >>> 0)) >>> 0))) | 0)) | 0)), Math.fround(Math.hypot(mathy1(( + (y , ( + ((((x >>> 0) == (0/0 >>> 0)) >>> 0) > Math.max(y, y))))), ( + (Math.fround(y) >>> 0))), Math.log2(((mathy0(y, x) | 0) | 0)))))); }); testMathyFunction(mathy4, [[0], false, '0', undefined, /0/, (new Number(-0)), ({valueOf:function(){return 0;}}), '/0/', null, [], '', (new Number(0)), (function(){return 0;}), 0.1, true, (new Boolean(true)), ({valueOf:function(){return '0';}}), objectEmulatingUndefined(), '\\0', 0, 1, NaN, (new Boolean(false)), ({toString:function(){return '0';}}), -0, (new String(''))]); ");
/*fuzzSeed-169986037*/count=1482; tryItOut("t2 = new Uint8ClampedArray(b0, 128, ({valueOf: function() { /*RXUB*/var r = /(\\2)(?=(?=(?!(?!^))){3}([^])+{2}{3,6}{3}+?)/gyi; var s = new (neuter)( \"\" , \"\\u7043\"); print(uneval(r.exec(s))); return 5; }}));");
/*fuzzSeed-169986037*/count=1483; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( - (( ~ ((mathy0(Math.cosh(x), Math.imul(x, (( + (x >>> 0)) >>> 0))) | 0) >>> 0)) >>> 0)); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [], Math.PI, Math.PI, [], [], Math.PI, [], Math.PI, [], [], [], objectEmulatingUndefined(), [], [], objectEmulatingUndefined(), Math.PI, [], [], Math.PI, objectEmulatingUndefined(), [], objectEmulatingUndefined(), [], Math.PI, Math.PI, [], Math.PI, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Math.PI, [], objectEmulatingUndefined(), objectEmulatingUndefined(), [], objectEmulatingUndefined(), objectEmulatingUndefined(), Math.PI, objectEmulatingUndefined(), Math.PI, Math.PI, Math.PI, objectEmulatingUndefined(), Math.PI, objectEmulatingUndefined(), Math.PI, [], Math.PI, [], [], objectEmulatingUndefined(), objectEmulatingUndefined(), [], [], [], objectEmulatingUndefined(), [], [], [], objectEmulatingUndefined(), objectEmulatingUndefined(), Math.PI, objectEmulatingUndefined(), objectEmulatingUndefined(), Math.PI, Math.PI, Math.PI, [], objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), Math.PI, objectEmulatingUndefined(), [], Math.PI, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), [], Math.PI, objectEmulatingUndefined()]); ");
/*fuzzSeed-169986037*/count=1484; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.ceil(((Math.acos((( + (Math.fround(y) % Math.fround(Math.fround(Math.atan(x))))) >>> 0)) >>> 0) & (( ~ ( ! Math.fround(( ! x)))) ? ((( ! (x >>> 0)) >>> 0) | 0) : Math.hypot(-0x080000001, y))))); }); ");
/*fuzzSeed-169986037*/count=1485; tryItOut("\"use strict\"; o2.v1 = a1.every(f2);");
/*fuzzSeed-169986037*/count=1486; tryItOut("\"use strict\"; a2[7] = (y -= e);");
/*fuzzSeed-169986037*/count=1487; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = ((((0x57d3dd30)+((((!(0xffffffff))+((((0x28c67af6))>>>((-0x8000000)))))|0))) & ((0xff2f4402))) != (((Float32ArrayView[((((i1)) >> ((0xfe731090)+(-0x8000000))) / (abs((((-0x8000000)) | ((-0x8000000))))|0)) >> 2]))|0));\n    }\n    return +((Float64ArrayView[1]));\n  }\n  return f; })(this, {ff: x}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [42, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0/0, -Number.MIN_VALUE, 0x080000001, 0x100000000, 0.000000000000001, -0x07fffffff, 2**53, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -0x100000000, 1/0, 2**53-2, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, 1.7976931348623157e308, 0x080000000, -0x100000001, 2**53+2, -(2**53+2), 0, -0x080000001, -0x080000000, -0, -(2**53), 0x100000001, -1/0, Number.MIN_VALUE, Math.PI, 1]); ");
/*fuzzSeed-169986037*/count=1488; tryItOut("o1.a1 = (let (e=eval) e);");
/*fuzzSeed-169986037*/count=1489; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var pow = stdlib.Math.pow;\n  var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    d0 = (d1);\n    switch ((((-0x8000000)) << ((0x792edee)-(0x4101c939)))) {\n    }\n    {\n      d1 = (+(-1.0/0.0));\n    }\n    d0 = ((+(((0xffffffff)-((~~(d1))))>>>(((Infinity) == (((-1.2089258196146292e+24)) / ((-576460752303423500.0))))+(!((((0x97236904)-(0x48a5aaf4)-(0xfdd70f59)) << ((0xe17f2ec3)-(0x5c86604c)+(0xf456ea38)))))))) + (+((((d1)) / ((d0))))));\n    return ((((~~(+((((5.0) > (8191.0))+(0x80166056)) >> ((-0xb34b9a)-((0x401044c2))-((0x18c76ea7)))))) < ((((0x99bc9245) ? (0xde7ef61e) : (0x8676822a))+(/*FFI*/ff(((((Int32ArrayView[0])) >> ((0xd7f9c7a1)-(0x86580ccb)))), ((~(((0x685646d5) >= (0x6167434f))))), ((((0xfedb4fcb)) ^ ((0xbe5f92b7)))), ((16385.0)), ((2.4178516392292583e+24)), ((17592186044417.0)), ((137438953473.0)))|0)-(0xbc40f120))|0))-((-0x8000000) ? (0x89de47ec) : (-0x8000000))))|0;\n    (Float32ArrayView[4096]) = ((d1));\n    {\n      d0 = (+pow(((+(((0x31964f8)-((((0xffffffff)) | ((0xfed3e8aa))) < (0x50eba4dc)))>>>(-((Infinity) > (+(1.0/0.0))))))), ((+(0.0/0.0)))));\n    }\n    d0 = (d1);\n    d0 = (d0);\n    return ((-0x4e26f*(0x3dc3a08f)))|0;\n    return (((0xffffffff)+(0x9f057f90)))|0;\n  }\n  return f; })(this, {ff: encodeURI}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-Number.MAX_VALUE, 0x07fffffff, -(2**53+2), 0x0ffffffff, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53), -0x080000001, 2**53+2, -0x100000001, 1, 0.000000000000001, 42, 1.7976931348623157e308, 0, -0, -0x0ffffffff, -(2**53-2), 1/0, -0x100000000, 0x080000000, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0, -Number.MIN_VALUE, Math.PI, -0x080000000, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x100000000, 2**53-2, -1/0, 0x080000001, 2**53, 0x100000001, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=1490; tryItOut("\"use strict\"; testMathyFunction(mathy3, [0x080000001, 0x080000000, 2**53-2, 2**53, 0.000000000000001, 0x07fffffff, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 0/0, -Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 2**53+2, -0x0ffffffff, 42, -Number.MIN_VALUE, 0, 1, -(2**53-2), -0, 0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, -0x100000000, 1/0, -0x07fffffff, -0x080000000, Math.PI, -(2**53), -(2**53+2), -0x080000001, -0x100000001, 0x100000000, -Number.MIN_SAFE_INTEGER, -1/0]); ");
/*fuzzSeed-169986037*/count=1491; tryItOut("\"use strict\"; v0 = (a1 instanceof s0);");
/*fuzzSeed-169986037*/count=1492; tryItOut("\"use strict\"; yield x /= x;");
/*fuzzSeed-169986037*/count=1493; tryItOut("e1.delete(b2);");
/*fuzzSeed-169986037*/count=1494; tryItOut("/*hhh*/function dogotz(z = w, eval = [1,,]){m1.has(this.o0.o0.b1);}dogotz( \"\" );");
/*fuzzSeed-169986037*/count=1495; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.pow(Math.exp(0x100000000), ((y !== Math.PI) , Math.acosh((x | 0)))) === (( + (( ! ( + x)) >>> 0)) >>> 0)); }); testMathyFunction(mathy0, [-0x080000001, 2**53-2, -(2**53), -0x080000000, -(2**53-2), 0x0ffffffff, 0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000001, 0.000000000000001, -(2**53+2), -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, Math.PI, 2**53, -Number.MAX_SAFE_INTEGER, 42, 0/0, -0, 0x100000000, 1/0, 1, 1.7976931348623157e308, 2**53+2, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, -0x100000000]); ");
/*fuzzSeed-169986037*/count=1496; tryItOut("\"use strict\"; ;\nyield \u3056;\n");
/*fuzzSeed-169986037*/count=1497; tryItOut("h2.valueOf = (function() { try { s0 = this.s0.charAt(1); } catch(e0) { } f2(b2); return g0.v1; });");
/*fuzzSeed-169986037*/count=1498; tryItOut("\"use strict\"; v0 = evaluate(\"(Math.pow(10, -25))\", ({ global: g2, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: /*MARR*/[new String('q'), [], [], [], function(){}, [], -0x100000001, -0x100000001, new String('q'), new String('q'), [], [], function(){}, [], [], [], [], [], [], [], [], [], [], [], [], function(){}, new String('q'), new String('q'), new String('q'), new String('q'), [], -0x100000001, -0x100000001, new String('q'), -0x100000001, new String('q'), function(){}, new String('q'), [], function(){}, function(){}, -0x100000001, function(){}, -0x100000001, function(){}, function(){}, function(){}, -0x100000001, function(){}, -0x100000001, function(){}], sourceIsLazy: false, catchTermination:  /x/  }));function y(eval = (Math.sin(/\\b|[^]\\2|\u3f9b?$|\\b(?![^])?|\\b{2,2}+?/gi))) { return x << 20 } e1.has(Math.atan(-6));");
/*fuzzSeed-169986037*/count=1499; tryItOut("/* no regression tests found */");
/*fuzzSeed-169986037*/count=1500; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=1501; tryItOut("[1];");
/*fuzzSeed-169986037*/count=1502; tryItOut("var cipind = new SharedArrayBuffer(8); var cipind_0 = new Uint16Array(cipind); print(cipind_0[0]); cipind_0[0] = -22; var cipind_1 = new Uint32Array(cipind); var cipind_2 = new Float64Array(cipind); print(cipind_2[0]); cipind_2[0] = 2; var cipind_3 = new Uint32Array(cipind); cipind_3[0] = 15; var cipind_4 = new Uint8Array(cipind); print(cipind_4[0]); cipind_4[0] = 23; var cipind_5 = new Int32Array(cipind); print(cipind_5[0]); var cipind_6 = new Float64Array(cipind); b1.__proto__ = b1;v1 = o2.r1.flags;;;t1[7] = -16;x = g2; /x/g  = g1.a0[5];s0.toString = (function() { t2 = new Uint8ClampedArray(t0); return b2; });print(cipind_2[2]);a1.shift(i2, t2);print(cipind_4[0]);");
/*fuzzSeed-169986037*/count=1503; tryItOut("\"use strict\"; /*oLoop*/for (var zjxrix = 0, ((yield \"\u03a0\")); zjxrix < 115; ++zjxrix) { print(x); } ");
/*fuzzSeed-169986037*/count=1504; tryItOut("m0.has(e2);p0.toString = (function() { try { print(b2); } catch(e0) { } try { /*MXX3*/g0.Date.prototype.getFullYear = g0.Date.prototype.getFullYear; } catch(e1) { } try { this.b2 = new ArrayBuffer(15); } catch(e2) { } m0.set(p0, f1); return m1; });");
/*fuzzSeed-169986037*/count=1505; tryItOut("function shapeyConstructor(qsgbhz){this[\"wrappedJSObject\"] = new Number(1);return this; }/*tLoopC*/for (let x of []) { try{let ewcyoi = shapeyConstructor(x); print('EETT'); f0(m1);}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-169986037*/count=1506; tryItOut("\"use strict\"; {print(x); }");
/*fuzzSeed-169986037*/count=1507; tryItOut("v2 = Array.prototype.reduce, reduceRight.call(a1, arguments.callee,  \"\" );");
/*fuzzSeed-169986037*/count=1508; tryItOut("s2 = new String(v1);");
/*fuzzSeed-169986037*/count=1509; tryItOut("mathy4 = (function(x, y) { \"use strict\"; return Math.asinh(Math.fround(((( + (mathy3(mathy1(((x >> (y >>> 0)) >>> 0), x), x) | 0)) | 0) !== ( ! ((Math.cosh((x | 0)) | 0) >> (mathy1(y, (( - Math.fround(x)) ? (y | 0) : (x | 0))) | 0)))))); }); testMathyFunction(mathy4, [0x100000001, -0x080000001, -0, 0/0, 0x080000001, -Number.MAX_VALUE, -(2**53-2), 42, 0.000000000000001, -(2**53+2), 0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53+2, -0x080000000, -(2**53), 1, -Number.MAX_SAFE_INTEGER, -1/0, -0x100000001, 0x080000000, 2**53-2, 0, Math.PI, Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_VALUE, 0x07fffffff, 2**53, -0x100000000, -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308]); ");
/*fuzzSeed-169986037*/count=1510; tryItOut("\"use strict\"; a2.splice(13, 2, m2);");
/*fuzzSeed-169986037*/count=1511; tryItOut("eval = linkedList(eval, 3150);");
/*fuzzSeed-169986037*/count=1512; tryItOut("g1.v0 = (s0 instanceof m2);");
/*fuzzSeed-169986037*/count=1513; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var imul = stdlib.Math.imul;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    var d2 = -5.0;\n    var d3 = 32769.0;\n    switch ((abs((imul((0xfd53bd04), (0xf85410e6))|0))|0)) {\n    }\n    d2 = (+atan2(((abs((0x1e86b197))|0)), ((128.0))));\n    /*FFI*/ff(((+abs(((-9007199254740991.0))))), (((((+/*FFI*/ff(((~((0xffdf4e09)+(0xfa4a4192)-(0x1e4c586)))))) + (d3))))), ((d2)), ((~((((0xffffffff))>>>((0xffffffff))) % (0xae7ab4f8)))), ((-0.0625)), ((d3)), ((+((7.555786372591432e+22)))), ((72057594037927940.0)), ((-9223372036854776000.0)), ((0.00390625)), ((-2147483648.0)), ((7.737125245533627e+25)), ((-32767.0)), ((-17179869184.0)), ((-2305843009213694000.0)), ((-1125899906842624.0)), ((-2.4178516392292583e+24)));\n    {\n      i1 = ((8796093022207.0));\n    }\n    /*FFI*/ff(((17.0)), ((~~(2097151.0))));\n    return +((d3));\n  }\n  return f; })(this, {ff: Date.prototype.setFullYear}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=1514; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var atan2 = stdlib.Math.atan2;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    return +((Infinity));\n    {\n      i1 = (0xbca04406);\n    }\n    i1 = ((0x7fffffff) <= (((0x4a7d9c99)+(i1)) & ((!((0x77ea87c7) ? (0x2d2d74a1) : (0xfce0f2de)))-(i1))));\n    {\n      (Float32ArrayView[((0xffffffff)) >> 2]) = (((((((((0xbd6eabb6)+(0x9c8255dc)+(0xff4498f3)) << ((0xff9ec959)+(0xfa734e82)+(0x1750c029))))) >> ((i1)+(/*FFI*/ff()|0)))) ? (((0xe6506e32) ? (i1) : (i1)) ? (0x6dccfabf) : ((0x1d7988a2) <= (0xe37662d4))) : (0xffffffff)));\n    }\n    d0 = (-4194305.0);\n    i1 = (i1);\n    (Float32ArrayView[((-0x8000000)+(i1)-((0xba012373) < (((-0x8000000))>>>((0xfd58e83d))))) >> 2]) = ((-((Float64ArrayView[4096]))));\n    d0 = (+(1.0/0.0));\n    {\n      d0 = (+(((((4277)) != (((+pow(((-2199023255553.0)), ((8589934593.0))))) / ((NaN))))*-0xfffff)>>>(-((-18446744073709552000.0) > (+(((0x5fc53d62)) | ((i1))))))));\n    }\n    d0 = (+atan2(((3.094850098213451e+26)), ((((d0)) % ((-4.835703278458517e+24))))));\n    return +((-295147905179352830000.0));\n  }\n  return f; })(this, {ff: function(y) { yield y; if(\"\u03a0\") (window); else {s0 = ''; }; yield y; }}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -(2**53+2), 0x100000001, 0x080000000, 42, -Number.MAX_VALUE, Math.PI, 0x07fffffff, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -(2**53-2), 1.7976931348623157e308, -0x0ffffffff, 2**53+2, -0, -0x100000000, 0.000000000000001, 0x100000000, -0x080000001, -1/0, 0x0ffffffff, 2**53, Number.MIN_VALUE, 0, 1/0, -Number.MIN_VALUE, 0x080000001, -0x07fffffff, 2**53-2, 0/0, -0x100000001, 1, -0x080000000]); ");
/*fuzzSeed-169986037*/count=1515; tryItOut("\"use strict\"; Array.prototype.splice.apply(a2, [NaN, 13, t2, s1]);");
/*fuzzSeed-169986037*/count=1516; tryItOut("\"use strict\"; /*bLoop*/for (let ifwumf = 0; ifwumf < 8; ++ifwumf) { if (ifwumf % 57 == 39) { /* no regression tests found */ } else { b0 = t2.buffer; }  } ");
/*fuzzSeed-169986037*/count=1517; tryItOut("testMathyFunction(mathy5, [-1/0, 2**53-2, 0.000000000000001, 0x0ffffffff, -0x100000001, 1.7976931348623157e308, -(2**53-2), Math.PI, -Number.MAX_VALUE, -0x0ffffffff, -0x080000001, -0, Number.MAX_SAFE_INTEGER, 0x100000000, 1/0, Number.MIN_SAFE_INTEGER, 0x07fffffff, 2**53+2, -0x07fffffff, 2**53, 0x100000001, -(2**53+2), 0, 0x080000001, Number.MIN_VALUE, 0/0, -0x080000000, 42, Number.MAX_VALUE, -0x100000000, -Number.MIN_SAFE_INTEGER, 1, -(2**53), -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-169986037*/count=1518; tryItOut("(/*UUV1*/(eval.now = OSRExit).valueOf(\"number\") != ((function factorial_tail(cnsfih, fkfwom) { ; if (cnsfih == 0) { ; return fkfwom; } /* no regression tests found */; return factorial_tail(cnsfih - 1, fkfwom * cnsfih); print(x); })(71935, 1)) += (arguments.callee)(new (delete b\u000c.a.watch(\"prototype\", function shapeyConstructor(jpsqkc){Object.defineProperty(this, \"tanh\", ({value: [1,,], writable: (x % 3 != 0), enumerable:  /x/ }));Object.freeze(this);if (jpsqkc) for (var ytqsorkcr in this) { }if (\"\\u49C8\") { Object.preventExtensions(v1); } if (jpsqkc) { (7); } this[\"apply\"] = 0x080000001;this[\"z\"] = q => q;return this; }))(true, ( '' (/(?!\\3)/yim, \"\\u0087\")[\"__proto__\"]|=new /$|\\b|(?:[^]|d|\\b\\B{2}){2,}+/(a0 = Array.prototype.slice.call(a2, NaN, -14);, window)))));");
/*fuzzSeed-169986037*/count=1519; tryItOut("\"use asm\"; m2 = new Map(v0);");
/*fuzzSeed-169986037*/count=1520; tryItOut("let (enfhcj) { print(x); }");
/*fuzzSeed-169986037*/count=1521; tryItOut("\"use strict\"; (());");
/*fuzzSeed-169986037*/count=1522; tryItOut("\"use strict\"; o1 = new Object;");
/*fuzzSeed-169986037*/count=1523; tryItOut("mathy2 = (function(x, y) { return ( - Math.fround((Math.max(x, (Math.ceil(((y % -0x07fffffff) >>> 0)) >>> 0)) >>  /x/ ))); }); testMathyFunction(mathy2, [1.7976931348623157e308, 2**53, Number.MIN_SAFE_INTEGER, -0x100000000, 1/0, 0.000000000000001, -1/0, 0/0, 0x080000000, Number.MIN_VALUE, -0x080000001, 42, -(2**53+2), -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1, 0x080000001, 2**53+2, 0x07fffffff, -0x100000001, -Number.MAX_SAFE_INTEGER, 0, -(2**53-2), Math.PI, -(2**53), -0, 2**53-2, Number.MAX_VALUE, -Number.MIN_VALUE, 0x100000001, -0x07fffffff, -0x0ffffffff, -0x080000000, 0x0ffffffff, 0x100000000, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1524; tryItOut("\"use strict\"; mlvutd();/*hhh*/function mlvutd(w, x){;}");
/*fuzzSeed-169986037*/count=1525; tryItOut("const y = NaN - x, w, z, x = let (x = \"\\u92FF\", gohctt, e, yietze, qzfdcl, x, pvisvp, NaN, e, NaN) Math.pow(-24,  '' ), a, eval = window ^ \"\\u586B\";this.zzz.zzz;");
/*fuzzSeed-169986037*/count=1526; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(?=\\\\\\u000f*|((?=[^\\\\S\\\\ri]{1}))*|((?=[^]\\\\d{1,3}))([^\\\\W\\\\W]*)(?=[^\\u722c-\\ua11e]|$)|(?:\\\\b){0,1}?*)\", \"gyi\"); var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1527; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + ( ! ( + Math.max(( - Math.tanh(-0)), ( ! (Math.sign((0x080000001 >>> 0)) | 0)))))); }); testMathyFunction(mathy0, [0x07fffffff, -0, -0x080000001, 0/0, -0x080000000, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -(2**53), -1/0, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, -0x100000001, 0x080000000, -Number.MAX_SAFE_INTEGER, 1, -0x100000000, Number.MAX_VALUE, -(2**53+2), Math.PI, 42, Number.MIN_SAFE_INTEGER, 1/0, 0, 2**53-2, 0x100000000, -(2**53-2), 0.000000000000001, 1.7976931348623157e308, 2**53, -0x0ffffffff, 0x080000001, 2**53+2, 0x0ffffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-169986037*/count=1528; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var pow = stdlib.Math.pow;\n  var NaN = stdlib.NaN;\n  var imul = stdlib.Math.imul;\n  var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      i1 = (i1);\n    }\n    d0 = (+pow(((+/*FFI*/ff(((~~(((+(0.0/0.0))) * ((NaN))))), ((imul((i1), (-0x8000000))|0)), ((((((0xffffffff))>>>((0xfe80a267))) % (0xac50f3da)) ^ (((imul((0x7f2e3a4), (0xd4ffd3c9))|0))-(i1)))), ((((-0x8000000)+(0xf8f9f7af)+(0xff0e4585)) >> (0xee489*((0xa9d31b53) >= (0x322b6f93)))))))), ((d0))));\n    d0 = (Infinity);\n    return (((0xfae737aa)-(0xd283fc70)))|0;\n    return (((0x31d4e347)+(0x56fe5a2)))|0;\n  }\n  return f; })(this, {ff: (Math.sign(timeout(1800)))}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-169986037*/count=1529; tryItOut("Array.prototype.unshift.call(a0, p2, t1);");
/*fuzzSeed-169986037*/count=1530; tryItOut("mathy4 = (function(x, y) { return Math.fround(((Math.acos(Math.fround(Math.pow(mathy2(0x080000000, Math.atan2(y, Math.acos(0x080000000))), (Math.fround(Math.imul(Math.fround(mathy1((0x0ffffffff || y), (y << 1.7976931348623157e308))), Math.fround(x))) >>> 0)))) | 0) >= (mathy3(Math.fround(Math.imul(Math.fround(((( + Math.pow(( + y), y)) >>> 0) <= x)), ((y >>> 0) * (Math.tanh(y) >>> 0)))), (Math.atan2((((mathy3((( + mathy3((y >>> 0), (y >>> 0))) | 0), (Math.log1p((y | 0)) | 0)) | 0) != Math.round(-0x100000000)) >>> 0), Math.log2((Math.max((0.000000000000001 >>> 0), (Math.imul(x, y) >>> 0)) >>> 0))) >>> 0)) | 0))); }); testMathyFunction(mathy4, [-(2**53+2), -0x080000001, -0x100000001, -0x100000000, Number.MAX_VALUE, 0x100000001, -0x07fffffff, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, -0x080000000, 0x07fffffff, -(2**53-2), 0.000000000000001, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -(2**53), 2**53-2, 2**53, Math.PI, 1/0, 0x080000000, -0x0ffffffff, 1, 0x100000000, 42, Number.MIN_VALUE, 2**53+2, -Number.MAX_VALUE, 0x0ffffffff, 0x080000001, -1/0, 0, Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-169986037*/count=1531; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.fround((Math.fround((Math.fround(( ! Math.ceil(( + mathy2((2**53-2 ? x : Math.hypot((x >>> 0), Math.fround(x))), (Math.min((y >>> 0), (x >>> 0)) >>> 0)))))) < Math.fround(( + ( ! (x >>> 0)))))) >> Math.fround(Math.min(Math.imul((( ! (0x100000001 >>> 0)) >>> 0), Math.fround(( ! Math.fround(Math.abs(Math.fround(y)))))), (((( ! Math.fround(mathy0(Math.fround(y), Math.fround(( + ( + 42)))))) | 0) / (y | 0)) | 0))))); }); testMathyFunction(mathy3, [Math.PI, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 42, -(2**53), 0x100000000, Number.MIN_SAFE_INTEGER, -0x100000000, 0x080000001, Number.MAX_VALUE, 0/0, 0x080000000, -Number.MAX_VALUE, 0, Number.MIN_VALUE, -0x080000000, -0, -1/0, -0x07fffffff, 0x07fffffff, 2**53-2, 1/0, 0x0ffffffff, -0x0ffffffff, -0x100000001, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x100000001, -0x080000001, 0.000000000000001, -(2**53+2), 1, 1.7976931348623157e308, 2**53+2, 2**53]); ");
/*fuzzSeed-169986037*/count=1532; tryItOut("v0 = Object.prototype.isPrototypeOf.call(t1, b0);");
/*fuzzSeed-169986037*/count=1533; tryItOut("s1 += 'x';");
/*fuzzSeed-169986037*/count=1534; tryItOut("\"use strict\"; /*iii*/print(x);/*hhh*/function fjhstd(\u3056){Array.prototype.splice.call(g2.g2.o2.a0, NaN, 18, e1, p1);}with({}) { let(x = (4277), y, wiklja, a, x, x = (void options('strict')), d = \"\\u172D\", mynvrv) ((function(){DataView.prototype = y;})()); } ");
/*fuzzSeed-169986037*/count=1535; tryItOut("\"use strict\"; t0 = new Uint8ClampedArray(t2);");
/*fuzzSeed-169986037*/count=1536; tryItOut("mathy2 = (function(x, y) { return Math.asin((( - (Math.pow(mathy1(((Math.fround(Math.hypot(Math.fround(x), (x | 0))) ? ( + (mathy0((Math.cbrt(y) >>> 0), (( ! ( + x)) >>> 0)) >>> 0)) : y) >>> 0), (x >>> 0)), x) | 0)) | 0)); }); ");
/*fuzzSeed-169986037*/count=1537; tryItOut("mathy5 = (function(x, y) { return Math.hypot(Math.max(Math.clz32(( + Math.sqrt(( + ( - (( ~ 0x080000000) === Math.fround(y))))))), (mathy4((Math.min(( + Math.exp(( + (((y >>> 0) !== (0x080000001 >>> 0)) >>> 0)))), Math.PI) >>> 0), ((mathy3((((y | 0) * (x | 0)) | 0), (Math.asinh((x >>> 0)) >>> 0)) >>> 0) >>> 0)) | 0)), Math.atan2(((Math.asinh(y) >>> 0) >>> 0), ( ! ( + y)))); }); testMathyFunction(mathy5, /*MARR*/[false]); ");
/*fuzzSeed-169986037*/count=1538; tryItOut("/*ODP-1*/Object.defineProperty(this.f2, \"getInt16\", ({enumerable: (x % 6 == 1)}));");
/*fuzzSeed-169986037*/count=1539; tryItOut("\"use strict\"; yield window;v2 = Object.prototype.isPrototypeOf.call(s0, h1);");
/*fuzzSeed-169986037*/count=1540; tryItOut("mathy3 = (function(x, y) { return (( ~ (( + (( + ((((y >>> 0) >= (Math.imul(0, y) >>> 0)) >>> 0) - 0x080000000)) && ( + (Math.log10(0x080000001) !== x)))) | 0)) >>> 0); }); testMathyFunction(mathy3, [0x100000000, 0, -0x080000001, 0.000000000000001, Number.MIN_VALUE, 1.7976931348623157e308, Number.MAX_VALUE, 42, -(2**53+2), 0x080000001, -0x0ffffffff, -0x100000001, 2**53, -0, -Number.MAX_SAFE_INTEGER, Math.PI, -1/0, 0/0, -Number.MIN_SAFE_INTEGER, 0x100000001, 0x080000000, -Number.MIN_VALUE, -0x080000000, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0x07fffffff, Number.MIN_SAFE_INTEGER, 1, 1/0, -(2**53-2), 0x0ffffffff, 2**53+2, -0x100000000, -(2**53)]); ");
/*fuzzSeed-169986037*/count=1541; tryItOut("s0 += 'x';");
/*fuzzSeed-169986037*/count=1542; tryItOut("\"use strict\"; testMathyFunction(mathy4, [-1/0, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 2**53-2, 0x0ffffffff, -(2**53), 2**53, 0.000000000000001, -(2**53-2), -0x100000001, -0x080000001, Number.MIN_VALUE, -0x07fffffff, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 42, 0x100000001, -0x100000000, -0, -0x080000000, 0/0, Math.PI, -Number.MIN_SAFE_INTEGER, 1/0, -(2**53+2), 1, 0x080000001, 0, 0x080000000, -Number.MIN_VALUE, 0x07fffffff, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53+2, 0x100000000]); ");
/*fuzzSeed-169986037*/count=1543; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.atan2(Math.fround((Math.min(( + Math.imul(Math.fround((mathy3((Math.cbrt((0.000000000000001 >>> 0)) >>> 0), y) >> Math.fround(mathy2(Math.fround(x), Math.fround(y))))), (0.000000000000001 && Math.fround(((Math.atan2(y, x) >>> 0) > ( + x)))))), ( + (Math.fround((( ~ (-0x07fffffff >>> 0)) >>> 0)) << ( + (-0x100000000 && x))))) != Math.asinh(Math.pow(((x ? y : Number.MAX_VALUE) > Number.MIN_SAFE_INTEGER), ( + Math.trunc(( + ( + Math.round((y | 0)))))))))), Math.fround((Math.fround(Math.imul(-0x100000000, (x ? Math.fround(Math.asin(Math.fround(((x <= (((x >>> 0) ? y : (y >>> 0)) >>> 0)) | 0)))) : ( + x)))) != Math.fround(( + mathy3(( + (x + (y | 0))), (2**53+2 | 0))))))); }); ");
/*fuzzSeed-169986037*/count=1544; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.atan(( + Math.min(( + mathy0(( + ((mathy1(Math.asinh(Math.sinh(x)), Number.MAX_VALUE) >>> 0) >>> ( + (( - x) >>> 0)))), (Math.pow(Math.fround(x), (( ! x) >>> 0)) >>> 0))), ( + (Math.clz32((Math.clz32(x) | 0)) | 0))))); }); testMathyFunction(mathy2, [-1/0, 2**53, Number.MAX_VALUE, 1, 42, 0.000000000000001, 0/0, -0x080000001, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Math.PI, -0, -(2**53), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x100000001, 0, 0x07fffffff, -0x07fffffff, -Number.MAX_VALUE, 2**53-2, -0x080000000, 2**53+2, 0x100000000, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x080000000, -(2**53+2), 0x100000001, 0x080000001, -(2**53-2), -0x100000000, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 1/0]); ");
/*fuzzSeed-169986037*/count=1545; tryItOut("\"use strict\"; testMathyFunction(mathy2, [true, undefined, (new Number(-0)), 0, [], false, /0/, NaN, '', 0.1, '\\0', [0], 1, null, objectEmulatingUndefined(), (new Boolean(false)), (function(){return 0;}), (new Boolean(true)), ({valueOf:function(){return 0;}}), -0, (new Number(0)), '/0/', ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), '0', (new String(''))]); ");
/*fuzzSeed-169986037*/count=1546; tryItOut("testMathyFunction(mathy1, /*MARR*/[function(){}, null, x, null, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){},  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , function(){}, x, x, null, null, x, x, null,  /x/ , function(){}, function(){}, null, null,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , null,  /x/ , null,  /x/ , x,  /x/ , function(){}, x, x, x,  /x/ , null, x, function(){}, null, x, null, x,  /x/ , null, x,  /x/ ,  /x/ , null, function(){}, x,  /x/ , null,  /x/ , function(){},  /x/ , function(){}, function(){},  /x/ , null,  /x/ ,  /x/ , function(){}, null, null,  /x/ ,  /x/ , null, function(){}, null, x,  /x/ , null, function(){}, function(){}, x, function(){}, null, function(){}, x, null, null, null, x]); ");
/*fuzzSeed-169986037*/count=1547; tryItOut("/*RXUB*/var r = /(?:\\b)+/gyi; var s = \nx ? x = x.yoyo((({getPrototypeOf: \"\\u0E7A\", x:  /x/g  }))) : (Object.defineProperty(e, \"__count__\", ({value: ({d: ( ''  >>=  \"\" ) }), writable: (x % 3 == 1)}))); print(uneval(s.match(r))); ");
/*fuzzSeed-169986037*/count=1548; tryItOut("\"use strict\"; this.b1 + '';");
/*fuzzSeed-169986037*/count=1549; tryItOut("\"use strict\"; /*tLoop*/for (let z of /*MARR*/[ /x/ ,  /x/ , -(2**53-2),  /x/ , new Boolean(false)]) { yield; }");
/*fuzzSeed-169986037*/count=1550; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return Math.min((Math.fround(( ~ Math.fround(Math.fround(( - ( + ( + 0x100000000))))))) | 0), (Math.min(Math.atan2(( + Math.min(( + y), ( + x))), y), mathy0(y, Math.max(( - (((Number.MAX_SAFE_INTEGER | 0) != (-0x080000001 | 0)) | 0)), Math.atan2(Math.fround(x), ( + Math.imul(( + -1/0), ( + Math.round(-0)))))))) | 0)); }); testMathyFunction(mathy2, [1, -(2**53-2), 0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x080000000, 0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE, -0x080000000, -(2**53), 2**53+2, 1.7976931348623157e308, 1/0, 0, 0x07fffffff, 2**53, Number.MAX_VALUE, 42, -(2**53+2), 0x080000001, -0, -0x07fffffff, Math.PI, 0/0, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, 2**53-2, -1/0, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MAX_SAFE_INTEGER, -0x080000001]); ");
/*fuzzSeed-169986037*/count=1551; tryItOut("");
/*fuzzSeed-169986037*/count=1552; tryItOut("e0.has(b1);");
/*fuzzSeed-169986037*/count=1553; tryItOut("(((function fibonacci(nqbksi) { p0 + i0;; if (nqbksi <= 1) { ; return 1; } ; return fibonacci(nqbksi - 1) + fibonacci(nqbksi - 2);  })(7)));");
/*fuzzSeed-169986037*/count=1554; tryItOut("\"use strict\"; ;");
/*fuzzSeed-169986037*/count=1555; tryItOut("mathy3 = (function(x, y) { return ( ~ (((Math.fround((Math.fround((( + Math.pow(x, (x | 0))) > ((1/0 >>> 0) | (y >>> 0)))) + Math.fround(Math.acos(y)))) | 0) << ((Math.fround(y) && 0x080000001) & mathy0(Math.fround(1/0), (Math.abs(-Number.MIN_VALUE) | 0)))) | 0)); }); testMathyFunction(mathy3, [Number.MAX_VALUE, 0x0ffffffff, 0x07fffffff, 0/0, 0, 0x080000001, -(2**53-2), 0x100000000, 2**53+2, -1/0, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0, -(2**53+2), -Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 1.7976931348623157e308, 2**53, 42, -Number.MAX_VALUE, 0x080000000, Number.MIN_VALUE, 2**53-2, 1/0, -0x07fffffff, 0x100000001, 1, Number.MIN_SAFE_INTEGER, -0x080000000, -0x100000001, -0x080000001, Math.PI, -0x100000000]); ");
/*fuzzSeed-169986037*/count=1556; tryItOut("b1 = g0.m0.get(p1);");
/*fuzzSeed-169986037*/count=1557; tryItOut("return;");
/*fuzzSeed-169986037*/count=1558; tryItOut("o1 = Object.create(t2);");
/*fuzzSeed-169986037*/count=1559; tryItOut("");
/*fuzzSeed-169986037*/count=1560; tryItOut("\"use strict\"; /*vLoop*/for (jvbfgg = 0; jvbfgg < 72; ++jvbfgg) { let c = jvbfgg; g2.g0.offThreadCompileScript(\"function f2(p0) x\"); } ");
/*fuzzSeed-169986037*/count=1561; tryItOut("g2.e1.add(o2);");
/*fuzzSeed-169986037*/count=1562; tryItOut("\"use strict\"; \"use asm\"; for (var v of o1.o0.a2) { try { f2 = f2; } catch(e0) { } try { v2 = (i1 instanceof g1); } catch(e1) { } try { this.g0.s0 += 'x'; } catch(e2) { } for (var v of o2.m2) { m0.set(e1, this.i2); } }");
/*fuzzSeed-169986037*/count=1563; tryItOut("\"use strict\"; b1 + f2;");
/*fuzzSeed-169986037*/count=1564; tryItOut("f2 = (function(j) { if (j) { try { f0 = Proxy.createFunction(h1, f1, f2); } catch(e0) { } try { a1.forEach((function(j) { if (j) { try { /*MXX1*/o1 = g2.Float64Array.length; } catch(e0) { } a0 = []; } else { try { Object.defineProperty(this, \"v2\", { configurable: true, enumerable: ((-0.776)),  get: function() {  return t1.length; } }); } catch(e0) { } b1 + ''; } }), (this.__defineGetter__(\"x\", window)), a1, t2); } catch(e1) { } try { v0 = a1.length; } catch(e2) { } for (var p in m0) { try { h1.hasOwn = encodeURI; } catch(e0) { } Object.defineProperty(this, \"t0\", { configurable: (x % 3 == 0), enumerable: (x % 40 == 33),  get: function() {  return new Int32Array(t1); } }); } } else { m2.has(i2); } });");
/*fuzzSeed-169986037*/count=1565; tryItOut("\"use strict\"; a0.pop();");
/*fuzzSeed-169986037*/count=1566; tryItOut("\"use strict\"; v2 = g1.eval(\"function f0(g1)  { \\\"use strict\\\"; yield (z != a) } \");");
/*fuzzSeed-169986037*/count=1567; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=1568; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    {\n      d0 = (-1.1805916207174113e+21);\n    }\n    (Float32ArrayView[1]) = ((d0));\n    {\n      i2 = (i2);\n    }\n    i1 = (i1);\n    d0 = (-4.722366482869645e+21);\n    switch (((((0x2058f88a))-(i2)) ^ ((0xf287d562)-(0xc3b5fd17)-(0x5248bb55)))) {\n      case -2:\n        i2 = (i1);\n      case -2:\n        i2 = (i2);\n        break;\n      case -3:\n        d0 = (NaN);\n        break;\n      default:\n        i2 = (i1);\n    }\n    {\n      i1 = (i2);\n    }\n    d0 = (d0);\n    (Float64ArrayView[1]) = ((d0));\n    return (((-0x8000000)+((1.0009765625) < (-140737488355329.0))))|0;\n  }\n  return f; })(this, {ff: let (w = z)  /x/g }, new ArrayBuffer(4096)); testMathyFunction(mathy0, [-(2**53), 0.000000000000001, Math.PI, Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, Number.MAX_VALUE, -0x080000000, -Number.MAX_VALUE, -1/0, 2**53, 0x0ffffffff, 42, 0x07fffffff, 0x100000001, 0/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000000, -Number.MIN_VALUE, 1, -Number.MIN_SAFE_INTEGER, 0x080000000, 1/0, 0x080000001, -0x100000001, -0x07fffffff, 0, 2**53-2, -0x100000000, -0, 2**53+2, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=1569; tryItOut("mathy1 = (function(x, y) { return (Math.max(( + Math.trunc(((Math.imul((mathy0(Math.fround(( + Math.asin(( + ( - x))))), (Math.min((1 | 0), Math.hypot(y, x)) | 0)) >>> 0), (Math.atanh(0x080000001) | 0)) >>> 0) >>> 0))), ( + ( + Math.sin(( + ((y & Math.pow((((y * -0) | 0) > ( ! y)), ((0x100000001 >>> y) >>> 0))) | 0)))))) >>> 0); }); ");
/*fuzzSeed-169986037*/count=1570; tryItOut("\"use strict\"; mathy0 = (function(stdlib, foreign, heap){ \"use asm\";   var Infinity = stdlib.Infinity;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    {\n      d0 = (Infinity);\n    }\n    return (((i1)))|0;\n  }\n  return f; })(this, {ff: x.parseInt}, new ArrayBuffer(4096)); testMathyFunction(mathy0, [({valueOf:function(){return 0;}}), '0', objectEmulatingUndefined(), '\\0', true, '/0/', ({toString:function(){return '0';}}), [], [0], (function(){return 0;}), NaN, undefined, /0/, ({valueOf:function(){return '0';}}), 0, (new Boolean(false)), (new Boolean(true)), (new String('')), '', 0.1, null, 1, false, -0, (new Number(0)), (new Number(-0))]); ");
/*fuzzSeed-169986037*/count=1571; tryItOut("var unxadn = new SharedArrayBuffer(16); var unxadn_0 = new Int16Array(unxadn); unxadn_0[0] = -19; var unxadn_1 = new Float32Array(unxadn); v2.toString = (function() { for (var j=0;j<95;++j) { f0(j%2==1); } });a0[({valueOf: function() { print( /x/g );return 2; }})] = g1.f2;unxadnprint(unxadn_0[5]);print(unxadn_0[5]);(-20);");
/*fuzzSeed-169986037*/count=1572; tryItOut("e0.add(e0);");
/*fuzzSeed-169986037*/count=1573; tryItOut("m1.has(v1);function NaN()(4277)a1.sort(function shapeyConstructor(umlnjb){{ a2[v1] =  /x/g ; } if (umlnjb) Object.defineProperty(this, \"toString\", ({get: Math.floor, configurable: true, enumerable: (umlnjb % 5 == 1)}));{ g0.offThreadCompileScript(\"a2.forEach((function() { try { e1.delete(p1); } catch(e0) { } a0.shift(s2); return s1; }));\"); } this[\"sqrt\"] = /(?=(?!(?:\\W)*))/gyim;this[\"__iterator__\"] = objectEmulatingUndefined();this[\"0\"] = decodeURIComponent;{ v2 = evalcx(\"/* no regression tests found */\", this.g2); } if (-2) Object.defineProperty(this, \"\\u8550\", ({}));return this; });");
/*fuzzSeed-169986037*/count=1574; tryItOut("mathy5 = (function(x, y) { return (Math.min(((Math.sign(y) >>> 0) | 0), Math.max(Math.tanh(y), (mathy3(y, (Math.asin(Number.MAX_SAFE_INTEGER) | 0)) == ( ~ (Math.fround(Math.fround(mathy4(Math.fround(y), (0x100000000 | 0)))) % x))))) ? ( + Math.atan2(( + (Math.min(((x - y) , ( + (x | Math.atan2(x, x)))), ((Math.min(Math.fround((y & ((-0x0ffffffff !== (y | 0)) | 0))), Number.MIN_VALUE) ? ((((y > 1.7976931348623157e308) | (Math.atanh(x) >>> 0)) << x) | 0) : x) | 0)) | 0)), (( - (Math.fround(Math.asinh(y)) >>> 0)) >>> 0))) : (Math.max(((( ! Math.asin(Math.fround((( + ( ! ( + y))) > Math.pow(x, y))))) << Math.atan2(mathy0(((y >>> 0) ^ x), 0x080000000), Math.max(( + Math.imul(y, Math.fround(Math.fround(( - y))))), (y >>> 0)))) | 0), ( + ( + Math.sqrt(Math.fround(Math.sinh(Math.fround(Math.fround(mathy4(Math.fround(x), Math.fround(x)))))))))) | 0)); }); testMathyFunction(mathy5, [0x100000000, Number.MIN_SAFE_INTEGER, -0x080000001, -(2**53-2), -0, 1, 0.000000000000001, -0x100000001, 0/0, 0x080000001, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 2**53+2, 0, 2**53-2, Number.MIN_VALUE, -(2**53+2), 2**53, -Number.MIN_VALUE, Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -1/0, -0x0ffffffff, -0x100000000, -0x080000000, -0x07fffffff, 1/0, 0x080000000, Math.PI, 0x07fffffff, -Number.MAX_VALUE, 0x100000001, 42, Number.MAX_SAFE_INTEGER, -(2**53), 0x0ffffffff]); ");
/*fuzzSeed-169986037*/count=1575; tryItOut("/*hhh*/function hllktk(){g1.v2 = g0.runOffThreadScript();}hllktk(((function a_indexing(rlhiqt, llxvsi) { ; if (rlhiqt.length == llxvsi) { ; return (undefined)() != llxvsi; } var bsrdzr = rlhiqt[llxvsi]; var xlbjeo = a_indexing(rlhiqt, llxvsi + 1); /*vLoop*/for (let sbbaze = 0; ( /x/ ) && sbbaze < 36; ++sbbaze) { const x = sbbaze; g1.a1.push(e1, g0.b0); }  })(/*MARR*/[x, NaN, false, NaN, x =  /x/ , NaN, x, x, x =  /x/ , NaN, x, NaN, x, x =  /x/ , NaN, x, x, false, x =  /x/ , x =  /x/ , x, NaN, x =  /x/ , false, NaN, x =  /x/ , false, x =  /x/ , NaN, x =  /x/ , false, NaN, x =  /x/ , x], 0)));");
/*fuzzSeed-169986037*/count=1576; tryItOut("/*infloop*/L: for  each(var c in x = {x: x}) {/*RXUB*/var r = /(?:^|(?=\\2[^]{1})+?(\u3e23(?!.)?[^]([^]\\B)?))/gyi; var s = \"\"; print(uneval(s.match(r))); print(r.lastIndex); print(x); }i1 = new Iterator(t2, true);");
/*fuzzSeed-169986037*/count=1577; tryItOut("mathy3 = (function(x, y) { return (((( - ( + (( + x) ? (( + Math.imul(( + (Math.imul(Number.MIN_VALUE, y) && ( + x))), ( + x))) >>> 0) : ( + ( + mathy2(( + 42), ( + Number.MAX_VALUE))))))) , (Math.max(( ~ 1/0), Math.atan2((x === (x | 0)), ( + ( ! ( + x))))) | 0)) | 0) << Math.ceil(Math.sin(Math.cbrt(mathy1(Number.MAX_VALUE, (x | 0)))))); }); testMathyFunction(mathy3, [-0x0ffffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53), 42, 1, 0.000000000000001, 0x07fffffff, -0x100000000, 0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, Number.MAX_SAFE_INTEGER, -(2**53+2), -(2**53-2), Math.PI, -0x080000001, Number.MIN_SAFE_INTEGER, 0x100000001, -Number.MAX_VALUE, Number.MAX_VALUE, 0x080000001, 0x080000000, 0/0, Number.MIN_VALUE, 2**53-2, -0, 1/0, 1.7976931348623157e308, 2**53, -1/0, 2**53+2, 0]); ");
/*fuzzSeed-169986037*/count=1578; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (Math.hypot(((Math.fround(Math.fround(( + Math.fround(Math.pow(Math.fround(0x07fffffff), Math.fround(x)))))) ** ( ~ Math.fround(mathy1(Math.min((x >>> 0), (42 >>> 0)), ( + (-0x100000001 == y)))))) >>> 0), (Math.imul(Math.imul(mathy1(Math.ceil(( + x)), (Math.imul((Math.log(x) | 0), x) | 0)), ( + -0)), (y !== ( + ((Math.atan2(Math.atan(y), y) !== Math.fround((y > (( - x) >>> 0)))) % ( + (mathy1(x, Math.pow((x >>> 0), (y | 0))) >>> 0)))))) >>> 0)) >>> 0); }); testMathyFunction(mathy2, [-(2**53-2), -0x100000001, Number.MIN_VALUE, -Number.MAX_VALUE, -1/0, -Number.MIN_VALUE, 0x080000001, 2**53, 1/0, Math.PI, 0x100000001, -0x080000001, -0, -Number.MAX_SAFE_INTEGER, -0x080000000, 0.000000000000001, 1.7976931348623157e308, 42, Number.MAX_VALUE, 0x080000000, 0x07fffffff, 1, -0x100000000, -Number.MIN_SAFE_INTEGER, -(2**53+2), 2**53+2, -(2**53), Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000000, Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x0ffffffff, 2**53-2, 0/0, 0]); ");
/*fuzzSeed-169986037*/count=1579; tryItOut("print(o1.o0);function eval(z, x, \u3056, a, [[, {x, NaN: \u3056}, {d: [[{window: (a)}], {x}, , ], NaN: window, b, NaN: w, x: {x: x, z: arguments.callee.arguments}}], d, Date.prototype.setMonth, [[x, /*\n*/[, , []], , x, ], , {}, , {z: [], b: [[], {a, x: {z: {x: []}}, x([ '' ])}]}], {x: [arguments], x: [x], z: {x: {this.x: {x: [, ], a, x: [ '' .__proto__]}}, b: []}}], x, x, z, a, a, e = this.valueOf(\"number\") !=  '' , x, x, x, get, a, y, x, x = window, eval = d, d, NaN, z, d, window = e, x, \u3056 =  \"\" , x, x, window, x, y, e, x, w, x, window, this, x, x, eval, x, \u3056, \u3056, window, x, z, x, c, e, w, \u3056 =  /x/ , x, x = null, a, x, b, NaN, x, NaN) { yield  ''  } /*RXUB*/var r = /\\2($|.+\\b+)?*/gy; var s = \"\"; print(uneval(r.exec(s))); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1580; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"(([^]\\\\b|\\\\1{4,}))|\\\\2|(?=(?:([\\u54d2\\\\xe4])*\\\\b\\\\b|\\\\b)){0,1}\", \"m\"); var s = \"\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1581; tryItOut("\"use strict\"; g1.f1 + f0;");
/*fuzzSeed-169986037*/count=1582; tryItOut("testMathyFunction(mathy0, [2**53-2, 0, 0x080000000, 0/0, -(2**53-2), 2**53+2, -0, -0x07fffffff, Number.MAX_VALUE, -1/0, -0x100000001, 0x080000001, 0x100000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -0x080000000, -Number.MAX_SAFE_INTEGER, 2**53, 0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, 0.000000000000001, -Number.MIN_VALUE, Math.PI, -0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000001, -0x100000000, 42, 1, 1.7976931348623157e308, 0x100000000, -(2**53), 1/0, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=1583; tryItOut("\"use asm\"; mathy4 = (function(x, y) { \"use strict\"; return Math.clz32(Math.fround(Math.max((( ! ( + Math.pow(( + (Math.asin(x) * (x <= (Math.trunc(( + y)) | 0)))), y))) | 0), (Math.log10(y) | 0)))); }); ");
/*fuzzSeed-169986037*/count=1584; tryItOut("\"use strict\"; h2.toString = (function(j) { if (j) { try { m0.has(v2); } catch(e0) { } (void schedulegc(g0)); } else { try { b1 = a1[3]; } catch(e0) { } f0.toSource = (function() { try { this.a0[8] = Math.imul(-8, x); } catch(e0) { } try { p0 + m0; } catch(e1) { } try { /*RXUB*/var r = g1.r0; var s = (\"\\u48C2\".watch(\"toSource\", (function handlerFactory() {return {getOwnPropertyDescriptor: function(name) { var desc = Object.getOwnPropertyDescriptor(x); desc.configurable = true; return desc; }, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: undefined, getOwnPropertyNames: undefined, delete: function() { throw 3; }, fix: q => q, has: function(name) { return name in x; }, hasOwn: function() { return false; }, get:  '' , set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; }))); print(uneval(r.exec(s)));  } catch(e2) { } const v1 = g2.eval(\"v1 = Object.prototype.isPrototypeOf.call(g1.h0, m2);\"); return f0; }); } });");
/*fuzzSeed-169986037*/count=1585; tryItOut("s2 += this.g1.g1.s0;");
/*fuzzSeed-169986037*/count=1586; tryItOut("{ void 0; setGCCallback({ action: \"minorGC\", phases: \"both\" }); }");
/*fuzzSeed-169986037*/count=1587; tryItOut("switch(this) { case new ((1 for (x in [])))(): break; break; case x = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: undefined, getPropertyDescriptor: function(name) { var desc = Object.getPropertyDescriptor(x); desc.configurable = true; return desc; }, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function() { return Object.getOwnPropertyNames(x); }, delete: function(name) { return delete x[name]; }, fix: function() { if (Object.isFrozen(x)) { return Object.getOwnProperties(x); } }, has: function(name) { return name in x; }, hasOwn: function(name) { return Object.prototype.hasOwnProperty.call(x, name); }, get: ({/*TOODEEP*/}), set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: function() { var result = []; for (var name in x) { result.push(name); }; return result; }, keys: function() { return Object.keys(x); }, }; })(arguments), ({/*TOODEEP*/})): default: break; case 4: { void 0; void relazifyFunctions(); }case 2: var yhyfsm = new ArrayBuffer(16); var yhyfsm_0 = new Int32Array(yhyfsm); print(yhyfsm_0[0]); yhyfsm_0[0] = -20; print(yhyfsm);break; case ((p={}, (p.z = \"\\uE18B\")())):  }");
/*fuzzSeed-169986037*/count=1588; tryItOut("/*RXUB*/var r = /(?!((?:\\1)*?)\\1)/i; var s = \"\\u38f6\"; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1589; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atan2((Math.min(Math.fround(Math.atan2(y, Math.fround(Math.sin(x)))), (Math.fround(Math.imul((x | 0), (Math.max(Math.clz32(( + y)), Number.MAX_VALUE) ? Math.fround(( ! 0/0)) : Math.pow(y, y)))) >>> 0)) ? ( - Math.clz32(y)) : (( - ( + ( + ((((1/0 | 0) , (y | 0)) | 0) % ((Math.atan((Math.pow(x, y) | 0)) | 0) >>> 0))))) | 0)), Math.fround((Math.fround(Math.fround(Math.hypot(Math.fround(x), Math.fround((( ~ ((x ** Math.fround((x * Math.imul(x, -1/0)))) >>> 0)) >>> 0))))) == Math.fround((((Math.sign(Math.fround(y)) , ((Math.sinh((-0x07fffffff | 0)) >>> 0) >>> 0)) | 0) ? ((Math.abs((x >>> 0)) >>> 0) | 0) : (x | 0)))))); }); testMathyFunction(mathy0, [42, -0x100000000, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0.000000000000001, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, 0x100000000, -0x080000001, 0x080000001, 2**53-2, -0x0ffffffff, Number.MAX_VALUE, 1/0, -(2**53+2), Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, 2**53, 0x07fffffff, -(2**53), 0x080000000, 2**53+2, -0, 0, -1/0, 0/0, 0x100000001, 1, -0x100000001, -(2**53-2), -0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1590; tryItOut("\"use strict\"; /*vLoop*/for (let mreekd = 0; mreekd < 61; ++mreekd) { var w = mreekd; Array.prototype.push.call(a0); } ");
/*fuzzSeed-169986037*/count=1591; tryItOut("e2.has(this.b2);\ng0.m2.has(o2);\n");
/*fuzzSeed-169986037*/count=1592; tryItOut("/*oLoop*/for (pgpsti = 0, x = function ([y]) { }; pgpsti < 38; ++pgpsti) { a2.shift(); } ");
/*fuzzSeed-169986037*/count=1593; tryItOut("mathy5 = (function(x, y) { return ( + ( + (Math.abs((y ? ((x && Math.fround(y)) | 0) : ((y >>> 0) != y))) ? (((Math.min(Math.min((( - (mathy3((0 >>> 0), -(2**53)) | 0)) >>> 0), x), ( + ( + y))) | 0) <= (Math.fround(mathy3(y, Math.exp((mathy4(y, (Math.acos(( + y)) >>> 0)) >>> 0)))) | 0)) >>> 0) : (( ! Math.round(x)) >>> 0)))); }); testMathyFunction(mathy5, /*MARR*/[(0/0), [1], [1], new Number(1.5), new Number(1.5), [1], [1], [1], new Number(1.5), [1], (0/0), (0/0), (0/0), [1], new Number(1.5), (0/0), new Number(1.5), [1], new Number(1.5), [1], new Number(1.5), new Number(1.5), (0/0), new Number(1.5), (0/0), [1], [1]]); ");
/*fuzzSeed-169986037*/count=1594; tryItOut("testMathyFunction(mathy0, [-(2**53+2), Number.MAX_SAFE_INTEGER, 0x100000001, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0.000000000000001, 2**53, 0x080000001, -0, -Number.MIN_VALUE, 2**53-2, Number.MAX_VALUE, -1/0, -0x07fffffff, -(2**53), 2**53+2, 42, 1/0, -Number.MIN_SAFE_INTEGER, 0x07fffffff, -0x100000000, 0/0, 0x100000000, -(2**53-2), 0x080000000, Math.PI, -Number.MAX_VALUE, 1.7976931348623157e308, -0x080000001, 1, -0x100000001, -0x080000000, -Number.MAX_SAFE_INTEGER, 0, 0x0ffffffff, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=1595; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return (( ! (Math.min(( + Math.log1p(( + ( ! y)))), ( + mathy2(( + Math.asinh((Math.atan2(x, ( + y)) | 0))), x))) >>> 0)) >>> 0); }); testMathyFunction(mathy3, [-0, Math.PI, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, 0x080000001, -Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, Number.MAX_VALUE, -0x0ffffffff, 2**53, 0x07fffffff, -Number.MAX_VALUE, 0.000000000000001, 42, -1/0, 0x100000001, -0x080000001, 0x0ffffffff, -0x07fffffff, Number.MIN_VALUE, -0x080000000, Number.MIN_SAFE_INTEGER, -(2**53-2), 2**53+2, 1, 2**53-2, -(2**53+2), 1/0, 0/0, 0, -Number.MIN_SAFE_INTEGER, 0x080000000, 0x100000000, -0x100000001, -0x100000000]); ");
/*fuzzSeed-169986037*/count=1596; tryItOut("\"use asm\"; h0 = {};");
/*fuzzSeed-169986037*/count=1597; tryItOut("\"use strict\"; /*RXUB*/var r = /(?=.|\\t+(?=[^]){0,})|\\b{1}|[^\\s\\x46-\\xeA\\\uc9b2]{3,}(?!(?:.?\\S|^\\2))*(?:(?!(?![^]))(?:.{0,})(\\W))+?/y; var s = \"\"; print(r.exec(s)); ");
/*fuzzSeed-169986037*/count=1598; tryItOut("testMathyFunction(mathy2, [0x100000001, Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 2**53+2, -(2**53-2), Math.PI, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x080000001, 1/0, 1, 2**53-2, 0x100000000, -1/0, 0/0, 0, -Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, -0x080000001, 0.000000000000001, -0x0ffffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, -(2**53), -0, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, Number.MIN_VALUE, -0x080000000, -0x100000001, 42]); ");
/*fuzzSeed-169986037*/count=1599; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (Math.hypot(((Math.min((((Math.atan2((( ! x) > y), -0x0ffffffff) | 0) >= ( - (( + (y != ( + x))) && y))) >>> 0), (Math.log2(Math.fround((( + ((42 ? (Math.max((0x07fffffff | 0), x) >>> 0) : Math.fround(y)) >>> 0)) | 0))) >>> 0)) >>> 0) >>> 0), ( ! Math.fround(( - (( - (-1/0 | 0)) | 0))))) >>> 0); }); testMathyFunction(mathy3, [0x07fffffff, -0x100000001, 0, -1/0, 0/0, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, 1/0, Math.PI, Number.MAX_SAFE_INTEGER, 0x100000001, 42, -0x100000000, 1.7976931348623157e308, 2**53, 2**53+2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 1, 0x0ffffffff, 0x080000000, 0.000000000000001, -0x07fffffff, -Number.MAX_SAFE_INTEGER, -0, 2**53-2, Number.MIN_VALUE, 0x100000000, -0x080000001, -0x080000000, -(2**53+2), Number.MAX_VALUE, -(2**53-2), 0x080000001]); ");
/*fuzzSeed-169986037*/count=1600; tryItOut("/*MXX3*/g0.Promise.name = g2.Promise.name;");
/*fuzzSeed-169986037*/count=1601; tryItOut("i0 + t1;");
/*fuzzSeed-169986037*/count=1602; tryItOut("/*infloop*/for(var z in ((function(y) { return d = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(){}, getOwnPropertyNames: (4277), delete: SyntaxError, fix: (Set.prototype.has).bind, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { for (var name in x) { yield name; } })(); }, enumerate: 12 &= y.__defineGetter__(\"/\\\\3/y\", \u000d-24), keys: function() { return []; }, }; })(new RegExp(\".\", \"ym\")), this) })(this.__defineGetter__(\"y\", /*wrap2*/(function(){ var zisilp = x | z; var yqaczo = decodeURI; return yqaczo;})())))){t1 + g2.m1; }");
/*fuzzSeed-169986037*/count=1603; tryItOut("\"use strict\"; L:if(false) {print(()); } else  if (window) {print(x); } else {{ if (isAsmJSCompilationAvailable()) { void 0; try { startgc(1103338); } catch(e) { } } void 0; } \"\\uF504\";x = linkedList(x, 2728); }");
/*fuzzSeed-169986037*/count=1604; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (mathy0(( ~ ( + ( + ( + (mathy3((y | 0), (x | 0)) | 0))))), Math.fround(( - Math.fround(Math.fround(Math.fround((Math.asin((0x100000001 | 0)) | 0))))))) ? Math.fround(mathy2(Math.fround(( + Math.min(( + Math.max((Math.min((y | 0), (0x07fffffff | 0)) | 0), Math.pow(y, ( + x)))), ( + mathy1((x > x), (Math.fround((Math.fround(x) + Math.fround(-0x080000000))) < y)))))), Math.fround(( ~ Math.min(x, ( - (( ~ y) | 0))))))) : Math.fround((Math.fround(( + ( ! y))) && (((( + (x < ( ! 2**53))) ? ( + Math.PI) : (( + (( + (( ! ((Math.min(x, 0x080000000) >>> 0) >>> 0)) >>> 0)) ? ( + x) : ( + Math.fround(Math.imul(Math.fround(0x07fffffff), Math.fround(( ~ x))))))) >>> 0)) >>> 0) > ((y ^ Math.imul(Math.atanh(x), x)) >>> 0))))); }); ");
/*fuzzSeed-169986037*/count=1605; tryItOut("mathy5 = (function(x, y) { return mathy2(( + (( + y) & Math.fround(mathy1(( + x), (Math.fround(y) | y))))), Math.acosh((( + (y < Math.fround(( ~ (-0x07fffffff | 0))))) <= ( + (( + mathy4(0x080000001, ( + y))) ** ( + x)))))); }); ");
/*fuzzSeed-169986037*/count=1606; tryItOut("mathy4 = (function(x, y) { return (Math.ceil((((Math.fround(Math.sign((Math.max((y | 0), (y | 0)) | 0))) | 0) ? Math.asinh((Math.asin((-Number.MAX_SAFE_INTEGER | 0)) | 0)) : (Math.pow((x | y), (Math.tan(1/0) >> mathy2(y, 0x080000001))) >>> 0)) | 0)) | 0); }); testMathyFunction(mathy4, [42, -0x080000000, 1, Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x0ffffffff, 0x100000000, 0.000000000000001, -(2**53), -0x100000001, 0x0ffffffff, -(2**53-2), Number.MAX_SAFE_INTEGER, 0, 0x07fffffff, 0x100000001, -(2**53+2), 1.7976931348623157e308, Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0/0, 1/0, 2**53+2, -0, 2**53-2, 0x080000000, -1/0, 2**53, 0x080000001, -0x080000001, Number.MIN_VALUE, -0x100000000]); ");
/*fuzzSeed-169986037*/count=1607; tryItOut(" for (d of 5) a1 = r1.exec(s0);throw  \"\" ;");
/*fuzzSeed-169986037*/count=1608; tryItOut("g0.s1 += 'x';");
/*fuzzSeed-169986037*/count=1609; tryItOut("{ void 0; void schedulegc(this); }");
/*fuzzSeed-169986037*/count=1610; tryItOut("let oxrbbb;Array.prototype.unshift.apply(a2, [g0.h1]);");
/*fuzzSeed-169986037*/count=1611; tryItOut("\"use strict\"; { if (!isAsmJSCompilationAvailable()) { void 0; void relazifyFunctions(); } void 0; }");
/*fuzzSeed-169986037*/count=1612; tryItOut("(void schedulegc(g0));");
/*fuzzSeed-169986037*/count=1613; tryItOut("\"use strict\"; /*bLoop*/for (let arsapy = 0, Date.prototype.setFullYear; arsapy < 11; ++arsapy) { if (arsapy % 67 == 52) { L: {this.h1.delete = (function() { for (var j=0;j<113;++j) { f2(j%2==0); } });g2.v2 = this.g2.runOffThreadScript(); } } else { /* no regression tests found */ }  } ");
/*fuzzSeed-169986037*/count=1614; tryItOut("\"use strict\"; /*hhh*/function iejayq(x, ...eval){v1 = r0.sticky;}/*iii*//*MXX2*/g2.g2.Int8Array.prototype = v1;");
/*fuzzSeed-169986037*/count=1615; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=1616; tryItOut("mathy3 = (function(x, y) { return Math.imul(Math.fround(mathy1(Math.fround(( + Math.hypot((( ! ( + Math.min( '' , x))) >>> 0), ( + y)))), Math.fround(( + (( + Math.atan2((( ! (Math.atanh((x >>> 0)) | 0)) | 0), Math.atan2(y, x))) === ( + Math.tan(Math.fround(( ~ x))))))))), ( ~ Math.min(( ~ 2**53+2), 2**53-2))); }); testMathyFunction(mathy3, [1/0, 1.7976931348623157e308, 0/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), 0x07fffffff, -(2**53), -1/0, 0x100000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -0x100000000, -0x07fffffff, Math.PI, 2**53+2, 2**53, 42, 0x100000000, -Number.MAX_VALUE, 0.000000000000001, -0x0ffffffff, -0x080000001, Number.MIN_SAFE_INTEGER, 1, 0x080000000, 0x080000001, 0x0ffffffff, 0, 2**53-2, -0x100000001, -Number.MIN_SAFE_INTEGER, -(2**53+2)]); ");
/*fuzzSeed-169986037*/count=1617; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return ((Math.fround(mathy2(Math.atanh((( - y) >>> 0)), Math.cbrt(y))) ^ Math.fround((Math.atan2((mathy1(( + y), (Math.PI | 0)) | 0), Math.imul(x, -1/0)) ? (Math.cosh((( ! ( + Math.fround(Math.sin(y)))) | 0)) | 0) : (Math.log2((y | 0)) | 0)))) >>> 0); }); testMathyFunction(mathy3, [-0x100000001, 1/0, 0x080000000, 0x080000001, 2**53-2, -0x080000001, 0x0ffffffff, -(2**53-2), -0x080000000, 0x100000001, 0x07fffffff, -1/0, 42, 2**53+2, Number.MAX_VALUE, 1.7976931348623157e308, 2**53, -0x0ffffffff, 0x100000000, Number.MIN_VALUE, 1, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -(2**53), -Number.MIN_VALUE, 0/0, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000000, 0, Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-169986037*/count=1618; tryItOut("v1 = evaluate(\";a1.sort();\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 19 == 2), noScriptRval: (x % 2 == 1), sourceIsLazy: (x % 4 == 2), catchTermination: true }));");
/*fuzzSeed-169986037*/count=1619; tryItOut("/*MXX1*/o1 = g0.Map.prototype.size;");
/*fuzzSeed-169986037*/count=1620; tryItOut("\"use strict\"; a1.sort((function() { try { r1 = /$/gyi; } catch(e0) { } try { o0.v2 = b1[\"clear\"]; } catch(e1) { } Array.prototype.unshift.call(this.a1, m2, g0); return i0; }), t0);");
/*fuzzSeed-169986037*/count=1621; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-169986037*/count=1622; tryItOut("\"use strict\"; var kbljzc = new SharedArrayBuffer(2); var kbljzc_0 = new Int8Array(kbljzc); print(kbljzc_0[0]); kbljzc_0[0] = 8; var kbljzc_1 = new Uint8ClampedArray(kbljzc); kbljzc_1[0] = -3; var kbljzc_2 = new Uint8ClampedArray(kbljzc); print(kbljzc_2[0]); kbljzc_2[0] = -4; t2 = new Uint8Array(b0);print(kbljzc_1[0]);Object.prototype.unwatch.call(g2, \"trunc\");([,,z1]);s0 = Array.prototype.join.call(a1, s2);eval/*RXUB*/var r = r0; var s = this.g0.g1.s0; print(s.split(r)); a1.reverse(f0, i2, b2, this.p2, this.m1, f2);v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: false, sourceIsLazy: true, catchTermination: /(?:\\S)/gim, element: o0, sourceMapURL: s2 }));g0.h1.getOwnPropertyNames = f2;");
/*fuzzSeed-169986037*/count=1623; tryItOut("\"use strict\"; ");
/*fuzzSeed-169986037*/count=1624; tryItOut("\"use strict\"; mathy0 = (function(x, y) { \"use strict\"; return (Math.ceil(Math.fround(Math.pow((( ~ ( + ( + y))) | 0), (y >>> 0)))) - ((((Math.imul((( + y) | 0), (( ~ Math.fround((Math.fround(x) == Math.fround(y)))) | 0)) | 0) % (Math.clz32(Math.hypot((y | 0), y)) | 0)) | 0) != Math.fround(Math.cosh(x)))); }); testMathyFunction(mathy0, [-0x07fffffff, 42, 0x07fffffff, Number.MIN_VALUE, -0x080000000, 0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -0, -(2**53), -0x080000001, 0x0ffffffff, 2**53-2, 0x100000001, 0x080000000, 1, -0x0ffffffff, -1/0, 0/0, -Number.MAX_VALUE, -0x100000000, Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 1/0, Number.MAX_SAFE_INTEGER, 0, 0.000000000000001, 0x100000000, -0x100000001, -Number.MAX_SAFE_INTEGER, 2**53, Number.MIN_SAFE_INTEGER, -(2**53-2), -(2**53+2), Math.PI]); ");
/*fuzzSeed-169986037*/count=1625; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + ( - (mathy0(x, (Math.max((mathy1((x >>> 0), (y >>> 0)) >>> 0), 0x07fffffff) >>> 0)) >>> 0))), ( + Math.fround((Math.fround(( ~ (Math.fround(mathy1((-0x0ffffffff | 0), Math.fround(((((x >>> 0) ? (y >>> 0) : x) >>> 0) & x)))) >>> Math.atanh((Math.min((Math.fround(( ! Math.fround(x))) >>> 0), (Math.imul(x, y) >>> 0)) >>> 0))))) ** Math.fround((( ! (Math.fround(( ! Math.fround(Math.expm1(y)))) | 0)) >>> 0))))))); }); ");
/*fuzzSeed-169986037*/count=1626; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + mathy0(Math.fround(Math.round(Math.fround(Math.asinh(0/0)))), Math.fround(Math.trunc((((( + (-0x0ffffffff > ( + Math.cosh(Math.fround(x))))) | 0) || (( ! Math.pow(Math.cos(Math.fround(-Number.MIN_SAFE_INTEGER)), x)) >>> 0)) >>> 0))))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), window = window, window = window, new Number(1), window = window, new Number(1), -Number.MAX_VALUE, new Number(1), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), -Number.MAX_VALUE, window = window, new Number(1), objectEmulatingUndefined(), window = window, -Number.MAX_VALUE, -Number.MAX_VALUE, (1/0), window = window, new Number(1), new Number(1), window = window, objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), -Number.MAX_VALUE, new Number(1), window = window, window = window, (1/0), -Number.MAX_VALUE, objectEmulatingUndefined(), -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, -Number.MAX_VALUE, objectEmulatingUndefined(), -Number.MAX_VALUE, window = window, new Number(1), new Number(1), window = window, new Number(1), new Number(1), -Number.MAX_VALUE, objectEmulatingUndefined(), -Number.MAX_VALUE, (1/0), -Number.MAX_VALUE, new Number(1), new Number(1), new Number(1), new Number(1), window = window, -Number.MAX_VALUE, -Number.MAX_VALUE, new Number(1)]); ");
/*fuzzSeed-169986037*/count=1627; tryItOut("testMathyFunction(mathy4, /*MARR*/[(-1/0), this, [], [], (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), (-1/0), this, this, this, this, this, [], this, (-1/0), [], [], (-1/0), this, [], this, this, this]); ");
/*fuzzSeed-169986037*/count=1628; tryItOut("{ void 0; void schedulegc(this); } o1.e1 = new Set(o0);");
/*fuzzSeed-169986037*/count=1629; tryItOut("/*RXUB*/var r = r0; var s = \"\"; print(s.split(r)); print(r.lastIndex); ");
/*fuzzSeed-169986037*/count=1630; tryItOut("\"use strict\"; if((w = Proxy.createFunction((function handlerFactory(x) {return {getOwnPropertyDescriptor: function(){}, getPropertyDescriptor: function(){}, defineProperty: function(name, desc) { Object.defineProperty(x, name, desc); }, getOwnPropertyNames: function (b)12, delete: function() { return true; }, fix: function() { return []; }, has: function(name) { return name in x; }, hasOwn: this, get: function() { return undefined }, set: function(receiver, name, val) { x[name] = val; return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: function() { return []; }, keys: function() { return []; }, }; })( /x/ ), Object.seal, undefined.preventExtensions))) {const c = (++d);/*tLoop*/for (let c of /*MARR*/[\"\\u5168\", (1/0), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), \"\\u5168\", \"\\u5168\", objectEmulatingUndefined(), \"\\u5168\", \"\\u5168\", objectEmulatingUndefined(), objectEmulatingUndefined(), \"\\u5168\", \"\\u5168\", objectEmulatingUndefined(), \"\\u5168\", \"\\u5168\", (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), \"\\u5168\", (1/0), (1/0), objectEmulatingUndefined(), (1/0), (1/0), objectEmulatingUndefined(), \"\\u5168\", (1/0), objectEmulatingUndefined(), \"\\u5168\", (1/0), \"\\u5168\", (1/0), \"\\u5168\", objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (1/0), objectEmulatingUndefined(), \"\\u5168\", objectEmulatingUndefined(), \"\\u5168\", objectEmulatingUndefined(), \"\\u5168\", \"\\u5168\", objectEmulatingUndefined(), \"\\u5168\", objectEmulatingUndefined()]) { yield 11; } } else h1.iterate = (function mcc_() { var krrila = 0; return function() { ++krrila; f2(/*ICCD*/krrila % 2 == 1);};})();");
/*fuzzSeed-169986037*/count=1631; tryItOut("print(x);");
/*fuzzSeed-169986037*/count=1632; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (i1);\n    i1 = ((~((0x8e9762dd) / ((((((0xfcb44384))>>>((0x81e49fab))))-(i1))>>>((0x413be7ba) % (0x11be8ea5))))) <= (((i1)) ^ ((\n-5\n)+(((((0x8343ebad) > (0xffffffff)))>>>((i0)-((0x1c88dcfa) != (0xffffffff))))))));\n    i0 = (i1);\n    {\n      i1 = (!(i0));\n    }\n    {\n      i0 = ((((i1))>>>(-0xfffff*((i0) ? ((abs((0x6793f57c))|0) != (~((0xd735edc8)))) : (i1)))));\n    }\n    i1 = ((((i1)) ^ ((34359738368.0))) == (((i0)+(i1)-(((0x72b70957)) ? (/*FFI*/ff(((17179869185.0)), ((32.0)), ((-2049.0)), ((1099511627777.0)), ((-73786976294838210000.0)), ((-1.0)), ((1.2089258196146292e+24)))|0) : (i0))) ^ ((((-(i0)) & (-((0x42f73969) != (0x7fffffff)))))-(i0))));\n    return +((window--).watch(new RegExp(\"\\\\W\", \"gyi\"), (let (e=eval) e)));\n  }\n  return f; })(this, {ff: a =>  { p0 + ''; } }, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [-0x100000001, 2**53+2, -Number.MAX_VALUE, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -(2**53), -0x100000000, -0, Number.MIN_SAFE_INTEGER, 0, 42, 0.000000000000001, -0x0ffffffff, -1/0, 0/0, 0x100000001, 1, Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1/0, -0x080000001, -Number.MIN_VALUE, 0x080000000, -0x080000000, -0x07fffffff, Math.PI, 0x100000000, 0x080000001, -(2**53+2), 1.7976931348623157e308, Number.MAX_VALUE, 2**53, 2**53-2, Number.MIN_VALUE]); ");
/*fuzzSeed-169986037*/count=1633; tryItOut("M:\u000cwhile(((void options('strict_mode')).eval(\"o0.t0 = a2[(x = (/*FARR*/[...[], [z1], \\\"\\\\uC9CB\\\"].filter.yoyo(x)))];\")) && 0){i1 = new Iterator(b1); }");
/*fuzzSeed-169986037*/count=1634; tryItOut("o2.a1.forEach((function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    d1 = (d1);\n    return ((-0x32c33*(i0)))|0;\n    i0 = ((((0xca70db81) / ((((((0x3665d594))>>>((0xffffffff))))+(x >>> x))>>>((0xfe050a78))))>>>((i0)+((((-0x8000000)-(0x4707650f)-(0xffffffff))>>>((Uint8ArrayView[((0x6af732f9)) >> 0]))) < (0x0)))));\n    {\n      {\n        d1 = (144115188075855870.0);\n      }\n    }\n    {\n      {\n        d1 = (((0x667be80f)) + (-9.0));\n      }\n    }\n    d1 = ((i0) ? (-1073741825.0) : (+(((i0))>>>((0x4d3cf6c3)+((((0x4e28fff0))>>>((0xfad900dc))))))));\n    return (((i0)))|0;\n  }\n  return f; })(this, {ff: Math.pow(-18, 2)}, new SharedArrayBuffer(4096)));");
/*fuzzSeed-169986037*/count=1635; tryItOut("/* no regression tests found */\n");
/*fuzzSeed-169986037*/count=1636; tryItOut("\"use strict\"; let a = intern(null), x = ((\u3056 =  /x/ )), a = window, rddqzw, x, zwfuva;print(uneval(a0));");
/*fuzzSeed-169986037*/count=1637; tryItOut("mathy5 = (function(x, y) { return ( ~ Math.fround(( ! mathy3((Math.hypot(((x ** 2**53+2) | 0), (mathy3(-Number.MIN_VALUE, Number.MIN_SAFE_INTEGER) | 0)) | 0), ((Math.fround(Math.pow((y >>> 0), Math.fround(x))) < Math.fround(Math.atan2(Math.fround(y), Math.fround((mathy4(-Number.MAX_SAFE_INTEGER, (-Number.MIN_SAFE_INTEGER >>> 0)) | 0))))) | 0))))); }); testMathyFunction(mathy5, [0, -0x100000000, 0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0x080000001, 42, -0x0ffffffff, -(2**53-2), 1, 0/0, Math.PI, -1/0, 2**53+2, -(2**53), Number.MAX_SAFE_INTEGER, 0.000000000000001, -(2**53+2), -0x080000001, 2**53, Number.MIN_VALUE, 0x0ffffffff, 1/0, -Number.MAX_VALUE, 2**53-2, -0x07fffffff, -0, 0x100000000, 0x080000000, -Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000001, -Number.MAX_SAFE_INTEGER, 0x07fffffff]); ");
/*fuzzSeed-169986037*/count=1638; tryItOut("((makeFinalizeObserver('nursery')));");
/*fuzzSeed-169986037*/count=1639; tryItOut("\"use strict\"; /*oLoop*/for (kvnfvi = 0; kvnfvi < 19; ++kvnfvi) { print(x); } ");
/*fuzzSeed-169986037*/count=1640; tryItOut("\"use strict\"; print(x);function x() { s2 += 'x'; } selectforgc(o0);");
/*fuzzSeed-169986037*/count=1641; tryItOut(";");
/*fuzzSeed-169986037*/count=1642; tryItOut("\"use asm\"; f2.valueOf = (function() { for (var j=0;j<115;++j) { f0(j%4==0); } });");
/*fuzzSeed-169986037*/count=1643; tryItOut("mathy0 = (function(x, y) { return (( + (Math.log((Math.hypot((Math.acos(((Math.imul((y >>> 0), (y >>> 0)) >>> 0) | 0)) >>> 0), Math.fround(y)) >>> 0)) >>> 0)) << (( + Math.atan(( - (( ~ y) | 0)))) | 0)); }); testMathyFunction(mathy0, [-1/0, 0x0ffffffff, -0x100000001, 1.7976931348623157e308, 0.000000000000001, 2**53-2, -0x0ffffffff, -0x080000001, -0, 2**53+2, -Number.MIN_VALUE, 0x100000000, 0x080000001, 42, 2**53, -0x100000000, 1/0, 1, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MIN_VALUE, 0x07fffffff, -Number.MAX_VALUE, Math.PI, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0x100000001, -0x07fffffff, -0x080000000, -(2**53), 0, 0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-169986037*/count=1644; tryItOut("\"use strict\"; /*RXUB*/var r = /(\\b|((?!\\1.{4,}))){536870913,}/gym; var s = \"\\n\\na\\\"\\uf4fda\\u00ea\\u07ea '\"; print(s.search(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.
