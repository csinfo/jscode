

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
/*fuzzSeed-72153729*/count=1701; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.imul(Math.abs(mathy1(((Math.atan2((Math.imul(y, x) | 0), (Math.hypot((( + (x >>> 0)) >>> 0), y) | 0)) | 0) >>> 0), (((x && y) | 0) , (( ~ (x | 0)) | 0)))), ( + Math.min(((( + (Math.trunc(Math.fround(Math.max((Math.atan(x) | 0), Math.fround(x)))) >>> 0)) >> ( + Math.log2(( + (Math.sinh(Number.MAX_VALUE) | 0))))) | 0), ( + (Math.cosh((((((Math.log(0x080000000) | y) | 0) * (-0x07fffffff | 0)) >>> 0) >>> 0)) >>> 0))))); }); testMathyFunction(mathy3, [null, [0], '/0/', (new String('')), '0', (function(){return 0;}), undefined, [], '', (new Number(0)), 0.1, objectEmulatingUndefined(), false, ({toString:function(){return '0';}}), 0, 1, NaN, /0/, -0, ({valueOf:function(){return '0';}}), (new Boolean(true)), (new Number(-0)), ({valueOf:function(){return 0;}}), true, (new Boolean(false)), '\\0']); ");
/*fuzzSeed-72153729*/count=1702; tryItOut("/*MXX3*/this.g0.ReferenceError.prototype.toString = g1.ReferenceError.prototype.toString;");
/*fuzzSeed-72153729*/count=1703; tryItOut("\"use strict\"; a1.length = 15;");
/*fuzzSeed-72153729*/count=1704; tryItOut("");
/*fuzzSeed-72153729*/count=1705; tryItOut("mathy4 = (function(x, y) { return (Math.fround(Math.min((( ! Math.fround(Math.atan(y))) >>> 0), (( + mathy0(y, ( + mathy0((x | 0), ( + (( + y) >>> 0)))))) < Math.hypot(y, (y ? -1/0 : y))))) ^ Math.fround(((Math.imul(((Math.fround(((Math.hypot((( + Math.cbrt(( + -0x0ffffffff))) | 0), Math.pow(Number.MAX_VALUE, (y >>> 0))) | 0) + (( + 1.7976931348623157e308) ? Math.fround(y) : ( + Number.MAX_VALUE)))) ? Math.atan2(x, -0x07fffffff) : ((Math.sin(x) | 0) >> ( + Math.log1p(x)))) | 0), (Math.pow(y, (( + Math.max(x, y)) >>> 0)) >>> 0)) | 0) >>> ( + ( ! ( + Math.imul(( ~ ( + 0x07fffffff)), (y >>> x)))))))); }); testMathyFunction(mathy4, [(new String('')), undefined, /0/, objectEmulatingUndefined(), '\\0', [0], (new Number(0)), ({valueOf:function(){return 0;}}), (function(){return 0;}), (new Boolean(false)), ({toString:function(){return '0';}}), 1, false, ({valueOf:function(){return '0';}}), '', (new Boolean(true)), true, [], NaN, -0, '/0/', 0.1, null, '0', 0, (new Number(-0))]); ");
/*fuzzSeed-72153729*/count=1706; tryItOut("mathy5 = (function(x, y) { return Math.ceil(( ~ Math.fround(Math.atan2(y, Math.fround(((( ! -0x080000001) * (y | 0)) | 0)))))); }); testMathyFunction(mathy5, [0x100000000, -0x080000000, 0.000000000000001, Math.PI, -0x080000001, 2**53, -(2**53-2), -Number.MAX_VALUE, 1/0, 0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000, 1, -(2**53), 0x080000001, -0x100000000, -0x100000001, Number.MAX_VALUE, 2**53+2, -Number.MAX_SAFE_INTEGER, 42, Number.MIN_VALUE, 1.7976931348623157e308, 2**53-2, 0x0ffffffff, 0x100000001, -(2**53+2), 0, -0, -1/0, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0/0]); ");
/*fuzzSeed-72153729*/count=1707; tryItOut("mathy5 = (function(x, y) { return Math.cbrt(Math.fround(mathy1(Math.fround(( + Math.pow(Number.MAX_SAFE_INTEGER, (Math.pow((y | 0), y) | 0)))), (Math.ceil(y) | 0)))); }); testMathyFunction(mathy5, /*MARR*/[x, x, (void 0), (void 0), (void 0), x, new String(''), (void 0), (void 0), x, new String(''), (void 0), x, new String(''), new String(''), x, new String(''), x, x, new String(''), (void 0), x, x, x, x, x, x, x, x, (void 0), (void 0), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, (void 0), (void 0), x, new String(''), x, x, x, new String(''), x, x, (void 0), new String(''), (void 0), x, (void 0), new String(''), new String(''), new String(''), (void 0), x, new String(''), (void 0), (void 0), x, (void 0), x, x, x, x, x, x, x, x, x, x, x, x, x, x, new String(''), x, x, x, x, x, x, new String(''), x, x, (void 0), new String(''), (void 0), new String(''), new String(''), x, x, x, x, x, new String(''), x, new String(''), x, new String(''), x, x, x, x, x, x]); ");
/*fuzzSeed-72153729*/count=1708; tryItOut("/*infloop*/ for  each(var this.zzz.zzz in (Math.max(\"\\uB4B1\",  /x/ )).throw( /x/ )) {e1.delete(b0); }");
/*fuzzSeed-72153729*/count=1709; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return (mathy2(Math.fround(Math.min(y, Math.trunc(( + x)))), Math.cos(Math.max(( ! y), ( ! Math.tanh(Math.fround(2**53-2)))))) , Math.round((( - (x >>> 0)) >>> 0))); }); ");
/*fuzzSeed-72153729*/count=1710; tryItOut("\"use strict\"; for (var p in v0) { try { i2 + ''; } catch(e0) { } v0 = g1.runOffThreadScript(); }");
/*fuzzSeed-72153729*/count=1711; tryItOut("\"use strict\"; print(b1);");
/*fuzzSeed-72153729*/count=1712; tryItOut("\"use strict\"; s0 + i1;");
/*fuzzSeed-72153729*/count=1721; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( ~ ((Math.atan2(( ! y), (x !== Math.log2(x))) | 0) | 0)); }); ");
/*fuzzSeed-72153729*/count=1722; tryItOut("h2 = {};");
/*fuzzSeed-72153729*/count=1723; tryItOut("\"use strict\"; ;");
/*fuzzSeed-72153729*/count=1724; tryItOut("f2 = (function() { for (var j=0;j<42;++j) { this.f0(j%5==1); } });function window(x, y)\"use asm\";   var Infinity = stdlib.Infinity;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Uint8ArrayView = new stdlib.Uint8Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    i1 = (0xf110e7b2);\nv0 = Object.prototype.isPrototypeOf.call(t2, o2.m0);    i0 = ((4095.0) < (-3.022314549036573e+23));\n    i1 = (i1);\n    i0 = (i0);\n    (Uint32ArrayView[1]) = (new Error(x, let (lhtfrv) [[]]));\n    i0 = (i0);\n    i0 = ((((0x74214fc) % (0x75b3b048))>>>(((((Uint8ArrayView[4096])) | ((i1)))))));\n    (Float64ArrayView[((1)-(0xff60a8b5)) >> 3]) = ((-1025.0));\n    i0 = ((i0) ? (i1) : (i0));\n    i1 = ((513.0) > ((1) ? (+((((((-255.0)) * ((4294967296.0)))) - ((-36893488147419103000.0))))) : (Infinity)));\n    return ((((((i0)-(i0)) & ((i1))))+(i1)-(i1)))|0;\n  }\n  return f;yield (Math.atan(12));e2.add(a1);");
/*fuzzSeed-72153729*/count=1725; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    return (((i0)*0xf7f9e))|0;\n  }\n  return f; })(this, {ff: ((x = this))}, new ArrayBuffer(4096)); testMathyFunction(mathy5, [-0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53+2), 0, 1.7976931348623157e308, -0x0ffffffff, 0x080000001, -0x080000000, -0x100000000, 2**53, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 42, -(2**53-2), -1/0, 2**53-2, 1/0, 0/0, Number.MIN_VALUE, -Number.MIN_VALUE, Number.MAX_VALUE, -(2**53), Number.MAX_SAFE_INTEGER, 0x100000000, -0, 0.000000000000001, Math.PI, -0x100000001, 0x100000001, 0x07fffffff, -0x080000001, -Number.MAX_SAFE_INTEGER, 2**53+2, 1]); ");
/*fuzzSeed-72153729*/count=1726; tryItOut("g0.h0.enumerate = this.f0;");
/*fuzzSeed-72153729*/count=1727; tryItOut("\"use strict\"; const e;g1.p1 + '';");
/*fuzzSeed-72153729*/count=1728; tryItOut("for (var v of f1) { try { for (var p in m1) { Array.prototype.unshift.apply(a0, [i1, t1, g0]); } } catch(e0) { } v0 = new Number(0); }");
/*fuzzSeed-72153729*/count=1729; tryItOut("/\\B|^|(?=(.)){0,}|([]|(\\b)+)|([^])+?(?=\\B){0}/yim;function x() { g1.g1.__proto__ = i1; } p0 + '';");
/*fuzzSeed-72153729*/count=1730; tryItOut("e2.has(o0.m2);");
/*fuzzSeed-72153729*/count=1731; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return Math.fround(mathy0(Math.cos(Math.sign(((y + Math.fround(Number.MIN_SAFE_INTEGER)) >>> 0))), Math.fround(Math.max(Math.pow(( + Math.hypot(( + Math.fround((Math.imul(y, 2**53-2) ^ (Math.hypot((-Number.MAX_VALUE >>> 0), (y >>> 0)) >>> 0)))), ( + y))), y), (( ! (Math.max(( + ( + (Math.fround(Math.hypot(Math.fround(0x0ffffffff), Math.fround(-Number.MIN_SAFE_INTEGER))) >>> 0))), ((mathy0(Math.fround((Math.clz32(-0x080000001) >>> 0)), y) | 0) | 0)) | 0)) | 0))))); }); testMathyFunction(mathy1, /*MARR*/[1e+81, 1e+81, 1e+81, 1e+81, true, 1e+81, true, 1e+81, 2**53, true, 1e+81, true, 1e+81, 2**53, 2**53, 1e+81, true, 1e+81, 1e+81, true, 2**53, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 1e+81, 2**53, 1e+81, 2**53, true, 1e+81, 1e+81, true, 1e+81, 1e+81, 2**53, 2**53, 1e+81, true, true, 1e+81, 2**53, true, 1e+81, true, 1e+81, true, 2**53, 2**53, 1e+81, 1e+81, 2**53, 1e+81, true, 1e+81, 2**53, 1e+81, 2**53, 2**53, 1e+81, true, 2**53, 2**53, true, true, true, 1e+81, 1e+81, 2**53, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, 1e+81, 2**53, 1e+81, true, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, true, 1e+81, 2**53, true, true, 1e+81, 1e+81, 2**53, true, 2**53, true, true, true, 1e+81, true, 2**53, 2**53, 2**53, true, 2**53, 1e+81, 2**53, 2**53, true, 2**53, 1e+81, 1e+81, 1e+81, true, 2**53, true, 2**53, 2**53, true, 2**53, 2**53, 2**53, true, 1e+81, true, true, 2**53, 2**53, true, true, 2**53, 1e+81, 1e+81, true, 1e+81, 2**53, 2**53, 1e+81, 1e+81, 2**53, 1e+81, 1e+81, true, 2**53, 2**53, true, 2**53, 1e+81, 2**53, 2**53, 2**53, true, 2**53, true, 2**53, true, 1e+81, true, 1e+81, true, 2**53, true, 1e+81, true, 2**53, 1e+81, 1e+81, 1e+81, true, 2**53, true, 1e+81]); ");
/*fuzzSeed-72153729*/count=1732; tryItOut("var lakron = new ArrayBuffer(0); var lakron_0 = new Int8Array(lakron); lakron_0[0] = -0; print( /x/ );");
/*fuzzSeed-72153729*/count=1733; tryItOut("v2 = evaluate(\"/* no regression tests found */\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: (x % 20 == 3), noScriptRval: false, sourceIsLazy: y = Proxy.createFunction((function handlerFactory() {return {getOwnPropertyDescriptor:  /x/ , getPropertyDescriptor: undefined, defineProperty: function(){}, getOwnPropertyNames: function() { return []; }, delete: function() { return true; }, fix: function() { return []; }, has: function() { return false; }, hasOwn: function() { return false; }, get: function() { return undefined }, set: function() { return true; }, iterate: function() { return (function() { throw StopIteration; }); }, enumerate: decodeURIComponent, keys: function() { return []; }, }; })(x), offThreadCompileScript)\n, catchTermination: false }));");
/*fuzzSeed-72153729*/count=1734; tryItOut("print(uneval(o1.m0));\n/*infloop*/for(let e in (( /x/ )(25)))( '' ).bind\n");
/*fuzzSeed-72153729*/count=1735; tryItOut("h0.getPropertyDescriptor = (function(j) { f1(j); });");
/*fuzzSeed-72153729*/count=1736; tryItOut("Array.prototype.splice.call(g1.a1, 9, 10);");
/*fuzzSeed-72153729*/count=1749; tryItOut("mathy3 = (function(x, y) { return Math.fround(((Math.fround(mathy1(Math.fround(( - ((((((Math.log(x) | 0) | 0) ^ y) | 0) < ( ! (( + 0x0ffffffff) + Math.fround(y)))) | 0))), (( ~ ((Math.fround(( + x)) != x) | 0)) | 0))) | 0) > Math.fround(((((mathy0(y, ( + y)) >= (( + Math.acosh(( + (Math.fround(Math.acosh(2**53)) ** Math.fround(Math.sin(1.7976931348623157e308)))))) | 0)) | 0) == mathy0((((( ~ (0/0 | 0)) | 0) + 0x100000001) == Math.max(Math.fround(y), (( ! -Number.MAX_SAFE_INTEGER) % 2**53))), x)) | 0)))); }); testMathyFunction(mathy3, /*MARR*/[objectEmulatingUndefined(), 1e+81, objectEmulatingUndefined(),  /x/ , (-1/0), 1e+81, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), (-1/0), objectEmulatingUndefined(), objectEmulatingUndefined(), 1e+81, 1e+81, (-1/0), (-1/0), 1e+81, 1e+81, (-1/0),  /x/ , objectEmulatingUndefined()]); ");
/*fuzzSeed-72153729*/count=1750; tryItOut("a1[this.v1] = x;");
/*fuzzSeed-72153729*/count=1751; tryItOut("\"use strict\"; /*MXX3*/g0.Date.prototype.getTimezoneOffset = g1.Date.prototype.getTimezoneOffset;");
/*fuzzSeed-72153729*/count=1752; tryItOut("f2 = x;\"\\u227B\";");
/*fuzzSeed-72153729*/count=1753; tryItOut("/*tLoop*/for (let b of /*MARR*/[new Boolean(true), {}, (b) = (delete x.e), {}, new Number(1.5), new Number(1.5), {}, new Boolean(true), new Number(1.5), new Boolean(true), new Boolean(true), new Boolean(true), (b) = (delete x.e), [undefined], [undefined], new Boolean(true), new Number(1.5), [undefined], new Boolean(true), new Boolean(true), new Number(1.5), new Number(1.5)]) { /* no regression tests found */ }");
/*fuzzSeed-72153729*/count=1754; tryItOut("\"use strict\"; \"use asm\"; e1.add(g0.o2);");
/*fuzzSeed-72153729*/count=1755; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ((Math.clz32((Math.imul(( + Math.pow(2**53-2, ( + ( ! Math.fround(x))))), Math.fround(Math.abs((( - x) >>> 0)))) >>> 0)) >>> 0) % ( ! ((Math.log10((-(2**53-2) | 0)) | 0) >>> 0))); }); testMathyFunction(mathy0, [0x07fffffff, -(2**53-2), 0, -Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, -0, Number.MIN_SAFE_INTEGER, 0x100000001, -(2**53), 2**53, -0x100000000, 0x100000000, -0x080000000, 0/0, Math.PI, -0x100000001, -1/0, -0x080000001, 42, -Number.MIN_SAFE_INTEGER, 2**53-2, -Number.MAX_SAFE_INTEGER, 1, -0x0ffffffff, 1/0, -0x07fffffff, -Number.MIN_VALUE, -(2**53+2), 2**53+2, Number.MIN_VALUE, 0x080000001, 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=1756; tryItOut("for (var v of o0) { try { o2.v1 = g1.runOffThreadScript(); } catch(e0) { } try { o0 = m0.get((~this.__defineGetter__(\"e\", Array.prototype.reverse))); } catch(e1) { } try { for (var p in a2) { try { print(v2); } catch(e0) { } try { v0 = Object.prototype.isPrototypeOf.call(t1, g1.g2); } catch(e1) { } try { /*ADP-2*/Object.defineProperty(a1, 9, { configurable: (let (a = window) a), enumerable: (x % 6 == 2), get: (function() { try { f1 = m0.get(h2); } catch(e0) { } t1.set(t1, 19); return g1.o1; }), set: (function() { try { print(uneval(g1.v2)); } catch(e0) { } try { this.v0 + ''; } catch(e1) { } try { e1 = x; } catch(e2) { } s2 += s2; return i2; }) }); } catch(e2) { } print(t2); } } catch(e2) { } /*MXX2*/g2.g2.String.prototype.charCodeAt = i0; }");
/*fuzzSeed-72153729*/count=1757; tryItOut("t2.set(t1, 11);");
/*fuzzSeed-72153729*/count=1758; tryItOut("mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    return ((((0x3935122b) < ((((imul((i2), (i1))|0))) << (((-1.2089258196146292e+24) != (+(0x7fffffff)))-((0x681b43bf))-(0xd551c398))))-(i2)))|0;\n  }\n  return f; })(this, {ff: decodeURIComponent}, new SharedArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(), x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, objectEmulatingUndefined(), x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, objectEmulatingUndefined(), objectEmulatingUndefined(), x, x]); ");
/*fuzzSeed-72153729*/count=1759; tryItOut("h1.getOwnPropertyNames = Uint16Array;");
/*fuzzSeed-72153729*/count=1760; tryItOut("a1 + '';");
/*fuzzSeed-72153729*/count=1761; tryItOut("\"use strict\"; h2.__proto__ = g1;");
/*fuzzSeed-72153729*/count=1762; tryItOut("mathy1 = (function(x, y) { return (((Math.imul(Math.sqrt(( + (( - (Math.pow((y >>> 0), (y >>> 0)) >>> 0)) <= Math.exp((x >>> 0))))), ( + ( + mathy0(((((-0x080000000 | 0) , (y | 0)) | 0) >>> 0), (y >>> 0))))) | 0) + (Math.sign(( ~ x)) | 0)) | 0); }); testMathyFunction(mathy1, [-0x100000000, -(2**53), 2**53, -1/0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -0x07fffffff, -0x100000001, 1.7976931348623157e308, -0x0ffffffff, 2**53-2, -0, 42, -0x080000000, 1, 1/0, 0x100000001, 0.000000000000001, 0x07fffffff, -Number.MIN_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, 2**53+2, -(2**53+2), Number.MIN_VALUE, Number.MAX_VALUE, 0x0ffffffff, -(2**53-2), -Number.MIN_SAFE_INTEGER, 0x080000000, Math.PI, 0, -0x080000001, 0/0, -Number.MAX_VALUE, 0x100000000]); ");
/*fuzzSeed-72153729*/count=1763; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return ( + Math.atan2(( + Math.fround((Math.min(Math.sqrt(Math.fround(Math.hypot(Math.fround((( + -(2**53+2)) > ( + x))), x))), (Math.cosh(Math.fround(Math.pow(Math.fround(y), (x >>> 0)))) & ((y >>> 0) ? x : (x + ( + (( - x) >>> 0)))))) / (Math.fround(Math.hypot(( ~ (-0x0ffffffff >>> 0)), x)) ? x : (Math.fround(((1/0 ? -Number.MIN_VALUE : (( + Math.hypot(( + y), ( + Number.MAX_VALUE))) | 0)) / (Math.fround(y) == (y >>> 0)))) + Math.fround((Math.round(y) >>> ((Math.fround((Math.fround((y >>> 0)) | 0)) | 0) >>> 0)))))))), ( + Math.trunc((-0 ? y : ((y == x) >> Math.fround(((Math.atan(( + y)) >>> 0) * Math.fround(x))))))))); }); ");
/*fuzzSeed-72153729*/count=1764; tryItOut("\"use strict\"; mathy3 = (function(x, y) { return Math.hypot(( - Math.fround(( ~ Math.fround((Math.exp((Math.acosh(x) | 0)) | 0))))), (mathy1((((x | 0) ** (Math.imul((y | 0), ( ~ (( - Number.MAX_VALUE) | 0))) | 0)) | 0), ( + mathy1((( ~ Math.fround(((x | 0) >= Math.fround(x)))) >>> 0), (Math.expm1(Math.cos(x)) >>> 0)))) >>> 0)); }); testMathyFunction(mathy3, [-(2**53), -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MAX_VALUE, -0x100000001, Number.MAX_SAFE_INTEGER, -0x100000000, -0x0ffffffff, 0x080000001, -1/0, Math.PI, 0x07fffffff, -(2**53+2), 1/0, 0.000000000000001, 0/0, 2**53-2, -0, Number.MIN_VALUE, 0, 0x0ffffffff, 42, -0x080000000, 1.7976931348623157e308, 0x100000001, -Number.MIN_VALUE, 2**53, 2**53+2, -(2**53-2), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 1, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000]); ");
/*fuzzSeed-72153729*/count=1765; tryItOut("\"use strict\"; v1 = evaluate(\"/*vLoop*/for (twnhwi = 0, (uneval(x)), (4277); twnhwi < 24; ++twnhwi) { d = twnhwi; print(uneval(e2)); } \", ({ global: g0, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: (x % 3 != 1), noScriptRval: (x % 10 == 1), sourceIsLazy: false, catchTermination: (x % 6 == 3) }));");
/*fuzzSeed-72153729*/count=1766; tryItOut("Object.getOwnPropertyDescriptorsArray.prototype.shift.apply(a2, [/(\\3){2,}/gym, s1, e0, s2, 28, e1, v2]);");
/*fuzzSeed-72153729*/count=1767; tryItOut("\"use strict\"; function(q) { return q; }d;");
/*fuzzSeed-72153729*/count=1768; tryItOut("/*bLoop*/for (var tdwxlb = 0; tdwxlb < 47; ++tdwxlb) { if (tdwxlb % 4 == 1) { throw new RegExp(\"\\\\3\", \"gym\"); } else { f2.valueOf = (function() { try { v1 = g0.eval(\"this\"); } catch(e0) { } try { g1.o0.h0.__proto__ = v1; } catch(e1) { } try { t1 = g2.t1.subarray(15); } catch(e2) { } b0 + s0; return g2; }); }  } ");
/*fuzzSeed-72153729*/count=1769; tryItOut("/*infloop*/L:for(b; x; mathy0) {b;\ng0.o1.s2 = '';\nL:for(var w in ((offThreadCompileScript)((null))))g1[\"toSource\"] = t0; }");
/*fuzzSeed-72153729*/count=1770; tryItOut("/*infloop*/while((((\"\\uB403\")) &= (w = x))) for (var y of \"\\u6E28\") {print(y);(1 for (x in [])) }");
/*fuzzSeed-72153729*/count=1771; tryItOut("mathy3 = (function(x, y) { \"use asm\"; return mathy0(Math.acosh(( - (((x >>> 0) >= (Math.atan2(x, (Number.MIN_SAFE_INTEGER | 0)) >>> 0)) >>> 0))), ( + ( - (Math.max((( + ((x * -0x080000001) ? ( + mathy2(0x080000000, (x >>> 0))) : ( + y))) | 0), ((( ! Math.fround(Math.imul(-0x100000001, ( + y)))) | 0) | 0)) | 0)))); }); testMathyFunction(mathy3, [-0x100000000, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 0x080000001, 1/0, 42, -0x07fffffff, 1.7976931348623157e308, 2**53-2, -0, 0/0, -0x0ffffffff, -(2**53-2), -(2**53), -0x080000001, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, Math.PI, 0, -0x100000001, 0x080000000, -Number.MAX_VALUE, 1, 0.000000000000001, 0x07fffffff, 0x100000001, -(2**53+2), -Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, Number.MAX_SAFE_INTEGER, 0x100000000, 0x0ffffffff, 2**53+2, -1/0]); ");
/*fuzzSeed-72153729*/count=1772; tryItOut("h1.defineProperty = (function() { try { s2.valueOf = (function() { for (var j=0;j<76;++j) { f0(j%4==1); } }); } catch(e0) { } o2.v1 = g0.runOffThreadScript(); return g2.i1; });");
/*fuzzSeed-72153729*/count=1773; tryItOut("h0.__proto__ = m1;");
/*fuzzSeed-72153729*/count=1774; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  var Int32ArrayView = new stdlib.Int32Array(heap);\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return ((((Int32ArrayView[0]))-(i1)+((0x98e5c989) > (((i1)+(i0))>>>((i0)-(i1)+((0x93db399d)))))))|0;\n  }\n  return f; })(this, {ff: ({x: (\"\\u31C7\")(undefined, true),  set 1 NaN (a, window = true)\"use asm\";   var imul = stdlib.Math.imul;\n  var NaN = stdlib.NaN;\n  var abs = stdlib.Math.abs;\n  var exp = stdlib.Math.exp;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -70368744177664.0;\n    var d3 = -4611686018427388000.0;\n    return +((d0));\n    {\n      (Uint32ArrayView[0]) = (((imul((0x27242ea1), ((d2) >= (NaN)))|0) >= (abs(((((((0x88a6a2f4))>>>((0xf8352de7))))) ^ ((0xffffffff))))|0)));\n    }\n    d0 = (+(0.0/0.0));\n    return +((+exp(((+((d3)))))));\n  }\n  return f; }) *= intern(/(?!$)/im)}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-0x100000001, -1/0, -0x100000000, 0, -0x0ffffffff, 0.000000000000001, -(2**53), 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0/0, Math.PI, 1.7976931348623157e308, 0x100000000, 2**53-2, 42, -0, 0x080000000, 1, -Number.MIN_VALUE, -0x080000000, 0x100000001, Number.MAX_VALUE, -(2**53-2), -0x07fffffff, Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 1/0, 0x080000001, -(2**53+2), 2**53+2, 2**53, 0x07fffffff, -Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=1775; tryItOut("mathy5 = (function(x, y) { return ((mathy4(Math.exp(x), x) >= ((x / ( ! (((( - -0x100000000) ? (x >>> 0) : (x >>> 0)) >>> 0) >>> 0))) * Math.cos(( - (Math.clz32(( + x)) | 0))))) != ( + ( + Math.exp(-(2**53))))); }); testMathyFunction(mathy5, [-0x07fffffff, Number.MAX_VALUE, Number.MIN_VALUE, 0x100000001, Math.PI, 0x080000000, 2**53, -0x100000001, 2**53-2, -0x080000001, -Number.MIN_VALUE, 0x07fffffff, -0, -0x080000000, -Number.MAX_VALUE, 0/0, -(2**53-2), -(2**53), 1/0, 0x0ffffffff, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0x100000000, -(2**53+2), 0, 0x080000001, -1/0, 2**53+2, -0x0ffffffff, 1, 0.000000000000001, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42]); ");
/*fuzzSeed-72153729*/count=1776; tryItOut("v2 = g1.g2.runOffThreadScript();");
/*fuzzSeed-72153729*/count=2049; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2050; tryItOut("v2 = a2.length;");
/*fuzzSeed-72153729*/count=2051; tryItOut("mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var sqrt = stdlib.Math.sqrt;\n  var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Uint32ArrayView = new stdlib.Uint32Array(heap);\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Uint32ArrayView[4096]) = ((((((0x9a8a90dc) > (0xbef330c0))+((~((0xf9d47e8c)+(0xa5766911)-(0xd178e5ab)))))>>>((0xfda4eaab)-((((0xffffffff)) | ((0x10790d3))) < (((0xfc9af1e0)) >> ((0xfd890656)))))) <= ((((((0xfc23e7e1)) ^ ((0x893efca2))))+(i1)+(-0x42aba43))>>>((0xffffffff))))+(0x3b77faf)-((i1) ? (0xdc13270d) : (0xbea5b30e)));\n    i1 = (/*FFI*/ff(((d0)), ((d0)), ((d0)), ((((7.555786372591432e+22)) % (((i1) ? ((-281474976710657.0) <= (4194305.0)) : (0x4102e246))))), ((~~(((-536870913.0)) % ((d0))))), ((+sqrt(((Float64ArrayView[((Int8ArrayView[2])) >> 3]))))), ((d0)), ((abs((((0x8911a49a))|0))|0)), ((d0)), ((1025.0)))|0);\n    i1 = (i1);\n    return (((0x35f986c5)))|0;\n  }\n  return f; })(this, {ff: decodeURI}, new ArrayBuffer(4096)); testMathyFunction(mathy3, [-(2**53+2), -0x07fffffff, -0x100000001, -0x100000000, 42, 2**53, -Number.MIN_VALUE, 2**53-2, 0, 0x07fffffff, -(2**53), -0x080000000, -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, 1/0, -Number.MAX_VALUE, 0.000000000000001, 0x100000000, 0x080000001, -1/0, 0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0x080000001, 0x100000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, -(2**53-2), 2**53+2, 0/0, -Number.MIN_SAFE_INTEGER, 1, Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=2052; tryItOut("v2 = t0.length;");
/*fuzzSeed-72153729*/count=2053; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.pow(( + Math.hypot(Math.fround(((Math.min(Math.fround(( + x)), ( - y)) ? 0x080000000 : (( + ( ~ Math.fround(Math.expm1((x >>> 0))))) | 0)) >>> 0)), Math.fround(( + Math.trunc(( ~ y)))))), ( + Math.max(( + (mathy1((x | 0), x) >>> 0)), ( + mathy0((( - x) + ( + ( + mathy0(-0x07fffffff, ( + y))))), ( + (Math.min(Math.fround(( + y)), Math.fround(2**53)) >>> 0))))))); }); ");
/*fuzzSeed-72153729*/count=2054; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.fround(( - mathy0(Math.fround(( + Math.fround(( ! -Number.MAX_SAFE_INTEGER)))), Math.fround(( - Math.fround((Math.cbrt((Math.fround(( + -0x100000001)) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy2, [Number.MIN_VALUE, -0x07fffffff, 0, Number.MAX_VALUE, -0x080000001, -(2**53-2), -Number.MIN_VALUE, 1, 1/0, -(2**53), 0x100000000, -0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -Number.MAX_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 1.7976931348623157e308, 0.000000000000001, -1/0, -0x080000000, 0x100000001, 0/0, -0x100000001, 42, 0x0ffffffff, -0x100000000, 2**53+2, Math.PI, 2**53-2, Number.MAX_SAFE_INTEGER, 0x080000001, 2**53, 0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000000]); ");
/*fuzzSeed-72153729*/count=2055; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ( + mathy0(( + Math.log10(Math.sinh(Math.fround(y)))), ( + (((Math.cosh((x | 0)) >>> 0) ? Math.fround(mathy0(-0x080000001, ( + mathy0(( + x), ( + Math.asin(x)))))) : Math.fround(x)) >>> 0)))); }); testMathyFunction(mathy1, [-Number.MAX_SAFE_INTEGER, 0.000000000000001, 0x100000000, -0x100000001, Number.MAX_SAFE_INTEGER, 0x080000001, 0x0ffffffff, 0/0, -0x07fffffff, Number.MIN_VALUE, 0x07fffffff, 0x080000000, 1/0, Number.MAX_VALUE, 2**53+2, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 1, 42, 0, -0x100000000, -Number.MAX_VALUE, -0, 2**53, -Number.MIN_VALUE, -0x080000000, -(2**53), -(2**53+2), 0x100000001, -(2**53-2), 2**53-2, -0x0ffffffff, -0x080000001, -1/0, Number.MIN_SAFE_INTEGER, Math.PI]); ");
/*fuzzSeed-72153729*/count=2056; tryItOut("\"use strict\"; /*infloop*/for(([z1,,].watch(\"entries\", x &= x)); Math.pow(/*RXUE*/new RegExp(\"(\\\\3|[^]\\\\1\\\\b|.|\\\\x1a+?)+\", \"ym\").exec(\"\\n\\u00f1\\u00f1\\u00f10\\u001a\\u001a\\u001a\"), x); (Math.exp(14))) this.h1.defineProperty = f2;");
/*fuzzSeed-72153729*/count=2057; tryItOut("mathy4 = (function(x, y) { return (Math.imul((( ! (((Math.clz32(( + x)) | 0) <= (y | 0)) | 0)) >>> 0), (((Math.asinh((Math.asin(y) >>> 0)) >>> 0) / (Math.log1p(Math.log10(((Math.imul(-Number.MAX_SAFE_INTEGER, ( + -Number.MAX_SAFE_INTEGER)) >>> 0) != y))) >>> 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, -(2**53), -0x07fffffff, -0x080000000, 0x100000000, -0x0ffffffff, -0x100000000, 0.000000000000001, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Math.PI, 0x0ffffffff, 2**53-2, 1, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -0, 2**53+2, -1/0, -0x080000001, 0x07fffffff, -(2**53+2), 0/0, 2**53, 0x080000000, -0x100000001, Number.MAX_VALUE, 1.7976931348623157e308, 0x100000001, Number.MIN_VALUE, -(2**53-2), 0x080000001, 1/0, 42, -Number.MIN_VALUE]); ");
/*fuzzSeed-72153729*/count=2058; tryItOut("\"use strict\"; t0[18] = h1;");
/*fuzzSeed-72153729*/count=2059; tryItOut("v0 = r0.toString;");
/*fuzzSeed-72153729*/count=2060; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-72153729*/count=2065; tryItOut("\"use strict\"; let tfnihu, z = (Math.ceil(x)), y = ((uneval(new RegExp(\"\\\\2(?=\\\\B{4,})*?|(?:[^])+?\\\\cO|\\\\r{17179869183,17196646400}(?:[\\\\cR-\\\\x65\\\\uaE0b-\\\\u941E\\\\\\u00cc\\u15db-\\\\ue479]^**)|(?:[^]|[^]+?)|\\\\r*|(?=.+?)\\\\1\", \"gyi\")))), {} = /(?!(?:(?!.|\u43fe))){1,}|(\\B|(?:[\\u00AD\\u0081-\\u00cD]|[^])**)/i.watch(\"valueOf\", ({/*TOODEEP*/})), e = undefined, w;var o2 = {};");
/*fuzzSeed-72153729*/count=2066; tryItOut("mathy0 = (function(x, y) { \"use strict\"; \"use asm\"; return Math.abs(Math.sin((((Math.max(-(2**53-2), Math.imul(y, y)) >>> 0) * -0x07fffffff) + ( + Math.max(( + (( + x) != Math.atan2((y | 0), Number.MIN_VALUE))), ( + (( + (((x | 0) ? Math.fround(( ~ y)) : Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0))))))); }); testMathyFunction(mathy0, [-0x0ffffffff, -(2**53-2), -0, -1/0, 2**53+2, Number.MAX_VALUE, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x080000000, 0x100000001, -(2**53+2), 2**53, 1.7976931348623157e308, 0x080000001, Math.PI, Number.MAX_SAFE_INTEGER, 0/0, 1/0, 0x07fffffff, -(2**53), 0x080000000, -Number.MIN_VALUE, 1, -0x100000001, 2**53-2, -0x07fffffff, -Number.MAX_VALUE, 42, 0, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0.000000000000001, 0x100000000, -0x080000001]); ");
/*fuzzSeed-72153729*/count=2067; tryItOut("\"use strict\"; \"use asm\"; for (var p in o2.i0) { try { v0 = evaluate(\"o2.o0.a0 = r2.exec(s1);\", ({ global: this.g0, fileName: null, lineNumber: 42, isRunOnce: true, noScriptRval: true, sourceIsLazy: (x % 6 != 2), catchTermination: (x % 77 == 74) })); } catch(e0) { } try { m1.has(e1); } catch(e1) { } m0.set((--delete a.NaN[\"__iterator__\"]), (4277)); }");
/*fuzzSeed-72153729*/count=2068; tryItOut("mathy4 = (function(x, y) { return Math.fround(Math.pow(( + Math.sin(( + ( + Math.max(( + y), Math.fround(mathy3(Math.fround((( + (Math.fround((Math.fround(y) + Math.fround(Number.MIN_SAFE_INTEGER))) >>> 0)) >>> 0)), Math.atanh(x)))))))), Math.fround((Math.imul((((((mathy3((y >>> 0), (mathy0(Math.fround(Math.imul(Math.fround(y), Math.fround(y))), (y ? x : Math.min(y, 0x100000000))) >>> 0)) >>> 0) >>> 0) ^ (Math.pow(x, Math.fround(y)) >>> 0)) >>> 0) | 0), Math.fround(Math.pow(Math.fround(Math.fround(( - Math.imul(Math.fround(y), (y >>> 0))))), x))) | 0)))); }); testMathyFunction(mathy4, [Math.PI, 0x100000000, Number.MAX_VALUE, 42, 0x0ffffffff, -0x100000001, -0x080000000, -1/0, 1/0, -0x0ffffffff, -(2**53), -Number.MIN_SAFE_INTEGER, -0, 1.7976931348623157e308, 0x100000001, 2**53-2, -0x07fffffff, 0, 2**53, 0x080000001, Number.MIN_VALUE, 0x07fffffff, -(2**53+2), Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, -Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), 1, Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0.000000000000001, -0x080000001, 0x080000000, -Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=2069; tryItOut("let(c) { c.fileName;}");
/*fuzzSeed-72153729*/count=2070; tryItOut("mathy3 = (function(x, y) { return (Math.fround(Math.atan2((Math.fround(mathy1(Math.fround(Math.fround(Math.atan2(Math.fround(mathy2(x, (((y >>> 0) <= (-Number.MAX_SAFE_INTEGER >>> 0)) >>> 0))), (Math.pow((y >>> 0), (Math.hypot(x, y) >>> 0)) >>> 0)))), (( ~ ((Math.max(Number.MIN_SAFE_INTEGER, ((Math.max((x | 0), (y | 0)) | 0) >>> 0)) >>> 0) >>> 0)) >>> 0))) | 0), Math.fround(( - ( + Math.sinh(x)))))) && (( ! (Math.fround(( + Math.fround(((y | ( ! (Math.asinh((0.000000000000001 >>> 0)) >>> 0))) | 0)))) >>> 0)) >>> 0)); }); ");
/*fuzzSeed-72153729*/count=2071; tryItOut("mathy1 = (function(x, y) { return (mathy0((((Math.fround(Math.pow(Math.fround(Math.acosh(Math.pow(( + y), x))), Math.fround(Math.fround(mathy0(Math.fround(x), Math.fround(y)))))) | 0) ? (( ~ ( + -0x080000001)) && (((( - y) >>> 0) & (mathy0(0, y) >>> 0)) >>> 0)) : (( + Math.hypot(( + y), ( + ((( + Math.atan2((x | 0), ( + x))) / y) >= (y || x))))) | 0)) | 0), (( + ((((( + (y <= (-0x080000000 | 0))) != ( + Math.pow(x, y))) >>> 0) - y) | 0)) | 0)) | 0); }); testMathyFunction(mathy1, [0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1.7976931348623157e308, 2**53-2, -Number.MAX_VALUE, -(2**53), -0x0ffffffff, -0, Number.MIN_SAFE_INTEGER, -0x080000000, -(2**53-2), Math.PI, -Number.MIN_VALUE, Number.MIN_VALUE, 0x100000000, -Number.MAX_SAFE_INTEGER, -(2**53+2), 2**53, 0/0, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0, 0, 0x080000000, 0x100000001, 0x080000001, -0x080000001, 0x07fffffff, -0x100000001, 1/0, 1, Number.MAX_VALUE, 2**53+2, -0x100000000]); ");
/*fuzzSeed-72153729*/count=2072; tryItOut("( '' );let z = (Math.hypot(Math.ceil( /x/g ), x));");
/*fuzzSeed-72153729*/count=2073; tryItOut("a0 = [];");
/*fuzzSeed-72153729*/count=2074; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (( + (((0x07fffffff >>> 0) ^ (-0x100000000 >>> 0)) >>> 0)) == (Math.fround(( /x/ .throw(new RegExp(\"(?:\\\\3)\", \"gi\")) | 0)) | 0)); }); testMathyFunction(mathy1, /*MARR*/[[undefined], [undefined], [undefined], undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined]); ");
/*fuzzSeed-72153729*/count=2075; tryItOut("s0 = t2[({valueOf: function() { /*infloop*/for(var [{x: set, x: x, z: {}, b: {}}, c, , , , {a: {e}, eval: NaN, x: x, x: {window: {}, b, e: \u000c{c: this}, NaN: c}}] = x; (p={}, (p.z = (a) = (eval(\"o2.m0.set(s1, i2);\")))()); (uneval(let (w = x) allocationMarker()))) {g0.v0 = evaluate(\"function f1(s1) \\\"use asm\\\";   var acos = stdlib.Math.acos;\\n  var Float64ArrayView = new stdlib.Float64Array(heap);\\n  function f(d0, d1)\\n  {\\n    d0 = +d0;\\n    d1 = +d1;\\n    d1 = (1024.0);\\n    d0 = (+(0.0/0.0));\\n    d0 = ((+(0x574b00ad)) + (((0x1c66b580) ? ((0xfc472220) ? (0xfb8576ef) : (0xfc20fee4)) : (0xfe865996)) ? (+acos(((d1)))) : (d0)));\\n    {\\n      {\\n        d1 = (d0);\\n      }\\n    }\\n    d0 = (-((d1)));\\n    return +((((d1)) / ((d1))));\\n    return +((Float64ArrayView[(((0xdfadbf80))-(((-0x64f61*(0xfcd6aa6c))>>>((-0x8000000)+(0xf8aaf75e)-((-8191.0) >= (-70368744177664.0)))))) >> 3]));\\n  }\\n  return f;\", ({ global: g1, fileName: null, lineNumber: 42, isRunOnce: (x % 67 != 8), noScriptRval: true, sourceIsLazy: true, catchTermination: (x % 18 == 9) }));let (x, x, z, oiqsos, hobekl, vptggz) { for (var p in f2) { print(i1); } } }return 10; }})];");
/*fuzzSeed-72153729*/count=2076; tryItOut("\"use strict\"; ");
/*fuzzSeed-72153729*/count=2077; tryItOut("\"use strict\"; g1.o1 = new Object;");
/*fuzzSeed-72153729*/count=2078; tryItOut("a1 = /*FARR*/[];");
/*fuzzSeed-72153729*/count=2079; tryItOut("mathy3 = (function(x, y) { return (Math.atan2((( + ( + ( + y))) ? Math.min(Math.fround(Math.sqrt(y)), ((( + (y | 0)) | 0) && y)) : ( + Math.fround(mathy0(( - x), Math.fround(mathy0(Math.fround(mathy0(x, Number.MIN_VALUE)), Math.fround(y))))))), (( + ( ~ ( + Math.fround(Math.log(Math.fround(( + x))))))) | 0)) | 0); }); testMathyFunction(mathy3, [-0x100000001, -(2**53), 2**53-2, 0, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000001, 0.000000000000001, 42, -0x0ffffffff, 1, 2**53, Math.PI, 0x0ffffffff, Number.MAX_VALUE, 0/0, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x080000000, -0, -0x080000001, 1/0, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53-2), 0x100000000, -Number.MIN_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), -0x100000000, 1.7976931348623157e308, 0x07fffffff, 2**53+2, -0x07fffffff]); ");
/*fuzzSeed-72153729*/count=2080; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return ( + (mathy0(( + Math.min(mathy0(y, mathy0(x, y)), Math.cbrt((Math.trunc(( + x)) >>> 0)))), mathy0(y, ( ! Math.fround((Math.fround((Math.trunc(((0x0ffffffff >>> -Number.MIN_SAFE_INTEGER) >>> 0)) >>> 0)) & y))))) | 0)); }); testMathyFunction(mathy1, [-0x080000001, Number.MIN_SAFE_INTEGER, 42, Number.MAX_VALUE, -Number.MIN_VALUE, -0x080000000, -0x07fffffff, -0x100000001, 1/0, -Number.MAX_SAFE_INTEGER, -(2**53-2), Number.MAX_SAFE_INTEGER, 0x07fffffff, 0x080000001, 0x0ffffffff, 0x080000000, 0/0, Math.PI, 0x100000001, -0, -(2**53+2), 0.000000000000001, -1/0, 1, -0x0ffffffff, 2**53, -Number.MIN_SAFE_INTEGER, -(2**53), Number.MIN_VALUE, 1.7976931348623157e308, -Number.MAX_VALUE, 2**53-2, 0x100000000, 2**53+2, 0, -0x100000000]); ");
/*fuzzSeed-72153729*/count=2113; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.round((Math.max((( ~ Math.tanh(x)) >>> 0), (Math.fround((Math.fround((Math.atan(Math.fround(( + Math.fround(( ~ (x | 0)))))) >>> 0)) , ( + ( + ((x / -0x100000000) >>> 0))))) >>> 0)) >>> 0)); }); testMathyFunction(mathy2, [0x080000001, -(2**53-2), Number.MAX_VALUE, -0x100000000, -0x080000001, 0, 0x100000000, -Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 1/0, 2**53, 0x080000000, Math.PI, -1/0, 2**53+2, 0/0, 0x07fffffff, -0x0ffffffff, -0, -(2**53+2), Number.MIN_VALUE, 1, 0.000000000000001, 1.7976931348623157e308, 0x100000001, -0x100000001, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 2**53-2, 0x0ffffffff, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 42, -0x080000000, -(2**53), -Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=2114; tryItOut("testMathyFunction(mathy1, [-0x080000001, 1.7976931348623157e308, -0x100000000, 2**53+2, -(2**53-2), 2**53, -0x100000001, -(2**53+2), Number.MIN_SAFE_INTEGER, -(2**53), 0x080000000, -0x0ffffffff, -0, 0, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, Number.MAX_VALUE, 0x100000000, Number.MAX_SAFE_INTEGER, 0x080000001, -1/0, 0x100000001, 2**53-2, 0x0ffffffff, 1, -Number.MIN_SAFE_INTEGER, 42, -0x080000000, 0/0, -Number.MIN_VALUE, Number.MIN_VALUE, 0.000000000000001, Math.PI, 1/0, -Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=2115; tryItOut("Array.prototype.pop.apply(a2, []);");
/*fuzzSeed-72153729*/count=2116; tryItOut("\"use strict\"; m2.has(m2);");
/*fuzzSeed-72153729*/count=2117; tryItOut("/*bLoop*/for (qgcead = 0, x; qgcead < 4; ++qgcead) { if (qgcead % 31 == 23) { yield; } else { print(29); }  } ");
/*fuzzSeed-72153729*/count=2118; tryItOut("\"use strict\"; testMathyFunction(mathy5, [0x07fffffff, -0x0ffffffff, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, Math.PI, -0x07fffffff, 0, 2**53+2, -Number.MAX_VALUE, 2**53-2, 1/0, 2**53, Number.MAX_SAFE_INTEGER, 0/0, -(2**53), -1/0, 42, -(2**53+2), -(2**53-2), -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0, 0x080000001, -Number.MIN_VALUE, -0x080000000, 1, 0x0ffffffff, -0x100000000, 0.000000000000001, 0x080000000, 0x100000000, -0x100000001, -0x080000001]); ");
/*fuzzSeed-72153729*/count=2119; tryItOut("selectforgc(this.o1);");
/*fuzzSeed-72153729*/count=2120; tryItOut("/* no regression tests found */\n/*infloop*/for(x = window; 13; ++\"\\u459B\".a\u0009) for (var p in o0) { s0 += s0; }\n");
/*fuzzSeed-72153729*/count=2121; tryItOut("\"use strict\"; /*oLoop*/for (rjubmz = 0; rjubmz < 24; ++rjubmz) { /*vLoop*/for (dspzyu = 0; dspzyu < 16; ++dspzyu) { c = dspzyu; print((/*PTHR*/(function() { for (var i of []) { yield i; } })())); }  } ");
/*fuzzSeed-72153729*/count=2122; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2123; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return Math.sqrt(( + (( + Math.fround(mathy1(Math.clz32(( + Math.log10((((x | 0) ? ((x - y) | 0) : (x | 0)) | 0)))), 0x100000001))) & ( + (((x | 0) * (0x080000000 | 0)) | 0))))); }); testMathyFunction(mathy5, [-0x080000001, 2**53-2, 1/0, 0x100000000, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, -1/0, 0, -0x080000000, -0x07fffffff, 0x080000001, Number.MAX_SAFE_INTEGER, 2**53, 1, -0x100000000, -Number.MIN_SAFE_INTEGER, Math.PI, 1.7976931348623157e308, 2**53+2, 0x0ffffffff, 0x07fffffff, Number.MIN_VALUE, 0x080000000, -(2**53-2), 42, -0x100000001, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x0ffffffff, -(2**53+2), -0, -(2**53), 0.000000000000001, 0/0, Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-72153729*/count=2124; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; return (Math.min((mathy0(( + ( + (((( - y) | 0) < (0x100000000 >>> 0)) | 0))), (((Math.fround(y) / (((Math.fround((Math.hypot((y | 0), (x | 0)) | 0)) === Math.fround(x)) | 0) >>> 0)) >>> 0) | 0)) | 0), (Math.fround(Math.acos(Math.fround((Math.round(((( + x) | 0) | 0)) | 0)))) | 0)) | 0); }); testMathyFunction(mathy1, [-0x080000001, 0x100000000, -(2**53+2), 2**53+2, 1/0, 2**53, -0x0ffffffff, Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 1, -Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), Math.PI, 0.000000000000001, -0x080000000, 0x080000000, 0x07fffffff, 42, 0x0ffffffff, -0, 0, -Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, 2**53-2, -0x100000000, 0x100000001, Number.MAX_VALUE, -Number.MAX_VALUE, -1/0, -0x100000001, -(2**53-2), -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2125; tryItOut("mathy5 = (function(x, y) { return Math.atan(( ! (((x >>> 0) ? ( ! y) : (Math.imul(( + x), -0x07fffffff) >>> 0)) >>> 0))); }); ");
/*fuzzSeed-72153729*/count=2126; tryItOut("\"use strict\"; testMathyFunction(mathy5, [1, -(2**53), -0x100000000, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, 0, -0, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), 0x080000000, -0x07fffffff, -0x080000000, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, 0x100000000, Math.PI, 2**53+2, -0x080000001, 0/0, -(2**53+2), 0x100000001, 2**53-2, 0.000000000000001, 1/0, 42, 2**53, 0x07fffffff, -1/0, Number.MAX_SAFE_INTEGER, -0x0ffffffff, Number.MAX_VALUE, -0x100000001, 0x080000001, 1.7976931348623157e308, Number.MIN_VALUE]); ");
/*fuzzSeed-72153729*/count=2127; tryItOut("print(x);");
/*fuzzSeed-72153729*/count=2128; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    {\n      d1 = (((3.022314549036573e+23)) % ((-17.0)));\n    }\n    {\n      return (((i0)))|0;\n    }\n    return (((0xdfbd99a1)+(0xbe10f8ba)-(((function a_indexing(cbadiu, mtruox) { ; if (cbadiu.length == mtruox) { ; return x; } var yjbdqr = cbadiu[mtruox]; var alvdbg = a_indexing(cbadiu, mtruox + 1); return [] = []; })(/*MARR*/[['z'], ['z'], ['z'],  '' ,  /x/g ,  /x/g , ['z'], 0x99, 0x99, (void 0),  '' , 0x99, (void 0), 0x99, ['z'], ['z'], (void 0),  /x/g ], 0)))))|0;\n  }\n  return f; })(this, {ff: (((4277).throw((let (x = window) []))) ? -15.watch(\"toString\", Int32Array) : new  \"\" (/*FARR*/[...[], ].some(String.prototype.trim, window)))}, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, [2**53, -0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, -0x080000000, -Number.MIN_SAFE_INTEGER, -(2**53), 0x080000001, -(2**53-2), 0x080000000, -0, Math.PI, -0x0ffffffff, -0x100000001, Number.MIN_SAFE_INTEGER, 0x100000000, -0x07fffffff, 2**53-2, 0/0, Number.MAX_VALUE, 0x0ffffffff, -(2**53+2), 2**53+2, 0.000000000000001, 1/0, -0x080000001, -Number.MIN_VALUE, 42, -1/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, 0x100000001, 0, 1]); ");
/*fuzzSeed-72153729*/count=2129; tryItOut("\"use strict\"; { void 0; gcslice(3951); }");
/*fuzzSeed-72153729*/count=2130; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return ((Math.fround(mathy0(Math.fround((y % (Math.max((y / 2**53-2), x) && -0x080000000))), (Math.fround(Math.min((y >>> 0), (-1/0 >>> 0))) ? ( ! Math.fround(Math.imul(Math.fround(Math.fround(((mathy0(x, 0) | 0) == (x >>> 0)))), ((( + Math.hypot(y, Number.MAX_SAFE_INTEGER)) >>> 0) ? (y >>> 0) : (y >>> 0))))) : Math.fround(( - Math.max(( + Math.round(-(2**53+2))), y)))))) | 0) * (( - (( + (Math.pow((( - y) >>> 0), Math.fround((( + x) ** ( + Math.log1p(( + y)))))) >>> 0)) < ( + (((Math.tanh(x) | 0) > (y | 0)) | 0)))) | 0)); }); testMathyFunction(mathy1, [0x080000001, 2**53, 2**53+2, 2**53-2, 0x07fffffff, Math.PI, Number.MIN_VALUE, 0/0, 1.7976931348623157e308, -0x07fffffff, -1/0, -0x080000001, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MAX_VALUE, -(2**53), -(2**53+2), -0x100000001, 0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -0x100000000, -0x080000000, -Number.MAX_SAFE_INTEGER, 1/0, 0, -Number.MIN_VALUE, -(2**53-2), 0x100000000, 1, 42, 0x080000000, -0, Number.MAX_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-72153729*/count=2131; tryItOut("mathy4 = (function(x, y) { return ( ~ ( + Math.min(( + (( + Math.log2(Math.acosh(( + mathy0(( + x), ( + x)))))) >>> 0)), (( + mathy1(( ~ ( ! (Math.tan((x >>> 0)) >>> 0))), y)) << Math.fround(Math.fround((-0x080000001 % Math.fround((( - (y >>> 0)) >>> 0))))))))); }); testMathyFunction(mathy4, /*MARR*/[\"\\u2873\", new String(''), function(){}, new Number(1.5), \"\\u2873\", \"\\u2873\", \"\\u2873\", \"\\u2873\", new Number(1.5), new Number(1.5), new Number(1.5), new String(''), new Number(1.5), function(){}, new String(''), \"\\u2873\"]); ");
/*fuzzSeed-72153729*/count=2132; tryItOut("print(x);");
/*fuzzSeed-72153729*/count=2133; tryItOut("var  /x/g  = (window >> (eval in window)), d = ((uneval(((4277).__defineGetter__(\"x\", function(q) { \"use strict\"; return q; }))))), d, set;let e =  '' ;i0.next();");
/*fuzzSeed-72153729*/count=2134; tryItOut("\"use strict\";  for  each(let a in /\uc11c|[\\w\\w]+?{4}/ym) print(a);\nv1 = (a1 instanceof f1);\n");
/*fuzzSeed-72153729*/count=2135; tryItOut("\"use strict\"; M: for (let x of (void options('strict'))) /* no regression tests found */");
/*fuzzSeed-72153729*/count=2136; tryItOut("mathy3 = (function(x, y) { return Math.fround(( ~ Math.fround((( + Math.atan(((( - (y >>> 0)) | 0) >>> 0))) ? ( + Math.max(( + ((0x07fffffff < 0x07fffffff) >>> (Math.pow((0x100000000 >>> 0), (x >>> 0)) >>> 0))), ( + Math.fround(Math.log10((( + (( ~ Math.atan2((x >>> 0), 1/0)) >>> 0)) >>> 0)))))) : ( + ( + Math.expm1(y))))))); }); testMathyFunction(mathy3, [Number.MIN_VALUE, 2**53+2, 0x0ffffffff, -1/0, 0/0, -0x0ffffffff, 0, Math.PI, -Number.MIN_SAFE_INTEGER, 2**53-2, Number.MAX_VALUE, 1/0, -(2**53), 1.7976931348623157e308, -0x080000001, 0x100000000, 0.000000000000001, 42, -0, 0x080000001, 0x100000001, 0x080000000, -0x080000000, 0x07fffffff, Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53, -(2**53+2), -0x100000001, 1, Number.MAX_SAFE_INTEGER, -0x100000000, -(2**53-2), -0x07fffffff, -Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=2161; tryItOut("mathy1 = (function(x, y) { return ( + (( + Math.trunc(Math.atan2(( + (0.000000000000001 + (y >>> 0))), Math.fround(( ! ( ~ y)))))) / ( + (Math.fround(( ~ Math.fround(( ~ (Math.pow((Math.hypot(y, y) , y), y) >>> 0))))) ? (Math.fround((Math.fround(Math.pow(( ! 0x100000001), x)) !== Math.fround(( ! ( + ( + ( + Math.sin(( + x))))))))) >>> 0) : Math.fround(((Math.log2(x) | 0) >= Math.fround((Math.sqrt((2**53 >>> 0)) >>> 0)))))))); }); testMathyFunction(mathy1, /*MARR*/[objectEmulatingUndefined(), objectEmulatingUndefined(), objectEmulatingUndefined(),  '' , Number.MAX_VALUE,  '' ,  '' , false, Number.MAX_VALUE, Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=2162; tryItOut("mathy3 = (function(x, y) { return (( + Math.pow(( + (Math.clz32((((Math.tanh((x | 0)) | 0) >>> (0x100000001 ? y : (-0x07fffffff * 0x100000000))) >>> 0)) >>> 0)), ( + ( + (( + Math.min((Math.fround(0x100000001) ? -0x07fffffff : x), (Math.max((y | 0), ( + 0/0)) >>> 0))) <= ( + (( + Math.hypot(( + Math.sqrt(x)), ( + y))) ? Math.atanh((x | 0)) : Math.round(x)))))))) >> ( + Math.fround(mathy1(Math.fround((( + Math.atan2(( + ( - ( + Math.imul(( + x), ( + y))))), ( + x))) % ( + -0))), Math.fround(Math.pow(Math.PI, Math.asin((( ! y) >>> 0)))))))); }); testMathyFunction(mathy3, [(function(){return 0;}), false, [], 0.1, '0', (new String('')), NaN, true, (new Boolean(true)), ({toString:function(){return '0';}}), ({valueOf:function(){return '0';}}), ({valueOf:function(){return 0;}}), -0, (new Number(0)), '', 0, objectEmulatingUndefined(), (new Number(-0)), (new Boolean(false)), 1, [0], '/0/', undefined, null, '\\0', /0/]); ");
/*fuzzSeed-72153729*/count=2163; tryItOut("return \"\\uECD5\";\nm0.__proto__ = f1;\n");
/*fuzzSeed-72153729*/count=2164; tryItOut("testMathyFunction(mathy0, [-0x07fffffff, -Number.MIN_SAFE_INTEGER, 0x080000001, 0.000000000000001, -0x100000001, 0x100000000, -0x080000001, Number.MAX_VALUE, -Number.MIN_VALUE, 1/0, 1.7976931348623157e308, Number.MIN_SAFE_INTEGER, 0/0, -0, -Number.MAX_VALUE, 0x07fffffff, 0, -0x100000000, -0x080000000, Math.PI, Number.MAX_SAFE_INTEGER, 2**53+2, 2**53, 1, -(2**53-2), 0x080000000, -1/0, 0x0ffffffff, -(2**53), -(2**53+2), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, 42, -0x0ffffffff]); ");
/*fuzzSeed-72153729*/count=2165; tryItOut("(window);\no2 = h1.__proto__;\n");
/*fuzzSeed-72153729*/count=2166; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return (Math.sqrt((Math.imul(((x % Math.hypot(x, (mathy0(x, x) >>> 0))) | 0), (mathy0(Math.fround(mathy0(x, y)), x) | 0)) | 0)) >>> 0); }); testMathyFunction(mathy1, [(new String('')), '\\0', ({valueOf:function(){return 0;}}), (new Number(0)), 0.1, (new Boolean(true)), true, '0', false, null, /0/, 0, 1, objectEmulatingUndefined(), -0, [0], NaN, ({valueOf:function(){return '0';}}), ({toString:function(){return '0';}}), (new Boolean(false)), '/0/', (function(){return 0;}), (new Number(-0)), '', undefined, []]); ");
/*fuzzSeed-72153729*/count=2167; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ! ((Math.exp((Math.imul((Math.min(Math.PI, (Math.min(x, x) >>> 0)) | 0), Math.fround(Math.cosh(Math.fround(Math.pow(Math.fround(y), Math.fround(42)))))) | 0)) | 0) || (Math.cbrt(Math.fround(( - x))) * ( + ( + ((( + 0x100000001) <= x) * ( + 0x07fffffff))))))) | 0); }); testMathyFunction(mathy4, [-Number.MIN_VALUE, 0x100000001, 0x07fffffff, 2**53-2, -0x080000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0x080000001, 1.7976931348623157e308, 0x0ffffffff, -0x0ffffffff, -1/0, -0x100000000, -(2**53+2), -0x07fffffff, 1, -(2**53-2), 2**53, 0x100000000, 2**53+2, -(2**53), Number.MAX_VALUE, 0x080000001, Number.MIN_SAFE_INTEGER, -0x100000001, 0, Number.MIN_VALUE, 0.000000000000001, 0x080000000, Math.PI, -Number.MIN_SAFE_INTEGER, 0/0, 42, 1/0, -Number.MAX_SAFE_INTEGER, -0]); ");
/*fuzzSeed-72153729*/count=2168; tryItOut("\"use strict\"; Array.prototype.pop.apply(a2, [g2.g2]);");
/*fuzzSeed-72153729*/count=2169; tryItOut("\"use strict\"; v0 = evaluate(\"/*tLoop*/for (let b of /*MARR*/[ /x/ ,  /x/ ,  /x/ , x,  /x/ , x,  /x/ ,  /x/ , x, x, x, x, x,  /x/ , x,  /x/ ,  /x/ , x, x, x,  /x/ , x, x, x,  /x/ , x,  /x/ , x,  /x/ ,  /x/ , x, x, x, x,  /x/ ,  /x/ , x,  /x/ , x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x,  /x/ , x, x, x,  /x/ , x,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , x, x, x, x,  /x/ , x, x,  /x/ , x,  /x/ ,  /x/ , x,  /x/ ,  /x/ ,  /x/ ,  /x/ , x,  /x/ , x, x]) { a0.shift(a2); }\", ({ global: g0, fileName: null, lineNumber: 42, isRunOnce: ++NaN, noScriptRval: x, sourceIsLazy: false, catchTermination: (x % 2 == 0) }));");
/*fuzzSeed-72153729*/count=2170; tryItOut("v0 = evaluate(\"({/*toXFun*/valueOf: q => q })\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: false, noScriptRval: (x % 95 == 55), sourceIsLazy: (uneval(/*wrap1*/(function(){ Array.prototype.splice.apply(a1, [NaN, 15]);return Uint8ClampedArray})().prototype)), catchTermination: false }));");
/*fuzzSeed-72153729*/count=2171; tryItOut("\"use strict\"; h0 = {};");
/*fuzzSeed-72153729*/count=2172; tryItOut("b1 + p0;var znimpz = new ArrayBuffer(8); var znimpz_0 = new Int8Array(znimpz); print(znimpz_0[0]); znimpz_0[0] = 13; a2 = [];");
/*fuzzSeed-72153729*/count=2173; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2174; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-72153729*/count=2175; tryItOut("this.a0.reverse(m2, o1.v2, this.o1, f2);");
/*fuzzSeed-72153729*/count=2176; tryItOut("\"use strict\"; (encodeURIComponent.prototype);");
/*fuzzSeed-72153729*/count=2305; tryItOut("");
/*fuzzSeed-72153729*/count=2306; tryItOut("\"use strict\"; \"\\u3D88\";");
/*fuzzSeed-72153729*/count=2307; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.min(Math.log2(Math.fround(Math.atan2(Math.round((Math.ceil((x >>> 0)) >>> 0)), ( + ( + Math.sqrt(( + ( - ( + -0x080000000))))))))), (( + (( + Math.max((y >>> 0), y)) | ( + Math.imul((Math.min(x, y) - (x === ( + 1/0))), x)))) & (( - y) | 0))); }); testMathyFunction(mathy0, [objectEmulatingUndefined(), [0], (new String('')), (new Boolean(true)), true, '', '0', (new Boolean(false)), (new Number(0)), 1, 0, /0/, undefined, -0, (function(){return 0;}), [], '\\0', NaN, null, ({valueOf:function(){return 0;}}), ({toString:function(){return '0';}}), '/0/', ({valueOf:function(){return '0';}}), 0.1, false, (new Number(-0))]); ");
/*fuzzSeed-72153729*/count=2308; tryItOut("testMathyFunction(mathy2, /*MARR*/[x, x, x, x]); ");
/*fuzzSeed-72153729*/count=2309; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    return (((i1)*0x2e126))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; (().throw(({b: w})));; yield y; }}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-72153729*/count=2310; tryItOut("\"use strict\"; Array.prototype.reverse.call(a1);");
/*fuzzSeed-72153729*/count=2311; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return ( + Math.round(( + Math.fround(Math.tanh(( + Math.asin(Math.fround((x ? Math.round(y) : y))))))))); }); testMathyFunction(mathy0, ['', /0/, '0', true, (new Number(-0)), 1, NaN, false, (new Boolean(false)), -0, 0.1, objectEmulatingUndefined(), ({valueOf:function(){return '0';}}), '\\0', ({toString:function(){return '0';}}), null, undefined, ({valueOf:function(){return 0;}}), (new Number(0)), [], (new String('')), [0], (function(){return 0;}), '/0/', (new Boolean(true)), 0]); ");
/*fuzzSeed-72153729*/count=2312; tryItOut("/*RXUB*/var r = /u(?=(?:\\d*)){0,4}/gi; var s = \"u\"; print(r.exec(s)); print(r.lastIndex); ");
/*fuzzSeed-72153729*/count=2313; tryItOut("g1.v2.valueOf = (function mcc_() { var sqmxyx = 0; return function() { ++sqmxyx; f0(/*ICCD*/sqmxyx % 3 == 1);};})();");
/*fuzzSeed-72153729*/count=2314; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2315; tryItOut("v1 = (a0 instanceof p1);");
/*fuzzSeed-72153729*/count=2316; tryItOut("mathy3 = (function(x, y) { return (( + (Math.hypot(Math.fround(Math.fround(((y >>> 0) == (x >>> 0)))), ( ~ y)) ** ((Math.atan2((y >= x), y) ^ mathy1(Math.log10(y), ( ! Math.fround(x)))) | 0))) == ( + ( + ( + Math.asinh(((( + (2**53+2 | 0)) | 0) | 0)))))); }); testMathyFunction(mathy3, [-0x080000001, Number.MAX_VALUE, -0, 0, 0x100000001, 0x100000000, -(2**53), 0x080000000, -0x0ffffffff, Math.PI, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 2**53+2, -(2**53-2), -0x100000001, 1/0, -Number.MIN_SAFE_INTEGER, 0x080000001, Number.MIN_SAFE_INTEGER, -0x07fffffff, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53-2, -Number.MAX_VALUE, 0/0, -1/0, 1, Number.MIN_VALUE, 2**53, -Number.MIN_VALUE, -0x100000000, 0x0ffffffff, -(2**53+2), 1.7976931348623157e308, -0x080000000, 42]); ");
/*fuzzSeed-72153729*/count=2317; tryItOut("\"use strict\"; ");
/*fuzzSeed-72153729*/count=2318; tryItOut("\"use strict\"; for(let [d, x] = (4277) in (4277)) {/*RXUB*/var r = /(?![^-\\w\\s])+?/gy; var s = \"\"; print(s.split(r));  }");
/*fuzzSeed-72153729*/count=2319; tryItOut("var w = x;s2 = new String(g0.g1.e0);let y = new this();\nm0.get(Math);\n");
/*fuzzSeed-72153729*/count=2320; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-72153729*/count=2321; tryItOut("\"use strict\"; o2 = g0.objectEmulatingUndefined();");
/*fuzzSeed-72153729*/count=2322; tryItOut("\"use strict\"; testMathyFunction(mathy5, [-0x100000001, -0x080000000, 0.000000000000001, 42, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0, 2**53, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x0ffffffff, 0x100000000, -0x100000000, 0x080000000, -(2**53), 0x07fffffff, -(2**53+2), -(2**53-2), 1/0, -0x07fffffff, 0x080000001, Number.MIN_SAFE_INTEGER, -1/0, Number.MAX_SAFE_INTEGER, Math.PI, 2**53-2, 1.7976931348623157e308, -0x080000001, 0/0, 2**53+2, Number.MAX_VALUE, 1, 0, -Number.MIN_VALUE, -Number.MAX_VALUE, 0x100000001]); ");
/*fuzzSeed-72153729*/count=2323; tryItOut("\"use strict\"; /*tLoop*/for (let e of /*MARR*/[1, false, 1, 1, false, 1, false, 1, false, false, false, false, 1, false, 1, false, 1, false, false, 1, 1, false, 1]) { print(x); }");
/*fuzzSeed-72153729*/count=2324; tryItOut("v0 = Array.prototype.reduce, reduceRight.call(g1.a1, p2, b1);");
/*fuzzSeed-72153729*/count=2325; tryItOut("{ void 0; void gc('compartment', 'shrinking'); } /*vLoop*/for (let omirrh = 0; omirrh < 49; ++omirrh) { var y = omirrh; var fqcxwc = new ArrayBuffer(2); var fqcxwc_0 = new Uint16Array(fqcxwc); print(fqcxwc_0[0]); fqcxwc_0[0] = -140737488355328; var fqcxwc_1 = new Uint8ClampedArray(fqcxwc); fqcxwc_1[0] = 27; print(fqcxwc_0[0]);{} } ");
/*fuzzSeed-72153729*/count=2326; tryItOut("\"use strict\"; mathy2 = (function(x, y) { \"use strict\"; return ( + (Math.fround(Math.sinh(Math.fround(Math.pow(x, (Math.cosh((y >>> 0)) >>> 0))))) | 0)); }); testMathyFunction(mathy2, [0, -1/0, 0x0ffffffff, -0x07fffffff, 1.7976931348623157e308, Math.PI, Number.MAX_VALUE, -0x100000000, -(2**53), 0.000000000000001, 0/0, 1/0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x100000001, -Number.MIN_VALUE, -(2**53+2), 2**53-2, -0x100000001, -0, -0x0ffffffff, -0x080000001, 2**53+2, 0x100000000, -0x080000000, 0x080000000, 1, 0x07fffffff, 0x080000001, Number.MIN_VALUE, -(2**53-2), 2**53, -Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=2327; tryItOut("s2 = new String(e2);");
/*fuzzSeed-72153729*/count=2328; tryItOut("mathy0 = (function(x, y) { return ((Math.fround(((((((((Math.atan2(Math.fround(x), x) >>> 0) ^ Math.fround(( ! Math.fround((( + Math.PI) != ( + x)))))) >>> 0) | 0) < (Math.max(( + y), ( + (-(2**53) % x))) | 0)) | 0) ? x : ((((x >>> 0) == (y >>> 0)) >>> 0) | 0)) && ( + ((0x100000001 >>> 0) >> (x >>> 0))))) + Math.fround(( ! Math.fround((Math.fround(( - Math.fround(x))) >>> Math.acosh(Math.min(y, y))))))) | 0); }); testMathyFunction(mathy0, /*MARR*/[0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x2D413CCC, 0x3FFFFFFF, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, 0x2D413CCC, false, 0x2D413CCC, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF]); ");
/*fuzzSeed-72153729*/count=2329; tryItOut("t2[(makeFinalizeObserver('tenured'))];");
/*fuzzSeed-72153729*/count=2330; tryItOut("var rzfdou = new SharedArrayBuffer(4); var rzfdou_0 = new Uint8ClampedArray(rzfdou); rzfdou_0[0] = 7; var rzfdou_1 = new Int16Array(rzfdou); print(rzfdou_1[0]); rzfdou_1[0] = -6; var rzfdou_2 = new Uint8Array(rzfdou); print(rzfdou_2[0]); rzfdou_2[0] = 15; var rzfdou_3 = new Uint8Array(rzfdou); print(rzfdou_3[0]); var rzfdou_4 = new Uint8Array(rzfdou); var rzfdou_5 = new Uint32Array(rzfdou); rzfdou_5[0] = -16; var rzfdou_6 = new Uint16Array(rzfdou); print(rzfdou_6[0]); rzfdou_6[0] = -24; var rzfdou_7 = new Float32Array(rzfdou); print(rzfdou_7[0]); rzfdou_7[0] = 28; var rzfdou_8 = new Int16Array(rzfdou); rzfdou_8[0] = 15; var rzfdou_9 = new Uint8Array(rzfdou); rzfdou_9[0] = -6; /* no regression tests found */");
/*fuzzSeed-72153729*/count=2331; tryItOut("s2 += 'x';");
/*fuzzSeed-72153729*/count=2332; tryItOut("mathy3 = (function(x, y) { return (Math.trunc((Math.imul((Math.imul(( + Math.atan2(x, x)), ( + Math.exp(42))) >>> 0), ( + (2**53-2 , x))) | 0)) >>> 0); }); testMathyFunction(mathy3, /*MARR*/[ /x/ , false, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ ,  /x/ , false, 2**53,  /x/ , 2**53, false, false, 2**53,  /x/ , false, 2**53, 2**53, false, false, 2**53, false,  /x/ ,  /x/ , false, 2**53,  /x/ ,  /x/ , false,  /x/ ,  /x/ ,  /x/ , false,  /x/ , 2**53, false,  /x/ , false, false, 2**53,  /x/ , 2**53, 2**53,  /x/ ,  /x/ ,  /x/ , 2**53,  /x/ , false,  /x/ , 2**53, 2**53,  /x/ , 2**53, 2**53]); ");
/*fuzzSeed-72153729*/count=2337; tryItOut("\"use strict\"; mathy5 = (function(x, y) { return (((( - Math.cos((( + (( ~ ( - (x | 0))) | 0)) | ( ! Math.fround((y && y)))))) >>> 0) ? (Math.asin(Math.fround(mathy4(0x100000000, Math.hypot(( + ( ~ x)), x)))) >>> 0) : (mathy3(( + (( + Math.sign(( + y))) / Math.fround(Math.imul(((y || (y | 0)) | (y | 0)), (Math.fround(Math.fround((Math.fround(x) | Math.fround(y)))) | 0))))), (Math.log1p(Math.cos(Math.fround(Math.asin(y)))) >>> 0)) >>> 0)) >>> 0); }); ");
/*fuzzSeed-72153729*/count=2338; tryItOut("mathy3 = (function(x, y) { return (Math.tan((mathy1(Math.min((2**53-2 <= Math.max(Math.fround(((mathy0((y >>> 0), (Number.MIN_VALUE | 0)) >>> 0) >> (y | 0))), Math.fround(x))), (( ~ (x >>> 0)) | 0)), ( + (Math.fround(x) > y))) | 0)) | 0); }); testMathyFunction(mathy3, [-0x0ffffffff, 1/0, -Number.MAX_VALUE, -0x080000001, 0x100000001, 42, 2**53, -(2**53-2), 0x100000000, -0x07fffffff, -0, 0/0, 0x07fffffff, 0.000000000000001, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, -1/0, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -Number.MIN_VALUE, -0x100000001, -(2**53+2), Number.MAX_VALUE, 0x0ffffffff, 2**53-2, -Number.MAX_SAFE_INTEGER, -0x100000000, 0, -0x080000000, 0x080000001, -(2**53), 1, Number.MIN_VALUE, Math.PI, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2339; tryItOut("v2 = r1.multiline;");
/*fuzzSeed-72153729*/count=2340; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround(( + ((( ~ (( + Math.asinh(( + x))) >>> 0)) | 0) >>> 0))); }); testMathyFunction(mathy3, /*MARR*/[[undefined], -0x100000000, true, [undefined], ['z'], NaN, -0x100000000, ['z'], [undefined], -0x100000000, ['z'], true, -0x100000000, [undefined], true, [undefined], -0x100000000, [undefined], ['z'], -0x100000000, NaN, ['z'], -0x100000000, -0x100000000, ['z'], [undefined], NaN, [undefined], -0x100000000, -0x100000000, [undefined], true, -0x100000000]); ");
/*fuzzSeed-72153729*/count=2341; tryItOut("f1(o0);");
/*fuzzSeed-72153729*/count=2342; tryItOut("s2 = new String(a1);");
/*fuzzSeed-72153729*/count=2343; tryItOut("mathy1 = (function(x, y) { return (Math.fround(Math.cosh(((Math.clz32(x) !== ( + Math.fround(Math.hypot((Math.sqrt(x) >>> 0), mathy0(x, y))))) | 0))) ^ (( ~ Math.fround(Math.cos((Math.hypot(((Math.max((( + (( + y) == ( + -Number.MAX_SAFE_INTEGER))) >>> 0), 0/0) >>> 0) | 0), (1 | 0)) | 0)))) >>> 0)); }); testMathyFunction(mathy1, [2**53, 1, 2**53-2, 0x100000000, Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, -Number.MIN_VALUE, 0, -1/0, 0x07fffffff, -0x100000000, -0, Math.PI, -Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_VALUE, 0/0, -(2**53-2), -0x07fffffff, 1/0, 0.000000000000001, 2**53+2, -(2**53), 0x100000001, 0x0ffffffff, -0x0ffffffff, -Number.MIN_SAFE_INTEGER, -0x080000001, 0x080000000, -0x080000000, -Number.MAX_VALUE, 42, Number.MAX_SAFE_INTEGER, 0x080000001, 1.7976931348623157e308]); ");
/*fuzzSeed-72153729*/count=2344; tryItOut("Array.prototype.pop.call(a0, v0);");
/*fuzzSeed-72153729*/count=2345; tryItOut("s1 = s0.charAt(3);");
/*fuzzSeed-72153729*/count=2346; tryItOut("m1.has(v2);");
/*fuzzSeed-72153729*/count=2347; tryItOut("\"use strict\"; a1 = Array.prototype.slice.apply(a1, [NaN, NaN]);");
/*fuzzSeed-72153729*/count=2348; tryItOut("\"use strict\"; Array.prototype.forEach.call(a2, (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Int8ArrayView = new stdlib.Int8Array(heap);\n  var Uint16ArrayView = new stdlib.Uint16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (4.722366482869645e+21);\n    d0 = (-2.4178516392292583e+24);\n    {\n      return +(((0xe8688ea9) ? (-134217729.0) : (NaN)));\n    }\n    (Float64ArrayView[1]) = ((d0));\n    i1 = (0xfd79d506);\n    d0 = (d0);\n    (Int8ArrayView[0]) = (((((i1) ? (i1) : (i1)))>>>((~~(-140737488355329.0)) % (~~(-549755813889.0)))) / (((-0x8000000)-(0x92bf6c35))>>>(((((Uint16ArrayView[1])) * ((d0))) != (-1.9342813113834067e+25)))));\n    return +((Float64ArrayView[(-(0xf99bb574)) >> 3]));\n  }\n  return f; }));");
/*fuzzSeed-72153729*/count=2349; tryItOut("Object.defineProperty(this, \"v1\", { configurable: (x % 5 != 1), enumerable: false,  get: function() {  return evalcx(\"const x = (/*UUV1*/(x.toString = q => q)), x;b2 = t0.buffer;this.v1 = a1.length;\", this.o2.g0); } });");
/*fuzzSeed-72153729*/count=2350; tryItOut("\"use strict\"; testMathyFunction(mathy3, [-0x07fffffff, Number.MAX_VALUE, 1, 0/0, -(2**53+2), -0x0ffffffff, -0x080000001, -0x080000000, Number.MAX_SAFE_INTEGER, 2**53, 2**53+2, -1/0, 42, Number.MIN_SAFE_INTEGER, -Number.MAX_VALUE, -(2**53), -Number.MAX_SAFE_INTEGER, 2**53-2, 0x100000001, 0, Number.MIN_VALUE, 0x100000000, 0x080000001, 0.000000000000001, Math.PI, -0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 1.7976931348623157e308, -0, 0x07fffffff, -0x100000000, 1/0, 0x0ffffffff, 0x080000000, -(2**53-2)]); ");
/*fuzzSeed-72153729*/count=2351; tryItOut("x = p0;");
/*fuzzSeed-72153729*/count=2352; tryItOut("mathy1 = (function(x, y) { return (((((( + -0x080000000) >>> 0) * ((( ~ ( + (Math.sign((y << x)) | 0))) | 0) < ((Math.log2((y >>> 0)) >>> 0) | 0))) >>> 0) != (Math.min(( + Math.max((Math.atan2(-Number.MAX_VALUE, ( + Number.MIN_VALUE)) >>> 0), (Math.exp((Number.MIN_SAFE_INTEGER == (2**53 < y))) >>> 0))), ( - ( + (x >>> 0)))) | 0)) >>> 0); }); testMathyFunction(mathy1, /*MARR*/[x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x]); ");
/*fuzzSeed-72153729*/count=2357; tryItOut("/*RXUB*/var r = new RegExp(\"$(?=s)|[^]|[^]|\\udc47[^\\\\w]**?|(?:[^]*?)?|(?=.){3,}Y{1,2}|\\\\cR{4,}\", \"gyim\"); var s = \"\\u0012\\u0012\"; print(s.search(r)); ");
/*fuzzSeed-72153729*/count=2358; tryItOut("\"use strict\"; mathy2 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  function f(i0, d1)\n  {\n    i0 = i0|0;\n    d1 = +d1;\n    var d2 = 4194304.0;\n    var d3 = -9223372036854776000.0;\n    var i4 = 0;\n    (Float64ArrayView[4096]) = ((16385.0));\n    {\n      d1 = (+(0xffffffff));\n    }\n    switch ((imul((/*FFI*/ff(((((0x37aa57b6)) ^ ((0x50dcf00e)))), ((-1.25)), ((-6.189700196426902e+26)), ((-134217729.0)))|0), (i0))|0)) {\n    }\n    d3 = (d1);\n    d1 = (+(0.0/0.0));\n    return +((d1));\n  }\n  return f; })(this, {ff: ({c: set <<= 15,  get 9 b (NaN, x, x, x, b, x, \u3056, window, b, x, w, x = /(?=.)+?/yim, this.x, x, b, d, a, z, NaN, b = null, \u3056 = -12, c, d, x, a, \u3056, \"\\u4368\", w, x, \u3056, d, \u3056, b, b, \u3056, z, x, x = \"\\u79BC\", x, NaN, z, e, 7, eval = null) { return window }  }).toString}, new ArrayBuffer(4096)); testMathyFunction(mathy2, /*MARR*/[-Infinity,  /x/ , (-1/0),  /x/ , arguments.caller, (-1/0), -Infinity, -Infinity, (-1/0), arguments.caller, (-1/0), arguments.caller, -Infinity, arguments.caller, new Number(1), arguments.caller, (-1/0), -Infinity, (-1/0),  /x/ , (-1/0), -Infinity, (-1/0), -Infinity, -Infinity, -Infinity, new Number(1), (-1/0),  /x/ , -Infinity, -Infinity, arguments.caller, -Infinity, (-1/0), new Number(1), (-1/0), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), new Number(1), (-1/0),  /x/ , arguments.caller,  /x/ , arguments.caller,  /x/ , new Number(1), (-1/0),  /x/ , arguments.caller, -Infinity, arguments.caller, arguments.caller, new Number(1), new Number(1), -Infinity,  /x/ , (-1/0),  /x/ , -Infinity, -Infinity, arguments.caller, new Number(1), new Number(1),  /x/ , (-1/0), -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, -Infinity, arguments.caller, (-1/0), new Number(1), (-1/0), arguments.caller, arguments.caller, new Number(1),  /x/ , (-1/0),  /x/ ,  /x/ , new Number(1), (-1/0), new Number(1),  /x/ , new Number(1), arguments.caller, arguments.caller, -Infinity, -Infinity, arguments.caller, (-1/0), new Number(1), (-1/0), -Infinity, arguments.caller, (-1/0), new Number(1), -Infinity, new Number(1), -Infinity, arguments.caller,  /x/ ,  /x/ , (-1/0), new Number(1),  /x/ , new Number(1), (-1/0), arguments.caller, new Number(1), new Number(1), arguments.caller]); ");
/*fuzzSeed-72153729*/count=2359; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (( - ((((Math.log2((Math.max((( ~ (x >>> 0)) >>> 0), (x >>> 0)) >>> 0)) == ( + (Math.atan2((x | 0), (x | 0)) | 0))) | 0) % Math.max(( + Math.min(Math.fround((Math.sign((Math.max(( + (y >>> ( + x))), 1/0) >>> 0)) >>> 0)), Math.fround(y))), (x > (( + 0x100000001) ? (x | 0) : (x >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy0, [0/0, -Number.MAX_VALUE, -0x100000000, 1/0, -0x080000000, -0, -Number.MIN_VALUE, 0x100000001, 2**53+2, -(2**53), 0, -Number.MAX_SAFE_INTEGER, -0x080000001, 2**53, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0x07fffffff, 0x080000000, 0x080000001, 42, -0x07fffffff, 1, Number.MAX_SAFE_INTEGER, -(2**53+2), Number.MIN_SAFE_INTEGER, -0x100000001, 1.7976931348623157e308, 0x100000000, Math.PI, 2**53-2, -(2**53-2), -1/0, 0.000000000000001, -0x0ffffffff, Number.MAX_VALUE, 0x0ffffffff]); ");
/*fuzzSeed-72153729*/count=2360; tryItOut("mathy1 = (function(x, y) { return Math.atan2((( + (Math.fround(((Math.max((Math.max((-Number.MIN_VALUE ** x), x) | 0), (( + (( + Math.pow(( + y), ( + x))) && ( + y))) | 0)) | 0) ? Math.imul(y, x) : Math.acos(Math.log1p(Math.atan(x))))) >>> Math.fround((Math.hypot(((((x >>> 0) >>> Math.atan2(y, 0x080000000)) >>> 0) | 0), x) | 0)))) | 0), (( + ( + Math.exp((Math.fround(Math.min((Math.fround(( ~ ( + ( ~ x)))) >>> 0), Math.fround(y))) >>> 0)))) | 0)); }); testMathyFunction(mathy1, /*MARR*/[Infinity, Infinity]); ");
/*fuzzSeed-72153729*/count=2381; tryItOut("\"use strict\"; t0 = new Uint32Array(t2);");
/*fuzzSeed-72153729*/count=2382; tryItOut("mathy0 = (function(x, y) { return Math.asinh(( + (Math.fround((Math.fround(Math.clz32((y >>> 0))) ** Math.fround(Math.log1p(y)))) && ( - ( - -1/0))))); }); testMathyFunction(mathy0, [-1/0, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, 0/0, 0x07fffffff, 0x100000001, -0x07fffffff, Math.PI, -Number.MIN_VALUE, 0.000000000000001, Number.MIN_VALUE, -0, -(2**53-2), -0x0ffffffff, -Number.MAX_SAFE_INTEGER, 2**53, 0x080000000, 2**53+2, Number.MIN_SAFE_INTEGER, 42, -0x100000001, -0x080000001, 1, -0x100000000, 0x0ffffffff, Number.MAX_VALUE, 1/0, 2**53-2, 0x100000000, 0x080000001, 1.7976931348623157e308, -0x080000000, 0, -(2**53+2), -(2**53)]); ");
/*fuzzSeed-72153729*/count=2383; tryItOut("/*RXUB*/var r = new RegExp(\"\\\\b|(?=(?:(?=[\\\\s\\u00d0-\\u0011][\\\\ww\\\\t]){0}|[]|\\\\d$(?!\\\\1(?![^]))|($*)))\", \"gym\"); var s = \"\\n\\n\\u59a7\\n\\u0001\\n\\u4b7d\\ud4b1\\n\\u0090\"; print(s.search(r)); print(r.lastIndex); ");
/*fuzzSeed-72153729*/count=2384; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var NaN = stdlib.NaN;\n  var ff = foreign.ff;\n  var Float64ArrayView = new stdlib.Float64Array(heap);\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    (Float64ArrayView[((i1)*0x54bf1) >> 3]) = ((d0));\n    d0 = (NaN);\n    (Float32ArrayView[2]) = ((d0));\n    return +(((d0) + (+(1.0/0.0))));\n  }\n  return f; })(this, {ff: (Array.prototype.toString).apply}, new SharedArrayBuffer(4096)); testMathyFunction(mathy5, [-(2**53-2), -0x080000000, -0x0ffffffff, Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, 2**53+2, 2**53-2, -Number.MAX_VALUE, 0x07fffffff, 0/0, 1/0, 0x100000000, 0x100000001, -(2**53+2), 1, -Number.MIN_VALUE, 42, Number.MAX_SAFE_INTEGER, -0x080000001, -0x07fffffff, Number.MIN_VALUE, 0.000000000000001, -0, -1/0, 0x0ffffffff, Math.PI, -Number.MIN_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, -0x100000000, 1.7976931348623157e308, -(2**53), 2**53, -0x100000001, 0x080000001]); ");
/*fuzzSeed-72153729*/count=2385; tryItOut("mathy3 = (function(x, y) { return (Math.asinh(( - Math.imul((((((x >>> 0) >> (x === -0x100000000)) | 0) ? (y | 0) : (Math.cosh(Math.fround(Math.min(mathy2(( + 2**53-2), ( + y)), Math.asinh(x)))) >>> 0)) | 0), Math.fround((Math.fround(x) >> Math.fround(y)))))) >>> 0); }); testMathyFunction(mathy3, [-0x100000000, -0x080000000, -0x100000001, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -0x0ffffffff, -1/0, 2**53-2, -(2**53-2), -0x07fffffff, -(2**53), 0.000000000000001, 0x080000001, -(2**53+2), Number.MAX_SAFE_INTEGER, 0, 1/0, 0x100000001, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 0x0ffffffff, 1, -Number.MAX_SAFE_INTEGER, 0/0, 0x080000000, -0, -Number.MAX_VALUE, -0x080000001, 42, -Number.MIN_VALUE, 1.7976931348623157e308, 0x100000000, 0x07fffffff, Math.PI, 2**53+2]); ");
/*fuzzSeed-72153729*/count=2386; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return (Math.log1p((Math.atan((Math.atan2(y, Math.fround(-Number.MIN_SAFE_INTEGER)) | 0)) | 0)) != Math.round(Math.acos(( - Math.fround(( + Math.asinh((2**53+2 >>> 0)))))))); }); testMathyFunction(mathy0, [-0x100000000, 0, 2**53, 2**53+2, 2**53-2, -(2**53-2), -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, 0x100000000, -Number.MIN_VALUE, 0x07fffffff, -0x07fffffff, 0x100000001, -(2**53), -0x100000001, 1/0, Number.MIN_VALUE, 0x0ffffffff, 1, -(2**53+2), 42, -0x080000001, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_SAFE_INTEGER, -0x0ffffffff, 1.7976931348623157e308, -0, Math.PI, 0.000000000000001, -0x080000000, 0x080000001, Number.MAX_VALUE, 0x080000000, -1/0, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2387; tryItOut("\"use strict\"; a0.push(f1, this.o1, a1, g0);");
/*fuzzSeed-72153729*/count=2388; tryItOut("g1.o0.__proto__ = g2.g1.s2;");
/*fuzzSeed-72153729*/count=2393; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(( - Math.fround((Math.min((( ~ ((y || ( - ( + (x ^ ( + ( + ( ! y))))))) | 0)) | 0), Math.fround(Math.acosh(Math.fround(Math.sinh(( ! (( ~ (-1/0 >>> 0)) | 0))))))) | 0)))); }); testMathyFunction(mathy0, [0x080000000, -0x0ffffffff, -0, 2**53+2, 0x100000001, -0x100000001, 1/0, 2**53-2, 0, Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, -(2**53+2), -(2**53-2), 0x07fffffff, 0.000000000000001, -0x080000001, -Number.MAX_SAFE_INTEGER, -Number.MIN_VALUE, Number.MAX_SAFE_INTEGER, 0/0, -Number.MAX_VALUE, -0x07fffffff, 1, Number.MAX_VALUE, -1/0, -Number.MIN_SAFE_INTEGER, 0x080000001, -0x080000000, 42, 0x0ffffffff, 2**53, 0x100000000, Number.MIN_VALUE, 1.7976931348623157e308, -(2**53)]); ");
/*fuzzSeed-72153729*/count=2394; tryItOut("\"use strict\"; Array.prototype.pop.call(a0);");
/*fuzzSeed-72153729*/count=2395; tryItOut("v2 = g2.a0.length;");
/*fuzzSeed-72153729*/count=2396; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return (((Math.atan2((Math.pow(Math.fround((((mathy1(1/0, (x >>> 0)) | 0) << Math.fround((x || x))) | 0)), Math.fround(mathy1(((( + -(2**53)) && Math.pow(( + y), 0/0)) >>> 0), x))) >>> 0), (((Math.fround(( ~ Math.fround(( + Math.acos(x))))) | 0) ? Math.sin((y - y)) : (( + Math.fround(( + (( + Math.sin(-Number.MIN_SAFE_INTEGER)) ** Math.fround(Math.fround(Math.expm1(Math.fround((mathy1((y >>> 0), ( + 1)) >>> 0))))))))) | 0)) | 0)) | 0) , (( - Math.cosh((( - Math.fround((-(2**53) - y))) >>> 0))) | 0)) | 0); }); testMathyFunction(mathy3, [0x100000000, -(2**53+2), -(2**53-2), 2**53-2, 1/0, 1, -0x080000001, 0x080000001, Number.MAX_VALUE, Number.MIN_VALUE, Math.PI, -0x100000000, 0x07fffffff, -0x100000001, -0x0ffffffff, 0x100000001, Number.MIN_SAFE_INTEGER, -0x080000000, -1/0, -Number.MAX_VALUE, 0x080000000, -0, 0/0, -(2**53), 0x0ffffffff, 2**53, -Number.MIN_VALUE, 0, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x07fffffff, 2**53+2, 42, 0.000000000000001, Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2397; tryItOut("testMathyFunction(mathy5, [-Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 2**53+2, 0x080000001, 0x0ffffffff, -(2**53-2), 0x100000001, -Number.MAX_SAFE_INTEGER, 0x100000000, 1, -0x0ffffffff, Number.MIN_VALUE, 1.7976931348623157e308, 0/0, 42, 1/0, -0x100000000, -0x100000001, Number.MAX_VALUE, -0x07fffffff, -0x080000001, -0x080000000, -Number.MIN_VALUE, -1/0, 2**53-2, 0x080000000, 0.000000000000001, 0x07fffffff, -0, 2**53, -(2**53), Math.PI, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, -(2**53+2), 0]); ");
/*fuzzSeed-72153729*/count=2398; tryItOut("testMathyFunction(mathy5, [42, 1/0, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000001, -0, -Number.MIN_VALUE, 2**53, Number.MIN_VALUE, 2**53-2, 0, -(2**53), -Number.MIN_SAFE_INTEGER, 0/0, -0x07fffffff, 2**53+2, Number.MAX_VALUE, 0.000000000000001, Number.MAX_SAFE_INTEGER, -1/0, -Number.MAX_SAFE_INTEGER, 0x100000000, 1.7976931348623157e308, -(2**53+2), -0x080000001, 0x07fffffff, -0x0ffffffff, 0x100000001, -0x100000000, 0x080000001, Math.PI, 0x0ffffffff, -0x080000000, 0x080000000, 1, -(2**53-2)]); ");
/*fuzzSeed-72153729*/count=2399; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.hypot(Math.imul(Math.imul(( + ( ! Math.fround((( - 0/0) >>> 0)))), ( + y)), Math.fround(( - Math.cosh((2**53+2 || y))))), ( + (( + (( ~ ((Math.fround(( - y)) - Math.fround(y)) >>> 0)) >>> 0)) >>> ( + ( ~ Math.fround(Math.min(y, (0x07fffffff ^ Math.fround((Math.fround(Number.MAX_SAFE_INTEGER) , y)))))))))); }); testMathyFunction(mathy0, [2**53, Number.MIN_VALUE, 2**53-2, Math.PI, -0x100000000, 1, 2**53+2, -(2**53+2), 0x080000001, -0x100000001, -(2**53-2), -0x080000001, 0, -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MIN_VALUE, 1/0, -0, -(2**53), 0x080000000, 1.7976931348623157e308, Number.MAX_SAFE_INTEGER, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, 0x100000000, -0x07fffffff, Number.MAX_VALUE, -1/0, 0.000000000000001, -0x080000000, 42, 0x07fffffff, 0x100000001, 0/0, Number.MIN_SAFE_INTEGER, 0x0ffffffff]); ");
/*fuzzSeed-72153729*/count=2400; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return Math.hypot(Math.fround((( + ( + mathy0(( + ( ~ (Math.log(( ! x)) >> (-(2**53) | 0)))), ( + ((Math.fround(Math.PI) >= (y | 0)) | 0))))) ? Math.fround(( + Math.hypot(( + (mathy1(((x != 1/0) >>> 0), Math.fround(x)) >>> 0)), ( + y)))) : ( + ( - ( + Math.imul(Math.hypot(Math.imul(y, 0x0ffffffff), x), y)))))), ((( - 0x07fffffff) >> ((x === (Math.cbrt(((Math.fround((Math.fround(x) << y)) ^ y) >>> 0)) >>> 0)) | 0)) | 0)); }); testMathyFunction(mathy4, /*MARR*/[]); ");
/*fuzzSeed-72153729*/count=2401; tryItOut("\"use strict\"; /*RXUB*/var r = r0; var s = s1; print(r.test(s)); print(r.lastIndex); ");
/*fuzzSeed-72153729*/count=2402; tryItOut("m0.set(g2, b2);");
/*fuzzSeed-72153729*/count=2403; tryItOut("mathy5 = (function(x, y) { return Math.fround(Math.atan2(Math.min(Math.min((mathy3(((y < ((x >>> 0) ^ x)) | 0), (0x080000000 | 0)) | 0), (Math.round(-(2**53-2)) | 0)), ( + Math.pow(( + (Math.min((Math.fround(Math.atan2(Math.fround(Math.fround(( + Math.fround(Number.MIN_VALUE)))), Math.fround(Math.fround(( ! Math.fround(y)))))) >>> 0), (x >>> 0)) | 0)), ( + Math.fround(( - ( + Math.clz32((x >>> 0))))))))), (Math.fround(mathy0((Math.hypot((Math.max(0/0, 0x080000000) >>> 0), (( ! x) >>> 0)) >>> 0), (Math.acos((( ! (x | 0)) | 0)) >>> 0))) >>> 0))); }); testMathyFunction(mathy5, [-0x080000000, 1.7976931348623157e308, -0x0ffffffff, 1/0, Number.MIN_VALUE, -0, 0x0ffffffff, 1, -0x080000001, -(2**53-2), -Number.MAX_VALUE, -0x100000000, Math.PI, 0, 2**53-2, 0/0, Number.MAX_SAFE_INTEGER, -(2**53), -Number.MIN_VALUE, 0x100000000, -(2**53+2), -0x07fffffff, Number.MAX_VALUE, -0x100000001, 42, 0x100000001, 2**53+2, 0x080000000, -1/0, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 0x07fffffff, -Number.MIN_SAFE_INTEGER, 2**53, 0x080000001]); ");
/*fuzzSeed-72153729*/count=2404; tryItOut("\"use strict\"; g2.g1.offThreadCompileScript(\"mathy2 = (function(x, y) { return (Math.imul(Math.atan2((Math.max(Math.acos(y), (Math.log(( + Math.hypot(Math.fround(y), ( + -0x07fffffff)))) | 0)) | 0), (mathy1((Number.MIN_SAFE_INTEGER | 0), (Math.tanh(0x0ffffffff) >>> 0)) >>> 0)), (Math.ceil(( ! y)) >>> 0)) >>> 0); }); \", ({ global: g2, fileName: null, lineNumber: 42, isRunOnce: (x % 4 != 2), noScriptRval: true, sourceIsLazy: true, catchTermination: true }));");
/*fuzzSeed-72153729*/count=2405; tryItOut("\"use strict\"; Array.prototype.reverse.call(a0, o0);");
/*fuzzSeed-72153729*/count=2406; tryItOut("o2.__proto__ = f2;");
/*fuzzSeed-72153729*/count=2407; tryItOut("function f1(t2) \"use asm\";   var Float32ArrayView = new stdlib.Float32Array(heap);\n  var Int16ArrayView = new stdlib.Int16Array(heap);\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var d2 = -33554432.0;\n    d0 = (-33554433.0);\n    {\n      return ((((d2) == (d0))+((((0xffffffff))>>>(-(0xffffffff))) == (((((Float32ArrayView[2])) % ((-1.2089258196146292e+24))))))))|0;\n    }\n    d2 = (1.0);\n    (Int16ArrayView[0]) = (((i1) ? (-0x8000000) : (0x745b3672))+(0x7fc19396));\n    return (((0x78ddcd75)))|0;\n  }\n  return f;");
/*fuzzSeed-72153729*/count=2408; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atanh(( ! ( ~ (y + Math.log1p(y))))); }); testMathyFunction(mathy0, [-Number.MIN_SAFE_INTEGER, Math.PI, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -(2**53), Number.MAX_SAFE_INTEGER, 0x080000001, 0/0, 0x080000000, -Number.MIN_VALUE, -0x100000001, 0x0ffffffff, 2**53-2, -(2**53+2), Number.MAX_VALUE, -(2**53-2), -0x07fffffff, -1/0, 1, -0, 2**53, 2**53+2, -0x080000000, -0x100000000, 1/0, 0x100000001, Number.MIN_VALUE, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0, 0x100000000, 1.7976931348623157e308, 42, 0x07fffffff, -0x0ffffffff, -0x080000001]); ");
/*fuzzSeed-72153729*/count=2409; tryItOut("mathy2 = (function(x, y) { return Math.tan((( ! y) ? Math.sign((Math.min((mathy0(Math.log(( + mathy0(( + y), ( + x)))), ( + Math.PI)) | 0), (Math.round(y) | 0)) | 0)) : Math.fround(Math.min(( + (y | 0)), ( + Math.round(( + x))))))); }); testMathyFunction(mathy2, /*MARR*/[new String(''), -Infinity, (void 0), (void 0),  /x/ ,  /x/ ,  \"use strict\" , (void 0), (void 0),  /x/ , -Infinity, new String(''), (void 0), (void 0),  \"use strict\" , (void 0), (void 0), new String(''),  /x/ , -Infinity, new String(''),  \"use strict\" , -Infinity, new String(''), -Infinity,  \"use strict\" , new String(''), (void 0), new String(''), (void 0), (void 0), new String(''),  /x/ ,  \"use strict\" , -Infinity, -Infinity,  \"use strict\" ,  \"use strict\" , new String(''), new String(''), new String(''),  /x/ , new String(''), new String(''),  \"use strict\" , -Infinity,  \"use strict\" ,  \"use strict\" , new String(''), (void 0), new String(''),  \"use strict\" , new String(''), new String(''),  /x/ , new String(''), (void 0),  /x/ , (void 0),  \"use strict\" , (void 0),  \"use strict\" , -Infinity, -Infinity,  \"use strict\" ,  \"use strict\" , new String(''), -Infinity,  /x/ ,  \"use strict\" , -Infinity, (void 0), (void 0), (void 0), -Infinity,  \"use strict\" , -Infinity, (void 0), (void 0),  \"use strict\" , new String(''),  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  \"use strict\" ,  /x/ ,  /x/ ,  /x/ ,  \"use strict\" , new String(''),  \"use strict\" , new String('')]); ");
/*fuzzSeed-72153729*/count=2410; tryItOut("\"use strict\"; testMathyFunction(mathy1, [-Number.MIN_VALUE, 0x07fffffff, -0x100000000, Number.MIN_SAFE_INTEGER, 2**53+2, -Number.MIN_SAFE_INTEGER, 1, -(2**53-2), 0/0, Math.PI, -0x080000001, -Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 42, -0x07fffffff, Number.MAX_VALUE, 0.000000000000001, 0x0ffffffff, 0, -0x100000001, 0x100000001, 0x080000001, 1/0, -(2**53+2), -1/0, 2**53-2, -0x080000000, -0x0ffffffff, -Number.MAX_VALUE, 0x080000000, 1.7976931348623157e308, -(2**53), -0, 0x100000000, Number.MAX_SAFE_INTEGER, 2**53]); ");
/*fuzzSeed-72153729*/count=2411; tryItOut("h1 = a1[v2];");
/*fuzzSeed-72153729*/count=2412; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var ff = foreign.ff;\n  function f(i0, i1)\n  {\n    i0 = i0|0;\n    i1 = i1|0;\n    return (((0xf95dbe24)+(i0)))|0;\n  }\n  return f; })(this, {ff: Uint8Array}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53, -0, 0x100000000, 1/0, 0.000000000000001, -Number.MIN_VALUE, -(2**53-2), Math.PI, -(2**53), -1/0, 1.7976931348623157e308, 0x07fffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 42, Number.MIN_SAFE_INTEGER, 0/0, 2**53+2, 1, 0x100000001, -0x100000001, 0x0ffffffff, 2**53-2, -0x100000000, -0x0ffffffff, -(2**53+2), -0x07fffffff, -Number.MAX_VALUE, -0x080000001, 0x080000000, Number.MIN_VALUE, 0, -Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000001]); ");
/*fuzzSeed-72153729*/count=2417; tryItOut("{ void 0; bailout(); }");
/*fuzzSeed-72153729*/count=2418; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (( - (( + (( + Math.cos(((Math.max(y, y) >>> 0) >>> 0))) > (( - (Math.fround(( ! y)) | 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [0x07fffffff, Number.MAX_SAFE_INTEGER, 42, 0x0ffffffff, -0x0ffffffff, 2**53+2, 0x080000001, -1/0, 0x100000001, 0/0, -(2**53), Number.MIN_VALUE, 0, -0x100000000, 0x100000000, 0x080000000, -(2**53-2), 0.000000000000001, -0x100000001, 2**53, 1.7976931348623157e308, -0x080000000, Math.PI, -Number.MAX_VALUE, -0x080000001, -Number.MAX_SAFE_INTEGER, 1/0, Number.MAX_VALUE, -(2**53+2), -0x07fffffff, 2**53-2, 1, -Number.MIN_SAFE_INTEGER, -Number.MIN_VALUE, -0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2419; tryItOut("/*tLoop*/for (let x of /*MARR*/[true, (void 0), true, true, true, -0x100000000, (void 0), -0x100000000, true, (void 0), (void 0), (void 0), (void 0), true, true, (void 0), true, true, -0x100000000, (void 0), true, -0x100000000, -0x100000000, (void 0), -0x100000000, -0x100000000, (void 0)]) { ( /x/g ); }");
/*fuzzSeed-72153729*/count=2420; tryItOut("\"use asm\"; mathy2 = (function(x, y) { \"use strict\"; return (( + (( + Math.asinh(Math.fround(( + Math.fround(mathy0((x >>> 0), y)))))) ** ( + (mathy1((mathy1(((-1/0 - y) >>> 0), ( + y)) >>> 0), y) === y)))) !== Math.fround(mathy1(( + Math.fround(Math.min((x | 0), Math.fround((((Math.sign(y) | 0) ** ((x ? (y >>> 0) : (y >>> 0)) >>> 0)) * ( + y)))))), ((((( ~ y) <= (mathy1(2**53+2, y) >>> 0)) , ((Math.pow((Math.expm1(-0x0ffffffff) >>> 0), (y >>> 0)) >>> 0) >>> 0)) | Math.trunc((mathy1((y | 0), (Math.max(0/0, y) | 0)) | 0))) | 0)))); }); testMathyFunction(mathy2, [-Number.MAX_VALUE, -0, 0x080000000, Number.MIN_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, -0x07fffffff, 0.000000000000001, -1/0, 0x100000000, 42, 0, -(2**53+2), -0x100000000, 0x080000001, -0x080000000, -0x100000001, 1/0, 2**53, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -(2**53-2), -Number.MIN_VALUE, -0x0ffffffff, Number.MAX_VALUE, 1.7976931348623157e308, Math.PI, 1, 2**53-2, -0x080000001, -(2**53), 0x100000001, Number.MAX_SAFE_INTEGER, 0x07fffffff, 2**53+2, 0/0]); ");
/*fuzzSeed-72153729*/count=2421; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.atan2(( - Math.fround(((( - (( + (( + (x || (-0x07fffffff | 0))) || ( + y))) >>> 0)) >>> 0) & Math.sqrt((( + (x >>> 0)) >>> 0))))), ( + Math.cosh((Math.cbrt(Math.ceil((( + ((-0x080000001 >>> 0) ? x : x)) , Math.fround(y)))) | 0)))); }); ");
/*fuzzSeed-72153729*/count=2422; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(((Math.pow(mathy0(((( + (( ! x) !== (Math.imul(x, Number.MAX_VALUE) >>> 0))) ^ Math.fround(Math.fround(Math.fround(((y | 0) % x))))) >>> 0), (x +  if (z = 11))), ((Math.max((Math.log1p(1) >>> 0), (Math.fround(Math.min(Math.imul((Math.sqrt(((( ~ y) >>> 0) | 0)) | 0), mathy0(( + x), y)), Math.fround(x))) >>> 0)) >>> 0) | 0)) >>> 0) * ((( ! (Math.abs(Math.imul(x, Math.fround(mathy0(( + Math.fround(( ~ (x | 0)))), (0x07fffffff >>> 0))))) | 0)) | 0) | 0))); }); testMathyFunction(mathy1, [0x07fffffff, 2**53, -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0.000000000000001, 0, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER, 0x080000001, -(2**53), 0/0, -0, 0x0ffffffff, 1, -0x100000001, 1/0, Math.PI, -0x07fffffff, -(2**53+2), 0x100000001, -0x080000001, 1.7976931348623157e308, -(2**53-2), -Number.MIN_SAFE_INTEGER, -0x0ffffffff, -Number.MAX_VALUE, 0x100000000, -Number.MIN_VALUE, 0x080000000, -0x100000000, 2**53+2, 42, -1/0, 2**53-2]); ");
/*fuzzSeed-72153729*/count=2423; tryItOut(" '' ;m1.toString = (function(j) { if (j) { try { /*MXX1*/o1 = g1.RangeError.prototype.name; } catch(e0) { } try { v2 = false; } catch(e1) { } selectforgc(o2); } else { try { for (var v of g0.b1) { try { o0.o0 = Object.create(m2); } catch(e0) { } e0.has(h0); } } catch(e0) { } g1 + f0; } });");
/*fuzzSeed-72153729*/count=2424; tryItOut("mathy4 = (function(x, y) { return ( + Math.fround(Math.clz32(( ~ 2**53-2)))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, 0x080000001, 2**53-2, 0.000000000000001, -Number.MAX_SAFE_INTEGER, 0x0ffffffff, 1.7976931348623157e308, Number.MAX_VALUE, -(2**53+2), 1/0, 2**53+2, -(2**53), -0, 0x080000000, -0x0ffffffff, -(2**53-2), -0x100000000, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 0x07fffffff, 0x100000000, 1, 0, 0/0, -Number.MIN_VALUE, -1/0, 0x100000001, Number.MIN_SAFE_INTEGER, Math.PI, -0x080000000, -0x080000001, -0x07fffffff, -0x100000001, 2**53, 42]); ");
/*fuzzSeed-72153729*/count=2817; tryItOut("e2 = Proxy.create(h1, i2);");
/*fuzzSeed-72153729*/count=2818; tryItOut("mathy1 = (function(x, y) { return mathy0(Math.fround(Math.hypot(Math.fround(( ~ ( - mathy0(Math.atan2(x, Number.MIN_VALUE), x)))), mathy0((mathy0(-(2**53), -0x100000000) | 0), y))), Math.acos(Math.max(( + (( + x) / Math.fround((Math.pow(y, (Math.sinh((0 | 0)) | 0)) >> 1.7976931348623157e308)))), (42 >>> 0)))); }); testMathyFunction(mathy1, [(new String('')), -0, (new Boolean(true)), null, '/0/', ({toString:function(){return '0';}}), 0.1, (new Boolean(false)), 0, '\\0', '0', [0], undefined, [], 1, ({valueOf:function(){return 0;}}), /0/, ({valueOf:function(){return '0';}}), (new Number(0)), NaN, true, (function(){return 0;}), objectEmulatingUndefined(), (new Number(-0)), '', false]); ");
/*fuzzSeed-72153729*/count=2819; tryItOut("e1.has(s1);");
/*fuzzSeed-72153729*/count=2820; tryItOut("\"use strict\"; h2.getOwnPropertyNames = f1;");
/*fuzzSeed-72153729*/count=2821; tryItOut("/*RXUB*/var r = /((?:(?=\\1{0,})^+))|./im; var s = \"\\n\"; print(r.exec(s)); ");
/*fuzzSeed-72153729*/count=2822; tryItOut("f2 + '';");
/*fuzzSeed-72153729*/count=2823; tryItOut("/*bLoop*/for (let htefou = 0, c; htefou < 44; ++htefou) { if (htefou % 7 == 1) { yield; } else { v0 = Object.prototype.isPrototypeOf.call(i0, p0); }  } ");
/*fuzzSeed-72153729*/count=2824; tryItOut("/*infloop*/while((({\"-0\": /*RXUE*//(^)(?!(?!.)){1048575,}(\u44e1{4,8})/yim.exec(\"\\n\\n\\n\\n\\nx\\u8254\") })))s0.toString = (function(j) { f0(j); });");
/*fuzzSeed-72153729*/count=2825; tryItOut("\"use strict\"; v2 = g2.eval(\"Math.round(((( ! ((( + ( ! (Math.clz32((Math.asin(((Math.fround(( + x)) <= Math.imul(x, Math.PI)) | 0)) >>> 0)) | 0))) ? ( + ( ~ Math.log(( + ( - (Math.imul(0x080000000, (( - (x | 0)) >>> 0)) >>> 0)))))) : ( + Math.fround(( ! Math.fround((Math.fround(Math.hypot(Math.PI, ( + ( + ( + x))))) <= ((Math.acosh(((((((Math.hypot(x, x) != x) | 0) >>> 0) , (Math.fround(( + Math.abs(x))) | 0)) | 0) >>> 0)) >>> 0) >>> 0))))))) >>> 0)) , ( + (Math.fround(( + (( + (Math.fround(Math.pow(Math.pow((( + x) << ((( + -1/0) ? x : ( ~ 0x080000000)) >>> 0)), ( + (( + ( + (x - Math.fround(( ! Math.fround(Math.hypot(x, x))))))) != ( + x)))), ( + (( + ( + Math.imul((x >= Math.max(x, x)), Math.log10(x)))) & ((( + ( ~ x)) >>> 0) ? -0 : Math.fround((Math.tanh(((( - (x >>> 0)) >>> 0) >>> 0)) >>> 0))))))) >>> Math.fround(Math.fround(Math.sinh(( + x)))))) < ( + (Math.cbrt((Math.pow((Math.hypot(Math.fround(Math.pow(( + ((Number.MAX_SAFE_INTEGER | 0) && ( + x))), ( + ( ~ ( + x))))), x) | 0), ( - x)) >>> 0)) > ((Math.max((( ! x) >>> 0), (Math.imul(Math.sign(x), (x << x)) >>> 0)) >>> 0) != (Math.sinh(( + x)) ? Math.fround(( + Math.min((Math.fround(( + -(2**53-2))) >>> 0), (1 >>> 0)))) : ((0x080000000 | (x | 0)) | 0)))))))) ? ( + Math.round(((Math.hypot((( ~ 0x0ffffffff) >>> 0), (Math.tanh(Math.abs(x)) >>> 0)) >>> 0) >>> (Math.abs(( - x)) >= Math.fround((Math.fround(x) % (( + (( + ( - x)) & (( + Math.min((x | 0), 2**53-2)) <= x))) >>> 0))))))) : ( + Math.sin(((Math.sin((Math.acos(x) !== x)) >>> 0) % ( ~ ( + (( + Math.sin(( + Math.atan2(Math.fround((x << Math.fround(x))), (x >>> 0))))) | 0))))))))) / Math.fround(Math.pow(( + Math.hypot(Math.cbrt(Math.fround(Math.pow(( - (Math.atan2(0/0, x) >> ( + ( + Math.round(( + x)))))), Math.fround(Math.hypot((0x07fffffff === (((2**53 | 0) | (Math.asin(Math.tanh(x)) | 0)) | 0)), ( ~ Math.acos(Math.fround(Math.imul(Math.fround(( + x)), Math.fround(( + 2**53-2))))))))))), (Math.ceil(Math.hypot(Math.fround(( + Math.pow(( + Math.exp((( ! ((Math.sin((2**53-2 >>> 0)) ? x : (Math.cos(42) | 0)) | 0)) | 0))), ( + Math.acosh(( + ( ~ x))))))), Math.fround((((( ! ((Math.asin(( + ( + ( - ((x != -0x07fffffff) | 0))))) >>> 0) | 0)) >>> 0) ^ (Math.fround(Math.min(Math.fround(-0x100000000), Math.clz32((x >>> 0)))) >>> 0)) >>> 0)))) >>> 0))), ( + (Math.fround(( + ( ~ ( + (Math.fround(({ void 0; minorgc(true); } ? Math.fround(Math.pow(Math.fround(((( + x) >= ( - ( + 0x080000000))) >>> x)), (( + Math.fround(Math.sin((x >>> 0)))) | 0))) : Math.fround(((Math.fround(Math.min(x, x)) != 0x100000000) << Math.log2(x))))) >= (Math.sin(x) >> (( + x) & ( + Math.cbrt(x))))))))) % (( + ( ~ Math.acosh(( + Math.min(( + x), ( + Math.sinh((Math.atan2(x, x) >>> 0)))))))) && ( ~ ( - ( + (Math.fround(Math.hypot(x, Math.fround(( - Math.fround(Math.imul(x, ((x << (x | 0)) | 0))))))) !== ( + ( - x)))))))))))))\");");
/*fuzzSeed-72153729*/count=2826; tryItOut("t0 = new Uint8Array(({valueOf: function() { v2 = evaluate(\"/* no regression tests found */\", ({ global: g1, fileName: 'evaluate.js', lineNumber: 42, isRunOnce: true, noScriptRval: [(x > (/*RXUE*/new RegExp(\"(((?=(?!\\u000c\\\\w)?)))?\", \"gym\").exec(\"\")))], sourceIsLazy: false, catchTermination: false }));return 19; }}));");
/*fuzzSeed-72153729*/count=2827; tryItOut(" for  each(z in let (uqzxci) false) /* no regression tests found */");
/*fuzzSeed-72153729*/count=2828; tryItOut("\"use strict\"; Array.prototype.forEach.apply(a1, [this.o2.f1]);");
/*fuzzSeed-72153729*/count=2829; tryItOut("\"use strict\"; /*tLoop*/for (let d of /*MARR*/[new Boolean(true),  '\\0' ,  '\\0' , new Boolean(true), new Boolean(true), 2**53, new Boolean(true), new Boolean(true),  '\\0' , new Boolean(true),  '\\0' , new Boolean(true),  '\\0' ,  '\\0' ,  '\\0' , 2**53, new Boolean(true), 2**53, 2**53,  '\\0' ,  '\\0' , 2**53, new Boolean(true), new Boolean(true), 2**53,  '\\0' , 2**53,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , 2**53,  '\\0' ,  '\\0' , new Boolean(true),  '\\0' , 2**53, 2**53, new Boolean(true), new Boolean(true), 2**53,  '\\0' ,  '\\0' , new Boolean(true), new Boolean(true),  '\\0' , 2**53, 2**53, new Boolean(true), 2**53, 2**53, 2**53, 2**53, new Boolean(true), 2**53, new Boolean(true), new Boolean(true), 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, 2**53, new Boolean(true), 2**53,  '\\0' ,  '\\0' ,  '\\0' ,  '\\0' , new Boolean(true), 2**53, 2**53, 2**53,  '\\0' ,  '\\0' , 2**53,  '\\0' , new Boolean(true), 2**53, new Boolean(true), 2**53,  '\\0' , new Boolean(true),  '\\0' , new Boolean(true),  '\\0' , 2**53, 2**53,  '\\0' , new Boolean(true), new Boolean(true), new Boolean(true), 2**53, new Boolean(true),  '\\0' , 2**53, new Boolean(true),  '\\0' , new Boolean(true), new Boolean(true), 2**53,  '\\0' , new Boolean(true), new Boolean(true),  '\\0' ,  '\\0' , 2**53, new Boolean(true), new Boolean(true), 2**53, new Boolean(true)]) { /*infloop*/for(x - x; d; [,,].yoyo(\"\\u1ACC\")) b0 = t2.buffer; }");
/*fuzzSeed-72153729*/count=2830; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0(Math.fround((Math.fround(( - y)) === Math.fround(( + (y >>> ( + ( + Math.min(y, ( + x))))))))), (( + Math.pow(( + ((( - Math.fround(Math.fround((y != ( + Math.min(( + x), ( + Math.fround((y % y))))))))) | 0) >= (Math.fround((Math.atan2(x, y) | (y >> -Number.MIN_SAFE_INTEGER))) | 0))), (mathy0(Math.ceil(Math.atan2(x, x)), (Math.pow(( + Math.PI), (Math.fround((Math.fround(Math.max(0.000000000000001, ( + y))) || Math.fround(0))) | 0)) | 0)) >>> 0))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [-0x07fffffff, -0x100000001, 1/0, -0x100000000, Number.MAX_VALUE, 0x080000000, 0, -0x080000000, 0x0ffffffff, Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 0.000000000000001, -Number.MIN_VALUE, 42, 1.7976931348623157e308, -Number.MAX_SAFE_INTEGER, -0x080000001, -0x0ffffffff, -1/0, -Number.MAX_VALUE, 0/0, -(2**53), Number.MIN_SAFE_INTEGER, 1, 0x080000001, -0, -(2**53-2), 2**53+2, 2**53, Number.MAX_SAFE_INTEGER, 0x100000000, 2**53-2, -(2**53+2), 0x07fffffff, 0x100000001, Math.PI]); ");
/*fuzzSeed-72153729*/count=2831; tryItOut("for (var p in o0.v1) { try { f1 = o0.f2; } catch(e0) { } try { p2 + ''; } catch(e1) { } o2 = {}; }");
/*fuzzSeed-72153729*/count=2832; tryItOut("\"use strict\"; throw x;");
/*fuzzSeed-72153729*/count=2833; tryItOut("\"use strict\"; print(x);\nprint(x);\n");
/*fuzzSeed-72153729*/count=2834; tryItOut("\"use asm\"; mathy5 = (function(x, y) { return Math.fround((Math.fround(mathy3((((( + (Math.sinh((y >>> 0)) >>> 0)) >>> 0) >>> 0) < ((((( + y) ? x : ( + x)) >>> 0) == ( - (x | 0))) >>> 0)), ( + mathy1(Math.fround((Math.log10((Math.sin(y) >>> 0)) >>> 0)), -0)))) << (((mathy2((Math.fround(Math.pow(Math.fround(-0x100000001), Math.fround(Math.fround(mathy3(Math.fround(y), Math.fround(Math.log(Math.fround((Math.asin(-0x100000000) | 0))))))))) | 0), ( + 0.000000000000001)) | 0) ? mathy2(Math.acosh(Math.fround(y)), (((-0x100000000 | 0) >> (Math.imul(Math.fround((Math.fround(y) >> Math.fround(y))), Math.fround((Math.fround(x) / y))) | 0)) | 0)) : Math.imul(x, Math.log10(mathy4((y | 0), x)))) | 0))); }); testMathyFunction(mathy5, [2**53, -0x100000000, 0x080000001, 2**53-2, -0x080000001, -(2**53), -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Math.PI, 1/0, 0x0ffffffff, 0/0, Number.MAX_SAFE_INTEGER, 0x07fffffff, -0x07fffffff, -0x100000001, 0x100000001, -1/0, -0x0ffffffff, -0x080000000, Number.MAX_VALUE, -Number.MIN_VALUE, -(2**53-2), 0, -Number.MAX_VALUE, Number.MIN_VALUE, 42, -0, 0x080000000, -Number.MAX_SAFE_INTEGER, 1, -(2**53+2), 1.7976931348623157e308, 0x100000000, 2**53+2, 0.000000000000001]); ");
/*fuzzSeed-72153729*/count=2835; tryItOut("\"use strict\"; /* no regression tests found */");
/*fuzzSeed-72153729*/count=2836; tryItOut("mathy4 = (function(x, y) { return Math.atanh(( ! (mathy0((( ~ 1.7976931348623157e308) >>> 0), ( + y)) >>> 0))); }); ");
/*fuzzSeed-72153729*/count=2837; tryItOut("\"use strict\"; mathy3 = (function(stdlib, foreign, heap){ \"use asm\";   var abs = stdlib.Math.abs;\n  var ff = foreign.ff;\n  var Float32ArrayView = new stdlib.Float32Array(heap);\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\nyield (4277);    d1 = (+/*FFI*/ff(((abs(((-0xd68f9*((((0x5aea89e7)*-0x4051a) << ((0x22a544b7) / (0x4a8ed77a))))) ^ ((0xe696c264)+((((0xee56f2dd)+(0x1a1a5a98)) & ((0xffffffff)-(0xdbe0a6ef)-(0xb1e405b2))))-((((-0x8000000)) >> ((0x49a67149))) <= (((0xf85e7c98)) & ((0x4ba383bf)))))))|0)), ((((/*FFI*/ff(((((!(0xf3c49aaa))) << (((-7.737125245533627e+25) > (-17592186044417.0))+((0xae31fe8) ? (0xffffffff) : (-0x8000000))+(-0x8000000)))), ((((-0x8000000)-((0.5) > (70368744177664.0))) | ((0x7fffffff) % (-0x755b6fd)))), ((d0)), ((((0xad8ba5ba)) ^ ((0xfe59db9d)))), ((Float32ArrayView[4096])), ((4503599627370497.0)), ((1025.0)), ((1.125)), ((8388607.0)), ((-0.25)), ((-0.0009765625)), ((8.0)))|0)) & (false))), ((((0xf8a0d8e7)) | ((0xff2d5564)))), ((-0x8000000)), ((d1)), ((d1)), ((((0xfe3fba88)-((0x7f9c08a1) > (0x17999d5b)))|0)), (x), (((0x2cac76a) ? (-32769.0) : (-281474976710657.0))), ((8796093022207.0)), ((2.4178516392292583e+24)), ((-65537.0)), ((9223372036854776000.0)), ((2.3611832414348226e+21)), ((-4194303.0)), ((-1.1805916207174113e+21)), ((36893488147419103000.0)), ((-1073741823.0)), ((-137438953472.0))));\n    {\n      d1 = (d1);\n    }\n    {\n      d0 = (+/*FFI*/ff(((~((((((+abs(((d0)))) >= (d1))) & ((((0xffffffff)-(0x596de60d))>>>((0x57d02468)-(0x550eca99))) % (0xf93eb902))))))), ((d1)), (((-0x868bd*(0x38ed538e)) ^ ((0x9f15857f) / (0x37e877e1)))), ((+abs(((d1))))), ((+(-0x35d65cf))), ((((0xffd09411)*0x9f16a)|0)), ((d1)), ((d0)), ((((0x91907601)) | ((0xfe49a7d8)))), ((1.5)), ((4194305.0)), ((1.015625)), ((2251799813685247.0)), ((-1.0078125))));\n    }\n    d1 = (d1);\n    d0 = (((d0)) % ((d1)));\n    return (((0xffffffff)))|0;\n  }\n  return f; })(this, {ff: Object.prototype.toString}, new SharedArrayBuffer(4096)); testMathyFunction(mathy3, [0x07fffffff, Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, Number.MIN_SAFE_INTEGER, -0x100000000, -0x080000001, -Number.MIN_VALUE, 1.7976931348623157e308, -0x07fffffff, Number.MIN_VALUE, 42, 0x0ffffffff, 0.000000000000001, 2**53+2, 0x080000001, -(2**53), -0x080000000, Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -Number.MIN_SAFE_INTEGER, 0x080000000, -0x0ffffffff, -(2**53-2), 1, 2**53, 0/0, 0x100000000, 0x100000001, 1/0, -(2**53+2), -1/0, -0, Math.PI, -0x100000001, 0]); ");
/*fuzzSeed-72153729*/count=2838; tryItOut(";");
/*fuzzSeed-72153729*/count=2839; tryItOut("testMathyFunction(mathy0, [-(2**53+2), -0x080000001, 1/0, 0.000000000000001, 2**53+2, -(2**53), -1/0, -0x100000000, -(2**53-2), -0x0ffffffff, -Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, -0, -0x07fffffff, 2**53, 1.7976931348623157e308, 0x080000001, -0x100000001, 2**53-2, 0x0ffffffff, 0x100000000, Number.MIN_SAFE_INTEGER, 0, Number.MIN_VALUE, 1, 0/0, Number.MAX_VALUE, 0x07fffffff, -Number.MIN_VALUE, Math.PI, 42, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000000, 0x100000001]); ");
/*fuzzSeed-72153729*/count=2840; tryItOut("g0.m0.toSource = (function() { v2 = Object.prototype.isPrototypeOf.call(b0, o2.i2); return o2; });");
/*fuzzSeed-72153729*/count=2849; tryItOut("mathy0 = (function(x, y) { return (Math.imul(Math.fround(( - Math.log2(Math.fround(Math.hypot((Math.atan2((y >>> 0), ((Math.pow((x >>> 0), (Number.MIN_VALUE | 0)) >>> 0) | 0)) >>> 0), x))))), (( ~ (Math.sign((( ~ Math.asin(-0)) / ( ! ( + ( + ( + -0x100000001)))))) | 0)) >>> 0)) >>> 0); }); testMathyFunction(mathy0, [-0x100000000, -(2**53), 2**53+2, -(2**53+2), Number.MAX_VALUE, 0x080000000, 1/0, Math.PI, 0x100000001, 2**53-2, -Number.MIN_VALUE, 0, 0.000000000000001, 0x07fffffff, -Number.MAX_SAFE_INTEGER, 1.7976931348623157e308, -0x080000001, -Number.MAX_VALUE, -0x0ffffffff, 1, -Number.MIN_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, -0, -0x080000000, 0x100000000, -(2**53-2), -1/0, -0x100000001, 0/0, Number.MIN_VALUE, 0x080000001, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -0x07fffffff, 42, 2**53]); ");
/*fuzzSeed-72153729*/count=2850; tryItOut("M:for(c in (void shapeOf(new c = (intern(new RegExp(\"(?:(?=\\\\3{2,}))\", \"yi\")))()))) var itvidv = new ArrayBuffer(16); var itvidv_0 = new Uint16Array(itvidv); itvidv_0[0] = 28; var itvidv_1 = new Float64Array(itvidv); itvidv_1[0] = 29; var itvidv_2 = new Uint8Array(itvidv); print(itvidv_2[0]); var itvidv_3 = new Float64Array(itvidv); m2 = new Map(m2);this.e1.delete(p2);print(itvidv_2);undefined;Object.freeze(s2);function eval(c, itvidv_2 = itvidv_1[0]) { print(itvidv_2); } this.a1.sort(this.g1);s2 += 'x';eval;");
/*fuzzSeed-72153729*/count=2851; tryItOut("\"use strict\"; mathy3 = (function(x, y) { \"use strict\"; return Math.fround((( + Math.atan2(Math.min(( + y), Math.fround(Math.sqrt(Math.fround(y)))), Math.atan(Math.hypot(Math.hypot(x, mathy2(Math.hypot((x >>> 0), 0x080000000), ( + -0x080000000))), Math.fround(0x080000001))))) !== ((Math.fround((((x || Math.hypot(x, x)) >>> (( + mathy2(x, y)) ^ y)) | 0)) >= (Math.abs(((-Number.MIN_SAFE_INTEGER >>> y) | 0)) | 0)) >>> 0))); }); ");
/*fuzzSeed-72153729*/count=2852; tryItOut("m2.has(m2);");
/*fuzzSeed-72153729*/count=2853; tryItOut("( /x/ );");
/*fuzzSeed-72153729*/count=2854; tryItOut("v2 = (t1 instanceof a1);");
/*fuzzSeed-72153729*/count=2855; tryItOut("testMathyFunction(mathy2, [-Number.MIN_VALUE, -0, 0.000000000000001, 0x07fffffff, -(2**53-2), -0x07fffffff, -0x0ffffffff, 2**53, -Number.MAX_SAFE_INTEGER, 2**53-2, -Number.MAX_VALUE, 1, 2**53+2, Number.MIN_SAFE_INTEGER, 0/0, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, -0x080000001, 0x080000000, 1.7976931348623157e308, 0, 0x0ffffffff, 0x100000000, -(2**53+2), Math.PI, 42, 0x100000001, -0x080000000, -0x100000000, -Number.MIN_SAFE_INTEGER, -0x100000001, -(2**53), 1/0, -1/0, 0x080000001]); ");
/*fuzzSeed-72153729*/count=2856; tryItOut("g0.o1.v1 = Object.prototype.isPrototypeOf.call(h2, p2);");
/*fuzzSeed-72153729*/count=2857; tryItOut("\"use strict\"; for(let e = yield (4277) in [z1].valueOf(\"number\")) print(uneval(o2.g0));");
/*fuzzSeed-72153729*/count=2858; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2859; tryItOut("\"use strict\"; testMathyFunction(mathy3, /*MARR*/[Number.MIN_VALUE, (-1/0), (-1/0),  /x/ ,  /x/ ,  /x/ , Number.MIN_VALUE, (-1/0),  /x/ , Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, (-1/0), (-1/0),  /x/ , (-1/0),  /x/ , Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE,  /x/ ,  /x/ , Number.MIN_VALUE,  /x/ , (-1/0),  /x/ , Number.MIN_VALUE, (-1/0),  /x/ , (-1/0), Number.MIN_VALUE,  /x/ , Number.MIN_VALUE,  /x/ , Number.MIN_VALUE, Number.MIN_VALUE, Number.MIN_VALUE, (-1/0), Number.MIN_VALUE, (-1/0), (-1/0), Number.MIN_VALUE, Number.MIN_VALUE,  /x/ ,  /x/ , Number.MIN_VALUE,  /x/ ]); ");
/*fuzzSeed-72153729*/count=2860; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return Math.atan2((( - (Math.fround(( - y)) <= Math.round(x))) | 0), ((( ! Math.min(0x07fffffff, ( + ( + Math.ceil(( + y)))))) | 0) ? Math.atan2((((-Number.MAX_SAFE_INTEGER >>> 0) >= ( ! Math.hypot(y, x))) >>> 0), Math.ceil(((y ? ( + y) : x) >>> 0))) : ( + ( + Math.fround((Math.fround(Math.cosh((( - Math.fround(x)) | 0))) != (mathy0((Number.MIN_VALUE >>> 0), (x >>> 0)) >>> 0))))))); }); testMathyFunction(mathy2, [2**53-2, Math.PI, 1, -(2**53-2), 42, 0x080000000, -(2**53), -Number.MAX_SAFE_INTEGER, 0x100000000, Number.MIN_VALUE, -Number.MAX_VALUE, -(2**53+2), 1.7976931348623157e308, -0x0ffffffff, 0x100000001, -0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, -0x100000000, 0x07fffffff, 0.000000000000001, Number.MAX_VALUE, -0x080000001, -0x07fffffff, Number.MIN_SAFE_INTEGER, 0x080000001, 1/0, -0, -0x100000001, 0/0, 0, 2**53+2, -Number.MIN_VALUE, 2**53, -1/0, Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2861; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2862; tryItOut("window = [] = [], e, vhfjlz, x = false, z, wlfunm, oytxic, this, c, x;m1 = new Map;");
/*fuzzSeed-72153729*/count=2863; tryItOut("m0 = new WeakMap;");
/*fuzzSeed-72153729*/count=2864; tryItOut("Array.prototype.push.call(a1, a0, s1, this, a1);v0 = (m2 instanceof s0);");
/*fuzzSeed-72153729*/count=2865; tryItOut("\"use strict\"; a1.splice(2, ({valueOf: function() { Array.prototype.unshift.apply(a0, [m0, h2, this.f0]);return 7; }}), b0);");
/*fuzzSeed-72153729*/count=2866; tryItOut("f2 = decodeURIComponent;");
/*fuzzSeed-72153729*/count=2867; tryItOut("\"use strict\"; /*RXUB*/var r = new RegExp(\"\\\\2\", \"gy\"); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-72153729*/count=2868; tryItOut("\"use strict\"; \"use asm\"; h2.enumerate = (function() { for (var j=0;j<20;++j) { f0(j%3==0); } });");
/*fuzzSeed-72153729*/count=2869; tryItOut("print( '' );");
/*fuzzSeed-72153729*/count=2870; tryItOut("\"use strict\"; \"use asm\"; m0.delete(x % window);");
/*fuzzSeed-72153729*/count=2871; tryItOut("\"use strict\"; mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var atan = stdlib.Math.atan;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    d0 = (-1.2089258196146292e+24);\n    d0 = (d0);\n    i1 = (0xf76a8648);\n    d0 = (-4294967296.0);\n    {\n      i1 = ((((/*FFI*/ff()|0)-((d0) > (-144115188075855870.0))-(i1))>>>((0x322b0820))));\n    }\n    return +((+atan(((d0)))));\n  }\n  return f; })(this, {ff: new Function}, new ArrayBuffer(4096)); testMathyFunction(mathy1, [2**53-2, -1/0, 1, 2**53, Number.MAX_VALUE, -(2**53-2), 0x080000000, 0/0, -0x100000000, Number.MIN_SAFE_INTEGER, -0x0ffffffff, 0, 2**53+2, 0x080000001, 0x07fffffff, -0x080000001, -Number.MIN_VALUE, 0x100000001, -0x080000000, Math.PI, -0x100000001, Number.MAX_SAFE_INTEGER, 0x100000000, 42, 1.7976931348623157e308, -(2**53), -Number.MAX_VALUE, 0x0ffffffff, -0x07fffffff, 0.000000000000001, 1/0, -(2**53+2), Number.MIN_VALUE, -0, -Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2872; tryItOut("\"use strict\"; /*RXUB*/var r = (c >>= x); var s = x; print(r.test(s)); ");
/*fuzzSeed-72153729*/count=2877; tryItOut("/*infloop*/L:for((let (c = null) undefined); x; SimpleObject()) i0.valueOf = f1;");
/*fuzzSeed-72153729*/count=2878; tryItOut("(void schedulegc(g1.g0));");
/*fuzzSeed-72153729*/count=2879; tryItOut("var lxtjhj;g1.v1 = r0.sticky;");
/*fuzzSeed-72153729*/count=2880; tryItOut("(void schedulegc(g1));");
/*fuzzSeed-72153729*/count=2881; tryItOut("s0[new String(\"-17\")] = s1;");
/*fuzzSeed-72153729*/count=2882; tryItOut("\"use strict\"; a0.unshift(b1, o2.a2, b0, s2, v1);");
/*fuzzSeed-72153729*/count=2883; tryItOut("mathy0 = (function(x, y) { return Math.atan2(Math.imul((Math.cosh((0.000000000000001 | 0)) | 0), ( + Math.max(( + Math.hypot(Math.fround(( + (( + ( - (0x0ffffffff ? 2**53+2 : x))) === ( + y)))), ( + ((Math.tan(y) < y) | 0)))), ((((x | 0) ? y : (y >>> 0)) >>> 0) | 0)))), ((( ! (( ! x) % ((x , y) / Math.max((y >>> 0), x)))) >>> 0) ? (Math.imul(y, Math.hypot(( + ( - 1.7976931348623157e308)), x)) >>> 0) : (Math.exp((Math.atanh((( - Math.fround(Math.fround((y | Math.fround((x ? -(2**53-2) : y)))))) | 0)) >>> 0)) >>> 0))); }); testMathyFunction(mathy0, [2**53-2, 0x0ffffffff, Number.MAX_VALUE, -(2**53-2), -0x0ffffffff, 1.7976931348623157e308, 2**53+2, 0.000000000000001, Number.MIN_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0x100000000, -0x07fffffff, 0/0, 0x080000001, 1, 0, -(2**53), -(2**53+2), -Number.MAX_VALUE, 1/0, Math.PI, -Number.MIN_SAFE_INTEGER, -0x100000001, Number.MAX_SAFE_INTEGER, 0x100000001, 0x080000000, -1/0, 0x07fffffff, -0, Number.MIN_VALUE, 42, 2**53, -0x080000000, -0x080000001, -Number.MIN_VALUE, 0x100000000]); ");
/*fuzzSeed-72153729*/count=2884; tryItOut("a0[(4277) >>>= \n(x = \"\\uEFE2\")] = g0;");
/*fuzzSeed-72153729*/count=2885; tryItOut("mathy2 = (function(x, y) { \"use strict\"; return (mathy0((Math.min(Math.tan(Math.fround(Math.hypot(( + ( ! (y >>> 0))), x))), ( + ( + ( ~ (y * y))))) | 0), (Math.hypot(Math.atan2(( + (Math.atan(Math.imul(y, x)) ^ Math.hypot(x, y))), 1), ((( + Math.log2(( + (Math.fround(mathy1(Math.fround(-(2**53-2)), Math.fround(x))) > y)))) ^ (((( + Math.max(y, ( + Math.abs(x)))) - ((Math.hypot((x | 0), (( ! Math.PI) | 0)) | 0) >>> 0)) >>> 0) | 0)) | 0)) | 0)) | 0); }); testMathyFunction(mathy2, [undefined, '\\0', ({valueOf:function(){return '0';}}), null, (function(){return 0;}), 1, NaN, '', true, false, (new Number(0)), (new Number(-0)), (new String('')), -0, (new Boolean(true)), [], '0', '/0/', [0], ({toString:function(){return '0';}}), objectEmulatingUndefined(), 0, /0/, ({valueOf:function(){return 0;}}), (new Boolean(false)), 0.1]); ");
/*fuzzSeed-72153729*/count=2886; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2887; tryItOut("function shapeyConstructor(ilfvcz){if ([[]]) for (var ytqborkxh in ilfvcz) { }delete ilfvcz[\"delete\"];ilfvcz[\"delete\"] = ();ilfvcz[\"includes\"] = String.prototype.big;{ e1 = new Set; } return ilfvcz; }/*tLoopC*/for (let b of objectEmulatingUndefined) { try{let jijxob = shapeyConstructor(b); print('EETT'); print(/*MARR*/[ 'A' , new Boolean(false), (-1/0),  'A' ,  'A' , 1.2e3,  'A' , (-1/0), (-1/0), new Boolean(false), new Boolean(false), true, 1.2e3, (-1/0), 1.2e3, new Boolean(false), true, (-1/0),  'A' , 1.2e3, 1.2e3, new Boolean(false), (-1/0)].some(Object.getOwnPropertySymbols, jijxob));}catch(e){print('TTEE ' + e); } }");
/*fuzzSeed-72153729*/count=2888; tryItOut("\"use strict\"; o1 = Object.create(b2);");
/*fuzzSeed-72153729*/count=2889; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2890; tryItOut("g1 = this;");
/*fuzzSeed-72153729*/count=2891; tryItOut("mathy0 = (function(x, y) { return (Math.fround((( - y) << Math.log10(Math.log2(y)))) === ( ~ Math.fround(( + (( + Math.max(( + Math.atan2(y, (Math.imul((y >>> 0), -Number.MIN_VALUE) >>> 0))), ( + 2**53))) ** ( + (( ~ (((( + (x >>> 0)) >>> 0) , 0/0) | 0)) >>> 0))))))); }); ");
/*fuzzSeed-72153729*/count=2892; tryItOut("e0.add((this.__defineGetter__(\"x\", (4277))));");
/*fuzzSeed-72153729*/count=2893; tryItOut("mathy5 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, i1)\n  {\n    d0 = +d0;\n    i1 = i1|0;\n    var i2 = 0;\n    var i3 = 0;\n    var d4 = 72057594037927940.0;\n    var i5 = 0;\n    var i6 = 0;\n    var d7 = 3.777893186295716e+22;\n    var i8 = 0;\n    return (((0xfc4ed6f5)+((imul((!(i5)), (0x7c2de310))|0))))|0;\n  }\n  return f; })(this, {ff: function(y) { yield y; b1 + '';; yield y; }}, new SharedArrayBuffer(4096)); ");
/*fuzzSeed-72153729*/count=2894; tryItOut("g2.a2 = [];");
/*fuzzSeed-72153729*/count=2895; tryItOut("mathy4 = (function(x, y) { return (( + Math.min(Math.fround(mathy2(Math.fround(( ! Math.min(y, (x >>> 0)))), Math.fround(Math.abs(42)))), Math.fround((y && Math.fround(Math.imul(Math.fround(-0), Math.fround(-0x07fffffff))))))) === (Math.asinh(( + (x ? ( - x) : Math.imul(Math.fround(( + ( ~ y))), Math.fround((( ~ (x | 0)) | 0)))))) >>> 0)); }); testMathyFunction(mathy4, ['/0/', null, ({toString:function(){return '0';}}), '\\0', (new Boolean(false)), 0, objectEmulatingUndefined(), false, 1, [], [0], (new Number(-0)), (function(){return 0;}), NaN, ({valueOf:function(){return 0;}}), (new String('')), ({valueOf:function(){return '0';}}), -0, /0/, undefined, true, (new Number(0)), (new Boolean(true)), '', 0.1, '0']); ");
/*fuzzSeed-72153729*/count=2896; tryItOut("Array.prototype.shift.call(a2);");
/*fuzzSeed-72153729*/count=2897; tryItOut("\"use strict\"; h1.defineProperty = (function(j) { if (j) { try { i1 = new Iterator(a2, true); } catch(e0) { } try { selectforgc(o2); } catch(e1) { } try { Array.prototype.shift.call(o2.a1); } catch(e2) { } Array.prototype.splice.call(a1, 7, 3, p1); } else { try { s2 += s0; } catch(e0) { } v2 = Object.prototype.isPrototypeOf.call(e1, g0.p2); } });");
/*fuzzSeed-72153729*/count=2898; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2899; tryItOut("o2.a0[v2];");
/*fuzzSeed-72153729*/count=2900; tryItOut("o2.v2 = Object.prototype.isPrototypeOf.call(o1.t0, s2);");
/*fuzzSeed-72153729*/count=2901; tryItOut("/*RXUB*/var r = /\\3/yi; var s = \"\\nc.A\\ube85\\n\\n\\u00bf\"; print(s.split(r)); ");
/*fuzzSeed-72153729*/count=2902; tryItOut("mathy3 = (function(x, y) { \"use strict\"; return Math.min(Math.log1p(mathy1(x, Math.fround(Math.min(Math.imul(Math.fround(y), y), x)))), Math.pow(( + ( ~ ( + ( + Math.fround(x))))), ( + Math.log1p(y)))); }); testMathyFunction(mathy3, [0x100000000, Number.MIN_SAFE_INTEGER, 2**53-2, -0x07fffffff, 0/0, 2**53+2, -(2**53+2), 0x080000001, 1, -0x080000001, -(2**53-2), -Number.MIN_VALUE, 42, Math.PI, -(2**53), -0x100000001, 0.000000000000001, -Number.MIN_SAFE_INTEGER, -1/0, -Number.MAX_VALUE, -Number.MAX_SAFE_INTEGER, -0x080000000, Number.MAX_VALUE, 1/0, 0x0ffffffff, -0, Number.MIN_VALUE, 0x080000000, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x07fffffff, -0x100000000, 0, 0x100000001, 1.7976931348623157e308, 2**53]); ");
/*fuzzSeed-72153729*/count=2903; tryItOut("\"use strict\"; Object.defineProperty(this, \"t1\", { configurable: true, enumerable: (x % 93 == 41),  get: function() {  return new Float32Array(this.b0); } });");
/*fuzzSeed-72153729*/count=2904; tryItOut("\"use strict\"; v0 = Array.prototype.every.apply(g1.a1, [(function() { var r0 = /./y; return g2; }), h0, f0]);");
/*fuzzSeed-72153729*/count=2905; tryItOut("h0.valueOf = f1;");
/*fuzzSeed-72153729*/count=2906; tryItOut("mathy3 = (function(x, y) { return (Math.min(Math.fround(Math.atan2(Math.fround(( + (( + Math.fround(Math.tan(Math.fround(x)))) ** ( + Math.sign((( + ((( + ( ~ y)) * -Number.MAX_SAFE_INTEGER) >>> 0)) >>> 0)))))), Math.fround((Math.max(Math.fround(x), ((Math.expm1((( + y) | 0)) | 0) | 0)) + Math.fround(Math.max(x, y)))))), (( + ((((mathy1((( + mathy1(( - x), ( + (((y | 0) || (x | 0)) | 0)))) >>> 0), (x >>> 0)) >>> 0) >>> 0) ^ mathy0(-0x0ffffffff, y)) >>> 0)) * Math.fround(((((( + ( + ( + x))) | 0) && (x | 0)) | 0) && Math.fround(y))))) >>> 0); }); testMathyFunction(mathy3, [(new String('')), true, '/0/', ({valueOf:function(){return '0';}}), '0', (new Boolean(false)), ({toString:function(){return '0';}}), false, NaN, undefined, (new Number(-0)), '', [], null, [0], (function(){return 0;}), 1, /0/, '\\0', -0, (new Number(0)), objectEmulatingUndefined(), 0.1, (new Boolean(true)), 0, ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-72153729*/count=2907; tryItOut("\"use asm\"; for(e in ((Number.prototype.toLocaleString)( '' )))/*tLoop*/for (let e of /*MARR*/[['z'],  /x/g , ['z'], ['z'],  /x/g ,  /x/g ,  /x/g ,  /x/g , ['z'], ['z'], ['z'], ['z'],  /x/g ,  /x/g ,  /x/g ,  /x/g ,  /x/g , ['z'],  /x/g , ['z'], ['z'],  /x/g ,  /x/g , ['z'], ['z'],  /x/g ,  /x/g , ['z'],  /x/g , ['z'], ['z'], ['z'], ['z'],  /x/g ,  /x/g ,  /x/g , ['z'],  /x/g ,  /x/g , ['z'], ['z'],  /x/g ,  /x/g ,  /x/g , ['z'], ['z'],  /x/g ,  /x/g ,  /x/g , ['z'], ['z'], ['z'],  /x/g ,  /x/g , ['z'], ['z'], ['z'],  /x/g ]) { selectforgc(o0); }");
/*fuzzSeed-72153729*/count=2908; tryItOut("g1.g0.i1 = e2.iterator;");
/*fuzzSeed-72153729*/count=2909; tryItOut("mathy0 = (function(x, y) { return (Math.expm1((Math.acos((( + Math.clz32((( ! x) | 0))) >>> 0)) >>> 0)) >> ( + (Math.atan2(Math.fround(Math.pow(Math.fround(( ! Math.fround(Math.atan(x)))), Math.fround(y))), (( - x) >>> ( ~ (Math.atanh(( + (y !== 0x100000001))) ? x : y)))) | 0))); }); testMathyFunction(mathy0, /*MARR*/[[], (-1/0), (-1/0), -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, -0x100000000, [], [], -0x100000000, (-1/0), -0x100000000, [], -0x100000000, [], -0x100000000, (-1/0), (-1/0), [], -0x100000000, (-1/0), [], -0x100000000, (-1/0), (-1/0), -0x100000000, (-1/0), (-1/0), (-1/0), [], (-1/0), -0x100000000, [], [], [], [], -0x100000000, [], [], (-1/0), -0x100000000, (-1/0), -0x100000000, (-1/0), -0x100000000, (-1/0), (-1/0), -0x100000000, [], -0x100000000, (-1/0), [], [], (-1/0), -0x100000000, [], -0x100000000, -0x100000000, [], [], [], -0x100000000, (-1/0), (-1/0), -0x100000000, -0x100000000, [], [], (-1/0), [], (-1/0), -0x100000000, -0x100000000, [], [], [], [], (-1/0), -0x100000000, []]); ");
/*fuzzSeed-72153729*/count=2910; tryItOut("\"use strict\"; mathy4 = (function(x, y) { return (( ! Math.fround(( ! Math.atan2(((( + (Math.fround(x) & ( + y))) % Math.sqrt((Math.hypot(((-0 | y) >>> 0), (Math.pow(x, x) >>> 0)) >>> 0))) >>> 0), Math.fround(Math.hypot(Math.fround(x), Math.fround(Math.PI))))))) >>> 0); }); testMathyFunction(mathy4, ['/0/', ({toString:function(){return '0';}}), null, -0, '0', (new String('')), 0, '', '\\0', /0/, (new Boolean(false)), NaN, false, ({valueOf:function(){return '0';}}), (new Boolean(true)), [], 0.1, (new Number(-0)), true, (function(){return 0;}), 1, objectEmulatingUndefined(), undefined, [0], (new Number(0)), ({valueOf:function(){return 0;}})]); ");
/*fuzzSeed-72153729*/count=2911; tryItOut("testMathyFunction(mathy0, [0x07fffffff, -Number.MIN_VALUE, -0x100000001, 1.7976931348623157e308, 2**53, 42, Number.MAX_SAFE_INTEGER, -0x07fffffff, 0x100000001, Number.MAX_VALUE, 1/0, -(2**53), 2**53-2, 0x080000000, 2**53+2, -0x080000001, -0x080000000, -(2**53-2), 0/0, -1/0, 0.000000000000001, 0x080000001, Number.MIN_SAFE_INTEGER, 0x100000000, -(2**53+2), -Number.MAX_VALUE, -Number.MIN_SAFE_INTEGER, -0x100000000, Math.PI, 1, -Number.MAX_SAFE_INTEGER, -0, -0x0ffffffff, 0x0ffffffff, 0, Number.MIN_VALUE]); ");
/*fuzzSeed-72153729*/count=2912; tryItOut("mathy3 = (function(x, y) { return ((Math.imul((Math.fround(Math.max(( ~ Math.fround((Math.fround((-Number.MIN_VALUE >>> x)) || Math.fround(x)))), Math.max(Math.fround((x === ( + ((y | 0) & ( + -0x0ffffffff))))), (( ! y) >>> 0)))) >>> 0), (mathy1(Math.fround(Math.max((( - mathy1(( + y), x)) ? x : Math.pow(-Number.MIN_VALUE, (Math.clz32((y | 0)) | 0))), ( + y))), ((Math.pow(( + x), (y >>> 0)) | 0) >>> 0)) >>> 0)) > (Math.acosh((Math.fround(( - Math.max(Math.max((((y >>> 0) ? (x >>> 0) : (y | 0)) >>> 0), x), ( + ((0/0 >>> 0) <= ( + x)))))) | 0)) | 0)) | 0); }); testMathyFunction(mathy3, [-0x100000001, Number.MIN_VALUE, -1/0, 2**53-2, -(2**53), -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, 0x100000000, 2**53, -(2**53+2), -0x080000000, 0x07fffffff, -0x080000001, -0x07fffffff, -Number.MIN_VALUE, -0, 42, 0x080000001, 1, -0x0ffffffff, 1/0, 1.7976931348623157e308, 0/0, -(2**53-2), 0, Number.MAX_SAFE_INTEGER, -0x100000000, 0x080000000, 2**53+2, 0x0ffffffff, 0.000000000000001, -Number.MIN_SAFE_INTEGER, 0x100000001, Math.PI, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2913; tryItOut("print(x);");
/*fuzzSeed-72153729*/count=2914; tryItOut("neuter(b1, \"same-data\");");
/*fuzzSeed-72153729*/count=2915; tryItOut("/*tLoop*/for (let z of /*MARR*/[x, new Boolean(true), 0x07fffffff, new Boolean(true), new Boolean(true),  \"\" ,  \"\" ,  \"\" , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), 0x07fffffff,  \"\" , 0x07fffffff, x, 0x07fffffff,  \"\" , new Boolean(true), x, new Boolean(true), x, new Boolean(true), 0x07fffffff, 0x07fffffff,  \"\" , new Boolean(true), x, new Boolean(true), 0x07fffffff, x, new Boolean(true),  \"\" , 0x07fffffff, x, new Boolean(true), 0x07fffffff, new Boolean(true), new Boolean(true), x, 0x07fffffff,  \"\" , new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), new Boolean(true), x, new Boolean(true), new Boolean(true),  \"\" ,  \"\" , 0x07fffffff, x, 0x07fffffff,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" ,  \"\" , x, x, new Boolean(true),  \"\" ,  \"\" , new Boolean(true), x, x, new Boolean(true), new Boolean(true), x,  \"\" , 0x07fffffff,  \"\" , 0x07fffffff, x,  \"\" ,  \"\" ]) { selectforgc(o2); }");
/*fuzzSeed-72153729*/count=2916; tryItOut("\"use strict\"; mathy1 = (function(x, y) { return (mathy0((Math.sqrt((x + ( + Math.acosh(( + (Math.min(Math.fround((Math.tanh((y | 0)) | 0)), Math.fround(2**53+2)) >>> 0)))))) >>> 0), ((Math.min(Math.fround((Math.fround(Math.acosh((y >>> 0))) << Math.fround(Math.fround(Math.sign((y <= -0x080000001)))))), Math.fround(y)) << Math.hypot(( ! y), ( + ( - ( + x))))) >>> 0)) >>> 0); }); testMathyFunction(mathy1, [[], '/0/', null, 0.1, '', objectEmulatingUndefined(), (function(){return 0;}), /0/, true, undefined, '\\0', 1, (new Number(-0)), (new Boolean(false)), ({valueOf:function(){return 0;}}), -0, (new Boolean(true)), ({toString:function(){return '0';}}), (new Number(0)), [0], '0', false, 0, (new String('')), NaN, ({valueOf:function(){return '0';}})]); ");
/*fuzzSeed-72153729*/count=2917; tryItOut("\"use strict\"; f0 = Proxy.createFunction(h0, f1, this.f2);");
/*fuzzSeed-72153729*/count=2918; tryItOut("var xrzezu = new SharedArrayBuffer(4); var xrzezu_0 = new Float64Array(xrzezu); print(xrzezu_0[0]); var xrzezu_1 = new Int32Array(xrzezu); xrzezu_1[0] = -11; var xrzezu_2 = new Uint8ClampedArray(xrzezu); xrzezu_2[0] = -6; var xrzezu_3 = new Uint32Array(xrzezu); xrzezu_3[0] = -7; var xrzezu_4 = new Float32Array(xrzezu); xrzezu_4[0] = 24; var xrzezu_5 = new Float64Array(xrzezu); xrzezu_5[0] = -6; var xrzezu_6 = new Float64Array(xrzezu); print(xrzezu_6[0]); /*infloop*/for(x; new 8( '' ); this) (window);h1.delete = (function() { o1.t2 = t1[2]; return h1; });");
/*fuzzSeed-72153729*/count=2919; tryItOut("v1 = g1.runOffThreadScript();");
/*fuzzSeed-72153729*/count=2920; tryItOut("var vdsnwm = new SharedArrayBuffer(24); var vdsnwm_0 = new Int32Array(vdsnwm); vdsnwm_0[0] = -12; var vdsnwm_1 = new Uint16Array(vdsnwm); vdsnwm_1[0] = -9; var vdsnwm_2 = new Int8Array(vdsnwm); print(vdsnwm_2[0]); vdsnwm_2[0] = -7; var vdsnwm_3 = new Int16Array(vdsnwm); vdsnwm_3[0] = -24; var vdsnwm_4 = new Uint8Array(vdsnwm); vdsnwm_4[0] = 1099063203; var vdsnwm_5 = new Int32Array(vdsnwm); /*infloop*/L:do /* no regression tests found */ while(vdsnwm_2[0]);print(e0);");
/*fuzzSeed-72153729*/count=2921; tryItOut("v1 = Object.prototype.isPrototypeOf.call(a1, i1);");
/*fuzzSeed-72153729*/count=2922; tryItOut("mathy2 = (function(x, y) { return ( ~ ( + (( + Math.min((mathy0(((Math.fround(y) && y) >>> 0), (( ~ y) | 0)) | 0), ( + Math.clz32(( + x))))) != (( + Math.fround(x)) * -0x0ffffffff)))); }); testMathyFunction(mathy2, [false, (new String('')), '\\0', 0.1, ({valueOf:function(){return '0';}}), [], ({valueOf:function(){return 0;}}), objectEmulatingUndefined(), (function(){return 0;}), '/0/', (new Number(-0)), true, (new Number(0)), (new Boolean(true)), undefined, (new Boolean(false)), NaN, '', 1, null, [0], -0, ({toString:function(){return '0';}}), 0, /0/, '0']); ");
/*fuzzSeed-72153729*/count=2923; tryItOut("mathy5 = (function(x, y) { return (( ! ((((Math.atan2((Math.asin(( + -0x100000000)) | 0), (( + Math.hypot(Math.fround(y), ( + 0x0ffffffff))) | 0)) | 0) - x) != (Math.fround(y) | 0)) | 0)) | 0); }); testMathyFunction(mathy5, [0/0, 1/0, 0x080000000, -Number.MIN_SAFE_INTEGER, 1, 0x100000001, Number.MIN_VALUE, 42, 1.7976931348623157e308, -1/0, 0, 0x07fffffff, Number.MAX_VALUE, -0x07fffffff, 0x0ffffffff, -Number.MAX_SAFE_INTEGER, -0x080000000, 0x080000001, -0, -Number.MIN_VALUE, -(2**53+2), -0x100000000, 0.000000000000001, Math.PI, 2**53, 2**53+2, -Number.MAX_VALUE, -(2**53), -0x080000001, Number.MAX_SAFE_INTEGER, -0x100000001, -0x0ffffffff, Number.MIN_SAFE_INTEGER, 2**53-2, 0x100000000, -(2**53-2)]); ");
/*fuzzSeed-72153729*/count=2924; tryItOut("for (var p in this.f2) { try { t0 = t0.subarray(11); } catch(e0) { } try { h2.__proto__ = i2; } catch(e1) { } try { Array.prototype.reverse.apply(this.a1, [a1, p2, f1, o1]); } catch(e2) { } Array.prototype.reverse.apply(a2, []); }");
/*fuzzSeed-72153729*/count=2925; tryItOut("\"use strict\"; v0 = null;");
/*fuzzSeed-72153729*/count=2926; tryItOut("\"use strict\"; /*RXUB*/var r = (let (z) [1]); var s = \"\"; print(s.search(r)); ");
/*fuzzSeed-72153729*/count=2927; tryItOut("\"use strict\"; Array.prototype.push.call(a0, o0, p1);\n/*vLoop*/for (let lpmhac = 0, x; lpmhac < 1; ++lpmhac) { let z = lpmhac; /*oLoop*/for (var xvbgha = 0; xvbgha < 5; ++xvbgha) { g1.f1.valueOf = (function() { try { v2 = Object.prototype.isPrototypeOf.call(g0, g1); } catch(e0) { } try { a2.sort((function mcc_() { var pvsffs = 0; return function() { ++pvsffs; if (/*ICCD*/pvsffs % 10 != 6) { dumpln('hit!'); Array.prototype.shift.call(a1); } else { dumpln('miss!'); try { g2 = this; } catch(e0) { } h2.toSource = (function(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) { x = 8 + 1; var r0 = z & a8; a5 = a5 & a1; a7 = a0 & 8; var r1 = a4 & a2; var r2 = 6 ^ a4; r2 = a9 ^ r1; var r3 = r1 | a5; var r4 = r1 % a3; var r5 = a6 ^ a0; var r6 = r5 + 8; var r7 = a3 & a4; var r8 = a2 * r1; var r9 = r1 & 0; r5 = 1 & r1; var r10 = a5 * 5; var r11 = a0 * 5; var r12 = 4 % a9; var r13 = 6 | 9; var r14 = r10 & 6; var r15 = a9 * r6; var r16 = 1 + 7; var r17 = r11 - a4; var r18 = 5 & 2; var r19 = z % r0; var r20 = r13 % 0; var r21 = r7 - r1; r14 = a6 & z; var r22 = z ^ a9; var r23 = 9 % 7; var r24 = r9 % a4; a8 = a6 - a6; print(z); var r25 = 6 ^ r1; r19 = 2 ^ r4; var r26 = x & 1; var r27 = z & 3; print(r13); var r28 = r22 ^ 2; var r29 = 8 & a4; return a9; }); } };})(), i1, g2); } catch(e1) { } try { for (var v of g0) { try { m1.set(this.h2, -0); } catch(e0) { } /*MXX3*/g0.Uint16Array.BYTES_PER_ELEMENT = g0.Uint16Array.BYTES_PER_ELEMENT; } } catch(e2) { } m0.delete( \"\" ); return g2.m1; }); }  } \n");
/*fuzzSeed-72153729*/count=2928; tryItOut("mathy4 = (function(x, y) { return (( + Math.atan2((( ! 0x07fffffff) | 0), ( + Math.fround((Math.min(Math.fround(( - (x | 0))), y) | ((Math.fround(0/0) % Math.exp((Number.MAX_SAFE_INTEGER ^ Number.MIN_VALUE))) >>> 0)))))) % ( + ( ~ ( + Math.ceil(Math.sqrt(x)))))); }); testMathyFunction(mathy4, [-Number.MIN_SAFE_INTEGER, Number.MIN_VALUE, 2**53, 0, -0x0ffffffff, 42, -0x080000000, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, 0x080000000, Number.MIN_SAFE_INTEGER, Math.PI, -0x100000001, 0.000000000000001, 1/0, -1/0, -(2**53+2), 0x080000001, -(2**53-2), 0x0ffffffff, 0x100000000, -Number.MIN_VALUE, 0/0, 0x07fffffff, -(2**53), -Number.MAX_VALUE, -0, -0x100000000, Number.MAX_SAFE_INTEGER, 2**53-2, 1, 1.7976931348623157e308, -0x080000001, 0x100000001, -0x07fffffff]); ");
/*fuzzSeed-72153729*/count=2929; tryItOut("\"use strict\"; ( \"\"  * true(\u000915) <= Math.pow(8, -27).unwatch(-6));");
/*fuzzSeed-72153729*/count=2930; tryItOut("mathy2 = (function(x, y) { return ( ! ((((( + (( - (( + y) >>> 0)) >>> 0)) && Math.fround(Math.pow(Math.fround(Number.MIN_SAFE_INTEGER), Math.fround((mathy0(Math.fround(Math.round(y)), (y | 0)) | 0))))) | 0) << (( ! y) | 0)) | 0)); }); testMathyFunction(mathy2, [0/0, -Number.MAX_VALUE, -1/0, -0x080000000, -0x0ffffffff, 42, -(2**53), -(2**53-2), 0x080000001, 0x080000000, 0x07fffffff, 2**53+2, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -(2**53+2), 0x0ffffffff, Math.PI, -0x080000001, 1/0, Number.MIN_VALUE, 2**53, 0.000000000000001, -0x100000001, 2**53-2, 0x100000001, 0, -Number.MIN_SAFE_INTEGER, -0x07fffffff, 1, 1.7976931348623157e308, 0x100000000, -0x100000000, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, -Number.MIN_VALUE, -0]); ");
/*fuzzSeed-72153729*/count=2931; tryItOut("o0.v1 = (v0 instanceof g1.m1);");
/*fuzzSeed-72153729*/count=2932; tryItOut("o1.b2 + '';");
/*fuzzSeed-72153729*/count=2933; tryItOut("\n /x/ ;e2.has(m0);");
/*fuzzSeed-72153729*/count=2934; tryItOut("\"use strict\"; a2.shift();");
/*fuzzSeed-72153729*/count=2935; tryItOut("\"use strict\"; print([] = {});t2 = t0.subarray(19, ((let (e=eval) e).prototype));");
/*fuzzSeed-72153729*/count=2936; tryItOut("mathy3 = (function(x, y) { return Math.fround(Math.atanh(Math.fround(mathy1(Math.atan2(( + Math.cosh(( + Math.fround(( - Math.fround(( ! Math.fround((Math.fround(x) !== Math.fround(y)))))))))), x), (Math.acosh(Math.round(y)) >>> 0))))); }); ");
/*fuzzSeed-72153729*/count=2937; tryItOut("\"use strict\"; testMathyFunction(mathy2, [0x080000000, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 0, -Number.MAX_SAFE_INTEGER, 0x100000001, -(2**53-2), 0x100000000, 1.7976931348623157e308, -0x080000001, 0.000000000000001, -Number.MAX_VALUE, 2**53-2, Number.MIN_SAFE_INTEGER, -1/0, -0x080000000, -(2**53), -0x100000001, -Number.MIN_VALUE, -Number.MIN_SAFE_INTEGER, 2**53, 0x07fffffff, 0x0ffffffff, -0x0ffffffff, -0, 0/0, 42, 2**53+2, -(2**53+2), 1/0, 1, -0x07fffffff, -0x100000000, Math.PI, Number.MIN_VALUE, 0x080000001]); ");
/*fuzzSeed-72153729*/count=2938; tryItOut("/*MXX1*/o2 = g0.Array.prototype.slice;");
/*fuzzSeed-72153729*/count=2939; tryItOut("mathy1 = (function(x, y) { return (( + (( ~ (Math.imul(y, (Math.min(x, (( ! x) >>> 0)) | 0)) == ( + mathy0((Math.cosh(( + y)) <= Math.fround(( ~ ((y >>> -(2**53-2)) | 0)))), (Math.max(( ~ x), y) >>> 0))))) | 0)) | 0); }); testMathyFunction(mathy1, [-0x100000000, 0x080000000, 2**53-2, 0, 0x100000000, 0.000000000000001, 1/0, -(2**53-2), 1, -0x080000000, -Number.MIN_SAFE_INTEGER, 2**53+2, 0x100000001, 0x080000001, 0/0, -(2**53+2), 1.7976931348623157e308, -0x100000001, 2**53, -(2**53), Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE, -Number.MAX_VALUE, -0x07fffffff, Number.MAX_SAFE_INTEGER, -0x0ffffffff, 0x0ffffffff, -0x080000001, -1/0, 0x07fffffff, 42, -Number.MIN_VALUE, Math.PI, -0, Number.MIN_SAFE_INTEGER]); ");
/*fuzzSeed-72153729*/count=2940; tryItOut("{ void 0; verifyprebarriers(); } print(uneval(b2));e2.add(o2.g0);");
/*fuzzSeed-72153729*/count=2941; tryItOut("v1 = (s2 instanceof g2.a2);");
/*fuzzSeed-72153729*/count=2942; tryItOut("puydov, window = false, e = Math.pow(x, 8), nbgzqs, flacuq, x, y, xxjslm, x, z;s0 += s0;");
/*fuzzSeed-72153729*/count=2943; tryItOut("s1 += g1.s2;let (b) { a0.pop(a0, o2.b0); }");
/*fuzzSeed-72153729*/count=2944; tryItOut("mathy2 = (function(x, y) { return Math.min((( ~ Math.max(0/0, ( + ( - ( + Math.hypot(-Number.MIN_VALUE, x)))))) ** ( + Math.exp(( + x)))), ( + Math.atanh(( + ( + Math.acosh(( + Math.tan((x / Math.fround(Math.acos(Math.fround(x)))))))))))); }); ");
/*fuzzSeed-72153729*/count=2945; tryItOut("(y = undefined);");
/*fuzzSeed-72153729*/count=2946; tryItOut("");
/*fuzzSeed-72153729*/count=2947; tryItOut("v1 = (this.i1 instanceof h0);");
/*fuzzSeed-72153729*/count=2948; tryItOut("\"use strict\"; mathy1 = (function(x, y) { \"use strict\"; \"use asm\"; return (( + Math.atan2(( + ( - ( + (Math.atanh((( + Math.atan(( + ( ~ x)))) | 0)) | 0)))), Math.fround(( ~ Math.fround(x))))) == ( + ((Math.atan2((( ! Math.fround(mathy0(0, Math.acos(Math.hypot(Math.PI, x))))) | 0), Math.fround((y + mathy0((y >>> 0), y)))) | 0) < ((Math.asin(Number.MAX_SAFE_INTEGER) | 0) | 0)))); }); testMathyFunction(mathy1, [-Number.MIN_SAFE_INTEGER, 42, -1/0, 0x100000000, -0x100000001, -(2**53+2), 1, Math.PI, 0x080000001, 2**53-2, -0x07fffffff, 0x07fffffff, Number.MAX_VALUE, 0x0ffffffff, Number.MIN_SAFE_INTEGER, -0x080000000, 2**53, -0x100000000, -0, -Number.MAX_VALUE, 0x080000000, -(2**53), Number.MAX_SAFE_INTEGER, 0/0, 0x100000001, 0, 1.7976931348623157e308, 2**53+2, -0x080000001, 1/0, -(2**53-2), -Number.MAX_SAFE_INTEGER, 0.000000000000001, -0x0ffffffff, -Number.MIN_VALUE, Number.MIN_VALUE]); ");
/*fuzzSeed-72153729*/count=2949; tryItOut("a0[17];");
/*fuzzSeed-72153729*/count=2950; tryItOut("\"use strict\"; mathy4 = (function(x, y) { \"use strict\"; return (Math.acos(mathy0((Math.acosh(( ! (x >>> 0))) >>> 0), ((((Math.atan2(((Math.atanh((-(2**53) | 0)) | 0) >>> 0), (x >>> 0)) | 0) >>> 0) * Math.fround(Math.fround(Math.sign(( + y))))) >>> 0))) != Math.sin(Math.fround(Math.fround(Math.imul(y, ( ! x)))))); }); ");
/*fuzzSeed-72153729*/count=2951; tryItOut("Array.prototype.reverse.apply(a2, [o0.t2]);");
/*fuzzSeed-72153729*/count=2952; tryItOut("t0 = new Float64Array(a1);");
/*fuzzSeed-72153729*/count=2953; tryItOut("let this.v1 = a0.reduce, reduceRight((function() { e0.has(m1); return b0; }));");
/*fuzzSeed-72153729*/count=2954; tryItOut("mathy0 = (function(x, y) { \"use strict\"; return Math.fround(Math.max(Math.fround(((((Math.atanh(((y * x) >>> 0)) >>> 0) | 0) | (Math.cosh(Math.fround(Math.cbrt(( + (( + x) ? ( + ( + (( + ( ~ ( + y))) & -(2**53+2)))) : (Math.log((y >>> 0)) >>> 0)))))) | 0)) | 0)), Math.fround(Math.fround(Math.atanh(Math.fround(Math.log((Math.min((Math.PI | 0), Math.round((Math.cbrt(-Number.MIN_SAFE_INTEGER) >>> 0))) | 0)))))))); }); testMathyFunction(mathy0, /*MARR*/[x, function(){}, Infinity, Infinity, function(){}, (void 0), Infinity, x, (void 0), x, Infinity, x, x, x, (void 0), Infinity, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, function(){}, Infinity, x, (void 0), x, Infinity, function(){}, Infinity, Infinity, Infinity, function(){}, Infinity, (void 0), Infinity, (void 0), (void 0), (void 0), function(){}, x, function(){}, (void 0), (void 0), (void 0), function(){}, x, (void 0)]); ");
/*fuzzSeed-72153729*/count=2955; tryItOut("\"use strict\"; { if (isAsmJSCompilationAvailable()) { void 0; try { startgc(3111); } catch(e) { } } void 0; } g2.a0.pop();\ng1.v0 = g2.eval(\"/* no regression tests found */\");\n");
/*fuzzSeed-72153729*/count=2956; tryItOut("mathy4 = (function(x, y) { return ( + ( - Math.fround(Math.atan2(Math.fround(Math.max(x, y)), x)))); }); testMathyFunction(mathy4, [0x080000001, 0x07fffffff, 2**53, 0.000000000000001, 1/0, 42, Number.MIN_SAFE_INTEGER, 2**53-2, 1.7976931348623157e308, -0, -Number.MAX_VALUE, -0x080000001, 0/0, -0x0ffffffff, -1/0, -Number.MIN_SAFE_INTEGER, -(2**53+2), 1, 2**53+2, Number.MAX_SAFE_INTEGER, 0x0ffffffff, -(2**53-2), -0x07fffffff, 0x080000000, 0, -0x100000000, -0x100000001, 0x100000001, Number.MIN_VALUE, Math.PI, 0x100000000, -Number.MIN_VALUE, -(2**53), -0x080000000, -Number.MAX_SAFE_INTEGER, Number.MAX_VALUE]); ");
/*fuzzSeed-72153729*/count=2957; tryItOut("mathy1 = (function(x, y) { \"use strict\"; return Math.fround(Math.exp(((((Math.fround(( ~ x)) * 2**53) >>> 0) ? (((mathy0(-0x100000001, Math.acosh((mathy0((x >>> 0), x) | 0))) - ( + mathy0(x, -(2**53+2)))) | 0) >>> 0) : Math.clz32(y)) - mathy0(y, mathy0(mathy0(0.000000000000001, x), Math.fround((x & y))))))); }); testMathyFunction(mathy1, [Number.MIN_VALUE, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 0x080000000, -(2**53+2), 42, -0x080000001, Number.MIN_SAFE_INTEGER, 0x07fffffff, 0.000000000000001, -0x0ffffffff, Math.PI, -0x100000001, -0, -0x07fffffff, -(2**53-2), -1/0, 2**53+2, 0x080000001, -(2**53), 0/0, -Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, 0, 1/0, 0x0ffffffff, 0x100000001, -Number.MIN_VALUE, 1, -0x100000000, 0x100000000, -Number.MAX_VALUE, 2**53, -0x080000000, 1.7976931348623157e308, 2**53-2]); ");
/*fuzzSeed-72153729*/count=2958; tryItOut("mathy4 = (function(x, y) { return Math.cosh((((Math.fround((Math.fround(0.000000000000001) ? Math.fround(Math.hypot((( + (Math.log2((Math.atan2(( + y), ( + x)) | 0)) | 0)) | 0), (( ~ (y | 0)) | 0))) : Math.fround((Math.tanh((Math.cosh(-0x080000001) | 0)) | 0)))) >>> 0) ? (Math.fround((Math.fround((Math.fround(x) != (Math.acos((( - y) | 0)) >>> 0))) ? Math.fround(Math.log1p(Math.fround((y << (x >> y))))) : y)) >>> 0) : Math.fround(( + Math.ceil(( + ( + (-0x0ffffffff ** Math.fround(( + (x / -Number.MIN_SAFE_INTEGER)))))))))) >>> 0)); }); testMathyFunction(mathy4, [Number.MIN_SAFE_INTEGER, 0, 0x080000001, Number.MAX_SAFE_INTEGER, Number.MIN_VALUE, 2**53, 0x100000001, -Number.MAX_SAFE_INTEGER, Math.PI, -0x080000000, -(2**53+2), -0x100000001, -(2**53-2), 1, -1/0, -(2**53), -Number.MIN_VALUE, 0x100000000, -0x07fffffff, -0x100000000, -0, 1.7976931348623157e308, 42, 0/0, -Number.MAX_VALUE, -0x0ffffffff, 0x080000000, -Number.MIN_SAFE_INTEGER, 0x0ffffffff, 0x07fffffff, -0x080000001, 2**53+2, 0.000000000000001, Number.MAX_VALUE, 2**53-2, 1/0]); ");
/*fuzzSeed-72153729*/count=2959; tryItOut("\"use strict\"; mathy0 = (function(x, y) { return (Math.min(( ~ (Math.fround(Math.imul((Math.tan((Math.log10(((Math.fround(2**53-2) != Math.fround(-(2**53-2))) | 0)) | 0)) | 0), ((( ! (( + ( - y)) | 0)) | 0) | 0))) | 0)), Math.imul((( - Math.hypot((Math.log((Math.fround(Math.cosh(x)) | 0)) | 0), Math.fround(Math.imul(Math.fround(2**53-2), Math.fround(y))))) | 0), Math.fround(Math.acos(Math.fround(Math.asin(Math.max((((Math.fround(Math.max((y >>> 0), y)) | 0) ** Math.fround(Math.min(Math.fround(x), y))) | 0), (Math.pow(((y === x) >>> 0), (y >>> 0)) >>> 0)))))))) | 0); }); ");
/*fuzzSeed-72153729*/count=2960; tryItOut("v2 = null;");
/*fuzzSeed-72153729*/count=2961; tryItOut("(x);");
/*fuzzSeed-72153729*/count=2962; tryItOut("s1 += s2;");
/*fuzzSeed-72153729*/count=2963; tryItOut("/* no regression tests found */");
/*fuzzSeed-72153729*/count=2964; tryItOut("mathy1 = (function(stdlib, foreign, heap){ \"use asm\";   var imul = stdlib.Math.imul;\n  var ff = foreign.ff;\n  function f(d0, d1)\n  {\n    d0 = +d0;\n    d1 = +d1;\n    var d2 = -1073741825.0;\n    var d3 = -536870913.0;\n    return +((+((((((0x4dea11a8) % (0x2522fe2b)) | ((0xfacca352)-(0x2f3cf80f))) == (imul((0xfa2c081b), ((~((-0x8000000)))))|0))-((((0x48411021)+(!(0xb0b9c888))) & (((arguments.callee.prototype.valueOf(\"number\")))))))>>>(((0x4c032295) == (0x755befe0))+(0xe5f883d2)))));\n  }\n  return f; })(this, {ff: var r0 = x & 0; var r1 = r0 & 2; var r2 = x % 7; var r3 = 9 ^ r0; var r4 = 3 ^ r0; var r5 = r3 + r4; var r6 = r0 | x; var r7 = x - r3; print(r4); var r8 = r1 * 4; var r9 = r4 % r3; r7 = r8 * 6; var r10 = r1 % r1; var r11 = r10 / 0; var r12 = r11 / r6; var r13 = 5 - r10; var r14 = r10 / r3; var r15 = 6 - r8; var r16 = r14 / 8; var r17 = r16 & r3; var r18 = 8 ^ r10; var r19 = 9 ^ 0; var r20 = r10 & r4; var r21 = r11 % 5; var r22 = r3 - 3; var r23 = r19 & r14; var r24 = 3 | 5; var r25 = r6 & r3; var r26 = 2 * 8; var r27 = r13 + r3; var r28 = r19 & 2; r26 = r14 / r0; r0 = 6 + x; var r29 = r13 | 2; r20 = r22 - r7; r3 = 5 ^ x; var r30 = r1 + x; var r31 = r2 / r9; var r32 = 4 / 2; var r33 = r19 * 3; var r34 = r30 ^ 1; var r35 = 7 * 3; var r36 = r9 ^ 9; var r37 = 3 ^ r13; var r38 = 7 + 8; r21 = r2 - 0; print(r36); var r39 = r31 | r35; r17 = r10 % 6; var r40 = r30 | r4; var r41 = r21 / r2; var r42 = 9 & r26; r10 = r12 + r14; var r43 = r27 - 3; var r44 = r19 - r41; var r45 = r23 - 1; var r46 = 7 | 4; var r47 = r44 | r9; var r48 = 0 | 9; var r49 = r14 / r21; var r50 = r42 | r9; var r51 = r19 * r13; var r52 = r9 + 4; r26 = r36 - r7; var r53 = 4 ^ 7; var r54 = 7 - r30; var r55 = r6 & 0; r3 = r22 / 3; var r56 = r33 + 3; var r57 = 4 % r4; var r58 = r23 / 1; r1 = 8 | r56; var r59 = r39 & r39; print(r43); var r60 = r34 + 0; var r61 = 7 - 3; var r62 = 4 ^ r7; r24 = r25 - r22; var r63 = r19 + r57; var r64 = r50 - r43; var r65 = r24 - 0; var r66 = r53 % 6; var r67 = r58 % r11; var r68 = 3 | r5; var r69 = r4 % r38; var r70 = r19 % r44; var r71 = 1 - 8; r23 = r57 | 6; var r72 = 1 / r51; var r73 = r13 | 5; var r74 = 8 / r42; var r75 = 7 - r5; var r76 = r57 | r55; var r77 = r62 / r1; var r78 = r72 | r49; var r79 = r55 % r12; var r80 = r38 ^ r17; print(r4); var r81 = 8 / r2; var r82 = r60 / 9; r57 = r35 - r12; r51 = r9 | r15; var r83 = r69 * r66; var r84 = r42 * r41; var r85 = r3 / r43; var r86 = 1 / 8; var r87 = r49 * r4; var r88 = r50 - r46; var r89 = r23 ^ 9; var r90 = r45 + r2; var r91 = r26 + r73; var r92 = r9 / 1; r56 = r49 * r28; var r93 = 3 / r54; var r94 = 5 ^ 9; print(r79); var r95 = 8 * r4; var r96 = 1 % r45; r49 = r90 ^ r64; var r97 = r10 & r10; var r98 = 8 | 1; r8 = r4 & r91; var r99 = 9 | r53; var r100 = r0 & r76; var r101 = r66 & r42; var r102 = 0 * r69; var r103 = r28 * r94; var r104 = r47 & r96; var r105 = r24 + r101; var r106 = r82 * r78; var r107 = r68 ^ 0; var r108 = 4 + r11; var r109 = r87 & r89; var r110 = r39 / r104; var r111 = r75 & r32; var r112 = r34 + r84; var r113 = 3 * r110; var r114 = 1 * r28; var r115 = r114 & r42; var r116 = r66 + r19; var r117 = 0 & 1; var r118 = r112 / r31; print(r72); var r119 = 2 / r42; var r120 = r18 & r43; var r121 = r47 | r19; r101 = 2 & 2; r34 = 4 + 8; r89 = r21 & 5; var r122 = r46 | r65; var r123 = 3 ^ 5; var r124 = 9 % r103; var r125 = r105 % 8; var r126 = r120 * r88; var r127 = r28 % r91; var r128 = 8 % r35; var r129 = 3 & r24; var r130 = 3 & r17; r48 = r41 | r27; var r131 = r68 / r61; }, new SharedArrayBuffer(4096)); testMathyFunction(mathy1, /*MARR*/[ /x/ ,  '\\0' , false,  /x/ ,  /x/g ,  /x/g ,  '\\0' , false, false,  '\\0' ,  /x/g ]); ");
/*fuzzSeed-72153729*/count=2965; tryItOut("this.v0 = Array.prototype.every.apply(a1, [(function() { for (var j=0;j<40;++j) { f0(j%2==1); } }), e0]);");
/*fuzzSeed-72153729*/count=2966; tryItOut("{ if (!isAsmJSCompilationAvailable()) { void 0; verifyprebarriers(); } void 0; } let (z) { let (x) { (\n[z1,,]); } }");
/*fuzzSeed-72153729*/count=2967; tryItOut("throw x;/*tLoop*/for (let z of /*MARR*/[x, false]) { print(\"\\u66E5\"); }");
/*fuzzSeed-72153729*/count=2968; tryItOut("\"use strict\"; /*RXUB*/var r = /(?:\\1)((?=((\\B)*)?){0,2}){2147483647}/; var s = \"\"; print(s.split(r)); ");
// SPLICE DDEND

if (jsshell)
  print("It's looking good!"); // Magic string that jsInteresting.py looks for


// 3. Run it.